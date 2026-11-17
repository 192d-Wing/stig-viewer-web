//! Single-system detail page: summary, posture/compliance trends, applied
//! STIGs, sharing (ACL), email recipients + schedule, and the runbook.

use crate::api::{api_fetch, api_get, api_json, response_blob, response_filename, BACKEND};
use crate::auth::use_current_user;
use crate::ui::*;
use crate::util::{document, encode_uri_component, parse_date_ms, spawn_local, to_locale_string};
use crate::utils::markdown::render_markdown;
use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen::JsCast;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct AssetDetailProps {
    pub asset_id: String,
    pub on_back: Callback<()>,
    /// Checklist id to open.
    pub on_open_checklist: Callback<String>,
    /// The asset JSON as returned by GET /api/assets/:id, for the edit modal.
    pub on_edit: Callback<serde_json::Value>,
}

// ── API payloads ────────────────────────────────────────────────────────────

/// The fields of the asset row this page reads.
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Asset {
    id: String,
    name: String,
    hostname: String,
    description: String,
    classification: String,
    owner_id: String,
    requires_approval: bool,
    email_cadence: String,
    email_last_sent_at: Option<String>,
    runbook: String,
}

/// The asset as typed fields plus the untouched JSON (handed to `on_edit`).
#[derive(Clone, PartialEq)]
struct LoadedAsset {
    data: Asset,
    raw: Value,
}

impl LoadedAsset {
    fn from_raw(raw: Value) -> Result<Self, String> {
        let data = serde_json::from_value(raw.clone()).map_err(|e| e.to_string())?;
        Ok(Self { data, raw })
    }
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Checklist {
    id: String,
    stig_id: String,
    status: String,
    updated_at: String,
    applied_version: String,
    applied_release: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CatalogEntry {
    id: String,
    title: String,
    category: String,
    version: String,
    release_info: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct TrendPoint {
    captured_at: String,
    open: f64,
    reviewed: f64,
    compliance_score: Option<f64>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Trend {
    overall: Vec<TrendPoint>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AclRow {
    user_id: String,
    display_name: String,
    permission: String,
    granted_at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct UserSummary {
    id: String,
    display_name: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CcRow {
    email: String,
    added_at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct EmailReportResult {
    recipients: Vec<String>,
    mode: String,
    error: Option<String>,
}

// ── Local state shapes ──────────────────────────────────────────────────────

/// Outcome of "Email report now".
#[derive(Clone, PartialEq)]
enum EmailSendStatus {
    Success { recipients: Vec<String>, mode: String, error: Option<String> },
    Error(String),
}

/// The checklist the "Re-apply STIG" modal is confirming.
#[derive(Clone, PartialEq)]
struct ReapplyTarget {
    id: String,
    title: String,
    from_version: String,
    from_release: String,
    to_version: String,
    to_release: String,
}

/// Handles written by the main page load.
#[derive(Clone)]
struct PageState {
    asset: UseStateHandle<Option<LoadedAsset>>,
    checklists: UseStateHandle<Vec<Checklist>>,
    catalog: UseStateHandle<Vec<CatalogEntry>>,
    trend: UseStateHandle<Option<Trend>>,
    loading: UseStateHandle<bool>,
    error: UseStateHandle<Option<String>>,
}

/// Handles written by the sharing (ACL) probe.
#[derive(Clone)]
struct AclState {
    rows: UseStateHandle<Vec<AclRow>>,
    visible: UseStateHandle<bool>,
    users: UseStateHandle<Vec<UserSummary>>,
}

/// Handles written by the email-CC probe.
#[derive(Clone)]
struct CcState {
    rows: UseStateHandle<Vec<CcRow>>,
    visible: UseStateHandle<bool>,
}

async fn fetch_page(
    asset_id: &str,
) -> Result<(LoadedAsset, Vec<Checklist>, Vec<CatalogEntry>, Option<Trend>), String> {
    let asset = LoadedAsset::from_raw(api_get::<Value>(&format!("/api/assets/{asset_id}")).await?)?;
    let checklists = api_get(&format!("/api/assets/{asset_id}/checklists")).await?;
    // catalog is public — but api_get sends creds anyway, no harm
    let catalog = api_get("/api/catalog").await?;
    // The trend is optional: a failure just hides the charts.
    let trend = api_get(&format!("/api/assets/{asset_id}/trend?days=30")).await.ok();
    Ok((asset, checklists, catalog, trend))
}

async fn refresh(asset_id: &str, st: &PageState) {
    st.loading.set(true);
    st.error.set(None);
    match fetch_page(asset_id).await {
        Ok((asset, checklists, catalog, trend)) => {
            st.asset.set(Some(asset));
            st.checklists.set(checklists);
            st.catalog.set(catalog);
            st.trend.set(trend);
        }
        Err(e) => st.error.set(Some(e)),
    }
    st.loading.set(false);
}

/// Probe + load the ACL roster. The backend 403s when the caller can't
/// manage sharing on the asset, which is exactly the signal we want for
/// hiding the section UI. We swallow the 403 (and any other failure) and
/// leave `visible` false so the section stays hidden.
async fn refresh_acl(asset_id: &str, st: &AclState) {
    let rows = match api_fetch("GET", &format!("/api/assets/{asset_id}/acl")).await {
        Ok(res) if res.ok() => res.json::<Vec<AclRow>>().await.ok(),
        // Non-2xx or a network-level failure — keep the section hidden
        // rather than leaking auth state via an alarming alert.
        _ => None,
    };
    let Some(rows) = rows else {
        st.visible.set(false);
        return;
    };
    st.rows.set(rows);
    st.visible.set(true);
    // Lazy-load the user picker too — only needed inside the section.
    // The picker just won't have options if this fails.
    st.users.set(api_get("/api/users").await.unwrap_or_default());
}

/// Mirrors `refresh_acl` — a 403 from the list endpoint is the signal
/// that the current user can't manage this asset, so we hide the
/// section silently instead of surfacing a scary error.
async fn refresh_cc(asset_id: &str, st: &CcState) {
    let rows = match api_fetch("GET", &format!("/api/assets/{asset_id}/email-cc")).await {
        Ok(res) if res.ok() => res.json::<Vec<CcRow>>().await.ok(),
        _ => None,
    };
    match rows {
        Some(rows) => {
            st.rows.set(rows);
            st.visible.set(true);
        }
        None => st.visible.set(false),
    }
}

/// Blob download via a temporary anchor. The object URL is revoked a second
/// later so the click has time to start the download.
async fn save_blob(blob: &web_sys::Blob, filename: &str) {
    let Ok(url) = web_sys::Url::create_object_url_with_blob(blob) else {
        return;
    };
    let doc = document();
    if let Ok(el) = doc.create_element("a") {
        let a: web_sys::HtmlAnchorElement = el.unchecked_into();
        a.set_href(&url);
        a.set_download(filename);
        if let Some(body) = doc.body() {
            let _ = body.append_child(&a);
        }
        a.click();
        a.remove();
    }
    gloo_timers::future::TimeoutFuture::new(1000).await;
    let _ = web_sys::Url::revoke_object_url(&url);
}

fn or_fallback(msg: String, fallback: &str) -> String {
    if msg.is_empty() {
        fallback.to_string()
    } else {
        msg
    }
}

fn cadence_options() -> Vec<SelectOption> {
    vec![
        SelectOption::new("off", "Off"),
        SelectOption::new("daily", "Daily"),
        SelectOption::new("weekly", "Weekly"),
        SelectOption::new("monthly", "Monthly"),
    ]
}

fn default_permission() -> SelectOption {
    SelectOption::new("write", "Write")
}

#[function_component]
pub fn AssetDetail(props: &AssetDetailProps) -> Html {
    let current_user = use_current_user();
    let asset_id = props.asset_id.clone();

    let page = PageState {
        asset: use_state(|| None),
        checklists: use_state(Vec::new),
        catalog: use_state(Vec::new),
        trend: use_state(|| None),
        loading: use_state(|| true),
        error: use_state(|| None),
    };

    let apply_open = use_state(|| false);
    let selected_stig = use_state(|| None::<SelectOption>);
    let apply_error = use_state(|| None::<String>);
    let applying = use_state(|| false);

    // ── Sharing (ACL) state ────────────────────────────────────────────
    // Loaded lazily — the ACL list endpoint 403s for non-managers, so we
    // probe it once and surface the section only when the response was
    // 200. `acl.visible` is the gate (owner / global admin / acl-admin).
    let acl = AclState {
        rows: use_state(Vec::new),
        visible: use_state(|| false),
        users: use_state(Vec::new),
    };
    let acl_target = use_state(|| None::<SelectOption>);
    let acl_permission = use_state(default_permission);
    let acl_error = use_state(|| None::<String>);
    let acl_busy = use_state(|| false);

    // ── Email CC state ─────────────────────────────────────────────────
    // The list endpoint 403s for anyone who can't manage the asset, so we
    // probe it and only render the section if the response was 200 — same
    // pattern as the Sharing section above. Owner / write-ACL / admin.
    let cc = CcState { rows: use_state(Vec::new), visible: use_state(|| false) };
    let cc_input = use_state(String::new);
    let cc_error = use_state(|| None::<String>);
    let cc_busy = use_state(|| false);
    let email_send_status = use_state(|| None::<EmailSendStatus>);
    let email_sending = use_state(|| false);

    let cadence_busy = use_state(|| false);
    let approval_toggle_busy = use_state(|| false);
    let reapply_target = use_state(|| None::<ReapplyTarget>);
    let reapplying = use_state(|| false);

    // Load the page, then probe ACL + email-CC access, whenever the asset
    // changes.
    {
        let (page, acl, cc) = (page.clone(), acl.clone(), cc.clone());
        use_effect_with(asset_id.clone(), move |id| {
            let (a, b, c) = (id.clone(), id.clone(), id.clone());
            spawn_local(async move { refresh(&a, &page).await });
            spawn_local(async move { refresh_acl(&b, &acl).await });
            spawn_local(async move { refresh_cc(&c, &cc).await });
        });
    }

    let grant_acl = {
        let (asset_id, acl) = (asset_id.clone(), acl.clone());
        let (target, permission) = (acl_target.clone(), acl_permission.clone());
        let (error, busy) = (acl_error.clone(), acl_busy.clone());
        Callback::from(move |_: MouseEvent| {
            let Some(user) = (*target).clone() else {
                return;
            };
            let body = json!({ "userId": user.value.as_str(), "permission": permission.value.as_str() });
            let (asset_id, acl) = (asset_id.clone(), acl.clone());
            let (target, permission) = (target.clone(), permission.clone());
            let (error, busy) = (error.clone(), busy.clone());
            busy.set(true);
            error.set(None);
            spawn_local(async move {
                match api_json::<Value, _>(&format!("/api/assets/{asset_id}/acl"), "POST", Some(&body)).await {
                    Ok(_) => {
                        target.set(None);
                        permission.set(default_permission());
                        refresh_acl(&asset_id, &acl).await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                busy.set(false);
            });
        })
    };

    let revoke_acl = {
        let (asset_id, acl, error) = (asset_id.clone(), acl.clone(), acl_error.clone());
        Callback::from(move |user_id: String| {
            let (asset_id, acl, error) = (asset_id.clone(), acl.clone(), error.clone());
            spawn_local(async move {
                let path = format!("/api/assets/{asset_id}/acl/{}", encode_uri_component(&user_id));
                match api_fetch("DELETE", &path).await {
                    Ok(res) if res.ok() => refresh_acl(&asset_id, &acl).await,
                    Ok(res) => error.set(Some(format!("Revoke failed: {}", res.status()))),
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    let add_cc = {
        let (asset_id, cc) = (asset_id.clone(), cc.clone());
        let (input, error, busy) = (cc_input.clone(), cc_error.clone(), cc_busy.clone());
        Callback::from(move |_: MouseEvent| {
            let email = input.trim().to_string();
            if email.is_empty() || !email.contains('@') {
                error.set(Some("Enter a valid email address (must contain @).".into()));
                return;
            }
            let (asset_id, cc) = (asset_id.clone(), cc.clone());
            let (input, error, busy) = (input.clone(), error.clone(), busy.clone());
            busy.set(true);
            error.set(None);
            spawn_local(async move {
                let body = json!({ "email": email });
                match api_json::<Vec<CcRow>, _>(&format!("/api/assets/{asset_id}/email-cc"), "POST", Some(&body)).await {
                    Ok(rows) => {
                        cc.rows.set(rows);
                        input.set(String::new());
                    }
                    Err(e) => error.set(Some(or_fallback(e, "Failed to add recipient."))),
                }
                busy.set(false);
            });
        })
    };

    let remove_cc = {
        let (asset_id, cc, error) = (asset_id.clone(), cc.clone(), cc_error.clone());
        Callback::from(move |email: String| {
            let (asset_id, cc, error) = (asset_id.clone(), cc.clone(), error.clone());
            error.set(None);
            spawn_local(async move {
                let path = format!("/api/assets/{asset_id}/email-cc/{}", encode_uri_component(&email));
                match api_fetch("DELETE", &path).await {
                    Ok(res) if res.ok() => refresh_cc(&asset_id, &cc).await,
                    Ok(res) => error.set(Some(format!("Remove failed: {}", res.status()))),
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    // ── Scheduled email cadence ────────────────────────────────────────
    // Re-uses the same write-ACL gate the on-demand send already uses
    // (cc.visible). Persists via the asset PATCH endpoint and stores the
    // returned asset row so `emailLastSentAt` reflects whatever the
    // scheduler last stamped.
    let set_cadence = {
        let (asset_id, asset) = (asset_id.clone(), page.asset.clone());
        let (error, busy) = (cc_error.clone(), cadence_busy.clone());
        Callback::from(move |next: SelectOption| {
            if asset.is_none() {
                return;
            }
            let (asset_id, asset) = (asset_id.clone(), asset.clone());
            let (error, busy) = (error.clone(), busy.clone());
            busy.set(true);
            spawn_local(async move {
                let body = json!({ "emailCadence": next.value.as_str() });
                let updated = api_json::<Value, _>(&format!("/api/assets/{asset_id}"), "PATCH", Some(&body))
                    .await
                    .and_then(LoadedAsset::from_raw);
                match updated {
                    Ok(a) => asset.set(Some(a)),
                    Err(e) => error.set(Some(or_fallback(e, "Failed to update cadence."))),
                }
                busy.set(false);
            });
        })
    };

    let email_report_now = {
        let asset_id = asset_id.clone();
        let (status, sending) = (email_send_status.clone(), email_sending.clone());
        Callback::from(move |_: MouseEvent| {
            let asset_id = asset_id.clone();
            let (status, sending) = (status.clone(), sending.clone());
            sending.set(true);
            status.set(None);
            spawn_local(async move {
                let path = format!("/api/assets/{asset_id}/email-report");
                status.set(Some(match api_json::<EmailReportResult, _>(&path, "POST", Some(&json!({}))).await {
                    Ok(r) => EmailSendStatus::Success {
                        recipients: r.recipients,
                        mode: r.mode,
                        error: r.error.filter(|e| !e.is_empty()),
                    },
                    Err(e) => EmailSendStatus::Error(or_fallback(e, "Failed to send report.")),
                }));
                sending.set(false);
            });
        })
    };

    let apply = {
        let (asset_id, page) = (asset_id.clone(), page.clone());
        let (open, selected) = (apply_open.clone(), selected_stig.clone());
        let (error, applying) = (apply_error.clone(), applying.clone());
        Callback::from(move |_: MouseEvent| {
            let Some(stig) = (*selected).clone() else {
                return;
            };
            let (asset_id, page) = (asset_id.clone(), page.clone());
            let (open, selected) = (open.clone(), selected.clone());
            let (error, applying) = (error.clone(), applying.clone());
            applying.set(true);
            error.set(None);
            spawn_local(async move {
                let body = json!({ "stigId": stig.value.as_str() });
                match api_json::<Value, _>(&format!("/api/assets/{asset_id}/checklists"), "POST", Some(&body)).await {
                    Ok(_) => {
                        open.set(false);
                        selected.set(None);
                        refresh(&asset_id, &page).await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                applying.set(false);
            });
        })
    };

    let remove_checklist = {
        let (asset_id, page) = (asset_id.clone(), page.clone());
        Callback::from(move |cid: String| {
            let (asset_id, page) = (asset_id.clone(), page.clone());
            spawn_local(async move {
                match api_fetch("DELETE", &format!("/api/checklists/{cid}")).await {
                    Ok(res) if res.ok() => refresh(&asset_id, &page).await,
                    Ok(res) => page.error.set(Some(format!("Delete failed: {}", res.status()))),
                    Err(e) => page.error.set(Some(e)),
                }
            });
        })
    };

    let toggle_approval_policy = {
        let (asset_id, page, busy) = (asset_id.clone(), page.clone(), approval_toggle_busy.clone());
        Callback::from(move |next: bool| {
            if page.asset.is_none() {
                return;
            }
            let (asset_id, page, busy) = (asset_id.clone(), page.clone(), busy.clone());
            busy.set(true);
            spawn_local(async move {
                let path = format!("/api/assets/{asset_id}/approval-policy");
                let updated = api_json::<Value, _>(&path, "PATCH", Some(&json!({ "requiresApproval": next })))
                    .await
                    .and_then(LoadedAsset::from_raw);
                match updated {
                    Ok(a) => page.asset.set(Some(a)),
                    Err(e) => page.error.set(Some(e)),
                }
                busy.set(false);
            });
        })
    };

    // OSCAL JSON download — fetched via api_fetch so we carry the
    // X-User-Id header through, then triggered as a blob download in the
    // browser. The filename comes from the server's Content-Disposition
    // when present (which is the case here — see backend/src/api/oscal.rs).
    let download_oscal = {
        let page = page.clone();
        Callback::from(move |_: MouseEvent| {
            let Some(asset) = (*page.asset).clone() else {
                return;
            };
            let error = page.error.clone();
            spawn_local(async move {
                let res = match api_fetch("GET", &format!("/api/assets/{}/oscal.json", asset.data.id)).await {
                    Ok(res) if res.ok() => res,
                    Ok(res) => {
                        error.set(Some(format!("OSCAL download failed: {}", res.status())));
                        return;
                    }
                    Err(e) => {
                        error.set(Some(or_fallback(e, "OSCAL download failed")));
                        return;
                    }
                };
                match response_blob(&res).await {
                    Ok(blob) => {
                        // Fall back to a sensible default so we don't end up with "download".
                        let filename =
                            response_filename(&res).unwrap_or_else(|| format!("oscal-{}.json", asset.data.name));
                        save_blob(&blob, &filename).await;
                    }
                    Err(e) => error.set(Some(or_fallback(e, "OSCAL download failed"))),
                }
            });
        })
    };

    let reapply = {
        let (asset_id, page) = (asset_id.clone(), page.clone());
        let (target, reapplying) = (reapply_target.clone(), reapplying.clone());
        Callback::from(move |_: MouseEvent| {
            let Some(t) = (*target).clone() else {
                return;
            };
            let (asset_id, page) = (asset_id.clone(), page.clone());
            let (target, reapplying) = (target.clone(), reapplying.clone());
            reapplying.set(true);
            spawn_local(async move {
                let path = format!("/api/checklists/{}/reapply", t.id);
                match api_json::<Value, _>(&path, "POST", Some(&json!({}))).await {
                    Ok(_) => {
                        target.set(None);
                        refresh(&asset_id, &page).await;
                    }
                    Err(e) => page.error.set(Some(e)),
                }
                reapplying.set(false);
            });
        })
    };

    let back = {
        let on_back = props.on_back.clone();
        Callback::from(move |_: MouseEvent| on_back.emit(()))
    };

    if *page.loading {
        return html! {
            <UiBox padding="xxl" text_align="center">
                <StatusIndicator kind="loading">{"Loading system"}</StatusIndicator>
            </UiBox>
        };
    }

    if let Some(error) = &*page.error {
        return html! {
            <UiBox padding="m">
                <Alert kind="error" header={html! { {"Error"} }}>{error.clone()}</Alert>
                <UiBox padding_top="m">
                    <Button onclick={back}>{"Back to systems"}</Button>
                </UiBox>
            </UiBox>
        };
    }

    let Some(loaded) = (*page.asset).clone() else {
        return Html::default();
    };
    let asset = loaded.data.clone();
    let is_owner = current_user.as_ref().is_some_and(|u| u.id == asset.owner_id);

    let checklists = (*page.checklists).clone();
    let catalog = (*page.catalog).clone();
    let available_stigs: Vec<&CatalogEntry> =
        catalog.iter().filter(|s| !checklists.iter().any(|c| c.stig_id == s.id)).collect();

    // ── Summary ────────────────────────────────────────────────────────
    let summary = html! {
        <Container header={html! {
            <Header
                variant="h1"
                description={if asset.description.is_empty() { Html::default() } else { html! { {asset.description.clone()} } }}
                actions={html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button
                            icon_name="download"
                            href={format!("{BACKEND}/api/assets/{}/report.pdf", asset.id)}
                            target="_blank"
                            download=""
                        >
                            {"Download PDF report"}
                        </Button>
                        <Button
                            icon_name="download"
                            href={format!("{BACKEND}/api/assets/{}/bundle.zip", asset.id)}
                            target="_blank"
                            download=""
                            aria_label="Download bundle (includes CKL files and evidence attachments)"
                        >
                            {"Download bundle"}
                        </Button>
                        <Button
                            icon_name="download"
                            onclick={download_oscal}
                            aria_label="Download OSCAL assessment-results JSON"
                        >
                            {"Download OSCAL"}
                        </Button>
                    </SpaceBetween>
                }}
            >
                {asset.name.clone()}
            </Header>
        }}>
            <ColumnLayout columns={4} variant="text-grid">
                <div>
                    <UiBox variant="awsui-key-label">{"Hostname"}</UiBox>
                    <div>{if asset.hostname.is_empty() { "—".to_string() } else { asset.hostname.clone() }}</div>
                </div>
                <div>
                    <UiBox variant="awsui-key-label">{"Classification"}</UiBox>
                    <Badge>{asset.classification.clone()}</Badge>
                </div>
                <div>
                    <UiBox variant="awsui-key-label">{"Owner"}</UiBox>
                    <div>{if is_owner { "You".to_string() } else { asset.owner_id.clone() }}</div>
                </div>
                <div>
                    <UiBox variant="awsui-key-label">{"Require approval to close findings"}</UiBox>
                    <Toggle
                        checked={asset.requires_approval}
                        disabled={!is_owner || *approval_toggle_busy}
                        on_change={toggle_approval_policy}
                        testid="approval-policy-toggle"
                    >
                        {if asset.requires_approval { "Enabled" } else { "Disabled" }}
                    </Toggle>
                </div>
            </ColumnLayout>
        </Container>
    };

    // ── Trend charts ───────────────────────────────────────────────────
    let trend_charts = match page.trend.as_ref().filter(|t| !t.overall.is_empty()) {
        None => Html::default(),
        Some(trend) => {
            let n = trend.overall.len();
            let description = format!("{n} snapshot{} in the last 30 days", if n == 1 { "" } else { "s" });
            let series = |y: fn(&TrendPoint) -> f64| -> Vec<(f64, f64)> {
                trend.overall.iter().map(|p| (parse_date_ms(&p.captured_at), y(p))).collect()
            };
            let empty = html! { <UiBox text_align="center" color="inherit">{"No snapshots yet"}</UiBox> };
            html! {
                <>
                    <Container header={html! {
                        <Header variant="h2" description={html! { {description.clone()} }}>{"Posture over time"}</Header>
                    }}>
                        <LineChart
                            series={vec![
                                ChartSeries::line("Open", series(|p| p.open)).color("#d13212"),
                                ChartSeries::line("Reviewed", series(|p| p.reviewed)).color("#1d8102"),
                            ]}
                            x_scale_type="time"
                            x_title="Time"
                            y_title="Rules"
                            height={220}
                            aria_label={format!("{} posture trend", asset.name)}
                            empty={empty.clone()}
                        />
                    </Container>
                    <Container header={html! {
                        <Header variant="h2" description={html! { {description} }}>{"Compliance trend"}</Header>
                    }}>
                        <LineChart
                            series={vec![
                                ChartSeries::line("Compliance", series(|p| p.compliance_score.unwrap_or(0.0)))
                                    .color("#1d8102"),
                            ]}
                            x_scale_type="time"
                            x_title="Time"
                            y_title="Compliance (%)"
                            y_domain={(0.0, 100.0)}
                            height={220}
                            aria_label={format!("{} compliance trend", asset.name)}
                            {empty}
                        />
                    </Container>
                </>
            }
        }
    };

    // ── Applied STIGs ──────────────────────────────────────────────────
    let checklist_columns = {
        let stig_cell = {
            let catalog = catalog.clone();
            let on_open = props.on_open_checklist.clone();
            let reapply_target = reapply_target.clone();
            move |c: &Checklist| {
                let meta = catalog.iter().find(|s| s.id == c.stig_id);
                let title = meta.map(|m| m.title.clone()).filter(|t| !t.is_empty()).unwrap_or_else(|| c.stig_id.clone());
                let outdated = !c.applied_version.is_empty()
                    && meta.is_some_and(|m| m.version != c.applied_version || m.release_info != c.applied_release);
                let open = {
                    let (on_open, id) = (on_open.clone(), c.id.clone());
                    Callback::from(move |_: MouseEvent| on_open.emit(id.clone()))
                };
                let ask_reapply = {
                    let reapply_target = reapply_target.clone();
                    let target = ReapplyTarget {
                        id: c.id.clone(),
                        title: title.clone(),
                        from_version: c.applied_version.clone(),
                        from_release: c.applied_release.clone(),
                        to_version: meta.map(|m| m.version.clone()).unwrap_or_default(),
                        to_release: meta.map(|m| m.release_info.clone()).unwrap_or_default(),
                    };
                    Callback::from(move |_: MouseEvent| reapply_target.set(Some(target.clone())))
                };
                html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="inline-link" onclick={open}>{title}</Button>
                        if outdated {
                            <Badge color="red">{"Out of date"}</Badge>
                            <Button variant="inline-link" disabled={!is_owner} onclick={ask_reapply}>
                                {"Re-apply"}
                            </Button>
                        }
                    </SpaceBetween>
                }
            }
        };
        let remove_checklist = remove_checklist.clone();
        vec![
            Column::new("stig", "STIG", stig_cell),
            Column::new("status", "Status", |c: &Checklist| html! { <Badge>{c.status.clone()}</Badge> }),
            Column::new("updated", "Last activity", |c: &Checklist| html! { {to_locale_string(&c.updated_at)} }),
            Column::new("actions", "", move |c: &Checklist| {
                let (remove, id) = (remove_checklist.clone(), c.id.clone());
                html! {
                    <Button variant="inline-link" disabled={!is_owner} onclick={move |_| remove.emit(id.clone())}>
                        {"Remove"}
                    </Button>
                }
            }),
        ]
    };
    let open_apply = {
        let (open, selected, error) = (apply_open.clone(), selected_stig.clone(), apply_error.clone());
        Callback::from(move |_: MouseEvent| {
            selected.set(None);
            error.set(None);
            open.set(true);
        })
    };
    let checklists_table = html! {
        <Table<Checklist>
            variant="container"
            items={checklists.clone()}
            columns={checklist_columns}
            empty={html! {
                <UiBox text_align="center" padding="l">
                    <UiBox variant="p" color="text-body-secondary">{"No STIGs applied to this system yet."}</UiBox>
                </UiBox>
            }}
            header={html! {
                <Header
                    counter={format!("({})", checklists.len())}
                    actions={html! {
                        <Button
                            variant="primary"
                            disabled={!is_owner || available_stigs.is_empty()}
                            onclick={open_apply}
                        >
                            {"Apply STIG"}
                        </Button>
                    }}
                >
                    {"Applied STIGs"}
                </Header>
            }}
        />
    };

    // ── Sharing ────────────────────────────────────────────────────────
    let sharing = if *acl.visible {
        let rows = (*acl.rows).clone();
        let columns = vec![
            Column::new("user", "User", |r: &AclRow| {
                html! { {if r.display_name.is_empty() { r.user_id.clone() } else { r.display_name.clone() }} }
            }),
            Column::new("permission", "Permission", |r: &AclRow| html! { <Badge>{r.permission.clone()}</Badge> }),
            Column::new("grantedAt", "Granted", |r: &AclRow| html! { {to_locale_string(&r.granted_at)} }),
            Column::new("actions", "", move |r: &AclRow| {
                let (revoke, id) = (revoke_acl.clone(), r.user_id.clone());
                html! {
                    <Button
                        variant="inline-link"
                        onclick={move |_| revoke.emit(id.clone())}
                        testid={format!("sharing-remove-{}", r.user_id)}
                    >
                        {"Remove"}
                    </Button>
                }
            }),
        ];
        // Hide the owner and anyone already in the roster — re-adding
        // them is either a no-op or rejected by the backend.
        let user_options: Vec<SelectOption> = acl
            .users
            .iter()
            .filter(|u| u.id != asset.owner_id && !rows.iter().any(|r| r.user_id == u.id))
            .map(|u| SelectOption::new(u.id.clone(), u.display_name.clone()))
            .collect();
        let on_target = {
            let target = acl_target.clone();
            Callback::from(move |o: SelectOption| target.set(Some(o)))
        };
        let on_permission = {
            let permission = acl_permission.clone();
            Callback::from(move |o: SelectOption| permission.set(o))
        };
        let dismiss_error = {
            let error = acl_error.clone();
            Callback::from(move |_| error.set(None))
        };
        html! {
            <Container
                header={html! {
                    <Header
                        variant="h2"
                        counter={format!("({})", rows.len())}
                        description={html! { {"Owner and global admins always have full access. Add a user below to grant additional read/write/admin permission on this system."} }}
                    >
                        {"Sharing"}
                    </Header>
                }}
                testid="sharing-section"
            >
                <SpaceBetween direction="vertical" size="m">
                    if let Some(e) = &*acl_error {
                        <Alert kind="error" on_dismiss={dismiss_error} dismissible=true>{e.clone()}</Alert>
                    }
                    <Table<AclRow>
                        variant="embedded"
                        items={rows}
                        testid="sharing-table"
                        {columns}
                        empty={html! {
                            <UiBox text_align="center" padding="m">
                                <UiBox variant="p" color="text-body-secondary">
                                    {"No additional users have been granted access."}
                                </UiBox>
                            </UiBox>
                        }}
                    />
                    <ColumnLayout columns={3}>
                        <FormField label={html! { {"User"} }}>
                            <Select
                                selected={acl_target.as_ref().map(|o| o.value.clone())}
                                selected_label={acl_target.as_ref().map(|o| o.label.clone())}
                                on_change={on_target}
                                placeholder="Choose a user"
                                filtering=true
                                testid="sharing-user-select"
                                options={user_options}
                            />
                        </FormField>
                        <FormField label={html! { {"Permission"} }}>
                            <Select
                                selected={acl_permission.value.clone()}
                                on_change={on_permission}
                                testid="sharing-permission-select"
                                options={vec![
                                    SelectOption::new("read", "Read"),
                                    SelectOption::new("write", "Write"),
                                    SelectOption::new("admin", "Admin"),
                                ]}
                            />
                        </FormField>
                        <FormField label={html! { {"\u{a0}"} }}>
                            <Button
                                variant="primary"
                                loading={*acl_busy}
                                disabled={acl_target.is_none()}
                                onclick={grant_acl}
                                testid="sharing-add-button"
                            >
                                {"Add"}
                            </Button>
                        </FormField>
                    </ColumnLayout>
                </SpaceBetween>
            </Container>
        }
    } else {
        Html::default()
    };

    // ── Email recipients ───────────────────────────────────────────────
    let email_section = if *cc.visible {
        let rows = (*cc.rows).clone();
        let columns = vec![
            Column::new("email", "Email", |r: &CcRow| html! { {r.email.clone()} }),
            Column::new("added", "Added", |r: &CcRow| html! { {to_locale_string(&r.added_at)} }),
            Column::new("actions", "", move |r: &CcRow| {
                let (remove, email) = (remove_cc.clone(), r.email.clone());
                html! {
                    <Button
                        variant="inline-link"
                        onclick={move |_| remove.emit(email.clone())}
                        testid={format!("email-cc-remove-{}", r.email)}
                    >
                        {"Remove"}
                    </Button>
                }
            }),
        ];
        let dismiss_error = {
            let error = cc_error.clone();
            Callback::from(move |_| error.set(None))
        };
        let dismiss_status = {
            let status = email_send_status.clone();
            Callback::from(move |_| status.set(None))
        };
        let send_result = match &*email_send_status {
            None => Html::default(),
            Some(EmailSendStatus::Success { recipients, mode, error }) => {
                let header = match error {
                    Some(_) => format!("Email send reported an error (mode: {mode})"),
                    None => format!(
                        "Email {} to {} recipient{}",
                        if mode == "dryrun" { "queued (dry-run)" } else { "sent" },
                        recipients.len(),
                        if recipients.len() == 1 { "" } else { "s" },
                    ),
                };
                let list = if recipients.is_empty() { "(no recipients)".to_string() } else { recipients.join(", ") };
                html! {
                    <Alert
                        kind={if error.is_some() { "warning" } else { "success" }}
                        dismissible=true
                        on_dismiss={dismiss_status}
                        testid="email-send-result"
                        header={html! { {header} }}
                    >
                        {list}
                        {error.as_ref().map(|e| format!(" — {e}")).unwrap_or_default()}
                    </Alert>
                }
            }
            Some(EmailSendStatus::Error(message)) => html! {
                <Alert kind="error" dismissible=true on_dismiss={dismiss_status} testid="email-send-result">
                    {message.clone()}
                </Alert>
            },
        };
        let cadence = cadence_options();
        let selected_cadence = cadence
            .iter()
            .find(|o| o.value.as_str() == asset.email_cadence)
            .map(|o| o.value.clone())
            .unwrap_or(AttrValue::Static("off"));
        let on_cc_input = {
            let input = cc_input.clone();
            Callback::from(move |v: String| input.set(v))
        };
        html! {
            <Container
                header={html! {
                    <Header
                        variant="h2"
                        counter={format!("({})", rows.len())}
                        description={html! { {"Additional addresses that receive the per-asset compliance PDF when you click ‘Email report now’. The asset owner's email is always included if set."} }}
                        actions={html! {
                            <Button
                                variant="primary"
                                loading={*email_sending}
                                onclick={email_report_now}
                                testid="email-report-now-button"
                            >
                                {"Email report now"}
                            </Button>
                        }}
                    >
                        {"Email recipients"}
                    </Header>
                }}
                testid="email-cc-section"
            >
                <SpaceBetween direction="vertical" size="m">
                    if let Some(e) = &*cc_error {
                        <Alert kind="error" dismissible=true on_dismiss={dismiss_error}>{e.clone()}</Alert>
                    }
                    {send_result}
                    <ColumnLayout columns={2}>
                        <FormField
                            label={html! { {"Scheduled cadence"} }}
                            description={html! { {"Auto-mail the per-asset compliance PDF to the recipients above on this cadence. ‘Off’ disables scheduled sends; the on-demand button above still works."} }}
                        >
                            <Select
                                selected={selected_cadence}
                                on_change={set_cadence}
                                options={cadence}
                                disabled={*cadence_busy}
                                testid="email-cadence-select"
                            />
                        </FormField>
                        <FormField label={html! { {"Last sent"} }}>
                            <UiBox testid="email-last-sent" color="text-body-secondary">
                                {match asset.email_last_sent_at.as_deref().filter(|s| !s.is_empty()) {
                                    Some(at) => to_locale_string(at),
                                    None => "Never".to_string(),
                                }}
                            </UiBox>
                        </FormField>
                    </ColumnLayout>
                    <Table<CcRow>
                        variant="embedded"
                        items={rows}
                        testid="email-cc-table"
                        {columns}
                        empty={html! {
                            <UiBox text_align="center" padding="m">
                                <UiBox variant="p" color="text-body-secondary">
                                    {"No additional recipients configured yet."}
                                </UiBox>
                            </UiBox>
                        }}
                    />
                    <ColumnLayout columns={2}>
                        <FormField label={html! { {"Email address"} }}>
                            <Input
                                value={(*cc_input).clone()}
                                on_change={on_cc_input}
                                placeholder="ops@example.gov"
                                testid="email-cc-input"
                            />
                        </FormField>
                        <FormField label={html! { {"\u{a0}"} }}>
                            <Button
                                variant="primary"
                                loading={*cc_busy}
                                disabled={cc_input.trim().is_empty()}
                                onclick={add_cc}
                                testid="email-cc-add-button"
                            >
                                {"Add"}
                            </Button>
                        </FormField>
                    </ColumnLayout>
                </SpaceBetween>
            </Container>
        }
    } else {
        Html::default()
    };

    // ── Runbook ────────────────────────────────────────────────────────
    // Edit is gated on write-or-better. `cc.visible` is a good proxy
    // because the email-cc list endpoint 403s for users without the write
    // ACL — reusing the signal avoids a separate ACL probe round-trip. The
    // PUT endpoint server-side gates on `admin`, so non-owner write-ACL
    // users will get a 403 if they try to save — handled by the existing
    // error path in the modal.
    let runbook_actions = if is_owner || *cc.visible {
        let (on_edit, raw) = (props.on_edit.clone(), loaded.raw.clone());
        html! {
            <Button onclick={move |_| on_edit.emit(raw.clone())} testid="runbook-edit-button">{"Edit"}</Button>
        }
    } else {
        Html::default()
    };
    let runbook = html! {
        <Container
            header={html! {
                <Header
                    variant="h2"
                    description={html! { {"Free-form markdown notes for this system — operational steps, escalation contacts, known issues."} }}
                    actions={runbook_actions}
                >
                    {"Runbook"}
                </Header>
            }}
            testid="runbook-section"
        >
            if !asset.runbook.trim().is_empty() {
                // The renderer in `utils/markdown.rs` HTML-escapes every
                // text token before assembling tags, so the only "raw"
                // content here is the tag shell we constructed. Bare URLs
                // are autolinked with rel="noopener noreferrer".
                <div class="runbook-rendered" data-testid="runbook-rendered">
                    {Html::from_html_unchecked(AttrValue::from(render_markdown(&asset.runbook)))}
                </div>
            } else {
                <UiBox color="text-body-secondary" testid="runbook-placeholder">
                    {"No runbook yet — click Edit to add one."}
                </UiBox>
            }
        </Container>
    };

    // ── Modals ─────────────────────────────────────────────────────────
    let close_apply = {
        let open = apply_open.clone();
        Callback::from(move |_: ()| open.set(false))
    };
    let on_select_stig = {
        let selected = selected_stig.clone();
        Callback::from(move |o: SelectOption| selected.set(Some(o)))
    };
    let stig_options: Vec<SelectOption> = available_stigs
        .iter()
        .map(|s| {
            SelectOption::new(s.id.clone(), s.title.clone()).description(format!("{} · v{}", s.category, s.version))
        })
        .collect();
    let apply_modal = html! {
        <Modal
            visible={*apply_open}
            on_dismiss={close_apply.clone()}
            header={html! { {"Apply STIG to this system"} }}
            footer={html! {
                <UiBox float="right">
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="link" onclick={close_apply.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                        <Button variant="primary" loading={*applying} disabled={selected_stig.is_none()} onclick={apply}>
                            {"Apply"}
                        </Button>
                    </SpaceBetween>
                </UiBox>
            }}
        >
            <SpaceBetween direction="vertical" size="m">
                <FormField label={html! { {"STIG"} }}>
                    <Select
                        selected={selected_stig.as_ref().map(|o| o.value.clone())}
                        selected_label={selected_stig.as_ref().map(|o| o.label.clone())}
                        on_change={on_select_stig}
                        options={stig_options}
                        placeholder="Choose a STIG"
                        filtering=true
                        empty="All STIGs have already been applied."
                    />
                </FormField>
                if let Some(e) = &*apply_error {
                    <Alert kind="error">{e.clone()}</Alert>
                }
            </SpaceBetween>
        </Modal>
    };

    let close_reapply = {
        let target = reapply_target.clone();
        Callback::from(move |_: ()| target.set(None))
    };
    let reapply_modal = html! {
        <Modal
            visible={reapply_target.is_some()}
            on_dismiss={close_reapply.clone()}
            header={html! { {"Re-apply STIG"} }}
            footer={html! {
                <UiBox float="right">
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="link" onclick={close_reapply.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                        <Button variant="primary" loading={*reapplying} onclick={reapply}>{"Re-apply"}</Button>
                    </SpaceBetween>
                </UiBox>
            }}
        >
            if let Some(t) = &*reapply_target {
                <SpaceBetween direction="vertical" size="m">
                    <UiBox>
                        <strong>{t.title.clone()}</strong>
                        <UiBox variant="p" color="text-body-secondary">
                            {format!(
                                "v{} ({}) → v{} ({})",
                                t.from_version, t.from_release, t.to_version, t.to_release
                            )}
                        </UiBox>
                    </UiBox>
                    <Alert kind="info">
                        {"Existing rule statuses are preserved where rule IDs still exist in the new revision. Overrides for rules that no longer exist will be dropped."}
                    </Alert>
                </SpaceBetween>
            }
        </Modal>
    };

    html! {
        <UiBox padding="m">
            <SpaceBetween direction="vertical" size="l">
                <Button icon_name="arrow-left" onclick={back}>{"Back to systems"}</Button>
                {summary}
                {trend_charts}
                {checklists_table}
                {sharing}
                {email_section}
                {runbook}
            </SpaceBetween>
            {apply_modal}
            {reapply_modal}
        </UiBox>
    }
}
