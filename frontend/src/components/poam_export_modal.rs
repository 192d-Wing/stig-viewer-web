use crate::model::{AssetInfo, Stig};
use crate::ui::*;
use crate::util::download_text;
use crate::utils::export_poam::{export_poam_csv, export_poam_json};
use std::rc::Rc;
use yew::prelude::*;

/// `title.replace(/[^a-zA-Z0-9]/g, '_')` — the base name of exported files.
/// Like the JS regex this works on UTF-16 code units, so a character outside
/// the BMP becomes two underscores.
pub(crate) fn export_base_name(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            (0..c.len_utf16()).for_each(|_| out.push('_'));
        }
    }
    out
}

#[derive(Properties, PartialEq)]
pub struct PoamExportModalProps {
    pub show: bool,
    pub on_close: Callback<()>,
    pub stig: Rc<Stig>,
    pub asset_info: AssetInfo,
}

#[function_component]
pub fn PoamExportModal(p: &PoamExportModalProps) -> Html {
    let include_non_reviewed = use_state(|| false);

    let base_name = export_base_name(&p.stig.title);

    let handle_csv = {
        let (stig, asset, include, base_name) =
            (p.stig.clone(), p.asset_info.clone(), *include_non_reviewed, base_name.clone());
        Callback::from(move |_: MouseEvent| {
            let csv = export_poam_csv(&stig, &asset, include);
            download_text(&csv, "text/csv;charset=utf-8;", &format!("{base_name}_POAM.csv"));
        })
    };

    let handle_json = {
        let (stig, asset, include, base_name) =
            (p.stig.clone(), p.asset_info.clone(), *include_non_reviewed, base_name.clone());
        Callback::from(move |_: MouseEvent| {
            let json = export_poam_json(&stig, &asset, include);
            download_text(&json, "application/json", &format!("{base_name}_POAM.json"));
        })
    };

    let open_count = p.stig.rules.iter().filter(|r| r.status == "open").count();
    let pending_count = p.stig.rules.iter().filter(|r| r.status == "not_reviewed").count();

    let on_scope = {
        let include_non_reviewed = include_non_reviewed.clone();
        Callback::from(move |value: AttrValue| include_non_reviewed.set(value == "all"))
    };
    let cancel = p.on_close.reform(|_: MouseEvent| ());

    html! {
        <Modal
            visible={p.show}
            on_dismiss={p.on_close.clone()}
            header="Export POA&M"
            footer={html! {
                <SpaceBetween direction="horizontal" size="xs">
                    <div style="flex:1;" />
                    <Button variant="link" onclick={cancel}>{"Cancel"}</Button>
                    <Button onclick={handle_json}>{"Download JSON"}</Button>
                    <Button variant="primary" onclick={handle_csv}>{"Download CSV"}</Button>
                </SpaceBetween>
            }}
        >
            <SpaceBetween size="l">
                // Counts
                <SpaceBetween direction="horizontal" size="l">
                    <StatusIndicator kind="error">{format!("{open_count} Open findings")}</StatusIndicator>
                    <StatusIndicator kind="pending">{format!("{pending_count} Not Reviewed")}</StatusIndicator>
                </SpaceBetween>

                // Scope
                <UiBox>
                    <UiBox margin_bottom="xs" font_size="body-s" font_weight="bold" color="text-label">
                        {"Scope"}
                    </UiBox>
                    <RadioGroup
                        value={if *include_non_reviewed { "all" } else { "open" }}
                        on_change={on_scope}
                        items={vec![
                            RadioItem::new("open", format!("Open findings only ({open_count} items)")),
                            RadioItem::new("all", format!("Open + Not Reviewed ({} items)", open_count + pending_count)),
                        ]}
                    />
                </UiBox>
            </SpaceBetween>
        </Modal>
    }
}
