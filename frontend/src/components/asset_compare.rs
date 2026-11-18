//! Side-by-side comparison of two systems: which rules they handle
//! differently in the STIGs they both have applied.

use serde::Deserialize;
use yew::prelude::*;

use crate::api::api_get;
use crate::ui::*;
use crate::util::{encode_uri_component, spawn_local};

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AssetOption {
    id: String,
    name: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DivergedRule {
    rule_id: String,
    left_status: String,
    right_status: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SharedStigDiff {
    stig_id: String,
    stig_title: String,
    diverged: Vec<DivergedRule>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AssetDiff {
    left: AssetOption,
    right: AssetOption,
    shared: Vec<SharedStigDiff>,
}

fn status_color(value: &str) -> &'static str {
    match value {
        "open" => "red",
        "not_a_finding" => "green",
        "not_applicable" => "blue",
        _ => "grey",
    }
}

fn status_label(value: &str) -> String {
    match value {
        "open" => "Open".into(),
        "not_a_finding" => "Not a finding".into(),
        "not_applicable" => "Not applicable".into(),
        "not_reviewed" => "Not reviewed".into(),
        other => other.to_string(),
    }
}

fn status_badge(value: &str) -> Html {
    html! { <Badge color={status_color(value)}>{status_label(value)}</Badge> }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[derive(Properties, PartialEq)]
pub struct AssetCompareProps {
    pub on_back: Callback<()>,
}

#[function_component]
pub fn AssetCompare(props: &AssetCompareProps) -> Html {
    let assets = use_state(Vec::<AssetOption>::new);
    let left_id = use_state(|| None::<String>);
    let right_id = use_state(|| None::<String>);
    let diff = use_state(|| None::<AssetDiff>);
    let loading = use_state(|| false);
    let error = use_state(|| None::<String>);

    {
        let assets = assets.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                assets.set(
                    api_get::<Vec<AssetOption>>("/api/assets")
                        .await
                        .unwrap_or_default(),
                );
            });
        });
    }

    // Re-fetch the diff whenever either side changes.
    {
        let diff = diff.clone();
        let loading = loading.clone();
        let error = error.clone();
        use_effect_with(
            ((*left_id).clone(), (*right_id).clone()),
            move |(left, right)| match (left, right) {
                (Some(l), Some(r)) if l != r => {
                    let path = format!(
                        "/api/assets/{}/diff/{}",
                        encode_uri_component(l),
                        encode_uri_component(r)
                    );
                    loading.set(true);
                    error.set(None);
                    spawn_local(async move {
                        match api_get::<AssetDiff>(&path).await {
                            Ok(d) => diff.set(Some(d)),
                            Err(e) => {
                                error.set(Some(e));
                                diff.set(None);
                            }
                        }
                        loading.set(false);
                    });
                }
                _ => diff.set(None),
            },
        );
    }

    let options: Vec<SelectOption> = assets
        .iter()
        .map(|a| SelectOption::new(a.id.clone(), a.name.clone()))
        .collect();

    let on_left = {
        let left_id = left_id.clone();
        Callback::from(move |o: SelectOption| left_id.set(Some(o.value.to_string())))
    };
    let on_right = {
        let right_id = right_id.clone();
        Callback::from(move |o: SelectOption| right_id.set(Some(o.value.to_string())))
    };

    let same_picked = matches!((&*left_id, &*right_id), (Some(l), Some(r)) if l == r);

    let diff_view = match (&*diff, *loading) {
        (Some(d), false) => {
            let total_diverged: usize = d.shared.iter().map(|s| s.diverged.len()).sum();
            let description = if d.shared.is_empty() {
                "These systems don't share any applied STIGs.".to_string()
            } else {
                format!(
                    "{} shared STIG{} · {} diverged rule{}",
                    d.shared.len(),
                    plural(d.shared.len()),
                    total_diverged,
                    plural(total_diverged)
                )
            };
            html! {
                <Container header={html! {
                    <Header variant="h2" description={html! { {description} }}>
                        {format!("{} vs {}", d.left.name, d.right.name)}
                    </Header>
                }}>
                    <SpaceBetween direction="vertical" size="m">
                        { for d.shared.iter().map(|s| html! {
                            <div key={s.stig_id.clone()}>
                                <UiBox variant="awsui-key-label">{s.stig_title.clone()}</UiBox>
                                if s.diverged.is_empty() {
                                    <UiBox padding_top="xs" color="text-status-success">
                                        {"All shared rules agree."}
                                    </UiBox>
                                } else {
                                    <UiBox padding_top="xs">
                                        <SpaceBetween direction="vertical" size="xxs">
                                            { for s.diverged.iter().map(|r| html! {
                                                <UiBox key={r.rule_id.clone()}>
                                                    <strong>{r.rule_id.clone()}</strong>
                                                    {" "}
                                                    {status_badge(&r.left_status)}
                                                    {" → "}
                                                    {status_badge(&r.right_status)}
                                                </UiBox>
                                            }) }
                                        </SpaceBetween>
                                    </UiBox>
                                }
                            </div>
                        }) }
                        if d.shared.is_empty() {
                            <UiBox color="text-body-secondary">
                                {"No shared STIGs to compare. Apply the same STIG to both systems to see a diff."}
                            </UiBox>
                        }
                    </SpaceBetween>
                </Container>
            }
        }
        _ => Html::default(),
    };

    html! {
        <UiBox padding="m">
            <SpaceBetween direction="vertical" size="l">
                <Button icon_name="arrow-left" onclick={props.on_back.reform(|_: MouseEvent| ())}>
                    {"Back to systems"}
                </Button>

                <Container header={html! {
                    <Header
                        variant="h1"
                        description={html! { {"Pick two systems to see which rules they handle differently in the STIGs they both have applied."} }}
                    >
                        {"Compare systems"}
                    </Header>
                }}>
                    <ColumnLayout columns={2}>
                        <div>
                            <UiBox variant="awsui-key-label">{"Left system"}</UiBox>
                            <Select
                                selected={(*left_id).clone().map(AttrValue::from)}
                                on_change={on_left}
                                options={options.clone()}
                                placeholder="Choose a system"
                                filtering=true
                            />
                        </div>
                        <div>
                            <UiBox variant="awsui-key-label">{"Right system"}</UiBox>
                            <Select
                                selected={(*right_id).clone().map(AttrValue::from)}
                                on_change={on_right}
                                options={options}
                                placeholder="Choose a system"
                                filtering=true
                            />
                        </div>
                    </ColumnLayout>
                </Container>

                if same_picked {
                    <Alert kind="info">{"Pick two different systems to compare."}</Alert>
                }

                if let Some(e) = &*error {
                    <Alert kind="error">{e.clone()}</Alert>
                }

                if *loading {
                    <UiBox padding="xxl" text_align="center">
                        <StatusIndicator kind="loading">{"Loading diff"}</StatusIndicator>
                    </UiBox>
                }

                {diff_view}
            </SpaceBetween>
        </UiBox>
    }
}
