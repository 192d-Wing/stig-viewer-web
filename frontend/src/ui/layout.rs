//! Text, spacing and structural components.

use super::{icon, space_px, use_id};
use yew::prelude::*;
use yew::virtual_dom::VTag;

// ── Box ─────────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct UiBoxProps {
    /// "div" (default) | "span" | "p" | "h1".."h5" | "small" | "strong" | "code" | "pre"
    /// | "awsui-key-label" | "awsui-value-large"
    #[prop_or(AttrValue::Static("div"))]
    pub variant: AttrValue,
    /// e.g. "text-body-secondary", "text-status-inactive", "text-status-error",
    /// "text-status-success", "text-label", "inherit"
    #[prop_or_default]
    pub color: Option<AttrValue>,
    /// Spacing token applied on all sides ("n", "xxs", "xs", "s", "m", "l", "xl", "xxl").
    #[prop_or_default]
    pub padding: Option<AttrValue>,
    #[prop_or_default]
    pub padding_top: Option<AttrValue>,
    #[prop_or_default]
    pub padding_bottom: Option<AttrValue>,
    #[prop_or_default]
    pub padding_left: Option<AttrValue>,
    #[prop_or_default]
    pub padding_right: Option<AttrValue>,
    #[prop_or_default]
    pub padding_horizontal: Option<AttrValue>,
    #[prop_or_default]
    pub padding_vertical: Option<AttrValue>,
    #[prop_or_default]
    pub margin: Option<AttrValue>,
    #[prop_or_default]
    pub margin_top: Option<AttrValue>,
    #[prop_or_default]
    pub margin_bottom: Option<AttrValue>,
    #[prop_or_default]
    pub margin_left: Option<AttrValue>,
    #[prop_or_default]
    pub margin_right: Option<AttrValue>,
    #[prop_or_default]
    pub margin_horizontal: Option<AttrValue>,
    #[prop_or_default]
    pub margin_vertical: Option<AttrValue>,
    /// "left" | "center" | "right"
    #[prop_or_default]
    pub text_align: Option<AttrValue>,
    /// "left" | "right"
    #[prop_or_default]
    pub float: Option<AttrValue>,
    /// "body-s" | "body-m" | "heading-xs" | "heading-s" | "heading-m" | "heading-l" | "heading-xl" | "display-l"
    #[prop_or_default]
    pub font_size: Option<AttrValue>,
    /// "light" | "normal" | "bold" | "heavy"
    #[prop_or_default]
    pub font_weight: Option<AttrValue>,
    /// "block" | "inline" | "inline-block" | "none"
    #[prop_or_default]
    pub display: Option<AttrValue>,
    #[prop_or_default]
    pub title: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

/// Cloudscape `Box`: typographic / spacing wrapper.
#[function_component]
pub fn UiBox(p: &UiBoxProps) -> Html {
    let (tag, vclass) = match p.variant.as_str() {
        "span" => ("span", ""),
        "p" => ("p", "ui-box-p"),
        "h1" => ("h1", "ui-box-h1"),
        "h2" => ("h2", "ui-box-h2"),
        "h3" => ("h3", "ui-box-h3"),
        "h4" => ("h4", "ui-box-h4"),
        "h5" => ("h5", "ui-box-h5"),
        "small" => ("small", "ui-box-small"),
        "strong" => ("strong", ""),
        "code" => ("code", "ui-box-code"),
        "pre" => ("pre", "ui-box-pre"),
        "awsui-key-label" => ("div", "ui-box-key-label"),
        "awsui-value-large" => ("span", "ui-box-value-large"),
        _ => ("div", ""),
    };
    let mut style = String::new();
    let mut sp = |prop: &str, v: &Option<AttrValue>| {
        if let Some(v) = v {
            style.push_str(&format!("{prop}:{}px;", space_px(v)));
        }
    };
    sp("padding", &p.padding);
    sp("padding-block", &p.padding_vertical);
    sp("padding-inline", &p.padding_horizontal);
    sp("padding-top", &p.padding_top);
    sp("padding-bottom", &p.padding_bottom);
    sp("padding-left", &p.padding_left);
    sp("padding-right", &p.padding_right);
    sp("margin", &p.margin);
    sp("margin-block", &p.margin_vertical);
    sp("margin-inline", &p.margin_horizontal);
    sp("margin-top", &p.margin_top);
    sp("margin-bottom", &p.margin_bottom);
    sp("margin-left", &p.margin_left);
    sp("margin-right", &p.margin_right);
    if let Some(v) = &p.text_align {
        style.push_str(&format!("text-align:{v};"));
    }
    if let Some(v) = &p.float {
        style.push_str(&format!("float:{v};"));
    }
    if let Some(v) = &p.display {
        style.push_str(&format!("display:{v};"));
    }
    if let Some(v) = &p.font_weight {
        let w = match v.as_str() {
            "light" => "300",
            "bold" => "700",
            "heavy" => "800",
            _ => "400",
        };
        style.push_str(&format!("font-weight:{w};"));
    }
    let mut classes = classes!("ui-box", vclass);
    if let Some(c) = &p.color {
        classes.push(format!("ui-color-{c}"));
    }
    if let Some(f) = &p.font_size {
        classes.push(format!("ui-font-{f}"));
    }
    let mut el = VTag::new(tag);
    el.add_attribute("class", classes.to_string());
    if !style.is_empty() {
        el.add_attribute("style", style);
    }
    if let Some(t) = &p.title {
        el.add_attribute("title", t.clone());
    }
    if let Some(t) = &p.testid {
        el.add_attribute("data-testid", t.clone());
    }
    el.add_child(p.children.clone());
    el.into()
}

// ── SpaceBetween ────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct SpaceBetweenProps {
    /// "vertical" (default) | "horizontal"
    #[prop_or(AttrValue::Static("vertical"))]
    pub direction: AttrValue,
    /// Spacing token.
    #[prop_or(AttrValue::Static("m"))]
    pub size: AttrValue,
    /// "center" | "start" | "end"
    #[prop_or_default]
    pub align_items: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn SpaceBetween(p: &SpaceBetweenProps) -> Html {
    let horizontal = p.direction == "horizontal";
    let mut style = format!("gap:{}px;", space_px(&p.size));
    if let Some(a) = &p.align_items {
        let a = match a.as_str() {
            "start" => "flex-start",
            "end" => "flex-end",
            o => o,
        };
        style.push_str(&format!("align-items:{a};"));
    }
    html! {
        <div class={classes!("ui-space", if horizontal { "ui-space-h" } else { "ui-space-v" })}
             {style} data-testid={p.testid.clone()}>
            {p.children.clone()}
        </div>
    }
}

// ── Header ──────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct HeaderProps {
    /// "h1" | "h2" (default) | "h3" | "awsui-h1-sticky"
    #[prop_or(AttrValue::Static("h2"))]
    pub variant: AttrValue,
    #[prop_or_default]
    pub description: Html,
    /// Rendered inside the heading, e.g. "(12)".
    #[prop_or_default]
    pub counter: Option<AttrValue>,
    #[prop_or_default]
    pub actions: Html,
    #[prop_or_default]
    pub info: Html,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn Header(p: &HeaderProps) -> Html {
    let tag = match p.variant.as_str() {
        "h1" | "awsui-h1-sticky" => "h1",
        "h3" => "h3",
        _ => "h2",
    };
    let mut h = VTag::new(tag);
    h.add_attribute("class", format!("ui-header-title ui-header-{tag}"));
    h.add_child(html! { <span class="ui-header-text">{p.children.clone()}</span> });
    if let Some(c) = &p.counter {
        h.add_child(html! { <span class="ui-header-counter">{" "}{c.clone()}</span> });
    }
    let h: Html = h.into();
    html! {
        <div class="ui-header" data-testid={p.testid.clone()}>
            <div class="ui-header-main">
                <div class="ui-header-title-row">{h}{p.info.clone()}</div>
                if p.description != Html::default() {
                    <div class="ui-header-description">{p.description.clone()}</div>
                }
            </div>
            if p.actions != Html::default() {
                <div class="ui-header-actions">{p.actions.clone()}</div>
            }
        </div>
    }
}

// ── Container ───────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct ContainerProps {
    #[prop_or_default]
    pub header: Html,
    #[prop_or_default]
    pub footer: Html,
    /// "default" | "stacked"
    #[prop_or_default]
    pub variant: Option<AttrValue>,
    #[prop_or_default]
    pub disable_content_paddings: bool,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn Container(p: &ContainerProps) -> Html {
    html! {
        <div class="ui-container" data-testid={p.testid.clone()}>
            if p.header != Html::default() {
                <div class="ui-container-header">{p.header.clone()}</div>
            }
            <div class={classes!("ui-container-content", p.disable_content_paddings.then_some("ui-no-pad"))}>
                {p.children.clone()}
            </div>
            if p.footer != Html::default() {
                <div class="ui-container-footer">{p.footer.clone()}</div>
            }
        </div>
    }
}

// ── ColumnLayout ────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct ColumnLayoutProps {
    #[prop_or(1)]
    pub columns: u8,
    /// "default" | "text-grid"
    #[prop_or_default]
    pub variant: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn ColumnLayout(p: &ColumnLayoutProps) -> Html {
    let text_grid = p.variant.as_deref() == Some("text-grid");
    html! {
        <div class={classes!("ui-columns", format!("ui-columns-{}", p.columns.clamp(1, 4)), text_grid.then_some("ui-columns-text-grid"))}
             data-testid={p.testid.clone()}>
            {p.children.clone()}
        </div>
    }
}

// ── Badge ───────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct BadgeProps {
    /// "grey" (default) | "blue" | "green" | "red" | "severity-critical" | "severity-high"
    /// | "severity-medium" | "severity-low" | "severity-neutral"
    #[prop_or(AttrValue::Static("grey"))]
    pub color: AttrValue,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub title: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn Badge(p: &BadgeProps) -> Html {
    html! {
        <span class={classes!("ui-badge", format!("ui-badge-{}", p.color))}
              data-testid={p.testid.clone()} title={p.title.clone()}>
            {p.children.clone()}
        </span>
    }
}

// ── StatusIndicator ─────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct StatusIndicatorProps {
    /// "success" (default) | "error" | "warning" | "info" | "pending" | "in-progress"
    /// | "stopped" | "loading"
    #[prop_or(AttrValue::Static("success"))]
    pub kind: AttrValue,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn StatusIndicator(p: &StatusIndicatorProps) -> Html {
    let ic = match p.kind.as_str() {
        "success" => icon("status-positive"),
        "error" => icon("status-negative"),
        "warning" => icon("status-warning"),
        "info" => icon("status-info"),
        "pending" => icon("status-pending"),
        "in-progress" => icon("status-in-progress"),
        "stopped" => icon("status-stopped"),
        "loading" => html! { <Spinner /> },
        _ => html! {},
    };
    html! {
        <span class={classes!("ui-status", format!("ui-status-{}", p.kind))} data-testid={p.testid.clone()}>
            <span class="ui-status-icon">{ic}</span>
            {p.children.clone()}
        </span>
    }
}

// ── Spinner ─────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct SpinnerProps {
    /// "normal" (default) | "big" | "large"
    #[prop_or(AttrValue::Static("normal"))]
    pub size: AttrValue,
}

#[function_component]
pub fn Spinner(p: &SpinnerProps) -> Html {
    html! { <span class={classes!("ui-spinner", format!("ui-spinner-{}", p.size))} role="progressbar" aria-label="Loading" /> }
}

// ── Alert ───────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct AlertProps {
    /// "info" (default) | "success" | "warning" | "error"
    #[prop_or(AttrValue::Static("info"))]
    pub kind: AttrValue,
    #[prop_or_default]
    pub header: Html,
    #[prop_or_default]
    pub dismissible: bool,
    #[prop_or_default]
    pub on_dismiss: Callback<()>,
    /// Action slot rendered on the right (usually a Button).
    #[prop_or_default]
    pub action: Html,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn Alert(p: &AlertProps) -> Html {
    let ic = match p.kind.as_str() {
        "success" => "status-positive",
        "warning" => "status-warning",
        "error" => "status-negative",
        _ => "status-info",
    };
    let on_dismiss = p.on_dismiss.clone();
    html! {
        <div class={classes!("ui-alert", format!("ui-alert-{}", p.kind))} data-testid={p.testid.clone()}>
            <span class="ui-alert-icon">{icon(ic)}</span>
            <div class="ui-alert-body">
                if p.header != Html::default() {
                    <div class="ui-alert-header">{p.header.clone()}</div>
                }
                <div class="ui-alert-content">{p.children.clone()}</div>
            </div>
            if p.action != Html::default() {
                <div class="ui-alert-action">{p.action.clone()}</div>
            }
            if p.dismissible {
                <button type="button" class="ui-btn ui-btn-icon ui-alert-dismiss"
                        onclick={move |_| on_dismiss.emit(())}>
                    {icon("close")}
                </button>
            }
        </div>
    }
}

// ── Flashbar (single non-dismissible banner list) ───────────────────────────

#[derive(Properties, PartialEq)]
pub struct FlashProps {
    #[prop_or(AttrValue::Static("info"))]
    pub kind: AttrValue,
    #[prop_or_default]
    pub header: Html,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn Flash(p: &FlashProps) -> Html {
    html! {
        <div class={classes!("ui-flash", format!("ui-flash-{}", p.kind))} role="status">
            <div class="ui-flash-header">{p.header.clone()}</div>
            <div class="ui-flash-content">{p.children.clone()}</div>
        </div>
    }
}

// ── ExpandableSection ───────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct ExpandableSectionProps {
    #[prop_or_default]
    pub header_text: Html,
    #[prop_or_default]
    pub default_expanded: bool,
    /// Controlled mode: when `Some`, overrides internal state.
    #[prop_or_default]
    pub expanded: Option<bool>,
    #[prop_or_default]
    pub on_change: Callback<bool>,
    /// "default" | "footer" | "container" | "navigation"
    #[prop_or_default]
    pub variant: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

/// Collapsible section. The header is a button with `aria-expanded`; content
/// stays mounted (hidden) while collapsed, as in Cloudscape.
#[function_component]
pub fn ExpandableSection(p: &ExpandableSectionProps) -> Html {
    let internal = use_state(|| p.default_expanded);
    let expanded = p.expanded.unwrap_or(*internal);
    let id = use_id("ui-exp");
    let toggle = {
        let internal = internal.clone();
        let on_change = p.on_change.clone();
        Callback::from(move |_: MouseEvent| {
            internal.set(!expanded);
            on_change.emit(!expanded);
        })
    };
    let container = p.variant.as_deref() == Some("container");
    html! {
        <div class={classes!("ui-expandable", container.then_some("ui-expandable-container"), expanded.then_some("ui-expanded"))}
             data-testid={p.testid.clone()}>
            <button type="button" class="ui-expandable-header" aria-expanded={expanded.to_string()}
                    aria-controls={id.clone()} onclick={toggle}>
                <span class="ui-expandable-caret">{icon(if expanded { "caret-down" } else { "caret-right" })}</span>
                <span class="ui-expandable-title">{p.header_text.clone()}</span>
            </button>
            <div class="ui-expandable-content" {id} hidden={!expanded}>
                {p.children.clone()}
            </div>
        </div>
    }
}

// ── ProgressBar ─────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct ProgressBarProps {
    /// 0–100
    pub value: f64,
    #[prop_or_default]
    pub label: Html,
    #[prop_or_default]
    pub description: Html,
    #[prop_or_default]
    pub additional_info: Html,
    /// "in-progress" (default) | "success" | "error"
    #[prop_or_default]
    pub status: Option<AttrValue>,
    #[prop_or_default]
    pub result_text: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn ProgressBar(p: &ProgressBarProps) -> Html {
    let v = p.value.clamp(0.0, 100.0);
    let status = p.status.clone().unwrap_or(AttrValue::Static("in-progress"));
    html! {
        <div class="ui-progress" data-testid={p.testid.clone()}>
            if p.label != Html::default() { <div class="ui-progress-label">{p.label.clone()}</div> }
            if p.description != Html::default() { <div class="ui-progress-desc">{p.description.clone()}</div> }
            if status == "in-progress" {
                <div class="ui-progress-row">
                    <progress class="ui-progress-bar" max="100" value={v.to_string()} />
                    <span class="ui-progress-pct">{format!("{}%", v.round())}</span>
                </div>
            } else {
                <StatusIndicator kind={status.clone()}>{p.result_text.clone().unwrap_or_default()}</StatusIndicator>
            }
            if p.additional_info != Html::default() { <div class="ui-progress-info">{p.additional_info.clone()}</div> }
        </div>
    }
}

// ── Link ────────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct LinkProps {
    #[prop_or_default]
    pub href: Option<AttrValue>,
    /// Opens in a new tab with an external icon.
    #[prop_or_default]
    pub external: bool,
    /// Fired on click. When there is no `href` the link behaves as a button.
    #[prop_or_default]
    pub on_follow: Callback<MouseEvent>,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn Link(p: &LinkProps) -> Html {
    let on_follow = p.on_follow.clone();
    let has_href = p.href.is_some();
    let onclick = Callback::from(move |e: MouseEvent| {
        if !has_href {
            e.prevent_default();
        }
        on_follow.emit(e);
    });
    html! {
        <a class="ui-link" href={p.href.clone().unwrap_or(AttrValue::Static("#"))}
           role={(!has_href).then_some("button")}
           target={p.external.then_some("_blank")}
           rel={p.external.then_some("noopener noreferrer")}
           aria-label={p.aria_label.clone()}
           data-testid={p.testid.clone()} {onclick}>
            {p.children.clone()}
            if p.external { <span class="ui-link-ext">{icon("external")}</span> }
        </a>
    }
}

// ── Tabs ────────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
pub struct TabItem {
    pub id: AttrValue,
    pub label: AttrValue,
    pub content: Html,
    pub disabled: bool,
}

impl TabItem {
    pub fn new(id: impl Into<AttrValue>, label: impl Into<AttrValue>, content: Html) -> Self {
        Self { id: id.into(), label: label.into(), content, disabled: false }
    }
}

#[derive(Properties, PartialEq)]
pub struct TabsProps {
    pub tabs: Vec<TabItem>,
    /// Controlled active tab; when `None` the component tracks it itself.
    #[prop_or_default]
    pub active_tab_id: Option<AttrValue>,
    #[prop_or_default]
    pub on_change: Callback<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn Tabs(p: &TabsProps) -> Html {
    let internal = use_state(|| p.tabs.first().map(|t| t.id.clone()));
    let active = p.active_tab_id.clone().or_else(|| (*internal).clone());
    let base = use_id("ui-tabs");
    html! {
        <div class="ui-tabs" data-testid={p.testid.clone()}>
            <div class="ui-tabs-list" role="tablist">
                { for p.tabs.iter().map(|t| {
                    let selected = Some(&t.id) == active.as_ref();
                    let onclick = {
                        let id = t.id.clone();
                        let internal = internal.clone();
                        let on_change = p.on_change.clone();
                        Callback::from(move |_: MouseEvent| {
                            internal.set(Some(id.clone()));
                            on_change.emit(id.clone());
                        })
                    };
                    html! {
                        <button type="button" role="tab" key={t.id.to_string()}
                                class={classes!("ui-tab", selected.then_some("ui-tab-active"))}
                                aria-selected={selected.to_string()}
                                aria-controls={format!("{base}-{}-panel", t.id)}
                                id={format!("{base}-{}-tab", t.id)}
                                data-testid={t.id.clone()}
                                disabled={t.disabled} {onclick}>
                            {t.label.clone()}
                        </button>
                    }
                }) }
            </div>
            { for p.tabs.iter().filter(|t| Some(&t.id) == active.as_ref()).map(|t| html! {
                <div class="ui-tab-panel" role="tabpanel" key={t.id.to_string()}
                     id={format!("{base}-{}-panel", t.id)}
                     aria-labelledby={format!("{base}-{}-tab", t.id)}>
                    {t.content.clone()}
                </div>
            }) }
        </div>
    }
}

// ── Issue list (per-rule lines in a result alert) ───────────────────────────

/// How many per-rule lines a result alert shows before "…and N more".
const ISSUE_LIST_CAP: usize = 10;

/// Bulleted `rule id: text` list for a result alert. Rows whose text is
/// `None` are skipped; at most ten are listed, followed by
/// "…and N more{more_suffix}." when rows were left out. Renders nothing when
/// there are no rows to show.
pub fn issue_list<'a>(rows: impl IntoIterator<Item = (&'a str, Option<&'a str>)>, more_suffix: &str) -> Html {
    let (lines, more) = crate::util::issue_lines(rows, ISSUE_LIST_CAP);
    if lines.is_empty() {
        return Html::default();
    }
    html! {
        <ul style="margin:6px 0 0;padding-left:18px;">
            { for lines.iter().map(|(id, text)| html! {
                <li key={id.clone()}>
                    <code>{id.clone()}</code>{": "}{text.clone()}
                </li>
            }) }
            if more > 0 {
                <li>{format!("…and {more} more{more_suffix}.")}</li>
            }
        </ul>
    }
}
