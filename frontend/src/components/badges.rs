use crate::constants::{severity_badge_color, status_indicator_kind, status_label};
use crate::ui::*;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SeverityBadgeProps {
    pub severity: AttrValue,
}

#[function_component]
pub fn SeverityBadge(p: &SeverityBadgeProps) -> Html {
    html! { <Badge color={severity_badge_color(&p.severity)}>{p.severity.clone()}</Badge> }
}

#[derive(Properties, PartialEq)]
pub struct StatusBadgeProps {
    pub status: AttrValue,
}

#[function_component]
pub fn StatusBadge(p: &StatusBadgeProps) -> Html {
    html! {
        <StatusIndicator kind={status_indicator_kind(&p.status)}>
            {status_label(&p.status).to_string()}
        </StatusIndicator>
    }
}
