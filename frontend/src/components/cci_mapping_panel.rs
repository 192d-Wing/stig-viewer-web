use crate::ui::*;
use crate::utils::cci_map::cci_info;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct CciMappingPanelProps {
    pub cci_ids: Vec<String>,
}

/// One badge per CCI, showing the NIST SP 800-53 control it maps to when known.
#[function_component]
pub fn CciMappingPanel(p: &CciMappingPanelProps) -> Html {
    if p.cci_ids.is_empty() {
        return html! {};
    }
    html! {
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;">
            { for p.cci_ids.iter().map(|id| {
                let (title, aria_label, color, text) = match cci_info(id) {
                    Some(m) => (
                        format!("{id}: {}", m.title),
                        format!("{id} maps to {}: {}", m.control, m.title),
                        "blue",
                        format!("{} \u{00b7} {id}", m.control),
                    ),
                    None => (id.clone(), id.clone(), "grey", id.clone()),
                };
                html! {
                    <span key={id.clone()} {title} aria-label={aria_label}>
                        <Badge {color}>{text}</Badge>
                    </span>
                }
            }) }
        </div>
    }
}
