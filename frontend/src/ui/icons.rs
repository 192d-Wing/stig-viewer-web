use yew::prelude::*;

/// Inline 16×16 icon by Cloudscape icon name. Unknown names render nothing.
pub fn icon(name: &str) -> Html {
    let body = match name {
        "add-plus" => html! { <path d="M8 2v12M2 8h12" /> },
        "close" => html! { <path d="M3 3l10 10M13 3L3 13" /> },
        "arrow-left" => html! { <path d="M14 8H2M7 3L2 8l5 5" /> },
        "angle-left" => html! { <path d="M10 3L5 8l5 5" /> },
        "angle-right" => html! { <path d="M6 3l5 5-5 5" /> },
        "caret-down" => html! { <path d="M4 6l4 4 4-4" /> },
        "caret-right" => html! { <path d="M6 4l4 4-4 4" /> },
        "download" => html! { <path d="M8 2v9M4 7l4 4 4-4M2 14h12" /> },
        "upload" => html! { <path d="M8 11V2M4 6l4-4 4 4M2 14h12" /> },
        "refresh" => html! { <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9M13.5 2v3h-3" /> },
        "copy" => {
            html! { <><rect x="5" y="5" width="9" height="9" rx="1" /><path d="M11 5V2H2v9h3" /></> }
        }
        "search" => html! { <><circle cx="7" cy="7" r="4.5" /><path d="M10.5 10.5L14 14" /></> },
        "calendar" => {
            html! { <><rect x="2" y="3" width="12" height="11" rx="1" /><path d="M2 7h12M5 1v3M11 1v3" /></> }
        }
        "notification" => html! { <path d="M4 11V7a4 4 0 0 1 8 0v4l1.5 1.5h-11zM6.5 14h3" /> },
        "user-profile" => {
            html! { <><circle cx="8" cy="5.5" r="3" /><path d="M2 14c.6-3 3-4.5 6-4.5s5.400 1.500 6 4.500" /></> }
        }
        "external" => html! { <path d="M9 2h5v5M14 2L7 9M12 9v5H2V4h5" /> },
        "menu" => html! { <path d="M2 4h12M2 8h12M2 12h12" /> },
        "status-positive" => {
            html! { <><circle cx="8" cy="8" r="6.5" /><path d="M5 8l2 2 4-4" /></> }
        }
        "status-negative" => {
            html! { <><circle cx="8" cy="8" r="6.5" /><path d="M5.500 5.500l5 5M10.500 5.500l-5 5" /></> }
        }
        "status-warning" => {
            html! { <><path d="M8 1.500l6.500 12h-13z" /><path d="M8 6v4M8 11.700v.300" /></> }
        }
        "status-info" => {
            html! { <><circle cx="8" cy="8" r="6.5" /><path d="M8 7v4M8 4.700v.300" /></> }
        }
        "status-pending" => {
            html! { <><circle cx="8" cy="8" r="6.5" /><path d="M8 4.500V8l2.500 1.500" /></> }
        }
        "status-stopped" => html! { <><circle cx="8" cy="8" r="6.5" /><path d="M5 8h6" /></> },
        "status-in-progress" => {
            html! { <><circle cx="8" cy="8" r="6.5" /><path d="M4.700 8h.300M7.850 8h.300M11 8h.300" /></> }
        }
        _ => return html! {},
    };
    html! {
        <svg class="ui-icon" viewBox="0 0 16 16" width="16" height="16" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round"
             stroke-linejoin="round" aria-hidden="true" focusable="false">
            {body}
        </svg>
    }
}
