//! Modal dialog.

use super::{icon, use_id};
use gloo_events::EventListener;
use wasm_bindgen::JsCast;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct ModalProps {
    pub visible: bool,
    #[prop_or_default]
    pub on_dismiss: Callback<()>,
    #[prop_or_default]
    pub header: Html,
    #[prop_or_default]
    pub footer: Html,
    /// "small" | "medium" (default) | "large" | "max"
    #[prop_or(AttrValue::Static("medium"))]
    pub size: AttrValue,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

/// `role="dialog"` named by its header. Children stay mounted while hidden
/// (so their state survives), matching Cloudscape. Escape, the backdrop and
/// the header X button all fire `on_dismiss`.
#[function_component]
pub fn Modal(p: &ModalProps) -> Html {
    let header_id = use_id("ui-modal");
    {
        let on_dismiss = p.on_dismiss.clone();
        use_effect_with(p.visible, move |visible| {
            let listener = visible.then(|| {
                EventListener::new(&crate::util::document(), "keydown", move |e| {
                    if e.dyn_ref::<web_sys::KeyboardEvent>().map(|k| k.key())
                        == Some("Escape".into())
                    {
                        on_dismiss.emit(());
                    }
                })
            });
            move || drop(listener)
        });
    }
    let dismiss = {
        let cb = p.on_dismiss.clone();
        Callback::from(move |_: MouseEvent| cb.emit(()))
    };
    let backdrop = {
        let cb = p.on_dismiss.clone();
        Callback::from(move |e: MouseEvent| {
            // Only clicks that land on the backdrop itself, not bubbled ones.
            if e.target() == e.current_target() {
                cb.emit(());
            }
        })
    };
    html! {
        <div class={classes!("ui-modal-root", (!p.visible).then_some("ui-hidden"))} onmousedown={backdrop}>
            <div class={classes!("ui-modal", format!("ui-modal-{}", p.size))} role="dialog" aria-modal="true"
                 aria-labelledby={header_id.clone()} data-testid={p.testid.clone()}>
                <div class="ui-modal-header">
                    <div class="ui-modal-title" id={header_id}>
                        if matches!(p.header, Html::VText(_)) {
                            <h2 class="ui-modal-heading">{p.header.clone()}</h2>
                        } else {
                            {p.header.clone()}
                        }
                    </div>
                    <button type="button" class="ui-btn ui-btn-icon ui-modal-dismiss" onclick={dismiss}>
                        {icon("close")}
                    </button>
                </div>
                <div class="ui-modal-body">{p.children.clone()}</div>
                if p.footer != Html::default() {
                    <div class="ui-modal-footer">{p.footer.clone()}</div>
                }
            </div>
        </div>
    }
}
