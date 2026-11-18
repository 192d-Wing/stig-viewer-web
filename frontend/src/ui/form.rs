//! Buttons and form controls.

use super::{icon, use_id, Spinner};
use crate::util::{event_checked, event_value, file_list_to_vec};
use gloo_events::EventListener;
use wasm_bindgen::JsCast;
use yew::prelude::*;

// ── Button ──────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct ButtonProps {
    /// "normal" (default) | "primary" | "link" | "icon" | "inline-link" | "inline-icon"
    #[prop_or(AttrValue::Static("normal"))]
    pub variant: AttrValue,
    #[prop_or_default]
    pub onclick: Callback<MouseEvent>,
    #[prop_or_default]
    pub disabled: bool,
    /// Shows a spinner and disables the button.
    #[prop_or_default]
    pub loading: bool,
    #[prop_or_default]
    pub icon_name: Option<AttrValue>,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    #[prop_or_default]
    pub aria_pressed: Option<bool>,
    /// Renders an `<a>` (role link) instead of a `<button>`.
    #[prop_or_default]
    pub href: Option<AttrValue>,
    #[prop_or_default]
    pub target: Option<AttrValue>,
    #[prop_or_default]
    pub download: Option<AttrValue>,
    #[prop_or_default]
    pub title: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component]
pub fn Button(p: &ButtonProps) -> Html {
    let class = classes!(
        "ui-btn",
        format!("ui-btn-{}", p.variant),
        p.loading.then_some("ui-btn-loading")
    );
    let content = html! {
        <>
            if p.loading {
                <Spinner />
            } else if let Some(name) = &p.icon_name {
                {icon(name)}
            }
            if p.children != Html::default() {
                <span class="ui-btn-text">{p.children.clone()}</span>
            }
        </>
    };
    let disabled = p.disabled || p.loading;
    if let Some(href) = &p.href {
        let rel = (p.target.as_deref() == Some("_blank")).then_some("noopener noreferrer");
        html! {
            <a {class} href={(!disabled).then(|| href.clone())}
               target={p.target.clone()} {rel} download={p.download.clone()}
               aria-label={p.aria_label.clone()} aria-disabled={disabled.then_some("true")}
               title={p.title.clone()} data-testid={p.testid.clone()} onclick={p.onclick.clone()}>
                {content}
            </a>
        }
    } else {
        html! {
            <button type="button" {class} {disabled}
                    aria-label={p.aria_label.clone()}
                    aria-pressed={p.aria_pressed.map(|b| b.to_string())}
                    title={p.title.clone()} data-testid={p.testid.clone()} onclick={p.onclick.clone()}>
                {content}
            </button>
        }
    }
}

// ── FormField ───────────────────────────────────────────────────────────────

/// Ids a control inside a `FormField` uses to wire itself to the label.
#[derive(Clone, PartialEq)]
pub struct FormFieldContext {
    pub control_id: AttrValue,
    pub label_id: AttrValue,
    pub description_id: Option<AttrValue>,
}

#[derive(Properties, PartialEq)]
pub struct FormFieldProps {
    #[prop_or_default]
    pub label: Html,
    #[prop_or_default]
    pub description: Html,
    #[prop_or_default]
    pub constraint_text: Html,
    #[prop_or_default]
    pub error_text: Html,
    /// Slot to the right of the control.
    #[prop_or_default]
    pub secondary_control: Html,
    #[prop_or_default]
    pub stretch: bool,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

/// Labelled wrapper. The first control inside (Input, Textarea, Select, …)
/// picks up the label via context, so `getByLabel` / role-name lookups work.
#[function_component]
pub fn FormField(p: &FormFieldProps) -> Html {
    let control_id = use_id("ui-field");
    let label_id = AttrValue::from(format!("{control_id}-label"));
    let has_desc = p.description != Html::default();
    let desc_id = AttrValue::from(format!("{control_id}-desc"));
    let ctx = FormFieldContext {
        control_id: control_id.clone(),
        label_id: label_id.clone(),
        description_id: has_desc.then(|| desc_id.clone()),
    };
    html! {
        <div class={classes!("ui-field", p.stretch.then_some("ui-field-stretch"))} data-testid={p.testid.clone()}>
            if p.label != Html::default() {
                <label class="ui-field-label" id={label_id} for={control_id}>{p.label.clone()}</label>
            }
            if has_desc {
                <div class="ui-field-description" id={desc_id}>{p.description.clone()}</div>
            }
            <div class="ui-field-controls">
                <div class="ui-field-control">
                    <ContextProvider<FormFieldContext> context={ctx}>
                        {p.children.clone()}
                    </ContextProvider<FormFieldContext>>
                </div>
                if p.secondary_control != Html::default() {
                    <div class="ui-field-secondary">{p.secondary_control.clone()}</div>
                }
            </div>
            if p.error_text != Html::default() {
                <div class="ui-field-error" role="alert">{icon("status-warning")}{p.error_text.clone()}</div>
            }
            if p.constraint_text != Html::default() {
                <div class="ui-field-constraint">{p.constraint_text.clone()}</div>
            }
        </div>
    }
}

// ── Input ───────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct InputProps {
    pub value: AttrValue,
    /// New value on every keystroke.
    #[prop_or_default]
    pub on_change: Callback<String>,
    #[prop_or_default]
    pub on_key_down: Callback<KeyboardEvent>,
    #[prop_or_default]
    pub on_blur: Callback<()>,
    #[prop_or_default]
    pub placeholder: Option<AttrValue>,
    #[prop_or_default]
    pub disabled: bool,
    #[prop_or_default]
    pub read_only: bool,
    #[prop_or_default]
    pub invalid: bool,
    /// "text" (default) | "search" | "password" | "number" | "email" | "url"
    #[prop_or(AttrValue::Static("text"))]
    pub kind: AttrValue,
    #[prop_or_default]
    pub auto_focus: bool,
    #[prop_or_default]
    pub autocomplete: Option<AttrValue>,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    /// Lands on the wrapper `<div>`; reach the control with `.locator("input")`.
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn Input(p: &InputProps) -> Html {
    let ctx = use_context::<FormFieldContext>();
    let node = use_node_ref();
    {
        let node = node.clone();
        let auto_focus = p.auto_focus;
        use_effect_with((), move |_| {
            if auto_focus {
                if let Some(el) = node.cast::<web_sys::HtmlElement>() {
                    let _ = el.focus();
                }
            }
        });
    }
    let oninput = p.on_change.reform(|e: InputEvent| event_value(&e));
    let onblur = p.on_blur.reform(|_: FocusEvent| ());
    let search = p.kind == "search";
    html! {
        <div class={classes!("ui-input-wrap", search.then_some("ui-input-search"))} data-testid={p.testid.clone()}>
            if search { <span class="ui-input-icon">{icon("search")}</span> }
            <input ref={node} class={classes!("ui-input", p.invalid.then_some("ui-invalid"))}
                   type={p.kind.clone()} value={p.value.clone()}
                   id={ctx.as_ref().map(|c| c.control_id.clone())}
                   aria-labelledby={if p.aria_label.is_none() { ctx.as_ref().map(|c| c.label_id.clone()) } else { None }}
                   aria-describedby={ctx.as_ref().and_then(|c| c.description_id.clone())}
                   aria-label={p.aria_label.clone()}
                   aria-invalid={p.invalid.then_some("true")}
                   placeholder={p.placeholder.clone()} disabled={p.disabled} readonly={p.read_only}
                   autocomplete={p.autocomplete.clone().unwrap_or(AttrValue::Static("off"))}
                   {oninput} {onblur} onkeydown={p.on_key_down.clone()} />
        </div>
    }
}

// ── Textarea ────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct TextareaProps {
    pub value: AttrValue,
    #[prop_or_default]
    pub on_change: Callback<String>,
    #[prop_or_default]
    pub on_key_down: Callback<KeyboardEvent>,
    #[prop_or_default]
    pub on_blur: Callback<()>,
    #[prop_or_default]
    pub placeholder: Option<AttrValue>,
    #[prop_or_default]
    pub disabled: bool,
    #[prop_or_default]
    pub read_only: bool,
    #[prop_or_default]
    pub invalid: bool,
    #[prop_or(3)]
    pub rows: u32,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    /// Lands on the wrapper `<span>`; reach the control with `.locator("textarea")`.
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn Textarea(p: &TextareaProps) -> Html {
    let ctx = use_context::<FormFieldContext>();
    let oninput = p.on_change.reform(|e: InputEvent| event_value(&e));
    let onblur = p.on_blur.reform(|_: FocusEvent| ());
    html! {
        <span class="ui-textarea-wrap" data-testid={p.testid.clone()}>
            <textarea class={classes!("ui-textarea", p.invalid.then_some("ui-invalid"))}
                      rows={p.rows.to_string()} value={p.value.clone()}
                      id={ctx.as_ref().map(|c| c.control_id.clone())}
                      aria-labelledby={if p.aria_label.is_none() { ctx.as_ref().map(|c| c.label_id.clone()) } else { None }}
                      aria-describedby={ctx.as_ref().and_then(|c| c.description_id.clone())}
                      aria-label={p.aria_label.clone()}
                      placeholder={p.placeholder.clone()} disabled={p.disabled} readonly={p.read_only}
                      {oninput} {onblur} onkeydown={p.on_key_down.clone()} />
        </span>
    }
}

// ── Toggle / Checkbox ───────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct ToggleProps {
    pub checked: bool,
    #[prop_or_default]
    pub on_change: Callback<bool>,
    #[prop_or_default]
    pub disabled: bool,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    /// Lands on the wrapper; the control is `input[type="checkbox"]` inside.
    #[prop_or_default]
    pub testid: Option<AttrValue>,
    #[prop_or_default]
    pub children: Html,
}

/// Switch-styled checkbox (role `checkbox`, named by its label text).
#[function_component]
pub fn Toggle(p: &ToggleProps) -> Html {
    let onchange = p.on_change.reform(|e: Event| event_checked(&e));
    html! {
        <span class={classes!("ui-toggle", p.disabled.then_some("ui-disabled"))} data-testid={p.testid.clone()}>
            <label class="ui-toggle-label">
                <input type="checkbox" class="ui-toggle-input" checked={p.checked} disabled={p.disabled}
                       aria-label={p.aria_label.clone()} {onchange} />
                <span class="ui-toggle-track" aria-hidden="true"><span class="ui-toggle-handle" /></span>
                <span class="ui-toggle-text">{p.children.clone()}</span>
            </label>
        </span>
    }
}

#[function_component]
pub fn Checkbox(p: &ToggleProps) -> Html {
    let onchange = p.on_change.reform(|e: Event| event_checked(&e));
    html! {
        <span class={classes!("ui-checkbox", p.disabled.then_some("ui-disabled"))} data-testid={p.testid.clone()}>
            <label class="ui-checkbox-label">
                <input type="checkbox" class="ui-checkbox-input" checked={p.checked} disabled={p.disabled}
                       aria-label={p.aria_label.clone()} {onchange} />
                <span class="ui-checkbox-text">{p.children.clone()}</span>
            </label>
        </span>
    }
}

// ── RadioGroup ──────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
pub struct RadioItem {
    pub value: AttrValue,
    pub label: AttrValue,
    pub description: Option<AttrValue>,
    pub disabled: bool,
}

impl RadioItem {
    pub fn new(value: impl Into<AttrValue>, label: impl Into<AttrValue>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            description: None,
            disabled: false,
        }
    }
}

#[derive(Properties, PartialEq)]
pub struct RadioGroupProps {
    pub items: Vec<RadioItem>,
    #[prop_or_default]
    pub value: Option<AttrValue>,
    #[prop_or_default]
    pub on_change: Callback<AttrValue>,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn RadioGroup(p: &RadioGroupProps) -> Html {
    let name = use_id("ui-radio");
    let ctx = use_context::<FormFieldContext>();
    html! {
        <div class="ui-radio-group" role="radiogroup" data-testid={p.testid.clone()}
             aria-label={p.aria_label.clone()}
             aria-labelledby={if p.aria_label.is_none() { ctx.as_ref().map(|c| c.label_id.clone()) } else { None }}>
            { for p.items.iter().map(|it| {
                let checked = p.value.as_ref() == Some(&it.value);
                let onchange = {
                    let v = it.value.clone();
                    let cb = p.on_change.clone();
                    Callback::from(move |_: Event| cb.emit(v.clone()))
                };
                let desc_id = format!("{name}-{}-desc", it.value);
                html! {
                    <div class="ui-radio" key={it.value.to_string()}>
                        <label class="ui-radio-label">
                            <input type="radio" name={name.clone()} value={it.value.clone()} {checked}
                                   disabled={it.disabled} {onchange}
                                   aria-describedby={it.description.as_ref().map(|_| desc_id.clone())} />
                            <span>{it.label.clone()}</span>
                        </label>
                        if let Some(d) = &it.description {
                            <div class="ui-radio-description" id={desc_id}>{d.clone()}</div>
                        }
                    </div>
                }
            }) }
        </div>
    }
}

// ── SegmentedControl ────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
pub struct SegmentOption {
    pub id: AttrValue,
    pub text: AttrValue,
    pub disabled: bool,
}

impl SegmentOption {
    pub fn new(id: impl Into<AttrValue>, text: impl Into<AttrValue>) -> Self {
        Self {
            id: id.into(),
            text: text.into(),
            disabled: false,
        }
    }
}

#[derive(Properties, PartialEq)]
pub struct SegmentedControlProps {
    pub options: Vec<SegmentOption>,
    #[prop_or_default]
    pub selected_id: Option<AttrValue>,
    #[prop_or_default]
    pub on_change: Callback<AttrValue>,
    #[prop_or_default]
    pub label: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn SegmentedControl(p: &SegmentedControlProps) -> Html {
    html! {
        <div class="ui-segmented" role="toolbar" aria-label={p.label.clone()} data-testid={p.testid.clone()}>
            { for p.options.iter().map(|o| {
                let selected = p.selected_id.as_ref() == Some(&o.id);
                let onclick = {
                    let id = o.id.clone();
                    let cb = p.on_change.clone();
                    Callback::from(move |_: MouseEvent| cb.emit(id.clone()))
                };
                html! {
                    <button type="button" key={o.id.to_string()}
                            class={classes!("ui-segment", selected.then_some("ui-segment-selected"))}
                            aria-pressed={selected.to_string()} disabled={o.disabled} {onclick}>
                        {o.text.clone()}
                    </button>
                }
            }) }
        </div>
    }
}

// ── Select / Multiselect ────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Default)]
pub struct SelectOption {
    pub value: AttrValue,
    pub label: AttrValue,
    pub description: Option<AttrValue>,
    pub disabled: bool,
}

impl SelectOption {
    pub fn new(value: impl Into<AttrValue>, label: impl Into<AttrValue>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            description: None,
            disabled: false,
        }
    }
    pub fn description(mut self, d: impl Into<AttrValue>) -> Self {
        self.description = Some(d.into());
        self
    }
    pub fn disabled(mut self, d: bool) -> Self {
        self.disabled = d;
        self
    }
}

/// Close-on-outside-click / Escape for a dropdown rooted at `root`.
#[hook]
fn use_dismiss(root: NodeRef, open: UseStateHandle<bool>) {
    use_effect_with(*open, move |is_open| {
        let mut listeners = Vec::new();
        if *is_open {
            let doc = crate::util::document();
            let o = open.clone();
            listeners.push(EventListener::new(&doc, "mousedown", move |e| {
                let inside = e
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::Node>().ok())
                    .zip(root.get())
                    .map(|(t, r)| r.contains(Some(&t)))
                    .unwrap_or(false);
                if !inside {
                    o.set(false);
                }
            }));
            let o = open.clone();
            listeners.push(EventListener::new(&doc, "keydown", move |e| {
                if e.dyn_ref::<web_sys::KeyboardEvent>().map(|k| k.key()) == Some("Escape".into()) {
                    o.set(false);
                }
            }));
        }
        move || drop(listeners)
    });
}

#[derive(Properties, PartialEq)]
pub struct SelectProps {
    pub options: Vec<SelectOption>,
    /// Value of the selected option.
    #[prop_or_default]
    pub selected: Option<AttrValue>,
    /// Label to show when `selected` is not among `options`.
    #[prop_or_default]
    pub selected_label: Option<AttrValue>,
    #[prop_or_default]
    pub on_change: Callback<SelectOption>,
    #[prop_or_default]
    pub placeholder: Option<AttrValue>,
    #[prop_or_default]
    pub disabled: bool,
    /// Adds a filter box above the options (Cloudscape `filteringType="auto"`).
    #[prop_or_default]
    pub filtering: bool,
    /// Shown when there are no options.
    #[prop_or_default]
    pub empty: Option<AttrValue>,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    /// Lands on the wrapper; clicking it opens the dropdown.
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

/// Dropdown select. The trigger is a `<button>`; when open, options render as
/// `role="option"` inside a `role="listbox"` (and only while open).
#[function_component]
pub fn Select(p: &SelectProps) -> Html {
    let open = use_state(|| false);
    let filter = use_state(String::new);
    let root = use_node_ref();
    let ctx = use_context::<FormFieldContext>();
    let own_id = use_id("ui-select");
    use_dismiss(root.clone(), open.clone());

    let current = p
        .selected
        .as_ref()
        .and_then(|v| p.options.iter().find(|o| &o.value == v))
        .map(|o| o.label.clone())
        .or_else(|| p.selected.as_ref().and(p.selected_label.clone()));

    let toggle = {
        let open = open.clone();
        let filter = filter.clone();
        let disabled = p.disabled;
        Callback::from(move |_: MouseEvent| {
            if !disabled {
                filter.set(String::new());
                open.set(!*open);
            }
        })
    };
    let needle = filter.to_lowercase();
    let visible: Vec<&SelectOption> = p
        .options
        .iter()
        .filter(|o| needle.is_empty() || o.label.to_lowercase().contains(&needle))
        .collect();
    let value_id = format!("{own_id}-value");
    let labelledby = match (&p.aria_label, &ctx) {
        (None, Some(c)) => Some(format!("{} {value_id}", c.label_id)),
        _ => None,
    };
    // As in Cloudscape, the trigger's name is the label plus whatever the
    // trigger shows: the selected option, or else the placeholder.
    let aria_label =
        p.aria_label
            .as_ref()
            .map(|l| match current.as_ref().or(p.placeholder.as_ref()) {
                Some(c) => format!("{l} {c}"),
                None => l.to_string(),
            });
    html! {
        <div ref={root} class={classes!("ui-select", p.disabled.then_some("ui-disabled"))} data-testid={p.testid.clone()}>
            <button type="button" class="ui-select-trigger" aria-haspopup="listbox"
                    id={ctx.as_ref().map(|c| c.control_id.clone())}
                    aria-expanded={open.to_string()} aria-labelledby={labelledby} aria-label={aria_label}
                    disabled={p.disabled} onclick={toggle}>
                <span class={classes!("ui-select-value", current.is_none().then_some("ui-placeholder"))} id={value_id}>
                    {current.clone().or_else(|| p.placeholder.clone()).unwrap_or_default()}
                </span>
                <span class="ui-select-caret">{icon("caret-down")}</span>
            </button>
            if *open {
                <div class="ui-dropdown">
                    if p.filtering {
                        <input class="ui-input ui-dropdown-filter" type="text" value={(*filter).clone()}
                               placeholder="Filter options" aria-label="Filter options" autocomplete="off"
                               oninput={{ let filter = filter.clone(); move |e: InputEvent| filter.set(event_value(&e)) }} />
                    }
                    <ul class="ui-options" role="listbox" aria-label={p.aria_label.clone()}>
                        { for visible.iter().map(|o| {
                            let selected = p.selected.as_ref() == Some(&o.value);
                            let onclick = {
                                let o = (*o).clone();
                                let cb = p.on_change.clone();
                                let open = open.clone();
                                Callback::from(move |_: MouseEvent| {
                                    if !o.disabled {
                                        open.set(false);
                                        cb.emit(o.clone());
                                    }
                                })
                            };
                            html! {
                                <li role="option" key={o.value.to_string()} data-value={o.value.clone()}
                                    class={classes!("ui-option", selected.then_some("ui-option-selected"), o.disabled.then_some("ui-disabled"))}
                                    aria-selected={selected.to_string()} aria-disabled={o.disabled.then_some("true")} {onclick}>
                                    <span class="ui-option-label">{o.label.clone()}</span>
                                    if let Some(d) = &o.description {
                                        <span class="ui-option-description">{d.clone()}</span>
                                    }
                                </li>
                            }
                        }) }
                    </ul>
                    if visible.is_empty() {
                        <div class="ui-dropdown-empty">{p.empty.clone().unwrap_or(AttrValue::Static("No options"))}</div>
                    }
                </div>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct MultiselectProps {
    pub options: Vec<SelectOption>,
    /// Values of the selected options.
    #[prop_or_default]
    pub selected: Vec<AttrValue>,
    /// Full new selection after each toggle / token dismissal.
    #[prop_or_default]
    pub on_change: Callback<Vec<SelectOption>>,
    #[prop_or_default]
    pub placeholder: Option<AttrValue>,
    #[prop_or_default]
    pub disabled: bool,
    #[prop_or_default]
    pub filtering: bool,
    #[prop_or_default]
    pub empty: Option<AttrValue>,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

/// Multi-select: dropdown stays open while toggling; selections show as
/// dismissible tokens underneath.
#[function_component]
pub fn Multiselect(p: &MultiselectProps) -> Html {
    let open = use_state(|| false);
    let filter = use_state(String::new);
    let root = use_node_ref();
    let ctx = use_context::<FormFieldContext>();
    use_dismiss(root.clone(), open.clone());

    let selected: Vec<SelectOption> = p
        .options
        .iter()
        .filter(|o| p.selected.contains(&o.value))
        .cloned()
        .collect();
    let toggle_open = {
        let open = open.clone();
        let disabled = p.disabled;
        Callback::from(move |_: MouseEvent| {
            if !disabled {
                open.set(!*open);
            }
        })
    };
    let toggle_value = {
        let selected = selected.clone();
        let cb = p.on_change.clone();
        Callback::from(move |o: SelectOption| {
            let mut next = selected.clone();
            if let Some(i) = next.iter().position(|s| s.value == o.value) {
                next.remove(i);
            } else {
                next.push(o);
            }
            cb.emit(next);
        })
    };
    let needle = filter.to_lowercase();
    let visible: Vec<&SelectOption> = p
        .options
        .iter()
        .filter(|o| needle.is_empty() || o.label.to_lowercase().contains(&needle))
        .collect();
    let labelledby = match (&p.aria_label, &ctx) {
        (None, Some(c)) => Some(c.label_id.clone()),
        _ => None,
    };
    html! {
        <div ref={root} class={classes!("ui-select", "ui-multiselect", p.disabled.then_some("ui-disabled"))} data-testid={p.testid.clone()}>
            <button type="button" class="ui-select-trigger" aria-haspopup="listbox"
                    id={ctx.as_ref().map(|c| c.control_id.clone())}
                    aria-expanded={open.to_string()} aria-labelledby={labelledby} aria-label={p.aria_label.clone()}
                    disabled={p.disabled} onclick={toggle_open}>
                <span class="ui-select-value ui-placeholder">{p.placeholder.clone().unwrap_or_default()}</span>
                <span class="ui-select-caret">{icon("caret-down")}</span>
            </button>
            if *open {
                <div class="ui-dropdown">
                    if p.filtering {
                        <input class="ui-input ui-dropdown-filter" type="text" value={(*filter).clone()}
                               placeholder="Filter options" aria-label="Filter options" autocomplete="off"
                               oninput={{ let filter = filter.clone(); move |e: InputEvent| filter.set(event_value(&e)) }} />
                    }
                    <ul class="ui-options" role="listbox" aria-multiselectable="true" aria-label={p.aria_label.clone()}>
                        { for visible.iter().map(|o| {
                            let is_sel = p.selected.contains(&o.value);
                            let onclick = {
                                let o = (*o).clone();
                                let cb = toggle_value.clone();
                                Callback::from(move |_: MouseEvent| if !o.disabled { cb.emit(o.clone()) })
                            };
                            html! {
                                <li role="option" key={o.value.to_string()} data-value={o.value.clone()}
                                    class={classes!("ui-option", is_sel.then_some("ui-option-selected"), o.disabled.then_some("ui-disabled"))}
                                    aria-selected={is_sel.to_string()} {onclick}>
                                    <input type="checkbox" class="ui-option-check" checked={is_sel} tabindex="-1" aria-hidden="true" readonly=true />
                                    <span class="ui-option-label">{o.label.clone()}</span>
                                    if let Some(d) = &o.description {
                                        <span class="ui-option-description">{d.clone()}</span>
                                    }
                                </li>
                            }
                        }) }
                    </ul>
                    if visible.is_empty() {
                        <div class="ui-dropdown-empty">{p.empty.clone().unwrap_or(AttrValue::Static("No options"))}</div>
                    }
                </div>
            }
            if !selected.is_empty() {
                <TokenGroup
                    items={selected.iter().map(|s| s.label.clone()).collect::<Vec<_>>()}
                    on_dismiss={{
                        let selected = selected.clone();
                        let cb = toggle_value.clone();
                        Callback::from(move |i: usize| if let Some(o) = selected.get(i) { cb.emit(o.clone()) })
                    }} />
            }
        </div>
    }
}

// ── TokenGroup ──────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct TokenGroupProps {
    pub items: Vec<AttrValue>,
    /// Index of the dismissed token.
    #[prop_or_default]
    pub on_dismiss: Callback<usize>,
    #[prop_or_default]
    pub read_only: bool,
    /// When set, each dismiss button is named "<dismiss_label> <token label>".
    /// Unnamed by default (as in Cloudscape without `dismissLabel`).
    #[prop_or_default]
    pub dismiss_label: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

/// Each token is a `role="group"` named by its label, with a dismiss button.
#[function_component]
pub fn TokenGroup(p: &TokenGroupProps) -> Html {
    html! {
        <div class="ui-tokens" data-testid={p.testid.clone()}>
            { for p.items.iter().enumerate().map(|(i, label)| {
                let cb = p.on_dismiss.clone();
                html! {
                    <span class="ui-token" role="group" aria-label={label.clone()} key={format!("{i}-{label}")}>
                        <span class="ui-token-label">{label.clone()}</span>
                        if !p.read_only {
                            <button type="button" class="ui-token-dismiss"
                                    aria-label={p.dismiss_label.as_ref().map(|d| format!("{d} {label}"))}
                                    onclick={move |_| cb.emit(i)}>
                                {icon("close")}
                            </button>
                        }
                    </span>
                }
            }) }
        </div>
    }
}

// ── TextFilter ──────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct TextFilterProps {
    pub filtering_text: AttrValue,
    #[prop_or_default]
    pub on_change: Callback<String>,
    #[prop_or_default]
    pub filtering_placeholder: Option<AttrValue>,
    #[prop_or_default]
    pub count_text: Option<AttrValue>,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn TextFilter(p: &TextFilterProps) -> Html {
    html! {
        <div class="ui-text-filter" data-testid={p.testid.clone()}>
            <Input kind="search" value={p.filtering_text.clone()} on_change={p.on_change.clone()}
                   placeholder={p.filtering_placeholder.clone()}
                   aria_label={p.aria_label.clone().or_else(|| p.filtering_placeholder.clone())} />
            if let Some(c) = &p.count_text {
                if !p.filtering_text.is_empty() {
                    <span class="ui-text-filter-count">{c.clone()}</span>
                }
            }
        </div>
    }
}

// ── Pagination ──────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct PaginationProps {
    /// 1-based.
    pub current_page_index: usize,
    pub pages_count: usize,
    #[prop_or_default]
    pub on_change: Callback<usize>,
    #[prop_or_default]
    pub disabled: bool,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn Pagination(p: &PaginationProps) -> Html {
    let cur = p.current_page_index.max(1);
    let total = p.pages_count.max(1);
    let go = |n: usize| {
        let cb = p.on_change.clone();
        Callback::from(move |_: MouseEvent| cb.emit(n))
    };
    // First, last, and a window around the current page.
    let mut pages: Vec<usize> = (1..=total)
        .filter(|n| *n == 1 || *n == total || n.abs_diff(cur) <= 2)
        .collect();
    pages.dedup();
    let mut items = Vec::new();
    let mut prev = 0usize;
    for n in pages {
        if n > prev + 1 {
            items.push(html! { <li class="ui-page-gap" key={format!("gap-{n}")}>{"…"}</li> });
        }
        items.push(html! {
            <li key={n}>
                <button type="button" class={classes!("ui-page", (n == cur).then_some("ui-page-current"))}
                        aria-label={format!("Page {n} of all pages")}
                        aria-current={(n == cur).then_some("true")}
                        disabled={p.disabled} onclick={go(n)}>{n}</button>
            </li>
        });
        prev = n;
    }
    html! {
        <ul class="ui-pagination" data-testid={p.testid.clone()}>
            <li><button type="button" class="ui-page ui-page-arrow" aria-label="Previous page"
                        disabled={p.disabled || cur <= 1} onclick={go(cur.saturating_sub(1).max(1))}>{icon("angle-left")}</button></li>
            { for items }
            <li><button type="button" class="ui-page ui-page-arrow" aria-label="Next page"
                        disabled={p.disabled || cur >= total} onclick={go((cur + 1).min(total))}>{icon("angle-right")}</button></li>
        </ul>
    }
}

// ── DatePicker ──────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct DatePickerProps {
    /// ISO `YYYY-MM-DD`, or empty.
    pub value: AttrValue,
    /// Emits ISO `YYYY-MM-DD` once a full date is entered, or "" when cleared.
    #[prop_or_default]
    pub on_change: Callback<String>,
    #[prop_or(AttrValue::Static("YYYY/MM/DD"))]
    pub placeholder: AttrValue,
    #[prop_or_default]
    pub disabled: bool,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    /// Lands on the wrapper; the text control is the `input` inside.
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

fn mask_date(raw: &str) -> String {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).take(8).collect();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i == 4 || i == 6 {
            out.push('/');
        }
        out.push(c);
    }
    out
}

/// Masked `YYYY/MM/DD` text entry plus a native calendar popup button.
#[function_component]
pub fn DatePicker(p: &DatePickerProps) -> Html {
    let ctx = use_context::<FormFieldContext>();
    let text = use_state(|| p.value.replace('-', "/"));
    {
        // Follow external value changes (including resets to "").
        let text = text.clone();
        use_effect_with(p.value.clone(), move |v| {
            let shown = v.replace('-', "/");
            // Only override what the user is typing when the parent holds a
            // complete date, or cleared a previously complete one.
            if (v.len() == 10 && *text != shown) || (v.is_empty() && text.len() == 10) {
                text.set(shown);
            }
        });
    }
    let oninput = {
        let text = text.clone();
        let cb = p.on_change.clone();
        Callback::from(move |e: InputEvent| {
            let masked = mask_date(&event_value(&e));
            if masked.len() == 10 {
                cb.emit(masked.replace('/', "-"));
            } else if masked.is_empty() {
                cb.emit(String::new());
            }
            text.set(masked);
        })
    };
    let native = use_node_ref();
    let open_native = {
        let native = native.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(el) = native.cast::<web_sys::HtmlInputElement>() {
                let f = js_sys::Reflect::get(&el, &"showPicker".into()).ok();
                if let Some(f) = f.and_then(|f| f.dyn_into::<js_sys::Function>().ok()) {
                    let _ = f.call0(&el);
                }
            }
        })
    };
    let on_native = {
        let text = text.clone();
        let cb = p.on_change.clone();
        Callback::from(move |e: Event| {
            let v = event_value(&e);
            text.set(v.replace('-', "/"));
            cb.emit(v);
        })
    };
    html! {
        <div class="ui-datepicker" data-testid={p.testid.clone()}>
            <input class="ui-input" type="text" inputmode="numeric" value={(*text).clone()}
                   id={ctx.as_ref().map(|c| c.control_id.clone())}
                   aria-labelledby={if p.aria_label.is_none() { ctx.as_ref().map(|c| c.label_id.clone()) } else { None }}
                   aria-label={p.aria_label.clone()}
                   placeholder={p.placeholder.clone()} disabled={p.disabled} autocomplete="off" {oninput} />
            <button type="button" class="ui-btn ui-btn-icon ui-datepicker-button"
                    disabled={p.disabled} onclick={open_native}>
                {icon("calendar")}
            </button>
            <input ref={native} class="ui-datepicker-native" type="date" tabindex="-1" aria-hidden="true"
                   value={p.value.clone()} onchange={on_native} />
        </div>
    }
}

// ── FileUpload ──────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct FileUploadProps {
    pub value: Vec<web_sys::File>,
    #[prop_or_default]
    pub on_change: Callback<Vec<web_sys::File>>,
    #[prop_or_default]
    pub multiple: bool,
    #[prop_or_default]
    pub accept: Option<AttrValue>,
    /// Trigger button text. Defaults to "Choose file" / "Choose files".
    #[prop_or_default]
    pub upload_button_text: Option<AttrValue>,
    #[prop_or_default]
    pub constraint_text: Option<AttrValue>,
    #[prop_or_default]
    pub show_file_size: bool,
    #[prop_or_default]
    pub disabled: bool,
    /// Lands on the wrapper; the control is `input[type="file"]` inside.
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn FileUpload(p: &FileUploadProps) -> Html {
    let input = use_node_ref();
    let pick = {
        let input = input.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(el) = input.cast::<web_sys::HtmlElement>() {
                el.click();
            }
        })
    };
    let onchange = {
        let cb = p.on_change.clone();
        let existing = p.value.clone();
        let multiple = p.multiple;
        Callback::from(move |e: Event| {
            let Some(el) = e
                .target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
            else {
                return;
            };
            let picked = file_list_to_vec(el.files());
            el.set_value("");
            if picked.is_empty() {
                return;
            }
            if multiple {
                let mut all = existing.clone();
                all.extend(picked);
                cb.emit(all);
            } else {
                cb.emit(picked.into_iter().take(1).collect());
            }
        })
    };
    let text = p
        .upload_button_text
        .clone()
        .unwrap_or(AttrValue::Static(if p.multiple {
            "Choose files"
        } else {
            "Choose file"
        }));
    html! {
        <div class="ui-file-upload" data-testid={p.testid.clone()}>
            <input ref={input} type="file" class="ui-file-input" multiple={p.multiple}
                   accept={p.accept.clone()} disabled={p.disabled} {onchange} />
            <Button icon_name="upload" onclick={pick} disabled={p.disabled}>{text}</Button>
            if let Some(c) = &p.constraint_text {
                <div class="ui-field-constraint">{c.clone()}</div>
            }
            if !p.value.is_empty() {
                <ul class="ui-file-list">
                    { for p.value.iter().enumerate().map(|(i, f)| {
                        let cb = p.on_change.clone();
                        let files = p.value.clone();
                        let remove = Callback::from(move |_: MouseEvent| {
                            let mut next = files.clone();
                            next.remove(i);
                            cb.emit(next);
                        });
                        html! {
                            <li class="ui-file-token" key={format!("{i}-{}", f.name())}>
                                <span class="ui-file-name">{f.name()}</span>
                                if p.show_file_size {
                                    <span class="ui-file-size">{format!("{:.2} KB", f.size() / 1024.0)}</span>
                                }
                                <button type="button" class="ui-token-dismiss" onclick={remove}>
                                    {icon("close")}
                                </button>
                            </li>
                        }
                    }) }
                </ul>
            }
        </div>
    }
}
