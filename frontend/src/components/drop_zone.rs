use crate::ui::*;
use crate::util::file_list_to_vec;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct DropZoneProps {
    pub on_files_load: Callback<Vec<web_sys::File>>,
    pub on_load_sample: Callback<()>,
}

#[function_component]
pub fn DropZone(p: &DropZoneProps) -> Html {
    let files = use_state(Vec::<web_sys::File>::new);
    let drag_over = use_state(|| false);

    let handle_files = {
        let on_files_load = p.on_files_load.clone();
        Callback::from(move |list: Vec<web_sys::File>| {
            if !list.is_empty() {
                on_files_load.emit(list);
            }
        })
    };

    let ondragover = {
        let drag_over = drag_over.clone();
        Callback::from(move |e: DragEvent| {
            e.prevent_default();
            drag_over.set(true);
        })
    };
    let ondragleave = {
        let drag_over = drag_over.clone();
        Callback::from(move |_: DragEvent| drag_over.set(false))
    };
    let ondrop = {
        let (drag_over, handle_files) = (drag_over.clone(), handle_files.clone());
        Callback::from(move |e: DragEvent| {
            e.prevent_default();
            drag_over.set(false);
            handle_files.emit(file_list_to_vec(e.data_transfer().and_then(|dt| dt.files())));
        })
    };
    let on_change = {
        let (files, handle_files) = (files.clone(), handle_files.clone());
        Callback::from(move |value: Vec<web_sys::File>| {
            files.set(value.clone());
            handle_files.emit(value);
        })
    };
    let load_sample = p.on_load_sample.reform(|_: MouseEvent| ());

    let upload_area_style = format!(
        "border:2px dashed {};border-radius:12px;padding:48px 32px;background:{};\
         transition:border-color 0.2s, background 0.2s;",
        if *drag_over { "#539fe5" } else { "#354150" },
        if *drag_over { "#539fe510" } else { "transparent" },
    );

    html! {
        <div {ondragover} {ondragleave} {ondrop}
             style="text-align:center;max-width:560px;width:100%;margin:0 auto;">
            <SpaceBetween size="l">
                // Brand
                <div style="display:inline-flex;align-items:center;gap:12px;margin-bottom:8px;">
                    <svg width="40" height="40" viewBox="0 0 40 40" fill="none" aria-hidden="true">
                        <rect width="40" height="40" rx="8" fill="#539fe5" />
                        <path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1b2e" />
                        <path d="M28 22l4 4-4 4" stroke="#0f1b2e" stroke-width="2.5"
                              stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                    <Header variant="h1" description="Web Edition v3.0">
                        {"STIG Tools"}
                    </Header>
                </div>

                // File upload area
                <div style={upload_area_style}>
                    <UiBox text_align="center">
                        <SpaceBetween size="m">
                            <svg width="48" height="48" viewBox="0 0 48 48" fill="none"
                                 style="margin:0 auto;display:block;opacity:0.5;" aria-hidden="true">
                                <path d="M24 32V16m0 0l-8 8m8-8l8 8M8 36h32" stroke="#8d99a8" stroke-width="2"
                                      stroke-linecap="round" stroke-linejoin="round" />
                            </svg>
                            <FileUpload
                                value={(*files).clone()}
                                {on_change}
                                accept=".xml,.ckl"
                                multiple=true
                                constraint_text="Supports XCCDF (.xml) and Checklist (.ckl)"
                            />
                        </SpaceBetween>
                    </UiBox>
                </div>

                // Demo button
                <Button variant="link" onclick={load_sample}>
                    {"Load Demo STIG"}
                </Button>
            </SpaceBetween>
        </div>
    }
}
