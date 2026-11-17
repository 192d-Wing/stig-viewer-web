//! STIG Tools web interface (Yew / WebAssembly).

mod api;
mod app;
mod auth;
mod components;
mod constants;
mod data;
mod hooks;
mod model;
mod ui;
mod util;
mod utils;

use yew::prelude::*;

#[function_component]
fn Root() -> Html {
    html! {
        <auth::AuthGate>
            <app::App />
        </auth::AuthGate>
    }
}

fn main() {
    console_error_panic_hook::set_once();
    let root = util::document()
        .get_element_by_id("root")
        .expect("Root element #root not found");
    yew::Renderer::<Root>::with_root(root).render();
}
