//! Authentication gate: resolves the current user before rendering the app.

use crate::api::{api_fetch, BACKEND};
use crate::ui::*;
use serde::Deserialize;
use yew::prelude::*;

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct User {
    pub id: String,
    pub display_name: String,
    pub role: String,
}

/// Context value: the signed-in user (always `Some` below `AuthGate`).
pub type AuthContext = Option<User>;

/// Current user, or `None` outside the gate.
#[hook]
pub fn use_current_user() -> Option<User> {
    use_context::<AuthContext>().flatten()
}

#[derive(Clone, PartialEq)]
enum AuthState {
    Loading,
    Authed(User),
    Unauthed,
    Error(String),
}

#[derive(Properties, PartialEq)]
pub struct AuthGateProps {
    #[prop_or_default]
    pub children: Html,
}

/// On mount, calls `/api/users/me` with credentials.
/// - 200: stores user in context, renders children.
/// - 401: shows sign-in buttons that redirect to the IdP.
/// - other: shows a connection error.
#[function_component]
pub fn AuthGate(props: &AuthGateProps) -> Html {
    let state = use_state(|| AuthState::Loading);
    {
        let state = state.clone();
        use_effect_with((), move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let next = match api_fetch("GET", "/api/users/me").await {
                    Ok(r) if r.ok() => match r.json::<User>().await {
                        Ok(u) => AuthState::Authed(u),
                        Err(e) => AuthState::Error(e.to_string()),
                    },
                    Ok(r) if r.status() == 401 => AuthState::Unauthed,
                    Ok(r) => AuthState::Error(format!("Server returned {}", r.status())),
                    Err(e) => AuthState::Error(e),
                };
                state.set(next);
            });
        });
    }

    let goto = |path: &'static str| {
        Callback::from(move |_: MouseEvent| {
            if let Some(w) = web_sys::window() {
                let _ = w.location().set_href(&format!("{BACKEND}{path}"));
            }
        })
    };

    match &*state {
        AuthState::Loading => html! {
            <UiBox text_align="center" padding="xxl"><Spinner size="large" /></UiBox>
        },
        AuthState::Error(err) => html! {
            <UiBox padding="xxl">
                <Alert kind="error" header="Cannot connect to backend">
                    {format!("{err}. Make sure the server is running at {BACKEND}.")}
                </Alert>
            </UiBox>
        },
        AuthState::Unauthed => html! {
            <UiBox text_align="center" padding="xxl">
                <SpaceBetween direction="vertical" size="l">
                    <UiBox variant="h1">{"STIG Tools"}</UiBox>
                    <UiBox variant="p" color="text-body-secondary">
                        {"Sign in with your organization account."}
                    </UiBox>
                    <SpaceBetween direction="horizontal" size="s">
                        <Button variant="primary" onclick={goto("/auth/login")}>
                            {"Sign in with Keycloak"}
                        </Button>
                        <Button variant="normal" onclick={goto("/auth/saml/login")}>
                            {"Sign in with SAML"}
                        </Button>
                    </SpaceBetween>
                </SpaceBetween>
            </UiBox>
        },
        AuthState::Authed(user) => html! {
            <ContextProvider<AuthContext> context={Some(user.clone())}>
                {props.children.clone()}
            </ContextProvider<AuthContext>>
        },
    }
}
