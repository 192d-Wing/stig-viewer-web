//! Authentication gate: resolves the current user before rendering the app.

use crate::api::{api_fetch, BACKEND};
use crate::ui::*;
use serde::Deserialize;
use yew::prelude::*;

/// Login emblem image: the operator-installed seal in `frontend/public/brand/`.
/// Change this if the asset is replaced with a different file name or format.
const LOGIN_EMBLEM_SRC: &str = "/brand/org-emblem.png";
/// Alt text for the emblem; update it if the emblem is replaced.
const LOGIN_EMBLEM_ALT: &str = "Department of War seal";
/// Number of decorative binary columns in the login background.
const LOGIN_BINARY_COLUMNS: usize = 36;
/// Number of digits per column.
const LOGIN_BINARY_ROWS: usize = 70;

/// Deterministic 0/1 text for one background column, one digit per line.
fn login_binary_column(col: usize) -> String {
    (0..LOGIN_BINARY_ROWS)
        .map(|row| {
            if (col * 7 + row * 3 + col * row) % 5 < 2 {
                '1'
            } else {
                '0'
            }
        })
        .map(String::from)
        .collect::<Vec<_>>()
        .join("\n")
}

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
            <main class="login-screen">
                <div class="login-bg" aria-hidden="true">
                    <div class="login-binary" aria-hidden="true">
                        { for (0..LOGIN_BINARY_COLUMNS).map(|c| html! {
                            <span key={c}>{login_binary_column(c)}</span>
                        }) }
                    </div>
                </div>
                <section class="login-card" aria-labelledby="login-title" data-testid="login-card">
                    <h1 id="login-title" class="login-title">{"STIG Tools"}</h1>
                    <p class="login-subtitle">{"Sign in with your organization account."}</p>
                    <div class="login-actions">
                        <Button variant="primary" onclick={goto("/auth/login")}>
                            {"Sign in with Keycloak"}
                        </Button>
                        <Button variant="normal" onclick={goto("/auth/saml/login")}>
                            {"Sign in with SAML"}
                        </Button>
                    </div>
                </section>
                <div class="login-emblem-panel">
                    <img
                        class="login-emblem"
                        src={LOGIN_EMBLEM_SRC}
                        alt={LOGIN_EMBLEM_ALT}
                        width="360"
                        height="360"
                        data-testid="login-emblem"
                    />
                </div>
            </main>
        },
        AuthState::Authed(user) => html! {
            <ContextProvider<AuthContext> context={Some(user.clone())}>
                {props.children.clone()}
            </ContextProvider<AuthContext>>
        },
    }
}
