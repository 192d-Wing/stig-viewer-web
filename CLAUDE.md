# Notes for Claude

Working file for AI coding assistants. Conventions and recurring
pitfalls that aren't obvious from the code.

## Architecture

- **Frontend**: React 19 + Vite 6 + Cloudscape Design System (dark mode
  via `applyMode(Mode.Dark)` in `main.jsx`). `AppLayout` with
  `headerSelector="#h"`, `SideNavigation` for open STIG tabs, `SplitPanel`
  (side position) for `RuleDetail`.
- **Backend**: Rust + Axum 0.7, sqlx::PgPool. One module per HTTP surface
  under `backend/src/api/`.
- **Auth pipeline**: `auth_middleware → rate_limit → viewer_guard →
  handler`. Admin routes additionally call `ensure_admin` in the handler.
- **Schedulers**: six `tokio::spawn` loops in `main.rs` (sync, snapshot,
  overdue_digest, audit_retention, compliance_report,
  asset_email_schedule). Each selects on a shared `Notify` so SIGTERM
  drains them cleanly.

## Always do

- All frontend HTTP goes through `apiFetch` / `apiGet` / `apiJson` in
  `src/utils/api.js`. Raw `fetch` skips the X-User-Id test bypass.
- Scope E2E table selectors by accessible name
  (`getByRole("table", { name: /.../i })`), never by position
  (`.last()` / `:nth-of-type`).
- For an E2E user id, fetch via `/api/users/me` — the `users.id` column
  is a UUID, not the friendly name (`"alice"` etc).
- Cloudscape `Toggle` / `Textarea` `data-testid` lands on a wrapper; the
  real input is the inner `<input type="checkbox">` / `<textarea>`. Drill
  to it before clicking / filling.

## Never do

- Don't use `{param}` path syntax with Axum 0.7 — it silently fails to
  match. Use `:param`.
- Don't call `setState` inside `useMemo` — infinite re-render in React 19,
  blank screen.
- Don't add `overflow: hidden` to `html` / `body` / `#root` — Cloudscape
  `AppLayout` manages its own scroll container.
- Don't put a wrapper `<div>` (or `Tabs`) between `AppLayout` and a
  `<Table variant="full-page">` — the table needs to be a direct child.

## E2E

- Capture servers in tests must bind on `0.0.0.0` and be reached via
  `host.docker.internal` (the backend container can't see `127.0.0.1`).
  `docker-compose.yml` already wires `extra_hosts: ["host.docker.internal:host-gateway"]`.
- The serde camelCase default rewrites snake_case JSON keys (e.g.
  `thumbs_up` → `thumbsUp`). Allowlist-style enum fields need explicit
  `#[serde(rename = "...")]` to preserve their wire shape.
- `apiJson` calls `.json()` unconditionally — don't use it for endpoints
  that return 204 (use `apiFetch` instead).

## Where to look

- Routing + scheduler wiring: `backend/src/main.rs`.
- Auth helpers: `backend/src/api/auth.rs` (`AuthUser`, `auth_middleware`).
- Admin role check: `ensure_admin(&user)` — duplicated across admin
  handler modules.
- Asset write authorization: `asset_acl::user_can` /
  `asset_acl::require_asset_write`.
- E2E helpers: `e2e/helpers.js` (`loginAs`, `resetDb`, `BACKEND`).
