# stig-viewer-web

A web application for working with DISA Security Technical Implementation Guides
(STIGs): browsing the published catalog, editing checklists against your assets,
tracking findings through a review workflow, and exporting evidence in the
formats compliance teams actually need.

Not just a viewer — a full-stack compliance workflow platform.

## Features

**Catalog**
- Scheduled sync of STIG ZIPs from DISA, with XCCDF extraction and upsert into a
  Postgres catalog (see `backend/src/sync/`, `backend/stig-sources.toml`).
- Catalog search, diff between STIG versions, archive of superseded releases.
- CCI mapping panel.

**Checklists & authoring**
- Upload and view `.ckl` and XCCDF files.
- Rule list with CAT I/II/III severity filtering, rule detail, split-pane viewer,
  side-by-side diff between checklists.
- STIG writer with drafts and reviewer assignment.

**Assets**
- Asset library with groups, per-asset ACLs, baselines, checklist versions,
  snapshots, and bulk operations.
- Per-asset markdown runbooks.
- Scheduled asset email reports with CC lists.

**Workflow**
- Finding assignment and approvals, "my findings," stale and overdue tracking.
- Rule comments with @mentions and reactions.
- Saved searches.

**Exports**
- CKL, XCCDF, POAM, OSCAL, PDF compliance reports.
- Signed export bundles (Ed25519).

**Admin & governance**
- OIDC and SAML authentication.
- ABAC policies, session audit, audit retention.
- Rate limiting, backup/restore, admin console.

**Integrations**
- Outbound webhooks with HMAC signing and payload flavors (Slack, Teams, generic).
- Per-user notification preferences.

## Architecture

```
          Browser
             │
             │  (Trunk dev / static build)
             ▼
    ┌─────────────────┐           ┌──────────────┐
    │  Rust / Yew     │  HTTP     │  Keycloak /  │
    │  (WebAssembly)  │◀─OIDC────▶│  SAML IdP    │
    └────────┬────────┘           └──────────────┘
             │ JSON over HTTP
             ▼
    ┌─────────────────┐           ┌──────────────┐
    │  Rust / Axum    │           │  DISA STIG   │
    │  backend        │──sync────▶│  distribution│
    │  (sqlx, tokio)  │           └──────────────┘
    └────────┬────────┘
             │
             ▼
       Postgres 18
       (schema in backend/migrations)
```

**Frontend** — `frontend/`, entry `frontend/src/main.rs`. Rust with
[Yew](https://yew.rs) 0.23, compiled to WebAssembly and bundled by
[Trunk](https://trunkrs.dev). `frontend/src/ui/` is an in-house component kit
(buttons, tables, modals, selects, charts); pages live in
`frontend/src/components/`, and the XCCDF/CKL parsers and exporters in
`frontend/src/utils/`. Clippy runs with `-D warnings`.

**Backend** — `backend/`. Rust with Axum for HTTP, `sqlx` against Postgres,
`tokio` for async. XCCDF parser in `backend/src/parser/`, DISA sync and scheduler
in `backend/src/sync/`, API handlers in `backend/src/api/`. Migrations in
`backend/migrations/` (currently 35).

**Database** — Postgres 18. Managed through `sqlx` migrations.

**Auth** — Keycloak in local dev (realm pre-seeded under `dev/keycloak/`),
pluggable OIDC or SAML in production.

**Tests** — `e2e/` holds the Playwright suite (~79 specs) covering auth, library,
writer, workflow, exports, dashboards, trends, severity, baselines, PDF report,
audit, ABAC, and webhooks.

## Running locally

Everything is wired through `docker-compose.yml`. You need Docker (or Podman with
a compose shim) and nothing else.

```bash
docker compose up
```

Or, with [Task](https://taskfile.dev) installed, `task dev` starts postgres,
keycloak and the backend in containers and serves the frontend on the host with
Trunk (faster rebuilds than the frontend container). It picks Docker or Podman
automatically; run `task` to list the other tasks (`down`, `logs`, `test`,
`e2e`, ...).

`docker compose up` brings up four services:

| Service   | Port | Notes                                                  |
|-----------|------|--------------------------------------------------------|
| frontend  | 5173 | `trunk serve`, rebuilds and reloads on change          |
| backend   | 8080 | `cargo watch` on `src/` and `migrations/`              |
| postgres  | 5433 | Mapped off the default to avoid clashes; user `stig`   |
| keycloak  | 8081 | Dev realm `stig-viewer`, admin `admin` / `admin`       |

Open http://localhost:5173 and sign in through Keycloak. The first start
compiles the WebAssembly bundle, so the frontend takes a few minutes to come up.

### Environment overrides

The compose file reads a handful of variables from the shell; defaults are fine
for local work. The ones you may want to change:

- `API_URL` — backend origin compiled into the frontend bundle (and into the
  production CSP `connect-src`). Set when the backend isn't on
  `localhost:8080` (for example when developing from a second machine).
  `VITE_API_URL` is still read as a fallback.
- `OIDC_INTERNAL_URL` / `OIDC_PUBLIC_URL` / `OIDC_CLIENT_ID` /
  `OIDC_CLIENT_SECRET` / `OIDC_REDIRECT_URI` — point the backend at a different
  identity provider. `INTERNAL` is how the backend reaches the IdP; `PUBLIC` is
  how the browser does.
- `STIG_SYNC_INTERVAL_HOURS` — hours between DISA sync runs. Set to a large
  number to effectively disable the sync (CI does this to keep startup fast).
- `ALLOW_TEST_AUTH_HEADER` — enables the `X-User-Id` test bypass (any client
  can act as any user). Off unless set to `true`/`1`; the compose file turns it
  on for local dev and the E2E suite.
- `STIG_ENABLE_TEST_ROUTES` — mounts the unauthenticated `/api/test/*` routes
  the E2E suite uses (database reset, role changes, session minting). Off
  unless set to `true`/`1`; the compose file turns it on.

Both test hooks must stay unset in production. The backend refuses to start if
either is enabled while `STIG_ENV=production`, and with neither set
`/api/test/*` returns 404 and `X-User-Id` is ignored.

Catalog uploads (`POST /api/upload`, `POST /api/upload/library`) require a
signed-in user with the `admin` role and accept bodies up to 500 MB. Other
routes cap request bodies at 10 MB, apart from evidence attachments (25 MB),
`/api/sign` and the admin restore.

### Database

Postgres data lives in a named volume (`postgres_data`). Migrations apply on
backend start. To reset:

```bash
docker compose down -v   # drops the volume
docker compose up
```

### Frontend-only development

To iterate on the frontend against a running backend without the container you
need a Rust toolchain with the wasm target, plus Trunk:

```bash
rustup target add wasm32-unknown-unknown
cargo install trunk --locked
cd frontend
API_URL=http://localhost:8080 trunk serve     # http://localhost:5173
```

`trunk build --release` writes the static site to `frontend/dist/`, with the
production Content-Security-Policy injected into `index.html`.

### Lint and tests

```bash
cd frontend && cargo clippy --target wasm32-unknown-unknown -- -D warnings
cd frontend && cargo test          # parsers, exporters, markdown, diff
npm ci && npm run test:e2e         # Playwright suite (requires the stack running)
cd backend && cargo test
cd backend && cargo clippy -- -D warnings
```

## Operations: audit

- Durable request events live in `audit_events` (see `/api/audit/events`).
  Each row carries the user's role at the time, a server-generated request id
  (also returned in the `X-Request-Id` response header; an inbound
  `X-Request-Id` is ignored) and the source IP. Reading the audit log is itself
  recorded, as `audit.read` (view, bounded filters, page and rows returned).
- Audit writes fail open: if a row cannot be written, the request still
  completes and the backend logs an error on the `audit` target containing
  `failed to write audit event`, with the user, action, outcome and ids. Alert
  on that line, and ship the application logs to a retained store, since it is
  the only record of an event that missed the database (AU-5).
- `source_ip` is the same client IP the login notice uses: the socket peer
  address, or, with `STIG_TRUST_PROXY_HEADERS=true`, the
  `STIG_TRUSTED_PROXY_HOPS`-th hop from the right of `X-Forwarded-For`. It is
  stored only as a canonical IP address (otherwise NULL). Behind a proxy
  without that setting every row records the proxy's address; with it set, the
  proxy must append to `X-Forwarded-For` as described above, since a value the
  client supplied further left is never used.
- A 403 from the authenticated API that its handler did not record itself
  (the viewer read-only gate, role checks, `/api/audit/*`) is recorded
  centrally as `authz.denied` with `detail = {method, route}`, where `route` is
  the route template, never the URL. 401 and 429 responses are not recorded.
- Repeated `denied`/`rejected` events collapse. Only a true repeat does: the
  same user, action, outcome, asset/checklist/STIG ids, `detail`
  (for `authz.denied`, the method and route template), ignoring only the
  client-derived counters `requested` and `distinct`, `source_ip` and
  `user_role`. Such an event, arriving within 5 minutes of the row's first
  occurrence, increments `repeat_count` and sets `last_occurred_at` on that row
  instead of adding one, so a collapsed row covers
  [`occurred_at`, `occurred_at` + 5 minutes]. Requests with different request
  ids still merge; the row keeps the first request's `request_id`, `source_ip`
  and `detail`, and later requests are represented only by the counter. The
  `method` of `authz.denied` is one of the standard methods or `OTHER`. `ok`
  and `partial` events are never collapsed. Retention prunes a row only when
  both `occurred_at` and `last_occurred_at` are past the cutoff, and the
  archive line carries both fields.
- IP addresses are retained with the audit rows, in the retention archive and
  in backups.


### Database guard on the audit tables

Migration `040_audit_guard.sql` makes `rule_audit` and `audit_events`
append-only at the database level. Triggers on both tables (`BEFORE UPDATE OR
DELETE` per row, `BEFORE TRUNCATE` per statement, one shared function) raise
SQLSTATE `42501` unless the transaction declared a maintenance mode with
`SELECT set_config('stig.audit_maintenance', '<mode>', true)`:

- `retention`: DELETE (the audit retention sweep);
- `restore`: TRUNCATE and DELETE (a forced backup restore, which also records
  a `backup.restore` event after it commits);
- `test`: UPDATE and TRUNCATE (the `/api/test/*` reset and backdate routes,
  which exist only under `STIG_ENABLE_TEST_ROUTES`).

The one update always allowed is the collapse of a repeated denial: only
`repeat_count` (strictly increasing) and `last_occurred_at` (not moving
backwards) may change.

Limit: this is a guard, not a privilege boundary. Any code that can run SQL as
the application role can set the mode, and a DBA or the table owner can
disable the triggers. It stops accidents, stray queries and injected
statements that do not know the mode; it does not stop a compromised
application or database administrator. For production hardening, run
migrations and the retention/restore jobs under a separate role that owns the
tables, give the application role only `SELECT` and `INSERT` on the audit
tables (plus `UPDATE (repeat_count, last_occurred_at)` on `audit_events`), and
ship audit rows to an external append-only store.

## Repository layout

```
.
├── frontend/
│   ├── src/              Yew app: ui kit, components, utils
│   ├── styles/           Stylesheet
│   ├── public/           Static assets (fonts)
│   └── Trunk.toml        Build / dev-server config
├── e2e/                  Playwright specs
├── backend/
│   ├── src/              Axum handlers, parser, sync, auth, policy
│   ├── migrations/       sqlx migrations
│   └── stig-sources.toml STIG ZIPs to sync from DISA
├── dev/keycloak/         Dev realm import
└── docker-compose.yml    Local dev stack
```

## Login emblem

The sign-in screen shows an emblem from `frontend/public/brand/org-emblem.png`
(served at `/brand/org-emblem.png`). This is the operator-installed seal, and
the operator is responsible for being authorized to display it (for example
under DoD seal and insignia policy). PNG is recommended because it has no
script surface; use at least 512px. The installed file is about 1.5 MB, so
consider losslessly compressing or downscaling it (it is shown at most 360px
wide) to speed up the first paint. To swap it, replace the file and adjust
`LOGIN_EMBLEM_SRC` and `LOGIN_EMBLEM_ALT` in `frontend/src/auth.rs`. The
background accent colour is the `--login-accent` variable in
`frontend/styles/app.css`.

## System use notification (AC-8)

The sign-in screen shows the DoD Notice and Consent text and requires "I Agree"
before the sign-in buttons appear. "I Agree" calls `POST /auth/notice/ack`, which
sets a 5-minute, single-use, HttpOnly `stig_notice_ack` cookie that
`/auth/login` and `/auth/saml/login` consume; without it they redirect to the
banner. A completed login writes an `auth.notice_ack` audit event. The wording
version is `USE_NOTICE_VERSION` in both `frontend/src/constants.rs` and
`backend/src/api/notice.rs`; keep them equal. `/auth/callback` and
`/auth/saml/acs` do not enforce the proof (they only link the audit record).

The `stig_notice_ack` cookie is `SameSite=Strict`, so the frontend and the API
must be same-site (for example `app.example.mil` and `api.example.mil`), or
sign-in will always bounce back to the banner. `/auth/notice/ack`,
`/auth/login` and `/auth/saml/login` share a per-IP token bucket
(`AUTH_RATE_LIMIT_BURST`, default 30; `AUTH_RATE_LIMIT_PER_MINUTE`, default 60;
over-limit gives 429 on the ack POST and a redirect to the banner on the login
GETs). IPv6 clients are limited per /64. The IP is the socket peer address, so
**behind a reverse proxy every client shares one bucket (the proxy's) unless
`STIG_TRUST_PROXY_HEADERS=true`**; the backend logs a startup warning when it is
unset. With it set, the hop `STIG_TRUSTED_PROXY_HOPS` places from the right of
`X-Forwarded-For` (default 1, the rightmost) is used; set it only behind a
proxy that appends to that header. `POST /auth/notice/ack` rejects bodies over
1 KB. Auth cookies are `Secure` in production or
when `FRONTEND_URL` is https.
