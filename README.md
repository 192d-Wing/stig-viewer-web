# STIG Viewer Web

A web-based viewer for DISA Security Technical Implementation Guides (STIGs).
Loads XCCDF and CKL files, tracks rule review status, exports checklists and
POAMs, and diffs two STIGs side-by-side.

## Architecture

```
┌───────────────────┐        ┌───────────────────┐        ┌────────────┐
│  React + Vite     │ HTTPS  │  Rust / Axum      │ SQL    │ PostgreSQL │
│  Cloudscape UI    ├───────▶│  XCCDF/CKL parser ├───────▶│ catalog    │
│  (browser)        │        │  DISA sync        │        │            │
└───────────────────┘        └─────────┬─────────┘        └────────────┘
                                       │ HTTPS
                                       ▼
                               DISA download portal
```

- **Frontend** (`src/`, `index.html`, `vite.config.js`): React 19 +
  Cloudscape Design. Vite build, strict CSP in production.
- **Backend** (`backend/`): Rust, Axum, SQLx. Parses uploaded STIGs, stores
  them as JSON on disk, keeps a Postgres catalog, and periodically syncs
  from DISA per `backend/stig-sources.toml`.
- **Roadmap** (`ROADMAP.md`): planned work, sequenced by phase.

## Quickstart

### Prerequisites

- Node 20+
- Rust stable (1.75+)
- Docker + Docker Compose (for Postgres)

### 1. Configure environment

```bash
cp .env.example .env
# edit .env — at minimum, change POSTGRES_PASSWORD and DATABASE_URL
```

### 2. Start Postgres (and, for auth, Keycloak)

```bash
# Postgres only
docker compose up -d

# Postgres + Keycloak (for the auth flow)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Compose refuses to start if `POSTGRES_{DB,USER,PASSWORD}` are missing.

Keycloak ships with a pre-imported realm (`stig-viewer-dev`) and three
test users:

| Username | Password | Role   |
| -------- | -------- | ------ |
| admin    | admin    | admin  |
| editor   | editor   | editor |
| viewer   | viewer   | viewer |

Admin console: http://localhost:8081 (`admin` / `admin`).

To point the backend at this dev Keycloak, add to your `.env`:

```
OIDC_ISSUER_URL=http://localhost:8081/realms/stig-viewer-dev
OIDC_CLIENT_ID=stig-viewer-web
OIDC_CLIENT_SECRET=dev-only-not-secret
OIDC_REDIRECT_URI=http://localhost:8080/api/auth/callback
OIDC_POST_LOGIN_REDIRECT=http://localhost:5173
SESSION_SECRET=<openssl rand -hex 32>
OIDC_ADMIN_GROUP=stig-admins
OIDC_EDITOR_GROUP=stig-editors
OIDC_VIEWER_GROUP=stig-viewers
```

Without these, the backend starts in **dev open mode**: auth is disabled and
every request is treated as an admin. Production must set `REQUIRE_AUTH=1`
so missing OIDC config aborts startup.

### 3. Run the backend

```bash
cd backend
# DATABASE_URL is read from ../.env; export it or source it before running:
set -a && source ../.env && set +a
cargo run
```

Listens on `http://localhost:8080` by default. Migrations run automatically
on startup.

### 4. Run the frontend

```bash
npm install
npm run dev
```

Opens on `http://localhost:5173`.

## Configuration

All settings live in environment variables. See `.env.example` for the full
list. Key variables:

| Variable                      | Who reads it      | Required | Default                  |
| ----------------------------- | ----------------- | -------- | ------------------------ |
| `DATABASE_URL`                | backend           | yes      | —                        |
| `PORT`                        | backend           | no       | `8080`                   |
| `DATA_DIR`                    | backend           | no       | `data`                   |
| `STIG_SYNC_INTERVAL_HOURS`    | backend           | no       | `24`                     |
| `MAX_UPLOAD_BYTES`            | backend           | no       | `52428800` (50 MiB)      |
| `MAX_LIBRARY_BYTES`           | backend           | no       | `524288000` (500 MiB)    |
| `UPLOAD_RATE_PER_MIN`         | backend           | no       | `10` (`0` disables)      |
| `RUST_LOG`                    | backend           | no       | `info`                   |
| `ALLOWED_ORIGINS`             | backend           | no       | localhost:{5173,8080}    |
| `REQUIRE_AUTH`                | backend           | no       | `0` (dev-open if OIDC\_\* missing) |
| `OIDC_ISSUER_URL`             | backend (auth)    | if auth  | —                        |
| `OIDC_CLIENT_ID`              | backend (auth)    | if auth  | —                        |
| `OIDC_CLIENT_SECRET`          | backend (auth)    | if auth  | —                        |
| `OIDC_REDIRECT_URI`           | backend (auth)    | if auth  | —                        |
| `OIDC_POST_LOGIN_REDIRECT`    | backend (auth)    | no       | `http://localhost:5173`  |
| `OIDC_{ADMIN,EDITOR,VIEWER}_GROUP` | backend (auth) | no    | —                        |
| `ALLOWED_GROUPS`              | backend (auth)    | no       | *(any authenticated)*    |
| `SESSION_SECRET`              | backend (auth)    | if auth  | — (hex-encoded, >=32 B)  |
| `COOKIE_SECURE`               | backend (auth)    | no       | `0` (set `1` over HTTPS) |
| `POSTGRES_{DB,USER,PASSWORD}` | docker compose    | yes      | —                        |
| `POSTGRES_PORT`               | docker compose    | no       | `5432`                   |
| `KEYCLOAK_{ADMIN,ADMIN_PASSWORD}` | docker compose (dev) | no | `admin` / `admin`     |
| `KEYCLOAK_PORT`               | docker compose (dev) | no    | `8081`                   |
| `VITE_API_BASE_URL`           | frontend build    | no       | `http://localhost:8080`  |

`VITE_API_BASE_URL` is baked into the built HTML's CSP `connect-src` and is
the only origin the browser can talk to. Set it at build time in production.

### Auth endpoints

| Method | Path                  | Purpose                                  |
| ------ | --------------------- | ---------------------------------------- |
| GET    | `/api/auth/login`     | Start OIDC auth code + PKCE flow         |
| GET    | `/api/auth/callback`  | IdP redirect target — completes login    |
| GET    | `/api/auth/me`        | Current session's `{sub,email,role,exp}` |
| POST   | `/api/auth/logout`    | Clear the session cookie                 |

All other `/api/*` routes except `/api/health` require a valid session.

### Error responses

All `/api/*` handlers return a consistent error body on failure:

```json
{
  "error": {
    "code": "payload_too_large",
    "message": "file exceeds MAX_UPLOAD_BYTES (…)",
    "details": { "limitBytes": 52428800, "actualBytes": 73400320 }
  }
}
```

Codes are stable strings (e.g. `bad_request`, `unauthorized`, `forbidden`,
`not_found`, `payload_too_large`, `unprocessable_entity`, `too_many_requests`,
`internal_error`). `details` is optional and carries structured context for
errors that need it. Internal errors never leak server-side messages; the
client always sees `"internal server error"`. The frontend renders these as
Cloudscape Flashbar notifications via `src/hooks/useNotifications.js`.

### Audit log

Every upload and every login/logout is recorded in the `audit_log` table
along with the actor, their role, the peer IP, a status code, and a JSONB
metadata blob. Query it via:

```
GET /api/audit?limit=100&before_id=<cursor>
```

Admins only. `before_id` enables keyset pagination: pass the last `id`
from the previous page to get the next older batch. Response is ordered
by `id DESC`. Recorded actions today: `upload.stig`, `upload.library`,
`auth.login`, `auth.logout`.

## Development workflow

```bash
# Frontend
npm run lint          # ESLint with security rules, zero warnings
npm run build         # Production build into dist/

# Backend
cd backend
cargo fmt --check     # Formatting
cargo clippy --all-targets -- -D warnings
cargo check
```

CI (`.github/workflows/ci.yml`) runs all of the above on every PR.

## Project layout

```
.
├── src/                  React source
├── index.html            Entry HTML (contains the prod CSP meta tag)
├── vite.config.js        Build config, dev-server CSP, HTML substitution
├── backend/
│   ├── src/              Rust source
│   ├── migrations/       SQLx migrations
│   ├── stig-sources.toml Curated DISA download manifest
│   └── Cargo.toml
├── docker-compose.yml    Postgres for local dev
├── docker-compose.dev.yml  Keycloak layer for the auth flow
├── keycloak/             Realm import for Keycloak dev
├── .env.example          Environment variable template
├── ROADMAP.md            Planned work
└── .github/workflows/    CI
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

- Production CSP: no `unsafe-inline` on `script-src`, no external origins
  except the configured API base, no `object-src`, no framing.
- Authentication: OIDC relying party with auth code + PKCE, encrypted
  session cookie (PrivateCookieJar), open-redirect protection on the
  `return_to` parameter.
- The backend validates upload IDs (alphanumeric + dashes) and guards
  against path traversal on disk writes.
- Per-file size caps (`MAX_UPLOAD_BYTES`, `MAX_LIBRARY_BYTES`) and per-IP
  upload rate limit (`UPLOAD_RATE_PER_MIN`).
- XML parsing via quick-xml, which does not resolve external entities
  (XXE). A regression test in `backend/src/parser/mod.rs` locks this in.
- Known gaps (audit logging, typed error responses) are tracked in
  `ROADMAP.md` phase 2.
