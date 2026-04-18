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

### 2. Start Postgres

```bash
docker compose up -d
```

Compose refuses to start if `POSTGRES_{DB,USER,PASSWORD}` are missing.

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

| Variable                   | Who reads it      | Required | Default                  |
| -------------------------- | ----------------- | -------- | ------------------------ |
| `DATABASE_URL`             | backend           | yes      | —                        |
| `PORT`                     | backend           | no       | `8080`                   |
| `DATA_DIR`                 | backend           | no       | `data`                   |
| `STIG_SYNC_INTERVAL_HOURS` | backend           | no       | `24`                     |
| `RUST_LOG`                 | backend           | no       | `info`                   |
| `POSTGRES_{DB,USER,PASSWORD}` | docker compose | yes    | —                        |
| `POSTGRES_PORT`            | docker compose    | no       | `5432`                   |
| `VITE_API_BASE_URL`        | frontend build    | no       | `http://localhost:8080`  |

`VITE_API_BASE_URL` is baked into the built HTML's CSP `connect-src` and is
the only origin the browser can talk to. Set it at build time in production.

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
├── .env.example          Environment variable template
├── ROADMAP.md            Planned work
└── .github/workflows/    CI
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

- Production CSP: no `unsafe-inline` on `script-src`, no external origins
  except the configured API base, no `object-src`, no framing.
- The backend validates upload IDs (alphanumeric + dashes) and guards
  against path traversal on disk writes.
- Known gaps (auth, rate limits, XXE protection, audit logging) are tracked
  in `ROADMAP.md` phases 1–2.
