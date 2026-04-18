# STIG Viewer Web — Roadmap

This roadmap addresses the gaps identified in the current codebase and sequences
the work from "deployable" to "polished". Each phase produces releasable value
on its own; phases run in parallel where the team has capacity.

Labels used in issues: `phase-1`, `phase-2`, `phase-3`, `phase-4`, plus
cross-cutting labels: `security`, `tests`, `docs`, `ops`.

Definition of done for every item:
- Code change merged
- Tests added or updated
- Docs / changelog entry updated

---

## Phase 1 — Make it deployable (2–3 weeks)

Goal: a secure, reproducible deployment outside a developer laptop.

- **Authentication & authorization**
  - Session-based login with bcrypt/argon2 password hashing
  - Roles: `viewer`, `editor`, `admin`
  - All `/api/*` routes protected except `/api/health`
- **Secrets & configuration**
  - `.env.example` checked in; `.env` git-ignored
  - Backend fails fast on missing required env vars
  - Remove hardcoded Postgres creds from `docker-compose.yml`
- **Production config**
  - Env-driven CSP `connect-src` (no more hardcoded `http://localhost:8080`)
  - Env-driven `API_BASE_URL`, `SYNC_INTERVAL`, `DATABASE_URL`
  - Separate `docker-compose.dev.yml` and `docker-compose.prod.yml`
  - Production Dockerfiles for backend and frontend (multi-stage)
- **CI baseline**
  - `.github/workflows/ci.yml`: ESLint, Vite build, `cargo fmt --check`,
    `cargo clippy`, `cargo check` on every PR

## Phase 2 — Trust & safety (2–3 weeks)

Goal: confidence that changes don't regress and that the app is safe to expose.

- **Testing**
  - Vitest + React Testing Library for parsers and core views
  - Rust integration tests for upload / parse / catalog endpoints
  - Target 60% line coverage on parsing modules
- **Security hardening**
  - Rate limit upload endpoints (per-IP + per-user)
  - Per-file size cap in addition to global body limit
  - XML parser configured against XXE / billion-laughs
  - Audit log table: who uploaded / changed what, when
  - Tighten CORS to an allowlist derived from env
- **Error handling**
  - Typed error enum in backend, mapped to structured JSON responses
  - Surface validation errors in UI via toast notifications
  - Distinguish client (4xx) vs server (5xx) failure modes

## Phase 3 — UX & ops (3–4 weeks)

Goal: daily-driver quality for real STIG reviewers and operators.

- **Persistence**
  - Save asset metadata and rule statuses to backend
  - Per-user workspaces / saved checklists
- **Frontend**
  - Global cross-rule full-text search
  - Bulk export across all open tabs
  - Undo/redo on rule status changes
  - Offline mode via IndexedDB cache
- **Operations**
  - `/api/sync` manual trigger endpoint (admin-only)
  - `/metrics` Prometheus endpoint
  - Structured JSON logs with request IDs
  - Graceful shutdown on SIGTERM
  - Split health into `/livez` and `/readyz`
- **Documentation**
  - Top-level README with quickstart
  - CONTRIBUTING.md with dev workflow
  - Architecture diagram (FE ↔ BE ↔ DB ↔ DISA sync)
  - API reference (OpenAPI spec)

## Phase 4 — Polish (ongoing)

- **Refactor** `stig-viewer.jsx` into feature modules:
  `upload/`, `rules/`, `diff/`, `export/`, `library/`
- **Dedupe** XCCDF/CKL parsing — backend becomes source of truth,
  frontend becomes a thin viewer
- **Backups** — documented `pg_dump` cron + restore runbook
- **Optional**
  - SSO via OIDC
  - Multi-tenant organizations
  - Signed CKL export (detached signature)

---

## Cross-cutting

- File a GitHub issue per bullet above with the appropriate `phase-*` label.
- Prefer small PRs (< 400 lines) that each close one issue.
- Keep this file current: move completed items to a "Done" section below as
  they ship.

## Done

_(nothing yet)_
