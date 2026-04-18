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

- **Authentication & authorization** — ✅ done
  (see the Done section for links)
- **Secrets & configuration** — ✅ done
- **Production config** — ⏳ partly done
  - ✅ env-driven CSP `connect-src`, `DATABASE_URL`, `SYNC_INTERVAL`
  - ✅ `docker-compose.dev.yml` for Keycloak layer
  - ⏳ `docker-compose.prod.yml` + multi-stage production Dockerfiles for
    backend and frontend
- **CI baseline** — ✅ done

## Phase 2 — Trust & safety (2–3 weeks)

Goal: confidence that changes don't regress and that the app is safe to expose.

- **Testing** — ⏳ in progress
  - ✅ Vitest + RTL scaffolding (43 tests): parseCKL, diffSTIGs,
    readApiError, useNotifications, useAuth, Login, StigLibrary,
    RuleDetail, DiffView, STIGView
  - ✅ Rust unit tests (14 tests): parser, ratelimit, ApiError
  - ✅ Rust integration tests (7 tests) via `sqlx::test` + real server:
    health, catalog, 404/400 error envelopes, upload → catalog →
    /stigs/:id round-trip, audit-log writes
  - ✅ `npm test` and `cargo test` run in CI, with Postgres as a service
    container for integration tests
  - ⏳ Coverage target 60% on parsing modules
- **Security hardening** — ⏳ mostly done
  - ✅ Per-IP rate limit on upload endpoints (UPLOAD_RATE_PER_MIN)
  - ✅ Per-file size caps (MAX_UPLOAD_BYTES, MAX_LIBRARY_BYTES)
  - ✅ XML parser XXE-safe (regression test)
  - ✅ CORS allowlist derived from ALLOWED_ORIGINS
  - ✅ Audit log (`audit_log` table, `GET /api/audit` admin-only;
    records upload.stig, upload.library, auth.login, auth.logout)
- **Error handling** — ✅ done
  - `ApiError` enum + `IntoResponse` → `{error:{code,message,details}}`
  - All `/api/*` handlers converted to return `Result<_, ApiError>`
  - Frontend `readApiError` + `notify.error` via Cloudscape Flashbar
  - Internal error messages never leak to the client

## Phase 3 — UX & ops (3–4 weeks)

Goal: daily-driver quality for real STIG reviewers and operators.

- **Persistence** — ✅ done
  - `workspaces` table keyed by (user_sub, stig_id) with JSONB
    `asset_info` and `rule_overrides` columns
  - `GET/PUT /api/workspaces/:stig_id` per-user endpoints
  - Frontend: catalog-loaded tabs fetch their workspace on open;
    status/asset changes trigger a 1-second debounced PUT
  - Local-file tabs are not persisted (no stable catalog id)
- **Frontend** — ✅ done
  - ✅ Global cross-rule search (Ctrl/Cmd+K modal)
  - ✅ Bulk export across all open tabs (all .ckl + combined POAM)
  - ✅ Undo/redo on rule status and bulk-status changes
  - ✅ Offline mode: catalog + per-STIG JSON cached in IndexedDB;
    network failure falls back to cache with a warning banner
- **Operations** — ✅ done
  - ✅ `/api/sync` manual trigger endpoint (admin-only, audited)
  - ✅ Graceful shutdown on SIGTERM + SIGINT
  - ✅ Split health into `/livez` and `/readyz` (with `/api/health` alias)
  - ✅ `/metrics` Prometheus endpoint (http_requests_total,
    http_request_duration_seconds, audit_events_total)
  - ✅ Request-ID middleware (`X-Request-Id` honored or generated, echoed,
    and attached to a tracing span)
  - ✅ JSON log format gated on `LOG_FORMAT=json`
- **Documentation**
  - Top-level README with quickstart
  - CONTRIBUTING.md with dev workflow
  - Architecture diagram (FE ↔ BE ↔ DB ↔ DISA sync)
  - API reference (OpenAPI spec)

## Phase 4 — Polish (ongoing)

- **Refactor** `stig-viewer.jsx` — ✅ done (actually already done before
  this roadmap was written; the legacy file was removed and the
  `src/components/` decomposition is the source of truth).
- **Dedupe** XCCDF/CKL parsing — ✅ kept intentional. The frontend
  parses user-supplied local files (offline workflow); the backend
  parses uploads to produce the catalog JSON. Divergence is guarded
  by the shared fixture in `testdata/fixtures/minimal.xccdf.xml`
  exercised by both FE (`src/utils/__tests__/parserParity.test.js`)
  and BE (`backend/src/parser/mod.rs::parity_fixture_*`) tests.
- **Backups** — ✅ `BACKUPS.md` covers pg_dump, data/ snapshot, cron
  cadence, restore runbook, and known gaps (no PITR, no at-rest
  encryption, non-atomic data-dir tar).
- **Optional**
  - ✅ SSO via OIDC (shipped in Phase 1)
  - ✅ Multi-tenant organisations — data isolation + session scope +
    `/api/orgs/me` + `/api/orgs/switch`, admin org-creation
    (`POST /api/orgs`) and member-management
    (`GET/POST/DELETE /api/orgs/:slug/members[/:user_sub]`), and a
    TopNavigation org switcher (`src/hooks/useOrgs.js`) that reloads
    the app on switch so tab state and the catalog refetch cleanly.
  - Signed CKL export (detached signature)

---

## Cross-cutting

- File a GitHub issue per bullet above with the appropriate `phase-*` label.
- Prefer small PRs (< 400 lines) that each close one issue.
- Keep this file current: move completed items to a "Done" section below as
  they ship.

## Done

### Phase 1

- **Auth (OIDC RP)** — Keycloak dev stack, `/api/auth/{login,callback,me,logout}`
  with PKCE, encrypted session cookie, `require_auth` middleware protecting
  all `/api/*` except `/api/health`. Frontend login page and session-aware
  `apiFetch`. Dev-open mode preserved for local work;
  `REQUIRE_AUTH=1` enforces OIDC in production.
  Files: `backend/src/auth/`, `src/components/Login.jsx`,
  `src/hooks/useAuth.js`, `src/api.js`, `docker-compose.dev.yml`,
  `keycloak/realm-dev.json`.
- **Env-driven config** — Frontend API base URL + production CSP
  `connect-src` come from `VITE_API_BASE_URL` at build time; backend reads
  `DATABASE_URL`, `PORT`, `DATA_DIR`, `STIG_SYNC_INTERVAL_HOURS`,
  `ALLOWED_ORIGINS` from env. Fail-fast on missing `DATABASE_URL`.
- **Secrets hygiene** — `.env.example`, `.env*` git-ignored,
  `docker-compose.yml` requires Postgres creds via `${VAR:?}` syntax.
- **CI** — GitHub Actions runs ESLint, Vite build, `cargo fmt --check`,
  `cargo clippy -D warnings`, `cargo check` on every PR.
- **Docs** — `README.md`, `CONTRIBUTING.md`, `ROADMAP.md` (this file).
