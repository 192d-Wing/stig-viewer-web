# STIG Viewer Web

A browser-based STIG / SRG compliance workbench. Lets teams browse the
DISA catalog, attach checklists to assets, track findings, run approvals,
and emit Slack / Teams / generic webhook notifications for fleet-wide
events.

## Stack

- **Frontend**: React 19, Vite 6, Cloudscape Design System (dark mode)
- **Backend**: Rust + Axum 0.7, sqlx, tokio
- **Database**: PostgreSQL (migrations in `backend/migrations/`)
- **Auth**: OIDC (Keycloak in dev), SAML 2.0, X-User-Id test bypass
- **Tests**: Playwright E2E (`e2e/`), `cargo test` for backend units

## Quick start (dev)

```bash
docker compose up -d            # Keycloak, Postgres, backend, frontend
npm install
npm run dev                     # Vite at http://localhost:5173
```

Backend listens at `http://localhost:8080`. The dev stack pre-seeds
Keycloak with a few test users (`alice`, `bob`, `mallory`); pick one in
the login dropdown.

To configure env vars, copy `.env.example` to `.env` and edit. In
non-production the backend falls back to dev defaults so you can run with
no env vars at all; in production (`STIG_ENV=production`) it refuses to
boot without `DATABASE_URL` and `OIDC_CLIENT_SECRET` set.

## Tests

```bash
# Backend units
cd backend && cargo test

# Full E2E suite (spins the stack via docker compose)
npm run e2e
```

## Layout

```
backend/          Axum API + sqlx migrations
backend/src/api/  One module per HTTP surface (assets, drafts, …)
src/              React frontend
e2e/              Playwright specs (numbered by feature; resetDb per test)
```

## Notes for contributors

- All frontend HTTP must go through `apiFetch` / `apiGet` / `apiJson` in
  `src/utils/api.js`. Raw `fetch` skips the X-User-Id test-bypass header
  and 401s in CI.
- Axum 0.7 uses `:param` path syntax, not `{param}`.
- The auth pipeline is `auth_middleware → rate_limit → viewer_guard →
  handler`. Admin routes additionally call `ensure_admin` in the handler.
- 35+ schedulers, all logged into the `scheduler_log` table; the admin
  console renders them under "Background jobs".
