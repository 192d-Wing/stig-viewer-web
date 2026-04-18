# Contributing

Thanks for your interest in contributing. This document covers day-to-day
workflow; see [README.md](./README.md) for setup and [ROADMAP.md](./ROADMAP.md)
for planned work.

## Workflow

1. Pick an issue labelled `phase-1`, `phase-2`, `phase-3`, or `phase-4`.
2. Branch from `main`. Name the branch after the issue, e.g.
   `auth-login-endpoint` or `fix-csp-production`.
3. Keep PRs small — aim for under ~400 lines of diff. Split larger work into
   stacked PRs.
4. Every change must include:
   - Tests (unit or integration as appropriate)
   - Docs update when behaviour or config changes
   - A changelog entry when user-visible
5. Open a PR against `main`. CI must be green before review.

## Local checks

Run these before pushing:

```bash
# Frontend
npm run lint
npm run build

# Backend
cd backend
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo check
```

## Commit messages

Use conventional-commit style prefixes:

- `feat:` — new user-visible behaviour
- `fix:` — bug fix
- `refactor:` — internal change, no behaviour change
- `docs:` — documentation only
- `chore:` — tooling, deps, formatting
- `ci:` — workflow changes
- `test:` — tests only

Include a short body when the *why* isn't obvious from the subject.

## Code style

- **Frontend**: ESLint config in `eslint.config.js` enforces the rules.
  Prefer small, focused components over one-file monoliths
  (`stig-viewer.jsx` is a legacy artefact scheduled for decomposition in
  phase 4).
- **Backend**: `cargo fmt` settles formatting. Clippy runs at
  `-D warnings` — fix warnings rather than suppress them unless there's a
  documented reason.

## Security-sensitive changes

If your change touches authentication, input parsing, file I/O, CSP, CORS,
or the DISA sync pipeline, call it out in the PR description. A reviewer
with security context will be tagged in.

Never commit secrets. `.env` and `.env.*.local` are git-ignored; the shape
lives in `.env.example`.

## Running Postgres locally

```bash
docker compose up -d           # start
docker compose logs -f postgres
docker compose down            # stop (keeps volume)
docker compose down -v         # stop and drop the database
```

Migrations run automatically when the backend starts.

## Questions

Open a GitHub discussion or issue — no question too small.
