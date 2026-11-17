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
- `STIG_SYNC_INTERVAL_HOURS` — hours between DISA sync runs.
- `STIG_SYNC_ON_START` — run the first DISA sync at boot (default `true`).
  `false` delays the first run by one interval; CI sets it to `false` so the
  e2e run never contacts DISA. (A large interval alone does not skip the
  boot sync.) A source URL that answers 404/410 is logged as a warning naming
  the entry and counted as a stale URL in the scheduler summary; update
  `backend/stig-sources.toml` when you see one.
- `ALLOW_TEST_AUTH_HEADER` — enables the `X-User-Id` test bypass (any client
  can act as any user). Off unless set to `true`/`1`; the compose file turns it
  on for local dev and the E2E suite.
- `STIG_ENABLE_TEST_ROUTES` — mounts the unauthenticated `/api/test/*` routes
  the E2E suite uses (database reset, role changes, session minting). Off
  unless set to `true`/`1`; the compose file turns it on.

Both test hooks must stay unset in production. The backend refuses to start if
either is enabled while `STIG_ENV=production`, and with neither set
`/api/test/*` returns 404 and `X-User-Id` is ignored.

### STIG data directory

The tracked `backend/data/stigs` is a read-only seed. It is never written by
the running stack: compose sets `DATA_DIR=/data`, a named volume (`stig_data`)
holding synced and uploaded STIGs, drafts, attachments and archives. A
dev-only `STIG_SEED_DIR` (set to `/app/data/stigs` in compose) makes the
backend copy seed files that are missing from `DATA_DIR/stigs` at start and
add catalog rows for any STIG file that has none; it never overwrites an
existing file. Production leaves `STIG_SEED_DIR` unset and points `DATA_DIR`
at its own persistent storage. The sync skips writing (and archiving) a STIG
whose serialised bytes are unchanged, so a no-op sync leaves files alone.

`task reset` also drops the `stig_data` volume. Dev drafts and attachments
created under the old `DATA_DIR` (inside the checkout, `backend/data`) are not
migrated to the new volume; recreate them. `task data:restore` is gone
because nothing rewrites the tracked files any more.

`STIG_SEED_DIR` is dev-only: the backend refuses to start if it is set while
`STIG_ENV=production`.

Renamed sync ids. The DISA sync manifest now uses the ids library import
derives: `windows-11` is `ms-windows-11`, `windows-server-2019` and
`windows-server-2022` are `ms-windows-server-2019` / `-2022`, `ubuntu-2004` is
`can-ubuntu-20-04-lts`, `ubuntu-2204` is `can-ubuntu-22-04-lts`,
`chrome-windows` is `google-chrome`, `firefox` is `moz-firefox`,
`active-directory` is `active-directory-domain` and `dns` is `bind-9-x`;
`cisco-ios-xe` was dropped (no current download). Nothing is migrated.
Checklists on an old id keep working against the old STIG file but are no
longer refreshed by sync, and the backend logs a warning at start naming such
ids. To move one forward, re-apply the STIG under the new id (or delete the
old catalog entry once its checklists are gone).

Catalog uploads (`POST /api/upload`, `POST /api/upload/library`) require a
signed-in user with the `admin` role and accept bodies up to 500 MB. Other
routes cap request bodies at 10 MB, apart from evidence attachments (25 MB),
`/api/sign` and the admin restore.

### Signing envelope (v2)

`POST /api/sign` returns:

```json
{
  "document": { "...": "convenience copy, NOT authenticated" },
  "payload": "<base64url, no padding, of the exact signed bytes>",
  "signature": "<base64 Ed25519, legacy = signatures[0].signature>",
  "keyId": "<legacy = signatures[0].keyId>",
  "version": 2,
  "signatures": [{ "algorithm": "ed25519", "keyId": "...", "signature": "<base64>" }]
}
```

`GET /api/signing/pubkey` returns `{algorithm, keyId, publicKey, keys:
[{algorithm, keyId, publicKey}]}`; pin the key from it out of band.

**Only `payload` is authenticated.** It is the compact UTF-8 JSON of the
signing document: `version`, `algorithm`, `keyId`, `signers`
(`[{algorithm, keyId}]`), `sha256`, `signedAt`, `signedBy`, `signedByName`,
and `resource` only when present. `algorithm` and `keyId` equal `signers[0]`.
The top-level `document`, `signature`, `keyId` and `version` are ignored by
verifiers. Verifiers never rebuild JSON: they decode `payload` and parse those
same bytes.

Domain separation: the signature input is
`b"stig-viewer/sign/v2\0" || payload_bytes` (`SIGN_DOMAIN` in
`backend/src/api/signing.rs`).

Verification steps (implemented by `verify_bundle` in `signing.rs`):

1. Base64url-decode `payload` and parse it as the signing document.
2. Require the signed `version` to be exactly 2.
3. Require `signers` to be non-empty and free of duplicates, with
   `signers[0]` equal to the signed `algorithm`/`keyId`.
4. If any signer uses an algorithm you do not support, reject (never skip).
5. Require the envelope's `signatures[]` to match `signers` one to one (same
   algorithm and keyId; no extras, none missing).
6. Require every signer's `keyId` to be the fingerprint of the key you pinned
   (first 8 bytes of SHA-256 of the raw public key, hex).
7. Verify every signature over `SIGN_DOMAIN || payload`.
8. Require the artifact's SHA-256 to equal `sha256` (hex, compared
   case-insensitively). `verify_bundle` makes this mandatory;
   `verify_bundle_document_only` skips it and binds no artifact.

v1 is detected by the absence of `version` (and of `payload`); v1 verifiers,
which checked a signature over a rebuilt document, break against v2 and must
be updated. ML-DSA is not supported yet. Adding it means a new entry in both
`signers` (inside the signed bytes) and `signatures`, and every signer must
verify, so stripping a post-quantum signature is detected. Export bundles do
not use this envelope.

Worked example (Python, `cryptography` package). It uses explicit `raise`
rather than `assert` (which `python -O` strips) and strict base64:

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate JSON key: " + k)
        d[k] = v
    return d

def verify(bundle_path, pinned_pub: Ed25519PublicKey, artifact_sha256_hex: str):
    b = json.load(open(bundle_path), object_pairs_hook=no_dupes)
    p = b["payload"]
    if "=" in p:
        raise ValueError("payload must be unpadded base64url")
    # Strict: rejects characters outside the URL-safe alphabet.
    payload = base64.b64decode(p + "=" * (-len(p) % 4), altchars=b"-_", validate=True)
    doc = json.loads(payload, object_pairs_hook=no_dupes)

    if doc.get("version") != 2:
        raise ValueError("unsupported version")
    signers = [(s["algorithm"], s["keyId"]) for s in doc["signers"]]
    sigs = [(s["algorithm"], s["keyId"]) for s in b["signatures"]]
    if not signers or len(signers) > 8 or len(set(signers)) != len(signers):
        raise ValueError("bad signer list")
    if signers[0] != (doc["algorithm"], doc["keyId"]):
        raise ValueError("algorithm/keyId do not match signers[0]")
    pub_raw = pinned_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pinned_id = hashlib.sha256(pub_raw).digest()[:8].hex()
    if signers != [("ed25519", pinned_id)]:   # reject unknown algorithms; never skip
        raise ValueError("signers are not exactly the pinned ed25519 key")
    if sorted(sigs) != sorted(signers):
        raise ValueError("signatures do not match signers")

    sig = base64.b64decode(b["signatures"][0]["signature"], validate=True)
    pinned_pub.verify(sig, b"stig-viewer/sign/v2\0" + payload)  # raises on failure

    if doc["sha256"].lower() != artifact_sha256_hex.lower():
        raise ValueError("artifact hash mismatch")
    return doc
```

The Rust verifier uses `verify_strict`, which rejects non-canonical
signatures and small-order keys. OpenSSL's Ed25519 verify (used by
`cryptography`) may be more permissive about non-canonical signatures; that is
harmless for authenticity here but means the two verifiers can disagree on
malformed input. Generalise the single-signer check above to a loop over
`signers` once more algorithms exist.

Rollout note: verifiers must support ML-DSA before the server starts emitting
it, because unknown algorithms are rejected rather than skipped. When ML-DSA is
added, derive key ids over `algorithm || pubkey` (so equal key bytes under two
algorithms cannot share an id) and have `verify_bundle` take pinned keys keyed
by `(algorithm, keyId)`.

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

## SAML service provider

Env: `SAML_IDP_SSO_URL` (enables SAML), `SAML_IDP_CERT_PEM` (required to
verify; pinned), `SAML_IDP_ENTITY_ID` (if set, the Assertion Issuer must equal
it), `SAML_SP_ENTITY_ID` (Audience, default `{frontend}/saml/sp`),
`SAML_SP_ACS_URL` (Recipient/Destination, default `{PUBLIC_BASE}/auth/saml/acs`),
`SAML_CLOCK_SKEW_SECS` (default 120, clamped 0-300).

The ACS accepts exactly one Assertion, a direct child of `samlp:Response`.
Accepted signature layouts: Assertion signed, Response signed, or both; a
`ds:Signature` must be a direct child of the Response or the Assertion, with one
Reference to its parent's ID, RSA-SHA256 and SHA-256 only. Identity is read only
from the signed scope. Required: Status Success, a bearer SubjectConfirmation
with matching Recipient and unexpired NotOnOrAfter, Conditions, and an
AudienceRestriction naming the SP; Destination is checked when present. DOCTYPE,
comments, processing instructions and EncryptedAssertion are rejected. Failed
ACS attempts return a generic 401 and log an `auth.saml_acs` audit line.

Only RSA-SHA256 with keys of at least 2048 bits is accepted (a weaker
`SAML_IDP_CERT_PEM` stops startup). `SignedInfo` and the signed element must
declare every namespace they use themselves (the `ds` namespace included), since
bindings outside the signed bytes are not authenticated. `POST /auth/saml/acs`
shares the per-IP pre-auth rate limit (429 when exceeded) and answers every
failure with a generic 401; reasons go to the audit log as fixed codes.

Limitation: exclusive canonicalisation is not implemented yet. Signatures are
verified over the bytes as sent, so IdPs that do not emit canonical XML will
fail closed until c14n is added.

`SAML_INSECURE_SKIP_VERIFY=true` skips only the signature check (all other
checks still run) and is for local development. The backend **refuses to start**
if it is set with `STIG_ENV=production`.

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
