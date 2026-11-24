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
- Signed export bundles (Ed25519, or hybrid Ed25519 + ML-DSA-87 when an ML-DSA key is configured), with an independent Node verifier.

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
- `STIG_FIPS_PENDING_ALGS` — comma-separated allow-list of post-quantum
  algorithms that are not yet FIPS-validated and may still be used in a
  `--no-default-features --features fips` build: `ML-DSA-87`, `ML-KEM-768`, `ML-KEM-1024`,
  `X25519MLKEM768` (case-insensitive). `X25519MLKEM768` is the hybrid group for
  the transition period; CNSA 2.0 deployments need `ML-KEM-1024`. Default
  empty. In a build without the `fips` feature the list does not change which
  algorithms are used (a warning is logged if set), but it is still validated
  and an unknown token stops startup.
- `SIGNING_KEY_HEX` — 64 hex characters, the Ed25519 seed; unset means signing
  is off. `SIGNING_MLDSA87_KEY_B64` — base64 PKCS#8 ML-DSA-87 key (generate with
  `stig-viewer-backend gen-mldsa-key`); with both set, `/api/sign` bundles,
  audit archive manifests and backup manifests carry both signatures (hybrid).
  ML-DSA alone, or a malformed key, stops startup. In a `fips` build the
  ML-DSA key also needs `ML-DSA-87` in `STIG_FIPS_PENDING_ALGS`.
  `SIGNING_REQUIRE_HYBRID=true` refuses to start without both keys and stops
  verifiers accepting Ed25519-only artifacts (default false). See "Signing
  envelope (v2)" and docs/deployment.md section 5.
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
  `backend/stig-sources.toml` when you see one. An entry may carry an optional
  `sha256` pin of the ZIP; a mismatch fails closed.
- `ADMISSION_BODY_MIN_RATE_KIB` (default `64`, 8 to 8192),
  `ADMISSION_BODY_GRACE_SECS` (default `10`, 1 to 120) and
  `ADMISSION_BODY_FIRST_BYTE_SECS` (default `5`, 1 to 60) — the request-body
  deadlines for admitted requests (see "Operations: audit"). An unset or empty
  value uses the default; a value that is not an integer in range stops the
  backend at startup. Lowering the rate floor lengthens how long one slow
  upload can hold a permit (10 MiB at 8 KiB/s takes about 21 minutes), so
  fewer accounts are needed to hold the 28 non-admin permits.
- `ALLOW_TEST_AUTH_HEADER` — enables the `X-User-Id` test bypass (any client
  can act as any user). Off unless set to `true`/`1`; the compose file turns it
  on for local dev and the E2E suite.
- `STIG_ENABLE_TEST_ROUTES` — mounts the unauthenticated `/api/test/*` routes
  the E2E suite uses (database reset, role changes, session minting, reading login
  acknowledgement metadata). Off
  unless set to `true`/`1`; the compose file turns it on.

Both test hooks must stay unset in production. The backend refuses to start if
either is enabled while `STIG_ENV=production`, and with neither set
`/api/test/*` returns 404 and `X-User-Id` is ignored.

### STIG data directory

The tracked `backend/seed/stigs` is a read-only seed. It is never written by
the running stack: compose sets `DATA_DIR=/data`, a named volume (`stig_data`)
holding synced and uploaded STIGs, drafts, attachments and archives. A
dev-only `STIG_SEED_DIR` (set to `/app/seed/stigs` in compose) makes the
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

Uploaded and synced ZIPs are bounded as they decompress, whatever their
compressed size. Each `*xccdf.xml` entry may be at most 64 MiB and each nested
ZIP 128 MiB; one `/api/upload` (or one sync source) may decompress at most
256 MiB in total, nested ZIPs included, and one `/api/upload/library` at most
2 GiB. A ZIP whose local headers disagree with its central directory (or with
duplicate or overlapping entries) is refused too. Over a limit,
`/api/upload` returns 413 (malformed or inconsistent: 422), and
`/api/upload/library` returns 413 when the whole-request budget runs out; one
over-limit or inconsistent entry inside a library is skipped and listed in
`errorDetail`. Every rejection is recorded as a `catalog.upload` or
`catalog.import_library` audit event with `outcome = 'rejected'` and
`detail = {reasonCode, reason, bytesCompressed}`. The response body for a
refused ZIP is a fixed message per `reasonCode` (`entry_too_large`,
`budget_exceeded`, `header_inconsistency`, `no_xccdf`, `malformed`); entry
names, limits and parser text stay in the server log and the audit `reason`.

In a library import, each `errorDetail` item is
`{"id", "reasonCode", "error"}` with the same fixed message (library entries
can also fail with `invalid_id` or `xccdf_parse_failed`; database errors keep
their `{"id", "error"}` shape). The first 100 skipped entries are each logged
(followed by one "N more" line) and get their own `catalog.import_library_entry` audit row
(`outcome = 'rejected'`, `stig_id` = entry id, `detail = {reasonCode, entry}`).
Identical entry rows (same entry id and `reasonCode`, for example several bad
files inside one `_STIG.zip`, or the same upload repeated within 300 s) collapse
into one row whose `repeat_count` carries the rest. Entry rows stop after a
15 s overall deadline if the database stalls. Whenever anything was skipped,
one `catalog.import_library` summary row
(`outcome` `partial`, or `rejected` when nothing was imported) records
`{reasonCode: "entries_skipped", skipped, skippedAudited, skippedTruncated,
byReason, parsed, bytesCompressed}`.

A downloaded sync source is cut off at the 500 MB upload limit. That stop is
recorded as a `catalog.sync` audit event with `outcome = 'rejected'`,
`stig_id` = the source id and `detail = {reasonCode: "download_too_large",
limitBytes, declaredBytes}`. It has no acting user: `user_id` is NULL,
`user_role` is `system`, and the audit view shows it as "system".

The sync only talks to `https://dl.dod.cyber.mil` (default port), and
re-checks that origin on every redirect hop; a source URL or redirect that
leaves it fails closed. That is recorded as `catalog.sync` /
`outcome = 'rejected'` with `detail = {reasonCode: "disallowed_origin",
stage: "source" | "redirect"}` (no URL or host). The SHA-256 of each
downloaded ZIP is logged. When the source has a `sha256` pin in
`stig-sources.toml` and the digest differs, nothing is extracted or written and
the event is `detail = {reasonCode: "checksum_mismatch", expectedSha256,
actualSha256}`.

### Signing envelope (v2)

`POST /api/sign` returns, with only `SIGNING_KEY_HEX` set (classical profile):

```json
{
  "document": { "...": "convenience copy, NOT authenticated" },
  "payload": "<base64url, no padding, of the exact signed bytes>",
  "signature": "<base64 Ed25519, legacy = signatures[0].signature>",
  "keyId": "<legacy = signatures[0].keyId>",
  "version": 2,
  "signatures": [{ "algorithm": "ed25519", "keyId": "<16 hex>", "signature": "<base64, 64 bytes>" }]
}
```

and, with `SIGNING_MLDSA87_KEY_B64` also set (hybrid profile; the legacy
top-level `signature` and `keyId` are omitted):

```json
{
  "document": { "...": "convenience copy, NOT authenticated" },
  "payload": "<base64url, no padding, of the exact signed bytes>",
  "version": 2,
  "signatures": [
    { "algorithm": "ed25519",   "keyId": "<16 hex>", "signature": "<base64, 64 bytes>" },
    { "algorithm": "ml-dsa-87", "keyId": "<32 hex>", "signature": "<base64, 4627 bytes>" }
  ]
}
```

`GET /api/signing/pubkey` returns `{algorithm, keyId, publicKey, keys:
[{algorithm, keyId, publicKey}]}`; the top-level fields are the Ed25519 key
and `keys` also lists the ML-DSA-87 key (raw FIPS 204 public key, 2592 bytes,
base64) in hybrid mode. Pin the keys from it out of band.

**Only `payload` is authenticated.** It is the compact UTF-8 JSON of the
signing document: `version`, `algorithm`, `keyId`, `signers`
(`[{algorithm, keyId}]`), `sha256`, `sha512`, `signedAt`, `signedBy`,
`signedByName`, and `resource` only when present. `algorithm` and `keyId`
equal `signers[0]`. `sha512` was added in the hybrid work; it is an additive
signed field and `sha256` is unchanged. The top-level `document`, `signature`,
`keyId` and `version` are ignored by verifiers. Verifiers never rebuild JSON:
they decode `payload` and parse those same bytes.

**Profiles.** The signed `signers` list is the profile, and exactly two are
accepted: `[ed25519]` (classical) and `[ed25519, ml-dsa-87]` (hybrid, in that
order). Anything else is rejected. EVERY listed signer must have a valid
signature (AND semantics), so removing the ML-DSA signature from a hybrid
bundle is detected; removing it and the signer entry needs an Ed25519 forgery,
because the signer list is inside the signed bytes. Key ids: Ed25519 is the
first 8 bytes of SHA-256 of the raw public key (16 hex); ML-DSA-87 is the first
16 bytes of SHA-384 over `"ml-dsa-87" || 0x00 || raw public key` (32 hex).
ML-DSA-87 is FIPS 204 pure ML-DSA with an EMPTY context string; domain
separation comes from the `SIGN_DOMAIN` prefix on the signed message below, not
from the ML-DSA context.

Hybrid signing alone gives no post-quantum protection for acceptance: a server
with both keys still accepts classical artifacts until
`SIGNING_REQUIRE_HYBRID=true` is set.

Domain separation: every signature's input is
`b"stig-viewer/sign/v2\0" || payload_bytes` (`SIGN_DOMAIN` in
`backend/src/api/signing.rs`).

Verification steps (implemented by `verify_bundle` in `signing.rs` and, as an
independent implementation, by `scripts/verify-bundle.mjs`):

1. Base64url-decode `payload` (strict, unpadded) and parse it as the signing
   document (no duplicate keys, no trailing bytes).
2. Require the signed `version` to be exactly 2.
3. Require `signers` to be non-empty, with `signers[0]` equal to the signed
   `algorithm`/`keyId`.
4. If any signer uses an algorithm you do not support, reject (never skip).
5. Require every signer to be a key you pinned, by `(algorithm, keyId)`.
6. Require the signer set to be exactly one of the two profiles above. Accept
   the classical profile only if you have not required hybrid.
7. Require the envelope's `signatures[]` to match `signers` one to one (same
   algorithm and keyId; no extras, none missing).
8. Verify every signature over `SIGN_DOMAIN || payload`.
9. Require the artifact's SHA-256 (and SHA-512 when present) to equal the
   signed values. `verify_bundle` makes this mandatory;
   `verify_bundle_document_only` skips it and binds no artifact.

v1 is detected by the absence of `version` (and of `payload`); pre-v2 bundles
are rejected and there is no legacy verification path. Export bundles do not
use this envelope.

**Independent verifier (Node 24.7+, no dependencies).**

```sh
node scripts/verify-bundle.mjs bundle bundle.json pubkey.json artifact.ckl
node scripts/verify-bundle.mjs vector testdata/signing/v2-hybrid-bundle.json
```

`pubkey.json` is the saved `GET /api/signing/pubkey` response. Pass
`--allow-classical` to accept Ed25519-only bundles. `testdata/signing/v2-hybrid-bundle.json`
is a cross-implementation test vector labelled TEST VECTOR ONLY: public keys,
signatures, negative cases, and a bundle signed by Node/OpenSSL that the Rust
verifier also accepts. The private keys were generated at runtime and
discarded. CI writes a fresh vector with the backend (default and `fips`
builds) and verifies it with this script.

Worked example (Python, `cryptography` package), **classical profile only**.
Python's `cryptography` can verify ML-DSA in recent releases, but this recipe
has not been extended or tested for it: use the Node verifier for hybrid
bundles, which a classical-only recipe like this one rejects. It uses explicit
`raise` rather than `assert` (which `python -O` strips) and strict base64:

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

The Rust verifier checks Ed25519 with AWS-LC (aws-lc-rs), which rejects
non-canonical signatures but is not dalek's `verify_strict`: it does not reject
small-order or mixed-order public keys. That is acceptable because the keys it
checks are the server's own pinned keys, never attacker-supplied ones.
OpenSSL's Ed25519 verify (used by `cryptography` and Node) may be more
permissive about non-canonical signatures; that is harmless for authenticity
here but means verifiers can disagree on malformed input.

Rollout note: external verifiers must support ML-DSA-87 and the hybrid profile
before the server starts emitting hybrid output, because the signer list is
checked strictly and unknown algorithms are rejected rather than skipped. Do not
roll the backend back to a build without ML-DSA support after enabling hybrid:
an older build cannot verify hybrid archive segments (it treats them as
definite failures and renames them `.rejected-*`) or restore hybrid backups.
ML-DSA-87 here runs in the AWS-LC module (in a `fips` build, the FIPS module)
but is a pending algorithm: no FIPS 140-3 validation of ML-DSA is claimed, and
hybrid signing is not CNSA 2.0 exclusive use.

### Database

Postgres data lives in a named volume (`postgres_data`). To reset:

```bash
docker compose down -v   # drops the volume
docker compose up
```

#### Two database roles (#84)

The server uses two roles so that the application role cannot tamper with the
audit guard (see "Database guard on the audit tables"):

- the **owner** role owns every table, sequence, the guard function and the
  schema, and runs migrations. Its URL is `DATABASE_MIGRATION_URL`.
- the **application** role (`DATABASE_URL`) gets only DML: `SELECT`, `INSERT`,
  `UPDATE`, `DELETE`, `TRUNCATE` on tables and `USAGE, SELECT, UPDATE` on
  sequences, except on the two audit tables and their sequences. On
  `rule_audit` and `audit_events` it has `SELECT`, column-level `INSERT` (never
  `id`, `occurred_at`, `repeat_count` or `last_occurred_at`),
  `UPDATE (repeat_count, last_occurred_at)` on `audit_events`, and
  `USAGE, SELECT` on their sequences: no `DELETE`, `TRUNCATE` or sequence
  `UPDATE`. It has `SELECT` only on `_sqlx_migrations`, `audit_policy` and
  `audit_restore_log`, and `EXECUTE` on the four audit functions of migration 050
  (`audit_prune_rule_audit`, `audit_prune_events`, `audit_restore_truncate`,
  `audit_restore_load`). It has no `TRIGGER`, `REFERENCES` or
  `CREATE`, so it cannot drop or disable the triggers, replace
  `audit_tables_guard()` or the audit functions, drop or alter the audit
  tables, or set `stig.audit_allow_test_mode`. It must not be a superuser, hold `CREATEROLE`,
  be a member of the owner role, or (PostgreSQL 15+) own the database.

With `DATABASE_MIGRATION_URL` set, the server migrates as the owner, re-applies
the application role's grants (after every migration run; the grant routine is
the single authority) and connects as the application role. The same can be
done out of band, which is preferred in production because it keeps the owner
credential out of the server's environment (anything that executes code in the
server process could otherwise read it; NIST CM-5):

```bash
DATABASE_URL=postgres://stig_app@db/stig DATABASE_MIGRATION_URL=postgres://stig_owner@db/stig \
  stig-viewer-backend migrate
```

`migrate` exits 0 on success, 75 (EX_TEMPFAIL) for a retryable failure (the
database is unreachable or the application role does not exist yet) and 1 for
anything else (checksum mismatch, planted objects, bad credentials, missing
URL), so a supervisor can retry only the former. Concurrent `migrate` runs are
serialised by a database advisory lock.

Without `DATABASE_MIGRATION_URL` the server behaves as before when its role
owns the schema (migrates itself; this single-role mode is for development
only, and production refuses it), and otherwise only verifies that all
migrations are applied with matching checksums, refusing to start on pending or
modified ones. At startup the server checks that its role cannot reach the
guard (superuser, `CREATEROLE`, membership of an owner role, `TRIGGER` on an
audit table, table-level `UPDATE` on an audit table outside test mode, `DELETE`,
`TRUNCATE` (outside test mode) or table-level `INSERT` on an audit table,
`UPDATE` on an audit sequence, any write on `audit_policy` or
`audit_restore_log`, and an audit function that is missing, not
`SECURITY DEFINER`, without its pinned `search_path`, owned by another role or
executable by `PUBLIC`). With
`STIG_ENV=production` it refuses to start if any of these hold; otherwise it
logs a warning. Neither URL is ever logged; if the URLs omit passwords,
`PGPASSWORD` applies to both.

Provisioning (as a superuser, once):

```sql
CREATE ROLE stig_owner LOGIN PASSWORD '...' NOSUPERUSER;
CREATE ROLE stig_app   LOGIN PASSWORD '...' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE stig OWNER stig_owner;
REVOKE ALL ON DATABASE stig FROM PUBLIC;
GRANT CONNECT ON DATABASE stig TO stig_app;
\c stig
-- PostgreSQL < 15 only: PUBLIC may create objects in the public schema.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

Upgrading an existing deployment: today's single role owns every object. Keep it
as the owner (`DATABASE_MIGRATION_URL`), create a new restricted login role
like `stig_app` above, and point `DATABASE_URL` at it. The first migrate run
grants it what it needs. If the application role's name must stay, a superuser
can move ownership instead (manual, never done automatically):

```sql
CREATE ROLE stig_owner LOGIN PASSWORD '...' NOSUPERUSER;
REASSIGN OWNED BY stig TO stig_owner;   -- run in the application database
ALTER DATABASE stig OWNER TO stig_owner;
ALTER ROLE stig NOSUPERUSER NOCREATEROLE;
```

then set `DATABASE_MIGRATION_URL` to `stig_owner` and run `migrate`.

The dev and CI compose stack does this: a one-shot `db-roles` service creates
`stig_app` (dev password only), the backend connects as `stig_app` and migrates
as `stig`. With `STIG_ENABLE_TEST_ROUTES` the owner role sets the audit test
flag, so it must be a superuser or hold the parameter grant. The backend
container runs the owner step once per start: after `migrate` succeeds, the
first server run is started without `DATABASE_MIGRATION_URL` (verify only);
later `cargo watch` restarts keep it so new migrations apply. With test routes
the owner step also sets the audit retention floor to 0, opens the audit restore
window for good and grants the test-only `UPDATE`/`TRUNCATE` on the audit tables.

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
npm run test:scripts   # dev entrypoint (migrate loop, SIGTERM)
cd backend && cargo test --no-default-features --features fips   # FIPS build (see below)
```

All application crypto goes through `backend/src/crypto` on aws-lc-rs. The
default build (`non-fips` feature) links the non-FIPS `aws-lc-sys`, needs only
a C compiler and makes no FIPS claim. The `fips` feature links the AWS-LC FIPS
module instead and the backend refuses to start unless it reports FIPS mode.
Build it with `--no-default-features --features fips` (with the default
`non-fips` also on, the build fails by design); it needs CMake, Go, Perl and a
C compiler. On macOS the module is a dylib (cargo run/test find it) and macOS
is not a validated environment.

What this does and does not establish: in a `fips` build, the Ed25519 and
ML-DSA-87 signing and verification (ML-DSA-87 only with `ML-DSA-87` in
`STIG_FIPS_PENDING_ALGS`; it is a pending algorithm, no validation claimed),
HMAC-SHA-256, SHA-256/SHA-384/SHA-512, SAML RSA signature
verification and session/identifier random generation that this application
calls run inside the module. Still outside it: TLS (rustls on ring), OIDC
ID-token verification and state/nonce/PKCE generation (RustCrypto, via
`openidconnect`; the audit token `oidc-state-nonce` covers OIDC state, nonce
and PKCE verifier generation) and Postgres SCRAM (`sqlx`). The in-module
primitives are classical except the optional ML-DSA-87 signature: FIPS mode is
not a CNSA 2.0 claim. AWS-LC-FIPS 4.x is in process
with CMVP and no certificate is confirmed, so the whole module is pending
validation, not only the post-quantum algorithms. It is not a FIPS-compliance
claim for the application.

`STIG_REQUIRE_FIPS=1` (or `true`) makes a build without the `fips` feature
refuse to start; `0`, `false` or unset leaves it off, and any other value stops
startup. It also applies to `migrate`. Set it in production only on images
built with `--no-default-features --features fips`.

At server startup (not for `migrate`) one `system.fips_policy` audit event is
written with the detail keys `fipsCompiled`, `fipsModeActive`, `requireFips`,
`appCryptoInModule` (`true` only in a `fips` build whose module check passed:
the primitives this application calls directly run in the module),
`cryptoOutsideModule` (what still does not: `tls`, `oidc-id-token-verify`,
`oidc-state-nonce`, `postgres-scram`) and `pendingAlgs` (the validated
`STIG_FIPS_PENDING_ALGS` list). A refused start has no audit row, only a
`target: "audit"` log line; if the audit write itself fails, it is logged the
same way and startup continues.

Webhook HMAC secrets shorter than 14 bytes (112 bits) are not an approved use
of HMAC under NIST SP 800-131A; the key length is not enforced (documentation
only).

## Operations: audit

- Login session and `auth.notice_ack` are not one transaction (accepted gap,
  see `notice::session_with_ack`). To reconcile, list `sessions` that have no
  `auth.notice_ack` audit row whose `detail->>'sessionId'` equals the session id.
- Catalog uploads stage the JSON to `stigs/.upload-{id}.{uuid}.tmp`, commit the
  catalog row and its audit row (`catalog.upload`, `catalog.import_library`)
  in one transaction, then rename the file into place. A crash in between leaves
  a temp; the next upload or import sweeps temps older than an hour (rolled
  forward when the catalog row matches, otherwise deleted).
- A library import is all-or-nothing in the catalog: a database failure fails
  the whole import (500) and leaves one `rejected` summary row with reason code
  `commit_failed`. Every import leaves exactly one `catalog.import_library` summary row. If a
  file cannot be renamed into place after the commit, a separate follow-up row
  is written under `catalog.import_library_publish` (single uploads use
  `catalog.upload_publish`), outcome `error`, reason code `publish_failed`;
  the next upload's sweep rolls the file forward.
- The owner step and the startup boundary check write system events (no user,
  `user_role = 'system'`): `db.migrate` (`ok` for every completed owner step,
  including no-ops, with `source`, `appliedVersions`, `schemaVersion`,
  `testRoutes`, `retentionFloorDays` and `retentionFloorPrevious` when the floor
  changed; `failure` with `source`, `stage`, `errorClass` and `sqlstate`, never
  the error text), `db.boundary_degraded` (`partial`: a non-production start
  with boundary violations, or a production start with
  `DATABASE_MIGRATION_URL` on the server) and `db.boundary_refused`
  (`rejected`: startup refused, with `reason` `violations`, `check_failed`,
  `test_mode_policy` or `migrations_unverified`). They are written
  synchronously. When no row can be written (no database connection yet, or
  `audit_events` missing) the same fields are logged on the `audit` target
  (`action=db.migrate`, `db.boundary_degraded`, `db.boundary_refused`) instead;
  the original error and exit code are never replaced.
- Durable request events live in `audit_events` (see `/api/audit/events`).
  Each row carries the user's role at the time, a server-generated request id
  (also returned in the `X-Request-Id` response header; an inbound
  `X-Request-Id` is ignored) and the source IP. Reading the audit log is itself
  recorded, as `audit.read` (view, bounded filters, page and rows returned).
  System-originated events have no user; `/api/audit/events` flags them
  `isSystem` and filters them with `actor=system`. System rows have
  `"byName": null`; `isSystem` is the authoritative field. A user whose display
  name is "system" still appears with `byName: "system"` and
  `isSystem: false`. API change (#160): `byName` used to be the literal
  `"system"` for system rows; consumers must key on `isSystem` and treat
  `byName` as nullable.
- Audit writes fail open: if a row cannot be written, the request still
  completes and the backend logs an error on the `audit` target containing
  `failed to write audit event`, with the user, action, outcome and ids. Alert
  on that line, and ship the application logs to a retained store, since it is
  the only record of an event that missed the database (AU-5). On
  `GET /api/health`, `checks.audit` is `degraded` after any such failure in the
  last 15 minutes and also reports `sustained: true` when failures span at
  least 3 distinct minutes of that window (an outage, not a blip); neither
  changes the HTTP status. Both are per replica. Check `shedWrites` on
  `GET /api/admin/failure-counters` and the "beyond the tracked set" log line
  before paging on `sustained` (colluding accounts flooding denied events, or
  a full queue, can raise it), and a replica with little audit traffic may
  never reach it, so also page on the `failed to write audit event` log line.
- Audit writes run as detached tasks, so a client that disconnects does not
  lose its event. A caller waits at most 5 s; a write still running then
  finishes on its own (counted as `lateWrites` on
  `/api/admin/failure-counters`) with a 30 s hard cap. At most 64 writes are
  pending, of which at most 16 are `denied`/`rejected` events and at most 4
  belong to one user (other events have no per-user cap); a write over a
  cap is shed and no row is written. A shed counts in `shedWrites` and logs the
  same `failed to write audit event` line (message starting `shed:`) and counts
  as a failure, except one caused by a user's own denied/rejected limit: that
  counts only in `shedWrites` (a user can trigger it at will, so it must not
  degrade the public health status). Denied/rejected sheds (both kinds) log
  at most once a minute per user, with a summary of the held-back ones; users
  beyond 32 tracked ones share one overflow bucket, and its summary line
  (`... shed for users beyond the tracked set`) means more than 32 distinct
  accounts were shed within a minute: alert on it as a collusion signal. Alert on the `shedWrites` rate and the
  failure counter, not only on the public status. Shedding is a backstop: an
  admission cap (`api::admission`) refuses audited requests before they mutate
  anything once 4 are in flight for one user (429, admins included) or 32 in
  all (503, `Retry-After: 1`). Every non-read request and the two audit GETs
  hold a permit until their audit write and any detached work finish, so the
  admitted writes fit the 48 non-restricted slots whatever `RATE_LIMIT_BURST`
  is (16 slots stay free for login acknowledgements and scheduled-sync events).
  Ordinary accounts can hold at most 28 of the 32 permits; the last 4 are for
  admins (who are still limited to 4 each). `HEAD` on the audit read routes
  counts like `GET`. A mutation by a `viewer` that the read-only gate will
  refuse takes no permit: it always gets 403 (with its `authz.denied` record,
  bounded by the rate limiter and the per-user denied limit), never 429 or 503
  (backend DB tests cover this, including at the cap; there is no browser test
  for the at-the-cap case, which would need permits held in flight and so a new
  test hook, #175). The bound is strict only while the database pool is
  healthy: a stalled audit insert can leave a request's late writes pending
  under its permit. A permit is also held while a request body is still being
  received, so bodies are rate-checked once the handler starts reading them:
  the first byte must arrive within 5 s, then the body must average at least
  64 KiB/s after a 10 s grace (a 500 MiB upload is fine at that rate); these are
  the defaults of the `ADMISSION_BODY_*` variables. A body that falls behind is
  cut off (400, permit released); the handler's work after the body has arrived
  is not limited. Time between a delivered chunk and the handler's next read is
  the handler's, so it extends the deadline (the exact arithmetic above
  therefore applies to a handler that reads without pausing). A handler that
  stops reading while the body is still being waited for is still charged, and
  an abandoned body at most 3 s. Each cut-off is counted as `bodyDeadline` on
  `/api/admin/failure-counters` and logged with the user id; 3 cut-offs
  within 60 s make that user's next requests fail with 429 for 30 s. A slow
  client behind a buffering reverse proxy never reaches the backend until the
  proxy has the whole body, which removes this vector entirely; slow links
  below 64 KiB/s will be cut off.
  A body that stays just inside those deadlines is also caught: if it spent
  more than 3 s waiting on the client in one stretch, or if the waits between
  chunks add up to more than 3 s beyond what the 64 KiB/s floor allows for each
  chunk (a chunk's credit counts only for the wait before it, never banked
  across the body), it is counted as `slowBody`, logged per user,
  and scores one penalty point (a cut-off scores two; 6 points within 60 s block
  the user for 30 s, so three cut-offs or six slow bodies do). A link averaging near
  the 64 KiB/s floor can earn such a half-weight strike. A body sent steadily at or
  above the 64 KiB/s floor is by design never slow and still holds a permit for
  its whole duration (about 160 s for 10 MiB), so about 7 accounts at about
  1.8 MB/s in all can hold the 28 non-admin permits; it is indistinguishable
  from a legitimate slow link and surfaces only through the 60 s body-wait
  warning. Stalls under 3 s
  each are not counted as slow; a user whose body-wait reaches 60 s within 60 s
  is logged, and blocks and audit-backlog changes are logged. The refusal log lines name the users with the most
  body-wait time (`top_body_wait`).
  The audit queue is watched too: while 32 or more audit writes that hold an
  admission permit and are not `denied`/`rejected` are pending (the healthy
  bound; login acknowledgements and scheduled-sync events hold no permit and
  are not counted), ordinary accounts are refused with 503
  `server busy` and `Retry-After: 5` until the count falls to 24 or fewer. Admins
  are refused only at 40 or more, so incident response survives pool contention;
  the two audited GETs are not spared. Each refusal is counted as
  `refusedBacklog` and logged as `audit_backlog`. This reduces stacking but does
  not eliminate it: requests already admitted can still leave writes pending.
  Refusals are counted on `/api/admin/failure-counters` (`admission`) and
  logged (a global or backlog refusal also names the users at their own cap) at most once a minute per reason, not written to the audit table. On SIGTERM or Ctrl-C the
  backend waits up to 8 s for open requests and pending writes; keep the
  container stop grace period above that. Production should allow at least 15 s
  of stop grace (compose `stop_grace_period: 15s`, Kubernetes
  `terminationGracePeriodSeconds`) and must deliver SIGTERM to the backend
  process itself; the dev compose file does both.
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

- `retention`: DELETE (the audit retention sweep), allowed only when the same
  transaction also sets `stig.audit_retention_protocol` to `2` (migration 047);
  older server versions never set it, so their sweeps fail with `42501` and
  delete nothing. Since migration 050 only the owner-owned function
  `audit_prune_rule_audit` / `audit_prune_events` declares it (the application
  role has no `DELETE`);
- `restore`: TRUNCATE only (a forced backup restore). Since migration 050 only
  `audit_restore_truncate` declares it;
- `migration`: UPDATE only (a data migration that backfills audit rows);

Since migration 050 (guard revision 4) `retention`, `restore` and `migration`
are honoured only when the statement runs as the owner of the audit table (or a
member of it, or a superuser): inside the `audit_prune_*` / `audit_restore_*`
functions and in owner-run migrations. The application role can still set the
settings, but they do nothing for it (42501, "honoured only for the owner").
`test` stays gated by the database flag, for any role. The startup check reports
a guard that is not revision 4.

- `test`: UPDATE and TRUNCATE (the `/api/test/*` reset and backdate routes,
  which exist only under `STIG_ENABLE_TEST_ROUTES`). Migration
  `043_audit_test_mode_flag.sql` honours it only in a database a superuser has
  flagged with `ALTER DATABASE <db> SET stig.audit_allow_test_mode = 'on'`
  (exactly `on`); otherwise it raises 42501 with a distinct message. The
  trigger reads the flag from `pg_db_role_setting`, so a session `SET` cannot
  spoof it, and only a superuser (or a holder of `GRANT SET ON PARAMETER
  stig.audit_allow_test_mode`) can set it. At startup the backend sets the flag
  only when `STIG_ENABLE_TEST_ROUTES` is on, as the owner role, which must then be a
  superuser or hold `GRANT SET ON PARAMETER stig.audit_allow_test_mode`
  (PostgreSQL 15+; on older versions only a superuser). The flag persists
  after test routes are turned off, and with test routes off the backend
  refuses to start on a flagged database in every environment until it is
  cleared with `ALTER DATABASE <db> RESET stig.audit_allow_test_mode` (or test
  routes are turned back on). Startup with test routes on writes an
  `audit.test_mode_enabled` system event (`detail.alreadySet` says whether the
  flag was already set); a running backend with test routes off re-checks the
  flag every 5 minutes (a fixed interval, not `AUDIT_RETENTION_HOURS`), logs an
  error on every detection and writes an `audit.test_mode_unexpected` system
  event (`detail.source = "scheduled_recheck"`) when the flag is first seen and
  then hourly while it stays set (audit TRUNCATE is allowed meanwhile, so one
  row could be deleted), without stopping. The flag travels with `pg_dump --create` and
  `pg_dumpall`, not with the app's JSON backup/restore.

The one update always allowed is the collapse of a repeated denial: on a
`denied` or `rejected` `audit_events` row only `repeat_count` (exactly +1) and
`last_occurred_at` (not before the row's last occurrence, not more than a
minute in the future) may change. Needing no mode, this is the only change the
application role can make to an audit row; since it can only add one to
`repeat_count` and move `last_occurred_at` forward, it cannot age a collapsed
row to get it pruned under the retention floor. The triggers are `ENABLE ALWAYS`, so
`session_replication_role = replica` does not skip them.

Retention floor (migration 050): `audit_policy.min_retain_days` (default 365,
0 to 36500) is set by the owner step from `AUDIT_RETENTION_DAYS` as the `migrate`
job sees it (0 with test routes); lowering it is recorded in the `db.migrate`
event (`retentionFloorPrevious`). The prune functions refuse the whole call
(`42501`) when any listed row is younger than the floor, and a sweep whose
`AUDIT_RETENTION_DAYS` is below the floor fails before archiving anything.

Restore window: `audit_restore_truncate` and `audit_restore_load` refuse
(`SV001`, HTTP 409 from the restore endpoint) unless the owner has opened the
window. A finite window is capped at 24 hours: a trigger on `audit_policy` rejects
a `restore_allowed_until` more than 24 hours ahead when it is set (22023;
`infinity` stays allowed for test routes), and the restore functions treat a
later one as closed at use time. Before a forced restore (or one that
carries audit rows), as the owner:

```sql
UPDATE audit_policy SET restore_allowed_until = now() + interval '30 minutes';
-- afterwards (optional, it expires by itself):
UPDATE audit_policy SET restore_allowed_until = NULL;
```

Audit rows load only into an empty table, the audit id sequences never move
backwards, and ids outside 1 to 10^12 above the current sequence value are
refused. A successful `audit_events` load closes a finite window again (an
`infinity` window, set by test routes, stays open); a forced restore always
loads both audit tables so the window closes. A truncate also refuses any table
the calling login could not truncate itself, and any call whose `CASCADE` (or inheritance/partition children) would
reach a table outside the list (the restore endpoint therefore lists every table
that references a restored one). Every truncate and load is recorded
in `audit_restore_log` (`caller` = database login, `actor` = the restoring
application user; owner write only, readable by the application role) and in
the PostgreSQL server log. The functions raise `SV001` (window closed) and
`SV002` (audit table not empty), which the restore endpoint maps to HTTP 409 and
records as a `backup.restore` event with outcome `rejected` and
`detail.reasonCode` `restore_window_closed` / `audit_tables_not_empty`; any other
error is a 500 with a fixed message. The startup check also reports an
`infinity` window, a finite window more than 24 hours ahead, or a zero retention
floor while test routes are off.

A forced restore records `backup.restore` inside the restore transaction,
re-inserting the acting admin's user row first if the backup lacks it. If the
record cannot be written the whole restore rolls back. A structured `audit`
log line is also written before the restore starts and after it commits
(including how many attachment blobs were written).

Migration authors: a migration that UPDATEs, backfills or DELETEs audit rows
fails with 42501. A data migration must first run
`SELECT set_config('stig.audit_maintenance', 'migration', true)` in its own
transaction (UPDATE only), and it works only as the owner role (the role
`migrate` runs as). Never use `test` mode in production code.

Limit: with the owner/application role split the application role cannot drop, disable or replace the guard, delete or truncate audit rows, choose the id or timestamp of a row it inserts, or `setval` the audit sequences, and it cannot change `repeat_count` or `last_occurred_at` except by the +1 collapse, so it cannot age a collapsed row to get it pruned under the floor. Retention and restore run through owner-owned `SECURITY DEFINER` functions (migration 050). What remains: code that can run SQL as the application role can insert new rows, can call the prune functions for rows older than the owner-set retention floor without archiving them, and can restore while the owner has opened a restore window; every truncate and load is recorded in `audit_restore_log`, which that role cannot change. A superuser or the owner role can always bypass the guard, and a single-role setup has no boundary; production refuses to start in that state. Ship audit rows to an external append-only store for stronger guarantees.

The database-backed tests (`task test:db`) need a superuser test role (or the
parameter grant) because they flag each test database with `ALTER DATABASE`
and create and `SET ROLE` to restricted roles.

### Integrity of audit archives and backups

With `AUDIT_ARCHIVE_ENABLED` (default on), each retention sweep writes
immutable segments to `${DATA_DIR}/audit_archive/`:
`rules-<UTC date>.<firstId>-<lastId>.jsonl` (`rule_audit`) and
`events-<UTC date>.<firstId>-<lastId>.jsonl` (`audit_events`). A segment is
written to a temp file, fsynced and published with a hard link, which never
replaces an existing file (the archive filesystem must support hard links,
otherwise retention fails closed and deletes nothing); its sidecar
`<segment>.manifest.json` is published first, so a visible segment always has
its sidecar (an orphan sidecar from a crash is ignored by the scan). At the start of each
archiving sweep, a sidecar whose segment is absent and that is at least 24 hours
old is renamed to `<sidecar>.orphan-<UTC timestamp>`, logged on the `audit`
target and recorded in the system audit event `audit_archive.file_set_aside`;
it is never deleted automatically, because it may be the only record of
a lost segment. An operator may delete an `.orphan-*` file once its id range is
still in the table or held by a verified segment; otherwise treat it as a lost
segment. Sweeps are serialized
per database by an advisory lock; a sweep that cannot get it within five
minutes fails (recorded in the scheduler log) and retries on the next tick. Rows are archived before the delete runs, and a
failed archive write deletes nothing.

After each publish the archive directory is fsynced. If the filesystem does not
support that (EINVAL or "unsupported", as on some CIFS/SMB and FUSE mounts), the
sweep fails closed: it deletes nothing and the error is recorded in the
scheduler log. Setting `AUDIT_ARCHIVE_ALLOW_UNSYNCED_DIR=true` (or `1`; any
other value leaves it off) accepts non-durable archive directory entries
instead. Each sweep that relies on it appends `DEGRADED durability` to the
`audit_retention` scheduler message and writes the system audit event
`audit_archive.durability_degraded`; prefer a filesystem that supports
directory fsync. Upgrade note: a deployment that previously ran on such a
filesystem (the old behaviour tolerated it with a log line) now fails closed
until the flag is set or the archive moves. Failing closed on an unsupported
directory fsync applies on unix only.

A file set aside as above (orphan sidecar or rejected segment) is listed, with
its old and new name, in the `audit_archive.file_set_aside` event. A move that
fails is listed there too (outcome `partial`) and counted in the scheduler
message as `archive moves FAILED: N`; the sweep itself still succeeds.
A failure of the archive tidy task itself is listed with reason
`tidy_task_failed` and counts as a failed move. These events are best effort:
they go through the shared audit write queue and may be shed under load, so the
scheduler message suffix and the `audit`-target log lines are the fallback
record.

Rolling upgrades: run `migrate` first. Once migration 047 is applied, sweeps
from older replicas fail with `42501` until those replicas are replaced; that is
expected and visible in the scheduler log. Mixed-version sweeping is
unsupported: stop pre-#82 replicas before the first new sweep, because they can
still overwrite archive files (the gate blocks their deletes, not their file
writes). Rolling a binary back after 047 leaves retention failing closed.

Upgrading to migration 050: run `migrate` before starting new servers (production
refuses to start while the application role still holds the old audit grants);
sweeps of old replicas fail closed (they can no longer `DELETE`). A deployment
with `AUDIT_RETENTION_DAYS` below 365 must pass the same value to the `migrate`
job, or sweeps fail closed (visible in the scheduler log). Forced restores now
need the owner-opened restore window. An older binary refuses a database with
migration 050; roll back by restoring a pre-migrate snapshot or with a forward
migration that drops the four functions and two tables, and re-runs migration
047's guard body to revert the guard to revision 3.

Archiving is idempotent by row id, without trusting the directory. A row is
skipped only when a segment that verifies holds the IDENTICAL serialized line
for it. "Verifies" means the sidecar exists and checks out (SHA-512, row count,
ids inside the range in the file name) and, when `SIGNING_KEY_HEX` is set, that
the signature is valid for the configured key (every signer: both keys in hybrid
mode). With a key, a planted segment
cannot pass at all. Without a key the digest is not a secret, so a planted
segment can be self-consistent; it still cannot hide a real row, because its
line would have to equal the row's actual line. A segment that fails
verification, or holds a different line, is logged on the `audit` target and its
rows are archived again (a duplicate is harmless, a lost row is not). Only a definite
verification failure (bad signature, digest, row-count or id-range mismatch, a
missing or unparseable sidecar) renames the segment and its sidecar to
`<name>.rejected-<UTC timestamp>`, keeping them as evidence (recorded in the
`audit_archive.file_set_aside` event); such files are never counted. An I/O
error, or a segment that is `unsigned` or `unknown_key` while a key is
configured, or a verified classical segment under `SIGNING_REQUIRE_HYBRID`, is
logged and not counted but left untouched (a classical segment is never a
definite failure and is never renamed). A
verified or left-in-place file is never replaced: new rows that would collide
with an existing name go to `<stream>-<date>.<first>-<last>.r<n>.jsonl`. Each
segment is read once, and the verified bytes are the bytes used. Without a key,
a warning is logged if verified segments hold different lines for one id.

After a key rotation, or when signing is switched on or off, older segments
are `unknown_key` or `unsigned` under the new configuration: they stay where
they are, the rows still in the database are archived again into new signed
segments beside them, and nothing is renamed.

Files named `<date>.jsonl` and `events-<date>.jsonl` come from earlier
versions (append mode). They are legacy: never rewritten, **unsigned**, with no
manifest, and never trusted to skip a row.

**Formats.** The sidecar and a backup's `manifest.sig.json` are envelopes:

```json
{"version":1,"type":"stig-viewer/audit-archive","payload":"<base64url>",
 "signatures":[{"algorithm":"ed25519","keyId":"...","signature":"<base64>"}]}
```

`payload` is the exact signed bytes and the only thing to trust; a verifier
decodes it and reads everything from there. For a segment it is `{type,
version, stream, file, rows, firstId, lastId, digest:{algorithm:"sha-512",
value}, signers:[{algorithm, keyId}]}`. A backup's `manifest.json` (format
version 2; version 1 is still accepted when policy allows) is the signed
payload itself, and adds `type`, `entries` (`{entry name: sha512 hex}` for every
other ZIP entry), `entriesDigest: "sha-512"` and `signers`. Every listed
signer must have a signature, and none may be extra.

**Keys and domains.** The Ed25519 key is `SIGNING_KEY_HEX` and the optional
ML-DSA-87 key is `SIGNING_MLDSA87_KEY_B64`, the same keys that sign `/api/sign`
exports. With both set, sidecars and backup signature files carry two signed
signers and two signatures (hybrid, `[ed25519, ml-dsa-87]`); the outer
`version` stays 1 and a backup manifest stays version 2. Only the two profiles
described in "Signing envelope (v2)" are accepted, every listed signer must
verify, and the restore audit detail and response gain `signatureProfile`
(`classical` or `hybrid`; absent for unsigned). The signature input is a domain prefix followed by
the payload, with a different prefix per purpose so one signature cannot be
replayed as another: `stig-viewer/audit-archive/v1\0`,
`stig-viewer/backup/v1\0` (and `stig-viewer/sign/v2\0` for exports). The signed
payload also carries a `type`. Fetch the public key from
`GET /api/signing/pubkey` and pin it offline; a key id alone proves nothing.
Ed25519 is checked with AWS-LC, which rejects non-canonical signatures but is
not dalek's `verify_strict`; the keys it checks are the server's own.

**Without `SIGNING_KEY_HEX`**, manifests carry digests only. That detects
corruption but not deliberate alteration: anyone who can edit a segment can
recompute its digest.

**Verify a segment.** (Classical profile only; the Ed25519-only recipes below
reject a hybrid artifact because they require the signer list to be exactly the
pinned Ed25519 key.) Needs Python 3 with `cryptography`; the third argument is
the pinned base64 public key. The script trusts only `payload` and
`signatures`, fails on an empty signer list, requires a valid signature for
every signer (and no others), and recomputes the SHA-512 itself. Run it as
`python3 -I verify_segment.py SEGMENT SEGMENT.manifest.json PUBKEY`:

```python
# usage: python3 -I verify_segment.py SEGMENT.jsonl SEGMENT.jsonl.manifest.json PINNED_PUBLIC_KEY_BASE64
import base64, hashlib, json, os, sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"stig-viewer/audit-archive/v1\0"
seg_path, sidecar_path, pub_b64 = sys.argv[1:4]

def fail(msg):
    sys.exit("FAIL: " + msg)

pub_raw = base64.b64decode(pub_b64)
pub = Ed25519PublicKey.from_public_bytes(pub_raw)
pinned_key_id = hashlib.sha256(pub_raw).hexdigest()[:16]

env = json.load(open(sidecar_path))
# Only `payload` and `signatures` are trusted inputs; everything else is ignored.
payload = base64.urlsafe_b64decode(env["payload"] + "=" * (-len(env["payload"]) % 4))
m = json.loads(payload)
if m.get("type") != "stig-viewer/audit-archive":
    fail("wrong type")
signers = m.get("signers") or []
if not signers:
    fail("manifest names no signers (unsigned)")
if pinned_key_id not in [s["keyId"] for s in signers]:
    fail("pinned key is not a signer")
sigs = {(s["algorithm"], s["keyId"]): s["signature"] for s in env["signatures"]}
if len(sigs) != len(env["signatures"]) or set(sigs) != {(s["algorithm"], s["keyId"]) for s in signers}:
    fail("signatures do not match the signer list")
for s in signers:
    if s["algorithm"] != "ed25519" or s["keyId"] != pinned_key_id:
        fail("signer %r cannot be verified with the pinned key" % (s,))
    try:
        pub.verify(base64.b64decode(sigs[(s["algorithm"], s["keyId"])]), DOMAIN + payload)
    except InvalidSignature:
        fail("bad signature")

body = open(seg_path, "rb").read()
if m["file"] != os.path.basename(seg_path):
    fail("manifest is for another file")
if m["digest"]["algorithm"] != "sha-512" or hashlib.sha512(body).hexdigest() != m["digest"]["value"]:
    fail("segment digest mismatch")
print("ok:", m["file"], m["rows"], "rows")
```

**Verify a backup**: `python3 -I verify_backup.py backup.zip PUBKEY`.

```python
# usage: python3 -I verify_backup.py BACKUP.zip PINNED_PUBLIC_KEY_BASE64
import base64, hashlib, json, sys, zipfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"stig-viewer/backup/v1\0"
zip_path, pub_b64 = sys.argv[1:3]

def fail(msg):
    sys.exit("FAIL: " + msg)

pub_raw = base64.b64decode(pub_b64)
pub = Ed25519PublicKey.from_public_bytes(pub_raw)
pinned_key_id = hashlib.sha256(pub_raw).hexdigest()[:16]

z = zipfile.ZipFile(zip_path)
names = z.namelist()
if len(names) != len(set(names)):
    fail("duplicate entries")
manifest_bytes = z.read("manifest.json")
env = json.loads(z.read("manifest.sig.json"))
payload = base64.urlsafe_b64decode(env["payload"] + "=" * (-len(env["payload"]) % 4))
if payload != manifest_bytes:
    fail("signed payload is not manifest.json")
m = json.loads(payload)
if m.get("type") != "stig-viewer/backup" or m.get("version") != "2":
    fail("not a version 2 backup manifest")
signers = m.get("signers") or []
if not signers:
    fail("manifest names no signers (unsigned)")
if pinned_key_id not in [s["keyId"] for s in signers]:
    fail("pinned key is not a signer")
sigs = {(s["algorithm"], s["keyId"]): s["signature"] for s in env["signatures"]}
if len(sigs) != len(env["signatures"]) or set(sigs) != {(s["algorithm"], s["keyId"]) for s in signers}:
    fail("signatures do not match the signer list")
for s in signers:
    if s["algorithm"] != "ed25519" or s["keyId"] != pinned_key_id:
        fail("signer %r cannot be verified with the pinned key" % (s,))
    try:
        pub.verify(base64.b64decode(sigs[(s["algorithm"], s["keyId"])]), DOMAIN + payload)
    except InvalidSignature:
        fail("bad signature")

if m.get("entriesDigest") != "sha-512":
    fail("unsupported entries digest")
actual = {n: hashlib.sha512(z.read(n)).hexdigest() for n in names
          if n not in ("manifest.json", "manifest.sig.json") and not n.endswith("/")}
if actual != m["entries"]:
    bad = sorted(n for n in set(actual) | set(m["entries"]) if actual.get(n) != m["entries"].get(n))
    fail("entries differ from the manifest: %r" % bad)
print("ok:", len(actual), "entries")
```

To check a digest by hand, use `sha512sum FILE` (Linux) or `shasum -a 512 FILE`
(macOS) and compare it with the digest in the decoded payload, not with any
other copy.

**Restore policy.** (The `SIGNING_REQUIRE_HYBRID` rule below is the only
addition for hybrid.) Restore checks the entry digests and the signature before
it changes the database. A signature that is present and wrong is always
rejected, as is an entry that is altered, added, missing or duplicated, and a
version 1 manifest carrying version 2 fields (a downgrade).

- When `SIGNING_KEY_HEX` is set, a restore **requires a verified signature** by
  default: unsigned, unknown-key and version 1 backups are rejected with a 400.
  Set `BACKUP_REQUIRE_SIGNATURE=false` to opt out explicitly, for example to
  migrate version 1 or unsigned backups.
- With `SIGNING_REQUIRE_HYBRID=true`, a verified classical (Ed25519-only)
  backup is also refused while a verified signature is required; the
  break-glass is the same `BACKUP_REQUIRE_SIGNATURE=false`.
- Without a key, unsigned backups are accepted (with a warning) as before.
  `BACKUP_REQUIRE_SIGNATURE=true` still requires a verified signature, which
  without a key no backup can have.
- `BACKUP_REQUIRE_SIGNATURE` accepts only `true/1/yes` or `false/0/no`, is read
  once at startup, and the backend refuses to start on any other value.

The outcome (`verified`, `unsigned` or `unknown_key`) is returned as
`signatureStatus`, shown in the admin console (a warning when not verified),
written to the pre-restore `audit` log line and recorded, with
`requireSignature`, in the `backup.restore` event's detail. A rejected restore
is also recorded, as a `backup.restore` event with `outcome = 'failure'` and
`detail = {reason, reasonCode, signatureStatus, requireSignature}` (`reasonCode` is
`entry_too_large`, `budget_exceeded`, `header_inconsistency`, `malformed` or
`invalid_backup`; `signatureStatus` is
`invalid` for a bad signature and `not_evaluated` when the backup was refused
before its signature was evaluated). Entries are read with a per-entry (1 GiB) and a
total (4 GiB) decompressed limit; `manifest.json` and `manifest.sig.json` are
capped at 16 MiB. A backup over a limit is refused with 413; one whose local
headers disagree with its central directory (or that has duplicate or
overlapping entries) is refused with 400 before the manifest is read.

With `SIGNING_KEY_HEX` set (so the default policy requires a verified
signature) a restore satisfies the intent of NIST SP 800-53 CP-9(8)
(cryptographic protection of backups) and SI-7(6) (cryptographic integrity
protection) for backups taken by this server. Without a key, or with
`BACKUP_REQUIRE_SIGNATURE=false`, it does not: digests alone detect corruption
only.

**Limits.**

- Deleting a whole segment (and its manifest) is not detectable: there is no
  chain between segments.
- Without a key, or with `BACKUP_REQUIRE_SIGNATURE=false`, whoever can modify a
  backup can also strip its signature and `signers` list.
- Key rotation: a signature made by a previous key verifies as `unknown_key`
  once `SIGNING_KEY_HEX` changes, so old backups need
  `BACKUP_REQUIRE_SIGNATURE=false` to restore. A list of trusted previous keys
  is a follow-up.
- Ed25519 alone is not quantum-safe, which matters for evidence that must stay
  trustworthy for decades. With `SIGNING_MLDSA87_KEY_B64` set, new artifacts
  are hybrid (Ed25519 and ML-DSA-87, both required). Artifacts signed before
  that stay classical and verify via the classical profile until
  `SIGNING_REQUIRE_HYBRID=true`. During the transition, stripping the ML-DSA
  half plus the signer entry needs an Ed25519 forgery, which
  `SIGNING_REQUIRE_HYBRID` closes. Do not roll back to a build without ML-DSA
  support after enabling hybrid.

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
├── docs/                 Deployment notes, runbook alerts, SSP notes
└── docker-compose.yml    Local dev stack
```

Deployment notes, runbook alerts and SSP notes are in [docs/deployment.md](docs/deployment.md).

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
`backend/src/api/notice.rs`; keep them equal. The proof is enforced at
session creation too. Login start stores the protocol values (OIDC state, nonce
and PKCE verifier, or the SAML AuthnRequest id) on the consumed acknowledgement
row. `/auth/callback` and `/auth/saml/acs` must atomically claim that row, using
the id carried in the browser's cookie plus the value the IdP echoes back
(`state`, or the signed `InResponseTo`), within 10 minutes of login start, or no
session is created. `stig_oidc_state` now holds only the acknowledgement id.
SAML sets a similar `stig_saml_req` cookie (path `/auth/saml`, `SameSite=None;
Secure` over https, `Lax` over plain http). IdP-initiated SAML responses (no
`InResponseTo`) are refused unconditionally. In plain-http dev, SAML therefore
works only with an IdP that is same-site with the API, or behind https.
Refusals are logged (`target: "audit"`, `outcome = "denied"`), not stored.

What is stored for an in-flight OIDC login, on its `login_notice_acks` row and
for at most 10 minutes: the `state` as a SHA-256 hash (it is only compared, never
read back), and the `nonce` and PKCE verifier in plaintext (the callback needs
them). The table is `UNLOGGED`, so those values never reach the WAL, replicas or
point-in-time recovery; the cost is that a crash or failover empties it and
in-flight users must acknowledge again (it fails closed; the durable record is
the `auth.notice_ack` audit event). It is not part of the application backup;
if you dump the database by hand, pass `--no-unlogged-table-data` to `pg_dump`.
The residual exposure is the plaintext nonce and verifier in the live table for
up to 10 minutes, which are of no use without an intercepted authorization code.

Auth audit events:

- Stored in `audit_events`: `auth.notice_ack`, outcome `ok` only, written when a
  login completes.
- Log-only (`target: "audit"`, not stored): `auth.notice_ack` / `issued`;
  `auth.login_start` / `denied` (reasons `rate_limited`, `missing`, `malformed`,
  `invalid`, `error`); `auth.oidc_callback` / `success` or `denied` (reasons
  `rate_limited`, `no_state_cookie`, `malformed_state_cookie`, `ack_not_claimed`,
  `claim_error`, `token_exchange`, `id_token`); `auth.saml_acs` / `success` or
  `denied` (reasons `rate_limited`, `decode`, `unsolicited`,
  `no_request_cookie`, `ack_not_claimed`, `claim_error`, plus the fixed
  validation codes of the SAML response checks).
- Removed: `auth.notice_ack` with outcome `missing` was written by the first AC-8
  release (f0b65f9) and removed by PR #56 (e0a0c9d). A login without the
  acknowledgement is now refused and appears as an `auth.oidc_callback` or
  `auth.saml_acs` `denied` line. Old `missing` rows remain in `audit_events`. A
  SIEM rule keyed on `outcome = 'missing'` will never fire again and should move
  to those `denied` lines.

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
