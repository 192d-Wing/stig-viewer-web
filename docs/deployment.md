# Deployment notes, runbook alerts and SSP notes

Short checklist. Each fact is stated once; the long-form reference is in
[README.md](../README.md), cited by heading name. The repo ships a production
`Containerfile` (section 10), plus `Dockerfile.dev` and a dev
`docker-compose.yml`; the latter two are not production manifests. Examples
below are generic, use `podman`, and use placeholders only.

## 1. Before you start

- `STIG_ENV=production` turns on the startup refusals and `Secure` cookies.
- `ALLOW_TEST_AUTH_HEADER`, `STIG_ENABLE_TEST_ROUTES`, `STIG_SEED_DIR` and
  `SAML_INSECURE_SKIP_VERIFY` must be unset. The backend refuses to start with
  them only when `STIG_ENV=production` is actually set, so confirm it is.
- Set `DATABASE_URL`, `DATABASE_MIGRATION_URL`, `OIDC_INTERNAL_URL`,
  `OIDC_PUBLIC_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
  `OIDC_REDIRECT_URI` and `FRONTEND_URL` explicitly. Their defaults are
  local-dev values and must not be relied on.
- FIPS: build with `--no-default-features --features fips` and set
  `STIG_REQUIRE_FIPS=1`. That runs the application's own Ed25519, HMAC,
  SHA-2, SAML RSA verification and session RNG inside the AWS-LC FIPS module
  (pending CMVP; no certificate), and outbound TLS (webhooks, OIDC, DISA
  sync, SMTP STARTTLS). OIDC ID-token verification and state/nonce, and
  Postgres SCRAM stay outside it. A FIPS build offers only classical
  (P-384, P-256) outbound TLS key exchange unless
  `STIG_FIPS_PENDING_ALGS=X25519MLKEM768,ML-KEM-1024` is set; set it to get
  the hybrid and `ML-KEM-1024` groups (pending validation). The in-module algorithms
  are classical; under CNSA 2.0 the IdP signing key should be RSA of at least
  3072 bits. See the README FIPS notes.

## 2. Database roles and migrations

- The owner role is `DATABASE_MIGRATION_URL`; the app role is `DATABASE_URL`.
  Provisioning SQL: README "Two database roles".
- The owner and app roles must have distinct passwords. Supply the full URLs
  to the `migrate` job from a secret store (e.g. podman secrets exposed as env
  vars `DATABASE_URL` and `DATABASE_MIGRATION_URL` for that job only). Never
  give the server the owner credential.
- Run the owner step out of band. The example passes both URLs from the job's
  environment (or use `--secret <name>,type=env,target=DATABASE_MIGRATION_URL`):

  ```
  podman run --rm -e DATABASE_URL -e DATABASE_MIGRATION_URL <image> migrate
  ```

  Exit codes: 0 success, 75 retryable, 1 failure.
- Keep the owner URL out of the server environment. Production with the owner
  URL on the server records `db.boundary_degraded`.
- Migrations are not selectable by range; `migrate` applies everything pending
  through `051_saml_replay_cache.sql`. All run as the owner role. None needs
  a superuser in production.

| Migration | Operator note |
|---|---|
| 037, 041 | `login_notice_acks` is transient and excluded from the app backup. |
| 038, 039, 042, 044, 045, 048, 049 | Schema only, no action. |
| 040 | Audit tables become append-only (guard). A later data migration touching audit rows must run as owner in `migration` mode. |
| 043 | The `stig.audit_allow_test_mode` flag is for test routes only. The backend refuses to start on a flagged database with test routes off. Clear with `ALTER DATABASE <db> RESET stig.audit_allow_test_mode`. |
| 046 | The table becomes `UNLOGGED`: in-flight logins re-acknowledge after a crash or failover. Pass `--no-unlogged-table-data` to a manual `pg_dump`. |
| 047 | Run `migrate` first. Sweeps from older replicas fail closed with `42501`. Stop pre-#82 replicas before the first new sweep. |
| 050 | Requires the owner/app split. Run `migrate` before starting new servers. Pass the same `AUDIT_RETENTION_DAYS` to the `migrate` job if it is below 365. Forced restores need the owner-opened window. An older binary refuses a database at 050. |
| 051 | `saml_seen_ids` (SAML replay cache) is transient and excluded from the app backup. Schema only, no action. |

- The retention floor `audit_policy.min_retain_days` is set by the owner step
  from `AUDIT_RETENTION_DAYS` as the `migrate` process sees it (default 365).
- Restore window, as owner:
  `UPDATE audit_policy SET restore_allowed_until = now() + interval '30 minutes';`
  Capped at 24 hours; refusals are HTTP 409 (`SV001`, `SV002`). Close it as
  soon as the restore finishes: `UPDATE audit_policy SET restore_allowed_until = NULL;`
  (NULL is the closed state). `infinity` is accepted only for test routes;
  never set it outside test databases. Every truncate
  and load is recorded in `audit_restore_log`.
- Residual: the app role can still prune rows older than the floor and restore
  inside an open window. See README "Database guard on the audit tables".

## 3. STIG data volume

- Mount persistent storage at `DATA_DIR` (default `data`, relative to cwd). It
  holds STIG JSON, drafts, attachments and `audit_archive/`.
- The archive filesystem must support hard links and directory fsync, or set
  `AUDIT_ARCHIVE_ALLOW_UNSYNCED_DIR=true`.
- Example: `podman volume create stig_data`, then
  `-v stig_data:/data -e DATA_DIR=/data`.
- `STIG_SEED_DIR` is dev-only and stays unset in production; it is not the
  persistent volume.

## 4. DISA sync

- `STIG_SYNC_ON_START` (on unless `false` or `0`) and
  `STIG_SYNC_INTERVAL_HOURS` (default 24; use 1 or more).
- A large interval alone does not skip the boot sync.
- Air-gapped sites: set `STIG_SYNC_ON_START=false` with a large interval and
  load STIGs by admin upload.

## 5. Signing and restore

- `SIGNING_KEY_HEX` (`<64-hex-chars>`; unset means signing is off) and
  `BACKUP_REQUIRE_SIGNATURE`. The key is the 32-byte Ed25519 seed as 64 hex
  characters. Keep keys in a secret store, not a compose or env file.
- Hybrid (Ed25519 + ML-DSA-87) signing, optional:
  - `SIGNING_MLDSA87_KEY_B64`: base64 PKCS#8 ML-DSA-87 private key. Generate
    one with `stig-viewer-backend gen-mldsa-key` (a `fips` build needs
    `STIG_FIPS_PENDING_ALGS=ML-DSA-87` for this too). The key goes to stdout
    and its key id to stderr; nothing is logged or stored, so capture stdout
    straight into the secret store. `openssl genpkey -algorithm ML-DSA-87`
    output (PKCS#8 DER, base64) also loads.
  - With both keys, `/api/sign` bundles, audit archive manifests and backup
    manifests carry both signatures, and verifiers need both to accept. ML-DSA
    alone, or a malformed key, stops startup; a failed ML-DSA operation fails
    the request or write and never falls back to Ed25519-only output.
  - In a `fips` build, the ML-DSA key requires `ML-DSA-87` in
    `STIG_FIPS_PENDING_ALGS`, otherwise startup fails. ML-DSA-87 runs in the
    AWS-LC module there but is a pending algorithm: no validation is claimed.
  - **Hybrid signing alone gives no post-quantum protection for acceptance.**
    A server with both keys still verifies and accepts classical (Ed25519-only)
    artifacts by default, so a forger of Ed25519 can still produce an
    acceptable artifact until `SIGNING_REQUIRE_HYBRID=true` is set.
  - `SIGNING_REQUIRE_HYBRID=true` (default false) refuses to start without both
    keys and makes restore (and the archive duplicate check) refuse a verified
    Ed25519-only artifact. Break-glass for restore is
    `BACKUP_REQUIRE_SIGNATURE=false`.
  - External verifiers must pin the keys from the `GET /api/signing/pubkey`
    JSON obtained out of band (not from the bundle or the same channel as the
    artifact), and must not use `--allow-classical` once
    `SIGNING_REQUIRE_HYBRID` is deployed.
  - Run `gen-mldsa-key` with stdout redirected to a file or secret store (it
    refuses to print to a terminal). Do not run it where a log driver captures
    stdout, for example `podman run` without redirection.
  - Enabling order: (1) update external verifiers to
    `scripts/verify-bundle.mjs` or equivalent, pinning both keys from
    `GET /api/signing/pubkey`; (2) set `SIGNING_MLDSA87_KEY_B64` and restart;
    (3) once old classical artifacts no longer need restoring or counting, set
    `SIGNING_REQUIRE_HYBRID=true`.
  - Do not roll back to a build without ML-DSA support after enabling hybrid:
    it cannot verify hybrid archive segments (it renames them `.rejected-*`)
    or restore hybrid backups. Remove the ML-DSA key (back to classical) on
    the new build instead; existing hybrid artifacts then verify as
    `unknown_key`.
- Production should set `SIGNING_KEY_HEX` and leave `BACKUP_REQUIRE_SIGNATURE`
  unset or `true`. `false` is break-glass (e.g. restoring `unknown_key`
  backups whose key is no longer listed); revert it afterwards.
- With a key set, a restore needs a verified signature unless
  `BACKUP_REQUIRE_SIGNATURE=false`.
- **Key rotation runbook** (old archives, backups and `/api/sign` bundles keep
  verifying through `SIGNING_PREVIOUS_KEYS_FILE`, or `SIGNING_PREVIOUS_KEYS_JSON`
  for env-only deployments; set at most one):
  1. Save the `keys` array of `GET /api/signing/pubkey` and store it offline.
  2. Generate the new keys (`SIGNING_KEY_HEX` seed; `gen-mldsa-key > key.b64`).
  3. Add the saved `keys` as a new entry of the previous-keys file
     (`{"version": 1, "previous": [{"label": "prod-2026a", "retiredAt":
     "2026-11-30", "keys": [...]}]}`). If the old Ed25519 key also signed
     classical artifacts that must keep verifying, add a second, classical entry
     for it and understand the trade-off: a hybrid entry never makes its
     Ed25519 key a classical signer, and a classical entry keeps the
     Ed25519-only forgery window open for that key. Never put a private key in
     the file (a pasted seed stops startup).
  4. Update external verifiers' pinned sets (`verify-bundle.mjs --previous`)
     BEFORE the swap: they need both old and new keys.
  5. Swap the key variables and restart. Check the startup log and the
     `system.signing_keys` audit event (key ids, previous sets, SHA-384 of the
     document).
  6. Verify: restore-check an old backup on a scratch instance (the response
     says `signatureKeySource: "previous"`), let one retention sweep run (no new
     `.r<n>` siblings for old dates and an `audit_archive.previous_key_verified`
     event), and verify an old bundle with `verify-bundle.mjs`.
  7. Retire: remove the entry. Artifacts then become `unknown_key`: backups need
     the break-glass override, archive segments are left in place and rows still
     in the database are archived again. For a compromised key remove it
     immediately and add it to `revoked` with a reason and date (never
     "verified", never renamed). Destroy the old private keys after step 6.
  Auditing: backups and archive segments are verified on the server, which
  records the key source, key ids and label (`backup.restore`,
  `audit_archive.previous_key_verified`). `/api/sign` bundles are verified
  offline (`scripts/verify-bundle.mjs` reports `verifiedBy`), so no server audit
  row names the key that verified a bundle. The previous-keys file has a
  `version`; a new algorithm (for example SLH-DSA) would arrive as a new
  `version`, never as extra fields in version 1 (unknown fields are refused).
  Previous-set labels and `retiredAt` are served publicly by
  `GET /api/signing/pubkey`.
  Rollback: an older binary ignores the variables and treats old artifacts as
  `unknown_key`; it renames nothing. Previous keys require `SIGNING_KEY_HEX`
  (startup error otherwise), and a hybrid previous set in a `fips` build needs
  `ML-DSA-87` in `STIG_FIPS_PENDING_ALGS`.
- Forced audit restores also need the restore window from section 2. See the
  **Restore policy** paragraph in README "Integrity of audit archives and
  backups", and "Signing envelope (v2)".

## 6. Reverse proxy

- `STIG_TRUST_PROXY_HEADERS=true` and `STIG_TRUSTED_PROXY_HOPS` (default 1).
  The proxy must append the client address to `X-Forwarded-For`; the Nth entry
  from the right is used. Set `STIG_TRUSTED_PROXY_HOPS` to exactly the number
  of proxies you control that append to `X-Forwarded-For`; never higher, or the
  chosen entry is client-supplied.
- The backend port must be reachable only from those proxies (bind or
  firewall); otherwise the whole header is client-supplied. Consequence: an
  attacker can rotate apparent IPs to evade the per-IP auth rate limit and
  forge audit `source_ip`.
- Without it, every client shares one auth rate-limit bucket and audit
  `source_ip` is the proxy address.
- Serve frontend and API same-site (the ack cookie is `SameSite=Strict`; if the browser does not send it, the
  login start has no proof of the notice acknowledgement and no session is
  created without a claimed ack).
- Terminate TLS at the proxy or ingress; the backend speaks plain HTTP and the
  image requires it (cookies are `Secure` under `STIG_ENV=production`). With
  `STIG_ENV=production` the backend also sends
  `Strict-Transport-Security: max-age=31536000; includeSubDomains` on the
  static frontend responses, so serve the whole site over HTTPS only.
- Where the TLS terminator supports it, offer a hybrid post-quantum key
  exchange group: `X25519MLKEM768`, or `SecP384r1MLKEM1024` for CNSA 2.0
  profiles. Do not pin classical-only groups (for example `X25519` or
  `secp256r1` alone): that blocks the hybrid groups and leaves traffic open to
  harvest-now-decrypt-later capture. See #66.
- Buffer request bodies at the proxy. That removes the slow request-body vector
  that `DeadlineBody` (`backend/src/api/admission.rs`) guards against; without
  buffering, the `ADMISSION_BODY_*` deadlines are the only control.

## 7. Shutdown

- The drain budget is 8 s from SIGTERM or Ctrl-C. Work still running at expiry
  is logged and lost.
- Use a stop grace of at least 15 s, e.g. `podman stop -t 15 <container>`.
- SIGTERM must reach the backend process itself (exec form, or an init that
  forwards signals).
- The production image uses an exec-form `ENTRYPOINT`, so SIGTERM reaches the
  backend. Dev compose signal handling is tracked in #147.

## 8. Runbook: alerts

Authoritative AU-5(2) signal: a log alert on the substring
`failed to write audit event` (target `audit`, level ERROR). Logs are plain
`tracing_subscriber::fmt` text, so match the substring. This depends on the plain-text fmt format; revisit it
if JSON logging is enabled.

Recommended starting thresholds (tunable; not enforced in code): ticket on any
occurrence; page when it appears in 3 or more distinct minutes within 15
minutes across the fleet.

Variants:

- `failed to write audit event: shed: ...`: the queue shed the write; no row
  exists.
- `failed to write audit event: the change was rolled back: ...`: a
  transactional write failed closed. The change was not made, so no event is
  missing, but audit capability is impaired.
- `failed to write audit event: timed out after ...`: the hard cap; the row may
  still have committed.
- Other suffixes are raw database errors; the alert matches the prefix
  regardless.

Ship logs to a retained store; the log line is the only record of an event
that missed the database.

Why not the counters: `GET /api/health` `checks.audit` and
`GET /api/admin/failure-counters` `audit.*` are in-process, per replica, and
reset on restart. A restart or load-balancer hop can hide a failure, and a
low-traffic replica may never reach `sustained`. Use them for triage. No
exporter exists.

Secondary alerts:

- `... more denied events shed for users beyond the tracked set`: collusion
  signal.
- WARN on target `audit`, `request refused: too many audited requests in
  flight`, field `reason` = `global_cap`, `audit_backlog` or `user_cap`.
  Throttled to one line per reason per replica per 60 s, with a `suppressed`
  count. Recommended starting values (tunable): ticket on any `global_cap` or
  `audit_backlog` line; page when such lines appear in 3 or more distinct
  minutes within 15, or `suppressed` is non-zero on consecutive lines.
- Optional poll: an increase in `admission.refusedGlobal` or
  `admission.refusedBacklog` on the admin endpoint (per replica; a decrease
  means a restart). Refusals never change `/api/health`.

Triage order: `shedWrites`, the collusion line, `pendingWrites` and
`lateWrites`, then database pool health.

## 9. SSP narrative notes

- **AU-5 / AU-5(2).** Audit writes fail open, except transactional ones, which
  roll back. The application emits the log line; the real-time alert is
  provided by the deployment's log pipeline, so the control is satisfied only
  when that alert is configured. In-process counters and `sustained` are per
  replica and reset on restart; they are not the control.
- **SC-5 / AU-5 residual.** Audit-backlog refusal starts at 32 pending
  permit-holding writes for non-admins, releases at 24, and applies to admins
  at 40. It damps the backlog but does not strictly bound pending audit writes:
  requests already admitted can still stack writes, admins continue up to 40,
  and the bound holds only while the DB pool is healthy. The hard stop is the
  64-write queue cap, beyond which writes are shed and logged.
- **SC-5.** A buffering reverse proxy is the primary control for slow-body
  exhaustion; `DeadlineBody` is the fallback.
- **AU-9 / AU-9(4) / CM-5.** The owner/app role split keeps the app role from
  dropping the audit guard or deleting audit rows. The documented remainder is
  in README "Database guard on the audit tables" (limit paragraph): the app
  role can insert rows, prune below the floor, and restore in an open window;
  the owner or a superuser can always bypass the guard.

## 10. Container image

`Containerfile` at the repo root builds one image: the backend plus the release
wasm frontend, which the backend serves same-origin from memory
(`STIG_STATIC_DIR=/app/static`; the frontend is built with an empty `API_URL`,
so every request is relative).

- Stages and bases, all pinned by multi-arch index digest and overridable:
  `frontend` (`rust:<ver>-slim-trixie`, builds the wasm bundle with Trunk; UBI
  has no wasm32 std), `backend` (`ubi10/ubi`, Red Hat's Rust RPMs) and
  `runtime` (`ubi10/ubi-micro`, no `RUN` steps). Trunk, `wasm-bindgen` (the
  version in `frontend/Cargo.lock`) and `wasm-opt` (binaryen) are release
  tarballs verified with `sha256sum -c` per architecture, and Trunk runs with
  `TRUNK_OFFLINE=true`, so it fetches nothing else during the build. The Rust
  version in the backend stage floats with UBI AppStream (the base digest does
  not pin dnf content); the build asserts it meets the `rust-version` in
  `backend/Cargo.toml`. The image carries `/app/BUILD-INFO` with the
  `rustc`, `cargo`, `gcc`, `clang` and `go` versions and the `aws-lc-*` crate
  versions it was built with.
- Base image digests are refreshed by hand (Dependabot is not configured for
  `Containerfile`): all three, including `rust:<ver>-slim-trixie`, using the
  commands in the `Containerfile` header (registry `docker-content-digest` of
  the index, then `podman manifest inspect` to confirm amd64 and arm64).
- Build (`--format docker` is needed to keep the `HEALTHCHECK`):

  ```
  podman build --format docker -t <image> -f Containerfile .
  podman build --format docker --build-arg CRYPTO=fips -t <image>-fips -f Containerfile .
  ```

  Add `--build-arg BUILD_JOBS=2` on a small build machine.
- Iron Bank or other hardened bases: `podman login registry1.dso.mil`, then
  `--build-arg BACKEND_BUILD_BASE=<ubi10 path>@sha256:...` and
  `--build-arg RUNTIME_BASE=<ubi10-micro path>@sha256:...`. The paths are for
  the operator to fill in. This only swaps base images; it is not an Iron Bank
  submission, which is a separate offline pipeline.
- Health: the image `HEALTHCHECK` runs `<binary> healthcheck` (a local
  `GET /api/health`, exit 0 only on 200; needs no database config). For an
  OCI-format image use `podman run --health-cmd` with the same command.
  Kubernetes ignores `HEALTHCHECK`; use an `httpGet` probe on `/api/health`.
- Migrate, then serve. The migrate job gets both URLs; the server gets only
  `DATABASE_URL` (placeholders; inject secrets, for example with
  `--secret <name>,type=env,target=DATABASE_URL`):

  ```
  podman run --rm -e DATABASE_URL -e DATABASE_MIGRATION_URL <image> migrate
  podman run -d --read-only --read-only-tmpfs=false --cap-drop=ALL \
    --security-opt no-new-privileges -v stig_data:/data -p 8080:8080 \
    -e DATABASE_URL -e OIDC_INTERNAL_URL -e OIDC_PUBLIC_URL -e OIDC_CLIENT_ID \
    -e OIDC_CLIENT_SECRET -e OIDC_REDIRECT_URI -e FRONTEND_URL <image>
  ```

  Giving the server `DATABASE_MIGRATION_URL` still works but is the
  discouraged fallback (section 2). Set `FRONTEND_URL` to the public origin;
  `STIG_ENV=production` is baked in, so cookies are `Secure` and the image
  must sit behind TLS.
- `STIG_STATIC_DIR` must contain only the public frontend bundle: everything in
  it is served without authentication, and hashed files get `public` caching.
  Never point it at a directory with data, uploads or secrets.
- Read-only root filesystem: the only writable path is `/data` (a volume).
  `/app`, the binary and the static files are read-only; no tmpfs is needed.
- User: numeric `1001:0` (no passwd entry). `/data` is mode 0770, group 0, so
  an arbitrary uid with gid 0 also works. A named volume inherits that
  ownership on first use; bind mounts need `:U` or a matching chown;
  Kubernetes uses `runAsUser: 1001` or `fsGroup: 0`.
- FIPS: the `fips` build links AWS-LC-FIPS statically into the binary. UBI
  supplies only glibc, `libgcc_s` and the loader, so a FIPS-mode RHEL host or
  UBI's own OpenSSL and crypto policies neither change this application's
  crypto nor add to its FIPS claim. AWS-LC-FIPS is pending CMVP with no
  certificate (#201). The FIPS build covers only classical
  algorithms: ML-KEM and ML-DSA are not inside the FIPS boundary here (see #66). `STIG_REQUIRE_FIPS=1` is not baked in; set it in the
  deployment so a wrongly deployed non-FIPS image refuses to start.
- Trust roots: the backend uses bundled `webpki-roots`; `ubi-micro` has no OS
  CA bundle, and an IdP with a DoD-issued certificate fails OIDC discovery
  (pre-existing, tracked separately).
- Check the image with `scripts/smoke-prod-image.sh` (`CRYPTO=fips` for the
  FIPS variant), which uses throwaway `svw-prod-smoke-*` resources on port
  28080.
