# Deployment notes, runbook alerts and SSP notes

Short checklist. Each fact is stated once; the long-form reference is in
[README.md](../README.md), cited by heading name. The repo ships only
`Dockerfile.dev` and a dev `docker-compose.yml`; neither is a production
manifest. Examples below are generic, use `podman`, and use placeholders only.

## 1. Before you start

- `STIG_ENV=production` turns on the startup refusals and `Secure` cookies.
- `ALLOW_TEST_AUTH_HEADER`, `STIG_ENABLE_TEST_ROUTES`, `STIG_SEED_DIR` and
  `SAML_INSECURE_SKIP_VERIFY` must be unset. The backend refuses to start with
  them only when `STIG_ENV=production` is actually set, so confirm it is.
- Set `DATABASE_URL`, `DATABASE_MIGRATION_URL`, `OIDC_INTERNAL_URL`,
  `OIDC_PUBLIC_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
  `OIDC_REDIRECT_URI` and `FRONTEND_URL` explicitly. Their defaults are
  local-dev values and must not be relied on.
- FIPS: see the FIPS notes in the README.

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
  podman run --rm -e DATABASE_URL -e DATABASE_MIGRATION_URL <image> \
    stig-viewer-backend migrate
  ```

  Exit codes: 0 success, 75 retryable, 1 failure.
- Keep the owner URL out of the server environment. Production with the owner
  URL on the server records `db.boundary_degraded`.
- Migrations are not selectable by range; `migrate` applies everything pending
  through `050_audit_owner_functions.sql`. All run as the owner role. None needs
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
  characters for the current algorithm; the length is algorithm-specific and may
  change if ML-DSA or hybrid signing is added (#66). Keep the key in a secret
  store, not a compose or env file.
- Production should set `SIGNING_KEY_HEX` and leave `BACKUP_REQUIRE_SIGNATURE`
  unset or `true`. `false` is break-glass (e.g. restoring `unknown_key`
  backups after rotation); revert it afterwards.
- With a key set, a restore needs a verified signature unless
  `BACKUP_REQUIRE_SIGNATURE=false`.
- After key rotation, old backups verify as `unknown_key`. Keep old public
  keys (from `GET /api/signing/pubkey`) offline so pre-rotation backups can
  still be checked by hand.
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
- Buffer request bodies at the proxy. That removes the slow request-body vector
  that `DeadlineBody` (`backend/src/api/admission.rs`) guards against; without
  buffering, the `ADMISSION_BODY_*` deadlines are the only control.

## 7. Shutdown

- The drain budget is 8 s from SIGTERM or Ctrl-C. Work still running at expiry
  is logged and lost.
- Use a stop grace of at least 15 s, e.g. `podman stop -t 15 <container>`.
- SIGTERM must reach the backend process itself (exec form, or an init that
  forwards signals).
- Dev compose signal handling is tracked in #147.

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
