# Backups & Restore

Postgres holds three tables that matter for disaster recovery:

| Table            | Content                                            | Can be rebuilt?           |
| ---------------- | -------------------------------------------------- | ------------------------- |
| `stigs_catalog`  | One row per ingested STIG with metadata + path.    | Yes — re-ingest uploads.  |
| `audit_log`      | Append-only record of uploads and auth events.     | No — irreplaceable.       |
| `workspaces`     | Per-user asset info + rule overrides.              | No — reviewer state.      |

The `data/stigs/` directory on disk holds the parsed JSON blobs referenced
by `stigs_catalog.json_path`. A backup that captures only the database
without that directory will leave broken references.

## What to back up

- The whole Postgres database (all three tables at a consistent snapshot).
- The `$DATA_DIR` tree (default `data/`), which contains the STIG JSON files.

## Taking a backup

### Logical dump (recommended)

`pg_dump` gives you a point-in-time, self-contained dump that restores
cleanly across minor Postgres versions.

```bash
# Dump the database. The custom format (-Fc) is compressed and restorable
# with pg_restore in any order the DBA wants.
pg_dump \
  --host=localhost --port=5432 \
  --username="$POSTGRES_USER" \
  --format=custom \
  --file="stig-viewer-$(date +%Y%m%dT%H%M%S).dump" \
  "$POSTGRES_DB"

# Mirror the data directory the backend writes STIG JSON into.
tar czf "stig-data-$(date +%Y%m%dT%H%M%S).tar.gz" -C /path/to/stig-viewer data/
```

Hold both artifacts together — they're useless separately.

### Cron example

A nightly host-crontab entry that keeps 14 days of backups:

```cron
# m h dom mon dow  command
15 2 * * * PGPASSWORD="$PGPASSWORD" \
  /usr/bin/pg_dump --host=db --username=stig --format=custom \
  --file=/var/backups/stig-viewer/db-$(date +\%Y\%m\%d).dump stig_viewer && \
  tar czf /var/backups/stig-viewer/data-$(date +\%Y\%m\%d).tar.gz -C /srv/stig-viewer data && \
  find /var/backups/stig-viewer -mtime +14 -delete
```

Run this as a user with read access to `$DATA_DIR`. On Kubernetes the
equivalent is a `CronJob` with the `pg_dump` image sidecar'd to the
Postgres service; the `data/` volume must be readable by that pod.

## Restoring

1. Stop the backend so no writes race the restore.

   ```bash
   docker compose stop app       # or: systemctl stop stig-viewer
   ```

2. Create an empty target database if it doesn't already exist.

   ```bash
   createdb --host=localhost --username=postgres stig_viewer
   ```

3. Restore the logical dump with `pg_restore`. `--clean` drops existing
   objects first so a partial restore against a stale DB still converges.

   ```bash
   pg_restore \
     --host=localhost --username=postgres \
     --dbname=stig_viewer \
     --clean --if-exists \
     path/to/stig-viewer-YYYYMMDDTHHMMSS.dump
   ```

4. Extract the `data/` archive on top of the current `$DATA_DIR`.

   ```bash
   tar xzf path/to/stig-data-YYYYMMDDTHHMMSS.tar.gz -C /path/to/stig-viewer
   ```

5. Start the backend. Migrations are idempotent; they'll no-op on a
   restored database but verify the schema version.

   ```bash
   docker compose up -d app
   ```

6. Smoke-test:

   - `curl -f http://host:8080/api/readyz` returns 200 with a `ready` body.
   - `curl http://host:8080/api/health` returns a `stig_count` that
     matches the row count in `stigs_catalog`.
   - Log in and open one STIG you know has workspace state. The asset
     info and rule overrides should match what the reviewer last saved.

## Retention

Audit log rows are kept forever by default — they're the primary artifact
for the "who did what, when" question. If you need to prune for size,
archive older rows elsewhere (S3, Glacier) before deleting:

```sql
COPY (SELECT * FROM audit_log WHERE created_at < NOW() - INTERVAL '1 year')
  TO '/var/archive/audit-2024.csv' CSV HEADER;
DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL '1 year';
```

## Known gaps

- No point-in-time recovery (PITR). Add WAL archiving + `recovery.conf`
  if RPO < 24 hours is required.
- `data/stigs/*.json` is captured via `tar`, not snapshotted. If the
  directory is actively being written during backup (live upload, live
  DISA sync) you may get a partial file. Run the backup during a quiet
  window or snapshot the filesystem first.
- Backups are not encrypted at rest. If they leave the host, pipe through
  `age` or `gpg` on the way out.
