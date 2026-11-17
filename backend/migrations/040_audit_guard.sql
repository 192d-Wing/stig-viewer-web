-- Database-level guard on the audit tables. `rule_audit` and `audit_events`
-- are append-only except for:
--   * the collapse UPDATE of a repeated denial: only `repeat_count` (exactly
--     +1) and `last_occurred_at` (not before the row's last occurrence, not in
--     the future) change, on a `denied` or `rejected` `audit_events` row;
--   * a transaction that declares a maintenance mode with
--     `SELECT set_config('stig.audit_maintenance', '<mode>', true)`:
--       retention  DELETE            (audit retention sweep)
--       restore    TRUNCATE          (forced backup restore)
--       migration  UPDATE            (a data migration that backfills audit rows)
--       test       UPDATE, TRUNCATE  (E2E reset and backdating; never in production code)
-- Anything else raises SQLSTATE 42501 (insufficient_privilege).
--
-- NOTE FOR MIGRATION AUTHORS: a migration that UPDATEs, backfills or DELETEs
-- rows of these tables fails with 42501. A data migration must run
-- `SELECT set_config('stig.audit_maintenance', 'migration', true)` in its own
-- transaction first (UPDATE only; there is no mode for DELETE in a migration).
--
-- This stops accidents, stray queries and injected statements that do not know
-- the mode. Code that can run SQL as the application role can still set it,
-- and a DBA or the table owner can disable the triggers.
CREATE FUNCTION audit_tables_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
-- Columns are read through to_jsonb so the function body also compiles for
-- rule_audit, which has no repeat_count / last_occurred_at.
DECLARE
    mode TEXT := COALESCE(current_setting('stig.audit_maintenance', true), '');
BEGIN
    IF TG_OP = 'DELETE' AND mode = 'retention' THEN
        RETURN OLD;
    ELSIF TG_OP = 'TRUNCATE' AND mode IN ('restore', 'test') THEN
        RETURN NULL;
    ELSIF TG_OP = 'UPDATE' THEN
        IF mode IN ('test', 'migration') THEN
            RETURN NEW;
        END IF;
        IF TG_TABLE_NAME = 'audit_events'
           AND to_jsonb(OLD)->>'outcome' IN ('denied', 'rejected')
           AND (to_jsonb(NEW) - 'repeat_count' - 'last_occurred_at')
               IS NOT DISTINCT FROM (to_jsonb(OLD) - 'repeat_count' - 'last_occurred_at')
           AND (to_jsonb(NEW)->>'repeat_count')::int = (to_jsonb(OLD)->>'repeat_count')::int + 1
           AND to_jsonb(NEW)->>'last_occurred_at' IS NOT NULL
           AND (to_jsonb(NEW)->>'last_occurred_at') NOT IN ('infinity', '-infinity')
           AND (to_jsonb(NEW)->>'last_occurred_at')::timestamptz
               >= COALESCE((to_jsonb(OLD)->>'last_occurred_at')::timestamptz,
                           (to_jsonb(OLD)->>'occurred_at')::timestamptz)
           AND (to_jsonb(NEW)->>'last_occurred_at')::timestamptz <= pg_catalog.now() + INTERVAL '1 minute'
        THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION '% on % is not permitted outside audit maintenance', TG_OP, TG_TABLE_NAME
        USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER rule_audit_guard_row BEFORE UPDATE OR DELETE ON rule_audit
    FOR EACH ROW EXECUTE FUNCTION audit_tables_guard();
CREATE TRIGGER rule_audit_guard_truncate BEFORE TRUNCATE ON rule_audit
    FOR EACH STATEMENT EXECUTE FUNCTION audit_tables_guard();
CREATE TRIGGER audit_events_guard_row BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_tables_guard();
CREATE TRIGGER audit_events_guard_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_tables_guard();

-- Fire even under session_replication_role = replica.
ALTER TABLE rule_audit   ENABLE ALWAYS TRIGGER rule_audit_guard_row;
ALTER TABLE rule_audit   ENABLE ALWAYS TRIGGER rule_audit_guard_truncate;
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard_row;
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard_truncate;
