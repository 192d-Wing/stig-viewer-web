-- Database-level guard on the audit tables. `rule_audit` and `audit_events`
-- are append-only except for:
--   * the collapse UPDATE of a repeated denial (only `repeat_count`, strictly
--     increasing, and `last_occurred_at`, not moving backwards, may change),
--   * a transaction that declares a maintenance mode with
--     `SELECT set_config('stig.audit_maintenance', '<mode>', true)`:
--       retention  DELETE            (audit retention sweep)
--       restore    DELETE, TRUNCATE  (forced backup restore)
--       test       UPDATE, TRUNCATE  (E2E reset and backdating)
-- Anything else raises SQLSTATE 42501 (insufficient_privilege). This stops
-- accidents, stray queries and injected statements that do not know the mode;
-- code that can run SQL as the application role can still set it, and a DBA or
-- the table owner can disable the triggers.
CREATE FUNCTION audit_tables_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    mode TEXT := COALESCE(current_setting('stig.audit_maintenance', true), '');
BEGIN
    IF TG_OP = 'DELETE' AND mode IN ('retention', 'restore') THEN
        RETURN OLD;
    ELSIF TG_OP = 'TRUNCATE' AND mode IN ('restore', 'test') THEN
        RETURN NULL;
    ELSIF TG_OP = 'UPDATE' THEN
        IF mode = 'test' THEN
            RETURN NEW;
        END IF;
        IF TG_TABLE_NAME = 'audit_events'
           AND (to_jsonb(NEW) - 'repeat_count' - 'last_occurred_at')
               IS NOT DISTINCT FROM (to_jsonb(OLD) - 'repeat_count' - 'last_occurred_at')
           AND (to_jsonb(NEW)->>'repeat_count')::int > (to_jsonb(OLD)->>'repeat_count')::int
           AND to_jsonb(NEW)->>'last_occurred_at' IS NOT NULL
           AND (to_jsonb(OLD)->>'last_occurred_at' IS NULL
                OR (to_jsonb(NEW)->>'last_occurred_at')::timestamptz
                   >= (to_jsonb(OLD)->>'last_occurred_at')::timestamptz)
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
