-- Audit guard, revision 2: maintenance mode `test` (UPDATE, TRUNCATE) is
-- honoured only in a database a superuser has flagged with
--   ALTER DATABASE <db> SET stig.audit_allow_test_mode = 'on';
-- The trigger reads pg_db_role_setting (database-wide row, setrole = 0), never
-- current_setting(), so a session-level SET cannot spoof the flag. The value
-- must be exactly `on`; `true`, `1` etc. do not count. Setting the flag needs
-- superuser or GRANT SET ON PARAMETER stig.audit_allow_test_mode
-- (PostgreSQL 15+; on older versions only a superuser).
--   retention  DELETE            unchanged
--   restore    TRUNCATE          unchanged
--   migration  UPDATE            unchanged
--   test       UPDATE, TRUNCATE  only in a flagged database, else 42501
-- Guaranteed with a non-superuser application role: neither the app nor
-- injected SQL can turn `test` mode on. NOT guaranteed before the separate
-- owner role (#84): while the app role owns the tables and this function it can
-- still CREATE OR REPLACE the guard or disable the triggers.
-- The function body is otherwise identical to migration 040.
CREATE OR REPLACE FUNCTION audit_tables_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
-- Columns are read through to_jsonb so the function body also compiles for
-- rule_audit, which has no repeat_count / last_occurred_at.
DECLARE
    mode TEXT := COALESCE(current_setting('stig.audit_maintenance', true), '');
BEGIN
    IF mode = 'test' AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_db_role_setting s
        JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE d.datname = pg_catalog.current_database()
          AND s.setrole = 0
          AND 'stig.audit_allow_test_mode=on' = ANY (s.setconfig)
    ) THEN
        RAISE EXCEPTION 'audit maintenance mode "test" is not enabled for this database (% on %)', TG_OP, TG_TABLE_NAME
            USING ERRCODE = '42501',
                  HINT = 'Test databases only: a superuser runs ALTER DATABASE ... SET stig.audit_allow_test_mode = ''on''.';
    END IF;
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
