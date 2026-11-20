-- Audit guard, revision 3: a retention DELETE is allowed only when the same
-- transaction also set stig.audit_retention_protocol to exactly '2' (set by
-- audit_retention::declare_retention_delete). Older server versions never set
-- it, so a mixed-version fleet fails closed: their sweeps get 42501 and delete
-- nothing, instead of racing a newer replica's archive publish (#116).
--   retention  DELETE            only with protocol marker '2', else 42501
--   restore    TRUNCATE          unchanged
--   migration  UPDATE            unchanged
--   test       UPDATE, TRUNCATE  unchanged (flagged database only)
-- The marker is a version gate, not a security boundary: SQL running as the
-- app role can set it, just as it can already declare `retention`.
-- Everything else is identical to migration 043.
-- Rollback: a new migration that re-runs the CREATE OR REPLACE FUNCTION from
-- migration 043 restores the previous guard (never edit this file).
CREATE OR REPLACE FUNCTION audit_tables_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
-- Columns are read through to_jsonb so the function body also compiles for
-- rule_audit, which has no repeat_count / last_occurred_at.
DECLARE
    mode TEXT := COALESCE(current_setting('stig.audit_maintenance', true), '');
    c_repeat CONSTANT TEXT := 'repeat_count';
    c_last CONSTANT TEXT := 'last_occurred_at';
    c_denied CONSTANT TEXT := '42501';
    proto TEXT := COALESCE(current_setting('stig.audit_retention_protocol', true), '');
BEGIN
    IF mode = 'test' AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_db_role_setting s
        JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE d.datname = pg_catalog.current_database()
          AND s.setrole = 0
          AND 'stig.audit_allow_test_mode=on' = ANY (s.setconfig)
    ) THEN
        RAISE EXCEPTION 'audit maintenance mode "test" is not enabled for this database (% on %)', TG_OP, TG_TABLE_NAME
            USING ERRCODE = c_denied,
                  HINT = 'Test databases only: a superuser runs ALTER DATABASE ... SET stig.audit_allow_test_mode = ''on''.';
    END IF;
    IF TG_OP = 'DELETE' AND mode = 'retention' THEN
        IF proto = '2' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'audit retention DELETE on % needs retention protocol 2; this server version is too old to prune audit rows', TG_TABLE_NAME
            USING ERRCODE = c_denied,
                  HINT = 'Upgrade this replica; retention sweeps from older versions are refused.';
    ELSIF TG_OP = 'TRUNCATE' AND mode IN ('restore', 'test') THEN
        RETURN NULL;
    ELSIF TG_OP = 'UPDATE' THEN
        IF mode IN ('test', 'migration') THEN
            RETURN NEW;
        END IF;
        IF TG_TABLE_NAME = 'audit_events'
           AND to_jsonb(OLD)->>'outcome' IN ('denied', 'rejected')
           AND (to_jsonb(NEW) - c_repeat - c_last)
               IS NOT DISTINCT FROM (to_jsonb(OLD) - c_repeat - c_last)
           AND (to_jsonb(NEW)->>c_repeat)::int = (to_jsonb(OLD)->>c_repeat)::int + 1
           AND to_jsonb(NEW)->>c_last IS NOT NULL
           AND (to_jsonb(NEW)->>c_last) NOT IN ('infinity', '-infinity')
           AND (to_jsonb(NEW)->>c_last)::timestamptz
               >= COALESCE((to_jsonb(OLD)->>c_last)::timestamptz,
                           (to_jsonb(OLD)->>'occurred_at')::timestamptz)
           AND (to_jsonb(NEW)->>c_last)::timestamptz <= pg_catalog.now() + INTERVAL '1 minute'
        THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION '% on % is not permitted outside audit maintenance', TG_OP, TG_TABLE_NAME
        USING ERRCODE = c_denied;
END;
$$;
