-- Owner-run audit retention and restore (#109).
-- The application role loses DELETE/TRUNCATE and table-level INSERT on
-- rule_audit / audit_events (db_roles::apply_app_grants). Pruning and
-- restoring audit rows go through four owner-owned SECURITY DEFINER functions
-- that enforce policy in the database:
--   audit_prune_rule_audit / audit_prune_events  refuse the whole call when any
--       listed row is younger than audit_policy.min_retain_days
--   audit_restore_truncate / audit_restore_load  work only while the owner has
--       opened a window (audit_policy.restore_allowed_until in the future);
--       audit rows load only into an empty table; the id sequence never
--       moves backwards; every truncate and load lands in audit_restore_log
-- The functions declare the guard's maintenance mode themselves (set_config in
-- the body, restored afterwards; a function-level SET of a custom GUC needs
-- superuser on PostgreSQL 15+). EXECUTE is granted to the application role by
-- the owner step, not here, because the role name is not known in SQL.
-- Custom SQLSTATEs the restore functions raise for the two policy refusals
-- (the HTTP restore maps them to 409):
--   SV001  the restore window is closed (audit_policy.restore_allowed_until)
--   SV002  an audit table is not empty (audit rows load only into an empty one)
-- A finite window is honoured for at most 24 hours from now.
-- A successful audit_events load closes a finite window again; an `infinity`
-- window (test routes) stays open. Each call records the acting user (p_actor)
-- and the database login (caller) in audit_restore_log.
-- The same migration appends audit guard revision 4 (see the end of this file):
-- the maintenance modes retention, restore and migration are honoured only for
-- the table owner.
-- Rollback: a forward migration that drops the four functions and the two
-- tables, plus a re-run of the CREATE OR REPLACE FUNCTION of migration 047 for
-- the guard (never edit this file).
CREATE TABLE public.audit_policy (
    singleton             boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    min_retain_days       integer     NOT NULL DEFAULT 365 CHECK (min_retain_days BETWEEN 0 AND 36500),
    restore_allowed_until timestamptz NULL,          -- NULL = restore closed
    updated_at            timestamptz NOT NULL DEFAULT pg_catalog.now()
);
INSERT INTO public.audit_policy DEFAULT VALUES;

-- The 24-hour cap on a finite restore window is anchored when the window is
-- SET (a mistyped far-future value is rejected), and stamps updated_at. The
-- restore functions check the cap again at use time. `infinity` is allowed
-- (test routes).
CREATE FUNCTION public.audit_policy_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF (TG_OP = 'INSERT' OR NEW.restore_allowed_until IS DISTINCT FROM OLD.restore_allowed_until)
       AND NEW.restore_allowed_until IS NOT NULL
       AND NEW.restore_allowed_until <> 'infinity'
       AND NEW.restore_allowed_until > now() + interval '24 hours' THEN
        RAISE EXCEPTION 'restore_allowed_until may be at most 24 hours ahead (or infinity with test routes)'
            USING ERRCODE = '22023';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
CREATE TRIGGER audit_policy_guard BEFORE INSERT OR UPDATE ON public.audit_policy
    FOR EACH ROW EXECUTE FUNCTION public.audit_policy_guard();

CREATE TABLE public.audit_restore_log (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    logged_at      timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    step           text   NOT NULL CHECK (step IN ('truncate', 'load')),
    target_table   text   NOT NULL CHECK (target_table IN ('rule_audit', 'audit_events')),
    caller         text   NOT NULL,   -- the database login (session_user)
    actor          text   NULL,       -- the application user who asked (p_actor)
    row_count      bigint NOT NULL,   -- truncate: rows removed; load: rows loaded
    max_id         bigint NULL,       -- truncate: highest id removed; load: highest id loaded
    sequence_after bigint NULL        -- load only
);

CREATE FUNCTION public.audit_prune_rule_audit(p_ids bigint[]) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    prev_mode  text := current_setting('stig.audit_maintenance', true);
    prev_proto text := current_setting('stig.audit_retention_protocol', true);
    floor_days integer;
    cutoff     timestamptz;
    young      bigint;
    n          bigint;
BEGIN
    SELECT p.min_retain_days INTO STRICT floor_days FROM public.audit_policy p;
    cutoff := now() - make_interval(days => floor_days);
    SELECT count(*) INTO young FROM public.rule_audit a
     WHERE a.id = ANY (p_ids) AND a.occurred_at >= cutoff;
    IF young > 0 THEN
        RAISE EXCEPTION 'audit prune refused: % rule_audit rows are younger than the retention floor (% days)', young, floor_days
            USING ERRCODE = '42501';
    END IF;
    PERFORM set_config('stig.audit_maintenance', 'retention', true);
    PERFORM set_config('stig.audit_retention_protocol', '2', true);
    DELETE FROM public.rule_audit a WHERE a.id = ANY (p_ids) AND a.occurred_at < cutoff;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('stig.audit_maintenance', COALESCE(prev_mode, ''), true);
    PERFORM set_config('stig.audit_retention_protocol', COALESCE(prev_proto, ''), true);
    IF n > 0 THEN
        RAISE LOG 'audit_prune_rule_audit: % rows deleted (session_user %)', n, session_user;
    END IF;
    RETURN n;
END;
$$;

CREATE FUNCTION public.audit_prune_events(p_ids bigint[]) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    prev_mode  text := current_setting('stig.audit_maintenance', true);
    prev_proto text := current_setting('stig.audit_retention_protocol', true);
    floor_days integer;
    cutoff     timestamptz;
    young      bigint;
    n          bigint;
BEGIN
    SELECT p.min_retain_days INTO STRICT floor_days FROM public.audit_policy p;
    cutoff := now() - make_interval(days => floor_days);
    SELECT count(*) INTO young FROM public.audit_events a
     WHERE a.id = ANY (p_ids) AND GREATEST(a.occurred_at, COALESCE(a.last_occurred_at, a.occurred_at)) >= cutoff;
    IF young > 0 THEN
        RAISE EXCEPTION 'audit prune refused: % audit_events rows are younger than the retention floor (% days)', young, floor_days
            USING ERRCODE = '42501';
    END IF;
    PERFORM set_config('stig.audit_maintenance', 'retention', true);
    PERFORM set_config('stig.audit_retention_protocol', '2', true);
    DELETE FROM public.audit_events a WHERE a.id = ANY (p_ids) AND GREATEST(a.occurred_at, COALESCE(a.last_occurred_at, a.occurred_at)) < cutoff;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('stig.audit_maintenance', COALESCE(prev_mode, ''), true);
    PERFORM set_config('stig.audit_retention_protocol', COALESCE(prev_proto, ''), true);
    IF n > 0 THEN
        RAISE LOG 'audit_prune_events: % rows deleted (session_user %)', n, session_user;
    END IF;
    RETURN n;
END;
$$;

CREATE FUNCTION public.audit_restore_truncate(p_tables text[], p_actor text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    prev_mode text := current_setting('stig.audit_maintenance', true);
    until_ts  timestamptz;
    bad       text;
    list      text;
    ra_rows bigint; ra_max bigint; ae_rows bigint; ae_max bigint;
BEGIN
    SELECT p.restore_allowed_until INTO STRICT until_ts FROM public.audit_policy p;
    IF until_ts IS NULL OR until_ts <= clock_timestamp()
       OR (until_ts <> 'infinity' AND until_ts > clock_timestamp() + interval '24 hours') THEN
        RAISE EXCEPTION 'audit restore is closed: the database owner must open a restore window (finite windows are capped at 24 hours)'
            USING ERRCODE = 'SV001',
                  HINT = 'As the owner: UPDATE audit_policy SET restore_allowed_until = now() + interval ''30 minutes''.';
    END IF;
    IF p_tables IS NULL OR NOT (p_tables @> ARRAY['rule_audit', 'audit_events']::text[]) THEN
        RAISE EXCEPTION 'audit_restore_truncate: the list must include rule_audit and audit_events'
            USING ERRCODE = '22023';
    END IF;
    SELECT t INTO bad FROM unnest(p_tables) AS t
     WHERE t IS NULL
        OR t IN ('_sqlx_migrations', 'audit_policy', 'audit_restore_log')
        OR NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
                       WHERE ns.nspname = 'public' AND c.relname = t AND c.relkind = 'r'
                         -- the definer never truncates what the caller could not
                         AND (t IN ('rule_audit', 'audit_events')
                              OR has_table_privilege(session_user, c.oid, 'TRUNCATE')))
     LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION 'audit_restore_truncate: table % is not allowed', COALESCE(quote_ident(bad), 'NULL')
            USING ERRCODE = '42501';
    END IF;
    -- CASCADE would also empty a table outside the list that references a
    -- listed one, bypassing the per-table privilege check above.
    IF EXISTS (
        SELECT 1 FROM pg_constraint k
          JOIN pg_class rc ON rc.oid = k.confrelid
          JOIN pg_namespace rn ON rn.oid = rc.relnamespace
          JOIN pg_class fc ON fc.oid = k.conrelid
          JOIN pg_namespace fn ON fn.oid = fc.relnamespace
         WHERE k.contype = 'f' AND rn.nspname = 'public' AND rc.relname = ANY (p_tables)
           AND NOT (fn.nspname = 'public' AND fc.relname = ANY (p_tables))
    ) THEN
        RAISE EXCEPTION 'audit_restore_truncate: a table outside the list references a listed table'
            USING ERRCODE = '42501';
    END IF;
    -- TRUNCATE without ONLY also empties inheritance and partition children.
    IF EXISTS (
        SELECT 1 FROM pg_inherits i
          JOIN pg_class pc ON pc.oid = i.inhparent
          JOIN pg_namespace pn ON pn.oid = pc.relnamespace
          JOIN pg_class cc ON cc.oid = i.inhrelid
          JOIN pg_namespace cn ON cn.oid = cc.relnamespace
         WHERE pn.nspname = 'public' AND pc.relname = ANY (p_tables)
           AND NOT (cn.nspname = 'public' AND cc.relname = ANY (p_tables))
    ) THEN
        RAISE EXCEPTION 'audit_restore_truncate: a table outside the list inherits from a listed table'
            USING ERRCODE = '42501';
    END IF;
    SELECT count(*), max(a.id) INTO ra_rows, ra_max FROM public.rule_audit a;
    SELECT count(*), max(e.id) INTO ae_rows, ae_max FROM public.audit_events e;
    SELECT string_agg(format('public.%I', t), ', ') INTO list FROM unnest(p_tables) AS t;
    PERFORM set_config('stig.audit_maintenance', 'restore', true);
    EXECUTE 'TRUNCATE ' || list || ' CASCADE';
    PERFORM set_config('stig.audit_maintenance', COALESCE(prev_mode, ''), true);
    INSERT INTO public.audit_restore_log (step, target_table, caller, actor, row_count, max_id)
    VALUES ('truncate', 'rule_audit', session_user, p_actor, ra_rows, ra_max),
           ('truncate', 'audit_events', session_user, p_actor, ae_rows, ae_max);
    RAISE LOG 'audit_restore_truncate: removed % rule_audit and % audit_events rows (session_user %)', ra_rows, ae_rows, session_user;
END;
$$;

CREATE FUNCTION public.audit_restore_load(p_table text, p_rows jsonb, p_actor text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    until_ts timestamptz;
    n bigint; mn bigint; mx bigint; cur bigint; target bigint;
BEGIN
    SELECT p.restore_allowed_until INTO STRICT until_ts FROM public.audit_policy p;
    IF until_ts IS NULL OR until_ts <= clock_timestamp()
       OR (until_ts <> 'infinity' AND until_ts > clock_timestamp() + interval '24 hours') THEN
        RAISE EXCEPTION 'audit restore is closed: the database owner must open a restore window (finite windows are capped at 24 hours)'
            USING ERRCODE = 'SV001',
                  HINT = 'As the owner: UPDATE audit_policy SET restore_allowed_until = now() + interval ''30 minutes''.';
    END IF;
    IF jsonb_typeof(p_rows) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'audit_restore_load: rows must be a JSON array' USING ERRCODE = '22023';
    END IF;
    IF p_table = 'rule_audit' THEN
        LOCK TABLE public.rule_audit IN SHARE ROW EXCLUSIVE MODE;
        IF EXISTS (SELECT 1 FROM public.rule_audit) THEN
            RAISE EXCEPTION 'audit_restore_load: rule_audit is not empty; audit rows load only into an empty table'
                USING ERRCODE = 'SV002';
        END IF;
        INSERT INTO public.rule_audit
            SELECT * FROM jsonb_populate_recordset(NULL::public.rule_audit, p_rows);
        GET DIAGNOSTICS n = ROW_COUNT;
        SELECT min(a.id), max(a.id) INTO mn, mx FROM public.rule_audit a;
        SELECT CASE WHEN s.is_called THEN s.last_value ELSE s.last_value - 1 END INTO cur
          FROM public.rule_audit_id_seq s;
        -- An id near bigint max would break nextval for good.
        IF mn <= 0 OR mx > GREATEST(cur, 0) + 1000000000000 THEN
            RAISE EXCEPTION 'audit_restore_load: rule_audit ids out of range' USING ERRCODE = '22023';
        END IF;
        target := GREATEST(cur, COALESCE(mx, 0));   -- the sequence never moves backwards
        IF target >= 1 THEN
            PERFORM setval('public.rule_audit_id_seq'::regclass, target, true);
        END IF;
    ELSIF p_table = 'audit_events' THEN
        LOCK TABLE public.audit_events IN SHARE ROW EXCLUSIVE MODE;
        IF EXISTS (SELECT 1 FROM public.audit_events) THEN
            RAISE EXCEPTION 'audit_restore_load: audit_events is not empty; audit rows load only into an empty table'
                USING ERRCODE = 'SV002';
        END IF;
        INSERT INTO public.audit_events
            SELECT * FROM jsonb_populate_recordset(NULL::public.audit_events, p_rows);
        GET DIAGNOSTICS n = ROW_COUNT;
        SELECT min(a.id), max(a.id) INTO mn, mx FROM public.audit_events a;
        SELECT CASE WHEN s.is_called THEN s.last_value ELSE s.last_value - 1 END INTO cur
          FROM public.audit_events_id_seq s;
        -- An id near bigint max would break nextval for good.
        IF mn <= 0 OR mx > GREATEST(cur, 0) + 1000000000000 THEN
            RAISE EXCEPTION 'audit_restore_load: audit_events ids out of range' USING ERRCODE = '22023';
        END IF;
        target := GREATEST(cur, COALESCE(mx, 0));   -- the sequence never moves backwards
        IF target >= 1 THEN
            PERFORM setval('public.audit_events_id_seq'::regclass, target, true);
        END IF;
    ELSE
        RAISE EXCEPTION 'audit_restore_load: unknown table' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.audit_restore_log (step, target_table, caller, actor, row_count, max_id, sequence_after)
    VALUES ('load', p_table, session_user, p_actor, n, mx, NULLIF(target, 0));
    IF p_table = 'audit_events' THEN
        -- The last audit table of a restore: close a finite window (the
        -- test-routes `infinity` window stays open).
        UPDATE public.audit_policy
           SET restore_allowed_until = NULL, updated_at = pg_catalog.now()
         WHERE restore_allowed_until <> 'infinity';
    END IF;
    RAISE LOG 'audit_restore_load: % rows into % (session_user %)', n, p_table, session_user;
    RETURN n;
END;
$$;

REVOKE ALL ON FUNCTION public.audit_prune_rule_audit(bigint[])  FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_prune_events(bigint[])      FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_restore_truncate(text[], text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_restore_load(text, jsonb, text) FROM PUBLIC;

-- Audit guard, revision 4: the modes `retention`, `restore` and `migration`
-- are honoured only when the statement runs as the owner of the audit table
-- (or a member of it, or a superuser). The guard is SECURITY INVOKER, so
-- inside the SECURITY DEFINER functions above current_user is the owner;
-- migrations run as the owner too. The application role can still set the
-- GUCs, but they no longer do anything for it.
--   retention  DELETE            owner only, protocol marker '2'
--   restore    TRUNCATE          owner only
--   migration  UPDATE            owner only
--   test       UPDATE, TRUNCATE  unchanged (flagged database only, any role)
-- The collapse UPDATE of a repeated denial is unchanged and needs no mode.
-- Rollback: a forward migration that re-runs the CREATE OR REPLACE FUNCTION
-- from migration 047.
CREATE OR REPLACE FUNCTION public.audit_tables_guard() RETURNS trigger
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
    -- rev 4
    as_owner BOOLEAN := COALESCE(pg_has_role(current_user,
        (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = TG_RELID), 'MEMBER'), false);
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
    IF TG_OP = 'DELETE' AND mode = 'retention' AND as_owner THEN          -- rev 4
        IF proto = '2' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'audit retention DELETE on % needs retention protocol 2; this server version is too old to prune audit rows', TG_TABLE_NAME
            USING ERRCODE = c_denied,
                  HINT = 'Upgrade this replica; retention sweeps from older versions are refused.';
    ELSIF TG_OP = 'TRUNCATE' AND (mode = 'test' OR (mode = 'restore' AND as_owner)) THEN   -- rev 4
        RETURN NULL;
    ELSIF TG_OP = 'UPDATE' THEN
        IF mode = 'test' OR (mode = 'migration' AND as_owner) THEN        -- rev 4
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
    IF mode IN ('retention', 'restore', 'migration') AND NOT as_owner THEN   -- rev 4
        RAISE EXCEPTION 'audit maintenance mode "%" is honoured only for the owner of % (% refused)', mode, TG_TABLE_NAME, TG_OP
            USING ERRCODE = c_denied,
                  HINT = 'Retention and restore run through the audit_prune_* / audit_restore_* functions; data migrations run as the owner role.';
    END IF;
    RAISE EXCEPTION '% on % is not permitted outside audit maintenance', TG_OP, TG_TABLE_NAME
        USING ERRCODE = c_denied;
END;
$$;
