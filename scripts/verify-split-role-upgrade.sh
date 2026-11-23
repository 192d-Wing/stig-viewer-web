#!/usr/bin/env bash
# Verify the split-role stack (#84) on a fresh volume and on a pre-#84 volume
# upgraded to HEAD, plus the dev backend's SIGTERM drain (#147). Manual, not CI.
# Uses a throwaway compose project on non-default ports; never touches the dev
# stack. Prints a plain-text summary suitable for pasting into #84.
#
#   SVW_PROJECT (svw-verify)  SVW_BACKEND_PORT (18080)  SVW_FRONTEND_PORT (15173)
#   SVW_KEYCLOAK_PORT (18081) SVW_POSTGRES_PORT (15433) SVW_OLD_REV (5cb96e6^)
#   SVW_PHASES ("fresh upgrade") SVW_SPECS (empty = full suite) SVW_KEEP=1
#   SVW_LOW_MEMORY=1 (1 cargo job, no debuginfo, and a lone pre-build of both crates)
#   SVW_REUSE=1  SVW_WORKDIR (parent dir for the old-revision worktree)
#   ENGINE (podman if installed, else docker)
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
P="${SVW_PROJECT:-svw-verify}"
BE="${SVW_BACKEND_PORT:-18080}"
FE="${SVW_FRONTEND_PORT:-15173}"
KC="${SVW_KEYCLOAK_PORT:-18081}"
PG="${SVW_POSTGRES_PORT:-15433}"
OLD_REV="${SVW_OLD_REV:-5cb96e6^}"
PHASES="${SVW_PHASES:-fresh upgrade}"
SPECS="${SVW_SPECS:-}"
if [ -n "${ENGINE:-}" ]; then
  :
elif command -v podman >/dev/null 2>&1; then
  ENGINE=podman
else
  ENGINE=docker
fi

die() { echo "ERROR: $*" >&2; exit 1; }

# --- guards (fail closed) ---------------------------------------------------
case "$P" in
  stig-viewer-web*|web-layout-redesign*) die "refusing project name '$P' (dev stack)" ;;
  svw-*) ;;
  *) die "project name '$P' must match svw-*" ;;
esac
for port in "$BE" "$FE" "$KC" "$PG"; do
  case "$port" in
    ''|*[!0-9]*) die "bad port '$port'" ;;
  esac
  num=$((10#$port))
  if [ "$num" -lt 1 ] || [ "$num" -gt 65535 ]; then die "port $port out of range"; fi
  case "$num" in
    8080|8081|5433|5173) die "refusing default dev port $port" ;;
  esac
  port="$num"
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then die "port $port is already listening"; fi
done
if [ "${SVW_REUSE:-}" != 1 ]; then
  if [ -n "$($ENGINE ps -a --format '{{.Names}}' | grep "^${P}[_-]" || true)" ] ||
     [ -n "$($ENGINE volume ls --format '{{.Name}}' | grep "^${P}[_-]" || true)" ]; then
    die "containers or volumes for project '$P' exist; remove them or set SVW_REUSE=1"
  fi
fi

# --- environment ------------------------------------------------------------
export DEV_BIND_ADDR=127.0.0.1
export KEYCLOAK_HOST_PORT="$KC" POSTGRES_HOST_PORT="$PG" BACKEND_HOST_PORT="$BE" FRONTEND_HOST_PORT="$FE"
export API_URL="http://localhost:$BE"
export VITE_API_URL_FRONTEND="http://localhost:$FE"
export OIDC_PUBLIC_URL="http://localhost:$KC"
export OIDC_REDIRECT_URI="http://localhost:$BE/auth/callback"
export STIG_SYNC_INTERVAL_HOURS=999999 STIG_SYNC_ON_START=false
export VITE_API_URL="http://localhost:$BE" BASE_URL="http://localhost:$FE"

# Runs compose for the current compose directory ($repo, or the old worktree
# while the upgrade phase starts the pre-#84 stack). SVW_LOW_MEMORY=1 lowers cargo's
# memory use through a temp override (a cold build can OOM a small podman VM).
compose_dir="$repo"
override=""
compose() {
  (
    cd "$compose_dir"
    if [ -n "$override" ]; then export COMPOSE_FILE="docker-compose.yml:$override"; fi
    $ENGINE compose -p "$P" "$@"
  )
}
compose_in() { local d="$1"; shift; compose_dir="$d" compose "$@"; }
psql_q() { compose exec -T postgres psql -U stig -d stig_viewer -tAc "$1" | tr -d '[:space:]'; }

old=""
if [ "${SVW_LOW_MEMORY:-}" = 1 ]; then
  override=$(mktemp "${TMPDIR:-/tmp}/svw-override.XXXXXX")
  printf 'services:\n  backend:\n    environment:\n      CARGO_BUILD_JOBS: "1"\n      CARGO_PROFILE_DEV_DEBUG: "0"\n  frontend:\n    environment:\n      CARGO_BUILD_JOBS: "1"\n      CARGO_PROFILE_DEV_DEBUG: "0"\n' > "$override"
fi
cleanup() {
  local rc=$?
  set +e
  if [ "${SVW_KEEP:-}" != 1 ]; then
    compose down -v >/dev/null 2>&1
    if [ -n "$override" ]; then rm -f "$override"; fi
    if [ -n "$old" ]; then git -C "$repo" worktree remove --force "$old" >/dev/null 2>&1; fi
  else
    echo "SVW_KEEP=1: leaving project '$P' running${old:+ and worktree $old}"
  fi
  exit $rc
}
trap cleanup EXIT

summary=()
note() { summary+=("$1"); echo "== $1"; }
failures=0

wait_http() { # url limit-seconds
  local i=0 cid state
  until curl -sf --max-time 3 "$1" >/dev/null 2>&1; do
    # Fail fast when the backend container has already died (e.g. a compile
    # error or an OOM-killed rustc) instead of waiting out the limit.
    cid=$($ENGINE ps -a -q --filter "name=^${P}[_-]backend[_-]1$" 2>/dev/null | head -n 1 || true)
    if [ -n "$cid" ]; then
      state=$($ENGINE inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo "")
      if [ "$state" = exited ] || [ "$state" = stopped ]; then
        compose logs --tail 20 backend >&2 || true
        die "backend container exited while waiting for $1"
      fi
    fi
    i=$((i + 2)); [ "$i" -lt "$2" ] || die "timed out waiting for $1"; sleep 2
  done
}

latest_migration() { # dir
  local f n max=0
  for f in "$1"/backend/migrations/[0-9]*; do
    n=${f##*/}
    n=$((10#${n%%[!0-9]*}))
    if [ "$n" -gt "$max" ]; then max=$n; fi
  done
  echo "$max"
}

check() { # description, command...
  local d="$1"; shift
  if "$@"; then note "PASS $d"; else note "FAIL $d"; failures=$((failures + 1)); fi
}

assert_eq() { [ "$1" = "$2" ]; }

run_playwright() { # label
  local out rc=0
  out=$(mktemp)
  # shellcheck disable=SC2086 # SPECS is intentionally word-split into file args
  (cd "$repo" && npx playwright test -c playwright.verify.config.js $SPECS) 2>&1 | tee "$out" || rc=$?
  local passed failed
  passed=$(grep -Eo '^ +[0-9]+ passed' "$out" | grep -Eo '[0-9]+' | tail -n 1 || true)
  failed=$(grep -Eo '^ +[0-9]+ failed' "$out" | grep -Eo '[0-9]+' | tail -n 1 || true)
  rm -f "$out"
  if [ "${rc:-0}" -eq 0 ]; then
    note "PASS $1 playwright: ${passed:-0} passed, 0 failed"
  else
    note "FAIL $1 playwright: ${passed:-0} passed, ${failed:-?} failed (exit $rc)"
    failures=$((failures + 1))
  fi
}

stop_check() { # label
  local start elapsed cid code
  cid=$($ENGINE ps -a -q --filter "name=^${P}[_-]backend[_-]1$" | head -n 1)
  start=$(date +%s)
  compose stop backend >/dev/null 2>&1 || true
  elapsed=$(( $(date +%s) - start ))
  code=$($ENGINE inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || echo "?")
  STOP_SECONDS="$elapsed"
  if compose logs backend 2>&1 | grep -q 'Shutting down'; then
    note "PASS $1 stop: backend logged 'Shutting down'"
  else
    note "FAIL $1 stop: no 'Shutting down' in backend logs"; failures=$((failures + 1))
  fi
  if [ "$code" != 137 ] && [ "$elapsed" -lt 15 ]; then
    note "PASS $1 stop: exit code $code, ${elapsed}s (< 15s, not SIGKILL)"
  else
    note "FAIL $1 stop: exit code $code, ${elapsed}s"; failures=$((failures + 1))
  fi
}

post_checks() { # label dir-of-HEAD
  local want have
  want=$(latest_migration "$2")
  check "$1 stig_app role exists" assert_eq "$(psql_q "SELECT 1 FROM pg_roles WHERE rolname='stig_app'")" 1
  have=$(psql_q "SELECT max(version) FROM _sqlx_migrations")
  check "$1 migrations at HEAD ($have = $want)" assert_eq "$have" "$want"
  check "$1 #205 owner-run audit functions (mig 050) owned by stig, EXECUTE for stig_app, not PUBLIC" \
    assert_eq "$(psql_q "SELECT count(*) FROM pg_proc p JOIN pg_roles o ON o.oid=p.proowner WHERE p.proname IN ('audit_prune_rule_audit','audit_prune_events','audit_restore_truncate','audit_restore_load') AND o.rolname='stig' AND p.prosecdef AND has_function_privilege('stig_app',p.oid,'EXECUTE') AND NOT has_function_privilege('public',p.oid,'EXECUTE')")" 4
  check "$1 #205 audit_policy and audit_restore_log owned by stig" \
    assert_eq "$(psql_q "SELECT count(*) FROM pg_tables WHERE tablename IN ('audit_policy','audit_restore_log') AND tableowner='stig'")" 2
  check "$1 audit_events owned by stig" assert_eq "$(psql_q "SELECT tableowner FROM pg_tables WHERE tablename='audit_events'")" stig
}

# --- phases -----------------------------------------------------------------
# In low-memory mode compile the crates one at a time (no Keycloak, no sibling builds)
# so rustc is not OOM-killed; the stack start then finds a warm target volume.
prebuild() {
  if [ "${SVW_LOW_MEMORY:-}" = 1 ]; then
    compose build backend
    compose run --rm --no-deps backend cargo build
    if [ -d "$compose_dir/frontend" ]; then
      compose build frontend
      compose run --rm --no-deps frontend cargo build --target=wasm32-unknown-unknown --manifest-path /app/frontend/Cargo.toml
    fi
  fi
}

phase_fresh() {
  note "phase fresh: HEAD $(git -C "$repo" rev-parse --short HEAD) on an empty volume"
  # Backend first, then the frontend: a cold backend and wasm compile at once
  # can exhaust a small podman VM (rustc SIGKILL).
  prebuild
  compose up -d --build postgres keycloak db-roles backend
  wait_http "http://localhost:$BE/api/health" 1800
  compose up -d --build frontend
  wait_http "http://localhost:$FE/" 1800
  post_checks "fresh" "$repo"
  run_playwright "fresh"
  stop_check "fresh"
  compose down
  $ENGINE volume rm "${P}_postgres_data" "${P}_stig_data" >/dev/null 2>&1 || true
}

phase_upgrade() {
  note "phase upgrade: $OLD_REV -> HEAD $(git -C "$repo" rev-parse --short HEAD)"
  old=$(mktemp -d "${SVW_WORKDIR:-${TMPDIR:-/tmp}}/svw-old.XXXXXX")
  git -C "$repo" worktree add --detach "$old" "$OLD_REV" >/dev/null
  # shellcheck disable=SC2016 # the ${...} defaults are compose syntax, not expanded here
  sed -i.bak \
    -e 's|"8081:8081"|"${DEV_BIND_ADDR:-0.0.0.0}:${KEYCLOAK_HOST_PORT:-8081}:8081"|' \
    -e 's|"5433:5432"|"${DEV_BIND_ADDR:-0.0.0.0}:${POSTGRES_HOST_PORT:-5433}:5432"|' \
    -e 's|"8080:8080"|"${DEV_BIND_ADDR:-0.0.0.0}:${BACKEND_HOST_PORT:-8080}:8080"|' \
    -e 's|"5173:5173"|"${DEV_BIND_ADDR:-0.0.0.0}:${FRONTEND_HOST_PORT:-5173}:5173"|' \
    "$old/docker-compose.yml"
  rm -f "$old/docker-compose.yml.bak"
  if grep -qE '"(8081:8081|5433:5432|8080:8080|5173:5173)"' "$old/docker-compose.yml"; then
    die "old compose still has a default host port mapping"
  fi
  compose_in "$old" up -d --build postgres keycloak backend
  wait_http "http://localhost:$BE/api/health" 1800
  curl -sf -H 'X-User-Id: upgrade-probe' "http://localhost:$BE/api/users/me" >/dev/null ||
    die "could not seed the upgrade-probe user"
  check "upgrade pre-state: no stig_app role" assert_eq "$(psql_q "SELECT count(*) FROM pg_roles WHERE rolname='stig_app'")" 0
  check "upgrade pre-state: migration version 43" assert_eq "$(psql_q "SELECT max(version) FROM _sqlx_migrations")" 43
  local users_pre audit_pre
  users_pre=$(psql_q "SELECT count(*) FROM users")
  audit_pre=$(psql_q "SELECT count(*) FROM audit_events")
  compose_in "$old" down
  prebuild
  compose up -d --build postgres keycloak db-roles backend
  wait_http "http://localhost:$BE/api/health" 1800
  compose up -d --build frontend
  wait_http "http://localhost:$FE/" 1800
  post_checks "upgrade" "$repo"
  check "upgrade users survived ($users_pre before)" test "$(psql_q "SELECT count(*) FROM users WHERE provider='test' AND sub='upgrade-probe'")" -ge 1
  check "upgrade audit_events kept (>= $audit_pre)" test "$(psql_q "SELECT count(*) FROM audit_events")" -ge "$audit_pre"
  if compose logs backend 2>&1 | grep -q 'migrate failed'; then
    note "FAIL upgrade backend logs contain 'migrate failed'"; failures=$((failures + 1))
  else
    note "PASS upgrade backend logs: no 'migrate failed'"
  fi
  run_playwright "upgrade"
  stop_check "upgrade"
}

for ph in $PHASES; do
  case "$ph" in
    fresh) phase_fresh ;;
    upgrade) phase_upgrade ;;
    *) die "unknown phase '$ph'" ;;
  esac
done

echo
echo "=== split-role verification summary ==="
echo "HEAD $(git -C "$repo" rev-parse --short HEAD), old revision $OLD_REV, phases: $PHASES, specs: ${SPECS:-full suite}"
printf '%s\n' "${summary[@]}"
echo "stop timing (last phase): ${STOP_SECONDS:-n/a}s (grace 15s)"
echo "result: $([ "$failures" -eq 0 ] && echo PASS || echo "FAIL ($failures failing checks)")"
[ "$failures" -eq 0 ]
