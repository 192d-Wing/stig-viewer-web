#!/usr/bin/env bash
# Smoke test for the production image (Containerfile, #71): builds it, starts a
# throwaway Postgres and Keycloak on a private network, runs `migrate` as the
# owner role, runs the server with a read-only root filesystem and checks the
# healthcheck, same-origin static serving, the non-root user, the FIPS audit
# row, an arbitrary-uid start and the require-FIPS refusal. Never touches the
# dev stack. Prints PASS/FAIL lines and exits non-zero on any failure.
#
#   ENGINE (podman)  CRYPTO (non-fips|fips)  SVW_SMOKE_PORT (28080)
#   SVW_SMOKE_SKIP_BUILD=1 (use an existing svw-prod-smoke:<crypto> image)
#   SVW_SMOKE_CARGO_JOBS (passed to the build as BUILD_JOBS)
#   SVW_KEEP=1 (leave containers, network and volume for debugging)
#
# All credentials are generated per run with openssl and passed to containers
# by variable name; none is written to a file or a command line on the host.
# The single-quoted bash -c bodies and the psql variables expand in the child.
# shellcheck disable=SC2016
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENGINE="${ENGINE:-podman}"
CRYPTO="${CRYPTO:-non-fips}"
PORT="${SVW_SMOKE_PORT:-28080}"

die() { echo "ERROR: $*" >&2; exit 1; }

# --- guards (fail closed) ---------------------------------------------------
case "$ENGINE" in
  podman) ;;
  *) die "ENGINE must be podman (got '$ENGINE')" ;;
esac
case "$CRYPTO" in
  non-fips|fips) ;;
  *) die "CRYPTO must be non-fips or fips (got '$CRYPTO')" ;;
esac
case "$PORT" in
  ''|*[!0-9]*) die "bad port '$PORT'" ;;
  *) ;;
esac
PORT=$((10#$PORT))
if [[ "$PORT" -lt 1024 ]] || [[ "$PORT" -gt 65534 ]]; then die "port $PORT out of range"; fi
case "$PORT" in
  5173|8080|8081|5433) die "refusing default dev port $PORT" ;;
  *) ;;
esac
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then die "port $PORT is already listening"; fi

PREFIX=svw-prod-smoke
IMAGE="$PREFIX:$CRYPTO"
NET="$PREFIX-net"
VOL="$PREFIX-data"
PG="$PREFIX-pg"
KC="$PREFIX-kc"
APP="$PREFIX-app"
for name in "$NET" "$VOL" "$PG" "$KC" "$APP" "$IMAGE"; do
  case "$name" in
    "$PREFIX"[-:]*) ;;
    *) die "resource name '$name' must start with $PREFIX" ;;
  esac
  case "$name" in
    stig-viewer-web*|web-layout-redesign*) die "refusing name '$name' (dev stack)" ;;
    *) ;;
  esac
done
if [[ -n "$($ENGINE ps -a --format '{{.Names}}' | grep "^$PREFIX-" || true)" ]] ||
   [[ -n "$($ENGINE volume ls --format '{{.Name}}' | grep "^$PREFIX-" || true)" ]]; then
  die "$PREFIX-* containers or volumes already exist; remove them first"
fi

# --- cleanup ----------------------------------------------------------------
cleanup() {
  local rc=$?
  set +e
  if [[ "$rc" -ne 0 ]]; then
    $ENGINE logs --tail 60 "$APP" >&2 2>&1
  fi
  if [[ "${SVW_KEEP:-}" != 1 ]]; then
    $ENGINE rm -f "$APP" "$APP-uid" "$KC" "$PG" >/dev/null 2>&1
    $ENGINE volume rm -f "$VOL" >/dev/null 2>&1
    $ENGINE network rm -f "$NET" >/dev/null 2>&1
  else
    echo "SVW_KEEP=1: leaving $PREFIX-* resources in place"
  fi
  exit "$rc"
}
trap cleanup EXIT

failures=0
note() { echo "== $*"; }
check() { # description, command...
  local d="$1"; shift
  if "$@"; then note "PASS $d"; else note "FAIL $d"; failures=$((failures + 1)); fi
}

# Image refs for Postgres and Keycloak come from docker-compose.yml so the
# digests are not duplicated here.
compose_image() {
  local service="$1"
  awk -v svc="  $service:" '$0 == svc {f=1; next} f && /^  [a-z]/ {f=0} f && $1 == "image:" {print $2; exit}' \
    "$repo/docker-compose.yml"
}
PG_IMAGE=$(compose_image postgres)
KC_IMAGE=$(compose_image keycloak)
[[ -n "$PG_IMAGE" ]] || die "postgres image not found in docker-compose.yml"
[[ -n "$KC_IMAGE" ]] || die "keycloak image not found in docker-compose.yml"

# --- build ------------------------------------------------------------------
if [[ "${SVW_SMOKE_SKIP_BUILD:-}" != 1 ]]; then
  build_args=(--build-arg "CRYPTO=$CRYPTO")
  if [[ -n "${SVW_SMOKE_CARGO_JOBS:-}" ]]; then
    build_args+=(--build-arg "BUILD_JOBS=$SVW_SMOKE_CARGO_JOBS")
  fi
  note "building $IMAGE"
  $ENGINE build --format docker "${build_args[@]}" -t "$IMAGE" -f "$repo/Containerfile" "$repo"
fi
$ENGINE image exists "$IMAGE" || die "image $IMAGE not found"

# --- credentials (per run, never printed) -----------------------------------
gen() { openssl rand -hex 24; }
PG_SUPER_PW=$(gen)
OWNER_PW=$(gen)
APP_PW=$(gen)
OIDC_CLIENT_SECRET=$(gen)
if [[ "${GITHUB_ACTIONS:-}" = true ]]; then
  for v in "$PG_SUPER_PW" "$OWNER_PW" "$APP_PW" "$OIDC_CLIENT_SECRET"; do echo "::add-mask::$v"; done
fi
DB=stig
export PG_SUPER_PW OWNER_PW APP_PW OIDC_CLIENT_SECRET
DATABASE_URL="postgres://stig_app:${APP_PW}@${PG}:5432/${DB}"
DATABASE_MIGRATION_URL="postgres://stig_owner:${OWNER_PW}@${PG}:5432/${DB}"
export DATABASE_URL DATABASE_MIGRATION_URL

# --- Postgres ---------------------------------------------------------------
$ENGINE network create "$NET" >/dev/null
note "starting Postgres"
POSTGRES_PASSWORD="$PG_SUPER_PW" $ENGINE run -d --name "$PG" --network "$NET" \
  -e POSTGRES_PASSWORD --tmpfs /var/lib/postgresql "$PG_IMAGE" >/dev/null
for i in $(seq 1 60); do
  if $ENGINE exec "$PG" pg_isready -U postgres >/dev/null 2>&1 &&
     $ENGINE exec "$PG" psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then break; fi
  [[ "$i" -lt 60 ]] || die "Postgres did not become ready"
  sleep 2
done

# Provision as README "Two database roles": passwords reach psql as variables.
$ENGINE exec -e OWNER_PW -e APP_PW -i "$PG" sh -c \
  'psql -U postgres -v ON_ERROR_STOP=1 -v owner_pw="$OWNER_PW" -v app_pw="$APP_PW"' >/dev/null <<SQL
CREATE ROLE stig_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER;
CREATE ROLE stig_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE $DB OWNER stig_owner;
REVOKE ALL ON DATABASE $DB FROM PUBLIC;
GRANT CONNECT ON DATABASE $DB TO stig_app;
SQL

# --- Keycloak (OIDC discovery is needed at server start) --------------------
note "starting Keycloak"
$ENGINE run -d --name "$KC" --network "$NET" \
  -e KC_HTTP_PORT=8081 -e KC_HOSTNAME_STRICT=false -e KC_HTTP_ENABLED=true \
  -v "$repo/dev/keycloak:/opt/keycloak/data/import:ro" \
  "$KC_IMAGE" start-dev --import-realm >/dev/null
discovery='exec 3<>/dev/tcp/localhost/8081 && printf "GET /realms/stig-viewer/.well-known/openid-configuration HTTP/1.1\r\nHost: localhost:8081\r\nConnection: close\r\n\r\n" >&3 && head -1 <&3 | grep -q "200 OK"'
for i in $(seq 1 90); do
  if $ENGINE exec "$KC" bash -c "$discovery" >/dev/null 2>&1; then break; fi
  [[ "$i" -lt 90 ]] || die "Keycloak discovery did not come up"
  sleep 2
done

# --- migrate (owner step, retry only on 75) ---------------------------------
note "running migrate"
rc=0
for attempt in 1 2 3 4 5; do
  rc=0
  $ENGINE run --rm --network "$NET" -e DATABASE_URL -e DATABASE_MIGRATION_URL "$IMAGE" migrate || rc=$?
  if [[ "$rc" -ne 75 ]]; then break; fi
  note "migrate exit 75, retry $attempt"; sleep 3
done
check "migrate exits 0" test "$rc" -eq 0
[[ "$rc" -eq 0 ]] || die "migrate failed (exit $rc)"

# --- server -----------------------------------------------------------------
oidc_url="http://$KC:8081/realms/stig-viewer"
server_args=(
  --network "$NET" --read-only --cap-drop=ALL --security-opt no-new-privileges
  -e DATABASE_URL
  -e STIG_SYNC_ON_START=false -e STIG_SYNC_INTERVAL_HOURS=999999
  -e "OIDC_INTERNAL_URL=$oidc_url" -e "OIDC_PUBLIC_URL=http://$KC:8081"
  -e OIDC_CLIENT_ID=stig-viewer-app -e OIDC_CLIENT_SECRET
  -e "OIDC_REDIRECT_URI=http://localhost:$PORT/auth/callback"
  -e "FRONTEND_URL=http://localhost:$PORT"
  -v "$VOL:/data"
)
# Podman mounts tmpfs on /tmp and /run under --read-only, which would hide a
# stray write; turn that off so the rootfs is strictly read-only.
server_args+=(--read-only-tmpfs=false)
if [[ "$CRYPTO" = fips ]]; then server_args+=(-e STIG_REQUIRE_FIPS=1); fi

note "starting server on 127.0.0.1:$PORT"
$ENGINE run -d --name "$APP" "${server_args[@]}" -p "127.0.0.1:$PORT:8080" "$IMAGE" >/dev/null

wait_healthy() { # container, seconds
  local c="$1" limit="$2" i=0
  until $ENGINE healthcheck run "$c" >/dev/null 2>&1; do
    i=$((i + 2))
    if [[ "$i" -ge "$limit" ]]; then return 1; fi
    if [[ "$($ENGINE inspect -f '{{.State.Status}}' "$c" 2>/dev/null)" != running ]]; then return 1; fi
    sleep 2
  done
}
check "podman healthcheck run reaches healthy" wait_healthy "$APP" 120
[[ "$failures" -eq 0 ]] || die "server never became healthy"

base="http://127.0.0.1:$PORT"
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@"; }
check "GET /api/health is 200" test "$(http_code "$base/api/health")" = 200

index=$(curl -s --max-time 5 "$base/")
check "/ is the shell with CSP meta and app-wasm" \
  bash -c 'grep -q "Content-Security-Policy" <<<"$1" && grep -q "id=\"app-wasm\"" <<<"$1"' _ "$index"
check "/ does not mention localhost:8080" bash -c '! grep -q "localhost:8080" <<<"$1"' _ "$index"
wasm=$(sed -n 's/.*id="app-wasm"[^>]*href="\([^"]*\)".*/\1/p;s/.*href="\([^"]*\)"[^>]*id="app-wasm".*/\1/p' <<<"$index" | head -n1)
check "found the wasm URL" test -n "$wasm"
check "wasm is application/wasm" bash -c \
  'curl -sI --max-time 5 "$1$2" | tr -d "\r" | grep -qi "^content-type: application/wasm"' _ "$base" "$wasm"
check "deep link returns the shell" bash -c \
  'curl -s --max-time 5 "$1/some/deep/link" | grep -q "id=\"app-wasm\""' _ "$base"
check "/api/nope is 404" test "$(http_code "$base/api/nope")" = 404
check "frame-ancestors header present" bash -c \
  'curl -sI --max-time 5 "$1/" | tr -d "\r" | grep -qi "^content-security-policy: frame-ancestors"' _ "$base"

check "image user is 1001:0" test "$($ENGINE inspect -f '{{.Config.User}}' "$APP")" = "1001:0"
check "process uid is 1001" test "$($ENGINE exec "$APP" id -u)" = 1001
check "root filesystem is read-only" test "$($ENGINE inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$APP")" = true

audit_flag=$($ENGINE exec "$PG" psql -U postgres -d "$DB" -tAc \
  "SELECT detail->>'fipsCompiled' FROM audit_events WHERE action = 'system.fips_policy' ORDER BY id DESC LIMIT 1" \
  2>/dev/null | tr -d '[:space:]' || true)
want_flag=false
if [[ "$CRYPTO" = fips ]]; then want_flag=true; fi
check "system.fips_policy audit row has fipsCompiled=$want_flag" test "$audit_flag" = "$want_flag"

# --- clean stop, then an arbitrary uid on the same volume --------------------
$ENGINE stop -t 15 "$APP" >/dev/null
check "SIGTERM stop exits 0" test "$($ENGINE inspect -f '{{.State.ExitCode}}' "$APP")" = 0
$ENGINE rm -f "$APP" >/dev/null

uid_args=()
for a in "${server_args[@]}"; do uid_args+=("$a"); done
note "starting server as uid 123456 gid 0 on the same volume"
$ENGINE run -d --name "$APP-uid" --user 123456:0 "${uid_args[@]}" -p "127.0.0.1:$PORT:8080" "$IMAGE" >/dev/null
check "arbitrary uid 123456:0 reaches healthy" wait_healthy "$APP-uid" 120
$ENGINE stop -t 15 "$APP-uid" >/dev/null || true

# --- require-FIPS refusal on a non-FIPS build --------------------------------
if [[ "$CRYPTO" = non-fips ]]; then
  refused() { ! $ENGINE run --rm -e STIG_REQUIRE_FIPS=1 "$IMAGE" >/dev/null 2>&1; }
  check "STIG_REQUIRE_FIPS=1 refuses to start on the non-FIPS image" refused
fi

if [[ "$failures" -ne 0 ]]; then die "$failures check(s) failed"; fi
note "ALL PASSED ($CRYPTO)"
