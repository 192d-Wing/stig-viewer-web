#!/bin/sh
# Dev backend entrypoint (docker-compose.yml). Tested by scripts/dev-entrypoint.test.js.
#
# podman-compose does not wait for db-roles to finish, so retry the owner
# step (`migrate`: migrations + grants) while it exits 75 (retryable:
# database unreachable or stig_app not created yet). Any other exit code is
# permanent (checksum mismatch, planted object, bad credentials, compile
# error) and stops the container at once instead of retrying 30 times.
# `migrate` already ran the owner step, so the FIRST serve blanks
# DATABASE_MIGRATION_URL and only verifies; later cargo-watch restarts keep
# the URL, so a newly added migration is still applied on reload.
#
# Shutdown: cargo-watch forwards SIGTERM to its child and then exits at once
# without waiting for it, which would cut the backend's 8 s drain short. So on
# TERM/INT this script signals the backend itself (pid from the pidfile),
# waits for it to exit, and only then stops cargo-watch.

state="${DEV_ENTRYPOINT_STATE_DIR:-/tmp}"
marker="$state/owner-step-done"
pidfile="$state/backend.pid"
rm -f "$marker" "$pidfile"

n=0
while true; do
  cargo run -- migrate
  rc=$?
  if [ "$rc" -eq 0 ]; then break; fi
  if [ "$rc" -ne 75 ]; then echo "migrate failed permanently (exit $rc)" >&2; exit "$rc"; fi
  n=$((n + 1))
  if [ "$n" -ge 30 ]; then echo "migrate failed 30 times; giving up" >&2; exit 1; fi
  echo "waiting for db-roles / postgres (attempt $n)"; sleep 2
done

touch "$marker"
export DEV_ENTRYPOINT_MARKER="$marker" DEV_ENTRYPOINT_PIDFILE="$pidfile"

# `cargo run` exec-replaces itself with the binary, so the pid written before
# the exec is the backend's pid.
# shellcheck disable=SC2016 # the snippet is expanded by cargo-watch's shell, not here
cargo watch -w src -w migrations -w Cargo.toml -w Cargo.lock -w stig-sources.toml -s 'echo $$ > "$DEV_ENTRYPOINT_PIDFILE"; if [ -e "$DEV_ENTRYPOINT_MARKER" ]; then rm -f "$DEV_ENTRYPOINT_MARKER"; exec env DATABASE_MIGRATION_URL= cargo run; else exec cargo run; fi' &
watch_pid=$!

# shellcheck disable=SC2329 # invoked through the trap below
stop() {
  trap '' TERM INT
  backend_pid=""
  if [ -s "$pidfile" ]; then backend_pid=$(cat "$pidfile"); fi
  if [ -n "$backend_pid" ]; then
    kill -TERM "$backend_pid" 2>/dev/null
    # 50 x 0.2 s = 10 s cap: above the backend's 8 s drain, below the 15 s grace.
    i=0
    while [ "$i" -lt 50 ] && kill -0 "$backend_pid" 2>/dev/null; do
      sleep 0.2
      i=$((i + 1))
    done
  fi
  kill -TERM "$watch_pid" 2>/dev/null
  wait "$watch_pid" 2>/dev/null
  exit 143
}
trap stop TERM INT

# `wait` is required: dash defers traps while a foreground child runs.
wait "$watch_pid"
exit $?
