// Tests for backend/scripts/dev-entrypoint.sh (#166, #147). The script runs for
// real; `cargo` and `sleep` are stubs on a temp PATH that record every call.
// Run: npm run test:scripts
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(root, "backend/scripts/dev-entrypoint.sh");
const realSleep = execFileSync("sh", ["-c", "command -v sleep"]).toString().trim();

const CARGO_STUB = `#!/bin/sh
echo "cargo $*" >> "$STUB_LOG"
if [ "$1" = run ] && [ "$2" = -- ] && [ "$3" = migrate ]; then
  code=$(head -n 1 "$STUB_CODES")
  if [ "$(wc -l < "$STUB_CODES")" -gt 1 ]; then
    tail -n +2 "$STUB_CODES" > "$STUB_CODES.tmp" && mv "$STUB_CODES.tmp" "$STUB_CODES"
  fi
  exit "$code"
fi
if [ "$1" = watch ]; then
  for last; do :; done
  if [ "\${STUB_SERVE_MODE:-}" = nopid ]; then
    # Never runs the -s snippet, so no pidfile is written.
    trap 'echo "watch TERM" >> "$STUB_LOG"; exit 143' TERM
    echo "watch started" >> "$STUB_LOG"
    while true; do sleep 0.05; done
  fi
  if [ "\${STUB_SERVE_MODE:-}" = term ]; then
    sh -c "$last" &
    child=$!
    trap 'echo "watch TERM" >> "$STUB_LOG"; kill -TERM "$child"; exit 143' TERM
    wait "$child"
    # Like cargo-watch, stay up after the child exits until told to stop.
    while true; do sleep 0.05; done
  fi
  i=0
  while [ "$i" -lt "\${STUB_WATCH_RUNS:-1}" ]; do
    sh -c "$last"
    i=$((i + 1))
  done
  exit 0
fi
if [ "$1" = run ]; then
  echo "serve migurl=[\${DATABASE_MIGRATION_URL-unset}]" >> "$STUB_LOG"
  if [ "\${STUB_SERVE_MODE:-}" = term ]; then
    trap 'echo "serve TERM" >> "$STUB_LOG"; sleep 0.3; echo "serve drained" >> "$STUB_LOG"; exit 0' TERM
    echo "serve started" >> "$STUB_LOG"
    while true; do sleep 0.05; done
  fi
  exit 0
fi
exit 99
`;

const SLEEP_STUB = `#!/bin/sh
echo "sleep $*" >> "$STUB_LOG"
if [ "$1" = 2 ] && [ -z "\${STUB_REAL_SLEEP:-}" ]; then exit 0; fi
exec ${realSleep} "$@"
`;

function setup(codes) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dev-entrypoint-"));
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "cargo"), CARGO_STUB, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "sleep"), SLEEP_STUB, { mode: 0o755 });
  const log = path.join(dir, "calls.log");
  fs.writeFileSync(log, "");
  const codesFile = path.join(dir, "codes");
  fs.writeFileSync(codesFile, codes.join("\n") + "\n");
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    DEV_ENTRYPOINT_STATE_DIR: dir,
    STUB_LOG: log,
    STUB_CODES: codesFile,
  };
  const lines = () => fs.readFileSync(log, "utf8").split("\n").filter(Boolean);
  return { dir, env, log, lines };
}

// Spawn the script; resolve with { code, signal, stdout, stderr }. `onSpawn`
// receives the child so a test can signal it.
function run(env, onSpawn) {
  return new Promise((resolve, reject) => {
    const child = spawn("sh", [script], { env, cwd: root, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`script timed out\nstdout: ${stdout}\nstderr: ${stderr}`));
    }, 20_000);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr });
    });
    if (onSpawn) onSpawn(child);
  });
}

const count = (lines, prefix) => lines.filter((l) => l.startsWith(prefix)).length;

test("migrate retries on exit 75 with sleep 2, then starts cargo-watch", async () => {
  const t = setup([75, 75, 0]);
  const r = await run(t.env);
  const lines = t.lines();
  assert.equal(r.code, 0);
  assert.equal(count(lines, "cargo run -- migrate"), 3);
  assert.equal(lines.filter((l) => l === "sleep 2").length, 2);
  assert.ok(
    lines.includes(
      "cargo watch -w src -w migrations -w Cargo.toml -w Cargo.lock -w stig-sources.toml -s " +
        fs.readFileSync(script, "utf8").match(/-s '([^']*)'/)[1],
    ),
    lines.join("\n"),
  );
});

for (const code of [1, 101]) {
  test(`migrate exit ${code} is permanent: no retry, no watch`, async () => {
    const t = setup([code]);
    const r = await run(t.env);
    const lines = t.lines();
    assert.equal(r.code, code);
    assert.equal(count(lines, "cargo run -- migrate"), 1);
    assert.equal(lines.filter((l) => l.startsWith("sleep")).length, 0);
    assert.equal(count(lines, "cargo watch"), 0);
    assert.match(r.stderr, new RegExp(`failed permanently \\(exit ${code}\\)`));
  });
}

test("migrate exit 75 forever gives up after 30 attempts", async () => {
  const t = setup([75]);
  const r = await run(t.env);
  const lines = t.lines();
  assert.equal(r.code, 1);
  assert.equal(count(lines, "cargo run -- migrate"), 30);
  assert.equal(lines.filter((l) => l === "sleep 2").length, 29);
  assert.equal(count(lines, "cargo watch"), 0);
  assert.match(r.stderr, /giving up/);
});

test("first serve blanks DATABASE_MIGRATION_URL, later serves keep it", async () => {
  const t = setup([0]);
  const url = "postgres://owner@x/y";
  const r = await run({ ...t.env, DATABASE_MIGRATION_URL: url, STUB_WATCH_RUNS: "2" });
  assert.equal(r.code, 0);
  const serves = t.lines().filter((l) => l.startsWith("serve "));
  assert.deepEqual(serves, ["serve migurl=[]", `serve migurl=[${url}]`]);
});

// Note: the real cargo-watch "exits without waiting for its child" behaviour
// (the reason this script waits for the backend itself) is not reproduced by
// the stub; it is covered only by the stop check in
// scripts/verify-split-role-upgrade.sh.
test("SIGTERM reaches the backend, its drain finishes, then watch stops (exit 143)", async () => {
  const t = setup([0]);
  const env = { ...t.env, STUB_SERVE_MODE: "term" };
  const r = await run(env, (child) => {
    const poll = setInterval(() => {
      if (t.lines().includes("serve started")) {
        clearInterval(poll);
        child.kill("SIGTERM");
      }
    }, 50);
  });
  assert.equal(r.code, 143);
  const events = t.lines().filter((l) => /^(serve TERM|serve drained|watch TERM)$/.test(l));
  assert.deepEqual(events, ["serve TERM", "serve drained", "watch TERM"]);
});

test("SIGTERM during the migrate loop ends the script promptly and starts no watch", async () => {
  const t = setup([75]);
  const env = { ...t.env, STUB_REAL_SLEEP: "1" };
  const started = Date.now();
  const r = await run(env, (child) => {
    const poll = setInterval(() => {
      if (t.lines().includes("sleep 2")) {
        clearInterval(poll);
        child.kill("SIGTERM");
      }
    }, 20);
  });
  // The TERM trap is installed only after the loop, so the shell dies from the
  // signal itself (default action; POSIX sh, dash and macOS sh all behave the
  // same here). stop() never runs, so no exit 143 and no TERM log lines.
  assert.equal(r.signal, "SIGTERM", `signal=${r.signal} code=${r.code}`);
  assert.equal(r.code, null);
  assert.equal(t.lines().filter((l) => /TERM/.test(l)).length, 0);
  assert.ok(Date.now() - started < 10_000);
  assert.equal(count(t.lines(), "cargo watch"), 0);
});

test("SIGTERM before the pidfile exists still stops watch and exits 143", async () => {
  const t = setup([0]);
  const r = await run({ ...t.env, STUB_SERVE_MODE: "nopid" }, (child) => {
    const poll = setInterval(() => {
      if (t.lines().includes("watch started")) {
        clearInterval(poll);
        child.kill("SIGTERM");
      }
    }, 20);
  });
  assert.equal(r.code, 143);
  assert.ok(!fs.existsSync(path.join(t.dir, "backend.pid")));
  assert.deepEqual(t.lines().filter((l) => l === "watch TERM"), ["watch TERM"]);
});

test("docker-compose.yml wires the backend to the entrypoint script", () => {
  const compose = fs.readFileSync(path.join(root, "docker-compose.yml"), "utf8");
  const start = compose.indexOf("\n  backend:\n");
  assert.ok(start >= 0, "backend service not found");
  const rest = compose.slice(start + 1);
  // The block runs until the next top-level service (two-space indent key).
  const end = rest.slice(1).search(/\n {2}[a-z][\w-]*:\n/u);
  const backend = end < 0 ? rest : rest.slice(0, end + 1);
  for (const needle of [
    'command: ["sh", "/app/scripts/dev-entrypoint.sh"]',
    "./backend:/app",
    "init: true",
    "stop_signal: SIGTERM",
    "stop_grace_period: 15s",
    '"${DEV_BIND_ADDR:-0.0.0.0}:${BACKEND_HOST_PORT:-8080}:8080"',
  ]) {
    assert.ok(backend.includes(needle), `backend block lacks: ${needle}`);
  }
});
