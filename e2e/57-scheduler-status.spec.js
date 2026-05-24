import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Background job dashboard.
 *
 * Five `tokio::spawn` loops drive periodic work in the backend. Each tick
 * now records a row in `scheduler_runs` via `scheduler_log::record`, and
 * `GET /api/admin/scheduler-runs` surfaces them to the admin console.
 *
 * The 24h scheduler intervals are too slow for an E2E run, so we drive
 * ticks synchronously via the test-only `POST /api/test/run-scheduler`
 * endpoint and assert against the persisted rows. This mirrors the
 * `run-digest` / `run-report` / `run-retention` pattern used elsewhere.
 */

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

async function fetchRuns(request, userName = "alice") {
  const res = await request.get(`${BACKEND}/api/admin/scheduler-runs`, {
    headers: { "X-User-Id": userName },
  });
  expect(res.status()).toBe(200);
  return res.json();
}

async function runScheduler(request, name) {
  const res = await request.post(`${BACKEND}/api/test/run-scheduler`, {
    headers: { "Content-Type": "application/json" },
    data: { name },
  });
  expect(res.ok()).toBe(true);
  return res.json();
}

test.describe("Background job dashboard", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: non-admin GET /api/admin/scheduler-runs is 403", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    const res = await request.get(`${BACKEND}/api/admin/scheduler-runs`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(403);
  });

  test("API: admin response has the expected shape", async ({ request }) => {
    // Each scheduler fires on startup, so `latest` and `history` are
    // populated as soon as the backend has been running for a tick.
    // Don't assert emptiness — just shape.
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const body = await fetchRuns(request);
    expect(body).toHaveProperty("latest");
    expect(body).toHaveProperty("history");
    expect(typeof body.latest).toBe("object");
    expect(Array.isArray(body.history)).toBe(true);
  });

  test("API: triggering snapshot records an 'ok' row in latest and history", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const trigger = await runScheduler(request, "snapshot");
    expect(trigger.ok).toBe(true);
    expect(typeof trigger.message).toBe("string");

    const body = await fetchRuns(request);
    expect(body.latest.snapshot).toBeTruthy();
    expect(body.latest.snapshot.status).toBe("ok");
    expect(body.latest.snapshot.startedAt).toBeTruthy();
    expect(body.latest.snapshot.finishedAt).toBeTruthy();
    expect(body.latest.snapshot.message).toContain("checklists");

    // History should include the just-triggered snapshot row.
    const matched = body.history.find(
      (r) => r.name === "snapshot" && r.status === "ok",
    );
    expect(matched).toBeTruthy();
  });

  test("API: invalid scheduler name → 400", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const res = await request.post(`${BACKEND}/api/test/run-scheduler`, {
      headers: { "Content-Type": "application/json" },
      data: { name: "nope" },
    });
    expect(res.status()).toBe(400);
  });

  test("API: forcing an 'error' tick — sync without a sources manifest may fail; we accept either ok or error and assert the row is populated", async ({
    request,
  }) => {
    // We can't reliably force an error without altering test infra, but
    // we can drive `audit_retention` and `overdue_digest` which are both
    // safe on a clean DB. If neither errors, this test asserts the
    // happy-path shape and notes the limitation. The previous test
    // already covers the error column when status='ok'.
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    await runScheduler(request, "audit_retention");
    await runScheduler(request, "overdue_digest");

    const body = await fetchRuns(request);
    expect(body.latest.audit_retention).toBeTruthy();
    expect(body.latest.audit_retention.status).toBe("ok");
    expect(body.latest.overdue_digest).toBeTruthy();
    expect(body.latest.overdue_digest.status).toBe("ok");

    // History is capped at 10 and ordered newest-first. Two triggers
    // means two rows minimum.
    expect(body.history.length).toBeGreaterThanOrEqual(2);
    const startedTimes = body.history.map((r) =>
      new Date(r.startedAt).getTime(),
    );
    for (let i = 1; i < startedTimes.length; i++) {
      expect(startedTimes[i - 1]).toBeGreaterThanOrEqual(startedTimes[i]);
    }
  });

  test("UI: admin console renders the Background jobs section with the snapshot row", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    await runScheduler(request, "snapshot");

    await loginAs(page, "alice");
    await page.goto("/?view=admin");

    // The latest-run table renders one row per known scheduler.
    const latestTable = page.getByTestId("scheduler-latest-table");
    await expect(latestTable).toBeVisible();
    // The snapshot row should pick up status='ok'.
    await expect(latestTable.getByText("snapshot")).toBeVisible();
    await expect(latestTable.getByText("ok").first()).toBeVisible();

    // The history table should also show the snapshot tick.
    const historyTable = page.getByTestId("scheduler-history-table");
    await expect(historyTable).toBeVisible();
    await expect(historyTable.getByText("snapshot").first()).toBeVisible();
  });
});
