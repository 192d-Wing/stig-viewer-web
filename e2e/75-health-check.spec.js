import { test, expect } from "@playwright/test";
import { resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Deep /api/health endpoint.
 *
 * The endpoint is intentionally unauthenticated (load balancers and
 * uptime monitors hit it without creds) and reports a per-component
 * status plus an aggregated top-level status. We exercise:
 *   * the happy path (no auth header at all)
 *   * the scheduler-degraded path via the inject-error test endpoint
 *   * the webhook-degraded path via firing a webhook at a port that
 *     refuses every connection (127.0.0.1:1)
 *
 * We deliberately avoid the "all webhook attempts failed" case — that
 * would flip the top-level status to `error` (HTTP 503) and any test
 * that runs after us would see the degraded state too.
 */

// Same trick used by 37-webhooks.spec.js: port 1 is reserved and the
// reqwest POST errors out, leaving a delivery row with `error` populated.
const UNREACHABLE_URL = "http://127.0.0.1:1/webhook";

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

async function waitForErrorDelivery(request, adminName, webhookId, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await request.get(
      `${BACKEND}/api/webhooks/${webhookId}/deliveries`,
      { headers: { "X-User-Id": adminName } },
    );
    if (res.ok()) {
      const rows = await res.json();
      const errRow = rows.find((r) => r.error);
      if (errRow) return errRow;
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("waitForErrorDelivery: no error row appeared");
}

test.describe("Deep /api/health", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: unauthenticated GET returns 200 with the documented shape", async ({
    request,
  }) => {
    // No `X-User-Id` header at all — health is the rare public endpoint.
    const res = await request.get(`${BACKEND}/api/health`);
    expect(res.status()).toBe(200);
    const body = await res.json();

    // Top-level shape.
    expect(body).toHaveProperty("status");
    expect(["ok", "degraded", "error"]).toContain(body.status);
    expect(typeof body.version).toBe("string");
    // The Cargo crate version is `0.1.0`; we don't pin to that exact
    // value to avoid a future bump breaking the test, but we do assert
    // it parses as a semver-shaped string.
    expect(body.version).toMatch(/^\d+\.\d+\.\d+/);

    // Per-component shape.
    expect(body.checks).toBeTruthy();
    expect(body.checks.db).toBeTruthy();
    expect(body.checks.schedulers).toBeTruthy();
    expect(body.checks.webhooks).toBeTruthy();

    // DB always reports ok on a healthy stack.
    expect(body.checks.db.status).toBe("ok");

    // Schedulers block carries a lastRuns map (may be sparse on a fresh DB).
    expect(typeof body.checks.schedulers.status).toBe("string");
    expect(body.checks.schedulers.lastRuns).toBeTruthy();
    expect(typeof body.checks.schedulers.lastRuns).toBe("object");

    // Webhook block carries the two counters.
    expect(typeof body.checks.webhooks.status).toBe("string");
    expect(typeof body.checks.webhooks.deliveries24h).toBe("number");
    expect(typeof body.checks.webhooks.errors24h).toBe("number");
  });

  test("API: works with no auth headers at all (public endpoint)", async ({
    request,
  }) => {
    // Explicitly drop the default extraHTTPHeaders so we know there's
    // nothing carrying the request. If a misguided middleware change
    // ever puts /api/health behind auth, this test will flip to 401.
    const res = await request.fetch(`${BACKEND}/api/health`, {
      method: "GET",
      headers: {},
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.status).toBeTruthy();
    expect(body.checks).toBeTruthy();
  });

  test("API: known-error scheduler tick degrades the schedulers block", async ({
    request,
  }) => {
    // We arm a one-shot failure on `snapshot`, drive it once, and assert
    // the health endpoint reports schedulers.status === 'degraded'. We
    // do NOT inject errors on every scheduler — that could combine with
    // a freshness-degraded scheduler to leave the top-level status as
    // `error` (which is HTTP 503, breaking any test that runs after us).
    const inject = await request.post(
      `${BACKEND}/api/test/inject-scheduler-error`,
      {
        headers: { "Content-Type": "application/json" },
        data: { name: "snapshot" },
      },
    );
    expect(inject.status()).toBe(204);

    const trigger = await request.post(`${BACKEND}/api/test/run-scheduler`, {
      headers: { "Content-Type": "application/json" },
      data: { name: "snapshot" },
    });
    expect(trigger.ok()).toBe(true);
    const triggerBody = await trigger.json();
    expect(triggerBody.ok).toBe(false);

    const res = await request.get(`${BACKEND}/api/health`);
    expect(res.status()).toBe(200);
    const body = await res.json();

    // The snapshot row's status is now `error`, so the schedulers block
    // must report `degraded`. The top-level must also be `degraded` (a
    // freshness-degraded scheduler can't make it worse).
    expect(body.checks.schedulers.status).toBe("degraded");
    expect(body.status).toBe("degraded");
  });

  test("API: a mixed-success webhook delivery batch reports degraded", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    // Create a webhook pointed at a refused port. Firing /test against
    // it writes a delivery row with `error` populated by the reqwest
    // connection-refused error.
    const broken = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "broken", url: UNREACHABLE_URL },
      })
      .then((r) => {
        expect(r.status()).toBe(201);
        return r.json();
      });

    // Create a second webhook pointed at /api/health itself. The
    // dispatcher only flips a row to `error` when the request itself
    // fails — a 200 reply leaves `error` null even though the body
    // isn't a Slack endpoint. This gives us a deterministic success
    // delivery alongside the failed one, so errors24h < deliveries24h
    // and the webhook check lands on `degraded` rather than `error`.
    const working = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "ok", url: `${BACKEND}/api/health` },
      })
      .then((r) => {
        expect(r.status()).toBe(201);
        return r.json();
      });

    const fireBroken = await request.post(
      `${BACKEND}/api/webhooks/${broken.id}/test`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(fireBroken.status()).toBe(202);
    const fireWorking = await request.post(
      `${BACKEND}/api/webhooks/${working.id}/test`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(fireWorking.status()).toBe(202);

    // Both deliveries fan out via tokio::spawn, so poll until the
    // error row lands. The success row will land at least as fast as
    // the error row (no socket timeout), so by the time we've seen the
    // error, both rows are visible to /api/health's COUNT.
    await waitForErrorDelivery(request, "alice", broken.id);

    // Make extra sure the working delivery has landed before we
    // sample /api/health — without it, errors==total briefly.
    const start = Date.now();
    while (Date.now() - start < 5000) {
      const res = await request.get(
        `${BACKEND}/api/webhooks/${working.id}/deliveries`,
        { headers: { "X-User-Id": "alice" } },
      );
      if (res.ok()) {
        const rows = await res.json();
        if (rows.length >= 1) break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }

    const res = await request.get(`${BACKEND}/api/health`);
    expect(res.status()).toBe(200);
    const body = await res.json();

    expect(body.checks.webhooks.deliveries24h).toBeGreaterThanOrEqual(2);
    expect(body.checks.webhooks.errors24h).toBeGreaterThanOrEqual(1);
    expect(body.checks.webhooks.errors24h).toBeLessThan(
      body.checks.webhooks.deliveries24h,
    );
    // Mixed errors → webhook check is `degraded`, top-level is
    // `degraded` (or worse if scheduler freshness also kicks in, but
    // never `error` since no scheduler tick errored in this test).
    expect(body.checks.webhooks.status).toBe("degraded");
    expect(body.status).toBe("degraded");
  });
});
