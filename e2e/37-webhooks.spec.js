import { test, expect } from "@playwright/test";
import { resetDb, setUserRole, BACKEND } from "./helpers.js";

// Address that's guaranteed to fail to connect (port 1 reserved/unused
// on every dev box we care about). The reqwest POST errors out and the
// delivery row gets written with a populated `error` column — that's
// what we assert on below.
const UNREACHABLE_URL = "http://127.0.0.1:1/webhook";

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

/**
 * Poll the deliveries endpoint until at least `min` rows are present or
 * the timeout fires. The webhook fan-out runs in a spawned task, so the
 * row may not exist the instant the PATCH/test returns.
 */
async function waitForDeliveries(request, adminName, webhookId, min = 1, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await request.get(
      `${BACKEND}/api/webhooks/${webhookId}/deliveries`,
      { headers: { "X-User-Id": adminName } },
    );
    if (res.ok()) {
      const rows = await res.json();
      if (rows.length >= min) return rows;
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`waitForDeliveries: never reached ${min} rows`);
}

test.describe("Outbound webhooks", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: non-admin GET /api/webhooks is 403", async ({ request }) => {
    await ensureUser(request, "alice");
    const res = await request.get(`${BACKEND}/api/webhooks`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(403);
  });

  test("API: admin can CRUD webhooks", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    // Create with no kinds → defaults to ['assigned'].
    const created = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "Slack #sec", url: "https://example.invalid/hook" },
      })
      .then((r) => {
        expect(r.status()).toBe(201);
        return r.json();
      });
    expect(created.id).toBeTruthy();
    expect(created.kinds).toEqual(["assigned"]);
    expect(created.enabled).toBe(true);

    // List returns the freshly-created row.
    const listed = await request
      .get(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(listed.length).toBe(1);
    expect(listed[0].name).toBe("Slack #sec");

    // PATCH partial update — flip enabled and rename.
    const updated = await request
      .patch(`${BACKEND}/api/webhooks/${created.id}`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "Slack #incidents", enabled: false },
      })
      .then((r) => {
        expect(r.status()).toBe(200);
        return r.json();
      });
    expect(updated.name).toBe("Slack #incidents");
    expect(updated.enabled).toBe(false);
    expect(updated.url).toBe("https://example.invalid/hook");

    // 400 on bad URL.
    const badRes = await request.post(`${BACKEND}/api/webhooks`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "x", url: "ftp://no" },
    });
    expect(badRes.status()).toBe(400);

    // 404 on update of a non-existent id.
    const missingRes = await request.patch(
      `${BACKEND}/api/webhooks/does-not-exist`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "nope" },
      },
    );
    expect(missingRes.status()).toBe(404);

    // DELETE.
    const delRes = await request.delete(
      `${BACKEND}/api/webhooks/${created.id}`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(delRes.status()).toBe(204);

    const after = await request
      .get(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(after.length).toBe(0);
  });

  test("API: assigning a rule produces a delivery row", async ({ request }) => {
    // Promote alice to admin so she can create webhooks. She also owns
    // the asset/checklist for the assignment side of the test.
    await ensureUser(request, "alice");
    const bob = await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    // A webhook pointed at an unreachable host. The POST will fail, but
    // a webhook_deliveries row with an `error` column still gets written
    // — that's the signal the dispatch path actually ran.
    const hook = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: {
          name: "test-hook",
          url: UNREACHABLE_URL,
          kinds: ["assigned"],
        },
      })
      .then((r) => r.json());

    // Seed asset + checklist + first rule open, assigned to bob.
    const asset = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "webhook-host" },
      })
      .then((r) => r.json());
    const checklist = await request
      .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { stigId: "edge" },
      })
      .then((r) => r.json());
    const detail = await request
      .get(`${BACKEND}/api/checklists/${checklist.id}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    const ruleId = detail.rules[0].id;
    const patchRes = await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: {
          status: "open",
          assigneeId: bob,
          dueDate: "2026-12-31",
        },
      },
    );
    expect(patchRes.ok()).toBe(true);

    const rows = await waitForDeliveries(request, "alice", hook.id, 1);
    const row = rows[0];
    expect(row.kind).toBe("assigned");
    // The POST to 127.0.0.1:1 fails → error string populated, http_status null.
    expect(row.error).toBeTruthy();
    expect(row.httpStatus).toBeNull();
    // Payload is the Slack-shaped JSON we generated server-side.
    expect(row.payload).toContain("assigned to");
    expect(row.payload).toContain("webhook-host");
  });

  test("API: disabled webhooks do not receive events", async ({ request }) => {
    await ensureUser(request, "alice");
    const bob = await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    const hook = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "off", url: UNREACHABLE_URL, kinds: ["assigned"] },
      })
      .then((r) => r.json());
    // Disable it.
    await request.patch(`${BACKEND}/api/webhooks/${hook.id}`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { enabled: false },
    });

    // Drive an assignment.
    const asset = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "disabled-host" },
      })
      .then((r) => r.json());
    const checklist = await request
      .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { stigId: "edge" },
      })
      .then((r) => r.json());
    const detail = await request
      .get(`${BACKEND}/api/checklists/${checklist.id}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    const ruleId = detail.rules[0].id;
    await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open", assigneeId: bob },
      },
    );

    // Give the dispatcher a generous window to *not* deliver.
    await new Promise((r) => setTimeout(r, 1000));
    const rows = await request
      .get(`${BACKEND}/api/webhooks/${hook.id}/deliveries`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(rows.length).toBe(0);
  });

  test("API: /test endpoint creates a delivery row", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const hook = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "manual-test", url: UNREACHABLE_URL },
      })
      .then((r) => r.json());

    const testRes = await request.post(
      `${BACKEND}/api/webhooks/${hook.id}/test`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect([200, 202, 204]).toContain(testRes.status());

    const rows = await waitForDeliveries(request, "alice", hook.id, 1);
    expect(rows[0].kind).toBe("assigned");
    expect(rows[0].error).toBeTruthy();
    expect(rows[0].payload).toContain("SV-TEST");
  });

  test("API: non-admin cannot hit /test or /deliveries", async ({ request }) => {
    await ensureUser(request, "alice");
    await ensureUser(request, "mallory");
    await setUserRole("alice", "admin");

    const hook = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "guarded", url: UNREACHABLE_URL },
      })
      .then((r) => r.json());

    const t = await request.post(`${BACKEND}/api/webhooks/${hook.id}/test`, {
      headers: { "X-User-Id": "mallory" },
    });
    expect(t.status()).toBe(403);

    const d = await request.get(
      `${BACKEND}/api/webhooks/${hook.id}/deliveries`,
      { headers: { "X-User-Id": "mallory" } },
    );
    expect(d.status()).toBe(403);
  });
});
