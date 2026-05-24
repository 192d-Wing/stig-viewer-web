import { test, expect } from "@playwright/test";
import { resetDb, setUserRole, BACKEND } from "./helpers.js";

// Same trick as 37-webhooks: port 1 is reserved/unused everywhere we
// care about, so reqwest fails to connect and `webhook_deliveries` gets
// a row with `error` populated. That's how we prove the dispatch path
// actually ran without standing up a real HTTP receiver.
const UNREACHABLE_URL = "http://127.0.0.1:1/x";

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

/** Poll deliveries until we see at least `min` rows (or time out). */
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

/**
 * Seed an asset + checklist + a single rule patched to status=open with
 * a due_date in the past so it appears in the fleet-wide overdue query.
 * Returns the rule id (not used by the asserts, kept for completeness).
 */
async function seedOverdueFinding(request, ownerName, assigneeId, assetName) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": ownerName, "Content-Type": "application/json" },
      data: { name: assetName },
    })
    .then((r) => r.json());
  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": ownerName, "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": ownerName },
    })
    .then((r) => r.json());
  const ruleId = detail.rules[0].id;
  const patchRes = await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": ownerName, "Content-Type": "application/json" },
      data: {
        status: "open",
        assigneeId,
        // Yesterday — guaranteed `< CURRENT_DATE` on any tz.
        dueDate: "2020-01-01",
      },
    },
  );
  expect(patchRes.ok()).toBe(true);
  return ruleId;
}

async function runDigest(request) {
  const res = await request.post(`${BACKEND}/api/test/run-digest`);
  expect(res.ok()).toBe(true);
  return res.json();
}

test.describe("Overdue digest webhook", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: no enabled digest webhook → count is 0", async ({ request }) => {
    // Even an `assigned`-only webhook should be ignored by the sweep.
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    await request.post(`${BACKEND}/api/webhooks`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "assigned-only", url: UNREACHABLE_URL, kinds: ["assigned"] },
    });

    const { count } = await runDigest(request);
    expect(count).toBe(0);
  });

  test("API: digest fires for overdue_digest webhooks and writes a delivery row", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    const bob = await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    const hook = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: {
          name: "digest",
          url: UNREACHABLE_URL,
          kinds: ["overdue_digest"],
        },
      })
      .then((r) => r.json());
    expect(hook.kinds).toEqual(["overdue_digest"]);

    await seedOverdueFinding(request, "alice", bob, "digest-host");

    const { count } = await runDigest(request);
    expect(count).toBe(1);

    const rows = await waitForDeliveries(request, "alice", hook.id, 1);
    const row = rows[0];
    expect(row.kind).toBe("overdue_digest");
    // POST to 127.0.0.1:1 fails → error string set, http_status null.
    expect(row.error).toBeTruthy();
    expect(row.httpStatus).toBeNull();
    // Payload mentions the fleet-wide overdue count and the asset.
    expect(row.payload).toContain("overdue findings across the fleet");
    expect(row.payload).toContain("digest-host");
  });

  test("API: 23-hour cooldown prevents back-to-back duplicate fires", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    const bob = await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    await request.post(`${BACKEND}/api/webhooks`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        name: "cooldown",
        url: UNREACHABLE_URL,
        kinds: ["overdue_digest"],
      },
    });
    await seedOverdueFinding(request, "alice", bob, "cooldown-host");

    const first = await runDigest(request);
    expect(first.count).toBe(1);

    // Immediate re-run should be a no-op — the webhook's `last_digest_at`
    // is now ~0 seconds old, well inside the 23h window.
    const second = await runDigest(request);
    expect(second.count).toBe(0);
  });

  test("API: 'assigned' webhook is not triggered by the digest", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    const bob = await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    const hook = await request
      .post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "wrong-kind", url: UNREACHABLE_URL, kinds: ["assigned"] },
      })
      .then((r) => r.json());

    await seedOverdueFinding(request, "alice", bob, "wrong-kind-host");
    // The seed step assigns the rule to bob, which fires an 'assigned'
    // delivery on the assigned-only webhook. Snapshot the current row
    // count so we can prove the digest run doesn't add to it.
    await waitForDeliveries(request, "alice", hook.id, 1);
    const before = await request
      .get(`${BACKEND}/api/webhooks/${hook.id}/deliveries`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    const beforeCount = before.length;

    const { count } = await runDigest(request);
    expect(count).toBe(0);

    // Give the digest a generous window to *not* deliver.
    await new Promise((r) => setTimeout(r, 500));
    const after = await request
      .get(`${BACKEND}/api/webhooks/${hook.id}/deliveries`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(after.length).toBe(beforeCount);
    // And none of the existing rows are digest-kind.
    expect(after.every((r) => r.kind === "assigned")).toBe(true);
  });

  test("API: kinds validation rejects unknown values with 400", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const res = await request.post(`${BACKEND}/api/webhooks`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "bogus", url: UNREACHABLE_URL, kinds: ["bogus"] },
    });
    expect(res.status()).toBe(400);
  });
});
