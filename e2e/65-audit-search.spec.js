import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Auto-create the test user via the X-User-Id bypass and return the
 * generated UUID. We never key off the user-supplied name because
 * `user.id` is a server-side UUID, not the X-User-Id string.
 */
async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

/**
 * Create an asset + checklist as `userName`, then patch the first rule a
 * configurable number of times. Each PATCH writes one audit row per
 * changed field, so the caller knows exactly how many rows landed.
 *
 * Returns the created asset id, checklist id, and the rule id that was
 * mutated. The asset name is the caller-supplied `assetName` so the UI
 * test can assert on a stable label.
 */
async function seedActivity(request, userName, assetName, patches, ruleIndex = 0) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: {
        "X-User-Id": userName,
        "Content-Type": "application/json",
      },
      data: { name: assetName },
    })
    .then((r) => r.json());

  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: {
        "X-User-Id": userName,
        "Content-Type": "application/json",
      },
      data: { stigId: "edge" },
    })
    .then((r) => r.json());

  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": userName },
    })
    .then((r) => r.json());
  const ruleId = detail.rules[ruleIndex].id;

  for (const body of patches) {
    const res = await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
      {
        headers: {
          "X-User-Id": userName,
          "Content-Type": "application/json",
        },
        data: body,
      },
    );
    expect(res.ok()).toBe(true);
  }

  return { assetId: asset.id, checklistId: checklist.id, ruleId };
}

async function backdateRule(request, ruleId, days) {
  const res = await request.post(`${BACKEND}/api/test/backdate-audit`, {
    headers: { "Content-Type": "application/json" },
    data: { rule_id: ruleId, days },
  });
  expect([200, 204]).toContain(res.status());
}

test.describe("Audit log search", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: non-admin GET /api/audit/search is 403", async ({ request }) => {
    await ensureUser(request, "alice");
    const res = await request.get(`${BACKEND}/api/audit/search`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(403);
  });

  test("API: admin GET with no filters returns recent rows", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    await seedActivity(request, "alice", "alice-host", [
      { status: "open", findingDetails: "first" },
    ]);

    const res = await request.get(`${BACKEND}/api/audit/search`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty("totalCount");
    expect(body).toHaveProperty("page", 1);
    expect(body).toHaveProperty("pageSize", 50);
    expect(Array.isArray(body.rows)).toBe(true);
    expect(body.totalCount).toBeGreaterThan(0);
    expect(body.rows.length).toBeGreaterThan(0);
    const row = body.rows[0];
    for (const key of [
      "id",
      "occurredAt",
      "byName",
      "assetName",
      "stigTitle",
      "ruleId",
      "field",
      "fromValue",
      "toValue",
    ]) {
      expect(row).toHaveProperty(key);
    }
  });

  test("API: filter by userId returns only that user's changes", async ({
    request,
  }) => {
    const aliceId = await ensureUser(request, "alice");
    await ensureUser(request, "bob");
    await ensureUser(request, "carol");
    await setUserRole("carol", "admin");

    await seedActivity(request, "alice", "alice-host", [
      { status: "open", findingDetails: "alice change" },
    ]);
    await seedActivity(request, "bob", "bob-host", [
      { status: "open", findingDetails: "bob change" },
    ]);

    const res = await request.get(
      `${BACKEND}/api/audit/search?userId=${aliceId}`,
      { headers: { "X-User-Id": "carol" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.totalCount).toBeGreaterThan(0);
    // Every row should be attributed to alice — the join uses
    // display_name, so the cheap assertion is "byName matches".
    for (const r of body.rows) {
      expect(r.byName).toBe("alice");
    }
  });

  test("API: filter by assetId returns only that asset's changes", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const a = await seedActivity(request, "alice", "alpha-host", [
      { status: "open", findingDetails: "on alpha" },
    ]);
    await seedActivity(request, "alice", "beta-host", [
      { status: "open", findingDetails: "on beta" },
    ]);

    const res = await request.get(
      `${BACKEND}/api/audit/search?assetId=${a.assetId}`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.totalCount).toBeGreaterThan(0);
    for (const r of body.rows) {
      expect(r.assetName).toBe("alpha-host");
    }
  });

  test("API: filter by date range narrows correctly", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    // Seed two distinct rules so we can backdate one independently of
    // the other. After the backdate, the "old" rule's rows live 60
    // days in the past — outside a from=yesterday window.
    // IMPORTANT: use different rule indices because backdate_audit shifts
    // ALL rows matching rule_id, and both checklists use the edge STIG —
    // so if both pick rules[0] the backdate hits both.
    const old = await seedActivity(
      request,
      "alice",
      "old-host",
      [{ status: "open", findingDetails: "long ago" }],
      0,
    );
    await seedActivity(
      request,
      "alice",
      "new-host",
      [{ status: "open", findingDetails: "just now" }],
      1,
    );
    await backdateRule(request, old.ruleId, 60);

    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000)
      .toISOString()
      .slice(0, 10);

    // Range = [yesterday, today] — should exclude the 60-day-old rows.
    const res = await request.get(
      `${BACKEND}/api/audit/search?from=${yesterday}`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.totalCount).toBeGreaterThan(0);
    for (const r of body.rows) {
      expect(r.assetName).toBe("new-host");
    }

    // Inverse range = far past → yesterday should pick up only the old rows.
    const farPast = "1970-01-01";
    const res2 = await request.get(
      `${BACKEND}/api/audit/search?from=${farPast}&to=${yesterday}`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res2.status()).toBe(200);
    const body2 = await res2.json();
    expect(body2.totalCount).toBeGreaterThan(0);
    for (const r of body2.rows) {
      expect(r.assetName).toBe("old-host");
    }
  });

  test("API: pagination — page=2 with pageSize=2 returns the next two rows", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    // 4 PATCHes × 2 fields each = 8 audit rows, plenty for paging.
    await seedActivity(request, "alice", "page-host", [
      { status: "open", findingDetails: "one" },
      { status: "not_a_finding", findingDetails: "two" },
      { status: "open", findingDetails: "three" },
      { status: "not_a_finding", findingDetails: "four" },
    ]);

    const page1 = await (
      await request.get(
        `${BACKEND}/api/audit/search?pageSize=2&page=1`,
        { headers: { "X-User-Id": "alice" } },
      )
    ).json();
    const page2 = await (
      await request.get(
        `${BACKEND}/api/audit/search?pageSize=2&page=2`,
        { headers: { "X-User-Id": "alice" } },
      )
    ).json();

    expect(page1.rows.length).toBe(2);
    expect(page2.rows.length).toBe(2);
    // Page 2 must be the next slice, not a repeat. Newest-first
    // ordering means page1 ids are strictly larger than page2 ids.
    const page1Ids = page1.rows.map((r) => r.id).sort((a, b) => a - b);
    const page2Ids = page2.rows.map((r) => r.id).sort((a, b) => a - b);
    for (const id of page2Ids) {
      expect(page1Ids).not.toContain(id);
    }
    expect(page1.totalCount).toBe(page2.totalCount);
  });

  test("API: invalid date param returns 400", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const res = await request.get(
      `${BACKEND}/api/audit/search?from=not-a-date`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(400);
  });

  test("UI: admin console renders the Audit log section and shows filtered rows", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "alice");
    await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    // Seed enough mixed activity that the table has visible rows once
    // the admin clicks Search.
    await seedActivity(request, "alice", "alice-ui-host", [
      { status: "open", findingDetails: "alice mark 1" },
      { status: "not_a_finding", findingDetails: "alice mark 2" },
    ]);
    await seedActivity(request, "bob", "bob-ui-host", [
      { status: "open", findingDetails: "bob mark" },
    ]);

    await loginAs(page, "alice");
    await page.goto("/?view=admin");

    const heading = page.getByRole("heading", { name: /^Audit log/ });
    await expect(heading).toBeVisible({ timeout: 10_000 });

    const table = page.getByTestId("audit-search-table");
    await expect(table).toBeVisible();

    // Hit Search with no filters first — should populate the table.
    await page.getByTestId("audit-search-button").click();
    await expect(table).toContainText("alice", { timeout: 10_000 });
    await expect(table).toContainText("bob");

    // Now narrow to alice via the User Select. Cloudscape Selects open a
    // dropdown; we type the name in the filter input and click the row.
    const userSelect = page.getByTestId("audit-user-select");
    await userSelect.click();
    await page
      .getByRole("option", { name: /^alice/ })
      .first()
      .click();
    await page.getByTestId("audit-search-button").click();

    // After narrowing, "alice" rows should still be visible. The
    // strongest assertion that bob is gone is to wait for the row count
    // to settle without bob's mark — checking via `not.toContainText`
    // would race the previous render, so we look for an alice-only
    // marker text first.
    await expect(table).toContainText("alice mark 1", { timeout: 10_000 });
    await expect(table).not.toContainText("bob mark");
  });
});
