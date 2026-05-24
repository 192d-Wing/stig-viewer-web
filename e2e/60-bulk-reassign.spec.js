import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

// `X-User-Id` is just the auto-create handle; the real user_id is the
// server-generated UUID. Every assignee-related test resolves that UUID
// via /api/users/me before touching the bulk endpoint.
async function whoAmI(request, handle) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": handle },
  });
  if (!res.ok()) {
    throw new Error(`/api/users/me as ${handle} failed: ${res.status()}`);
  }
  return res.json();
}

// Seed alice's asset, apply the edge STIG, open the first N rules and
// assign each to `assigneeUserId`. Returns the ids we need to assert on.
async function seedOpenAssignedToAlice(request, count = 2) {
  const alice = await whoAmI(request, "alice");

  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "reassign-host" },
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

  const ruleIds = [];
  for (let i = 0; i < count; i++) {
    const rid = detail.rules[i].id;
    ruleIds.push(rid);
    await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(rid)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open", assigneeId: alice.id },
      },
    );
  }
  return { checklistId: checklist.id, ruleIds, aliceId: alice.id };
}

test.describe("Bulk reassign — streamlined assignee-only PATCH", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: assignee-only patch reassigns every target to the new user", async ({
    request,
  }) => {
    const { checklistId, ruleIds } = await seedOpenAssignedToAlice(request, 3);
    const bob = await whoAmI(request, "bob");

    const res = await request.patch(`${BACKEND}/api/findings/bulk`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        targets: ruleIds.map((rid) => ({ checklistId, ruleId: rid })),
        patch: { assigneeId: bob.id },
      },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.updated).toBe(ruleIds.length);

    // Confirm via GET — every open finding now points at bob.
    const open = await request
      .get(`${BACKEND}/api/findings?status=open`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(open.length).toBe(ruleIds.length);
    for (const f of open) {
      expect(f.assigneeId).toBe(bob.id);
    }
  });

  test("API: explicit null assignee clears the field on every target", async ({
    request,
  }) => {
    const { checklistId, ruleIds } = await seedOpenAssignedToAlice(request, 2);

    const res = await request.patch(`${BACKEND}/api/findings/bulk`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        targets: ruleIds.map((rid) => ({ checklistId, ruleId: rid })),
        patch: { assigneeId: null },
      },
    });
    expect(res.status()).toBe(200);

    const open = await request
      .get(`${BACKEND}/api/findings?status=open`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(open.length).toBe(ruleIds.length);
    for (const f of open) {
      // Unassigned findings should report no assignee — accept either a
      // null/missing id OR an empty display name, depending on how the
      // server serialises absent fields.
      expect(f.assigneeId ?? null).toBeNull();
      expect(f.assigneeName ?? "").toBe("");
    }
  });

  test("UI: drill-down → multi-select → Reassign updates every row", async ({
    page,
    request,
  }) => {
    const { ruleIds, aliceId } = await seedOpenAssignedToAlice(request, 2);
    const bob = await whoAmI(request, "bob");

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // Open the Open-findings drill-down. The dashboard surfaces a "View
    // details" button on the open-findings KPI card.
    await page.getByRole("button", { name: /view details/i }).click();

    // The drill-down Table picks up its Header text as the accessible
    // name. No positional selectors — we look it up by name.
    const drilldown = page.getByRole("table", { name: /open findings/i });
    await expect(drilldown).toBeVisible({ timeout: 10_000 });

    // Sanity: both seeded findings are present, currently assigned to alice.
    for (const rid of ruleIds) {
      await expect(drilldown.getByText(rid)).toBeVisible();
    }

    // Select all rows via the header "select all" checkbox.
    const selectAll = drilldown.locator('input[type="checkbox"]').first();
    await selectAll.check();

    // Reassign button is enabled now — open the preset modal.
    const reassignBtn = page.getByTestId("reassign-open");
    await expect(reassignBtn).toBeEnabled();
    await reassignBtn.click();

    // Pick bob in the Select. Cloudscape Select renders a trigger button
    // inside our test wrapper; click it then pick the option by visible text.
    const selectWrapper = page.getByTestId("reassign-select");
    await selectWrapper.click();
    await page.getByRole("option", { name: /^bob$/i }).click();

    // Submit.
    await page.getByTestId("reassign-submit").click();

    // Success flash + dashboard refresh.
    await expect(page.getByTestId("reassign-flash")).toBeVisible({
      timeout: 10_000,
    });

    // Re-open the drilldown table (refresh tick re-renders it) and confirm
    // both rows now show bob as the assignee. The "alice" label that was
    // present in the assignee column should no longer appear in the table.
    const drilldown2 = page.getByRole("table", { name: /open findings/i });
    await expect(drilldown2).toBeVisible();
    // bob shows up twice (one per row).
    await expect(drilldown2.getByText(/^bob$/).first()).toBeVisible({
      timeout: 10_000,
    });

    // Belt-and-braces: ask the API directly that the assignee_id on each
    // row was flipped from alice → bob.
    const open = await request
      .get(`${BACKEND}/api/findings?status=open`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(open.length).toBe(ruleIds.length);
    for (const f of open) {
      expect(f.assigneeId).toBe(bob.id);
      expect(f.assigneeId).not.toBe(aliceId);
    }
  });
});
