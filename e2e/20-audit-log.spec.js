import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedTwoPatches(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "audit-host" },
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
      data: { status: "open", findingDetails: "first finding" },
    },
  );
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "not_a_finding", findingDetails: "resolved" },
    },
  );
  return { checklistId: checklist.id, ruleId };
}

test.describe("Audit log", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("rule-history endpoint returns one row per changed field, newest first", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedTwoPatches(request);
    const rows = await request
      .get(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/history`,
        { headers: { "X-User-Id": "alice" } },
      )
      .then((r) => r.json());

    // 2 PATCHes × 2 changed fields each = 4 audit rows.
    expect(rows.length).toBe(4);
    // Newest first → first entry is from the second PATCH.
    expect(rows[0].toValue === "resolved" || rows[0].toValue === "not_a_finding").toBe(
      true,
    );
    expect(rows.every((r) => r.userName === "alice")).toBe(true);
  });

  test("Recent activity appears on dashboard with entries", async ({
    page,
    request,
  }) => {
    await seedTwoPatches(request);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    await expect(
      page.getByRole("heading", { name: /Recent activity/i }),
    ).toBeVisible({ timeout: 10_000 });
    // The widget shows audit-log rows with field labels.
    await expect(page.getByText(/finding details/i).first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("clicking a finding in the drill-down shows its History timeline", async ({
    page,
    request,
  }) => {
    const { ruleId } = await seedTwoPatches(request);
    // Re-open the finding so it shows in the open drill-down.
    // (After the second PATCH it's NaF; flip it back to Open for this test.)
    const checklistId = (await request
      .get(`${BACKEND}/api/findings?status=not_a_finding`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json()))[0].checklistId;
    await request.patch(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open" },
      },
    );

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: /view details/i }).click();

    // Wait for both Top-Open-Rules and the drill-down to render the rule.
    const ruleButtons = page.getByRole("button", { name: ruleId });
    await expect(ruleButtons).toHaveCount(2, { timeout: 10_000 });
    await ruleButtons.last().click();

    // History section appears once expanded
    await expect(page.getByText("History", { exact: true })).toBeVisible({
      timeout: 10_000,
    });
  });
});
