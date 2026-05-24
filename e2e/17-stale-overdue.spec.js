import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedOverdueAndStale(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "alert-host" },
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

  // Open the rule with a due date in the past.
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "open", dueDate: "2020-01-01" },
    },
  );

  // Backdate the row's updated_at 60 days so it's stale (default 30d).
  await request.post(`${BACKEND}/api/test/backdate-rule`, {
    headers: { "Content-Type": "application/json" },
    data: { checklist_id: checklist.id, rule_id: ruleId, days: 60 },
  });

  return { ruleId };
}

test.describe("Overdue + stale alerts", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("dashboard KPIs show Overdue and Stale counts after seeding", async ({
    page,
    request,
  }) => {
    await seedOverdueAndStale(request);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // Both KPI cards visible with count = 1; "View details" link beside each.
    await expect(page.getByText("Overdue").first()).toBeVisible();
    await expect(page.getByText("Stale (>30d)").first()).toBeVisible();
  });

  test("clicking Overdue KPI opens drill-down filtered to past-due findings", async ({
    page,
    request,
  }) => {
    const { ruleId } = await seedOverdueAndStale(request);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // Click the "View details" link beneath the Overdue card. There are
    // three view-details links (Open / Overdue / Stale). Use a parent
    // scope on the KPI ColumnLayout to target the one under "Overdue".
    const viewDetailsLinks = page.getByRole("button", { name: /view details/i });
    // Order in the row: Open, Overdue, Stale → Overdue is index 1.
    await viewDetailsLinks.nth(1).click();

    await expect(
      page.getByRole("heading", { name: /^Overdue findings/ }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(`text=${ruleId}`).first()).toBeVisible();
  });

  test("clicking Stale KPI opens drill-down filtered to stale findings", async ({
    page,
    request,
  }) => {
    const { ruleId } = await seedOverdueAndStale(request);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    const viewDetailsLinks = page.getByRole("button", { name: /view details/i });
    // Stale is index 2.
    await viewDetailsLinks.nth(2).click();

    await expect(
      page.getByRole("heading", { name: /^Stale findings/ }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(`text=${ruleId}`).first()).toBeVisible();
  });
});
