import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

test.describe("Compliance dashboard", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
  });

  test("renders empty state when no assets exist", async ({ page }) => {
    await expect(
      page.getByRole("heading", { name: /Compliance dashboard/i }),
    ).toBeVisible();
    await expect(
      page.getByText("No systems yet", { exact: false }),
    ).toBeVisible();
  });

  test("renders KPIs, per-asset table, and top open rules after seeding", async ({
    page,
    request,
  }) => {
    // Seed: 1 asset + 1 checklist (edge STIG) + 1 open rule
    const asset = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "e2e-host" },
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
        data: { status: "open" },
      },
    );

    // Refresh and verify the dashboard reflects the seed
    await page.getByRole("button", { name: /refresh/i }).click();

    // Per-asset table shows the asset
    await expect(page.locator("text=e2e-host").first()).toBeVisible();

    // Top open rules table appears with the seeded rule
    await expect(page.getByText("Top open rules")).toBeVisible();
    await expect(page.locator(`text=${ruleId}`).first()).toBeVisible();
  });
});
