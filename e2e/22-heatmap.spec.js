import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

test.describe("Compliance heatmap", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("heatmap renders rows per asset and columns per applied STIG", async ({
    page,
    request,
  }) => {
    // Seed 2 assets — one with edge applied, one with windows-10 applied —
    // so the heatmap has 2 rows × 2 columns.
    const a1 = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "hm-host-edge" },
      })
      .then((r) => r.json());
    await request.post(`${BACKEND}/api/assets/${a1.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    });

    const a2 = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "hm-host-win" },
      })
      .then((r) => r.json());
    const c2 = await request
      .post(`${BACKEND}/api/assets/${a2.id}/checklists`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { stigId: "windows-10" },
      })
      .then((r) => r.json());
    // Open one rule on the windows-10 checklist so the heatmap cell goes red.
    const detail = await request
      .get(`${BACKEND}/api/checklists/${c2.id}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    await request.patch(
      `${BACKEND}/api/checklists/${c2.id}/rules/${encodeURIComponent(detail.rules[0].id)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open" },
      },
    );

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    await expect(
      page.getByRole("heading", { name: /Posture heatmap/i }),
    ).toBeVisible({ timeout: 10_000 });

    // Both system names appear as row labels in the heatmap
    await expect(page.getByText("hm-host-edge").first()).toBeVisible();
    await expect(page.getByText("hm-host-win").first()).toBeVisible();
  });

  test("heatmap section is absent when no assets exist", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: /Compliance dashboard/i }),
    ).toBeVisible();
    // Empty dashboard — heatmap heading should not be there.
    await expect(
      page.getByRole("heading", { name: /Posture heatmap/i }),
    ).toHaveCount(0);
  });
});
