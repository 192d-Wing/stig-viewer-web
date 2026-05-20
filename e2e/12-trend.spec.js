import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

test.describe("Posture trend", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("trend section appears after snapshots are captured", async ({
    page,
    request,
  }) => {
    // Seed an asset + checklist + one open rule
    const asset = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "trend-host" },
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

    // Take two snapshots ~1.2s apart so the (captured_at, checklist_id) PK
    // doesn't collide.
    await request.post(`${BACKEND}/api/test/snapshot`);
    await page.waitForTimeout(1200);
    await request.post(`${BACKEND}/api/test/snapshot`);

    // Open the Dashboard and verify the Trend section is visible.
    await page.goto("/");
    await page
      .getByRole("button", { name: "Dashboard", exact: true })
      .click();

    await expect(
      page.getByRole("heading", { name: /Posture over time/i }),
    ).toBeVisible();
    // Two snapshots in the description text. Both Posture and Compliance
    // charts share the same "N snapshots…" caption, so use .first().
    await expect(
      page.getByText(/2 snapshots in the last 30 days/i).first(),
    ).toBeVisible();
  });

  test("no trend section before any snapshots exist", async ({ page }) => {
    await page.goto("/");
    await page
      .getByRole("button", { name: "Dashboard", exact: true })
      .click();

    await expect(
      page.getByRole("heading", { name: /Compliance dashboard/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: /Posture over time/i }),
    ).toHaveCount(0);
  });
});
