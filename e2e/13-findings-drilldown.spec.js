import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedOneOpenFinding(request, { stigId = "edge" } = {}) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "drill-host" },
    })
    .then((r) => r.json());
  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId },
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
  return { ruleId, assetName: "drill-host" };
}

test.describe("Dashboard findings drill-down", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("View details on Open findings opens drill-down listing the finding", async ({
    page,
    request,
  }) => {
    const { ruleId, assetName } = await seedOneOpenFinding(request);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // Open findings KPI shows the link
    const detailsBtn = page.getByRole("button", { name: /view details/i });
    await expect(detailsBtn).toBeVisible();
    await detailsBtn.click();

    await expect(
      page.getByRole("heading", { name: /^Open findings/ }),
    ).toBeVisible();
    await expect(page.locator(`text=${ruleId}`).first()).toBeVisible();
    await expect(page.locator(`text=${assetName}`).first()).toBeVisible();

    // Close
    await page.getByRole("button", { name: "Close", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: /^Open findings/ }),
    ).toHaveCount(0);
  });

  test("Clicking a Top-open-rules row drills to that rule across systems", async ({
    page,
    request,
  }) => {
    const { ruleId } = await seedOneOpenFinding(request);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // The rule link in the Top-open-rules table
    await page.getByRole("button", { name: ruleId }).click();

    await expect(
      page.getByRole("heading", { name: /^Rule drill-down/ }),
    ).toBeVisible();
    await expect(page.locator(`text=${ruleId}`).first()).toBeVisible();
  });
});
