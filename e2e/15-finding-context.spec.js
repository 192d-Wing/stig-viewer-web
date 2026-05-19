import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedOneOpenFinding(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "ctx-host" },
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
  const rule = detail.rules[0];
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(rule.id)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "open" },
    },
  );
  return { ruleId: rule.id, title: rule.title };
}

test.describe("Finding inline context", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("clicking a rule expands the inline detail panel", async ({
    page,
    request,
  }) => {
    const { ruleId, title } = await seedOneOpenFinding(request);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: /view details/i }).click();
    // Wait for the rule button to render in BOTH Top-Open-Rules and the
    // drill-down (count === 2) before .last() resolves to the drill-down
    // button — otherwise the click can race the drill-down fetch.
    const ruleButtons = page.getByRole("button", { name: ruleId });
    await expect(ruleButtons).toHaveCount(2, { timeout: 10_000 });
    await ruleButtons.last().click();

    // Wait for the Close button on the detail panel — most reliable
    // indicator that the panel has rendered.
    const closeBtn = page.getByRole("button", { name: "Close", exact: true }).last();
    await expect(closeBtn).toBeVisible({ timeout: 10_000 });

    // Detail content shows rule title + section labels.
    await expect(page.getByText(title, { exact: false }).first()).toBeVisible();
    await expect(page.getByText("Check", { exact: true })).toBeVisible();
    await expect(page.getByText("Fix", { exact: true })).toBeVisible();

    // Close collapses the panel.
    await closeBtn.click();
    await expect(page.getByText("Check", { exact: true })).toHaveCount(0);
  });

  test("clicking the same rule again collapses the panel", async ({
    page,
    request,
  }) => {
    const { ruleId } = await seedOneOpenFinding(request);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: /view details/i }).click();
    const ruleButtons = page.getByRole("button", { name: ruleId });
    await expect(ruleButtons).toHaveCount(2, { timeout: 10_000 });
    const ruleBtn = ruleButtons.last();
    await ruleBtn.click();
    await expect(
      page.getByRole("button", { name: "Close", exact: true }).last(),
    ).toBeVisible({ timeout: 10_000 });

    // Click again to toggle off
    await ruleBtn.click();
    await expect(page.getByText("Check", { exact: true })).toHaveCount(0);
  });
});
