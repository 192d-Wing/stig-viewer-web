import { test, expect } from "@playwright/test";
import { loginAs, resetDb } from "./helpers.js";

test.describe("STIG Library", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "lib-tester");
  });

  test("renders the library page with table", async ({ page }) => {
    await page.goto("/");

    // The library / landing page should show the table or empty state
    // Look for the table or the "Browse Library" heading
    const heading = page.locator("h1, h2").filter({ hasText: /library|stig/i });
    await expect(heading.first()).toBeVisible({ timeout: 15_000 });
  });

  test("shows Viewer and Writer mode buttons in top nav", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByRole("button", { name: "Viewer" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Writer" })).toBeVisible();
  });
});
