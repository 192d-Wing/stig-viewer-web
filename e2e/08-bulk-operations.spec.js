import { test, expect } from "@playwright/test";
import { loadDemoStig } from "./helpers.js";

test.describe("Bulk Operations", () => {
  test.beforeEach(async ({ page }) => {
    await loadDemoStig(page);
  });

  test("All NaF sets all rules to not_a_finding", async ({ page }) => {
    await page.getByRole("button", { name: "All NaF" }).click();

    // Progress should show 12 of 12
    await expect(page.getByText("12 of 12")).toBeVisible();

    // "Not a Finding" (lowercase a) count should be 12
    await expect(page.getByText("Not a Finding: 12")).toBeVisible();
  });

  test("Reset All reverts all rules to not_reviewed", async ({ page }) => {
    // First set all to NaF
    await page.getByRole("button", { name: "All NaF" }).click();
    await expect(page.getByText("12 of 12")).toBeVisible();

    // Then reset
    await page.getByRole("button", { name: "Reset All" }).click();

    await expect(page.getByText("Not Reviewed: 12")).toBeVisible();
  });
});
