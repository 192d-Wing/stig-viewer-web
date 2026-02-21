import { test, expect } from "@playwright/test";
import { loadDemoStig } from "./helpers.js";

test.describe("Load Demo STIG", () => {
  test("loads the sample STIG and shows rules", async ({ page }) => {
    await loadDemoStig(page);

    // Should show the STIG title in the page heading
    await expect(
      page.getByRole("heading", { name: /Sample STIG/ }),
    ).toBeVisible();

    // Side nav should show the loaded STIG tab
    await expect(
      page.locator("nav").getByText(/sample stig/i),
    ).toBeVisible();

    // Summary stats should show 12 total rules
    await expect(page.getByText("Total Rules")).toBeVisible();
    await expect(page.locator("main").getByText("12").first()).toBeVisible();
  });

  test("shows correct severity breakdown", async ({ page }) => {
    await loadDemoStig(page);

    // CAT I: 3, CAT II: 6, CAT III: 3
    await expect(page.getByText("CAT I: 3")).toBeVisible();
    await expect(page.getByText("CAT II: 6")).toBeVisible();
    await expect(page.getByText("CAT III: 3")).toBeVisible();
  });
});
