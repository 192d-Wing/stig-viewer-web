import { test, expect } from "@playwright/test";
import { loadDemoStig } from "./helpers.js";

test.describe("Rule Detail Panel", () => {
  test.beforeEach(async ({ page }) => {
    await loadDemoStig(page);
  });

  test("clicking a rule opens the split panel", async ({ page }) => {
    // Click on rule V-1001 in the listbox
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await listbox.getByRole("option", { name: /V-1001/ }).click();

    // Split panel should show the rule ID
    await expect(page.getByText("Rule ID: SV-1001r1_rule")).toBeVisible();
  });

  test("changing compliance status updates the stats", async ({ page }) => {
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await listbox.getByRole("option", { name: /V-1001/ }).click();

    // Click "Open" in the segmented control (Compliance Status)
    // The segmented control renders buttons with the status text
    await page.getByRole("button", { name: "Open", exact: true }).click();

    // The status stats should update — open count should increase from 1 to 2
    await expect(page.getByText("Open: 2")).toBeVisible();
  });

  test("clicking a different rule updates the panel", async ({ page }) => {
    const listbox = page.getByRole("listbox", { name: "Rules" });

    await listbox.getByRole("option", { name: /V-1001/ }).click();
    await expect(page.getByText("Rule ID: SV-1001r1_rule")).toBeVisible();

    await listbox.getByRole("option", { name: /V-1004/ }).click();
    await expect(page.getByText("Rule ID: SV-1004r1_rule")).toBeVisible();
  });

  test("finding details textarea accepts input", async ({ page }) => {
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await listbox.getByRole("option", { name: /V-1001/ }).click();

    const textarea = page.getByPlaceholder(/enter finding details/i);
    await textarea.fill("Test finding details for E2E");
    await expect(textarea).toHaveValue("Test finding details for E2E");
  });
});
