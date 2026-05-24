import { test, expect } from "@playwright/test";
import { loadDemoStig } from "./helpers.js";

test.describe("Rule Navigation", () => {
  test.beforeEach(async ({ page }) => {
    await loadDemoStig(page);
  });

  test("search by rule ID filters the list", async ({ page }) => {
    await page.getByPlaceholder(/search/i).fill("V-1001");

    // Should show only the matching rule
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByText("V-1001")).toBeVisible();
    // Other rules should be hidden
    await expect(listbox.getByText("V-1004")).toBeHidden();
  });

  test("search by text content filters results", async ({ page }) => {
    await page.getByPlaceholder(/search/i).fill("TLS");

    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByText("V-1003")).toBeVisible();
  });

  test("filter by severity shows only matching rules", async ({ page }) => {
    // Click the Severity select (Cloudscape Select renders as a button)
    await page.getByRole("button", { name: /Severity/ }).first().click();
    // Select CAT I (exact match to avoid matching rule items)
    await page
      .getByRole("option", { name: "CAT I", exact: true })
      .click();

    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByText("V-1001")).toBeVisible();
    await expect(listbox.getByText("V-1002")).toBeVisible();
    await expect(listbox.getByText("V-1003")).toBeVisible();

    // CAT II rules should not be visible
    await expect(listbox.getByText("V-1004")).toBeHidden();
  });

  test("filter by status shows only matching rules", async ({ page }) => {
    // Click the Status select
    await page.getByRole("button", { name: /Status/ }).first().click();
    await page.getByRole("option", { name: "Open", exact: true }).click();

    const listbox = page.getByRole("listbox", { name: "Rules" });
    // V-1006 is the only open rule in sample data
    await expect(listbox.getByText("V-1006")).toBeVisible();
    await expect(listbox.getByText("V-1001")).toBeHidden();
  });

  test("clearing search restores all rules", async ({ page }) => {
    const searchInput = page.getByPlaceholder(/search/i);
    const listbox = page.getByRole("listbox", { name: "Rules" });

    await searchInput.fill("V-1001");
    await expect(listbox.getByText("V-1004")).toBeHidden();

    await searchInput.fill("");

    await expect(listbox.getByText("V-1001")).toBeVisible();
    await expect(listbox.getByText("V-1004")).toBeVisible();
    await expect(listbox.getByText("V-1012")).toBeVisible();
  });
});
