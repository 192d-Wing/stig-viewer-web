import { test, expect } from "@playwright/test";
import { loadDemoStig } from "./helpers.js";

test.describe("Exports", () => {
  test.beforeEach(async ({ page }) => {
    await loadDemoStig(page);
  });

  test("Export .ckl downloads a valid CKL file", async ({ page }) => {
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export .ckl" }).click();
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toMatch(/\.ckl$/);

    const content = await (await download.createReadStream()).toArray();
    const xml = Buffer.concat(content).toString("utf-8");
    expect(xml).toContain("<CHECKLIST>");
    expect(xml).toContain("</CHECKLIST>");
    expect(xml).toContain("V-1001");
  });

  test("Export POAM modal opens and downloads CSV", async ({ page }) => {
    // The sample STIG already has an open rule (V-1006), so there's something to export
    await page.getByRole("button", { name: "Export POAM" }).click();
    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();
    await expect(modal).toContainText("Export POA&M");

    await expect(modal.getByText(/\d+ Open findings/)).toBeVisible();

    const downloadPromise = page.waitForEvent("download");
    await modal.getByRole("button", { name: "Download CSV" }).click();
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toMatch(/POAM\.csv$/);
  });

  test("Export POAM as JSON", async ({ page }) => {
    await page.getByRole("button", { name: "Export POAM" }).click();
    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();

    // Select "Open + Not Reviewed" scope
    await modal.getByText(/Open \+ Not Reviewed/).click();

    const downloadPromise = page.waitForEvent("download");
    await modal.getByRole("button", { name: "Download JSON" }).click();
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toMatch(/POAM\.json$/);
  });
});
