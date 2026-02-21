import { test, expect } from "@playwright/test";
import { resetDb } from "./helpers.js";

test.describe("User Setup", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("shows welcome modal on first visit", async ({ page }) => {
    await page.goto("/");
    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();
    await expect(modal).toContainText("Welcome to STIG Tools");
    await expect(modal.getByLabel("Display Name")).toBeVisible();
  });

  test("creates user and dismisses modal after entering name", async ({
    page,
  }) => {
    await page.goto("/");
    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();

    await modal.getByLabel("Display Name").fill("E2E Tester");
    await modal.getByRole("button", { name: "Get Started" }).click();

    // Modal should disappear
    await expect(modal).toBeHidden();

    // userId should be persisted in localStorage
    const userId = await page.evaluate(() => localStorage.getItem("userId"));
    expect(userId).toBe("E2E Tester");
  });

  test("skips modal on revisit when userId is already stored", async ({
    page,
  }) => {
    // First visit — set up the user
    await page.goto("/");
    const modal = page.getByRole("dialog");
    await modal.getByLabel("Display Name").fill("E2E Tester");
    await modal.getByRole("button", { name: "Get Started" }).click();
    await expect(modal).toBeHidden();

    // Reload — modal should not reappear
    await page.reload();
    await expect(page.getByRole("dialog")).toBeHidden();
  });
});
