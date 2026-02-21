import { test, expect } from "@playwright/test";
import { loginAs, resetDb } from "./helpers.js";

test.describe("Writer — Draft CRUD", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "draft-author");
  });

  test("create a new draft and see it in the table", async ({ page }) => {
    await page.goto("/");

    // Switch to Writer mode
    await page.getByRole("button", { name: "Writer" }).click();

    // Click "New Draft"
    await page.getByRole("button", { name: "New Draft" }).click();

    // Should navigate to the draft editor — look for "Back to drafts"
    await expect(
      page.getByRole("button", { name: /back/i }),
    ).toBeVisible();

    // Fill in the title
    const titleInput = page.getByLabel(/title/i).first();
    await titleInput.fill("My E2E Draft");

    // Go back to the drafts list
    await page.getByRole("button", { name: /back/i }).click();

    // The draft should appear in the table
    await expect(page.getByText("My E2E Draft")).toBeVisible();
  });

  test("open an existing draft and edit it", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Writer" }).click();

    // Create a draft first
    await page.getByRole("button", { name: "New Draft" }).click();
    await expect(page.getByRole("button", { name: /back/i })).toBeVisible();

    const titleInput = page.getByLabel(/title/i).first();
    await titleInput.fill("Draft To Edit");
    await page.getByRole("button", { name: /back/i }).click();
    await expect(page.getByText("Draft To Edit")).toBeVisible();

    // Open it
    await page.getByRole("button", { name: "Open" }).first().click();
    await expect(page.getByRole("button", { name: /back/i })).toBeVisible();

    // Edit the title
    const editTitleInput = page.getByLabel(/title/i).first();
    await editTitleInput.fill("Draft Edited");

    // Go back and verify
    await page.getByRole("button", { name: /back/i }).click();
    await expect(page.getByText("Draft Edited")).toBeVisible();
  });

  test("delete a draft", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Writer" }).click();

    // Create a draft
    await page.getByRole("button", { name: "New Draft" }).click();
    const titleInput = page.getByLabel(/title/i).first();
    await titleInput.fill("Draft To Delete");
    await page.getByRole("button", { name: /back/i }).click();
    await expect(page.getByText("Draft To Delete")).toBeVisible();

    // Delete it
    await page.getByRole("button", { name: "Delete" }).first().click();

    // Draft should be gone
    await expect(page.getByText("Draft To Delete")).toBeHidden();
  });
});
