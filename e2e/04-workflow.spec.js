import { test, expect } from "@playwright/test";
import {
  loginAs,
  resetDb,
  createDraftViaApi,
  transitionDraft,
  setUserRole,
} from "./helpers.js";

test.describe("Approval Workflow", () => {
  const AUTHOR = "wf-author";
  const REVIEWER = "wf-reviewer";

  test.beforeEach(async () => {
    await resetDb();
  });

  test("author submits draft for review", async ({ page }) => {
    // Seed a draft via API
    const draft = await createDraftViaApi(AUTHOR, "Workflow Draft");
    await loginAs(page, AUTHOR);
    await page.goto("/");

    // Switch to Writer
    await page.getByRole("button", { name: "Writer" }).click();

    // Wait for drafts table to load, then open
    await expect(page.getByRole("button", { name: "Open" }).first()).toBeVisible();
    await page.getByRole("button", { name: "Open" }).first().click();
    await expect(page.getByRole("button", { name: /back/i })).toBeVisible();

    // Submit for review — this now opens a reviewer-picker modal first.
    // Default option is "Any reviewer", so confirming submits without an
    // assignee.
    await page
      .getByRole("button", { name: /submit for review/i })
      .click();
    await page.getByTestId("confirm-submit").click();

    // Status badge should show "Submitted" (exact match to avoid flash message)
    await expect(page.getByText("Submitted", { exact: true })).toBeVisible();
  });

  test("reviewer approves a submitted draft", async ({ page }) => {
    // Seed: create draft and submit it via API
    const draft = await createDraftViaApi(AUTHOR, "Approval Draft");
    await transitionDraft(AUTHOR, draft.id, "submit");

    // Set up the reviewer with the reviewer role
    await setUserRole(REVIEWER, "reviewer");

    // Have reviewer pick up the review
    await transitionDraft(REVIEWER, draft.id, "review");

    // Now log in as reviewer in the browser
    await loginAs(page, REVIEWER);
    await page.goto("/");
    await page.getByRole("button", { name: "Writer" }).click();

    // Wait for drafts table to load, then open
    await expect(page.getByRole("button", { name: "Open" }).first()).toBeVisible();
    await page.getByRole("button", { name: "Open" }).first().click();
    await expect(page.getByRole("button", { name: /back/i })).toBeVisible();

    // Click Approve
    await page.getByRole("button", { name: /^approve$/i }).click();

    // Fill in comment in the modal and confirm
    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();
    await modal.getByRole("textbox").fill("Looks good to me");
    await modal
      .getByRole("button", { name: /^approve$/i })
      .click();

    // Status badge should show "Approved"
    await expect(page.getByText("Approved", { exact: true })).toBeVisible();
  });

  test("reviewer rejects and author revises", async ({ page }) => {
    // Seed: create, submit, and move to in_review
    const draft = await createDraftViaApi(AUTHOR, "Reject Draft");
    await transitionDraft(AUTHOR, draft.id, "submit");
    await setUserRole(REVIEWER, "reviewer");
    await transitionDraft(REVIEWER, draft.id, "review");

    // Reject via API
    await transitionDraft(REVIEWER, draft.id, "reject", {
      comment: "Needs more detail",
    });

    // Now author logs in and sees rejected draft
    await loginAs(page, AUTHOR);
    await page.goto("/");
    await page.getByRole("button", { name: "Writer" }).click();

    // Wait for drafts table to load, then open
    await expect(page.getByRole("button", { name: "Open" }).first()).toBeVisible();
    await page.getByRole("button", { name: "Open" }).first().click();
    await expect(page.getByRole("button", { name: /back/i })).toBeVisible();

    // Should see Rejected status badge
    await expect(page.getByText("Rejected", { exact: true })).toBeVisible();

    // Click Revise to reopen as draft
    await page.getByRole("button", { name: /revise/i }).click();

    // Status badge should change to "Draft" (exact match)
    await expect(page.getByText("Draft", { exact: true })).toBeVisible();
  });
});
