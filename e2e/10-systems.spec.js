import { test, expect } from "@playwright/test";
import { loginAs, resetDb } from "./helpers.js";

test.describe("Systems / per-asset checklists", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
    await page.goto("/");
    await page
      .getByRole("button", { name: "Systems", exact: true })
      .click();
  });

  test("create system, edit it, delete it", async ({ page }) => {
    await page.getByRole("button", { name: "Add system", exact: true }).click();
    const modal = page.getByRole("dialog");
    await modal.getByRole("textbox").first().fill("host-a");
    await modal.getByRole("textbox").nth(1).fill("host-a.example.test");
    await modal.getByRole("button", { name: "Create" }).click();

    await expect(page.getByRole("button", { name: "host-a" })).toBeVisible();

    // Edit
    await page.getByRole("button", { name: "Edit" }).click();
    const editModal = page.getByRole("dialog");
    await editModal.getByRole("textbox").first().fill("host-a-renamed");
    await editModal.getByRole("button", { name: "Save" }).click();
    await expect(
      page.getByRole("button", { name: "host-a-renamed" }),
    ).toBeVisible();

    // Delete (with confirmation modal)
    await page.getByRole("button", { name: "Delete" }).click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Delete" })
      .click();
    await expect(
      page.getByRole("button", { name: "host-a-renamed" }),
    ).toHaveCount(0);
  });

  test("apply STIG to system and edit a rule's status", async ({ page }) => {
    // Create a system
    await page.getByRole("button", { name: "Add system", exact: true }).click();
    const createModal = page.getByRole("dialog");
    await createModal.getByRole("textbox").first().fill("host-b");
    await createModal.getByRole("button", { name: "Create" }).click();

    // Drill into it
    await page.getByRole("button", { name: "host-b" }).click();
    await expect(page.getByText("Applied STIGs")).toBeVisible();

    // Apply a STIG
    await page.getByRole("button", { name: /apply stig/i }).click();
    const applyModal = page.getByRole("dialog");
    await applyModal
      .getByRole("button", { name: /choose a stig/i })
      .click();
    await page.getByRole("option").first().click();
    await applyModal.getByRole("button", { name: "Apply", exact: true }).click();

    // Click into the checklist (the STIG link in the table)
    const stigLink = page.locator("table").last().getByRole("button").first();
    await stigLink.click();

    await expect(
      page.getByRole("heading", { name: /^Rules/ }),
    ).toBeVisible({ timeout: 10_000 });

    // Edit the first rule
    const firstRuleLink = page
      .locator("table")
      .last()
      .getByRole("button")
      .first();
    await firstRuleLink.click();

    // Wait for the modal heading (the rule id) before interacting
    const editModal = page.getByRole("dialog").last();
    await expect(editModal).toBeVisible();
    await editModal.getByRole("radio", { name: "Not a finding" }).click();

    // Compliance gate requires a justification for closing statuses —
    // fill the Finding details textarea so Save becomes enabled.
    await editModal
      .getByRole("textbox", { name: /finding details/i })
      .fill("test justification");

    // Confirm Save isn't disabled (owner check + gate)
    const saveBtn = editModal.getByRole("button", { name: "Save", exact: true });
    await expect(saveBtn).toBeEnabled();
    await saveBtn.click();

    // Modal closes after PATCH + refresh
    await expect(editModal).toBeHidden({ timeout: 15_000 });
  });
});
