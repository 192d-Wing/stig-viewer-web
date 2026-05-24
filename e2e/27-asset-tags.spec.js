import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

test.describe("Asset tags", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
    await page.goto("/");
    await page
      .getByRole("button", { name: "Systems", exact: true })
      .click();
  });

  test("create a system with tags, then remove and add tags via edit", async ({
    page,
  }) => {
    // Create
    await page.getByRole("button", { name: "Add system", exact: true }).click();
    const modal = page.getByRole("dialog");
    await modal.getByRole("textbox").first().fill("tagged-host");

    // Add two tags via Enter
    const tagInput = modal.getByPlaceholder("Add tag…");
    await tagInput.fill("production");
    await tagInput.press("Enter");
    await tagInput.fill("pii");
    await tagInput.press("Enter");

    await modal.getByRole("button", { name: "Create" }).click();

    // Tags should render as chips in the row
    const row = page.getByRole("row", { name: /tagged-host/ });
    await expect(row.getByText("production", { exact: true })).toBeVisible();
    await expect(row.getByText("pii", { exact: true })).toBeVisible();

    // Edit: remove "pii", add "public-facing"
    await row.getByRole("button", { name: "Edit" }).click();
    const editModal = page.getByRole("dialog");

    // TokenGroup dismiss: the token is a `group` named after the tag,
    // with an unnamed dismiss button inside it.
    await editModal
      .getByRole("group", { name: "pii" })
      .getByRole("button")
      .click();

    const editTagInput = editModal.getByPlaceholder("Add tag…");
    await editTagInput.fill("public-facing");
    await editTagInput.press("Enter");

    await editModal.getByRole("button", { name: "Save" }).click();
    await expect(editModal).toBeHidden();

    await expect(row.getByText("production", { exact: true })).toBeVisible();
    await expect(row.getByText("public-facing", { exact: true })).toBeVisible();
    await expect(row.getByText("pii", { exact: true })).toHaveCount(0);
  });

  test("API rejects tags longer than 50 chars", async ({ request }) => {
    const long = "x".repeat(60);
    const res = await request.post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice" },
      data: { name: "should-fail", tags: [long] },
    });
    expect(res.status()).toBe(400);
  });

  test("API trims, de-dupes, and drops empty tags", async ({ request }) => {
    const res = await request.post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice" },
      data: {
        name: "norm-host",
        tags: ["  production  ", "production", "", "  ", "pii"],
      },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.tags).toEqual(["production", "pii"]);
  });
});
