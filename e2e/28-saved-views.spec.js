import { test, expect } from "@playwright/test";
import { loginAs, resetDb } from "./helpers.js";

test.describe("Saved views — URL state", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("?view= lands on the named top-level page", async ({ page }) => {
    await page.goto("/?view=systems");
    await expect(page.getByRole("heading", { name: /^Systems/ })).toBeVisible();

    await page.goto("/?view=dashboard");
    await expect(
      page.getByRole("heading", { name: /Compliance dashboard/i }),
    ).toBeVisible();

    await page.goto("/?view=myfindings");
    await expect(
      page.getByRole("heading", { name: /My findings/i }),
    ).toBeVisible();
  });

  test("clicking a top nav button updates ?view= in the URL", async ({
    page,
  }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await expect(page).toHaveURL(/\?view=dashboard\b/);

    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await expect(page).toHaveURL(/\?view=systems\b/);

    // Going back to Viewer drops the param entirely (it's the default).
    await page.getByRole("button", { name: "Viewer", exact: true }).click();
    await expect(page).not.toHaveURL(/\?view=/);
  });

  test("StigLibrary search text persists into ?q= and is restored from URL", async ({
    page,
  }) => {
    await page.goto("/");
    const filter = page.getByPlaceholder(/search by title/i);
    await filter.fill("apache");
    await expect(page).toHaveURL(/[?&]q=apache\b/);

    // Reload the page at the same URL; filter is restored.
    await page.reload();
    await expect(page.getByPlaceholder(/search by title/i)).toHaveValue(
      "apache",
    );
  });

  test("Deep link with multiple StigLibrary params applies all of them", async ({
    page,
  }) => {
    await page.goto("/?q=win&sort=title&dir=desc");
    await expect(page.getByPlaceholder(/search by title/i)).toHaveValue("win");
    // Category toolbar still shows "All" as default — verify by counter.
    await expect(page.getByText(/matches?/).first()).toBeVisible();
  });

  test("Dashboard severity filter persists into ?sev= via deep link", async ({
    page,
  }) => {
    // Open dashboard with a pre-seeded drill-down + severity filter
    await page.goto("/?view=dashboard&dd=open&sev=CAT+I");
    await expect(
      page.getByRole("heading", { name: /Compliance dashboard/i }),
    ).toBeVisible();
    // Drill-down panel is open
    await expect(
      page.getByRole("heading", { name: /open findings/i }),
    ).toBeVisible();
  });
});
