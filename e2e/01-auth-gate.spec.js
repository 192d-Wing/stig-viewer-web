import { test, expect } from "@playwright/test";
import { loginAs, resetDb } from "./helpers.js";

test.describe("Auth Gate", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("unauthenticated visit shows Sign in screen", async ({ page }) => {
    await page.goto("/");
    // Both Keycloak and SAML sign-in buttons render; assert the primary
    // Keycloak path specifically rather than matching /sign in/.
    await expect(
      page.getByRole("button", { name: /sign in with keycloak/i }),
    ).toBeVisible();
    await expect(page.getByText("STIG Tools").first()).toBeVisible();
  });

  test("clicking Sign in redirects to the IdP login page", async ({ page }) => {
    await page.goto("/");
    await page
      .getByRole("button", { name: /sign in with keycloak/i })
      .click();
    // Backend issues a 303 to Keycloak; browser ends up on Keycloak's login form.
    await expect(page).toHaveURL(/keycloak|realms\/stig-viewer/i, {
      timeout: 10_000,
    });
  });

  test("X-User-Id test bypass: skips Sign in and renders the library", async ({
    page,
  }) => {
    await loginAs(page, "e2e-tester");
    await page.goto("/");
    // No Sign in button — gated content (the library / top nav) is visible instead.
    await expect(page.getByRole("button", { name: /sign in/i })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /viewer/i })).toBeVisible();
  });
});
