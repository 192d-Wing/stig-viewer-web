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

test.describe("Login screen", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("emblem loads", async ({ page }) => {
    await page.goto("/");
    const img = page.getByTestId("login-emblem");
    await expect(img).toBeVisible();
    await expect(img).toHaveAttribute("alt", "Department of War seal");
    await expect
      .poll(() => img.evaluate((el) => el.naturalWidth))
      .toBeGreaterThan(0);
  });

  test("no CSP violations", async ({ page }) => {
    const msgs = [];
    page.on("console", (m) => msgs.push(m.text()));
    await page.goto("/");
    await expect(page.getByTestId("login-card")).toBeVisible();
    expect(msgs.filter((t) => /Content Security Policy/i.test(t))).toEqual([]);
  });

  test("fits a phone viewport", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/");
    await expect(
      page.getByRole("button", { name: /sign in with keycloak/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /sign in with saml/i }),
    ).toBeVisible();
    const noOverflow = await page.evaluate(
      () =>
        document.documentElement.scrollWidth <=
        document.documentElement.clientWidth,
    );
    expect(noOverflow).toBe(true);
    const box = await page.getByTestId("login-card").boundingBox();
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(375);
    const emblem = await page.getByTestId("login-emblem").boundingBox();
    expect(emblem.y + emblem.height).toBeLessThanOrEqual(box.y);
    expect(emblem.x < box.x + box.width && box.x < emblem.x + emblem.width).toBe(true);
  });

  test("reduced motion disables background animation", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/");
    await expect(page.getByTestId("login-card")).toBeVisible();
    const name = await page
      .locator(".login-bg")
      .evaluate((el) => getComputedStyle(el).animationName);
    expect(name).toBe("none");
  });

  test("background animates when motion is allowed", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await page.goto("/");
    await expect(page.getByTestId("login-card")).toBeVisible();
    const name = await page
      .locator(".login-bg")
      .evaluate((el) => getComputedStyle(el).animationName);
    expect(name).not.toBe("none");
  });

  test("binary layer animates, respects reduced motion, and is hidden from AT", async ({
    page,
  }) => {
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await page.goto("/");
    await expect(page.getByTestId("login-card")).toBeVisible();
    const col = page.locator(".login-binary span").first();
    await expect(page.locator(".login-binary")).toHaveAttribute("aria-hidden", "true");
    expect(await col.evaluate((el) => getComputedStyle(el).animationName)).not.toBe("none");
    await page.emulateMedia({ reducedMotion: "reduce" });
    expect(await col.evaluate((el) => getComputedStyle(el).animationName)).toBe("none");
  });

  test("desktop layout puts sign-in right of the emblem", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto("/");
    const card = await page.getByTestId("login-card").boundingBox();
    const emblem = await page.getByTestId("login-emblem").boundingBox();
    expect(emblem.x + emblem.width).toBeLessThanOrEqual(card.x);
    const panel = await page.locator(".login-emblem-panel").boundingBox();
    expect(card.width / 1280).toBeGreaterThan(0.28);
    expect(card.width / 1280).toBeLessThan(0.38);
    expect(panel.width / 1280).toBeGreaterThan(0.62);
    expect(panel.width / 1280).toBeLessThan(0.72);
  });

  test("Enter on SAML button navigates to the SAML login", async ({ page }) => {
    // The SAML IdP may not be configured in the e2e stack, so assert the
    // request to /auth/saml/login and that its response is a redirect.
    const respP = page.waitForResponse((r) => /\/auth\/saml\/login/.test(r.url()));
    await page.goto("/");
    const saml = page.getByRole("button", { name: /sign in with saml/i });
    await saml.focus();
    await page.keyboard.press("Enter");
    const resp = await respP;
    expect(resp.request().url()).toMatch(/\/auth\/saml\/login/);
    expect([301, 302, 303, 307, 308]).toContain(resp.status());
  });

  test("login buttons use the requested colours", async ({ page }) => {
    await page.goto("/");
    const bg = (name) =>
      page.getByRole("button", { name }).evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(await bg(/sign in with keycloak/i)).toBe("rgb(21, 38, 59)");
    expect(await bg(/sign in with saml/i)).toBe("rgb(113, 113, 113)");
  });

  test("keyboard navigation reaches both buttons and Enter signs in", async ({
    page,
  }) => {
    await page.goto("/");
    const kc = page.getByRole("button", { name: /sign in with keycloak/i });
    const saml = page.getByRole("button", { name: /sign in with saml/i });
    await expect(kc).toBeVisible();
    await page.keyboard.press("Tab");
    await expect(kc).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(saml).toBeFocused();
    await page.keyboard.press("Shift+Tab");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/keycloak|realms\/stig-viewer/i, {
      timeout: 10_000,
    });
  });
});
