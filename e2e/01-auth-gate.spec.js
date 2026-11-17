import { test, expect, request as pwRequest } from "@playwright/test";
import { acknowledgeNotice, BACKEND, FRONTEND, NOTICE_VERSION, loginAs, resetDb } from "./helpers.js";

test.describe("Auth Gate", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("unauthenticated visit shows Sign in screen", async ({ page }) => {
    await page.goto("/");
    await acknowledgeNotice(page);
    // Both Keycloak and SAML sign-in buttons render; assert the primary
    // Keycloak path specifically rather than matching /sign in/.
    await expect(
      page.getByRole("button", { name: /sign in with keycloak/i }),
    ).toBeVisible();
    await expect(page.getByText("STIG Tools").first()).toBeVisible();
  });

  test("clicking Sign in redirects to the IdP login page", async ({ page }) => {
    await page.goto("/");
    await acknowledgeNotice(page);
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
    await acknowledgeNotice(page);
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
    // request to /auth/saml/login and that its response is either a redirect
    // to the IdP or the backend's 503 for "SAML not configured"
    // (see saml.rs, `saml_login_unconfigured_is_503_and_keeps_proof`).
    const respP = page.waitForResponse((r) => /\/auth\/saml\/login/.test(r.url()));
    await page.goto("/");
    await acknowledgeNotice(page);
    const saml = page.getByRole("button", { name: /sign in with saml/i });
    await saml.focus();
    await page.keyboard.press("Enter");
    const resp = await respP;
    expect(resp.request().url()).toMatch(/\/auth\/saml\/login/);
    expect([301, 302, 303, 307, 308, 503]).toContain(resp.status());
  });

  test("login buttons use the requested colours", async ({ page }) => {
    await page.goto("/");
    await acknowledgeNotice(page);
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
    await acknowledgeNotice(page);
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

test.describe("System use notification (AC-8)", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  const signIn = (page) => page.getByRole("button", { name: /sign in/i });

  test("banner present, sign-in absent", async ({ page }) => {
    await page.goto("/");
    const notice = page.getByTestId("login-notice");
    await expect(notice).toBeVisible();
    await expect(notice).toContainText("You are accessing a U.S. Government (USG) Information System (IS)");
    await expect(notice).toContainText("See User Agreement for details.");
    await expect(notice.locator("li")).toHaveCount(5);
    await expect(signIn(page)).toHaveCount(0);
    await expect(page.getByRole("button", { name: "I Agree" })).toBeVisible();
  });

  test("acknowledge reveals sign-in", async ({ page }) => {
    await page.goto("/");
    await acknowledgeNotice(page);
    for (const n of [/sign in with keycloak/i, /sign in with saml/i]) {
      const b = page.getByRole("button", { name: n });
      await expect(b).toBeVisible();
      await expect(b).toBeEnabled();
    }
    await expect(page.getByTestId("login-notice")).toHaveCount(0);
  });

  test("Escape and clicking away do not bypass", async ({ page }) => {
    await page.goto("/");
    await page.keyboard.press("Escape");
    await page.locator(".login-emblem-panel").click({ position: { x: 5, y: 5 } });
    await expect(signIn(page)).toHaveCount(0);
    await expect(page.getByTestId("login-notice")).toBeVisible();
  });

  test("keyboard flow", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByTestId("login-notice")).toBeVisible();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: "I Agree" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("group", { name: "Sign-in options" })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: /sign in with keycloak/i })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/keycloak|realms\/stig-viewer/i, { timeout: 10_000 });
  });

  test("re-required on reload, nothing persisted", async ({ page }) => {
    await page.goto("/");
    await acknowledgeNotice(page);
    await expect(signIn(page)).toHaveCount(2);
    const lens = await page.evaluate(() => [localStorage.length, sessionStorage.length]);
    expect(lens).toEqual([0, 0]);
    await page.reload();
    await expect(page.getByTestId("login-notice")).toBeVisible();
    await expect(signIn(page)).toHaveCount(0);
  });

  test("phone viewport", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/");
    await expect(page.getByTestId("login-notice")).toBeVisible();
    const noOverflow = () =>
      page.evaluate(
        () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
      );
    expect(await noOverflow()).toBe(true);
    const ack = page.getByTestId("login-notice-ack");
    await ack.scrollIntoViewIfNeeded();
    await ack.click();
    for (const n of [/sign in with keycloak/i, /sign in with saml/i]) {
      const b = page.getByRole("button", { name: n });
      await b.scrollIntoViewIfNeeded();
      await expect(b).toBeVisible();
      const box = await b.boundingBox();
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(375);
    }
    expect(await noOverflow()).toBe(true);
  });

  test("reduced motion: animated layers are static after acknowledging", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/");
    await acknowledgeNotice(page);
    for (const sel of [".login-bg", ".login-binary span"]) {
      expect(
        await page.locator(sel).first().evaluate((el) => getComputedStyle(el).animationName),
      ).toBe("none");
    }
    expect(
      await page
        .locator(".login-bg")
        .evaluate((el) => getComputedStyle(el, "::after").animationName),
    ).toBe("none");
  });
});

test.describe("AC-8 server-side gate", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  const ack = (ctx, headers = {}, version = NOTICE_VERSION) =>
    ctx.post(`${BACKEND}/auth/notice/ack`, {
      headers: { Origin: FRONTEND, "Content-Type": "application/json", ...headers },
      data: { noticeVersion: version },
    });

  test("direct GET /auth/login without proof redirects to the banner", async () => {
    const ctx = await pwRequest.newContext();
    const res = await ctx.get(`${BACKEND}/auth/login`, { maxRedirects: 0 });
    expect(res.status()).toBe(303);
    expect(new URL(res.headers()["location"]).origin).toBe(new URL(FRONTEND).origin);
    await ctx.dispose();
  });

  test("browser hitting /auth/login directly lands on the banner", async ({ page }) => {
    await page.goto(`${BACKEND}/auth/login`);
    await expect(page.getByTestId("login-notice")).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in/i })).toHaveCount(0);
  });

  test("ack then login proceeds to the IdP once; reuse is denied", async () => {
    const ctx = await pwRequest.newContext();
    expect((await ack(ctx)).status()).toBe(204);
    const first = await ctx.get(`${BACKEND}/auth/login`, { maxRedirects: 0 });
    expect(first.status()).toBe(303);
    expect(first.headers()["location"]).toMatch(/keycloak|realms\/stig-viewer/i);
    const second = await ctx.get(`${BACKEND}/auth/login`, { maxRedirects: 0 });
    expect(second.status()).toBe(303);
    expect(new URL(second.headers()["location"]).origin).toBe(new URL(FRONTEND).origin);
    await ctx.dispose();
  });

  test("ack rejects a foreign Origin (403) and a wrong version (409)", async () => {
    const ctx = await pwRequest.newContext();
    expect((await ack(ctx, { Origin: "http://evil.example" })).status()).toBe(403);
    expect((await ack(ctx, {}, "wrong-version")).status()).toBe(409);
    await ctx.dispose();
  });

  test("UI stays on the banner when the ack request fails", async ({ page }) => {
    await page.route("**/auth/notice/ack", (route) => route.abort());
    await page.goto("/");
    await page.getByTestId("login-notice-ack").click();
    await expect(page.getByTestId("login-notice-error")).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in/i })).toHaveCount(0);
    await expect(page.getByTestId("login-notice")).toBeVisible();
  });
});
