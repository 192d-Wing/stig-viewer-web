import { test, expect } from "@playwright/test";
import { loginAs, openEdgeFromLibrary, resetDb, BACKEND, FRONTEND } from "./helpers.js";

/**
 * A page restored from the back/forward cache after its pagehide save.
 *
 * Playwright passes --disable-back-forward-cache and its headless shell never
 * restores from the cache, so this file uses full Chromium with that flag
 * removed. CI's `npx playwright install --with-deps chromium` installs it;
 * locally set E2E_CHROMIUM_PATH to a Chromium binary if needed.
 */
test.use({
  channel: "chromium",
  launchOptions: {
    ignoreDefaultArgs: ["--disable-back-forward-cache"],
    ...(process.env.E2E_CHROMIUM_PATH ? { executablePath: process.env.E2E_CHROMIUM_PATH } : {}),
  },
});

const SETS = `${BACKEND}/api/checklist-sets`;

test.describe("Checklist sets - back/forward cache", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("a page restored from the back/forward cache settles its pagehide save without a conflict", async ({ page, request }) => {
    test.setTimeout(90_000);
    await page.addInitScript(() => {
      window.__shows = [];
      window.addEventListener("pageshow", (e) => window.__shows.push(e.persisted));
    });
    await loginAs(page, "alice");
    await openEdgeFromLibrary(page);
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });
    const [set] = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    const state = async () => {
      const d = await request.get(`${SETS}/${set.id}`, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
      return `${d.revision}:${d.stigs[0].rules.length}`;
    };
    expect(await state()).toBe("1:1");

    // Edit a second rule and leave inside the debounce window.
    await listbox.getByRole("option").nth(1).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    page.on("dialog", (d) => d.accept());
    await page.goto(`${FRONTEND}/boot.js`);
    // The keepalive save lands while the page is frozen.
    await expect.poll(state, { timeout: 15_000 }).toBe("2:2");

    // A restore fires no load event, so wait for the commit only.
    await page.goBack({ waitUntil: "commit" });
    await expect.poll(() => page.evaluate(() => window.__shows?.at(-1)), { timeout: 15_000 }).toBe(true);

    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 30_000 });
    await expect(page.getByTestId("set-conflict")).toHaveCount(0);
    expect(await state()).toBe("2:2");
    await expect(listbox.getByRole("option").nth(1)).toContainText(/open/i);
  });
});
