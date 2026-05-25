import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Cross-rule catalog search. The backend module scans every catalog
 * JSON for substring matches on stig title / rule id / rule title and
 * returns scored hits with `<mark>`-highlighted snippets.
 *
 * The catalog is shipped with the dev backend image and includes a
 * Microsoft Edge STIG with rule ids like SV-235719…_rule, so we lean
 * on that for the assertions instead of seeding fixtures.
 */
test.describe("Cross-rule catalog search", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: q=edge returns at least one stigTitle hit with <mark>", async ({
    request,
  }) => {
    const res = await request.get(`${BACKEND}/api/catalog/search?q=edge`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.query).toBe("edge");
    expect(Array.isArray(body.results)).toBe(true);
    expect(body.results.length).toBeGreaterThan(0);
    // Score 10 stigTitle hits sort first.
    expect(body.results[0].field).toBe("stigTitle");
    expect(body.results[0].snippet).toContain("<mark>Edge</mark>");
  });

  test("API: 1-char query returns 400", async ({ request }) => {
    const res = await request.get(`${BACKEND}/api/catalog/search?q=e`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(400);
  });

  test("API: rule id substring returns a ruleId hit", async ({ request }) => {
    const res = await request.get(
      `${BACKEND}/api/catalog/search?q=SV-235719&limit=200`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    const ruleIdHits = body.results.filter((r) => r.field === "ruleId");
    expect(ruleIdHits.length).toBeGreaterThan(0);
    // Every ruleId hit must carry a rule id.
    for (const hit of ruleIdHits) {
      expect(hit.ruleId).toBeTruthy();
    }
  });

  test("API: limit caps the result count", async ({ request }) => {
    const res = await request.get(
      `${BACKEND}/api/catalog/search?q=security&limit=5`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.results.length).toBeLessThanOrEqual(5);
  });

  test("API: no matches returns empty results array (not 404)", async ({
    request,
  }) => {
    const res = await request.get(
      `${BACKEND}/api/catalog/search?q=zzzzqqqqxxxx-no-such-thing`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.results).toEqual([]);
  });

  test("UI: typing into the cross-search box reveals highlighted matches", async ({
    page,
  }) => {
    await loginAs(page, "alice");
    await page.goto("/");

    // The catalog table needs to be on screen before the filter strip
    // shows up. Wait for any row to render.
    await expect(page.getByRole("heading", { name: /STIG Library/i }))
      .toBeVisible({ timeout: 15_000 });

    const input = page.getByTestId("catalog-cross-search-input")
      .locator("input");
    await input.fill("edge");

    const panel = page.getByTestId("catalog-cross-search-panel");
    await expect(panel).toBeVisible({ timeout: 5_000 });

    // First result is a stigTitle row — assert its snippet renders
    // the highlighted <mark> term. The cell uses
    // dangerouslySetInnerHTML so the actual <mark> element ends up in
    // the DOM (and Playwright matches it via getByRole or selector).
    const firstMark = panel.locator("mark").first();
    await expect(firstMark).toBeVisible();
    await expect(firstMark).toHaveText(/edge/i);
  });
});
