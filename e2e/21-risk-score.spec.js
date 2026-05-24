import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

// Seed two assets with mixed-severity open findings so we can verify
// (a) per-asset scoring, (b) highest-risk asset surfacing, and (c) the
// per-asset table sort order.
async function seedMixedSeverityRisk(request) {
  // Asset A: a couple of CAT II rules (~6 weighted points)
  const a = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "low-risk-host" },
    })
    .then((r) => r.json());
  const ac = await request
    .post(`${BACKEND}/api/assets/${a.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "windows-10" },
    })
    .then((r) => r.json());
  const ad = await request
    .get(`${BACKEND}/api/checklists/${ac.id}`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());
  // First two windows-10 rules are CAT II.
  for (const idx of [0, 1]) {
    await request.patch(
      `${BACKEND}/api/checklists/${ac.id}/rules/${encodeURIComponent(ad.rules[idx].id)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open" },
      },
    );
  }

  // Asset B: a CAT I rule (10) + a CAT II (3) = 13 points
  const b = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "high-risk-host" },
    })
    .then((r) => r.json());
  const bc = await request
    .post(`${BACKEND}/api/assets/${b.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "windows-10" },
    })
    .then((r) => r.json());
  const bd = await request
    .get(`${BACKEND}/api/checklists/${bc.id}`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());
  // Index 5 is CAT I, index 0 is CAT II (per the smoke-test output).
  for (const idx of [5, 0]) {
    await request.patch(
      `${BACKEND}/api/checklists/${bc.id}/rules/${encodeURIComponent(bd.rules[idx].id)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open" },
      },
    );
  }

  return { lowName: "low-risk-host", highName: "high-risk-host" };
}

test.describe("Risk scoring", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("dashboard API returns weighted risk per asset", async ({ request }) => {
    await seedMixedSeverityRisk(request);
    const d = await request
      .get(`${BACKEND}/api/dashboard`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());

    const byName = Object.fromEntries(
      d.byAsset.map((a) => [a.name, a.riskScore]),
    );
    // low: 2 × CAT II = 6
    expect(byName["low-risk-host"]).toBe(6);
    // high: 1 × CAT I + 1 × CAT II = 13
    expect(byName["high-risk-host"]).toBe(13);
    // Totals reflect the worst system
    expect(d.totals.highestRiskScore).toBe(13);
    expect(d.totals.highestRiskAssetName).toBe("high-risk-host");
  });

  test("Dashboard shows Highest risk KPI and Risk column", async ({
    page,
    request,
  }) => {
    await seedMixedSeverityRisk(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // KPI card label visible (Box variant=h1 keyword would be 13)
    await expect(page.getByText(/^Highest risk$/i)).toBeVisible({
      timeout: 10_000,
    });

    // Both asset names are visible, and high-risk-host appears before
    // low-risk-host in DOM order (per-asset table sorted by risk desc).
    await expect(page.getByText("high-risk-host").first()).toBeVisible();
    await expect(page.getByText("low-risk-host").first()).toBeVisible();
    const bodyText = await page.locator("body").innerText();
    expect(bodyText.indexOf("high-risk-host")).toBeLessThan(
      bodyText.indexOf("low-risk-host"),
    );
  });
});
