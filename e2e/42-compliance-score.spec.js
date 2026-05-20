import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

// ── Seeding helpers ─────────────────────────────────────────────────────────
//
// The edge STIG has 59 rules — formula values below are pre-computed
// against that rule count.
//   2 NaF / 59 total = 3.4%
//   3 NaF / 59 total = 5.1%
//
// Each helper provisions an asset, applies a STIG, and optionally
// transitions rule statuses.

const HEADERS = (user = "alice") => ({
  "X-User-Id": user,
  "Content-Type": "application/json",
});

async function createAsset(request, name) {
  const r = await request.post(`${BACKEND}/api/assets`, {
    headers: HEADERS(),
    data: { name },
  });
  expect(r.ok()).toBeTruthy();
  return r.json();
}

async function applyStig(request, assetId, stigId = "edge") {
  const r = await request.post(`${BACKEND}/api/assets/${assetId}/checklists`, {
    headers: HEADERS(),
    data: { stigId },
  });
  expect(r.ok()).toBeTruthy();
  const checklist = await r.json();
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((res) => res.json());
  return { checklistId: checklist.id, rules: detail.rules };
}

async function setRuleStatus(request, checklistId, ruleId, status) {
  // Compliance gate requires a justification for closing statuses.
  const findingDetails =
    status === "not_a_finding" || status === "not_applicable"
      ? "auto-justified for test"
      : "";
  const r = await request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: HEADERS(),
      data: { status, findingDetails },
    },
  );
  expect(r.ok()).toBeTruthy();
}

async function getDashboard(request) {
  const r = await request.get(`${BACKEND}/api/dashboard`, {
    headers: { "X-User-Id": "alice" },
  });
  expect(r.ok()).toBeTruthy();
  return r.json();
}

async function getTrend(request, days = 30) {
  const r = await request.get(`${BACKEND}/api/dashboard/trend?days=${days}`, {
    headers: { "X-User-Id": "alice" },
  });
  expect(r.ok()).toBeTruthy();
  return r.json();
}

// ── Tests ───────────────────────────────────────────────────────────────────

test.describe("Continuous compliance score", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("asset complianceScore matches formula with mixed statuses", async ({
    request,
  }) => {
    // 2 NaF + 1 open + rest not_reviewed on the 59-rule edge STIG.
    // Expected: (2 + 0) / 59 × 100 ≈ 3.4
    const asset = await createAsset(request, "mix-host");
    const { checklistId, rules } = await applyStig(request, asset.id);
    await setRuleStatus(request, checklistId, rules[0].id, "not_a_finding");
    await setRuleStatus(request, checklistId, rules[1].id, "not_a_finding");
    await setRuleStatus(request, checklistId, rules[2].id, "open");

    const d = await getDashboard(request);
    const a = d.byAsset.find((x) => x.name === "mix-host");
    expect(a).toBeDefined();
    expect(a.complianceScore).toBe(3.4);

    // Per-checklist score matches the asset score because the asset
    // owns exactly one checklist.
    expect(a.checklists).toHaveLength(1);
    expect(a.checklists[0].complianceScore).toBe(3.4);
    expect(a.checklists[0].nafCount).toBe(2);
    expect(a.checklists[0].naCount).toBe(0);
    expect(a.checklists[0].ruleCount).toBe(59);
  });

  test("complianceScore is 0.0 when no rules are touched", async ({
    request,
  }) => {
    const asset = await createAsset(request, "untouched-host");
    const { checklistId } = await applyStig(request, asset.id);

    const d = await getDashboard(request);
    const a = d.byAsset.find((x) => x.name === "untouched-host");
    expect(a.complianceScore).toBe(0.0);
    const c = a.checklists.find((cc) => cc.id === checklistId);
    expect(c.complianceScore).toBe(0.0);
  });

  test("dashboard totals.complianceScore aggregates across assets", async ({
    request,
  }) => {
    // Asset 1: 2 NaF, 0 N/A out of 59 → contributes 2 compliant / 59 rules
    const a1 = await createAsset(request, "host-1");
    const c1 = await applyStig(request, a1.id);
    await setRuleStatus(request, c1.checklistId, c1.rules[0].id, "not_a_finding");
    await setRuleStatus(request, c1.checklistId, c1.rules[1].id, "not_a_finding");

    // Asset 2: 1 NaF + 1 N/A out of 59 → contributes 2 compliant / 59 rules
    const a2 = await createAsset(request, "host-2");
    const c2 = await applyStig(request, a2.id);
    await setRuleStatus(request, c2.checklistId, c2.rules[0].id, "not_a_finding");
    await setRuleStatus(request, c2.checklistId, c2.rules[1].id, "not_applicable");

    // Asset 3: nothing touched → 0 compliant / 59 rules
    const a3 = await createAsset(request, "host-3");
    await applyStig(request, a3.id);

    // Fleet total: (2 + 2 + 0) / (59 + 59 + 59) × 100 = 4 / 177 × 100 ≈ 2.3
    const d = await getDashboard(request);
    expect(d.totals.complianceScore).toBe(2.3);

    // Per-asset values are still computed against just that asset's rules.
    const byName = Object.fromEntries(
      d.byAsset.map((a) => [a.name, a.complianceScore]),
    );
    expect(byName["host-1"]).toBe(3.4);
    expect(byName["host-2"]).toBe(3.4);
    expect(byName["host-3"]).toBe(0.0);
  });

  test("trend endpoint returns complianceScore per snapshot day", async ({
    request,
  }) => {
    const asset = await createAsset(request, "trend-host");
    const { checklistId, rules } = await applyStig(request, asset.id);
    await setRuleStatus(request, checklistId, rules[0].id, "not_a_finding");
    await setRuleStatus(request, checklistId, rules[1].id, "not_a_finding");
    await setRuleStatus(request, checklistId, rules[2].id, "not_a_finding");

    // Force a snapshot, then verify the trend reflects it.
    const snap = await request.post(`${BACKEND}/api/test/snapshot`);
    expect(snap.ok() || snap.status() === 204).toBeTruthy();

    const t = await getTrend(request, 30);
    expect(t.overall.length).toBeGreaterThanOrEqual(1);
    // 3 NaF / 59 ≈ 5.1
    const latest = t.overall[t.overall.length - 1];
    expect(latest.complianceScore).toBe(5.1);
    expect(latest.naf).toBe(3);
    expect(latest.total).toBe(59);
  });

  test("UI renders the Compliance KPI tile with expected percentage", async ({
    page,
    request,
  }) => {
    // Seed 4 NaF rules out of 59 → 4 / 59 × 100 ≈ 6.8%
    const asset = await createAsset(request, "ui-host");
    const { checklistId, rules } = await applyStig(request, asset.id);
    for (let i = 0; i < 4; i++) {
      await setRuleStatus(request, checklistId, rules[i].id, "not_a_finding");
    }

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // Wait for the dashboard heading.
    await expect(
      page.getByRole("heading", { name: /Compliance dashboard/i }),
    ).toBeVisible({ timeout: 10_000 });

    // Compliance KPI label is rendered (Sanity: matches the new tile label).
    await expect(page.getByText(/^Compliance$/).first()).toBeVisible();

    // The expected percentage text is visible somewhere on the page.
    // 4 / 59 ≈ 6.8 → "6.8%".
    await expect(page.getByText("6.8%").first()).toBeVisible();
  });
});
