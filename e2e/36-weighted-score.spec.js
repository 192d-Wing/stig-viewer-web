import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

// ── Seeding helpers ─────────────────────────────────────────────────────────
//
// Each helper provisions an asset, applies the windows-10 STIG, optionally
// re-classifies the asset (via PUT /api/assets/:id), and opens one or more
// rules. The windows-10 STIG's rule indices used here come from the
// existing 21-risk-score.spec.js: index 5 is CAT I, index 0 is CAT II.

const HEADERS = (user = "alice") => ({
  "X-User-Id": user,
  "Content-Type": "application/json",
});

async function createAsset(request, name, classification = "unclassified") {
  // Two-step creation so we can flip classification independently of the
  // API's create-default. The PUT endpoint re-asserts the full struct.
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: HEADERS(),
      data: { name },
    })
    .then((r) => r.json());
  if (classification !== "unclassified") {
    const updated = await request.put(`${BACKEND}/api/assets/${asset.id}`, {
      headers: HEADERS(),
      data: {
        name,
        hostname: asset.hostname,
        description: asset.description,
        classification,
        tags: asset.tags ?? [],
      },
    });
    expect(updated.ok()).toBeTruthy();
  }
  return asset;
}

async function applyStigAndGetRules(request, assetId, stigId = "windows-10") {
  const c = await request
    .post(`${BACKEND}/api/assets/${assetId}/checklists`, {
      headers: HEADERS(),
      data: { stigId },
    })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${c.id}`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());
  return { checklistId: c.id, rules: detail.rules };
}

async function openRule(request, checklistId, ruleId, { dueDate } = {}) {
  const data = { status: "open" };
  if (dueDate) data.dueDate = dueDate;
  const res = await request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: HEADERS(),
      data,
    },
  );
  expect(res.ok()).toBeTruthy();
}

async function getFindings(request) {
  return await request
    .get(`${BACKEND}/api/findings?status=open`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());
}

async function getDashboard(request) {
  return await request
    .get(`${BACKEND}/api/dashboard`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());
}

function findingFor(findings, ruleId) {
  const f = findings.find((x) => x.ruleId === ruleId);
  if (!f) throw new Error(`No finding for ${ruleId}: ${JSON.stringify(findings)}`);
  return f;
}

// ── Tests ───────────────────────────────────────────────────────────────────

test.describe("Weighted severity score", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("CAT I weighted_score reflects classification multiplier", async ({
    request,
  }) => {
    // Top-secret asset → CAT I rule opened (not past-due).
    // Expect: 10 × 2.0 × 1.0 = 20.0
    const ts = await createAsset(request, "ts-host", "top-secret");
    const { checklistId: tsCid, rules: tsRules } = await applyStigAndGetRules(
      request,
      ts.id,
    );
    await openRule(request, tsCid, tsRules[5].id); // CAT I

    // Unclassified asset → same CAT I rule.
    // Expect: 10 × 1.0 × 1.0 = 10.0
    const u = await createAsset(request, "u-host", "unclassified");
    const { checklistId: uCid, rules: uRules } = await applyStigAndGetRules(
      request,
      u.id,
    );
    await openRule(request, uCid, uRules[5].id); // CAT I

    const findings = await getFindings(request);
    const tsF = findingFor(
      findings.filter((f) => f.assetName === "ts-host"),
      tsRules[5].id,
    );
    const uF = findingFor(
      findings.filter((f) => f.assetName === "u-host"),
      uRules[5].id,
    );
    expect(tsF.weightedScore).toBe(20.0);
    expect(uF.weightedScore).toBe(10.0);
    // Sanity: classification surfaced on the finding row.
    expect(tsF.classification).toBe("top-secret");
    expect(uF.classification).toBe("unclassified");
  });

  test("overdue bonus doubles the weighted score", async ({ request }) => {
    const a = await createAsset(request, "od-host", "unclassified");
    const { checklistId, rules } = await applyStigAndGetRules(request, a.id);
    // Two CAT I rules: one with a past-due date, one without.
    // Past-due: 10 × 1.0 × 2.0 = 20.0
    // Not due:  10 × 1.0 × 1.0 = 10.0
    await openRule(request, checklistId, rules[5].id, {
      dueDate: "2020-01-01",
    });
    await openRule(request, checklistId, rules[6].id);

    const findings = await getFindings(request);
    const past = findingFor(findings, rules[5].id);
    const future = findingFor(findings, rules[6].id);
    expect(past.weightedScore).toBe(20.0);
    expect(future.weightedScore).toBe(10.0);
  });

  test("dashboard.weightedRiskScore sums per-finding scores per asset", async ({
    request,
  }) => {
    // secret-host: 1× CAT I (open, not past-due)
    //   = 10 × 1.5 × 1.0 = 15.0
    // ts-host: 1× CAT I past-due + 1× CAT II
    //   = (10 × 2.0 × 2.0) + (3 × 2.0 × 1.0) = 40 + 6 = 46.0
    const secret = await createAsset(request, "secret-host", "secret");
    const sec = await applyStigAndGetRules(request, secret.id);
    await openRule(request, sec.checklistId, sec.rules[5].id);

    const ts = await createAsset(request, "ts-host", "top-secret");
    const top = await applyStigAndGetRules(request, ts.id);
    await openRule(request, top.checklistId, top.rules[5].id, {
      dueDate: "2020-01-01",
    });
    await openRule(request, top.checklistId, top.rules[0].id);

    const d = await getDashboard(request);
    const byName = Object.fromEntries(
      d.byAsset.map((a) => [a.name, a.weightedRiskScore]),
    );
    expect(byName["secret-host"]).toBe(15.0);
    expect(byName["ts-host"]).toBe(46.0);

    // Totals: highest single-finding weighted score = 40 (CAT I past-due
    // on top-secret), and the asset/rule it came from is surfaced.
    expect(d.totals.highestWeightedScore).toBe(40.0);
    expect(d.totals.highestWeightedAssetName).toBe("ts-host");
    expect(d.totals.highestWeightedRuleId).toBe(top.rules[5].id);

    // Classification surfaced on each per-asset row.
    const secAsset = d.byAsset.find((a) => a.name === "secret-host");
    expect(secAsset.classification).toBe("secret");
  });

  test("weightedRiskScore is sealed by a checklist deletion", async ({
    request,
  }) => {
    const a = await createAsset(request, "del-host", "top-secret");
    const { checklistId, rules } = await applyStigAndGetRules(request, a.id);
    await openRule(request, checklistId, rules[5].id); // CAT I → 20.0

    let d = await getDashboard(request);
    const beforeDelete = d.byAsset.find((x) => x.name === "del-host");
    expect(beforeDelete.weightedRiskScore).toBe(20.0);

    // Delete the checklist — open findings disappear with it, so the
    // weighted aggregate must drop back to 0.0.
    const res = await request.delete(`${BACKEND}/api/checklists/${checklistId}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.ok() || res.status() === 204).toBeTruthy();

    d = await getDashboard(request);
    const afterDelete = d.byAsset.find((x) => x.name === "del-host");
    expect(afterDelete.weightedRiskScore).toBe(0.0);
    expect(d.totals.highestWeightedScore).toBe(0.0);
  });

  test("dashboard UI surfaces Weighted risk column and Top weighted KPI", async ({
    page,
    request,
  }) => {
    const a = await createAsset(request, "ui-host", "top-secret");
    const { checklistId, rules } = await applyStigAndGetRules(request, a.id);
    await openRule(request, checklistId, rules[5].id); // CAT I → 20.0

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // New column header on the per-system table.
    await expect(
      page.getByRole("columnheader", { name: /Weighted risk/i }),
    ).toBeVisible({ timeout: 10_000 });

    // KPI label for the new tile.
    await expect(page.getByText(/^Top weighted$/i)).toBeVisible();

    // The seeded asset's per-system row should show its weighted score
    // (20.0 for CAT I on top-secret) somewhere on the page.
    await expect(page.getByText("20.0").first()).toBeVisible();
  });
});
