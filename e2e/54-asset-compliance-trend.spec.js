import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

// ── Seeding helpers ─────────────────────────────────────────────────────────
//
// The edge STIG has 59 rules. With 1 NaF rule:
//   (1 + 0) / 59 × 100 ≈ 1.7
//
// The compliance gate requires a non-empty `findingDetails` when
// transitioning a rule to a closing status (not_a_finding /
// not_applicable). Without it the PATCH is rejected before the snapshot
// can pick it up.

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

test.describe("Per-asset compliance trend", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API returns no snapshots when none have been taken", async ({
    request,
  }) => {
    const asset = await createAsset(request, "no-snap-host");
    await applyStig(request, asset.id);

    const r = await request.get(
      `${BACKEND}/api/assets/${asset.id}/trend?days=30`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.overall).toEqual([]);
  });

  test("API populates complianceScore from the formula after a snapshot", async ({
    request,
  }) => {
    // 1 NaF rule out of 59 on the edge STIG → 1 / 59 × 100 ≈ 1.7
    const asset = await createAsset(request, "compliance-trend-host");
    const { checklistId, rules } = await applyStig(request, asset.id);
    await setRuleStatus(request, checklistId, rules[0].id, "not_a_finding");

    const snap = await request.post(`${BACKEND}/api/test/snapshot`);
    expect(snap.ok() || snap.status() === 204).toBeTruthy();

    const r = await request.get(
      `${BACKEND}/api/assets/${asset.id}/trend?days=30`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.overall.length).toBeGreaterThanOrEqual(1);
    const latest = d.overall[d.overall.length - 1];
    expect(latest.naf).toBe(1);
    expect(latest.total).toBe(59);
    expect(latest.complianceScore).toBe(1.7);
  });

  test("AssetDetail page shows the Compliance trend chart after a snapshot", async ({
    page,
    request,
  }) => {
    const asset = await createAsset(request, "compliance-ui-host");
    const { checklistId, rules } = await applyStig(request, asset.id);
    await setRuleStatus(request, checklistId, rules[0].id, "not_a_finding");
    const snap = await request.post(`${BACKEND}/api/test/snapshot`);
    expect(snap.ok() || snap.status() === 204).toBeTruthy();

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "compliance-ui-host" }).click();

    await expect(
      page.getByRole("heading", { name: /Compliance trend/i }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("Compliance trend chart is hidden until a snapshot has run", async ({
    page,
    request,
  }) => {
    await request.post(`${BACKEND}/api/assets`, {
      headers: HEADERS(),
      data: { name: "no-compliance-snap-host" },
    });

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page
      .getByRole("button", { name: "no-compliance-snap-host" })
      .click();

    await expect(page.getByText("Applied STIGs")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: /Compliance trend/i }),
    ).toHaveCount(0);
  });
});
