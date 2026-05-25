import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * OSCAL assessment-results export per asset.
 *
 * Field-name assertions use bracket notation (`body["assessment-results"]`)
 * because OSCAL uses kebab-case keys.
 */

async function createAsset(request, name, user = "alice") {
  const res = await request.post(`${BACKEND}/api/assets`, {
    headers: { "X-User-Id": user, "Content-Type": "application/json" },
    data: { name },
  });
  expect(res.status()).toBe(201);
  return res.json();
}

async function applyStig(request, assetId, stigId, user = "alice") {
  const res = await request.post(
    `${BACKEND}/api/assets/${assetId}/checklists`,
    {
      headers: { "X-User-Id": user, "Content-Type": "application/json" },
      data: { stigId },
    },
  );
  expect(res.status()).toBe(201);
  return res.json();
}

async function getChecklist(request, checklistId, user = "alice") {
  const res = await request.get(`${BACKEND}/api/checklists/${checklistId}`, {
    headers: { "X-User-Id": user },
  });
  expect(res.status()).toBe(200);
  return res.json();
}

async function setRuleStatus(
  request,
  checklistId,
  ruleId,
  status,
  details = "",
  user = "alice",
) {
  const res = await request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": user, "Content-Type": "application/json" },
      data: { status, findingDetails: details },
    },
  );
  expect(res.ok()).toBeTruthy();
  return res.json();
}

test.describe("OSCAL JSON export — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("returns 200, application/json, and an OSCAL filename in Content-Disposition", async ({
    request,
  }) => {
    const asset = await createAsset(request, "oscal-host-headers");
    await applyStig(request, asset.id, "edge");

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/oscal.json`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toContain("application/json");
    const cd = res.headers()["content-disposition"] || "";
    expect(cd).toContain("oscal-");
    expect(cd).toContain(".json");
  });

  test("body shape matches OSCAL assessment-results with asset/STIG metadata", async ({
    request,
  }) => {
    const asset = await createAsset(request, "oscal-host-shape");
    const checklist = await applyStig(request, asset.id, "edge");

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/oscal.json`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.json();

    expect(body["assessment-results"]).toBeTruthy();
    expect(body["assessment-results"].uuid).toBe(asset.id);
    expect(body["assessment-results"].metadata.title).toContain(asset.name);
    expect(body["assessment-results"].metadata["oscal-version"]).toBe("1.1.2");

    // Look up the live STIG title and confirm it round-trips into results[0].
    const cat = await request
      .get(`${BACKEND}/api/catalog`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    const edge = cat.find((s) => s.id === "edge");
    expect(edge).toBeTruthy();

    const results = body["assessment-results"].results;
    expect(Array.isArray(results)).toBe(true);
    expect(results).toHaveLength(1);
    expect(results[0].uuid).toBe(checklist.id);
    expect(results[0].title).toBe(edge.title);
  });

  test("findings.target.status.state reflects per-rule status", async ({
    request,
  }) => {
    const asset = await createAsset(request, "oscal-host-states");
    const checklist = await applyStig(request, asset.id, "edge");
    const detail = await getChecklist(request, checklist.id);
    expect(detail.rules.length).toBeGreaterThanOrEqual(3);

    const satisfiedRule = detail.rules[0].id;
    const openRule = detail.rules[1].id;
    const notReviewedRule = detail.rules[2].id;

    await setRuleStatus(
      request,
      checklist.id,
      satisfiedRule,
      "not_a_finding",
      "compliant per local config",
    );
    await setRuleStatus(
      request,
      checklist.id,
      openRule,
      "open",
      "missing GPO",
    );
    // notReviewedRule left untouched → default `not_reviewed`.

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/oscal.json`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.json();
    const findings = body["assessment-results"].results[0].findings;

    const byId = new Map();
    for (const f of findings) {
      byId.set(f.target["target-id"], f);
    }
    expect(byId.get(satisfiedRule).target.status.state).toBe("satisfied");
    expect(byId.get(openRule).target.status.state).toBe("not-satisfied");
    expect(byId.get(notReviewedRule).target.status.state).toBe("other");
  });

  test("asset with no applied checklists gets results: []", async ({
    request,
  }) => {
    const asset = await createAsset(request, "oscal-host-empty");

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/oscal.json`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body["assessment-results"].uuid).toBe(asset.id);
    expect(body["assessment-results"].results).toEqual([]);
  });

  test("404 on unknown asset id", async ({ request }) => {
    const res = await request.get(
      `${BACKEND}/api/assets/does-not-exist/oscal.json`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(404);
  });
});

test.describe("OSCAL JSON export — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("AssetDetail Download OSCAL button triggers a browser download", async ({
    page,
    request,
  }) => {
    await loginAs(page, "alice");
    const asset = await createAsset(request, "oscal-host-ui");
    await applyStig(request, asset.id, "edge");

    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "oscal-host-ui" }).click();

    const btn = page.getByRole("button", { name: /download oscal/i });
    await expect(btn).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      btn.click(),
    ]);
    // Filename comes from the server's Content-Disposition; the suggested
    // value should at least start with "oscal-" and end with ".json".
    const suggested = download.suggestedFilename();
    expect(suggested).toMatch(/^oscal-.*\.json$/);
  });
});
