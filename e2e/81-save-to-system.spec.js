import { test, expect } from "@playwright/test";
import { loginAs, loadDemoStig, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * "Save to system" (issue #19): push a Viewer tab's per-rule status, finding
 * details and comments into a system's checklist via
 * POST /api/assets/:id/checklists/save.
 */

const ASSET_NAME = "save-host";
const JSON_HEADERS = (user) => ({ "X-User-Id": user, "Content-Type": "application/json" });

async function seedAsset(request, owner = "alice") {
  return request
    .post(`${BACKEND}/api/assets`, { headers: JSON_HEADERS(owner), data: { name: ASSET_NAME } })
    .then((r) => r.json());
}

async function edgeRuleIds(request) {
  const stig = await request.get(`${BACKEND}/api/stigs/edge`).then((r) => r.json());
  return stig.rules.map((r) => r.id);
}

function save(request, assetId, data, user = "alice") {
  return request.post(`${BACKEND}/api/assets/${assetId}/checklists/save`, {
    headers: JSON_HEADERS(user),
    data: { stigId: "edge", ...data },
  });
}

async function ruleStates(request, checklistId, user = "alice") {
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklistId}`, { headers: { "X-User-Id": user } })
    .then((r) => r.json());
  return Object.fromEntries(detail.rules.map((r) => [r.id, r.state ?? {}]));
}

test.describe("Save to system — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("creates the checklist, then a repeat save is a no-op", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    const rules = [
      { ruleId: ids[0], status: "open", comments: "looking" },
      { ruleId: ids[1], status: "not_a_finding", findingDetails: "Verified." },
    ];
    const first = await save(request, asset.id, { rules }).then((r) => r.json());
    expect(first.created).toBe(true);
    expect(first.appliedCount).toBe(2);
    const states = await ruleStates(request, first.checklistId);
    expect(states[ids[0]].status).toBe("open");
    expect(states[ids[0]].comments).toBe("looking");
    expect(states[ids[1]].findingDetails).toBe("Verified.");

    const second = await save(request, asset.id, { rules }).then((r) => r.json());
    expect(second.created).toBe(false);
    expect(second.checklistId).toBe(first.checklistId);
    expect(second.unchangedCount).toBe(2);
    expect(second.appliedCount).toBe(0);
  });

  test("per-rule errors do not abort the batch", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    const body = await save(request, asset.id, {
      rules: [
        { ruleId: ids[0], status: "not_a_finding" },
        { ruleId: ids[1], status: "open" },
        { ruleId: "SV-does-not-exist", status: "open" },
        { ruleId: ids[2], status: "bogus" },
        { ruleId: ids[3], status: "open", comments: "x".repeat(40 * 1024) },
        { ruleId: ids[1], status: "not_applicable", findingDetails: "dup ignored" },
      ],
    }).then((r) => r.json());
    expect(body.results.length).toBe(5);
    expect(body.appliedCount).toBe(1);
    expect(body.errorCount).toBe(4);
    expect(body.results[0].error).toMatch(/finding details required/i);
    expect(body.results[2].status).toBe("error");
  });

  test("untouched rules never downgrade; notes merge without touching status, assignee or due date", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    const bob = await request.get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "bob" } }).then((r) => r.json());
    const checklist = await request
      .post(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: JSON_HEADERS("alice"), data: { stigId: "edge" } })
      .then((r) => r.json());
    const patch = await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ids[0])}`,
      { headers: JSON_HEADERS("alice"), data: { status: "open", comments: "old", assigneeId: bob.id, dueDate: "2026-12-31" } },
    );
    expect(patch.ok()).toBeTruthy();

    // Untouched (not_reviewed, no text): unchanged, server keeps open.
    let body = await save(request, asset.id, { rules: [{ ruleId: ids[0], status: "not_reviewed" }] }).then((r) => r.json());
    expect(body.created).toBe(false);
    expect(body.results[0].status).toBe("unchanged");
    expect((await ruleStates(request, checklist.id))[ids[0]].status).toBe("open");

    // not_reviewed with comments: text merges, status/assignee/due kept.
    body = await save(request, asset.id, { rules: [{ ruleId: ids[0], status: "not_reviewed", comments: "new" }] }).then((r) => r.json());
    expect(body.appliedCount).toBe(1);
    const s = (await ruleStates(request, checklist.id))[ids[0]];
    expect(s.status).toBe("open");
    expect(s.comments).toBe("new");
    expect(s.assigneeId).toBe(bob.id);
    expect(s.dueDate).toContain("2026-12-31");
  });

  test("approval assets: closing statuses are queued; comments are kept", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    await request.patch(`${BACKEND}/api/assets/${asset.id}/approval-policy`, {
      headers: JSON_HEADERS("alice"),
      data: { requiresApproval: true },
    });
    const body = await save(request, asset.id, {
      rules: [{ ruleId: ids[0], status: "not_a_finding", findingDetails: "Fixed.", comments: "see ticket" }],
    }).then((r) => r.json());
    expect(body.pendingCount).toBe(1);
    expect(body.appliedCount).toBe(0);
    const s = (await ruleStates(request, body.checklistId))[ids[0]];
    expect(s.status ?? "not_reviewed").toBe("not_reviewed");
    expect(s.comments).toBe("see ticket");
    const pending = await request
      .get(`${BACKEND}/api/approvals?status=pending`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(pending.length).toBe(1);
  });

  test("writes one audit row per changed field, attributed to the acting user", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    const body = await save(request, asset.id, {
      rules: [{ ruleId: ids[0], status: "not_a_finding", findingDetails: "Saved.", comments: "note" }],
    }).then((r) => r.json());
    expect(body.appliedCount).toBe(1);
    const rows = await request
      .get(`${BACKEND}/api/checklists/${body.checklistId}/rules/${encodeURIComponent(ids[0])}/history`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(rows.map((r) => r.field).sort()).toEqual(["comments", "finding_details", "status"]);
    expect(rows.every((r) => r.userName === "alice")).toBe(true);
  });

  test("a second save while an approval is pending is flagged, not duplicated", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    await request.patch(`${BACKEND}/api/assets/${asset.id}/approval-policy`, {
      headers: JSON_HEADERS("alice"),
      data: { requiresApproval: true },
    });
    const rules = [{ ruleId: ids[0], status: "not_a_finding", findingDetails: "Fixed." }];
    const first = await save(request, asset.id, { rules }).then((r) => r.json());
    expect(first.results[0].note).toBeUndefined();
    const second = await save(request, asset.id, { rules }).then((r) => r.json());
    expect(second.pendingCount).toBe(1);
    expect(second.results[0].note).toMatch(/already pending/i);
  });

  test("two parallel saves to a fresh system leave exactly one checklist", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    const rules = [{ ruleId: ids[0], status: "open" }];
    const [a, b] = await Promise.all([save(request, asset.id, { rules }), save(request, asset.id, { rules })]);
    expect(a.status()).toBe(200);
    expect(b.status()).toBe(200);
    const list = await request
      .get(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(list.length).toBe(1);
  });

  test("validation and authorization", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    const rules = [{ ruleId: ids[0], status: "open" }];
    const tooMany = Array.from({ length: 2001 }, (_, i) => ({ ruleId: `SV-fake-${i}`, status: "open" }));
    expect((await save(request, asset.id, { rules: tooMany })).status()).toBe(400);
    // More distinct ids than the STIG has rules (59 for edge).
    const moreThanStig = Array.from({ length: 100 }, (_, i) => ({ ruleId: `SV-fake-${i}`, status: "open" }));
    expect((await save(request, asset.id, { rules: moreThanStig })).status()).toBe(400);
    expect((await save(request, asset.id, { stigId: "../etc", rules })).status()).toBe(400);
    expect((await save(request, asset.id, { stigId: "no-such-stig", rules })).status()).toBe(404);
    expect((await save(request, "no-such-asset", { rules })).status()).toBe(404);
    expect((await save(request, asset.id, { rules }, "mallory")).status()).toBe(403);
    await setUserRole("viewer-vic", "viewer");
    expect((await save(request, asset.id, { rules }, "viewer-vic")).status()).toBe(403);
    // Nothing was created by the rejected or failed requests.
    const list = await request
      .get(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(list.length).toBe(0);

    // An over-long rule id is a per-rule error with a truncated echo.
    const longId = await save(request, asset.id, { rules: [{ ruleId: "x".repeat(300), status: "open" }] }).then((r) => r.json());
    expect(longId.results[0].error).toMatch(/too long/);
    expect(longId.results[0].ruleId.length).toBeLessThanOrEqual(64);
  });
});

test.describe("Save to system — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("open edge from the library, evaluate two rules, save to a system", async ({ page, request }) => {
    const asset = await seedAsset(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByText(/Microsoft Edge Security Technical/).first().click();
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });

    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await listbox.getByRole("option").nth(1).click();
    await page.getByRole("button", { name: "Not a Finding", exact: true }).click();
    await page.getByPlaceholder(/enter finding details/i).fill("Verified in UI.");

    await page.getByTestId("save-to-system").click();
    await page.getByTestId("save-system-select").click();
    await page.getByRole("option", { name: new RegExp(ASSET_NAME) }).click();
    await expect(page.getByText("A new checklist will be created.")).toBeVisible();
    await page.getByTestId("save-system-apply").click();

    const result = page.getByTestId("save-system-result");
    await expect(result).toContainText(`Saved 2 rules to ${ASSET_NAME}.`);

    const list = await request
      .get(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(list.length).toBe(1);
    const states = Object.values(await ruleStates(request, list[0].id));
    expect(states.filter((x) => x.status === "open").length).toBe(1);
    expect(states.filter((x) => x.status === "not_a_finding" && x.findingDetails === "Verified in UI.").length).toBe(1);
  });

  test("selecting a system that already has a checklist shows the overwrite notice", async ({ page, request }) => {
    const asset = await seedAsset(request);
    await request.post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: JSON_HEADERS("alice"),
      data: { stigId: "edge" },
    });
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByText(/Microsoft Edge Security Technical/).first().click();
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
    await page.getByTestId("save-to-system").click();
    await page.getByTestId("save-system-select").click();
    await page.getByRole("option", { name: new RegExp(ASSET_NAME) }).click();
    await expect(page.getByText(/already has a checklist for this STIG/)).toBeVisible();
  });

  test("the demo STIG cannot be saved to a system", async ({ page }) => {
    await loadDemoStig(page);
    await expect(page.getByTestId("save-to-system")).toBeDisabled();
  });

  test("a viewer-role user has no Save to system button", async ({ page }) => {
    await setUserRole("viewer-vic", "viewer");
    await loadDemoStig(page); // logs in as demo-user; re-login as the viewer
    await loginAs(page, "viewer-vic");
    await page.goto("/");
    await page.getByRole("button", { name: "Open Local File" }).click();
    await page.getByRole("button", { name: "Load Demo STIG" }).click();
    await expect(page.getByRole("button", { name: "Export POAM" })).toBeVisible();
    await expect(page.getByTestId("save-to-system")).toHaveCount(0);
  });
});
