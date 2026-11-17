import { test, expect } from "@playwright/test";
import { loginAs, loadDemoStig, openEdgeFromLibrary, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * "Save to system" (issue #19): push a Viewer tab's per-rule status, finding
 * details and comments into a system's checklist via
 * POST /api/assets/:id/checklists/save.
 */

const ASSET_NAME = "save-host";
const ensureUserViaMe = (request, user) =>
  request.get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": user } });
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

  test("GET /api/assets?writable=true lists only systems the caller can write to", async ({ request }) => {
    const mine = await seedAsset(request);
    const theirs = await request
      .post(`${BACKEND}/api/assets`, { headers: JSON_HEADERS("mallory"), data: { name: "mallory-host" } })
      .then((r) => r.json());
    const ids = async (query, user = "alice") =>
      (await request.get(`${BACKEND}/api/assets${query}`, { headers: { "X-User-Id": user } }).then((r) => r.json())).map((a) => a.id);

    // Unfiltered and writable=false are identical and hold exactly both systems.
    const all = (await ids("")).sort();
    expect(all).toEqual([mine.id, theirs.id].sort());
    expect((await ids("?writable=false")).sort()).toEqual(all);
    // Fail closed on a malformed value.
    for (const bad of ["yes", "", "0"]) {
      const res = await request.get(`${BACKEND}/api/assets?writable=${bad}`, { headers: { "X-User-Id": "alice" } });
      expect(res.status()).toBe(400);
    }
    // A user with no writable systems gets [].
    await ensureUserViaMe(request, "carol");
    expect(await ids("?writable=true", "carol")).toEqual([]);
    expect(await ids("?writable=true")).toEqual([mine.id]);

    // A read grant does not make it writable; a write grant does.
    const alice = await request.get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    const grant = (permission) =>
      request.post(`${BACKEND}/api/assets/${theirs.id}/acl`, {
        headers: JSON_HEADERS("mallory"),
        data: { userId: alice.id, permission },
      });
    expect((await grant("read")).ok()).toBeTruthy();
    expect(await ids("?writable=true")).toEqual([mine.id]);
    expect((await grant("write")).ok()).toBeTruthy();
    expect((await ids("?writable=true")).sort()).toEqual([mine.id, theirs.id].sort());
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

test.describe("Save to system — audit events and creator", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  async function events(request) {
    await setUserRole("audit-admin", "admin");
    const res = await request.get(`${BACKEND}/api/audit/events`, {
      headers: { "X-User-Id": "audit-admin" },
    });
    expect(res.status()).toBe(200);
    return (await res.json()).rows;
  }

  test("a save that creates the checklist leaves create and save events and sets createdBy", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    const secret = "E2E-SECRET-COMMENT";
    const out = await save(request, asset.id, {
      rules: [
        { ruleId: ids[0], status: "open", comments: secret },
        { ruleId: "SV-not-in-this-stig", status: "open" },
      ],
    }).then((r) => r.json());
    expect(out.created).toBe(true);

    const rows = await events(request);
    const create = rows.filter((r) => r.action === "checklist.create");
    const saves = rows.filter((r) => r.action === "checklist.save");
    expect(create).toHaveLength(1);
    expect(create[0].detail.via).toBe("save");
    expect(saves).toHaveLength(1);
    expect(saves[0].outcome).toBe("partial");
    expect(saves[0].detail.created).toBe(true);
    expect(saves[0].detail.applied).toBe(1);
    expect(saves[0].detail.errors).toBe(1);
    expect(JSON.stringify(rows)).not.toContain(secret);

    const me = await request.get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    const detail = await request
      .get(`${BACKEND}/api/checklists/${out.checklistId}`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(detail.checklist.createdBy).toBe(me.id);
  });

  test("creating through POST /checklists sets createdBy and leaves a create event", async ({ request }) => {
    const asset = await seedAsset(request);
    const created = await request
      .post(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: JSON_HEADERS("alice"), data: { stigId: "edge" } })
      .then((r) => r.json());
    const me = await request.get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    expect(created.createdBy).toBe(me.id);
    const rows = await events(request);
    expect(rows.filter((r) => r.action === "checklist.create" && r.detail.via === "create")).toHaveLength(1);
  });

  test("an over-long stigId on create is refused and never stored in an event", async ({ request }) => {
    const asset = await seedAsset(request);
    const huge = "A".repeat(100_000);
    const create = (user) =>
      request.post(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: JSON_HEADERS(user), data: { stigId: huge } });
    expect((await create("mallory")).status()).toBe(403);
    expect((await create("alice")).status()).toBe(400);
    const rows = (await events(request)).filter((r) => r.action === "checklist.create");
    expect(rows.map((r) => [r.outcome, r.detail.reason]).sort()).toEqual([
      ["denied", "forbidden"],
      ["rejected", "invalid_stig_id"],
    ]);
    for (const r of rows) expect(r.stigTitle).toBeNull();
    expect(JSON.stringify(rows).length).toBeLessThan(2000);
  });

  test("a 403 leaves a denied event; a 400 leaves a rejected event", async ({ request }) => {
    const asset = await seedAsset(request);
    const ids = await edgeRuleIds(request);
    const rules = [{ ruleId: ids[0], status: "open" }];
    expect((await save(request, asset.id, { rules }, "mallory")).status()).toBe(403);
    expect((await save(request, asset.id, { stigId: "../etc", rules })).status()).toBe(400);
    const rows = (await events(request)).filter((r) => r.action === "checklist.save");
    expect(rows.map((r) => [r.outcome, r.detail.reason]).sort()).toEqual([
      ["denied", "forbidden"],
      ["rejected", "invalid_stig_id"],
    ]);
    expect(rows.find((r) => r.outcome === "denied").byName).toBe("mallory");
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
    await openEdgeFromLibrary(page);
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

  test("a rule the server rejects is listed in the result alert", async ({ page, request }) => {
    await seedAsset(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await openEdgeFromLibrary(page);
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
    const [ruleId] = await edgeRuleIds(request);

    // Not a Finding without finding details is rejected per rule.
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Not a Finding", exact: true }).click();

    await page.getByTestId("save-to-system").click();
    await page.getByTestId("save-system-select").click();
    await page.getByRole("option", { name: new RegExp(ASSET_NAME) }).click();
    await page.getByTestId("save-system-apply").click();

    const result = page.getByTestId("save-system-result");
    await expect(result).toContainText("1 not saved");
    await expect(result.locator("li code")).toHaveCount(1);
    await expect(result).toContainText(/finding details required/i);
    await expect(result.locator("li code")).toHaveText(ruleId);
  });

  test("a closing status already pending is listed with its note", async ({ page, request }) => {
    const asset = await seedAsset(request);
    const [ruleId] = await edgeRuleIds(request);
    await request.patch(`${BACKEND}/api/assets/${asset.id}/approval-policy`, {
      headers: JSON_HEADERS("alice"),
      data: { requiresApproval: true },
    });
    await save(request, asset.id, {
      rules: [{ ruleId, status: "not_a_finding", findingDetails: "Verified in UI." }],
    });
    await loginAs(page, "alice");
    await page.goto("/");
    await openEdgeFromLibrary(page);
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Not a Finding", exact: true }).click();
    await page.getByPlaceholder(/enter finding details/i).fill("Verified in UI.");

    await page.getByTestId("save-to-system").click();
    await page.getByTestId("save-system-select").click();
    await page.getByRole("option", { name: new RegExp(ASSET_NAME) }).click();
    await page.getByTestId("save-system-apply").click();

    const result = page.getByTestId("save-system-result");
    await expect(result.locator("li code")).toHaveText(ruleId);
    await expect(result).toContainText(/already pending/i);
  });

  test("selecting a system that already has a checklist shows the overwrite notice", async ({ page, request }) => {
    const asset = await seedAsset(request);
    await request.post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: JSON_HEADERS("alice"),
      data: { stigId: "edge" },
    });
    await loginAs(page, "alice");
    await page.goto("/");
    await openEdgeFromLibrary(page);
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
    await page.getByTestId("save-to-system").click();
    await page.getByTestId("save-system-select").click();
    await page.getByRole("option", { name: new RegExp(ASSET_NAME) }).click();
    await expect(page.getByText(/already has a checklist for this STIG/)).toBeVisible();
  });

  test("the picker lists only systems the user can write to", async ({ page, request }) => {
    await seedAsset(request);
    await request.post(`${BACKEND}/api/assets`, { headers: JSON_HEADERS("mallory"), data: { name: "mallory-host" } });
    await loginAs(page, "alice");
    await page.goto("/");
    await openEdgeFromLibrary(page);
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
    await page.getByTestId("save-to-system").click();
    await page.getByTestId("save-system-select").click();
    await expect(page.getByRole("option", { name: new RegExp(ASSET_NAME) })).toBeVisible();
    await expect(page.getByRole("option", { name: /mallory-host/ })).toHaveCount(0);
  });

  test("a user with no writable systems sees the empty state", async ({ page, request }) => {
    await seedAsset(request); // alice's system, not writable by carol
    await loginAs(page, "carol");
    await page.goto("/");
    await openEdgeFromLibrary(page);
    const listbox = page.getByRole("listbox", { name: "Rules" });
    await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
    await page.getByTestId("save-to-system").click();
    await page.getByTestId("save-system-select").click();
    await expect(page.getByText("No systems you can write to.")).toBeVisible();
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
