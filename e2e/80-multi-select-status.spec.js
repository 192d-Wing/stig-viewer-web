import { test, expect } from "@playwright/test";
import { loginAs, loadDemoStig, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Multi-select "set status" (issue #20):
 *   - Viewer: tick rules in the rule list and set their status in one action.
 *   - Asset checklists: select table rows and apply a status through
 *     POST /api/checklists/:id/rules/bulk-status.
 */

const ASSET_NAME = "multi-select-host";

async function seedChecklist(request, owner = "alice") {
  const headers = { "X-User-Id": owner, "Content-Type": "application/json" };
  const asset = await request
    .post(`${BACKEND}/api/assets`, { headers, data: { name: ASSET_NAME } })
    .then((r) => r.json());
  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers, data: { stigId: "edge" } })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklist.id}`, { headers })
    .then((r) => r.json());
  return {
    checklistId: checklist.id,
    ruleIds: detail.rules.slice(0, 4).map((r) => r.id),
  };
}

async function ruleStates(request, checklistId, user = "alice") {
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklistId}`, { headers: { "X-User-Id": user } })
    .then((r) => r.json());
  return Object.fromEntries(detail.rules.map((r) => [r.id, r.state ?? {}]));
}

function bulkStatus(request, checklistId, data, user = "alice") {
  return request.post(`${BACKEND}/api/checklists/${checklistId}/rules/bulk-status`, {
    headers: { "X-User-Id": user, "Content-Type": "application/json" },
    data,
  });
}

test.describe("Viewer — multi-select status", () => {
  test.beforeEach(async ({ page }) => {
    await loadDemoStig(page);
  });

  test("ticking rules and choosing a status changes only those rules", async ({ page }) => {
    const checks = page.getByTestId("rule-check");
    await expect(checks).toHaveCount(12);
    await expect(page.getByTestId("rule-bulk-bar")).toHaveCount(0);

    await checks.nth(0).click();
    await checks.nth(2).click();
    await expect(page.getByTestId("rule-bulk-count")).toHaveText("2 selected");

    // The demo STIG starts with mixed statuses, so compare against the
    // untouched row rather than absolute counts.
    const rows = page.getByRole("option");
    const untouched = await rows.nth(1).textContent();
    await page.getByTestId("rule-bulk-set-not_applicable").click();
    await expect(rows.nth(0)).toContainText("Not Applicable");
    await expect(rows.nth(2)).toContainText("Not Applicable");
    await expect(rows.nth(1)).toHaveText(untouched);
  });

  test("ticks are discarded when switching STIG tabs", async ({ page }) => {
    // Open a second tab with the same rule ids so stale ticks would show.
    await page.getByRole("link", { name: "Browse Library" }).click();
    await page.getByRole("button", { name: "Open Local File" }).click();
    await page.getByRole("button", { name: "Load Demo STIG" }).click();
    const tabs = page.locator("nav .ui-sidenav-item a");
    await expect(tabs).toHaveCount(2);

    await tabs.nth(1).click();
    await page.getByTestId("rule-check").nth(0).click();
    await expect(page.getByTestId("rule-bulk-count")).toHaveText("1 selected");

    await tabs.nth(0).click();
    await expect(page.getByTestId("rule-check")).toHaveCount(12);
    await expect(page.getByTestId("rule-bulk-bar")).toHaveCount(0);

    // Switching away discards the ticks: they do not come back on return.
    await tabs.nth(1).click();
    await expect(page.getByTestId("rule-check")).toHaveCount(12);
    await expect(page.getByTestId("rule-bulk-bar")).toHaveCount(0);
    await expect(page.locator('[data-testid="rule-check"]:checked')).toHaveCount(0);
  });

  test("shift-click selects a range; Clear empties the selection", async ({ page }) => {
    const checks = page.getByTestId("rule-check");
    await checks.nth(1).click();
    await checks.nth(4).click({ modifiers: ["Shift"] });
    await expect(page.getByTestId("rule-bulk-count")).toHaveText("4 selected");

    await page.getByTestId("rule-bulk-set-not_applicable").click();
    const rows = page.getByRole("option");
    for (const i of [1, 2, 3, 4]) await expect(rows.nth(i)).toContainText("Not Applicable");
    await expect(rows.nth(0)).not.toContainText("Not Applicable");
    await expect(rows.nth(5)).not.toContainText("Not Applicable");

    await page.getByTestId("rule-bulk-clear").click();
    await expect(page.getByTestId("rule-bulk-bar")).toHaveCount(0);
  });

  test("Select all follows the active filter", async ({ page }) => {
    await page.getByPlaceholder("Search by ID, title, or content…").fill("password");
    await expect(page.getByText(/^\d+ of 12 rules$/)).not.toHaveText("12 of 12 rules");
    const visible = await page.getByTestId("rule-check").count();
    expect(visible).toBeGreaterThan(0);
    expect(visible).toBeLessThan(12);
    await expect(page.getByText(`${visible} of 12 rules`, { exact: true })).toBeVisible();

    await page.getByTestId("rule-check-all").click();
    await expect(page.getByTestId("rule-bulk-count")).toHaveText(`${visible} selected`);
    await page.getByTestId("rule-bulk-set-not_applicable").click();
    const rows = page.getByRole("option");
    await expect(rows.filter({ hasText: "Not Applicable" })).toHaveCount(visible);

    // Rules hidden by the filter were not selected and keep their status.
    await page.getByPlaceholder("Search by ID, title, or content…").fill("");
    await expect(rows).toHaveCount(12);
    await expect(page.getByTestId("rule-bulk-count")).toHaveText(`${visible} selected`);
    expect(await rows.filter({ hasText: "Not Applicable" }).count()).toBeLessThan(12);
  });
});

test.describe("Checklist bulk status — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("sets a non-closing status on every listed rule", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const res = await bulkStatus(request, checklistId, { ruleIds: ruleIds.slice(0, 3), status: "open" });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.appliedCount).toBe(3);
    expect(body.errorCount).toBe(0);

    const states = await ruleStates(request, checklistId);
    for (const id of ruleIds.slice(0, 3)) expect(states[id].status).toBe("open");
    expect(states[ruleIds[3]].status ?? "not_reviewed").toBe("not_reviewed");
  });

  test("closing statuses need finding details, shared or per rule", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);

    // No justification anywhere: nothing is closed.
    let body = await bulkStatus(request, checklistId, {
      ruleIds: ruleIds.slice(0, 2),
      status: "not_a_finding",
    }).then((r) => r.json());
    expect(body.appliedCount).toBe(0);
    expect(body.errorCount).toBe(2);
    expect(body.results[0].error).toMatch(/finding details required/i);

    // Shared justification applies to every rule.
    body = await bulkStatus(request, checklistId, {
      ruleIds: ruleIds.slice(0, 2),
      status: "not_a_finding",
      findingDetails: "Verified by scan 2026-11.",
    }).then((r) => r.json());
    expect(body.appliedCount).toBe(2);
    const states = await ruleStates(request, checklistId);
    expect(states[ruleIds[0]].status).toBe("not_a_finding");
    expect(states[ruleIds[0]].findingDetails).toBe("Verified by scan 2026-11.");
  });

  test("unknown rule ids are reported, valid ones still apply", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = await bulkStatus(request, checklistId, {
      ruleIds: [ruleIds[0], "SV-does-not-exist"],
      status: "open",
    }).then((r) => r.json());
    expect(body.appliedCount).toBe(1);
    expect(body.errorCount).toBe(1);
    expect(body.results.find((r) => r.ruleId === "SV-does-not-exist").status).toBe("error");
  });

  test("rejects bad input and users without write access", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    expect((await bulkStatus(request, checklistId, { ruleIds, status: "bogus" })).status()).toBe(400);
    expect((await bulkStatus(request, checklistId, { ruleIds: [], status: "open" })).status()).toBe(400);
    expect((await bulkStatus(request, "no-such-checklist", { ruleIds, status: "open" })).status()).toBe(404);
    expect((await bulkStatus(request, checklistId, { ruleIds, status: "open" }, "mallory")).status()).toBe(403);
    const states = await ruleStates(request, checklistId);
    expect(states[ruleIds[0]].status ?? "not_reviewed").toBe("not_reviewed");
  });

  test("approval assets: closing statuses are queued, not applied, and not duplicated", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const asset = await request
      .get(`${BACKEND}/api/checklists/${checklistId}`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json())
      .then((d) => d.asset);
    const policy = await request.patch(`${BACKEND}/api/assets/${asset.id}/approval-policy`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { requiresApproval: true },
    });
    expect(policy.ok()).toBeTruthy();

    const targets = ruleIds.slice(0, 3);
    const req = { ruleIds: targets, status: "not_a_finding", findingDetails: "Verified by scan." };
    for (let i = 0; i < 2; i++) {
      const body = await bulkStatus(request, checklistId, req).then((r) => r.json());
      expect(body.pendingCount).toBe(3);
      expect(body.appliedCount).toBe(0);
      expect(body.errorCount).toBe(0);
      if (i === 1) expect(body.results[0].note).toMatch(/already pending/i);
      else expect(body.results[0].note).toBeUndefined();
    }

    const states = await ruleStates(request, checklistId);
    for (const id of targets) expect(states[id].status ?? "not_reviewed").toBe("not_reviewed");
    const pending = await request
      .get(`${BACKEND}/api/approvals?status=pending`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(pending.length).toBe(3);
    expect(pending.map((a) => a.ruleId).sort()).toEqual([...targets].sort());
  });

  test("over-limit ruleIds and oversized finding details are rejected", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const many = Array.from({ length: 2001 }, (_, i) => `SV-fake-${i}`);
    expect((await bulkStatus(request, checklistId, { ruleIds: many, status: "open" })).status()).toBe(400);
    // More distinct ids than the STIG has rules (59 for edge).
    const tooMany = Array.from({ length: 100 }, (_, i) => `SV-fake-${i}`);
    expect((await bulkStatus(request, checklistId, { ruleIds: tooMany, status: "open" })).status()).toBe(400);
    const huge = "x".repeat(40 * 1024);
    expect(
      (await bulkStatus(request, checklistId, { ruleIds, status: "not_a_finding", findingDetails: huge })).status(),
    ).toBe(400);
  });

  test("an over-long rule id is a per-rule error", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = await bulkStatus(request, checklistId, {
      ruleIds: [ruleIds[0], "x".repeat(300)],
      status: "open",
    }).then((r) => r.json());
    expect(body.appliedCount).toBe(1);
    expect(body.errorCount).toBe(1);
    const bad = body.results.find((r) => r.status === "error");
    expect(bad.error).toBe("rule id too long");
    expect(bad.ruleId.length).toBeLessThanOrEqual(64);
  });

  test("a duplicate rule id yields one result row", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = await bulkStatus(request, checklistId, {
      ruleIds: [ruleIds[0], ruleIds[0], ruleIds[1]],
      status: "open",
    }).then((r) => r.json());
    expect(body.results.length).toBe(2);
    expect(body.appliedCount).toBe(2);
  });

  test("comments, assignee and due date survive a bulk status change", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const bob = await request
      .get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "bob" } })
      .then((r) => r.json());
    const patch = await request.patch(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleIds[0])}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open", comments: "keep me", assigneeId: bob.id, dueDate: "2026-12-31" },
      },
    );
    expect(patch.ok()).toBeTruthy();

    const body = await bulkStatus(request, checklistId, { ruleIds: [ruleIds[0]], status: "not_applicable", findingDetails: "n/a here" })
      .then((r) => r.json());
    expect(body.appliedCount).toBe(1);
    const s = (await ruleStates(request, checklistId))[ruleIds[0]];
    expect(s.status).toBe("not_applicable");
    expect(s.comments).toBe("keep me");
    expect(s.assigneeId).toBe(bob.id);
    expect(s.dueDate).toContain("2026-12-31");
  });

  test("writes one audit row per changed field, attributed to the acting user", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = await bulkStatus(request, checklistId, {
      ruleIds: [ruleIds[0]],
      status: "not_a_finding",
      findingDetails: "Audited.",
    }).then((r) => r.json());
    expect(body.appliedCount).toBe(1);
    const rows = await request
      .get(`${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleIds[0])}/history`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(rows.map((r) => r.field).sort()).toEqual(["finding_details", "status"]);
    expect(rows.every((r) => r.userName === "alice")).toBe(true);
    expect(rows.find((r) => r.field === "status").toValue).toBe("not_a_finding");
  });

  test("a viewer-role user gets 403 and nothing changes", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    await setUserRole("viewer-vic", "viewer");
    const res = await bulkStatus(request, checklistId, { ruleIds, status: "open" }, "viewer-vic");
    expect(res.status()).toBe(403);
    const states = await ruleStates(request, checklistId);
    for (const id of ruleIds) expect(states[id].status ?? "not_reviewed").toBe("not_reviewed");
  });
});

test.describe("Checklist bulk status — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("select rows, set status with a shared justification", async ({ page, request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: ASSET_NAME }).click();
    await page.getByRole("button", { name: /edge/i }).first().click();

    const setStatus = page.getByTestId("set-status-button");
    await expect(setStatus).toBeDisabled();

    const rowChecks = page.getByRole("checkbox", { name: "Select row" });
    await rowChecks.nth(0).check();
    await rowChecks.nth(1).check();
    await expect(setStatus).toHaveText("Set status (2)");
    await setStatus.click();

    const modal = page.getByTestId("set-status-modal");
    await modal.getByLabel("Not a finding").check();
    await modal.getByTestId("set-status-details").locator("textarea").fill("Confirmed compliant during audit.");
    await modal.getByTestId("set-status-apply").click();

    await expect(page.getByTestId("set-status-result")).toContainText("Set 2 rules to Not a finding.");
    const states = await ruleStates(request, checklistId);
    expect(states[ruleIds[0]].status).toBe("not_a_finding");
    expect(states[ruleIds[1]].status).toBe("not_a_finding");
    expect(states[ruleIds[1]].findingDetails).toBe("Confirmed compliant during audit.");
    // Selection is cleared once everything applied.
    await expect(setStatus).toBeDisabled();
  });

  test("a bulk change that fails for every rule lists 10 ids and the overflow", async ({ page, request }) => {
    await seedChecklist(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: ASSET_NAME }).click();
    await page.getByRole("button", { name: /edge/i }).first().click();

    const rowChecks = page.getByRole("checkbox", { name: "Select row" });
    await expect(rowChecks.first()).toBeVisible();
    for (let i = 0; i < 11; i++) await rowChecks.nth(i).check();
    await page.getByTestId("set-status-button").click();
    // Closing status with no justification: the server rejects every rule.
    await page.getByTestId("set-status-modal").getByLabel("Not a finding").check();
    await page.getByTestId("set-status-apply").click();

    const result = page.getByTestId("set-status-result");
    await expect(result).toContainText("…and 1 more (still selected).");
    await expect(result.locator("li code")).toHaveCount(10);
  });

  test("select all and Set status act only on rows the filter shows", async ({ page, request }) => {
    const { checklistId } = await seedChecklist(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: ASSET_NAME }).click();
    await page.getByRole("button", { name: /edge/i }).first().click();

    const rowChecks = page.getByRole("checkbox", { name: "Select row" });
    await expect(rowChecks.first()).toBeVisible();
    const total = await rowChecks.count();
    await page.getByPlaceholder("Filter rules").fill("password");
    await expect(rowChecks).not.toHaveCount(total);
    const visible = await rowChecks.count();
    expect(visible).toBeGreaterThan(0);

    await page.getByRole("checkbox", { name: /select all/i }).first().check();
    await expect(page.getByTestId("set-status-button")).toHaveText(`Set status (${visible})`);
    await page.getByTestId("set-status-button").click();
    await page.getByTestId("set-status-modal").getByLabel("Open", { exact: true }).check();
    await page.getByTestId("set-status-apply").click();
    await expect(page.getByTestId("set-status-result")).toContainText(`Set ${visible} rule`);

    const states = await ruleStates(request, checklistId);
    const opened = Object.values(states).filter((x) => x.status === "open").length;
    expect(opened).toBe(visible);
  });
});

test.describe("Checklist bulk status — audit events", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  async function events(request, query = "") {
    await setUserRole("audit-admin", "admin");
    const res = await request.get(`${BACKEND}/api/audit/events${query}`, {
      headers: { "X-User-Id": "audit-admin" },
    });
    expect(res.status()).toBe(200);
    return (await res.json()).rows.filter((r) => r.action === "rules.bulk_status");
  }

  test("an admin sees one event with the right counts, and no request text", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const secret = "E2E-SECRET-FINDING-TEXT";
    const res = await bulkStatus(request, checklistId, {
      ruleIds: [...ruleIds.slice(0, 3), "SV-not-in-this-stig"],
      status: "not_a_finding",
      findingDetails: secret,
    });
    expect(res.status()).toBe(200);

    const rows = await events(request);
    expect(rows).toHaveLength(1);
    const [ev] = rows;
    expect(ev.outcome).toBe("partial");
    expect(ev.assetName).toBe(ASSET_NAME);
    expect(ev.detail.targetStatus).toBe("not_a_finding");
    expect(ev.detail.requested).toBe(4);
    expect(ev.detail.applied).toBe(3);
    expect(ev.detail.errors).toBe(1);
    expect(ev.detail.rejected).toEqual([
      { ruleId: "SV-not-in-this-stig", reason: "rule is not part of this checklist's STIG" },
    ]);
    expect(JSON.stringify(ev)).not.toContain(secret);
  });

  test("a clean request is recorded as ok", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    await bulkStatus(request, checklistId, { ruleIds: ruleIds.slice(0, 2), status: "open" });
    const rows = await events(request, "?outcome=ok");
    expect(rows).toHaveLength(1);
    expect(rows[0].detail.applied).toBe(2);
  });

  test("a 403 leaves a denied event and a 400 leaves a rejected event", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    expect((await bulkStatus(request, checklistId, { ruleIds, status: "open" }, "mallory")).status()).toBe(403);
    expect((await bulkStatus(request, checklistId, { ruleIds, status: "bogus" })).status()).toBe(400);
    const rows = await events(request);
    expect(rows.map((r) => [r.outcome, r.detail.reason]).sort()).toEqual([
      ["denied", "forbidden"],
      ["rejected", "invalid_status"],
    ]);
    const denied = rows.find((r) => r.outcome === "denied");
    expect(denied.byName).toBe("mallory");
    expect(denied.assetName).toBe(ASSET_NAME);
  });

  test("a NUL or quote in a rule id still leaves an event", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const res = await bulkStatus(request, checklistId, { ruleIds: [ruleIds[0], "\u0000", 'q"\\'], status: "open" });
    expect(res.status()).toBe(200);
    const rows = await events(request);
    expect(rows).toHaveLength(1);
    expect(rows[0].outcome).toBe("partial");
    expect(rows[0].detail.rejected.map((r) => r.ruleId)).toEqual(["?", "q??"]);
  });
});
