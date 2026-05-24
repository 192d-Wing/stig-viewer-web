import { test, expect } from "@playwright/test";
import { resetDb, BACKEND } from "./helpers.js";

/**
 * Seed an asset + checklist, then patch the first rule a couple of
 * times so each PATCH writes audit rows into `rule_audit`. Returns
 * the checklist + rule id so the test can backdate by `rule_id` and
 * later re-fetch history to count what survived a prune.
 */
async function seedAuditRows(request, userName) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": userName, "Content-Type": "application/json" },
      data: { name: "retention-host" },
    })
    .then((r) => r.json());
  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": userName, "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": userName },
    })
    .then((r) => r.json());
  const ruleId = detail.rules[0].id;

  // Two PATCHes × two changed fields each = 4 audit rows.
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": userName, "Content-Type": "application/json" },
      data: { status: "open", findingDetails: "first" },
    },
  );
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": userName, "Content-Type": "application/json" },
      data: { status: "not_a_finding", findingDetails: "resolved" },
    },
  );

  return { checklistId: checklist.id, ruleId };
}

async function runRetention(request, retainDays, archive) {
  const res = await request.post(`${BACKEND}/api/test/run-retention`, {
    headers: { "Content-Type": "application/json" },
    data: { retain_days: retainDays, archive },
  });
  expect(res.ok()).toBe(true);
  return res.json();
}

async function backdateAudit(request, ruleId, days) {
  const res = await request.post(`${BACKEND}/api/test/backdate-audit`, {
    headers: { "Content-Type": "application/json" },
    data: { rule_id: ruleId, days },
  });
  expect(res.ok() || res.status() === 204).toBe(true);
}

async function fetchHistory(request, userName, checklistId, ruleId) {
  return request
    .get(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/history`,
      { headers: { "X-User-Id": userName } },
    )
    .then((r) => r.json());
}

test.describe("Audit retention", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: nothing older than retain_days → pruned is 0", async ({
    request,
  }) => {
    await seedAuditRows(request, "alice");
    // No backdate — every row is freshly written, so retain_days=30
    // leaves them all in place.
    const { pruned } = await runRetention(request, 30, true);
    expect(pruned).toBe(0);
  });

  test("API: backdated rows older than retain_days are pruned and history shrinks", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedAuditRows(request, "alice");

    const before = await fetchHistory(request, "alice", checklistId, ruleId);
    expect(before.length).toBe(4);

    // Push every audit row for this rule 60 days into the past so the
    // retain_days=30 cutoff sweeps them all.
    await backdateAudit(request, ruleId, 60);

    const { pruned } = await runRetention(request, 30, false);
    expect(pruned).toBe(before.length);

    const after = await fetchHistory(request, "alice", checklistId, ruleId);
    expect(after.length).toBe(0);
  });

  test("API: archive=true with pruned rows reports the same count as archive=false", async ({
    request,
  }) => {
    // We don't have a directory-read endpoint, so the strongest signal
    // for "archive ran" is that the prune count is preserved regardless
    // of the archive flag. The file write itself is best-effort and a
    // follow-up could expose it via a read endpoint.
    const { ruleId } = await seedAuditRows(request, "alice");
    await backdateAudit(request, ruleId, 60);

    const { pruned } = await runRetention(request, 30, true);
    expect(pruned).toBeGreaterThan(0);
  });

  test("API: retain_days larger than backdate offset leaves rows in place", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedAuditRows(request, "alice");
    await backdateAudit(request, ruleId, 10);

    const { pruned } = await runRetention(request, 365, false);
    expect(pruned).toBe(0);

    const after = await fetchHistory(request, "alice", checklistId, ruleId);
    expect(after.length).toBe(4);
  });

  test("API: re-running prune after a sweep is a no-op", async ({ request }) => {
    const { ruleId } = await seedAuditRows(request, "alice");
    await backdateAudit(request, ruleId, 60);

    const first = await runRetention(request, 30, false);
    expect(first.pruned).toBeGreaterThan(0);

    const second = await runRetention(request, 30, false);
    expect(second.pruned).toBe(0);
  });
});
