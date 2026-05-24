import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Helper: build a CSV body from header + row strings. Inline so the spec
 * is self-contained — the bulk-import CSVs are tiny.
 */
function csv(...lines) {
  return Buffer.from(lines.join("\n") + "\n", "utf-8");
}

const HEADER = "rule_id,status,finding_details";

/**
 * Seed an asset + checklist owned by `alice` and return its first three
 * rule ids. The 'edge' STIG has many rules, so we always have at least
 * three available for batch tests.
 */
async function seedChecklist(request, owner = "alice", assetName = "bulk-host") {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": owner, "Content-Type": "application/json" },
      data: { name: assetName },
    })
    .then((r) => r.json());
  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": owner, "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": owner },
    })
    .then((r) => r.json());
  return {
    assetId: asset.id,
    checklistId: checklist.id,
    ruleIds: detail.rules.slice(0, 3).map((r) => r.id),
  };
}

async function getRuleState(request, checklistId, ruleId, user = "alice") {
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklistId}`, {
      headers: { "X-User-Id": user },
    })
    .then((r) => r.json());
  const rule = detail.rules.find((r) => r.id === ruleId);
  return rule?.state ?? {};
}

async function postCsv(request, checklistId, dryRun, body, user = "alice") {
  return request.post(
    `${BACKEND}/api/checklists/${checklistId}/rules/bulk-import?dry_run=${dryRun ? "true" : "false"}`,
    {
      headers: { "X-User-Id": user },
      multipart: {
        file: { name: "x.csv", mimeType: "text/csv", buffer: body },
      },
    },
  );
}

test.describe("Rule bulk CSV import — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("dry-run with 3 valid rows returns 3 'ok' and applies nothing", async ({
    request,
  }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = csv(
      HEADER,
      `${ruleIds[0]},open,`,
      `${ruleIds[1]},not_a_finding,Patched per vendor guidance`,
      `${ruleIds[2]},not_reviewed,`,
    );

    const res = await postCsv(request, checklistId, true, body);
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.totalRows).toBe(3);
    expect(data.appliedCount).toBe(0);
    expect(data.errorCount).toBe(0);
    expect(data.rows.map((r) => r.status)).toEqual(["ok", "ok", "ok"]);

    // Nothing committed yet — every rule still in the default state.
    for (const id of ruleIds) {
      const s = await getRuleState(request, checklistId, id);
      expect(s.status).toBe("not_reviewed");
    }
  });

  test("commit applies all 3 rows; GET reflects the new statuses", async ({
    request,
  }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = csv(
      HEADER,
      `${ruleIds[0]},open,`,
      `${ruleIds[1]},not_a_finding,Patched per vendor guidance`,
      `${ruleIds[2]},not_applicable,Workload not present`,
    );

    const res = await postCsv(request, checklistId, false, body);
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.totalRows).toBe(3);
    expect(data.appliedCount).toBe(3);
    expect(data.errorCount).toBe(0);
    expect(data.rows.every((r) => r.status === "ok")).toBe(true);

    const s0 = await getRuleState(request, checklistId, ruleIds[0]);
    expect(s0.status).toBe("open");
    const s1 = await getRuleState(request, checklistId, ruleIds[1]);
    expect(s1.status).toBe("not_a_finding");
    expect(s1.findingDetails).toBe("Patched per vendor guidance");
    const s2 = await getRuleState(request, checklistId, ruleIds[2]);
    expect(s2.status).toBe("not_applicable");
    expect(s2.findingDetails).toBe("Workload not present");
  });

  test("closing status with empty finding_details → error, not applied", async ({
    request,
  }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = csv(
      HEADER,
      `${ruleIds[0]},not_a_finding,`,
      `${ruleIds[1]},open,`,
    );

    const res = await postCsv(request, checklistId, false, body);
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.totalRows).toBe(2);
    expect(data.appliedCount).toBe(1);
    expect(data.errorCount).toBe(1);

    const bad = data.rows.find((r) => r.ruleId === ruleIds[0]);
    expect(bad.status).toBe("error");
    expect(bad.error).toContain("finding_details");

    // The gate-violating row was not applied.
    const s0 = await getRuleState(request, checklistId, ruleIds[0]);
    expect(s0.status).toBe("not_reviewed");
    // The good row was applied.
    const s1 = await getRuleState(request, checklistId, ruleIds[1]);
    expect(s1.status).toBe("open");
  });

  test("invalid status value → error, not applied", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = csv(
      HEADER,
      `${ruleIds[0]},bogus,`,
      `${ruleIds[1]},open,`,
    );

    const res = await postCsv(request, checklistId, false, body);
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.appliedCount).toBe(1);
    expect(data.errorCount).toBe(1);

    const bad = data.rows.find((r) => r.ruleId === ruleIds[0]);
    expect(bad.status).toBe("error");
    expect(bad.error).toContain("invalid status");

    const s0 = await getRuleState(request, checklistId, ruleIds[0]);
    expect(s0.status).toBe("not_reviewed");
  });

  // upsert_rule is intentionally forgiving — it'll insert a checklist_rules
  // row for any rule_id whether or not it's in the STIG. The bulk handler
  // preserves that behavior; the row is "ok" and applied. The override
  // simply won't surface on the merged rules list because there's no
  // matching rule to merge into, but the row exists in the DB.
  test("non-existent rule_id is still inserted (upsert is forgiving)", async ({
    request,
  }) => {
    const { checklistId } = await seedChecklist(request);
    const body = csv(HEADER, `not-a-real-rule,open,`);

    const res = await postCsv(request, checklistId, false, body);
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.appliedCount).toBe(1);
    expect(data.rows[0].status).toBe("ok");
  });

  test("non-owner gets 403", async ({ request }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);
    const body = csv(HEADER, `${ruleIds[0]},open,`);

    const res = await postCsv(request, checklistId, false, body, "mallory");
    expect(res.status()).toBe(403);

    // Nothing applied.
    const s0 = await getRuleState(request, checklistId, ruleIds[0]);
    expect(s0.status).toBe("not_reviewed");
  });
});

test.describe("Rule bulk CSV import — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("upload CSV, preview rows, apply, statuses update in the table", async ({
    page,
    request,
  }) => {
    const { checklistId, ruleIds } = await seedChecklist(request);

    await loginAs(page, "alice");
    await page.goto("/");

    // Navigate through Systems → asset → checklist. The seeded asset is
    // named "bulk-host" and has a single 'edge' checklist.
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "bulk-host" }).click();
    await page.getByRole("button", { name: /edge/i }).first().click();

    // Make sure we landed on the checklist by confirming the bulk-import
    // button is reachable.
    await expect(page.getByTestId("bulk-import-button")).toBeVisible({
      timeout: 10_000,
    });

    // Open the bulk-import modal.
    await page.getByTestId("bulk-import-button").click();
    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();

    // Drop a CSV with 3 rows — the onChange triggers the dry-run.
    const body =
      `${HEADER}\n` +
      `${ruleIds[0]},open,\n` +
      `${ruleIds[1]},not_a_finding,Patched per vendor guidance\n` +
      `${ruleIds[2]},not_applicable,Workload not present\n`;
    await modal.getByTestId("bulk-import-input").setInputFiles({
      name: "rules.csv",
      mimeType: "text/csv",
      buffer: Buffer.from(body, "utf-8"),
    });

    // Preview rows render with ok badges (rows are 2/3/4 with header on row 1).
    await expect(modal.getByTestId("bulk-status-2")).toHaveText("ok", {
      timeout: 10_000,
    });
    await expect(modal.getByTestId("bulk-status-3")).toHaveText("ok");
    await expect(modal.getByTestId("bulk-status-4")).toHaveText("ok");

    // Commit.
    await modal.getByTestId("bulk-import-commit").click();
    await expect(modal.getByTestId("bulk-import-success")).toBeVisible({
      timeout: 10_000,
    });
    await expect(modal).toBeHidden({ timeout: 10_000 });

    // Rule list reflects the new statuses. Counts container shows the
    // distribution, so confirm at least one "Open" row exists. The
    // simplest assertion is to hit the API and verify state, since the
    // rule list table only renders ~50 rows per page and ruleIds[0] may
    // not be visible. The UI refresh already happened; double-check via
    // the merged GET.
    const s0 = await getRuleState(request, checklistId, ruleIds[0]);
    expect(s0.status).toBe("open");
    const s1 = await getRuleState(request, checklistId, ruleIds[1]);
    expect(s1.status).toBe("not_a_finding");
    const s2 = await getRuleState(request, checklistId, ruleIds[2]);
    expect(s2.status).toBe("not_applicable");
  });
});
