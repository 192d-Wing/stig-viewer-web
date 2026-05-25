import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Seed an asset + 'edge' checklist owned by alice and return ids needed
 * by the per-test assertions. Mirrors the pattern used by other rule
 * specs (47-rule-comments, 48-rule-bulk-import) so the suite stays
 * uniform.
 */
async function seedChecklist(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "cci-host" },
    })
    .then((r) => r.json());
  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
    .then((r) => r.json());
  return {
    assetId: asset.id,
    checklistId: checklist.id,
  };
}

test.describe("Per-rule CCI tag display — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("checklist rules carry a populated cci array on the first row", async ({
    request,
  }) => {
    const { checklistId } = await seedChecklist(request);

    const detail = await request
      .get(`${BACKEND}/api/checklists/${checklistId}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());

    expect(Array.isArray(detail.rules)).toBe(true);
    expect(detail.rules.length).toBeGreaterThan(0);

    const first = detail.rules[0];
    // The edge.json fixture has CCIs only on the first two rules; the
    // shape contract is "always present as an array, populated for at
    // least the first row of this seeded STIG".
    expect(Array.isArray(first.cci)).toBe(true);
    expect(first.cci.length).toBeGreaterThanOrEqual(1);
    // CCI identifiers always start with the literal "CCI-" prefix —
    // assert that to catch accidental control-id substitutions.
    for (const id of first.cci) {
      expect(id).toMatch(/^CCI-/);
    }
  });

  test("every rule exposes cci as an array (never undefined or null)", async ({
    request,
  }) => {
    const { checklistId } = await seedChecklist(request);

    const detail = await request
      .get(`${BACKEND}/api/checklists/${checklistId}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());

    // Real STIG rules almost always carry at least one CCI — the
    // contract here is purely about shape: `cci` is always an array,
    // never missing/null. Earlier drafts narrowed edge.json's seed to
    // a partial set, but real-world STIGs don't have empty-CCI rules.
    expect(detail.rules.length).toBeGreaterThan(0);
    for (const r of detail.rules) {
      expect(r.cci).not.toBeUndefined();
      expect(r.cci).not.toBeNull();
      expect(Array.isArray(r.cci)).toBe(true);
    }
  });
});

test.describe("Per-rule CCI tag display — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("CCI column header appears and the first row shows CCI- badges", async ({
    page,
    request,
  }) => {
    await seedChecklist(request);

    await loginAs(page, "alice");
    await page.goto("/");

    // Navigate via systems list → asset → checklist, same path used by
    // the other UI specs in this suite.
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "cci-host" }).click();
    await page.getByRole("button", { name: /edge/i }).first().click();

    // Column header — accessible-name lookup avoids positional selectors
    // per project memory.
    await expect(
      page.getByRole("columnheader", { name: "CCI" }),
    ).toBeVisible();

    // First populated cell. The cell is wrapped in a data-testid span
    // so we can target it without depending on table row indices.
    const firstCell = page.getByTestId("rule-cci-cell").first();
    await expect(firstCell).toBeVisible();
    await expect(firstCell).toContainText("CCI-");
  });
});
