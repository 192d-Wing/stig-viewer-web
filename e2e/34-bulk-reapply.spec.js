import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function bumpStig(request, stigId, version, releaseInfo) {
  const r = await request.post(`${BACKEND}/api/test/bump-stig`, {
    headers: { "Content-Type": "application/json" },
    data: { stig_id: stigId, version, release_info: releaseInfo },
  });
  if (r.status() !== 204) throw new Error(`bumpStig failed: ${r.status()}`);
}

async function createAsset(request, userName, name) {
  const res = await request.post(`${BACKEND}/api/assets`, {
    headers: { "X-User-Id": userName, "Content-Type": "application/json" },
    data: { name },
  });
  if (!res.ok()) throw new Error(`createAsset failed: ${res.status()}`);
  return res.json();
}

async function applyChecklist(request, userName, assetId, stigId) {
  const res = await request.post(
    `${BACKEND}/api/assets/${assetId}/checklists`,
    {
      headers: { "X-User-Id": userName, "Content-Type": "application/json" },
      data: { stigId },
    },
  );
  if (!res.ok()) throw new Error(`applyChecklist failed: ${res.status()}`);
  return res.json();
}

async function fetchDashboard(request, userName) {
  const res = await request.get(`${BACKEND}/api/dashboard`, {
    headers: { "X-User-Id": userName },
  });
  if (!res.ok()) throw new Error(`dashboard failed: ${res.status()}`);
  return res.json();
}

/**
 * Seed two outdated checklists owned by `alice` against two different
 * STIGs so we can verify the batch path. Returns the asset/checklist
 * pairs.
 */
async function seedTwoDrifted(request) {
  // Establish baseline catalog rows for both STIGs.
  await bumpStig(request, "edge", "1", "01 Jan 2026");
  await bumpStig(request, "rhel-9", "1", "01 Jan 2026");

  const assetA = await createAsset(request, "alice", "fleet-host-a");
  const checklistA = await applyChecklist(request, "alice", assetA.id, "edge");

  const assetB = await createAsset(request, "alice", "fleet-host-b");
  const checklistB = await applyChecklist(
    request,
    "alice",
    assetB.id,
    "rhel-9",
  );

  // Bump both so the checklists drift.
  await bumpStig(request, "edge", "99", "99 Dec 2099");
  await bumpStig(request, "rhel-9", "99", "99 Dec 2099");

  return { assetA, assetB, checklistA, checklistB };
}

test.describe("Bulk re-apply STIG", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: bulk-reapply clears outdatedChecklists for the caller", async ({
    request,
  }) => {
    await seedTwoDrifted(request);

    const before = await fetchDashboard(request, "alice");
    expect(before.totals.outdatedChecklists).toBe(2);

    const res = await request.post(`${BACKEND}/api/checklists/bulk-reapply`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.results).toHaveLength(2);
    for (const row of body.results) {
      expect(row.status).toBe("reapplied");
      expect(row.toVersion).toBe("99");
    }

    const after = await fetchDashboard(request, "alice");
    expect(after.totals.outdatedChecklists).toBe(0);
  });

  test("API: only the caller's owned checklists are re-applied", async ({
    request,
  }) => {
    // Alice has one drifted checklist on `edge`. Bob also has one on
    // `rhel-9`. Alice's bulk-reapply must not touch Bob's row.
    await bumpStig(request, "edge", "1", "01 Jan 2026");
    await bumpStig(request, "rhel-9", "1", "01 Jan 2026");

    const aliceAsset = await createAsset(request, "alice", "alice-host");
    await applyChecklist(request, "alice", aliceAsset.id, "edge");

    const bobAsset = await createAsset(request, "bob", "bob-host");
    await applyChecklist(request, "bob", bobAsset.id, "rhel-9");

    await bumpStig(request, "edge", "99", "99 Dec 2099");
    await bumpStig(request, "rhel-9", "99", "99 Dec 2099");

    // Global drift before: 2 outdated checklists.
    const globalBefore = await fetchDashboard(request, "alice");
    expect(globalBefore.totals.outdatedChecklists).toBe(2);

    const res = await request.post(`${BACKEND}/api/checklists/bulk-reapply`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.results).toHaveLength(1);
    expect(body.results[0].assetName).toBe("alice-host");
    expect(body.results[0].status).toBe("reapplied");

    // Bob's row is still outdated (dashboard is global, so still reports 1).
    const after = await fetchDashboard(request, "alice");
    expect(after.totals.outdatedChecklists).toBe(1);

    // Bob's own checklist remains outdated.
    const bobView = await fetchDashboard(request, "bob");
    const bobChecklists = bobView.byAsset
      .find((a) => a.name === "bob-host")
      ?.checklists ?? [];
    expect(bobChecklists.some((c) => c.outdated)).toBe(true);
  });

  test("UI: Re-apply all button confirms, runs, and flips the KPI", async ({
    page,
    request,
  }) => {
    await seedTwoDrifted(request);

    await loginAs(page, "alice");
    await page.goto("/?view=dashboard");

    // Header button shows the outdated count.
    const headerBtn = page.getByRole("button", { name: /Re-apply all \(2\)/ });
    await expect(headerBtn).toBeVisible();
    await headerBtn.click();

    // Confirmation modal mentions the count.
    const confirmModal = page.getByRole("dialog");
    await expect(confirmModal).toBeVisible();
    await expect(confirmModal.getByText(/2 checklists/)).toBeVisible();

    await page.getByTestId("bulk-reapply-confirm").click();

    // Results modal renders the per-row table.
    const resultsModal = page.getByRole("dialog");
    await expect(
      resultsModal.getByText(/Re-apply complete — 2 checklists/),
    ).toBeVisible();
    await expect(resultsModal.getByText("fleet-host-a")).toBeVisible();
    await expect(resultsModal.getByText("fleet-host-b")).toBeVisible();
    // Both rows show a `reapplied` status badge.
    await expect(resultsModal.getByText("reapplied")).toHaveCount(2);

    // Close — KPI tile now reads "all up to date".
    await resultsModal.getByRole("button", { name: "Close" }).click();
    await expect(
      page.getByText("all up to date", { exact: true }),
    ).toBeVisible();
  });
});
