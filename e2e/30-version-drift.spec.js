import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function bumpStig(request, stigId, version, releaseInfo) {
  const res = await request.post(`${BACKEND}/api/test/bump-stig`, {
    headers: { "Content-Type": "application/json" },
    data: { stig_id: stigId, version, release_info: releaseInfo },
  });
  if (res.status() !== 204) {
    throw new Error(`bumpStig failed: ${res.status()}`);
  }
}

async function seedAssetWithChecklist(request, name = "drift-host") {
  // Set a known baseline catalog version BEFORE seeding so we capture a
  // non-empty applied_version. Tests can then bump to a different value
  // to trigger drift. Without this, leftover catalog state from prior
  // runs makes the test non-hermetic.
  await bumpStig(request, "edge", "1", "01 Jan 2026");

  const asset = await (
    await request.post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name },
    })
  ).json();
  const checklist = await (
    await request.post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
  ).json();
  return { asset, checklist };
}

test.describe("STIG version drift", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: dashboard reports 0 outdated before bump, 1 after", async ({
    request,
  }) => {
    await seedAssetWithChecklist(request);

    const before = await (
      await request.get(`${BACKEND}/api/dashboard`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(before.totals.outdatedChecklists).toBe(0);
    expect(before.byAsset[0].checklists[0].outdated).toBe(false);

    await bumpStig(request, "edge", "99", "99 Dec 2099");

    const after = await (
      await request.get(`${BACKEND}/api/dashboard`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(after.totals.outdatedChecklists).toBe(1);
    expect(after.byAsset[0].checklists[0].outdated).toBe(true);
  });

  test("API: bumping a different STIG does NOT flag the checklist", async ({
    request,
  }) => {
    await seedAssetWithChecklist(request);
    await bumpStig(request, "windows-11", "99", "99 Dec 2099");
    const d = await (
      await request.get(`${BACKEND}/api/dashboard`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(d.totals.outdatedChecklists).toBe(0);
  });

  test('Dashboard shows "STIG updates" KPI and tile flips on bump', async ({
    page,
    request,
  }) => {
    await seedAssetWithChecklist(request);
    await loginAs(page, "alice");
    await page.goto("/?view=dashboard");

    // KPI is visible with 0 initially.
    await expect(page.getByText("STIG updates", { exact: true })).toBeVisible();
    await expect(
      page.getByText("all up to date", { exact: true }),
    ).toBeVisible();

    // Bump the catalog and refresh.
    await bumpStig(request, "edge", "99", "99 Dec 2099");
    await page.getByRole("button", { name: /refresh/i }).click();

    await expect(
      page.getByText("checklists out of date", { exact: true }),
    ).toBeVisible();
    // The per-system table now shows an "Out of date" badge for the row.
    await expect(
      page.getByText("Out of date", { exact: true }).first(),
    ).toBeVisible();
  });

  test("AssetDetail also shows the badge once the catalog bumps", async ({
    page,
    request,
  }) => {
    const { asset } = await seedAssetWithChecklist(request, "tagged-host");
    await bumpStig(request, "edge", "99", "99 Dec 2099");

    await loginAs(page, "alice");
    await page.goto("/?view=systems");
    await page.getByRole("button", { name: asset.name }).click();
    await expect(page.getByText("Applied STIGs")).toBeVisible();
    await expect(
      page.getByText("Out of date", { exact: true }).first(),
    ).toBeVisible();
  });
});
