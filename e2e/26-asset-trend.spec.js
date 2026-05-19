import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedAssetWithSnapshots(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "trend-host" },
    })
    .then((r) => r.json());
  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());
  const ruleId = detail.rules[0].id;

  // Snapshot 1: rule open.
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "open" },
    },
  );
  await request.post(`${BACKEND}/api/test/snapshot`);

  return { assetId: asset.id, checklistId: checklist.id, ruleId };
}

test.describe("Per-asset trend", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API returns one series filtered to the asset", async ({ request }) => {
    const { assetId } = await seedAssetWithSnapshots(request);
    const d = await request
      .get(`${BACKEND}/api/assets/${assetId}/trend?days=1`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());

    expect(d.overall.length).toBeGreaterThanOrEqual(1);
    expect(d.overall[0].open).toBe(1);
    // Counts come from this asset's checklist only — total = 59 (edge STIG).
    expect(d.overall[0].total).toBe(59);
  });

  test("AssetDetail page shows the Posture-over-time container after snapshots exist", async ({
    page,
    request,
  }) => {
    await seedAssetWithSnapshots(request);

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "trend-host" }).click();

    await expect(
      page.getByRole("heading", { name: /Posture over time/i }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("Posture-over-time is hidden until a snapshot has run for the asset", async ({
    page,
    request,
  }) => {
    // Create asset but no checklist & no snapshot.
    await request.post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "no-snap-host" },
    });

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "no-snap-host" }).click();

    await expect(page.getByText("Applied STIGs")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: /Posture over time/i }),
    ).toHaveCount(0);
  });
});
