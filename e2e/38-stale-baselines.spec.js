import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedAssetWithRule(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "stale-bl-host" },
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
  return { checklistId: checklist.id, ruleId: detail.rules[0].id };
}

async function createBaseline(request, name) {
  const res = await request.post(`${BACKEND}/api/baselines`, {
    headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
    data: { name },
  });
  return res.json();
}

async function backdateBaseline(request, baselineId, days) {
  const res = await request.post(`${BACKEND}/api/test/backdate-baseline`, {
    headers: { "Content-Type": "application/json" },
    data: { baseline_id: baselineId, days },
  });
  if (!res.ok() && res.status() !== 204) {
    throw new Error(`backdate-baseline failed: ${res.status()}`);
  }
}

test.describe("Stale baseline reminders", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("fresh baseline is not stale; backdated baseline is stale (API)", async ({
    request,
  }) => {
    // Seed an asset/rule so baseline capture has something to snapshot.
    await seedAssetWithRule(request);
    const baseline = await createBaseline(request, "Fresh baseline");

    // List endpoint reports fresh baseline as not stale.
    let list = await request
      .get(`${BACKEND}/api/baselines`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(list).toHaveLength(1);
    expect(list[0].isStale).toBe(false);

    // Dashboard reports 0 stale baselines and default 90d threshold.
    let dash = await request
      .get(`${BACKEND}/api/dashboard`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(dash.totals.staleBaselines).toBe(0);
    expect(dash.totals.staleBaselineDays).toBe(90);

    // Backdate 200 days → now stale.
    await backdateBaseline(request, baseline.id, 200);

    list = await request
      .get(`${BACKEND}/api/baselines`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(list[0].isStale).toBe(true);

    dash = await request
      .get(`${BACKEND}/api/dashboard`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(dash.totals.staleBaselines).toBe(1);
  });

  test("dashboard shows Stale baselines KPI after backdating", async ({
    page,
    request,
  }) => {
    await seedAssetWithRule(request);
    const baseline = await createBaseline(request, "Aging baseline");
    await backdateBaseline(request, baseline.id, 200);

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // KPI label is "Stale baselines".
    await expect(page.getByText("Stale baselines").first()).toBeVisible({
      timeout: 10_000,
    });

    // The KPI sub-label echoes the threshold in days.
    await expect(page.getByText(">90d").first()).toBeVisible();

    // The selected baseline triggers the stale warning Alert.
    await expect(
      page.getByRole("heading", { name: /Stale baseline/i }).first(),
    ).toBeVisible({ timeout: 10_000 });
  });
});
