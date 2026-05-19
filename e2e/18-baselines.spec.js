import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedAssetWithTwoRules(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "bl-host" },
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
  return {
    checklistId: checklist.id,
    rule1: detail.rules[0].id,
    rule2: detail.rules[1].id,
  };
}

async function patch(request, checklistId, ruleId, body) {
  await request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: body,
    },
  );
}

test.describe("Compliance baselines", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("save baseline then flip two rules → regressed + improved appear", async ({
    page,
    request,
  }) => {
    const { checklistId, rule1, rule2 } = await seedAssetWithTwoRules(request);
    await patch(request, checklistId, rule1, { status: "not_a_finding" });
    await patch(request, checklistId, rule2, { status: "open" });

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    // Save baseline
    await page.getByRole("button", { name: "Save baseline" }).click();
    const modal = page.getByRole("dialog");
    await modal.getByRole("textbox").first().fill("Q1 baseline");
    await modal.getByRole("button", { name: "Save", exact: true }).click();
    await expect(modal).toBeHidden({ timeout: 10_000 });

    // The "Changes since baseline" container should render with 0 changes.
    await expect(
      page.getByRole("heading", { name: /Changes since baseline/i }),
    ).toBeVisible();
    await expect(page.getByText(/0 regressed/i)).toBeVisible();

    // Now flip both rules → 1 regressed + 1 improved.
    await patch(request, checklistId, rule1, { status: "open" });
    await patch(request, checklistId, rule2, { status: "not_a_finding" });
    await page.getByRole("button", { name: "Refresh" }).click();

    // Reselect the baseline to retrigger the diff fetch.
    // (After Refresh the dashboard refetches; the baseline picker preserves
    // the selection, and the diff useEffect refetches on selection change.
    // To force a re-pull, click into the picker again — but simplest path:
    // wait for the description text to update.)
    await expect(page.getByText(/1 regressed/i)).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByText(/1 improved/i)).toBeVisible();
  });

  test("non-owner cannot delete a baseline (button disabled)", async ({
    page,
    request,
  }) => {
    const { checklistId, rule1 } = await seedAssetWithTwoRules(request);
    await patch(request, checklistId, rule1, { status: "not_a_finding" });

    // Alice creates the baseline.
    await request.post(`${BACKEND}/api/baselines`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "Alice's baseline" },
    });

    // Bob views the dashboard.
    await page.context().clearCookies();
    await loginAs(page, "bob");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();

    await expect(
      page.getByRole("heading", { name: /Changes since baseline/i }),
    ).toBeVisible();
    // Delete button rendered but disabled for non-creator.
    const delBtn = page.getByRole("button", { name: "Delete", exact: true });
    await expect(delBtn).toBeDisabled();
  });
});
