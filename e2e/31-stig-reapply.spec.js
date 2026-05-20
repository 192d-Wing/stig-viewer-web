import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function bumpStig(request, stigId, version, releaseInfo) {
  const r = await request.post(`${BACKEND}/api/test/bump-stig`, {
    headers: { "Content-Type": "application/json" },
    data: { stig_id: stigId, version, release_info: releaseInfo },
  });
  if (r.status() !== 204) throw new Error(`bumpStig failed: ${r.status()}`);
}

async function seedDriftedChecklist(request) {
  await bumpStig(request, "edge", "1", "01 Jan 2026");
  const asset = await (
    await request.post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "reapply-host" },
    })
  ).json();
  const checklist = await (
    await request.post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
  ).json();
  // Touch one rule so we can verify the override is preserved.
  const detail = await (
    await request.get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": "alice" },
    })
  ).json();
  const firstRuleId = detail.rules[0].id;
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(firstRuleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "not_a_finding" },
    },
  );
  await bumpStig(request, "edge", "99", "99 Dec 2099");
  return { asset, checklist, firstRuleId };
}

test.describe("Re-apply STIG", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: reapply clears outdated flag and preserves rule overrides", async ({
    request,
  }) => {
    const { checklist, firstRuleId } = await seedDriftedChecklist(request);

    let dash = await (
      await request.get(`${BACKEND}/api/dashboard`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(dash.totals.outdatedChecklists).toBe(1);

    const re = await request.post(
      `${BACKEND}/api/checklists/${checklist.id}/reapply`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(re.ok()).toBeTruthy();
    const body = await re.json();
    expect(body.checklist.appliedVersion).toBe("99");
    expect(body.checklist.appliedRelease).toBe("99 Dec 2099");

    dash = await (
      await request.get(`${BACKEND}/api/dashboard`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(dash.totals.outdatedChecklists).toBe(0);

    // The rule override survives the re-apply (bump-stig doesn't touch the
    // STIG JSON file so the rule_id still exists in the new revision).
    const detail = await (
      await request.get(`${BACKEND}/api/checklists/${checklist.id}`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    const updated = detail.rules.find((r) => r.id === firstRuleId);
    expect(updated.state.status).toBe("not_a_finding");
  });

  test("API: re-apply is owner-only (403 for other user)", async ({
    request,
  }) => {
    const { checklist } = await seedDriftedChecklist(request);
    const res = await request.post(
      `${BACKEND}/api/checklists/${checklist.id}/reapply`,
      { headers: { "X-User-Id": "bob" } },
    );
    expect(res.status()).toBe(403);
  });

  test("UI: Re-apply button on an outdated row clears the badge", async ({
    page,
    request,
  }) => {
    const { asset } = await seedDriftedChecklist(request);

    await loginAs(page, "alice");
    await page.goto("/?view=systems");
    await page.getByRole("button", { name: asset.name }).click();
    await expect(page.getByText("Applied STIGs")).toBeVisible();

    // Click Re-apply on the outdated row.
    await page
      .getByRole("button", { name: "Re-apply", exact: true })
      .first()
      .click();
    // Confirm in the modal.
    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();
    await expect(modal.getByText(/v1.*99/)).toBeVisible();
    await modal
      .getByRole("button", { name: "Re-apply", exact: true })
      .click();

    // Badge disappears.
    await expect(modal).toBeHidden();
    await expect(page.getByText("Out of date", { exact: true })).toHaveCount(0);
  });
});
