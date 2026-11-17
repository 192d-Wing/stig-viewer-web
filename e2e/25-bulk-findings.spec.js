import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedThreeOpenFindings(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "bulk-host" },
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

  const ruleIds = [];
  for (let i = 0; i < 3; i++) {
    ruleIds.push(detail.rules[i].id);
    await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(detail.rules[i].id)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open" },
      },
    );
  }
  return { assetId: asset.id, checklistId: checklist.id, ruleIds };
}

test.describe("Bulk operations on findings", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: PATCH /api/findings/bulk applies one patch to many targets", async ({
    request,
  }) => {
    const { checklistId, ruleIds } = await seedThreeOpenFindings(request);

    const res = await request.patch(`${BACKEND}/api/findings/bulk`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        targets: ruleIds.map((rid) => ({
          checklistId,
          ruleId: rid,
        })),
        patch: {
          status: "not_a_finding",
          findingDetails: "closed by smoke test",
        },
      },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.updated).toBe(3);
    expect(body.pendingApproval).toBe(0);
    expect(body.alreadyPending).toBe(0);

    // All three findings are now not_a_finding.
    const naf = await request
      .get(`${BACKEND}/api/findings?status=not_a_finding`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(naf.length).toBe(3);
    expect(naf.every((f) => f.findingDetails === "closed by smoke test")).toBe(
      true,
    );
  });

  test("API: cross-user bulk PATCH is 403", async ({ request }) => {
    const { checklistId, ruleIds } = await seedThreeOpenFindings(request);
    const res = await request.patch(`${BACKEND}/api/findings/bulk`, {
      headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
      data: {
        targets: [{ checklistId, ruleId: ruleIds[0] }],
        patch: { status: "not_a_finding" },
      },
    });
    expect(res.status()).toBe(403);
  });

  test("API: on an approval asset closing is queued, not applied", async ({
    request,
  }) => {
    const { assetId, checklistId, ruleIds } =
      await seedThreeOpenFindings(request);
    const policy = await request.patch(
      `${BACKEND}/api/assets/${assetId}/approval-policy`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { requiresApproval: true },
      },
    );
    expect(policy.status()).toBe(200);

    const res = await request.patch(`${BACKEND}/api/findings/bulk`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        targets: ruleIds.map((ruleId) => ({ checklistId, ruleId })),
        patch: {
          status: "not_a_finding",
          findingDetails: "closed by smoke test",
          comments: "queued note",
        },
      },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.updated).toBe(0);
    expect(body.pendingApproval).toBe(3);

    const open = await request
      .get(`${BACKEND}/api/findings?status=open`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(open.length).toBe(3);
    expect(open.every((f) => f.comments === "queued note")).toBe(true);
  });

  test("API: closing without finding details is a per-target error", async ({
    request,
  }) => {
    const { checklistId, ruleIds } = await seedThreeOpenFindings(request);
    const res = await request.patch(`${BACKEND}/api/findings/bulk`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        targets: [{ checklistId, ruleId: ruleIds[0] }],
        patch: { status: "not_a_finding" },
      },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.updated).toBe(0);
    expect(body.errorCount).toBe(1);
    expect(body.errors[0].ruleId).toBe(ruleIds[0]);
  });

  test("API: an ACL write-holder may bulk update", async ({ request }) => {
    const { assetId, checklistId, ruleIds } =
      await seedThreeOpenFindings(request);
    const bobId = (
      await request
        .get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "bob" } })
        .then((r) => r.json())
    ).id;
    const grant = await request.post(`${BACKEND}/api/assets/${assetId}/acl`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { userId: bobId, permission: "write" },
    });
    expect(grant.status()).toBe(201);
    const res = await request.patch(`${BACKEND}/api/findings/bulk`, {
      headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
      data: {
        targets: [{ checklistId, ruleId: ruleIds[0] }],
        patch: { comments: "by bob" },
      },
    });
    expect(res.status()).toBe(200);
    expect((await res.json()).updated).toBe(1);
  });

  test("API: empty targets rejected with 400", async ({ request }) => {
    const res = await request.patch(`${BACKEND}/api/findings/bulk`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        targets: [],
        patch: { status: "open" },
      },
    });
    expect(res.status()).toBe(400);
  });

  test("UI: drill-down exposes a Bulk update button (disabled with no selection)", async ({
    page,
    request,
  }) => {
    await seedThreeOpenFindings(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: /view details/i }).click();

    // Wait for the drill-down counter to show (3)
    await expect(page.getByText("(3)").last()).toBeVisible({
      timeout: 10_000,
    });

    // Bulk update button is rendered and starts disabled — selection
    // semantics with Cloudscape's checkbox role tangle with the
    // Mine-only Toggle so we cover the actual bulk PATCH flow in the
    // backend tests above. Here we just confirm the wiring is in place.
    const bulkBtn = page.getByRole("button", { name: /^Bulk update$/ });
    await expect(bulkBtn).toBeVisible();
    await expect(bulkBtn).toBeDisabled();
  });

  test("UI: bulk update shows a result flash", async ({ page, request }) => {
    await seedThreeOpenFindings(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: /view details/i }).click();
    const drilldown = page.getByRole("table", { name: /open findings/i });
    await expect(drilldown).toBeVisible({ timeout: 10_000 });
    await drilldown.locator('input[type="checkbox"]').first().check();
    await page.getByRole("button", { name: /^Bulk update/ }).click();
    const modal = page.getByRole("dialog");
    await modal.getByLabel("Comments").fill("from the UI");
    await modal.getByRole("button", { name: "Apply" }).click();
    await expect(page.getByTestId("bulk-update-flash")).toContainText(
      "3 updated",
      { timeout: 10_000 },
    );
  });
});
