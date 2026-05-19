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
  return { checklistId: checklist.id, ruleIds };
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
});
