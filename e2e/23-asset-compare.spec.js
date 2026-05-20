import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedTwoEdgeAssets(request) {
  const a1 = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "cmp-a" },
    })
    .then((r) => r.json());
  const c1 = await request
    .post(`${BACKEND}/api/assets/${a1.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${c1.id}`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());
  const r1 = detail.rules[0].id;
  const r2 = detail.rules[1].id;

  // left: r1=Open, r2=NaF
  await request.patch(
    `${BACKEND}/api/checklists/${c1.id}/rules/${encodeURIComponent(r1)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "open" },
    },
  );
  await request.patch(
    `${BACKEND}/api/checklists/${c1.id}/rules/${encodeURIComponent(r2)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "not_a_finding", findingDetails: "test justification" },
    },
  );

  const a2 = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "cmp-b" },
    })
    .then((r) => r.json());
  const c2 = await request
    .post(`${BACKEND}/api/assets/${a2.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    })
    .then((r) => r.json());

  // right: r1=NaF, r2=NaF (so r1 diverges, r2 matches)
  await request.patch(
    `${BACKEND}/api/checklists/${c2.id}/rules/${encodeURIComponent(r1)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "not_a_finding", findingDetails: "test justification" },
    },
  );
  await request.patch(
    `${BACKEND}/api/checklists/${c2.id}/rules/${encodeURIComponent(r2)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "not_a_finding", findingDetails: "test justification" },
    },
  );

  return { leftId: a1.id, rightId: a2.id, divergedRuleId: r1 };
}

test.describe("Compare two assets", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API returns diverged rules only", async ({ request }) => {
    const { leftId, rightId, divergedRuleId } = await seedTwoEdgeAssets(request);
    const d = await request
      .get(`${BACKEND}/api/assets/${leftId}/diff/${rightId}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());

    expect(d.shared.length).toBe(1);
    expect(d.shared[0].diverged.length).toBe(1);
    expect(d.shared[0].diverged[0].ruleId).toBe(divergedRuleId);
    expect(d.shared[0].diverged[0].leftStatus).toBe("open");
    expect(d.shared[0].diverged[0].rightStatus).toBe("not_a_finding");
  });

  test("UI: Compare button opens the view; picking 2 systems shows the diff", async ({
    page,
    request,
  }) => {
    const { divergedRuleId } = await seedTwoEdgeAssets(request);

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();

    await page.getByRole("button", { name: "Compare", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: /Compare systems/i }),
    ).toBeVisible();

    // Two "Choose a system" buttons (the Select triggers). Click the first
    // and pick cmp-a, then the now-only-remaining one and pick cmp-b.
    await page
      .getByRole("button", { name: /choose a system/i })
      .first()
      .click();
    await page.getByRole("option", { name: "cmp-a" }).click();
    await page
      .getByRole("button", { name: /choose a system/i })
      .first()
      .click();
    await page.getByRole("option", { name: "cmp-b" }).click();

    // Diverged rule id appears
    await expect(page.getByText(divergedRuleId).first()).toBeVisible({
      timeout: 10_000,
    });
  });
});
