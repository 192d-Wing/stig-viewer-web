import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

function yesterday() {
  const d = new Date(Date.now() - 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 10);
}

async function patch(request, checklistId, ruleId, body) {
  const closing =
    body.status === "not_a_finding" || body.status === "not_applicable";
  const data =
    closing && !body.findingDetails
      ? { ...body, findingDetails: "auto-justified for test" }
      : body;
  const res = await request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data,
    },
  );
  expect(res.ok()).toBeTruthy();
}

async function seedAssetWithRule(request, name = "diff-host") {
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
  const detail = await (
    await request.get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": "alice" },
    })
  ).json();
  return {
    assetId: asset.id,
    checklistId: checklist.id,
    ruleId: detail.rules[0].id,
  };
}

test.describe("Rule-level diff snapshots", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: empty window returns no rules", async ({ request }) => {
    await seedAssetWithRule(request);
    const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000)
      .toISOString()
      .slice(0, 10);
    const res = await request.get(
      `${BACKEND}/api/diff?since=${tomorrow}`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.rules).toHaveLength(0);
  });

  test("API: single PATCH shows up as one rule with one status change", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedAssetWithRule(request);
    await patch(request, checklistId, ruleId, { status: "open" });

    const body = await (
      await request.get(`${BACKEND}/api/diff?since=${yesterday()}`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();

    expect(body.rules).toHaveLength(1);
    const r = body.rules[0];
    expect(r.ruleId).toBe(ruleId);
    const statusChange = r.changes.find((c) => c.field === "status");
    expect(statusChange.from).toBe("not_reviewed");
    expect(statusChange.to).toBe("open");
    expect(statusChange.by).toBe("alice");
  });

  test("API: two sequential PATCHes collapse to one entry with first→latest", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedAssetWithRule(request);
    await patch(request, checklistId, ruleId, { status: "open" });
    await patch(request, checklistId, ruleId, { status: "not_a_finding" });

    const body = await (
      await request.get(`${BACKEND}/api/diff?since=${yesterday()}`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();

    expect(body.rules).toHaveLength(1);
    const statusChange = body.rules[0].changes.find(
      (c) => c.field === "status",
    );
    expect(statusChange.from).toBe("not_reviewed");
    expect(statusChange.to).toBe("not_a_finding");
  });

  test("API: assetId filter scopes the result set", async ({ request }) => {
    const left = await seedAssetWithRule(request, "diff-left");
    const right = await seedAssetWithRule(request, "diff-right");
    await patch(request, left.checklistId, left.ruleId, { status: "open" });
    await patch(request, right.checklistId, right.ruleId, { status: "open" });

    const all = await (
      await request.get(`${BACKEND}/api/diff?since=${yesterday()}`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(all.rules).toHaveLength(2);

    const onlyLeft = await (
      await request.get(
        `${BACKEND}/api/diff?since=${yesterday()}&assetId=${left.assetId}`,
        { headers: { "X-User-Id": "alice" } },
      )
    ).json();
    expect(onlyLeft.rules).toHaveLength(1);
    expect(onlyLeft.rules[0].assetName).toBe("diff-left");
  });

  test("API: missing since returns 400", async ({ request }) => {
    const res = await request.get(`${BACKEND}/api/diff`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(400);
  });

  test("UI: dashboard renders the Changes-since section and shows a change", async ({
    page,
    request,
  }) => {
    const { checklistId, ruleId } = await seedAssetWithRule(request);
    await patch(request, checklistId, ruleId, { status: "open" });

    await loginAs(page, "alice");
    await page.goto("/?view=dashboard");

    await expect(
      page.getByRole("heading", { name: /Changes since/i }),
    ).toBeVisible();
    // The rule id should appear in the diff table.
    await expect(page.getByText(ruleId).first()).toBeVisible({
      timeout: 10_000,
    });
  });
});
