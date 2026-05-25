import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Seed: alice's asset + 'edge' checklist, returning the first rule id
 * plus a comment that alice has authored on that rule.
 */
async function seedChecklistAndComment(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "reactions-host" },
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
  const comment = await request
    .post(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}/comments`,
      {
        headers: {
          "X-User-Id": "alice",
          "Content-Type": "application/json",
        },
        data: { body: "react to me" },
      },
    )
    .then((r) => r.json());
  return {
    assetId: asset.id,
    checklistId: checklist.id,
    ruleId,
    commentId: comment.id,
  };
}

async function fetchComment(request, checklistId, ruleId, commentId, user) {
  const list = await request
    .get(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
      { headers: { "X-User-Id": user } },
    )
    .then((r) => r.json());
  return list.find((c) => c.id === commentId);
}

test.describe("Comment reactions — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("POST reaction shows count + mine per viewer", async ({ request }) => {
    const { checklistId, ruleId, commentId } =
      await seedChecklistAndComment(request);

    const post = await request.post(
      `${BACKEND}/api/comments/${commentId}/reactions`,
      {
        headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
        data: { reaction: "thumbs_up" },
      },
    );
    expect(post.status()).toBe(204);

    // alice (non-reactor) sees count 1, mine: false.
    const fromAlice = await fetchComment(
      request,
      checklistId,
      ruleId,
      commentId,
      "alice",
    );
    expect(fromAlice.reactions.thumbs_up).toEqual({ count: 1, mine: false });
    expect(fromAlice.reactions.check).toEqual({ count: 0, mine: false });
    expect(fromAlice.reactions.question).toEqual({ count: 0, mine: false });

    // bob (reactor) sees mine: true.
    const fromBob = await fetchComment(
      request,
      checklistId,
      ruleId,
      commentId,
      "bob",
    );
    expect(fromBob.reactions.thumbs_up).toEqual({ count: 1, mine: true });
  });

  test("POST same reaction twice is idempotent", async ({ request }) => {
    const { checklistId, ruleId, commentId } =
      await seedChecklistAndComment(request);

    for (let i = 0; i < 2; i++) {
      const res = await request.post(
        `${BACKEND}/api/comments/${commentId}/reactions`,
        {
          headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
          data: { reaction: "check" },
        },
      );
      expect(res.status()).toBe(204);
    }

    const c = await fetchComment(
      request,
      checklistId,
      ruleId,
      commentId,
      "bob",
    );
    expect(c.reactions.check).toEqual({ count: 1, mine: true });
  });

  test("DELETE removes the caller's reaction", async ({ request }) => {
    const { checklistId, ruleId, commentId } =
      await seedChecklistAndComment(request);

    await request.post(`${BACKEND}/api/comments/${commentId}/reactions`, {
      headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
      data: { reaction: "question" },
    });

    const del = await request.delete(
      `${BACKEND}/api/comments/${commentId}/reactions/question`,
      { headers: { "X-User-Id": "bob" } },
    );
    expect(del.status()).toBe(204);

    const after = await fetchComment(
      request,
      checklistId,
      ruleId,
      commentId,
      "bob",
    );
    expect(after.reactions.question).toEqual({ count: 0, mine: false });

    // DELETE again should still be 204 (idempotent).
    const del2 = await request.delete(
      `${BACKEND}/api/comments/${commentId}/reactions/question`,
      { headers: { "X-User-Id": "bob" } },
    );
    expect(del2.status()).toBe(204);
  });

  test("invalid reaction type returns 400", async ({ request }) => {
    const { commentId } = await seedChecklistAndComment(request);

    const res = await request.post(
      `${BACKEND}/api/comments/${commentId}/reactions`,
      {
        headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
        data: { reaction: "fire" },
      },
    );
    expect(res.status()).toBe(400);

    // Same for DELETE.
    const del = await request.delete(
      `${BACKEND}/api/comments/${commentId}/reactions/fire`,
      { headers: { "X-User-Id": "bob" } },
    );
    expect(del.status()).toBe(400);
  });

  test("deleting the parent comment cascades to its reactions", async ({
    request,
  }) => {
    const { checklistId, ruleId, commentId } =
      await seedChecklistAndComment(request);

    // Two distinct reactors, two reaction types so the row count is > 1.
    await request.post(`${BACKEND}/api/comments/${commentId}/reactions`, {
      headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
      data: { reaction: "thumbs_up" },
    });
    await request.post(`${BACKEND}/api/comments/${commentId}/reactions`, {
      headers: { "X-User-Id": "carol", "Content-Type": "application/json" },
      data: { reaction: "check" },
    });

    // Owner (alice) deletes the comment.
    const del = await request.delete(`${BACKEND}/api/comments/${commentId}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(del.status()).toBe(204);

    // Listing the rule's comments shows the comment is gone.
    const list = await request
      .get(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        { headers: { "X-User-Id": "alice" } },
      )
      .then((r) => r.json());
    expect(list.find((c) => c.id === commentId)).toBeUndefined();

    // Re-create a comment with the same body and verify it starts with
    // zero counts (i.e. nothing leaked through). Use a fresh comment id.
    const fresh = await request
      .post(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        {
          headers: {
            "X-User-Id": "alice",
            "Content-Type": "application/json",
          },
          data: { body: "fresh comment" },
        },
      )
      .then((r) => r.json());
    const freshRow = await fetchComment(
      request,
      checklistId,
      ruleId,
      fresh.id,
      "alice",
    );
    expect(freshRow.reactions.thumbs_up.count).toBe(0);
    expect(freshRow.reactions.check.count).toBe(0);
    expect(freshRow.reactions.question.count).toBe(0);
  });
});

test.describe("Comment reactions — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("clicking the thumbs-up button toggles count and pressed state", async ({
    page,
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklistAndComment(request);

    await loginAs(page, "alice");
    await page.goto(`/?checklist=${checklistId}`);

    // Navigate to the checklist via the systems list.
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "reactions-host" }).click();
    await page.getByRole("button", { name: /edge/i }).first().click();

    // Open the rule editor.
    await page.getByRole("button", { name: ruleId }).first().click();

    // Existing comment is rendered.
    await expect(page.getByText("react to me")).toBeVisible({
      timeout: 10_000,
    });

    const thumbsBtn = page
      .getByTestId("rule-comment-reaction-thumbs_up")
      .first();
    await expect(thumbsBtn).toBeVisible();
    // Initial count is 0.
    await expect(thumbsBtn).toContainText("0");

    // Click → POST reaction. Count flips to 1.
    await thumbsBtn.click();
    await expect(
      page.getByTestId("rule-comment-reaction-thumbs_up").first(),
    ).toContainText("1", { timeout: 10_000 });

    // Click again → DELETE reaction. Count flips back to 0.
    await page.getByTestId("rule-comment-reaction-thumbs_up").first().click();
    await expect(
      page.getByTestId("rule-comment-reaction-thumbs_up").first(),
    ).toContainText("0", { timeout: 10_000 });
  });
});
