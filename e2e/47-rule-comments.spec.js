import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Seed: alice's asset + 'edge' checklist, returning the first rule id.
 */
async function seedChecklist(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "comments-host" },
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
    assetId: asset.id,
    checklistId: checklist.id,
    ruleId: detail.rules[0].id,
  };
}

test.describe("Per-rule comments — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("POST creates a comment with userName; GET lists newest-first", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const post1 = await request.post(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
      {
        headers: {
          "X-User-Id": "alice",
          "Content-Type": "application/json",
        },
        data: { body: "first comment" },
      },
    );
    expect(post1.status()).toBe(201);
    const row1 = await post1.json();
    expect(row1.body).toBe("first comment");
    expect(row1.userName).toBeTruthy();
    expect(row1.userId).toBe("alice");
    expect(row1.editedAt).toBeNull();
    expect(row1.id).toBeTruthy();

    // Slight delay so created_at differs and ordering is deterministic.
    await new Promise((r) => setTimeout(r, 50));

    const post2 = await request.post(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
      {
        headers: {
          "X-User-Id": "bob",
          "Content-Type": "application/json",
        },
        data: { body: "second comment" },
      },
    );
    expect(post2.status()).toBe(201);

    // GET — newest first.
    const list = await request
      .get(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        { headers: { "X-User-Id": "alice" } },
      )
      .then((r) => r.json());
    expect(list).toHaveLength(2);
    expect(list[0].body).toBe("second comment");
    expect(list[1].body).toBe("first comment");
  });

  test("POST with empty body returns 400", async ({ request }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await request.post(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
      {
        headers: {
          "X-User-Id": "alice",
          "Content-Type": "application/json",
        },
        data: { body: "   " },
      },
    );
    expect(res.status()).toBe(400);
  });

  test("PATCH updates body + stamps edited_at", async ({ request }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const created = await request
      .post(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        {
          headers: {
            "X-User-Id": "alice",
            "Content-Type": "application/json",
          },
          data: { body: "original" },
        },
      )
      .then((r) => r.json());

    const patched = await request.patch(
      `${BACKEND}/api/comments/${created.id}`,
      {
        headers: {
          "X-User-Id": "alice",
          "Content-Type": "application/json",
        },
        data: { body: "updated text" },
      },
    );
    expect(patched.status()).toBe(200);
    const row = await patched.json();
    expect(row.body).toBe("updated text");
    expect(row.editedAt).not.toBeNull();
  });

  test("PATCH by non-owner returns 403", async ({ request }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const created = await request
      .post(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        {
          headers: {
            "X-User-Id": "alice",
            "Content-Type": "application/json",
          },
          data: { body: "alice owns this" },
        },
      )
      .then((r) => r.json());

    const res = await request.patch(`${BACKEND}/api/comments/${created.id}`, {
      headers: {
        "X-User-Id": "mallory",
        "Content-Type": "application/json",
      },
      data: { body: "tampering" },
    });
    expect(res.status()).toBe(403);
  });

  test("DELETE by owner removes it; non-owner returns 403", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const created = await request
      .post(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        {
          headers: {
            "X-User-Id": "alice",
            "Content-Type": "application/json",
          },
          data: { body: "to be deleted" },
        },
      )
      .then((r) => r.json());

    // Non-owner cannot delete.
    const badDelete = await request.delete(
      `${BACKEND}/api/comments/${created.id}`,
      { headers: { "X-User-Id": "mallory" } },
    );
    expect(badDelete.status()).toBe(403);

    // Still present.
    const stillThere = await request
      .get(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        { headers: { "X-User-Id": "alice" } },
      )
      .then((r) => r.json());
    expect(stillThere).toHaveLength(1);

    // Owner deletes.
    const ok = await request.delete(`${BACKEND}/api/comments/${created.id}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(ok.status()).toBe(204);

    const after = await request
      .get(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        { headers: { "X-User-Id": "alice" } },
      )
      .then((r) => r.json());
    expect(after).toHaveLength(0);
  });
});

test.describe("Per-rule comments — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("add, edit, delete a comment from the rule editor", async ({
    page,
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    await loginAs(page, "alice");
    await page.goto(`/?checklist=${checklistId}`);

    // Navigate via the systems list → asset → checklist.
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "comments-host" }).click();
    await page.getByRole("button", { name: /edge/i }).first().click();

    // Open the rule editor.
    await page.getByRole("button", { name: ruleId }).first().click();

    // No comments yet.
    await expect(page.getByText("No comments yet.")).toBeVisible();

    // Add a comment.
    await page.getByTestId("rule-comment-input").fill("hello thread");
    await page.getByTestId("rule-comment-add").click();

    await expect(page.getByText("hello thread")).toBeVisible({
      timeout: 10_000,
    });

    // Edit it.
    await page.getByTestId("rule-comment-edit").first().click();
    // The edit textarea pre-fills with the existing body; clear + retype.
    const textareas = page.locator("textarea");
    // The inline edit textarea is the one that currently has 'hello thread'.
    const editArea = textareas.filter({ hasText: "hello thread" }).first();
    await editArea.fill("edited body");
    await page.getByTestId("rule-comment-save-edit").click();

    await expect(page.getByText("edited body")).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByText("(edited)")).toBeVisible();

    // Delete it.
    await page.getByTestId("rule-comment-delete").first().click();
    await expect(page.getByText("edited body")).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.getByText("No comments yet.")).toBeVisible();
  });
});
