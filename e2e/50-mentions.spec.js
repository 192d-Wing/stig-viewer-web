import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Seed: alice owns 'mention-host' + an 'edge' checklist, returning the
 * first rule id so we can post comments on a real (checklistId, ruleId).
 */
async function seedChecklist(request) {
  const asset = await (
    await request.post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "mention-host" },
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

async function ensureUser(request, name) {
  // Hitting /api/users/me with X-User-Id triggers the test-header upsert
  // path, creating the user row if it doesn't exist yet. We do this for
  // 'bob' before alice mentions him so the handle lookup actually finds
  // a row.
  await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
}

async function postComment(request, userName, checklistId, ruleId, body) {
  return request.post(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
    {
      headers: { "X-User-Id": userName, "Content-Type": "application/json" },
      data: { body },
    },
  );
}

async function getNotifications(request, userName) {
  return (
    await request.get(`${BACKEND}/api/notifications`, {
      headers: { "X-User-Id": userName },
    })
  ).json();
}

test.describe("@-mentions in rule comments — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("@bob in alice's comment shows up in bob's mentions bucket", async ({
    request,
  }) => {
    await ensureUser(request, "bob");
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await postComment(
      request,
      "alice",
      checklistId,
      ruleId,
      "hey @bob can you take a look at this?",
    );
    expect(res.status()).toBe(201);

    const bobsNotifs = await getNotifications(request, "bob");
    expect(bobsNotifs.mentions).toHaveLength(1);
    const m = bobsNotifs.mentions[0];
    expect(m.ruleId).toBe(ruleId);
    expect(m.checklistId).toBe(checklistId);
    expect(m.byName).toBe("alice");
    expect(m.body).toContain("@bob");
    expect(m.unread).toBe(true);
    expect(bobsNotifs.unreadCount).toBeGreaterThanOrEqual(1);
  });

  test("authoring user does NOT see her own comment's mention", async ({
    request,
  }) => {
    await ensureUser(request, "bob");
    const { checklistId, ruleId } = await seedChecklist(request);

    await postComment(
      request,
      "alice",
      checklistId,
      ruleId,
      "ping @bob please review",
    );

    const alicesNotifs = await getNotifications(request, "alice");
    expect(alicesNotifs.mentions).toHaveLength(0);
  });

  test("self-mention is silently dropped", async ({ request }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    await postComment(
      request,
      "alice",
      checklistId,
      ruleId,
      "note to self @alice double-check this",
    );

    const alicesNotifs = await getNotifications(request, "alice");
    expect(alicesNotifs.mentions).toHaveLength(0);
  });

  test("@nonexistent is silently ignored, no mention row created", async ({
    request,
  }) => {
    await ensureUser(request, "bob");
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await postComment(
      request,
      "alice",
      checklistId,
      ruleId,
      "anybody know @nobody-here-at-all?",
    );
    expect(res.status()).toBe(201);

    // Neither bob nor alice should see a mention from this.
    const bobs = await getNotifications(request, "bob");
    expect(bobs.mentions).toHaveLength(0);
    const alices = await getNotifications(request, "alice");
    expect(alices.mentions).toHaveLength(0);
  });

  test("mark-read stamps read_at; mentions stay in bucket but flip to read", async ({
    request,
  }) => {
    await ensureUser(request, "bob");
    const { checklistId, ruleId } = await seedChecklist(request);

    await postComment(
      request,
      "alice",
      checklistId,
      ruleId,
      "hey @bob heads up",
    );

    const before = await getNotifications(request, "bob");
    expect(before.mentions).toHaveLength(1);
    expect(before.mentions[0].unread).toBe(true);

    const mr = await request.post(`${BACKEND}/api/notifications/mark-read`, {
      headers: { "X-User-Id": "bob" },
    });
    expect(mr.status()).toBe(204);

    const after = await getNotifications(request, "bob");
    // History persists; only the unread flag flips and the counter clears.
    expect(after.mentions).toHaveLength(1);
    expect(after.mentions[0].unread).toBe(false);
    // Without any other unread items, the counter is back to zero.
    expect(after.unreadCount).toBe(0);
  });
});

test.describe("@-mentions in rule comments — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("bell badge counts mentions; opening shows the Mentions section", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "bob");
    const { checklistId, ruleId } = await seedChecklist(request);
    await postComment(
      request,
      "alice",
      checklistId,
      ruleId,
      "FYI @bob this needs your eyes",
    );

    await loginAs(page, "bob");
    await page.goto("/");

    const bell = page.getByRole("button", { name: "Notifications" });
    await expect(bell).toBeVisible();
    await expect(bell).toContainText("(1)");
    await bell.click();

    const dialog = page.getByRole("dialog", { name: "Notifications" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Mentions")).toBeVisible();
    await expect(dialog.getByTestId("mention-item")).toHaveCount(1);
    await expect(dialog.getByTestId("mention-item")).toContainText("alice");
    await expect(dialog.getByTestId("mention-item")).toContainText(ruleId);

    // Closing clears the unread counter on the bell.
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(bell).not.toContainText("(1)");
  });
});
