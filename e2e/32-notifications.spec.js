import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function meId(request, userName) {
  return (
    await (
      await request.get(`${BACKEND}/api/users/me`, {
        headers: { "X-User-Id": userName },
      })
    ).json()
  ).id;
}

async function seedAssignmentTo(request, assigneeName) {
  const assigneeId = await meId(request, assigneeName);
  const asset = await (
    await request.post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "n-host" },
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
  const ruleId = detail.rules[0].id;
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { status: "open", assigneeId },
    },
  );
  return { asset, checklist, ruleId, assigneeId };
}

test.describe("Notifications", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: assigning a rule creates an unread notification for the assignee", async ({
    request,
  }) => {
    await seedAssignmentTo(request, "bob");

    const before = await (
      await request.get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    expect(before.unreadCount).toBe(1);
    expect(before.assigned).toHaveLength(1);
    expect(before.assigned[0].unread).toBe(true);

    // mark-read clears the counter on subsequent fetches
    const mr = await request.post(`${BACKEND}/api/notifications/mark-read`, {
      headers: { "X-User-Id": "bob" },
    });
    expect(mr.status()).toBe(204);

    const after = await (
      await request.get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    expect(after.unreadCount).toBe(0);
    expect(after.assigned).toHaveLength(1); // history persists, only flag flips
    expect(after.assigned[0].unread).toBe(false);
  });

  test("API: alice does NOT see bob's assignment notification", async ({
    request,
  }) => {
    await seedAssignmentTo(request, "bob");
    const d = await (
      await request.get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(d.assigned).toHaveLength(0);
    expect(d.unreadCount).toBe(0);
  });

  test("UI: TopNav bell shows unread count and panel lists the item", async ({
    page,
    request,
  }) => {
    await seedAssignmentTo(request, "bob");
    await loginAs(page, "bob");
    await page.goto("/");

    const bell = page.getByRole("button", { name: "Notifications" });
    await expect(bell).toBeVisible();
    // The unread count is in the button's inner text, not its aria-label.
    await expect(bell).toContainText("(1)");
    await bell.click();

    const dialog = page.getByRole("dialog", { name: "Notifications" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Newly assigned")).toBeVisible();
    await expect(dialog.getByText(/SV-/)).toBeVisible();

    // Close the dialog (Cloudscape's X has no accessible name); the
    // badge counter on the bell drops back to plain "Notifications".
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(bell).not.toContainText("(1)");
  });
});
