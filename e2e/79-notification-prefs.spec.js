import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Fetch the canonical (UUID) id for the named test user. Per the
 * memory-backed pitfall, the `users.id` column is a UUID — never
 * compare it to a friendly name like "alice".
 */
async function meId(request, userName) {
  const me = await (
    await request.get(`${BACKEND}/api/users/me`, {
      headers: { "X-User-Id": userName },
    })
  ).json();
  return me.id;
}

/**
 * Seed: alice creates an asset + edge checklist and assigns its first
 * rule to `assigneeName`. Returns the rule id so callers can
 * cross-check the resulting "assigned" notification.
 */
async function seedAssignmentTo(request, assigneeName) {
  const assigneeId = await meId(request, assigneeName);
  const asset = await (
    await request.post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "prefs-host" },
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
  return { checklistId: checklist.id, ruleId };
}

test.describe("Notification preferences", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: fresh user defaults to all six event types enabled", async ({
    request,
  }) => {
    // Touch /api/users/me to materialize the user row, then fetch prefs.
    await meId(request, "bob");
    const prefs = await (
      await request.get(`${BACKEND}/api/notifications/prefs`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    expect(prefs).toEqual({
      assigned: true,
      overdue: true,
      mentions: true,
      approvals: true,
      decisions: true,
      assignedDrafts: true,
    });
  });

  test("API: PUT with a partial body upserts only the supplied fields", async ({
    request,
  }) => {
    await meId(request, "bob");

    const put = await request.put(`${BACKEND}/api/notifications/prefs`, {
      headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
      data: { assigned: false },
    });
    expect(put.ok()).toBeTruthy();

    const prefs = await (
      await request.get(`${BACKEND}/api/notifications/prefs`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    // The toggled field flips; everything else stays at the default
    // (true) because their rows were never inserted.
    expect(prefs.assigned).toBe(false);
    expect(prefs.overdue).toBe(true);
    expect(prefs.mentions).toBe(true);
    expect(prefs.approvals).toBe(true);
    expect(prefs.decisions).toBe(true);
    expect(prefs.assignedDrafts).toBe(true);
  });

  test("API: disabling 'assigned' hides the bucket AND drops it from unreadCount", async ({
    request,
  }) => {
    await seedAssignmentTo(request, "bob");

    // Baseline: bob sees the assignment + an unread badge.
    const baseline = await (
      await request.get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    expect(baseline.assigned).toHaveLength(1);
    expect(baseline.unreadCount).toBeGreaterThanOrEqual(1);
    const baselineUnread = baseline.unreadCount;

    // Disable 'assigned' and re-fetch.
    await request.put(`${BACKEND}/api/notifications/prefs`, {
      headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
      data: { assigned: false },
    });
    const filtered = await (
      await request.get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    expect(filtered.assigned).toEqual([]);
    // The one unread assignment no longer contributes — count drops by
    // exactly that amount (other buckets, if any, are untouched).
    expect(filtered.unreadCount).toBe(baselineUnread - 1);
  });

  test("API: re-enabling 'assigned' brings the assignment back", async ({
    request,
  }) => {
    await seedAssignmentTo(request, "bob");

    await request.put(`${BACKEND}/api/notifications/prefs`, {
      headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
      data: { assigned: false },
    });
    const off = await (
      await request.get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    expect(off.assigned).toEqual([]);

    await request.put(`${BACKEND}/api/notifications/prefs`, {
      headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
      data: { assigned: true },
    });
    const on = await (
      await request.get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    expect(on.assigned).toHaveLength(1);
  });

  test("UI: toggling 'Newly assigned' off in Preferences empties that bucket", async ({
    page,
    request,
  }) => {
    await seedAssignmentTo(request, "bob");
    await loginAs(page, "bob");
    await page.goto("/");

    // Open the bell.
    const bell = page.getByRole("button", { name: "Notifications" });
    await expect(bell).toBeVisible();
    await bell.click();

    const dialog = page.getByRole("dialog", { name: "Notifications" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Newly assigned")).toBeVisible();

    // Open Preferences sub-modal.
    await page.getByTestId("notif-prefs-open").click();
    const prefsDialog = page.getByTestId("notif-prefs-modal");
    await expect(prefsDialog).toBeVisible();

    // Cloudscape Toggle's data-testid lands on a wrapper; the real
    // input is the inner <input type="checkbox">. Flip 'assigned' off
    // and save.
    const assignedToggle = page
      .getByTestId("notif-pref-assigned")
      .locator("input[type=checkbox]");
    await expect(assignedToggle).toBeChecked();
    await assignedToggle.click();
    await expect(assignedToggle).not.toBeChecked();

    await page.getByTestId("notif-prefs-save").click();
    await expect(prefsDialog).toBeHidden();

    // The parent Notifications dialog stays open behind the sub-modal,
    // and saveNotifPrefs triggers a bell refresh. Just wait for the
    // empty-state copy to land in the still-visible dialog — don't
    // re-click the bell (the modal backdrop blocks it anyway).
    await expect(dialog).toBeVisible();
    await expect(
      dialog.getByText("Nothing assigned to you recently."),
    ).toBeVisible({ timeout: 10_000 });
  });
});
