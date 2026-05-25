import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Auto-create the test user via the X-User-Id bypass and return the
 * generated UUID. We never key off the user-supplied name because
 * `user.id` is a server-side UUID, not the X-User-Id string.
 */
async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

test.describe("Session activity audit + admin revoke", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: admin GET /api/admin/sessions returns rows with audit fields", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    const res = await request.get(`${BACKEND}/api/admin/sessions`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(200);
    const rows = await res.json();
    expect(Array.isArray(rows)).toBe(true);
    expect(rows.length).toBeGreaterThan(0);
    const row = rows[0];
    // Every row should carry the audit fields the panel renders.
    for (const key of [
      "id",
      "userId",
      "userName",
      "ip",
      "userAgent",
      "createdAt",
      "expiresAt",
    ]) {
      expect(row).toHaveProperty(key);
    }
  });

  test("API: non-admin GET /api/admin/sessions is 403", async ({ request }) => {
    await ensureUser(request, "alice");
    const res = await request.get(`${BACKEND}/api/admin/sessions`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(403);
  });

  test("API: revoking an alice session drops it from the active list", async ({
    request,
  }) => {
    const aliceId = await ensureUser(request, "alice");
    await ensureUser(request, "bob");
    await setUserRole("bob", "admin");

    const listed = await (
      await request.get(`${BACKEND}/api/admin/sessions`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    const aliceSession = listed.find((s) => s.userId === aliceId);
    expect(aliceSession).toBeTruthy();

    const revoke = await request.delete(
      `${BACKEND}/api/admin/sessions/${aliceSession.id}`,
      { headers: { "X-User-Id": "bob" } },
    );
    expect([200, 204]).toContain(revoke.status());

    // Refetch — the revoked row must be gone from the active list.
    const afterRows = await (
      await request.get(`${BACKEND}/api/admin/sessions`, {
        headers: { "X-User-Id": "bob" },
      })
    ).json();
    expect(afterRows.find((s) => s.id === aliceSession.id)).toBeUndefined();
  });

  test("API: revoking a non-existent session id returns 404", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    const res = await request.delete(
      `${BACKEND}/api/admin/sessions/does-not-exist-00000000`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(404);
  });

  test("UI: admin console renders the active sessions table with at least one row", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    await loginAs(page, "alice");
    await page.goto("/?view=admin");

    const heading = page.getByRole("heading", { name: /^Active sessions/ });
    await expect(heading).toBeVisible({ timeout: 10_000 });

    const table = page.getByTestId("active-sessions-table");
    await expect(table).toBeVisible();
    // The admin's own session should always be in the list.
    await expect(table).toContainText("alice");
  });
});
