import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

test.describe("Admin console", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: GET /api/admin/users is 403 for a non-admin caller", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    const res = await request.get(`${BACKEND}/api/admin/users`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(403);
  });

  test("API: GET /api/admin/users returns the user list for an admin", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    const res = await request.get(`${BACKEND}/api/admin/users`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(200);
    const users = await res.json();
    // Both alice and bob (and possibly nobody else) should be present.
    const names = users.map((u) => u.displayName);
    expect(names).toContain("alice");
    expect(names).toContain("bob");
    const alice = users.find((u) => u.displayName === "alice");
    expect(alice.role).toBe("admin");
    // last_login should be set for users who've authenticated.
    expect(alice.lastLogin).not.toBeNull();
  });

  test("API: PATCH role works and rejects an invalid role with 400", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    const bobId = await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    // Valid promotion → 204.
    const okRes = await request.patch(
      `${BACKEND}/api/admin/users/${bobId}/role`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { role: "reviewer" },
      },
    );
    expect(okRes.status()).toBe(204);

    // Verify it stuck.
    const list = await (
      await request.get(`${BACKEND}/api/admin/users`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(list.find((u) => u.id === bobId).role).toBe("reviewer");

    // Invalid role → 400.
    const badRes = await request.patch(
      `${BACKEND}/api/admin/users/${bobId}/role`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { role: "godking" },
      },
    );
    expect(badRes.status()).toBe(400);

    // Non-admin caller → 403.
    const forbidden = await request.patch(
      `${BACKEND}/api/admin/users/${bobId}/role`,
      {
        headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
        data: { role: "author" },
      },
    );
    expect(forbidden.status()).toBe(403);
  });

  test("UI: Admin nav button is only visible when alice has the admin role", async ({
    page,
    request,
  }) => {
    // First, alice is a plain author — no Admin button.
    await ensureUser(request, "alice");
    await loginAs(page, "alice");
    await page.goto("/");
    await expect(
      page.getByRole("button", { name: "Viewer" }),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Admin" })).toHaveCount(0);

    // Promote her and reload — the Admin button should now appear.
    await setUserRole("alice", "admin");
    await page.reload();
    const adminBtn = page.getByRole("button", { name: "Admin" });
    await expect(adminBtn).toBeVisible();

    // Clicking it navigates to the console and shows the Users header.
    await adminBtn.click();
    await expect(page).toHaveURL(/[?&]view=admin/);
    await expect(page.getByRole("heading", { name: /^Users/ })).toBeVisible();
  });
});
