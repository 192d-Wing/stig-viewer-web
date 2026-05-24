import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Seed: alice's asset + 'edge' checklist, returning the first rule id.
 * Mirrors the seed in 47-rule-comments.spec.js — we need a real
 * checklist + rule to attempt a PATCH against under the viewer role.
 */
async function seedChecklist(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "viewer-role-host" },
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

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

test.describe("Read-only viewer role", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: viewer cannot PATCH a rule (403 with JSON error body)", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);
    await setUserRole("alice", "viewer");

    const res = await request.patch(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
      {
        headers: {
          "X-User-Id": "alice",
          "Content-Type": "application/json",
        },
        data: { status: "open" },
      },
    );
    expect(res.status()).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("viewer role is read-only");
  });

  test("API: viewer GETs still work (assets / dashboard / diff)", async ({
    request,
  }) => {
    // Seed a draft so /api/diff has a starting point and won't 400.
    await seedChecklist(request);
    await setUserRole("alice", "viewer");

    const assetsRes = await request.get(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(assetsRes.status()).toBe(200);

    const dashRes = await request.get(`${BACKEND}/api/dashboard`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(dashRes.status()).toBe(200);

    const diffRes = await request.get(
      `${BACKEND}/api/diff?since=2000-01-01`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(diffRes.status()).toBe(200);
  });

  test("API: viewer POST /api/notifications/mark-read is allowed (allowlisted)", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "viewer");

    const res = await request.post(
      `${BACKEND}/api/notifications/mark-read`,
      {
        headers: {
          "X-User-Id": "alice",
          "Content-Type": "application/json",
        },
        data: {},
      },
    );
    // Should NOT be 403 — must be the handler's normal success status.
    expect(res.status()).not.toBe(403);
    expect(res.status()).toBe(204);
  });

  test("API: admin can promote a user to 'viewer' via /api/admin/users/:id/role", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    const bobId = await ensureUser(request, "bob");
    await setUserRole("alice", "admin");

    // Promotion to viewer must succeed.
    const ok = await request.patch(
      `${BACKEND}/api/admin/users/${bobId}/role`,
      {
        headers: {
          "X-User-Id": "alice",
          "Content-Type": "application/json",
        },
        data: { role: "viewer" },
      },
    );
    expect(ok.status()).toBe(204);

    // The list must reflect the new role.
    const list = await (
      await request.get(`${BACKEND}/api/admin/users`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    expect(list.find((u) => u.id === bobId).role).toBe("viewer");
  });

  test("API: /api/test/set-role rejects a bogus role with 400", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    const res = await request.post(`${BACKEND}/api/test/set-role`, {
      headers: { "Content-Type": "application/json" },
      data: { user_id: "alice", role: "godking" },
    });
    expect(res.status()).toBe(400);
  });

  test("UI: 'Read-only' badge is visible in the TopNav for a viewer", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "viewer");
    await loginAs(page, "alice");
    await page.goto("/");

    const badge = page.getByTestId("viewer-badge");
    await expect(badge).toBeVisible();
    await expect(badge).toContainText("Read-only");
  });
});
