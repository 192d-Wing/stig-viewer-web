import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Asset groups — first-class, named collections of assets.
 *
 * Authorization model:
 *   - Listing groups / members is open to any authenticated user.
 *   - Mutating a group (name/description/membership/delete) requires the
 *     caller to be the group owner OR a global admin.
 */

async function userId(request, name) {
  const r = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  return (await r.json()).id;
}

async function seedAsset(request, owner = "alice", name = "group-host") {
  const r = await request.post(`${BACKEND}/api/assets`, {
    headers: { "X-User-Id": owner, "Content-Type": "application/json" },
    data: { name },
  });
  if (!r.ok()) {
    throw new Error(`seedAsset failed: ${r.status()}`);
  }
  return r.json();
}

async function createGroup(request, asUser, body) {
  return request.post(`${BACKEND}/api/asset-groups`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data: body,
  });
}

async function addMember(request, asUser, groupId, assetId) {
  return request.post(`${BACKEND}/api/asset-groups/${groupId}/members`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data: { assetId },
  });
}

test.describe("Asset groups", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: alice creates a group → 201 + list returns it", async ({
    request,
  }) => {
    const aliceId = await userId(request, "alice");
    const res = await createGroup(request, "alice", {
      name: "Production",
      description: "prod hosts",
    });
    expect(res.status()).toBe(201);
    const created = await res.json();
    expect(created.id).toBeTruthy();
    expect(created.name).toBe("Production");
    expect(created.ownerId).toBe(aliceId);
    expect(created.memberCount).toBe(0);

    const listRes = await request.get(`${BACKEND}/api/asset-groups`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(listRes.status()).toBe(200);
    const list = await listRes.json();
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe(created.id);
    expect(list[0].name).toBe("Production");
  });

  test("API: duplicate group name → 409", async ({ request }) => {
    expect((await createGroup(request, "alice", { name: "Dup" })).status()).toBe(
      201,
    );
    const second = await createGroup(request, "bob", { name: "Dup" });
    expect(second.status()).toBe(409);
  });

  test("API: add asset to group, list members shows it", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    const group = await createGroup(request, "alice", { name: "G1" }).then(
      (r) => r.json(),
    );

    const add = await addMember(request, "alice", group.id, asset.id);
    expect(add.status()).toBe(204);

    const members = await request
      .get(`${BACKEND}/api/asset-groups/${group.id}/members`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(members).toHaveLength(1);
    expect(members[0].assetId).toBe(asset.id);
    expect(members[0].name).toBe(asset.name);

    // Idempotent: a repeat add is still 204 and member count stays at 1.
    expect((await addMember(request, "alice", group.id, asset.id)).status()).toBe(
      204,
    );
    const members2 = await request
      .get(`${BACKEND}/api/asset-groups/${group.id}/members`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(members2).toHaveLength(1);
  });

  test("API: non-owner cannot add members (403); admin can", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    const group = await createGroup(request, "alice", { name: "G2" }).then(
      (r) => r.json(),
    );

    // bob has no role → forbidden.
    const denied = await addMember(request, "bob", group.id, asset.id);
    expect(denied.status()).toBe(403);

    // Promote dora to admin globally — that bypasses owner-gating.
    await setUserRole("dora", "admin");
    const ok = await addMember(request, "dora", group.id, asset.id);
    expect(ok.status()).toBe(204);

    const members = await request
      .get(`${BACKEND}/api/asset-groups/${group.id}/members`, {
        headers: { "X-User-Id": "bob" },
      })
      .then((r) => r.json());
    expect(members).toHaveLength(1);
  });

  test("API: delete cascades — group gone + members 404", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    const group = await createGroup(request, "alice", { name: "G3" }).then(
      (r) => r.json(),
    );
    expect((await addMember(request, "alice", group.id, asset.id)).status()).toBe(
      204,
    );

    const del = await request.delete(`${BACKEND}/api/asset-groups/${group.id}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(del.status()).toBe(204);

    // Group itself is gone — listing members returns 404.
    const after = await request.get(
      `${BACKEND}/api/asset-groups/${group.id}/members`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(after.status()).toBe(404);

    // List endpoint no longer returns it.
    const list = await request
      .get(`${BACKEND}/api/asset-groups`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(list.find((g) => g.id === group.id)).toBeUndefined();

    // The asset itself still exists — the cascade should drop the
    // membership row, not the asset.
    const assetAfter = await request.get(`${BACKEND}/api/assets/${asset.id}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(assetAfter.status()).toBe(200);
  });

  test("API: PATCH is owner-only (non-owner 403, owner 200)", async ({
    request,
  }) => {
    const group = await createGroup(request, "alice", {
      name: "G4",
      description: "original",
    }).then((r) => r.json());

    // Ensure bob's row exists before he tries to PATCH.
    await userId(request, "bob");
    const denied = await request.patch(
      `${BACKEND}/api/asset-groups/${group.id}`,
      {
        headers: { "X-User-Id": "bob", "Content-Type": "application/json" },
        data: { name: "hijacked" },
      },
    );
    expect(denied.status()).toBe(403);

    const ok = await request.patch(`${BACKEND}/api/asset-groups/${group.id}`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { description: "renamed" },
    });
    expect(ok.status()).toBe(200);
    expect((await ok.json()).description).toBe("renamed");
  });

  test("UI: create group on Groups page, then filter Systems list", async ({
    page,
    request,
  }) => {
    // Seed two assets — only the first will end up in the group, so the
    // filter has something measurable to do.
    const a1 = await seedAsset(request, "alice", "group-a");
    await seedAsset(request, "alice", "group-b");

    await loginAs(page, "alice");
    await page.goto("/");

    // Navigate to Groups via the TopNav button.
    await page.getByRole("button", { name: "Groups", exact: true }).click();

    // Create a new group via the modal.
    await page.getByTestId("create-group-button").click();
    await page
      .getByTestId("group-name-input")
      .locator("input")
      .fill("UI-Group");
    await page
      .getByTestId("group-description-input")
      .locator("textarea")
      .fill("from the e2e");
    await page.getByTestId("group-modal-submit").click();

    // Group row should appear in the table (use the named accessible
    // table — `<Table header={<Header>Asset groups</Header>}>` wires
    // that name automatically).
    const groupsTable = page.getByRole("table", { name: /Asset groups/i });
    await expect(groupsTable.getByText("UI-Group")).toBeVisible({
      timeout: 10_000,
    });

    // Open the group's members sub-view by clicking its name link.
    await page.getByTestId("group-name-UI-Group").click();

    // Add the first asset to the group via the Multiselect.
    const ms = page.getByTestId("add-member-multiselect");
    await ms.click();
    await page.getByRole("option", { name: "group-a" }).click();
    // Click outside the dropdown so Cloudscape commits the selection,
    // then press Add.
    await page.keyboard.press("Escape");
    await page.getByTestId("add-member-button").click();

    // Wait for the member to land in the API view to avoid racing the UI.
    await expect
      .poll(
        async () => {
          // Resolve the group id via list endpoint (we don't capture it
          // from the UI flow).
          const groups = await request
            .get(`${BACKEND}/api/asset-groups`, {
              headers: { "X-User-Id": "alice" },
            })
            .then((r) => r.json());
          const g = groups.find((x) => x.name === "UI-Group");
          if (!g) return 0;
          const m = await request
            .get(`${BACKEND}/api/asset-groups/${g.id}/members`, {
              headers: { "X-User-Id": "alice" },
            })
            .then((r) => r.json());
          return m.length;
        },
        { timeout: 10_000 },
      )
      .toBe(1);

    // Now flip to Systems and use the group filter to ensure only the
    // member asset is shown.
    await page.getByRole("button", { name: "Systems", exact: true }).click();

    const systemsTable = page.getByRole("table", { name: /Systems/i });
    await expect(systemsTable.getByText("group-a")).toBeVisible({
      timeout: 10_000,
    });
    await expect(systemsTable.getByText("group-b")).toBeVisible();

    // Pick UI-Group from the filter Select.
    await page.getByTestId("asset-group-filter").click();
    await page.getByRole("option", { name: "UI-Group" }).click();

    await expect(systemsTable.getByText("group-a")).toBeVisible();
    await expect(systemsTable.getByText("group-b")).not.toBeVisible();
  });
});
