import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Granular per-asset ACL.
 *
 * Default behavior (no ACL rows) MUST stay unchanged so the bulk of the
 * existing E2E suite passes — the rest of the suite covers that path
 * implicitly. These specs walk the explicit ACL grants.
 */

async function seedAsset(request, owner = "alice", name = "acl-host") {
  const r = await request.post(`${BACKEND}/api/assets`, {
    headers: { "X-User-Id": owner, "Content-Type": "application/json" },
    data: { name },
  });
  if (!r.ok()) {
    throw new Error(`seedAsset failed: ${r.status()}`);
  }
  return r.json();
}

async function seedChecklist(request, owner, assetId, stigId = "edge") {
  const cl = await request
    .post(`${BACKEND}/api/assets/${assetId}/checklists`, {
      headers: { "X-User-Id": owner, "Content-Type": "application/json" },
      data: { stigId },
    })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${cl.id}`, {
      headers: { "X-User-Id": owner },
    })
    .then((r) => r.json());
  return { checklistId: cl.id, ruleId: detail.rules[0].id };
}

async function userId(request, name) {
  const r = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  return (await r.json()).id;
}

async function grant(request, asUser, assetId, targetUserId, permission) {
  return request.post(`${BACKEND}/api/assets/${assetId}/acl`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data: { userId: targetUserId, permission },
  });
}

async function revoke(request, asUser, assetId, targetUserId) {
  return request.delete(
    `${BACKEND}/api/assets/${assetId}/acl/${encodeURIComponent(targetUserId)}`,
    { headers: { "X-User-Id": asUser } },
  );
}

async function patchRule(request, asUser, checklistId, ruleId, data) {
  return request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
      data,
    },
  );
}

test.describe("Granular per-asset ACL", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: owner lists empty ACL → 200, []", async ({ request }) => {
    const asset = await seedAsset(request);
    const res = await request.get(`${BACKEND}/api/assets/${asset.id}/acl`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(200);
    expect(await res.json()).toEqual([]);
  });

  test("API: grant write → grantee can PATCH a rule (was 403 before)", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    const { checklistId, ruleId } = await seedChecklist(
      request,
      "alice",
      asset.id,
    );

    // Pre-grant: bob is forbidden.
    const before = await patchRule(request, "bob", checklistId, ruleId, {
      status: "open",
      findingDetails: "investigating",
      comments: "",
    });
    expect(before.status()).toBe(403);

    const bobId = await userId(request, "bob");
    const grantRes = await grant(request, "alice", asset.id, bobId, "write");
    expect(grantRes.status()).toBe(201);
    expect((await grantRes.json()).permission).toBe("write");

    const after = await patchRule(request, "bob", checklistId, ruleId, {
      status: "open",
      findingDetails: "investigating",
      comments: "",
    });
    expect(after.status()).toBe(200);
  });

  test("API: write grant does NOT let you grant ACL to others (403)", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    const bobId = await userId(request, "bob");
    const charlieId = await userId(request, "charlie");
    expect((await grant(request, "alice", asset.id, bobId, "write")).status()).toBe(
      201,
    );

    const res = await grant(request, "bob", asset.id, charlieId, "read");
    expect(res.status()).toBe(403);
  });

  test("API: write grant cannot delete the asset (403)", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    const bobId = await userId(request, "bob");
    expect((await grant(request, "alice", asset.id, bobId, "write")).status()).toBe(
      201,
    );

    const res = await request.delete(`${BACKEND}/api/assets/${asset.id}`, {
      headers: { "X-User-Id": "bob" },
    });
    expect(res.status()).toBe(403);
  });

  test("API: admin grant lets the grantee in turn grant ACL", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    const bobId = await userId(request, "bob");
    const charlieId = await userId(request, "charlie");

    // First give bob `write` and confirm they can't grant.
    expect((await grant(request, "alice", asset.id, bobId, "write")).status()).toBe(
      201,
    );
    expect(
      (await grant(request, "bob", asset.id, charlieId, "read")).status(),
    ).toBe(403);

    // Upgrade bob to admin — same upsert endpoint, new permission.
    expect((await grant(request, "alice", asset.id, bobId, "admin")).status()).toBe(
      201,
    );

    const res = await grant(request, "bob", asset.id, charlieId, "read");
    expect(res.status()).toBe(201);
  });

  test("API: revoking the grant returns 403 again on next mutation", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    const { checklistId, ruleId } = await seedChecklist(
      request,
      "alice",
      asset.id,
    );
    const bobId = await userId(request, "bob");
    expect((await grant(request, "alice", asset.id, bobId, "write")).status()).toBe(
      201,
    );

    // Sanity: bob can patch while granted.
    expect(
      (
        await patchRule(request, "bob", checklistId, ruleId, {
          status: "open",
          findingDetails: "checking",
          comments: "",
        })
      ).status(),
    ).toBe(200);

    expect((await revoke(request, "alice", asset.id, bobId)).status()).toBe(204);

    const after = await patchRule(request, "bob", checklistId, ruleId, {
      status: "open",
      findingDetails: "checking again",
      comments: "",
    });
    expect(after.status()).toBe(403);
  });

  test("API: global admin role bypasses ACL on read paths (no grant needed)", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    // Pre-seed dora's user row, then bump to admin role.
    await setUserRole("dora", "admin");

    // The ACL listing is restricted to the asset owner / acl-admin /
    // global admin — dora has never been granted anything on this
    // asset, yet the admin role lets her read the roster.
    const list = await request.get(`${BACKEND}/api/assets/${asset.id}/acl`, {
      headers: { "X-User-Id": "dora" },
    });
    expect(list.status()).toBe(200);

    // And dora can also grant on alice's asset without being acl-admin
    // herself — the role bypasses every layer of ACL gating.
    const bobId = await userId(request, "bob");
    const granted = await grant(request, "dora", asset.id, bobId, "read");
    expect(granted.status()).toBe(201);
  });

  test("UI: owner can add and remove a user from Sharing", async ({
    page,
    request,
  }) => {
    const asset = await seedAsset(request);
    // Make sure bob's user row exists before opening the page so the
    // user picker has someone to pick.
    await userId(request, "bob");

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "acl-host" }).click();

    const sharing = page.getByTestId("sharing-section");
    await expect(sharing).toBeVisible({ timeout: 10_000 });

    // Open the user picker (Cloudscape Select renders its hit area as
    // the wrapper — clicking the testid itself works fine here).
    await sharing.getByTestId("sharing-user-select").click();
    await page.getByRole("option", { name: "bob" }).click();
    await sharing.getByTestId("sharing-add-button").click();

    // The new row appears with the "write" badge (default permission).
    await expect
      .poll(
        async () => {
          const acl = await request
            .get(`${BACKEND}/api/assets/${asset.id}/acl`, {
              headers: { "X-User-Id": "alice" },
            })
            .then((r) => r.json());
          return acl.length;
        },
        { timeout: 5_000 },
      )
      .toBe(1);

    await expect(sharing.getByText("bob")).toBeVisible();

    // Remove the row and confirm it vanishes both from the API and UI.
    const bobId = await userId(request, "bob");
    await sharing.getByTestId(`sharing-remove-${bobId}`).click();

    await expect
      .poll(
        async () => {
          const acl = await request
            .get(`${BACKEND}/api/assets/${asset.id}/acl`, {
              headers: { "X-User-Id": "alice" },
            })
            .then((r) => r.json());
          return acl.length;
        },
        { timeout: 5_000 },
      )
      .toBe(0);
  });
});
