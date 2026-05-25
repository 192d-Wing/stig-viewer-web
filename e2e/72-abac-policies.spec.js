import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Attribute-based access control (ABAC) policies.
 *
 * ABAC sits behind the existing owner / per-asset ACL / admin-role
 * checks in `asset_acl::user_can`. With zero rows in `abac_policies`
 * the helper falls through to today's behavior, so the broader suite
 * stays untouched. These specs walk the four new paths:
 *   - admin-only CRUD on /api/admin/policies
 *   - matching allow flips a previously-403 PATCH to 200
 *   - a matching deny overrides a matching allow
 *   - mismatched classification leaves the request 403
 *   - duplicate names get 409
 *   - the admin console renders the Policies section + modal
 */

async function ensureUser(request, name) {
  const r = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  if (!r.ok()) throw new Error(`ensureUser failed: ${r.status()}`);
  return (await r.json()).id;
}

async function seedAsset(
  request,
  owner = "alice",
  name = "abac-host",
  classification = "unclassified",
) {
  const r = await request.post(`${BACKEND}/api/assets`, {
    headers: { "X-User-Id": owner, "Content-Type": "application/json" },
    data: { name, classification },
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

async function patchRule(request, asUser, checklistId, ruleId, data) {
  return request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
      data,
    },
  );
}

async function createPolicy(request, asUser, body) {
  return request.post(`${BACKEND}/api/admin/policies`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data: body,
  });
}

test.describe("ABAC policies", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: admin lists empty → 200 [], non-admin → 403", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const list = await request.get(`${BACKEND}/api/admin/policies`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(list.status()).toBe(200);
    expect(await list.json()).toEqual([]);

    await ensureUser(request, "bob");
    const forbidden = await request.get(`${BACKEND}/api/admin/policies`, {
      headers: { "X-User-Id": "bob" },
    });
    expect(forbidden.status()).toBe(403);
  });

  test("API: admin can create a policy → 201", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const res = await createPolicy(request, "alice", {
      name: "reviewers-write-unclassified",
      effect: "allow",
      level: "write",
      roleMatch: "reviewer",
      classificationMatch: "unclassified",
    });
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.effect).toBe("allow");
    expect(body.level).toBe("write");
    expect(body.roleMatch).toBe("reviewer");
    expect(body.classificationMatch).toBe("unclassified");
    // Empty optional fields land as null (wildcard).
    expect(body.tagMatch).toBeNull();
    expect(body.enabled).toBe(true);
  });

  test("API: without a policy, reviewer without ACL gets 403 (legacy behavior preserved)", async ({
    request,
  }) => {
    // Asset owned by alice; bob is a reviewer with no ACL grant — the
    // pre-ABAC contract is that bob can't PATCH a rule on alice's
    // checklist, and the helper must keep returning false when the
    // policy table is empty.
    const asset = await seedAsset(request, "alice", "abac-default");
    const { checklistId, ruleId } = await seedChecklist(
      request,
      "alice",
      asset.id,
    );
    await ensureUser(request, "bob");
    await setUserRole("bob", "reviewer");

    const res = await patchRule(request, "bob", checklistId, ruleId, {
      status: "open",
      findingDetails: "investigating",
      comments: "",
    });
    expect(res.status()).toBe(403);
  });

  test("API: enabled allow policy lets the reviewer PATCH the rule", async ({
    request,
  }) => {
    const asset = await seedAsset(request, "alice", "abac-allow-host");
    const { checklistId, ruleId } = await seedChecklist(
      request,
      "alice",
      asset.id,
    );
    await ensureUser(request, "bob");
    await setUserRole("bob", "reviewer");

    // Pre-policy: forbidden.
    const before = await patchRule(request, "bob", checklistId, ruleId, {
      status: "open",
      findingDetails: "",
      comments: "",
    });
    expect(before.status()).toBe(403);

    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    const policyRes = await createPolicy(request, "alice", {
      name: "reviewer-write-unclassified",
      effect: "allow",
      level: "write",
      roleMatch: "reviewer",
      classificationMatch: "unclassified",
    });
    expect(policyRes.status()).toBe(201);

    const after = await patchRule(request, "bob", checklistId, ruleId, {
      status: "open",
      findingDetails: "abac let me in",
      comments: "",
    });
    expect(after.status()).toBe(200);
  });

  test("API: a matching deny policy overrides the matching allow", async ({
    request,
  }) => {
    const asset = await seedAsset(request, "alice", "abac-deny-host");
    const { checklistId, ruleId } = await seedChecklist(
      request,
      "alice",
      asset.id,
    );
    await ensureUser(request, "bob");
    await setUserRole("bob", "reviewer");
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    expect(
      (
        await createPolicy(request, "alice", {
          name: "reviewer-allow",
          effect: "allow",
          level: "write",
          roleMatch: "reviewer",
          classificationMatch: "unclassified",
        })
      ).status(),
    ).toBe(201);

    // Sanity: allow alone lets bob in.
    expect(
      (
        await patchRule(request, "bob", checklistId, ruleId, {
          status: "open",
          findingDetails: "first",
          comments: "",
        })
      ).status(),
    ).toBe(200);

    // Layer a matching deny at the same level — single deny wins.
    expect(
      (
        await createPolicy(request, "alice", {
          name: "reviewer-deny",
          effect: "deny",
          level: "write",
          roleMatch: "reviewer",
          classificationMatch: "unclassified",
        })
      ).status(),
    ).toBe(201);

    const after = await patchRule(request, "bob", checklistId, ruleId, {
      status: "open",
      findingDetails: "should be blocked",
      comments: "",
    });
    expect(after.status()).toBe(403);
  });

  test("API: classification mismatch keeps the request 403", async ({
    request,
  }) => {
    // Asset is `secret`, the policy targets `unclassified` — predicate
    // fails and bob stays locked out.
    const asset = await seedAsset(request, "alice", "abac-secret-host", "secret");
    const { checklistId, ruleId } = await seedChecklist(
      request,
      "alice",
      asset.id,
    );
    await ensureUser(request, "bob");
    await setUserRole("bob", "reviewer");
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    expect(
      (
        await createPolicy(request, "alice", {
          name: "reviewer-write-unclassified-only",
          effect: "allow",
          level: "write",
          roleMatch: "reviewer",
          classificationMatch: "unclassified",
        })
      ).status(),
    ).toBe(201);

    const res = await patchRule(request, "bob", checklistId, ruleId, {
      status: "open",
      findingDetails: "should not apply",
      comments: "",
    });
    expect(res.status()).toBe(403);
  });

  test("API: duplicate policy name → 409", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const first = await createPolicy(request, "alice", {
      name: "dup-name",
      effect: "allow",
      level: "read",
    });
    expect(first.status()).toBe(201);

    const second = await createPolicy(request, "alice", {
      name: "dup-name",
      effect: "deny",
      level: "write",
    });
    expect(second.status()).toBe(409);
  });

  test("UI: admin console renders the Policies section and 'Add policy' opens the modal", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    await loginAs(page, "alice");

    await page.goto("/?view=admin");

    const policiesTable = page.getByTestId("policies-table");
    await expect(policiesTable).toBeVisible();

    await page.getByTestId("add-policy-btn").click();

    const modal = page.getByTestId("policy-modal");
    await expect(modal).toBeVisible();
    // The name input is in the modal — drill via the input element so
    // the Cloudscape wrapper testid doesn't confuse the locator.
    await expect(
      page.getByTestId("policy-name-input").locator("input"),
    ).toBeVisible();
  });
});
