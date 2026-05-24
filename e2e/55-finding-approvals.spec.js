import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Per-asset approval workflow.
 *
 * Default behavior (requires_approval = FALSE) MUST stay unchanged so the
 * bulk of the existing E2E suite passes — the first test in this spec is a
 * sanity check that closing a finding still writes through directly.
 */

async function seedChecklist(request, assetName = "approval-host") {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: assetName },
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

async function patchRule(request, userId, checklistId, ruleId, data) {
  return request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": userId, "Content-Type": "application/json" },
      data,
    },
  );
}

async function setApprovalPolicy(request, userId, assetId, requiresApproval) {
  return request.patch(`${BACKEND}/api/assets/${assetId}/approval-policy`, {
    headers: { "X-User-Id": userId, "Content-Type": "application/json" },
    data: { requiresApproval },
  });
}

async function getRuleState(request, userId, checklistId, ruleId) {
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklistId}`, {
      headers: { "X-User-Id": userId },
    })
    .then((r) => r.json());
  const rule = detail.rules.find((r) => r.id === ruleId);
  return rule?.state ?? {};
}

test.describe("Per-asset finding-close approval workflow", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: requires_approval=false (default) → closing applies directly", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "vendor patch verified",
      comments: "",
    });
    expect(res.status()).toBe(200);

    const state = await getRuleState(request, "alice", checklistId, ruleId);
    expect(state.status).toBe("not_a_finding");

    // No approval row should have been created on the default path.
    const approvals = await request
      .get(`${BACKEND}/api/approvals?status=all`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(approvals.length).toBe(0);
  });

  test("API: requires_approval=true → closing returns 202 + creates pending approval, rule stays open", async ({
    request,
  }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);

    // Flip rule to 'open' first so the "from" status is meaningful.
    await patchRule(request, "alice", checklistId, ruleId, {
      status: "open",
      findingDetails: "needs evidence",
      comments: "",
    });

    const policyRes = await setApprovalPolicy(request, "alice", assetId, true);
    expect(policyRes.status()).toBe(200);

    const res = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "patched per vendor advisory",
      comments: "",
    });
    expect(res.status()).toBe(202);
    const body = await res.json();
    expect(body.status).toBe("pending_approval");
    expect(body.approvalId).toBeTruthy();
    expect(body.proposedStatus).toBe("not_a_finding");

    // Rule status stays 'open' — the approval gate held it.
    const state = await getRuleState(request, "alice", checklistId, ruleId);
    expect(state.status).toBe("open");

    // The approval row is visible to the requester.
    const own = await request
      .get(`${BACKEND}/api/approvals?status=pending`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(own.length).toBe(1);
    expect(own[0].ruleId).toBe(ruleId);
    expect(own[0].proposedStatus).toBe("not_a_finding");
  });

  test("API: reviewer can approve → rule status flips to not_a_finding", async ({
    request,
  }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);
    await setApprovalPolicy(request, "alice", assetId, true);
    await setUserRole("reviewer-bob", "reviewer");

    const submit = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "kernel patched 2026-05-01",
      comments: "",
    });
    expect(submit.status()).toBe(202);
    const { approvalId } = await submit.json();
    expect(approvalId).toBeTruthy();

    const decide = await request.post(
      `${BACKEND}/api/approvals/${approvalId}/approve`,
      {
        headers: {
          "X-User-Id": "reviewer-bob",
          "Content-Type": "application/json",
        },
      },
    );
    expect(decide.status()).toBe(200);
    const row = await decide.json();
    expect(row.status).toBe("approved");
    expect(row.decidedBy).toBe("reviewer-bob");

    const state = await getRuleState(request, "alice", checklistId, ruleId);
    expect(state.status).toBe("not_a_finding");
    expect(state.findingDetails).toBe("kernel patched 2026-05-01");
  });

  test("API: reviewer can reject with reason → rule stays open, approval row marked rejected", async ({
    request,
  }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);
    await setApprovalPolicy(request, "alice", assetId, true);
    await setUserRole("reviewer-bob", "reviewer");

    // Flip rule to 'open' so we can confirm it stays there after reject.
    await patchRule(request, "alice", checklistId, ruleId, {
      status: "open",
      findingDetails: "investigating",
      comments: "",
    });

    const submit = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_applicable",
      findingDetails: "this control does not apply to the host class",
      comments: "",
    });
    expect(submit.status()).toBe(202);
    const { approvalId } = await submit.json();

    const decide = await request.post(
      `${BACKEND}/api/approvals/${approvalId}/reject`,
      {
        headers: {
          "X-User-Id": "reviewer-bob",
          "Content-Type": "application/json",
        },
        data: { reason: "the control DOES apply — re-evaluate" },
      },
    );
    expect(decide.status()).toBe(200);
    const row = await decide.json();
    expect(row.status).toBe("rejected");
    expect(row.decisionReason).toBe("the control DOES apply — re-evaluate");

    const state = await getRuleState(request, "alice", checklistId, ruleId);
    expect(state.status).toBe("open");
  });

  test("API: non-reviewer cannot approve (403)", async ({ request }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);
    await setApprovalPolicy(request, "alice", assetId, true);
    await setUserRole("carol", "author");

    const submit = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "auto-remediated",
      comments: "",
    });
    expect(submit.status()).toBe(202);
    const { approvalId } = await submit.json();

    const decide = await request.post(
      `${BACKEND}/api/approvals/${approvalId}/approve`,
      {
        headers: {
          "X-User-Id": "carol",
          "Content-Type": "application/json",
        },
      },
    );
    expect(decide.status()).toBe(403);

    // And rejecting is also forbidden for non-reviewers.
    const rejectAttempt = await request.post(
      `${BACKEND}/api/approvals/${approvalId}/reject`,
      {
        headers: {
          "X-User-Id": "carol",
          "Content-Type": "application/json",
        },
        data: { reason: "nope" },
      },
    );
    expect(rejectAttempt.status()).toBe(403);
  });

  test("API: requester sees decisions bucket in notifications", async ({
    request,
  }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);
    await setApprovalPolicy(request, "alice", assetId, true);
    await setUserRole("reviewer-bob", "reviewer");

    const submit = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "verified",
      comments: "",
    });
    const { approvalId } = await submit.json();

    await request.post(`${BACKEND}/api/approvals/${approvalId}/approve`, {
      headers: {
        "X-User-Id": "reviewer-bob",
        "Content-Type": "application/json",
      },
    });

    const notif = await request
      .get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());

    expect(Array.isArray(notif.decisions)).toBe(true);
    expect(notif.decisions.length).toBe(1);
    expect(notif.decisions[0].status).toBe("approved");
    expect(notif.decisions[0].ruleId).toBe(ruleId);
    expect(notif.decisions[0].proposedStatus).toBe("not_a_finding");
    // Authors don't see the approvals bucket; only reviewers/admins do.
    expect(Array.isArray(notif.approvals)).toBe(true);
    expect(notif.approvals.length).toBe(0);
  });

  test("API: reviewer sees approvals bucket in notifications", async ({
    request,
  }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);
    await setApprovalPolicy(request, "alice", assetId, true);
    await setUserRole("reviewer-bob", "reviewer");

    await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "verified",
      comments: "",
    });

    const notif = await request
      .get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": "reviewer-bob" },
      })
      .then((r) => r.json());

    expect(Array.isArray(notif.approvals)).toBe(true);
    expect(notif.approvals.length).toBe(1);
    expect(notif.approvals[0].ruleId).toBe(ruleId);
    expect(notif.approvals[0].proposedStatus).toBe("not_a_finding");
    expect(notif.approvals[0].assetName).toBe("approval-host");
  });

  test("API: re-submitting a pending close is idempotent (no duplicate row)", async ({
    request,
  }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);
    await setApprovalPolicy(request, "alice", assetId, true);

    const first = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "first attempt",
      comments: "",
    });
    expect(first.status()).toBe(202);

    const second = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "second attempt",
      comments: "",
    });
    expect(second.status()).toBe(202);

    const own = await request
      .get(`${BACKEND}/api/approvals?status=pending`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(own.length).toBe(1);
  });

  test("API: rejecting without a reason → 400", async ({ request }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);
    await setApprovalPolicy(request, "alice", assetId, true);
    await setUserRole("reviewer-bob", "reviewer");

    const submit = await patchRule(request, "alice", checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "ok",
      comments: "",
    });
    const { approvalId } = await submit.json();

    const res = await request.post(
      `${BACKEND}/api/approvals/${approvalId}/reject`,
      {
        headers: {
          "X-User-Id": "reviewer-bob",
          "Content-Type": "application/json",
        },
        data: { reason: "   " },
      },
    );
    expect(res.status()).toBe(400);
  });

  test("UI: toggle the require-approval policy, close a finding, see Submitted for review", async ({
    page,
    request,
  }) => {
    const { assetId } = await seedChecklist(request);
    await loginAs(page, "alice");
    await page.goto("/");

    // Drill into the asset and flip the toggle on.
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "approval-host" }).click();
    await expect(page.getByText("Applied STIGs")).toBeVisible();

    const toggleScope = page.getByTestId("approval-policy-toggle");
    await expect(toggleScope).toBeVisible();
    await toggleScope.click();

    // Confirm via API the flag actually flipped before driving the UI.
    await expect
      .poll(
        async () => {
          const a = await request
            .get(`${BACKEND}/api/assets/${assetId}`, {
              headers: { "X-User-Id": "alice" },
            })
            .then((r) => r.json());
          return a.requiresApproval;
        },
        { timeout: 5_000 },
      )
      .toBe(true);

    // Open the checklist and the first rule's editor.
    const stigLink = page.locator("table").last().getByRole("button").first();
    await stigLink.click();
    await expect(page.getByRole("heading", { name: /^Rules/ })).toBeVisible({
      timeout: 10_000,
    });
    await page.locator("table").last().getByRole("button").first().click();
    const editModal = page.getByRole("dialog").last();
    await expect(editModal).toBeVisible();

    // Switch to not-a-finding + justification + save → expect the
    // submitted-for-review alert instead of the modal closing.
    await editModal.getByRole("radio", { name: "Not a finding" }).click();
    await editModal
      .getByRole("textbox", { name: /finding details/i })
      .fill("patched per vendor advisory");
    await editModal
      .getByRole("button", { name: "Save", exact: true })
      .click();

    await expect(
      editModal.getByTestId("pending-approval-alert"),
    ).toBeVisible({ timeout: 10_000 });
  });
});
