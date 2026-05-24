import { test, expect } from "@playwright/test";
import {
  loginAs,
  resetDb,
  createDraftViaApi,
  transitionDraft,
  setUserRole,
  BACKEND,
} from "./helpers.js";

// `X-User-Id` is just an auto-create handle; the real `user_id` is the
// UUID the server generates on first contact. Resolve via /api/users/me
// before we ever set assignedReviewerId.
async function whoAmI(request, handle) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": handle },
  });
  if (!res.ok()) {
    throw new Error(`/api/users/me as ${handle} failed: ${res.status()}`);
  }
  return res.json();
}

async function submitWith(request, handle, draftId, body) {
  return request.post(`${BACKEND}/api/drafts/${draftId}/submit`, {
    headers: { "X-User-Id": handle, "Content-Type": "application/json" },
    data: body ?? {},
  });
}

async function approveAs(request, handle, draftId, body = {}) {
  return request.post(`${BACKEND}/api/drafts/${draftId}/approve`, {
    headers: { "X-User-Id": handle, "Content-Type": "application/json" },
    data: body,
  });
}

test.describe("Draft reviewer assignment", () => {
  const ALICE = "dr-alice";
  const BOB = "dr-bob";
  const CHARLIE = "dr-charlie";
  const DENISE = "dr-denise"; // admin
  const FRANK = "dr-frank"; // author/viewer — invalid reviewer

  test.beforeEach(async () => {
    await resetDb();
    // Seed roles. Alice is the author by default; bob/charlie are
    // reviewers; denise is admin; frank stays an author so we can
    // exercise the "invalid reviewer role" path.
    await setUserRole(BOB, "reviewer");
    await setUserRole(CHARLIE, "reviewer");
    await setUserRole(DENISE, "admin");
    await setUserRole(FRANK, "author");
  });

  test("API: alice submits with bob assigned; list reflects it", async ({
    request,
  }) => {
    const bob = await whoAmI(request, BOB);
    const draft = await createDraftViaApi(ALICE, "Assigned to Bob");

    const submitRes = await submitWith(request, ALICE, draft.id, {
      assignedReviewerId: bob.id,
    });
    expect(submitRes.status()).toBe(200);
    const submitBody = await submitRes.json();
    expect(submitBody.status).toBe("submitted");
    expect(submitBody.assignedReviewerId).toBe(bob.id);

    const list = await request
      .get(`${BACKEND}/api/drafts`, { headers: { "X-User-Id": ALICE } })
      .then((r) => r.json());
    const row = list.find((d) => d.id === draft.id);
    expect(row).toBeTruthy();
    expect(row.assignedReviewerId).toBe(bob.id);
    expect(row.assignedReviewerName).toBeTruthy();
  });

  test("API: non-assignee reviewer charlie cannot approve (403)", async ({
    request,
  }) => {
    const bob = await whoAmI(request, BOB);
    const draft = await createDraftViaApi(ALICE, "Charlie Forbidden");
    const submit = await submitWith(request, ALICE, draft.id, {
      assignedReviewerId: bob.id,
    });
    expect(submit.status()).toBe(200);

    const res = await approveAs(request, CHARLIE, draft.id, {
      comment: "trying",
    });
    expect(res.status()).toBe(403);
    const body = await res.json();
    expect(body.error).toMatch(/assigned to a specific reviewer/i);
  });

  test("API: assignee bob can approve (200)", async ({ request }) => {
    const bob = await whoAmI(request, BOB);
    const draft = await createDraftViaApi(ALICE, "Bob Approves");
    await submitWith(request, ALICE, draft.id, {
      assignedReviewerId: bob.id,
    });

    const res = await approveAs(request, BOB, draft.id, {
      comment: "lgtm",
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("approved");
  });

  test("API: admin denise can approve even when draft is assigned to bob", async ({
    request,
  }) => {
    const bob = await whoAmI(request, BOB);
    const draft = await createDraftViaApi(ALICE, "Admin Override");
    await submitWith(request, ALICE, draft.id, {
      assignedReviewerId: bob.id,
    });

    const res = await approveAs(request, DENISE, draft.id);
    expect(res.status()).toBe(200);
  });

  test("API: submitting with a non-reviewer assignee returns 400", async ({
    request,
  }) => {
    const frank = await whoAmI(request, FRANK);
    const draft = await createDraftViaApi(ALICE, "Bad Assignment");

    const res = await submitWith(request, ALICE, draft.id, {
      assignedReviewerId: frank.id,
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/reviewer or admin/i);
  });

  test("API: /api/drafts/pending-for-me filters by assigned reviewer", async ({
    request,
  }) => {
    const bob = await whoAmI(request, BOB);
    const draft = await createDraftViaApi(ALICE, "Pending For Bob");
    await submitWith(request, ALICE, draft.id, {
      assignedReviewerId: bob.id,
    });

    const bobPending = await request
      .get(`${BACKEND}/api/drafts/pending-for-me`, {
        headers: { "X-User-Id": BOB },
      })
      .then((r) => r.json());
    expect(bobPending.find((d) => d.id === draft.id)).toBeTruthy();

    const charliePending = await request
      .get(`${BACKEND}/api/drafts/pending-for-me`, {
        headers: { "X-User-Id": CHARLIE },
      })
      .then((r) => r.json());
    expect(charliePending.find((d) => d.id === draft.id)).toBeFalsy();
  });

  test("API: notifications include the draft for bob, not for alice", async ({
    request,
  }) => {
    const bob = await whoAmI(request, BOB);
    const draft = await createDraftViaApi(ALICE, "Notify Bob");
    await submitWith(request, ALICE, draft.id, {
      assignedReviewerId: bob.id,
    });

    const bobNotif = await request
      .get(`${BACKEND}/api/notifications`, { headers: { "X-User-Id": BOB } })
      .then((r) => r.json());
    expect(bobNotif.assignedDrafts).toBeTruthy();
    expect(
      bobNotif.assignedDrafts.find((d) => d.draftId === draft.id),
    ).toBeTruthy();
    // The unread counter should include the assigned draft.
    expect(bobNotif.unreadCount).toBeGreaterThan(0);

    const aliceNotif = await request
      .get(`${BACKEND}/api/notifications`, {
        headers: { "X-User-Id": ALICE },
      })
      .then((r) => r.json());
    expect(
      (aliceNotif.assignedDrafts ?? []).find((d) => d.draftId === draft.id),
    ).toBeFalsy();
  });

  test("UI: alice submits with bob; bob sees Drafts waiting on you in the bell", async ({
    page,
    request,
  }) => {
    // Ensure bob's user row exists so /api/users surfaces him.
    await whoAmI(request, BOB);

    const draft = await createDraftViaApi(ALICE, "UI Reviewer Path");

    await loginAs(page, ALICE);
    await page.goto("/");
    await page.getByRole("button", { name: "Writer" }).click();
    await expect(
      page.getByRole("button", { name: "Open" }).first(),
    ).toBeVisible();
    await page.getByRole("button", { name: "Open" }).first().click();
    await expect(page.getByRole("button", { name: /back/i })).toBeVisible();

    // Open the submit modal and pick bob.
    await page
      .getByRole("button", { name: /submit for review/i })
      .click();

    const reviewerSelect = page.getByTestId("reviewer-select");
    await reviewerSelect.click();
    await page.getByRole("option", { name: new RegExp(`^${BOB}$`, "i") }).click();

    await page.getByTestId("confirm-submit").click();

    // Status badge flips to Submitted.
    await expect(page.getByText("Submitted", { exact: true })).toBeVisible();

    // Now log in as bob and pop the bell.
    await page.context().clearCookies();
    await loginAs(page, BOB);
    await page.goto("/");

    // Wait for notifications poll, then click the bell utility. The
    // button text contains "Notifications" possibly with a counter.
    const bellBtn = page.getByRole("button", { name: /^notifications/i });
    await expect(bellBtn).toBeVisible({ timeout: 15_000 });
    await bellBtn.click();

    // Modal opens with the "Drafts waiting on you" section.
    const draftsList = page.getByTestId("assigned-drafts-list");
    await expect(draftsList).toBeVisible({ timeout: 10_000 });
    // List renders the draft title; assert on that, not on the UUID.
    await expect(draftsList).toContainText("UI Reviewer Path");
    void draft; // satisfy linters that flag unused locals
  });
});
