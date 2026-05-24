import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Seed an asset + checklist owned by `alice` and return the first rule id.
 * The rule starts at the default `not_reviewed` state with no overrides.
 */
async function seedChecklist(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "gate-host" },
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
  return { checklistId: checklist.id, ruleId: detail.rules[0].id };
}

async function patchRule(request, checklistId, ruleId, data) {
  return request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data,
    },
  );
}

async function getRuleState(request, checklistId, ruleId) {
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklistId}`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());
  const rule = detail.rules.find((r) => r.id === ruleId);
  return rule?.state ?? {};
}

test.describe("Compliance gate — finding_details required for closing status", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: not_a_finding with empty findingDetails → 400 and rule unchanged", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await patchRule(request, checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "",
      comments: "",
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe(
      "finding_details required for status not_a_finding",
    );

    // No override was written — the merged state has no status override.
    // (Rules without overrides report status: "not_reviewed".)
    const state = await getRuleState(request, checklistId, ruleId);
    expect(state.status ?? "not_reviewed").toBe("not_reviewed");
  });

  test("API: not_applicable with whitespace-only findingDetails → 400", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await patchRule(request, checklistId, ruleId, {
      status: "not_applicable",
      findingDetails: "   \n\t  ",
      comments: "",
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe(
      "finding_details required for status not_applicable",
    );

    const state = await getRuleState(request, checklistId, ruleId);
    expect(state.status ?? "not_reviewed").toBe("not_reviewed");
  });

  test("API: not_a_finding with a justification → 200 and status updated", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await patchRule(request, checklistId, ruleId, {
      status: "not_a_finding",
      findingDetails: "compensating control documented in ticket #123",
      comments: "",
    });
    expect(res.status()).toBe(200);

    const state = await getRuleState(request, checklistId, ruleId);
    expect(state.status).toBe("not_a_finding");
    expect(state.findingDetails).toBe(
      "compensating control documented in ticket #123",
    );
  });

  test("API: open with empty findingDetails → 200 (gate does not apply)", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await patchRule(request, checklistId, ruleId, {
      status: "open",
      findingDetails: "",
      comments: "",
    });
    expect(res.status()).toBe(200);

    const state = await getRuleState(request, checklistId, ruleId);
    expect(state.status).toBe("open");
  });

  test("API: not_reviewed with empty findingDetails → 200", async ({
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    // First flip to `open` so an override row actually exists, then back to
    // `not_reviewed` to exercise the path with an explicit empty body.
    let res = await patchRule(request, checklistId, ruleId, {
      status: "open",
      findingDetails: "investigating",
      comments: "",
    });
    expect(res.status()).toBe(200);

    res = await patchRule(request, checklistId, ruleId, {
      status: "not_reviewed",
      findingDetails: "",
      comments: "",
    });
    expect(res.status()).toBe(200);

    const state = await getRuleState(request, checklistId, ruleId);
    expect(state.status).toBe("not_reviewed");
  });

  test("UI: editor shows inline error and disables Save until justification entered", async ({
    page,
    request,
  }) => {
    await seedChecklist(request);
    await loginAs(page, "alice");
    await page.goto("/");

    // Navigate from the dashboard/library into the seeded asset → STIG.
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "gate-host" }).click();
    await expect(page.getByText("Applied STIGs")).toBeVisible();

    // Open the checklist (single STIG, single button in the Applied STIGs
    // table — scope by accessible name so the new Sharing table on
    // AssetDetail doesn't shadow this selector).
    const stigLink = page
      .getByRole("table", { name: /Applied STIGs/i })
      .getByRole("button")
      .first();
    await stigLink.click();
    await expect(page.getByRole("heading", { name: /^Rules/ })).toBeVisible({
      timeout: 10_000,
    });

    // Open the rule editor for the first rule.
    await page
      .getByRole("table", { name: /Rules/i })
      .getByRole("button")
      .first()
      .click();
    const editModal = page.getByRole("dialog").last();
    await expect(editModal).toBeVisible();

    // Switch status to "Not a finding" — inline error appears, Save disabled.
    await editModal.getByRole("radio", { name: "Not a finding" }).click();
    await expect(
      editModal.getByText("Required when closing this finding."),
    ).toBeVisible();
    const saveBtn = editModal.getByRole("button", { name: "Save", exact: true });
    await expect(saveBtn).toBeDisabled();

    // Type a justification — error clears, Save enabled, modal closes after save.
    await editModal
      .getByRole("textbox", { name: /finding details/i })
      .fill("compensating control documented in ticket #123");
    await expect(
      editModal.getByText("Required when closing this finding."),
    ).toBeHidden();
    await expect(saveBtn).toBeEnabled();
    await saveBtn.click();
    await expect(editModal).toBeHidden({ timeout: 15_000 });
  });
});
