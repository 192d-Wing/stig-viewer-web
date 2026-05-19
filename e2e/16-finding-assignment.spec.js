import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

// Seed alice's asset + checklist + first rule opened, assigned to bob, due 2026-12-31.
async function seedAssignedToBob(request) {
  // Make sure bob exists (auto-creates on first API call as bob).
  const bob = await request
    .get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "bob" } })
    .then((r) => r.json());

  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "asn-host" },
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
  const ruleId = detail.rules[0].id;
  await request.patch(
    `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        status: "open",
        assigneeId: bob.id,
        dueDate: "2026-12-31",
      },
    },
  );
  return { ruleId, bobId: bob.id };
}

test.describe("Finding assignment + due date", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("drill-down shows Assignee and Due columns; 'Mine only' filters to current user", async ({
    page,
    request,
  }) => {
    await seedAssignedToBob(request);

    // View as bob — Mine only should show the seeded finding (assigned to bob).
    await loginAs(page, "bob");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: /view details/i }).click();

    // Wait for the drill-down to render the seeded row.
    await expect(page.getByText("asn-host").first()).toBeVisible({
      timeout: 10_000,
    });

    // Assignee column shows "bob" and Due shows "2026-12-31".
    await expect(page.getByText("2026-12-31").first()).toBeVisible();

    // Toggle "Mine only" — bob is the assignee, the row stays.
    await page.getByText("Mine only").click();
    await expect(page.getByText("asn-host").first()).toBeVisible();
  });

  test("as a different user, 'Mine only' yields no rows", async ({
    page,
    request,
  }) => {
    await seedAssignedToBob(request);

    // View as carol — Mine only should be empty (no assigned findings).
    await loginAs(page, "carol");
    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: /view details/i }).click();

    // Without filter — drill-down shows the seeded row.
    await expect(page.getByText("asn-host").first()).toBeVisible({
      timeout: 10_000,
    });

    // With "Mine only" — carol has no assignments → drill-down empties.
    // The per-asset summary table above still shows asn-host (it's not
    // filtered), so we assert on the drill-down's counter going to (0).
    await page.getByText("Mine only").click();
    await expect(
      page.getByRole("heading", { name: /^Open findings \(0\)/ }),
    ).toBeVisible({ timeout: 5_000 });
  });
});
