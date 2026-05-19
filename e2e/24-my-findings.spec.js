import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

function isoDateOffset(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

// Seed three open findings assigned to bob with different due dates:
//   r0: due yesterday → Overdue
//   r1: due in 3 days → Due soon
//   r2: due in 60 days → Open (no urgent due)
async function seedThreeBuckets(request) {
  const bob = await request
    .get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "bob" } })
    .then((r) => r.json());

  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "mf-host" },
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

  const dues = [isoDateOffset(-1), isoDateOffset(3), isoDateOffset(60)];
  for (let i = 0; i < 3; i++) {
    await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(detail.rules[i].id)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: {
          status: "open",
          assigneeId: bob.id,
          dueDate: dues[i],
        },
      },
    );
  }
}

test.describe("My Findings workspace", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("empty state when nothing is assigned", async ({ page }) => {
    await loginAs(page, "alice");
    await page.goto("/");
    await page
      .getByRole("button", { name: "My findings", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: /^My findings/i }),
    ).toBeVisible();
    await expect(
      page.getByText(/Nothing assigned to you right now/i),
    ).toBeVisible();
  });

  test("buckets render based on due-date proximity", async ({
    page,
    request,
  }) => {
    await seedThreeBuckets(request);
    await loginAs(page, "bob");
    await page.goto("/");
    await page
      .getByRole("button", { name: "My findings", exact: true })
      .click();

    // All three bucket labels visible.
    await expect(
      page.getByRole("heading", { name: /Overdue/ }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(
      page.getByRole("heading", { name: /Due in the next 7 days/ }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: /Open \(no urgent due\)/ }),
    ).toBeVisible();
  });

  test("a different user sees only their own findings", async ({
    page,
    request,
  }) => {
    await seedThreeBuckets(request);

    // Carol has nothing assigned — empty state.
    await loginAs(page, "carol");
    await page.goto("/");
    await page
      .getByRole("button", { name: "My findings", exact: true })
      .click();
    await expect(
      page.getByText(/Nothing assigned to you right now/i),
    ).toBeVisible({ timeout: 10_000 });
  });
});
