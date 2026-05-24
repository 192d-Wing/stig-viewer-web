import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function seedAssets(request) {
  const mk = async (name, tags) =>
    (
      await request.post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name, tags },
      })
    ).json();
  const web = await mk("web-1", ["prod", "public"]);
  const db = await mk("db-1", ["prod", "pii"]);
  const dev = await mk("dev-1", ["dev"]);
  return { web, db, dev };
}

test.describe("Tag filtering & grouping", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("Systems table filters by ?tag= chip and AND-combines multiple tags", async ({
    page,
    request,
  }) => {
    await seedAssets(request);

    await page.goto("/?view=systems");

    // All three rows visible initially.
    await expect(page.getByRole("button", { name: "web-1" })).toBeVisible();
    await expect(page.getByRole("button", { name: "db-1" })).toBeVisible();
    await expect(page.getByRole("button", { name: "dev-1" })).toBeVisible();

    // Click "prod" chip — web and db remain, dev is filtered out.
    await page.getByRole("button", { name: "prod", exact: true }).click();
    await expect(page).toHaveURL(/[?&]tag=prod\b/);
    await expect(page.getByRole("button", { name: "web-1" })).toBeVisible();
    await expect(page.getByRole("button", { name: "db-1" })).toBeVisible();
    await expect(page.getByRole("button", { name: "dev-1" })).toHaveCount(0);

    // Add "pii" — only db remains (AND).
    await page.getByRole("button", { name: "pii", exact: true }).click();
    await expect(page).toHaveURL(/[?&]tag=prod%2Cpii\b/);
    await expect(page.getByRole("button", { name: "db-1" })).toBeVisible();
    await expect(page.getByRole("button", { name: "web-1" })).toHaveCount(0);

    // Clear restores all three.
    await page.getByRole("button", { name: "Clear", exact: true }).click();
    await expect(page).not.toHaveURL(/[?&]tag=/);
    await expect(page.getByRole("button", { name: "dev-1" })).toBeVisible();
  });

  test("Deep link with ?view=systems&tag=prod filters on load", async ({
    page,
    request,
  }) => {
    await seedAssets(request);
    await page.goto("/?view=systems&tag=prod");
    await expect(page.getByRole("button", { name: "web-1" })).toBeVisible();
    await expect(page.getByRole("button", { name: "dev-1" })).toHaveCount(0);
  });

  test("Dashboard heatmap toggle groups rows by tag", async ({
    page,
    request,
  }) => {
    const { web } = await seedAssets(request);
    // Apply a STIG to one asset so the heatmap renders.
    const checklist = await request
      .post(`${BACKEND}/api/assets/${web.id}/checklists`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { stigId: "edge" },
      })
      .then((r) => r.json());
    expect(checklist.id).toBeTruthy();

    await page.goto("/?view=dashboard");

    // Heatmap is visible.
    await expect(
      page.getByRole("heading", { name: /posture heatmap/i }),
    ).toBeVisible();
    // Flat mode shows the asset row (web-1 visible somewhere).
    await expect(page.getByText("web-1", { exact: true }).first()).toBeVisible();

    // Toggle group-by-tag.
    const toggle = page.getByRole("checkbox", { name: /group by tag/i });
    await toggle.click();
    await expect(page).toHaveURL(/[?&]grpTag=true\b/);

    // Now the row labels are tags. Use .first() because chips may also
    // appear in the per-asset table.
    await expect(page.getByText("prod", { exact: true }).first()).toBeVisible();
    await expect(
      page.getByText("public", { exact: true }).first(),
    ).toBeVisible();
  });

  test("Deep link ?view=dashboard&grpTag=true starts in group-by-tag mode", async ({
    page,
    request,
  }) => {
    const { web } = await seedAssets(request);
    await request.post(`${BACKEND}/api/assets/${web.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    });

    await page.goto("/?view=dashboard&grpTag=true");
    await expect(
      page.getByRole("checkbox", { name: /group by tag/i }),
    ).toBeChecked();
  });
});
