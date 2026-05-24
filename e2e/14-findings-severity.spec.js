import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

// Seed N rules at mixed severities — uses windows-10 since it has CAT I/II/III mix.
async function seedMixedSeverities(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "sev-host" },
    })
    .then((r) => r.json());
  const checklist = await request
    .post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "windows-10" },
    })
    .then((r) => r.json());
  const detail = await request
    .get(`${BACKEND}/api/checklists/${checklist.id}`, {
      headers: { "X-User-Id": "alice" },
    })
    .then((r) => r.json());

  // Open the first 10 rules — windows-10's first dozen mix CAT I/II/III.
  const seeded = [];
  for (let i = 0; i < 10; i++) {
    const r = detail.rules[i];
    await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(r.id)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open" },
      },
    );
    seeded.push({ id: r.id, severity: r.severity });
  }
  return seeded;
}

test.describe("Findings severity column + filter", () => {
  test.beforeEach(async ({ page }) => {
    await resetDb();
    await loginAs(page, "alice");
  });

  test("drill-down shows severity badges and filtering narrows the rows", async ({
    page,
    request,
  }) => {
    const seeded = await seedMixedSeverities(request);
    const catICount = seeded.filter((r) => r.severity === "CAT I").length;
    expect(catICount).toBeGreaterThan(0); // sanity: windows-10 has CAT I rules

    await page.goto("/");
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: /view details/i }).click();

    // All 10 findings visible, severity column shows badges
    await expect(
      page.getByRole("heading", { name: /^Open findings/ }),
    ).toBeVisible();
    await expect(page.getByText("(10)").first()).toBeVisible();
    // At least one severity badge visible
    await expect(page.getByText("CAT II").first()).toBeVisible();

    // Filter to CAT I
    await page
      .getByRole("button", { name: /all severities/i })
      .click();
    await page.getByRole("option", { name: "CAT I", exact: true }).click();

    // Count should drop to catICount
    await expect(
      page.getByText(`(${catICount})`).first(),
    ).toBeVisible({ timeout: 5_000 });
  });
});
