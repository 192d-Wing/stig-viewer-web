import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

test.describe("PDF report", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("endpoint returns a valid PDF for an asset with no checklists", async ({
    request,
  }) => {
    const asset = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "pdf-host-empty" },
      })
      .then((r) => r.json());

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/report.pdf`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toBe("application/pdf");
    expect(res.headers()["content-disposition"]).toContain(
      "pdf-host-empty-stig-report.pdf",
    );

    const body = await res.body();
    expect(body.length).toBeGreaterThan(500);
    // PDF magic header
    expect(body.subarray(0, 5).toString()).toBe("%PDF-");
  });

  test("PDF reflects an applied STIG and an open finding", async ({
    request,
  }) => {
    const asset = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "pdf-host-full" },
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
    await request.patch(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(detail.rules[0].id)}`,
      {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { status: "open", findingDetails: "smoke-test finding" },
      },
    );

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/report.pdf`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.body();
    // Larger than the empty-checklists report (which is ~2-3KB); a full
    // edge STIG with 59 rules should be in the tens of KB.
    expect(body.length).toBeGreaterThan(5_000);
    expect(body.subarray(0, 5).toString()).toBe("%PDF-");
  });

  test("AssetDetail page exposes a Download PDF report button", async ({
    page,
    request,
  }) => {
    await loginAs(page, "alice");
    const asset = await request
      .post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "pdf-host-ui" },
      })
      .then((r) => r.json());

    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "pdf-host-ui" }).click();

    const btn = page.getByRole("link", { name: /download pdf report/i });
    await expect(btn).toBeVisible();
    // The link points at the backend's report endpoint
    await expect(btn).toHaveAttribute(
      "href",
      new RegExp(`/api/assets/${asset.id}/report\\.pdf`),
    );
  });
});
