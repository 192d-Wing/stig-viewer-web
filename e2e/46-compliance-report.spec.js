import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

async function runReport(request, rangeDays = 7) {
  const res = await request.post(`${BACKEND}/api/test/run-report`, {
    headers: { "Content-Type": "application/json" },
    data: { range_days: rangeDays },
  });
  if (!res.ok()) throw new Error(`run-report failed: ${res.status()}`);
  return res.json();
}

test.describe("Continuous compliance report", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: run-report writes a row, list returns it, PDF downloads", async ({
    request,
  }) => {
    // Seed an asset with a checklist so the summary has real numbers.
    const asset = await (
      await request.post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "report-host", classification: "secret" },
      })
    ).json();
    await request.post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    });

    const generated = await runReport(request, 30);
    expect(generated.id).toBeTruthy();
    expect(generated.pdfPath).toMatch(/^compliance_reports\/.+\.pdf$/);

    // List endpoint includes the new row.
    const list = await (
      await request.get(`${BACKEND}/api/reports`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    const row = list.find((r) => r.id === generated.id);
    expect(row).toBeTruthy();
    expect(row.summary.assets).toBeGreaterThan(0);
    expect(row.summary.complianceScore).toBeGreaterThanOrEqual(0);

    // PDF endpoint streams a valid PDF.
    const pdf = await request.get(
      `${BACKEND}/api/reports/${generated.id}/report.pdf`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(pdf.status()).toBe(200);
    expect(pdf.headers()["content-type"]).toContain("application/pdf");
    const body = await pdf.body();
    expect(body.length).toBeGreaterThan(500);
    // Magic bytes: %PDF
    expect(body.subarray(0, 4).toString("ascii")).toBe("%PDF");
  });

  test("API: 404 on unknown report id", async ({ request }) => {
    const res = await request.get(
      `${BACKEND}/api/reports/does-not-exist/report.pdf`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(404);
  });

  test("API: generation fires the compliance_report webhook", async ({
    request,
  }) => {
    // Set up an admin so we can configure a webhook.
    await setUserRole("alice", "admin");
    const hook = await (
      await request.post(`${BACKEND}/api/webhooks`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: {
          name: "compliance",
          url: "http://127.0.0.1:1/compliance",
          kinds: ["compliance_report"],
        },
      })
    ).json();
    expect(hook.id).toBeTruthy();

    await runReport(request, 7);

    // Fan-out is fire-and-forget via tokio::spawn; poll briefly.
    let rows = [];
    for (let i = 0; i < 10; i += 1) {
      rows = await (
        await request.get(`${BACKEND}/api/webhooks/${hook.id}/deliveries`, {
          headers: { "X-User-Id": "alice" },
        })
      ).json();
      if (rows.length > 0) break;
      await new Promise((r) => setTimeout(r, 200));
    }
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].kind).toBe("compliance_report");
    // 127.0.0.1:1 is intentionally unroutable so we expect an error,
    // not an http_status.
    expect(rows[0].error || rows[0].response).toBeTruthy();
  });

  test("API: kinds=['compliance_report'] passes the kinds validation", async ({
    request,
  }) => {
    await setUserRole("alice", "admin");
    const res = await request.post(`${BACKEND}/api/webhooks`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        name: "ok",
        url: "http://127.0.0.1:1/x",
        kinds: ["compliance_report"],
      },
    });
    expect(res.ok()).toBeTruthy();
  });

  test("UI: admin console lists the report with a PDF download link", async ({
    page,
    request,
  }) => {
    await setUserRole("alice", "admin");
    await runReport(request, 7);

    await loginAs(page, "alice");
    await page.goto("/?view=admin");

    await expect(
      page.getByRole("heading", { name: /^Compliance reports/ }),
    ).toBeVisible();
    // PDF download button is present.
    await expect(page.getByRole("link", { name: /PDF/i }).first()).toBeVisible();
  });
});
