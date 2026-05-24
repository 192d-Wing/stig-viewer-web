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

async function listEmailDeliveries(request, userId) {
  return (
    await request.get(`${BACKEND}/api/admin/email-deliveries`, {
      headers: { "X-User-Id": userId },
    })
  ).json();
}

test.describe("Compliance report email delivery", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API (admin): run-report writes a mode='dryrun' email row with the correct subject + attachment", async ({
    request,
  }) => {
    await setUserRole("alice", "admin");

    // Seed an asset + checklist so the summary has real numbers.
    const asset = await (
      await request.post(`${BACKEND}/api/assets`, {
        headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
        data: { name: "email-host", classification: "secret" },
      })
    ).json();
    await request.post(`${BACKEND}/api/assets/${asset.id}/checklists`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { stigId: "edge" },
    });

    const generated = await runReport(request, 7);
    expect(generated.id).toBeTruthy();

    const rows = await listEmailDeliveries(request, "alice");
    // The new dryrun row is the most recent.
    expect(rows.length).toBeGreaterThan(0);
    const row = rows[0];
    expect(row.kind).toBe("compliance_report");
    expect(row.mode).toBe("dryrun");
    expect(row.error).toBeNull();
    // Subject format: "Fleet compliance report — N.N% compliant"
    expect(row.subject).toMatch(
      /^Fleet compliance report — \d+(\.\d+)?% compliant$/,
    );
    // Attachment path matches the PDF path on disk.
    expect(row.attached).toBe(generated.pdfPath);
    expect(row.attached).toMatch(/^compliance_reports\/.+\.pdf$/);
    // Body snippet includes the human-readable summary.
    expect(row.bodySnippet).toContain("Fleet compliance report");
  });

  test("API: non-admin GET /api/admin/email-deliveries returns 403", async ({
    request,
  }) => {
    await setUserRole("bob", "author");
    const res = await request.get(`${BACKEND}/api/admin/email-deliveries`, {
      headers: { "X-User-Id": "bob" },
    });
    expect(res.status()).toBe(403);
  });

  test("API (admin): with no SMTP env vars set, to_addresses is empty and mode is dryrun", async ({
    request,
  }) => {
    await setUserRole("alice", "admin");

    // No COMPLIANCE_REPORT_RECIPIENTS in the running backend — we can't
    // mutate env from the test, so just assert the default-empty case.
    await runReport(request, 7);

    const rows = await listEmailDeliveries(request, "alice");
    expect(rows.length).toBeGreaterThan(0);
    const row = rows[0];
    expect(row.mode).toBe("dryrun");
    expect(row.toAddresses).toBe("");
  });

  test("UI: admin console renders the Email deliveries table with the dryrun row", async ({
    page,
    request,
  }) => {
    await setUserRole("alice", "admin");
    await runReport(request, 7);

    await loginAs(page, "alice");
    await page.goto("/?view=admin");

    await expect(
      page.getByRole("heading", { name: /^Email deliveries/ }),
    ).toBeVisible();
    // The dryrun badge for the freshly-inserted row should be visible.
    await expect(page.getByText("dryrun").first()).toBeVisible();
    // Subject text shows up too.
    await expect(
      page.getByText(/Fleet compliance report — /).first(),
    ).toBeVisible();
  });
});
