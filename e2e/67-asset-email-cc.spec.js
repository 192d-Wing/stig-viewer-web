import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Per-asset compliance-report email CC list + on-demand send.
 *
 * The asset owner (or anyone with write/admin ACL) curates a small
 * list of extra addresses that receive the per-asset compliance PDF
 * when "Email report now" is clicked. Send is synchronous; the audit
 * row in `email_deliveries` lets us confirm the path fired even when
 * SMTP isn't configured (the default in CI — mode='dryrun').
 */

async function seedAsset(request, owner = "alice", name = "email-cc-host") {
  const r = await request.post(`${BACKEND}/api/assets`, {
    headers: { "X-User-Id": owner, "Content-Type": "application/json" },
    data: { name },
  });
  if (!r.ok()) throw new Error(`seedAsset failed: ${r.status()}`);
  return r.json();
}

async function listCc(request, asUser, assetId) {
  return request.get(`${BACKEND}/api/assets/${assetId}/email-cc`, {
    headers: { "X-User-Id": asUser },
  });
}

async function addCc(request, asUser, assetId, email) {
  return request.post(`${BACKEND}/api/assets/${assetId}/email-cc`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data: { email },
  });
}

async function removeCc(request, asUser, assetId, email) {
  return request.delete(
    `${BACKEND}/api/assets/${assetId}/email-cc/${encodeURIComponent(email)}`,
    { headers: { "X-User-Id": asUser } },
  );
}

async function emailReport(request, asUser, assetId) {
  return request.post(`${BACKEND}/api/assets/${assetId}/email-report`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data: {},
  });
}

async function latestDeliveries(request) {
  // The admin role is needed to read email_deliveries; alice is upgraded
  // via setUserRole in the test that needs it.
  return (
    await request.get(`${BACKEND}/api/admin/email-deliveries`, {
      headers: { "X-User-Id": "alice" },
    })
  ).json();
}

test.describe("Per-asset compliance email CC", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: owner lists empty CC → 200, []", async ({ request }) => {
    const asset = await seedAsset(request);
    const res = await listCc(request, "alice", asset.id);
    expect(res.status()).toBe(200);
    expect(await res.json()).toEqual([]);
  });

  test("API: owner adds a CC, GET reflects it", async ({ request }) => {
    const asset = await seedAsset(request);
    const add = await addCc(request, "alice", asset.id, "ops@example.gov");
    expect(add.status()).toBe(200);
    const rows = await (await listCc(request, "alice", asset.id)).json();
    expect(rows).toHaveLength(1);
    expect(rows[0].email).toBe("ops@example.gov");
  });

  test("API: duplicate POST is idempotent", async ({ request }) => {
    const asset = await seedAsset(request);
    expect((await addCc(request, "alice", asset.id, "ops@example.gov")).status()).toBe(200);
    const second = await addCc(request, "alice", asset.id, "ops@example.gov");
    expect(second.status()).toBe(200);
    const rows = await (await listCc(request, "alice", asset.id)).json();
    expect(rows).toHaveLength(1);
  });

  test("API: invalid email body → 400", async ({ request }) => {
    const asset = await seedAsset(request);
    expect((await addCc(request, "alice", asset.id, "")).status()).toBe(400);
    expect((await addCc(request, "alice", asset.id, "no-at-sign")).status()).toBe(400);
    expect((await addCc(request, "alice", asset.id, "missing@tld")).status()).toBe(400);
  });

  test("API: non-owner POST → 403", async ({ request }) => {
    const asset = await seedAsset(request);
    const res = await addCc(request, "bob", asset.id, "ops@example.gov");
    expect(res.status()).toBe(403);
  });

  test("API: DELETE removes a row", async ({ request }) => {
    const asset = await seedAsset(request);
    expect((await addCc(request, "alice", asset.id, "ops@example.gov")).status()).toBe(200);
    const del = await removeCc(request, "alice", asset.id, "ops@example.gov");
    expect(del.status()).toBe(204);
    const rows = await (await listCc(request, "alice", asset.id)).json();
    expect(rows).toHaveLength(0);
  });

  test("API: email-report writes a dryrun row with kind=asset_report and CCs in to_addresses", async ({
    request,
  }) => {
    // Need admin to read email_deliveries; alice owns the asset AND is
    // bumped to admin so we can verify the audit row directly.
    await setUserRole("alice", "admin");
    const asset = await seedAsset(request);
    expect((await addCc(request, "alice", asset.id, "ops@example.gov")).status()).toBe(200);
    expect((await addCc(request, "alice", asset.id, "secops@example.gov")).status()).toBe(200);

    const send = await emailReport(request, "alice", asset.id);
    expect(send.status()).toBe(200);
    const body = await send.json();
    expect(body.mode).toBe("dryrun");
    expect(body.recipients).toEqual(
      expect.arrayContaining(["ops@example.gov", "secops@example.gov"]),
    );

    const rows = await latestDeliveries(request);
    const asset_row = rows.find((r) => r.kind === "asset_report");
    expect(asset_row).toBeTruthy();
    expect(asset_row.mode).toBe("dryrun");
    expect(asset_row.toAddresses).toContain("ops@example.gov");
    expect(asset_row.toAddresses).toContain("secops@example.gov");
    expect(asset_row.subject).toContain("Compliance report");
    expect(asset_row.attached).toMatch(/in-memory PDF, \d+ bytes/);
  });

  test("API: email-report with no recipients (owner has no email, no CCs) → 400", async ({
    request,
  }) => {
    // Test-bypass users get auto-created with empty email — alice
    // matches that. So with zero CCs the resolved recipient set is
    // empty and the handler returns 400 instead of writing a row.
    const asset = await seedAsset(request);
    const res = await emailReport(request, "alice", asset.id);
    expect(res.status()).toBe(400);
  });

  test("UI: owner adds and removes an Email recipient", async ({
    page,
    request,
  }) => {
    const asset = await seedAsset(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "email-cc-host" }).click();

    const section = page.getByTestId("email-cc-section");
    await expect(section).toBeVisible({ timeout: 10_000 });

    // Cloudscape Input renders the data-testid on a wrapper — drill to
    // the actual <input> the way the project-memory rule requires.
    await section
      .getByTestId("email-cc-input")
      .locator("input")
      .fill("ops@example.gov");
    await section.getByTestId("email-cc-add-button").click();

    await expect
      .poll(
        async () => {
          const rows = await (await listCc(request, "alice", asset.id)).json();
          return rows.length;
        },
        { timeout: 5_000 },
      )
      .toBe(1);
    await expect(section.getByText("ops@example.gov")).toBeVisible();

    await section.getByTestId("email-cc-remove-ops@example.gov").click();
    await expect
      .poll(
        async () => {
          const rows = await (await listCc(request, "alice", asset.id)).json();
          return rows.length;
        },
        { timeout: 5_000 },
      )
      .toBe(0);
  });
});
