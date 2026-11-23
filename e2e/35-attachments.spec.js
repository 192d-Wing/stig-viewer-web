import { test, expect } from "@playwright/test";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Seed: alice's asset + 'edge' checklist, returning the first rule id.
 */
async function seedChecklist(request) {
  const asset = await request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { name: "evidence-host" },
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
  return {
    assetId: asset.id,
    checklistId: checklist.id,
    ruleId: detail.rules[0].id,
  };
}

test.describe("Evidence attachments — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("upload + list + download + delete round-trip", async ({ request }) => {
    const { checklistId, ruleId } = await seedChecklist(request);
    const fileBody = Buffer.from("hello evidence", "utf-8");

    const up = await request.post(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: {
            name: "evidence.txt",
            mimeType: "text/plain",
            buffer: fileBody,
          },
        },
      },
    );
    expect(up.status()).toBe(201);
    const row = await up.json();
    expect(row.filename).toBe("evidence.txt");
    expect(row.mimeType).toBe("text/plain");
    expect(row.sizeBytes).toBe(fileBody.length);
    expect(row.sha256).toMatch(/^[0-9a-f]{64}$/);

    // List returns the row.
    const listed = await request
      .get(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
        { headers: { "X-User-Id": "alice" } },
      )
      .then((r) => r.json());
    expect(listed).toHaveLength(1);
    expect(listed[0].id).toBe(row.id);

    // Checklist-wide counts include this rule.
    const counts = await request
      .get(`${BACKEND}/api/checklists/${checklistId}/attachments`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    expect(counts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ ruleId, count: 1 }),
      ]),
    );

    // Download returns the bytes verbatim.
    const dl = await request.get(`${BACKEND}/api/attachments/${row.id}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(dl.status()).toBe(200);
    expect(dl.headers()["content-type"]).toBe("text/plain");
    expect(dl.headers()["content-disposition"]).toContain("evidence.txt");
    const body = await dl.body();
    expect(body.toString("utf-8")).toBe("hello evidence");

    // Delete clears the row.
    const del = await request.delete(`${BACKEND}/api/attachments/${row.id}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(del.status()).toBe(204);

    const after = await request
      .get(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
        { headers: { "X-User-Id": "alice" } },
      )
      .then((r) => r.json());
    expect(after).toHaveLength(0);
  });

  test("non-owner cannot upload (403)", async ({ request }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const res = await request.post(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
      {
        headers: { "X-User-Id": "mallory" },
        multipart: {
          file: {
            name: "bad.txt",
            mimeType: "text/plain",
            buffer: Buffer.from("nope"),
          },
        },
      },
    );
    expect(res.status()).toBe(403);
  });

  test("non-owner cannot delete (403)", async ({ request }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    // Alice uploads.
    const up = await request.post(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: {
            name: "ev.txt",
            mimeType: "text/plain",
            buffer: Buffer.from("data"),
          },
        },
      },
    );
    const row = await up.json();

    // Mallory tries to delete.
    const del = await request.delete(`${BACKEND}/api/attachments/${row.id}`, {
      headers: { "X-User-Id": "mallory" },
    });
    expect(del.status()).toBe(403);

    // Row still exists.
    const listed = await request
      .get(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
        { headers: { "X-User-Id": "alice" } },
      )
      .then((r) => r.json());
    expect(listed).toHaveLength(1);
  });

  test("user without asset access cannot list, count, download or bundle (403), and it is audited", async ({
    request,
  }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);
    const marker = `evidence-${Date.now()}-bytes`;
    const row = await request
      .post(
        `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
        {
          headers: { "X-User-Id": "alice" },
          multipart: {
            file: { name: "secret-evidence.txt", mimeType: "text/plain", buffer: Buffer.from(marker) },
          },
        },
      )
      .then((r) => r.json());
    const as = (user) => ({ headers: { "X-User-Id": user } });
    // The ACL grant below needs mallory to exist as a user; /api/users/me
    // provisions the row (the attachment endpoints do not).
    expect((await request.get(`${BACKEND}/api/users/me`, as("mallory"))).ok()).toBe(true);
    const urls = {
      list: `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
      counts: `${BACKEND}/api/checklists/${checklistId}/attachments`,
      download: `${BACKEND}/api/attachments/${row.id}`,
      bundle: `${BACKEND}/api/assets/${assetId}/bundle.zip`,
    };

    for (const [name, url] of Object.entries(urls)) {
      const res = await request.get(url, as("mallory"));
      expect(res.status(), name).toBe(403);
      expect((await res.body()).toString()).not.toContain(marker);
    }
    expect((await request.get(`${BACKEND}/api/attachments/does-not-exist`, as("mallory"))).status()).toBe(404);

    const grant = await request.post(`${BACKEND}/api/assets/${assetId}/acl`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: { userId: "mallory", permission: "read" },
    });
    expect(grant.ok()).toBe(true);
    for (const [name, url] of Object.entries(urls)) {
      expect((await request.get(url, as("mallory"))).status(), name).toBe(200);
    }

    await setUserRole("audit-admin", "admin");
    const events = async (action) =>
      (await request.get(`${BACKEND}/api/audit/events?action=${action}`, as("audit-admin")).then((r) => r.json())).rows;
    const downloads = await events("attachment.download");
    expect(downloads.length).toBeGreaterThan(0);
    expect(downloads[0].outcome).toBe("ok");
    expect(downloads[0].detail.attachmentId).toBe(row.id);
    expect(JSON.stringify(downloads)).not.toContain("secret-evidence");
    const denied = await events("authz.denied");
    const routes = denied.map((r) => r.detail.route);
    expect(routes).toContain("/api/attachments/:id");
    expect(routes.some((r) => r.endsWith("/attachments"))).toBe(true);
    expect(JSON.stringify(denied)).not.toContain(row.id);
  });

  test("file over 25 MB returns 413", async ({ request }) => {
    const { checklistId, ruleId } = await seedChecklist(request);

    const big = Buffer.alloc(26 * 1024 * 1024, 0x41);
    const res = await request.post(
      `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: {
            name: "big.bin",
            mimeType: "application/octet-stream",
            buffer: big,
          },
        },
      },
    );
    expect(res.status()).toBe(413);
  });
});

test.describe("Evidence attachments — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("Evidence section in rule editor uploads + lists + deletes", async ({
    page,
    request,
  }) => {
    const { assetId, checklistId, ruleId } = await seedChecklist(request);

    await loginAs(page, "alice");
    await page.goto(`/?asset=${assetId}&checklist=${checklistId}`);

    // Navigate via the systems list → asset → checklist. Direct deep-linking
    // isn't supported, so click through the UI.
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "evidence-host" }).click();
    // Open the only checklist on this asset.
    await page.getByRole("button", { name: /edge/i }).first().click();

    // Open the rule editor.
    await page.getByRole("button", { name: ruleId }).first().click();

    // Evidence section is visible. Use exact match — "evidence-host"
    // substring matches the page subtitle and the FormField description.
    await expect(page.getByText("Evidence", { exact: true })).toBeVisible();
    await expect(page.getByText("No attachments yet.")).toBeVisible();

    // Upload a small file via the file input.
    const fileInput = page.getByTestId("attachment-file-input");
    await fileInput.setInputFiles({
      name: "ui-evidence.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("ui-upload-content"),
    });

    // Wait for the row to appear in the table.
    await expect(page.getByText("ui-evidence.txt")).toBeVisible({
      timeout: 10_000,
    });

    // Delete the row and confirm it disappears.
    await page.getByTestId("attachment-delete").first().click();
    await expect(page.getByText("ui-evidence.txt")).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.getByText("No attachments yet.")).toBeVisible();
  });

  test("a user without read access sees a no-access note, not an error or controls", async ({
    page,
    request,
  }) => {
    const { checklistId, ruleId } = await seedChecklist(request);
    // Auto-create mallory (no grant on alice's asset).
    await request.get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": "mallory" } });
    const counts = await request.get(`${BACKEND}/api/checklists/${checklistId}/attachments`, {
      headers: { "X-User-Id": "mallory" },
    });
    expect(counts.status()).toBe(403);

    await loginAs(page, "mallory");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "evidence-host" }).click();
    await page.getByRole("button", { name: /edge/i }).first().click();
    await page.getByRole("button", { name: ruleId }).first().click();

    await expect(
      page.getByText("You do not have access to this system's evidence."),
    ).toBeVisible();
    await expect(page.getByText("No attachments yet.")).toHaveCount(0);
    await expect(page.getByTestId("attachment-file-input")).toHaveCount(0);
    await expect(page.getByTestId("attachment-delete")).toHaveCount(0);
    await expect(page.getByText("Forbidden")).toHaveCount(0);
  });
});
