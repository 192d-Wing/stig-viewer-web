import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

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
});
