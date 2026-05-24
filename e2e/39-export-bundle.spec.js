import { test, expect } from "@playwright/test";
import { resetDb, BACKEND } from "./helpers.js";

/**
 * Walk a ZIP's central directory to extract the list of stored file
 * names. This avoids pulling in a parser dep — we only need filenames
 * and presence, not actual decompression.
 *
 * Each central-directory file header starts with 0x02014b50 (little-endian
 * "PK\x01\x02") and carries the filename length + filename bytes at a
 * fixed offset.
 */
function listZipEntries(buf) {
  const names = [];
  for (let i = 0; i + 30 <= buf.length; i++) {
    if (
      buf[i] === 0x50 &&
      buf[i + 1] === 0x4b &&
      buf[i + 2] === 0x01 &&
      buf[i + 3] === 0x02
    ) {
      // Central directory file header layout (offsets from header start):
      //   28: file name length (2 bytes, LE)
      //   30: extra field length (2 bytes, LE)
      //   32: file comment length (2 bytes, LE)
      //   46: file name (variable)
      const nameLen = buf.readUInt16LE(i + 28);
      const extraLen = buf.readUInt16LE(i + 30);
      const commentLen = buf.readUInt16LE(i + 32);
      const nameStart = i + 46;
      const nameEnd = nameStart + nameLen;
      if (nameEnd <= buf.length) {
        names.push(buf.subarray(nameStart, nameEnd).toString("utf-8"));
      }
      // Skip past this central directory record to keep scanning.
      i = nameEnd + extraLen + commentLen - 1;
    }
  }
  return names;
}

async function createAsset(request, name, user = "alice") {
  return request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": user, "Content-Type": "application/json" },
      data: { name },
    })
    .then((r) => r.json());
}

async function applyStig(request, assetId, stigId, user = "alice") {
  return request
    .post(`${BACKEND}/api/assets/${assetId}/checklists`, {
      headers: { "X-User-Id": user, "Content-Type": "application/json" },
      data: { stigId },
    })
    .then((r) => r.json());
}

test.describe("Export bundle ZIP — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("returns 200 + application/zip + non-empty body for an asset with no STIGs", async ({
    request,
  }) => {
    const asset = await createAsset(request, "bundle-host-empty");
    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/bundle.zip`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toBe("application/zip");
    expect(res.headers()["content-disposition"]).toContain(
      "bundle-host-empty-bundle.zip",
    );

    const body = await res.body();
    expect(body.length).toBeGreaterThan(0);
    // ZIP magic header (local file header or end-of-central-directory).
    expect(body.subarray(0, 2).toString()).toBe("PK");

    // Empty bundle still has a MANIFEST.txt.
    const entries = listZipEntries(body);
    expect(entries).toContain("MANIFEST.txt");
  });

  test("includes one .ckl per applied STIG", async ({ request }) => {
    const asset = await createAsset(request, "bundle-host-stig");
    await applyStig(request, asset.id, "edge");

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/bundle.zip`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.body();
    const entries = listZipEntries(body);

    const ckls = entries.filter((n) => n.endsWith(".ckl"));
    expect(ckls).toHaveLength(1);
    expect(ckls[0]).toBe("checklists/edge.ckl");
    expect(entries).toContain("MANIFEST.txt");
  });

  test("includes attachment files when present", async ({ request }) => {
    const asset = await createAsset(request, "bundle-host-att");
    const checklist = await applyStig(request, asset.id, "edge");
    const detail = await request
      .get(`${BACKEND}/api/checklists/${checklist.id}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    const ruleId = detail.rules[0].id;

    const up = await request.post(
      `${BACKEND}/api/checklists/${checklist.id}/rules/${encodeURIComponent(ruleId)}/attachments`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: {
            name: "evidence.txt",
            mimeType: "text/plain",
            buffer: Buffer.from("bundle evidence"),
          },
        },
      },
    );
    expect(up.status()).toBe(201);

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/bundle.zip`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.body();
    const entries = listZipEntries(body);

    const attachmentPath = `attachments/${checklist.id}/${ruleId}/evidence.txt`;
    expect(entries).toContain(attachmentPath);
    // CKL still present alongside the attachment.
    expect(entries).toContain("checklists/edge.ckl");
  });

  test("404 if asset doesn't exist", async ({ request }) => {
    const res = await request.get(
      `${BACKEND}/api/assets/does-not-exist/bundle.zip`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(404);
  });
});
