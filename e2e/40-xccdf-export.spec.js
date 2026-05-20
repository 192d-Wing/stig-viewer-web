import { test, expect } from "@playwright/test";
import { resetDb, BACKEND } from "./helpers.js";

/**
 * Walk a ZIP's central directory to extract filenames + per-entry byte
 * ranges into the local file data. Mirrors the helper in
 * `e2e/39-export-bundle.spec.js` and additionally returns the local
 * header offset so the test can decompress (or read stored) individual
 * entries when it needs the XML payload.
 */
function listZipEntries(buf) {
  const entries = [];
  for (let i = 0; i + 30 <= buf.length; i++) {
    if (
      buf[i] === 0x50 &&
      buf[i + 1] === 0x4b &&
      buf[i + 2] === 0x01 &&
      buf[i + 3] === 0x02
    ) {
      const compMethod = buf.readUInt16LE(i + 10);
      const compSize = buf.readUInt32LE(i + 20);
      const uncompSize = buf.readUInt32LE(i + 24);
      const nameLen = buf.readUInt16LE(i + 28);
      const extraLen = buf.readUInt16LE(i + 30);
      const commentLen = buf.readUInt16LE(i + 32);
      const localHeaderOffset = buf.readUInt32LE(i + 42);
      const nameStart = i + 46;
      const nameEnd = nameStart + nameLen;
      if (nameEnd <= buf.length) {
        entries.push({
          name: buf.subarray(nameStart, nameEnd).toString("utf-8"),
          compMethod,
          compSize,
          uncompSize,
          localHeaderOffset,
        });
      }
      i = nameEnd + extraLen + commentLen - 1;
    }
  }
  return entries;
}

/**
 * Read the raw compressed bytes for a ZIP entry given the central
 * directory entry. Resolves the local file header to skip the variable
 * name + extra fields, then slices out the data segment.
 */
function entryRawData(buf, entry) {
  const lh = entry.localHeaderOffset;
  // Local file header: signature(4) + 22 bytes + nameLen(2) + extraLen(2)
  const nameLen = buf.readUInt16LE(lh + 26);
  const extraLen = buf.readUInt16LE(lh + 28);
  const dataStart = lh + 30 + nameLen + extraLen;
  return buf.subarray(dataStart, dataStart + entry.compSize);
}

/**
 * Decompress a ZIP entry. Uses zlib inflateRaw for Deflated (method 8)
 * and returns the slice as-is for Stored (method 0). Anything else
 * blows up loudly — the backend only ever emits 0 or 8.
 */
function readEntryText(buf, entry) {
  const raw = entryRawData(buf, entry);
  if (entry.compMethod === 0) {
    return raw.toString("utf-8");
  }
  if (entry.compMethod === 8) {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const zlib = require("node:zlib");
    return zlib.inflateRawSync(raw).toString("utf-8");
  }
  throw new Error(`unsupported zip compression method ${entry.compMethod}`);
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

async function setRuleStatus(request, checklistId, ruleId, status, user = "alice") {
  const res = await request.patch(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}`,
    {
      headers: { "X-User-Id": user, "Content-Type": "application/json" },
      data: { status, findingDetails: "", comments: "" },
    },
  );
  expect(res.status()).toBe(200);
  return res.json();
}

test.describe("XCCDF export — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("bundle includes one .xccdf.xml per applied STIG", async ({ request }) => {
    const asset = await createAsset(request, "xccdf-host-basic");
    await applyStig(request, asset.id, "edge");

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/bundle.zip`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.body();
    const entries = listZipEntries(body);

    const xccdfs = entries.filter((e) => e.name.endsWith(".xccdf.xml"));
    expect(xccdfs).toHaveLength(1);
    expect(xccdfs[0].name).toBe("checklists/edge.xccdf.xml");

    // CKL is still emitted alongside the XCCDF.
    const ckls = entries.filter((e) => e.name.endsWith(".ckl"));
    expect(ckls).toHaveLength(1);
    expect(ckls[0].name).toBe("checklists/edge.ckl");
  });

  test("XCCDF rule-result reflects the latest rule status mapping", async ({
    request,
  }) => {
    const asset = await createAsset(request, "xccdf-host-status");
    const checklist = await applyStig(request, asset.id, "edge");

    const detail = await request
      .get(`${BACKEND}/api/checklists/${checklist.id}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    const ruleId = detail.rules[0].id;

    // Drive the rule to "open" — XCCDF should render this as "fail".
    await setRuleStatus(request, checklist.id, ruleId, "open");

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/bundle.zip`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.body();
    const entries = listZipEntries(body);
    const xccdf = entries.find((e) => e.name === "checklists/edge.xccdf.xml");
    expect(xccdf).toBeTruthy();

    const xml = readEntryText(body, xccdf);

    // Document shell sanity-checks before drilling into the rule.
    expect(xml).toContain("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    expect(xml).toContain(
      "xmlns=\"http://checklists.nist.gov/xccdf/1.2\"",
    );
    expect(xml).toContain(
      "id=\"xccdf_mil.disa.stig_benchmark_edge\"",
    );

    // Locate the <rule-result> block for our specific rule and pull its
    // <result> token out. Regex is fine here — output shape is fixed by
    // the backend and we don't want to add an XML parser dep.
    const escapedRid = ruleId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const rrRegex = new RegExp(
      `<rule-result idref=\"${escapedRid}\"[^>]*>\\s*<result>([a-z]+)</result>`,
    );
    const match = xml.match(rrRegex);
    expect(match, `expected a rule-result block for ${ruleId}`).toBeTruthy();
    expect(match[1]).toBe("fail");
  });

  test("XCCDF maps not_a_finding to pass", async ({ request }) => {
    const asset = await createAsset(request, "xccdf-host-pass");
    const checklist = await applyStig(request, asset.id, "edge");
    const detail = await request
      .get(`${BACKEND}/api/checklists/${checklist.id}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    const ruleId = detail.rules[0].id;
    await setRuleStatus(request, checklist.id, ruleId, "not_a_finding");

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/bundle.zip`,
      { headers: { "X-User-Id": "alice" } },
    );
    const body = await res.body();
    const entries = listZipEntries(body);
    const xccdf = entries.find((e) => e.name === "checklists/edge.xccdf.xml");
    const xml = readEntryText(body, xccdf);
    const escapedRid = ruleId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = xml.match(
      new RegExp(
        `<rule-result idref=\"${escapedRid}\"[^>]*>\\s*<result>([a-z]+)</result>`,
      ),
    );
    expect(match[1]).toBe("pass");
  });

  test("MANIFEST.txt lists the XCCDF file alongside the CKL", async ({
    request,
  }) => {
    const asset = await createAsset(request, "xccdf-host-manifest");
    await applyStig(request, asset.id, "edge");

    const res = await request.get(
      `${BACKEND}/api/assets/${asset.id}/bundle.zip`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.body();
    const entries = listZipEntries(body);

    const manifestEntry = entries.find((e) => e.name === "MANIFEST.txt");
    expect(manifestEntry).toBeTruthy();
    const manifestTxt = readEntryText(body, manifestEntry);

    expect(manifestTxt).toContain("checklists/edge.ckl");
    expect(manifestTxt).toContain("checklists/edge.xccdf.xml");
  });
});
