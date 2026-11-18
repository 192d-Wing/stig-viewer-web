import { test, expect } from "@playwright/test";
import { inflateRawSync } from "node:zlib";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

// ── ZIP helpers (same shape as e2e/40-xccdf-export.spec.js) ─────────────────

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

function entryRawData(buf, entry) {
  const lh = entry.localHeaderOffset;
  const nameLen = buf.readUInt16LE(lh + 26);
  const extraLen = buf.readUInt16LE(lh + 28);
  const dataStart = lh + 30 + nameLen + extraLen;
  return buf.subarray(dataStart, dataStart + entry.compSize);
}

function readEntryBytes(buf, entry) {
  const raw = entryRawData(buf, entry);
  if (entry.compMethod === 0) return raw;
  if (entry.compMethod === 8) return inflateRawSync(raw);
  throw new Error(`unsupported zip compression method ${entry.compMethod}`);
}

function readEntryText(buf, entry) {
  return readEntryBytes(buf, entry).toString("utf-8");
}

// ── Seeding helpers ─────────────────────────────────────────────────────────

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

async function createAsset(request, name, user = "alice") {
  return request
    .post(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": user, "Content-Type": "application/json" },
      data: { name },
    })
    .then((r) => r.json());
}

async function applyStig(request, assetId, stigId = "edge", user = "alice") {
  return request
    .post(`${BACKEND}/api/assets/${assetId}/checklists`, {
      headers: { "X-User-Id": user, "Content-Type": "application/json" },
      data: { stigId },
    })
    .then((r) => r.json());
}

async function uploadAttachment(request, checklistId, ruleId, user = "alice") {
  const fileBody = Buffer.from("backup-restore evidence", "utf-8");
  const res = await request.post(
    `${BACKEND}/api/checklists/${checklistId}/rules/${encodeURIComponent(
      ruleId,
    )}/attachments`,
    {
      headers: { "X-User-Id": user },
      multipart: {
        file: {
          name: "evidence.txt",
          mimeType: "text/plain",
          buffer: fileBody,
        },
      },
    },
  );
  expect(res.status()).toBe(201);
  return { row: await res.json(), fileBody };
}

// ── API tests ───────────────────────────────────────────────────────────────

test.describe("Backup + restore — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("non-admin caller is rejected with 403", async ({ request }) => {
    await ensureUser(request, "alice");
    const res = await request.get(`${BACKEND}/api/admin/backup`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(403);
  });

  test("admin receives a zip whose manifest + tables are well-formed", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const res = await request.get(`${BACKEND}/api/admin/backup`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toBe("application/zip");
    expect(res.headers()["content-disposition"]).toMatch(
      /attachment; filename="stig-backup-\d{4}-\d{2}-\d{2}\.zip"/,
    );

    const body = await res.body();
    const entries = listZipEntries(body);
    const names = entries.map((e) => e.name);
    expect(names).toContain("manifest.json");

    // At least one tables/*.jsonl present (we always emit users at minimum).
    const jsonlEntries = entries.filter(
      (e) => e.name.startsWith("tables/") && e.name.endsWith(".jsonl"),
    );
    expect(jsonlEntries.length).toBeGreaterThan(0);
    expect(names).toContain("tables/users.jsonl");
    expect(names).toContain("tables/assets.jsonl");
    expect(names).toContain("tables/attachments.jsonl");

    // Manifest is valid JSON with the expected keys.
    const manifestEntry = entries.find((e) => e.name === "manifest.json");
    const manifest = JSON.parse(readEntryText(body, manifestEntry));
    expect(manifest.version).toBe("2");
    expect(manifest.type).toBe("stig-viewer/backup");
    // Every other entry is digested (SHA-512 hex).
    expect(manifest.entries["tables/users.jsonl"]).toMatch(/^[0-9a-f]{128}$/);
    expect(Array.isArray(manifest.signers)).toBe(true);
    expect(typeof manifest.takenAt).toBe("string");
    expect(typeof manifest.schemaMigration).toBe("number");
    expect(manifest.schemaMigration).toBeGreaterThan(0);
    expect(manifest.counts).toBeTruthy();
    expect(typeof manifest.counts.users).toBe("number");
    expect(typeof manifest.counts.audit_events).toBe("number");
    expect(names).toContain("tables/audit_events.jsonl");
  });

  test("audit events survive a backup round trip and the id sequence continues", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    const asset = await createAsset(request, "backup-host-events");
    await applyStig(request, asset.id);

    // Every read of /api/audit/events is itself audited (audit.read). Hide
    // those rows from the comparisons, but count them where the backup counts them.
    const fetchEvents = async (query = "") =>
      (
        await request
          .get(`${BACKEND}/api/audit/events${query}`, { headers: { "X-User-Id": "alice" } })
          .then((r) => r.json())
      ).rows;
    // A forced restore also records a backup.restore event inside the restore transaction.
    const listEvents = async () =>
      (await fetchEvents()).filter((e) => e.action !== "audit.read" && e.action !== "backup.restore");
    const before = await listEvents();
    expect(before.map((e) => e.action)).toContain("checklist.create");
    // The backup holds the audit.read rows already written, plus the one this
    // very call writes after its query.
    const readsSeen = (await fetchEvents("?action=audit.read")).length;
    expect(readsSeen).toBeGreaterThan(0);
    const readsInBackup = readsSeen + 1;

    const backupBytes = await request
      .get(`${BACKEND}/api/admin/backup`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.body());

    await resetDb();
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    expect(await listEvents()).toHaveLength(0);
    // (that call wrote one audit.read row into the freshly reset database)

    const restoreRes = await request.post(`${BACKEND}/api/admin/restore?force=true`, {
      headers: { "X-User-Id": "alice" },
      multipart: { file: { name: "backup.zip", mimeType: "application/zip", buffer: backupBytes } },
    });
    expect(restoreRes.status()).toBe(200);
    expect((await restoreRes.json()).restored.audit_events).toBe(before.length + readsInBackup);

    // The restore itself leaves a record in the replaced audit trail.
    expect((await fetchEvents("?action=backup.restore")).length).toBe(1);

    // The audit.read rows survive the round trip like any other event.
    const restoredReads = await fetchEvents("?action=audit.read");
    expect(restoredReads.length).toBeGreaterThanOrEqual(readsInBackup);
    const after = await listEvents();
    expect(after.map((e) => e.id)).toEqual(before.map((e) => e.id));

    // New events are numbered after the restored ones.
    const asset2 = await createAsset(request, "backup-host-events-2");
    await applyStig(request, asset2.id);
    const later = await listEvents();
    expect(later.length).toBe(before.length + 1);
    expect(Math.max(...later.map((e) => e.id))).toBeGreaterThan(Math.max(...before.map((e) => e.id)));
  });

  test("round-trip: backup → reset → force-restore brings data back", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const asset = await createAsset(request, "backup-host-rt");
    const checklist = await applyStig(request, asset.id);
    const detail = await request
      .get(`${BACKEND}/api/checklists/${checklist.id}`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());
    const ruleId = detail.rules[0].id;
    const { row: attRow, fileBody } = await uploadAttachment(
      request,
      checklist.id,
      ruleId,
    );

    // Snapshot the backup before we wipe.
    const backupRes = await request.get(`${BACKEND}/api/admin/backup`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(backupRes.status()).toBe(200);
    const backupBytes = await backupRes.body();

    // Wipe everything (also clears alice's admin role since users is truncated).
    await resetDb();

    // Re-create alice + admin so we can call restore.
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    // Restore from the backup with force=true.
    const restoreRes = await request.post(
      `${BACKEND}/api/admin/restore?force=true`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: {
            name: "backup.zip",
            mimeType: "application/zip",
            buffer: backupBytes,
          },
        },
      },
    );
    expect(restoreRes.status()).toBe(200);
    const restoreBody = await restoreRes.json();
    expect(restoreBody.restored).toBeTruthy();
    // Pre-wipe state had at least 1 user, 1 asset, 1 checklist, 1 attachment.
    expect(restoreBody.restored.assets).toBeGreaterThanOrEqual(1);
    expect(restoreBody.restored.checklists).toBeGreaterThanOrEqual(1);
    expect(restoreBody.restored.attachments).toBeGreaterThanOrEqual(1);
    expect(restoreBody.attachmentsWritten).toBeGreaterThanOrEqual(1);

    // Asset should be back under its original id. Get it back via the
    // attachments owner path — alice was the owner pre-wipe, and the
    // restore wrote her row back too, so she should still own it.
    const aliceMe = await request
      .get(`${BACKEND}/api/users/me`, {
        headers: { "X-User-Id": "alice" },
      })
      .then((r) => r.json());

    const assetsRes = await request.get(`${BACKEND}/api/assets`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(assetsRes.status()).toBe(200);
    const assetsAfter = await assetsRes.json();
    expect(assetsAfter.map((a) => a.id)).toContain(asset.id);
    void aliceMe;

    // Attachment blob is back on disk: download returns the original bytes.
    const dl = await request.get(`${BACKEND}/api/attachments/${attRow.id}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(dl.status()).toBe(200);
    const dlBody = await dl.body();
    expect(dlBody.toString("utf-8")).toBe(fileBody.toString("utf-8"));
  });

  test("restore without force on a non-empty db returns 400", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    await createAsset(request, "non-empty-host");

    const backupRes = await request.get(`${BACKEND}/api/admin/backup`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(backupRes.status()).toBe(200);
    const backupBytes = await backupRes.body();

    const restoreRes = await request.post(
      `${BACKEND}/api/admin/restore?force=false`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: {
            name: "backup.zip",
            mimeType: "application/zip",
            buffer: backupBytes,
          },
        },
      },
    );
    expect(restoreRes.status()).toBe(400);
    const body = await restoreRes.json();
    expect(body.error).toMatch(/not empty|force=true/);
  });

  test("restore of a backup with a corrupted entry returns 400", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const backupRes = await request.get(`${BACKEND}/api/admin/backup`, {
      headers: { "X-User-Id": "alice" },
    });
    const original = Buffer.from(await backupRes.body());
    const usersBefore = await (
      await request.get(`${BACKEND}/api/admin/users`, {
        headers: { "X-User-Id": "alice" },
      })
    ).json();
    const entry = listZipEntries(original).find(
      (e) => e.name === "tables/users.jsonl",
    );
    // Flip one byte inside that entry's stored data. Whether the zip layer or
    // the manifest digest catches it, the restore must be refused untouched.
    const lh = entry.localHeaderOffset;
    const dataStart =
      lh + 30 + original.readUInt16LE(lh + 26) + original.readUInt16LE(lh + 28);
    const corrupted = Buffer.from(original);
    corrupted[dataStart + Math.floor(entry.compSize / 2)] ^= 0xff;

    const restoreRes = await request.post(
      `${BACKEND}/api/admin/restore?force=true`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: {
            name: "corrupt-backup.zip",
            mimeType: "application/zip",
            buffer: corrupted,
          },
        },
      },
    );
    expect(restoreRes.status()).toBe(400);

    // The data is untouched: same users before and after. `lastLogin` is
    // left out because every authenticated request updates it.
    const stillThere = await request.get(`${BACKEND}/api/admin/users`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(stillThere.ok()).toBe(true);
    const withoutLastLogin = (users) =>
      users.map(({ lastLogin, ...rest }) => rest);
    expect(withoutLastLogin(await stillThere.json())).toEqual(
      withoutLastLogin(usersBefore),
    );
  });

  test("restore with mismatched schemaMigration returns 400", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    // Take a real backup, then surgically rewrite its manifest's
    // schemaMigration to something nonsensical (9999) and POST it back.
    const backupRes = await request.get(`${BACKEND}/api/admin/backup`, {
      headers: { "X-User-Id": "alice" },
    });
    const original = await backupRes.body();
    const entries = listZipEntries(original);
    const manifestEntry = entries.find((e) => e.name === "manifest.json");
    const manifest = JSON.parse(readEntryText(original, manifestEntry));
    // With SIGNING_KEY_HEX set, restore requires a verified signature by default
    // and an unsigned repacked manifest is refused before the schema gate. The
    // test API cannot change the backend's environment, so skip in that setup.
    test.skip(
      Array.isArray(manifest.signers) && manifest.signers.length > 0,
      "backend has SIGNING_KEY_HEX set; this test assumes unsigned restores are allowed",
    );
    manifest.schemaMigration = 9999;
    // The repacked zip holds only the manifest, so drop the digest list and
    // signers (an unsigned, digest-free manifest passes the integrity check
    // and reaches the schema gate this test exercises).
    manifest.entries = {};
    manifest.signers = [];

    // Re-pack a minimal zip: we don't have a zip writer in the test, so
    // construct one by hand using node's built-in `zlib.deflateRawSync`.
    // Easier: lean on the JSZip-equivalent approach — write a STORED
    // (uncompressed) one-file zip containing just the rewritten manifest
    // alongside an empty `tables/users.jsonl` so the restore zip walker
    // still sees a tables/ entry. The restore checks the manifest first,
    // so it'll fail on the schema mismatch before it tries to import
    // anything.
    const repacked = buildMinimalZipWithManifest(manifest);

    const restoreRes = await request.post(
      `${BACKEND}/api/admin/restore?force=true`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: {
            name: "bad-backup.zip",
            mimeType: "application/zip",
            buffer: repacked,
          },
        },
      },
    );
    expect(restoreRes.status()).toBe(400);
    const body = await restoreRes.json();
    expect(body.error).toMatch(/schema version mismatch/);
  });
});

// ── UI tests ────────────────────────────────────────────────────────────────

test.describe("Backup + restore — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("admin console renders Backup & restore and the Download button triggers a download", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    await loginAs(page, "alice");

    await page.goto("/?view=admin");

    const section = page.getByTestId("backup-restore-section");
    await expect(section).toBeVisible();

    const downloadBtn = page.getByTestId("backup-download-btn");
    await expect(downloadBtn).toBeVisible();

    // Listen for the synthetic download triggered by the <a download>
    // click that the handler injects. Playwright surfaces this as a
    // Download event regardless of the underlying transport.
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      downloadBtn.click(),
    ]);
    expect(download.suggestedFilename()).toMatch(
      /^stig-backup-\d{4}-\d{2}-\d{2}\.zip$/,
    );
  });
});

// ── Hand-rolled minimal ZIP for the schema-mismatch case ────────────────────
//
// PK\3\4 local header, single STORED file, then PK\1\2 central directory,
// then PK\5\6 end-of-central-directory. Stored (compMethod=0) so no
// deflate plumbing is needed. The restore handler only needs to see a
// valid manifest.json — table parsing happens after the schema check.

function buildMinimalZipWithManifest(manifest) {
  const manifestBytes = Buffer.from(JSON.stringify(manifest), "utf-8");
  const nameBuf = Buffer.from("manifest.json", "utf-8");

  const crc = crc32(manifestBytes);
  const size = manifestBytes.length;

  // Local file header
  const lfh = Buffer.alloc(30);
  lfh.writeUInt32LE(0x04034b50, 0); // signature
  lfh.writeUInt16LE(20, 4); // version needed
  lfh.writeUInt16LE(0, 6); // flags
  lfh.writeUInt16LE(0, 8); // method = STORED
  lfh.writeUInt16LE(0, 10); // time
  lfh.writeUInt16LE(0, 12); // date
  lfh.writeUInt32LE(crc, 14);
  lfh.writeUInt32LE(size, 18); // compressed size
  lfh.writeUInt32LE(size, 22); // uncompressed size
  lfh.writeUInt16LE(nameBuf.length, 26);
  lfh.writeUInt16LE(0, 28); // extra length

  const localHeaderOffset = 0;
  const local = Buffer.concat([lfh, nameBuf, manifestBytes]);

  // Central directory header
  const cdh = Buffer.alloc(46);
  cdh.writeUInt32LE(0x02014b50, 0); // signature
  cdh.writeUInt16LE(20, 4); // version made by
  cdh.writeUInt16LE(20, 6); // version needed
  cdh.writeUInt16LE(0, 8); // flags
  cdh.writeUInt16LE(0, 10); // method
  cdh.writeUInt16LE(0, 12); // time
  cdh.writeUInt16LE(0, 14); // date
  cdh.writeUInt32LE(crc, 16);
  cdh.writeUInt32LE(size, 20);
  cdh.writeUInt32LE(size, 24);
  cdh.writeUInt16LE(nameBuf.length, 28);
  cdh.writeUInt16LE(0, 30); // extra len
  cdh.writeUInt16LE(0, 32); // comment len
  cdh.writeUInt16LE(0, 34); // disk number
  cdh.writeUInt16LE(0, 36); // internal attrs
  cdh.writeUInt32LE(0, 38); // external attrs
  cdh.writeUInt32LE(localHeaderOffset, 42);
  const central = Buffer.concat([cdh, nameBuf]);

  // End of central directory
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4); // disk
  eocd.writeUInt16LE(0, 6); // disk with cd
  eocd.writeUInt16LE(1, 8); // entries on this disk
  eocd.writeUInt16LE(1, 10); // total entries
  eocd.writeUInt32LE(central.length, 12); // cd size
  eocd.writeUInt32LE(local.length, 16); // cd offset
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([local, central, eocd]);
}

// Minimal CRC-32/IEEE — used only by the hand-rolled zip helper above.
function crc32(buf) {
  let table = crc32._t;
  if (!table) {
    table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      }
      table[n] = c >>> 0;
    }
    crc32._t = table;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}
