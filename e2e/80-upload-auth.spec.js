import { test, expect } from "@playwright/test";
import { resetDb, setUserRole, uploadStigAs, buildZip, breakCentralName, BACKEND } from "./helpers.js";

// Catalog uploads replace shared STIG content, so they sit behind the
// session middleware and require the admin role.
test.describe("Catalog upload — authentication", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  // Not a real ZIP: an admin gets past auth and is rejected by the parser,
  // which is enough to prove the request reached the handler body.
  const bogus = {
    file: Buffer.from("not a zip"),
    filename: "bogus.zip",
    id: "upload-auth-probe",
    category: "Windows",
  };

  test("anonymous upload → 401 on both endpoints", async ({ request }) => {
    for (const path of ["/api/upload", "/api/upload/library"]) {
      const res = await request.post(`${BACKEND}${path}`, {
        multipart: {
          file: { name: "bogus.zip", mimeType: "application/zip", buffer: bogus.file },
        },
      });
      expect(res.status(), path).toBe(401);
    }
  });

  test("non-admin upload → 403", async () => {
    for (const role of ["author", "reviewer", "viewer"]) {
      await setUserRole(`upload-${role}`, role);
      const res = await uploadStigAs(`upload-${role}`, bogus);
      expect(res.status, role).toBe(403);
    }
  });

  test("admin upload passes auth and reaches the parser", async ({ request }) => {
    await setUserRole("upload-admin", "admin");
    const res = await uploadStigAs("upload-admin", bogus);
    expect(res.status).toBe(422);
    expect(await res.text()).toContain("ZIP extraction failed");

    const catalog = await request.get(`${BACKEND}/api/catalog`).then((r) => r.json());
    expect(catalog.map((e) => e.id)).not.toContain(bogus.id);
  });

  test("an over-long id is rejected before the parser runs", async () => {
    await setUserRole("upload-admin", "admin");
    const res = await uploadStigAs("upload-admin", { ...bogus, id: "a".repeat(129) });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("1-128");
    const ok = await uploadStigAs("upload-admin", { ...bogus, id: "a".repeat(128) });
    expect(ok.status).toBe(422); // length accepted; the bogus ZIP then fails parsing
  });

  test("empty, path-like and upper-case ids are rejected with 400", async ({ request }) => {
    await setUserRole("upload-admin", "admin");
    for (const id of ["", "a/b", "Upper-Case"]) {
      const res = await uploadStigAs("upload-admin", { ...bogus, id });
      expect(res.status).toBe(400);
      if (id === "Upper-Case") expect(await res.text()).toContain("lower-case");
    }
    const listedRes = await request.get(`${BACKEND}/api/catalog`);
    expect(listedRes.ok()).toBeTruthy();
    expect((await listedRes.json()).map((e) => e.id)).not.toContain("Upper-Case");
  });

  test("a decompression bomb is refused with 413 and leaves the catalog empty", async ({ request }) => {
    await setUserRole("upload-admin", "admin");
    // 64 MiB + 1 of whitespace deflates to about 64 KiB.
    const bomb = buildZip([
      { name: "bomb-xccdf.xml", data: Buffer.concat([Buffer.from("<Benchmark/>"), Buffer.alloc(64 * 1024 * 1024 + 1, 0x20)]) },
    ]);
    expect(bomb.length).toBeLessThan(1024 * 1024);
    const res = await uploadStigAs("upload-admin", { ...bogus, file: bomb, id: "upload-bomb" });
    expect(res.status).toBe(413);
    expect(await res.text()).toContain("larger than");

    const catalog = await request.get(`${BACKEND}/api/catalog`).then((r) => r.json());
    expect(catalog.map((e) => e.id)).not.toContain("upload-bomb");
  });

  test("a ZIP whose headers disagree is refused with 422", async ({ request }) => {
    await setUserRole("upload-admin", "admin");
    const zip = breakCentralName(buildZip([{ name: "a-xccdf.xml", data: "<Benchmark/>" }]));
    const res = await uploadStigAs("upload-admin", { ...bogus, file: zip, id: "upload-mismatch" });
    expect(res.status).toBe(422);
    expect(await res.text()).toContain("inconsistent ZIP headers");

    const catalog = await request.get(`${BACKEND}/api/catalog`).then((r) => r.json());
    expect(catalog.map((e) => e.id)).not.toContain("upload-mismatch");
  });
});
