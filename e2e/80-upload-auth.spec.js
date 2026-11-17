import { test, expect } from "@playwright/test";
import { resetDb, setUserRole, uploadStigAs, BACKEND } from "./helpers.js";

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

  test("empty, path-like and upper-case ids are rejected with 400", async () => {
    await setUserRole("upload-admin", "admin");
    for (const id of ["", "a/b", "Upper-Case"]) {
      const res = await uploadStigAs("upload-admin", { ...bogus, id });
      expect(res.status).toBe(400);
    }
  });
});
