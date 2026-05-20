import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Helpers for CSV body construction. Kept inline so the spec is self
 * contained — these CSVs are tiny.
 */
function csv(...lines) {
  return Buffer.from(lines.join("\n") + "\n", "utf-8");
}

const HEADER = "name,hostname,description,classification,tags";

async function listAssets(request, user) {
  const res = await request.get(`${BACKEND}/api/assets`, {
    headers: { "X-User-Id": user },
  });
  return res.json();
}

test.describe("Asset CSV import — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("dry-run with 3 valid rows: totalRows=3, createdCount=0, all ok", async ({
    request,
  }) => {
    const body = csv(
      HEADER,
      "web-1,web-1.example.com,first,unclassified,production;public-facing",
      "web-2,web-2.example.com,second,cui,production",
      "web-3,web-3.example.com,third,,",
    );

    const res = await request.post(
      `${BACKEND}/api/assets/import?dry_run=true`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: { name: "x.csv", mimeType: "text/csv", buffer: body },
        },
      },
    );
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.totalRows).toBe(3);
    expect(data.createdCount).toBe(0);
    expect(data.skippedCount).toBe(0);
    expect(data.rows.map((r) => r.status)).toEqual(["ok", "ok", "ok"]);
    // Default classification fills in when blank.
    expect(data.rows[2].classification).toBe("unclassified");

    // Asset count unchanged.
    const assets = await listAssets(request, "alice");
    expect(assets).toHaveLength(0);
  });

  test("commit inserts; re-running with same csv marks them as skipped", async ({
    request,
  }) => {
    const body = csv(
      HEADER,
      "web-1,h1,,unclassified,production",
      "web-2,h2,,cui,",
      "web-3,h3,,secret,",
    );

    const first = await request.post(
      `${BACKEND}/api/assets/import?dry_run=false`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: { name: "x.csv", mimeType: "text/csv", buffer: body },
        },
      },
    );
    expect(first.status()).toBe(200);
    const firstData = await first.json();
    expect(firstData.createdCount).toBe(3);
    expect(firstData.rows.every((r) => r.status === "ok")).toBe(true);

    const assets = await listAssets(request, "alice");
    expect(assets).toHaveLength(3);
    const tagged = assets.find((a) => a.name === "web-1");
    expect(tagged.tags).toContain("production");

    // Second dry-run with identical CSV: everything is a duplicate.
    const second = await request.post(
      `${BACKEND}/api/assets/import?dry_run=true`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: { name: "x.csv", mimeType: "text/csv", buffer: body },
        },
      },
    );
    expect(second.status()).toBe(200);
    const secondData = await second.json();
    expect(secondData.totalRows).toBe(3);
    expect(secondData.skippedCount).toBe(3);
    expect(secondData.rows.every((r) => r.status === "skipped")).toBe(true);
    expect(secondData.rows.every((r) => r.error === "duplicate")).toBe(true);
  });

  test("rows with invalid classification are errors and skipped on commit", async ({
    request,
  }) => {
    const body = csv(
      HEADER,
      "good-1,h1,,unclassified,",
      "bad-1,h2,,bogus,",
      "good-2,h3,,top-secret,",
    );

    const res = await request.post(
      `${BACKEND}/api/assets/import?dry_run=false`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: { name: "x.csv", mimeType: "text/csv", buffer: body },
        },
      },
    );
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.createdCount).toBe(2);
    const bad = data.rows.find((r) => r.name === "bad-1");
    expect(bad.status).toBe("error");
    expect(bad.error).toBe("invalid classification");

    const assets = await listAssets(request, "alice");
    expect(assets.map((a) => a.name).sort()).toEqual(["good-1", "good-2"]);
  });

  test("empty name → error; rest of batch still inserts", async ({ request }) => {
    const body = csv(
      HEADER,
      "keep-1,h1,,unclassified,",
      ",h2,,unclassified,",
      "keep-2,h3,,unclassified,",
    );

    const res = await request.post(
      `${BACKEND}/api/assets/import?dry_run=false`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: { name: "x.csv", mimeType: "text/csv", buffer: body },
        },
      },
    );
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.createdCount).toBe(2);
    const blank = data.rows.find((r) => r.name === "");
    expect(blank.status).toBe("error");
    expect(blank.error).toBe("name required");

    const assets = await listAssets(request, "alice");
    expect(assets.map((a) => a.name).sort()).toEqual(["keep-1", "keep-2"]);
  });

  test("tag over 50 chars surfaces 'tag too long: <tag>'", async ({ request }) => {
    const long = "x".repeat(51);
    const body = csv(HEADER, `bad,h,,unclassified,${long}`);
    const res = await request.post(
      `${BACKEND}/api/assets/import?dry_run=true`,
      {
        headers: { "X-User-Id": "alice" },
        multipart: {
          file: { name: "x.csv", mimeType: "text/csv", buffer: body },
        },
      },
    );
    expect(res.status()).toBe(200);
    const data = await res.json();
    expect(data.rows[0].status).toBe("error");
    expect(data.rows[0].error).toBe(`tag too long: ${long}`);
  });
});

test.describe("Asset CSV import — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("upload a CSV, preview rows, commit, see new rows in the table", async ({
    page,
  }) => {
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();

    // Open the import modal.
    await page.getByTestId("import-csv-button").click();

    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();

    // Drop a CSV into the file input. The onChange triggers a dry-run.
    await modal.getByTestId("import-csv-input").setInputFiles({
      name: "small.csv",
      mimeType: "text/csv",
      buffer: Buffer.from(
        `${HEADER}\n` +
          "ui-host-1,h1,,unclassified,production\n" +
          "ui-host-2,h2,,cui,\n",
        "utf-8",
      ),
    });

    // Preview shows two ok rows.
    await expect(modal.getByTestId("import-status-2")).toHaveText("ok", {
      timeout: 10_000,
    });
    await expect(modal.getByTestId("import-status-3")).toHaveText("ok");

    // Commit.
    await modal.getByTestId("import-csv-commit").click();
    await expect(modal.getByTestId("import-csv-success")).toBeVisible({
      timeout: 10_000,
    });

    // Modal auto-closes; the new rows show up in the systems table.
    await expect(modal).toBeHidden({ timeout: 10_000 });
    await expect(
      page.getByRole("button", { name: "ui-host-1", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "ui-host-2", exact: true }),
    ).toBeVisible();
  });
});
