import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Per-asset markdown runbook.
 *
 * Operators capture free-form notes per asset — escalation contacts,
 * known issues, restart procedures, etc. Backend stores the content
 * as plain TEXT on the asset row (migration 033) and the frontend
 * renders a tiny purpose-built markdown subset via
 * `src/utils/markdown.js` (avoiding a heavy `react-markdown` dep).
 *
 * Write-side has no cap — the read path in `db_assets::get_asset`
 * defensively truncates anything over `MAX_RUNBOOK_BYTES` (100 KB).
 * That lets a runaway runbook write succeed but bounds the API
 * payload on subsequent fetches.
 */

const RUNBOOK_TEXT = "## Steps\n- Restart nginx\n- Verify port 443";

async function seedAsset(request, owner = "alice", name = "runbook-host") {
  const r = await request.post(`${BACKEND}/api/assets`, {
    headers: { "X-User-Id": owner, "Content-Type": "application/json" },
    data: { name },
  });
  if (!r.ok()) throw new Error(`seedAsset failed: ${r.status()}`);
  return r.json();
}

async function patchRunbook(request, asUser, assetId, runbook) {
  return request.patch(`${BACKEND}/api/assets/${assetId}`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data: { runbook },
  });
}

async function getAsset(request, asUser, assetId) {
  return (
    await request.get(`${BACKEND}/api/assets/${assetId}`, {
      headers: { "X-User-Id": asUser },
    })
  ).json();
}

test.describe("Per-asset runbook", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: new asset defaults runbook to empty string", async ({
    request,
  }) => {
    const asset = await seedAsset(request);
    expect(asset.runbook).toBe("");
    // Round-trip GET reflects the default too.
    const fetched = await getAsset(request, "alice", asset.id);
    expect(fetched.runbook).toBe("");
  });

  test("API: PATCH runbook persists; GET reflects it", async ({ request }) => {
    const asset = await seedAsset(request);
    const patch = await patchRunbook(request, "alice", asset.id, RUNBOOK_TEXT);
    expect(patch.status()).toBe(200);
    const updated = await patch.json();
    expect(updated.runbook).toBe(RUNBOOK_TEXT);

    const fetched = await getAsset(request, "alice", asset.id);
    expect(fetched.runbook).toBe(RUNBOOK_TEXT);
  });

  test("API: PATCH runbook empty string clears it", async ({ request }) => {
    const asset = await seedAsset(request);
    expect((await patchRunbook(request, "alice", asset.id, "hello")).status()).toBe(
      200,
    );
    expect(
      (await patchRunbook(request, "alice", asset.id, "")).status(),
    ).toBe(200);
    const fetched = await getAsset(request, "alice", asset.id);
    expect(fetched.runbook).toBe("");
  });

  test("API: non-owner PATCH runbook → 403", async ({ request }) => {
    const asset = await seedAsset(request);
    // Ensure bob exists so the auth layer auto-creates a user row.
    await request.get(`${BACKEND}/api/users/me`, {
      headers: { "X-User-Id": "bob" },
    });
    const res = await patchRunbook(request, "bob", asset.id, "## Hi");
    expect(res.status()).toBe(403);
  });

  test("API: 200 KB write is accepted; subsequent GET is truncated to 100 KB", async ({
    request,
  }) => {
    // The brief leaves the choice between "cap on write" and
    // "cap on read" to the implementer. We chose cap-on-read so a
    // pathological write doesn't reject with an opaque 4xx — the
    // payload is simply clipped on the next fetch.
    const asset = await seedAsset(request);
    const big = "x".repeat(200 * 1024);
    const patch = await patchRunbook(request, "alice", asset.id, big);
    expect(patch.status()).toBe(200);

    const fetched = await getAsset(request, "alice", asset.id);
    // 100 KB cap is the source of truth on the read path.
    expect(fetched.runbook.length).toBe(100 * 1024);
  });

  test("API: PUT update accepts runbook field", async ({ request }) => {
    // The legacy PUT endpoint (used by the edit modal) should also
    // accept the new field. Owner is required (PUT gates on `admin`).
    const asset = await seedAsset(request);
    const res = await request.put(`${BACKEND}/api/assets/${asset.id}`, {
      headers: { "X-User-Id": "alice", "Content-Type": "application/json" },
      data: {
        name: asset.name,
        hostname: asset.hostname,
        description: asset.description,
        classification: asset.classification,
        tags: asset.tags || [],
        runbook: "## via PUT",
      },
    });
    expect(res.status()).toBe(200);
    const fetched = await getAsset(request, "alice", asset.id);
    expect(fetched.runbook).toBe("## via PUT");
  });

  test("UI: AssetDetail renders runbook markdown as HTML, not raw text", async ({
    page,
    request,
  }) => {
    const asset = await seedAsset(request);
    expect(
      (await patchRunbook(request, "alice", asset.id, RUNBOOK_TEXT)).status(),
    ).toBe(200);

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "runbook-host" }).click();

    const section = page.getByTestId("runbook-section");
    await expect(section).toBeVisible({ timeout: 10_000 });

    const rendered = section.getByTestId("runbook-rendered");
    // Heading should be an <h2>, not raw `## Steps`.
    await expect(rendered.locator("h2", { hasText: "Steps" })).toBeVisible();
    // Bullets should be <li> elements inside a <ul>.
    await expect(rendered.locator("ul > li", { hasText: "Restart nginx" })).toBeVisible();
    await expect(
      rendered.locator("ul > li", { hasText: "Verify port 443" }),
    ).toBeVisible();
    // And the raw `##` marker should NOT appear in the rendered output.
    await expect(rendered).not.toContainText("## Steps");
  });

  test("UI: empty runbook shows the placeholder text", async ({
    page,
    request,
  }) => {
    await seedAsset(request);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "runbook-host" }).click();

    const section = page.getByTestId("runbook-section");
    await expect(section).toBeVisible({ timeout: 10_000 });

    const placeholder = section.getByTestId("runbook-placeholder");
    await expect(placeholder).toBeVisible();
    await expect(placeholder).toContainText("No runbook yet");
  });

  test("UI: owner sees Edit button which opens the edit modal with the runbook field", async ({
    page,
    request,
  }) => {
    const asset = await seedAsset(request);
    expect(
      (await patchRunbook(request, "alice", asset.id, "## Hello")).status(),
    ).toBe(200);

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "runbook-host" }).click();

    const section = page.getByTestId("runbook-section");
    await expect(section).toBeVisible({ timeout: 10_000 });
    const editBtn = section.getByTestId("runbook-edit-button");
    await expect(editBtn).toBeVisible();
    await editBtn.click();

    // Modal opens. The Runbook textarea wrapper carries the testid;
    // drill into the actual <textarea> per the project convention.
    const runbookField = page.getByTestId("runbook-textarea").locator("textarea");
    await expect(runbookField).toBeVisible();
    await expect(runbookField).toHaveValue("## Hello");
  });

  test("UI: markdown renderer smoke — exercise each supported syntax", async ({
    page,
    request,
  }) => {
    // Drive the rendered output rather than unit-testing the module
    // directly (no vitest in the repo). Set a runbook covering every
    // supported syntax and assert the DOM has the right tags.
    const sample = [
      "## H2 heading",
      "### H3 heading",
      "",
      "Plain paragraph with **bold** and *italic* and `inline code`.",
      "",
      "- bullet one",
      "- bullet two",
      "",
      "1. first",
      "2. second",
      "",
      "Visit https://example.gov/runbook for details.",
      "",
      "```",
      "fenced code line",
      "```",
    ].join("\n");

    const asset = await seedAsset(request);
    expect(
      (await patchRunbook(request, "alice", asset.id, sample)).status(),
    ).toBe(200);

    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Systems", exact: true }).click();
    await page.getByRole("button", { name: "runbook-host" }).click();

    const r = page.getByTestId("runbook-rendered");
    await expect(r).toBeVisible({ timeout: 10_000 });
    await expect(r.locator("h2", { hasText: "H2 heading" })).toBeVisible();
    await expect(r.locator("h3", { hasText: "H3 heading" })).toBeVisible();
    await expect(r.locator("strong", { hasText: "bold" })).toBeVisible();
    await expect(r.locator("em", { hasText: "italic" })).toBeVisible();
    await expect(r.locator("code", { hasText: "inline code" })).toBeVisible();
    await expect(r.locator("ul > li", { hasText: "bullet one" })).toBeVisible();
    await expect(r.locator("ol > li", { hasText: "first" })).toBeVisible();
    await expect(
      r.locator('a[href="https://example.gov/runbook"]'),
    ).toBeVisible();
    await expect(r.locator("pre code")).toContainText("fenced code line");
  });
});
