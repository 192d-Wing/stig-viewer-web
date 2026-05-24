import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

/**
 * Seed a catalog_archive row for `edge` with the given rule list. The
 * "previous" snapshot lets the diff endpoint compare against the live
 * edge.json without us having to run a real DISA sync. Wraps the
 * STIG_ENV-gated /api/test/seed-archive helper added by this feature.
 */
async function seedArchive(request, rules) {
  const res = await request.post(`${BACKEND}/api/test/seed-archive`, {
    headers: { "Content-Type": "application/json" },
    data: {
      stigId: "edge",
      version: "1",
      releaseInfo: "Release: 1 Benchmark Date: 01 Jan 2024",
      rules,
    },
  });
  expect(res.ok()).toBeTruthy();
  return res.json();
}

/** Pull the first three live edge rules so we can build an archive
 * that differs by exactly one removal, one addition, and one title
 * change. Using the real catalog instead of hard-coding ids keeps the
 * test resilient to catalog refreshes. */
async function liveEdgeRules(request) {
  const res = await request.get(`${BACKEND}/api/stigs/edge`);
  expect(res.ok()).toBeTruthy();
  const stig = await res.json();
  return stig.rules;
}

test.describe("Catalog version diff", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: diff with no archive returns 404", async ({ request }) => {
    const res = await request.get(`${BACKEND}/api/stigs/edge/diff`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.status()).toBe(404);
  });

  test("API: diff returns expected added / removed / changed", async ({
    request,
  }) => {
    const live = await liveEdgeRules(request);
    // Take the first two live rules; "previous" snapshot contains
    // them PLUS one extra (which becomes "removed") and the FIRST
    // live rule's title is mutated so it shows up as "changed". The
    // SECOND live rule (and any later ones not in the seed) become
    // "added" relative to the previous snapshot.
    const removedId = "SV-removed-fake_rule";
    const previousRules = [
      {
        id: live[0].id,
        title: "OLD TITLE",
        severity: live[0].severity,
        description: live[0].description,
        fixText: live[0].fixText,
        checkText: live[0].checkText,
      },
      {
        id: removedId,
        title: "Rule that no longer exists",
        severity: "CAT II",
        description: "",
        fixText: "",
        checkText: "",
      },
    ];
    await seedArchive(request, previousRules);

    const res = await request.get(`${BACKEND}/api/stigs/edge/diff`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.ok()).toBeTruthy();
    const diff = await res.json();

    expect(diff.stigId).toBe("edge");
    expect(diff.fromVersion).toBe("1");
    // Removed list must contain our fake id and exclude live rules.
    const removedIds = diff.removed.map((r) => r.id);
    expect(removedIds).toContain(removedId);
    // Added list must contain at least the second live rule (which
    // was not in the seeded previous snapshot).
    const addedIds = diff.added.map((r) => r.id);
    expect(addedIds).toContain(live[1].id);
    // Changed list must include a title change for the first rule
    // since the seed had "OLD TITLE" but live JSON has the real title.
    const titleChange = diff.changed.find(
      (c) => c.id === live[0].id && c.field === "title",
    );
    expect(titleChange).toBeTruthy();
    expect(titleChange.from).toBe("OLD TITLE");
    expect(titleChange.to).toBe(live[0].title);
  });

  test("API: archive list returns the seeded row", async ({ request }) => {
    await seedArchive(request, []);
    const res = await request.get(`${BACKEND}/api/stigs/edge/archive`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(res.ok()).toBeTruthy();
    const list = await res.json();
    expect(Array.isArray(list)).toBe(true);
    expect(list.length).toBeGreaterThanOrEqual(1);
    expect(list[0].stigId).toBe("edge");
    expect(list[0].version).toBe("1");
  });

  test("UI: clicking the Diff button opens the modal with sections populated", async ({
    page,
    request,
  }) => {
    const live = await liveEdgeRules(request);
    const removedId = "SV-removed-fake_rule";
    await seedArchive(request, [
      {
        id: live[0].id,
        title: "OLD TITLE",
        severity: live[0].severity,
        description: live[0].description,
        fixText: live[0].fixText,
        checkText: live[0].checkText,
      },
      {
        id: removedId,
        title: "Rule that no longer exists",
        severity: "CAT II",
        description: "",
        fixText: "",
        checkText: "",
      },
    ]);

    await loginAs(page, "alice");
    await page.goto("/");
    // Find the edge row's Diff button via the per-row testid set by
    // the StigLibrary column definition.
    const diffBtn = page.getByTestId("diff-button-edge");
    await expect(diffBtn).toBeVisible({ timeout: 10_000 });
    await diffBtn.click();

    const modal = page.getByTestId("catalog-diff-modal");
    await expect(modal).toBeVisible();

    // Each section testid is rendered regardless of whether items
    // exist, so we can assert on them directly. We then check that
    // the relevant rule ids appear under each section.
    const added = page.getByTestId("catalog-diff-added");
    const removed = page.getByTestId("catalog-diff-removed");
    const changed = page.getByTestId("catalog-diff-changed");
    await expect(added).toContainText(live[1].id);
    await expect(removed).toContainText(removedId);
    await expect(changed).toContainText(live[0].id);
  });
});
