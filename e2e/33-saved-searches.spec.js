import { test, expect } from "@playwright/test";
import { loginAs, resetDb, BACKEND } from "./helpers.js";

async function meId(request, userName) {
  return (
    await (
      await request.get(`${BACKEND}/api/users/me`, {
        headers: { "X-User-Id": userName },
      })
    ).json()
  ).id;
}

async function createSearch(request, userName, body) {
  return request.post(`${BACKEND}/api/saved-searches`, {
    headers: { "X-User-Id": userName, "Content-Type": "application/json" },
    data: body,
  });
}

async function listSearches(request, userName, page) {
  const url = page
    ? `${BACKEND}/api/saved-searches?page=${encodeURIComponent(page)}`
    : `${BACKEND}/api/saved-searches`;
  return request.get(url, { headers: { "X-User-Id": userName } });
}

test.describe("Saved searches", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: POST creates a saved search, GET returns it, DELETE removes it", async ({
    request,
  }) => {
    // Ensure the user exists.
    await meId(request, "alice");

    const created = await createSearch(request, "alice", {
      page: "myfindings",
      name: "Critical only",
      params: "sev=CAT+I",
    });
    expect(created.status()).toBe(201);
    const row = await created.json();
    expect(row.name).toBe("Critical only");
    expect(row.page).toBe("myfindings");
    expect(row.params).toBe("sev=CAT+I");
    expect(typeof row.id).toBe("string");

    const list = await listSearches(request, "alice", "myfindings");
    expect(list.status()).toBe(200);
    const rows = await list.json();
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(row.id);

    // No page filter returns the same row (alice only has one).
    const allList = await listSearches(request, "alice");
    expect((await allList.json()).map((r) => r.id)).toContain(row.id);

    const del = await request.delete(`${BACKEND}/api/saved-searches/${row.id}`, {
      headers: { "X-User-Id": "alice" },
    });
    expect(del.status()).toBe(204);

    const after = await listSearches(request, "alice", "myfindings");
    expect(await after.json()).toHaveLength(0);
  });

  test("API: empty name / page returns 400", async ({ request }) => {
    await meId(request, "alice");

    const blankName = await createSearch(request, "alice", {
      page: "myfindings",
      name: "  ",
      params: "sev=CAT+I",
    });
    expect(blankName.status()).toBe(400);

    const blankPage = await createSearch(request, "alice", {
      page: "",
      name: "x",
      params: "",
    });
    expect(blankPage.status()).toBe(400);
  });

  test("API: same name on the same page returns 409", async ({ request }) => {
    await meId(request, "alice");
    const first = await createSearch(request, "alice", {
      page: "myfindings",
      name: "Mine",
      params: "sev=CAT+II",
    });
    expect(first.status()).toBe(201);

    const dup = await createSearch(request, "alice", {
      page: "myfindings",
      name: "Mine",
      params: "sev=CAT+III",
    });
    expect(dup.status()).toBe(409);

    // Same name, different page → allowed.
    const otherPage = await createSearch(request, "alice", {
      page: "dashboard",
      name: "Mine",
      params: "sev=CAT+II",
    });
    expect(otherPage.status()).toBe(201);
  });

  test("API: another user can't see or delete the first user's searches", async ({
    request,
  }) => {
    await meId(request, "alice");
    await meId(request, "bob");
    const created = await createSearch(request, "alice", {
      page: "myfindings",
      name: "alice-only",
      params: "sev=CAT+I",
    });
    expect(created.status()).toBe(201);
    const row = await created.json();

    // Bob's list is empty.
    const bobList = await listSearches(request, "bob", "myfindings");
    expect(bobList.status()).toBe(200);
    expect(await bobList.json()).toHaveLength(0);

    // Bob can't delete alice's row.
    const bobDel = await request.delete(
      `${BACKEND}/api/saved-searches/${row.id}`,
      { headers: { "X-User-Id": "bob" } },
    );
    expect(bobDel.status()).toBe(404);

    // Alice still sees it.
    const aliceList = await listSearches(request, "alice", "myfindings");
    expect((await aliceList.json()).map((r) => r.id)).toContain(row.id);
  });

  test("UI: save current view from My Findings, then apply it", async ({
    page,
    request,
  }) => {
    await meId(request, "alice");
    await loginAs(page, "alice");

    // Land on My Findings with sev=CAT I pre-applied via the URL.
    await page.goto("/?view=myfindings&sev=CAT+I");
    await expect(
      page.getByRole("heading", { name: /^My findings/i }),
    ).toBeVisible();

    // Save the current view.
    await page.getByRole("button", { name: "Save current view" }).click();
    const dialog = page.getByRole("dialog", { name: /Save current view/i });
    await expect(dialog).toBeVisible();
    await dialog.getByPlaceholder(/e\.g\. CAT I only/i).fill("Critical only");
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await expect(dialog).toBeHidden();

    // Clear the URL filter — saved search should restore it.
    await page.goto("/?view=myfindings");
    await expect(
      page.getByRole("heading", { name: /^My findings/i }),
    ).toBeVisible();

    // Pick the saved search from the dropdown.
    await page
      .getByRole("button", { name: /Apply saved search/i })
      .click();
    await page.getByRole("option", { name: /Critical only/i }).click();

    // URL should now carry the saved params again.
    await expect(page).toHaveURL(/[?&]sev=CAT(\+|%20)I\b/);
  });
});
