import { test, expect } from "@playwright/test";
import { loginAs, openEdgeFromLibrary, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Checklist sets: named, owner-private working checklists with autosave.
 * API: /api/checklist-sets. UI: edit a library STIG (the first edit creates a
 * set), "My checklists", rename, add a STIG, save to a system.
 */

const JSON_HEADERS = (user) => ({ "X-User-Id": user, "Content-Type": "application/json" });
const SETS = `${BACKEND}/api/checklist-sets`;

const ensureUser = (request, user) => request.get(`${BACKEND}/api/users/me`, { headers: { "X-User-Id": user } });

async function createSet(request, user, data = { stigIds: ["edge"] }) {
  const res = await request.post(SETS, { headers: JSON_HEADERS(user), data });
  expect(res.status()).toBe(201);
  return res.json();
}

async function getSet(request, user, id) {
  return request.get(`${SETS}/${id}`, { headers: { "X-User-Id": user } });
}

async function edgeRuleIds(request) {
  const stig = await request.get(`${BACKEND}/api/stigs/edge`).then((r) => r.json());
  return stig.rules.map((r) => r.id);
}

function autosave(request, user, id, revision, changes) {
  return request.patch(`${SETS}/${id}/rules`, { headers: JSON_HEADERS(user), data: { revision, changes } });
}

async function seedAsset(request, name = "set-host", owner = "alice") {
  return request.post(`${BACKEND}/api/assets`, { headers: JSON_HEADERS(owner), data: { name } }).then((r) => r.json());
}

async function openEdge(page) {
  await openEdgeFromLibrary(page);
  const listbox = page.getByRole("listbox", { name: "Rules" });
  await expect(listbox.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
  return listbox;
}

test.describe("Checklist sets — API", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("create, read, rename, delete", async ({ request }) => {
    const created = await createSet(request, "alice");
    expect(created.name).toMatch(/^edge \d{4}-\d{2}-\d{2}$/);
    expect(created.revision).toBe(0);
    expect(created.stigs.map((s) => s.stigId)).toEqual(["edge"]);

    const renamed = await request.patch(`${SETS}/${created.id}`, {
      headers: JSON_HEADERS("alice"),
      data: { name: "  Quarterly review " },
    });
    expect(renamed.status()).toBe(200);
    expect((await renamed.json()).name).toBe("Quarterly review");

    const list = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    expect(list.map((s) => s.id)).toEqual([created.id]);
    expect(list[0].stigCount).toBe(1);
    expect(list[0].touchedCount).toBe(0);

    expect((await request.delete(`${SETS}/${created.id}`, { headers: { "X-User-Id": "alice" } })).status()).toBe(204);
    expect((await getSet(request, "alice", created.id)).status()).toBe(404);
  });

  test("validation: bad names and STIG ids are 400", async ({ request }) => {
    const post = (data) => request.post(SETS, { headers: JSON_HEADERS("alice"), data });
    expect((await post({ stigIds: [] })).status()).toBe(400);
    expect((await post({ stigIds: ["../etc"] })).status()).toBe(400);
    expect((await post({ stigIds: ["no-such-stig"] })).status()).toBe(400);
    expect((await post({ stigIds: ["edge"], name: "x".repeat(121) })).status()).toBe(400);
  });

  test("sets are private: other users and admins get 404", async ({ request }) => {
    const set = await createSet(request, "alice");
    await ensureUser(request, "mallory");
    await setUserRole("root-admin", "admin");
    for (const user of ["mallory", "root-admin"]) {
      expect((await getSet(request, user, set.id)).status()).toBe(404);
      expect((await request.delete(`${SETS}/${set.id}`, { headers: { "X-User-Id": user } })).status()).toBe(404);
      expect((await autosave(request, user, set.id, 0, [])).status()).toBe(404);
      const list = await request.get(SETS, { headers: { "X-User-Id": user } }).then((r) => r.json());
      expect(list).toEqual([]);
    }
  });

  test("autosave replaces state exactly; a stale revision is 409 and writes nothing", async ({ request }) => {
    const set = await createSet(request, "alice");
    const ids = await edgeRuleIds(request);
    const first = await autosave(request, "alice", set.id, 0, [
      { stigId: "edge", ruleId: ids[0], status: "open", findingDetails: "", comments: "note" },
      { stigId: "edge", ruleId: ids[1], status: "not_a_finding", findingDetails: "ok", comments: "" },
    ]);
    expect(first.status()).toBe(200);
    expect((await first.json()).revision).toBe(1);

    const stale = await autosave(request, "alice", set.id, 0, [
      { stigId: "edge", ruleId: ids[2], status: "open", findingDetails: "", comments: "" },
    ]);
    expect(stale.status()).toBe(409);
    expect(await stale.json()).toEqual({ error: "revision_conflict", revision: 1 });

    // Back to untouched deletes the stored row.
    const back = await autosave(request, "alice", set.id, 1, [
      { stigId: "edge", ruleId: ids[0], status: "not_reviewed", findingDetails: "", comments: "" },
    ]);
    expect(back.status()).toBe(200);
    const detail = await getSet(request, "alice", set.id).then((r) => r.json());
    expect(detail.revision).toBe(2);
    expect(detail.stigs[0].rules.map((r) => r.ruleId)).toEqual([ids[1]]);
  });

  test("autosave rejects a bad request whole", async ({ request }) => {
    const set = await createSet(request, "alice");
    const ids = await edgeRuleIds(request);
    const good = { stigId: "edge", ruleId: ids[0], status: "open", findingDetails: "", comments: "" };
    for (const bad of [
      { ...good, stigId: "windows-10" },
      { ...good, status: "bogus" },
      { ...good, comments: "x".repeat(33 * 1024) },
      { ...good, comments: "a\u0000b" },
    ]) {
      expect((await autosave(request, "alice", set.id, 0, [good, bad])).status()).toBe(400);
    }
    const detail = await getSet(request, "alice", set.id).then((r) => r.json());
    expect(detail.revision).toBe(0);
    expect(detail.stigs[0].rules).toEqual([]);
  });

  test("autosave refuses an empty rule id", async ({ request }) => {
    const set = await createSet(request, "alice");
    const res = await autosave(request, "alice", set.id, 0, [
      { stigId: "edge", ruleId: "", status: "open", findingDetails: "", comments: "" },
    ]);
    expect(res.status()).toBe(400);
  });

  test("add and remove a STIG", async ({ request }) => {
    const set = await createSet(request, "alice");
    const add = () =>
      request.post(`${SETS}/${set.id}/stigs`, { headers: JSON_HEADERS("alice"), data: { stigId: "windows-10" } });
    expect((await add()).status()).toBe(200);
    expect((await add()).status()).toBe(200); // idempotent
    let detail = await getSet(request, "alice", set.id).then((r) => r.json());
    expect(detail.stigs.map((s) => s.stigId)).toEqual(["edge", "windows-10"]);
    const removed = await request.delete(`${SETS}/${set.id}/stigs/windows-10`, { headers: { "X-User-Id": "alice" } });
    expect(removed.status()).toBe(200);
    detail = await getSet(request, "alice", set.id).then((r) => r.json());
    expect(detail.stigs.map((s) => s.stigId)).toEqual(["edge"]);
    expect(detail.revision).toBe(1);
  });

  test("a viewer cannot create or change sets", async ({ request }) => {
    await setUserRole("viewer-vic", "viewer");
    const res = await request.post(SETS, { headers: JSON_HEADERS("viewer-vic"), data: { stigIds: ["edge"] } });
    expect(res.status()).toBe(403);
    const list = await request.get(SETS, { headers: { "X-User-Id": "viewer-vic" } });
    expect(list.status()).toBe(200);
  });

  test("save to a system fans out, links the set, and can be repeated", async ({ request }) => {
    const asset = await seedAsset(request);
    const set = await createSet(request, "alice", { stigIds: ["edge", "windows-10"] });
    const ids = await edgeRuleIds(request);
    await autosave(request, "alice", set.id, 0, [
      { stigId: "edge", ruleId: ids[0], status: "open", findingDetails: "", comments: "" },
    ]);
    const push = (revision, data = {}) =>
      request.post(`${SETS}/${set.id}/save-to-system`, { headers: JSON_HEADERS("alice"), data: { revision, ...data } });

    expect((await push(0, { assetId: asset.id })).status()).toBe(409); // stale
    expect((await push(1)).status()).toBe(400); // no target
    const first = await push(1, { assetId: asset.id }).then((r) => r.json());
    expect(first.assetId).toBe(asset.id);
    expect(first.results.map((r) => [r.stigId, r.ok])).toEqual([["edge", true], ["windows-10", true]]);
    expect(first.results[0].save.appliedCount).toBe(1);

    const checklists = await request
      .get(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(checklists.map((c) => c.stigId).sort()).toEqual(["edge", "windows-10"]);

    // The set stays linked and a second push changes nothing.
    const again = await push(1).then((r) => r.json());
    expect(again.results[0].save.unchangedCount).toBe(1);
    expect(again.results[0].save.appliedCount).toBe(0);
    const detail = await getSet(request, "alice", set.id).then((r) => r.json());
    expect(detail.assetId).toBe(asset.id);

    // Another system needs an unlink first.
    const other = await seedAsset(request, "other-host");
    expect((await push(1, { assetId: other.id })).status()).toBe(400);
    const unlinked = await request.patch(`${SETS}/${set.id}`, { headers: JSON_HEADERS("alice"), data: { assetId: null } });
    expect((await unlinked.json()).assetId).toBeNull();
  });

  test("save to a system needs write access to it", async ({ request }) => {
    const asset = await seedAsset(request);
    await ensureUser(request, "mallory");
    const set = await createSet(request, "mallory");
    const res = await request.post(`${SETS}/${set.id}/save-to-system`, {
      headers: JSON_HEADERS("mallory"),
      data: { revision: 0, assetId: asset.id },
    });
    expect(res.status()).toBe(403);
    const checklists = await request
      .get(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(checklists).toEqual([]);
  });

  test("create with a repeated clientRequestId returns the same set", async ({ request }) => {
    const data = { stigIds: ["edge"], clientRequestId: "0b9d6f0e-39a4-4d7a-9a0e-5d6a1c2b3e4f" };
    const first = await request.post(SETS, { headers: JSON_HEADERS("alice"), data });
    expect(first.status()).toBe(201);
    const again = await request.post(SETS, { headers: JSON_HEADERS("alice"), data });
    expect(again.status()).toBe(200);
    expect((await again.json()).id).toBe((await first.json()).id);
    const list = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    expect(list).toHaveLength(1);
    const bad = await request.post(SETS, { headers: JSON_HEADERS("alice"), data: { ...data, clientRequestId: "nope" } });
    expect(bad.status()).toBe(400);
  });

  test("an autosave replayed with its saveId is acknowledged; after another write it is a 409", async ({ request }) => {
    const set = await createSet(request, "alice");
    const ids = await edgeRuleIds(request);
    const saveId = "7c1e2f3a-4b5c-4d6e-8f70-91a2b3c4d5e6";
    const change = [{ stigId: "edge", ruleId: ids[0], status: "open", findingDetails: "", comments: "" }];
    const send = (revision, id) =>
      request.patch(`${SETS}/${set.id}/rules`, {
        headers: JSON_HEADERS("alice"),
        data: { revision, changes: change, saveId: id },
      });
    const first = await send(0, saveId);
    expect(first.status()).toBe(200);
    expect((await first.json()).revision).toBe(1);
    const replay = await send(0, saveId);
    expect(replay.status()).toBe(200);
    expect((await replay.json()).revision).toBe(1);
    // Another write moves the set on; the old request is now a real conflict.
    expect((await autosave(request, "alice", set.id, 1, [])).status()).toBe(200);
    expect((await send(0, saveId)).status()).toBe(409);
  });

  test("a clientRequestId reused with different stigIds is a 409 and creates nothing", async ({ request }) => {
    const key = "0b9d6f0e-39a4-4d7a-9a0e-5d6a1c2b3e4f";
    const first = await request.post(SETS, { headers: JSON_HEADERS("alice"), data: { stigIds: ["edge"], clientRequestId: key } });
    expect(first.status()).toBe(201);
    const other = await request.post(SETS, {
      headers: JSON_HEADERS("alice"),
      data: { stigIds: ["edge", "windows-10"], clientRequestId: key },
    });
    expect(other.status()).toBe(409);
    expect(await other.json()).toEqual({ error: "request_id_conflict" });
    const list = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    expect(list).toHaveLength(1);
  });

  test("a saveId reused at the same revision with different changes is a 409 and changes nothing", async ({ request }) => {
    const set = await createSet(request, "alice");
    const ids = await edgeRuleIds(request);
    const saveId = "7c1e2f3a-4b5c-4d6e-8f70-91a2b3c4d5e6";
    const send = (changes) =>
      request.patch(`${SETS}/${set.id}/rules`, { headers: JSON_HEADERS("alice"), data: { revision: 0, changes, saveId } });
    const original = [{ stigId: "edge", ruleId: ids[0], status: "open", findingDetails: "", comments: "" }];
    expect((await send(original)).status()).toBe(200);
    const changed = [{ stigId: "edge", ruleId: ids[0], status: "not_a_finding", findingDetails: "x", comments: "" }];
    const res = await send(changed);
    expect(res.status()).toBe(409);
    expect(await res.json()).toEqual({ error: "revision_conflict", revision: 1 });
    const detail = await getSet(request, "alice", set.id).then((r) => r.json());
    expect(detail.revision).toBe(1);
    expect(detail.stigs[0].rules).toHaveLength(1);
    expect(detail.stigs[0].rules[0].status).toBe("open");
    // The exact original is still acknowledged.
    expect((await send(original)).status()).toBe(200);
  });

  test("autosave shares the per-user mutation budget", async ({ request }) => {
    expect((await request.post(`${BACKEND}/api/test/reset-ratelimit`)).status()).toBe(204);
    const set = await createSet(request, "alice");
    let limited = null;
    for (let i = 0; i < 30 && !limited; i++) {
      const res = await request.patch(`${SETS}/${set.id}`, {
        headers: JSON_HEADERS("alice"),
        data: { name: `name ${i}` },
      });
      if (res.status() === 429) limited = res;
    }
    expect(limited).not.toBeNull();
    expect(limited.headers()["retry-after"]).toBeTruthy();
    expect((await request.post(`${BACKEND}/api/test/reset-ratelimit`)).status()).toBe(204);
  });
});

test.describe("Checklist sets — UI", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("the first edit creates a set, autosaves, and resumes from My checklists", async ({ page, request }) => {
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    // Opening a STIG alone creates nothing.
    expect(await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json())).toEqual([]);

    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved \d\d:\d\d/, { timeout: 20_000 });

    const sets = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    expect(sets).toHaveLength(1);
    expect(sets[0].touchedCount).toBe(1);

    // Reload and resume.
    await page.reload();
    await page.getByRole("button", { name: "My checklists" }).click();
    await page.getByTestId("set-open").click();
    const again = page.getByRole("listbox", { name: "Rules" });
    await expect(again.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
    await expect(again.getByRole("option").nth(0)).toContainText(/open/i);
  });

  test("rename, add a second STIG, then save both to a system and re-save after an edit", async ({ page, request }) => {
    const asset = await seedAsset(request);
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });

    await page.getByTestId("set-rename").click();
    await page.getByTestId("set-name-input").locator("input").fill("My review");
    await page.getByTestId("set-name-save").click();
    await expect(page.getByTestId("set-name")).toHaveText("My review");

    await page.getByTestId("set-add-stig").click();
    await page.getByTestId("set-add-stig-select").click();
    await page.getByRole("option", { name: /Windows 10/ }).first().click();
    await page.keyboard.press("Escape"); // close the dropdown that covers the Add button
    await page.getByTestId("set-add-stig-apply").click();
    await expect(page.getByRole("link", { name: /My review · .*Windows 10/ })).toBeVisible({ timeout: 15_000 });

    await page.getByRole("link", { name: /My review · .*Edge/ }).click();
    await page.getByTestId("save-to-system").click();
    await page.getByTestId("save-system-select").click();
    await page.getByRole("option", { name: /set-host/ }).click();
    await page.getByTestId("save-system-apply").click();
    await expect(page.getByTestId("save-system-result")).toContainText("Saved 1 rule to set-host.");
    const checklists = await request
      .get(`${BACKEND}/api/assets/${asset.id}/checklists`, { headers: { "X-User-Id": "alice" } })
      .then((r) => r.json());
    expect(checklists).toHaveLength(2);
    await page.getByRole("button", { name: "Close", exact: true }).click();

    // Edit again and re-save: the system is preselected and locked.
    await page.getByRole("option").nth(1).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await page.getByTestId("save-to-system").click();
    await expect(page.getByTestId("save-system-unlink")).toBeVisible();
    await page.getByTestId("save-system-apply").click();
    await expect(page.getByTestId("save-system-result")).toContainText("Saved 1 rule to set-host.");
  });

  test("a change from another tab shows the conflict alert", async ({ browser, request }) => {
    const ctxA = await browser.newContext();
    const pageA = await ctxA.newPage();
    await loginAs(pageA, "alice");
    const listbox = await openEdge(pageA);
    await listbox.getByRole("option").nth(0).click();
    await pageA.getByRole("button", { name: "Open", exact: true }).click();
    await expect(pageA.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });

    // Someone else (same user, another device) saves a change.
    const [set] = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    const ids = await edgeRuleIds(request);
    const res = await autosave(request, "alice", set.id, set.revision, [
      { stigId: "edge", ruleId: ids[5], status: "open", findingDetails: "", comments: "elsewhere" },
    ]);
    expect(res.status()).toBe(200);

    await listbox.getByRole("option").nth(1).click();
    await pageA.getByRole("button", { name: "Open", exact: true }).click();
    await expect(pageA.getByTestId("set-conflict")).toContainText("Changed in another tab or device", { timeout: 20_000 });
    await pageA.getByTestId("set-conflict-keep").click();
    await expect(pageA.getByTestId("set-conflict")).toHaveCount(0);
    await expect(pageA.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });
    const detail = await getSet(request, "alice", set.id).then((r) => r.json());
    // The first edit, the other device's edit and the second edit are all kept.
    const stored = detail.stigs[0].rules;
    expect(stored).toHaveLength(3);
    expect(stored.find((r) => r.ruleId === ids[5]).comments).toBe("elsewhere");
    await ctxA.close();
  });

  test("Reload latest discards the unsaved edit and shows the server's values", async ({ browser, request }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });

    // Another device saves rule 5 as Open.
    const [set] = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    const ids = await edgeRuleIds(request);
    const res = await autosave(request, "alice", set.id, set.revision, [
      { stigId: "edge", ruleId: ids[5], status: "open", findingDetails: "", comments: "elsewhere" },
    ]);
    expect(res.status()).toBe(200);

    // The local edit (rule 1 Open) hits the conflict. Open: 2 = rules 0 and 1 here.
    await listbox.getByRole("option").nth(1).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page.getByText("Open: 2")).toBeVisible();
    await expect(page.getByTestId("set-conflict")).toBeVisible({ timeout: 20_000 });

    await page.getByTestId("set-conflict-reload").click();
    await expect(page.getByTestId("set-conflict")).toHaveCount(0);
    // Rules 0 (saved) and 5 (other device) are Open; the unsaved rule 1 is gone.
    await expect(page.getByText("Open: 2")).toBeVisible();
    await expect(listbox.getByRole("option").nth(5)).toContainText(/open/i);
    const detail = await getSet(request, "alice", set.id).then((r) => r.json());
    expect(detail.stigs[0].rules.map((r) => r.ruleId).sort()).toEqual([ids[0], ids[5]].sort());
    await ctx.close();
  });

  test("closing the page with unsaved edits prompts; once saved it does not", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    // Still inside the debounce window: the edit is unsaved.
    await expect(page.getByTestId("autosave-status")).toContainText(/Unsaved|Saving/);
    // close({ runBeforeUnload }) does not wait, so wait for the dialog itself.
    const prompt = page.waitForEvent("dialog");
    await page.close({ runBeforeUnload: true });
    const dialog = await prompt;
    expect(dialog.type()).toBe("beforeunload");
    await dialog.dismiss();
    expect(page.isClosed()).toBe(false);
    await page.close();

    // A fresh page: edit, wait for Saved, then closing is silent.
    const page2 = await ctx.newPage();
    const listbox2 = await openEdge(page2);
    await listbox2.getByRole("option").nth(1).click();
    await page2.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page2.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });
    const seen = [];
    page2.on("dialog", (d) => {
      seen.push(d.type());
      d.dismiss();
    });
    const closed = page2.waitForEvent("close");
    await page2.close({ runBeforeUnload: true });
    await closed;
    expect(seen).toEqual([]);
    await ctx.close();
  });

  test("signing out right after an edit still saves it", async ({ page, request }) => {
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await page.getByRole("button", { name: "alice" }).click();
    await page.getByRole("menuitem", { name: "Sign out" }).click();
    await expect
      .poll(async () => {
        const sets = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
        return sets[0]?.touchedCount ?? 0;
      })
      .toBe(1);
  });

  test("a save whose response is lost does not raise a conflict", async ({ page, request }) => {
    test.setTimeout(60_000);
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });
    const [set] = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());

    // The server applies the next save, but the browser never sees the answer.
    let patches = 0;
    await page.route("**/api/checklist-sets/*/rules", async (route) => {
      patches += 1;
      if (patches === 1) {
        await route.fetch();
        await route.abort();
        return;
      }
      await route.continue();
    });
    await listbox.getByRole("option").nth(1).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    // The dropped answer shows first, then the retry settles it.
    await expect(page.getByTestId("autosave-status")).toContainText(/Offline - will retry/, { timeout: 30_000 });
    await expect.poll(() => patches, { timeout: 30_000 }).toBeGreaterThanOrEqual(2);
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 30_000 });
    await expect(page.getByTestId("set-conflict")).toHaveCount(0);
    // Both edits are stored, on revisions 1 and 2 (one write per save).
    await expect
      .poll(async () => {
        const d = await getSet(request, "alice", set.id).then((r) => r.json());
        return `${d.revision}:${d.stigs[0].rules.length}`;
      })
      .toBe("2:2");
  });

  test("a create whose response is lost makes one set", async ({ page, request }) => {
    test.setTimeout(60_000);
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    let posts = 0;
    await page.route(new RegExp("/api/checklist-sets$"), async (route) => {
      if (route.request().method() === "POST") {
        posts += 1;
        if (posts === 1) {
          await route.fetch();
          await route.abort();
          return;
        }
      }
      await route.continue();
    });
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect.poll(() => posts, { timeout: 30_000 }).toBeGreaterThanOrEqual(2);
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 40_000 });
    const sets = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    expect(sets).toHaveLength(1);
    expect(sets[0].touchedCount).toBe(1);
  });

  test("My checklists reports a request that never answers", async ({ page }) => {
    test.setTimeout(45_000);
    await loginAs(page, "alice");
    await page.goto("/");
    await page.route(new RegExp("/api/checklist-sets$"), () => {
      // Never fulfil or continue: the request hangs until the client gives up.
    });
    await page.getByRole("button", { name: "My checklists" }).click();
    await expect(page.getByText(/timed out/i).first()).toBeVisible({ timeout: 25_000 });
  });

  test("a save in doubt after pagehide is resent unchanged and settles without a conflict", async ({ page, request }) => {
    test.setTimeout(60_000);
    // Record every fetch made with keepalive (the pagehide save).
    await page.addInitScript(() => {
      window.__keepalives = [];
      const orig = window.fetch.bind(window);
      window.fetch = (input, init) => {
        if (init && init.keepalive === true) {
          window.__keepalives.push({ url: String(input), method: init.method, body: String(init.body) });
        }
        return orig(input, init);
      };
    });
    const bodies = [];
    await page.route("**/api/checklist-sets/*/rules", async (route) => {
      if (route.request().method() === "PATCH") bodies.push(route.request().postData());
      await route.continue();
    });
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });
    const [set] = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());

    // Edit again and hide the page inside the 3 s debounce window.
    await listbox.getByRole("option").nth(1).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
    const keepalives = await page.evaluate(() => window.__keepalives);
    expect(keepalives).toHaveLength(1);
    expect(keepalives[0].method).toBe("PATCH");
    expect(keepalives[0].url).toMatch(/\/api\/checklist-sets\/[^/]+\/rules$/);
    const sent = JSON.parse(keepalives[0].body);
    expect(sent.revision).toBe(1);
    expect(sent.saveId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

    // The page lived on: the in-doubt body is resent as it was, and the server
    // acknowledges it as a replay rather than a conflict.
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 30_000 });
    await expect(page.getByTestId("set-conflict")).toHaveCount(0);
    expect(bodies.at(-1)).toBe(keepalives[0].body);
    await expect
      .poll(async () => {
        const d = await getSet(request, "alice", set.id).then((r) => r.json());
        return `${d.revision}:${d.stigs[0].rules.length}`;
      })
      .toBe("2:2");
  });

  test("a save in doubt that the set has moved past raises the conflict alert", async ({ page, request }) => {
    test.setTimeout(60_000);
    await loginAs(page, "alice");
    const listbox = await openEdge(page);
    await listbox.getByRole("option").nth(0).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect(page.getByTestId("autosave-status")).toContainText(/Saved/, { timeout: 20_000 });
    const [set] = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());

    // The next save never reaches the server, and the set moves on meanwhile.
    let patches = 0;
    await page.route("**/api/checklist-sets/*/rules", async (route) => {
      patches += 1;
      if (patches === 1) {
        expect((await autosave(request, "alice", set.id, 1, [])).status()).toBe(200);
        await route.abort();
        return;
      }
      await route.continue();
    });
    await listbox.getByRole("option").nth(1).click();
    await page.getByRole("button", { name: "Open", exact: true }).click();
    await expect.poll(() => patches, { timeout: 30_000 }).toBeGreaterThanOrEqual(2);
    await expect(page.getByTestId("set-conflict")).toBeVisible({ timeout: 30_000 });
  });

  test("a create whose answer stalls mid-body is reported as timed out", async ({ page }) => {
    test.setTimeout(45_000);
    // Headers arrive, the body never finishes; the client's own timer must fire
    // and abort it. The fake body follows the request's abort signal.
    await page.addInitScript(() => {
      const orig = window.fetch.bind(window);
      window.fetch = (input, init) => {
        const req = input instanceof Request ? input : null;
        const url = req ? req.url : String(input);
        const method = ((init && init.method) || (req && req.method) || "GET").toUpperCase();
        if (window.__stallBody && method === "GET" && /\/api\/checklist-sets$/.test(url)) {
          const signal = (init && init.signal) || (req && req.signal);
          const body = new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("["));
              if (signal) {
                signal.addEventListener("abort", () => controller.error(new DOMException("aborted", "AbortError")));
              }
            },
          });
          return Promise.resolve(new Response(body, { status: 200, headers: { "Content-Type": "application/json" } }));
        }
        return orig(input, init);
      };
    });
    await loginAs(page, "alice");
    await page.goto("/");
    await page.evaluate(() => {
      window.__stallBody = true;
    });
    await page.getByRole("button", { name: "My checklists" }).click();
    await expect(page.getByText(/timed out/i).first()).toBeVisible({ timeout: 25_000 });
  });

  test("deleting a set that is already gone is not an error", async ({ page, request }) => {
    await createSet(request, "alice");
    const [set] = await request.get(SETS, { headers: { "X-User-Id": "alice" } }).then((r) => r.json());
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "My checklists" }).click();
    await expect(page.getByTestId("set-open")).toHaveCount(1);
    expect((await request.delete(`${SETS}/${set.id}`, { headers: { "X-User-Id": "alice" } })).status()).toBe(204);
    page.on("dialog", (d) => d.accept());
    const deleted = page.waitForResponse((r) => r.request().method() === "DELETE" && r.url().includes("/api/checklist-sets/"));
    await page.getByTestId("set-delete").click();
    expect((await deleted).status()).toBe(404);
    await expect(page.getByTestId("set-open")).toHaveCount(0);
    await expect(page.getByText(/Delete failed/)).toHaveCount(0);
  });

  test("a request id the server rejects as reused is replaced on the next create", async ({ page }) => {
    const keys = [];
    await page.route(new RegExp("/api/checklist-sets$"), async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      keys.push(JSON.parse(route.request().postData() ?? "{}").clientRequestId);
      return route.fulfill({
        status: 409,
        contentType: "application/json",
        body: JSON.stringify({ error: "request_id_conflict" }),
      });
    });
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "My checklists" }).click();
    await page.getByTestId("new-set-stigs").click();
    await page.getByRole("option", { name: /edge/i }).first().click();
    await page.getByRole("heading", { name: "New checklist" }).click();
    const create = page.getByTestId("new-set-create");
    await create.click();
    await expect(page.getByText("Could not create the checklist. Try again.")).toBeVisible();
    await create.click();
    await expect.poll(() => keys.length).toBe(2);
    expect(keys[0]).toBeTruthy();
    expect(keys[1]).toBeTruthy();
    expect(keys[1]).not.toBe(keys[0]);
  });

  test("a local file tab is marked as not saved to the account", async ({ page }) => {
    await loginAs(page, "alice");
    await page.goto("/");
    await page.getByRole("button", { name: "Open Local File" }).click();
    await page.getByRole("button", { name: "Load Demo STIG" }).click();
    await expect(page.getByTestId("local-file-note")).toContainText("Not saved to your account");
  });
});
