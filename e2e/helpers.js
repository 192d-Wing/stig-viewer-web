import { readFileSync } from "node:fs";
const BACKEND = process.env.VITE_API_URL || "http://localhost:8080";

/**
 * Inject a userId into localStorage before every page load so the
 * UserSetup modal is bypassed. Call this before `page.goto()`.
 */
export async function loginAs(page, name) {
  await page.addInitScript((n) => {
    localStorage.setItem("userId", n);
  }, name);
}

/**
 * Truncate all user-generated tables via the test-only reset endpoint.
 * Call in beforeEach/beforeAll to ensure a clean slate.
 *
 * `/api/test/*` only exists when the backend runs with
 * STIG_ENABLE_TEST_ROUTES=true, and the X-User-Id header used throughout
 * these helpers only works with ALLOW_TEST_AUTH_HEADER=true. The compose
 * stack and CI set both.
 */
export async function resetDb() {
  const res = await fetch(`${BACKEND}/api/test/reset`, { method: "POST" });
  if (res.status === 404) {
    throw new Error(
      "resetDb failed: 404 — start the backend with STIG_ENABLE_TEST_ROUTES=true " +
        "(and ALLOW_TEST_AUTH_HEADER=true) to run the E2E suite",
    );
  }
  if (!res.ok && res.status !== 204) {
    throw new Error(`resetDb failed: ${res.status}`);
  }
}

/**
 * Create a draft via the API and return the JSON response.
 * Automatically triggers user auto-creation via the X-User-Id header.
 */
export async function createDraftViaApi(userName, title = "Test Draft") {
  const res = await fetch(`${BACKEND}/api/drafts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-User-Id": userName,
    },
    body: JSON.stringify({ title }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`createDraftViaApi failed: ${res.status} ${text}`);
  }
  return res.json();
}

/**
 * Transition a draft's status via the API.
 */
export async function transitionDraft(userName, draftId, action, body = {}) {
  const res = await fetch(`${BACKEND}/api/drafts/${draftId}/${action}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-User-Id": userName,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`transitionDraft(${action}) failed: ${res.status} ${text}`);
  }
  return res.json();
}

/**
 * Directly update a user's role in the database via a raw SQL endpoint.
 * Since we don't have an admin API yet, we use the test reset endpoint
 * pattern — but for role changes we just call the backend API with a
 * simple fetch to /api/users/me after setting up the user.
 *
 * For now, we set the role by making a direct SQL call through a
 * helper endpoint. As a workaround, we'll use the auto-create flow
 * and then directly PATCH the role.
 */
/**
 * POST a STIG ZIP to the catalog upload endpoint as `userName`. Uploads are
 * admin-only, so pass a user that has been given the admin role (see
 * `setUserRole`). Returns the raw fetch Response.
 */
export async function uploadStigAs(userName, { file, filename, id, category }) {
  const form = new FormData();
  form.append("file", new Blob([file]), filename);
  form.append("id", id);
  form.append("category", category);
  return fetch(`${BACKEND}/api/upload`, {
    method: "POST",
    headers: { "X-User-Id": userName },
    body: form,
  });
}

export async function setUserRole(userName, role) {
  // First ensure the user exists by hitting /api/users/me
  await fetch(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": userName },
  });
  // Update role via test endpoint
  const res = await fetch(`${BACKEND}/api/test/set-role`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: userName, role }),
  });
  if (!res.ok && res.status !== 204) {
    throw new Error(`setUserRole failed: ${res.status}`);
  }
}

/**
 * Log in and load the built-in demo STIG.
 * The demo button is under the "Open Local File" tab in the library.
 * After this call the app is on the STIGView page with 12 sample rules.
 */
export async function loadDemoStig(page) {
  await loginAs(page, "demo-user");
  await page.goto("/");
  await page.getByRole("button", { name: "Open Local File" }).click();
  await page.getByRole("button", { name: "Load Demo STIG" }).click();
}

export { BACKEND };

/** Frontend origin the specs run against (must match the backend's FRONTEND_URL). */
export const FRONTEND = process.env.BASE_URL || "http://localhost:5173";

/**
 * Version of the AC-8 notice wording, read from the frontend constant so the
 * specs cannot drift from it (the backend has a test pinning the same value).
 */
export const NOTICE_VERSION = (() => {
  const src = readFileSync(
    new URL("../frontend/src/constants.rs", import.meta.url),
    "utf8",
  );
  const m = src.match(/USE_NOTICE_VERSION: &str = "([^"]+)"/);
  if (!m) throw new Error("USE_NOTICE_VERSION not found in frontend constants");
  return m[1];
})();

/**
 * Acknowledge the AC-8 system use notification on the login screen. Waits for
 * the server's 204 so the single-use proof cookie is set before sign-in.
 */
export async function acknowledgeNotice(page) {
  const [res] = await Promise.all([
    page.waitForResponse(
      (r) => /\/auth\/notice\/ack$/.test(r.url()) && r.request().method() === "POST",
    ),
    page.getByTestId("login-notice-ack").click(),
  ]);
  if (res.status() !== 204) {
    throw new Error(`notice ack failed: HTTP ${res.status()}`);
  }
}
