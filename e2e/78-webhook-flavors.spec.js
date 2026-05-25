import { test, expect } from "@playwright/test";
import http from "node:http";
import crypto from "node:crypto";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Spin up an in-process HTTP listener on a random port. Mirrors the
 * helper in `69-webhook-hmac.spec.js` — bound to 0.0.0.0 so the
 * docker-compose backend can reach us via host.docker.internal (mapped
 * in docker-compose `extra_hosts`).
 */
async function startCaptureServer() {
  const captures = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      captures.push({
        method: req.method,
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
  });
  await new Promise((resolve) => server.listen(0, "0.0.0.0", resolve));
  const { port } = server.address();
  return {
    url: `http://host.docker.internal:${port}/hook`,
    captures,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

async function waitForCaptures(captures, min = 1, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (captures.length >= min) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(
    `waitForCaptures: only saw ${captures.length} of ${min} requests`,
  );
}

async function createWebhook(request, asUser, data) {
  const res = await request.post(`${BACKEND}/api/webhooks`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data,
  });
  return { status: res.status(), body: res.ok() ? await res.json() : null };
}

async function fireTest(request, asUser, webhookId) {
  const res = await request.post(
    `${BACKEND}/api/webhooks/${webhookId}/test`,
    { headers: { "X-User-Id": asUser } },
  );
  expect([200, 202, 204]).toContain(res.status());
}

test.describe("Webhook payload flavor adapters", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: flavor=slack delivers the legacy attachments-shape body", async ({
    request,
  }) => {
    const capture = await startCaptureServer();
    try {
      await ensureUser(request, "alice");
      await setUserRole("alice", "admin");

      const { status, body: hook } = await createWebhook(request, "alice", {
        name: "slack-hook",
        url: capture.url,
        kinds: ["assigned"],
        flavor: "slack",
      });
      expect(status).toBe(201);
      expect(hook.flavor).toBe("slack");

      await fireTest(request, "alice", hook.id);
      await waitForCaptures(capture.captures, 1);
      const received = capture.captures[0];
      const payload = JSON.parse(received.body);

      // Legacy Slack incoming-webhook shape.
      expect(payload).toHaveProperty("text");
      expect(Array.isArray(payload.attachments)).toBe(true);
      expect(payload.attachments[0]).toHaveProperty("title");
      expect(payload.attachments[0]).toHaveProperty("text");
      expect(payload.attachments[0]).toHaveProperty("color");
      // None of the other flavors' marker keys should leak through.
      expect(payload["@type"]).toBeUndefined();
      expect(payload.kind).toBeUndefined();
    } finally {
      await capture.close();
    }
  });

  test("API: flavor=teams delivers a MessageCard body", async ({ request }) => {
    const capture = await startCaptureServer();
    try {
      await ensureUser(request, "alice");
      await setUserRole("alice", "admin");

      const { status, body: hook } = await createWebhook(request, "alice", {
        name: "teams-hook",
        url: capture.url,
        kinds: ["assigned"],
        flavor: "teams",
      });
      expect(status).toBe(201);
      expect(hook.flavor).toBe("teams");

      await fireTest(request, "alice", hook.id);
      await waitForCaptures(capture.captures, 1);
      const received = capture.captures[0];
      const payload = JSON.parse(received.body);

      // Microsoft Teams "MessageCard" legacy schema markers.
      expect(payload["@type"]).toBe("MessageCard");
      expect(payload["@context"]).toBe("https://schema.org/extensions");
      expect(payload).toHaveProperty("summary");
      expect(payload).toHaveProperty("title");
      // themeColor is 6-char hex without '#' (Teams strips the hash).
      expect(payload.themeColor).toMatch(/^[0-9a-f]{6}$/i);
      expect(Array.isArray(payload.sections)).toBe(true);
      expect(payload.sections.length).toBeGreaterThanOrEqual(1);
      expect(payload.sections[0]).toHaveProperty("text");
      // Slack-shape markers must NOT be present.
      expect(payload.attachments).toBeUndefined();
    } finally {
      await capture.close();
    }
  });

  test("API: flavor=generic delivers a flat shape", async ({ request }) => {
    const capture = await startCaptureServer();
    try {
      await ensureUser(request, "alice");
      await setUserRole("alice", "admin");

      const { status, body: hook } = await createWebhook(request, "alice", {
        name: "generic-hook",
        url: capture.url,
        kinds: ["assigned"],
        flavor: "generic",
      });
      expect(status).toBe(201);
      expect(hook.flavor).toBe("generic");

      await fireTest(request, "alice", hook.id);
      await waitForCaptures(capture.captures, 1);
      const received = capture.captures[0];
      const payload = JSON.parse(received.body);

      // Flat shape — no platform-specific framing.
      expect(payload.kind).toBe("assigned");
      expect(typeof payload.title).toBe("string");
      expect(typeof payload.body).toBe("string");
      expect(typeof payload.color).toBe("string");
      expect(Array.isArray(payload.fields)).toBe(true);
      // No Slack or Teams marker keys.
      expect(payload.attachments).toBeUndefined();
      expect(payload["@type"]).toBeUndefined();
    } finally {
      await capture.close();
    }
  });

  test("API: invalid flavor on create returns 400", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const { status } = await createWebhook(request, "alice", {
      name: "bad-flavor",
      url: "https://example.invalid/hook",
      kinds: ["assigned"],
      flavor: "discord", // not in the allow-list
    });
    expect(status).toBe(400);
  });

  test("API: HMAC signature still matches body bytes for the teams flavor", async ({
    request,
  }) => {
    const capture = await startCaptureServer();
    try {
      await ensureUser(request, "alice");
      await setUserRole("alice", "admin");

      const secret = "teams-flavor-secret-!@#";
      const { body: hook } = await createWebhook(request, "alice", {
        name: "signed-teams",
        url: capture.url,
        secret,
        kinds: ["assigned"],
        flavor: "teams",
      });

      await fireTest(request, "alice", hook.id);
      await waitForCaptures(capture.captures, 1);
      const received = capture.captures[0];

      // Sanity: this *is* a Teams payload, not the legacy Slack shape.
      const parsed = JSON.parse(received.body);
      expect(parsed["@type"]).toBe("MessageCard");

      // Signature is over the raw wire bytes — i.e. the Teams JSON.
      const sigHeader = received.headers["x-webhook-signature"];
      expect(sigHeader).toMatch(/^sha256=[0-9a-f]{64}$/);
      const expected =
        "sha256=" +
        crypto.createHmac("sha256", secret).update(received.body).digest("hex");
      expect(sigHeader).toBe(expected);
    } finally {
      await capture.close();
    }
  });

  test("UI: admin webhook modal exposes a Flavor select; saving Teams flips the badge", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    // Seed a webhook so the row already exists, then we'll edit it.
    const { body: hook } = await createWebhook(request, "alice", {
      name: "ui-flavor-hook",
      url: "https://example.invalid/ui-flavor",
      kinds: ["assigned"],
      flavor: "slack",
    });

    await loginAs(page, "alice");
    await page.goto("/?view=admin");

    // Initial badge: slack.
    const badge = page.getByTestId(`webhook-flavor-${hook.id}`);
    await expect(badge).toBeVisible();
    await expect(badge).toHaveText(/slack/i);

    // Open the row's edit modal. The "Edit" inline-link button lives in
    // the row's actions cell — scope to the row by webhook name so we
    // don't pick up the wrong row.
    const row = page.getByRole("row", { name: new RegExp(hook.name) });
    await row.getByRole("button", { name: "Edit" }).click();

    // The Flavor Select is keyed by data-testid on the wrapper; Cloudscape
    // exposes the open button via that wrapper. Click the wrapper to open
    // the dropdown, then pick Teams.
    const flavorSelect = page.getByTestId("webhook-flavor-select");
    await expect(flavorSelect).toBeVisible();
    await flavorSelect.click();
    await page.getByRole("option", { name: "Microsoft Teams" }).click();

    // Save.
    await page.getByRole("button", { name: "Save" }).click();

    // Badge in the row updates to teams.
    await expect(page.getByTestId(`webhook-flavor-${hook.id}`)).toHaveText(
      /teams/i,
    );
  });
});
