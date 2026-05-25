import { test, expect } from "@playwright/test";
import http from "node:http";
import crypto from "node:crypto";
import { resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Spin up an in-process HTTP listener bound to 127.0.0.1:<random>.
 * Every inbound request is captured (method, headers, raw body) and
 * acked with 200. Returned helpers let the test read the capture array
 * and shut the server down at teardown.
 *
 * Playwright's `request` fixture intercepts client-originated traffic
 * only — it can't see outbound calls the backend makes — so we need a
 * real listener the Rust process can POST to.
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
  // Bind 0.0.0.0 (not 127.0.0.1) so the backend container can reach us.
  // The backend uses host.docker.internal — the special DNS name that
  // docker-compose maps to the host gateway via extra_hosts.
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

/** Wait until the capture array has at least `min` entries. */
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

/** Poll the deliveries endpoint until at least `min` rows are present. */
async function waitForDeliveries(
  request,
  adminName,
  webhookId,
  min = 1,
  timeoutMs = 5000,
) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await request.get(
      `${BACKEND}/api/webhooks/${webhookId}/deliveries`,
      { headers: { "X-User-Id": adminName } },
    );
    if (res.ok()) {
      const rows = await res.json();
      if (rows.length >= min) return rows;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`waitForDeliveries: never reached ${min} rows`);
}

test.describe("Webhook HMAC payload signing", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("signed webhook delivers X-Webhook-Signature matching HMAC-SHA256(body, secret)", async ({
    request,
  }) => {
    const capture = await startCaptureServer();
    try {
      await ensureUser(request, "alice");
      await setUserRole("alice", "admin");

      const secret = "s3cr3t-key-with-mixed-Chars-!@#";
      const hook = await request
        .post(`${BACKEND}/api/webhooks`, {
          headers: {
            "X-User-Id": "alice",
            "Content-Type": "application/json",
          },
          data: {
            name: "hmac-hook",
            url: capture.url,
            secret,
            kinds: ["assigned"],
          },
        })
        .then((r) => {
          expect(r.status()).toBe(201);
          return r.json();
        });

      // Trigger the synthetic 'assigned' event — same path the Admin UI
      // exercises when an operator clicks the "Test" button.
      const testRes = await request.post(
        `${BACKEND}/api/webhooks/${hook.id}/test`,
        { headers: { "X-User-Id": "alice" } },
      );
      expect([200, 202, 204]).toContain(testRes.status());

      await waitForCaptures(capture.captures, 1);
      expect(capture.captures.length).toBe(1);

      const [received] = capture.captures;
      const sigHeader = received.headers["x-webhook-signature"];
      expect(sigHeader).toBeTruthy();
      expect(sigHeader).toMatch(/^sha256=[0-9a-f]{64}$/);

      // Recompute the HMAC client-side and demand byte equality.
      const expected =
        "sha256=" +
        crypto.createHmac("sha256", secret).update(received.body).digest("hex");
      expect(sigHeader).toBe(expected);

      // The pre-HMAC literal-secret header must be gone — this is the
      // wire-level guarantee operators rely on to know the secret is
      // never exposed in transit.
      expect(received.headers["x-webhook-secret"]).toBeUndefined();

      // Sanity: server logged the delivery as a 200 success.
      const rows = await waitForDeliveries(request, "alice", hook.id, 1);
      expect(rows[0].httpStatus).toBe(200);
      expect(rows[0].error).toBeNull();
    } finally {
      await capture.close();
    }
  });

  test("webhook with empty secret is delivered unsigned (no X-Webhook-Signature)", async ({
    request,
  }) => {
    const capture = await startCaptureServer();
    try {
      await ensureUser(request, "alice");
      await setUserRole("alice", "admin");

      const hook = await request
        .post(`${BACKEND}/api/webhooks`, {
          headers: {
            "X-User-Id": "alice",
            "Content-Type": "application/json",
          },
          data: {
            name: "unsigned-hook",
            url: capture.url,
            // Explicit empty secret — the "opt-in to signing" path.
            secret: "",
            kinds: ["assigned"],
          },
        })
        .then((r) => r.json());

      const testRes = await request.post(
        `${BACKEND}/api/webhooks/${hook.id}/test`,
        { headers: { "X-User-Id": "alice" } },
      );
      expect([200, 202, 204]).toContain(testRes.status());

      await waitForCaptures(capture.captures, 1);
      const [received] = capture.captures;
      expect(received.headers["x-webhook-signature"]).toBeUndefined();
      expect(received.headers["x-webhook-secret"]).toBeUndefined();

      // Delivery row is still recorded, even though no header was sent.
      const rows = await waitForDeliveries(request, "alice", hook.id, 1);
      expect(rows.length).toBe(1);
      expect(rows[0].httpStatus).toBe(200);
    } finally {
      await capture.close();
    }
  });
});
