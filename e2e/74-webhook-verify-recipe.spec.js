import { test, expect } from "@playwright/test";
import crypto from "node:crypto";
import { loginAs, resetDb, setUserRole, BACKEND } from "./helpers.js";

async function ensureUser(request, name) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": name },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).id;
}

async function createWebhook(request, asUser, { name, url, secret, kinds = ["assigned"] }) {
  const res = await request.post(`${BACKEND}/api/webhooks`, {
    headers: { "X-User-Id": asUser, "Content-Type": "application/json" },
    data: { name, url, secret, kinds },
  });
  expect(res.status()).toBe(201);
  return res.json();
}

test.describe("Webhook receiver verifier docs", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("API: non-admin GET /verify-recipe is 403", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");
    await ensureUser(request, "mallory");

    const hook = await createWebhook(request, "alice", {
      name: "guarded",
      url: "https://example.invalid/hook",
      secret: crypto.randomBytes(12).toString("hex"),
    });

    const res = await request.get(
      `${BACKEND}/api/webhooks/${hook.id}/verify-recipe`,
      { headers: { "X-User-Id": "mallory" } },
    );
    expect(res.status()).toBe(403);
  });

  test("API: admin GET on a signed webhook returns snippets with matching HMAC", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const secret = crypto.randomBytes(16).toString("hex");
    const url = "https://example.invalid/incoming/abc123";
    const hook = await createWebhook(request, "alice", {
      name: "signed-hook",
      url,
      secret,
    });

    const res = await request.get(
      `${BACKEND}/api/webhooks/${hook.id}/verify-recipe`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.json();

    // Echo of the webhook metadata + the literal header name receivers
    // need to read off of inbound requests.
    expect(body.id).toBe(hook.id);
    expect(body.name).toBe("signed-hook");
    expect(body.url).toBe(url);
    expect(body.headerName).toBe("X-Webhook-Signature");
    expect(body.headerNameV2).toBe("X-Webhook-Signature-V2");
    expect(typeof body.samplePayload).toBe("string");
    expect(body.samplePayload.length).toBeGreaterThan(0);

    // All three snippets present and non-empty.
    expect(body.snippets.curl).toBeTruthy();
    expect(body.snippets.python).toBeTruthy();
    expect(body.snippets.node).toBeTruthy();

    // The curl snippet must contain the literal URL and the sha256= prefix
    // (otherwise the operator's paste-and-run won't actually validate).
    expect(body.snippets.curl).toContain(url);
    expect(body.snippets.curl).toContain("sha256=");
    expect(body.snippets.python).toContain("sha256=");
    expect(body.snippets.node).toContain("sha256=");

    // Recompute the HMAC ourselves and demand byte-equality with the
    // hex baked into the curl snippet. If this diverges the snippet is
    // useless — copy/paste would 401 on the receiver.
    const expected = crypto
      .createHmac("sha256", secret)
      .update(body.samplePayload)
      .digest("hex");
    const match = body.snippets.curl.match(/sha256=([0-9a-f]{64})/);
    expect(match).not.toBeNull();
    expect(match[1]).toBe(expected);

    // The V2 (HMAC-SHA384) signature is in the curl snippet too.
    const expectedV2 = crypto
      .createHmac("sha384", secret)
      .update(body.samplePayload)
      .digest("hex");
    expect(body.snippets.curl).toContain(
      `X-Webhook-Signature-V2: sha384=${expectedV2}`,
    );
    // V3: timestamp-bound signature, signed at recipe-generation time.
    expect(body.headerNameV3).toBe("X-Webhook-Signature-V3");
    expect(body.timestampHeaderName).toBe("X-Webhook-Timestamp");
    expect(body.toleranceSeconds).toBe(300);
    const tsMatch = body.snippets.curl.match(/X-Webhook-Timestamp: ([1-9][0-9]*)/);
    expect(tsMatch).not.toBeNull();
    expect(
      Math.abs(Date.now() / 1000 - Number(tsMatch[1])),
    ).toBeLessThanOrEqual(300);
    const expectedV3 = crypto
      .createHmac("sha384", secret)
      .update(`${tsMatch[1]}.${body.samplePayload}`)
      .digest("hex");
    expect(body.snippets.curl).toContain(
      `X-Webhook-Signature-V3: sha384=${expectedV3}`,
    );
    // Execute the shipped Node verifyV3 against the recipe's own signed
    // sample delivery (ts + sig from the curl snippet): it must accept.
    const sigV3Match = body.snippets.curl.match(
      /X-Webhook-Signature-V3: (sha384=[0-9a-f]{96})/,
    );
    expect(sigV3Match).not.toBeNull();
    const harness =
      body.snippets.node +
      `\nprocess.stdout.write(verifyV3(Buffer.from(${JSON.stringify(
        body.samplePayload,
      )}), ${JSON.stringify(tsMatch[1])}, ${JSON.stringify(sigV3Match[1])}) ? "ok" : "rejected");\n`;
    const out = require("child_process").execFileSync(
      process.execPath,
      ["-e", harness],
      { env: { ...process.env, WEBHOOK_SECRET: secret }, encoding: "utf8" },
    );
    expect(out).toBe("ok");
    expect(body.snippets.python).toContain("def verify_v3");
    expect(body.snippets.node).toContain("verifyV3");
    expect(body.snippets.python).toContain("def verify_v2");
    expect(body.snippets.python).toContain("hashlib.sha384");
    expect(body.snippets.node).toContain("verifyV2");
    expect(body.snippets.node).toContain("'sha384'");

    // The secret is write-only: the receiver snippets read it from the
    // environment and nothing in the response embeds it.
    expect(body.snippets.python).toContain("WEBHOOK_SECRET");
    expect(body.snippets.node).toContain("WEBHOOK_SECRET");
    expect(body.snippets.python).not.toContain(secret);
    expect(body.snippets.node).not.toContain(secret);
    expect(JSON.stringify(body)).not.toContain(secret);
  });

  test("API: admin GET on an unsigned webhook explains it is unsigned", async ({
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const hook = await createWebhook(request, "alice", {
      name: "unsigned-hook",
      url: "https://example.invalid/incoming/plain",
      secret: "",
    });

    const res = await request.get(
      `${BACKEND}/api/webhooks/${hook.id}/verify-recipe`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(200);
    const body = await res.json();

    // Snippets exist but explain there is no signature to verify.
    const all = [body.snippets.curl, body.snippets.python, body.snippets.node]
      .join("\n")
      .toLowerCase();
    expect(all).toMatch(/unsigned|no signature/);
    // The curl snippet should not embed a sha256= header in the unsigned case.
    expect(body.snippets.curl).not.toMatch(/X-Webhook-Signature:\s*sha256=/);
  });

  test("API: GET on a non-existent webhook id is 404", async ({ request }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const res = await request.get(
      `${BACKEND}/api/webhooks/does-not-exist/verify-recipe`,
      { headers: { "X-User-Id": "alice" } },
    );
    expect(res.status()).toBe(404);
  });

  test("UI: Admin console exposes Verify recipe per webhook and tabs through snippets", async ({
    page,
    request,
  }) => {
    await ensureUser(request, "alice");
    await setUserRole("alice", "admin");

    const hook = await createWebhook(request, "alice", {
      name: "ui-hook",
      url: "https://example.invalid/ui-hook",
      secret: crypto.randomBytes(12).toString("hex"),
    });

    await loginAs(page, "alice");
    await page.goto("/?view=admin");

    // Each webhook row exposes a per-row Verify recipe trigger. Drill
    // by webhook id rather than by table position so a future reorder
    // of the columns doesn't break this assertion.
    const trigger = page.getByTestId(`verify-recipe-${hook.id}`);
    await expect(trigger).toBeVisible();
    await trigger.click();

    // Modal opens with the curl tab visible by default.
    await expect(
      page.getByTestId("verify-snippet-copy-curl"),
    ).toBeVisible();
    await expect(
      page.getByTestId("verify-snippet-body-curl"),
    ).toContainText("sha256=");

    // Switch to the Python tab — body + copy button swap to python.
    await page.getByRole("tab", { name: "Python" }).click();
    await expect(
      page.getByTestId("verify-snippet-copy-python"),
    ).toBeVisible();
    await expect(
      page.getByTestId("verify-snippet-body-python"),
    ).toContainText("hmac");

    // And the Node tab.
    await page.getByRole("tab", { name: "Node" }).click();
    await expect(
      page.getByTestId("verify-snippet-copy-node"),
    ).toBeVisible();
    await expect(
      page.getByTestId("verify-snippet-body-node"),
    ).toContainText("createHmac");
  });
});
