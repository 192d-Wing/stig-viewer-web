import { test, expect, request as pwRequest } from "@playwright/test";
import { resetDb, BACKEND } from "./helpers.js";

/**
 * SAML SP endpoints. These specs exercise the API directly (no browser
 * page) since the real IdP isn't running in CI — the synthetic
 * /api/test/saml-login endpoint stands in for an ACS round-trip.
 */
test.describe("SAML 2.0 SSO", () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test("GET /auth/saml/metadata returns XML with SP entityID + ACS URL", async ({ request }) => {
    const res = await request.get(`${BACKEND}/auth/saml/metadata`);
    expect(res.status()).toBe(200);
    const ct = res.headers()["content-type"] || "";
    expect(ct).toContain("xml");
    const body = await res.text();
    // entityID and Location attributes must be present in the metadata
    // so an IdP admin can paste this in and register the SP.
    expect(body).toContain("EntityDescriptor");
    expect(body).toContain("entityID=");
    expect(body).toContain("AssertionConsumerService");
    expect(body).toMatch(/Location="https?:\/\/[^"]+\/auth\/saml\/acs"/);
  });

  test("GET /auth/saml/login redirects to IdP (or returns 503 when unconfigured)", async () => {
    // Use a fresh request context with redirects disabled so we can
    // inspect the 302 — the default context follows redirects, which
    // would have us hit the IdP (or its placeholder) for real.
    const ctx = await pwRequest.newContext();
    const res = await ctx.get(`${BACKEND}/auth/saml/login`, { maxRedirects: 0 });

    if (res.status() === 503) {
      // No IdP configured in this test env — that's an accepted shape.
      const body = await res.text();
      expect(body.toLowerCase()).toContain("saml");
    } else {
      expect(res.status()).toBe(302);
      const location = res.headers()["location"];
      expect(location).toBeTruthy();
      // Should carry a SAMLRequest query param (per HTTP-Redirect binding).
      expect(location).toContain("SAMLRequest=");
    }
    await ctx.dispose();
  });

  test("POST /api/test/saml-login creates a user and sets a session cookie", async () => {
    const ctx = await pwRequest.newContext();

    const res = await ctx.post(`${BACKEND}/api/test/saml-login`, {
      headers: { "Content-Type": "application/json" },
      data: {
        nameId: "saml-alice@example.com",
        email: "saml-alice@example.com",
        displayName: "SAML Alice",
      },
    });
    expect(res.status()).toBe(200);
    const json = await res.json();
    expect(json.userId).toBeTruthy();
    expect(json.sessionId).toBeTruthy();

    // The Set-Cookie should land in the context's cookie jar; verify by
    // calling /api/users/me without any extra headers and getting the
    // SAML user back.
    const me = await ctx.get(`${BACKEND}/api/users/me`);
    expect(me.status()).toBe(200);
    const user = await me.json();
    expect(user.email).toBe("saml-alice@example.com");
    expect(user.display_name).toBe("SAML Alice");

    await ctx.dispose();
  });

  test("POST /api/test/saml-login is idempotent on nameId — no duplicate user rows", async () => {
    const ctx1 = await pwRequest.newContext();
    const a = await ctx1.post(`${BACKEND}/api/test/saml-login`, {
      headers: { "Content-Type": "application/json" },
      data: {
        nameId: "saml-bob@example.com",
        email: "saml-bob@example.com",
        displayName: "SAML Bob",
      },
    });
    expect(a.status()).toBe(200);
    const firstUserId = (await a.json()).userId;
    await ctx1.dispose();

    // Second login with same nameId from a separate request context
    // (fresh cookie jar) must resolve to the same user row.
    const ctx2 = await pwRequest.newContext();
    const b = await ctx2.post(`${BACKEND}/api/test/saml-login`, {
      headers: { "Content-Type": "application/json" },
      data: {
        nameId: "saml-bob@example.com",
        email: "saml-bob-renamed@example.com",
        displayName: "SAML Bob (renamed)",
      },
    });
    expect(b.status()).toBe(200);
    const secondUserId = (await b.json()).userId;
    expect(secondUserId).toBe(firstUserId);

    // And the freshly minted cookie still authenticates as Bob — with
    // the updated display_name + email reflected.
    const me = await ctx2.get(`${BACKEND}/api/users/me`);
    expect(me.status()).toBe(200);
    const user = await me.json();
    expect(user.id).toBe(firstUserId);
    expect(user.email).toBe("saml-bob-renamed@example.com");
    expect(user.display_name).toBe("SAML Bob (renamed)");
    await ctx2.dispose();
  });
});
