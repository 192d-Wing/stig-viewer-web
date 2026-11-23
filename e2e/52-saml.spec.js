import { test, expect, request as pwRequest } from "@playwright/test";
import { resetDb, BACKEND, FRONTEND, NOTICE_VERSION } from "./helpers.js";

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
      // Without an AC-8 acknowledgement the login start bounces to the banner.
      expect(res.status()).toBe(303);
      expect(new URL(res.headers()["location"]).origin).toBe(new URL(FRONTEND).origin);
      const ackRes = await ctx.post(`${BACKEND}/auth/notice/ack`, {
        headers: { Origin: FRONTEND, "Content-Type": "application/json" },
        data: { noticeVersion: NOTICE_VERSION },
      });
      expect(ackRes.status()).toBe(204);
      const res2 = await ctx.get(`${BACKEND}/auth/saml/login`, { maxRedirects: 0 });
      expect(res2.status()).toBe(303);
      // The request cookie carries the ack id to the ACS, scoped to /auth/saml.
      const reqCookie = res2
        .headersArray()
        .filter((h) => h.name.toLowerCase() === "set-cookie")
        .map((h) => h.value)
        .find((v) => v.startsWith("stig_saml_req="));
      expect(reqCookie).toBeTruthy();
      expect(reqCookie).toMatch(/Path=\/auth\/saml(;|$)/);
      // Dev runs over plain http: Lax without Secure. https/production uses None; Secure.
      if (new URL(BACKEND).protocol === "https:") {
        expect(reqCookie).toMatch(/SameSite=None/i);
        expect(reqCookie).toMatch(/;\s*Secure/i);
      } else {
        expect(reqCookie).toMatch(/SameSite=Lax/i);
      }
      // Should carry a SAMLRequest query param (per HTTP-Redirect binding).
      expect(res2.headers()["location"]).toContain("SAMLRequest=");
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

  test("POST /auth/saml/acs rejects an unsigned SAMLResponse and sets no session", async () => {
    // Not configured with the dev skip flag in CI, so an unsigned (or
    // garbage) response must be refused with exactly 401 (both processing
    // and decode failures use the generic 401) and never set a
    // stig_session cookie.
    const ctx = await pwRequest.newContext();
    const xml =
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a"><saml:Subject><saml:NameID>admin@victim.example</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>';
    for (const body of [Buffer.from(xml).toString("base64"), "!!not-base64!!"]) {
      const res = await ctx.post(`${BACKEND}/auth/saml/acs`, {
        form: { SAMLResponse: body },
        maxRedirects: 0,
      });
      expect(res.status()).toBe(401);
      expect(res.headers()["set-cookie"] || "").not.toContain("stig_session");
    }
    await ctx.dispose();
  });

  test("POST /auth/saml/acs refuses an over-limit body with 413 and an oversized field with 401; neither sets a session", async () => {
    const ctx = await pwRequest.newContext();
    // Over the route's 512 KiB body cap: refused by the body limit.
    const tooBig = await ctx.post(`${BACKEND}/auth/saml/acs`, {
      form: { SAMLResponse: "A".repeat(600_000) },
      maxRedirects: 0,
    });
    expect(tooBig.status()).toBe(413);
    expect(tooBig.headers()["set-cookie"] || "").toBe("");
    // Under the body cap but over the field cap: the generic 401.
    const oversized = await ctx.post(`${BACKEND}/auth/saml/acs`, {
      // "-" is not base64 and is not expanded by form encoding, so this stays under the body cap.
      form: { SAMLResponse: "-".repeat(400_000) },
      maxRedirects: 0,
    });
    expect(oversized.status()).toBe(401);
    expect(await oversized.text()).toBe("SAML authentication failed");
    expect(oversized.headers()["set-cookie"] || "").not.toContain("stig_session");
    await ctx.dispose();
  });
});
