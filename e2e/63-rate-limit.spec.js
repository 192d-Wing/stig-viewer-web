import { test, expect } from "@playwright/test";
import { resetDb, setUserRole, BACKEND } from "./helpers.js";

/**
 * Per-user token-bucket rate limiter on mutating endpoints.
 *
 * The default budget is RATE_LIMIT_BURST=20 / RATE_LIMIT_PER_MINUTE=60.
 * We can't twiddle env at runtime so this spec drives the defaults:
 * 20 mutations succeed, the 21st gets a 429 + Retry-After. Admins and
 * GETs bypass.
 *
 * Every test starts from a clean DB AND a flushed bucket map so prior
 * specs that did heavy mutation work (rules bulk import, etc.) don't
 * eat into alice's budget here.
 */

async function resetRateLimit(request) {
  const res = await request.post(`${BACKEND}/api/test/reset-ratelimit`);
  expect(res.status()).toBe(204);
}

/** Resolve the generated user UUID for the X-User-Id alias. We never
 * compare against the alias directly — that's the memory-backed pitfall
 * the other specs hit. */
async function whoAmI(request, alias) {
  const res = await request.get(`${BACKEND}/api/users/me`, {
    headers: { "X-User-Id": alias },
  });
  expect(res.ok()).toBeTruthy();
  return res.json();
}

/** Create an asset owned by the calling alias and return its row. The
 * mutation rate limiter is OFF for the burst-21 test we set up next
 * because we always reset right after seeding. */
async function createAsset(request, alias, name) {
  const res = await request.post(`${BACKEND}/api/assets`, {
    headers: {
      "Content-Type": "application/json",
      "X-User-Id": alias,
    },
    data: { name, hostname: "", description: "", classification: "unclassified" },
  });
  expect(res.status()).toBe(201);
  return res.json();
}

/** Fire one update against /api/assets/:id. The endpoint is PUT (axum
 * routes only PUT here, not PATCH) — both are mutations and both go
 * through the rate-limit middleware identically, so this is the right
 * surface to exercise. */
async function updateAsset(request, alias, id, name) {
  return request.put(`${BACKEND}/api/assets/${id}`, {
    headers: {
      "Content-Type": "application/json",
      "X-User-Id": alias,
    },
    data: { name, hostname: "", description: "", classification: "unclassified" },
  });
}

test.describe("Per-user rate limit", () => {
  test.beforeEach(async ({ request }) => {
    await resetDb();
    await resetRateLimit(request);
  });

  test("API: burst of 21 mutations — 20 pass, 21st gets 429 with Retry-After", async ({
    request,
  }) => {
    // Seed alice + asset. The 4 setup mutations above (POST /api/users
    // implicit, POST /api/assets) are themselves counted, so we drain
    // and reset right before the burst to start from a full bucket.
    await whoAmI(request, "alice");
    const asset = await createAsset(request, "alice", "asset-1");
    await resetRateLimit(request);

    let okCount = 0;
    let limited = null;
    for (let i = 0; i < 21; i++) {
      const res = await updateAsset(request, "alice", asset.id, `asset-1-${i}`);
      if (res.status() === 200) {
        okCount++;
      } else if (res.status() === 429) {
        limited = res;
        break;
      } else {
        throw new Error(`unexpected status ${res.status()} on iteration ${i}`);
      }
    }

    expect(okCount).toBe(20);
    expect(limited).not.toBeNull();
    expect(limited.status()).toBe(429);
    expect(limited.headers()["retry-after"]).toBe("1");
    const body = await limited.json();
    expect(body).toEqual({ error: "rate limit exceeded" });
  });

  test("API: admin role bypasses the rate limit", async ({ request }) => {
    await whoAmI(request, "alice");
    const asset = await createAsset(request, "alice", "asset-admin");
    await setUserRole("alice", "admin");
    await resetRateLimit(request);

    for (let i = 0; i < 21; i++) {
      const res = await updateAsset(
        request,
        "alice",
        asset.id,
        `asset-admin-${i}`,
      );
      expect(res.status()).toBe(200);
    }
  });

  test("API: GET requests don't count against the bucket", async ({
    request,
  }) => {
    await whoAmI(request, "alice");
    await resetRateLimit(request);

    for (let i = 0; i < 50; i++) {
      const res = await request.get(`${BACKEND}/api/dashboard`, {
        headers: { "X-User-Id": "alice" },
      });
      expect(res.status()).toBe(200);
    }
  });

  test("API: /api/test/* paths are exempt", async ({ request }) => {
    // 50 reset calls in a row — these are unauthenticated mutations
    // that the middleware should pass straight through (and never even
    // reaches the rate limiter, since /api/test/* isn't on the auth
    // router). Still, we lock the behavior down so a future refactor
    // that does route them through auth + rate-limit doesn't silently
    // break the E2E setup path.
    for (let i = 0; i < 50; i++) {
      const res = await request.post(`${BACKEND}/api/test/reset`);
      expect(res.status()).toBe(204);
    }
  });
});
