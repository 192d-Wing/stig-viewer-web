import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 1,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: "http://localhost:5173",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
  webServer: [
    {
      command: "cd backend && cargo run",
      // Only used when nothing is listening on 8080 yet. The suite needs the
      // opt-in test hooks (X-User-Id auth and /api/test/*).
      env: { ALLOW_TEST_AUTH_HEADER: "true", STIG_ENABLE_TEST_ROUTES: "true" },
      port: 8080,
      timeout: 120_000,
      reuseExistingServer: true,
    },
    {
      // `trunk serve`; a cold start compiles the wasm bundle first.
      command: "npm run dev",
      port: 5173,
      timeout: 600_000,
      reuseExistingServer: true,
    },
  ],
});
