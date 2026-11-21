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
      // The owner step runs as its own job; the server then starts verify-only
      // without the owner credential (an empty DATABASE_MIGRATION_URL parses as
      // unset), as in docker-compose.yml.
      command: "cd backend && cargo run -- migrate && DATABASE_MIGRATION_URL= cargo run",
      // Only used when nothing is listening on 8080 yet. The suite needs the
      // opt-in test hooks (X-User-Id auth and /api/test/*), and the compose
      // `postgres` and `db-roles` services (the restricted `stig_app` role must
      // exist; otherwise `migrate` exits 75 with a clear message). Override
      // the URLs/password via the environment for another database.
      env: {
        ALLOW_TEST_AUTH_HEADER: "true",
        STIG_ENABLE_TEST_ROUTES: "true",
        DATABASE_URL:
          process.env.DATABASE_URL ?? "postgres://stig_app@127.0.0.1:5433/stig_viewer",
        DATABASE_MIGRATION_URL:
          process.env.DATABASE_MIGRATION_URL ?? "postgres://stig@127.0.0.1:5433/stig_viewer",
        // `stig_local` is the local-compose-only dev password (same as
        // docker-compose.yml); never reuse it outside the local stack.
        PGPASSWORD: process.env.PGPASSWORD ?? "stig_local",
      },
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
