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
      port: 8080,
      timeout: 120_000,
      reuseExistingServer: true,
    },
    {
      command: "npm run dev",
      port: 5173,
      timeout: 30_000,
      reuseExistingServer: true,
    },
  ],
});
