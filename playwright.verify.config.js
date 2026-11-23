// Playwright config for scripts/verify-split-role-upgrade.sh. Targets the
// throwaway verify stack only: no webServer, and it refuses the dev ports so a
// stray run can never hit the developer's own stack.
import base from "./playwright.config.js";

const baseURL = process.env.BASE_URL;
const apiURL = process.env.VITE_API_URL;
for (const [name, value] of [
  ["BASE_URL", baseURL],
  ["VITE_API_URL", apiURL],
]) {
  if (!value) throw new Error(`${name} must be set to the verify stack's URL`);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} is not a valid URL (${value})`);
  }
  if (!url.port || [5173, 8080].includes(Number(url.port))) {
    throw new Error(`${name} must name an explicit non-default port (${value})`);
  }
}

export default {
  ...base,
  use: {
    ...base.use,
    baseURL,
    launchOptions: {
      ...base.use?.launchOptions,
      ...(process.env.E2E_CHROMIUM_PATH ? { executablePath: process.env.E2E_CHROMIUM_PATH } : {}),
    },
  },
  webServer: undefined,
};
