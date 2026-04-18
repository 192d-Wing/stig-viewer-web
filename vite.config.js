import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Shared security headers (non-CSP)
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}

// Dev default; overridden by VITE_API_BASE_URL in prod builds / deployments.
const DEFAULT_API_BASE_URL = 'http://localhost:8080'

// Production: fully strict, no external origins.
// connect-src is env-driven so a prod deployment can point at its own API origin.
// Note: style-src needs 'unsafe-inline' for Cloudscape runtime style injection.
const buildProdCsp = (apiBase) => [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  `connect-src 'self' ${apiBase}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join('; ')

// Dev: relaxed for Vite HMR.
// - unsafe-eval: required by some Vite internals
// - unsafe-inline (script-src): @vitejs/plugin-react injects an inline <script type="module">
//   for React Fast Refresh; this is a dev-only preamble that does not ship in production builds.
// - unsafe-inline (style-src): Vite may inject <style> tags for CSS HMR
// - ws:/wss: allow HMR WebSocket connection
const buildDevCsp = (apiBase) => [
  "default-src 'none'",
  "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  `connect-src 'self' ws: wss: ${apiBase}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ')

// Strip the production CSP <meta> tag during `vite dev` so that the dev server HTTP header
// is the sole enforced policy. Without this, the browser intersects both the meta-tag policy
// and the server-header policy, which blocks the React Fast Refresh inline preamble script
// even though the server header permits it.
function devCspMetaPlugin() {
  return {
    name: 'dev-strip-csp-meta',
    apply: 'serve', // only active during `vite dev`, not `vite build`
    transformIndexHtml(html) {
      return html.replace(
        /<meta[\s\S]*?http-equiv=["']Content-Security-Policy["'][\s\S]*?>/i,
        '',
      )
    },
  }
}

// Substitute %VITE_API_BASE_URL% in index.html with the resolved value (env or default),
// so the production CSP <meta> tag always has a concrete origin even when the env var
// isn't explicitly set at build time.
function apiBaseHtmlPlugin(apiBase) {
  return {
    name: 'substitute-api-base-url',
    transformIndexHtml(html) {
      return html.replace(/%VITE_API_BASE_URL%/g, apiBase)
    },
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiBase = env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL

  return {
    plugins: [react(), devCspMetaPlugin(), apiBaseHtmlPlugin(apiBase)],

    build: {
      sourcemap: false,
      cssCodeSplit: true,
      rollupOptions: {
        output: {
          manualChunks: {
            vendor: ['react', 'react-dom'],
            cloudscape: ['@cloudscape-design/components', '@cloudscape-design/global-styles'],
          },
        },
      },
    },

    server: {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Security-Policy': buildDevCsp(apiBase),
      },
    },

    preview: {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Security-Policy': buildProdCsp(apiBase),
      },
    },
  }
})
