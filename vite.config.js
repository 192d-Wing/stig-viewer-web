import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Shared security headers (non-CSP)
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}

// Production: fully strict, no external origins
// Note: style-src needs 'unsafe-inline' for Cloudscape runtime style injection
const PROD_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src http://localhost:8080",
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
const DEV_CSP = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' ws: wss: http://localhost:8080",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ')

// Strip the production CSP <meta> tag during `vite dev` so that the dev server HTTP header
// (DEV_CSP above) is the sole enforced policy. Without this, the browser intersects both
// the meta-tag policy and the server-header policy, which blocks the React Fast Refresh
// inline preamble script even though the server header permits it.
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

export default defineConfig({
  plugins: [react(), devCspMetaPlugin()],

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
      'Content-Security-Policy': DEV_CSP,
    },
  },

  preview: {
    headers: {
      ...SECURITY_HEADERS,
      'Content-Security-Policy': PROD_CSP,
    },
  },
})
