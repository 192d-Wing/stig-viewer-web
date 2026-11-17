#!/bin/sh
# Trunk post_build hook: write the production Content-Security-Policy <meta>
# into the staged index.html on release builds. Debug builds are served by
# `trunk serve`, which sends the (relaxed) dev policy as a header instead.
set -eu

html="${TRUNK_STAGING_DIR:?}/index.html"

if [ "${TRUNK_PROFILE:-debug}" != "release" ]; then
  exit 0
fi

# Must match the origin compiled into the bundle (src/api.rs).
api_url="${API_URL:-${VITE_API_URL:-http://localhost:8080}}"

# No unsafe-inline for scripts, no external origins. 'wasm-unsafe-eval' is
# required to compile the WebAssembly module. style-src keeps 'unsafe-inline'
# for inline style attributes. frame-ancestors is ignored in <meta> per spec;
# enforce it via a server header.
csp="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self' ${api_url}; object-src 'none'; base-uri 'self'; form-action 'none'; upgrade-insecure-requests"

tmp="${html}.tmp"
sed "s|<!--CSP-->|<meta http-equiv=\"Content-Security-Policy\" content=\"${csp}\" />|" "$html" > "$tmp"
mv "$tmp" "$html"
