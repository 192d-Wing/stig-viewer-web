// Bootstraps the WebAssembly bundle. Kept as an external module (instead of
// Trunk's default inline script) so the Content-Security-Policy needs no
// 'unsafe-inline' for scripts. Asset URLs come from the <link> tags Trunk
// writes into index.html (see pattern_script in Trunk.toml).
const js = document.getElementById('app-js').href
const wasm = document.getElementById('app-wasm').href

const { default: init } = await import(js)
await init({ module_or_path: wasm })
