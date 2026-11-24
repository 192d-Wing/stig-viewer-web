#!/usr/bin/env node
// Reference verifier for the stig-viewer-web signed bundle (POST /api/sign,
// envelope v2) in both profiles: classical [ed25519] and hybrid
// [ed25519, ml-dsa-87]. Independent of the Rust backend: only node:crypto
// (Node 24.7+ with OpenSSL ML-DSA support), no npm dependency.
//
//   node scripts/verify-bundle.mjs bundle <bundle.json> <pubkey.json> [artifact] [--allow-classical]
//   node scripts/verify-bundle.mjs vector <vector.json>
//
// <pubkey.json> is the GET /api/signing/pubkey response (its `keys` array).
// Pin it from a trusted channel, never from the bundle. The artifact hash is
// mandatory in library use; the CLI checks it when an artifact path is given.
//
// Rules (mirrors backend/src/api/signing.rs `verify_bundle`): only `payload`
// and `signatures` of the envelope are read; the signed payload must be strict
// base64url (no padding), strict JSON (no duplicate keys, no trailing bytes),
// version 2; `signers` is exactly [ed25519] (only with allowClassical) or
// [ed25519, ml-dsa-87], the first equal to the signed algorithm/keyId; every
// signer must be a trusted (algorithm, keyId); `signatures` must equal the
// signer set; every signature must verify over
// "stig-viewer/sign/v2\0" || payload; the signed sha256 (and sha512, when
// present) must match the artifact.
//
// ML-DSA-87 is FIPS 204 pure mode with the EMPTY context string (Node's
// default); domain separation comes only from the "stig-viewer/sign/v2\0"
// prefix on the signed message, not from the ML-DSA context.
//
// Hostile input is bounded (payload at most 64 KiB, JSON nesting at most 32,
// at most 8 signers) and every malformed shape raises a labelled VerifyError,
// never a TypeError or RangeError.

import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

export const SIGN_DOMAIN = Buffer.from("stig-viewer/sign/v2\0", "latin1");
const ED_PUB = 32;
const ED_SIG = 64;
const MLDSA_PUB = 2592;
const MLDSA_SIG = 4627;
const MAX_PAYLOAD = 64 * 1024;
const MAX_DEPTH = 32;

export class VerifyError extends Error {
  constructor(code, detail = "") {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}
const fail = (code, detail) => {
  throw new VerifyError(code, detail);
};

/** Key id of a raw public key (same derivation as the server). */
export function keyId(algorithm, raw) {
  if (algorithm === "ed25519") {
    return crypto.createHash("sha256").update(raw).digest().subarray(0, 8).toString("hex");
  }
  if (algorithm === "ml-dsa-87") {
    const input = Buffer.concat([Buffer.from("ml-dsa-87\0", "latin1"), raw]);
    return crypto.createHash("sha384").update(input).digest().subarray(0, 16).toString("hex");
  }
  return fail("UnsupportedAlgorithm", algorithm);
}

function b64(s, what) {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) {
    fail("BadSignatureEncoding", what);
  }
  return Buffer.from(s, "base64");
}

function b64urlStrict(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) fail("BadPayloadEncoding");
  const raw = Buffer.from(s, "base64url");
  // Rejects non-canonical trailing bits and any length that is not valid.
  if (raw.toString("base64url") !== s) fail("BadPayloadEncoding");
  return raw;
}

/** JSON.parse that rejects duplicate object keys and trailing non-whitespace. */
export function parseStrictJson(text) {
  let i = 0;
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  let depth = 0;
  const value = () => {
    if (++depth > MAX_DEPTH) fail("MalformedDocument", "nesting too deep");
    try {
      return value1();
    } finally {
      depth--;
    }
  };
  const value1 = () => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const o = {};
      const seen = new Set();
      ws();
      if (text[i] === "}") return i++, o;
      for (;;) {
        ws();
        if (text[i] !== '"') fail("MalformedDocument", "key");
        const k = str();
        if (seen.has(k)) fail("MalformedDocument", "duplicate key");
        seen.add(k);
        ws();
        if (text[i++] !== ":") fail("MalformedDocument", "colon");
        Object.defineProperty(o, k, {
          value: value(),
          enumerable: true,
          writable: true,
          configurable: true,
        });
        ws();
        if (text[i] === ",") i++;
        else if (text[i] === "}") return i++, o;
        else fail("MalformedDocument", "object");
      }
    }
    if (c === "[") {
      i++;
      const a = [];
      ws();
      if (text[i] === "]") return i++, a;
      for (;;) {
        a.push(value());
        ws();
        if (text[i] === ",") i++;
        else if (text[i] === "]") return i++, a;
        else fail("MalformedDocument", "array");
      }
    }
    if (c === '"') return str();
    const m = /^(-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i));
    if (!m) fail("MalformedDocument", "token");
    i += m[0].length;
    return JSON.parse(m[0]);
  };
  const str = () => {
    const start = i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === "\\") i++;
      i++;
    }
    if (i >= text.length) fail("MalformedDocument", "string");
    i++;
    try {
      return JSON.parse(text.slice(start, i));
    } catch {
      return fail("MalformedDocument", "string");
    }
  };
  const v = value();
  ws();
  if (i !== text.length) fail("MalformedDocument", "trailing bytes");
  return v;
}

function publicKeyObject(algorithm, raw) {
  if (algorithm === "ed25519") {
    return crypto.createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
      format: "jwk",
    });
  }
  return crypto.createPublicKey({
    key: { kty: "AKP", alg: "ML-DSA-87", pub: raw.toString("base64url") },
    format: "jwk",
  });
}

function verifySig(algorithm, raw, input, sig) {
  const [pubLen, sigLen] =
    algorithm === "ed25519" ? [ED_PUB, ED_SIG] : [MLDSA_PUB, MLDSA_SIG];
  if (raw.length !== pubLen || sig.length !== sigLen) fail("BadSignatureEncoding");
  let ok = false;
  try {
    ok = crypto.verify(null, input, publicKeyObject(algorithm, raw), sig);
  } catch {
    ok = false;
  }
  if (!ok) fail("SignatureInvalid", algorithm);
}

/** Turn a pubkey response's `keys` array into a lookup, recomputing key ids. */
export function trustedKeysFrom(keys) {
  return keys.map((k) => {
    const raw = Buffer.from(k.publicKey, "base64");
    if (keyId(k.algorithm, raw) !== k.keyId) fail("KeyIdMismatch", "pinned key id");
    return { algorithm: k.algorithm, keyId: k.keyId, raw };
  });
}

const isHex = (s) => typeof s === "string" && /^[0-9a-f]+$/i.test(s);

/**
 * Verify a bundle. `trustedKeys` is a `keys` array from /api/signing/pubkey.
 * `artifact` (Buffer) is required: its SHA-256 (and SHA-512 when signed) must
 * match. Returns the verified signed document. Throws VerifyError.
 */
export function verifyBundle({ bundle, trustedKeys, artifact, allowClassical = false }) {
  if (!Buffer.isBuffer(artifact)) throw new TypeError("artifact (Buffer) is required");
  try {
    return verifyChecked({ bundle, trustedKeys, artifact, allowClassical });
  } catch (e) {
    if (e instanceof VerifyError) throw e;
    // Any unexpected failure on hostile input is a rejection, not a crash.
    return fail("MalformedEnvelope", e instanceof Error ? e.name : "error");
  }
}

const isObj = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
const isStr = (s) => typeof s === "string";

function verifyChecked({ bundle, trustedKeys, artifact, allowClassical }) {
  if (!Array.isArray(trustedKeys) || !trustedKeys.every((k) => isObj(k) && isStr(k.algorithm) && isStr(k.keyId) && isStr(k.publicKey))) {
    fail("MalformedEnvelope", "trusted keys");
  }
  if (
    isObj(bundle) &&
    isStr(bundle.payload) &&
    bundle.payload.length > Math.ceil((MAX_PAYLOAD * 4) / 3)
  ) {
    fail("MalformedEnvelope", "payload too large");
  }
  if (
    isObj(bundle) &&
    Array.isArray(bundle.signatures) &&
    !(bundle.signatures.length <= 16 && bundle.signatures.every((x) => isObj(x) && isStr(x.algorithm) && isStr(x.keyId) && isStr(x.signature)))
  ) {
    fail("MalformedEnvelope", "signatures");
  }
  if (
    !bundle ||
    typeof bundle !== "object" ||
    typeof bundle.payload !== "string" ||
    !Array.isArray(bundle.signatures)
  ) {
    fail("MalformedEnvelope");
  }
  const payload = b64urlStrict(bundle.payload);
  let doc;
  try {
    doc = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  } catch (e) {
    if (e instanceof VerifyError) throw e;
    return fail("MalformedDocument");
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) fail("MalformedDocument");
  if (doc.version !== 2) fail("UnsupportedVersion");
  const signers = doc.signers;
  if (!Array.isArray(signers) || signers.length === 0 || signers.length > 8) {
    fail("BadSignerSet", "too many signers");
  }
  if (!signers.every((x) => isObj(x) && isStr(x.algorithm) && isStr(x.keyId))) fail("BadSignerSet");
  if (signers[0].algorithm !== doc.algorithm || signers[0].keyId !== doc.keyId) fail("BadSignerSet");

  const trusted = trustedKeysFrom(trustedKeys);
  for (const s of signers) {
    if (s.algorithm !== "ed25519" && s.algorithm !== "ml-dsa-87") {
      fail("UnsupportedAlgorithm", String(s.algorithm));
    }
    if (!trusted.some((t) => t.algorithm === s.algorithm && t.keyId === s.keyId)) {
      fail("KeyIdMismatch");
    }
  }
  const names = signers.map((s) => s.algorithm).join(",");
  let profile;
  if (names === "ed25519") profile = "classical";
  else if (names === "ed25519,ml-dsa-87") profile = "hybrid";
  else fail("BadSignerSet", "profile");
  if (profile === "classical" && !allowClassical) fail("ClassicalNotAllowed");

  const same = (a, b) => a.algorithm === b.algorithm && a.keyId === b.keyId;
  bundle.signatures.forEach((sig, i) => {
    const known = signers.some((s) => same(s, sig));
    const dup = bundle.signatures.slice(0, i).some((o) => same(o, sig));
    if (!known || dup) fail("UnexpectedSignature");
  });
  const input = Buffer.concat([SIGN_DOMAIN, payload]);
  for (const s of signers) {
    const sig = bundle.signatures.find((x) => same(x, s));
    if (!sig) fail("MissingSignature", s.algorithm);
    const key = trusted.find((t) => same(t, s));
    verifySig(s.algorithm, key.raw, input, b64(sig.signature, s.algorithm));
  }

  const sha256 = crypto.createHash("sha256").update(artifact).digest("hex");
  if (!isHex(doc.sha256) || doc.sha256.toLowerCase() !== sha256) fail("ArtifactHashMismatch");
  if (doc.sha512 !== undefined) {
    const sha512 = crypto.createHash("sha512").update(artifact).digest("hex");
    if (!isHex(doc.sha512) || doc.sha512.toLowerCase() !== sha512) fail("ArtifactHashMismatch");
  }
  return doc;
}

/**
 * Verify a vector file (see testdata/signing/v2-hybrid-bundle.json): the
 * positive hybrid bundle, the classical bundle (accepted only with
 * allowClassical), the foreign-signed bundle when present, and every negative
 * case must fail with its labelled error code. Returns a summary.
 */
export function verifyVector(v) {
  if (typeof v.label !== "string" || !v.label.startsWith("TEST VECTOR ONLY")) {
    throw new Error("not a labelled test vector");
  }
  const artifact = Buffer.from(v.artifactBase64, "base64");
  const summary = { positive: 0, negative: 0 };
  verifyBundle({ bundle: v.bundle, trustedKeys: v.trustedKeys, artifact });
  summary.positive++;
  verifyBundle({
    bundle: v.classical.bundle,
    trustedKeys: v.classical.trustedKeys,
    artifact,
    allowClassical: true,
  });
  summary.positive++;
  if (v.foreign) {
    verifyBundle({
      bundle: v.foreign.bundle,
      trustedKeys: v.foreign.trustedKeys,
      artifact: Buffer.from(v.foreign.artifactBase64, "base64"),
    });
    summary.positive++;
  }
  for (const n of v.negative) {
    let err = null;
    try {
      verifyBundle({
        bundle: n.bundle,
        trustedKeys: n.trustedKeys ?? v.trustedKeys,
        artifact: n.artifactBase64 ? Buffer.from(n.artifactBase64, "base64") : artifact,
      });
    } catch (e) {
      err = e;
    }
    if (!(err instanceof VerifyError) || err.code !== n.expect) {
      throw new Error(`negative case ${n.name}: expected ${n.expect}, got ${err ? err.message : "accept"}`);
    }
    summary.negative++;
  }
  return summary;
}

function main(argv) {
  const flags = argv.filter((a) => a.startsWith("--"));
  const args = argv.filter((a) => !a.startsWith("--"));
  const read = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
  if (args[0] === "vector" && args.length === 2) {
    const s = verifyVector(read(args[1]));
    console.log(`ok: ${s.positive} positive and ${s.negative} negative cases`);
    return 0;
  }
  if (args[0] === "bundle" && args.length >= 3 && args.length <= 4) {
    const pub = read(args[2]);
    const artifact = args[3] ? fs.readFileSync(args[3]) : null;
    if (!artifact) {
      console.error("an artifact path is required: the bundle must be bound to the artifact");
      return 2;
    }
    const doc = verifyBundle({
      bundle: read(args[1]),
      trustedKeys: pub.keys,
      artifact,
      allowClassical: flags.includes("--allow-classical"),
    });
    console.log(`ok: signed by ${doc.signedBy} at ${doc.signedAt}, signers ${doc.signers.map((s) => s.algorithm).join("+")}`);
    return 0;
  }
  console.error("usage: verify-bundle.mjs bundle <bundle.json> <pubkey.json> <artifact> [--allow-classical]\n       verify-bundle.mjs vector <vector.json>");
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    console.error(`FAILED: ${e.message}`);
    process.exitCode = 1;
  }
}
