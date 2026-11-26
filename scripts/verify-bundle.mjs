#!/usr/bin/env node
// Reference verifier for the stig-viewer-web signed bundle (POST /api/sign,
// envelope v2) in both profiles: classical [ed25519] and hybrid
// [ed25519, ml-dsa-87]. Independent of the Rust backend: only node:crypto
// (Node 24.7+ with OpenSSL ML-DSA support), no npm dependency.
//
//   node scripts/verify-bundle.mjs bundle <bundle.json> <pubkey.json> <artifact> [--allow-classical] [--previous <file>]...
//   node scripts/verify-bundle.mjs vector <vector.json>
//
// <pubkey.json> is the GET /api/signing/pubkey response (its `keys` array, and
// its `previousKeys` when present). Pin it from a trusted channel, never from
// the bundle. The artifact hash is mandatory in library use; the CLI requires
// an artifact path.
//
// Key rotation (#68): after a key rotation the server also lists retired key
// sets (`previousKeys`). `--previous <file>` (repeatable) adds more: either the
// server's previous-keys configuration (`previous` array, optional `revoked`)
// or a pubkey response saved before the rotation (its `keys` become one set).
// Trust is per key SET: the signed signer list must equal exactly one trusted
// set, so halves of two generations never combine, and a previous hybrid
// pair's Ed25519 key never verifies a classical bundle unless an explicit
// classical set lists it.
//
// Rules (mirrors backend/src/api/signing.rs `verify_bundle`): only `payload`
// and `signatures` of the envelope are read; the signed payload must be strict
// base64url (no padding), strict JSON (no duplicate keys, no trailing bytes),
// version 2; `signers` is exactly [ed25519] (only with allowClassical) or
// [ed25519, ml-dsa-87], the first equal to the signed algorithm/keyId; every
// signer must be a trusted (algorithm, keyId) and the signer list must equal
// exactly one trusted key set; `signatures` must equal the signer set; every signature must verify over
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
 * Verify a bundle. `trustedKeys` is a `keys` array from /api/signing/pubkey
 * (the current key set; its Ed25519 key alone is also the classical set).
 * `previousKeySets` is a list of `{label, keys}` retired sets (the pubkey
 * response's `previousKeys`); each is bound: it matches only a signer list
 * equal to its own keys. `revoked` is a list of `{algorithm, keyId}`.
 * `artifact` (Buffer) is required: its SHA-256 (and SHA-512 when signed) must
 * match. Returns the verified signed document. Throws VerifyError.
 */
export function verifyBundle(options) {
  return verifyBundleDetailed(options).doc;
}

/**
 * Same checks as [`verifyBundle`], and reports which key set verified:
 * `{ doc, verifiedBy: { source: "current" | "previous", keyIds, label } }`.
 * The report is kept apart from `doc`, whose fields all come from the signed
 * payload.
 */
export function verifyBundleDetailed({
  bundle,
  trustedKeys,
  previousKeySets = [],
  revoked = [],
  artifact,
  allowClassical = false,
}) {
  if (!Buffer.isBuffer(artifact)) throw new TypeError("artifact (Buffer) is required");
  try {
    return verifyChecked({ bundle, trustedKeys, previousKeySets, revoked, artifact, allowClassical });
  } catch (e) {
    if (e instanceof VerifyError) throw e;
    // Any unexpected failure on hostile input is a rejection, not a crash.
    return fail("MalformedEnvelope", e instanceof Error ? e.name : "error");
  }
}

const isObj = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
const isStr = (s) => typeof s === "string";

const isKeyEntry = (k) => isObj(k) && isStr(k.algorithm) && isStr(k.keyId) && isStr(k.publicKey);
const same = (a, b) => a.algorithm === b.algorithm && a.keyId === b.keyId;

/**
 * The trusted key sets: the current keys' classical set `[ed25519]` and, when
 * exactly one Ed25519 and one ML-DSA-87 key are pinned, the hybrid set; then
 * each previous set. Previous sets must be `[ed25519]` or
 * `[ed25519, ml-dsa-87]`.
 */
function keySets(trustedKeys, previousKeySets) {
  const current = trustedKeysFrom(trustedKeys);
  const eds = current.filter((k) => k.algorithm === "ed25519");
  const mls = current.filter((k) => k.algorithm === "ml-dsa-87");
  const sets = eds.map((k) => ({ source: "current", label: null, keys: [k] }));
  if (eds.length === 1 && mls.length === 1) {
    sets.push({ source: "current", label: null, keys: [eds[0], mls[0]] });
  }
  for (const p of previousKeySets) {
    const keys = trustedKeysFrom(p.keys);
    const names = keys.map((k) => k.algorithm).join(",");
    if (names !== "ed25519" && names !== "ed25519,ml-dsa-87") {
      fail("MalformedEnvelope", "previous key set profile");
    }
    sets.push({ source: "previous", label: isStr(p.label) ? p.label : null, keys });
  }
  return sets;
}

function checkInputs(trustedKeys, previousKeySets, revoked) {
  if (!Array.isArray(trustedKeys) || !trustedKeys.every(isKeyEntry)) {
    fail("MalformedEnvelope", "trusted keys");
  }
  const validSet = (p) => isObj(p) && Array.isArray(p.keys) && p.keys.length <= 2 && p.keys.every(isKeyEntry);
  if (!Array.isArray(previousKeySets) || previousKeySets.length > 32 || !previousKeySets.every(validSet)) {
    fail("MalformedEnvelope", "previous key sets");
  }
  const validRevoked = (r) => isObj(r) && isStr(r.algorithm) && isStr(r.keyId);
  if (!Array.isArray(revoked) || revoked.length > 64 || !revoked.every(validRevoked)) {
    fail("MalformedEnvelope", "revoked keys");
  }
}

function checkEnvelopeShape(bundle) {
  if (isObj(bundle) && isStr(bundle.payload) && bundle.payload.length > Math.ceil((MAX_PAYLOAD * 4) / 3)) {
    fail("MalformedEnvelope", "payload too large");
  }
  const validSig = (x) => isObj(x) && isStr(x.algorithm) && isStr(x.keyId) && isStr(x.signature);
  if (isObj(bundle) && Array.isArray(bundle.signatures) && !(bundle.signatures.length <= 16 && bundle.signatures.every(validSig))) {
    fail("MalformedEnvelope", "signatures");
  }
  if (!bundle || typeof bundle !== "object" || typeof bundle.payload !== "string" || !Array.isArray(bundle.signatures)) {
    fail("MalformedEnvelope");
  }
}

function parseSignedDocument(payload) {
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
  return doc;
}

/** Every signer is a supported, unrevoked, known key; returns the one trusted set. */
function resolveTrustedSet(signers, sets, revoked, allowClassical) {
  for (const s of signers) {
    if (s.algorithm !== "ed25519" && s.algorithm !== "ml-dsa-87") {
      fail("UnsupportedAlgorithm", String(s.algorithm));
    }
    if (revoked.some((r) => same(r, s))) fail("KeyRevoked");
    if (!sets.some((set) => set.keys.some((k) => same(k, s)))) fail("KeyIdMismatch");
  }
  const names = signers.map((s) => s.algorithm).join(",");
  if (names !== "ed25519" && names !== "ed25519,ml-dsa-87") fail("BadSignerSet", "profile");
  if (names === "ed25519" && !allowClassical) fail("ClassicalNotAllowed");
  // Trust is per key set: the signer list must be exactly one trusted set.
  const set = sets.find((c) => c.keys.length === signers.length && c.keys.every((k, i) => same(k, signers[i])));
  return set ?? fail("KeyIdMismatch", "signer set");
}

function verifySignatures(bundle, signers, set, payload) {
  bundle.signatures.forEach((sig, i) => {
    const known = signers.some((s) => same(s, sig));
    const dup = bundle.signatures.slice(0, i).some((o) => same(o, sig));
    if (!known || dup) fail("UnexpectedSignature");
  });
  const input = Buffer.concat([SIGN_DOMAIN, payload]);
  for (const s of signers) {
    const sig = bundle.signatures.find((x) => same(x, s));
    if (!sig) fail("MissingSignature", s.algorithm);
    const key = set.keys.find((t) => same(t, s));
    verifySig(s.algorithm, key.raw, input, b64(sig.signature, s.algorithm));
  }
}

function checkArtifactHashes(doc, artifact) {
  const sha256 = crypto.createHash("sha256").update(artifact).digest("hex");
  if (!isHex(doc.sha256) || doc.sha256.toLowerCase() !== sha256) fail("ArtifactHashMismatch");
  if (doc.sha512 !== undefined) {
    const sha512 = crypto.createHash("sha512").update(artifact).digest("hex");
    if (!isHex(doc.sha512) || doc.sha512.toLowerCase() !== sha512) fail("ArtifactHashMismatch");
  }
}

function verifyChecked({ bundle, trustedKeys, previousKeySets, revoked, artifact, allowClassical }) {
  checkInputs(trustedKeys, previousKeySets, revoked);
  checkEnvelopeShape(bundle);
  const payload = b64urlStrict(bundle.payload);
  const doc = parseSignedDocument(payload);
  const sets = keySets(trustedKeys, previousKeySets);
  const set = resolveTrustedSet(doc.signers, sets, revoked, allowClassical);
  verifySignatures(bundle, doc.signers, set, payload);
  checkArtifactHashes(doc, artifact);
  return { doc, verifiedBy: { source: set.source, keyIds: set.keys.map((k) => k.keyId), label: set.label } };
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
  const summary = { positive: 0, negative: 0, rotation: { positive: 0, negative: 0 } };
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
  if (v.rotation) verifyRotation(v.rotation, artifact, summary.rotation);
  return summary;
}

/** The key rotation (#68) cases of a vector. */
function verifyRotation(r, artifact, summary) {
  for (const p of r.positive) {
    const { verifiedBy } = verifyBundleDetailed({
      bundle: p.bundle,
      trustedKeys: r.trustedKeys,
      previousKeySets: r.previousKeySets,
      artifact,
      allowClassical: p.allowClassical === true,
    });
    if (verifiedBy.source !== p.expectSource || (p.expectLabel !== undefined && verifiedBy.label !== p.expectLabel)) {
      throw new Error(`rotation case ${p.name}: verified by ${verifiedBy.source}/${verifiedBy.label}`);
    }
    summary.positive++;
  }
  for (const n of r.negative) {
    let err = null;
    try {
      verifyBundle({
        bundle: n.bundle,
        trustedKeys: r.trustedKeys,
        previousKeySets: n.previousKeySets ?? r.previousKeySets,
        revoked: n.revoked ?? [],
        artifact,
        allowClassical: n.allowClassical === true,
      });
    } catch (e) {
      err = e;
    }
    if (!(err instanceof VerifyError) || err.code !== n.expect) {
      throw new Error(`rotation case ${n.name}: expected ${n.expect}, got ${err ? err.message : "accept"}`);
    }
    summary.negative++;
  }
}

/**
 * Read a `--previous` file: the server's previous-keys configuration (a
 * `previous` array of `{label, retiredAt, keys}` and an optional `revoked`
 * list), or a pubkey response saved before a rotation (its `keys` become one
 * set, labelled `saved-pubkey`; its own `previousKeys` are included).
 */
export function previousFromFile(doc) {
  if (!isObj(doc)) fail("MalformedEnvelope", "previous keys file");
  if (Array.isArray(doc.previous)) {
    return { sets: doc.previous, revoked: Array.isArray(doc.revoked) ? doc.revoked : [] };
  }
  if (Array.isArray(doc.keys)) {
    const sets = [{ label: "saved-pubkey", keys: doc.keys }];
    if (Array.isArray(doc.previousKeys)) sets.push(...doc.previousKeys);
    return { sets, revoked: [] };
  }
  return fail("MalformedEnvelope", "previous keys file");
}

/** Split argv into positional args, `--flag`s and the repeatable `--previous <file>`; null on a dangling `--previous`. */
function parseArgs(argv) {
  const out = { flags: new Set(), previousFiles: [], args: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--previous") {
      if (i + 1 >= argv.length) return null;
      out.previousFiles.push(argv[++i]);
    } else if (argv[i].startsWith("--")) {
      out.flags.add(argv[i]);
    } else {
      out.args.push(argv[i]);
    }
  }
  return out;
}

const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));

function runVector(file) {
  const s = verifyVector(readJson(file));
  console.log(
    `ok: ${s.positive} positive and ${s.negative} negative cases; rotation: ${s.rotation.positive} positive and ${s.rotation.negative} negative`,
  );
  return 0;
}

function runBundle(args, flags, previousFiles) {
  const pub = readJson(args[2]);
  const artifact = args[3] ? fs.readFileSync(args[3]) : null;
  if (!artifact) {
    console.error("an artifact path is required: the bundle must be bound to the artifact");
    return 2;
  }
  const previousKeySets = Array.isArray(pub.previousKeys) ? [...pub.previousKeys] : [];
  const revoked = [];
  for (const f of previousFiles) {
    const p = previousFromFile(readJson(f));
    previousKeySets.push(...p.sets);
    revoked.push(...p.revoked);
  }
  const { doc, verifiedBy } = verifyBundleDetailed({
    bundle: readJson(args[1]),
    trustedKeys: pub.keys,
    previousKeySets,
    revoked,
    artifact,
    allowClassical: flags.has("--allow-classical"),
  });
  const label = verifiedBy.label ? ` (${verifiedBy.label})` : "";
  const by = `${verifiedBy.source} keys ${verifiedBy.keyIds.join("+")}${label}`;
  const algs = doc.signers.map((s) => s.algorithm).join("+");
  console.log(`ok: signed by ${doc.signedBy} at ${doc.signedAt}, signers ${algs}, verified by ${by}`);
  return 0;
}

function main(argv) {
  const parsed = parseArgs(argv);
  if (!parsed) return usage();
  const { flags, previousFiles, args } = parsed;
  if (args[0] === "vector" && args.length === 2) return runVector(args[1]);
  if (args[0] === "bundle" && args.length >= 3 && args.length <= 4) return runBundle(args, flags, previousFiles);
  return usage();
}

function usage() {
  console.error("usage: verify-bundle.mjs bundle <bundle.json> <pubkey.json> <artifact> [--allow-classical] [--previous <file>]...\n       verify-bundle.mjs vector <vector.json>");
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
