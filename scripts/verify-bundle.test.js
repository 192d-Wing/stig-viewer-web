// Tests for scripts/verify-bundle.mjs (#69). Keys are generated at runtime;
// the checked-in vector holds public keys and signatures only.
// Run: npm run test:scripts
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  SIGN_DOMAIN,
  VerifyError,
  keyId,
  parseStrictJson,
  previousFromFile,
  verifyBundle,
  verifyBundleDetailed,
  verifyVector,
} from "./verify-bundle.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vectorPath = path.join(root, "testdata/signing/v2-hybrid-bundle.json");
const vector = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
const artifact = Buffer.from(vector.artifactBase64, "base64");

const code = (fn) => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof VerifyError, String(e));
    return e.code;
  }
  return "accepted";
};

test("the checked-in vector verifies, including the bundle signed by node:crypto", () => {
  assert.ok(vector.label.startsWith("TEST VECTOR ONLY"));
  assert.ok(vector.foreign, "vector must contain the foreign-signed bundle");
  const s = verifyVector(vector);
  assert.equal(s.positive, 3);
  assert.ok(s.negative >= 10);
});

test("the vector holds no private key material", () => {
  const text = JSON.stringify(vector);
  assert.ok(!/BEGIN [A-Z ]*PRIVATE/.test(text));
  for (const k of ["d", "priv", "seed"]) {
    assert.ok(!text.includes(`"${k}":`), k);
  }
});

function freshSigner() {
  const ed = crypto.generateKeyPairSync("ed25519");
  const ml = crypto.generateKeyPairSync("ml-dsa-87");
  const edRaw = Buffer.from(ed.publicKey.export({ format: "jwk" }).x, "base64url");
  const mlRaw = Buffer.from(ml.publicKey.export({ format: "jwk" }).pub, "base64url");
  const keys = [
    { algorithm: "ed25519", keyId: keyId("ed25519", edRaw), publicKey: edRaw.toString("base64") },
    { algorithm: "ml-dsa-87", keyId: keyId("ml-dsa-87", mlRaw), publicKey: mlRaw.toString("base64") },
  ];
  const sign = (doc, domain = SIGN_DOMAIN, which = [0, 1]) => {
    const payload = Buffer.from(JSON.stringify(doc));
    const input = Buffer.concat([domain, payload]);
    const privs = [ed.privateKey, ml.privateKey];
    return {
      payload: payload.toString("base64url"),
      signatures: which.map((i) => ({
        algorithm: keys[i].algorithm,
        keyId: keys[i].keyId,
        signature: crypto.sign(null, input, privs[i]).toString("base64"),
      })),
    };
  };
  const doc = (art, signers = keys) => ({
    version: 2,
    algorithm: "ed25519",
    keyId: keys[0].keyId,
    signers: signers.map((k) => ({ algorithm: k.algorithm, keyId: k.keyId })),
    sha256: crypto.createHash("sha256").update(art).digest("hex"),
    signedAt: "2026-01-01T00:00:00Z",
    signedBy: "u",
    signedByName: "U",
  });
  return { keys, sign, doc, privs: [ed.privateKey, ml.privateKey] };
}

test("a fresh hybrid bundle verifies and every tamper is rejected", () => {
  const { keys, sign, doc } = freshSigner();
  const art = Buffer.from("hello");
  const good = sign(doc(art));
  const ok = (b, o = {}) => verifyBundle({ bundle: b, trustedKeys: keys, artifact: art, ...o });
  assert.equal(ok(good).signedBy, "u");

  assert.equal(code(() => ok({ ...good, signatures: [good.signatures[0]] })), "MissingSignature");
  assert.equal(code(() => ok({ ...good, signatures: [good.signatures[1]] })), "MissingSignature");
  assert.equal(
    code(() => ok({ ...good, signatures: [good.signatures[0], good.signatures[1], good.signatures[1]] })),
    "UnexpectedSignature",
  );
  const flipped = structuredClone(good);
  const raw = Buffer.from(flipped.signatures[1].signature, "base64");
  raw[7] ^= 1;
  flipped.signatures[1].signature = raw.toString("base64");
  assert.equal(code(() => ok(flipped)), "SignatureInvalid");
  const short = structuredClone(good);
  short.signatures[1].signature = raw.subarray(0, 100).toString("base64");
  assert.equal(code(() => ok(short)), "BadSignatureEncoding");
  assert.equal(code(() => ok(sign(doc(art), Buffer.from("stig-viewer/backup/v1\0")))), "SignatureInvalid");
  assert.equal(
    code(() => verifyBundle({ bundle: good, trustedKeys: keys, artifact: Buffer.from("other") })),
    "ArtifactHashMismatch",
  );
  assert.equal(code(() => ok({ payload: 1, signatures: [] })), "MalformedEnvelope");
  assert.equal(code(() => ok({ ...good, payload: good.payload + "=" })), "BadPayloadEncoding");
  assert.equal(code(() => ok({ ...good, payload: good.payload.replace(/-/g, "+") + "+" })), "BadPayloadEncoding");
});

test("signer profiles: only [ed25519] (when allowed) and [ed25519, ml-dsa-87]", () => {
  const { keys, sign, doc } = freshSigner();
  const art = Buffer.from("x");
  const v = (b, o = {}) => verifyBundle({ bundle: b, trustedKeys: keys, artifact: art, ...o });
  const classical = sign(doc(art, [keys[0]]), SIGN_DOMAIN, [0]);
  assert.equal(code(() => v(classical)), "ClassicalNotAllowed");
  assert.equal(v(classical, { allowClassical: true }).signers.length, 1);
  // Reversed order, ML-DSA only, duplicates, unknown algorithm.
  const rev = sign({ ...doc(art), signers: [...doc(art).signers].reverse() });
  assert.equal(code(() => v(rev)), "BadSignerSet");
  const dup = sign({ ...doc(art), signers: [...doc(art).signers, doc(art).signers[1]] });
  assert.equal(code(() => v(dup)), "BadSignerSet");
  const unknown = sign({ ...doc(art), signers: [...doc(art).signers, { algorithm: "ml-dsa-65", keyId: "00" }] });
  assert.equal(code(() => v(unknown)), "UnsupportedAlgorithm");
  // Untrusted ML-DSA key.
  assert.equal(
    code(() => verifyBundle({ bundle: sign(doc(art)), trustedKeys: [keys[0]], artifact: art })),
    "KeyIdMismatch",
  );
  // A wrong keyId pinned for the right key is detected.
  assert.equal(
    code(() => verifyBundle({ bundle: sign(doc(art)), trustedKeys: [{ ...keys[0], keyId: "0".repeat(16) }, keys[1]], artifact: art })),
    "KeyIdMismatch",
  );
});

test("strict JSON: duplicate keys and trailing bytes are rejected", () => {
  assert.deepEqual(parseStrictJson(' {"a":[1,{"b":null}],"c":"x\\n"} \n'), { a: [1, { b: null }], c: "x\n" });
  assert.equal(code(() => parseStrictJson('{"a":1,"a":2}')), "MalformedDocument");
  assert.equal(code(() => parseStrictJson('{"a":1}x')), "MalformedDocument");
  assert.equal(code(() => parseStrictJson('{"a":1,}')), "MalformedDocument");
  const { keys, sign, doc } = freshSigner();
  const art = Buffer.from("x");
  const d = JSON.stringify(doc(art)).slice(0, -1) + ',"sha256":"00"}';
  const payload = Buffer.from(d);
  const bundle = { ...sign(doc(art)), payload: payload.toString("base64url") };
  // Signatures would not match anyway; the duplicate key is refused first.
  assert.equal(code(() => verifyBundle({ bundle, trustedKeys: keys, artifact: art })), "MalformedDocument");
});

test("CLI: vector mode passes and bundle mode needs an artifact", () => {
  const cli = path.join(root, "scripts/verify-bundle.mjs");
  const out = execFileSync(process.execPath, [cli, "vector", vectorPath]).toString();
  assert.match(out, /^ok: 3 positive/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vb-"));
  try {
    const b = path.join(dir, "bundle.json");
    const k = path.join(dir, "pub.json");
    const a = path.join(dir, "artifact");
    fs.writeFileSync(b, JSON.stringify(vector.bundle));
    fs.writeFileSync(k, JSON.stringify({ keys: vector.trustedKeys }));
    fs.writeFileSync(a, artifact);
    const ok = spawnSync(process.execPath, [cli, "bundle", b, k, a]);
    assert.equal(ok.status, 0, ok.stderr.toString());
    assert.match(ok.stdout.toString(), /ed25519\+ml-dsa-87/);
    assert.equal(spawnSync(process.execPath, [cli, "bundle", b, k]).status, 2);
    fs.writeFileSync(a, "tampered");
    const bad = spawnSync(process.execPath, [cli, "bundle", b, k, a]);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr.toString(), /ArtifactHashMismatch/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("hostile input gives labelled errors, never TypeError or RangeError", () => {
  const { keys, sign, doc } = freshSigner();
  const art = Buffer.from("x");
  const good = sign(doc(art));
  const v = (bundle, trustedKeys = keys) => verifyBundle({ bundle, trustedKeys, artifact: art });
  // Oversized payload is refused before decoding.
  assert.equal(code(() => v({ ...good, payload: "A".repeat(100 * 1024) })), "MalformedEnvelope");
  // Payload size boundary: 64 KiB of base64url is 87382 chars (ceil(65536*4/3)).
  const limit = Math.ceil((64 * 1024 * 4) / 3);
  // Exactly at the limit: passes the size check, then decodes (all-zero bits are canonical) and fails the JSON parse.
  assert.throws(
    () => v({ ...good, payload: "A".repeat(limit) }),
    (e) => e instanceof VerifyError && e.code === "MalformedDocument" && !e.message.includes("payload too large"),
  );
  // One over: refused by the size check itself.
  assert.throws(
    () => v({ ...good, payload: "A".repeat(limit + 1) }),
    (e) => e instanceof VerifyError && e.code === "MalformedEnvelope" && e.message.includes("payload too large"),
  );
  // Signer count boundary: 9 is refused by the count cap, 8 passes the cap and
  // is refused by the profile check.
  const many = (n) => Array.from({ length: n }, () => doc(art).signers[0]);
  assert.throws(
    () => v(sign({ ...doc(art), signers: many(9) })),
    (e) => e.code === "BadSignerSet" && e.message.includes("too many signers"),
  );
  assert.throws(
    () => v(sign({ ...doc(art), signers: many(8) })),
    (e) => e.code === "BadSignerSet" && e.message.includes("profile"),
  );
  // Deep nesting is refused, not a stack overflow.
  const deep = "[".repeat(100_000) + "]".repeat(100_000);
  assert.equal(code(() => parseStrictJson(deep)), "MalformedDocument");
  const deepPayload = Buffer.from('{"a":' + "[".repeat(60) + "]".repeat(60) + "}");
  assert.equal(code(() => v({ ...good, payload: deepPayload.toString("base64url") })), "MalformedDocument");
  // Wrong types in signatures, signers and trusted keys.
  assert.equal(code(() => v({ ...good, signatures: [null] })), "MalformedEnvelope");
  assert.equal(code(() => v({ ...good, signatures: [{ algorithm: 1, keyId: "a", signature: "b" }] })), "MalformedEnvelope");
  assert.equal(code(() => v({ ...good, signatures: Array(17).fill(good.signatures[0]) })), "MalformedEnvelope");
  assert.equal(code(() => v(null)), "MalformedEnvelope");
  assert.equal(code(() => v(good, null)), "MalformedEnvelope");
  assert.equal(code(() => v(good, [null])), "MalformedEnvelope");
  assert.equal(code(() => v(good, [{ algorithm: "ed25519", keyId: "x", publicKey: 5 }])), "MalformedEnvelope");
  const badSigners = sign({ ...doc(art), signers: [null, 5] });
  assert.equal(code(() => v(badSigners)), "BadSignerSet");
  const strSigners = sign({ ...doc(art), signers: ["ed25519"] });
  assert.equal(code(() => v(strSigners)), "BadSignerSet");
  const noSigners = sign({ ...doc(art), signers: "x" });
  assert.equal(code(() => v(noSigners)), "BadSignerSet");
  // A signature that is not a string.
  const g = structuredClone(good);
  g.signatures[0].signature = 7;
  assert.equal(code(() => v(g)), "MalformedEnvelope");
});

test("the downgrade case fails on the signature, not only on policy, when classical is allowed", () => {
  const n = vector.negative.find((c) => c.name === "downgrade_to_classical");
  assert.ok(n);
  assert.equal(
    code(() => verifyBundle({ bundle: n.bundle, trustedKeys: vector.trustedKeys, artifact, allowClassical: true })),
    "SignatureInvalid",
  );
  assert.equal(
    code(() => verifyBundle({ bundle: n.bundle, trustedKeys: vector.trustedKeys, artifact })),
    "ClassicalNotAllowed",
  );
});

// ── Key rotation: previous key sets (#68) ────────────────────────────────

function rotation() {
  const old = freshSigner();
  const cur = freshSigner();
  const art = Buffer.from("rotation artifact");
  const previousKeySets = [{ label: "old", retiredAt: "2026-11-30", keys: old.keys }];
  const v = (bundle, o = {}) =>
    verifyBundleDetailed({ bundle, trustedKeys: cur.keys, previousKeySets, artifact: art, ...o });
  return { old, cur, art, previousKeySets, v };
}

test("a bundle signed by a previous hybrid set verifies and reports its source", () => {
  const { old, cur, art, v } = rotation();
  const prev = v(old.sign(old.doc(art)));
  assert.equal(prev.verifiedBy.source, "previous");
  assert.equal(prev.verifiedBy.label, "old");
  assert.deepEqual(prev.verifiedBy.keyIds, old.keys.map((k) => k.keyId));
  const now = v(cur.sign(cur.doc(art)));
  assert.equal(now.verifiedBy.source, "current");
  assert.equal(now.verifiedBy.label, null);
  // verifyBundle keeps returning the bare signed document.
  assert.equal(verifyBundle({ bundle: old.sign(old.doc(art)), trustedKeys: cur.keys, previousKeySets: [{ label: "old", keys: old.keys }], artifact: art }).signedBy, "u");
});

test("trust is per key set: mixed generations and bare hybrid halves are refused", () => {
  const { old, cur, art, v } = rotation();
  // Old Ed25519 key + current ML-DSA key, both signatures genuine.
  const mixedKeys = [old.keys[0], cur.keys[1]];
  const mixedDoc = old.doc(art, mixedKeys);
  const payload = Buffer.from(JSON.stringify(mixedDoc));
  const input = Buffer.concat([SIGN_DOMAIN, payload]);
  const mixed = {
    payload: payload.toString("base64url"),
    signatures: [
      { ...mixedKeys[0], signature: crypto.sign(null, input, old.privs[0]).toString("base64") },
      { ...mixedKeys[1], signature: crypto.sign(null, input, cur.privs[1]).toString("base64") },
    ].map(({ algorithm, keyId, signature }) => ({ algorithm, keyId, signature })),
  };
  assert.equal(code(() => v(mixed)), "KeyIdMismatch");
  // The old pair's Ed25519 key alone is not a classical signer.
  const classical = old.sign(old.doc(art, [old.keys[0]]), SIGN_DOMAIN, [0]);
  assert.equal(code(() => v(classical, { allowClassical: true })), "KeyIdMismatch");
  // An explicit classical set for it makes the bundle verify, with allowClassical only.
  const withClassical = [
    { label: "old", keys: old.keys },
    { label: "old-classical", keys: [old.keys[0]] },
  ];
  assert.equal(code(() => v(classical, { previousKeySets: withClassical })), "ClassicalNotAllowed");
  const ok = v(classical, { previousKeySets: withClassical, allowClassical: true });
  assert.equal(ok.verifiedBy.label, "old-classical");
});

test("removed and revoked previous keys are refused; a bad signature is still an error", () => {
  const { old, art, v } = rotation();
  const good = old.sign(old.doc(art));
  assert.equal(code(() => v(good, { previousKeySets: [] })), "KeyIdMismatch");
  assert.equal(
    code(() => v(good, { previousKeySets: [], revoked: [{ algorithm: "ed25519", keyId: old.keys[0].keyId }] })),
    "KeyRevoked",
  );
  const flipped = structuredClone(good);
  const raw = Buffer.from(flipped.signatures[1].signature, "base64");
  raw[5] ^= 1;
  flipped.signatures[1].signature = raw.toString("base64");
  assert.equal(code(() => v(flipped)), "SignatureInvalid");
  // A malformed previous set is a labelled rejection.
  assert.equal(code(() => v(good, { previousKeySets: [{ label: "x", keys: [old.keys[1]] }] })), "MalformedEnvelope");
  assert.equal(code(() => v(good, { previousKeySets: "nope" })), "MalformedEnvelope");
});

test("a previous set without a label verifies (the label is informational; the server requires one)", () => {
  const { old, art, v } = rotation();
  const out = v(old.sign(old.doc(art)), { previousKeySets: [{ keys: old.keys }] });
  assert.equal(out.verifiedBy.source, "previous");
  assert.equal(out.verifiedBy.label, null);
});

test("flat trustedKeys keeps working: current hybrid and classical bundles", () => {
  const { cur, art } = rotation();
  const ok = (b, o = {}) => verifyBundle({ bundle: b, trustedKeys: cur.keys, artifact: art, ...o });
  assert.equal(ok(cur.sign(cur.doc(art))).signedBy, "u");
  const classical = cur.sign(cur.doc(art, [cur.keys[0]]), SIGN_DOMAIN, [0]);
  assert.equal(code(() => ok(classical)), "ClassicalNotAllowed");
  assert.equal(ok(classical, { allowClassical: true }).signers.length, 1);
});

test("CLI: --previous accepts the server config and a saved pubkey response", () => {
  const { old, cur, art } = rotation();
  const cli = path.join(root, "scripts/verify-bundle.mjs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vb-rot-"));
  try {
    const w = (name, data) => {
      const f = path.join(dir, name);
      fs.writeFileSync(f, typeof data === "string" || Buffer.isBuffer(data) ? data : JSON.stringify(data));
      return f;
    };
    const bundle = w("bundle.json", old.sign(old.doc(art)));
    const pub = w("pub.json", { keys: cur.keys });
    const a = w("artifact", art);
    const run = (...args) => spawnSync(process.execPath, [cli, "bundle", bundle, ...args, a]);
    // No previous keys: the old bundle is refused.
    const none = run(pub);
    assert.equal(none.status, 1);
    assert.match(none.stderr.toString(), /KeyIdMismatch/);
    // The server's previous-keys configuration.
    const conf = w("conf.json", { version: 1, previous: [{ label: "prod-old", keys: old.keys }] });
    const viaConf = spawnSync(process.execPath, [cli, "bundle", bundle, pub, a, "--previous", conf]);
    assert.equal(viaConf.status, 0, viaConf.stderr.toString());
    assert.match(viaConf.stdout.toString(), /verified by previous keys .* \(prod-old\)/);
    // A pubkey response saved before the rotation.
    const saved = w("saved.json", { keys: old.keys });
    const viaSaved = spawnSync(process.execPath, [cli, "bundle", bundle, pub, a, "--previous", saved]);
    assert.equal(viaSaved.status, 0, viaSaved.stderr.toString());
    // The new server's own pubkey response with `previousKeys`.
    const full = w("full.json", { keys: cur.keys, previousKeys: [{ label: "old", keys: old.keys }] });
    assert.equal(spawnSync(process.execPath, [cli, "bundle", bundle, full, a]).status, 0);
    // Revoked in the configuration.
    const revoked = w("revoked.json", { version: 1, previous: [], revoked: [{ algorithm: "ed25519", keyId: old.keys[0].keyId }] });
    const bad = spawnSync(process.execPath, [cli, "bundle", bundle, pub, a, "--previous", conf, "--previous", revoked]);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr.toString(), /KeyRevoked/);
    // A dangling --previous is a usage error.
    assert.equal(spawnSync(process.execPath, [cli, "bundle", bundle, pub, a, "--previous"]).status, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert.throws(() => previousFromFile({}), (e) => e instanceof VerifyError);
});
