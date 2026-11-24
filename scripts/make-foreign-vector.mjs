#!/usr/bin/env node
// Adds a bundle signed by a DIFFERENT implementation (node:crypto / OpenSSL,
// both Ed25519 and ML-DSA-87) to the checked-in test vector, so the Rust
// verifier is tested against signatures it did not produce.
//
//   node scripts/make-foreign-vector.mjs
//
// It always rewrites testdata/signing/v2-hybrid-bundle.json.
//
// Keys are generated at runtime and discarded; only public keys and signatures
// are written. TEST VECTOR ONLY.

import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { SIGN_DOMAIN, keyId, verifyBundle } from "./verify-bundle.mjs";

// The vector path is fixed (no command-line input), so the script can only
// read and rewrite the checked-in vector.
const path = fileURLToPath(
  new URL("../testdata/signing/v2-hybrid-bundle.json", import.meta.url),
);
const vector = JSON.parse(fs.readFileSync(path, "utf8"));
if (typeof vector.label !== "string" || !vector.label.startsWith("TEST VECTOR ONLY")) {
  console.error("refusing: not a labelled test vector");
  process.exit(1);
}

const ed = crypto.generateKeyPairSync("ed25519");
const ml = crypto.generateKeyPairSync("ml-dsa-87");
const edRaw = Buffer.from(ed.publicKey.export({ format: "jwk" }).x, "base64url");
const mlRaw = Buffer.from(ml.publicKey.export({ format: "jwk" }).pub, "base64url");
const edId = keyId("ed25519", edRaw);
const mlId = keyId("ml-dsa-87", mlRaw);

const artifact = Buffer.from("TEST VECTOR ONLY artifact signed by node:crypto\n");
const signers = [
  { algorithm: "ed25519", keyId: edId },
  { algorithm: "ml-dsa-87", keyId: mlId },
];
// Same field order as the server's signing document.
const doc = {
  version: 2,
  algorithm: "ed25519",
  keyId: edId,
  signers,
  sha256: crypto.createHash("sha256").update(artifact).digest("hex"),
  sha512: crypto.createHash("sha512").update(artifact).digest("hex"),
  signedAt: "2026-01-01T00:00:00+00:00",
  signedBy: "vector",
  signedByName: "Vector",
  resource: "foreign",
};
const payload = Buffer.from(JSON.stringify(doc));
const input = Buffer.concat([SIGN_DOMAIN, payload]);
const bundle = {
  document: doc,
  payload: payload.toString("base64url"),
  version: 2,
  signatures: [
    {
      algorithm: "ed25519",
      keyId: edId,
      signature: crypto.sign(null, input, ed.privateKey).toString("base64"),
    },
    {
      algorithm: "ml-dsa-87",
      keyId: mlId,
      signature: crypto.sign(null, input, ml.privateKey).toString("base64"),
    },
  ],
};
const trustedKeys = [
  { algorithm: "ed25519", keyId: edId, publicKey: edRaw.toString("base64") },
  { algorithm: "ml-dsa-87", keyId: mlId, publicKey: mlRaw.toString("base64") },
];
verifyBundle({ bundle, trustedKeys, artifact }); // self-check before writing

vector.foreign = {
  generator: `node ${process.version} node:crypto (OpenSSL)`,
  trustedKeys,
  artifactBase64: artifact.toString("base64"),
  bundle,
};
fs.writeFileSync(path, JSON.stringify(vector, null, 2) + "\n");
console.log(`added foreign bundle to ${path}`);
