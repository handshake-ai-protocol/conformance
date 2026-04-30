#!/usr/bin/env node
// TypeScript / Node conformance runner. Pure ESM, runs from `node` directly.
// Reads the shared fixtures + test vector 001, emits a JSON report on stdout
// matching the schema the Rust + Go runners produce.
//
// The point of this file is proving the TypeScript SDK (a thin NAPI-RS wrapper
// over the canonical Rust core, see docs/decisions/0006-rust-core-authoritative.md)
// emits byte-identical JCS, SHA-256, Ed25519 and ML-DSA-65 outputs to the other
// implementations.

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..", "..", "..");

// Load the NAPI-RS native addon directly from the package. We sidestep
// `dist/index.js` because this runner runs immediately after `napi build` in
// the demo script — no TS compile step has happened yet at this point.
const require = createRequire(import.meta.url);
const native = require(resolve(ROOT, "packages/handshake-ts/index.cjs"));

function canonicalize(value) {
  // Always serialize: a JS string here is the JSON value `"…"`, not raw JSON.
  return native.canonicalize(JSON.stringify(value));
}
const sha256Hex = (data) => native.sha256Hex(data);

function hash(value) {
  return sha256Hex(canonicalize(value));
}

const FIXTURES = resolve(ROOT, "tests/conformance/fixtures/jcs.json");
const VECTOR_001 = resolve(ROOT, "packages/handshake-spec/test-vectors/v0.2.3/core/001-valid-handshake.json");

async function readJson(p) {
  return JSON.parse(await readFile(p, "utf8"));
}

function hexToBytes(hex) {
  const out = Buffer.alloc(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function runJcsFixtures() {
  const parsed = await readJson(FIXTURES);
  const out = [];
  for (const f of parsed.fixtures) {
    if (typeof f.name !== "string") continue; // skip "_comment_*" entries
    const canonical = canonicalize(f.input);
    if (typeof f.expected_canonical === "string") {
      const actual = new TextDecoder().decode(canonical);
      if (actual !== f.expected_canonical) {
        throw new Error(
          `fixture ${f.name}: canonical bytes diverge from golden\n  expected: ${JSON.stringify(f.expected_canonical)}\n  actual:   ${JSON.stringify(actual)}`,
        );
      }
    }
    out.push({ name: f.name, sha256: sha256Hex(canonical) });
  }
  return out;
}

async function runEd25519Kat() {
  const parsed = await readJson(FIXTURES);
  const kat = parsed.ed25519_kat;
  const seed = hexToBytes(kat.seed_hex);
  const expectedPub = hexToBytes(kat.public_key_hex);
  const message = hexToBytes(kat.message_hex);
  const expectedSig = hexToBytes(kat.signature_hex);

  const kp = native.ed25519KeypairFromSeed(seed);
  const pubMatch = bytesEq(kp.publicKey, expectedPub);
  const sig = native.ed25519Sign(seed, message);
  const sigMatch = bytesEq(sig, expectedSig);
  const verifies = native.ed25519Verify(kp.publicKey, sig, message);

  return {
    name: kat.name,
    public_key_match: pubMatch,
    signature_match: sigMatch,
    verifies,
    passed: pubMatch && sigMatch && verifies,
  };
}

async function runMlDsa65Kat() {
  const parsed = await readJson(FIXTURES);
  const kat = parsed.mldsa65_kat;
  const seed = hexToBytes(kat.seed_hex);
  const message = Buffer.from(kat.message_utf8, "utf8");

  const kp = native.mldsa65KeypairFromSeed(seed);
  const sig = native.mldsa65Sign(seed, message);
  const pkSha = sha256Hex(kp.publicKey);
  const sgSha = sha256Hex(sig);
  const pkMatch = pkSha === kat.expected_public_key_sha256;
  const sgMatch = sgSha === kat.expected_signature_sha256;
  const verifies = native.mldsa65Verify(kp.publicKey, sig, message);

  return {
    name: kat.name,
    public_key_size: kp.publicKey.length,
    signature_size: sig.length,
    public_key_sha256: pkSha,
    signature_sha256: sgSha,
    public_key_match: pkMatch,
    signature_match: sgMatch,
    verifies,
    passed: pkMatch && sgMatch && verifies,
  };
}

async function runVector001() {
  const v = await readJson(VECTOR_001);
  const expectedResult = v.expected?.result ?? "accept";

  const delegation = structuredClone(v.input.delegation);
  delete delegation.signature;
  const unsignedDelSha = hash(delegation);

  // Cross-implementation byte-equality bar: build the canonical snapshot with
  // the *unsigned* delegation in chain (deterministic). Round-trip below uses
  // a signed copy whose signature is local to this runner.
  const requestForHash = structuredClone(v.input.request);
  delete requestForHash.signature;
  requestForHash.delegation_chain = [delegation];
  const unsignedReqSha = hash(requestForHash);

  const userSeed = Buffer.alloc(32, 0x11);
  const agentSeed = Buffer.alloc(32, 0x22);
  const userKp = native.ed25519KeypairFromSeed(userSeed);
  const agentKp = native.ed25519KeypairFromSeed(agentSeed);

  const delCanonical = canonicalize(delegation);
  const delSig = native.ed25519Sign(userSeed, delCanonical);
  if (!native.ed25519Verify(userKp.publicKey, delSig, delCanonical)) {
    throw new Error("delegation signature did not verify");
  }

  const signedDelegation = { ...delegation, signature: delSig.toString("hex") };
  const requestForSigning = { ...requestForHash, delegation_chain: [signedDelegation] };
  const reqCanonical = canonicalize(requestForSigning);
  const reqSig = native.ed25519Sign(agentSeed, reqCanonical);
  if (!native.ed25519Verify(agentKp.publicKey, reqSig, reqCanonical)) {
    throw new Error("request signature did not verify");
  }

  return {
    passed: true,
    result: expectedResult,
    unsigned_delegation_sha256: unsignedDelSha,
    unsigned_request_sha256: unsignedReqSha,
  };
}

const report = {
  implementation: "typescript",
  spec_version: native.SPEC_VERSION,
  jcs_fixtures: await runJcsFixtures(),
  ed25519_kat: await runEd25519Kat(),
  mldsa65_kat: await runMlDsa65Kat(),
  vector_001: await runVector001(),
};
process.stdout.write(JSON.stringify(report, null, 2) + "\n");
