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
const VECTORS_DIR = resolve(ROOT, "packages/handshake-spec/test-vectors/v0.2.3/core");
const VECTOR_001 = resolve(VECTORS_DIR, "001-valid-handshake.json");
// Same vector set as the Rust conformance runner.
const VECTOR_FILES = [
  ["001-valid-handshake", "001-valid-handshake.json"],
  ["002-expired-delegation", "002-expired-delegation.json"],
  ["003-scope-exceeded", "003-scope-exceeded.json"],
];

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

// Encode signatures as base64url without padding — the Rust verifier rejects
// any other variant per `_common.json#/$defs/base64url`. Node's Buffer
// supports the `base64url` encoding name natively since v16.
function signLink(link, seedKeys) {
  const seed = seedKeys[link.iss].seed;
  const body = { ...link };
  delete body.signature;
  const canonical = canonicalize(body);
  const sig = native.ed25519Sign(seed, canonical);
  body.signature = Buffer.from(sig).toString("base64url");
  return body;
}

function signRequest(req, seedKeys) {
  const seed = seedKeys[req.iss].seed;
  const body = { ...req };
  delete body.signature;
  const canonical = canonicalize(body);
  const sig = native.ed25519Sign(seed, canonical);
  body.signature = Buffer.from(sig).toString("base64url");
  return body;
}

async function runVector(vectorId, vectorPath) {
  const v = await readJson(vectorPath);
  const context = v.context;
  const publicKeys = context.public_keys ?? {};
  const revokedPrincipals = context.registry_state?.revoked_principals ?? [];
  const revokedDelegations = context.registry_state?.revoked_delegations ?? [];

  // Synthesize a deterministic Ed25519 seed per DID via SHA-256(DID).
  const seedKeys = {};
  for (const did of Object.keys(publicKeys)) {
    const seed = native.sha256(Buffer.from(did, "utf8"));
    const kp = native.ed25519KeypairFromSeed(seed);
    seedKeys[did] = { seed, publicKey: kp.publicKey };
  }

  const input = v.input;
  const signedChain = [];
  if (input.delegation) signedChain.push(signLink(input.delegation, seedKeys));
  for (const link of input.delegation_chain ?? []) signedChain.push(signLink(link, seedKeys));

  const request = { ...input.request, delegation_chain: signedChain };
  const signedRequest = signRequest(request, seedKeys);

  const pubKeys = {};
  for (const [did, k] of Object.entries(seedKeys)) pubKeys[did] = k.publicKey;

  const { verifyHandshakeRequest } = await import("../../../packages/handshake-ts/ts/verify.ts").catch(async () => {
    // Fallback: call the FFI directly when the TS source isn't available
    // (e.g. when running against a published wheel where only index.cjs ships).
    return {
      verifyHandshakeRequest: (req, keys, recv, now, opts = {}) => {
        const payload = native.verifyHandshakeRequestJson(
          JSON.stringify(req),
          keys,
          recv,
          now,
          opts.revokedPrincipals ?? [],
          opts.revokedDelegations ?? [],
        );
        return JSON.parse(payload);
      },
    };
  });

  const result = verifyHandshakeRequest(signedRequest, pubKeys, signedRequest.aud, context.now, {
    revokedPrincipals,
    revokedDelegations,
  });
  const expected = v.expected ?? {};
  const expectedResult = expected.result ?? "accept";
  const actualResult = result.result;

  let passed = actualResult === expectedResult;
  if (expected.error_code !== undefined) {
    passed = passed && result.error_code === expected.error_code;
  }
  if (expected.rejected_at_step !== undefined) {
    passed = passed && result.rejected_at_step === expected.rejected_at_step;
  }
  const detail = result.detail ?? "";
  for (const needle of expected.detail_must_include ?? []) {
    passed = passed && detail.includes(needle);
  }

  return {
    vector_id: vectorId,
    expected_result: expectedResult,
    expected_error_code: expected.error_code ?? null,
    actual_result: actualResult,
    actual_error_code: result.error_code ?? null,
    actual_rejected_at_step: result.rejected_at_step ?? null,
    detail,
    passed,
  };
}

async function runVectors() {
  const out = [];
  for (const [id, fname] of VECTOR_FILES) {
    out.push(await runVector(id, resolve(VECTORS_DIR, fname)));
  }
  return out;
}

const report = {
  implementation: "typescript",
  spec_version: native.SPEC_VERSION,
  jcs_fixtures: await runJcsFixtures(),
  ed25519_kat: await runEd25519Kat(),
  mldsa65_kat: await runMlDsa65Kat(),
  vector_001: await runVector001(),
  vectors: await runVectors(),
};
process.stdout.write(JSON.stringify(report, null, 2) + "\n");
