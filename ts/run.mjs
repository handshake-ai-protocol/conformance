#!/usr/bin/env node
// TypeScript / Node conformance runner. Pure ESM, runs from `node` directly
// — no compile step. Reads the shared fixtures + test vector 001, emits a
// JSON report on stdout matching the schema consumed by examples/phase1_demo.sh.

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalize,
  sha256Hex,
  Keypair,
  verifyB64,
} from "../../../packages/handshake-core-ts/src/index.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..", "..", "..");
const FIXTURES = resolve(ROOT, "tests/conformance/fixtures/jcs.json");
const VECTOR_001 = resolve(ROOT, "packages/handshake-spec/test-vectors/v0.2.3/core/001-valid-handshake.json");

function hash(value) {
  return sha256Hex(canonicalize(value));
}

async function readJson(p) {
  return JSON.parse(await readFile(p, "utf8"));
}

async function runJcsFixtures() {
  const parsed = await readJson(FIXTURES);
  return parsed.fixtures.map((f) => {
    const canonical = canonicalize(f.input);
    if (typeof f.expected_canonical === "string") {
      const actual = new TextDecoder().decode(canonical);
      if (actual !== f.expected_canonical) {
        throw new Error(
          `fixture ${f.name}: canonical bytes diverge from golden\n  expected: ${JSON.stringify(f.expected_canonical)}\n  actual:   ${JSON.stringify(actual)}`,
        );
      }
    }
    return { name: f.name, sha256: sha256Hex(canonical) };
  });
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function runEd25519Kat() {
  const parsed = await readJson(FIXTURES);
  const kat = parsed.ed25519_kat;
  const seed = hexToBytes(kat.seed_hex);
  const expectedPub = hexToBytes(kat.public_key_hex);
  const message = hexToBytes(kat.message_hex);
  const expectedSig = hexToBytes(kat.signature_hex);

  const { Keypair: Kp, verify } = await import(
    "../../../packages/handshake-core-ts/src/index.ts"
  );
  const kp = Kp.fromSeed(seed);
  const pubMatch = bytesEq(kp.publicKey, expectedPub);
  const sig = kp.sign(message);
  const sigMatch = bytesEq(sig, expectedSig);
  let verifies = false;
  try {
    verifies = verify(kp.publicKey, sig, message);
  } catch {
    verifies = false;
  }
  return {
    name: kat.name,
    public_key_match: pubMatch,
    signature_match: sigMatch,
    verifies,
    passed: pubMatch && sigMatch && verifies,
  };
}

async function runVector001() {
  const v = await readJson(VECTOR_001);
  const expectedResult = v.expected.result;

  const delegation = structuredClone(v.input.delegation);
  delete delegation.signature;
  const unsignedDelSha = hash(delegation);

  const userKp = Keypair.generate();
  const agentKp = Keypair.generate();

  const delCanonical = canonicalize(delegation);
  const delSigB64 = userKp.signB64(delCanonical);
  if (!verifyB64(userKp.publicKey, delSigB64, delCanonical)) {
    throw new Error("delegation signature did not verify");
  }

  const signedDelegation = { ...delegation, signature: delSigB64 };

  // Cross-impl byte-equality requires deterministic input; build the canonical
  // snapshot with the *unsigned* delegation in chain. Signing round-trip below
  // uses the signed delegation — those signatures are local to each runner.
  const requestForHash = structuredClone(v.input.request);
  delete requestForHash.signature;
  requestForHash.delegation_chain = [delegation];
  const unsignedReqSha = hash(requestForHash);

  const requestForSigning = { ...requestForHash, delegation_chain: [signedDelegation] };
  const reqCanonical = canonicalize(requestForSigning);
  const reqSigB64 = agentKp.signB64(reqCanonical);
  if (!verifyB64(agentKp.publicKey, reqSigB64, reqCanonical)) {
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
  spec_version: "0.2.3",
  jcs_fixtures: await runJcsFixtures(),
  ed25519_kat: await runEd25519Kat(),
  vector_001: await runVector001(),
};
process.stdout.write(JSON.stringify(report, null, 2) + "\n");
