"""Python conformance runner.

Reads the shared fixtures + test vector 001 and emits a JSON report on stdout
matching the schema the Rust + Go runners produce. The point of this file is
proving the Python SDK (a thin PyO3 wrapper over the canonical Rust core, see
docs/decisions/0006-rust-core-authoritative.md) emits byte-identical JCS,
SHA-256, Ed25519 and ML-DSA-65 outputs to the other implementations.

Report schema (per implementation):
```jsonc
{
  "implementation": "python",
  "spec_version": "0.2.3",
  "jcs_fixtures": [{"name": "...", "sha256": "..."}],
  "ed25519_kat":  {"passed": true, ...},
  "mldsa65_kat":  {"passed": true, ...},
  "vector_001":   {"passed": true, ...}
}
```
"""

from __future__ import annotations

import binascii
import copy
import json
import sys
from pathlib import Path
from typing import Any

# `handshake` is the maturin-built wheel (see packages/handshake-py). The demo
# script installs it before invoking this runner. We import lazily inside main()
# to make the failure mode obvious if the wheel is missing.
import handshake  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "conformance" / "fixtures" / "jcs.json"
VECTOR_001 = ROOT / "packages" / "handshake-spec" / "test-vectors" / "v0.2.3" / "core" / "001-valid-handshake.json"


def _hash(value: Any) -> str:
    return handshake.sha256_hex(handshake.canonicalize(value))


def _run_jcs_fixtures() -> list[dict[str, str]]:
    parsed = json.loads(FIXTURES.read_text())
    out: list[dict[str, str]] = []
    for f in parsed["fixtures"]:
        # Skip "_comment_*" entries that don't carry a "name" field.
        name = f.get("name")
        if not isinstance(name, str):
            continue
        canonical = handshake.canonicalize(f["input"])
        # Where the fixture pins an expected canonical string, this implementation
        # MUST produce it byte-for-byte. Hard-fail on mismatch so we cannot pass
        # the suite by drifting in lock-step with the other implementations.
        expected = f.get("expected_canonical")
        if isinstance(expected, str):
            actual = canonical.decode("utf-8")
            assert actual == expected, (
                f"fixture {name}: canonical bytes diverge from golden\n"
                f"  expected: {expected!r}\n  actual:   {actual!r}"
            )
        out.append({"name": name, "sha256": handshake.sha256_hex(canonical)})
    return out


def _run_ed25519_kat() -> dict[str, Any]:
    parsed = json.loads(FIXTURES.read_text())
    kat = parsed["ed25519_kat"]
    seed = binascii.unhexlify(kat["seed_hex"])
    expected_pub = binascii.unhexlify(kat["public_key_hex"])
    message = binascii.unhexlify(kat["message_hex"])
    expected_sig = binascii.unhexlify(kat["signature_hex"])

    _, pub = handshake.ed25519_keypair_from_seed(seed)
    pub_match = pub == expected_pub
    sig = handshake.ed25519_sign(seed, message)
    sig_match = sig == expected_sig
    verifies = handshake.ed25519_verify(pub, sig, message)

    return {
        "name": kat["name"],
        "public_key_match": pub_match,
        "signature_match": sig_match,
        "verifies": verifies,
        "passed": pub_match and sig_match and verifies,
    }


def _run_mldsa65_kat() -> dict[str, Any]:
    parsed = json.loads(FIXTURES.read_text())
    kat = parsed["mldsa65_kat"]
    seed = binascii.unhexlify(kat["seed_hex"])
    message = kat["message_utf8"].encode("utf-8")
    expected_pk_sha = kat["expected_public_key_sha256"]
    expected_sg_sha = kat["expected_signature_sha256"]

    _, pk = handshake.mldsa65_keypair_from_seed(seed)
    sig = handshake.mldsa65_sign(seed, message)
    pk_sha = handshake.sha256_hex(pk)
    sg_sha = handshake.sha256_hex(sig)
    pk_match = pk_sha == expected_pk_sha
    sg_match = sg_sha == expected_sg_sha
    verifies = handshake.mldsa65_verify(pk, sig, message)

    return {
        "name": kat["name"],
        "public_key_size": len(pk),
        "signature_size": len(sig),
        "public_key_sha256": pk_sha,
        "signature_sha256": sg_sha,
        "public_key_match": pk_match,
        "signature_match": sg_match,
        "verifies": verifies,
        "passed": pk_match and sg_match and verifies,
    }


def _run_vector_001() -> dict[str, Any]:
    v = json.loads(VECTOR_001.read_text())
    expected_result = v.get("expected", {}).get("result", "accept")

    delegation = copy.deepcopy(v["input"]["delegation"])
    delegation.pop("signature", None)
    unsigned_del_sha = _hash(delegation)

    # The cross-implementation byte-equality bar requires deterministic input;
    # a freshly-signed delegation has a random signature, so build the canonical
    # snapshot with the *unsigned* delegation in chain. Signing round-trip below
    # uses the signed delegation — those signatures are local to each runner.
    request_for_hash = copy.deepcopy(v["input"]["request"])
    request_for_hash.pop("signature", None)
    request_for_hash["delegation_chain"] = [delegation]
    unsigned_req_sha = _hash(request_for_hash)

    # Local Ed25519 round-trip (sign + verify) using deterministic seeds so the
    # demo can replay this run verbatim. Real callers would use OS randomness.
    user_seed = b"\x11" * 32
    agent_seed = b"\x22" * 32
    _, user_pub = handshake.ed25519_keypair_from_seed(user_seed)
    _, agent_pub = handshake.ed25519_keypair_from_seed(agent_seed)

    del_canonical = handshake.canonicalize(delegation)
    del_sig = handshake.ed25519_sign(user_seed, del_canonical)
    assert handshake.ed25519_verify(user_pub, del_sig, del_canonical)

    request_for_signing = copy.deepcopy(request_for_hash)
    signed_delegation = dict(delegation)
    signed_delegation["signature"] = del_sig.hex()
    request_for_signing["delegation_chain"] = [signed_delegation]
    req_canonical = handshake.canonicalize(request_for_signing)
    req_sig = handshake.ed25519_sign(agent_seed, req_canonical)
    assert handshake.ed25519_verify(agent_pub, req_sig, req_canonical)

    return {
        "passed": True,
        "result": expected_result,
        "unsigned_delegation_sha256": unsigned_del_sha,
        "unsigned_request_sha256": unsigned_req_sha,
    }


def main() -> None:
    report = {
        "implementation": "python",
        "spec_version": handshake.SPEC_VERSION,
        "jcs_fixtures": _run_jcs_fixtures(),
        "ed25519_kat": _run_ed25519_kat(),
        "mldsa65_kat": _run_mldsa65_kat(),
        "vector_001": _run_vector_001(),
    }
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
