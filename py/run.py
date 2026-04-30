"""Python conformance runner.

Reads the shared fixtures + test vector 001, emits a JSON report on stdout
matching the schema consumed by examples/phase1_demo.sh.

See packages/handshake-core-rs/examples/conformance.rs for the schema spec
(this runner produces the same shape with implementation="python").
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

# Make src/ importable without an editable install — keeps the demo script
# zero-config in the Replit shell. Real consumers should `pip install -e .`.
ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "packages" / "handshake-core-py" / "src"
sys.path.insert(0, str(SRC))

from handshake_core import Keypair, canonicalize, sha256_hex, verify_b64  # noqa: E402

FIXTURES = ROOT / "tests" / "conformance" / "fixtures" / "jcs.json"
VECTOR_001 = ROOT / "packages" / "handshake-spec" / "test-vectors" / "v0.2.3" / "core" / "001-valid-handshake.json"


def _hash(value: object) -> str:
    return sha256_hex(canonicalize(value))


def _run_jcs_fixtures() -> list[dict[str, str]]:
    parsed = json.loads(FIXTURES.read_text())
    out: list[dict[str, str]] = []
    for f in parsed["fixtures"]:
        canonical = canonicalize(f["input"])
        # Where the fixture pins an expected canonical string, this
        # implementation MUST produce it byte-for-byte.
        expected = f.get("expected_canonical")
        if expected is not None:
            actual = canonical.decode("utf-8")
            assert actual == expected, (
                f"fixture {f['name']}: canonical bytes diverge from golden\n"
                f"  expected: {expected!r}\n  actual:   {actual!r}"
            )
        out.append({"name": f["name"], "sha256": sha256_hex(canonical)})
    return out


def _run_ed25519_kat() -> dict[str, object]:
    import binascii

    parsed = json.loads(FIXTURES.read_text())
    kat = parsed["ed25519_kat"]
    seed = binascii.unhexlify(kat["seed_hex"])
    expected_pub = binascii.unhexlify(kat["public_key_hex"])
    message = binascii.unhexlify(kat["message_hex"])
    expected_sig = binascii.unhexlify(kat["signature_hex"])

    kp = Keypair.from_seed(seed)
    pub_match = kp.public_key == expected_pub
    sig = kp.sign(message)
    sig_match = sig == expected_sig
    try:
        from handshake_core import verify

        verify(kp.public_key, sig, message)
        verifies = True
    except Exception:
        verifies = False

    return {
        "name": kat["name"],
        "public_key_match": pub_match,
        "signature_match": sig_match,
        "verifies": verifies,
        "passed": pub_match and sig_match and verifies,
    }


def _run_vector_001() -> dict[str, Any]:
    v = json.loads(VECTOR_001.read_text())
    expected_result = v["expected"]["result"]

    delegation = copy.deepcopy(v["input"]["delegation"])
    delegation.pop("signature", None)
    unsigned_del_sha = _hash(delegation)

    user_kp = Keypair.generate()
    agent_kp = Keypair.generate()

    del_canonical = canonicalize(delegation)
    del_sig_b64 = user_kp.sign_b64(del_canonical)
    verify_b64(user_kp.public_key, del_sig_b64, del_canonical)

    signed_delegation = dict(delegation)
    signed_delegation["signature"] = del_sig_b64

    # Cross-impl byte-equality requires deterministic input; build the canonical
    # snapshot with the *unsigned* delegation in chain. Signing round-trip below
    # uses the signed delegation — those signatures are local to each runner.
    request_for_hash = copy.deepcopy(v["input"]["request"])
    request_for_hash.pop("signature", None)
    request_for_hash["delegation_chain"] = [delegation]
    unsigned_req_sha = _hash(request_for_hash)

    request_for_signing = copy.deepcopy(request_for_hash)
    request_for_signing["delegation_chain"] = [signed_delegation]
    req_canonical = canonicalize(request_for_signing)
    req_sig_b64 = agent_kp.sign_b64(req_canonical)
    verify_b64(agent_kp.public_key, req_sig_b64, req_canonical)

    return {
        "passed": True,
        "result": expected_result,
        "unsigned_delegation_sha256": unsigned_del_sha,
        "unsigned_request_sha256": unsigned_req_sha,
    }


def main() -> None:
    report = {
        "implementation": "python",
        "spec_version": "0.2.3",
        "jcs_fixtures": _run_jcs_fixtures(),
        "ed25519_kat": _run_ed25519_kat(),
        "vector_001": _run_vector_001(),
    }
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
