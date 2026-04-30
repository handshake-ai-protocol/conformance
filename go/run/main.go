// Go conformance runner. Reads the shared fixtures + test vector 001, emits a
// JSON report on stdout matching the schema consumed by examples/phase1_demo.sh.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/hashing"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/jcs"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/signing"
)

const repoFixtures = "tests/conformance/fixtures/jcs.json"
const repoVector001 = "packages/handshake-spec/test-vectors/v0.2.3/core/001-valid-handshake.json"

func canonHashHex(v any) string {
	b, err := jcs.Canonicalize(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize failed: %v\n", err)
		os.Exit(2)
	}
	return hashing.SHA256Hex(b)
}

func mustReadJSON(path string, dst any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(2)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
		os.Exit(2)
	}
}

func runJCSFixtures(rootDir string) []map[string]string {
	var raw map[string]any
	mustReadJSON(filepath.Join(rootDir, repoFixtures), &raw)
	fixtures := raw["fixtures"].([]any)
	out := make([]map[string]string, 0, len(fixtures))
	for _, fAny := range fixtures {
		fx := fAny.(map[string]any)
		// Skip "comment" entries that don't carry a "name" field.
		nameAny, ok := fx["name"]
		if !ok {
			continue
		}
		name := nameAny.(string)
		canonical, err := jcs.Canonicalize(fx["input"])
		if err != nil {
			fmt.Fprintf(os.Stderr, "canonicalize %s: %v\n", name, err)
			os.Exit(2)
		}
		if exp, ok := fx["expected_canonical"].(string); ok {
			if string(canonical) != exp {
				fmt.Fprintf(os.Stderr,
					"fixture %s: canonical bytes diverge from golden\n  expected: %q\n  actual:   %q\n",
					name, exp, string(canonical),
				)
				os.Exit(2)
			}
		}
		out = append(out, map[string]string{
			"name":   name,
			"sha256": hashing.SHA256Hex(canonical),
		})
	}
	return out
}

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func runEd25519KAT(rootDir string) map[string]any {
	var raw map[string]any
	mustReadJSON(filepath.Join(rootDir, repoFixtures), &raw)
	kat := raw["ed25519_kat"].(map[string]any)
	seed := mustHexDecode(kat["seed_hex"].(string))
	expectedPub := mustHexDecode(kat["public_key_hex"].(string))
	message := mustHexDecode(kat["message_hex"].(string))
	expectedSig := mustHexDecode(kat["signature_hex"].(string))

	kp, err := signing.Ed25519FromSeed(seed)
	if err != nil {
		panic(err)
	}
	pubMatch := bytes.Equal([]byte(kp.Public), expectedPub)
	sig := signing.SignEd25519(kp.Private, message)
	sigMatch := bytes.Equal(sig, expectedSig)
	verifies := signing.VerifyEd25519(kp.Public, sig, message) == nil

	return map[string]any{
		"name":             kat["name"],
		"public_key_match": pubMatch,
		"signature_match":  sigMatch,
		"verifies":         verifies,
		"passed":           pubMatch && sigMatch && verifies,
	}
}

func runMLDSA65KAT(rootDir string) map[string]any {
	var raw map[string]any
	mustReadJSON(filepath.Join(rootDir, repoFixtures), &raw)
	kat := raw["mldsa65_kat"].(map[string]any)
	seed := mustHexDecode(kat["seed_hex"].(string))
	message := []byte(kat["message_utf8"].(string))
	expectedPkSha := kat["expected_public_key_sha256"].(string)
	expectedSgSha := kat["expected_signature_sha256"].(string)

	kp, err := signing.MLDSA65FromSeed(seed)
	if err != nil {
		panic(err)
	}
	pk, err := signing.MarshalMLDSA65PublicKey(kp.Public)
	if err != nil {
		panic(err)
	}
	sig, err := signing.SignMLDSA65(kp.Private, message)
	if err != nil {
		panic(err)
	}

	pkSha := sha256Hex(pk)
	sgSha := sha256Hex(sig)
	verifies := signing.VerifyMLDSA65(kp.Public, sig, message) == nil

	return map[string]any{
		"name":              kat["name"],
		"public_key_size":   len(pk),
		"signature_size":    len(sig),
		"public_key_sha256": pkSha,
		"signature_sha256":  sgSha,
		"public_key_match":  pkSha == expectedPkSha,
		"signature_match":   sgSha == expectedSgSha,
		"verifies":          verifies,
		"passed":            pkSha == expectedPkSha && sgSha == expectedSgSha && verifies,
	}
}

func sha256Hex(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func runVector001(rootDir string) map[string]any {
	var v map[string]any
	mustReadJSON(filepath.Join(rootDir, repoVector001), &v)

	expectedResult := v["expected"].(map[string]any)["result"].(string)

	input := v["input"].(map[string]any)
	delegation := cloneMap(input["delegation"].(map[string]any))
	delete(delegation, "signature")
	unsignedDelSha := canonHashHex(delegation)

	userKp, err := signing.GenerateEd25519()
	if err != nil {
		panic(err)
	}
	agentKp, err := signing.GenerateEd25519()
	if err != nil {
		panic(err)
	}

	delBytes, err := jcs.Canonicalize(delegation)
	if err != nil {
		panic(err)
	}
	delSigB64 := signing.SignEd25519B64(userKp.Private, delBytes)
	if err := signing.VerifyEd25519B64(userKp.Public, delSigB64, delBytes); err != nil {
		panic(fmt.Errorf("delegation verify: %w", err))
	}

	signedDelegation := cloneMap(delegation)
	signedDelegation["signature"] = delSigB64

	requestForHash := cloneMap(input["request"].(map[string]any))
	delete(requestForHash, "signature")
	requestForHash["delegation_chain"] = []any{delegation}
	unsignedReqSha := canonHashHex(requestForHash)

	requestForSigning := cloneMap(requestForHash)
	requestForSigning["delegation_chain"] = []any{signedDelegation}
	reqBytes, err := jcs.Canonicalize(requestForSigning)
	if err != nil {
		panic(err)
	}
	reqSigB64 := signing.SignEd25519B64(agentKp.Private, reqBytes)
	if err := signing.VerifyEd25519B64(agentKp.Public, reqSigB64, reqBytes); err != nil {
		panic(fmt.Errorf("request verify: %w", err))
	}

	return map[string]any{
		"passed":                     true,
		"result":                     expectedResult,
		"unsigned_delegation_sha256": unsignedDelSha,
		"unsigned_request_sha256":    unsignedReqSha,
	}
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func main() {
	root := os.Getenv("REPO_ROOT")
	if root == "" {
		root = "."
	}
	report := map[string]any{
		"implementation": "go",
		"spec_version":   "0.2.3",
		"jcs_fixtures":   runJCSFixtures(root),
		"ed25519_kat":    runEd25519KAT(root),
		"mldsa65_kat":    runMLDSA65KAT(root),
		"vector_001":     runVector001(root),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(2)
	}
}
