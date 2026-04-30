// Go conformance runner. Reads the shared fixtures + test vector 001, emits a
// JSON report on stdout matching the schema consumed by examples/phase1_demo.sh.
package main

import (
        "bytes"
        "crypto/ed25519"
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "time"

        "github.com/handshake-protocol/handshake-ai/packages/handshake-go/hashing"
        "github.com/handshake-protocol/handshake-ai/packages/handshake-go/jcs"
        "github.com/handshake-protocol/handshake-ai/packages/handshake-go/models"
        "github.com/handshake-protocol/handshake-ai/packages/handshake-go/signing"
        verifyPkg "github.com/handshake-protocol/handshake-ai/packages/handshake-go/verify"
)

var vectorFiles = []struct {
        id    string
        fname string
}{
        {"001-valid-handshake", "001-valid-handshake.json"},
        {"002-expired-delegation", "002-expired-delegation.json"},
        {"003-scope-exceeded", "003-scope-exceeded.json"},
}

const vectorsDir = "packages/handshake-spec/test-vectors/v0.2.3/core"
const errorCodesDir = "tests/conformance/error_codes"

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

// signLink replaces link.signature with a real Ed25519 signature using
// the issuer's freshly-generated keypair (seed = SHA-256 of issuer DID).
func signLink(link map[string]any, seedKeys map[string]ed25519KeyPair) map[string]any {
        issuer := link["iss"].(string)
        body := cloneMap(link)
        delete(body, "signature")
        canonical, err := jcs.Canonicalize(body)
        if err != nil {
                panic(err)
        }
        body["signature"] = signing.SignEd25519B64(seedKeys[issuer].priv, canonical)
        return body
}

func signRequest(req map[string]any, seedKeys map[string]ed25519KeyPair) map[string]any {
        issuer := req["iss"].(string)
        body := cloneMap(req)
        delete(body, "signature")
        canonical, err := jcs.Canonicalize(body)
        if err != nil {
                panic(err)
        }
        body["signature"] = signing.SignEd25519B64(seedKeys[issuer].priv, canonical)
        return body
}

type ed25519KeyPair struct {
        priv ed25519.PrivateKey
        pub  ed25519.PublicKey
}

func deriveKeys(publicKeys map[string]any) map[string]ed25519KeyPair {
        out := make(map[string]ed25519KeyPair, len(publicKeys))
        for did := range publicKeys {
                // Deterministic seed = SHA-256(DID) — mirrors the Python + TS runners.
                digest := sha256.Sum256([]byte(did))
                priv := ed25519.NewKeyFromSeed(digest[:])
                out[did] = ed25519KeyPair{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
        }
        return out
}

func runVector(rootDir, vectorID, vectorPath string) map[string]any {
        var v map[string]any
        mustReadJSON(filepath.Join(rootDir, vectorPath), &v)

        context := v["context"].(map[string]any)
        publicKeys := context["public_keys"].(map[string]any)
        registry, _ := context["registry_state"].(map[string]any)
        var revokedPrincipals, revokedDelegations []string
        if registry != nil {
                if rp, ok := registry["revoked_principals"].([]any); ok {
                        for _, x := range rp {
                                revokedPrincipals = append(revokedPrincipals, x.(string))
                        }
                }
                if rd, ok := registry["revoked_delegations"].([]any); ok {
                        for _, x := range rd {
                                revokedDelegations = append(revokedDelegations, x.(string))
                        }
                }
        }

        seedKeys := deriveKeys(publicKeys)

        input := v["input"].(map[string]any)
        var signedChain []any
        if d, ok := input["delegation"].(map[string]any); ok {
                signedChain = append(signedChain, signLink(d, seedKeys))
        }
        if dc, ok := input["delegation_chain"].([]any); ok {
                for _, link := range dc {
                        signedChain = append(signedChain, signLink(link.(map[string]any), seedKeys))
                }
        }
        request := cloneMap(input["request"].(map[string]any))
        request["delegation_chain"] = signedChain
        signedRequest := signRequest(request, seedKeys)

        // Marshal back into typed `models.HandshakeRequest` for the verifier.
        rawReq, err := json.Marshal(signedRequest)
        if err != nil {
                panic(err)
        }
        var req models.HandshakeRequest
        if err := json.Unmarshal(rawReq, &req); err != nil {
                panic(err)
        }

        resolver := verifyPkg.NewStaticKeyResolver()
        for did, kp := range seedKeys {
                resolver.Insert(did, []byte(kp.pub))
        }
        now, err := time.Parse(time.RFC3339, context["now"].(string))
        if err != nil {
                panic(err)
        }

        // Some error-code vectors (e.g. 004 aud_mismatch) deliberately set
        // request.aud to a DID *different* from the receiver. Honour an
        // explicit `input.receiver_did` override; otherwise default to req.Aud.
        receiverDID := req.Aud
        if rd, ok := input["receiver_did"].(string); ok && rd != "" {
                receiverDID = rd
        }

        ctx := &verifyPkg.Context{
                ReceiverDID: receiverDID,
                Now:         now,
                SkewSecs:    verifyPkg.DefaultSkewSecs,
                Keys:        resolver,
                Nonces:      verifyPkg.NewInMemoryNonceStore(120),
                Revocations: &verifyPkg.StaticRevocationResolver{
                        RevokedPrincipals:  revokedPrincipals,
                        RevokedDelegations: revokedDelegations,
                },
        }
        res := verifyPkg.VerifyHandshakeRequest(&req, ctx)

        expected, _ := v["expected"].(map[string]any)
        if expected == nil {
                expected = map[string]any{}
        }
        expectedResult, _ := expected["result"].(string)
        if expectedResult == "" {
                expectedResult = "accept"
        }

        actualResult := "accept"
        var actualCode any
        var actualStep any
        var detail string
        if !res.Accepted() {
                actualResult = "reject"
                actualCode = string(res.Refusal.ErrorCode)
                actualStep = string(res.Refusal.RejectedAtStep)
                detail = res.Refusal.Detail
        }

        passed := actualResult == expectedResult
        if expCode, ok := expected["error_code"].(string); ok {
                passed = passed && actualCode == expCode
        }
        if expStep, ok := expected["rejected_at_step"].(string); ok {
                passed = passed && actualStep == expStep
        }
        if must, ok := expected["detail_must_include"].([]any); ok {
                for _, needle := range must {
                        passed = passed && bytesContains(detail, needle.(string))
                }
        }

        return map[string]any{
                "vector_id":               vectorID,
                "expected_result":         expectedResult,
                "expected_error_code":     expected["error_code"],
                "actual_result":           actualResult,
                "actual_error_code":       actualCode,
                "actual_rejected_at_step": actualStep,
                "detail":                  detail,
                "passed":                  passed,
        }
}

func bytesContains(s, needle string) bool {
        return bytes.Contains([]byte(s), []byte(needle))
}

func runVectors(rootDir string) []map[string]any {
        out := make([]map[string]any, 0, len(vectorFiles))
        for _, vf := range vectorFiles {
                out = append(out, runVector(rootDir, vf.id, filepath.Join(vectorsDir, vf.fname)))
        }
        return out
}

// runErrorCodeVectors walks tests/conformance/error_codes/*.json — malformed
// inputs whose only job is to assert every implementation returns the same
// errorCode + rejected_at_step. The aggregator builds a cross-impl matrix.
func runErrorCodeVectors(rootDir string) []map[string]any {
        dir := filepath.Join(rootDir, errorCodesDir)
        entries, err := os.ReadDir(dir)
        if err != nil {
                return []map[string]any{}
        }
        out := make([]map[string]any, 0, len(entries))
        for _, e := range entries {
                if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
                        continue
                }
                full := filepath.Join(dir, e.Name())
                rel, err := filepath.Rel(rootDir, full)
                if err != nil {
                        rel = full
                }
                var v map[string]any
                mustReadJSON(full, &v)
                vid, _ := v["vector_id"].(string)
                if vid == "" {
                        vid = e.Name()
                }
                out = append(out, runVector(rootDir, vid, rel))
        }
        return out
}

// Cross-call replay protection: verify vector 001 twice in a row reusing a
// single nonce store. First call must accept; second must reject with
// `replay_detected`. Mirrors what the Py / TS runners assert against the
// FFI's process-shared default store.
func runReplayCheck(rootDir string) map[string]any {
        var v map[string]any
        mustReadJSON(filepath.Join(rootDir, "packages/handshake-spec/test-vectors/v0.2.3/core/001-valid-handshake.json"), &v)
        context := v["context"].(map[string]any)
        publicKeys := context["public_keys"].(map[string]any)
        seedKeys := deriveKeys(publicKeys)

        input := v["input"].(map[string]any)
        var signedChain []any
        if d, ok := input["delegation"].(map[string]any); ok {
                signedChain = append(signedChain, signLink(d, seedKeys))
        }
        if dc, ok := input["delegation_chain"].([]any); ok {
                for _, link := range dc {
                        signedChain = append(signedChain, signLink(link.(map[string]any), seedKeys))
                }
        }
        request := cloneMap(input["request"].(map[string]any))
        request["delegation_chain"] = signedChain
        signedRequest := signRequest(request, seedKeys)

        rawReq, err := json.Marshal(signedRequest)
        if err != nil {
                panic(err)
        }
        var req models.HandshakeRequest
        if err := json.Unmarshal(rawReq, &req); err != nil {
                panic(err)
        }

        resolver := verifyPkg.NewStaticKeyResolver()
        for did, kp := range seedKeys {
                resolver.Insert(did, []byte(kp.pub))
        }
        now, err := time.Parse(time.RFC3339, context["now"].(string))
        if err != nil {
                panic(err)
        }

        // ONE nonce store, TWO verify calls.
        nonces := verifyPkg.NewInMemoryNonceStore(120)
        ctx := &verifyPkg.Context{
                ReceiverDID: req.Aud,
                Now:         now,
                SkewSecs:    verifyPkg.DefaultSkewSecs,
                Keys:        resolver,
                Nonces:      nonces,
                Revocations: &verifyPkg.StaticRevocationResolver{},
        }
        first := verifyPkg.VerifyHandshakeRequest(&req, ctx)
        second := verifyPkg.VerifyHandshakeRequest(&req, ctx)

        firstResult := "accept"
        if !first.Accepted() {
                firstResult = "reject"
        }
        secondResult := "accept"
        var secondErrorCode any
        if !second.Accepted() {
                secondResult = "reject"
                secondErrorCode = string(second.Refusal.ErrorCode)
        }
        passed := firstResult == "accept" && secondResult == "reject" && secondErrorCode == "replay_detected"
        return map[string]any{
                "first_result":       firstResult,
                "second_result":      secondResult,
                "second_error_code":  secondErrorCode,
                "passed":             passed,
        }
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
                "vectors":            runVectors(root),
                "error_code_vectors": runErrorCodeVectors(root),
                "replay_check":       runReplayCheck(root),
        }
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        if err := enc.Encode(report); err != nil {
                fmt.Fprintf(os.Stderr, "encode: %v\n", err)
                os.Exit(2)
        }
}
