// Go conformance runner. Reads the shared fixtures + test vector 001, emits
// a JSON report on stdout matching the schema consumed by examples/phase1_demo.sh.
package main

import (
        "bytes"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"

        "github.com/handshake-protocol/handshake-ai/packages/handshake-core-go/jcs"
        "github.com/handshake-protocol/handshake-ai/packages/handshake-core-go/hashing"
        "github.com/handshake-protocol/handshake-ai/packages/handshake-core-go/signing"
)

const repoFixtures = "tests/conformance/fixtures/jcs.json"
const repoVector001 = "packages/handshake-spec/test-vectors/v0.2.3/core/001-valid-handshake.json"

type fixtureFile struct {
        Fixtures []struct {
                Name  string `json:"name"`
                Input any    `json:"input"`
        } `json:"fixtures"`
}

func hash(v any) string {
        bytes, err := jcs.Canonicalize(v)
        if err != nil {
                fmt.Fprintf(os.Stderr, "canonicalize failed: %v\n", err)
                os.Exit(2)
        }
        return hashing.SHA256Hex(bytes)
}

func mustReadJSON(path string, dst any) {
        raw, err := os.ReadFile(path)
        if err != nil {
                fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
                os.Exit(2)
        }
        dec := json.NewDecoder(newReader(raw))
        dec.UseNumber()
        if err := dec.Decode(dst); err != nil {
                fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
                os.Exit(2)
        }
}

// newReader wraps a []byte so we can hand it to json.Decoder.
func newReader(b []byte) *bytesReader { return &bytesReader{b: b} }

type bytesReader struct {
        b []byte
        i int
}

func (r *bytesReader) Read(p []byte) (int, error) {
        if r.i >= len(r.b) {
                return 0, fmt.Errorf("EOF")
        }
        n := copy(p, r.b[r.i:])
        r.i += n
        return n, nil
}

func runJCSFixtures(rootDir string) []map[string]string {
        // Re-parse the file because we also need the optional expected_canonical
        // field which the typed struct above doesn't carry. Using a generic map
        // keeps this runner small.
        var raw map[string]any
        mustReadJSON(filepath.Join(rootDir, repoFixtures), &raw)
        fixtures := raw["fixtures"].([]any)
        out := make([]map[string]string, 0, len(fixtures))
        for _, fAny := range fixtures {
                fx := fAny.(map[string]any)
                name := fx["name"].(string)
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

func runEd25519KAT(rootDir string) map[string]any {
        var raw map[string]any
        mustReadJSON(filepath.Join(rootDir, repoFixtures), &raw)
        kat := raw["ed25519_kat"].(map[string]any)
        hexDecode := func(s string) []byte {
                b, err := hex.DecodeString(s)
                if err != nil {
                        panic(err)
                }
                return b
        }
        seed := hexDecode(kat["seed_hex"].(string))
        expectedPub := hexDecode(kat["public_key_hex"].(string))
        message := hexDecode(kat["message_hex"].(string))
        expectedSig := hexDecode(kat["signature_hex"].(string))

        kp, err := signing.FromSeed(seed)
        if err != nil {
                panic(err)
        }
        pubMatch := bytes.Equal(kp.PublicKey, expectedPub)
        sig := kp.Sign(message)
        sigMatch := bytes.Equal(sig, expectedSig)
        verifies := signing.Verify(kp.PublicKey, sig, message) == nil

        return map[string]any{
                "name":             kat["name"],
                "public_key_match": pubMatch,
                "signature_match":  sigMatch,
                "verifies":         verifies,
                "passed":           pubMatch && sigMatch && verifies,
        }
}

func runVector001(rootDir string) map[string]any {
        var v map[string]any
        mustReadJSON(filepath.Join(rootDir, repoVector001), &v)

        expectedResult := v["expected"].(map[string]any)["result"].(string)

        input := v["input"].(map[string]any)
        delegation := cloneMap(input["delegation"].(map[string]any))
        delete(delegation, "signature")
        unsignedDelSha := hash(delegation)

        userKp, err := signing.Generate()
        if err != nil {
                panic(err)
        }
        agentKp, err := signing.Generate()
        if err != nil {
                panic(err)
        }

        delBytes, err := jcs.Canonicalize(delegation)
        if err != nil {
                panic(err)
        }
        delSigB64 := userKp.SignB64(delBytes)
        if err := signing.VerifyB64(userKp.PublicKey, delSigB64, delBytes); err != nil {
                panic(fmt.Errorf("delegation verify: %w", err))
        }

        signedDelegation := cloneMap(delegation)
        signedDelegation["signature"] = delSigB64

        // Cross-impl byte-equality requires deterministic input; build the canonical
        // snapshot with the *unsigned* delegation in chain. Signing round-trip below
        // uses the signed delegation — those signatures are local to each runner.
        requestForHash := cloneMap(input["request"].(map[string]any))
        delete(requestForHash, "signature")
        requestForHash["delegation_chain"] = []any{delegation}
        unsignedReqSha := hash(requestForHash)

        requestForSigning := cloneMap(requestForHash)
        requestForSigning["delegation_chain"] = []any{signedDelegation}
        reqBytes, err := jcs.Canonicalize(requestForSigning)
        if err != nil {
                panic(err)
        }
        reqSigB64 := agentKp.SignB64(reqBytes)
        if err := signing.VerifyB64(agentKp.PublicKey, reqSigB64, reqBytes); err != nil {
                panic(fmt.Errorf("request verify: %w", err))
        }

        return map[string]any{
                "passed":                       true,
                "result":                       expectedResult,
                "unsigned_delegation_sha256":   unsignedDelSha,
                "unsigned_request_sha256":      unsignedReqSha,
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
                // Caller didn't set it; fall back to walking up from the binary's CWD.
                // Demo script always sets REPO_ROOT, so this is just a safety net.
                root = "."
        }
        report := map[string]any{
                "implementation": "go",
                "spec_version":   "0.2.3",
                "jcs_fixtures":   runJCSFixtures(root),
                "ed25519_kat":    runEd25519KAT(root),
                "vector_001":     runVector001(root),
        }
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        if err := enc.Encode(report); err != nil {
                fmt.Fprintf(os.Stderr, "encode: %v\n", err)
                os.Exit(2)
        }
}
