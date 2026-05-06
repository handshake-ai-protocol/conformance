module github.com/handshake-ai-protocol/conformance/go

go 1.26.2

require github.com/handshake-ai-protocol/go v0.0.0

require (
        github.com/cloudflare/circl v1.6.3 // indirect
        github.com/gabriel-vasile/mimetype v1.4.13 // indirect
        github.com/go-playground/locales v0.14.1 // indirect
        github.com/go-playground/universal-translator v0.18.1 // indirect
        github.com/go-playground/validator/v10 v10.30.2 // indirect
        github.com/gowebpki/jcs v1.0.1 // indirect
        github.com/leodido/go-urn v1.4.0 // indirect
        golang.org/x/crypto v0.50.0 // indirect
        golang.org/x/sys v0.43.0 // indirect
        golang.org/x/text v0.36.0 // indirect
)

// Resolve the SDK from the local checkout so the conformance runner builds
// without needing a published module version. go.work also lists this module,
// but the replace makes plain `go build` (without workspace mode) work too.
replace github.com/handshake-ai-protocol/go => ../../../packages/handshake-go
