module github.com/handshake-protocol/handshake-ai/tests/conformance/go

go 1.22.0

require (
	github.com/handshake-protocol/handshake-ai/packages/handshake-go v0.0.0
)

// Resolve the SDK from the local checkout so the conformance runner builds
// without needing a published module version. go.work also lists this module,
// but the replace makes plain `go build` (without workspace mode) work too.
replace github.com/handshake-protocol/handshake-ai/packages/handshake-go => ../../../packages/handshake-go
