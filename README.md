# tests/conformance

Cross-implementation conformance vectors for the Handshake protocol.
Every SDK (Python, TypeScript, Go, Rust) replays the fixtures in this
directory and must produce byte-identical results so wire-format drift
is caught before any release.

## Layout

```
fixtures/      Shared JSON inputs + expected outputs (e.g. jcs.json).
error_codes/   Vectors covering wire-level error responses.
py/            Python conformance runner.
ts/            TypeScript conformance runner.
go/            Go conformance runner.
results/       Per-language output written by each runner.
results.json   Consolidated cross-language summary.
```

The Rust runner lives alongside the Rust SDK in
`packages/handshake-rs/` and consumes the same fixtures via a relative
path.

## Run

From the repo root:

```bash
make conformance
```

This builds all four SDKs from source and runs the cross-language
conformance suite. Each runner writes its results into `results/` and
the consolidated comparison is asserted against `results.json`.

## Add a vector

1. Add the new fixture to the relevant file under `fixtures/` (or a new
   file there) — every entry has at minimum a `name`, an `input`, and
   the expected canonical/structured output for the operation under
   test. See `fixtures/jcs.json` for the canonical example.
2. Run `make conformance` locally; all four SDKs must pass.
3. Commit the fixture together with any SDK fix it forces.

Vectors are append-only: never edit an existing vector's expected
output without bumping `SPEC_VERSION` in the spec site, since
downstream implementations pin against the published set.
