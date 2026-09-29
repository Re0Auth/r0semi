//go:build !audit7

// Package z12configstartupobservability holds round 7's zone-12 probes
// (configuration / startup / observability / shutdown).
//
// Every probe file here carries //go:build audit7, so an ordinary `go build ./...`
// or `go test ./...` sees this package with no test and no symbol in it: the
// default suite stays green and no probe can leak into a release binary.
//
// The probes are read-only. They add tests; they change no non-test file.
package z12configstartupobservability
