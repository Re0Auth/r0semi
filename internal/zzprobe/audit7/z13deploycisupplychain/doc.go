//go:build !audit7

// Package z13deploycisupplychain holds the seventh audit round's probes for the
// deployment / CI / supply-chain / release-artifact surface of this repository:
// the Dockerfile, deploy/k8s, scripts/, the Makefile and .github/workflows, plus
// the gates in internal/archtest that are supposed to keep those honest.
//
// The probes are red-first: each one states the invariant the artifact claims
// and fails when the artifact does not hold it. They live behind the `audit7`
// build tag so the default suite never sees them:
//
//	go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z13deploycisupplychain/...
//
// Nothing in this package is imported by production code.
package z13deploycisupplychain
