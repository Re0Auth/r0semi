//go:build !audit7

// Package z13verify holds the seventh audit round's adversarial re-verification of
// zone 13 (deploy / CI / supply-chain / release artifacts). It reproduces the
// reviewed probes' positive controls, adds the ones they were missing, executes
// the shell scripts for real (Git for Windows ships a bash the zone report did not
// find on PATH), and states one new finding: .dockerignore covers most of
// .gitignore but not the audit workspace or the other gitignored local state.
//
// Everything is behind the `audit7` build tag so the default suite never sees it:
//
//	go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z13verify/...
//
// Nothing in this package is imported by production code.
package z13verify
