//go:build !audit7

// Package zzprobe_z20independent holds the round-7 INDEPENDENT cross-check
// probes for area Z20: the authorization isolation matrix
// (subject x client x scope x resource).
//
// It is deliberately a second, self-contained fixture: the zone-20 report
// (`scratchpad/audit7/findings/Z20-authz-isolation-matrix.md`) was produced by a
// different agent with its own wiring, and an independent reproduction has to
// share no helper with it. Everything here is built from exported surfaces only
// (httpapi.New + Config, internal/oidchttp, internal/store/memory,
// internal/federation, internal/auth, internal/admin, vault, oauth).
//
// Everything is behind the `audit7` build tag, so the default test suite never
// sees it. Build with:
//
//	go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z20independent/...
//
// No tracked file is modified.
package zzprobe_z20independent
