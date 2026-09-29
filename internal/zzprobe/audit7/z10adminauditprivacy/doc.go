//go:build !audit7

// Package z10adminauditprivacy holds the round-7 audit probes for zone 10
// (operator plane / audit chain / privacy and erasure). They are behind the
// `audit7` build tag: run them with
//
//	go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z10adminauditprivacy/...
//
// Without the tag this package is intentionally empty, so the ordinary
// `go test ./...` stays green. See scratchpad/audit7/findings/
// Z10-admin-audit-privacy.md.
package z10adminauditprivacy
