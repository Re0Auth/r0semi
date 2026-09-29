//go:build !audit6

// Package z03crypto holds the round-6 audit probes for zone 03
// (cryptography: vault envelope encryption / KEK / rotation / key lifecycle).
//
// They are behind the `audit6` build tag: run them with
//
//	go test -tags audit6 -count=1 ./internal/zzprobe/audit6/z03crypto/...
//
// Without the tag this package is intentionally empty, so the ordinary
// `go test ./...` stays green. See scratchpad/audit6/BRIEF.md.
package z03crypto
