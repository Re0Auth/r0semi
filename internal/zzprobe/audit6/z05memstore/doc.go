//go:build !audit6

// Package z05memstore holds the round-6 audit probes for zone 05
// (in-memory store: semantic drift against Postgres, races, growth bounds).
// They are behind the `audit6` build tag: run them with
// go test -tags audit6 ./internal/zzprobe/audit6/z05memstore/...
// Without the tag this package is intentionally empty, so the normal
// go test ./... stays green.
package z05memstore
