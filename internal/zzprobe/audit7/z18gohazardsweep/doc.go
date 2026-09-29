//go:build !audit7

// Package zzprobe_z18gohazardsweep holds round-7 area-Z18 probes: a Go-level
// hazard sweep across the non-test tree (integer and clock handling, slice and
// map aliasing, goroutine and context propagation, concurrency and locking,
// header/path/command injection, randomness, file permissions).
//
// The probes carry the audit7 build tag, so the default `go test ./...` never
// sees them. This file exists only so the directory is a valid package without
// the tag; it contains no code.
package zzprobe_z18gohazardsweep
