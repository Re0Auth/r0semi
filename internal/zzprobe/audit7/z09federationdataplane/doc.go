//go:build !audit7

// Package zzprobe_z09federationdataplane holds the round-7 audit probes for area
// Z09 (federation data plane / egress / SSRF / binding lifecycle).
//
// Every file in this directory carries `//go:build audit7`, so the default test
// suite does not see them. This placeholder exists only so the directory is a
// valid package in the default build; the probes are compiled with
// `go test -tags audit7 ./internal/zzprobe/audit7/z09federationdataplane/...`.
package zzprobe_z09federationdataplane
