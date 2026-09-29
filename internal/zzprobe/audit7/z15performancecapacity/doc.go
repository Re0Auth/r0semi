//go:build !audit7

// Package z15performancecapacity holds the round-7 audit probes for area Z15
// (performance / capacity / memory / allocation).
//
// Every other file in this directory carries `//go:build audit7`, so the default
// test suite never compiles them. This placeholder exists only so the directory
// is a valid package in the default build; the probes run with
// `go test -tags audit7 ./internal/zzprobe/audit7/z15performancecapacity/...`.
package z15performancecapacity
