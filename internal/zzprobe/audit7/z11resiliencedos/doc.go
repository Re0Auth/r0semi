//go:build !audit7

// Package zzprobe_z11resiliencedos holds round-7 audit probes for area Z11
// (resilience: rate limiting, concurrency caps, DoS surface). The probes are
// behind the `audit7` build tag, so this file exists only to keep the package
// present — and therefore vet-able and gofmt-able — in the default build.
package zzprobe_z11resiliencedos
