//go:build !audit5

// Package zzprobe_verifyfederation holds the round-5 audit probes for this area. They are
// behind the `audit5` build tag: run them with go test -tags audit5 ./....
// Without the tag this package is intentionally empty, so the normal
// go test ./... stays green. See docs/security-audit-5.md.
package zzprobe_verifyfederation
