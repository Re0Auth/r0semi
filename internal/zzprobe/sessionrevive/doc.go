//go:build !audit5

// Package sessionrevive holds the round-10 session probes for R10-96. They are
// behind the `audit5` build tag: run them with go test -tags audit5 ./....
// Without the tag this package is intentionally empty, so the normal
// go test ./... stays green. See AUDIT-ROUND10.md.
package sessionrevive
