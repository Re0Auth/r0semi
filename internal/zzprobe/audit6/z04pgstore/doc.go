//go:build !audit6

// Package z04pgstore holds the round-6 audit probes for zone 04 (the Postgres
// storage layer). The package is empty without the audit6 build tag; with it,
// the *_test.go files next to this one run against the shipped sources and, for
// the revocation probes, against a real pgxpool pointed at an address where no
// database will ever answer.
package z04pgstore
