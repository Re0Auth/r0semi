//go:build !audit7

// Package z21migrationsschemaintegrity holds audit-round-7 probes for zone 21
// (database migrations / schema / constraint integrity).
//
// Without the audit7 build tag this package is intentionally empty: the probes
// are source-level and must not run as part of the default suite.
package z21migrationsschemaintegrity
