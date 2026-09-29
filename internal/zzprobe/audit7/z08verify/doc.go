//go:build !audit7

// Package z08verify holds the round-7 adversarial re-verification probes for
// zone 08 (frontend / browser plane). They only build under the audit7 tag, so
// the default test suite never sees them.
package z08verify
