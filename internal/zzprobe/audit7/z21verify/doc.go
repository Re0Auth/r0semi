//go:build audit7

// Package z21verify holds the adversarial re-check of the Z21 (migrations /
// schema integrity) report. It is deliberately independent: it re-derives the
// facts from the migration text, the shipped store sources and the goose module
// source rather than importing the reviewed probes' helpers.
//
// Everything here is build-tagged audit7 so the default test suite never sees it.
package z21verify
