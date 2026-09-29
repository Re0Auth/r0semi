//go:build !audit7

// Package z15verify holds the round-7 adversarial verification probes for the
// Z15 (performance / capacity) report. It exists only so the directory is a valid
// package in the default build; the probes carry `//go:build audit7`.
package z15verify
