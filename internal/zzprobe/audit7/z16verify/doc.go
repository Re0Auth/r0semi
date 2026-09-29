//go:build audit7

// Package z16verify is the adversarial re-verification of zone 16's
// guard-and-test-quality findings (round 7). Every probe here is either a
// positive control for a mechanism the Z16 report rests on, or the falsification
// attempt that failed. Nothing in this package touches a tracked file.
package z16verify
