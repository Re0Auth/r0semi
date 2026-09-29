//go:build !audit7

// Package z22reconcile holds the round-7 zone-22 audit probes: the per-probe
// reconciliation of the round-5 `audit5` probes that are still red at HEAD
// (scratchpad/audit7/findings/22-audit5-red-reconciliation.md).
//
// This file keeps the package present when the audit7 build tag is not set, so
// the default suite never sees the probes, and the probes never see the default
// suite's helpers.
package z22reconcile
