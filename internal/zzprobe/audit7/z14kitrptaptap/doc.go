//go:build !audit7

// Package z14kitrptaptap holds the round-7 zone-14 audit probes: the Upstream
// Kit, the RP side of idp/, and the TapTap adapter surface
// (scratchpad/audit7/findings/Z14-kit-rp-taptap.md).
//
// This file keeps the package present when the audit7 build tag is not set, so
// the default suite never sees the probes, and the probes never see the default
// suite's helpers.
package z14kitrptaptap
