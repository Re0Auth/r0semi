//go:build !audit7

// Package z07authsessionlifecycle holds the round-7 zone-07 audit probes:
// session, account, identity-binding and erasure lifecycle
// (scratchpad/audit7/findings/Z07-auth-session-lifecycle.md).
//
// This file keeps the package present when the audit7 build tag is not set, so
// the default suite never sees the probes, and the probes never see the default
// suite's helpers.
package z07authsessionlifecycle
