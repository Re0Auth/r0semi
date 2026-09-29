//go:build !audit6

// Package z07authsession holds the round-6 identity / session / CSRF /
// account-lifecycle audit probes
// (scratchpad/audit6/findings/07-auth-session-lifecycle.md).
//
// This file keeps the package present when the audit6 build tag is not set, so
// the default suite and the probes never see each other.
package z07authsession
