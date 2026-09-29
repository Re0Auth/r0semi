//go:build !audit6

// Package z06httpedge holds the round-6 HTTP-edge audit probes
// (scratchpad/audit6/findings/06-http-edge.md).
//
// This file keeps the package present when the audit6 build tag is not set, so
// the default suite and the probes never see each other.
package z06httpedge
