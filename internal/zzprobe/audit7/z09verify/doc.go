//go:build !audit7

// Package zzprobe_z09verify holds the round-7 adversarial-verification probes for
// area Z09 (federation data plane / egress / SSRF / binding lifecycle).
//
// It is a separate directory from z09federationdataplane on purpose: the review
// may add probes but must not touch the reviewed area's own probes. Every probe
// file here carries `//go:build audit7`, so the default suite does not see them.
package zzprobe_z09verify
