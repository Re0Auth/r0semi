//go:build audit7

// Package zzprobe_z11verify is the round-7 ADVERSARIAL verification of area Z11
// (resilience / rate limiting / concurrency caps / DoS surface).
//
// It is a copy of the audited fixtures on purpose: the probes here must not
// modify or depend on the reviewed package's files, and they exist to answer
// three questions the review left open:
//
//  1. Z11-2 — are the "held" upstream bodies actually live in the heap while the
//     handler is inside w.Write, or had the writes completed (and the bodies
//     become garbage) when the author measured? The author's own print showed a
//     4.2 MiB heap delta for 8 x 4 MiB bodies, which its text does not explain.
//  2. Z11-1 — is the poison reachable when the dependency check is instant (a
//     same-host pgx Ping is ~1ms, not the 300ms stub the author used)?
//  3. Z11-5 / Z11-4 — mechanism re-derivation from the other side.
package zzprobe_z11verify
