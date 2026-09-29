//go:build audit7

// Package z14verify holds the zone-14 adversarial re-verification probes.
//
// It exists to (a) independently re-run the audited zone's own shapes where they
// need a second construction, (b) check the "tried and did not break" guards for
// fixture-induced false green, and (c) carry the new findings this review found.
//
// The new finding probed here is about WHICH URL the conformance suite probes:
// the suite reads the advertised `revocation_endpoint` / the advertised
// `cascade_revocation_endpoint` and then never contacts them — every probe is
// sent to `{target}{path}` at the target origin.
package z14verify
