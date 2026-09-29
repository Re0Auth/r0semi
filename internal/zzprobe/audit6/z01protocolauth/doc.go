//go:build !audit6

// Package z01protocolauth holds the round-6 audit probes for zone 01 (the OIDC
// protocol face: authorize, device flow, PKCE, session binding). They live
// behind the `audit6` build tag:
//
//	go test -tags audit6 -count=1 ./internal/zzprobe/audit6/z01protocolauth/...
//
// Without the tag the package is intentionally empty, so the normal
// go test ./... stays green. See scratchpad/audit6/BRIEF.md.
package z01protocolauth
