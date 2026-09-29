//go:build !audit7

// Package zzprobe_z20authzisolationmatrix holds round-7 audit probes for area
// Z20: the authorization isolation matrix (subject x client x scope x resource).
//
// Everything here is behind the `audit7` build tag, so the default test suite
// never sees it. Build with:
//
//	go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z20authzisolationmatrix/...
//
// The probes drive the real HTTP surface: internal/httpapi mounted on an
// httptest server, the real OpenID Provider (internal/oidchttp) behind it, real
// access tokens minted through authorize -> consent -> callback -> token, the
// real scope registry, and a real upstream http server reached through the real
// data plane. No tracked file is modified.
package zzprobe_z20authzisolationmatrix
