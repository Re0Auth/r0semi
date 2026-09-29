//go:build !audit6

// Package z02protocoltoken holds the round-6 audit probes for zone 02, the
// protocol plane's token surface: token / refresh / introspection / revocation
// / userinfo / discovery / JWKS / id_token.
//
// They are behind the `audit6` build tag: run them with
//
//	go test -tags audit6 -count=1 ./internal/zzprobe/audit6/z02protocoltoken/...
//
// Without the tag this package is intentionally empty, so the default
// go test ./... stays green. Every probe attacks through a real entry point:
// a real *oidchttp.Handler (the same constructors cmd/re0auth composes) mounted
// on an httptest.Server, backed by the in-memory OP store.
package z02protocoltoken
