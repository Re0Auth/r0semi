//go:build audit || protocolaudit

// Audit probe, round 6, area 01 — the business-plane introspection seam.
//
// Run with:
//
//	go test -tags protocolaudit -count=1 -run TestZZAudit_ ./internal/oidchttp/ -v
//
// internal/oidchttp.Handler.Introspect is what /v1 uses to decide whether a
// bearer is a live token this server issued. It decrypts with the token key and
// treats anything that does not decrypt as inactive; this probe pins that an
// id_token — a compact JWS signed by this very OP, and the shape the library's
// own userinfo path falls back to verifying — is not one.
package oidchttp

import (
	"strings"
	"testing"
)

func TestZZAudit_IntrospectRejectsAnIDToken(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	_, _, out := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))

	idToken, _ := out["id_token"].(string)
	access, _ := out["access_token"].(string)
	refresh, _ := out["refresh_token"].(string)
	if idToken == "" || access == "" {
		t.Fatalf("missing tokens: %v", out)
	}

	info, err := e.handler.Introspect(t.Context(), idToken)
	if err != nil {
		t.Fatalf("Introspect(id_token) returned an error: %v", err)
	}
	t.Logf("Introspect(id_token) = %+v", info)
	if info.Active {
		t.Errorf("the business plane accepts an id_token as a live access token: %+v", info)
	}

	if info, err := e.handler.Introspect(t.Context(), access); err != nil || !info.Active {
		t.Errorf("Introspect(live access token) = %+v, %v; want active", info, err)
	}
	if info, err := e.handler.Introspect(t.Context(), refresh); err != nil || info.Active {
		t.Errorf("Introspect(refresh token) = %+v, %v; want inactive", info, err)
	}
	if info, err := e.handler.Introspect(t.Context(), ""); err != nil || info.Active {
		t.Errorf("Introspect(\"\") = %+v, %v; want inactive", info, err)
	}
}
