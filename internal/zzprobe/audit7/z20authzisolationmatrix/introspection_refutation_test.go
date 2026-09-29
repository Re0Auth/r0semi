//go:build audit7

// Z20 probe that pins the real reach of the introspection guard bypass
// (`_audit/protocol.md` P-01 / round-6 zone-01).
package zzprobe_z20authzisolationmatrix

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// TestZ20AllowlistedPublicClientDisclosesNothingEvenEncoded refutes the IMPACT
// half of P-01 while confirming its mechanism half.
//
// Mechanism (P-01 is right): `refuseIntrospectionByANonConfidentialClient`
// (oidchttp.go:1107-1122) reads the raw Basic userinfo, so a percent-encoded
// spelling does not resolve to a client, the guard returns "cannot tell" and the
// library — which percent-DECODES first (zitadel/oidc pkg/op/client.go:118-126) —
// authenticates a public client with an empty secret.
//
// Impact (P-01's amplification paragraph is wrong): the answer still discloses
// nothing, because `filterIntrospection` (oidchttp.go:1208-1234) compares the
// caller it is handed — `callerClientID`, again the RAW Basic userinfo — against
// the token's `client_id` and against the allowlist. An encoded caller is
// neither, so the body is rewritten to `{"active":false}` before it leaves. The
// deployment's own allowlist entry does not help the encoded spelling either: the
// allowlist is keyed on the same raw bytes.
//
// This probe is therefore GREEN when the bypass is harmless. It fails if any
// token field reaches the caller.
func TestZ20AllowlistedPublicClientDisclosesNothingEvenEncoded(t *testing.T) {
	e := newZEnv(t, zOptions{IntrospectionClients: []string{zClientID}})

	// A live token this public client itself holds: the case P-01 said would
	// return `active=true`.
	own := e.mintToken(zSubject, "account.id")
	if own == "" {
		t.Fatal("control: no token minted")
	}

	// Control 1: the plain public id is refused by the runtime guard, before the
	// library ever reads the token.
	status, body := e.zPostForm("/oauth/introspect", url.Values{"token": {own}}, zBasicHeader(zClientID, ""))
	t.Logf("plain public caller        -> %d %s", status, body)
	if status != http.StatusUnauthorized {
		t.Fatalf("control: the runtime guard answered %d for a plain public caller, want 401", status)
	}

	// Control 2: the same caller, percent-encoded, DOES get past the guard (the
	// mechanism P-01 proved). The status is what proves the probe reached the
	// library rather than the guard.
	const encodedID = "c%6ci" // url.QueryUnescape -> "cli"
	status, body = e.zPostForm("/oauth/introspect", url.Values{"token": {own}}, zBasicHeader(encodedID, ""))
	t.Logf("percent-encoded public caller -> %d %s", status, body)
	if status == http.StatusUnauthorized {
		t.Skipf("the encoded spelling no longer bypasses the guard (it was fixed): %s", body)
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("introspection body is not JSON: %s", body)
	}
	if active, _ := out["active"].(bool); active {
		t.Errorf("active=true reached a public caller with no secret: %s", body)
	}
	for _, field := range []string{"sub", "scope", "client_id", "exp", "aud", "iss"} {
		if _, ok := out[field]; ok {
			t.Errorf("introspection disclosed %q to an unauthenticated public caller: %s", field, body)
		}
	}
}
