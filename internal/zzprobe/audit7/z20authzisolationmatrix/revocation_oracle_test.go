//go:build audit7

// Z20 cross-client probes on the deployed protocol plane's revocation endpoint.
package zzprobe_z20authzisolationmatrix

import (
	"net/http"
	"net/url"
	"testing"
)

// TestZ20RevocationIsALivenessOracleForForeignTokens is the finding probe.
//
// `oauth/as.go:223-239` states the project's own rule in code: an unknown value
// and a value owned by somebody else must be refused the SAME way, "rather than
// confirmed — answering 'that is not yours' would turn this endpoint into an
// oracle for whether a stolen string is a live token". G-8 recorded the
// violation on the public engine. The DEPLOYED plane has the same shape on a
// different code path — zitadel/oidc's `Revoke` plus this project's `RevokeToken`
// — and never got the same note: a stranger's live token answers 401
// (`oidc.ErrInvalidClient`, internal/store/memory/oidc.go:619-622 and :649-652),
// while a string this server never issued answers 200.
//
// A public client's id is not a credential (it is printed in every authorization
// URL), so "one registered client" costs an attacker nothing.
func TestZ20RevocationIsALivenessOracleForForeignTokens(t *testing.T) {
	e := newZEnv(t, zOptions{ExtraPublicIDs: []string{"cli2"}})

	// A live token, minted for a DIFFERENT client.
	victim := e.mintTokensFor("cli2", zSubject, "account.id").AccessToken
	if victim == "" {
		t.Fatal("control: no victim token")
	}

	unknownStatus, unknownBody := e.zRevoke(zClientID, "", "this-string-was-never-issued")
	t.Logf("revoke an unknown string        -> %d %s", unknownStatus, unknownBody)

	foreignStatus, foreignBody := e.zRevoke(zClientID, "", victim)
	t.Logf("revoke another client's live AT -> %d %s", foreignStatus, foreignBody)

	// Control: the attempt really is about ownership — the token still works, so
	// the 401 is a refusal, not a deletion.
	status, _, _ := e.zGet("/v1/me", victim)
	if status != http.StatusOK {
		t.Fatalf("control: the foreign token stopped working (%d); the probe cannot tell "+
			"a refusal from a revocation", status)
	}

	if unknownStatus == http.StatusOK && foreignStatus != http.StatusOK {
		t.Errorf("revocation distinguishes a stranger's LIVE token (%d) from a string that "+
			"was never issued (%d): the endpoint confirms whether a string this server "+
			"issued is live. Upstream guidance is in oauth/as.go:223-239; G-8 recorded it "+
			"on the public engine only", foreignStatus, unknownStatus)
	}
}

// TestZ20RevocationRefusesToDeleteAnotherClientsGrant is the G-8 guard: a
// foreign revocation answers the uniform RFC 7009 success (indistinguishable
// from an unknown string) and deletes nothing, while the owner's own revocation
// still works. (Before the fix the foreign case answered 401 invalid_client on
// the deployed plane too; the refusal itself was the liveness oracle.)
func TestZ20RevocationRefusesToDeleteAnotherClientsGrant(t *testing.T) {
	e := newZEnv(t, zOptions{ExtraPublicIDs: []string{"cli2"}})
	tokens := e.mintTokensFor("cli2", zSubject, "account.id")

	if st, body := e.zRevoke(zClientID, "", tokens.AccessToken); st != http.StatusOK {
		t.Errorf("another client's revocation of a foreign access token answered %d, want the uniform RFC 7009 200: %s",
			st, body)
	}
	if st, body := e.zRevoke(zClientID, "", tokens.RefreshToken); st != http.StatusOK {
		t.Errorf("another client's revocation of a foreign refresh token answered %d, want the uniform RFC 7009 200: %s",
			st, body)
	}
	// The mismatch guard: neither foreign attempt deleted anything.
	if st, _, _ := e.zGet("/v1/me", tokens.AccessToken); st != http.StatusOK {
		t.Errorf("the foreign revocations killed the access token (%d)", st)
	}
	// The owner can.
	if st, body := e.zRevoke("cli2", "", tokens.RefreshToken); st != http.StatusOK {
		t.Errorf("the owner could not revoke its own refresh token: %d %s", st, body)
	}
	// And the access token went with it (RFC 7009 §2.1: the whole grant).
	if st, _, _ := e.zGet("/v1/me", tokens.AccessToken); st == http.StatusOK {
		t.Errorf("revoking the refresh token left the paired access token live")
	}
}

// zRevoke posts the revocation endpoint with raw Basic userinfo.
func (e *zEnv) zRevoke(clientID, secret, token string) (int, []byte) {
	e.t.Helper()
	form := url.Values{"token": {token}}
	return e.zPostForm("/oauth/revoke", form, zBasicHeader(clientID, secret))
}
