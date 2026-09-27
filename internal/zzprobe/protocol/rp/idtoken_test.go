//go:build audit5

package rp

import (
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/Re0Auth/r0semi/idp"
)

// TestRPControlOIDCLoginSucceeds is the anti-vacuity control for every probe in
// this file: the full RP round trip against the fake OP has to work, or a later
// "it was rejected" assertion proves nothing.
func TestRPControlOIDCLoginSucceeds(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	ident, err := login(t, c, f, nonce)
	if err != nil {
		t.Fatalf("control round trip failed: %v", err)
	}
	if ident.Subject != "rp-user-1" || ident.Provider != "google" {
		t.Fatalf("identity = %+v", ident)
	}
	discovery, jwks, token, info := f.hits()
	if discovery == 0 || jwks == 0 || token == 0 {
		t.Fatalf("control did not exercise the provider: discovery=%d jwks=%d token=%d", discovery, jwks, token)
	}
	if info != 0 {
		t.Fatalf("control fell back to userinfo (%d calls) instead of the id_token", info)
	}
}

// OIDC Core 3.1.3.7: when the token has more than one audience, azp MUST be
// present and MUST name this client. go-oidc checks only that our client_id is
// *among* the audiences, and says so in its own comment ("This check DOES NOT
// ensure that the ClientID is the party to which the ID Token was issued").
//
// A parseable instance: an id_token minted for another client at the same
// issuer, whose aud happens to list ours too, is accepted as this client's
// identity -- and the RP then signs a session in as the token's subject.
func TestRPAzpNamingAnotherClientIsAccepted(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	ident, err := login(t, c, f, nonce)
	if err != nil {
		t.Fatalf("control failed: %v", err)
	}
	control := ident.Subject

	// The same issuer mints a token for "other-client" that also lists our
	// client id as an audience, and says so in azp.
	f.setClaims(func(m map[string]any) {
		m["aud"] = []string{"cid", "other-client"}
		m["azp"] = "other-client"
		m["sub"] = "victim-of-another-client"
	})
	ident, err = login(t, c, f, nonce)
	if err != nil {
		t.Logf("accepted=no (rejected): %v", err)
		return
	}
	t.Errorf("RP accepted an id_token whose azp is another client: sub=%q aud=[cid other-client] azp=other-client (control sub=%q)",
		ident.Subject, control)
}

// The other half of the same rule: multiple audiences with no azp at all.
func TestRPAzpMissingWithMultipleAudiencesIsAccepted(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	f.setClaims(func(m map[string]any) {
		m["aud"] = []string{"cid", "other-client"}
		m["azp"] = nil
		m["sub"] = "no-azp-subject"
	})
	ident, err := login(t, c, f, nonce)
	if err != nil {
		t.Logf("accepted=no (rejected): %v", err)
		return
	}
	t.Errorf("RP accepted a multi-audience id_token with no azp: sub=%q aud=[cid other-client]", ident.Subject)
}

// A single audience plus a foreign azp: OIDC says azp, when present, must be
// this client.
func TestRPAzpMismatchSingleAudienceIsAccepted(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	f.setClaims(func(m map[string]any) {
		m["aud"] = "cid"
		m["azp"] = "someone-else"
	})
	ident, err := login(t, c, f, nonce)
	if err != nil {
		t.Logf("accepted=no (rejected): %v", err)
		return
	}
	t.Errorf("RP accepted an id_token whose azp (%q) is neither the audience nor this client: sub=%q",
		"someone-else", ident.Subject)
}

// The JWKS cache has no TTL and is only replaced when a fetch happens, and a
// fetch happens only when no cached key verifies the token. So a key the
// provider has revoked keeps verifying -- and no request to the provider is
// made to notice.
func TestRPRetiredSigningKeyKeepsVerifyingAfterRotation(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	old := f.signingKey()
	if _, err := login(t, c, f, nonce); err != nil {
		t.Fatalf("control round trip failed: %v", err)
	}
	_, jwksBefore, _, _ := f.hits()

	// The provider rotates: a new key signs from now on, and the old key is gone
	// from the published set -- the shape of "we rotated because the key leaked".
	rotated := newTestKey(t, "k2")
	f.setSigningKey(rotated)
	f.setJWKS(rotated.publicJWK())

	// The retired key alone. It is signed by a key the provider no longer
	// publishes, so accepting it means the RP never asked again.
	now := time.Now()
	forged := old.sign(t, map[string]any{
		"iss": f.issuer(), "sub": "attacker-with-the-retired-key", "aud": "cid",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": nonce,
	})
	ident, err := identityOf(t, c, f, forged, nonce)
	_, jwksAfter, _, _ := f.hits()
	if err == nil {
		t.Errorf("RP accepted an id_token signed by a key removed from the JWKS: sub=%q (jwks fetches before=%d after=%d)",
			ident.Subject, jwksBefore, jwksAfter)
		return
	}
	t.Logf("rejected as expected: %v (jwks fetches before=%d after=%d)", err, jwksBefore, jwksAfter)
}

// A JWKS fetch failure must not clear the cache (which would be a downgrade) and
// must not stop a token whose key is already cached from verifying.
func TestRPJWKSFailureDoesNotClearTheCache(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	if _, err := login(t, c, f, nonce); err != nil {
		t.Fatalf("control round trip failed: %v", err)
	}
	_, jwksPrimed, _, _ := f.hits()

	// The keys endpoint starts failing, and a token arrives with an unknown kid,
	// which is what forces a refetch.
	f.setJWKSStatus(500)
	now := time.Now()
	unknown := newTestKey(t, "k-unknown")
	other := unknown.sign(t, map[string]any{
		"iss": f.issuer(), "sub": "unknown-kid", "aud": "cid",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": nonce,
	})
	if _, err := identityOf(t, c, f, other, nonce); err == nil {
		t.Error("RP accepted a token signed by a key that is in no JWKS, while the fetch was failing")
	}
	_, jwksFailed, _, _ := f.hits()
	if jwksFailed <= jwksPrimed {
		t.Fatalf("the probe never forced a refetch (jwks fetches %d -> %d): the failure path was not reached",
			jwksPrimed, jwksFailed)
	}

	// The cached key still works, which is what "the failure did not clear the
	// cache" means.
	if _, err := login(t, c, f, nonce); err != nil {
		t.Errorf("a failed JWKS fetch invalidated the cached key set: %v", err)
	}
}

// Two providers, two issuers, two keys: a token minted by one must not verify at
// the other's verifier, whatever it claims about iss.
func TestRPOneProvidersKeyDoesNotVerifyAtAnother(t *testing.T) {
	a := newFakeOP(t)
	b := newFakeOP(t)
	ca := newRegistry(t, a, "beta-a", idpCred())
	nonce := ca.NewNonce()
	a.nonce = nonce
	b.nonce = nonce

	if _, err := login(t, ca, a, nonce); err != nil {
		t.Fatalf("control round trip at provider A failed: %v", err)
	}

	// B signs a token that claims to be issued by A.
	now := time.Now()
	forged := b.signingKey().sign(t, map[string]any{
		"iss": a.issuer(), "sub": "impostor", "aud": "cid",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": nonce,
	})
	if ident, err := identityOf(t, ca, a, forged, nonce); err == nil {
		t.Errorf("provider B's key verified at provider A's verifier: sub=%q", ident.Subject)
	}
}

// An id_token signed by nobody: alg=none. Pinned algorithms are the thing that
// stops it, so this is the guard for the "no none" property.
func TestRPAlgNoneIsRejected(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	if _, err := login(t, c, f, nonce); err != nil {
		t.Fatalf("control round trip failed: %v", err)
	}
	now := time.Now()
	none := unsignedToken(t, map[string]any{
		"iss": f.issuer(), "sub": "nobody", "aud": "cid",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": nonce,
	})
	if ident, err := identityOf(t, c, f, none, nonce); err == nil {
		t.Errorf("RP accepted an alg=none id_token: sub=%q", ident.Subject)
	}
}

// HS256 confusion: the provider advertises HS256 as a supported signing
// algorithm and publishes the symmetric key in its own JWKS. go-oidc filters the
// advertised list down to asymmetric algorithms, so this has to be refused.
func TestRPHS256WithPublishedSymmetricKeyIsRejected(t *testing.T) {
	f := newFakeOP(t)
	secret := []byte("published-symmetric-key-0123456789")
	f.setAlgs("RS256", "HS256")
	f.setJWKS(jose.JSONWebKey{Key: secret, KeyID: "oct-1", Algorithm: string(jose.HS256), Use: "sig"})
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	discovery, _, _, _ := f.hits()
	if discovery != 0 {
		t.Fatalf("probe precondition: discovery already fetched")
	}
	now := time.Now()
	forged := hmacToken(t, secret, map[string]any{
		"iss": f.issuer(), "sub": "hs256-forgery", "aud": "cid",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": nonce,
	})
	if ident, err := identityOf(t, c, f, forged, nonce); err == nil {
		t.Errorf("RP accepted an HS256 id_token signed with the published symmetric key: sub=%q", ident.Subject)
	}
	discovery, _, _, _ = f.hits()
	if discovery == 0 {
		t.Fatal("the probe never reached discovery: the assertion above is vacuous")
	}
}

// The nonce must be present and equal, not merely "not wrong".
func TestRPMissingNonceClaimIsRejected(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce("") // the provider mints the id_token with no nonce claim at all
	f.setClaims(func(m map[string]any) { m["nonce"] = nil })

	if _, err := login(t, c, f, nonce); err == nil {
		t.Error("RP accepted an id_token with no nonce claim")
	}

	// Anti-vacuity: the same call with the nonce present succeeds.
	f.setClaims(func(m map[string]any) { m["nonce"] = nonce })
	if _, err := login(t, c, f, nonce); err != nil {
		t.Fatalf("control failed, so the rejection above proves nothing: %v", err)
	}
}

// A verifier that is asked to check an empty nonce must refuse rather than treat
// "" as "no nonce expected".
func TestRPEmptyExpectedNonceIsFatal(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	if _, err := login(t, c, f, ""); err == nil {
		t.Error("Identity accepted an empty expected nonce")
	}
	if _, err := login(t, c, f, nonce); err != nil {
		t.Fatalf("control failed: %v", err)
	}
}

// An empty sub must not become an account key.
func TestRPEmptySubjectIsRejected(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)
	f.setClaims(func(m map[string]any) { m["sub"] = "" })

	if _, err := login(t, c, f, nonce); err == nil {
		t.Error("RP accepted an id_token with an empty sub")
	}
	f.setClaims(func(m map[string]any) { m["sub"] = "rp-user-1" })
	if _, err := login(t, c, f, nonce); err != nil {
		t.Fatalf("control failed: %v", err)
	}
}

// No id_token at all must fail closed: the userinfo endpoint must not be
// consulted as a fallback for an OIDC provider.
func TestRPNoIDTokenDoesNotFallBackToUserinfo(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	f.setOmitIDToken(true)

	if _, err := login(t, c, f, "any-nonce"); err == nil {
		t.Error("RP accepted a token response with no id_token")
	}
	_, _, token, info := f.hits()
	if token == 0 {
		t.Fatal("the probe never reached the token endpoint")
	}
	if info != 0 {
		t.Errorf("RP fell back to userinfo (%d calls) for an OIDC provider", info)
	}
}

// Discovery that advertises a different issuer is the mix-up shape. go-oidc
// refuses it; this is the guard that keeps that true through the idp wrapper.
func TestRPDiscoveryIssuerMismatchIsRejected(t *testing.T) {
	f := newFakeOP(t)
	f.setIssuerOverride("https://evil.example")
	c := newRegistry(t, f, "google", idpCred())
	f.setNonce("n-1")

	if _, err := login(t, c, f, "n-1"); err == nil {
		t.Error("RP accepted a discovery document whose issuer is not the configured one")
	}
	discovery, _, _, _ := f.hits()
	if discovery == 0 {
		t.Fatal("the probe never reached discovery")
	}

	// Anti-vacuity: with the discovered issuer matching, the same flow works.
	f.setIssuerOverride("")
	f2 := newFakeOP(t)
	c2 := newRegistry(t, f2, "google", idpCred())
	f2.setNonce("n-2")
	if _, err := login(t, c2, f2, "n-2"); err != nil {
		t.Fatalf("control failed: %v", err)
	}
}

// PKCE has to be S256 and the verifier the exchange sends has to be the one that
// produced the challenge in the authorization URL.
func TestRPSendsS256PKCEAndTheMatchingVerifier(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)

	verifier := c.NewVerifier()
	authURL, err := c.AuthCodeURL(ctxOf(f), "state-1", verifier, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("authorization URL does not ask for S256: %s", authURL)
	}
	if !strings.Contains(authURL, "nonce="+nonce) {
		t.Fatalf("authorization URL does not carry the nonce: %s", authURL)
	}
	if !strings.Contains(authURL, "redirect_uri=https%3A%2F%2Fre0auth.test%2Fauth%2Fgoogle%2Fcallback") {
		t.Fatalf("authorization URL's redirect_uri is not the configured callback: %s", authURL)
	}

	if _, err := c.Exchange(ctxOf(f), "code-1", verifier); err != nil {
		t.Fatal(err)
	}
	form := f.tokenForm()
	if got := form.Get("code_verifier"); got != verifier {
		t.Errorf("token request code_verifier = %q, want the verifier whose challenge was sent", got)
	}
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q", got)
	}
}

// The callback URL is built from configuration only: a provider name that could
// escape the path is refused at construction, and the name is used verbatim in
// the redirect_uri.
func TestRPProviderNameIsValidatedBeforeItReachesAURL(t *testing.T) {
	for _, name := range []string{"../evil", "a/b", "evil.example", "Google", "-lead", "_lead", "", "sp ace"} {
		_, err := newFakeRegistryErr(idp.Provider(name))
		if err == nil {
			t.Errorf("provider name %q was accepted", name)
		}
	}
	if _, err := newFakeRegistryErr("authentik"); err != nil {
		t.Errorf("control: a valid custom provider name was refused: %v", err)
	}
}
