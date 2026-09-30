//go:build audit7

// RP probes: what the idp wrapper does with a discovery document it should not
// fully trust, and how long a retired signing key keeps verifying.
//
// RP-3 (round 5) was "the discovered endpoints are not pinned to the issuer";
// fix 60de35d pinned authorization_endpoint and token_endpoint
// (idp/idp.go:486-509 pinToIssuer). The probes below are the two endpoints that
// pinToIssuer does NOT cover:
//
//   - jwks_uri, which go-oidc copies out of the document verbatim
//     (oidc.go:172,261) and which decides *whose signature counts*.
//   - the provider cache's TTL, whose bound is defeated by the
//     retain-the-stale-provider branch of a failed re-discovery.
package z14kitrptaptap

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestZ14ControlIDTokenFromTheIssuerJWKSIsAccepted is the anti-vacuity control:
// with jwks_uri on the issuer's own origin, a token signed by the issuer's key
// is accepted. Without this, "the foreign key was accepted" could be a probe
// that never worked.
func TestZ14ControlIDTokenFromTheIssuerJWKSIsAccepted(t *testing.T) {
	f := newFakeOP(t)
	c := probeRegistry(t, f, 0)
	nonce := c.NewNonce()

	raw := f.key.sign(t, idClaims(f.issuer(), "issuer-user", probeAudience, nonce))
	ident, err := verifyMinted(t, c, raw, nonce)
	if err != nil {
		t.Fatalf("control: the issuer's own key was rejected: %v", err)
	}
	if ident.Subject != "issuer-user" {
		t.Fatalf("control: sub = %q", ident.Subject)
	}
	discovery, jwks := f.hits()
	t.Logf("control: accepted sub=%q discovery=%d jwks=%d", ident.Subject, discovery, jwks)
}

// TestZ14ControlForeignKeyAgainstTheIssuerJWKSIsRejected is the second control:
// the same foreign key that the attack probe below gets accepted is *rejected*
// while jwks_uri still points at the issuer. That proves the acceptance really
// comes from the redirect of jwks_uri and not from the key being trusted some
// other way.
func TestZ14ControlForeignKeyAgainstTheIssuerJWKSIsRejected(t *testing.T) {
	f := newFakeOP(t)
	c := probeRegistry(t, f, 0)
	nonce := c.NewNonce()

	attacker := newProbeKey(t, "attacker-k1")
	raw := attacker.sign(t, idClaims(f.issuer(), "foreign-key-subject", probeAudience, nonce))
	if _, err := verifyMinted(t, c, raw, nonce); err == nil {
		t.Fatal("control: a key that is in nobody's JWKS verified")
	} else {
		t.Logf("control: the foreign key was rejected while jwks_uri was on the issuer: %v", err)
	}
}

// TestZ14DiscoveryJWKSURIIsNotPinnedToTheIssuer: the RP takes the JWKS location
// from the discovery document without requiring it to share the issuer's origin,
// so whoever can answer discovery can also decide whose signature the RP trusts.
//
// This is the signing-key half of RP-3, left open by the round-5 fix. It is not
// the same defect as RP-3's endpoint hijack: there the stolen thing is the
// long-lived client_secret; here it is the RP's entire notion of "the provider
// said this". A token for any sub, for this client, is accepted.
func TestZ14DiscoveryJWKSURIIsNotPinnedToTheIssuer(t *testing.T) {
	f := newFakeOP(t)

	// The attacker's key material, served from an origin that is not the issuer.
	attackerKey := newProbeKey(t, "attacker-k1")
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		probeWriteJSON(w, map[string]any{"keys": []any{attackerKey.jwk()}})
	}))
	defer attacker.Close()

	f.setJWKSURIOverride(attacker.URL + "/jwks")

	c := probeRegistry(t, f, 0)
	nonce := c.NewNonce()
	raw := attackerKey.sign(t, idClaims(f.issuer(), "sub-forged-by-another-origin", probeAudience, nonce))

	ident, err := verifyMinted(t, c, raw, nonce)
	discovery, jwks := f.hits()
	t.Logf("issuer=%s jwks_uri=%s discovery=%d issuer-jwks-hits=%d", f.issuer(), attacker.URL+"/jwks", discovery, jwks)

	if err == nil {
		t.Errorf("the RP verified and accepted an id_token signed by a key served from %s — an origin other than the issuer %s — and took sub=%q from it.\n"+
			"pinToIssuer (idp/idp.go:486-509) checks authorization_endpoint and token_endpoint only; go-oidc copies jwks_uri out of the document (oidc.go:172,261) and builds the key set from it.",
			attacker.URL, f.issuer(), ident.Subject)
		return
	}
	t.Logf("a foreign jwks_uri was refused: %v", err)
}

// TestZ14ControlTheProviderTTLCacheRetiresARotatedKey: with discovery reachable,
// the provider cache TTL does what fix 60de35d intended — after the TTL the
// provider is rebuilt, its key set is empty, and a token signed by the retired
// key is refused.
func TestZ14ControlTheProviderTTLCacheRetiresARotatedKey(t *testing.T) {
	f := newFakeOP(t)
	c := probeRegistry(t, f, time.Nanosecond)
	nonce := c.NewNonce()

	old := f.key
	raw := old.sign(t, idClaims(f.issuer(), "before-rotation", probeAudience, nonce))
	if _, err := verifyMinted(t, c, raw, nonce); err != nil {
		t.Fatalf("control: the first (published) key was rejected: %v", err)
	}

	// Upstream retires the old key and publishes only the new one.
	f.rotate(newProbeKey(t, "issuer-k2"))

	if _, err := verifyMinted(t, c, raw, nonce); err == nil {
		t.Fatal("control: the retired key still verified although discovery was reachable and the TTL had elapsed")
	} else {
		t.Logf("control: with discovery reachable the retired key was refused after the TTL: %v", err)
	}
}

// TestZ14ProviderTTLIsDefeatedByAFailingRediscovery: the TTL alone is not an
// upper bound on how long a retired key verifies — the retain-on-failure branch
// is, and it has a ceiling now.
//
// oidcProvider used to keep the cached provider when a re-discovery failed
// (idp/idp.go, "Keep serving the cached provider") with no age bound, and a
// provider owns its key set — go-oidc only refetches the JWKS when a kid misses
// the cache (jwks.go:163-179) and its cache never expires. So while the issuer's
// discovery endpoint was failing, the *last successful* document and every key it
// ever published kept working indefinitely: the TTL had no effect at all.
//
// retainOnDiscoveryFailure now serves the cached provider only while it is
// younger than providerStaleCeiling*providerTTL and refuses it past that, naming
// the age. With a 1ns TTL the ceiling is 2ns, so every attempt below is refused
// as soon as discovery fails; restoring discovery then rebuilds the provider and
// drops the retired key.
func TestZ14ProviderTTLIsDefeatedByAFailingRediscovery(t *testing.T) {
	f := newFakeOP(t)
	c := probeRegistry(t, f, time.Nanosecond)
	nonce := c.NewNonce()

	retired := f.key
	raw := retired.sign(t, idClaims(f.issuer(), "attacker-with-the-retired-key", probeAudience, nonce))
	if _, err := verifyMinted(t, c, raw, nonce); err != nil {
		t.Fatalf("setup: the published key was rejected: %v", err)
	}

	// The upstream retires the key, and its discovery endpoint is unavailable at
	// the same time (either order is realistic; the outage is what matters).
	f.rotate(newProbeKey(t, "issuer-k2"))
	f.setDiscoveryStatus(http.StatusInternalServerError)

	// Well past the TTL: several fresh calls, so this is not a one-off race.
	var accepted int
	for i := 0; i < 3; i++ {
		ident, err := verifyMinted(t, c, raw, nonce)
		if err == nil {
			accepted++
			t.Logf("attempt %d: ACCEPTED sub=%q with the retired key", i+1, ident.Subject)
		} else {
			t.Logf("attempt %d: refused: %v", i+1, err)
		}
	}

	// Control: restore discovery. The cached provider is rebuilt, the retired key
	// is gone, and the same token must now be refused — which is what shows the
	// acceptance above is the retain-on-failure branch and not something else.
	f.setDiscoveryStatus(http.StatusOK)
	if _, err := verifyMinted(t, c, raw, nonce); err == nil {
		t.Errorf("a retired key still verified even after discovery was reachable again")
	} else {
		t.Logf("after discovery recovered, the retired key was refused: %v", err)
	}

	if accepted > 0 {
		discovery, _ := f.hits()
		t.Errorf("the provider cache TTL (time.Nanosecond) elapsed and 2*TTL is 2ns, but a token signed by a key the upstream no longer publishes was accepted %d/3 times while discovery was failing (discovery requests so far: %d).\n"+
			"retainOnDiscoveryFailure (idp/idp.go) must serve the cached provider only while it is younger than providerStaleCeiling*providerTTL; past that the never-expiring go-oidc key set (oidc.go:154-165, jwks.go:163-179) keeps a retired key alive for the whole outage.",
			accepted, discovery)
	}
}
