//go:build audit5

package protocol

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/oidchttp"
)

// PROBE 26 — what the opaque access token is, and what it is not.
//
// The threat model calls the token "AES-GCM 加密的 tokenID:subject"
// (docs/threat-model.md §6.0.1). What the library actually mints is a JWE
// (A256GCMKW + A256GCM, pkg/op/crypto.go:51-84, pkg/op/token.go:137-139), i.e. a
// five-part compact serialization whose HEADER is cleartext. This probe pins what
// that means for an attacker who holds a token: the header reveals nothing beyond
// the algorithm, the key id and the per-message IV; the body is authenticated, so
// tampering and truncation are indistinguishable refusals; a token encrypted under
// a key this handler does not hold is refused; and encryption is randomized, so
// two tokens for the same subject are not equal — there is no equality oracle.
func TestProbeOpaqueAccessTokenShape(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	first := asTokens(t, e.codeFlow(t, []string{"account.id"}))
	second := asTokens(t, e.codeFlow(t, []string{"account.id"}))
	if first.AccessToken == "" || second.AccessToken == "" {
		t.Fatal("no tokens minted")
	}

	// Shape: five parts; the header is readable and carries no secret.
	parts := strings.Split(first.AccessToken, ".")
	if len(parts) != 5 {
		t.Fatalf("the access token is not a compact JWE (%d parts): %q", len(parts), first.AccessToken)
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(header, &hdr); err != nil {
		t.Fatal(err)
	}
	t.Logf("the cleartext JWE header is %s", header)
	for _, leak := range []string{"usr_probe", "usr_" + "probe"} {
		if strings.Contains(string(header), leak) {
			t.Errorf("the JWE header leaks the subject: %s", header)
		}
	}
	if hdr["alg"] != "A256GCMKW" || hdr["enc"] != "A256GCM" {
		t.Errorf("unexpected JWE header: %v", hdr)
	}

	// Randomized, and the plaintext really is `tokenID:subject` (pkg/op/token.go:137-139
	// CreateBearerToken). The crypto object below is built with the very same 32-byte
	// key and key id the fixture handed to oidchttp.Config, which is what makes both
	// claims checkable from outside.
	crypto := op.NewAES256GCMCrypto(e.cryptoKey, "probe")
	c1, err := crypto.Encrypt("same-id:same-subject")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := crypto.Encrypt("same-id:same-subject")
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 {
		t.Errorf("token encryption is deterministic: the same plaintext produced the same ciphertext")
	}
	plain, err := crypto.Decrypt(first.AccessToken)
	if err != nil {
		t.Fatalf("the minted token does not decrypt under oidchttp.Config's own key: %v", err)
	}
	if !strings.HasSuffix(plain, ":usr_probe") {
		t.Errorf("the token plaintext is %q, want `<tokenID>:usr_probe`", plain)
	}
	t.Logf("the token decrypts with the config key alone, to %q", plain)

	active := func(t *testing.T, bearer string) bool {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = bodyOf(t, resp)
		if resp.StatusCode == http.StatusOK {
			return true
		}
		info, err := e.handler.Introspect(t.Context(), bearer)
		if err != nil {
			t.Fatal(err)
		}
		return info.Active
	}

	if !active(t, first.AccessToken) {
		t.Fatal("control failed: a freshly minted token is not active")
	}

	// Tampering: flip one character of the ciphertext segment.
	tampered := []byte(first.AccessToken)
	if tampered[len(tampered)-3] == 'A' {
		tampered[len(tampered)-3] = 'B'
	} else {
		tampered[len(tampered)-3] = 'A'
	}
	if active(t, string(tampered)) {
		t.Errorf("a tampered ciphertext was accepted")
	}
	// Truncation, both in the middle and at the end.
	for _, cut := range []string{
		first.AccessToken[:len(first.AccessToken)-5],
		strings.Join(parts[:4], "."),
		parts[0] + ".." + parts[2] + "." + parts[3] + "." + parts[4],
	} {
		if active(t, cut) {
			t.Errorf("a truncated token was accepted: %q", cut)
		}
	}
	// Alg confusion: claim a different key-management algorithm in the header.
	confused := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"dir","enc":"A256GCM"}`)) +
		"." + strings.Join(parts[1:], ".")
	if active(t, confused) {
		t.Errorf("a token with a rewritten alg header was accepted")
	}

	// Key mismatch: a token minted by a deployment with a DIFFERENT 32-byte token
	// key must not be accepted here.
	var otherKey [32]byte
	copy(otherKey[:], []byte("other-0123456789abcdef0123456789a"))
	other := newEnv(t, envOptions{issuer: "https://issuer.probe", cryptoKey: &otherKey})
	otherTokens := asTokens(t, other.codeFlow(t, []string{"account.id"}))
	if active(t, otherTokens.AccessToken) {
		t.Errorf("a token encrypted under another key was accepted")
	}

	// Rotation: the documented contract is that the CURRENT key encrypts and any
	// RETIRED key still decrypts (threat-model §6.0.1). A handler whose current key
	// is new but which retires the old one must therefore keep serving the old
	// token; a handler that did not retire it must not.
	var next [32]byte
	copy(next[:], []byte("next-0123456789abcdef0123456789ab"))
	rotated := other.withCrypto(t, next, "probe-next", nil)
	oldKey := other.cryptoKey
	retiring := other.withCrypto(t, next, "probe-next", []oidchttp.RetiredTokenKey{{ID: "probe", Key: oldKey}})

	if activeOn(t, retiring, otherTokens.AccessToken) != true {
		t.Errorf("a retired token key no longer decrypts tokens issued before the rotation")
	}
	if activeOn(t, rotated, otherTokens.AccessToken) {
		t.Errorf("a handler with no retired key accepted a token from the previous key")
	}
	t.Logf("rotation: current=%s+retired accepted the old token; current-only refused it", "probe-next")
}

// activeOn asks a DIFFERENT handler (same store, different crypto) whether the
// bearer is usable, through both readers it has.
func activeOn(t *testing.T, e env, bearer string) bool {
	t.Helper()
	info, err := e.handler.Introspect(t.Context(), bearer)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		return true
	}
	return false
}

// PROBE 27 — `/oauth/userinfo` never asks whether the access token is still live.
//
// pkg/op/userinfo.go hands GetUserinfoFromToken the tokenID AND the subject it
// decrypted from the bearer, and this project's implementation
// (internal/store/memory/oidc.go:691-694, internal/store/postgres/oidc.go:583-586)
// copies the subject and ignores the tokenID — no row lookup, no expiry check, no
// revocation check. The store DOES know the token is dead (the business plane's
// Introspect reads the row's expiry), so the two readers of the same token
// disagree: one says active, the other refuses.
//
// Consequence: an access token that has expired, or that was explicitly revoked
// through /oauth/revoke, still returns `sub` from userinfo for as long as somebody
// holds the bearer string. The token is a bearer credential with an effective
// lifetime of "as long as its ciphertext is kept".
func TestProbeUserinfoIgnoresExpiryAndRevocation(t *testing.T) {
	clock := newTestClock()
	e := newEnv(t, envOptions{issuer: "https://issuer.probe", now: clock.Now, clock: clock})

	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id"}))
	if tokens.AccessToken == "" {
		t.Fatal("no access token")
	}

	userinfo := func(bearer string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, decodeJSON(t, bodyOf(t, resp))
	}
	businessPlane := func(bearer string) bool {
		t.Helper()
		info, err := e.handler.Introspect(t.Context(), bearer)
		if err != nil {
			t.Fatal(err)
		}
		return info.Active
	}

	// Control: while it is live, both readers agree.
	status, claims := userinfo(tokens.AccessToken)
	if status != http.StatusOK || claims["sub"] != "usr_probe" {
		t.Fatalf("control failed: %d %v", status, claims)
	}
	if !businessPlane(tokens.AccessToken) {
		t.Fatal("control failed: the business plane does not see the live token")
	}

	// Expiry. The store's access TTL is an hour (internal/store/memory/oidc.go:306).
	clock.Advance(2 * time.Hour)
	if businessPlane(tokens.AccessToken) {
		t.Fatalf("the business plane still accepts an expired token, so this probe proves nothing")
	}
	status, claims = userinfo(tokens.AccessToken)
	if status == http.StatusOK {
		t.Errorf("userinfo accepted an EXPIRED access token: %d %v", status, claims)
	}

	// Revocation. Mint a fresh one (the old is expired) and revoke it explicitly,
	// the way a user revoking a compromised client would.
	fresh := asTokens(t, e.codeFlow(t, []string{"openid", "account.id"}))
	if !businessPlane(fresh.AccessToken) {
		t.Fatal("control failed: the fresh token is not live")
	}
	resp, raw := e.postForm(t, "/oauth/revoke", url.Values{"token": {fresh.AccessToken}}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revocation answered %d: %s", resp.StatusCode, raw)
	}
	if businessPlane(fresh.AccessToken) {
		t.Fatalf("the business plane still accepts a revoked token, so this probe proves nothing")
	}
	status, claims = userinfo(fresh.AccessToken)
	if status == http.StatusOK {
		t.Errorf("userinfo accepted a REVOKED access token: %d %v", status, claims)
	} else {
		t.Logf("userinfo refused the revoked token with %d", status)
	}
}
