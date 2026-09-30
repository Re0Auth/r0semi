//go:build audit5

// Package kit probes the OAuth/upstreamkit surface adversarially.
//
// READ-ONLY audit probe: this package only adds files. It is intentionally
// separate from internal/zzprobe/protocol/ and internal/zzprobe/protocol/rp/.
//
// Run: go test ./internal/zzprobe/protocol/kit/ -v
package kit

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/upstreamkit/conformance"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const (
	accountScope = oauth.Scope("account.read")
	profileScope = oauth.Scope("phigros.profile.read")
	writeScope   = oauth.Scope("phigros.score.write")

	confClientID  = "conf"
	confSecret    = "s3cr3t-confidential"
	pubClientID   = "pub"
	narrowID      = "narrow"
	narrowSecret  = "narrow-secret"
	confRedirect  = "https://conf.example/cb"
	pubRedirect   = "https://pub.example/cb"
	narrowRedir   = "https://narrow.example/cb"
	subject       = "usr_probe_subject"
	probeVerifier = "probe-verifier-probe-verifier-probe"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newRegistry(t *testing.T) *oauth.Registry {
	t.Helper()
	reg, err := oauth.NewRegistry(
		oauth.Descriptor{Scope: accountScope, Title: "account"},
		oauth.Descriptor{Scope: profileScope, Title: "profile"},
		oauth.Descriptor{Scope: writeScope, Title: "write"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func mkClient(t *testing.T, id string, typ oauth.ClientType, secret, redirect string, scopes ...oauth.Scope) oauth.Client {
	t.Helper()
	c, err := oauth.NewClient(id, id, typ, secret, []string{redirect}, scopes)
	if err != nil {
		t.Fatalf("NewClient(%s): %v", id, err)
	}
	return c
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// newAS builds the hand-written engine with a confidential client, a public
// client that only carries account.read, and a narrow confidential client.
func newAS(t *testing.T) (oauth.Service, *oauth.MemoryClientRegistry, *oauth.MemoryStore, *fakeClock) {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	for _, c := range []oauth.Client{
		mkClient(t, confClientID, oauth.ClientConfidential, confSecret, confRedirect, accountScope, profileScope, writeScope),
		mkClient(t, pubClientID, oauth.ClientPublic, "", pubRedirect, accountScope),
		mkClient(t, narrowID, oauth.ClientConfidential, narrowSecret, narrowRedir, accountScope),
	} {
		if err := clients.Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	tokens := oauth.NewMemoryStore()
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	svc, err := oauth.NewService(clients, tokens, audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://auth.probe.test",
		Scopes: newRegistry(t),
		Now:    clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, clients, tokens, clock
}

func oauthCode(t *testing.T, err error) string {
	t.Helper()
	var oe *oauth.Error
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v, want *oauth.Error", err)
	}
	return oe.Code
}

// issueCode mints an authorization code for client id.
func issueCode(t *testing.T, svc oauth.Service, clientID, redirect, verifier string, scopes ...oauth.Scope) string {
	t.Helper()
	resp, err := svc.Authorize(context.Background(), oauth.AuthorizationRequest{
		ClientID: clientID, RedirectURI: redirect, Subject: subject,
		Scopes: scopes, CodeChallenge: challengeFor(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.Code == "" {
		t.Fatal("Authorize returned no code")
	}
	return resp.Code
}

// mint issues a token pair for one client with the given scopes.
func mint(t *testing.T, svc oauth.Service, clientID, secret, redirect string, scopes ...oauth.Scope) oauth.TokenResponse {
	t.Helper()
	code := issueCode(t, svc, clientID, redirect, probeVerifier, scopes...)
	tok, err := svc.Exchange(context.Background(), oauth.CodeExchangeRequest{
		ClientID: clientID, ClientSecret: secret, Code: code,
		RedirectURI: redirect, CodeVerifier: probeVerifier,
	})
	if err != nil {
		t.Fatalf("mint(%s): %v", clientID, err)
	}
	return tok
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// A. client authentication
// ---------------------------------------------------------------------------

// Control: the happy path works, so every later "rejected" assertion has been
// shown to be reachable.
func TestA0_ControlConfidentialExchangeSucceeds(t *testing.T) {
	svc, _, _, _ := newAS(t)
	code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)
	tok, err := svc.Exchange(context.Background(), oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: confSecret, Code: code,
		RedirectURI: confRedirect, CodeVerifier: probeVerifier,
	})
	if err != nil {
		t.Fatalf("control exchange failed: %v", err)
	}
	t.Logf("control OK: access=%s... refresh=%s... scope=%q", tok.AccessToken[:8], tok.RefreshToken[:8], tok.Scope)
}

func TestA1_EmptyOrWrongSecretRefused(t *testing.T) {
	svc, _, _, _ := newAS(t)
	code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)
	_, err := svc.Exchange(context.Background(), oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: "", Code: code,
		RedirectURI: confRedirect, CodeVerifier: probeVerifier,
	})
	t.Logf("empty secret for a confidential client: code=%s err=%v", oauthCode(t, err), err)
	if oauthCode(t, err) != "invalid_client" {
		t.Errorf("empty secret accepted")
	}

	code2 := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)
	_, err = svc.Exchange(context.Background(), oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: "wrong", Code: code2,
		RedirectURI: confRedirect, CodeVerifier: probeVerifier,
	})
	t.Logf("wrong secret: code=%s", oauthCode(t, err))
	if oauthCode(t, err) != "invalid_client" {
		t.Errorf("wrong secret accepted")
	}
}

// KIT finding: HTTP Basic and the form body can declare two different client
// identities at once, and neither is cross-checked.
func TestA2_FormAndBasicMayDisagree(t *testing.T) {
	base, svc, _, _ := newKit(t, true)
	code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)

	// Basic identifies conf; the form claims pub and hands over the WRONG
	// secret. The public client has no secret hash, so nothing is checked.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {confRedirect},
		"code_verifier": {probeVerifier},
		"client_id":     {pubClientID},
		"client_secret": {"not-the-secret"},
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(confClientID, confSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("Basic=conf + form=pub(wrong secret) -> %d %s", resp.StatusCode, strings.TrimSpace(string(body)))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vacuity: the request never reached the success path (%d)", resp.StatusCode)
	}
	t.Errorf("two client identities in one request were accepted; RFC 6749 §2.3 permits exactly one")
}

// A public client may present any client_secret and it is ignored rather than a
// 4xx.
func TestA3_PublicClientSecretIgnored(t *testing.T) {
	base, svc, _, _ := newKit(t, true)
	code := issueCode(t, svc, pubClientID, pubRedirect, probeVerifier, accountScope)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {pubRedirect},
		"code_verifier": {probeVerifier},
		"client_id":     {pubClientID},
		"client_secret": {"anything-at-all"},
	}
	resp, err := http.PostForm(base+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("public client with a bogus secret -> %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode == http.StatusOK {
		t.Logf("NOTE: not reported as a finding on its own -- the id is public, so the secret carries no " +
			"authority either way. It is logged because the surrounding identity handling (KIT-1) is what " +
			"makes an unused secret field meaningful.")
	}
}

// A4 (FIXED) — suspension is enforced on the way OUT too: a token issued to a
// client that is suspended afterwards introspects as inactive, because
// oauth.Introspect now consults the client registry (it was the one protocol
// entrance that did not).
func TestA4_SuspendedClientTokensGoInactive(t *testing.T) {
	svc, clients, _, _ := newAS(t)
	code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope, profileScope)
	tok, err := svc.Exchange(context.Background(), oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: confSecret, Code: code,
		RedirectURI: confRedirect, CodeVerifier: probeVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := clients.SetStatus(context.Background(), confClientID, oauth.ClientSuspended); err != nil {
		t.Fatal(err)
	}

	// Control for the suspension itself: the protocol entrances do refuse it.
	if err := svc.AuthenticateClient(context.Background(), confClientID, confSecret); err == nil {
		t.Error("vacuity: suspension did not take effect at AuthenticateClient")
	} else {
		t.Logf("control: AuthenticateClient after suspension = %v", err)
	}
	_, err = svc.Refresh(context.Background(), oauth.RefreshRequest{
		ClientID: confClientID, ClientSecret: confSecret, RefreshToken: tok.RefreshToken,
	})
	t.Logf("control: Refresh after suspension = %v", err)

	info, err := svc.Introspect(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Introspect of a suspended client's access token: active=%v subject=%s client=%s scopes=%v",
		info.Active, info.Subject, info.ClientID, info.Scopes)
	if info.Active {
		t.Errorf("an access token issued to a client suspended afterwards is still Active "+
			"(subject=%s scopes=%v), so suspension does not stop access", info.Subject, info.Scopes)
	}
}

// A5 (FIXED) — deleting the registration entirely is the same story: the token
// goes inactive, because a deleted client is reported as unknown by every
// protocol entrance (oauth/client.go ClientStatus) and now by Introspect as well.
func TestA5_DeletedClientTokensGoInactive(t *testing.T) {
	svc, clients, _, _ := newAS(t)
	code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)
	tok, err := svc.Exchange(context.Background(), oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: confSecret, Code: code,
		RedirectURI: confRedirect, CodeVerifier: probeVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Delete(context.Background(), confClientID); err != nil {
		t.Fatal(err)
	}
	info, err := svc.Introspect(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Introspect after the client row was deleted: active=%v subject=%s", info.Active, info.Subject)
	if info.Active {
		t.Errorf("a deleted client's access token is still Active")
	}
}

// Deleting a client does not remove its tokens, so the rows keep the id.
func TestA6_DeleteClientLeavesTokenRows(t *testing.T) {
	svc, clients, tokens, _ := newAS(t)
	code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)
	if _, err := svc.Exchange(context.Background(), oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: confSecret, Code: code,
		RedirectURI: confRedirect, CodeVerifier: probeVerifier,
	}); err != nil {
		t.Fatal(err)
	}
	if err := clients.Delete(context.Background(), confClientID); err != nil {
		t.Fatal(err)
	}
	rows, err := tokens.ListBySubject(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token rows for the subject after ClientAdmin.Delete: %d", len(rows))
	if len(rows) != 0 {
		t.Errorf("ClientAdmin.Delete left %d token rows behind; the client is gone but its grants are not", len(rows))
	}
}

// ---------------------------------------------------------------------------
// B. redirect URI matching
// ---------------------------------------------------------------------------

func TestB1_RedirectURIMatchingIsExact(t *testing.T) {
	svc, _, _, _ := newAS(t)
	ctx := context.Background()

	base := oauth.AuthorizationRequest{
		ClientID: confClientID, RedirectURI: confRedirect, Subject: subject,
		Scopes:        []oauth.Scope{accountScope},
		CodeChallenge: challengeFor(probeVerifier), CodeChallengeMethod: "S256",
	}

	// Control first: the registered URI is accepted.
	if _, err := svc.DescribeAuthorization(ctx, base); err != nil {
		t.Fatalf("vacuity: the registered redirect URI was refused: %v", err)
	}

	variants := map[string]string{
		"appended query":      confRedirect + "?x=1",
		"appended fragment":   confRedirect + "#frag",
		"trailing slash":      confRedirect + "/",
		"dotdot":              "https://conf.example/cb/../evil",
		"encoded dotdot":      "https://conf.example/cb/%2e%2e/evil",
		"userinfo":            "https://conf.example@evil.example/cb",
		"uppercase host":      "https://CONF.EXAMPLE/cb",
		"uppercase scheme":    "HTTPS://conf.example/cb",
		"default https port":  "https://conf.example:443/cb",
		"percent-encoded pat": "https://conf.example/%63b",
		"double slash":        "https://conf.example//cb",
		"empty":               "",
	}
	for name, uri := range variants {
		req := base
		req.RedirectURI = uri
		_, err := svc.DescribeAuthorization(ctx, req)
		if err == nil {
			t.Errorf("redirect URI variant %q (%s) was accepted", name, uri)
		} else {
			t.Logf("redirect URI variant %-20s rejected: %v", name, err)
		}
	}
}

func TestB2_RegistrationRefusesDangerousRedirects(t *testing.T) {
	for _, uri := range []string{
		"javascript:alert(1)", "data:text/html,x", "file:///etc/passwd",
		"http://example.com/cb", "https://u:p@example.com/cb",
		"https://example.com/cb#f", "//example.com/cb", "notaurl", "app:cb",
	} {
		if _, err := oauth.NewClient("x", "x", oauth.ClientPublic, "", []string{uri}, nil); err == nil {
			t.Errorf("NewClient accepted redirect %q", uri)
		} else {
			t.Logf("NewClient refused %-30q: %v", uri, err)
		}
	}
	// Control: the loopback http form RFC 8252 allows still works.
	if _, err := oauth.NewClient("x", "x", oauth.ClientPublic, "", []string{"http://127.0.0.1:8080/cb"}, nil); err != nil {
		t.Errorf("vacuity: NewClient refused a legal loopback redirect: %v", err)
	}
}

// RestoreClient deliberately skips validation, so a registry row can carry a
// javascript: redirect and the authorize path honours it.
func TestB3_RestoreClientSkipsRedirectValidation(t *testing.T) {
	svc, clients, _, _ := newAS(t)
	bad, err := oauth.RestoreClient("restored", "restored", oauth.ClientPublic, nil,
		[]string{"javascript:alert(document.cookie)"}, []oauth.Scope{accountScope}, time.Now())
	if err != nil {
		t.Fatalf("RestoreClient refused the row: %v", err)
	}
	if err := clients.Create(context.Background(), bad); err != nil {
		t.Fatal(err)
	}
	details, err := svc.DescribeAuthorization(context.Background(), oauth.AuthorizationRequest{
		ClientID: "restored", RedirectURI: "javascript:alert(document.cookie)", Subject: subject,
		Scopes:        []oauth.Scope{accountScope},
		CodeChallenge: challengeFor(probeVerifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Logf("DescribeAuthorization refused the restored javascript: redirect: %v", err)
		return
	}
	t.Logf("DescribeAuthorization ACCEPTED client %s whose registered redirect is %v",
		details.Client.ID, details.Client.RedirectURIs)
	t.Errorf("a restored registry row can carry a javascript: redirect URI and the authorize path honours it")
}

// ---------------------------------------------------------------------------
// C. authorization code lifecycle
// ---------------------------------------------------------------------------

// A failed exchange must NOT spend the code. The exchange reads the record
// (GetCode), judges the client/redirect_uri/PKCE bindings, and only then claims
// it atomically (ConsumeCode), so an attacker who merely knows the code cannot
// deny it to the client that earned it. This is the KIT-4 guard.
func TestC1_FailedExchangeDoesNotConsumeTheCode(t *testing.T) {
	svc, _, _, _ := newAS(t)
	ctx := context.Background()
	code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)

	// Attacker: knows the code, has no verifier. Refused, and it must cost the
	// code nothing.
	_, err := svc.Exchange(ctx, oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: confSecret, Code: code,
		RedirectURI: confRedirect, CodeVerifier: "wrong-verifier",
	})
	if err == nil {
		t.Fatal("the attacker's exchange with a bad verifier succeeded")
	}
	t.Logf("attacker exchange with a bad verifier: %v", err)

	// Legitimate client, correct verifier, immediately after: the code is intact.
	if _, err := svc.Exchange(ctx, oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: confSecret, Code: code,
		RedirectURI: confRedirect, CodeVerifier: probeVerifier,
	}); err != nil {
		t.Errorf("a failed exchange consumed the authorization code (%v), so knowing a code is enough to deny the legitimate client its tokens", err)
	}
}

// A wrong client id / redirect_uri / verifier is refused, and each refusal leaves
// the code redeemable by the fully correct request. The error stays the same
// invalid_grant the endpoint has always written, so clients see no change on the
// failure paths. Before KIT-4 was fixed this documented the opposite: every
// failure burned the code.
func TestC2_BindingFailuresDoNotBurnTheCode(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		req  oauth.CodeExchangeRequest
	}{
		{"wrong client", oauth.CodeExchangeRequest{ClientID: pubClientID, RedirectURI: confRedirect, CodeVerifier: probeVerifier}},
		{"wrong redirect", oauth.CodeExchangeRequest{ClientID: confClientID, ClientSecret: confSecret, RedirectURI: pubRedirect, CodeVerifier: probeVerifier}},
		{"wrong verifier", oauth.CodeExchangeRequest{ClientID: confClientID, ClientSecret: confSecret, RedirectURI: confRedirect, CodeVerifier: "nope"}},
		{"missing redirect", oauth.CodeExchangeRequest{ClientID: confClientID, ClientSecret: confSecret, CodeVerifier: probeVerifier}},
	}
	for _, tc := range cases {
		svc, _, _, _ := newAS(t)
		code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)
		req := tc.req
		req.Code = code
		_, err := svc.Exchange(ctx, req)
		if err == nil {
			t.Errorf("%s: the exchange SUCCEEDED (vacuity or a real hole)", tc.name)
			continue
		}
		// Second attempt with the fully correct request: it must redeem, because
		// the refused attempt spent nothing.
		_, err2 := svc.Exchange(ctx, oauth.CodeExchangeRequest{
			ClientID: confClientID, ClientSecret: confSecret, Code: code,
			RedirectURI: confRedirect, CodeVerifier: probeVerifier,
		})
		t.Logf("%-16s -> %v ; then correct exchange -> %v", tc.name, err, err2)
		if err2 != nil {
			t.Errorf("%s: the correct exchange was refused afterwards (%v): the failed attempt burned the code", tc.name, err2)
		}
	}
}

func TestC3_PKCEMethodEnforcement(t *testing.T) {
	svc, _, _, _ := newAS(t)
	ctx := context.Background()

	if _, err := svc.DescribeAuthorization(ctx, oauth.AuthorizationRequest{
		ClientID: confClientID, RedirectURI: confRedirect, Subject: subject,
		Scopes: []oauth.Scope{accountScope}, CodeChallenge: "whatever", CodeChallengeMethod: "plain",
	}); err == nil {
		t.Error("code_challenge_method=plain was accepted at the authorize endpoint")
	} else {
		t.Logf("plain at authorize: %v", err)
	}

	// Control: an S256 code exchanges.
	code := issueCode(t, svc, confClientID, confRedirect, probeVerifier, accountScope)
	if _, err := svc.Exchange(ctx, oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: confSecret, Code: code,
		RedirectURI: confRedirect, CodeVerifier: probeVerifier,
	}); err != nil {
		t.Fatalf("control: the S256 code did not exchange: %v", err)
	}

	// A verifier that is the challenge itself (the `plain` attack) must fail.
	svc2, _, _, _ := newAS(t)
	ch := challengeFor(probeVerifier)
	resp, err := svc2.Authorize(ctx, oauth.AuthorizationRequest{
		ClientID: confClientID, RedirectURI: confRedirect, Subject: subject,
		Scopes: []oauth.Scope{accountScope}, CodeChallenge: ch, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc2.Exchange(ctx, oauth.CodeExchangeRequest{
		ClientID: confClientID, ClientSecret: confSecret, Code: resp.Code,
		RedirectURI: confRedirect, CodeVerifier: ch, // the plain-style verifier
	})
	t.Logf("verifier == challenge (the plain attack): %v", err)
	if err == nil {
		t.Error("a challenge used as its own verifier was accepted")
	}
}

// Authorize accepts any non-empty code_challenge with method S256, including one
// that cannot be a SHA-256 digest in the required encoding. The exchange then
// fails, so an honest client's mistake costs it the login — though since KIT-4
// the code itself is no longer burned by the refusal.
func TestC4_PKCEChallengeShapeIsNotValidated(t *testing.T) {
	ctx := context.Background()
	full := challengeFor(probeVerifier)
	sum := sha256.Sum256([]byte(probeVerifier))
	padded := base64.URLEncoding.EncodeToString(sum[:]) // with '=' padding
	accepted := map[string]bool{}

	for _, tc := range []struct {
		name string
		ch   string
	}{
		{"std/url padded", padded},
		{"truncated", full[:len(full)-1]},
		{"uppercase", strings.ToUpper(full)},
		{"one char", "A"},
		{"empty", ""},
	} {
		svc, _, _, _ := newAS(t)
		_, derr := svc.DescribeAuthorization(ctx, oauth.AuthorizationRequest{
			ClientID: confClientID, RedirectURI: confRedirect, Subject: subject,
			Scopes: []oauth.Scope{accountScope}, CodeChallenge: tc.ch, CodeChallengeMethod: "S256",
		})
		if derr != nil {
			t.Logf("%-16s rejected at authorize: %v", tc.name, derr)
			continue
		}
		accepted[tc.name] = true
		t.Logf("%-16s ACCEPTED at authorize (describe only checks non-empty + S256)", tc.name)
		resp, aerr := svc.Authorize(ctx, oauth.AuthorizationRequest{
			ClientID: confClientID, RedirectURI: confRedirect, Subject: subject,
			Scopes: []oauth.Scope{accountScope}, CodeChallenge: tc.ch, CodeChallengeMethod: "S256",
		})
		if aerr != nil {
			t.Fatalf("vacuity: authorize disagreed with describe: %v", aerr)
		}
		_, xerr := svc.Exchange(ctx, oauth.CodeExchangeRequest{
			ClientID: confClientID, ClientSecret: confSecret, Code: resp.Code,
			RedirectURI: confRedirect, CodeVerifier: probeVerifier,
		})
		t.Logf("%-16s -> the code it minted is unredeemable: %v", tc.name, xerr)
		if xerr == nil {
			t.Errorf("%s: a malformed code_challenge still produced tokens", tc.name)
		}
	}
	if accepted["one char"] {
		t.Errorf("a one-character code_challenge was accepted at authorize")
	}
}

// ---------------------------------------------------------------------------
// D. token issuance and scope
// ---------------------------------------------------------------------------

func TestD1_ScopeSmugglingAtTheTokenEndpoint(t *testing.T) {
	base, svc, _, _ := newKit(t, true)

	cases := []struct {
		name string
		body url.Values
	}{
		{"plain widen", url.Values{"scope": {string(profileScope)}}},
		{"comma separated", url.Values{"scope": {"account.read," + string(profileScope)}}},
		{"duplicate param", url.Values{"scope": {string(accountScope), string(profileScope)}}},
		{"array syntax", url.Values{"scope[]": {string(profileScope)}}},
		{"uppercase", url.Values{"scope": {strings.ToUpper(string(profileScope))}}},
		{"empty", url.Values{"scope": {""}}},
		{"newline separated", url.Values{"scope": {"account.read\n" + string(profileScope)}}},
		{"tab separated", url.Values{"scope": {"account.read\t" + string(profileScope)}}},
		{"comma suffix", url.Values{"scope": {string(accountScope) + ","}}},
	}
	for _, tc := range cases {
		tok := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)
		body := tc.body
		body.Set("grant_type", "refresh_token")
		body.Set("refresh_token", tok.RefreshToken)
		body.Set("client_id", confClientID)
		body.Set("client_secret", confSecret)
		resp, err := http.PostForm(base+"/oauth/token", body)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("%-20s -> %d %s", tc.name, resp.StatusCode, truncate(string(raw), 140))
		if resp.StatusCode == http.StatusOK && strings.Contains(string(raw), string(profileScope)) {
			t.Errorf("scope smuggling %q widened the refresh to %s", tc.name, profileScope)
		}
	}

	// Control: the refresh path itself works.
	tok := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)
	resp, err := http.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken},
		"client_id": {confClientID}, "client_secret": {confSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("control refresh -> %d %s", resp.StatusCode, truncate(string(raw), 140))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vacuity: the control refresh did not succeed")
	}

	// A scope given in the QUERY rather than the body is not read at all.
	tok2 := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)
	u, _ := url.Parse(base + "/oauth/token")
	u.RawQuery = url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok2.RefreshToken},
		"client_id": {confClientID}, "client_secret": {confSecret},
		"scope": {string(profileScope)},
	}.Encode()
	resp, err = http.Post(u.String(), "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("scope in the query string -> %d %s", resp.StatusCode, truncate(string(raw2), 140))
	if resp.StatusCode == http.StatusOK && strings.Contains(string(raw2), string(profileScope)) {
		t.Errorf("a scope in the query string widened the refresh")
	}
}

// Omitted vs explicitly empty scope: both keep the granted set.
func TestD2_EmptyScopeRefreshKeepsTheGrant(t *testing.T) {
	svc, _, _, _ := newAS(t)
	ctx := context.Background()

	pair := mint(t, svc, confClientID, confSecret, confRedirect, accountScope, profileScope)
	got, err := svc.Refresh(ctx, oauth.RefreshRequest{
		ClientID: confClientID, ClientSecret: confSecret, RefreshToken: pair.RefreshToken})
	if err != nil {
		t.Fatalf("refresh with omitted scopes: %v", err)
	}
	t.Logf("refresh scopes=omitted -> scope=%q", got.Scope)
	if got.Scope == "" {
		t.Errorf("refresh with omitted scopes produced an EMPTY scope")
	}

	pair = mint(t, svc, confClientID, confSecret, confRedirect, accountScope, profileScope)
	got, err = svc.Refresh(ctx, oauth.RefreshRequest{
		ClientID: confClientID, ClientSecret: confSecret, RefreshToken: pair.RefreshToken,
		Scopes: []oauth.Scope{}})
	if err != nil {
		t.Fatalf("refresh with an explicit empty slice: %v", err)
	}
	t.Logf("refresh scopes=[] -> scope=%q", got.Scope)
	if got.Scope == "" {
		t.Errorf("refresh with an explicit empty slice produced an EMPTY scope")
	}

	// A slice holding one empty string must be refused, not silently kept.
	pair = mint(t, svc, confClientID, confSecret, confRedirect, accountScope, profileScope)
	_, err = svc.Refresh(ctx, oauth.RefreshRequest{
		ClientID: confClientID, ClientSecret: confSecret, RefreshToken: pair.RefreshToken,
		Scopes: []oauth.Scope{""}})
	t.Logf("refresh scopes=[\"\"] -> %v", err)
	if err == nil {
		t.Errorf("a refresh asking for the scope \"\" was accepted")
	}
}

// A client asking to authorize a scope it is not registered for is refused, and
// so is a scope outside the catalogue -- while the control request succeeds.
func TestD3_UnregisteredScopeRefused(t *testing.T) {
	svc, _, _, _ := newAS(t)
	ctx := context.Background()
	controlOK := false
	for _, req := range []oauth.AuthorizationRequest{
		{ClientID: narrowID, RedirectURI: narrowRedir, Subject: subject, Scopes: []oauth.Scope{accountScope}, CodeChallenge: challengeFor(probeVerifier), CodeChallengeMethod: "S256"},
		{ClientID: narrowID, RedirectURI: narrowRedir, Subject: subject, Scopes: []oauth.Scope{profileScope}, CodeChallenge: challengeFor(probeVerifier), CodeChallengeMethod: "S256"},
		{ClientID: narrowID, RedirectURI: narrowRedir, Subject: subject, Scopes: []oauth.Scope{"not.in.catalogue"}, CodeChallenge: challengeFor(probeVerifier), CodeChallengeMethod: "S256"},
		{ClientID: narrowID, RedirectURI: narrowRedir, Subject: subject, Scopes: []oauth.Scope{accountScope, profileScope}, CodeChallenge: challengeFor(probeVerifier), CodeChallengeMethod: "S256"},
		{ClientID: narrowID, RedirectURI: narrowRedir, Subject: subject, Scopes: []oauth.Scope{"ACCOUNT.READ"}, CodeChallenge: challengeFor(probeVerifier), CodeChallengeMethod: "S256"},
	} {
		_, err := svc.Authorize(ctx, req)
		t.Logf("scopes=%v -> %v", req.Scopes, err)
		if err == nil && len(req.Scopes) == 1 && req.Scopes[0] == accountScope {
			controlOK = true
		}
		if err == nil && len(req.Scopes) > 1 {
			t.Errorf("the narrow client got a code for %v", req.Scopes)
		}
	}
	if !controlOK {
		t.Fatal("vacuity: the narrow client could not even get its registered scope")
	}
}

// The scope granted is the code's, never what the exchange request claims.
func TestD4_TokenScopeIsTheCodes(t *testing.T) {
	svc, _, _, _ := newAS(t)
	tok := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)
	t.Logf("code granted account.read only; token scope = %q", tok.Scope)
	if tok.Scope != string(accountScope) {
		t.Errorf("token scope = %q, want %q", tok.Scope, accountScope)
	}
}

// ---------------------------------------------------------------------------
// E. upstreamkit generated surface
// ---------------------------------------------------------------------------

type kitFixture struct {
	base          string
	svc           oauth.Service
	clients       *oauth.MemoryClientRegistry
	cascadeCalls  *[]upstreamkit.CascadeRevocationRequest
	consentCalls  *int
	accountCalls  *int
	resourceCalls *int
}

var (
	kitMu       sync.Mutex
	kitFixtures = map[string]*kitFixture{}
)

// newKit builds the generated data-source surface once per key and reuses it.
func newKit(t *testing.T, withCascade bool) (string, oauth.Service, *[]upstreamkit.CascadeRevocationRequest, *int) {
	t.Helper()
	key := fmt.Sprintf("cascade=%v", withCascade)

	kitMu.Lock()
	defer kitMu.Unlock()
	if f, ok := kitFixtures[key]; ok {
		return f.base, f.svc, f.cascadeCalls, f.consentCalls
	}

	svc, clients, _, _ := newAS(t)
	cascadeCalls := &[]upstreamkit.CascadeRevocationRequest{}
	consentCalls := new(int)
	accountCalls := new(int)
	resourceCalls := new(int)

	hooks := upstreamkit.Hooks{
		OAuth: svc,
		Scope: newRegistry(t),
		Consent: func(_ context.Context, _ upstreamkit.ConsentRequest) (upstreamkit.ConsentDecision, error) {
			*consentCalls++
			return upstreamkit.ConsentDecision{Subject: subject}, nil
		},
		Account: func(_ context.Context, s string) (upstreamkit.AccountInfo, error) {
			*accountCalls++
			return upstreamkit.AccountInfo{Subject: s}, nil
		},
		Resources: map[string]upstreamkit.ResourceHandler{
			"profile": func(_ context.Context, s string) (any, error) {
				*resourceCalls++
				return map[string]any{"subject": s}, nil
			},
		},
	}
	if withCascade {
		hooks.CascadeRevoke = func(_ context.Context, req upstreamkit.CascadeRevocationRequest) error {
			*cascadeCalls = append(*cascadeCalls, req)
			return nil
		}
	}

	kit, err := upstreamkit.New(upstreamkit.Config{
		Game: "phigros", Source: "probe", DisplayName: "Probe Source",
		Issuer: "https://probe.upstream.test", TokenClass: upstreamkit.TokenRevocable,
		Resources: []upstreamkit.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: string(profileScope)}},
	}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	// No t.Cleanup: the fixture is shared by every test in the binary, and a
	// first test's cleanup would close the listener underneath the rest.
	srv := httptest.NewServer(kit.Handler())

	f := &kitFixture{base: srv.URL, svc: svc, clients: clients, cascadeCalls: cascadeCalls,
		consentCalls: consentCalls, accountCalls: accountCalls, resourceCalls: resourceCalls}
	kitFixtures[key] = f
	return f.base, f.svc, f.cascadeCalls, f.consentCalls
}

// kitClientsFor returns the client registry of the fixture for this key, so a test
// that mutates a client's status does it in the registry the fixture's service
// actually consults. Selecting an arbitrary fixture (the previous kitClients) made
// the mutation miss whenever more than one fixture existed.
func kitClientsFor(t *testing.T, withCascade bool) *oauth.MemoryClientRegistry {
	t.Helper()
	key := fmt.Sprintf("cascade=%v", withCascade)
	kitMu.Lock()
	defer kitMu.Unlock()
	if f, ok := kitFixtures[key]; ok {
		return f.clients
	}
	t.Fatal("no kit fixture for " + key)
	return nil
}

// E1 (FIXED) — the generated cascade endpoint authenticates the client before the
// hook runs, so an anonymous request never reaches CascadeRevoke.
//
// Was: the kit extracted whatever credentials were present and forwarded them to
// the hook without checking, so a request with no client_id/client_secret reached
// CascadeRevoke and was answered 200 — anyone who could name a token could end the
// subject's whole upstream session. The endpoint now calls
// OAuth.AuthenticateClient first (upstreamkit/server.go handleCascadeRevocation).
func TestE1_CascadeRevocationRequiresAuthentication(t *testing.T) {
	base, _, calls, _ := newKit(t, true)

	resp, err := http.PostForm(base+"/oauth/cascade_revocation", url.Values{
		"token": {"a-token-the-attacker-came-by"}, "token_type_hint": {"refresh_token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("anonymous POST /oauth/cascade_revocation -> %d %s (hook calls=%d)",
		resp.StatusCode, truncate(string(body), 120), len(*calls))

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an anonymous cascade POST = %d, want 401: the endpoint ends a whole upstream "+
			"session and must authenticate the client first", resp.StatusCode)
	}
	if len(*calls) != 0 {
		t.Errorf("the cascade hook ran for an unauthenticated caller (%d calls): it is handed an "+
			"empty client identity an attacker controls", len(*calls))
	}
}

// Control: with real credentials the same call also succeeds, so the endpoint is
// not simply broken.
func TestE2_CascadeRevocationAcceptsCredentials(t *testing.T) {
	base, _, _, _ := newKit(t, true)
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/cascade_revocation",
		strings.NewReader(url.Values{"token": {"t"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(confClientID, confSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	t.Logf("authenticated cascade -> %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control: authenticated cascade = %d", resp.StatusCode)
	}
}

// E3 (FIXED) — an unknown client id with a bogus secret is refused before the
// hook, so the endpoint is not merely checking that some credentials were present.
func TestE3_CascadeRevocationRefusesAnUnknownClient(t *testing.T) {
	base, _, calls, _ := newKit(t, true)
	before := len(*calls)
	resp, err := http.PostForm(base+"/oauth/cascade_revocation", url.Values{
		"token": {"t"}, "client_id": {"no-such-client"}, "client_secret": {"whatever"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("cascade with an unknown client id = %d, want 401", resp.StatusCode)
	}
	if len(*calls) != before {
		t.Errorf("the hook ran for an unknown client (calls delta=%d)", len(*calls)-before)
	}
}

// The token endpoint is protected by the engine, so the contrast is real.
func TestE4_TokenEndpointRequiresClientAuth(t *testing.T) {
	base, _, _, _ := newKit(t, false)
	resp, err := http.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {"bogus"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("token with no client identity -> %d %s", resp.StatusCode, truncate(string(body), 120))
	if resp.StatusCode/100 == 2 {
		t.Errorf("the token endpoint answered 2xx to an unauthenticated request")
	}
}

// The authorize endpoint refuses an unregistered redirect URI without asking the
// user anything.
func TestE5_AuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	base, _, _, consent := newKit(t, false)
	before := *consent
	q := url.Values{
		"response_type": {"code"}, "client_id": {confClientID},
		"redirect_uri":          {"https://evil.example/cb"},
		"scope":                 {string(accountScope)},
		"code_challenge":        {challengeFor(probeVerifier)},
		"code_challenge_method": {"S256"},
	}.Encode()
	resp, err := http.Get(base + "/oauth/authorize?" + q)
	if err != nil {
		t.Fatal(err)
	}
	loc := resp.Header.Get("Location")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("authorize with an unregistered redirect -> %d Location=%q body=%s", resp.StatusCode, loc, truncate(string(body), 120))
	if loc != "" {
		t.Errorf("an unregistered redirect_uri produced a redirect to %q", loc)
	}
	if *consent != before {
		t.Errorf("consent was requested for a request with an unregistered redirect_uri")
	}
}

// The body limit: a declared oversize is refused up front, a chunked oversize
// body is not, and an ordinary request still works.
func TestE6_BodyLimitVariants(t *testing.T) {
	base, _, _, _ := newKit(t, false)

	// Control: a normal-sized request reaches the endpoint.
	ctrl := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}
	resp, err := http.PostForm(base+"/oauth/token", ctrl)
	if err != nil {
		t.Fatal(err)
	}
	ctrlStatus := resp.StatusCode
	ctrlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("control small body -> %d %s", ctrlStatus, truncate(string(ctrlBody), 100))
	if ctrlStatus == http.StatusRequestEntityTooLarge {
		t.Fatal("vacuity: even a small body was refused")
	}

	big := url.Values{"grant_type": {"authorization_code"}, "code": {strings.Repeat("x", oauth.MaxFormBytes+16)}}

	// 1. declared oversize
	resp, err = http.PostForm(base+"/oauth/token", big)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("declared oversize (Content-Length) -> %d %s", resp.StatusCode, truncate(string(b1), 100))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("a declared oversize body got %d, want 413", resp.StatusCode)
	}

	// 2. chunked, unknown length: ContentLength == -1 on the server
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/token", io.NopCloser(strings.NewReader(big.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = -1 // force chunked
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("chunked oversize (no Content-Length) -> %d %s", resp.StatusCode, truncate(string(b2), 100))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("a chunked oversize body got %d, want 413: the body IS capped, but the caller sees a malformed-request error instead", resp.StatusCode)
	}

	// 3. gzip body declaring a small Content-Length
	var buf strings.Builder
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(big.Encode())); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("gzip oversize (%d wire bytes) -> %d %s", buf.Len(), resp.StatusCode, truncate(string(b3), 100))
}

// A request whose only valid parameters sit AFTER the 64 KB cap is refused (no
// bypass), while a request whose parameters fit inside it is served.
func TestE6b_BodyLimitHasNoBypass(t *testing.T) {
	base, svc, _, _ := newKit(t, false)
	tok := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)

	// The refresh token first, then a 70 KB filler, then the grant type. If the
	// filler were skipped rather than capped, this would succeed.
	body := "refresh_token=" + url.QueryEscape(tok.RefreshToken) +
		"&client_id=" + confClientID + "&client_secret=" + url.QueryEscape(confSecret) +
		"&filler=" + strings.Repeat("x", 70<<10) + "&grant_type=refresh_token"
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("grant_type hidden past the cap -> %d %s", resp.StatusCode, truncate(string(raw), 140))
	if resp.StatusCode == http.StatusOK {
		t.Errorf("a body whose grant_type sat past the %d-byte cap was executed: the cap is a bypass", oauth.MaxFormBytes)
	}

	// Control: the same shape inside the cap is served.
	body2 := "refresh_token=" + url.QueryEscape(tok.RefreshToken) +
		"&client_id=" + confClientID + "&client_secret=" + url.QueryEscape(confSecret) +
		"&grant_type=refresh_token"
	req, _ = http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(body2))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("control, same body under the cap -> %d %s", resp.StatusCode, truncate(string(raw2), 140))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vacuity: the under-cap control did not succeed")
	}
}

// The discovery documents carry no cache directive.
func TestE7_DiscoveryCacheHeaders(t *testing.T) {
	base, _, _, _ := newKit(t, false)
	for _, path := range []string{
		"/.well-known/re0auth-upstream",
		"/.well-known/oauth-authorization-server",
	} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Logf("%-42s %d Cache-Control=%q Vary=%q", path, resp.StatusCode,
			resp.Header.Get("Cache-Control"), resp.Header.Get("Vary"))
		if resp.Header.Get("Cache-Control") == "" {
			t.Errorf("%s has no Cache-Control header", path)
		}
	}
}

// A token error response must not be cached either.
func TestE8_TokenResponseCacheHeaders(t *testing.T) {
	base, _, _, _ := newKit(t, false)
	resp, err := http.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {"bogus"},
		"client_id": {confClientID}, "client_secret": {confSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	t.Logf("token error response: %d Cache-Control=%q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	if resp.Header.Get("Cache-Control") == "" {
		t.Errorf("an OAuth error response from the token endpoint has no Cache-Control")
	}
}

// An authorize request for an unknown client must not consult the consent hook
// and must not redirect.
func TestE9_AuthorizeUnknownClient(t *testing.T) {
	base, _, _, consent := newKit(t, false)
	before := *consent
	q := url.Values{
		"response_type": {"code"}, "client_id": {"nobody"},
		"redirect_uri": {confRedirect}, "scope": {string(accountScope)},
		"code_challenge": {challengeFor(probeVerifier)}, "code_challenge_method": {"S256"},
	}.Encode()
	resp, err := http.Get(base + "/oauth/authorize?" + q)
	if err != nil {
		t.Fatal(err)
	}
	loc := resp.Header.Get("Location")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("unknown client -> %d Location=%q body=%s", resp.StatusCode, loc, truncate(string(body), 140))
	if loc != "" || *consent != before {
		t.Errorf("an unknown client reached consent or got a redirect")
	}
}

// The generated surface's /account and /resources endpoints enforce the bearer
// token and the scope. E10 (FIXED): a suspended client's token no longer opens
// them, because Introspect reports it inactive.
func TestE10_DataPlaneRequiresTokenAndScope(t *testing.T) {
	base, svc, _, _ := newKit(t, false)

	resp, err := http.Get(base + "/account")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	t.Logf("/account with no token -> %d", resp.StatusCode)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/account without a token = %d, want 401", resp.StatusCode)
	}

	tok := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)

	// Control: with the token, /account works.
	req, _ := http.NewRequest(http.MethodGet, base+"/account", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("control /account with account.read -> %d %s", resp.StatusCode, truncate(string(ctrl), 100))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vacuity: /account did not work with a valid token")
	}

	// A token without the profile scope must not read the profile resource.
	req, _ = http.NewRequest(http.MethodGet, base+"/resources/profile", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("/resources/profile with an account.read-only token -> %d %s", resp.StatusCode, truncate(string(raw), 100))
	if resp.StatusCode == http.StatusOK {
		t.Errorf("a token without %s read a resource that requires it", profileScope)
	}

	// A suspended client's token no longer opens the data plane: Introspect reports
	// it inactive, so the end-to-end form of the library-level fix holds.
	tok2 := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)
	if err := kitClientsFor(t, false).SetStatus(context.Background(), confClientID, oauth.ClientSuspended); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodGet, base+"/account", nil)
	req.Header.Set("Authorization", "Bearer "+tok2.AccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("/account with a SUSPENDED client's token -> %d %s", resp.StatusCode, truncate(string(raw2), 100))
	if resp.StatusCode == http.StatusOK {
		t.Errorf("a token issued to a client that was suspended afterwards still reads the data plane")
	}
}

// ---------------------------------------------------------------------------
// H. discovery / metadata honesty
// ---------------------------------------------------------------------------

// Every endpoint the two documents advertise must actually be served, and no
// endpoint may be served without being advertised. This is the property the kit
// states in prose ("advertising it without implementing it would be the same
// class of lie as advertising DPoP while issuing plain bearer tokens").
func TestH1_AdvertisedEndpointsAreServed(t *testing.T) {
	for _, withCascade := range []bool{false, true} {
		base, _, _, _ := newKit(t, withCascade)

		type doc struct {
			OAuth struct {
				Issuer                string `json:"issuer"`
				AuthorizationEndpoint string `json:"authorization_endpoint"`
				TokenEndpoint         string `json:"token_endpoint"`
				RevocationEndpoint    string `json:"revocation_endpoint"`
				CascadeEndpoint       string `json:"cascade_revocation_endpoint"`
			} `json:"oauth"`
			ScopesSupported []string `json:"scopes_supported"`
			TokenClass      string   `json:"token_class"`
		}
		var d doc
		resp, err := http.Get(base + "/.well-known/re0auth-upstream")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			t.Fatalf("discovery did not decode: %v", err)
		}
		resp.Body.Close()

		t.Logf("cascade=%v: issuer=%q authorize=%q token=%q revoke=%q cascade=%q token_class=%q scopes=%v",
			withCascade, d.OAuth.Issuer, d.OAuth.AuthorizationEndpoint, d.OAuth.TokenEndpoint,
			d.OAuth.RevocationEndpoint, d.OAuth.CascadeEndpoint, d.TokenClass, d.ScopesSupported)

		// The issuer must not be the plaintext http the probe is served over;
		// that is the fixture's choice, so it is only logged, not asserted.
		if d.OAuth.CascadeEndpoint != "" && strings.HasPrefix(d.OAuth.CascadeEndpoint, "http://") {
			t.Errorf("cascade_revocation_endpoint is advertised over plaintext http: %q", d.OAuth.CascadeEndpoint)
		}
		if d.OAuth.CascadeEndpoint == "" && withCascade {
			t.Errorf("the cascade hook is installed but the endpoint is not advertised")
		}
		if d.OAuth.CascadeEndpoint != "" && !withCascade {
			t.Errorf("the cascade endpoint is advertised without a hook: %q", d.OAuth.CascadeEndpoint)
		}

		// The metadata document must agree with the discovery document.
		resp, err = http.Get(base + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
			t.Fatalf("metadata did not decode: %v", err)
		}
		resp.Body.Close()
		t.Logf("cascade=%v metadata: %v", withCascade, meta)

		// Each endpoint named in metadata must be reachable (not 404).
		for _, key := range []string{"authorization_endpoint", "token_endpoint", "revocation_endpoint"} {
			raw, _ := meta[key].(string)
			if raw == "" {
				t.Errorf("metadata omits %s", key)
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Errorf("metadata %s is not a URL: %q", key, raw)
				continue
			}
			req, _ := http.NewRequest(http.MethodPost, base+u.Path, strings.NewReader(""))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			t.Logf("  POST %-30s -> %d", u.Path, r.StatusCode)
			if r.StatusCode == http.StatusNotFound {
				t.Errorf("the metadata advertises %s at %s but POSTing there is 404", key, u.Path)
			}
		}

		// And the scopes advertised must match what the registry resolves.
		reg := newRegistry(t)
		for _, sc := range d.ScopesSupported {
			if _, ok := reg.Get(oauth.Scope(sc)); !ok && sc != string(accountScope) {
				t.Errorf("discovery advertises scope %q which the hook registry does not know", sc)
			}
		}
		// The kit's own account scope is advertised but the hook registry in this
		// probe does not carry it; that mismatch is the probe's, not the kit's.
	}
}

// The metadata document is built by hand rather than from the Discovery struct,
// so it can drift. It currently omits the endpoint the discovery document names
// for cascade revocation -- which is safe, but only by omission.
func TestH2_MetadataAndDiscoveryAgreeOnCascade(t *testing.T) {
	base, _, _, _ := newKit(t, true)
	resp, err := http.Get(base + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = http.Get(base + "/.well-known/re0auth-upstream")
	if err != nil {
		t.Fatal(err)
	}
	var disc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	sec, _ := disc["oauth"].(map[string]any)
	inDisc, _ := sec["cascade_revocation_endpoint"].(string)
	inMeta, _ := meta["cascade_revocation_endpoint"].(string)
	t.Logf("discovery cascade = %q; metadata cascade = %q", inDisc, inMeta)
	// And RFC 8414 §3 recommends a cache lifetime policy for metadata.
	t.Logf("metadata keys = %v", metaKeys(meta))
}

func metaKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------
// F. conformance anti-vacuity
// ---------------------------------------------------------------------------

// A deliberately non-conformant server: it serves both well-known documents and
// then accepts everything.
func brokenSource() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/re0auth-upstream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"re0auth_upstream_version":1,"game":"g","source":"s","display_name":"d",`+
			`"token_class":"revocable","scopes_supported":["account.read"],`+
			`"oauth":{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"revocation_endpoint":%q}}`,
			"http://"+r.Host, "http://"+r.Host+"/oauth/authorize",
			"http://"+r.Host+"/oauth/token", "http://"+r.Host+"/oauth/revoke")
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code_challenge_methods_supported":["S256"],`+
			`"response_types_supported":["code"],`+
			`"token_endpoint_auth_methods_supported":["client_secret_basic"]}`)
	})
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code=whatever", http.StatusFound)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"bearer-for-everyone","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

func logFindings(t *testing.T, findings []conformance.Finding) (errs, warns, skips int) {
	t.Helper()
	for _, f := range findings {
		switch f.Level {
		case conformance.LevelError:
			errs++
		case conformance.LevelWarning:
			warns++
		case conformance.LevelSkipped:
			skips++
		}
		t.Logf("[%s] %s: %s", f.Level, f.Check, f.Message)
	}
	return errs, warns, skips
}

// Control for every anti-vacuity claim below: the suite does fire on a server
// that accepts any client and mints tokens for bogus grants.
func TestF1_ConformanceDetectsAnObviousNonConformance(t *testing.T) {
	srv := brokenSource()
	defer srv.Close()

	findings := conformance.Run(context.Background(), srv.URL, conformance.Options{})
	errs, warns, skips := logFindings(t, findings)
	t.Logf("errors=%d warnings=%d skipped=%d", errs, warns, skips)
	if errs == 0 {
		t.Errorf("conformance passed a source that accepts any client, redirects unknown clients and mints tokens for bogus grants")
	}
	for _, want := range []string{"authorize.rejects_unknown_client", "token.rejects_bad_grant"} {
		found := false
		for _, f := range findings {
			if f.Check == want && f.Level == conformance.LevelError {
				found = true
			}
		}
		if !found {
			t.Errorf("expected check %s to fire, it did not", want)
		}
	}
}

// F2 (FIXED) — a source that declares client_secret_basic and then authenticates
// nobody now FAILS: the suite refuses a token endpoint whose bogus-grant answer is
// not the invalid_client refusal (token.requires_auth) and a revocation endpoint
// that answers 2xx to a caller with no credentials (revoke.requires_auth). Both
// are the Z14-2 assertions.
//
// Was: the suite made no assertion about client authentication at all, so this
// source passed with zero errors while it minted a token for anyone who asked.
func TestF2_ConformanceIgnoresClientAuthentication(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/re0auth-upstream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"re0auth_upstream_version":1,"game":"g","source":"s","display_name":"d",`+
			`"token_class":"revocable","scopes_supported":["account.read"],`+
			`"oauth":{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"revocation_endpoint":%q}}`,
			"http://"+r.Host, "http://"+r.Host+"/oauth/authorize",
			"http://"+r.Host+"/oauth/token", "http://"+r.Host+"/oauth/revoke")
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code_challenge_methods_supported":["S256"],`+
			`"response_types_supported":["code"],`+
			`"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"]}`)
	})
	// Unknown client -> 401, so the authorize check is satisfied.
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("client_id") == "conformance-unknown-client" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code=x", http.StatusFound)
	})
	// Refuses only the bogus code the suite uses, so token.rejects_bad_grant is
	// satisfied; a real code with NO client credentials would be served.
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("code") == "conformance-bogus-code" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"minted-without-any-client-auth","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	findings := conformance.Run(context.Background(), srv.URL, conformance.Options{})
	errs, warns, _ := logFindings(t, findings)
	t.Logf("a source that authenticates nobody: errors=%d warnings=%d", errs, warns)
	if errs == 0 {
		t.Errorf("the auth-free source passed conformance with zero errors")
	}
	for _, want := range []string{"token.requires_auth", "revoke.requires_auth"} {
		found := false
		for _, f := range findings {
			if f.Check == want && f.Level == conformance.LevelError {
				found = true
			}
		}
		if !found {
			t.Errorf("expected check %s to fire for a source that authenticates nobody", want)
		}
	}

	// Prove the server really is unauthenticated, so this is not a vacuous pass.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/token",
		strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {"a-real-looking-code"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("token with no client identity at all -> %d %s", resp.StatusCode, truncate(string(raw), 120))
	if resp.StatusCode/100 != 2 {
		t.Fatalf("vacuity: the supposedly auth-free server refused the request (%d)", resp.StatusCode)
	}
}

// F3 (FIXED) — a source that advertises cascade revocation and answers 200 to an
// UNKNOWN client id now FAILS the cascade check: conformance asserts the endpoint
// refuses an unauthenticated caller, not merely that it exists.
//
// Was: the check only looked for 404, so an endpoint that ends a real upstream
// session for anyone who can name a token passed. That is the shape a third party
// hand-rolling the spec (rather than using the kit) would ship, which is why the
// assertion lives in the suite as well as in the kit.
func TestF3_ConformanceFailsAnUnauthenticatedCascade(t *testing.T) {
	var sawUnknownClientCascade, sawAnonymousCascade bool
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/re0auth-upstream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"re0auth_upstream_version":1,"game":"g","source":"s","display_name":"d",`+
			`"token_class":"revocable","scopes_supported":["account.read"],`+
			`"oauth":{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,`+
			`"revocation_endpoint":%q,"cascade_revocation_endpoint":%q}}`,
			"http://"+r.Host, "http://"+r.Host+"/oauth/authorize", "http://"+r.Host+"/oauth/token",
			"http://"+r.Host+"/oauth/revoke", "http://"+r.Host+"/oauth/cascade_revocation")
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code_challenge_methods_supported":["S256"],"response_types_supported":["code"]}`)
	})
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// The vulnerability under test: this endpoint ends a real upstream session for
	// anyone who can name a token, whatever credentials they present.
	mux.HandleFunc("/oauth/cascade_revocation", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, _, basic := r.BasicAuth()
		if r.PostFormValue("client_id") == "conformance-unknown-client" && !basic {
			sawUnknownClientCascade = true
		}
		if r.PostFormValue("client_id") == "" && r.PostFormValue("client_secret") == "" && !basic &&
			r.PostFormValue("token") != "" {
			sawAnonymousCascade = true
		}
		w.WriteHeader(http.StatusOK) // accepted, whatever the credentials were
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	findings := conformance.Run(context.Background(), srv.URL, conformance.Options{})
	cascadeErrs := 0
	for _, f := range findings {
		t.Logf("[%s] %s: %s", f.Level, f.Check, f.Message)
		if strings.HasPrefix(f.Check, "cascade") && f.Level == conformance.LevelError {
			cascadeErrs++
		}
	}
	if !sawUnknownClientCascade {
		t.Fatalf("vacuity: the suite never posted to the advertised cascade endpoint with an unknown client")
	}
	t.Logf("the suite posted to the cascade endpoint with an unknown client id and no Basic auth, "+
		"and the endpoint answered 200; a truly anonymous call was also accepted=%v", sawAnonymousCascade)
	if cascadeErrs == 0 {
		t.Errorf("the suite passed a cascade endpoint that accepts any client: it must report an error, " +
			"since that is the vulnerability")
	}
}

// ---------------------------------------------------------------------------
// G. revoke / introspect / token internals
// ---------------------------------------------------------------------------

// Revocation: an unknown token is idempotent success, somebody else's token is
// refused, and the owner can revoke. The controls come first.
func TestG1_RevocationOwnership(t *testing.T) {
	svc, _, _, _ := newAS(t)
	ctx := context.Background()
	tok := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)
	pub := mint(t, svc, pubClientID, "", pubRedirect, accountScope)

	cases := []struct {
		name        string
		clientID    string
		secret      string
		token       string
		wantErrCode string
	}{
		{"unknown token", confClientID, confSecret, "no-such-token", ""},
		{"other client's access token", pubClientID, "", tok.AccessToken, "invalid_client"},
		{"other client's refresh token", pubClientID, "", tok.RefreshToken, "invalid_client"},
		{"own access token", confClientID, confSecret, tok.AccessToken, ""},
		{"own refresh token", confClientID, confSecret, tok.RefreshToken, ""},
		{"wrong secret", confClientID, "bad", tok.AccessToken, "invalid_client"},
	}
	for _, tc := range cases {
		err := svc.Revoke(ctx, oauth.RevokeRequest{ClientID: tc.clientID, ClientSecret: tc.secret, Token: tc.token})
		got := ""
		if err != nil {
			got = oauthCode(t, err)
		}
		if got != tc.wantErrCode {
			t.Errorf("%s: revoke returned %q, want %q", tc.name, got, tc.wantErrCode)
		}
		t.Logf("%-28s -> %q", tc.name, got)
	}

	// After its owner revoked it, the access token must be dead.
	info, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("introspect of the revoked access token: active=%v", info.Active)
	if info.Active {
		t.Errorf("a revoked access token still introspects as Active")
	}
	// And the public client's token, which the confidential client tried to
	// revoke, must still be alive.
	info, err = svc.Introspect(ctx, pub.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("introspect of the OTHER client's token after the failed revoke: active=%v", info.Active)
	if !info.Active {
		t.Errorf("another client's failed revoke attempt killed the token anyway")
	}
}

// Introspect has no requester, so any caller that can reach it learns the
// subject, client and scopes of any token value it holds.
func TestG2_IntrospectLeaksSubjectAndScopes(t *testing.T) {
	svc, _, _, _ := newAS(t)
	tok := mint(t, svc, confClientID, confSecret, confRedirect, accountScope, profileScope)
	info, err := svc.Introspect(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Introspect(one client's token) with no caller identity -> active=%v subject=%q client=%q scopes=%v",
		info.Active, info.Subject, info.ClientID, info.Scopes)
	t.Logf("NOTE: this is the kit's own /account and /resources path and is correct for it; " +
		"the exposure only becomes a finding if Introspect is ever wired to an RFC 7662 endpoint")
}

// Token material: 32 random bytes, base64url, no counter and no timestamp.
func TestG3_TokenEntropy(t *testing.T) {
	svc, _, _, _ := newAS(t)
	const n = 64
	seen := make(map[string]bool, n*2)
	prev := ""
	prefixHits := 0
	for i := 0; i < n; i++ {
		tok := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)
		raw, err := base64.RawURLEncoding.DecodeString(tok.AccessToken)
		if err != nil {
			t.Fatalf("token %q is not base64url: %v", tok.AccessToken, err)
		}
		if len(raw) != 32 {
			t.Errorf("token decodes to %d bytes, want 32", len(raw))
		}
		if seen[tok.AccessToken] {
			t.Fatalf("token value repeated: %q", tok.AccessToken)
		}
		seen[tok.AccessToken] = true
		if seen[tok.RefreshToken] {
			t.Fatalf("refresh token value repeated: %q", tok.RefreshToken)
		}
		seen[tok.RefreshToken] = true
		if prev != "" && prev[:8] == tok.AccessToken[:8] {
			prefixHits++
		}
		prev = tok.AccessToken
	}
	t.Logf("%d pairs, %d unique values, %d shared 8-char prefixes", n, len(seen), prefixHits)
	if prefixHits > 0 {
		t.Errorf("%d consecutive tokens shared an 8-character prefix, which suggests structure", prefixHits)
	}
}

// ClientCredentials percent-decodes the Basic credentials. This test pins the
// consequence that was HYPOTHESISED and then REFUTED: a secret containing '+'
// and a secret containing ' ' do NOT become interchangeable, because the decode
// is applied to the value the client sent and a mismatched client id fails
// outright. What the decoding does cost is the unencoded form.
func TestG4_BasicPercentDecodingDoesNotCrossAuthenticate(t *testing.T) {
	ctx := context.Background()
	clients := oauth.NewMemoryClientRegistry()
	// Client A's secret is "a+b"; client B's is "a b". RFC 6749 §2.3.1 encodes
	// them as "a%2Bb" and "a+b" respectively.
	for id, secret := range map[string]string{"A": "a+b", "B": "a b"} {
		c, err := oauth.NewClient(id, id, oauth.ClientConfidential, secret,
			[]string{confRedirect}, []oauth.Scope{accountScope})
		if err != nil {
			t.Fatal(err)
		}
		if err := clients.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://auth.probe.test", Scopes: newRegistry(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	decode := func(clientID, wireSecret string) (string, error) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
		req.SetBasicAuth(clientID, wireSecret)
		id, secret := oauth.ClientCredentials(req)
		return secret, svc.AuthenticateClient(ctx, id, secret)
	}

	// Controls: each client with its own correctly encoded secret still works, so
	// the round trip is lossless for the forms the spec prescribes.
	for _, tc := range []struct{ id, wire string }{{"A", "a%2Bb"}, {"B", "a+b"}} {
		got, err := decode(tc.id, tc.wire)
		t.Logf("control: %s presents %-6q -> decoded %-4q err=%v", tc.id, tc.wire, got, err)
		if err != nil {
			t.Fatalf("vacuity: %s could not authenticate with its own secret", tc.id)
		}
	}

	// The refuted hypothesis, now a guard: neither client can authenticate as the
	// other, whatever form it puts on the wire.
	for _, tc := range []struct {
		id, wire string
		isWrong  bool
	}{
		{"A", "a+b", true},   // decodes to B's secret value, but the id is A
		{"B", "a%2Bb", true}, // decodes to A's secret value, but the id is B
	} {
		got, err := decode(tc.id, tc.wire)
		t.Logf("cross:   %s presents %-6q -> decoded %-4q err=%v", tc.id, tc.wire, got, err)
		if tc.isWrong && err == nil {
			t.Errorf("%s authenticated with another client's secret value (%q -> %q)", tc.id, tc.wire, got)
		}
	}
	// And the direct form: presenting B's literal secret to A's id.
	if err := svc.AuthenticateClient(ctx, "A", "a b"); err == nil {
		t.Errorf("client A authenticated with B's secret value")
	} else {
		t.Logf("AuthenticateClient(A, B's secret value \"a b\") = %v (refused, as it must be)", err)
	}
	if err := svc.AuthenticateClient(ctx, "B", "a+b"); err == nil {
		t.Errorf("client B authenticated with A's secret value")
	} else {
		t.Logf("AuthenticateClient(B, A's secret value \"a+b\") = %v (refused, as it must be)", err)
	}

	// The part that IS true: a secret containing '+' cannot be presented in the
	// unencoded form, because the decode turns it into a space. RFC 6749 requires
	// the encoding, so this is a client's bug -- but it fails as
	// invalid_client, indistinguishable from a wrong secret.
	if _, err := decode("A", "a+b"); err == nil {
		t.Errorf("A's secret was accepted unencoded; the decode must have been skipped")
	} else {
		t.Logf("A presents its own secret unencoded as \"a+b\" -> %v "+
			"(the '+' decodes to a space; the client must send a%%2Bb)", err)
	}
}
