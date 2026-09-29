//go:build audit6

package z02protocoltoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/oauth"
)

// Z02-9 (regression, P0-6 fix) — introspection is authorized by client
// authentication, and a public client has none. The allowlisted shape (the one
// that was the round-5 P0) and the unlisted shape must both answer 401, and no
// token facts may leak.
func TestZ02IntrospectionRefusesPublicClients(t *testing.T) {
	denied := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})
	allowed := denied.withIntrospection(t, []string{denied.deviceID, denied.webID})

	tokens := asTokens(t, denied.codeFlow(t, []string{"openid", "account.id", "phigros.score.read"}))
	if tokens.AccessToken == "" {
		t.Fatal("no access token minted")
	}

	introspect := func(e zoneEnv, basicID, basicSecret string) (int, map[string]any, string) {
		t.Helper()
		resp, raw := e.postForm(t, "/oauth/introspect", form("token", tokens.AccessToken), basicID, basicSecret)
		return resp.StatusCode, decodeJSON(t, raw), string(raw)
	}
	for _, e := range []zoneEnv{denied, allowed} {
		for _, secret := range []string{"not-the-secret", ""} {
			status, body, raw := introspect(e, e.deviceID, secret)
			if status != http.StatusUnauthorized {
				t.Errorf("the public client's introspection answered %d (secret %q), want 401: %s", status, secret, raw)
			}
			if status == http.StatusOK && body["active"] == true {
				t.Errorf("the public client introspected another client's token: %s", raw)
			}
			if strings.Contains(raw, "phigros.score.read") || strings.Contains(raw, "usr_z02") {
				t.Errorf("the refusal leaked the token's facts: %s", raw)
			}
		}
	}

	// Form-only identity (client_secret_post shape) is also refused here: the
	// endpoint authenticates with Basic only (P2-23).
	resp, formRaw := allowed.postForm(t, "/oauth/introspect", form(
		"token", tokens.AccessToken, "client_id", allowed.webID, "client_secret", allowed.webSec), "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("introspection accepted a posted secret: %d %s", resp.StatusCode, formRaw)
	}

	// Controls: the honest confidential paths still work.
	status, body, raw := introspect(denied, denied.webID, denied.webSec)
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("control failed: the issuing client could not introspect its own token: %d %s", status, raw)
	}
	status, _, raw = introspect(allowed, "no-such-client-id", "x")
	if status != http.StatusUnauthorized {
		t.Fatalf("control failed: an unknown client id got %d, want 401", status)
	}

	// The allowlisted confidential entry still needs its secret (the P0-6 fix
	// did not overreach).
	status, _, raw = introspect(allowed, allowed.webID, "wrong")
	if status != http.StatusUnauthorized {
		t.Errorf("an allowlisted confidential client accepted a wrong secret: %d %s", status, raw)
	}
}

// Z02-3 (FINDING) — the P0-6 guard reads the Basic username raw while the
// library url.QueryUnescape's it (pkg/op/client.go ClientBasicAuth), so a
// caller that percent-encodes a character of a public client's id presents an
// id the guard cannot resolve ("unknown", let it through) that the library
// then authenticates as the public client. The guard's contract — "a caller
// whose client is not confidential is refused, allowlisted or not" — is
// bypassable; the data half still fails closed because filterIntrospection
// keys on the raw id, so what escapes is the refusal itself (200 active=false
// where the documented answer is 401 invalid_client).
func TestZ02IntrospectionGuardBypassedByPercentEncodedClientID(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})
	e = e.withIntrospection(t, []string{e.deviceID}) // the round-5 P0-6 shape

	// A garbage token: no facts to leak either way, so the probe isolates the
	// client-authentication half of the endpoint.
	const garbage = "AAAA.BBBB.CCCC.DDDD.EEEE"

	raw := e.deviceID
	escaped := strings.Replace(raw, "e", "%65", 1) // QueryUnescape(escaped) == raw
	if escaped == raw {
		t.Fatalf("fixture id %q has no escapable character", raw)
	}

	// Control: the unescaped public id is refused, allowlisted or not.
	status, _, plainBody := e.introspect(t, garbage, raw, "anything")
	if status != http.StatusUnauthorized {
		t.Fatalf("control failed: the plain public client id was not refused: %d %s", status, plainBody)
	}

	// The finding: the same public client, one character percent-encoded.
	status, respBody, out := e.introspect(t, garbage, escaped, "anything")
	if status == http.StatusUnauthorized {
		t.Fatalf("the escaped id was refused after all — the finding does not hold: %d %v", status, respBody)
	}
	if status != http.StatusOK {
		t.Fatalf("the escaped id answered %d, which the mechanism does not predict: %v", status, respBody)
	}
	if respBody["active"] != false {
		t.Errorf("the escaped id minted an active response: %v", respBody)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), "usr_") || strings.Contains(string(blob), "scope") {
		t.Errorf("the escaped id leaked token facts: %s", blob)
	}
	t.Errorf("CONFIRMED: Basic id %q sent as %q is authenticated by the library as the public client "+
		"(url.QueryUnescape), while the P0-6 guard refused to resolve it — the documented 401 invalid_client "+
		"for a non-confidential caller is bypassable with a percent-encoded id", raw, escaped)

	// And with a real foreign token the data half must still fail closed: the
	// filter keys on the raw id, which is not the token's client.
	tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
	status, foreignBody, _ := e.introspect(t, tokens.AccessToken, escaped, "anything")
	if status == http.StatusOK && foreignBody["active"] == true {
		t.Errorf("the escaped public client read another client's token facts: %v", foreignBody)
	}
}

// Z02-10 guards — introspection answers only what the caller may see, and the
// store decides liveness for expiry, revocation and unknown ids.
func TestZ02IntrospectionIsolationAndLiveness(t *testing.T) {
	clock := newTestClock()
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02", now: clock.Now})

	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "phigros.score.read"}))

	// A foreign confidential client: active=false, no facts.
	status, body, raw := e.introspect(t, tokens.AccessToken, e.narrowID, e.narrowSec)
	if status != http.StatusOK || body["active"] != false {
		t.Fatalf("a foreign client did not get active=false: %d %s", status, raw)
	}
	if _, leaked := body["scope"]; leaked {
		t.Errorf("cross-client introspection leaked scope: %s", raw)
	}
	if _, leaked := body["sub"]; leaked {
		t.Errorf("cross-client introspection leaked sub: %s", raw)
	}

	// The owner's view carries exactly the RFC 7662 facts the store sets.
	status, body, raw = e.introspect(t, tokens.AccessToken, e.webID, e.webSec)
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("the owner could not introspect: %d %s", status, raw)
	}
	for _, key := range []string{"sub", "client_id", "scope", "exp"} {
		if _, ok := body[key]; !ok {
			t.Errorf("the owner's introspection response lacks %q: %s", key, raw)
		}
	}
	if body["sub"] != "usr_z02" || body["client_id"] != e.webID {
		t.Errorf("introspection misattributed the token: %s", raw)
	}
	if cc := rawCacheControl(t, e, tokens.AccessToken); cc != "no-store" {
		t.Errorf("introspection Cache-Control = %q, want no-store", cc)
	}

	// Expired: active=false.
	clock.Advance(2 * time.Hour)
	status, body, _ = e.introspect(t, tokens.AccessToken, e.webID, e.webSec)
	if status != http.StatusOK || body["active"] != false {
		t.Errorf("an expired token introspected as active: %v", body)
	}
	clock.Advance(-2 * time.Hour)

	// Revoked: active=false.
	fresh := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
	if _, raw := e.postForm(t, "/oauth/revoke", form("token", fresh.AccessToken), e.webID, e.webSec); true {
		_ = raw
	}
	status, body, _ = e.introspect(t, fresh.AccessToken, e.webID, e.webSec)
	if status != http.StatusOK || body["active"] != false {
		t.Errorf("a revoked token introspected as active: %v", body)
	}

	// Unknown and wrong-shaped tokens: active=false, never an error.
	for _, token := range []string{"", "garbage", "a.b.c", tokens.IDToken, tokens.RefreshToken} {
		status, body, _ = e.introspect(t, token, e.webID, e.webSec)
		if status != http.StatusOK || body["active"] != false {
			t.Errorf("token %q introspected as %d %v, want 200 active=false", truncate(token), status, body)
		}
	}
}

// Z02-11 guards — a suspended client cannot call introspection: the registry
// reports it as unknown and the store's client resolution follows (the
// b5f01da class, on the OP endpoint's authentication path).
func TestZ02IntrospectionRefusesASuspendedCaller(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
	status, _, raw := e.introspect(t, tokens.AccessToken, e.webID, e.webSec)
	if status != http.StatusOK {
		t.Fatalf("control failed: the live client could not introspect: %d %s", status, raw)
	}

	if err := e.clients.SetStatus(context.Background(), e.webID, oauth.ClientSuspended); err != nil {
		t.Fatal(err)
	}
	status, _, raw = e.introspect(t, tokens.AccessToken, e.webID, e.webSec)
	if status != http.StatusUnauthorized {
		t.Fatalf("a suspended client's introspection answered %d, want 401: %s", status, raw)
	}
}

// Z02-12 guards — the AS engine's own Introspect consults the client's
// status (b5f01da): a suspended client's tokens are inactive to the engine
// that reads them.
func TestZ02ASEngineIntrospectRefusesASuspendedClient(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})
	svc := e.asEngine(t)
	ctx := context.Background()

	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authz, err := svc.Authorize(ctx, oauth.AuthorizationRequest{
		ClientID: e.webID, RedirectURI: "https://client.example/cb", Subject: "usr_z02",
		Scopes:        []oauth.Scope{oauth.ScopeAccountID},
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.Exchange(ctx, oauth.CodeExchangeRequest{
		ClientID: e.webID, ClientSecret: e.webSec, Code: authz.Code,
		RedirectURI: "https://client.example/cb", CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := svc.Introspect(ctx, issued.AccessToken)
	if err != nil || !info.Active {
		t.Fatalf("control failed: the live client's token is not active: %+v %v", info, err)
	}

	if err := e.clients.SetStatus(ctx, e.webID, oauth.ClientSuspended); err != nil {
		t.Fatal(err)
	}
	info, err = svc.Introspect(ctx, issued.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		t.Errorf("b5f01da regression: a suspended client's token introspected as active")
	}
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}

func rawCacheControl(t *testing.T, e zoneEnv, token string) string {
	t.Helper()
	req := postRequest(t, e, "/oauth/introspect", form("token", token), e.webID, e.webSec)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("Cache-Control")
}

func postRequest(t *testing.T, e zoneEnv, path string, values url.Values, basicID, basicSecret string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	return req
}
