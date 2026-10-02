// Package conformance checks whether a live server implements the Re0Auth
// upstream protocol (docs/upstream-protocol.md).
//
// It is the executable form of the spec: running it against a source produces a
// list of findings, split into hard errors (non-compliant) and warnings
// (discouraged). Checks that need a real access token are skipped unless
// Options.AccessToken is supplied.
package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/upstreamkit"
)

// closeBody closes a response body and discards the error. This client owns each
// response for the duration of one check; a Close error on a body it has already
// finished reading is not actionable, while leaving the body open would leak a
// connection across the many requests a conformance run makes.
func closeBody(resp *http.Response) { _ = resp.Body.Close() }

// Level classifies a finding.
type Level string

const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
	LevelSkipped Level = "skipped"
)

// Finding is one conformance result.
type Finding struct {
	Check   string
	Level   Level
	Message string
}

// Options tunes a run.
type Options struct {
	// HTTPClient is used for all requests. Defaults to a 10s-timeout client.
	HTTPClient *http.Client
	// AccessToken, when set, enables the data-plane checks.
	AccessToken string
	// ClientID and ClientSecret, when BOTH are set, enable the token-endpoint
	// client-authentication checks. They are optional and additive: a run that
	// supplies neither still asserts that an unknown, credential-less client is
	// refused, it just cannot observe which method a correct client is accepted
	// with.
	ClientID     string
	ClientSecret string
}

// Run checks target (a source base URL) and returns its findings.
func Run(ctx context.Context, target string, opts Options) []Finding {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	// Conformance inspects redirects (a compliant source must NOT redirect an
	// unknown client), so never follow them.
	noRedirect := *hc
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	r := &runner{
		ctx:    ctx,
		hc:     &noRedirect,
		base:   strings.TrimRight(target, "/"),
		opts:   opts,
		checks: map[string]bool{},
	}

	disc, ok := r.checkDiscovery()
	if !ok {
		return r.findings
	}
	// Client authentication is exercised before the metadata document is read,
	// because the metadata check compares what the suite OBSERVED accepted
	// against what the document declares.
	r.checkClientAuthentication(disc)
	r.checkOAuthMetadata()
	r.checkAuthorizeRejectsUnknownClient()
	r.checkTokenRejectsBadGrant()
	r.checkRevocationEndpoint(disc)
	r.checkCascadeEndpoint(disc)
	r.checkDataPlane(disc)
	return r.findings
}

type runner struct {
	ctx      context.Context
	hc       *http.Client
	base     string
	opts     Options
	findings []Finding
	checks   map[string]bool

	// observedAuthMethod names the client-authentication method the token
	// endpoint accepted, or "" when the suite did not exercise one (no
	// credentials were supplied, or the correct ones were refused as
	// invalid_client). Only a non-empty value lets the metadata comparison run:
	// nothing was observed, so nothing can contradict the document.
	observedAuthMethod string
}

func (r *runner) report(level Level, check, format string, args ...any) {
	if level != LevelSkipped {
		if r.checks[check] {
			return
		}
		r.checks[check] = true
	}
	r.findings = append(r.findings, Finding{Check: check, Level: level, Message: fmt.Sprintf(format, args...)})
}

func (r *runner) err(check, format string, args ...any) { r.report(LevelError, check, format, args...) }
func (r *runner) warn(check, format string, args ...any) {
	r.report(LevelWarning, check, format, args...)
}
func (r *runner) skip(check, format string, args ...any) {
	r.report(LevelSkipped, check, format, args...)
}

func (r *runner) request(method, path string, body string, headers map[string]string) (*http.Response, error) {
	return r.requestURL(method, r.base+path, body, headers)
}

// requestURL sends to an absolute URL. It exists because the endpoints a source
// ADVERTISES are URLs, not paths on the target: the suite must exercise the
// advertised URL itself (docs/upstream-protocol.md §4), origin included, or it
// judges a different endpoint than Re0Auth will call.
func (r *runner) requestURL(method, target string, body string, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return r.hc.Do(req)
}

func (r *runner) checkDiscovery() (upstreamkit.Discovery, bool) {
	resp, err := r.request(http.MethodGet, "/.well-known/re0auth-upstream", "", nil)
	if err != nil {
		r.err("discovery.present", "request failed: %v", err)
		return upstreamkit.Discovery{}, false
	}
	defer closeBody(resp)
	if resp.StatusCode != http.StatusOK {
		r.err("discovery.present", "status %d, want 200", resp.StatusCode)
		return upstreamkit.Discovery{}, false
	}

	var disc upstreamkit.Discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&disc); err != nil {
		r.err("discovery.decode", "invalid JSON: %v", err)
		return upstreamkit.Discovery{}, false
	}

	switch {
	case disc.ProtocolVersion != upstreamkit.ProtocolVersion:
		r.err("discovery.version", "re0auth_upstream_version = %d, want %d", disc.ProtocolVersion, upstreamkit.ProtocolVersion)
	case disc.Game == "" || disc.Source == "" || disc.DisplayName == "":
		r.err("discovery.identity", "game, source and display_name are required")
	}

	if disc.TokenClass != upstreamkit.TokenRevocable && disc.TokenClass != upstreamkit.TokenLongLived {
		r.err("discovery.token_class", "token_class = %q, want revocable or long_lived", disc.TokenClass)
	}

	hasAccount := false
	for _, s := range disc.ScopesSupported {
		if s == upstreamkit.AccountScope {
			hasAccount = true
			break
		}
	}
	if !hasAccount {
		r.err("discovery.scopes", "scopes_supported must include %s", upstreamkit.AccountScope)
	}

	if disc.OAuth.Issuer == "" || disc.OAuth.AuthorizationEndpoint == "" || disc.OAuth.TokenEndpoint == "" || disc.OAuth.RevocationEndpoint == "" {
		r.err("discovery.oauth_endpoints", "oauth endpoints are incomplete")
	}

	for _, res := range disc.Resources {
		if res.Name == "" || !strings.HasPrefix(res.Schema, "re0auth.") {
			r.err("discovery.resources", "resource %+v is invalid", res)
		}
	}
	return disc, true
}

// checkOAuthMetadata reads the authorization-server metadata document.
//
// Besides PKCE and the response type, it compares
// token_endpoint_auth_methods_supported against the method the suite observed
// accepted (checkClientAuthentication). The field is optional in RFC 8414, so an
// ABSENT field is a warning that the claim cannot be checked rather than a
// conformance error; a PRESENT field that does not contain the accepted method
// contradicts observable behaviour and is an error. The comparison only runs
// when something was observed, so a credential-less run is unaffected.
func (r *runner) checkOAuthMetadata() {
	resp, err := r.request(http.MethodGet, "/.well-known/oauth-authorization-server", "", nil)
	if err != nil {
		r.warn("oauth.metadata", "authorization server metadata not reachable; inline endpoints are assumed")
		return
	}
	// The body is closed before the status is judged: a non-200 document still
	// owns a connection, and returning on the status used to leave it open for
	// the rest of the run (S06-6).
	defer closeBody(resp)
	if resp.StatusCode != http.StatusOK {
		r.warn("oauth.metadata", "authorization server metadata not reachable; inline endpoints are assumed")
		return
	}

	var doc struct {
		CodeChallengeMethods []string `json:"code_challenge_methods_supported"`
		ResponseTypes        []string `json:"response_types_supported"`
		// A pointer distinguishes an absent field (nil) from an explicit empty
		// list, which the absent-field rule depends on.
		TokenAuthMethods *[]string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		r.err("oauth.metadata", "invalid metadata JSON: %v", err)
		return
	}
	if !slices.Contains(doc.CodeChallengeMethods, "S256") {
		r.err("oauth.pkce", "code_challenge_methods_supported must include S256")
	}
	if len(doc.ResponseTypes) > 0 && !slices.Contains(doc.ResponseTypes, "code") {
		r.err("oauth.response_type", "response_types_supported must include code")
	}

	if r.observedAuthMethod == "" {
		return
	}
	if doc.TokenAuthMethods == nil {
		r.warn("oauth.token_auth_methods", "the metadata document does not declare "+
			"token_endpoint_auth_methods_supported, so the %s credentials the token endpoint "+
			"accepted cannot be checked against it", r.observedAuthMethod)
		return
	}
	if !slices.Contains(*doc.TokenAuthMethods, r.observedAuthMethod) {
		r.err("oauth.token_auth_methods", "the token endpoint accepted %s, which is not among "+
			"token_endpoint_auth_methods_supported %v", r.observedAuthMethod, *doc.TokenAuthMethods)
	}
}

// checkClientAuthentication exercises the client-authentication half of the token
// endpoint, which a credential-less run cannot observe.
//
// It is deliberately additive. The Z14-2 checks beside it assert that an UNKNOWN
// client is refused; this one asserts that a CORRECT client is not, and that a
// WRONG secret is — the pair RFC 6749 §5.2 makes observable without a valid
// grant. The register's literal "correct credentials yield 200" is not
// implementable: the suite owns no valid grant, and the interactive flow is
// explicitly decoupled from these checks (docs/upstream-protocol.md §13), so the
// refusal-side formulation is the one used here. A correct client with an invalid
// grant must NOT be answered `401 invalid_client` (400 `invalid_grant` is the
// expected answer), while a wrong secret must be `401 invalid_client`.
func (r *runner) checkClientAuthentication(disc upstreamkit.Discovery) {
	if r.opts.ClientID == "" || r.opts.ClientSecret == "" {
		r.skip("token.client_auth", "no client credentials supplied; set Options.ClientID and "+
			"Options.ClientSecret to check client authentication")
		return
	}

	endpoint := disc.OAuth.TokenEndpoint
	parsed, err := url.Parse(endpoint)
	if endpoint == "" || err != nil {
		parsed = &url.URL{Path: "/oauth/token"}
	}
	path := parsed.RequestURI()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"conformance-bogus-code"},
		"redirect_uri":  {"https://conformance.invalid/cb"},
		"code_verifier": {"conformance-verifier-conformance-verifier"},
	}

	// (a) The configured client, correct credentials, an invalid grant. The answer
	// must not be the invalid_client refusal.
	status, code, err := r.postToken(path, form, r.opts.ClientID, r.opts.ClientSecret)
	if err != nil {
		r.err("token.reachable", "request failed: %v", err)
		return
	}
	if status == http.StatusUnauthorized && code == "invalid_client" {
		r.err("token.accepts_valid_credentials", "the token endpoint answered 401 invalid_client "+
			"for the configured client with correct credentials, so it does not accept the client "+
			"it was told about")
	} else {
		// The suite now knows which method the endpoint accepted, and
		// checkOAuthMetadata compares that against the document's claim.
		r.observedAuthMethod = "client_secret_basic"
	}

	// (b) The same client with a WRONG secret must be refused as invalid_client.
	status, code, err = r.postToken(path, form, r.opts.ClientID, r.opts.ClientSecret+"-wrong")
	if err != nil {
		r.err("token.reachable", "request failed: %v", err)
		return
	}
	if status != http.StatusUnauthorized || code != "invalid_client" {
		r.err("token.rejects_bad_credentials", "a wrong client secret got status %d error %q, "+
			"want 401 invalid_client", status, code)
	}
}

// postToken sends one token request authenticated with HTTP Basic credentials and
// returns the status and the OAuth error code ("" when the body is not an OAuth
// error document). The client id and secret are form-encoded before being placed
// in the Basic value, which is what RFC 6749 §2.3.1 requires and what the kit
// undoes (oauth.ClientCredentials).
func (r *runner) postToken(path string, form url.Values, clientID, clientSecret string) (int, string, error) {
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)))
	resp, err := r.request(http.MethodPost, path, form.Encode(), map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic " + basic,
	})
	if err != nil {
		return 0, "", err
	}
	defer closeBody(resp)
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
	return resp.StatusCode, body.Error, nil
}

func (r *runner) checkAuthorizeRejectsUnknownClient() {
	verifier := "conformance-verifier-conformance-verifier"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"conformance-unknown-client"},
		"redirect_uri":          {"https://conformance.invalid/cb"},
		"scope":                 {upstreamkit.AccountScope},
		"state":                 {"conformance"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	resp, err := r.request(http.MethodGet, "/oauth/authorize?"+q.Encode(), "", nil)
	if err != nil {
		r.err("authorize.reachable", "request failed: %v", err)
		return
	}
	defer closeBody(resp)
	switch {
	case resp.StatusCode/100 == 3:
		r.err("authorize.rejects_unknown_client", "redirected (status %d) instead of returning an error", resp.StatusCode)
	case resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized:
		r.warn("authorize.rejects_unknown_client", "status %d for an unknown client; expected 400 or 401", resp.StatusCode)
	}
}

func (r *runner) checkTokenRejectsBadGrant() {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"conformance-unknown-client"},
		"code":          {"conformance-bogus-code"},
		"redirect_uri":  {"https://conformance.invalid/cb"},
		"code_verifier": {"conformance-verifier-conformance-verifier"},
	}
	resp, err := r.request(http.MethodPost, "/oauth/token", form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if err != nil {
		r.err("token.reachable", "request failed: %v", err)
		return
	}
	defer closeBody(resp)
	if resp.StatusCode/100 == 2 {
		r.err("token.rejects_bad_grant", "a bogus grant was accepted with status %d", resp.StatusCode)
	}
	// The refusal must be the client-authentication one. RFC 6749 §5.2 makes
	// invalid_client a 401 for a client that authenticated with (or was expected
	// to authenticate with) credentials, so an unknown client that presented
	// none must not be answered as though the grant were the only problem: a
	// source that skips the client check is exactly what a hand-rolled endpoint
	// ships.
	if resp.StatusCode != http.StatusUnauthorized {
		r.err("token.requires_auth", "an unknown client with no credentials got status %d, "+
			"want 401 invalid_client (RFC 6749 §5.2)", resp.StatusCode)
	}
}

// checkRevocationEndpoint checks that the RFC 7009 endpoint exists AND that it
// authenticates the client, mirroring checkCascadeEndpoint's shape. The probe
// carries a bogus token, an unknown client id and no credentials, so a 2xx means
// the endpoint accepted a caller it authenticated nobody for — RFC 7009 §2.1
// requires client authentication before a revocation is acted on.
//
// The endpoint is read from the discovery document, not assumed to be on
// /oauth/revoke. A source may advertise revocation anywhere — another path, a
// whole other host — and Re0Auth calls the advertised URL
// (internal/federation/revocation.go). Probing the target's own decoy path gave
// a compliant source "revocation endpoint is missing" (Z14-V1) while an
// advertised-but-absent URL was never contacted at all. A value that is not an
// absolute URL cannot be called by anyone and is an error, not a warning.
func (r *runner) checkRevocationEndpoint(disc upstreamkit.Discovery) {
	endpoint := disc.OAuth.RevocationEndpoint
	parsed, err := url.Parse(endpoint)
	if err != nil || !parsed.IsAbs() {
		r.err("revoke.absolute", "revocation_endpoint is not an absolute URL: %q", endpoint)
		return
	}
	form := url.Values{"token": {"conformance-bogus-token"}, "client_id": {"conformance-unknown-client"}}
	resp, err := r.requestURL(http.MethodPost, endpoint, form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if err != nil {
		r.err("revoke.reachable", "request failed: %v", err)
		return
	}
	defer closeBody(resp)
	if resp.StatusCode == http.StatusNotFound {
		r.err("revoke.present", "advertised but missing: %s", endpoint)
		return
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		r.err("revoke.requires_auth", "the revocation endpoint answered %d to an unauthenticated "+
			"caller (no credentials, unknown client): RFC 7009 §2.1 requires client authentication "+
			"before a token is revoked", resp.StatusCode)
	}
}

// checkCascadeEndpoint checks the claim AND the one property that makes it safe.
//
// Nothing destructive is attempted, on purpose: a conformance run must not sign
// the person running it out of their own devices. What can be checked without
// doing harm is that an advertised endpoint exists, is addressed absolutely, and
// REFUSES an unauthenticated caller — because a source that advertises a
// capability it does not serve is worse than one that stays quiet, and an endpoint
// that ends a whole session for anyone who can name a token is the loudest thing a
// source can do. The probe carries a bogus token and no credentials, so it is
// rejected before any effect.
//
// The auth check is asserted even though the kit now authenticates for its
// generated endpoint: a source that hand-rolls the endpoint from the spec rather
// than using the kit must still be caught. (upstreamkit.handleCascadeRevocation
// does the same check; that is the belt to this suspenders.)
func (r *runner) checkCascadeEndpoint(disc upstreamkit.Discovery) {
	endpoint := disc.OAuth.CascadeRevocationEndpoint
	if endpoint == "" {
		r.skip("cascade.absent", "no cascade revocation advertised; Re0Auth will not offer it")
		return
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || !parsed.IsAbs() {
		r.err("cascade.absolute", "cascade_revocation_endpoint is not an absolute URL: %q", endpoint)
		return
	}

	// No credentials, an unknown client id, and a token that means nothing.
	// The request goes to the advertised URL itself: taking only its path and
	// re-attaching the target's origin silently swapped the endpoint for whatever
	// the target happened to serve at that path (Z14-V1), which both failed
	// compliant multi-host sources and passed a decoy.
	form := url.Values{"token": {"conformance-bogus-token"}, "client_id": {"conformance-unknown-client"}}
	resp, err := r.requestURL(http.MethodPost, endpoint, form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if err != nil {
		r.err("cascade.reachable", "request failed: %v", err)
		return
	}
	defer closeBody(resp)
	if resp.StatusCode == http.StatusNotFound {
		r.err("cascade.present", "advertised but missing: %s", endpoint)
		return
	}
	// An unauthenticated POST must be refused. 2xx means the endpoint accepted an
	// unknown client, which is the "anyone can end every session" shape.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		r.err("cascade.requires_auth", "the cascade endpoint answered %d to an unauthenticated caller "+
			"(no credentials, unknown client): it must authenticate the client before ending a session",
			resp.StatusCode)
	}
}

func (r *runner) checkDataPlane(disc upstreamkit.Discovery) {
	if r.opts.AccessToken == "" {
		r.skip("data.skipped", "no access token supplied; set Options.AccessToken to check /account and /resources")
		return
	}
	auth := map[string]string{"Authorization": "Bearer " + r.opts.AccessToken}

	// /account requires authentication.
	resp, err := r.request(http.MethodGet, "/account", "", nil)
	if err != nil {
		r.err("account.reachable", "request failed: %v", err)
	} else {
		status := resp.StatusCode
		closeBody(resp)
		if status != http.StatusUnauthorized {
			r.err("account.requires_auth", "status %d without a token, want 401", status)
		}
	}

	// /account returns a stable subject.
	resp, err = r.request(http.MethodGet, "/account", "", auth)
	if err != nil {
		r.err("account.reachable", "request failed: %v", err)
	} else {
		status := resp.StatusCode
		var account struct {
			Subject string `json:"subject"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&account)
		closeBody(resp)
		switch {
		case status != http.StatusOK:
			r.err("account.read", "status %d, want 200", status)
		case decodeErr != nil:
			r.err("account.read", "invalid JSON: %v", decodeErr)
		case account.Subject == "":
			r.err("account.read", "subject is empty")
		}
	}

	// Each declared resource must exist.
	for _, res := range disc.Resources {
		resp, err := r.request(http.MethodGet, "/resources/"+url.PathEscape(res.Name), "", auth)
		if err != nil {
			r.err("resource.reachable", "%s: request failed: %v", res.Name, err)
			continue
		}
		status := resp.StatusCode
		closeBody(resp)
		switch status {
		case http.StatusOK:
			// ok
		case http.StatusForbidden:
			r.skip("resource."+res.Name, "token lacks %s; skipped", res.Scope)
		default:
			r.err("resource."+res.Name, "status %d, want 200 (or 403 if the token lacks the scope)", status)
		}
	}

	// Unknown resources must 404.
	resp, err = r.request(http.MethodGet, "/resources/__conformance_unknown__", "", auth)
	if err != nil {
		r.err("resource.unknown", "request failed: %v", err)
		return
	}
	status, contentType := resp.StatusCode, resp.Header.Get("Content-Type")
	closeBody(resp)
	if status != http.StatusNotFound {
		r.err("resource.unknown", "unknown resource returned %d, want 404", status)
	} else if !strings.HasPrefix(contentType, "application/problem+json") {
		r.warn("resource.unknown", "unknown resource did not use problem+json (got %q)", contentType)
	}
}
