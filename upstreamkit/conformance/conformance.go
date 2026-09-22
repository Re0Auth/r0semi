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
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/upstreamkit"
)

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
	r.checkOAuthMetadata()
	r.checkAuthorizeRejectsUnknownClient()
	r.checkTokenRejectsBadGrant()
	r.checkRevocationEndpoint()
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
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.ctx, method, r.base+path, reader)
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
	defer resp.Body.Close()
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

func (r *runner) checkOAuthMetadata() {
	resp, err := r.request(http.MethodGet, "/.well-known/oauth-authorization-server", "", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		r.warn("oauth.metadata", "authorization server metadata not reachable; inline endpoints are assumed")
		return
	}
	defer resp.Body.Close()

	var doc struct {
		CodeChallengeMethods []string `json:"code_challenge_methods_supported"`
		ResponseTypes        []string `json:"response_types_supported"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		r.err("oauth.metadata", "invalid metadata JSON: %v", err)
		return
	}
	if !contains(doc.CodeChallengeMethods, "S256") {
		r.err("oauth.pkce", "code_challenge_methods_supported must include S256")
	}
	if len(doc.ResponseTypes) > 0 && !contains(doc.ResponseTypes, "code") {
		r.err("oauth.response_type", "response_types_supported must include code")
	}
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		r.err("token.rejects_bad_grant", "a bogus grant was accepted with status %d", resp.StatusCode)
	}
}

func (r *runner) checkRevocationEndpoint() {
	form := url.Values{"token": {"conformance-bogus-token"}, "client_id": {"conformance-unknown-client"}}
	resp, err := r.request(http.MethodPost, "/oauth/revoke", form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if err != nil {
		r.err("revoke.reachable", "request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		r.err("revoke.present", "revocation endpoint is missing")
	}
}

// checkCascadeEndpoint checks the claim, not the effect.
//
// Nothing destructive is attempted, on purpose: a conformance run must not sign
// the person running it out of their own devices. What can be checked without
// doing harm is that an advertised endpoint exists and is addressed absolutely —
// because a source that advertises a capability it does not serve is worse than
// one that stays quiet, and Re0Auth offers "sign out everywhere" only where it is
// claimed.
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

	form := url.Values{"token": {"conformance-bogus-token"}, "client_id": {"conformance-unknown-client"}}
	resp, err := r.request(http.MethodPost, parsed.RequestURI(), form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if err != nil {
		r.err("cascade.reachable", "request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		r.err("cascade.present", "advertised but missing: %s", endpoint)
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
		resp.Body.Close()
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
		resp.Body.Close()
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
		resp.Body.Close()
		switch {
		case status == http.StatusOK:
			// ok
		case status == http.StatusForbidden:
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
	resp.Body.Close()
	if status != http.StatusNotFound {
		r.err("resource.unknown", "unknown resource returned %d, want 404", status)
	} else if !strings.HasPrefix(contentType, "application/problem+json") {
		r.warn("resource.unknown", "unknown resource did not use problem+json (got %q)", contentType)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
