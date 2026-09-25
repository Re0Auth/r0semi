package httpapi

import (
	"encoding/json"
	"net/http"
)

// problem is an RFC 9457 Problem Details object. Business plane only.
type problem struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Detail        string `json:"detail,omitempty"`
	Instance      string `json:"instance,omitempty"`
	Code          string `json:"code"`
	RequestID     string `json:"request_id,omitempty"`
	RequiredScope string `json:"required_scope,omitempty"`
	Game          string `json:"game,omitempty"`
	Source        string `json:"source,omitempty"`
	BindURL       string `json:"bind_url,omitempty"`
}

// problemTitles is the closed catalogue of codes this API can produce. Every key
// here is emitted by some handler, and the OpenAPI document enumerates exactly
// this set; a test asserts the two stay equal, so a code can neither be
// documented without being reachable nor emitted without being documented.
//
// Three entries were removed rather than kept as placeholders:
// `credential_not_found`, `conflict` and `idempotency_key_reused` belonged to the
// withdrawn credential-export API and to idempotency keys that were never
// implemented. A catalogue of errors that cannot happen is just a lie with a
// longer half-life.
var problemTitles = map[string]string{
	"invalid_request":           "Invalid request",
	"unauthenticated":           "Authentication required",
	"invalid_token":             "Invalid access token",
	"scope_not_granted":         "Missing required scope",
	"source_not_bound":          "Source not bound",
	"source_unavailable":        "Source unavailable",
	"source_retired":            "Source retired",
	"cascade_unsupported":       "Upstream session cannot be revoked",
	"not_found":                 "Not found",
	"last_identity":             "Cannot unlink the last identity",
	"rate_limited":              "Rate limit exceeded",
	"not_acceptable":            "Not acceptable",
	"upstream_unavailable":      "Upstream unavailable",
	"explicit_consent_required": "Explicit consent required",
	"reauth_required":           "Re-authentication required",
	"internal_error":            "Internal error",
}

func problemTitle(code string) string {
	if t, ok := problemTitles[code]; ok {
		return t
	}
	return "Error"
}

// writeProblem renders an RFC 9457 problem+json response with the stable code,
// a documentation type URI, and the request id.
func (s *Server) writeProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string, opts ...func(*problem)) {
	p := problem{
		Type:      s.errorBase + "/" + code,
		Title:     problemTitle(code),
		Status:    status,
		Detail:    detail,
		Instance:  r.URL.Path,
		Code:      code,
		RequestID: requestID(r),
	}
	for _, opt := range opts {
		opt(&p)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

func withRequiredScope(scope string) func(*problem) {
	return func(p *problem) { p.RequiredScope = scope }
}

func withBinding(game, source, bindURL string) func(*problem) {
	return func(p *problem) {
		p.Game = game
		p.Source = source
		p.BindURL = bindURL
	}
}

// oauthErrorBody is the RFC 6749 §5.2 error response. Protocol plane only.
type oauthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeOAuthError(w http.ResponseWriter, r *http.Request, status int, code, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oauthErrorBody{Error: code, ErrorDescription: description})
}

// writeJSON is the business plane's one success writer.
//
// It sets no-store for the same reason the protocol plane does: every response on
// this plane is authenticated and per-person — the session bootstrap and the admin
// client list carry a CSRF token, and the account export is the whole of somebody's
// account. A shared cache in front of the deployment has no key that distinguishes
// accounts (there is no Vary here either), and a browser cache would keep the CSRF
// token on disk after the session ended.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
