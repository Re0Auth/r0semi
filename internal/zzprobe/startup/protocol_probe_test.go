//go:build audit5

// Probes for the protocol plane's failure shape at the boundary the existing walk
// does not cover: POST-only endpoints asked with hostile content types.
//
// internal/httpapi/plane_test.go walks every protocol path by GET, plus POST for
// the two endpoints the library serves without a method constraint (authorize,
// userinfo). token/revoke/introspect/device_authorization are deliberately left to
// their GET refusal — so the *POST* leg of those endpoints is only ever exercised
// with a well-formed form by other tests. That is the same "a check attached to one
// request shape" gap the second and third audits each found once.
//
// Read-only: tests only.
package startup

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
)

// TestProbePostOnlyProtocolEndpointsAlwaysAnswerOAuthJSON asks the POST-only
// endpoints with bodies the library cannot parse, and asserts the protocol plane's
// contract holds on every one of them.
//
// serveOAuth normalises a bare failure with normalizeOAuthFailure only in the
// `default` branch of a switch whose first case is `isToken` — so a token-endpoint
// failure written without an `error` field would keep whatever the library wrote.
// This walk is what says whether such a failure is reachable.
func TestProbePostOnlyProtocolEndpointsAlwaysAnswerOAuthJSON(t *testing.T) {
	srv, err := newProbeHandler(t)
	if err != nil {
		t.Fatal(err)
	}

	type attempt struct {
		name        string
		path        string
		contentType string
		body        string
	}
	attempts := []attempt{
		{"json body", "/oauth/token", "application/json", `{"grant_type":"authorization_code"}`},
		{"json body on introspect", "/oauth/introspect", "application/json", `{"token":"x"}`},
		{"json body on revoke", "/oauth/revoke", "application/json", `{"token":"x"}`},
		{"json body on device_authorization", "/oauth/device_authorization", "application/json", `{}`},
		{"no content type", "/oauth/token", "", "grant_type=authorization_code"},
		{"text/plain with a form body", "/oauth/token", "text/plain", "grant_type=authorization_code"},
		{"multipart without a boundary", "/oauth/token", "multipart/form-data", "grant_type=x"},
		{"bad percent-encoding", "/oauth/token", "application/x-www-form-urlencoded", "grant_type=%zz"},
		{"bad percent-encoding on introspect", "/oauth/introspect",
			"application/x-www-form-urlencoded", "token=%zz"},
		{"an empty body", "/oauth/token", "application/x-www-form-urlencoded", ""},
		{"binary garbage", "/oauth/token", "application/octet-stream", "\x00\x01\x02\xff"},
		{"an unknown grant type", "/oauth/token", "application/x-www-form-urlencoded", "grant_type=wat"},
		{"a missing grant type", "/oauth/token", "application/x-www-form-urlencoded", "code=x"},
	}
	methods := []string{http.MethodPost, http.MethodPut}

	checked := 0
	for _, a := range attempts {
		for _, method := range methods {
			t.Run(method+" "+a.name, func(t *testing.T) {
				req := httptest.NewRequest(method, a.path, strings.NewReader(a.body))
				if a.contentType != "" {
					req.Header.Set("Content-Type", a.contentType)
				}
				rec := httptest.NewRecorder()
				srv.ServeHTTP(rec, req)
				if rec.Code < 400 {
					t.Fatalf("%s %s (%s) answered %d, so this probe asserts nothing: %s",
						method, a.path, a.name, rec.Code, rec.Body.String())
				}
				checked++
				ct := rec.Header().Get("Content-Type")
				if strings.Contains(ct, "problem+json") {
					t.Fatalf("the protocol plane leaked problem+json: %s", rec.Body.String())
				}
				var body map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("%s %s (%s) answered %d with Content-Type %q and a NON-JSON body: %q",
						method, a.path, a.name, rec.Code, ct, rec.Body.String())
				}
				if _, ok := body["error"]; !ok {
					t.Fatalf("%s %s (%s) answered %d without an `error` field: %s",
						method, a.path, a.name, rec.Code, rec.Body.String())
				}
				// The description must not be the library's internal text.
				if d, _ := body["error_description"].(string); strings.Contains(d, "ErrorType=") ||
					strings.Contains(d, "Parent=") {
					t.Fatalf("library internals leaked into the wire body: %q", d)
				}
				if method == http.MethodPost {
					t.Logf("%s %-32s -> %d %s (content-type %q)", a.path, a.name, rec.Code, compact(rec.Body.String()), ct)
				}
			})
		}
	}
	if checked < len(attempts) {
		t.Fatalf("only %d attempts reached an assertion", checked)
	}
}

// TestProbeProtocolEndpointsRefuseEveryUnlistedVerb is the verb matrix for the
// protocol plane, the counterpart of the business plane's existing one.
//
// endpointMethods is the single table every protocol endpoint's allowed methods
// come from, so this walks the same table the handler consults. The property is
// that a verb outside it is refused *before* any pre-flight or handler runs, in the
// protocol plane's own shape.
func TestProbeProtocolEndpointsRefuseEveryUnlistedVerb(t *testing.T) {
	srv, err := newProbeHandler(t)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]map[string]bool{
		"/oauth/authorize":            {http.MethodGet: true, http.MethodPost: true, http.MethodHead: true},
		"/oauth/authorize/callback":   {http.MethodGet: true, http.MethodHead: true},
		"/oauth/token":                {http.MethodPost: true},
		"/oauth/introspect":           {http.MethodPost: true},
		"/oauth/revoke":               {http.MethodPost: true},
		"/oauth/userinfo":             {http.MethodGet: true, http.MethodPost: true, http.MethodHead: true},
		"/oauth/keys":                 {http.MethodGet: true, http.MethodHead: true},
		"/oauth/device_authorization": {http.MethodPost: true},
	}
	verbs := []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodOptions, http.MethodHead, "TRACE",
	}

	refused := 0
	for path, methods := range allowed {
		for _, verb := range verbs {
			if methods[verb] {
				continue
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, httptest.NewRequest(verb, path, nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405", verb, path, rec.Code)
				continue
			}
			refused++
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Errorf("%s %s: 405 body is not JSON: %q", verb, path, rec.Body.String())
				continue
			}
			if _, ok := body["error"]; !ok {
				t.Errorf("%s %s: 405 body carries no error field: %s", verb, path, rec.Body.String())
			}
		}
	}
	if refused < 20 {
		t.Fatalf("only %d wrong-verb refusals asserted; the walk is not reaching the guard", refused)
	}
}

func compact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// newProbeHandler builds the public handler with the real protocol plane mounted.
func newProbeHandler(t *testing.T) (http.Handler, error) {
	t.Helper()
	srv, err := httpapi.New(probeConfig(t))
	if err != nil {
		return nil, err
	}
	return srv.Handler(), nil
}
