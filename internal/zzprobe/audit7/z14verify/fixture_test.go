//go:build audit7

package z14verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/upstreamkit/conformance"
)

// verifySource is a hand-rolled source whose advertised OAuth endpoints are
// fully under the probe's control, and whose responses are keyed by path so a
// probe can tell which server a request actually arrived at.
//
// It is hand-rolled on purpose: the kit always advertises
// `{issuer}/oauth/cascade_revocation` (upstreamkit/server.go:120-124), so only a
// source that implements the spec itself can advertise an endpoint the suite
// would have to use the document to find. That is exactly the source the suite
// documents itself as guarding (conformance.go:278-281).
type verifySource struct {
	mu sync.Mutex

	// advertised* are the absolute URLs the discovery document names. An empty
	// advertisedCascade omits the field entirely (the capability is optional).
	advertisedRevoke  string
	advertisedCascade string

	// statuses maps a request path to the status this server answers. A path not
	// in the map answers 404.
	statuses map[string]int
	// hits counts requests per path, so a probe can prove which URL was used.
	hits map[string]int
}

func newVerifySource(advertisedRevoke, advertisedCascade string) *verifySource {
	return &verifySource{
		advertisedRevoke:  advertisedRevoke,
		advertisedCascade: advertisedCascade,
		statuses:          map[string]int{},
		hits:              map[string]int{},
	}
}

func (v *verifySource) set(path string, status int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.statuses[path] = status
}

func (v *verifySource) hitCount(path string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.hits[path]
}

// handler serves the source. Every endpoint other than discovery is answered
// from the path table.
func (v *verifySource) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/re0auth-upstream", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		v.mu.Lock()
		revoke := v.advertisedRevoke
		cascade := v.advertisedCascade
		v.mu.Unlock()
		if revoke == "" {
			revoke = base + "/oauth/revoke"
		}
		writeVerifyJSON(w, upstreamkit.Discovery{
			ProtocolVersion: upstreamkit.ProtocolVersion,
			Game:            "phigros",
			Source:          "z14verify",
			DisplayName:     "Z14 verification source",
			TokenClass:      upstreamkit.TokenRevocable,
			ScopesSupported: []string{upstreamkit.AccountScope},
			OAuth: upstreamkit.OAuthEndpoints{
				Issuer:                    base,
				AuthorizationEndpoint:     base + "/oauth/authorize",
				TokenEndpoint:             base + "/oauth/token",
				RevocationEndpoint:        revoke,
				CascadeRevocationEndpoint: cascade,
			},
		})
	})

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeVerifyJSON(w, map[string]any{
			"code_challenge_methods_supported": []string{"S256"},
			"response_types_supported":         []string{"code"},
		})
	})

	// Everything else is answered from the table, so a probe can place a
	// deliberately non-compliant handler at one URL and a decoy at another.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.hits[r.URL.Path]++
		status, ok := v.statuses[r.URL.Path]
		v.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
	})
	return mux
}

func startVerifySource(t *testing.T, v *verifySource) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(v.handler())
	t.Cleanup(srv.Close)
	return srv
}

// compliantStatuses is the baseline a source must answer to pass the suite
// without a token: unknown clients refused, bogus grants refused, and revocation
// refusing an unauthenticated caller.
func compliantStatuses() map[string]int {
	return map[string]int{
		"/oauth/authorize": http.StatusBadRequest,
		"/oauth/token":     http.StatusBadRequest,
		"/oauth/revoke":    http.StatusUnauthorized,
	}
}

func runVerifyConformance(t *testing.T, target string) []conformance.Finding {
	t.Helper()
	return conformance.Run(context.Background(), target, conformance.Options{})
}

func hasError(findings []conformance.Finding, check string) (string, bool) {
	for _, f := range findings {
		if f.Check == check && f.Level == conformance.LevelError {
			return f.Message, true
		}
	}
	return "", false
}

func hasAnyError(findings []conformance.Finding) bool {
	for _, f := range findings {
		if f.Level == conformance.LevelError {
			return true
		}
	}
	return false
}

func describeVerify(findings []conformance.Finding) string {
	b, _ := json.Marshal(findings)
	return string(b)
}

func writeVerifyJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
