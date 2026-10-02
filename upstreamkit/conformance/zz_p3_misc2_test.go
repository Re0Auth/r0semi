package conformance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// zzSource serves a source whose discovery document advertises whatever oauth
// returns for the given issuer, and counts requests per path.
//
// The advertised values are absolute URLs on purpose: that is the shape
// docs/upstream-protocol.md §4 requires, and the whole point of these probes is
// that the suite must call the advertised URL rather than assume a path on the
// target.
func zzSource(
	t *testing.T,
	oauth func(issuer string) map[string]any,
	metadata http.HandlerFunc,
	routes map[string]http.HandlerFunc,
) (*httptest.Server, func(path string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/re0auth-upstream", func(w http.ResponseWriter, r *http.Request) {
		disc := map[string]any{
			"re0auth_upstream_version": 1,
			"game":                     "phigros",
			"source":                   "fake",
			"display_name":             "Fake Backend",
			"oauth":                    oauth("http://" + r.Host),
			"token_class":              "revocable",
			"scopes_supported":         []string{"account.read"},
			"resources":                []any{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(disc)
	})
	if metadata == nil {
		metadata = func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code_challenge_methods_supported": []string{"S256"},
				"response_types_supported":         []string{"code"},
			})
		}
	}
	mux.HandleFunc("/.well-known/oauth-authorization-server", metadata)
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	})
	// Everything else is counted, then dispatched to routes or answered 404.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[path]
	}
}

func zzUnauthorized(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }

func hasWarning(findings []Finding, check string) bool {
	for _, f := range findings {
		if f.Check == check && f.Level == LevelWarning {
			return true
		}
	}
	return false
}

func zzOAuth(issuer string) map[string]any {
	return map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"revocation_endpoint":    issuer + "/oauth/revoke",
	}
}

// Z14-V1, red 1: the suite used to POST the literal path "/oauth/revoke" on the
// target, ignoring disc.OAuth.RevocationEndpoint entirely. A source that
// advertises its revocation endpoint at another path — which the discovery
// document allows and Re0Auth honours — was therefore judged at a path it never
// advertised, and reported as missing the endpoint it does serve.
func TestZ14_V1TheAdvertisedRevocationEndpointIsUsed(t *testing.T) {
	srv, hits := zzSource(t, func(issuer string) map[string]any {
		oauth := zzOAuth(issuer)
		oauth["revocation_endpoint"] = issuer + "/oauth/revoke-v2"
		return oauth
	}, nil, map[string]http.HandlerFunc{
		// The path the suite used to assume; it does not exist here.
		"/oauth/revoke": func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		// The advertised endpoint: present and authenticating.
		"/oauth/revoke-v2": zzUnauthorized,
	})

	findings := Run(context.Background(), srv.URL, Options{})
	if got := hits("/oauth/revoke-v2"); got != 1 {
		t.Errorf("the advertised revocation endpoint was contacted %d times, want 1: the suite must "+
			"probe the URL the document names, not a path on the target", got)
	}
	if got := hits("/oauth/revoke"); got != 0 {
		t.Errorf("the target's /oauth/revoke was contacted %d times even though the document does not "+
			"advertise it", got)
	}
	if hasError(findings, "revoke.present") {
		t.Errorf("a source that advertises its revocation endpoint at %s/oauth/revoke-v2 was reported "+
			"missing: %+v", srv.URL, findings)
	}
}

// Z14-V1, red 3: a value that is not a URL cannot be called by anyone, so it is
// an error. The discovery check only required the field to be non-empty, so
// "not-a-url" passed the whole suite while internal/federation hands the string
// to http.NewRequestWithContext and fails at use time.
func TestZ14_V1GarbageRevocationEndpointIsAnError(t *testing.T) {
	srv, _ := zzSource(t, func(issuer string) map[string]any {
		oauth := zzOAuth(issuer)
		oauth["revocation_endpoint"] = "not-a-url"
		return oauth
	}, nil, nil)

	findings := Run(context.Background(), srv.URL, Options{})
	if !hasError(findings, "revoke.absolute") {
		t.Errorf("a revocation_endpoint that is not an absolute URL was accepted: %+v", findings)
	}
}

// Z14-V1, red 2: the cascade probe asserted that the advertised endpoint was
// absolute and then threw the origin away, POSTing to the target at the same
// path. A decoy on the target was judged instead of the advertised endpoint —
// so an endpoint that answers 200 to anyone (the "ends every session" shape)
// passed, and a compliant endpoint on another host was never contacted, even
// though Re0Auth calls exactly the advertised URL.
func TestZ14_V1TheAdvertisedCascadeEndpointIsUsedEvenOnAnotherOrigin(t *testing.T) {
	var cascadeHits atomic.Int32
	cascade := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cascadeHits.Add(1)
		// "Open": it accepts a caller it authenticated nobody for.
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(cascade.Close)

	srv, hits := zzSource(t, func(issuer string) map[string]any {
		oauth := zzOAuth(issuer)
		oauth["cascade_revocation_endpoint"] = cascade.URL + "/cascade"
		return oauth
	}, nil, map[string]http.HandlerFunc{
		"/oauth/revoke": zzUnauthorized,
		// The decoy on the target at the advertised path: it authenticates, which
		// is what made the old code report PASS.
		"/cascade": zzUnauthorized,
	})

	findings := Run(context.Background(), srv.URL, Options{})
	if got := cascadeHits.Load(); got != 1 {
		t.Errorf("the advertised cascade endpoint was contacted %d times, want 1: the suite judged the "+
			"target's own %s/cascade instead of the URL the document names", got, srv.URL)
	}
	if !hasError(findings, "cascade.requires_auth") {
		t.Errorf("an advertised cascade endpoint that answered 200 to an unauthenticated caller was not "+
			"flagged: %+v", findings)
	}
	_ = hits
}

// Z14-V1 control: the advertised URL being honoured must not turn every
// compliant source red. A same-origin advertised cascade endpoint that refuses
// the unauthenticated probe is still contacted exactly once and is not flagged.
func TestZ14_V1ControlASameOriginAdvertisedCascadeIsStillProbed(t *testing.T) {
	srv, hits := zzSource(t, func(issuer string) map[string]any {
		oauth := zzOAuth(issuer)
		oauth["cascade_revocation_endpoint"] = issuer + "/oauth/cascade_revocation"
		return oauth
	}, nil, map[string]http.HandlerFunc{
		"/oauth/revoke":             zzUnauthorized,
		"/oauth/cascade_revocation": zzUnauthorized,
	})

	findings := Run(context.Background(), srv.URL, Options{})
	if got := hits("/oauth/cascade_revocation"); got != 1 {
		t.Errorf("the advertised cascade endpoint was contacted %d times, want 1", got)
	}
	for _, f := range findings {
		if f.Level == LevelError {
			t.Errorf("a compliant source with a same-origin cascade endpoint was flagged: %+v", f)
		}
	}
}

// S06-6: checkOAuthMetadata returned on a non-200 status before its
// `defer closeBody(resp)`, so the body of a metadata document the server refused
// to serve was never closed — one leaked connection per run, held for as long as
// the client lives.
//
// The probe wraps the transport and counts bodies that were never closed, so it
// observes the leak itself rather than inferring it from the source. The warning
// assertion pins that the non-200 branch is the one that ran: without it, a probe
// that never reached the branch would pass vacuously.
func TestS06_6TheMetadataBodyIsClosedWhenTheDocumentIsNotOK(t *testing.T) {
	srv, _ := zzSource(t, zzOAuth, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no metadata for you", http.StatusNotFound)
	}, map[string]http.HandlerFunc{
		"/oauth/revoke": zzUnauthorized,
	})

	tracker := &zzBodyTracker{base: http.DefaultTransport}
	hc := &http.Client{Transport: tracker, Timeout: 10 * time.Second}

	findings := Run(context.Background(), srv.URL, Options{HTTPClient: hc})
	if !hasWarning(findings, "oauth.metadata") {
		t.Fatalf("setup: the non-200 metadata branch did not run: %+v", findings)
	}
	if total, open := tracker.counts(); open != 0 {
		t.Errorf("%d of %d response bodies were never closed; the non-200 metadata document's body is "+
			"the one this probe exists for", open, total)
	}
}

// zzBodyTracker wraps a RoundTripper and counts response bodies that were handed
// out versus closed.
type zzBodyTracker struct {
	base http.RoundTripper

	mu    sync.Mutex
	total int
	open  int
}

func (t *zzBodyTracker) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	t.mu.Lock()
	t.total++
	t.open++
	t.mu.Unlock()
	resp.Body = &zzTrackedBody{ReadCloser: resp.Body, tracker: t}
	return resp, nil
}

func (t *zzBodyTracker) counts() (total, open int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total, t.open
}

type zzTrackedBody struct {
	io.ReadCloser
	tracker *zzBodyTracker
	once    sync.Once
}

func (b *zzTrackedBody) Close() error {
	b.once.Do(func() {
		b.tracker.mu.Lock()
		b.tracker.open--
		b.tracker.mu.Unlock()
	})
	return b.ReadCloser.Close()
}
