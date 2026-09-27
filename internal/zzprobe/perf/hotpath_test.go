//go:build audit5

package perf

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

// These probes measure the request paths the repository's own benchmarks do not:
// the token endpoint (no benchmark covers token minting), the data plane's
// normalized and raw proxy paths (4MiB bodies, a vault read and an audit append
// each), a 404 and a probe. Each one is driven through the composed handler, so
// the measurement includes the whole middleware chain.
//
// Allocations are what these measure, not nanoseconds: the machine running this
// audit is shared with a dozen other builds, so ns/op here is noise while B/op and
// allocs/op are structure.

const (
	probeIssuer     = "https://auth.test"
	probeGame       = "phigros"
	probeSource     = "phigros-official"
	probeResource   = "score"
	probeScope      = "phigros.score.read"
	probeClientID   = "probe-app"
	probeSecret     = "s3cret"
	probeRedirect   = "https://app.example/cb"
	probeVerifier   = "verifier-verifier-verifier-verifier-verifier"
	probeSubject    = "usr_probe"
	probeUpstreamAt = `{"access_token":"upstream-access-token","refresh_token":""}`
)

// discardWriter is an http.ResponseWriter that throws the response away, so B/op
// measures what the *server* allocated rather than what the harness buffered. The
// standard recorder holds the whole response, which for the raw proxy is the 4MiB
// this probe is trying to attribute.
type discardWriter struct {
	header http.Header
	status int
	bytes  int64
}

func newDiscardWriter() *discardWriter {
	return &discardWriter{header: make(http.Header), status: http.StatusOK}
}

func (w *discardWriter) Header() http.Header { return w.header }

func (w *discardWriter) WriteHeader(status int) { w.status = status }

func (w *discardWriter) Write(p []byte) (int, error) {
	w.bytes += int64(len(p))
	return len(p), nil
}

// Flush keeps the compression middleware's http.Flusher assertion satisfied.
func (w *discardWriter) Flush() {}

func (w *discardWriter) reset(status int) {
	w.status = status
	w.bytes = 0
	for k := range w.header {
		delete(w.header, k)
	}
}

// stubDoer stands in for an upstream source. It replays one canned body without a
// network, so the measurement is the proxy's own cost.
type stubDoer struct {
	body  []byte
	calls atomic.Int64
}

func (d *stubDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls.Add(1)
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(d.body)),
		Request:    req,
	}, nil
}

type probeEnv struct {
	handler http.Handler
	token   string
	basic   string
	store   *memory.OIDCStore
}

// bodyOf builds a JSON body of roughly size bytes, shaped like a source payload.
func bodyOf(tb testing.TB, size int) []byte {
	tb.Helper()
	row := `{"id":123456789,"score":1000000,"acc":98.7654,"fc":true,"level":"IN 15"}`
	if size < len(row)+4 {
		size = len(row) + 4
	}
	var b bytes.Buffer
	b.WriteString(`{"items":[`)
	for b.Len() < size-4 {
		b.WriteString(row)
		b.WriteByte(',')
	}
	b.WriteString(`{}]}`)
	if b.Len() > maxUpstreamBodyOfInterest {
		tb.Fatalf("fixture body = %d bytes, past the proxy's own cap", b.Len())
	}
	return b.Bytes()
}

// maxUpstreamBodyOfInterest is federation maxBody, mirrored here so a fixture that
// would be refused is a fixture failure rather than a 502.
const maxUpstreamBodyOfInterest = 4 << 20

// exactJSONBody builds valid JSON of exactly n bytes, so a body just under the
// proxy's cap can be replayed.
func exactJSONBody(n int) []byte {
	const prefix = `{"pad":"`
	const suffix = `"}`
	if n < len(prefix)+len(suffix) {
		panic("exactJSONBody: size too small")
	}
	return []byte(prefix + strings.Repeat("x", n-len(prefix)-len(suffix)) + suffix)
}

// newProbeEnv composes the server the way cmd/re0auth does, with the in-memory
// stores and one configured, bound upstream source.
func newProbeEnv(tb testing.TB, upstreamBody []byte) *probeEnv {
	tb.Helper()
	return newProbeEnvWithDoer(tb, &stubDoer{body: upstreamBody})
}

// blockingBody delivers its bytes and then parks, so every request reading it
// holds its whole buffer at once. That is what makes an in-flight measurement
// possible: N requests are all inside the proxy, each having read the body, and
// the live heap can be read while they wait.
type blockingBody struct {
	data     []byte
	off      int
	reached  chan struct{}
	release  chan struct{}
	signaled bool
}

func (b *blockingBody) Read(p []byte) (int, error) {
	if b.off < len(b.data) {
		n := copy(p, b.data[b.off:])
		b.off += n
		if b.off == len(b.data) && !b.signaled {
			b.signaled = true
			close(b.reached)
		}
		return n, nil
	}
	<-b.release
	return 0, io.EOF
}

func (b *blockingBody) Close() error { return nil }

// gatedDoer answers every upstream read with the same body and hands the test a
// handle on each one, so it can wait until every request holds its buffer and then
// release them together.
type gatedDoer struct {
	body    []byte
	bodies  chan *blockingBody
	release chan struct{}
}

func newGatedDoer(n int, body []byte) *gatedDoer {
	return &gatedDoer{
		body:    body,
		bodies:  make(chan *blockingBody, n),
		release: make(chan struct{}),
	}
}

func (d *gatedDoer) Do(req *http.Request) (*http.Response, error) {
	b := &blockingBody{data: d.body, reached: make(chan struct{}), release: d.release}
	d.bodies <- b
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     h,
		Body:       b,
		Request:    req,
	}, nil
}

func newProbeEnvWithDoer(tb testing.TB, doer httpclient.Doer) *probeEnv {
	tb.Helper()
	// The access log writes a line per request, which at these iteration counts
	// buries the measurements. It has its own test.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	metrics := observability.New()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient(probeClientID, "Probe", oauth.ClientConfidential, probeSecret,
		[]string{probeRedirect},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		tb.Fatal(err)
	}
	if err := clients.Create(ctx, client); err != nil {
		tb.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("probe", key),
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		tb.Fatal(err)
	}
	op, err := oidchttp.New(oidchttp.Config{
		Issuer:        probeIssuer,
		Storage:       store,
		CryptoKey:     probeCryptoKey(),
		CryptoKeyID:   "probe",
		AllowInsecure: false,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
		Metrics:       metrics,
	})
	if err != nil {
		tb.Fatal(err)
	}

	// One active source declaring the resource the probe token is scoped for.
	registry, err := federation.NewRegistry(federation.Source{
		Game: probeGame, Name: probeSource, DisplayName: "Phigros (official)",
		Issuer:     "https://upstream.example",
		TokenClass: "bearer",
		RawBase:    "https://upstream.example/api/v1",
		Resources: []federation.Resource{
			{Name: probeResource, Schema: "phigros.score/1", Scope: probeScope},
		},
	})
	if err != nil {
		tb.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	binding := federation.Binding{
		User: probeSubject, Game: probeGame, Source: probeSource,
		TokenType: "bearer", Expiry: time.Now().Add(time.Hour), Version: 1,
	}
	if err := bindings.Put(ctx, binding); err != nil {
		tb.Fatal(err)
	}

	wrapper, err := vault.NewLocalKeyWrapper("probe", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		tb.Fatal(err)
	}
	vaultSvc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		tb.Fatal(err)
	}
	if err := vaultSvc.Enroll(ctx, federation.BindingIdentity(binding), []byte(probeUpstreamAt),
		map[string]string{"game": probeGame, "source": probeSource}); err != nil {
		tb.Fatal(err)
	}

	fed, err := federation.NewService(federation.Config{
		Registry: registry,
		Bindings: bindings,
		Flows:    federation.NewMemoryBindFlowStore(),
		Vault:    vaultSvc,
		Doer:     doer,
		BaseURL:  probeIssuer,
		Metrics:  metrics,
	})
	if err != nil {
		tb.Fatal(err)
	}

	api, err := httpapi.New(httpapi.Config{
		Issuer:            probeIssuer,
		OIDC:              op,
		TokenIntrospector: op,
		GrantStore:        store,
		DeviceStore:       store,
		Federation:        fed,
		Accounts:          account.NewMemoryStore(),
		Metrics:           metrics,
	})
	if err != nil {
		tb.Fatal(err)
	}
	handler := api.Handler()

	token := probeCodeFlow(tb, handler, store)
	return &probeEnv{
		handler: handler,
		token:   token,
		basic:   "Basic " + base64.StdEncoding.EncodeToString([]byte(probeClientID+":"+probeSecret)),
		store:   store,
	}
}

func probeCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

// probeCodeFlow drives authorize → login → callback → token once and returns the
// access token. It is how the probe gets a bearer token the server really issued,
// scoped for the data plane.
func probeCodeFlow(tb testing.TB, handler http.Handler, store *memory.OIDCStore) string {
	tb.Helper()
	scopes := []string{oauth.ScopeAccountID.String(), probeScope}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {probeClientID},
		"redirect_uri":          {probeRedirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"st"},
		"code_challenge":        {pkce(probeVerifier)},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		tb.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	id := mustURL(tb, rec.Header().Get("Location")).Query().Get("authRequestID")
	if id == "" {
		tb.Fatalf("no authRequestID in %q", rec.Header().Get("Location"))
	}
	if err := store.CompleteLogin(context.Background(), id, probeSubject, scopes); err != nil {
		tb.Fatal(err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	if rec.Code != http.StatusFound {
		tb.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	code := mustURL(tb, rec.Header().Get("Location")).Query().Get("code")
	if code == "" {
		tb.Fatalf("no code in %q", rec.Header().Get("Location"))
	}
	token := probeExchange(tb, handler, code)
	if token == "" {
		tb.Fatal("the code exchange returned no access token")
	}
	return token
}

// probeMintCode runs the authorize half of the flow and returns the code a
// subsequent token request can exchange.
func probeMintCode(tb testing.TB, handler http.Handler, store *memory.OIDCStore) string {
	tb.Helper()
	scopes := []string{oauth.ScopeAccountID.String()}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {probeClientID},
		"redirect_uri":          {probeRedirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"st"},
		"code_challenge":        {pkce(probeVerifier)},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		tb.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	id := mustURL(tb, rec.Header().Get("Location")).Query().Get("authRequestID")
	if err := store.CompleteLogin(context.Background(), id, probeSubject, scopes); err != nil {
		tb.Fatal(err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	if rec.Code != http.StatusFound {
		tb.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	return mustURL(tb, rec.Header().Get("Location")).Query().Get("code")
}

func probeExchange(tb testing.TB, handler http.Handler, code string) string {
	tb.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {probeClientID},
		"client_secret": {probeSecret},
		"redirect_uri":  {probeRedirect},
		"code_verifier": {probeVerifier},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		tb.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		tb.Fatal(err)
	}
	return tok.AccessToken
}

func mustURL(tb testing.TB, raw string) *url.URL {
	tb.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return u
}

func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// --- measurements ---

// TestProbeInFlightBytesPerDataPlaneRequest is the number that decides whether
// docs/capacity-planning.md §3 is true.
//
// That section says a 4MiB response body is the main heap term, but nothing in the
// configuration ties `server.max_in_flight` to it: the cap is derived from the
// database pool (8 × max_conns, i.e. 128 by default), and the only per-body bound
// is federation's 4MiB. This measures the live heap one in-flight proxy request
// costs — with the requests parked inside the upstream read, so nothing is
// garbage — and multiplies it by the default cap.
func TestProbeInFlightBytesPerDataPlaneRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}
	const inFlight = 32
	body := exactJSONBody(maxUpstreamBodyOfInterest - 1024)

	gated := newGatedDoer(inFlight, body)
	env := newProbeEnvWithDoer(t, gated)
	req := httptest.NewRequest(http.MethodGet,
		"/v1/games/"+probeGame+"/sources/"+probeSource+"/raw/big", nil)
	req.Header.Set("Authorization", "Bearer "+env.token)

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var wg sync.WaitGroup
	statuses := make([]int, inFlight)
	for i := 0; i < inFlight; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := newDiscardWriter()
			env.handler.ServeHTTP(w, req)
			statuses[i] = w.status
		}(i)
	}

	// Wait until every request has read its whole upstream body (so every one of
	// them is holding its buffer), then read the live heap while they are parked.
	for i := 0; i < inFlight; i++ {
		b := <-gated.bodies
		<-b.reached
	}
	runtime.GC()
	var during runtime.MemStats
	runtime.ReadMemStats(&during)

	// Release: the second read returns EOF and each request finishes.
	close(gated.releaseAll())

	wg.Wait()
	for i, status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("request %d answered %d", i, status)
		}
	}

	perRequest := float64(int64(during.HeapAlloc)-int64(base.HeapAlloc)) / inFlight
	if perRequest < float64(len(body))/2 {
		t.Fatalf("live heap per in-flight request = %.0f bytes, which is under the %.0f-byte body; "+
			"the probe did not park the requests where it claims to", perRequest, float64(len(body)))
	}
	t.Logf("body=%d bytes; live heap +%d bytes over %d in-flight requests = %.0f bytes/request",
		len(body), int64(during.HeapAlloc)-int64(base.HeapAlloc), inFlight, perRequest)
	for _, cap := range []int{64, 128, 512} {
		t.Logf("  max_in_flight=%3d  ->  %5.0f MiB of live response buffers alone", cap, perRequest*float64(cap)/(1<<20))
	}
}

// releaseAll is a tiny helper so the gated bodies can share one release channel.
func (d *gatedDoer) releaseAll() chan struct{} { return d.release }

// TestProbeHotPathAllocationBudget reports the per-request allocation of every
// path a load balancer or a bot can reach without credentials.
func TestProbeHotPathAllocationBudget(t *testing.T) {
	env := newProbeEnv(t, bodyOf(t, 4096))

	cases := []struct {
		name  string
		build func() *http.Request
	}{
		{"404 (browser plane)", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/nope", nil)
		}},
		{"404 (/v1 subtree)", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/v1/nope", nil)
		}},
		{"/healthz", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/healthz", nil)
		}},
		{"/.well-known/openid-configuration", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
		}},
		{"GET /v1/me (opaque bearer)", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.Header.Set("Authorization", "Bearer "+env.token)
			return req
		}},
		{"GET /v1/me (invalid bearer)", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.Header.Set("Authorization", "Bearer not-a-token")
			return req
		}},
		{"GET /v1/games/phigros/score", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/v1/games/"+probeGame+"/"+probeResource, nil)
			req.Header.Set("Authorization", "Bearer "+env.token)
			return req
		}},
		{"GET /v1/games/.../raw (4KiB)", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet,
				"/v1/games/"+probeGame+"/sources/"+probeSource+"/raw/small", nil)
			req.Header.Set("Authorization", "Bearer "+env.token)
			return req
		}},
	}

	for _, tc := range cases {
		const iterations = 200
		w := newDiscardWriter()
		// Warm up outside the measurement so one-time lazily built state (the
		// discovery cache, a pooled buffer) is not counted as per-request cost.
		env.handler.ServeHTTP(w, tc.build())

		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := 0; i < iterations; i++ {
			w.reset(http.StatusOK)
			env.handler.ServeHTTP(w, tc.build())
		}
		runtime.ReadMemStats(&after)

		t.Logf("%-36s status=%-3d body=%-6d bytes/req=%8.1f allocs/req=%6.1f",
			tc.name, w.status, w.bytes,
			float64(after.TotalAlloc-before.TotalAlloc)/iterations,
			float64(after.Mallocs-before.Mallocs)/iterations)
	}
}

// BenchmarkProbeRawProxy4MiBGzip is the same request from a client that accepts
// gzip, which is every browser. The body crosses the size threshold in one write,
// so the coding is applied streaming — no second buffer, but the whole 4MiB is
// deflated on the request's own goroutine, under the container's 1-CPU limit.
func BenchmarkProbeRawProxy4MiBGzip(b *testing.B) {
	body := exactJSONBody(maxUpstreamBodyOfInterest - 1024)
	env := newProbeEnv(b, body)
	req := httptest.NewRequest(http.MethodGet,
		"/v1/games/"+probeGame+"/sources/"+probeSource+"/raw/big", nil)
	req.Header.Set("Authorization", "Bearer "+env.token)
	req.Header.Set("Accept-Encoding", "gzip")
	w := newDiscardWriter()
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.reset(http.StatusOK)
		env.handler.ServeHTTP(w, req)
		if w.status != http.StatusOK {
			b.Fatalf("status = %d", w.status)
		}
	}
}

// BenchmarkProbeDataPlaneResource is the normalized proxy path: introspection,
// a binding lookup, a vault read (which audits before handing over the
// credential), the upstream fetch, a JSON validity pass over the whole body and
// the response.
func BenchmarkProbeDataPlaneResource(b *testing.B) {
	env := newProbeEnv(b, bodyOf(b, 4096))
	req := httptest.NewRequest(http.MethodGet, "/v1/games/"+probeGame+"/"+probeResource, nil)
	req.Header.Set("Authorization", "Bearer "+env.token)
	w := newDiscardWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.reset(http.StatusOK)
		env.handler.ServeHTTP(w, req)
		if w.status != http.StatusOK {
			b.Fatalf("status = %d", w.status)
		}
	}
}

// BenchmarkProbeRawProxy4MiB is the passthrough path at the size the code allows:
// federation.maxBody is 4MiB, and the handler reads the whole thing before it
// writes any of it.
func BenchmarkProbeRawProxy4MiB(b *testing.B) {
	// Just under the proxy's cap: this is the largest body it will pass through.
	body := exactJSONBody(maxUpstreamBodyOfInterest - 1024)
	env := newProbeEnv(b, body)
	req := httptest.NewRequest(http.MethodGet,
		"/v1/games/"+probeGame+"/sources/"+probeSource+"/raw/big", nil)
	req.Header.Set("Authorization", "Bearer "+env.token)
	w := newDiscardWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.reset(http.StatusOK)
		env.handler.ServeHTTP(w, req)
		if w.status != http.StatusOK {
			b.Fatalf("status = %d", w.status)
		}
	}
}

// BenchmarkProbeTokenExchange measures the one write path no benchmark in the
// repository covers: POST /oauth/token exchanging an authorization code. Codes are
// single-use, so a pool is minted up front and refilled with the timer stopped.
func BenchmarkProbeTokenExchange(b *testing.B) {
	env := newProbeEnv(b, bodyOf(b, 1024))
	const poolSize = 512
	mint := func() []string {
		codes := make([]string, poolSize)
		for i := range codes {
			codes[i] = probeMintCode(b, env.handler, env.store)
		}
		return codes
	}
	codes := mint()
	at := 0
	w := newDiscardWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if at == len(codes) {
			b.StopTimer()
			codes = mint()
			at = 0
			b.StartTimer()
		}
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {codes[at]},
			"client_id":     {probeClientID},
			"client_secret": {probeSecret},
			"redirect_uri":  {probeRedirect},
			"code_verifier": {probeVerifier},
		}
		at++
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w.reset(http.StatusOK)
		env.handler.ServeHTTP(w, req)
		if w.status != http.StatusOK {
			b.Fatalf("token = %d", w.status)
		}
	}
}

// BenchmarkProbeIntrospect is /oauth/introspect measured with a discarding writer,
// so the harness contributes only the form body it has to send.
func BenchmarkProbeIntrospect(b *testing.B) {
	env := newProbeEnv(b, bodyOf(b, 1024))
	form := url.Values{"token": {env.token}}.Encode()
	w := newDiscardWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", env.basic)
		w.reset(http.StatusOK)
		env.handler.ServeHTTP(w, req)
		if w.status != http.StatusOK {
			b.Fatalf("introspect = %d", w.status)
		}
	}
}
