//go:build audit5

// Package verifyperf holds the adversarial-verification probes for
// docs/audit-5/findings/performance.md (PERF-1 … PERF-12).
//
// It is a test-only package (no non-test files), so it does not enter any
// production import graph. Every probe here exists to REFUTE a claim in that
// report, so the informative outcomes are the ones that disagree with it:
//
//   - TestVerifyInFlightAttribution: is PERF-1's "5.8 MB of live heap per
//     in-flight raw request" actually attributable to that request, or is it a
//     process-wide number divided by the request count? It measures the same
//     parked state at four concurrency levels and at four body sizes, so the
//     per-request term and any fixed term separate.
//   - TestVerifyRawPathRefreshesSequentially: does a single raw proxy request
//     really make four sequential outbound calls (PERF-2's 20 s x 4 = 80 s)?
//     A slow-but-answering upstream makes the multiplication visible in wall
//     time instead of arguing about it.
package verifyperf

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"runtime/debug"
	"sort"
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

const (
	verifyIssuer   = "https://auth.test"
	verifyGame     = "phigros"
	verifySource   = "phigros-official"
	verifyResource = "score"
	verifyScope    = "phigros.score.read"
	verifyClientID = "probe-app"
	verifySecret   = "s3cret"
	verifyRedirect = "https://app.example/cb"
	verifyVerifier = "verifier-verifier-verifier-verifier-verifier"
	verifySubject  = "usr_probe"

	// maxBody mirrors internal/federation's unexported cap, so a fixture body
	// that the proxy would refuse is a fixture failure rather than a 502.
	maxBody = 4 << 20
)

// discardWriter throws the response away, so a measurement sees what the server
// allocated rather than what the harness buffered.
type discardWriter struct {
	header http.Header
	status int
	bytes  int64
}

func newDiscardWriter() *discardWriter {
	return &discardWriter{header: make(http.Header), status: http.StatusOK}
}

func (w *discardWriter) Header() http.Header         { return w.header }
func (w *discardWriter) WriteHeader(status int)      { w.status = status }
func (w *discardWriter) Flush()                      {}
func (w *discardWriter) Write(p []byte) (int, error) { w.bytes += int64(len(p)); return len(p), nil }

// exactJSONBody builds valid JSON of exactly n bytes.
func exactJSONBody(n int) []byte {
	const prefix = `{"pad":"`
	const suffix = `"}`
	return []byte(prefix + strings.Repeat("x", n-len(prefix)-len(suffix)) + suffix)
}

// readAllCap reports the []byte io.ReadAll actually ends up holding for this
// body. It is the intrinsic per-request buffer, independent of any measurement,
// and it is what the in-flight number has to be compared against.
func readAllCap(body []byte) (length, capacity int) {
	b, err := io.ReadAll(io.LimitReader(bytes.NewReader(body), maxBody+1))
	if err != nil {
		panic(err)
	}
	return len(b), cap(b)
}

// --- gated upstream -------------------------------------------------------

// blockingBody delivers its bytes and then parks until released, so N requests
// can all be held inside the proxy holding their whole buffer at once.
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

type gatedDoer struct {
	body    []byte
	bodies  chan *blockingBody
	release chan struct{}
}

func newGatedDoer(n int, body []byte) *gatedDoer {
	return &gatedDoer{body: body, bodies: make(chan *blockingBody, n), release: make(chan struct{})}
}

func (d *gatedDoer) Do(req *http.Request) (*http.Response, error) {
	b := &blockingBody{data: d.body, reached: make(chan struct{}), release: d.release}
	d.bodies <- b
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	return &http.Response{StatusCode: http.StatusOK, Header: h, Body: b, Request: req}, nil
}

// stubDoer answers immediately with the whole body, so a request's upstream read
// completes before the response is written.
type stubDoer struct {
	body []byte
}

func (d *stubDoer) Do(req *http.Request) (*http.Response, error) {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(d.body)),
		Request:    req,
	}, nil
}

// --- environment ----------------------------------------------------------

type envConfig struct {
	src        federation.Source
	secret     string
	binding    federation.Binding
	doer       httpclient.Doer
	httpClient *http.Client
	scopes     []string
	// maxBufferedBytes is the data plane's joint buffer budget. Zero takes the
	// service default (64 MiB); a probe that deliberately parks MANY large bodies
	// at once has to say so, because the default would shed it (that is the
	// property P0-3 added — see internal/zzprobe/federation/zzprobe_p03_test.go).
	// Since Z09-4 the joint budget is also divided per caller
	// (max(2*maxBody, limit/4)), so a probe that parks everything under ONE
	// subject has to clear that share as well as the global limit.
	maxBufferedBytes int
}

type env struct {
	handler http.Handler
	token   string
	store   *memory.OIDCStore
	fed     federation.Service
}

func newEnv(tb testing.TB, cfg envConfig) *env {
	tb.Helper()
	// The access log writes a line per request and has its own test.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	metrics := observability.New()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient(verifyClientID, "Probe", oauth.ClientConfidential, verifySecret,
		[]string{verifyRedirect},
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
		Issuer:        verifyIssuer,
		Storage:       store,
		CryptoKey:     verifyCryptoKey(),
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

	registry, err := federation.NewRegistry(cfg.src)
	if err != nil {
		tb.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	if err := bindings.Put(ctx, cfg.binding); err != nil {
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
	if err := vaultSvc.Enroll(ctx, federation.BindingIdentity(cfg.binding), []byte(cfg.secret),
		map[string]string{"game": cfg.binding.Game, "source": cfg.binding.Source}); err != nil {
		tb.Fatal(err)
	}

	fed, err := federation.NewService(federation.Config{
		Registry:   registry,
		Bindings:   bindings,
		Flows:      federation.NewMemoryBindFlowStore(),
		Vault:      vaultSvc,
		Doer:       cfg.doer,
		HTTPClient: cfg.httpClient,
		BaseURL:    verifyIssuer,
		Metrics:    metrics,
		// Explicit, because this probe measures what the buffering costs: it parks
		// up to 32 x 4 MiB at once on purpose, which the shipped budget would shed.
		MaxBufferedBytes: cfg.maxBufferedBytes,
	})
	if err != nil {
		tb.Fatal(err)
	}

	api, err := httpapi.New(httpapi.Config{
		Issuer:            verifyIssuer,
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

	return &env{handler: handler, token: codeFlow(tb, handler, store, cfg.scopes), store: store, fed: fed}
}

func verifyCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

func codeFlow(tb testing.TB, handler http.Handler, store *memory.OIDCStore, scopes []string) string {
	tb.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {verifyClientID},
		"redirect_uri":          {verifyRedirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"st"},
		"code_challenge":        {pkce(verifyVerifier)},
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
	if err := store.CompleteLogin(context.Background(), id, verifySubject, scopes); err != nil {
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
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {verifyClientID},
		"client_secret": {verifySecret},
		"redirect_uri":  {verifyRedirect},
		"code_verifier": {verifyVerifier},
	}
	rec = httptest.NewRecorder()
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
	if tok.AccessToken == "" {
		tb.Fatal("the code exchange returned no access token")
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

func rawSource(rawBase string) federation.Source {
	return federation.Source{
		Game: verifyGame, Name: verifySource, DisplayName: "Phigros (official)",
		Issuer: "https://upstream.example", TokenClass: "revocable", RawBase: rawBase,
		Resources: []federation.Resource{{Name: verifyResource, Schema: "phigros.score/1", Scope: verifyScope}},
	}
}

func bearerBinding() federation.Binding {
	return federation.Binding{
		User: verifySubject, Game: verifyGame, Source: verifySource,
		TokenType: "bearer", Expiry: time.Now().Add(time.Hour), Version: 1,
	}
}

func rawRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet,
		"/v1/games/"+verifyGame+"/sources/"+verifySource+"/raw/big", nil)
}

// --- PERF-1: is the in-flight number attributable to the request? ----------

// TestVerifyInFlightAttribution re-runs PERF-1's measurement, but varies the
// concurrency and the body size so the per-request term and any process-wide
// fixed term separate.
//
// PERF-1's arithmetic multiplies one measured number by a concurrency cap. That
// is only sound if the number is linear in the request count AND in body size.
// The report's probe cannot show either: it only ever runs 32 requests at one
// body size and divides.
func TestVerifyInFlightAttribution(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}

	// What io.ReadAll holds for a body of this size, measured without any
	// handler, runtime or goroutine in the picture.
	for _, size := range []int{64 << 10, 512 << 10, 1 << 20, maxBody - 1024} {
		body := exactJSONBody(size)
		length, capacity := readAllCap(body)
		t.Logf("fixture: body=%8d  io.ReadAll holds len=%d cap=%d (%.2f MiB)", size, length, capacity,
			float64(capacity)/(1<<20))
	}

	type point struct {
		n     int
		body  int
		delta int64
		per   float64
	}

	measure := func(n, bodySize int) point {
		body := exactJSONBody(bodySize)
		gated := newGatedDoer(n, body)
		env := newEnv(t, envConfig{
			src:     rawSource("https://upstream.example/api/v1"),
			secret:  `{"access_token":"upstream-access-token","refresh_token":""}`,
			binding: bearerBinding(),
			doer:    gated,
			scopes:  []string{oauth.ScopeAccountID.String(), verifyScope},
			// Headroom for the sweep's worst point (32 x 4 MiB = 128 MiB): this
			// probe is about what io.ReadAll holds, so the budget under test must
			// not be what ends the measurement. The gated Doer below declares no
			// Content-Length, so every read reserves the full cap. 1 GiB, not the
			// 512 MiB this used to be: Z09-4 also gives each caller a share of
			// max(2*maxBody, limit/4), and all 32 parked bodies belong to one
			// caller, so the share (256 MiB here) must exceed 32 x (4 MiB + 1).
			maxBufferedBytes: 1 << 30,
		})
		req := rawRequest()
		req.Header.Set("Authorization", "Bearer "+env.token)

		runtime.GC()
		var base runtime.MemStats
		runtime.ReadMemStats(&base)

		var wg sync.WaitGroup
		statuses := make([]int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				w := newDiscardWriter()
				env.handler.ServeHTTP(w, req)
				statuses[i] = w.status
			}(i)
		}
		for i := 0; i < n; i++ {
			b := <-gated.bodies
			<-b.reached
		}
		// Two GCs: the first moves sync.Pool contents to the victim cache, the
		// second drops it. One GC leaves pooled buffers counted as live.
		runtime.GC()
		runtime.GC()
		var during runtime.MemStats
		runtime.ReadMemStats(&during)

		close(gated.release)
		wg.Wait()
		for i, status := range statuses {
			if status != http.StatusOK {
				t.Fatalf("request %d answered %d", i, status)
			}
		}
		delta := int64(during.HeapAlloc) - int64(base.HeapAlloc)
		return point{n: n, body: bodySize, delta: delta, per: float64(delta) / float64(n)}
	}

	t.Log("concurrency sweep at body = maxBody-1024 (the report's fixture):")
	var conc []point
	for _, n := range []int{1, 4, 16, 32} {
		p := measure(n, maxBody-1024)
		conc = append(conc, p)
		t.Logf("  n=%3d  live heap delta=%12d  per-request=%9.0f B (%.2f MiB)",
			p.n, p.delta, p.per, p.per/(1<<20))
	}
	// Least squares through the origin over consecutive points gives the marginal
	// per-request cost; the intercept is what a fixed process-wide term would be.
	for i := 1; i < len(conc); i++ {
		slope := float64(conc[i].delta-conc[i-1].delta) / float64(conc[i].n-conc[i-1].n)
		t.Logf("  marginal per added request, n=%d->%d: %.0f B", conc[i-1].n, conc[i].n, slope)
	}

	t.Log("body sweep at n=16 (fixed per-request term vs body term):")
	for _, size := range []int{64 << 10, 512 << 10, 1 << 20, maxBody - 1024} {
		p := measure(16, size)
		_, capacity := readAllCap(exactJSONBody(size))
		t.Logf("  body=%8d  per-request=%9.0f B  io.ReadAll holds=%8d B  ratio=%.2f",
			size, p.per, capacity, p.per/float64(capacity))
	}
}

// topLiveHeap prints the allocations the parked requests are actually holding,
// so "per-request live heap" can be attributed to a call site instead of being
// taken on faith.
func topLiveHeap(t *testing.T, label string, n int) {
	t.Helper()
	var recs []runtime.MemProfileRecord
	for {
		got, ok := runtime.MemProfile(recs, false)
		if ok {
			recs = recs[:got]
			break
		}
		recs = make([]runtime.MemProfileRecord, got+64)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].InUseBytes() > recs[j].InUseBytes() })
	var total int64
	for _, r := range recs {
		total += r.InUseBytes()
	}
	t.Logf("%s: top live heap (%d stacks, total %.1f MiB)", label, len(recs), float64(total)/(1<<20))
	for i := 0; i < 10 && i < len(recs); i++ {
		r := recs[i]
		var sb strings.Builder
		shown := 0
		frames := runtime.CallersFrames(r.Stack())
		for shown < 3 {
			f, more := frames.Next()
			if !strings.Contains(f.Function, "runtime.") && !strings.Contains(f.Function, "testing.") {
				fmt.Fprintf(&sb, "        %s  %s:%d\n", f.Function, f.File, f.Line)
				shown++
			}
			if !more {
				break
			}
		}
		t.Logf("  %10d B in %6d objects:\n%s", r.InUseBytes(), r.InUseObjects(), sb.String())
	}
}

// TestVerifyInFlightWhoHoldsTheBytes attributes PERF-1's number to the code that
// holds it. The report says the bytes are "response buffers"; if the profile
// shows a second copy per request, the number is real but the description (and
// so the proposed fix) is not.
func TestVerifyInFlightWhoHoldsTheBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}
	const n = 8
	// Sample every allocation while the requests are parked, so the profile below
	// accounts for the whole live heap rather than an estimate of it.
	runtime.MemProfileRate = 1
	defer func() { runtime.MemProfileRate = 512 << 10 }()
	body := exactJSONBody(maxBody - 1024)
	gated := newGatedDoer(n, body)
	env := newEnv(t, envConfig{
		src:     rawSource("https://upstream.example/api/v1"),
		secret:  `{"access_token":"upstream-access-token","refresh_token":""}`,
		binding: bearerBinding(),
		doer:    gated,
		scopes:  []string{oauth.ScopeAccountID.String(), verifyScope},
		// 1 GiB, not the 64 MiB default: Z09-4 gives each caller a share of
		// max(2*maxBody, limit/4), and all 8 parked bodies belong to one caller,
		// so the share (256 MiB here) has to exceed 8 x (4 MiB + 1).
		maxBufferedBytes: 1 << 30,
	})
	req := rawRequest()
	req.Header.Set("Authorization", "Bearer "+env.token)

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			env.handler.ServeHTTP(newDiscardWriter(), req)
		}()
	}
	for i := 0; i < n; i++ {
		b := <-gated.bodies
		<-b.reached
	}
	runtime.GC()
	runtime.GC()
	var during runtime.MemStats
	runtime.ReadMemStats(&during)
	t.Logf("body=%d bytes, %d parked requests: live heap +%d bytes = %.0f B/request",
		len(body), n, int64(during.HeapAlloc)-int64(base.HeapAlloc),
		float64(int64(during.HeapAlloc)-int64(base.HeapAlloc))/float64(n))
	topLiveHeap(t, "parked in-flight raw requests", n)

	// A forced GC plus scavenge, which is the only way to know whether the number
	// above is memory the requests are HOLDING or memory the sweeper has not
	// finished releasing. Everything the requests hold survives this; garbage does
	// not.
	debug.FreeOSMemory()
	runtime.GC()
	var swept runtime.MemStats
	runtime.ReadMemStats(&swept)
	t.Logf("after debug.FreeOSMemory + GC: live heap +%d bytes = %.0f B/request  (delta vs plain GC: %.0f B/request)",
		int64(swept.HeapAlloc)-int64(base.HeapAlloc),
		float64(int64(swept.HeapAlloc)-int64(base.HeapAlloc))/float64(n),
		float64(int64(during.HeapAlloc)-int64(swept.HeapAlloc))/float64(n))

	close(gated.release)
	wg.Wait()
}

// blockingWriter parks on the first write and reports how many bytes the handler
// had ready when it did, so a request can be held AFTER its upstream read has
// finished rather than in the middle of it.
type blockingWriter struct {
	header  http.Header
	status  int
	first   []byte
	ready   chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingWriter(release chan struct{}) *blockingWriter {
	return &blockingWriter{header: make(http.Header), status: http.StatusOK, ready: make(chan struct{}), release: release}
}

func (w *blockingWriter) Header() http.Header { return w.header }
func (w *blockingWriter) Flush()              {}
func (w *blockingWriter) WriteHeader(status int) {
	w.status = status
}
func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		w.first = p
		close(w.ready)
		<-w.release
	})
	return len(p), nil
}

// TestVerifyInFlightAfterTheReadIsTheSameQuestion asks the same question as
// PERF-1 at a different parking point: the requests have finished reading the
// upstream body, so nothing is in the middle of io.ReadAll's growth. If the
// per-request number moves here, PERF-1's "5.8 MB of response buffers" is
// really "5.8 MB while a request is mid-read", which is a different (and
// narrower) statement than the one the report makes.
func TestVerifyInFlightAfterTheReadIsTheSameQuestion(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}
	const n = 8
	body := exactJSONBody(maxBody - 1024)
	release := make(chan struct{})
	doer := &stubDoer{body: body}
	env := newEnv(t, envConfig{
		src:     rawSource("https://upstream.example/api/v1"),
		secret:  `{"access_token":"upstream-access-token","refresh_token":""}`,
		binding: bearerBinding(),
		doer:    doer,
		scopes:  []string{oauth.ScopeAccountID.String(), verifyScope},
	})
	req := rawRequest()
	req.Header.Set("Authorization", "Bearer "+env.token)

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var wg sync.WaitGroup
	writers := make([]*blockingWriter, n)
	for i := 0; i < n; i++ {
		writers[i] = newBlockingWriter(release)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			env.handler.ServeHTTP(writers[i], req)
		}(i)
	}
	for i := 0; i < n; i++ {
		<-writers[i].ready
	}
	runtime.GC()
	runtime.GC()
	var during runtime.MemStats
	runtime.ReadMemStats(&during)
	t.Logf("body=%d bytes, %d requests parked in the response write (read complete): "+
		"live heap +%d = %.0f B/request; the bytes handed to Write are %d",
		len(body), n, int64(during.HeapAlloc)-int64(base.HeapAlloc),
		float64(int64(during.HeapAlloc)-int64(base.HeapAlloc))/float64(n), len(writers[0].first))

	close(release)
	wg.Wait()
}

// --- PERF-2: four sequential outbound calls per raw request? --------------

// TestVerifyRawPathRefreshAmplification makes the multiplication in PERF-2
// visible: an upstream that answers slowly (but always answers) and rejects the
// resource read with 401 turns one client request into however many sequential
// outbound round trips the code really performs. Each of them is bounded by the
// outbound client's own timeout in production (20 s, cmd/re0auth/main.go), so
// the wall time here is the count that matters.
func TestVerifyRawPathRefreshAmplification(t *testing.T) {
	if testing.Short() {
		t.Skip("perf probe: skipped under -short")
	}
	const upstreamDelay = 120 * time.Millisecond

	var mu sync.Mutex
	var calls []string
	var sawBasic atomic.Bool

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			sawBasic.Store(true)
		}
		start := time.Now()
		time.Sleep(upstreamDelay)
		mu.Lock()
		calls = append(calls, fmt.Sprintf("%-22s %s  (took %s)", r.Method+" "+r.URL.Path,
			map[bool]string{true: "TokenEndpoint", false: "resource"}[r.URL.Path == "/oauth/token"],
			time.Since(start).Round(time.Millisecond)))
		mu.Unlock()
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"at2","refresh_token":"rt2","token_type":"Bearer","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_token"}`)
	}))
	defer up.Close()

	doer := &http.Client{Transport: up.Client().Transport, Timeout: 20 * time.Second}
	src := rawSource(up.URL + "/api")
	src.Issuer = up.URL
	src.ClientID = "upstream-client"
	src.ClientSecret = "upstream-secret"
	src.TokenEndpoint = up.URL + "/oauth/token"

	// The binding is already past its expiry, so the proactive refresh fires
	// first; the 401 on the resource read then forces the reactive one.
	binding := bearerBinding()
	binding.HasRefresh = true
	binding.Expiry = time.Now().Add(-time.Minute)

	env := newEnv(t, envConfig{
		src:        src,
		secret:     `{"access_token":"at1","refresh_token":"rt1"}`,
		binding:    binding,
		doer:       doer,
		httpClient: doer,
		scopes:     []string{oauth.ScopeAccountID.String(), verifyScope},
	})

	req := rawRequest()
	req.Header.Set("Authorization", "Bearer "+env.token)
	start := time.Now()
	w := newDiscardWriter()
	env.handler.ServeHTTP(w, req)
	elapsed := time.Since(start)

	mu.Lock()
	got := append([]string(nil), calls...)
	mu.Unlock()

	t.Logf("client request finished in %s with status %d (upstream answers after %s each)",
		elapsed.Round(time.Millisecond), w.status, upstreamDelay)
	for i, c := range got {
		t.Logf("  outbound call %d: %s", i+1, c)
	}
	t.Logf("upstream saw %d calls; basic auth used somewhere = %v", len(got), sawBasic.Load())

	// Non-vacuous: the fixture must really have driven the refresh path, or the
	// count below means nothing.
	if len(got) < 3 {
		t.Fatalf("only %d outbound calls: the probe did not reach the refresh path "+
			"(expected the proactive refresh, the resource read, the forced refresh and "+
			"the retry)", len(got))
	}
	// The ceiling the report quotes is "one call per outbound deadline, times the
	// number of calls, and they are serial". Serial means wall time is the sum.
	if elapsed < time.Duration(len(got))*upstreamDelay*8/10 {
		t.Fatalf("wall time %s is much less than %d sequential %s delays: the calls are not serial "+
			"or the fixture is not measuring them", elapsed, len(got), upstreamDelay)
	}
}
