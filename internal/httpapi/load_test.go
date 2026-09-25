package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/oauth"
)

// The capacity profile. The benchmarks next door measure one request at a time and
// report ns/op; this drives the same server through a real network stack with
// several clients at once, and reports what an operator actually asks about: how
// many requests per second, and what the slow tail looks like.
//
// It reports rather than asserts a rate. A capacity gate that fails on a slow
// runner is a gate people delete — the same reasoning `make bench` gives for
// reporting its numbers instead of thresholding them. The one floor it does enforce
// is on its own work (see the end), so a green run can never mean "nothing was
// measured".
//
// Run with: make load
func TestLoadProfile(t *testing.T) {
	if os.Getenv("RE0AUTH_LOAD_PROFILE") == "" {
		t.Skip("set RE0AUTH_LOAD_PROFILE=1 (or run `make load`) to run the capacity profile")
	}
	duration := envPositive(t, "RE0AUTH_LOAD_SECONDS", 10)
	workers := envPositive(t, "RE0AUTH_LOAD_WORKERS", 8)

	// The access log writes a line per request, which at this rate buries the
	// result lines. It has its own test; the numbers are this file's job.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	metrics := observability.New()
	clients := oauth.NewMemoryClientRegistry()
	opHandler, store := newOPBackend(t, testIssuer, clients, nil, metrics)
	api, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Metrics:           metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	const (
		clientID = "load"
		secret   = "s3cret"
	)
	client, err := oauth.NewClient(clientID, "Load", oauth.ClientConfidential, secret,
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
	// A pooled client, which is what this service hands its own adapters.
	//
	// http.DefaultClient keeps only two idle connections per host, so under
	// concurrency most connections are closed at the end of each request instead of
	// being reused — tens of thousands of connections per run, each parked in
	// TIME_WAIT. On Windows that exhausts the ephemeral port range and the *next*
	// run fails with "only one usage of each socket address", which reads like a
	// service failure and is really the harness measuring its own churn. It also
	// depresses the numbers, since reconnecting is most of the request.
	loadClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        workers * 2,
			MaxIdleConnsPerHost: workers,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer loadClient.CloseIdleConnections()
	goroutinesBefore := runtime.NumGoroutine()

	type samples struct {
		mu     sync.Mutex
		read   []time.Duration
		intro  []time.Duration
		errors []string
	}
	all := &samples{}
	record := func(dst *[]time.Duration, d time.Duration) {
		all.mu.Lock()
		*dst = append(*dst, d)
		all.mu.Unlock()
	}
	failed := func(format string, args ...any) {
		all.mu.Lock()
		defer all.mu.Unlock()
		if len(all.errors) < 10 {
			all.errors = append(all.errors, fmt.Sprintf(format, args...))
		}
	}

	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			// Each worker establishes its own session, so the profile covers the
			// code flow as well as the steady state, and no single token entry is
			// the whole workload.
			token, err := loadSession(loadClient, srv.URL, clientID, secret, func(authRequestID string) error {
				return store.CompleteLogin(context.Background(), authRequestID,
					fmt.Sprintf("load-user-%d", worker), []string{"account.id"})
			})
			if err != nil {
				failed("worker %d could not establish a session: %v", worker, err)
				return
			}
			for time.Now().Before(deadline) {
				if d, err := loadRead(loadClient, srv.URL, token); err != nil {
					failed("GET /v1/me: %v", err)
				} else {
					record(&all.read, d)
				}
				if d, err := loadIntrospect(loadClient, srv.URL, basic, token); err != nil {
					failed("POST /oauth/introspect: %v", err)
				} else {
					record(&all.intro, d)
				}
			}
		}(w)
	}
	wg.Wait()

	if len(all.errors) > 0 {
		t.Fatalf("the profile hit errors, so its numbers are not a capacity number:\n%s",
			strings.Join(all.errors, "\n"))
	}

	read := summarise("GET  /v1/me", all.read)
	intro := summarise("POST /oauth/introspect", all.intro)
	total := read.n + intro.n
	if total < 100 {
		t.Fatalf("the profile completed only %d requests in %ds; it measured nothing", total, duration)
	}

	var heap runtime.MemStats
	// Sample after the client's idle connections are gone: each of them holds a
	// reader and a writer goroutine, so a raw count right after the run reports the
	// connection pool rather than anything the server kept.
	loadClient.CloseIdleConnections()
	time.Sleep(50 * time.Millisecond)
	runtime.ReadMemStats(&heap)

	granularity := clockGranularity()
	clock := ">1ms"
	if granularity > 0 {
		clock = granularity.Round(time.Microsecond).String()
	}
	caveat := ""
	if granularity == 0 || granularity > 100*time.Microsecond {
		caveat = "\n  clock: this machine cannot resolve a request, so the latencies above are quantized (0 means \"below one tick\").\n" +
			"  Read the Linux CI job for the tail numbers; the throughput and the goroutine figures are unaffected."
	}
	report := fmt.Sprintf(`capacity profile: %d workers, %ds, %d requests, %.1f req/s
%s
%s
  goroutines %d -> %d, heap %.1f MiB, clock %s, GOMAXPROCS %d%s`,
		workers, duration, total, float64(total)/float64(duration),
		read.line(granularity), intro.line(granularity),
		goroutinesBefore, runtime.NumGoroutine(),
		float64(heap.HeapAlloc)/(1<<20), clock, runtime.GOMAXPROCS(0), caveat)

	fmt.Println(report)
	t.Log("\n" + report)
	// The numbers belong in the job summary too, so a run that is only read from
	// the CI UI still shows what it measured.
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err == nil {
			_, _ = fmt.Fprintf(f, "```\n%s\n```\n", report)
			_ = f.Close()
		}
	}
}

type profileRow struct {
	name string
	n    int
	p50  time.Duration
	p95  time.Duration
	p99  time.Duration
	max  time.Duration
}

func (r profileRow) line(granularity time.Duration) string {
	return fmt.Sprintf("  %-22s n=%-7d p50=%-9s p95=%-9s p99=%-9s max=%-9s",
		r.name, r.n,
		format(r.p50, granularity), format(r.p95, granularity),
		format(r.p99, granularity), format(r.max, granularity))
}

func summarise(name string, latencies []time.Duration) profileRow {
	row := profileRow{name: name, n: len(latencies)}
	if len(latencies) == 0 {
		return row
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	row.p50 = percentOf(latencies, 0.50)
	row.p95 = percentOf(latencies, 0.95)
	row.p99 = percentOf(latencies, 0.99)
	row.max = latencies[len(latencies)-1]
	return row
}

// clockGranularity estimates the smallest interval this machine's monotonic clock
// can distinguish, and returns 0 when even a millisecond of sleep does not move it.
//
// This is not academic: a Windows host without a fine-grained timer source ticks at
// milliseconds, so every request faster than a tick measures as exactly zero and the
// rest are quantized to it. That produces a table of zeros that reads like a
// result. The figure is reported alongside the profile so nobody mistakes one for
// the other, and the CI job (Linux) is where the tail numbers are real.
func clockGranularity() time.Duration {
	best := time.Duration(0)
	tighter := func(d time.Duration) {
		if d > 0 && (best == 0 || d < best) {
			best = d
		}
	}
	for i := 0; i < 20_000; i++ {
		start := time.Now()
		tighter(time.Since(start))
	}
	if best > 0 {
		return best
	}
	// The clock did not move in a tight loop, so it is coarser than the loop.
	for i := 0; i < 50; i++ {
		start := time.Now()
		time.Sleep(time.Millisecond)
		tighter(time.Since(start))
	}
	return best
}

// format renders a duration at a resolution the machine can actually support: a
// value below the clock's tick is reported as "<tick" rather than as zero.
func format(d, granularity time.Duration) string {
	if granularity > 0 && d < granularity {
		return "<" + granularity.Round(time.Microsecond).String()
	}
	return d.Round(10 * time.Microsecond).String()
}

func percentOf(sorted []time.Duration, p float64) time.Duration {
	return sorted[int(float64(len(sorted)-1)*p)]
}

// loadSession drives the real code flow once and returns the access token it
// minted, so the steady state below is measured against a token the service
// actually issued. The login step is completed in-process — the login plane is its
// own surface with its own tests, and what this profile measures is what comes
// after it.
func loadSession(client *http.Client, base, clientID, secret string, completeLogin func(authRequestID string) error) (string, error) {
	verifier := strings.Repeat("v", 64)
	scopes := []string{"account.id"}
	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"st"},
		"code_challenge":        {pkce(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp, err := client.Get(base + "/oauth/authorize?" + authz.Encode())
	if err != nil {
		return "", err
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		return "", fmt.Errorf("no authRequestID in %q", loc)
	}
	// The login plane is a separate surface with its own tests; the profile is
	// about what comes after it.
	if err := completeLogin(id); err != nil {
		return "", err
	}
	resp, err = client.Get(base + "/oauth/authorize/callback?id=" + url.QueryEscape(id))
	if err != nil {
		return "", err
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	code := cb.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("no code in %q", cb)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {secret},
		"redirect_uri":  {"https://app.example/cb"},
		"code_verifier": {verifier},
	}
	resp, err = http.PostForm(base+"/oauth/token", form)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token = %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token response carried no access token: %s", body)
	}
	return tok.AccessToken, nil
}

func loadRead(client *http.Client, base, token string) (time.Duration, error) {
	req, err := http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	took := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return took, nil
}

func loadIntrospect(client *http.Client, base, basic, token string) (time.Duration, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequest(http.MethodPost, base+"/oauth/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basic)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	took := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return took, nil
}

func envPositive(t *testing.T, name string, fallback int) int {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		t.Fatalf("%s = %q, want a positive integer", name, raw)
	}
	return n
}
