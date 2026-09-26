package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/observability"
)

type stubHead struct {
	sum []byte
	err error
}

func (s stubHead) Head(context.Context) ([]byte, error) { return s.sum, s.err }

// stubVerifier answers a chain walk with a canned outcome.
type stubVerifier struct {
	verification audit.Verification
	err          error
}

func (s stubVerifier) Verify(context.Context) (audit.Verification, error) {
	return s.verification, s.err
}

// scrapeMetrics returns the Prometheus exposition text for this Metrics set.
func scrapeMetrics(t *testing.T, m *observability.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.InternalHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// captureLog swaps the process default logger for one writing into a buffer. This
// package has no parallel tests, so the swap is safe; anchorOnce is called
// synchronously, so the buffer needs no lock.
func captureLog(t *testing.T) func() string {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf.String
}

// The anchor is what makes a truncated audit tail detectable: verification by itself
// accepts a shorter chain, so the only comparison available is against a head that
// was recorded somewhere else. This pins what gets recorded and, just as important,
// that a failed read records no head at all — an anchored value that came from an
// error would be worse than none, because it would look like evidence.
func TestAnchorRecordsTheChainHead(t *testing.T) {
	for _, tc := range []struct {
		name string
		head []byte
		err  error
		want string
	}{
		{"a chained head", []byte{0xde, 0xad, 0xbe, 0xef}, nil, "head=deadbeef"},
		{"a chain nobody has written to yet", nil, nil, "head=genesis"},
		{"a sink that cannot be read", nil, errors.New("pool is closed"), "could not anchor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLog(t)
			anchorOnce(context.Background(), stubHead{sum: tc.head, err: tc.err})

			out := logged()
			if !strings.Contains(out, tc.want) {
				t.Fatalf("log does not mention %q:\n%s", tc.want, out)
			}
			if tc.err != nil && strings.Contains(out, "head=") {
				t.Fatalf("a failed read still anchored a value:\n%s", out)
			}
		})
	}
}

// The verify loop exists to move `audit_verify_total`, because that series is S5:
// `result="failed"` being identically zero is the target, and until this loop the
// only thing that ever moved it was an operator calling the admin endpoint by hand.
// So what each outcome records is the contract worth pinning — in particular that a
// walk which did not finish is `error` and not `failed`. Conflating them would
// either page someone for a busy database or hide a genuine chain failure behind
// the value the runbooks treat as routine.
func TestVerifyOnceRecordsTheOutcomeItFound(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stub    stubVerifier
		want    string
		wantLog string
	}{
		{
			name:    "an intact chain",
			stub:    stubVerifier{verification: audit.Verification{OK: true, Chained: 12, Legacy: 3}},
			want:    `re0auth_audit_verify_total{result="ok"} 1`,
			wantLog: "audit chain verified",
		},
		{
			name: "a chain that does not hold",
			stub: stubVerifier{verification: audit.Verification{
				OK: false, Chained: 40, FirstBadID: 42, Reason: "prev_hash does not match",
			}},
			want:    `re0auth_audit_verify_total{result="failed"} 1`,
			wantLog: "first_bad_id=42",
		},
		{
			name:    "a walk that did not finish",
			stub:    stubVerifier{err: errors.New("statement timeout")},
			want:    `re0auth_audit_verify_total{result="error"} 1`,
			wantLog: "could not verify the audit chain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLog(t)
			metrics := observability.New()
			verifyOnce(context.Background(), tc.stub, metrics)

			if body := scrapeMetrics(t, metrics); !strings.Contains(body, tc.want) {
				t.Errorf("exposition is missing %q:\n%s", tc.want, body)
			}
			if out := logged(); !strings.Contains(out, tc.wantLog) {
				t.Errorf("log does not mention %q:\n%s", tc.wantLog, out)
			}
		})
	}
}

// The loop must not inherit the read API's allowlist. That gate exists because
// reading the log exposes every account's activity to whoever calls it; the loop is
// the service examining its own log and has no caller to authorize. Gating it the
// same way would mean a durable deployment that names no operators — legitimate, and
// exactly the case auditReadSide returns nil for — silently stops verifying.
func TestAuditVerifierIsNotGatedOnAnAllowlist(t *testing.T) {
	readable := auditReadSink{audit.NewMemoryLogger()}

	if got := auditVerifier(readable); got == nil {
		t.Fatal("the verifier was withheld from a sink that can verify")
	}
	if got := auditVerifier(audit.NewMemoryLogger()); got != nil {
		t.Fatal("the verifier was offered by a sink that cannot verify")
	}
	// The contrast that makes the point: the allowlist withholds the read API from
	// the same sink the loop still verifies.
	if got := auditReadSide(nil, readable); got != nil {
		t.Fatal("the read API was offered without an admin allowlist")
	}
}

// countingVerifier counts the walks it was asked for.
type countingVerifier struct {
	mu sync.Mutex
	n  int
}

func (c *countingVerifier) Verify(context.Context) (audit.Verification, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return audit.Verification{OK: true}, nil
}

func (c *countingVerifier) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// Two properties of the loop itself, neither of which the body's test can see.
//
// It walks once at startup rather than waiting for the first tick: a rolling deploy
// restarts replicas far more often than six hours, so a loop that only acted on its
// ticker would on such a deployment never walk anything at all — a control that
// appears configured and never runs.
//
// And it stops when the process's context ends, like every other loop here, rather
// than outliving the storage it reads.
func TestAuditVerifyLoopWalksAtStartAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	verifier := &countingVerifier{}
	metrics := observability.New()
	done := make(chan struct{})
	// An interval far longer than the test: the ticker cannot fire, so any walk at
	// all must be the startup one. Asserting "it already happened" without this
	// would be a race against the scheduler, not a statement about the loop.
	go func() {
		auditVerifyLoop(ctx, verifier, metrics, time.Hour)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for verifier.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if verifier.count() == 0 {
		t.Fatal("the loop waited for its first tick instead of walking at startup")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop ignored cancellation")
	}
}

func TestOIDCTokenKeyFailClosed(t *testing.T) {
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", "")
	if _, err := oidcTokenKey(); err == nil {
		t.Fatal("missing token key was accepted")
	}

	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if _, err := oidcTokenKey(); err == nil {
		t.Fatal("16-byte token key was accepted")
	}

	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", good)
	if _, err := oidcTokenKey(); err != nil {
		t.Fatalf("valid token key rejected: %v", err)
	}
}

func TestOIDCSigningKeyFailClosed(t *testing.T) {
	t.Setenv("RE0AUTH_OIDC_SIGNING_KEY", "")
	if _, err := oidcSigningKey(); err == nil {
		t.Fatal("missing signing key was accepted")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RE0AUTH_OIDC_SIGNING_KEY", base64.StdEncoding.EncodeToString(der))
	if _, err := oidcSigningKey(); err != nil {
		t.Fatalf("valid signing key rejected: %v", err)
	}
}

func TestOIDCRetiredKeysParsing(t *testing.T) {
	t.Setenv("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS", "old:"+base64.StdEncoding.EncodeToString(make([]byte, 32)))
	tokens, err := oidcRetiredTokenKeys()
	if err != nil || len(tokens) != 1 || tokens[0].ID != "old" {
		t.Fatalf("retired token keys = %v (%v)", tokens, err)
	}
	t.Setenv("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS", "malformed")
	if _, err := oidcRetiredTokenKeys(); err == nil {
		t.Fatal("malformed retired token key accepted")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS", "old:"+base64.StdEncoding.EncodeToString(pubDER))
	signing, err := oidcRetiredSigningKeys()
	if err != nil || len(signing) != 1 || signing[0].ID != "old" {
		t.Fatalf("retired signing keys = %v (%v)", signing, err)
	}
	t.Setenv("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS", "malformed")
	if _, err := oidcRetiredSigningKeys(); err == nil {
		t.Fatal("malformed retired signing key accepted")
	}
}

// A provider name that is not built in is a custom OIDC provider, and must name
// its issuer. This is how a self-hosted Passkey/Keycloak/Authentik login is
// configured without a code change.
func TestLoadIdPAllowsCustomOIDCProvider(t *testing.T) {
	var cfg settings
	if err := loadIdP(&cfg, map[string]idpSection{
		"authentik": {
			ClientID:    "cid",
			Issuer:      "https://id.example/application/o/re0auth/",
			DisplayName: "Authentik",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if len(cfg.idpCredentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(cfg.idpCredentials))
	}
	c := cfg.idpCredentials[0]
	if c.Provider != "authentik" || c.Issuer == "" || c.DisplayName != "Authentik" {
		t.Fatalf("credential = %+v", c)
	}
}

func TestLoadIdPRejectsCustomProviderWithoutIssuer(t *testing.T) {
	var cfg settings
	if err := loadIdP(&cfg, map[string]idpSection{"mystery": {ClientID: "cid"}}); err == nil {
		t.Fatal("accepted a custom provider with no issuer")
	}
}

// countingSweeper stands in for the memory store: it records how often the
// janitor asks it to sweep, and never reports anything removed.
type countingSweeper struct {
	mu sync.Mutex
	n  int
}

func (c *countingSweeper) SweepExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return 0
}

func (c *countingSweeper) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// The in-memory OP store has no janitor of its own, so this loop is what keeps
// its maps from growing for the life of the process. It must actually sweep, and
// it must stop when the process's context ends rather than outliving it.
func TestOPJanitorLoopSweepsAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fake := &countingSweeper{}
	done := make(chan struct{})
	go func() {
		opJanitorLoop(ctx, fake, time.Millisecond)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for fake.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fake.count() == 0 {
		t.Fatal("the janitor never swept")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the janitor ignored cancellation")
	}

	stopped := fake.count()
	time.Sleep(10 * time.Millisecond)
	if fake.count() != stopped {
		t.Fatal("the janitor swept after it was cancelled")
	}
}

// TestLoopGroupWaitsForTheBodyNotTheCancellation is the shutdown-ordering
// property: cancelling asks a loop to stop, it does not mean the loop has
// returned. The storage handle is closed after Wait, so a Wait that returned on
// cancellation would close the pool under a sweep that is still mid-query — the
// race the group exists to close.
func TestLoopGroupWaitsForTheBodyNotTheCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var loops loopGroup

	// A body that models a sweep in flight: it notices the cancellation and then
	// takes measurable time to return.
	finished := make(chan struct{})
	loops.Go(func() {
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		close(finished)
	})

	cancel()
	loops.Wait()
	select {
	case <-finished:
	default:
		t.Fatal("Wait returned before the loop body finished")
	}
}

// A group with nothing in it must not block, so the deferred join is safe on
// every exit path (a -rotate-keys run starts no loops at all).
func TestLoopGroupWaitIsImmediateWhenEmpty(t *testing.T) {
	var loops loopGroup
	done := make(chan struct{})
	go func() {
		loops.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait blocked with no loops running")
	}
}

// A shutdown signal must drain the request that is already in flight rather than
// cut it off. On a rolling deploy the process is replaced while it is answering,
// and an abrupt exit is a failed request the user sees.
func TestServeUntilSignalDrainsInFlightRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("done"))
	})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- serveUntilSignal(ctx, 5*time.Second, endpoint{server: srv, listener: ln}) }()

	respCh := make(chan *http.Response, 1)
	reqErrCh := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			reqErrCh <- err
			return
		}
		respCh <- resp
	}()

	<-started      // the handler is running and the request is in flight
	cancel()       // begin shutdown while it is still in flight
	close(release) // let it finish

	select {
	case err := <-reqErrCh:
		t.Fatalf("the in-flight request was dropped: %v", err)
	case resp := <-respCh:
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "done" {
			t.Fatalf("in-flight response = %d %q, want 200 %q", resp.StatusCode, body, "done")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight request never completed")
	}

	if err := <-errCh; err != nil {
		t.Fatalf("serveUntilSignal = %v, want nil for a clean drain", err)
	}
}

// A handler that will not finish must not hold a deploy open forever: once the
// drain timeout passes, the connections are closed and the error is reported so
// the caller can decide what to do about it.
func TestServeUntilSignalClosesHungConnectionsAfterTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	// Release the handler when the test ends so its goroutine does not leak.
	defer close(release)
	srv := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- serveUntilSignal(ctx, 50*time.Millisecond, endpoint{server: srv, listener: ln}) }()

	go func() { _, _ = http.Get("http://" + ln.Addr().String() + "/") }()
	<-started
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("a drain that timed out returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveUntilSignal did not return after the drain timeout")
	}
}

// Trusted proxies accept CIDRs and bare addresses, and a malformed entry is an
// error rather than a silent skip: a typo that quietly trusted nobody — or, if
// it were handled differently, everybody — is exactly the kind of setting that
// looks applied and is not.
func TestParseTrustedProxies(t *testing.T) {
	got, err := parseTrustedProxies([]string{"10.0.0.0/8", " 192.168.1.5 ", "", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d prefixes, want 3: %v", len(got), got)
	}
	// A bare address becomes a single-host prefix.
	if !got[1].Contains(netip.MustParseAddr("192.168.1.5")) || got[1].Bits() != 32 {
		t.Fatalf("bare address = %v, want a /32", got[1])
	}

	if _, err := parseTrustedProxies([]string{"not-a-network"}); err == nil {
		t.Fatal("a malformed entry was accepted")
	}
}

// The audit chain key is required exactly when the audit log is durable. An
// unsigned durable chain would be a control that only looks like one, and the
// in-memory log has nothing for a key to protect.
//
// Durability is chosen by the config file's storage driver, not by DATABASE_URL
// alone: with no driver named, the store defaults to memory and the DSN is
// deliberately ignored. So the test writes a real config rather than setting an
// environment variable that would be silently overridden.
func TestAuditKeyIsRequiredOnlyWhenDurable(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))

	writeConfig := func(t *testing.T, driver string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "re0auth.toml")
		body := "[server]\nissuer = \"https://re0auth.test\"\n\n[storage]\ndriver = \"" + driver + "\"\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	base := func() {
		t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
		// An https issuer requires a Secure session cookie; the config loader
		// refuses the pair otherwise (TestIssuerSchemeAndCookieSecureMustAgree).
		t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
		t.Setenv("RE0AUTH_KEK", valid)
		t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", valid)
	}

	t.Run("durable without a key is refused", func(t *testing.T) {
		base()
		t.Setenv("DATABASE_URL", "postgres://localhost/r0semi")
		t.Setenv("RE0AUTH_AUDIT_KEY", "")
		if _, err := loadConfig(writeConfig(t, "postgres")); err == nil {
			t.Fatal("a durable deployment without RE0AUTH_AUDIT_KEY was accepted")
		}
	})

	t.Run("a wrong-sized key is refused", func(t *testing.T) {
		base()
		t.Setenv("DATABASE_URL", "postgres://localhost/r0semi")
		t.Setenv("RE0AUTH_AUDIT_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
		if _, err := loadConfig(writeConfig(t, "postgres")); err == nil {
			t.Fatal("a 16-byte audit key was accepted")
		}
	})

	t.Run("durable with a key is accepted", func(t *testing.T) {
		base()
		t.Setenv("DATABASE_URL", "postgres://localhost/r0semi")
		t.Setenv("RE0AUTH_AUDIT_KEY", valid)
		cfg, err := loadConfig(writeConfig(t, "postgres"))
		if err != nil {
			t.Fatalf("a valid audit key was rejected: %v", err)
		}
		if len(cfg.AuditKey) != 32 {
			t.Fatalf("audit key is %d bytes, want 32", len(cfg.AuditKey))
		}
	})

	t.Run("memory mode needs no key", func(t *testing.T) {
		base()
		t.Setenv("DATABASE_URL", "")
		t.Setenv("RE0AUTH_AUDIT_KEY", "")
		cfg, err := loadConfig(writeConfig(t, "memory"))
		if err != nil {
			t.Fatalf("memory mode should not need an audit key: %v", err)
		}
		if cfg.AuditKey != nil {
			t.Errorf("memory mode resolved an audit key: %v", cfg.AuditKey)
		}
	})
}

// auditReadSink is the durable sink's shape in miniature: it can be logged to,
// through the embedded in-memory logger, and it can be read.
type auditReadSink struct {
	*audit.MemoryLogger
}

func (auditReadSink) Query(context.Context, audit.Query) (audit.Page, error) {
	return audit.Page{}, nil
}

func (auditReadSink) Verify(context.Context) (audit.Verification, error) {
	return audit.Verification{}, nil
}

func (auditReadSink) Head(context.Context) ([]byte, error) { return nil, nil }

// The audit read API needs both a sink that can answer and an allowlist to read
// through. Wiring only the first is what took the whole server down: the durable
// run has a readable sink, so httpapi.New was handed an audit reader with no
// admins and refused to start.
func TestAuditReadSideIsGatedOnAnAllowlist(t *testing.T) {
	readable := auditReadSink{audit.NewMemoryLogger()}

	if got := auditReadSide(nil, readable); got != nil {
		t.Fatal("the read API was offered without an admin allowlist")
	}
	if got := auditReadSide([]string{"usr_admin"}, readable); got == nil {
		t.Fatal("the read API was withheld from a named admin")
	}
	// And the allowlist alone is not enough: the sink has to be able to answer,
	// which the in-memory ring buffer cannot.
	if got := auditReadSide([]string{"usr_admin"}, audit.NewMemoryLogger()); got != nil {
		t.Fatal("the read API was offered by a sink that cannot read")
	}
}

// The operational surface — metrics and profiling — is a separate listener on
// purpose: profiling dumps process internals, and none of it belongs on the
// public port. Pointing both at the same address would silently put it there.
func TestInternalAddrMustDifferFromThePublicAddr(t *testing.T) {
	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("RE0AUTH_ADDR", "127.0.0.1:8080")

	t.Setenv("RE0AUTH_INTERNAL_ADDR", "127.0.0.1:8080")
	if _, err := loadConfig(""); err == nil {
		t.Fatal("internal_addr equal to addr was accepted")
	}

	t.Setenv("RE0AUTH_INTERNAL_ADDR", "127.0.0.1:9090")
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("a distinct internal_addr was rejected: %v", err)
	}
	if cfg.InternalAddr != "127.0.0.1:9090" {
		t.Fatalf("internal_addr = %q, want 127.0.0.1:9090", cfg.InternalAddr)
	}
}

// Being a *different* address is not the same as being a private one, and the old
// check only asked the first question. `0.0.0.0:9090` — an ordinary way to write
// "every interface", and what the k8s baseline itself needs — passed it, putting
// /metrics and /debug/pprof/ on the network with nothing but a documentation line in
// the way. Now it takes an acknowledgement, and the acknowledgement is where the
// NetworkPolicy that makes it safe gets recorded.
func TestNonLoopbackInternalAddrNeedsAcknowledgement(t *testing.T) {
	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("RE0AUTH_ADDR", "0.0.0.0:8080")

	t.Setenv("RE0AUTH_INTERNAL_ADDR", "0.0.0.0:9090")
	t.Setenv("RE0AUTH_INTERNAL_EXPOSE", "")
	if _, err := loadConfig(""); err == nil {
		t.Fatal("a non-loopback internal_addr was accepted without acknowledgement")
	}

	t.Setenv("RE0AUTH_INTERNAL_EXPOSE", "true")
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("an acknowledged non-loopback internal_addr was rejected: %v", err)
	}
	if !cfg.ExposeInternal {
		t.Fatal("expose_internal did not reach the settings")
	}

	// A loopback address still needs no acknowledgement — and a stray
	// acknowledgement for one is harmless rather than an error, because the binding
	// is the thing that decides.
	t.Setenv("RE0AUTH_INTERNAL_ADDR", "127.0.0.1:9090")
	t.Setenv("RE0AUTH_INTERNAL_EXPOSE", "")
	if _, err := loadConfig(""); err != nil {
		t.Fatalf("a loopback internal_addr was rejected: %v", err)
	}
}

// The classification is deliberately conservative, and the asymmetry is why: the
// two mistakes do not cost the same. Refusing a private address costs one config
// line; accepting a public one publishes heap profiles and goroutine dumps. So
// anything not provably loopback counts as reachable — including a hostname, which
// would need DNS to settle and could disagree with what the bind does.
func TestInternalAddrReachabilityIsClassifiedConservatively(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9090", true},
		{"127.0.0.53:9090", true}, // the whole 127/8 block, not just .0.1
		{"[::1]:9090", true},
		{"localhost:9090", true},
		{"0.0.0.0:9090", false},
		{"[::]:9090", false},
		{":9090", false},
		{"10.1.2.3:9090", false},
		{"re0auth.internal:9090", false},
		{"", false},
	} {
		if got := internalAddrIsLocal(tc.addr); got != tc.want {
			t.Errorf("internalAddrIsLocal(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// The session cookie's Secure flag and the issuer's scheme are one decision seen
// from two settings, and nothing else in the process looks at both. The previous
// treatment was documentation — the troubleshooting guide described the symptom
// ("signed in, no session") — which is a foot-gun an operator walks into at the
// least convenient moment.
func TestIssuerSchemeAndCookieSecureMustAgree(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("RE0AUTH_KEK", key)
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", key)

	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "false")
	if _, err := loadConfig(""); err == nil {
		t.Fatal("an https issuer with an insecure session cookie was accepted")
	}

	// The deployment that says what it means is the one that works.
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	if _, err := loadConfig(""); err != nil {
		t.Fatalf("an https issuer with a Secure cookie was refused: %v", err)
	}

	// And the plain-http direction is deliberately left alone: browsers send Secure
	// cookies over http to localhost, so that is a working local setup asking for the
	// production cookie shape — refusing it would be a gate that is wrong on a real
	// workflow, which is how gates get routed around.
	t.Setenv("RE0AUTH_ISSUER", "http://127.0.0.1:8080")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	if _, err := loadConfig(""); err != nil {
		t.Fatalf("a plain-http issuer with a Secure cookie was refused: %v", err)
	}
}

// Shutdown has to reach every listener, not just the public one: an internal
// listener that kept serving after the signal would leave metrics and profiling
// reachable on a process that was supposed to be gone.
func TestServeUntilSignalDrainsEveryEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var endpoints []endpoint
	var addrs []string
	for i := 0; i < 2; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		endpoints = append(endpoints, endpoint{
			server: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})},
			listener: ln,
		})
		addrs = append(addrs, ln.Addr().String())
	}

	errCh := make(chan error, 1)
	go func() { errCh <- serveUntilSignal(ctx, 5*time.Second, endpoints...) }()

	// Both are serving before the signal.
	for _, addr := range addrs {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			t.Fatalf("GET %s: %v", addr, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("serveUntilSignal = %v, want nil for a clean drain", err)
	}
	// Every listener is closed: a fresh connection is refused.
	for _, addr := range addrs {
		resp, err := http.Get("http://" + addr + "/")
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("listener %s was still accepting after shutdown", addr)
		}
	}
}
