package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

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

// The operational surface — metrics and profiling — is a separate listener on
// purpose: profiling dumps process internals, and none of it belongs on the
// public port. Pointing both at the same address would silently put it there.
func TestInternalAddrMustDifferFromThePublicAddr(t *testing.T) {
	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
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
