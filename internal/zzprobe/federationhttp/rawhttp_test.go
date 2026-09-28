//go:build audit5

package zzprobe_federationhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/oauth"
)

// zzOneSourceHTTP wires the real HTTP surface with one source that has a raw base
// and echoes whatever Content-Type it is told to.
func zzOneSourceHTTP(t *testing.T, contentType, body string, status int) (base, token string) {
	t.Helper()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.URL.Query().Get("ct"); ct != "" {
			w.Header().Set("Content-Type", ct)
		} else if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(src.Close)

	registry, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", DisplayName: "Src", Issuer: src.URL,
		TokenClass: "revocable", RawBase: src.URL + "/v1",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	binding := federation.Binding{User: "usr_test", Game: "phigros", Source: "src", Version: 1}
	if err := bindings.Put(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	v := newTestVault(t)
	if err := v.Enroll(context.Background(), federation.BindingIdentity(binding), mustPair(t, "tok", ""), nil); err != nil {
		t.Fatal(err)
	}
	fed, err := federation.NewService(federation.Config{
		Registry: registry, Bindings: bindings, Vault: v,
		Doer: src.Client(), HTTPClient: src.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "", []string{zzRedirect},
		[]oauth.Scope{"phigros.profile.read"})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	opHandler, store := zzOPBackend(t, "https://re0auth.test", clients)
	api, err := httpapi.New(httpapi.Config{
		Issuer: "https://re0auth.test", OIDC: opHandler,
		TokenIntrospector: opHandler, GrantStore: store, DeviceStore: store,
		Federation: fed,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv.URL, zzMintToken(t, api.Handler(), store, "cli", "usr_test", "phigros.profile.read")
}

func zzGet(t *testing.T, target, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// The raw proxy promises: the body, the status and the media type are the
// source's, and the response is made undangerous with a route-level CSP plus
// Content-Disposition. This checks the promise holds on the success path and
// asks what happens on the paths that do not go through the raw handler at all.
func TestZZProbeRawResponseHeaderShape(t *testing.T) {
	base, at := zzOneSourceHTTP(t, "text/html", `<html><body><script>alert(1)</script></body></html>`, http.StatusOK)

	resp := zzGet(t, base+"/v1/games/phigros/sources/src/raw/page", at)
	body, _ := io.ReadAll(resp.Body)
	t.Logf("raw success: status=%d", resp.StatusCode)
	for _, h := range []string{
		"Content-Type", "Content-Disposition", "Content-Security-Policy",
		"X-Content-Type-Options", "Cache-Control", "Re0Auth-Source", "Referrer-Policy",
	} {
		t.Logf("  %-26s = %q", h, resp.Header.Get(h))
	}
	t.Logf("body = %s", body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw proxy did not return the source's 200")
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(got, "attachment") {
		t.Errorf("raw success is missing the attachment disposition: %q", got)
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("raw success is missing the sandbox CSP: %q", resp.Header.Get("Content-Security-Policy"))
	}
	if resp.Header.Get("Content-Type") != "text/html" {
		t.Logf("note: the source's text/html was not passed through verbatim: %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("raw success is missing nosniff: %q", resp.Header.Get("X-Content-Type-Options"))
	}
}

// The media type is echoed unvalidated, which is correct for the contract 鈥?the
// question is whether anything downstream of a *failed* raw call can be made to
// render source-controlled markup on this origin.
func TestZZProbeRawErrorPathsCarryNoSourceBody(t *testing.T) {
	base, at := zzOneSourceHTTP(t, "text/html", "<script>alert(1)</script>", http.StatusOK)

	// A raw path that escapes: refused by the federation guard.
	resp := zzGet(t, base+"/v1/games/phigros/sources/src/raw/..%2f..%2fadmin", at)
	body, _ := io.ReadAll(resp.Body)
	t.Logf("escaping path: status=%d ct=%q csp=%q cd=%q body=%s",
		resp.StatusCode, resp.Header.Get("Content-Type"),
		resp.Header.Get("Content-Security-Policy"), resp.Header.Get("Content-Disposition"), body)
	if strings.Contains(string(body), "alert(1)") {
		t.Errorf("a refused raw path still carried the source's body")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("a refused raw path answered with the source's media type %q", ct)
	}
}

// A source that answers 401 makes the data plane return 503; the 401 body must
// not be forwarded.
func TestZZProbeRawUpstream401BodyIsNotForwarded(t *testing.T) {
	base, at := zzOneSourceHTTP(t, "text/html", "<script>alert('401')</script>", http.StatusUnauthorized)
	resp := zzGet(t, base+"/v1/games/phigros/sources/src/raw/x", at)
	body, _ := io.ReadAll(resp.Body)
	t.Logf("upstream 401: status=%d ct=%q body=%s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	if resp.StatusCode == http.StatusUnauthorized && strings.Contains(string(body), "alert(") {
		t.Errorf("the source's 401 body reached the caller verbatim on the raw path")
	}
}

// A kill-switch request from a non-admin must not be actionable, and must not
// even confirm the operator plane exists.
//
// The documented answer with no admin allowlist is 404, not 401: docs/admin.md
// §"面" says the plane is not mounted at all, and a non-admin gets `404 not_found`
// "with no difference from a path that does not exist". The earlier expectation of
// 401 was the probe contradicting both the doc and the handler.
func TestZZProbeKillSwitchRequiresAnOperator(t *testing.T) {
	// No admin allowlist configured at all: the plane is not mounted.
	base, at := zzOneSourceHTTP(t, "application/json", `{}`, http.StatusOK)
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/admin/kill_switch",
		strings.NewReader(`{"target":"all"}`))
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("POST /v1/admin/kill_switch with only a bearer token, no admin plane => %d %s",
		resp.StatusCode, body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an unauthenticated kill switch was answered %d, want the documented 404 "+
			"(the plane is not mounted)", resp.StatusCode)
	}
	// The answer must not advertise the plane: it has to be indistinguishable from
	// a path that does not exist.
	if !strings.Contains(string(body), "not_found") {
		t.Errorf("kill-switch refusal does not read as a plain not_found problem: %s", body)
	}
}
