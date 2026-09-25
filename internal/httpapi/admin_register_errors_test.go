package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/admin"
)

// failingRegister stands in for the store refusing the write. Register is the
// only method that matters here, so the rest delegates to the real service.
type failingRegister struct{ admin.Service }

func (failingRegister) Register(context.Context, string, admin.RegisterRequest) (admin.Registration, error) {
	return admin.Registration{}, errors.New(`pq: connection refused`)
}

// A malformed registration is the caller's fault and stays a 400 — without ever
// echoing the internal error text.
func TestAdminRegisterRejectsInvalidInput(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/clients", csrf, map[string]any{
		"name":          "Bad",
		"type":          "public",
		"redirect_uris": []string{"not-a-url"},
		"scopes":        []string{"openid"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed registration = %d, want 400", resp.StatusCode)
	}
	body := decodeResp(t, resp)
	if body["code"] != "invalid_request" {
		t.Fatalf("code = %v, want invalid_request", body["code"])
	}
	assertNoInternalLeak(t, body["detail"])
}

// A storage failure is not the caller's fault: it must be a 500, and the wire
// must not carry the database's words.
func TestAdminRegisterStoreFailureIsInternal(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	env.srv.adminSvc = failingRegister{env.srv.adminSvc}

	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/clients", csrf, map[string]any{
		"name":          "Fine",
		"type":          "public",
		"redirect_uris": []string{"https://new.example/cb"},
		"scopes":        []string{"openid"},
	})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("store failure = %d, want 500", resp.StatusCode)
	}
	body := decodeResp(t, resp)
	if body["code"] != "internal_error" {
		t.Fatalf("code = %v, want internal_error", body["code"])
	}
	assertNoInternalLeak(t, body["detail"])
}

// assertNoInternalLeak checks a problem detail for text that belongs in a log,
// not on the wire.
func assertNoInternalLeak(t *testing.T, detail any) {
	t.Helper()
	s, _ := detail.(string)
	for _, leak := range []string{"pq:", "oauth:", "connection refused", "not-a-url"} {
		if strings.Contains(s, leak) {
			t.Errorf("the response detail %q leaked internal text %q", s, leak)
		}
	}
}
