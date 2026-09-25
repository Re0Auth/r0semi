package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// stubAuditReader stands in for the durable sink. It records the query it was
// handed, so a test can assert that filters survived parsing and reached the
// reader unchanged — the handler must not be the place a filter is silently lost.
type stubAuditReader struct {
	query  audit.Query
	page   audit.Page
	verify audit.Verification
	head   []byte
	err    error
}

func (s *stubAuditReader) Head(context.Context) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.head, nil
}

func (s *stubAuditReader) Query(_ context.Context, q audit.Query) (audit.Page, error) {
	s.query = q
	if s.err != nil {
		return audit.Page{}, s.err
	}
	return s.page, nil
}

func (s *stubAuditReader) Verify(context.Context) (audit.Verification, error) {
	if s.err != nil {
		return audit.Verification{}, s.err
	}
	return s.verify, nil
}

// TestAdminAuditIsHiddenFromNonAdmins: the log describes every account, so a
// signed-in non-admin gets the same 404 as an unknown path.
func TestAdminAuditIsHiddenFromNonAdmins(t *testing.T) {
	env := newAdminEnv(t, false)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	for _, path := range []string{"/v1/admin/audit", "/v1/admin/audit/verify"} {
		resp := getURL(t, browser, env.base+path)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("non-admin GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestAdminAuditRequiresASession(t *testing.T) {
	env := newAdminEnv(t, true)
	resp := getURL(t, newBrowser(t), env.base+"/v1/admin/audit")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestAdminAuditPassesFiltersThrough: each parameter must arrive at the reader.
// A filter that parses but is dropped is worse than a rejected one, because the
// caller believes they narrowed the view.
func TestAdminAuditPassesFiltersThrough(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	until := since.Add(24 * time.Hour)
	target := env.base + "/v1/admin/audit?subject=usr_x&action=oauth.token&limit=7&cursor=42" +
		"&since=" + since.Format(time.RFC3339) + "&until=" + until.Format(time.RFC3339)

	resp := getURL(t, browser, target)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	got := env.audit.query
	// The subject is passed through as the account id: resolving it to a pseudonym
	// is the reader's job, because only the reader has the key.
	if got.Subject != "usr_x" || got.Action != "oauth.token" {
		t.Errorf("filters = %+v", got)
	}
	if got.Limit != 7 || got.Before != 42 {
		t.Errorf("limit/cursor = %d/%d, want 7/42", got.Limit, got.Before)
	}
	if !got.Since.Equal(since) || !got.Until.Equal(until) {
		t.Errorf("window = %v..%v, want %v..%v", got.Since, got.Until, since, until)
	}
}

func TestAdminAuditRejectsMalformedParameters(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	for name, q := range map[string]string{
		"limit is not a number":  "limit=abc",
		"limit is zero":          "limit=0",
		"limit is negative":      "limit=-5",
		"cursor is not a number": "cursor=abc",
		"cursor is zero":         "cursor=0",
		"since is not a time":    "since=yesterday",
		"until is not a time":    "until=20260101",
	} {
		t.Run(name, func(t *testing.T) {
			resp := getURL(t, browser, env.base+"/v1/admin/audit?"+q)
			body := decodeResp(t, resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if body["code"] != "invalid_request" {
				t.Errorf("code = %v, want invalid_request", body["code"])
			}
			// A rejected request must not have reached the reader.
			if env.audit.query.Limit != 0 || env.audit.query.Before != 0 {
				t.Errorf("the reader was called with %+v", env.audit.query)
			}
		})
	}
}

// TestAdminAuditReturnsEntriesAndPagination checks the response shape, including
// that the cursor is only present when there is a next page.
func TestAdminAuditReturnsEntriesAndPagination(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	env.audit.page = audit.Page{
		Limit: 100,
		Entries: []audit.Entry{{
			ID: 9, Time: time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC),
			Action: "vault.use", Subject: "pseudonym_abc", Provider: "phigros.taptap",
			Outcome: audit.OutcomeOK, Detail: map[string]string{"client_id": "cli"},
		}},
		NextBefore: 9,
	}

	body := decodeResp(t, getURL(t, browser, env.base+"/v1/admin/audit"))
	entries, ok := body["data"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("data = %v, want one entry", body["data"])
	}
	entry := entries[0].(map[string]any)
	if entry["action"] != "vault.use" || entry["subject"] != "pseudonym_abc" {
		t.Errorf("entry = %v", entry)
	}
	if entry["time"] != "2026-05-06T07:08:09Z" {
		t.Errorf("time = %v, want RFC 3339 UTC", entry["time"])
	}
	pagination, ok := body["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("pagination missing: %v", body)
	}
	if pagination["next_cursor"] != "9" {
		t.Errorf("next_cursor = %v, want 9", pagination["next_cursor"])
	}
	if pagination["limit"] != float64(100) {
		t.Errorf("limit = %v, want the reader's applied limit", pagination["limit"])
	}
}

// TestAdminAuditOmitsTheCursorOnTheLastPage: an absent cursor is how a caller
// knows to stop, so sending a stale one would make it loop.
func TestAdminAuditOmitsTheCursorOnTheLastPage(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	env.audit.page = audit.Page{Limit: 100, Entries: []audit.Entry{}}
	body := decodeResp(t, getURL(t, browser, env.base+"/v1/admin/audit"))
	pagination := body["pagination"].(map[string]any)
	if _, present := pagination["next_cursor"]; present {
		t.Errorf("next_cursor present on the last page: %v", pagination)
	}
}

// TestAdminAuditVerifyReportsTheChain: a broken chain must be reported as a
// result, not as an error — "the log has been tampered with" is a successful
// answer to the question that was asked.
func TestAdminAuditVerifyReportsTheChain(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	env.audit.verify = audit.Verification{OK: true, Chained: 12, Legacy: 3}
	body := decodeResp(t, getURL(t, browser, env.base+"/v1/admin/audit/verify"))
	if body["ok"] != true || body["chained"] != float64(12) || body["legacy"] != float64(3) {
		t.Fatalf("verify = %v", body)
	}

	env.audit.verify = audit.Verification{OK: false, Chained: 4, FirstBadID: 7, Reason: "signature does not verify"}
	body = decodeResp(t, getURL(t, browser, env.base+"/v1/admin/audit/verify"))
	if body["ok"] != false || body["first_bad_id"] != float64(7) || body["reason"] != "signature does not verify" {
		t.Fatalf("tampered verify = %v", body)
	}
}

// TestAdminAuditReportsAReadFailure: a store that cannot answer is a 500, not a
// silently empty page that reads as "no records".
func TestAdminAuditReportsAReadFailure(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	env.audit.err = errors.New("database is on fire")

	for _, path := range []string{"/v1/admin/audit", "/v1/admin/audit/verify"} {
		resp := getURL(t, browser, env.base+path)
		body := decodeResp(t, resp)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("GET %s = %d, want 500", path, resp.StatusCode)
		}
		if body["code"] != "internal_error" {
			t.Errorf("GET %s code = %v", path, body["code"])
		}
	}
}

// TestAdversarialAuditZeroTimeBoundIsRefused: a bound that parses to Go's zero
// time (0001-01-01T00:00:00Z) must be refused, not dropped. The reader treats the
// zero time as "no bound", so accepting it silently widened the result to the
// whole log while the caller believed they had narrowed it.
func TestAdversarialAuditZeroTimeBoundIsRefused(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	for _, q := range []string{"?since=0001-01-01T00:00:00Z", "?until=0001-01-01T00:00:00Z"} {
		resp := getURL(t, browser, env.base+"/v1/admin/audit"+q)
		body := decodeResp(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 (a bound that cannot be honoured must be refused)", q, resp.StatusCode)
		}
		if body["code"] != "invalid_request" {
			t.Errorf("GET %s code = %v, want invalid_request", q, body["code"])
		}
	}
}

// TestAdminAuditIsAbsentWhenNotConfigured: a deployment whose audit log cannot be
// read must not advertise the endpoints. They fall to the business-plane
// catch-all, a 404 like any other unknown resource.
func TestAdminAuditIsAbsentWhenNotConfigured(t *testing.T) {
	cfg := newFullConfig(t)
	cfg.Audit = nil
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, rt := range srv.specRoutes() {
		if rt.Pattern == "/v1/admin/audit" || rt.Pattern == "/v1/admin/audit/verify" {
			t.Fatalf("%s is in specRoutes without an audit reader", rt.Pattern)
		}
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/audit", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestAuditRequiresAnAllowlist: the config refuses a reader with nobody allowed to
// call it, rather than mounting a door with no handle.
func TestAuditRequiresAnAllowlist(t *testing.T) {
	cfg := newFullConfig(t)
	cfg.Admins = nil
	if _, err := New(cfg); err == nil {
		t.Fatal("a reader with an empty allowlist was accepted")
	}
}
