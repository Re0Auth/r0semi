package tapsign

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
)

// failingAudit is an audit.Logger whose every write fails, which is the state
// that makes finish() return an error after the operation itself succeeded.
type failingAudit struct{ err error }

func (f failingAudit) Record(context.Context, audit.Event) error { return f.err }

// S07-6 — Verify sends the decrypted session token to the upstream host, so it
// is one of the credential-bearing boundary operations the package's audit
// contract (invariant I3) covers. It used to be the one such method that wrote
// no record at all.
func TestVerifyRecordsTheCredentialUse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		want    string
		wantErr error
	}{
		{"accepted", http.StatusOK, audit.OutcomeOK, nil},
		{"rejected", http.StatusForbidden, audit.OutcomeDenied, ErrInvalidCredential},
		{"upstream fault", http.StatusInternalServerError, audit.OutcomeError, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, logger := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			err := c.Verify(context.Background(), testCred())
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && tc.status == http.StatusOK && err != nil {
				t.Fatalf("Verify = %v, want nil", err)
			}
			events := logger.Events()
			if len(events) != 1 {
				t.Fatalf("audit events = %+v, want exactly one", events)
			}
			if events[0].Action != "tapsign.verify" || events[0].Outcome != tc.want {
				t.Fatalf("audit event = %+v, want action tapsign.verify outcome %s", events[0], tc.want)
			}
			if events[0].Subject != testCred().ObjectID {
				t.Fatalf("audit subject = %q, want the credential's object id", events[0].Subject)
			}
		})
	}
}

// S07-10 — after a successful rotation the replacement token is the ONLY live
// credential: the old one was invalidated upstream. An audit write that then
// fails must not read as "the rotation failed", or a caller drops the live token
// and the user is locked out with no way to converge.
func TestRotateAuditFailureKeepsTheLiveReplacement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"sessionToken":"rotated-token"}`)
	}))
	defer srv.Close()

	c := newClient(Config{BaseURL: srv.URL, AppID: "app", AppKey: "key"},
		srv.Client(), failingAudit{err: errors.New("audit sink down")})

	next, err := c.Rotate(context.Background(), testCred())
	if err == nil {
		t.Fatal("a failed audit write was not surfaced")
	}
	if !errors.Is(err, ErrRotationAuditFailed) {
		t.Fatalf("err = %v, want errors.Is(err, ErrRotationAuditFailed)", err)
	}
	if next.SessionToken != "rotated-token" || next.ObjectID != testCred().ObjectID {
		t.Fatalf("the live replacement was lost: next = %+v", next)
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Fatalf("the error does not name the audit failure: %v", err)
	}
}

// The distinction is only useful if the ordinary failure keeps its old meaning:
// a rotation that did not happen must NOT be marked as a partial success.
func TestRotateUpstreamFailureIsNotMarkedAsPartialSuccess(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	_, err := c.Rotate(context.Background(), testCred())
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
	if errors.Is(err, ErrRotationAuditFailed) {
		t.Fatalf("a failed rotation was marked as a partial success: %v", err)
	}
}

// S07-8 — a bespoke Doer may return (nil, nil) or a response without a body.
// The adapter must report that, not panic inside the caller's handler.
func TestNilResponseFromTheDoerIsAnErrorNotAPanic(t *testing.T) {
	nilResp := httpclient.DoerFunc(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})
	c := newClient(Config{BaseURL: "http://upstream.invalid", AppID: "app", AppKey: "key"},
		nilResp, audit.NewMemoryLogger())

	if err := c.Verify(context.Background(), testCred()); err == nil {
		t.Fatal("Verify accepted a nil response with a nil error")
	}
	if _, err := c.Rotate(context.Background(), testCred()); err == nil {
		t.Fatal("Rotate accepted a nil response with a nil error")
	}
	if _, err := c.Redeem(context.Background(), TapTapToken{Kid: "k", MacKey: "m", OpenID: "o"}); err == nil {
		t.Fatal("Redeem accepted a nil response with a nil error")
	}
}

func TestResponseWithoutABodyIsAnErrorNotAPanic(t *testing.T) {
	nilBody := httpclient.DoerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: nil, Header: http.Header{}}, nil
	})
	c := newClient(Config{BaseURL: "http://upstream.invalid", AppID: "app", AppKey: "key"},
		nilBody, audit.NewMemoryLogger())

	if err := c.Verify(context.Background(), testCred()); err != nil {
		t.Fatalf("Verify of an OK response with no body = %v, want nil", err)
	}
	if _, err := c.Rotate(context.Background(), testCred()); err == nil {
		t.Fatal("Rotate decoded a response without a body")
	}

	// drain itself must tolerate both nil forms; calling it directly pins the
	// guard that the deferred calls above rely on.
	drain(nil)
	drain(&http.Response{StatusCode: http.StatusOK})
}
