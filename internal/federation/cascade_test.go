package federation

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/internal/account"
)

func cascadeSource(issuer string) Source {
	src := unbindSource(issuer, "revocable")
	src.CascadeRevocationEndpoint = issuer + "/oauth/cascade_revocation"
	return src
}

// The happy path: the source ends the session, and only then does the binding go.
func TestCascadeEndsTheSessionAndThenUnbinds(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, bindings, v := unbindService(t, cascadeSource(up.URL))
	ctx := context.Background()

	binding := connect(t, svc, "usr_1")
	result, err := svc.CascadeRevoke(ctx, "usr_1", game, sourceName)
	if err != nil {
		t.Fatal(err)
	}
	if result.Upstream != RevocationDone {
		t.Fatalf("upstream = %q, want done", result.Upstream)
	}
	// The source was asked about the refresh token: it names the durable
	// authorization, and an access token may already be dead.
	if calls := rec.cascadeCalls(); len(calls) != 1 || calls[0] != "up-rt" {
		t.Fatalf("cascade calls = %v, want the refresh token once", calls)
	}
	// The plain revocation endpoint was not used: this is not a token revocation.
	if calls := rec.calls(); len(calls) != 0 {
		t.Fatalf("cascade went to the token revocation endpoint: %v", calls)
	}

	if _, err := bindings.Get(ctx, "usr_1", game, sourceName); err == nil {
		t.Error("the binding row survived a successful cascade")
	}
	if exists, _ := v.Exists(ctx, BindingIdentity(binding)); exists {
		t.Error("the binding secret survived a successful cascade")
	}
}

// The rule that is the mirror image of disconnecting: if the source could not be
// told, **nothing** is removed, because the stored credential is the only means
// of asking again. Removing it here would leave the person permanently unable to
// do the thing they asked for.
func TestCascadeRemovesNothingWhenTheSourceRefuses(t *testing.T) {
	rec := &releasingSource{cascadeStatus: http.StatusInternalServerError}
	up := newReleasingSource(t, rec)
	svc, bindings, v := unbindService(t, cascadeSource(up.URL))
	ctx := context.Background()

	binding := connect(t, svc, "usr_1")
	if _, err := svc.CascadeRevoke(ctx, "usr_1", game, sourceName); err == nil {
		t.Fatal("a refused cascade reported success")
	}

	// Both halves are still here, so a retry is possible.
	if _, err := bindings.Get(ctx, "usr_1", game, sourceName); err != nil {
		t.Errorf("the binding was removed after a failed cascade: %v", err)
	}
	if exists, _ := v.Exists(ctx, BindingIdentity(binding)); !exists {
		t.Error("the credential was shredded after a failed cascade")
	}

	// And the retry works once the source recovers.
	rec.mu.Lock()
	rec.cascadeStatus = 0
	rec.mu.Unlock()
	if result, err := svc.CascadeRevoke(ctx, "usr_1", game, sourceName); err != nil {
		t.Fatalf("retry: %v", err)
	} else if result.Upstream != RevocationDone {
		t.Fatalf("retry upstream = %q", result.Upstream)
	}
	if _, err := bindings.Get(ctx, "usr_1", game, sourceName); err == nil {
		t.Error("the binding survived the successful retry")
	}
}

// A source that was never configured with the capability must not be asked, and
// the answer must be distinguishable from "the source was down".
func TestCascadeUnsupportedIsItsOwnAnswer(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, bindings, _ := unbindService(t, unbindSource(up.URL, "revocable"))
	connect(t, svc, "usr_1")

	_, err := svc.CascadeRevoke(context.Background(), "usr_1", game, sourceName)
	if !errors.Is(err, ErrCascadeUnsupported) {
		t.Fatalf("err = %v, want ErrCascadeUnsupported", err)
	}
	if calls := rec.cascadeCalls(); len(calls) != 0 {
		t.Fatalf("an unsupported source was asked anyway: %v", calls)
	}
	// Nothing happened, so the binding is untouched.
	if _, err := bindings.Get(context.Background(), "usr_1", game, sourceName); err != nil {
		t.Errorf("a refused capability removed the binding: %v", err)
	}
}

func TestCascadeRequiresAConnectionAndIdentifiers(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, _, _ := unbindService(t, cascadeSource(up.URL))
	ctx := context.Background()

	// Nothing connected: there is no token, so there is nothing to identify the
	// session with. Not a silent success.
	if _, err := svc.CascadeRevoke(ctx, "usr_1", game, sourceName); !errors.Is(err, ErrNotBound) {
		t.Fatalf("unbound cascade = %v, want ErrNotBound", err)
	}
	if _, err := svc.CascadeRevoke(ctx, "usr_1", game, "nope"); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("unknown source = %v, want ErrUnknownSource", err)
	}
	for _, tc := range []struct{ user, game, source string }{
		{"", game, sourceName},
		{"usr_1", "", sourceName},
		{"usr_1", game, ""},
	} {
		if _, err := svc.CascadeRevoke(ctx, account.UserID(tc.user), tc.game, tc.source); err == nil {
			t.Errorf("CascadeRevoke accepted %+v", tc)
		}
	}
}
