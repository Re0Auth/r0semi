package federation

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

// audit9Challenge reads the PKCE challenge a bind URL was built with.
func audit9Challenge(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("code_challenge")
}

// AUDIT9 / S14-2 residual (fixed) — a bind flow that began while a binding was
// live must not be able to re-create it after an Unbind has completed.
//
// 992710b made CompleteBind take the per-binding keyed lock, which orders it
// against a CONCURRENT Unbind. But the flow is consumed BEFORE the lock and the
// row write is an unconditional Put, so a removal that has already finished is
// still undone when the stale callback finally runs: two tabs, a Kill Switch
// sweep, or an account erasure. The lock cannot see it — the removal is over.
//
// The deterministic order here is the point: no race is needed to reproduce it.
func TestAudit9ABindStartedBeforeAnUnbindCannotResurrectIt(t *testing.T) {
	up, challenge := fakeTokenServer(t, "up-token")
	svc, store, v := bindService(t, up.URL)
	ctx := context.Background()

	// 1. A binding exists.
	first, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	*challenge = audit9Challenge(t, first.AuthorizeURL)
	bound, _, err := svc.CompleteBind(ctx, "usr_1", first.ID, "code-1")
	if err != nil {
		t.Fatal(err)
	}

	// 2. The user starts a re-bind while the binding is live. This is the flow
	//    that "was started before" the disconnect.
	second, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	*challenge = audit9Challenge(t, second.AuthorizeURL)

	// 3. The user disconnects. Unbind reports success and is completely done.
	if _, err := svc.Unbind(ctx, "usr_1", game, sourceName); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if _, err := store.Get(ctx, "usr_1", game, sourceName); !errors.Is(err, ErrNotBound) {
		t.Fatalf("control: Unbind did not remove the row: %v", err)
	}
	if ok, xerr := v.Exists(ctx, BindingIdentity(bound)); xerr != nil || ok {
		t.Fatalf("control: Unbind did not shred the secret: exists=%v err=%v", ok, xerr)
	}

	// 4. The stale callback finally runs. It must be refused, and the refusal
	//    must defeat the resurrection: neither the row nor a usable upstream
	//    credential may come back.
	resurrected, _, err := svc.CompleteBind(ctx, "usr_1", second.ID, "code-2")
	if err == nil {
		t.Fatalf("a bind that began before the Unbind completed was accepted: %+v", resurrected)
	}
	if !errors.Is(err, ErrBindSuperseded) {
		t.Fatalf("err = %v, want ErrBindSuperseded (the bind lost its precondition)", err)
	}
	if _, gerr := store.Get(ctx, "usr_1", game, sourceName); !errors.Is(gerr, ErrNotBound) {
		t.Fatalf("the revoked binding was resurrected: %v", gerr)
	}
	if ok, xerr := v.Exists(ctx, BindingIdentity(bound)); xerr != nil || ok {
		t.Fatalf("a live upstream secret was resurrected after the binding was revoked: exists=%v err=%v", ok, xerr)
	}
}

// The honest shapes the guard above must not break: a first bind and a normal
// re-bind (nothing revoked in between) both still succeed and still store a
// usable secret.
func TestAudit9AFirstBindAndNormalRebindStillWork(t *testing.T) {
	up, challenge := fakeTokenServer(t, "up-token")
	svc, _, v := bindService(t, up.URL)
	ctx := context.Background()

	first, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	*challenge = audit9Challenge(t, first.AuthorizeURL)
	one, _, err := svc.CompleteBind(ctx, "usr_1", first.ID, "code-1")
	if err != nil {
		t.Fatalf("a first bind was refused: %v", err)
	}
	if ok, xerr := v.Exists(ctx, BindingIdentity(one)); xerr != nil || !ok {
		t.Fatalf("a first bind stored no usable secret: exists=%v err=%v", ok, xerr)
	}

	second, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	*challenge = audit9Challenge(t, second.AuthorizeURL)
	two, _, err := svc.CompleteBind(ctx, "usr_1", second.ID, "code-2")
	if err != nil {
		t.Fatalf("a normal re-bind was refused: %v", err)
	}
	if two.Version == one.Version {
		t.Fatalf("the re-bind reused version %d", one.Version)
	}
	if ok, xerr := v.Exists(ctx, BindingIdentity(two)); xerr != nil || !ok {
		t.Fatalf("the re-bind stored no usable secret: exists=%v err=%v", ok, xerr)
	}
}
