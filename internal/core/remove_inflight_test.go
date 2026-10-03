package core

import (
	"sync/atomic"
	"testing"
	"time"
)

var keyRemoveRace = NewKey[string]("remove-race", "cap")

// TestRemoveWhileApplyInFlight is the white-box regression probe for S03-11=A.
//
// It removes a fiber while its Apply is still running. Remove's forceUnload
// tears the activation down and marks the fiber inactive, but Apply then
// completes and step re-acquires a.mu. Without the retired check, step would
// unconditionally write StateActive, resurrecting a fiber that is no longer in
// a.fibers and whose scope has already been disposed.
func TestRemoveWhileApplyInFlight(t *testing.T) {
	app := New()

	entered := make(chan *Fiber, 1)
	release := make(chan struct{})
	var ctxSeen *Context
	var inverses atomic.Int32

	comp := Component{
		Name:     "in-flight",
		Provides: []KeyRef{keyRemoveRace.Ref()},
		Apply: func(ctx *Context, cfg any) (Disposer, error) {
			ctxSeen = ctx
			// Install a capability binding and a reversible effect, then block
			// so Remove runs while this activation is still in flight.
			if _, err := keyRemoveRace.Provide(ctx, "v1"); err != nil {
				return nil, err
			}
			ctx.Effect(func() Disposer {
				return func() { inverses.Add(1) }
			})
			entered <- ctx.owner
			<-release
			return nil, nil
		},
	}

	useDone := make(chan error, 1)
	go func() {
		_, err := app.Use(comp, nil)
		useDone <- err
	}()

	var f *Fiber
	select {
	case f = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Apply never started")
	}

	if err := app.Remove(f); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	close(release)

	// Use returns only after reconcile reaches its fixpoint, so this is a
	// happens-before barrier for step's post-Apply state write.
	select {
	case err := <-useDone:
		if err != nil {
			t.Fatalf("Use: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Use never returned")
	}

	if got := f.State(); got == StateActive {
		t.Fatalf("fiber removed while loading was resurrected to %s", got)
	}
	if got := f.State(); got != StateInactive {
		t.Fatalf("final state = %s, want inactive", got)
	}
	if ctxSeen == nil {
		t.Fatal("Apply did not run")
	}
	if !ctxSeen.scope.isDisposed() {
		t.Fatal("activation scope of the removed fiber is not disposed")
	}
	if inverses.Load() == 0 {
		t.Fatal("activation inverse never ran")
	}

	app.mu.Lock()
	_, bound := app.store[keyRemoveRace.Ref()]
	residual := 0
	for _, b := range app.store {
		if b.provider == f {
			residual++
		}
	}
	app.mu.Unlock()
	if bound || residual != 0 {
		t.Fatalf("store still binding for removed fiber: keyBound=%v residual=%d", bound, residual)
	}

	for _, c := range app.Capabilities() {
		if c.Name == comp.Name {
			t.Fatalf("Capabilities still lists removed fiber: %+v", c)
		}
	}
}
