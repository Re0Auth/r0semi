package core_test

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/internal/core"
)

var (
	keyAlpha = core.NewKey[string]("test", "alpha")
	keyBeta  = core.NewKey[int]("test", "beta")
	keyGamma = core.NewKey[string]("test", "gamma")
)

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.events = append(r.events, s)
	r.mu.Unlock()
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// I2: effects are reverted in reverse registration order.
func TestEffectRunsLIFO(t *testing.T) {
	app := core.New()
	var rec recorder

	if _, err := app.Use(core.Component{
		Name: "c",
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			for _, name := range []string{"a", "b", "c"} {
				name := name
				ctx.Effect(func() core.Disposer {
					return func() { rec.add(name) }
				})
			}
			return nil, nil
		},
	}, nil); err != nil {
		t.Fatal(err)
	}

	app.Shutdown()

	if got, want := rec.snapshot(), []string{"c", "b", "a"}; !slices.Equal(got, want) {
		t.Fatalf("teardown order = %v, want %v", got, want)
	}
}

func TestDisposerIsIdempotent(t *testing.T) {
	app := core.New()
	count := 0

	if _, err := app.Use(core.Component{
		Name: "c",
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			d := ctx.Effect(func() core.Disposer {
				return func() { count++ }
			})
			d()
			d()
			return nil, nil
		},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("early dispose count = %d, want 1", count)
	}

	app.Shutdown()
	if count != 1 {
		t.Fatalf("count after shutdown = %d, want 1", count)
	}
}

// I1: a component cannot read a key it did not declare, even when that key is
// available in the store.
func TestUndeclaredCapabilityIsRejected(t *testing.T) {
	app := core.New()

	// keyAlpha is genuinely provided and available.
	if _, err := app.Use(core.Component{
		Name:     "provider",
		Provides: []core.KeyRef{keyAlpha.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			_, err := keyAlpha.Provide(ctx, "secret")
			return nil, err
		},
	}, nil); err != nil {
		t.Fatal(err)
	}

	// keyBeta is provided by the root so the "attacker" can activate.
	if _, err := keyBeta.Provide(app.Root(), 7); err != nil {
		t.Fatal(err)
	}

	attacker, err := app.Use(core.Component{
		Name:   "attacker",
		Inject: []core.KeyRef{keyBeta.Ref()}, // does not declare keyAlpha
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			_, err := keyAlpha.Get(ctx)
			return nil, err
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := attacker.State(); got != core.StateFailed {
		t.Fatalf("attacker state = %s, want failed", got)
	}
	if !errors.Is(attacker.Err(), core.ErrUndeclared) {
		t.Fatalf("attacker err = %v, want ErrUndeclared", attacker.Err())
	}
}

// I1: publishing a key outside Provides is likewise rejected.
func TestProvideRequiresDeclaration(t *testing.T) {
	app := core.New()
	f, err := app.Use(core.Component{
		Name: "publisher",
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			_, err := keyAlpha.Provide(ctx, "x")
			return nil, err
		},
	}, nil) // no Provides declared
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(f.Err(), core.ErrUndeclared) {
		t.Fatalf("err = %v, want ErrUndeclared", f.Err())
	}
}

// I5: a component whose dependency has no provider never runs.
func TestFailClosedMissingProvider(t *testing.T) {
	app := core.New()
	called := false

	f, err := app.Use(core.Component{
		Name:   "needs-alpha",
		Inject: []core.KeyRef{keyAlpha.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			called = true
			return nil, nil
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if called {
		t.Fatal("Apply ran without its dependency")
	}
	if got := f.State(); got != core.StateInactive {
		t.Fatalf("state = %s, want inactive", got)
	}
}

// I5 + reactivity: a dependent activates when its provider appears and
// deactivates, before the provider, when the provider is removed.
func TestReactiveActivationAndDeactivation(t *testing.T) {
	app := core.New()
	var rec recorder

	dependent, err := app.Use(core.Component{
		Name:   "dependent",
		Inject: []core.KeyRef{keyAlpha.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			v := keyAlpha.MustGet(ctx)
			rec.add("dep:active:" + v)
			return func() { rec.add("dep:inactive") }, nil
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := dependent.State(); got != core.StateInactive {
		t.Fatalf("dependent state = %s, want inactive", got)
	}

	provider, err := app.Use(core.Component{
		Name:     "provider",
		Provides: []core.KeyRef{keyAlpha.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			rec.add("prov:active")
			if _, err := keyAlpha.Provide(ctx, "v1"); err != nil {
				return nil, err
			}
			return func() { rec.add("prov:inactive") }, nil
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := dependent.State(); got != core.StateActive {
		t.Fatalf("dependent state = %s, want active", got)
	}
	if got, want := rec.snapshot(), []string{"prov:active", "dep:active:v1"}; !slices.Equal(got, want) {
		t.Fatalf("activation events = %v, want %v", got, want)
	}

	if err := app.Remove(provider); err != nil {
		t.Fatal(err)
	}
	if got := dependent.State(); got != core.StateInactive {
		t.Fatalf("dependent state after remove = %s, want inactive", got)
	}
	// Dependents tear down before their provider.
	if got, want := rec.snapshot(), []string{"prov:active", "dep:active:v1", "dep:inactive", "prov:inactive"}; !slices.Equal(got, want) {
		t.Fatalf("teardown events = %v, want %v", got, want)
	}
}

// I2: decrypted material acquired by a component is zeroized exactly when the
// activation is torn down.
func TestZeroizeOnUnload(t *testing.T) {
	app := core.New()
	plaintext := []byte("tapstoken-plaintext")
	var buf []byte

	if _, err := app.Use(core.Component{
		Name: "vault-client",
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			buf = append([]byte(nil), plaintext...)
			ctx.Effect(func() core.Disposer {
				return func() {
					for i := range buf {
						buf[i] = 0
					}
				}
			})
			return nil, nil
		},
	}, nil); err != nil {
		t.Fatal(err)
	}

	if buf[0] == 0 {
		t.Fatal("plaintext should be live while the activation is active")
	}
	app.Shutdown()
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("plaintext byte %d not zeroized: %v", i, buf)
		}
	}
}

// A failed activation is rolled back, not left half-installed.
func TestFailedApplyRollsBackEffects(t *testing.T) {
	app := core.New()
	var rec recorder

	f, err := app.Use(core.Component{
		Name: "flaky",
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			ctx.Effect(func() core.Disposer {
				return func() { rec.add("reverted") }
			})
			return nil, errors.New("boom")
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := f.State(); got != core.StateFailed {
		t.Fatalf("state = %s, want failed", got)
	}
	if got, want := rec.snapshot(), []string{"reverted"}; !slices.Equal(got, want) {
		t.Fatalf("rollback events = %v, want %v", got, want)
	}
}

func TestDuplicateProviderFailsClosed(t *testing.T) {
	app := core.New()

	if _, err := app.Use(core.Component{
		Name:     "p1",
		Provides: []core.KeyRef{keyAlpha.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			_, err := keyAlpha.Provide(ctx, "first")
			return nil, err
		},
	}, nil); err != nil {
		t.Fatal(err)
	}

	p2, err := app.Use(core.Component{
		Name:     "p2",
		Provides: []core.KeyRef{keyAlpha.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			_, err := keyAlpha.Provide(ctx, "second")
			return nil, err
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := p2.State(); got != core.StateFailed {
		t.Fatalf("p2 state = %s, want failed", got)
	}
	if !errors.Is(p2.Err(), core.ErrDuplicate) {
		t.Fatalf("p2 err = %v, want ErrDuplicate", p2.Err())
	}
	if v, err := keyAlpha.Get(app.Root()); err != nil || v != "first" {
		t.Fatalf("keyAlpha = %q, %v; want %q", v, err, "first")
	}
}

// A dependency cycle leaves both components permanently inactive rather than
// deadlocking or partially loading.
func TestCycleStaysInactive(t *testing.T) {
	app := core.New()
	ran := false

	a, _ := app.Use(core.Component{
		Name:     "a",
		Provides: []core.KeyRef{keyAlpha.Ref()},
		Inject:   []core.KeyRef{keyBeta.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			ran = true
			return nil, nil
		},
	}, nil)
	b, _ := app.Use(core.Component{
		Name:     "b",
		Provides: []core.KeyRef{keyBeta.Ref()},
		Inject:   []core.KeyRef{keyAlpha.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			ran = true
			return nil, nil
		},
	}, nil)

	if ran {
		t.Fatal("a component in a cycle ran")
	}
	if a.State() != core.StateInactive || b.State() != core.StateInactive {
		t.Fatalf("states = %s, %s; want inactive, inactive", a.State(), b.State())
	}
}

func TestCheckReportsCyclesAndDuplicates(t *testing.T) {
	app := core.New()

	mustUse := func(c core.Component) {
		t.Helper()
		if _, err := app.Use(c, nil); err != nil {
			t.Fatal(err)
		}
	}

	noop := func(ctx *core.Context, cfg any) (core.Disposer, error) { return nil, nil }
	mustUse(core.Component{Name: "a", Provides: []core.KeyRef{keyAlpha.Ref()}, Inject: []core.KeyRef{keyBeta.Ref()}, Apply: noop})
	mustUse(core.Component{Name: "b", Provides: []core.KeyRef{keyBeta.Ref()}, Inject: []core.KeyRef{keyAlpha.Ref()}, Apply: noop})
	mustUse(core.Component{Name: "c", Provides: []core.KeyRef{keyGamma.Ref()}, Apply: noop})
	mustUse(core.Component{Name: "d", Provides: []core.KeyRef{keyGamma.Ref()}, Apply: noop})

	errs := app.Check()
	if len(errs) == 0 {
		t.Fatal("Check returned no findings")
	}
	var joined strings.Builder
	for _, err := range errs {
		joined.WriteString(err.Error())
		joined.WriteByte('\n')
	}
	if !strings.Contains(joined.String(), "cycle") {
		t.Fatalf("Check findings missing cycle:\n%s", joined.String())
	}
	if !strings.Contains(joined.String(), "duplicate provider") {
		t.Fatalf("Check findings missing duplicate:\n%s", joined.String())
	}
}

func TestCapabilitiesAudit(t *testing.T) {
	app := core.New()

	if _, err := app.Use(core.Component{
		Name:     "vault",
		Provides: []core.KeyRef{keyAlpha.Ref()},
		Inject:   []core.KeyRef{keyBeta.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			return nil, nil
		},
	}, nil); err != nil {
		t.Fatal(err)
	}

	caps := app.Capabilities()
	if len(caps) != 1 {
		t.Fatalf("len(caps) = %d, want 1", len(caps))
	}
	got := caps[0]
	if got.Name != "vault" || len(got.Provides) != 1 || got.Provides[0] != keyAlpha.Ref() {
		t.Fatalf("capability = %+v", got)
	}
	if len(got.Inject) != 1 || got.Inject[0] != keyBeta.Ref() {
		t.Fatalf("inject = %v", got.Inject)
	}
}

func TestPanicInApplyFailsClosed(t *testing.T) {
	app := core.New()

	f, err := app.Use(core.Component{
		Name: "panicky",
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			panic("kaboom")
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.State(); got != core.StateFailed {
		t.Fatalf("state = %s, want failed", got)
	}
	if f.Err() == nil || !strings.Contains(f.Err().Error(), "panicked") {
		t.Fatalf("err = %v, want panic report", f.Err())
	}
}

func TestRootProvidedCapabilityIsAvailable(t *testing.T) {
	app := core.New()
	if _, err := keyAlpha.Provide(app.Root(), "from-root"); err != nil {
		t.Fatal(err)
	}

	f, err := app.Use(core.Component{
		Name:   "consumer",
		Inject: []core.KeyRef{keyAlpha.Ref()},
		Apply: func(ctx *core.Context, cfg any) (core.Disposer, error) {
			if got := keyAlpha.MustGet(ctx); got != "from-root" {
				t.Fatalf("got %q", got)
			}
			return nil, nil
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.State(); got != core.StateActive {
		t.Fatalf("state = %s, want active", got)
	}
}
