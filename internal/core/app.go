package core

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
)

// binding is one value in the capability store, together with the fiber that
// published it. A nil provider denotes the root context, whose bindings are
// always available.
type binding struct {
	value    any
	provider *Fiber
}

// Capability is a snapshot of one component's declared authority.
type Capability struct {
	Name     string
	Provides []KeyRef
	Inject   []KeyRef
	State    State
}

// App is the component runtime.
//
// It owns the capability store and drives the reactive lifecycle of every
// Fiber: a fiber loads as soon as its declared dependencies are satisfied by
// active providers, and unloads as soon as they are not. The runtime is
// single-writer by construction -- all lifecycle transitions are serialized by
// reconcile -- while component goroutines may publish capabilities at any time.
type App struct {
	mu     sync.Mutex
	store  map[KeyRef]binding
	fibers []*Fiber
	root   *Context
	closed bool

	// reconcile serialization. reconciling guards admission; dirty records
	// work requested while a reconciliation is already in flight.
	reconcileMu sync.Mutex
	reconciling bool
	dirty       bool
}

// New returns an empty runtime with an unrestricted root context.
func New() *App {
	a := &App{store: make(map[KeyRef]binding)}
	a.root = &Context{app: a, scope: newScope()}
	return a
}

// Root returns the framework-level context. It is not confined to any
// capability declaration; use it only for wiring that is not attributable to a
// component.
func (a *App) Root() *Context { return a.root }

// Use registers a component. The returned fiber starts INACTIVE and activates
// once its dependencies resolve; it is not an error for a dependency to be
// registered afterwards.
func (a *App) Use(c Component, cfg any) (*Fiber, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("core: component name is required")
	}
	if c.Apply == nil {
		return nil, fmt.Errorf("core: component %q has a nil Apply", c.Name)
	}

	f := &Fiber{comp: c, cfg: cfg, app: a, state: StateInactive}

	a.mu.Lock()
	a.fibers = append(a.fibers, f)
	a.mu.Unlock()

	a.requestReconcile()
	return f, nil
}

// Remove retires a fiber and activates no longer. Dependents are deactivated
// before the fiber's own effects are reverted.
func (a *App) Remove(f *Fiber) error {
	a.mu.Lock()
	idx := -1
	for i, g := range a.fibers {
		if g == f {
			idx = i
			break
		}
	}
	if idx < 0 {
		a.mu.Unlock()
		return fmt.Errorf("core: fiber %q is not registered", f.comp.Name)
	}
	a.fibers = append(a.fibers[:idx], a.fibers[idx+1:]...)
	// Stop providing immediately so dependents recompute as unsatisfied.
	if f.state == StateActive {
		f.state = StateUnloading
	}
	a.mu.Unlock()

	a.requestReconcile() // dependents unload first
	a.forceUnload(f)     // then this fiber's own inverses run
	return nil
}

// Shutdown unloads every fiber in dependency order and disposes the root
// context. It is safe to call more than once.
func (a *App) Shutdown() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	a.mu.Unlock()

	for _, f := range a.unloadOrder() {
		a.forceUnload(f)
	}
	a.root.scope.dispose()
}

// Capabilities returns a snapshot of every registered component's declared
// authority and current state. It is the input to the static capability audit
// (invariant I1).
func (a *App) Capabilities() []Capability {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Capability, 0, len(a.fibers))
	for _, f := range a.fibers {
		out = append(out, Capability{
			Name:     f.comp.Name,
			Provides: append([]KeyRef(nil), f.comp.Provides...),
			Inject:   append([]KeyRef(nil), f.comp.Inject...),
			State:    f.state,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Check statically validates the registered composition without running it.
// It reports duplicate providers and dependency cycles, both of which would
// otherwise leave components permanently inactive at runtime.
func (a *App) Check() []error {
	a.mu.Lock()
	defer a.mu.Unlock()

	providers := map[KeyRef][]string{}
	byName := map[string]*Fiber{}
	for _, f := range a.fibers {
		byName[f.comp.Name] = f
		for _, ref := range f.comp.Provides {
			providers[ref] = append(providers[ref], f.comp.Name)
		}
	}

	seen := map[string]bool{}
	var msgs []string
	for ref, names := range providers {
		if len(names) > 1 {
			sort.Strings(names)
			msgs = append(msgs, fmt.Sprintf("duplicate provider for %s: %s", ref, strings.Join(names, ", ")))
		}
	}

	// Cycle detection over the declared dependency graph.
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var stack []string
	var dfs func(name string)
	dfs = func(name string) {
		color[name] = gray
		stack = append(stack, name)
		if f := byName[name]; f != nil {
			for _, ref := range f.comp.Inject {
				for _, p := range providers[ref] {
					switch color[p] {
					case white:
						dfs(p)
					case gray:
						cycle := append([]string(nil), stack[slices.Index(stack, p):]...)
						cycle = append(cycle, p)
						msg := "dependency cycle: " + strings.Join(cycle, " -> ")
						if !seen[msg] {
							seen[msg] = true
							msgs = append(msgs, msg)
						}
					}
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[name] = black
	}
	for _, f := range a.fibers {
		if color[f.comp.Name] == white {
			dfs(f.comp.Name)
		}
	}

	sort.Strings(msgs)
	errs := make([]error, 0, len(msgs))
	for _, m := range msgs {
		errs = append(errs, fmt.Errorf("core: %s", m))
	}
	return errs
}

// bind publishes a value in the capability store and returns its withdrawal.
func (a *App) bind(provider *Fiber, ref KeyRef, value any) (Disposer, error) {
	a.mu.Lock()
	if _, exists := a.store[ref]; exists {
		a.mu.Unlock()
		return nil, duplicate(ref)
	}
	a.store[ref] = binding{value: value, provider: provider}
	a.mu.Unlock()

	a.requestReconcile()

	return onceDisposer(func() {
		a.mu.Lock()
		if b, ok := a.store[ref]; ok && b.provider == provider {
			delete(a.store, ref)
		}
		a.mu.Unlock()
		a.requestReconcile()
	}), nil
}

// requestReconcile schedules a reconciliation, coalescing concurrent requests.
func (a *App) requestReconcile() {
	a.mu.Lock()
	a.dirty = true
	if a.closed || a.reconciling {
		a.mu.Unlock()
		return
	}
	a.reconciling = true
	a.mu.Unlock()

	a.reconcile()
}

// reconcile drives the composition to a fixpoint: repeatedly take one pass
// over the fibers until no state changes and no new work was requested.
func (a *App) reconcile() {
	a.reconcileMu.Lock()
	defer a.reconcileMu.Unlock()

	for {
		a.mu.Lock()
		a.dirty = false
		a.mu.Unlock()

		changed := a.pass()

		a.mu.Lock()
		dirty := a.dirty
		if !changed && !dirty {
			a.reconciling = false
			a.mu.Unlock()
			return
		}
		a.mu.Unlock()
	}
}

func (a *App) pass() bool {
	a.mu.Lock()
	fibers := append([]*Fiber(nil), a.fibers...)
	a.mu.Unlock()

	changed := false
	for _, f := range fibers {
		if a.step(f) {
			changed = true
		}
	}
	return changed
}

// step advances one fiber by at most one transition.
func (a *App) step(f *Fiber) bool {
	a.mu.Lock()

	target, satisfied := a.resolveTargetLocked(f)

	// A fiber loads when it is inactive, or when its resolved providers have
	// changed since its last attempt (which also governs retrying a failure).
	needsLoad := satisfied && (f.state == StateInactive ||
		(f.state == StateActive || f.state == StateFailed) && !maps.Equal(target, f.target))

	switch {
	case needsLoad:
		// A reload (target changed while Active) must revert the previous
		// activation before running the new one.
		old := f.ctx
		f.state = StateLoading
		f.err = nil
		f.target = target
		ctx := &Context{
			app:      a,
			owner:    f,
			scope:    newScope(),
			injects:  keySet(f.comp.Inject),
			provides: keySet(f.comp.Provides),
		}
		f.ctx = ctx
		apply := f.comp.Apply
		cfg := f.cfg
		a.mu.Unlock()

		if old != nil {
			old.scope.dispose()
		}
		d, err := applySafe(apply, ctx, cfg)
		if err != nil {
			// Roll back whatever the failed activation managed to install.
			ctx.scope.dispose()
		} else {
			ctx.scope.add(d)
		}

		a.mu.Lock()
		if err != nil {
			f.state = StateFailed
			f.err = err
		} else {
			f.state = StateActive
		}
		a.mu.Unlock()
		return true

	case !satisfied && (f.state == StateActive || f.state == StateLoading):
		f.state = StateUnloading
		ctx := f.ctx
		a.mu.Unlock()

		if ctx != nil {
			ctx.scope.dispose()
		}

		a.mu.Lock()
		if f.state == StateUnloading {
			f.state = StateInactive
		}
		a.mu.Unlock()
		return true
	}

	a.mu.Unlock()
	return false
}

// resolveTargetLocked computes the provider identity for every declared key.
// It reports false as soon as any declared key has no active provider. a.mu
// must be held.
func (a *App) resolveTargetLocked(f *Fiber) (map[KeyRef]*Fiber, bool) {
	if len(f.comp.Inject) == 0 {
		return map[KeyRef]*Fiber{}, true
	}
	target := make(map[KeyRef]*Fiber, len(f.comp.Inject))
	for _, ref := range f.comp.Inject {
		b, ok := a.store[ref]
		if !ok {
			return nil, false
		}
		if b.provider != nil && b.provider.state != StateActive {
			return nil, false
		}
		target[ref] = b.provider
	}
	return target, true
}

// forceUnload reverts a fiber's effects unconditionally.
func (a *App) forceUnload(f *Fiber) {
	a.mu.Lock()
	if f.state == StateInactive {
		a.mu.Unlock()
		return
	}
	ctx := f.ctx
	f.state = StateUnloading
	f.target = nil
	a.mu.Unlock()

	if ctx != nil {
		ctx.scope.dispose()
	}

	a.mu.Lock()
	if f.state == StateUnloading {
		f.state = StateInactive
	}
	a.mu.Unlock()
}

// unloadOrder returns the fibers such that a dependent precedes its providers.
func (a *App) unloadOrder() []*Fiber {
	a.mu.Lock()
	defer a.mu.Unlock()

	var order []*Fiber
	seen := map[*Fiber]int{} // 0 unvisited, 1 in progress, 2 done
	var visit func(f *Fiber)
	visit = func(f *Fiber) {
		if seen[f] != 0 {
			return
		}
		seen[f] = 1
		for _, ref := range f.comp.Inject {
			if b, ok := a.store[ref]; ok && b.provider != nil {
				visit(b.provider)
			}
		}
		seen[f] = 2
		order = append(order, f)
	}
	for _, f := range a.fibers {
		visit(f)
	}
	// order lists providers before dependents; teardown wants the reverse.
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}
	return order
}

// applySafe runs a component entry point, converting a panic into an error so
// that a faulty component fails closed instead of crashing the runtime.
func applySafe(apply func(*Context, any) (Disposer, error), ctx *Context, cfg any) (d Disposer, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("core: component %q panicked: %v", ctx.Component(), r)
		}
	}()
	return apply(ctx, cfg)
}
