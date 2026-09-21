package core

// Context is the handle a component uses to interact with its environment.
//
// Every dependency read, provision, and reversible effect is mediated by the
// context, so the runtime can enforce capability confinement (I1) and
// deterministic teardown (I2). A context is bound to exactly one component
// activation; the root context returned by App.Root is the unrestricted
// framework-level exception.
type Context struct {
	app      *App
	owner    *Fiber
	scope    *scope
	injects  map[KeyRef]struct{} // nil on the root context: unrestricted
	provides map[KeyRef]struct{}
}

// Effect runs fn immediately and pushes the inverse it returns onto the
// context's LIFO teardown stack. The returned Disposer reverts the effect
// early and is idempotent.
//
// Anything a component acquires -- memory, file handles, goroutines, decrypted
// plaintext -- must be released through Effect. That is what makes teardown
// deterministic and what guarantees decrypted stoken material is zeroized
// exactly once (invariant I2).
func (c *Context) Effect(fn func() Disposer) Disposer {
	inv := fn()
	if inv == nil {
		inv = func() {}
	}
	d := onceDisposer(inv)
	c.scope.add(d)
	return d
}

// Disposed reports whether the calling activation has already been torn down.
func (c *Context) Disposed() bool { return c.scope.isDisposed() }

// Component returns the name of the component this context belongs to, or
// "<root>" for the root context.
func (c *Context) Component() string {
	if c.owner == nil {
		return "<root>"
	}
	return c.owner.comp.Name
}

func (c *Context) requireInjected(ref KeyRef) error {
	if c.injects == nil {
		return nil
	}
	if _, ok := c.injects[ref]; !ok {
		return undeclared(ref)
	}
	return nil
}

func (c *Context) requireProvided(ref KeyRef) error {
	if c.provides == nil {
		return nil
	}
	if _, ok := c.provides[ref]; !ok {
		return undeclared(ref)
	}
	return nil
}

// Provide binds value under key for as long as the calling activation lives.
// The binding is itself an effect: it is withdrawn when the activation is torn
// down or when the returned Disposer is invoked.
func (k Key[T]) Provide(ctx *Context, value T) (Disposer, error) {
	if err := ctx.requireProvided(k.ref); err != nil {
		return nil, err
	}
	d, err := ctx.app.bind(ctx.owner, k.ref, value)
	if err != nil {
		return nil, err
	}
	ctx.scope.add(d)
	return d, nil
}

// Get resolves a declared dependency.
//
// It returns ErrUndeclared when the key is outside the caller's capability
// declaration, and ErrUnavailable when the key is declared but has no active
// provider.
func (k Key[T]) Get(ctx *Context) (T, error) {
	var zero T
	v, err := ctx.get(k.ref)
	if err != nil {
		return zero, err
	}
	typed, ok := v.(T)
	if !ok {
		return zero, typeMismatch(k.ref)
	}
	return typed, nil
}

// MustGet is Get that panics on error.
//
// It is intended for Component.Apply bodies, where a capability or
// availability failure is a programming error: the runtime only activates a
// component once every declared key resolves. The panic is contained by the
// runtime and turns the fiber FAILED (fail-closed), it does not crash the
// process.
func (k Key[T]) MustGet(ctx *Context) T {
	v, err := k.Get(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (c *Context) get(ref KeyRef) (any, error) {
	if err := c.requireInjected(ref); err != nil {
		return nil, err
	}
	c.app.mu.Lock()
	b, ok := c.app.store[ref]
	if !ok {
		c.app.mu.Unlock()
		return nil, unavailable(ref)
	}
	// A binding counts as available only while its provider is ACTIVE. A
	// provider that is LOADING or UNLOADING has, from the dependent's point of
	// view, already stopped providing.
	active := b.provider == nil || b.provider.state == StateActive
	c.app.mu.Unlock()
	if !active {
		return nil, unavailable(ref)
	}
	return b.value, nil
}
