package core

// State is the lifecycle state of a Fiber.
type State int

const (
	// StateInactive means the fiber is not loaded: its dependencies are
	// unsatisfied, or it has not been reconciled yet.
	StateInactive State = iota
	// StateLoading means Apply is currently running.
	StateLoading
	// StateActive means the fiber is loaded and its provisions are available.
	StateActive
	// StateUnloading means the fiber's inverses are currently running.
	StateUnloading
	// StateFailed means Apply returned an error or panicked. The fiber provides
	// nothing and its dependents stay INACTIVE.
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateInactive:
		return "inactive"
	case StateLoading:
		return "loading"
	case StateActive:
		return "active"
	case StateUnloading:
		return "unloading"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Component is a unit of dynamic composition.
//
// Provides and Inject together form the component's complete capability
// declaration. The runtime permits a component neither to read a key outside
// Inject nor to publish one outside Provides; any other access fails with
// ErrUndeclared. This is what makes least privilege an enforced property (I1)
// rather than a convention.
//
// Apply is invoked when, and only when, every key in Inject resolves to an
// active provider. It returns an optional Disposer that is treated as the
// activation's final effect; in most cases a component can return nil and rely
// on Context.Effect and Key.Provide for cleanup.
type Component struct {
	Name     string
	Provides []KeyRef
	Inject   []KeyRef
	Apply    func(ctx *Context, cfg any) (Disposer, error)
}

func keySet(refs []KeyRef) map[KeyRef]struct{} {
	m := make(map[KeyRef]struct{}, len(refs))
	for _, r := range refs {
		m[r] = struct{}{}
	}
	return m
}

// Fiber is one instantiation of a Component.
type Fiber struct {
	comp Component
	cfg  any
	app  *App

	ctx    *Context
	state  State
	err    error
	target map[KeyRef]*Fiber // provider identity per declared key
}

// Name returns the component name.
func (f *Fiber) Name() string { return f.comp.Name }

// State returns the fiber's current lifecycle state.
func (f *Fiber) State() State {
	f.app.mu.Lock()
	defer f.app.mu.Unlock()
	return f.state
}

// Err returns the error that moved the fiber to StateFailed, if any.
func (f *Fiber) Err() error {
	f.app.mu.Lock()
	defer f.app.mu.Unlock()
	return f.err
}

// Provides reports the capabilities the fiber currently binds.
func (f *Fiber) Provides() []KeyRef {
	f.app.mu.Lock()
	defer f.app.mu.Unlock()
	var out []KeyRef
	for ref, b := range f.app.store {
		if b.provider == f {
			out = append(out, ref)
		}
	}
	return out
}
