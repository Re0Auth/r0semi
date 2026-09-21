package core

import "sync"

// Disposer reverts one effect. A Disposer handed out by the core is
// idempotent: invoking it more than once has no additional effect.
type Disposer func()

// onceDisposer wraps fn so that it runs at most once.
func onceDisposer(fn func()) Disposer {
	var once sync.Once
	return func() { once.Do(fn) }
}

// scope is the LIFO stack of inverses belonging to one component activation.
type scope struct {
	mu       sync.Mutex
	stack    []Disposer
	disposed bool
}

func newScope() *scope { return &scope{} }

// add registers an inverse. If the scope is already disposed the inverse runs
// immediately, so an effect racing with teardown is never left dangling.
func (s *scope) add(d Disposer) {
	if d == nil {
		return
	}
	s.mu.Lock()
	if s.disposed {
		s.mu.Unlock()
		d()
		return
	}
	s.stack = append(s.stack, d)
	s.mu.Unlock()
}

func (s *scope) isDisposed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disposed
}

// dispose runs every registered inverse in reverse registration order, so each
// inverse observes the state its own forward effect produced. It is
// idempotent.
func (s *scope) dispose() {
	s.mu.Lock()
	if s.disposed {
		s.mu.Unlock()
		return
	}
	s.disposed = true
	stack := s.stack
	s.stack = nil
	s.mu.Unlock()

	for i := len(stack) - 1; i >= 0; i-- {
		stack[i]()
	}
}
