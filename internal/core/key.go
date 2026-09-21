package core

// KeyRef is the type-erased identity of a capability key: a namespace plus a
// name. It is comparable and may therefore be used as a map key.
type KeyRef struct {
	Namespace string
	Name      string
}

func (r KeyRef) String() string { return r.Namespace + "/" + r.Name }

// Key is a typed, namespaced capability key.
//
// Identity is (namespace, name). The type parameter T only supplies
// compile-time type safety for values exchanged under the key; two Key values
// sharing a namespace and name denote the same capability regardless of T, and
// the store rejects a conflicting second binding.
type Key[T any] struct {
	ref KeyRef
}

// NewKey constructs a capability key.
//
// It panics when namespace or name is empty: an unnamed capability cannot be
// audited or confined, so it is a programming error rather than a runtime
// condition.
func NewKey[T any](namespace, name string) Key[T] {
	if namespace == "" || name == "" {
		panic("core: key namespace and name must be non-empty")
	}
	return Key[T]{ref: KeyRef{Namespace: namespace, Name: name}}
}

// Ref returns the type-erased identity of the key.
func (k Key[T]) Ref() KeyRef { return k.ref }

func (k Key[T]) String() string { return k.ref.String() }
