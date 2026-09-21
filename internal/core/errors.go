package core

import (
	"errors"
	"fmt"
)

var (
	// ErrUndeclared reports a capability violation: a component accessed a key
	// it did not declare. This enforces invariant I1 (capability confinement).
	ErrUndeclared = errors.New("core: undeclared capability")

	// ErrUnavailable reports that a declared dependency has no active provider.
	// The component must remain INACTIVE rather than run degraded; this is
	// invariant I5 (fail-closed).
	ErrUnavailable = errors.New("core: dependency unavailable")

	// ErrDuplicate reports an attempt to provide a key that is already bound.
	ErrDuplicate = errors.New("core: capability already provided")

	// ErrTypeMismatch reports that a key's bound value has a type other than
	// the one the accessor expects. Since key identity is (namespace, name),
	// this indicates two declaration sites disagreeing on T.
	ErrTypeMismatch = errors.New("core: capability type mismatch")
)

func undeclared(ref KeyRef) error   { return fmt.Errorf("%w: %s", ErrUndeclared, ref) }
func unavailable(ref KeyRef) error  { return fmt.Errorf("%w: %s", ErrUnavailable, ref) }
func duplicate(ref KeyRef) error    { return fmt.Errorf("%w: %s", ErrDuplicate, ref) }
func typeMismatch(ref KeyRef) error { return fmt.Errorf("%w: %s", ErrTypeMismatch, ref) }
