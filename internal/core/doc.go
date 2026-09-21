// Package core implements the r0semi component runtime: a minimal,
// self-contained kernel providing
//
//   - typed, namespaced capability keys          (Key[T], KeyRef)
//   - revertible effects with LIFO teardown       (Context.Effect, Disposer)
//   - reactive dependency resolution              (Component, Fiber, App)
//
// It deliberately omits hot module replacement, runtime code loading, and
// dynamic interception. The design rationale is recorded in
// docs/architecture.md; the security invariants it must uphold (I1, I2, I5)
// are recorded in docs/threat-model.md and exercised by core_test.go.
package core
