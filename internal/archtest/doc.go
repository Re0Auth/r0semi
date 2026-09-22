// Package archtest holds machine checks for the module's dependency direction.
//
// The project's layering (docs/architecture.md §4) and its public/internal
// split are only real if a machine refuses to let them rot. This package is that
// machine: instead of trusting a code review to notice the day a public library
// starts importing internal/, or a domain package reaches for the Postgres
// adapter, the checks below read the real import graph with `go list` and fail.
//
// The approach is the Go counterpart of the sibling project r0semi-mp's
// tools/check-deps.py, and it exists for the reason recorded there: a dependency
// firewall is cheap and must be built on day one, while interfaces can wait.
// Running it as a test (rather than a separate CI step) means `go test ./...`
// cannot forget it.
package archtest
