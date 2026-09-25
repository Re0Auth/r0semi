<!--
Keep the PR description short and concrete. If a section does not apply, delete it.
-->

## What this changes

<!-- One paragraph. Link the issue if there is one. -->

## Why

<!-- The problem, not the patch. Reviewers can read the diff. -->

## Checklist

- [ ] `make check` passes (gofmt, `go vet`, golangci-lint, the dependency firewall, `svelte-check`)
- [ ] `go test ./...` passes
- [ ] Storage-layer changes: `TEST_DATABASE_URL` integration tests were run
- [ ] Contract changes (protocol, API, component capabilities) are reflected in `docs/`
- [ ] Operator-visible or breaking changes are recorded in `CHANGELOG.md`
- [ ] New behaviour has tests; a bug fix has a test that reproduced the bug
- [ ] New dependencies are justified below and `NOTICE` is updated if needed

## Contributions are accepted only under the contributor agreement

By submitting this pull request I have read and agree to the
[license and relicensing agreement](CONTRIBUTING.md), including the license and
sublicense grant in clause 2, the patent grant and its termination clause in
clause 3, and the relicensing option in clause 4. I confirm I have the right to
make that grant (and, if employed, that my employer agrees), and that I am not
submitting code I do not have the rights to.

- [ ] I agree to the contributor agreement (**required**)
