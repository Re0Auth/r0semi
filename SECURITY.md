# Security Policy

## Project status: pre-release

**Re0Auth is not production-ready.** Do not deploy it with real user credentials.

Known and documented limitations (these are *not* vulnerabilities; please do not
report them):

- With no `DATABASE_URL`, every store falls back to memory and the server says
  so at startup; a restart then loses sessions, bindings and pending requests.
  With Postgres set, the nine storage ports and the audit log are durable.
- The KEK is supplied through the environment and lives in the process. A
  database dump is useless without it, but a leaked key or a compromised process
  can read every credential it wrapped. There is no KMS/HSM adapter yet; what
  that would and would not buy is in `docs/threat-model.md` §6.0.
- The reference data source (`referencesource`) is a demonstration. Its own
  vault and sessions are in-memory, and its demo login is a stub.
- v1 issues plain bearer tokens. DPoP (RFC 9449) is deliberately not offered,
  and the authorization server metadata does not advertise it.
- The component runtime in `internal/core` is exercised by its own tests and by
  `internal/wiring`; the production composition root in `cmd/re0auth` wires the
  services directly, so its capability-confinement checks are **by decision**
  (ADR-0002, `docs/core-runtime-decision.md`) not a gate on a real deployment.
  The dependency direction that *is* machine-enforced is the package-level
  firewall in `internal/archtest`.

We still want reports: a flaw in the design of a credential-holding system is
worth knowing about before it is deployed anywhere, which is exactly why this
project is developed in the open.

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). If that is unavailable, email the
maintainer at the address on the GitHub profile linked from the repository.

Include, as far as you can:

- a description of the issue and the impact you believe it has;
- the affected component (for example `vault`, `oauth`, `idp`, `federation`);
- reproduction steps or a proof of concept;
- any suggested fix or mitigation.

### Two hard rules

1. **Never send live credentials.** No real `sessionToken`, no API keys, no
   OAuth tokens, no personal data. If you need to demonstrate something, mint
   throwaway values or use a disposable account.
2. **Do not test against someone else's deployment.** Test against your own
   local instance.

## What we commit to

- **Acknowledgement** within 5 working days.
- **An initial assessment** (accepted / needs more information / out of scope)
  within 14 days.
- **Coordinated disclosure**: we will agree a disclosure date with you, and
  credit you in the release notes unless you ask us not to.
- If we disagree that something is a vulnerability, we will explain why rather
  than simply closing the report.

There is no bug bounty. This is an unfunded project.

## Scope

**In scope**

- The authorization server core (`oauth/`): protocol handling, token lifecycle,
  PKCE, scope and consent enforcement, introspection and revocation.
- The credential vault (`vault/`): envelope encryption, key handling, the
  plaintext window, and the zeroization guarantees it claims.
- The OIDC/IdP client (`idp/`): `id_token` verification, nonce handling,
  request forgery, open redirects.
- The Upstream Kit and its conformance suite (`upstreamkit/`).
- The federation layer (`internal/federation`): binding, provenance, refresh,
  and its interaction with the vault.
- The HTTP layers (`internal/httpapi`): plane separation, authentication,
  authorization, CSRF, session handling.

**Out of scope**

- Vulnerabilities in third-party dependencies. Report those upstream; if the
  issue is how we *use* a dependency, that is in scope here.
- Findings that require a compromised host, a malicious operator, or physical
  access. The operators are explicitly outside the trust boundary (see
  `docs/threat-model.md` §3, B6), and we do not claim to defend against them.
- Missing hardening that is already documented as a known limitation above.
- Missing rate limits, missing WAF, or the absence of a reverse proxy in front
  of a public instance.
- The `referencesource` demo login, which is a stub by design.

## Design context

Two documents will save you time before reporting:

- `docs/threat-model.md` — the assets, the trust boundaries, and the risks we
  have already accepted.
- `docs/architecture.md` — the invariants the tests are meant to guard.

If you believe one of our stated invariants is violated, that is a high-value
report: the invariants are the product.

## Our own audits

We run an adversarial pass against our own invariants rather than waiting for
someone else to. The rounds so far are on disk:

- [`docs/security-audit-2.md`](docs/security-audit-2.md) — the invariant sweep:
  token issuance, account isolation, revocation, credential containment,
  fail-closed. Every finding, with the test that pins it.
- [`docs/security-audit-3.md`](docs/security-audit-3.md) — the targeted round:
  the seam with the third-party OpenID Provider library, the audit-log read
  surface, and the device flow's concurrency and binding. Same rule: a finding is
  not a finding until a test can fail on it.

Each finding's reproducer is now part of the ordinary suite: it failed before the
fix and passes after, so it guards the fix the way any other test guards its
subject. They are grouped in `adversary_test.go` next to the code they attack,
and each names the finding it pins.
