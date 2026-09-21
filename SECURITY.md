# Security Policy

## Project status: pre-release

**Re0Auth is not production-ready.** Do not deploy it with real user credentials.

Known and documented limitations (these are *not* vulnerabilities; please do not
report them):

- The vault's credential store, pending authorization requests, source bindings
  and session store are still in-memory. **Upstream credentials do not survive a
  restart.** The server announces each of these at startup.
- No frontend ships with the server; only the HTTP APIs exist.
- The reference data source (`referencesource`) is a demonstration. Its demo
  login is explicitly a stub.

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
  `docs/threat-model.md` §3, B5), and we do not claim to defend against them.
- Missing hardening that is already documented as a known limitation above.
- Missing rate limits, missing WAF, or the absence of a frontend.
- The `referencesource` demo login, which is a stub by design.

## Design context

Two documents will save you time before reporting:

- `docs/threat-model.md` — the assets, the trust boundaries, and the risks we
  have already accepted.
- `docs/architecture.md` — the invariants the tests are meant to guard.

If you believe one of our stated invariants is violated, that is a high-value
report: the invariants are the product.
