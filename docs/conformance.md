# OpenID Conformance Suite (spike → nightly → release gate)

This is the plan's step 3/4: get the OpenID Foundation's official
[conformance suite](https://openid.net/certification/) wired into CI, run it every
night until it is green, and only then make it a release gate.

**Status: experimental.** The job is report-only (`continue-on-error`). It proves
connectivity and prints the suite's plan catalogue; it does not yet assert a plan
result.

## Why it is worth a slot

The protocol core is `zitadel/oidc` (itself a certified implementation), but the
things that are ours are exactly the things a self-written test suite has already
missed once: the authorize/login boundary, `auth_time`/`max_age`, `prompt=none`,
the scope pre-flights and the store wiring. Round 9 found S02-1 (a fabricated
`auth_time`) and S02-2 (`prompt=none` rendering the consent UI) by reading code;
the conformance suite is the black-box, third-party, adversarial layer that would
have caught them on every commit.

## How it runs

`.github/workflows/conformance.yml` (nightly + `workflow_dispatch`) runs
`scripts/conformance/spike.sh`, which:

1. builds `cmd/re0auth` and starts it on `:8080` with generated keys and a seeded
   `[client]`;
2. starts `caddy:2` as a TLS terminator (`tls internal`, self-signed) on `:8443`
   for `https://re0auth.test:8443`, reversing to the OP;
3. fetches discovery through Caddy from the host;
4. fetches it again from a **container** using Caddy's extracted root CA — the
   path the suite container will use;
5. builds a derived suite image that imports Caddy's CA into the JVM `cacerts`
   (the JVM ignores a mounted PEM), falling back to the upstream image if that
   build fails;
6. starts the suite **and its MongoDB** — the published suite image is the server
   half of the project's compose topology: it listens on `:8080` and needs a
   `mongo` beside it (`mongo:6.0.13`, the version the project pins). The suite
   **refuses plain HTTP** (`RejectPlainHttpTrafficFilter` demands scheme `https`,
   and `server.forward-headers-strategy=NATIVE` honors `X-Forwarded-Proto`), so the
   Caddy instance doubles as its TLS front: a second site serves
   `https://oidf-suite:8443`, Caddy joins the spike network under that name, and the
   suite's `cacerts` already carries the issuing CA from milestone 4b. Prints the
   **plan** catalogue from `GET /api/plan/available` (milestones 1–5, plus 4b).
7. when a plan payload is supplied, builds the OP with the `conformance` build tag
   and its auto-login opt-in (see the headless gap below), then runs the suite's own
   flow through `scripts/conformance/run-plan.py`:
   `POST /api/plan?planName=…&variant=…` → for each module,
   `POST /api/runner?test=<module>&plan=<id>`, long-poll
   `GET /api/runner/<id>/wait-state`, **visit the front-channel URLs** the suite
   lists (`GET /api/runner/browser/<id>` → real GET → `POST …/visit`) and read the
   final `GET /api/info/<id>`. The visit also runs the one piece of JavaScript a plain
   HTTP client cannot: the suite's callback answers with the `implicitCallback` page,
   whose script POSTs the URL fragment (empty for a query-mode response) to a one-time
   `/implicit/<random>` URL — without that POST the module waits forever and the code
   is never exchanged. Modules run one at a time — creating a whole plan's worth at
   once interrupts the suite's configuration (30 of 35 modules ended INTERRUPTED on
   the first real run). Failures carry their `GET /api/log/<id>` reasons into the
   summary, and a module that stops for a human is tagged
   `interactive: human-step` rather than read as a protocol bug — that includes the
   suite's `REVIEW` placeholders, e.g. `oidcc-prompt-login`'s "a screenshot of this
   must be uploaded".
   `max_modules` caps the run for a smoke test (milestones 6–7). The payload shape and
   the ready-made Basic OP file are in `scripts/conformance/plans/`.

Every milestone is written to `conformance-artifacts/summary.md`, which the
workflow appends to the run's **step summary** — that table is what the nightly
"check last night's report" routine reads, no artifact download needed.

Local runs need Docker, which this project's Windows host does not have: use WSL2
or a Linux machine.

```sh
SPIKE_ARTIFACTS=$PWD/conformance-artifacts \
  bash scripts/conformance/spike.sh
```

## Running a plan

`workflow_dispatch` takes three inputs:

| input | meaning |
|---|---|
| `plan_json` | repo-relative path to a plan payload (our wrapper around the suite's `POST /api/plan`; see [`scripts/conformance/plans/README.md`](../scripts/conformance/plans/README.md)). **Leave empty on the first run**: the spike then prints the suite's plan catalogue under "Available plans" in the run summary. |
| `redirect_uri` | the redirect URI seeded into the OP's `[client]`. It must equal the one the suite generates for the test; read it from the suite and pass it back here so both sides match. Blank keeps the script default. |
| `require_plan` | when true, the script exits non-zero unless the plan reaches `FINISHED` with `SUCCESS`/`WARNING`/`REVIEW`/`SKIPPED`. Use this once the nightly is green — it is the same switch as dropping `continue-on-error`. |

**First run, concretely:** dispatch with `plan_json` empty. Read the milestone table
and the plan list in the run summary, and `available.json` in the
`conformance-spike` artifact. Then copy
[`scripts/conformance/plans/basic-op.example.json`](../scripts/conformance/plans/basic-op.example.json)
to a real payload, fill it from that catalogue, and dispatch again with
`plan_json` set (plus `redirect_uri` if the suite's value differs from the seeded
one).

## Dispatch it in one command

[`scripts/conformance/dispatch.sh`](../scripts/conformance/dispatch.sh) dispatches
the workflow through the REST API, waits for the run, downloads the
`conformance-spike` artifact and prints the summary and the verdict — no web UI, no
manual download:

```sh
scripts/conformance/dispatch.sh                  # the ready-made Basic OP plan, all modules
scripts/conformance/dispatch.sh --max-modules 5  # smoke run
scripts/conformance/dispatch.sh --dry-run        # print the REST call, send nothing
```

Credentials come from `GH_TOKEN` / `GITHUB_TOKEN`, or from `gh auth token` when the
CLI is installed (this host has no `gh`, so the REST path is the one in use). The
token needs `workflow` (classic PAT) or *Actions: read and write* (fine-grained);
artifact download needs it even for a public repository. Runs land in
`conformance-runs/<timestamp>/` (git-ignored): `summary.md` is the table the run's
step summary shows, `plan-run.json` holds every module's verdict and reasons, and
`suite-logs/` holds the full suite log of each module that did not pass. Exit code
`0` means the plan passed (or none ran), `2` means the run finished without passing,
`1` is an operational failure. `_audit/conformance/dispatch-check.sh` pins the
argument parsing and the payload it would send.

Environment equivalents for a direct script run: `CONFORMANCE_PLAN_JSON`,
`CONFORMANCE_REQUIRE_PLAN=1`, `CONFORMANCE_REDIRECT_URI`,
`CONFORMANCE_PLAN_MAX_MODULES`, `CONFORMANCE_PLAN_TIMEOUT_SECONDS`,
`CONFORMANCE_PLAN_MODULE_TIMEOUT_SECONDS`, `CONFORMANCE_PLAN_VISIT_ROUNDS`,
`CONFORMANCE_PLAN_VISIT_DELAY_SECONDS`, `CONFORMANCE_CLIENT_SECRET`. The OP-side
exemption is `RE0AUTH_CLIENT_ALLOW_MISSING_PKCE`; the script writes
`[client] allow_missing_pkce = true` itself once a plan is requested.

## The first real finding: mandatory PKCE vs the Basic OP profile

The first plan run produced one substantive result, and it was a policy collision
rather than an OP bug:

- The suite's OP tests send an authorization request **without `code_challenge`**
  (`oidcc-server`'s front-channel URL carries only client_id, nonce, redirect_uri,
  response_type, scope, state).
- Re0Auth **mandates PKCE S256 for every client** (`internal/oidchttp/oidchttp.go`'s
  PKCE gate; `docs/api-design.md` §207; guarded by `TestAuthorizeRequiresPKCE` and
  `TestZZAudit_ConfidentialClientNeedsPKCE`), so the OP answered the only way its own
  policy allows: `error=invalid_request&error_description=code_challenge is required`.
  The module then stayed `WAITING`; `run-plan.py` stopped it after a few unproductive
  rounds and reported `divergence: pkce-required`.

**Resolution: a per-client exemption, defaulting to strict.** `[client]
allow_missing_pkce = true` (or `RE0AUTH_CLIENT_ALLOW_MISSING_PKCE`) registers one
client that may omit `code_challenge` — the shape a certification suite or a legacy
RP needs. It is opt-in (the field's zero value keeps PKCE mandatory), it is compared
by the startup drift check like every other field, the startup log says the client is
exempt, and each authorization that actually uses the exemption logs a WARN. A
challenge that *is* sent still has to be a well-formed S256 value: the switch covers
"no PKCE", not "any PKCE". See ADR-0005 §7b.

The spike writes the exemption only when a plan is requested (`CONFORMANCE_PLAN_JSON`
points at a file), so a connectivity-only run keeps the fully strict client. If the
modules still report `divergence: pkce-required`, the OP was started without the
exemption — check `op.log` for the startup WARN and for
`authorization request without PKCE accepted for an exempt client`.

## Known gaps (the reason this is still a spike)

- **JVM trust store.** Addressed by milestone 4b: the script builds a derived image
  `FROM registry.gitlab.com/openid/conformance-suite:latest` (the base is
  `eclipse-temurin:21`, so the JDK is at `/opt/java/openjdk`) that runs
  `keytool -importcert` against its `cacerts` with Caddy's local CA — root, plus the
  intermediate when the layout has one, because the chain is root → intermediate →
  leaf and some builds serve only the leaf. This has not been observed on a runner
  yet — if the base image's JDK path differs, the build fails and the script falls
  back to the upstream image (the connectivity milestones still report). A publicly
  trusted certificate removes the need entirely.
- **Client registration.** The redirect URI the suite generates must be the one
  seeded into `[client]` (`CONFORMANCE_REDIRECT_URI`). Until it is observed, the
  value in the script is a placeholder.
- **Which plan.** Certification plans are named per OP profile; this OP implements
  authorization code + PKCE + refresh + device, and not dynamic registration or
  PAR. The plan allowlist must name what is supported and record the rest as
  intentionally out of scope, never silently skipped.
- **One seeded client vs the plan's two.** `[client]` seeds exactly one downstream
  client, so the spike points the Basic OP plan's `client2` at the same registration.
  The plan's refresh module ends with "Attempting to use refresh_token issued to
  client 2 with client 1" and expects `invalid_grant`; with one shared client the
  request legitimately succeeds and the module reports a failure that is a fixture
  limitation, not an OP defect. The behaviour is enforced (the engine's
  `AuthorizeRefreshClient` rejects a client mismatch, and `oauth/as.go` returns
  `invalid_grant` for a token issued to another client) and pinned by
  `internal/oidchttp/refresh_client_binding_test.go`
  (`TestRefreshTokenIsBoundToItsClient`: foreign client → 400 `invalid_grant`, and
  the refusal does not consume the token). A deployment that wants that module green
  needs two real client registrations — a config feature this OP does not have yet.
- **Headless authorization (addressed by the `conformance` build tag).** The spike's
  OP has no identity provider ("nobody can sign in") and answers every authorization
  with an interactive consent screen by design, so a plan that drives an
  authorization-code flow — the Basic OP plan is one — cannot be completed by a
  humanless suite on the ordinary binary. Requesting a plan therefore makes the spike
  build the OP with `-tags conformance` and set `RE0AUTH_CONFORMANCE_AUTOLOGIN=1`.
  That path stamps a real `auth_time`, completes the login as a fixed subject
  (`usr_conformance`) and returns the OP's own callback URL, so the code is issued
  with no browser.
  Guards, in layers: the code exists **only** under the build tag, and no release
  target passes tags (`Makefile:169` builds with `go build -trimpath`); the runtime
  opt-in is required; a warning is logged at startup and on every auto-approved
  request; and a binary built **without** the tag **refuses to start** when the
  variable is set (`cmd/re0auth/conformance_stub.go`), so nobody is left believing a
  bypass is active. The tagged half is tested by
  `go test -tags conformance ./cmd/re0auth` in CI, and the production half by the
  default suite (`zz_conformance_stub_test.go`).
  This is only for the suite's own run: it proves protocol behaviour, and it is not a
  certification result — the OIDF certification plans still expect a real client and
  user at the OP.
- **Pinned images.** `caddy:2`, `curlimages/curl:latest`,
  `registry.gitlab.com/openid/conformance-suite:latest` and `mongo:6.0.13` are
  floating tags. Once the job is a gate they must be pinned by digest, like the
  `Dockerfile` base images. (Docker Hub's `openid/conformance-suite` no longer
  exists — the first CI run found that out; the project publishes to its own GitLab
  registry.)

## Turning it into a gate

1. A nightly run with all chosen plans green.
2. Drop `continue-on-error` from the spike step and pin every image by digest.
3. Call the job from `release.yml` so a `v*` tag cannot publish without it.
