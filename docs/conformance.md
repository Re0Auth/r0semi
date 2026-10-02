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
| `plan_json` | repo-relative path to a plan payload (our wrapper around the suite's `POST /api/plan`; see [`scripts/conformance/plans/README.md`](../scripts/conformance/plans/README.md)). **Leave empty on the first run**: the spike then prints the suite's plan catalogue under "Available plans" in the run summary. A non-empty value must name a plan on the allowlist (`CONFORMANCE_ALLOWED_PLANS`) or the job fails before the spike starts — see the *Which plan* gap. |
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
`CONFORMANCE_PLAN_VISIT_DELAY_SECONDS`, `CONFORMANCE_CLIENT_SECRET`,
`CONFORMANCE_CLIENT2_SECRET`. The OP-side exemption is
`RE0AUTH_CLIENT_ALLOW_MISSING_PKCE`; the script writes
`[client] allow_missing_pkce = true` itself once a plan is requested, and also seeds
the plan's second client as a `[[clients]]` entry (see the known gap below).

> The plan allowlist (CONF-2) is enforced by a workflow step, **not** by
> `spike.sh` — a direct script run bypasses it. That is deliberate (the workflow is
> the gate; the script is the mechanism), but it means "run it locally with any
> `plan_json`" is not the same as "the gate would run it".

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

- **JVM trust store — PENDING VERIFICATION, never observed on a runner (CONF-3).**
  The mechanism exists (milestone 4b): the script builds a derived image
  `FROM registry.gitlab.com/openid/conformance-suite:latest` (`eclipse-temurin:21`)
  that runs `keytool -importcert` against the JVM's `cacerts` with Caddy's local CA —
  root, plus the intermediate when the layout has one, because the chain is
  root → intermediate → leaf and some builds serve only the leaf.
  **What is not established is that the build succeeds on a runner.** The JDK path
  (`${JAVA_HOME:-/opt/java/openjdk}`) is an assumption read off the upstream base,
  not an observation; if it is wrong the build fails and the script silently falls
  back to the upstream image — the connectivity milestones still report, but the
  suite keeps only the public CAs, so a plan run against the self-signed issuer fails
  at TLS. Milestone 4b prints `PASS` or `WARN` in the run summary; do not write
  "addressed" until a run shows `PASS`.
  How to observe it on the runner (the same check can be run locally under WSL2):
  ```sh
  # 1. the JDK path the Dockerfile's RUN resolves to must exist
  docker run --rm re0auth-conformance-spike:local \
    sh -c 'echo JAVA_HOME=${JAVA_HOME:-unset}; ls -d "${JAVA_HOME:-/opt/java/openjdk}/lib/security/cacerts"'
  # 2. both spike aliases must be in the trust store (intermediate only when Caddy has one)
  docker run --rm re0auth-conformance-spike:local \
    sh -c 'keytool -list -keystore "${JAVA_HOME:-/opt/java/openjdk}/lib/security/cacerts" \
             -storepass changeit | grep -E "re0auth-spike-(root|intermediate)"'
  ```
  Command 1 must print an existing path, command 2 at least `re0auth-spike-root`; the
  spike's `suite-build.log` (in the artifact) and its milestone-4b summary line are
  the durable record. **Exit criteria to close CONF-3:** one CI run with milestone 4b
  `PASS`, plus at least one plan module that exercises the suite→issuer TLS path green
  with the derived image. Only then decide whether to keep the fallback as
  warning-only safety or delete it. A publicly trusted certificate removes the need
  entirely.
- **Client registration.** The redirect URI the suite generates must be the one
  seeded into `[client]` (`CONFORMANCE_REDIRECT_URI`). Until it is observed, the
  value in the script is a placeholder.
- **Which plan — an explicit allowlist, and an unknown plan is an error (CONF-2).**
  This OP implements authorization code + PKCE + refresh + device authorization; it
  deliberately does **not** implement dynamic client registration (DCR) or pushed
  authorization requests (PAR). The gate therefore names what it will run and refuses
  everything else instead of silently skipping it:
  - **Allowed** — `CONFORMANCE_ALLOWED_PLANS` in `.github/workflows/conformance.yml`
    (job-level environment, comma-separated). It must contain only names copied from
    the suite's own `plan-catalogue.json`; a name is never guessed. What is observed
    so far is the authorization-code + PKCE Basic OP plan
    `oidcc-basic-certification-test-plan` (the shipped
    `scripts/conformance/plans/oidcc-basic.json`).
  - **Intentionally unsupported** — plans that require DCR (the
    `client_registration: dynamic_client` variant) or PAR. Recorded here and in
    [oidc-decision.md](./oidc-decision.md) O-9 as out of scope by decision, not
    skipped by accident. Device-grant and refresh plans are in scope and may be
    added once their names are read off the catalogue.
  - **Unknown / unlisted plan → the workflow fails before the spike starts**, naming
    the value and the allowlist (the "Enforce the plan allowlist" step). A typo in
    `plan_json` previously looked like a successful connectivity-only run.
  - **Adding a plan is two edits**: prove it against `plan-catalogue.json` (its exact
    `planName`, its variants, its configuration fields), then add the exact spelling
    to `CONFORMANCE_ALLOWED_PLANS`.
- **`oidcc-server`'s `client_id` warning is known behaviour, not a defect.** The
  engine's `NewIDTokenClaims` always writes a non-standard `client_id` claim into the
  `id_token` and offers no override point. The value is the RP's own `client_id` — no
  new information — and OIDC Core does not forbid extra claims, so removing it would
  mean re-signing the JWT at the token layer for no gain. Recorded as O-10 in
  [oidc-decision.md](./oidc-decision.md); that module stays a WARNING by decision.
- **Two plan clients, two registrations (addressed by `[[clients]]`).** The Basic OP
  plan's refresh module ends with "Attempting to use refresh_token issued to client 2
  with client 1" and expects `invalid_grant`. While the plan's `client2` pointed at
  the same registration as `client`, that request legitimately succeeded and the
  module was red for the harness's reason, not the OP's. The OP now seeds a second
  client through the `[[clients]]` array, and the spike writes
  `client2.client_id = "conformance2"` with its own secret
  (`CONFORMANCE_CLIENT2_SECRET`, default `spike-secret-2`), so the check is real. The
  behaviour itself was already enforced (the engine's `AuthorizeRefreshClient` rejects
  a client mismatch, and `oauth/as.go` returns `invalid_grant` for a token issued to
  another client) and is pinned by
  `internal/oidchttp/refresh_client_binding_test.go`
  (`TestRefreshTokenIsBoundToItsClient`: foreign client → 400 `invalid_grant`, and the
  refusal does not consume the token).
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
- **Pinned images — not pinned yet, and no digest may be invented (CONF-1).**
  `caddy:2`, `curlimages/curl:latest`,
  `registry.gitlab.com/openid/conformance-suite:latest` and `mongo:6.0.13` are
  floating tags (`scripts/conformance/spike.sh`). The project's rule is that a gate
  pins every image by digest, exactly as the `Dockerfile` base images do
  (`node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1`,
  `golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414`),
  the CI/release Postgres service does
  (`postgres:16@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`,
  the same digest `deploy/k8s/backup/cronjob.yaml` uses; S15-2) and the release
  scanner does (`aquasec/trivy@sha256:ab70a02200597efa04748f210f793936eb647cbcdb0ea69cc30b226d6f5a22c7`).
  **None of the four conformance images has an audited digest in this repository
  yet**, so there is nothing to reuse: pinning them starts by observing each digest
  once. Dependency row: [dependencies.md](./dependencies.md) §6.
  Observe them once (the `conformance.yml` step "Record the image digests to pin"
  already writes this table to the run summary; the same works on any Docker host):
  ```sh
  for ref in caddy:2 curlimages/curl:latest \
             registry.gitlab.com/openid/conformance-suite:latest mongo:6.0.13; do
    printf '%s %s\n' "$ref" \
      "$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}')"
  done
  ```
  Then replace each tag in `scripts/conformance/spike.sh` (the `SUITE_IMAGE` /
  `MONGO_IMAGE` variables and the `caddy` / `curlimages/curl` `docker run` commands)
  with `<tag>@<digest>`, using only a digest that was observed resolving to the tag
  that was tested — a digest copied from a blog or a registry page is not an
  observation. Docker Hub's `openid/conformance-suite` no longer exists — the first
  CI run found that out; the project publishes to its own GitLab registry.

## Turning it into a gate (upgrade path + blocking conditions)

This is still a spike and `continue-on-error` is still **on purpose**: no plan has
been observed green, so removing it today would turn an unproven signal into a
blocking job — the failure mode that ends with a gate being deleted rather than
fixed. What can be done without pretending is already done: the conformance
auto-login is build-tagged and runtime-gated, the plan allowlist is enforced (CONF-2),
the four images' digests are recorded by the run itself (CONF-1), `conformance.yml`
already declares `workflow_call` (the mechanical prerequisite for step 4), and the
`require_plan` dispatch input already fails a single dispatch hard. The remaining
steps are gated on evidence and are run in order.

**Blocking conditions — every one must hold before the next step:**

1. **Nightly, chosen plans, all green.**
   - Gate: a scheduled run, or a dispatch with `require_plan: true`, finishes with
     every module in `SUCCESS`/`WARNING`/`REVIEW`/`SKIPPED`, and every `WARNING` is a
     known one tied to a decision (the `oidcc-server` `client_id` warning is O-10 in
     [oidc-decision.md](./oidc-decision.md)).
   - Evidence to attach: the run's step summary, `plan-run.json` from the
     `conformance-spike` artifact, and `op.log` with no unexpected `WARN`.
2. **Drop `continue-on-error`** (CONF-4).
   - Precondition: step 1 holds, the derived suite image is observed green (CONF-3),
     and the allowlist contains exactly the plans that are green.
   - Edit: remove `continue-on-error: true` from the spike step in
     `.github/workflows/conformance.yml`, and keep the nightly's
     `CONFORMANCE_REQUIRE_PLAN=1`.
   - Rollback: if the *suite* turns out to be the flaky part, note the flake and fix
     it; do not leave a permanently red gate.
3. **Pin every image by digest** (CONF-1).
   - Precondition: the four digests were observed resolving to the tested tags.
   - Edit: `scripts/conformance/spike.sh` (and any `docker run` in the workflow).
   - Why it is ordered here: a pinned digest makes a later red run attributable to
     the OP or the plan, not to whatever `latest` became overnight.
4. **Call it from `release.yml` before a tag can publish.**
   - Precondition: steps 1–3 done. Calling a report-only workflow from the release
     graph is worse than not calling it — it reads as a gate without being one.
   - Edit: one job in `release.yml`, then add it to the `needs:` of `image` and
     `release`:

     ```yaml
     conformance:
       needs: ci
       uses: ./.github/workflows/conformance.yml
       with:
         plan_json: scripts/conformance/plans/oidcc-basic.json
         require_plan: true
       permissions:
         contents: read
     ```

     `image` becomes `needs: [ci, conformance]`, `release` becomes
     `needs: [ci, conformance, image]`.
