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
   `mongo` beside it (we run `mongo:6.0.13`, the version the project pins). It is
   published on `:9443` and reached over **HTTP**; the compose's nginx/TLS front is
   only there to give a tester's browser a TLS origin. Prints
   `/api/runner/available` (milestones 1–5, plus 4b).
7. when a plan payload is supplied, builds the OP with the `conformance` build tag
   and its auto-login opt-in (see the headless gap below), posts the payload to
   `/api/runner`, polls the run to a terminal status, and records the verdict
   (milestones 6–7). The suite has used `id`/`testId`/`test_id` and
   `status`/`result` across versions; the script reads whichever appears rather than
   pinning knowledge it cannot verify locally.

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
| `plan_json` | repo-relative path to a JSON payload for `POST /api/runner`. **Leave empty on the first run**: the spike then prints the suite's plan catalogue under "Available plans" in the run summary, and that catalogue is the authority on the plan name and variant. [`scripts/conformance/plans/README.md`](../scripts/conformance/plans/README.md) has the fill-in guide and a template. |
| `redirect_uri` | the redirect URI seeded into the OP's `[client]`. It must equal the one the suite generates for the test; read it from the suite and pass it back here so both sides match. Blank keeps the script default. |
| `require_plan` | when true, the script exits non-zero unless the plan reaches `FINISHED` with `SUCCESS`/`WARNING`/`REVIEW`/`SKIPPED`. Use this once the nightly is green — it is the same switch as dropping `continue-on-error`. |

**First run, concretely:** dispatch with `plan_json` empty. Read the milestone table
and the plan list in the run summary, and `available.json` in the
`conformance-spike` artifact. Then copy
[`scripts/conformance/plans/basic-op.example.json`](../scripts/conformance/plans/basic-op.example.json)
to a real payload, fill it from that catalogue, and dispatch again with
`plan_json` set (plus `redirect_uri` if the suite's value differs from the seeded
one).

Environment equivalents for a direct script run: `CONFORMANCE_PLAN_JSON`,
`CONFORMANCE_REQUIRE_PLAN=1`, `CONFORMANCE_TIMEOUT_SECONDS` (default 600),
`CONFORMANCE_REDIRECT_URI`.

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
