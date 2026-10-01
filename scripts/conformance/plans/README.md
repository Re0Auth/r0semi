# Plan payloads for the conformance spike

`plan_json` (the `conformance` workflow input and `CONFORMANCE_PLAN_JSON`) is a
**repo-relative path to this wrapper**, which the spike's
[`run-plan.py`](../run-plan.py) turns into the suite's own API calls:

| our field | suite call |
|---|---|
| `planName` | `POST /api/plan?planName=…` |
| `variant` | `&variant=<json>` (variant parameter names, e.g. `response_type`) |
| `config` | the request body — the suite's test configuration JSON |

The suite's API is documented in its own
[`frontend/src/api/openapi.json`](https://gitlab.com/openid/conformance-suite/-/blob/master/frontend/src/api/openapi.json)
and implemented by `scripts/run-test-plan.py` upstream. The flow is: create the plan,
create one test per module (`POST /api/runner?test=<module>&plan=<planId>`), poll
`GET /api/info/<id>`.

## First run: leave it empty

Dispatch with `plan_json` blank. The spike proves the connectivity milestones and
writes the suite's **plan catalogue** to the run summary under *Available plans*
(first 60 names) and `plan-catalogue.json` to the `conformance-spike` artifact. That
catalogue is the authority for plan names and variant keys — do not guess them.

## Second run: supply a payload

[`oidcc-basic.json`](./oidcc-basic.json) is ready to use as-is for the spike's seeded
environment; [`basic-op.example.json`](./basic-op.example.json) is the same shape with
placeholders for another plan. What must line up:

| field | must equal |
|---|---|
| `planName` | a plan from `plan-catalogue.json` |
| `variant` keys | **only the variants that plan leaves to the user.** The Basic OP plan offers just `server_metadata` (`static`/`discovery`) and `client_registration` (`static_client`/`dynamic_client`) — it fixes `response_type`, `client_auth_type` and `response_mode` itself. Sending a plan-fixed variant is a 400: `Variant 'client_auth_type' has been set by user, but test plan already sets this variant for module 'oidcc-server'`. |
| `config.server.discoveryUrl` | the OP's discovery URL, `https://re0auth.test:8443/.well-known/openid-configuration` |
| `config.client.client_id` / `client_secret` | `conformance` / `CONFORMANCE_CLIENT_SECRET` (default `spike-secret`) — what the spike seeds in `[client]` |
| `config.client2`, `config.client_secret_post` | the plan lists `client2.client_secret` and `client_secret_post.client_secret` as required fields; the spike points both at the same seeded client |
| `config.alias` | the path segment the suite puts in its redirect URI |

The catalogue entry for each plan lists its `variants` (with `variantValues`) and
`configurationFields` — read it before editing a payload. The current Basic OP entry
was taken from a real `plan-catalogue.json` produced by this spike.

The suite derives its redirect URI as
**`https://oidf-suite:8443/test/a/<alias>/callback`** (its `fintechlabs.base_url`, on
the TLS front the spike runs). The spike seeds exactly that into the OP's `[client]`
unless `redirect_uri` is overridden, so `alias: "conformance"` matches by default.

If the plan has modules that need a **second client** (the Basic OP plan has a
`client_secret_post` group), add those fields too — see the
`client_secret_post` block in `oidcc-basic.json`.

A mismatch surfaces as `redirect_uri is not registered` from the OP, or a suite
complaint that the authorization response went to the wrong place.

Dispatch with `plan_json: scripts/conformance/plans/oidcc-basic.json`. It is
report-only until `require_plan: true` is set, which is the switch to flip once the
nightly is green.

A full Basic OP pass runs ~35 modules **one at a time** and drives each front-channel
URL, so start with a smoke run: dispatch with `max_modules: 5`. Then widen to the
whole plan (or leave it at `0` for the nightly). The runner is
[`run-plan.py`](../run-plan.py); per-module failure reasons are pulled from
`GET /api/log/<id>` and appear under *Why modules did not pass* in the run summary.

**Expect a policy divergence first.** The suite's OP tests send no `code_challenge`,
while Re0Auth mandates PKCE S256 for every client, so most Basic OP modules come back
`invalid_request: code_challenge is required` and the runner tags them
`divergence: pkce-required`. See [docs/conformance.md](../../../docs/conformance.md).

## Before you pick a plan

The spike's OP has no identity provider and no automated consent on the ordinary
binary: it starts with the warning "nobody can sign in", so an authorization-code
plan would reach the login plane and stop. Supplying `plan_json` is the switch that
changes this — the spike then builds the OP with `-tags conformance` and sets
`RE0AUTH_CONFORMANCE_AUTOLOGIN=1`, which auto-authenticates and auto-approves the
request so the suite can finish the flow. That build-tagged path never reaches a
shipped binary; see the "Headless authorization" gap in
[docs/conformance.md](../../../docs/conformance.md) for the guards.
