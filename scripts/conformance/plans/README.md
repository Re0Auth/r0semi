# Plan payloads for the conformance spike

`plan_json` (the `conformance` workflow input and `CONFORMANCE_PLAN_JSON`) is a
**repo-relative path to a JSON body for `POST /api/runner`**. It is the suite's own
"test configuration" object, not something this repository defines.

## First run: leave it empty

Dispatch the workflow with `plan_json` blank. The spike then:

1. proves the connectivity milestones (self-signed TLS via Caddy, a container
   fetching discovery with the CA, the suite API answering);
2. writes the suite's plan catalogue to the run summary under **Available plans**
   (first 40 names) and the full `available.json` to the `conformance-spike`
   artifact.

That catalogue is the authority for the plan name, the variant keys and the
configuration template. Do not guess them.

## Second run: fill the payload

Copy [`basic-op.example.json`](./basic-op.example.json) to a real file (for example
`scripts/conformance/plans/basic-op.json`) and replace the placeholders. Three
things must line up at once:

| field | must equal |
|---|---|
| `test`, `variant` | the plan name and variant keys from `available.json` |
| `config.server.issuer` | the OP's issuer, `https://re0auth.test:8443` |
| `config.client.client_id` | `conformance` (the id the spike seeds via `[client]`) |
| `config.client.client_secret` | `CONFORMANCE_CLIENT_SECRET`, default `spike-secret` |
| `config.client.redirect_uri` | **both** the value the suite expects for this test **and** the one the spike seeds. The suite generates it per test from its public origin (`BASE_URL`, which the spike sets to `http://localhost:9443`); read it from the test page or ask the suite in the first run, then pass it back as the `redirect_uri` input so the OP's `[client]` matches. |

A mismatch surfaces as `redirect_uri is not registered` from the OP (or a suite
complaint that the authorization response went to the wrong place), which is why
the redirect URI is the one field worth checking twice.

Then dispatch with `plan_json` set and, once it is green, `require_plan: true`.

## Before you pick a plan

The spike's OP has **no identity provider and no automated consent**: it starts with
the warning "nobody can sign in". A plan that drives an authorization-code flow will
reach the login plane and stop there. Discovery-level plans run headless; an
interactive plan needs a test-only auto-login/auto-consent path (build-tagged, never
in a shipped binary) or an attended run. See the "Headless limit" gap in
[docs/conformance.md](../../../docs/conformance.md).

