// Starts everything a browser test needs: a fake identity provider, an endpoint
// for the client's redirect URI, and a real re0auth binary pointed at both.
//
// The identity provider is faked at the network edge and **no test-only way to
// obtain a session is added**. Everything between the browser and the fake IdP —
// PKCE, the code exchange, account creation, the session cookie, the CSRF token,
// the consent handle bound to that session — is the shipping code. A suite that
// needed a bypass would be proving things about a login path that never runs in
// production, which is worse than having no suite.
//
// The same fake server answers the client's registered redirect_uri, so a test
// can read the authorization code straight out of the browser's address bar once
// consent is given.
import { execFileSync, spawn } from 'node:child_process';
import { createPublicKey, createSign, generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');

const appPort = Number(process.env.E2E_PORT ?? 18099);
const idpPort = Number(process.env.E2E_IDP_PORT ?? 18098);
const appBase = `http://127.0.0.1:${appPort}`;
const idpBase = `http://127.0.0.1:${idpPort}`;
// When set, re0auth runs on Postgres and therefore uses the OpenID Provider
// engine (ADR-0001); unset keeps the in-memory built-in engine.
const dbUrl = process.env.E2E_DATABASE_URL ?? '';

const CLIENT_ID = 'cli';
const CALLBACK_URL = `${idpBase}/callback`;

// Which identity the next sign-in produces, and the accounts minted so far.
//
// This used to be a fixed `{id: 42}`, which meant every test signed in as the
// same account — so one test's grants showed up in the next test's list, and the
// failure moved between tests depending on what had already run. Tests have to be
// independent to be worth trusting.
//
// A single mutable "current identity" is safe here because the suite runs one
// worker and every sign-in is awaited before the next begins.
let nextIdentity = 'default';
const identities = new Map();
function subjectFor(identity) {
	if (!identities.has(identity)) identities.set(identity, identities.size + 1000);
	return identities.get(identity);
}

// The OAuth error the next /github/authorize should redirect with, if any. It is
// how a login-denied callback is simulated without inventing a test-only path
// inside re0auth: the provider itself refuses, exactly as a real one would.
let nextError = '';

// A generated RS256 key for the OpenID Provider run. re0auth requires it
// (fail-closed), so the harness cannot lean on an ephemeral key any more.
let cachedSigningKey = '';
function signingKey() {
	if (!cachedSigningKey) {
		const { privateKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			privateKeyEncoding: { type: 'pkcs8', format: 'der' }
		});
		cachedSigningKey = privateKey.toString('base64');
	}
	return cachedSigningKey;
}

// A second key, for the fake generic OIDC provider. re0auth verifies the id_token
// against the provider's JWKS, so the fake signs with a real key and publishes
// its real public half — nothing about the custom-provider path is stubbed.
const oidcKey = generateKeyPairSync('rsa', {
	modulusLength: 2048,
	publicKeyEncoding: { type: 'spki', format: 'pem' },
	privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const oidcJWK = {
	...createPublicKey(oidcKey.publicKey).export({ format: 'jwk' }),
	kid: 'e2e-oidc',
	alg: 'RS256',
	use: 'sig'
};
// The nonce from the last /oidc/authorize, echoed into the id_token. A single
// slot is safe for the same reason nextIdentity is: one worker, awaited sign-ins.
let oidcNonce = '';

function b64url(value) {
	return Buffer.from(value).toString('base64url');
}

function signIDToken(claims) {
	const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'e2e-oidc' }));
	const payload = b64url(JSON.stringify(claims));
	const signingInput = `${header}.${payload}`;
	const signature = createSign('RSA-SHA256').update(signingInput).sign(oidcKey.privateKey);
	return `${signingInput}.${signature.toString('base64url')}`;
}

function json(res, status, body) {
	res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
}

async function readForm(req) {
	let body = '';
	for await (const chunk of req) body += chunk;
	return new URLSearchParams(body);
}

// The fake data source's revocation log, so a test can assert that the source was
// actually told rather than inferring it from Re0Auth's own bookkeeping.
const revocations = [];
// And the cascade log, kept apart from it: they are different requests with
// different effects, and one test asserts the wrong one was not used.
const cascades = [];

// The fake identity provider, in the shape `idp.GitHub` expects: a userinfo
// endpoint rather than an OIDC id_token, so nothing here needs a signing key.
//
// The same server also plays the data source. It is one process because both are
// just "some HTTP server on the other side", and splitting them would add a port
// without adding a distinction the tests care about.
const idp = createServer(async (req, res) => {
	const url = new URL(req.url, idpBase);

	switch (url.pathname) {
		case '/github/authorize': {
			if (nextError) {
				const code = nextError;
				nextError = '';
				const target = new URL(url.searchParams.get('redirect_uri'));
				target.searchParams.set('error', code);
				target.searchParams.set('state', url.searchParams.get('state') ?? '');
				res.writeHead(302, { location: target.toString() }).end();
				return;
			}
			// Consent at the provider is assumed; the interesting consent is ours.
			const target = new URL(url.searchParams.get('redirect_uri'));
			target.searchParams.set('code', 'e2e-idp-code');
			target.searchParams.set('state', url.searchParams.get('state') ?? '');
			res.writeHead(302, { location: target.toString() }).end();
			return;
		}
		case '/github/token':
			json(res, 200, { access_token: 'e2e-idp-at', token_type: 'Bearer', expires_in: 3600 });
			return;
		case '/github/user':
			// A distinct subject per identity, so a distinct account per test.
			json(res, 200, {
				id: subjectFor(nextIdentity),
				login: nextIdentity,
				name: `Octo ${nextIdentity}`
			});
			return;
		case '/callback':
			// The client's redirect_uri. A test asserts on the query string, so the
			// body only has to exist.
			res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(
				'<!doctype html><meta charset="utf-8"><title>client callback</title><p>client callback'
			);
			return;

		// A generic OIDC provider, so the custom [idp.<name>] path is exercised end
		// to end: discovery, JWKS, a signed id_token and a nonce.
		// A second OIDC issuer whose discovery is down, so "a login that cannot even
		// start" is exercised end to end: a normal provider that is unreachable.
		case '/oidc-down/.well-known/openid-configuration':
			res.writeHead(503, { 'content-type': 'application/json' }).end('{"error":"temporarily_unavailable"}');
			return;
		case '/oidc/.well-known/openid-configuration':
			json(res, 200, {
				issuer: `${idpBase}/oidc`,
				authorization_endpoint: `${idpBase}/oidc/authorize`,
				token_endpoint: `${idpBase}/oidc/token`,
				jwks_uri: `${idpBase}/oidc/jwks`,
				response_types_supported: ['code'],
				subject_types_supported: ['public'],
				id_token_signing_alg_values_supported: ['RS256']
			});
			return;
		case '/oidc/jwks':
			json(res, 200, { keys: [oidcJWK] });
			return;
		case '/oidc/authorize': {
			oidcNonce = url.searchParams.get('nonce') ?? '';
			const target = new URL(url.searchParams.get('redirect_uri'));
			target.searchParams.set('code', 'e2e-oidc-code');
			target.searchParams.set('state', url.searchParams.get('state') ?? '');
			res.writeHead(302, { location: target.toString() }).end();
			return;
		}
		case '/oidc/token': {
			const form = await readForm(req);
			let clientID = form.get('client_id');
			if (!clientID) {
				const auth = req.headers.authorization ?? '';
				if (auth.startsWith('Basic ')) {
					clientID = decodeURIComponent(Buffer.from(auth.slice(6), 'base64').toString().split(':')[0]);
				}
			}
			const now = Math.floor(Date.now() / 1000);
			json(res, 200, {
				access_token: 'e2e-oidc-at',
				token_type: 'Bearer',
				expires_in: 3600,
				id_token: signIDToken({
					iss: `${idpBase}/oidc`,
					sub: String(subjectFor(nextIdentity)),
					aud: clientID || 'e2e-oidc-client',
					iat: now,
					exp: now + 3600,
					nonce: oidcNonce,
					name: `OIDC ${nextIdentity}`,
					email: 'oidc@example.com'
				})
			});
			return;
		}

		// The data source. Enough of the upstream protocol for a real bind to
		// succeed against it.
		case '/gamesource/oauth/authorize':
		case '/plainsource/oauth/authorize': {
			const target = new URL(url.searchParams.get('redirect_uri'));
			target.searchParams.set('code', 'e2e-source-code');
			target.searchParams.set('state', url.searchParams.get('state') ?? '');
			res.writeHead(302, { location: target.toString() }).end();
			return;
		}
		case '/gamesource/oauth/token':
		case '/plainsource/oauth/token':
			json(res, 200, {
				access_token: 'e2e-source-at',
				token_type: 'Bearer',
				expires_in: 3600,
				refresh_token: 'e2e-source-rt'
			});
			return;
		case '/gamesource/oauth/revoke': {
			const form = await readForm(req);
			revocations.push(form.get('token'));
			res.writeHead(200).end();
			return;
		}
		case '/gamesource/oauth/cascade_revocation': {
			// Only gamesource serves this. plainsource deliberately does not, which is
			// what makes it the control case for "a source without the capability gets
			// no button and no pretend attempt".
			const form = await readForm(req);
			cascades.push(form.get('token'));
			res.writeHead(200).end();
			return;
		}
		case '/gamesource/resources/b30': {
			// A bound token reaches this. The body's shape is the source's business; the
			// test only cares that the call got here at all.
			if (req.headers.authorization !== 'Bearer e2e-source-at') {
				res.writeHead(401).end();
				return;
			}
			json(res, 200, { game: 'phigros', b30: [] });
			return;
		}

		// Test-only control channels. Nothing in re0auth knows they exist, which is
		// the point of faking the counterpart at the network edge.
		case '/__revocations':
			json(res, 200, { tokens: revocations });
			return;
		case '/__cascades':
			json(res, 200, { tokens: cascades });
			return;
		case '/__reset':
			revocations.length = 0;
			cascades.length = 0;
			res.writeHead(204).end();
			return;
		default:
			// The control channel: a test says who the next sign-in should be before it
			// starts one. Not part of the provider protocol, and it only exists on this
			// fake — which is why faking the provider at the network edge rather than
			// adding a bypass inside re0auth keeps the login path honest.
			if (url.pathname.startsWith('/__identity/')) {
				nextIdentity = decodeURIComponent(url.pathname.slice('/__identity/'.length));
				res.writeHead(204).end();
				return;
			}
			// Make the next provider authorization fail with the named OAuth error.
			if (url.pathname.startsWith('/__error/')) {
				nextError = decodeURIComponent(url.pathname.slice('/__error/'.length));
				res.writeHead(204).end();
				return;
			}
			res.writeHead(404).end();
	}
});

function configFile() {
	const dir = mkdtempSync(join(tmpdir(), 're0auth-e2e-'));
	const path = join(dir, 're0auth.toml');
	writeFileSync(
		path,
		`[server]
issuer = "${appBase}"
addr = "127.0.0.1:${appPort}"
cookie_secure = false

# Off, and not because the limiter is untested — it has its own unit tests.
#
# Every browser and every API call in this suite comes from 127.0.0.1, so the
# per-address limiter sees one client for the whole run. With it on, a test
# eventually receives a 429 for a page load and fails on an element that never
# appeared: a failure that moves between tests between runs, which is the worst
# kind. A browser suite is the wrong place to prove that load shedding works.
rate_limit = 0

[storage]
# Memory by default: each run starts from nothing, which is what makes the tests
# independent of each other and of whatever ran before. A DSN switches to
# Postgres, and with it the OpenID Provider engine.
driver = "${dbUrl ? 'postgres' : 'memory'}"

[vault]
kek_env = "RE0AUTH_KEK"

[client]
id = "${CLIENT_ID}"
name = "Phi CLI"
redirect_uris = ["${CALLBACK_URL}"]
scopes = ["account.id", "phigros.b30.read"]

[idp.github]
client_id = "e2e-client"
client_secret_env = "E2E_IDP_SECRET"
auth_url = "${idpBase}/github/authorize"
token_url = "${idpBase}/github/token"
userinfo_url = "${idpBase}/github/user"

# A generic OIDC provider: a self-hosted Authentik/Keycloak/Passkey login, wired
# with nothing but an issuer. Its endpoints are discovered, and its id_token is
# verified against the JWKS the fake publishes.
[idp.authentik]
client_id = "e2e-oidc-client"
client_secret_env = "E2E_IDP_SECRET"
issuer = "${idpBase}/oidc"
display_name = "Authentik"

# A provider whose discovery endpoint is down. The point is that a login which
# cannot even start returns the user to the app with a reason, not a dead-end 502.
[idp.legacy]
client_id = "e2e-legacy-client"
client_secret_env = "E2E_IDP_SECRET"
issuer = "${idpBase}/oidc-down"
display_name = "Legacy SSO"

# A registered source, so that a scope can be shown to be enforced by the server
# rather than by a checkbox. Nothing here is ever contacted: the tests never bind,
# and the two outcomes they assert — 403 when the token lacks the scope, 409 when
# it has it but no binding exists — are both decided before any upstream call.
[[sources]]
game = "phigros"
source = "e2e"
display_name = "E2E Source"
issuer = "${idpBase}/gamesource"
token_class = "revocable"
# Declared, as an operator would after reading this source's discovery document.
# It is what makes Re0Auth offer "sign out everywhere" for this source — and
# offering it where it is not declared is what the plain source below exists to
# rule out.
cascade_revocation = "${idpBase}/gamesource/oauth/cascade_revocation"
client_id = "re0auth"
client_secret_env = "E2E_SOURCE_SECRET"
resources = [
  { name = "b30", schema = "re0auth.phigros.b30/1", scope = "phigros.b30.read" },
]

# A second source that deliberately cannot end an upstream session. It is the
# control case for the capability: the point is that Re0Auth offers no button for
# it and refuses rather than pretending.
[[sources]]
game = "phigros"
source = "plain"
display_name = "Plain Source"
issuer = "${idpBase}/plainsource"
token_class = "revocable"
client_id = "re0auth"
client_secret_env = "E2E_SOURCE_SECRET"
resources = [
  { name = "profile", schema = "re0auth.phigros.profile/1", scope = "phigros.profile.read" },
]
`
	);
	return path;
}

await new Promise((done, fail) => {
	idp.once('error', fail);
	idp.listen(idpPort, '127.0.0.1', done);
});

const bin = join(mkdtempSync(join(tmpdir(), 're0auth-e2e-bin-')), process.platform === 'win32' ? 're0auth.exe' : 're0auth');
execFileSync('go', ['build', '-o', bin, './cmd/re0auth'], { cwd: repoRoot, stdio: 'inherit' });

const app = spawn(bin, ['-config', configFile()], {
	env: {
		...process.env,
		// Any 32 bytes. base64 so the server's key parser accepts it directly.
		RE0AUTH_KEK: Buffer.alloc(32, 7).toString('base64'),
		// Required exactly when the audit log is durable, which the Postgres run is
		// and the memory run is not. Set unconditionally so both launches are the
		// same env and only the storage driver differs.
		RE0AUTH_AUDIT_KEY: Buffer.alloc(32, 11).toString('base64'),
		E2E_IDP_SECRET: 'e2e-secret',
		E2E_SOURCE_SECRET: 'e2e-source-secret',
		// Fixed keys keep the run deterministic. Every deployment runs the OpenID
		// Provider now (ADR-0001 P4b), memory mode included, so the signing key is
		// required whether or not a database is configured.
		RE0AUTH_OIDC_TOKEN_KEY: Buffer.alloc(32, 9).toString('base64'),
		RE0AUTH_OIDC_SIGNING_KEY: signingKey(),
		...(dbUrl ? { DATABASE_URL: dbUrl } : {})
	},
	stdio: 'inherit'
});

app.once('exit', (code) => {
	if (code !== 0 && code !== null) console.error(`re0auth exited with ${code}`);
	process.exit(code ?? 0);
});

// Playwright terminates this process to stop the server. Kill the child with it,
// or the next run finds the port occupied and fails for a reason that has nothing
// to do with the code.
let stopping = false;
function stop(signal) {
	if (stopping) return;
	stopping = true;
	app.kill(signal);
	idp.close();
}
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
	process.on(signal, () => stop(signal));
}
