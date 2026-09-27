// Probe: can a scope that the server grants be one the consent screen never showed?
//
// It completes a real authorization-code flow against the e2e server, but instead
// of approving through the browser it calls the same two /v1 endpoints the consent
// page calls, and compares three sets:
//
//   displayed = GET /v1/authorization_requests/{id}.scopes[].scope
//   sent      = the `scopes` array the consent page would put in the POST body
//   granted   = the `scope` field of the token response
//
// Run against a server started with `node e2e/server.mjs`.

import { createHash, randomBytes } from 'node:crypto';

const APP = process.env.E2E_APP ?? 'http://127.0.0.1:18099';
const IDP = process.env.E2E_IDP ?? 'http://127.0.0.1:18098';
const CLIENT_ID = 'cli';
const CALLBACK = `${IDP}/callback`;

/** The scopes oidcstore.StandardOIDCScope accepts without consulting the catalogue. */
const PROTOCOL_FLAGS = new Set(['openid', 'profile', 'email', 'phone', 'address', 'offline_access']);

const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');

function cookieJar() {
	let jar = '';
	const capture = (res) => {
		const set = res.headers.getSetCookie?.() ?? [];
		for (const c of set) {
			const pair = c.split(';')[0];
			const name = pair.split('=')[0];
			const rest = jar
				.split('; ')
				.filter((p) => p && p.split('=')[0] !== name)
				.join('; ');
			jar = rest ? `${rest}; ${pair}` : pair;
		}
		return set;
	};
	return {
		capture,
		get header() {
			return { cookie: jar };
		},
		get value() {
			return jar;
		}
	};
}

async function main() {
	const requested = process.env.E2E_SCOPES ?? 'openid profile email account.id';
	const jar = cookieJar();

	const tell = await fetch(`${IDP}/__identity/probe-narrowing`, { method: 'POST' });
	if (!tell.ok) throw new Error(`identity control channel: ${tell.status}`);

	// 1. Start the login through the real /auth plane, following redirects by hand
	//    so the session cookie is captured.
	let url = `${APP}/auth/github/start?return_to=${encodeURIComponent('/app/')}`;
	for (let hop = 0; hop < 8; hop++) {
		const res = await fetch(url, { redirect: 'manual', headers: jar.header });
		const set = jar.capture(res);
		const loc = res.headers.get('location');
		console.log(`  hop ${hop}: ${res.status} ${url}`);
		console.log(`    -> ${loc ?? '(no location)'}`);
		if (set.length) console.log(`    set-cookie: ${set.map((c) => c.split(';')[0]).join(' | ')}`);
		if (!loc) break;
		url = new URL(loc, url).toString();
		if (res.status < 300 || res.status > 399) break;
	}
	const sessionRes = await fetch(`${APP}/v1/sessions/current`, { headers: jar.header });
	if (!sessionRes.ok) throw new Error(`no session after login: ${sessionRes.status}`);
	const session = await sessionRes.json();
	console.log(`signed in as ${session.user_id}`);

	// 2. Ask for a scope set that includes the OIDC claim scopes.
	const authorize = new URL(`${APP}/oauth/authorize`);
	authorize.search = new URLSearchParams({
		response_type: 'code',
		client_id: CLIENT_ID,
		redirect_uri: CALLBACK,
		scope: requested,
		state: 'probe-state',
		code_challenge: challenge,
		code_challenge_method: 'S256'
	}).toString();
	const start = await fetch(authorize, { redirect: 'manual', headers: jar.header });
	jar.capture(start);
	const consentURL = new URL(start.headers.get('location') ?? '', APP).toString();
	const handle = new URL(consentURL).searchParams.get('id');
	if (!handle) throw new Error(`no consent handle; landed on ${consentURL}`);
	console.log(`consent handle: ${handle}`);

	// 3. What the consent screen is given.
	const describeRes = await fetch(`${APP}/v1/authorization_requests/${handle}`, { headers: jar.header });
	if (!describeRes.ok) throw new Error(`describe: ${describeRes.status} ${await describeRes.text()}`);
	const described = await describeRes.json();
	const displayed = (described.scopes ?? []).map((s) => s.scope);

	// 4. What the page sends back: exactly the displayed scopes, all selected.
	const decisionRes = await fetch(`${APP}/v1/authorization_requests/${handle}/decision`, {
		method: 'POST',
		headers: {
			...jar.header,
			'content-type': 'application/json',
			'x-csrf-token': described.csrf_token
		},
		body: JSON.stringify({
			decision: 'approve',
			scopes: displayed,
			explicit: displayed.filter(
				(s) => described.scopes.find((d) => d.scope === s)?.explicit_consent
			)
		}),
		redirect: 'manual'
	});
	if (!decisionRes.ok) throw new Error(`decision: ${decisionRes.status} ${await decisionRes.text()}`);
	const decided = await decisionRes.json();
	console.log(`decision response: ${JSON.stringify(decided)}`);
	const { redirect_to } = decided;
	if (!redirect_to) throw new Error('the decision returned no redirect_to');

	// The decision returns the OP callback, which is where the code is minted; the
	// browser navigates there, so the probe does too.
	let next = new URL(redirect_to, APP).toString();
	let code = null;
	for (let hop = 0; hop < 5; hop++) {
		const res = await fetch(next, { redirect: 'manual', headers: jar.header });
		jar.capture(res);
		const loc = res.headers.get('location');
		console.log(`  redirect hop ${hop}: ${res.status} ${next} -> ${loc ?? '(no location)'}`);
		if (!loc) break;
		const target = new URL(loc, next).toString();
		const params = new URL(target).searchParams;
		if (params.get('code')) {
			code = params.get('code');
			break;
		}
		next = target;
	}
	if (!code) throw new Error(`no code came back (last hop ${next})`);

	// 5. What the client actually receives.
	const tokenRes = await fetch(`${APP}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: CLIENT_ID,
			code: code,
			code_verifier: verifier,
			redirect_uri: CALLBACK
		})
	});
	if (!tokenRes.ok) throw new Error(`token: ${tokenRes.status} ${await tokenRes.text()}`);
	const tokens = await tokenRes.json();
	const granted = String(tokens.scope ?? '').split(' ').filter(Boolean);

	console.log(`requested: ${requested}`);
	console.log(`displayed: ${displayed.join(' ') || '(nothing)'}`);
	console.log(`sent     : ${displayed.join(' ')}`);
	console.log(`granted  : ${granted.join(' ')}`);
	const silent = granted.filter((s) => !displayed.includes(s));
	console.log(`granted but never displayed: ${silent.join(' ') || '(none)'}`);

	// --- second half: the direction that would matter -------------------------
	//
	// A scope that a client registered for, that is also in the catalogue, reaches
	// the UI. A scope that is NOT described by the catalogue is dropped from the
	// view while the server's approval still narrows "requested", not "displayed".
	// Resolve what a *second* client — one registered for a scope the catalogue
	// does describe but this deployment's registry might not — would see. Without a
	// second registration in the e2e deployment this cannot be exercised, so the
	// probe reports what it can: the displayed set is a strict subset of the
	// requested set, and everything granted outside it falls in the protocol bucket.
	const inCatalogue = described.scopes.length;
	console.log(`scopes the catalogue described in this request: ${inCatalogue}`);
	console.log(`scopes requested: ${requested.split(' ').length}`);
	if (silent.length) {
		console.log(
			`NOTE: ${silent.length} granted scope(s) were never on the consent screen. ` +
				`Every one of them is a protocol/claim scope the design accepts as a no-op ` +
				`(oidcstore.StandardOIDCScope). If a *data* scope ever joined that list, ` +
				`the screen would be showing less than it grants.`
		);
		const dataish = silent.filter((s) => !PROTOCOL_FLAGS.has(s));
		if (dataish.length) {
			console.log(`!! DATA SCOPES GRANTED BUT NOT DISPLAYED: ${dataish.join(' ')}`);
			process.exitCode = 2;
		}
	}
}

main().catch((err) => {
	console.error(`probe failed: ${err.message}`);
	process.exit(1);
});
