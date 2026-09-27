// Verifier probe for A-FE-3: does a scope the consent screen never showed grant
// anything? Completes the flow exactly like docs/audit-5/probes/web/scope-narrowing.mjs
// and then asks the OP what the resulting token can read.
import { createHash, randomBytes } from 'node:crypto';

const APP = process.env.E2E_APP ?? 'http://127.0.0.1:18099';
const IDP = process.env.E2E_IDP ?? 'http://127.0.0.1:18098';
const CLIENT_ID = 'cli';
const CALLBACK = `${IDP}/callback`;

const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');

let jar = '';
function capture(res) {
	for (const c of res.headers.getSetCookie?.() ?? []) {
		const pair = c.split(';')[0];
		const name = pair.split('=')[0];
		const rest = jar
			.split('; ')
			.filter((p) => p && p.split('=')[0] !== name)
			.join('; ');
		jar = rest ? `${rest}; ${pair}` : pair;
	}
}
const H = () => ({ cookie: jar });
const b64urlDecode = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

const requested = process.env.E2E_SCOPES ?? 'openid profile email account.id';

await fetch(`${IDP}/__identity/probe-grant`, { method: 'POST' });

let url = `${APP}/auth/github/start?return_to=${encodeURIComponent('/app/')}`;
for (let hop = 0; hop < 8; hop++) {
	const res = await fetch(url, { redirect: 'manual', headers: H() });
	capture(res);
	const loc = res.headers.get('location');
	if (!loc) break;
	url = new URL(loc, url).toString();
	if (res.status < 300 || res.status > 399) break;
}
const session = await (await fetch(`${APP}/v1/sessions/current`, { headers: H() })).json();

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
const start = await fetch(authorize, { redirect: 'manual', headers: H() });
capture(start);
const consentURL = new URL(start.headers.get('location') ?? '', APP).toString();
const handle = new URL(consentURL).searchParams.get('id');
if (!handle) throw new Error(`no consent handle; landed on ${consentURL}`);

const described = await (await fetch(`${APP}/v1/authorization_requests/${handle}`, { headers: H() })).json();
const displayed = (described.scopes ?? []).map((s) => s.scope);

const decisionRes = await fetch(`${APP}/v1/authorization_requests/${handle}/decision`, {
	method: 'POST',
	headers: { ...H(), 'content-type': 'application/json', 'x-csrf-token': described.csrf_token },
	body: JSON.stringify({
		decision: 'approve',
		scopes: displayed,
		explicit: displayed.filter((s) => described.scopes.find((d) => d.scope === s)?.explicit_consent)
	}),
	redirect: 'manual'
});
if (!decisionRes.ok) throw new Error(`decision: ${decisionRes.status} ${await decisionRes.text()}`);
const { redirect_to } = await decisionRes.json();

let next = new URL(redirect_to, APP).toString();
let code = null;
for (let hop = 0; hop < 5; hop++) {
	const res = await fetch(next, { redirect: 'manual', headers: H() });
	capture(res);
	const loc = res.headers.get('location');
	if (!loc) break;
	const target = new URL(loc, next).toString();
	const params = new URL(target).searchParams;
	if (params.get('code')) {
		code = params.get('code');
		break;
	}
	next = target;
}
if (!code) throw new Error('no code');

const tokenRes = await fetch(`${APP}/oauth/token`, {
	method: 'POST',
	headers: { 'content-type': 'application/x-www-form-urlencoded' },
	body: new URLSearchParams({
		grant_type: 'authorization_code',
		client_id: CLIENT_ID,
		code,
		code_verifier: verifier,
		redirect_uri: CALLBACK
	})
});
if (!tokenRes.ok) throw new Error(`token: ${tokenRes.status} ${await tokenRes.text()}`);
const tokens = await tokenRes.json();
const granted = String(tokens.scope ?? '').split(' ').filter(Boolean);

console.log(`requested : ${requested}`);
console.log(`displayed : ${displayed.join(' ') || '(nothing)'}`);
console.log(`granted   : ${granted.join(' ')}`);
console.log(`silent    : ${granted.filter((s) => !displayed.includes(s)).join(' ') || '(none)'}`);
console.log(`token response keys: ${Object.keys(tokens).join(', ')}`);

// 1. userinfo with the access token: does `profile`/`email` produce claims?
const ui = await fetch(`${APP}/oauth/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
const uiBody = await ui.text();
console.log(`userinfo  : ${ui.status} ${uiBody}`);

// 2. introspect: what does the OP say the token holds?
const intro = await fetch(`${APP}/oauth/introspect`, {
	method: 'POST',
	headers: { 'content-type': 'application/x-www-form-urlencoded' },
	body: new URLSearchParams({ token: tokens.access_token, client_id: CLIENT_ID, token_type_hint: 'access_token' })
});
console.log(`introspect: ${intro.status} ${await intro.text()}`);

// 3. id_token claims (only issued because `openid` was silently re-attached).
if (tokens.id_token) {
	const [h, p] = tokens.id_token.split('.');
	console.log(`id_token header : ${JSON.stringify(b64urlDecode(h))}`);
	console.log(`id_token claims : ${JSON.stringify(b64urlDecode(p))}`);
} else {
	console.log('id_token: (absent)');
}
console.log(`signed in as ${session.user_id}`);

// 4. Does any /v1 endpoint accept the claim scopes as authorization? Enumerate the
//    documented surface and see which answer 403 for this token.
for (const path of [
	'/v1/me',
	'/v1/account',
	'/v1/grants',
	'/v1/sources',
	'/v1/games/phigros/e2e/resources/b30',
	'/v1/games/phigros/plain/resources/profile'
]) {
	const res = await fetch(APP + path, { headers: { ...H(), authorization: `Bearer ${tokens.access_token}` } });
	console.log(`  ${path} -> ${res.status} ${(await res.text()).slice(0, 90)}`);
}
