// Verifier probe: is the interactive consent screen the ONLY place where the
// displayed scope set can be smaller than the granted one? (Refutes/confirms the
// report's "唯一入口" remark about authorization_routes.go:189.)
//
// Drives the device flow (RFC 8628) end to end with the two standard OIDC claim
// scopes plus one data scope, and compares displayed vs granted.
const APP = process.env.E2E_APP ?? 'http://127.0.0.1:18099';
const IDP = process.env.E2E_IDP ?? 'http://127.0.0.1:18098';
const CLIENT_ID = 'cli';
const REQUESTED = process.env.E2E_SCOPES ?? 'openid profile email phigros.b30.read';

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
const H = (extra = {}) => ({ cookie: jar, ...extra });

await fetch(`${IDP}/__identity/probe-device-split`, { method: 'POST' });
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
if (!session.user_id) throw new Error(`not signed in: ${JSON.stringify(session)}`);
console.log(`signed in as ${session.user_id}`);

console.log(`\nrequested: ${REQUESTED}`);
const daRes = await fetch(`${APP}/oauth/device_authorization`, {
	method: 'POST',
	headers: { 'content-type': 'application/x-www-form-urlencoded' },
	body: new URLSearchParams({ client_id: CLIENT_ID, scope: REQUESTED })
});
const daBody = await daRes.text();
console.log(`device_authorization -> ${daRes.status} ${daBody}`);
if (!daRes.ok) {
	console.log('=> the device endpoint refused the claim scopes outright; no divergence to test');
	process.exit(0);
}
const da = JSON.parse(daBody);

const describeRes = await fetch(`${APP}/v1/device/verification?user_code=${encodeURIComponent(da.user_code)}`, {
	headers: H()
});
const describeBody = await describeRes.text();
console.log(`describe -> ${describeRes.status} ${describeBody}`);
if (!describeRes.ok) throw new Error('could not describe the device request');
const described = JSON.parse(describeBody);
const displayed = (described.scopes ?? []).map((s) => s.scope);
const csrf = described.csrf_token;

const decisionRes = await fetch(`${APP}/v1/device/decision`, {
	method: 'POST',
	headers: H({ 'content-type': 'application/json', 'x-csrf-token': csrf }),
	body: JSON.stringify({
		user_code: da.user_code,
		decision: 'approve',
		scopes: displayed,
		explicit: displayed.filter((s) => described.scopes.find((d) => d.scope === s)?.explicit_consent)
	})
});
console.log(`decision -> ${decisionRes.status} ${await decisionRes.text()}`);

const tokenRes = await fetch(`${APP}/oauth/token`, {
	method: 'POST',
	headers: { 'content-type': 'application/x-www-form-urlencoded' },
	body: new URLSearchParams({
		grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
		device_code: da.device_code,
		client_id: CLIENT_ID
	})
});
const tokenBody = await tokenRes.text();
console.log(`token -> ${tokenRes.status} ${tokenBody}`);
if (tokenRes.ok) {
	const tokens = JSON.parse(tokenBody);
	const granted = String(tokens.scope ?? '').split(' ').filter(Boolean);
	console.log(`\ndisplayed (device page): ${displayed.join(' ') || '(nothing)'}`);
	console.log(`granted  (token)       : ${granted.join(' ')}`);
	const silent = granted.filter((s) => !displayed.includes(s));
	console.log(`granted but never displayed: ${silent.join(' ') || '(none)'}`);
	if (silent.length) console.log('=> the device screen also grants scopes it never listed');
}
