// Verifier probe: (1) can a hostile scope name reach the consent/device view at all
// (the injection sink the report says is unreachable), and (2) does every non-HTML
// asset carry the document-level CSP in the real composition?
const APP = process.env.E2E_APP ?? 'http://127.0.0.1:18099';

const HOSTILE = ['"><script>window.__scope_probe=1</script>', 'a" onmouseover="x', 'x. y'];

for (const scope of HOSTILE) {
	const u = new URL(`${APP}/oauth/authorize`);
	u.search = new URLSearchParams({
		response_type: 'code',
		client_id: 'cli',
		redirect_uri: 'http://127.0.0.1:18098/callback',
		scope,
		state: 's',
		code_challenge: 'x'.repeat(43),
		code_challenge_method: 'S256'
	}).toString();
	const res = await fetch(u, { redirect: 'manual' });
	const body = await res.text();
	console.log(`authorize scope=${JSON.stringify(scope)} -> ${res.status} ${body.slice(0, 120).replace(/\n/g, ' ')}`);
}

for (const scope of HOSTILE) {
	const res = await fetch(`${APP}/oauth/device_authorization`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ client_id: 'cli', scope })
	});
	console.log(
		`device_authorization scope=${JSON.stringify(scope)} -> ${res.status} ${(await res.text()).slice(0, 120)}`
	);
}

// (2) document-level CSP on the real composition, per response kind.
for (const p of [
	'/app/',
	'/app/favicon.svg',
	'/app/_app/immutable/entry/start.js',
	'/app/_app/version.json',
	'/app/robots.txt',
	'/robots.txt',
	'/v1/sessions/current',
	'/oauth/userinfo'
]) {
	const res = await fetch(APP + p, { redirect: 'manual' });
	console.log(
		`${p} -> ${res.status} ct=${res.headers.get('content-type')} csp=${JSON.stringify(
			res.headers.get('content-security-policy')
		)} cc=${JSON.stringify(res.headers.get('cache-control'))}`
	);
}

// Does /app serve any *other* HTML document? (adapter-static emits one index.html)
