// Verifier probe: what does the server answer for an asset URL that no longer
// exists? The report's A-FE-9 failure chain says `http.ServeFileFS` answers 404
// and that the SPA fallback "does not stand in for script files".
const APP = process.env.E2E_APP ?? 'http://127.0.0.1:18099';

const shellRefs = await (async () => {
	const html = await (await fetch(`${APP}/app/`)).text();
	return [...html.matchAll(/\/app\/_app\/immutable\/[^"']+/g)].map((m) => m[0]);
})();
console.log(`assets the shell names: ${[...new Set(shellRefs)].join('\n  ')}`);

const real = [...new Set(shellRefs)].find((u) => u.endsWith('.js'));
const res = await fetch(APP + real);
console.log(
	`\nexisting entry chunk ${real}\n  -> ${res.status} ct=${res.headers.get('content-type')} cc=${JSON.stringify(
		res.headers.get('cache-control')
	)} csp=${JSON.stringify(res.headers.get('content-security-policy'))} len=${(await res.text()).length}`
);

// The shape a stale shell produces after a deploy that dropped the old chunk name.
for (const p of [
	'/app/_app/immutable/entry/start.DELETEDBYDEPLOY.js',
	'/app/_app/immutable/chunks/nonexistent-chunk.js',
	'/app/_app/immutable/entry/start.js',
	'/app/does-not-exist.png'
]) {
	const r = await fetch(APP + p);
	const body = await r.text();
	console.log(
		`${p}\n  -> ${r.status} ct=${r.headers.get('content-type')} cc=${JSON.stringify(
			r.headers.get('cache-control')
		)} body[0:40]=${JSON.stringify(body.slice(0, 40))}`
	);
}
