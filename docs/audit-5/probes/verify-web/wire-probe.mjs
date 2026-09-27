// Verifier probe (frontend-VERIFIED.md): wire facts for A-FE-1, A-FE-2, A-FE-6, A-FE-9.
// Run with the e2e server up: `node e2e/server.mjs` in web/.
const APP = process.env.E2E_APP ?? 'http://127.0.0.1:18099';

async function show(label, path, init = {}) {
	const res = await fetch(APP + path, { redirect: 'manual', ...init });
	const body = await res.text();
	const pick = (n) => res.headers.get(n);
	console.log(`\n=== ${label}  ${init.method ?? 'GET'} ${path} -> ${res.status}`);
	for (const h of [
		'cache-control',
		'etag',
		'last-modified',
		'content-type',
		'content-length',
		'content-range',
		'accept-ranges',
		'content-encoding',
		'content-security-policy',
		'vary'
	]) {
		const v = pick(h);
		if (v !== null) console.log(`    ${h}: ${v}`);
	}
	console.log(`    body(${body.length}): ${JSON.stringify(body.slice(0, 60))}`);
	return { res, body };
}

const shell = await show('shell', '/app/consent');
const root = await show('shell root', '/app/');
const asset = await show('asset', '/app/_app/immutable/assets/0.GGQYCh1V.css');
const ver = await show('version.json', '/app/_app/version.json');

// A-FE-1: conditional request with a made-up validator and with a plausible one.
await show('If-None-Match (bogus)', '/app/consent', { headers: { 'if-none-match': '"anything"' } });
await show('If-Modified-Since (old)', '/app/consent', {
	headers: { 'if-modified-since': 'Wed, 21 Oct 2015 07:28:00 GMT' }
});

// A-FE-2: Range on the document, both a head range and a tail range.
const head = await show('Range head', '/app/consent', { headers: { range: 'bytes=0-9' } });
const tail = await show('Range tail', '/app/consent', { headers: { range: 'bytes=10-' } });
if (tail.res.status === 206) {
	// Does the truncated document still carry the CSP meta tag and a usable hash?
	const hasMeta = /http-equiv="content-security-policy"/i.test(tail.body);
	const hasScript = /<script/i.test(tail.body);
	console.log(`    truncated tail: meta-csp present=${hasMeta} script-tag present=${hasScript}`);
}
await show('Range on asset', '/app/_app/immutable/assets/0.GGQYCh1V.css', {
	headers: { range: 'bytes=0-9' }
});

// What does the shell actually declare, and where is the timestamp?
const html = shell.body;
const meta = html.match(/http-equiv="content-security-policy" content="([^"]*)"/i);
console.log(`\nshell meta policy: ${meta ? meta[1] : '(none)'}`);
const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
const { createHash } = await import('node:crypto');
for (const s of inline) {
	console.log(
		`inline script sha256-${createHash('sha256').update(s).digest('base64')} len=${s.length} head=${JSON.stringify(
			s.slice(0, 70)
		)}`
	);
}
console.log(`version.json body: ${ver.body}`);
console.log(`shell asset refs: ${JSON.stringify(html.match(/\/app\/_app\/immutable\/[^"']+/g))}`);
