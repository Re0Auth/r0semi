// Verifier probe: how far into the shell does the meta CSP live, and what does a
// Range that starts past it actually return?
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, '../../../../internal/webui/dist');
const html = readFileSync(resolve(dist, 'index.html'), 'utf8');

const metaAt = html.indexOf('content-security-policy');
const metaEnd = html.indexOf('>', metaAt) + 1;
const scriptAt = html.indexOf('<script');
console.log(`shell bytes: ${html.length}`);
console.log(`meta CSP tag: ${metaAt}..${metaEnd}`);
console.log(`inline <script> at: ${scriptAt}`);
console.log(`inline <script> ends at: ${html.indexOf('</script>', scriptAt) + 9}`);

const APP = process.env.E2E_APP ?? 'http://127.0.0.1:18099';
for (const start of [0, metaEnd, scriptAt]) {
	const res = await fetch(`${APP}/app/`, { headers: { range: `bytes=${start}-` } });
	const body = await res.text();
	console.log(
		`\nRange bytes=${start}- -> ${res.status} content-range=${JSON.stringify(
			res.headers.get('content-range')
		)} len=${body.length}`
	);
	console.log(`  carries meta CSP: ${/content-security-policy/i.test(body)}`);
	console.log(`  carries <script>: ${/<script/i.test(body)}`);
	console.log(`  carries </html>: ${/<\/html>/i.test(body)}`);
	console.log(`  carries a closing </script>: ${/<\/script>/i.test(body)}`);
	console.log(`  body head: ${JSON.stringify(body.slice(0, 80))}`);
}
