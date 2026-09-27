// Bundle hygiene scan for the built SPA under internal/webui/dist.
//
// Three questions, all of which the existing guards do NOT ask:
//   1. did anything dev-only reach the shipped bundle (localhost, debug hooks,
//      console noise, source maps, dev-mode branches)?
//   2. did anything secret-shaped reach it (keys, tokens, JWTs, env values)?
//   3. is the shipped bundle internally consistent (every asset URL the shell
//      preloads exists; the inline script's hash covers what it says)?
//
// Run: node docs/audit-5/probes/web/bundle-hygiene.mjs

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative, extname, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, '../../../../internal/webui/dist');

function walk(dir) {
	const out = [];
	for (const e of readdirSync(dir, { withFileTypes: true })) {
		const full = join(dir, e.name);
		if (e.isDirectory()) out.push(...walk(full));
		else out.push(full);
	}
	return out;
}

const files = walk(dist);
const jsFiles = files.filter((f) => extname(f) === '.js');
const cssFiles = files.filter((f) => extname(f) === '.css');
const htmlFile = join(dist, 'index.html');

// dev-only / leak markers to search for in shipped JS and CSS
const MARKERS = [
	['localhost', /\blocalhost\b/g],
	['127.0.0.1', /\b127\.0\.0\.1\b/g],
	['0.0.0.0', /\b0\.0\.0\.0\b/g],
	['debugger statement', /\bdebugger\b/g],
	['console.log/debug/trace', /console\.(log|debug|trace|info)\s*\(/g],
	['sourceMappingURL', /sourceMappingURL/g],
	['sourcesContent', /sourcesContent/g],
	['dev-mode branch', /import\.meta\.env\.DEV|__DEV__|isDev\b|NODE_ENV\s*!==?\s*["']production["']/g],
	['vite dev modules', /\/@vite\/|@fs\/|\/@id\//g],
	['hmr', /\bhot\b.*\baccept\b|import\.meta\.hot/gi],
	['svelte dev warning', /svelte\.dev|hydration_mismatch|compilerOptions/g],
];

// secret-shaped patterns: these are the ones that would actually matter
const SECRETS = [
	['private key block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
	['AWS access key id', /\bAKIA[0-9A-Z]{16}\b/g],
	['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g],
	['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g],
	['JWT (three base64url segments)', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
	['pem/cert', /-----BEGIN CERTIFICATE-----/g],
	['bearer literal', /["'`]Bearer\s+[A-Za-z0-9._-]{16,}["'`]/g],
	['password assignment', /\b(password|passwd|secret|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["'`][^"'`]{8,}["'`]/gi],
	['usr_ handle', /\busr_[0-9a-f]{16,}\b/g],
	['cli_ id', /\bcli_[A-Za-z0-9_-]{6,}\b/g],
	['long base64 blob (>200)', /["'][A-Za-z0-9+/]{200,}={0,2}["']/g],
];

function scan(label, text, patterns) {
	const hits = [];
	for (const [name, re] of patterns) {
		const m = text.match(re);
		if (m) hits.push({ name, count: m.length, sample: m[0].slice(0, 120) });
	}
	if (hits.length) {
		console.log(`\n[${label}]`);
		for (const h of hits) console.log(`  ${h.name} ×${h.count}: ${JSON.stringify(h.sample)}`);
	}
	return hits;
}

console.log(`bundle root: ${dist}`);
console.log(`files: ${files.length} (js ${jsFiles.length}, css ${cssFiles.length})`);

// --- sizes, the number the budget guard measures --------------------------
const sum = (list) => list.reduce((n, f) => n + statSync(f).size, 0);
const gz = (list) => list.reduce((n, f) => n + readFileSync(f).length, 0); // raw; gzip measured by the project script
console.log(`js total: ${(sum(jsFiles) / 1024).toFixed(1)} KiB over ${jsFiles.length} files`);
console.log(`css total: ${(sum(cssFiles) / 1024).toFixed(1)} KiB`);
const biggest = [...jsFiles, ...cssFiles]
	.map((f) => ({ f: relative(dist, f), size: statSync(f).size }))
	.sort((a, b) => b.size - a.size)
	.slice(0, 6);
console.log('largest:');
for (const b of biggest) console.log(`  ${(b.size / 1024).toFixed(1).padStart(8)} KiB  ${b.f}`);
void gz;

// --- 1 & 2: markers and secrets in every shipped text asset ---------------
const allText = [];
for (const f of files) {
	if (!['.js', '.css', '.html', '.json', '.svg', '.txt'].includes(extname(f))) continue;
	allText.push({ f: relative(dist, f), text: readFileSync(f, 'utf8') });
}

let totalHits = 0;
for (const { f, text } of allText) {
	const hits = scan(f, text, MARKERS);
	totalHits += hits.length;
}
console.log(`\ndev-only marker groups found: ${totalHits}`);

let totalSecrets = 0;
for (const { f, text } of allText) {
	const hits = scan(f, text, SECRETS);
	totalSecrets += hits.length;
}
console.log(`secret-shaped groups found: ${totalSecrets}`);

// --- 3: the shell and its assets must agree -------------------------------
const html = readFileSync(htmlFile, 'utf8');
const refs = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1]);
const missing = [];
const external = [];
for (const ref of refs) {
	if (/^(https?:)?\/\//.test(ref)) {
		external.push(ref);
		continue;
	}
	const local = ref.startsWith('/app/') ? ref.slice('/app/'.length) : ref.replace(/^\//, '');
	try {
		statSync(join(dist, local));
	} catch {
		missing.push(ref);
	}
}
console.log(`\nshell references: ${refs.length}; missing on disk: ${missing.length}; off-origin: ${external.length}`);
if (missing.length) for (const m of missing) console.log(`  MISSING ${m}`);
if (external.length) for (const e of external) console.log(`  EXTERNAL ${e}`);

// the meta hash must equal sha256 of the inline script it governs
const metaMatch = html.match(/http-equiv="content-security-policy" content="([^"]*)"/);
const policy = metaMatch ? metaMatch[1] : '';
const declared = new Set(
	[...policy.matchAll(/'sha256-([A-Za-z0-9+/=]+)'/g)].map((m) => m[1])
);
const inlineScripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
let covered = 0;
for (const s of inlineScripts) {
	const h = createHash('sha256').update(s).digest('base64');
	if (declared.has(h)) covered++;
	else console.log(`  UNCOVERED inline script, sha256-${h}`);
}
console.log(`inline scripts: ${inlineScripts.length}; covered by declared hash: ${covered}`);

// hash-named assets must actually be content-addressed: the name's hash prefix
// is a build id, not a content hash, so re-checking it is not possible here;
// what IS checkable is that no two different files share a name.
const names = files.map((f) => relative(dist, f));
const dupes = names.filter((n, i) => names.indexOf(n) !== i);
console.log(`duplicate asset names: ${dupes.length}`);

// every module the shell preloads should be imported by something, and every
// emitted chunk should be reachable — an orphan chunk is dead weight in every
// binary, and dead weight is where forgotten code lives.
const imported = new Set();
for (const { f, text } of allText) {
	if (!f.endsWith('.js')) continue;
	for (const m of text.matchAll(/["']\.\/([A-Za-z0-9._/-]+\.js)["']/g)) imported.add(m[1]);
	for (const m of text.matchAll(/\/app\/_app\/immutable\/([^"']+\.js)/g)) imported.add(m[1]);
}
const allJs = jsFiles.map((f) => relative(dist, f));
const orphans = allJs.filter(
	(f) => !f.startsWith('entry/') && !imported.has(f) && !html.includes(f) && !imported.has(f.replace(/^_app\/immutable\//, ''))
);
console.log(`js files never referenced by the shell or by another chunk: ${orphans.length}`);
for (const o of orphans) console.log(`  ORPHAN ${o}`);

console.log('\ndone');
