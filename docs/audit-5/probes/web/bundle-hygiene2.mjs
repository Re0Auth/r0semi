// Second pass on the built bundle: reachability, console noise, and the
// dev-warning path — the three things the first pass got imprecise.
//
// Run: node docs/audit-5/probes/web/bundle-hygiene2.mjs

import { readdirSync, readFileSync, statSync } from 'node:fs';
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

const files = walk(dist).map((f) => relative(dist, f).split(/[\\/]/).join('/'));
const jsFiles = files.filter((f) => extname(f) === '.js');
const texts = new Map(files.map((f) => [f, readFileSync(join(dist, f), 'utf8')]));
const html = texts.get('index.html');

// --- reachability, following imports the way a browser would ---------------
// Every emitted chunk must be named somewhere in the graph that starts at the
// two entry modules the shell imports. A chunk nothing names is dead weight in
// every binary and every image, and forgotten code lives in dead weight.
const imported = new Set();
for (const [f, text] of texts) {
	if (!f.endsWith('.js')) continue;
	// import("./x.js"), import('/app/_app/immutable/...'), and bare "'./x.js'"
	for (const m of text.matchAll(/["'`](?:\.\/|\/app\/_app\/immutable\/|\.\.\/)*([A-Za-z0-9._/-]+\.js)["'`]/g)) {
		imported.add(m[1]);
	}
}

const reachable = new Set();
const queue = ['_app/immutable/entry/start.BYxz_rv8.js', '_app/immutable/entry/app.DToPh9gB.js'];
for (const f of jsFiles) {
	// what the shell itself names
	if (html.includes(f)) queue.push(f);
}
// a chunk is reachable when its basename appears inside a reachable chunk
function named(text, file) {
	const base = file.split('/').pop();
	return text.includes(base) || text.includes('./' + base);
}
while (queue.length) {
	const cur = queue.shift();
	if (!cur || reachable.has(cur) || !texts.has(cur)) continue;
	reachable.add(cur);
	const text = texts.get(cur);
	for (const f of jsFiles) {
		if (reachable.has(f)) continue;
		if (named(text, f)) queue.push(f);
	}
}
const orphans = jsFiles.filter((f) => !reachable.has(f));
console.log(`js chunks: ${jsFiles.length}; reachable from the shell graph: ${reachable.size}`);
console.log(`unreachable chunks: ${orphans.length}`);
for (const o of orphans) console.log(`  UNREACHABLE ${o}`);

// --- console noise --------------------------------------------------------
let consoleCalls = 0;
const consoleByFile = [];
for (const f of jsFiles) {
	const m = texts.get(f).match(/console\.(log|debug|trace|info|warn|error)\s*\(/g) ?? [];
	if (m.length) {
		consoleByFile.push({ f, n: m.length, kinds: [...new Set(m)].join(',') });
		consoleCalls += m.length;
	}
}
console.log(`\nconsole.* call sites in shipped js: ${consoleCalls}`);
for (const c of consoleByFile.sort((a, b) => b.n - a.n)) {
	console.log(`  ${String(c.n).padStart(3)}  ${c.f}  [${c.kinds}]`);
}

// --- the dev-warning path -------------------------------------------------
// svelte.dev URLs are the runtime's warning strings. The question is whether
// they can be reached in a production build: Svelte gates them behind its own
// dev flag, and the compiler strips dev blocks. Print the surrounding bytes so
// the gate is visible rather than assumed.
const runtime = '_app/immutable/chunks/B-QHV2o-.js';
const text = texts.get(runtime) ?? '';
const idx = text.indexOf('svelte.dev');
if (idx >= 0) {
	console.log(`\nsvelte.dev occurrence context in ${runtime}:`);
	console.log(JSON.stringify(text.slice(Math.max(0, idx - 260), idx + 120)));
	console.log(`occurrences: ${(text.match(/svelte\.dev/g) ?? []).length}`);
	// Is the whole warning block inside a `development`-style guard?
	for (const guard of ['dev', 'DEV', 'NODE_ENV', 'esm-env']) {
		console.log(`  contains ${JSON.stringify(guard)}: ${text.includes(guard)}`);
	}
} else {
	console.log(`\nno svelte.dev string in ${runtime}`);
}

// The error/warning strings live across the chunks; find which file carries one
// and whether a `console.warn` sits next to it (a shipped dev warning) or only a
// `throw`/`console.error` does.
for (const f of jsFiles) {
	const t = texts.get(f);
	if (!t.includes('svelte.dev')) continue;
	const warns = (t.match(/console\.warn\s*\(/g) ?? []).length;
	const throws = (t.match(/throw new Error\(/g) ?? []).length;
	console.log(`  ${f}: svelte.dev=${(t.match(/svelte\.dev/g) ?? []).length} console.warn=${warns} throw=${throws}`);
}

// --- content addressing sanity --------------------------------------------
// The hash in a hashed filename is a build id, not a content digest, so it
// cannot be recomputed. What is checkable is the property that matters for
// cache-busting: two different files never share a name, and the name changes
// when the content does (verified separately by rebuilding).
const names = files.map((f) => f.split('/').pop());
const dup = names.filter((n, i) => names.indexOf(n) !== i);
console.log(`\nduplicate basenames: ${dup.length}`);

// --- where does the app talk to? -----------------------------------------
// Every absolute URL in shipped JS: anything off-origin would be a request the
// CSP blocks (and a party that would see the consent page's URL).
const urls = new Map();
for (const f of jsFiles) {
	for (const m of texts.get(f).matchAll(/(?:https?:)?\/\/[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s"'`)]*/g)) {
		const u = m[0];
		urls.set(u, (urls.get(u) ?? 0) + 1);
	}
}
console.log(`\nabsolute URLs in shipped js: ${urls.size}`);
for (const [u, n] of [...urls].sort((a, b) => b[1] - a[1]).slice(0, 12)) console.log(`  ×${n}  ${u}`);

// path literals the app fetches: these must all be same-origin /v1 or /oauth
const paths = new Map();
for (const f of jsFiles) {
	for (const m of texts.get(f).matchAll(/["'`](\/(?:v1|oauth|auth|bind|app)\/[A-Za-z0-9_./${}-]*)["'`]/g)) {
		paths.set(m[1], (paths.get(m[1]) ?? 0) + 1);
	}
}
console.log(`\nabsolute request paths in shipped js: ${paths.size}`);
for (const [p, n] of [...paths].sort()) console.log(`  ×${n}  ${p}`);
void statSync;
