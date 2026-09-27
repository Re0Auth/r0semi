// Is the shipped Svelte dev-warning path reachable? (A-FE-10's open half.)
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, '../../../../internal/webui/dist');
const p = resolve(dist, '_app/immutable/chunks/B-QHV2o-.js');
const t = readFileSync(p, 'utf8');

const re = /function ([A-Za-z_$][A-Za-z0-9_$]*)\(\)\s*\{\s*console\.warn\(/g;
let m;
const names = [];
while ((m = re.exec(t))) names.push(m[1]);
console.log(`warn functions: ${names.join(', ')}`);

for (const n of names) {
	const callRe = new RegExp(`(?<![A-Za-z0-9_$])${n.replace(/\$/g, '\\$')}\\(`, 'g');
	const calls = [...t.matchAll(callRe)];
	console.log(`${n}: ${calls.length} occurrence(s) of "${n}("`);
	for (const c of calls) {
		const before = t.slice(Math.max(0, c.index - 60), c.index + 4);
		console.log(`    …${JSON.stringify(before)}`);
	}
}
console.log(`total console.warn sites: ${(t.match(/console\.warn\(/g) ?? []).length}`);
for (const w of t.matchAll(/.{0,50}console\.warn\(/g)) console.log(`  context: ${JSON.stringify(w[0])}`);
