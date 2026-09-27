// Verifier detail probe: 13-digit-timestamp census and console.* location in the
// current build (A-FE-9 mechanism 2, A-FE-10 counts).
import { readdirSync, readFileSync } from 'node:fs';
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
const js = files.filter((f) => extname(f) === '.js');

let withStamp = 0;
for (const f of js) {
	const t = readFileSync(join(dist, f), 'utf8');
	const m = t.match(/\b1\d{12}\b/g) ?? [];
	if (m.length) {
		withStamp++;
		console.log(`timestamp in ${f}: ${[...new Set(m)].join(', ')}`);
	}
}
console.log(`chunks carrying a 13-digit epoch: ${withStamp}/${js.length}`);

const version = JSON.parse(readFileSync(join(dist, '_app/version.json'), 'utf8'));
console.log(`version.json: ${JSON.stringify(version)} -> ${new Date(Number(version.version)).toISOString()}`);

for (const f of js) {
	const t = readFileSync(join(dist, f), 'utf8');
	const warn = (t.match(/console\.warn\(/g) ?? []).length;
	const err = (t.match(/console\.error\(/g) ?? []).length;
	const log = (t.match(/console\.log\(/g) ?? []).length;
	if (warn || err || log) console.log(`console in ${f}: warn=${warn} error=${err} log=${log}`);
}
