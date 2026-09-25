// The bundle budget.
//
// The SPA is embedded in the binary, so its weight is the weight of every
// `re0auth` download and every container image — and nothing else in the build
// notices when it grows. Vite prints sizes and moves on; a panel of "the frontend
// got 300 kB bigger" appears in a review only if somebody happened to read the
// build log. This turns that into a check.
//
// The numbers below are MEASURED, not guessed: they come from a real build with
// headroom, and they are meant to be raised deliberately — in a commit that says
// why — not nudged to make a red build green. That is the same trade the Go side
// makes with its coverage floor.
//
// Usage: node scripts/check-bundle-size.mjs [distDir]
// Run it after `pnpm run build`: it refuses to measure the embed placeholder,
// since a budget that passes on an empty directory is worse than no budget.

import { readdirSync, readFileSync, statSync, appendFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join, relative, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = process.argv[2] ?? join(here, '..', '..', 'internal', 'webui', 'dist');

// The budget, per category, in bytes of the files that actually ship.
//
// Measured on the build this script shipped with: 156.7 KiB of JS and 19.3 KiB of
// CSS. The headroom is about a quarter — enough that a patch bump of Svelte or
// Tailwind does not trip it, small enough that gradual growth is caught before it
// is the size of the app itself.
const BUDGET = {
	js: 200 * 1024,
	css: 24 * 1024
};

function walk(dir) {
	const out = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...walk(full));
		else out.push(full);
	}
	return out;
}

let files;
try {
	files = walk(dist);
} catch {
	console.error(`bundle: cannot read ${dist} — run \`pnpm run build\` first`);
	process.exit(1);
}

// A placeholder passes every size check there is, which is exactly why it must be
// refused instead of measured.
if (!files.some((f) => f.endsWith('index.html'))) {
	console.error(
		`bundle: ${dist} holds the embed placeholder, not a build — run \`pnpm run build\` first.\n` +
			'  (A budget measured on an empty directory reports a very good number.)'
	);
	process.exit(1);
}

const byCategory = { js: [], css: [], html: [], other: [] };
for (const file of files) {
	const size = statSync(file).size;
	const ext = extname(file).toLowerCase();
	const category = ext === '.js' ? 'js' : ext === '.css' ? 'css' : ext === '.html' ? 'html' : 'other';
	byCategory[category].push({ file: relative(dist, file), size });
}

const total = (entries) => entries.reduce((sum, e) => sum + e.size, 0);
const gzip = (entries) =>
	entries.reduce((sum, e) => sum + gzipSync(readFileSync(join(dist, e.file))).length, 0);

const rows = Object.entries(byCategory).map(([category, entries]) => ({
	category,
	files: entries.length,
	bytes: total(entries),
	gzip: category === 'js' || category === 'css' ? gzip(entries) : null
}));

const lines = [
	'bundle budget:',
	...rows.map(
		(r) =>
			`  ${r.category.padEnd(6)} ${String(r.files).padStart(3)} files  ${(r.bytes / 1024)
				.toFixed(1)
				.padStart(8)} KiB` + (r.gzip === null ? '' : `  (${(r.gzip / 1024).toFixed(1)} KiB gzipped)`)
	)
];
console.log(lines.join('\n'));

let failed = false;
for (const [category, budget] of Object.entries(BUDGET)) {
	const used = total(byCategory[category]);
	if (used <= budget) continue;
	failed = true;
	const offenders = [...byCategory[category]]
		.sort((a, b) => b.size - a.size)
		.slice(0, 5)
		.map((e) => `      ${(e.size / 1024).toFixed(1).padStart(8)} KiB  ${e.file}`)
		.join('\n');
	console.error(
		`\nbundle: ${category} is ${(used / 1024).toFixed(1)} KiB, over the ${(budget / 1024).toFixed(
			0
		)} KiB budget.\n` +
			`  Largest ${category} files:\n${offenders}\n` +
			'  Either trim it, or raise BUDGET in this script in a commit that says why.'
	);
}

if (process.env.GITHUB_STEP_SUMMARY) {
	appendFileSync(process.env.GITHUB_STEP_SUMMARY, '```\n' + lines.join('\n') + '\n```\n');
}

process.exit(failed ? 1 : 0);
