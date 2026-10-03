// The shipped-output hygiene gate.
//
// `check-bundle-size.mjs` measures how big the SPA is; nothing looks at what is
// IN it. The build output goes straight into the Go binary and is served from the
// consent and device screens — the pages a user is making a security decision on
// — so a leftover `console.log`, a `debugger`, a sourcemap pointer or a
// `localhost` URL in a shipped chunk is an avoidable exposure, and a `console.warn`
// from somebody's debugging session ships to every user's console.
//
// This gate reads the built chunks (A-FE-10) and fails on:
//   * `console.log(` / `console.debug(` / `debugger` / `sourceMappingURL` /
//     `localhost` — unconditionally;
//   * a `console.warn` site that is not one of the Svelte client-runtime
//     diagnostics allowlisted below;
//   * a `svelte.dev/e/…` link that is not the message of a `throw Error(…)` or of
//     an allowlisted `console.warn`.
//
// The allowlist is the point. The vendor chunk carries Svelte 5's own client
// runtime, and that runtime ships five warning helpers plus nineteen documented
// `throw Error(\`https://svelte.dev/e/…\`)` messages. They are NOT our code, we
// cannot remove them without patching Svelte, and the audit that found them could
// not demonstrate that any warning actually fires at runtime (the production
// build compiles Svelte's dev blocks out of component code, but the shared
// runtime module is bundled whole). So they are exempted EXPLICITLY, one literal
// at a time, with the reason written down — not silently passed. Any warning site
// that is not on this list fails, which is what catches a new one from our source
// or a dependency change.
//
// REVIEW ON EVERY SVELTE UPGRADE: if an upgrade adds or removes a warning, this
// gate fails and the allowlist below is meant to be edited deliberately, in the
// commit that says why.
//
// Usage: node scripts/check-dist-warnings.mjs [distDir]
// Run it after `pnpm run build`; like the bundle budget, it refuses to scan the
// embed placeholder — a scan of an empty directory reports a very clean artifact.

import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = process.argv[2] ?? join(here, '..', '..', 'internal', 'webui', 'dist');

// Patterns that must never appear in a shipped chunk, whatever the size.
// `console.error` is deliberately absent: SvelteKit's hydration-failure recovery
// writes one, and that is a real error report, not console noise.
const BANNED = [
	{ pattern: /console\.log\s*\(/g, what: 'console.log(' },
	{ pattern: /console\.debug\s*\(/g, what: 'console.debug(' },
	{ pattern: /\bdebugger\b/g, what: 'debugger' },
	{ pattern: /sourceMappingURL/g, what: 'sourceMappingURL' },
	{ pattern: /localhost/g, what: 'localhost' }
];

// The Svelte 5 client-runtime warning literals that are allowed to ship. Each is
// a first argument to `console.warn(…)` in Svelte's bundled `internal/client`
// module; the reason column is what "explicitly exempt and write down why" means.
const ALLOWED_WARNINGS = new Map([
	['https://svelte.dev/e/derived_inert', 'Svelte client runtime: inert $derived diagnostic'],
	['https://svelte.dev/e/hydratable_missing_but_expected', 'Svelte client runtime: hydratable value missing'],
	['https://svelte.dev/e/hydration_mismatch', 'Svelte client runtime: hydration mismatch'],
	['https://svelte.dev/e/select_multiple_invalid_value', 'Svelte client runtime: invalid <select multiple> value'],
	['https://svelte.dev/e/svelte_boundary_reset_noop', 'Svelte client runtime: boundary reset was a no-op'],
	['Failed to hydrate: ', 'Svelte client runtime: hydration recovery report (the router retries CSR)']
]);

// The shape every `svelte.dev/e/…` link has to have: the message of a thrown
// Error (the runtime's documented error surface) or of an allowlisted warning
// above. A link anywhere else is a new shape and is reported.
const ERROR_LINK = /(?:throw Error\(|console\.warn\()\s*`https:\/\/$/;

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
	files = walk(dist).filter((f) => extname(f).toLowerCase() === '.js');
} catch {
	console.error(`dist-warnings: cannot read ${dist} — run \`pnpm run build\` first`);
	process.exit(1);
}

// Same refusal as the bundle budget: the placeholder is not a build.
if (!existsSync(join(dist, 'index.html'))) {
	console.error(
		`dist-warnings: ${dist} holds the embed placeholder, not a build — run \`pnpm run build\` first.\n` +
			'  (A hygiene scan of an empty directory finds nothing and proves nothing.)'
	);
	process.exit(1);
}
if (files.length < 5) {
	console.error(`dist-warnings: only ${files.length} js chunks under ${dist}; that is not a build output`);
	process.exit(1);
}

const problems = [];
const warningSites = [];
const errorLinks = [];
let scanned = 0;

for (const file of files) {
	const rel = relative(dist, file);
	const text = readFileSync(file, 'utf8');
	scanned += statSync(file).size;

	for (const { pattern, what } of BANNED) {
		pattern.lastIndex = 0;
		for (const m of text.matchAll(pattern)) {
			problems.push(`${rel}: ${what} at byte ${m.index}`);
		}
	}

	// `console.warn(` with its first argument captured. A warn whose first
	// argument is not a template literal (or has a different shape) does not
	// match, so it is unknown and fails below rather than slipping through.
	const warn = /console\.warn\s*\(\s*`([^`]*)`/g;
	const seenAt = new Set();
	for (const m of text.matchAll(warn)) {
		seenAt.add(m.index);
		warningSites.push({ file: rel, literal: m[1] });
		if (!ALLOWED_WARNINGS.has(m[1])) {
			problems.push(`${rel}: console.warn(\`${m[1]}\`) is not an allowlisted runtime diagnostic`);
		}
	}
	// Any `console.warn(` the capture above did not cover is a shape this gate
	// does not understand, which is reported rather than ignored.
	const anyWarn = /console\.warn/g;
	for (const m of text.matchAll(anyWarn)) {
		let covered = false;
		for (const at of seenAt) if (m.index >= at && m.index <= at + 40) covered = true;
		if (!covered) problems.push(`${rel}: console.warn at byte ${m.index} does not have an allowlisted literal argument`);
	}

	for (const m of text.matchAll(/svelte\.dev\/e\/[a-z0-9_]+/g)) {
		const before = text.slice(Math.max(0, m.index - 40), m.index);
		const link = m[0];
		if (!ERROR_LINK.test(before)) {
			problems.push(`${rel}: ${link} is neither a thrown Error message nor an allowlisted warning`);
			continue;
		}
		errorLinks.push(link);
	}
}

// Anti-vacuous floors. The checks above pass by finding nothing, which is also
// what a scan that stopped reading the chunks looks like — and the allowlist is
// only meaningful if the vendor chunk it exempts was actually seen.
if (warningSites.length < 5 || errorLinks.length < 10) {
	problems.push(
		`the scan found ${warningSites.length} allowlisted warnings and ${errorLinks.length} ` +
			'svelte.dev error links in the vendor chunk; expected at least 5 and 10 — ' +
			'either Svelte changed and the allowlist needs updating, or the scan is not reading the build'
	);
}

const lines = [
	'dist hygiene:',
	`  ${files.length} js chunks, ${(scanned / 1024).toFixed(1)} KiB scanned`,
	`  ${warningSites.length} console.warn sites (all allowlisted runtime diagnostics)`,
	`  ${errorLinks.length} svelte.dev/e links (thrown Error messages / allowlisted warnings)`
];

if (problems.length === 0) {
	console.log(lines.join('\n'));
	console.log('  no console.log/debugger/sourceMappingURL/localhost, and no unlisted console.warn');
	if (process.env.GITHUB_STEP_SUMMARY) {
		appendFileSync(process.env.GITHUB_STEP_SUMMARY, '```\n' + lines.join('\n') + '\n```\n');
	}
	process.exit(0);
}

console.error(lines.join('\n'));
console.error('\ndist-warnings: the shipped output has ' + problems.length + ' problem(s):');
for (const p of problems.slice(0, 20)) console.error('      ' + p);
if (problems.length > 20) console.error(`      … and ${problems.length - 20} more`);
console.error(
	'\n  Remove the call from `web/src`, or — if it came from a dependency — add its\n' +
		'  literal to ALLOWED_WARNINGS in this script with the reason it must ship.'
);
process.exit(1);
