// Verifier probe for A-FE-10 / A-FE-5's runtime claim: re-run the report's own
// negative scans over the built output, WITH a positive control for each, and
// check whether the advisory package (`cookie`) reaches the shipped bundle.
import { readdirSync, readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, relative, extname, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
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
const read = (f) => readFileSync(join(dist, f), 'utf8');
const js = files.filter((f) => extname(f) === '.js');
const texts = new Map(js.map((f) => [f, read(f)]));
const allText = [...texts.values()].join('\n') + '\n' + read('index.html');

// The scans the report ran (names must match its prose).
const SCANS = [
	['console.log', /console\.log\s*\(/g],
	['console.debug', /console\.debug\s*\(/g],
	['console.warn', /console\.warn\s*\(/g],
	['console.error', /console\.error\s*\(/g],
	['debugger', /\bdebugger\b/g],
	['sourceMappingURL', /sourceMappingURL/g],
	['localhost', /localhost/g],
	['127.0.0.1', /127\.0\.0\.1/g],
	['@vite', /@vite/g],
	['@fs', /@fs/g],
	['import.meta.env.DEV', /import\.meta\.env\.DEV/g],
	["NODE_ENV !== 'production'", /NODE_ENV\s*!==\s*['"]production['"]/g],
	['private key block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
	['aws key id', /\bAKIA[0-9A-Z]{16}\b/g],
	['github token', /\bghp_[A-Za-z0-9]{20,}\b/g],
	['slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g],
	['jwt literal', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
	['Bearer <long>', /Bearer\s+[A-Za-z0-9._~+/-]{32,}=*/g],
	['secret assignment', /(?:password|secret|api_key|access_token|refresh_token)\s*[:=]\s*["'][^"']{16,}["']/gi],
	['re0auth id', /\b(?:usr|cli)_[0-9a-f]{16,}\b/g],
	['long base64', /["'`][A-Za-z0-9+/]{200,}={0,2}["'`]/g]
];

console.log(`--- negative scans over ${js.length} shipped js files + index.html ---`);
const hits = {};
for (const [name, re] of SCANS) {
	const n = (allText.match(re) ?? []).length;
	hits[name] = n;
	if (n) console.log(`  HIT  ${name}: ${n}`);
}
console.log(`  scans with zero hits: ${SCANS.filter(([n]) => !hits[n]).length}/${SCANS.length}`);

// --- POSITIVE CONTROL -----------------------------------------------------
// The same scans must fire on a corpus with planted strings. If they do not,
// "0 hits" would mean "the regex is broken", which is the costly kind of error.
console.log('\n--- positive control (planted corpus) ---');
const planted = [
	'console.log("x")',
	'console.debug("x")',
	'console.warn("x")',
	'console.error("x")',
	'debugger;',
	'//# sourceMappingURL=app.js.map',
	'http://localhost:5173/',
	'http://127.0.0.1:8080/',
	'import.meta.env.DEV',
	"if (NODE_ENV !== 'production') {}",
	'"@vite/client"',
	'"/@fs/C:/secret"',
	'-----BEGIN RSA PRIVATE KEY-----',
	'"AKIAIOSFODNN7EXAMPLE"',
	'"ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
	'"xoxb-1234567890-abcdefghijkl"',
	'"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"',
	'Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCD',
	'password = "supersecretvalue123"',
	'"usr_0123456789abcdef0123456789abcdef"',
	'"' + 'A'.repeat(210) + '"'
];
const plantedText = planted.join('\n');
let caught = 0;
for (const [name, re] of SCANS) {
	const n = (plantedText.match(re) ?? []).length;
	if (n) caught++;
	else console.log(`  MISS  ${name} did not fire on its own planted string`);
}
console.log(`  scans that fired on the planted corpus: ${caught}/${SCANS.length}`);

// --- console.warn detail (A-FE-10) ---------------------------------------
console.log('\n--- console.warn call sites, per file ---');
for (const [f, t] of texts) {
	const n = (t.match(/console\.warn\s*\(/g) ?? []).length;
	if (n) console.log(`  ${f}: ${n}`);
}
const sv = [...texts].filter(([, t]) => t.includes('svelte.dev'));
console.log(`files containing svelte.dev: ${sv.map(([f]) => f).join(', ')}`);
for (const [f, t] of sv) {
	const idx = t.indexOf('svelte.dev');
	console.log(`  context in ${f}: ${JSON.stringify(t.slice(Math.max(0, idx - 120), idx + 40))}`);
}
console.log(`any 'esm-env' / DEV gate string in the svelte runtime chunk: ${sv.some(([, t]) => t.includes('esm-env'))}`);

// --- does the advisory package ship? (A-FE-5 exposure judgement) ----------
console.log('\n--- cookie@0.6.0 reachability ---');
const cookieMarkers = ['argument str must be a string', 'fieldContentRegExp', 'cookie is expected to have'];
for (const m of cookieMarkers) {
	console.log(`  marker ${JSON.stringify(m)} in shipped js: ${allText.includes(m)}`);
}
console.log(`  'Cookie' as a word in shipped js: ${(allText.match(/\bCookie\b/g) ?? []).length}`);
console.log(`  'document.cookie' in shipped js: ${(allText.match(/document\.cookie/g) ?? []).length}`);

rmSync(mkdtempSync(join(tmpdir(), 'x-')), { recursive: true, force: true });
void writeFileSync;
