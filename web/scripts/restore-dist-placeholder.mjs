// Restores the placeholder in internal/webui/dist after a build.
//
// adapter-static empties its output directory before writing, which deletes the
// two dotfiles that let `//go:embed all:dist` compile. That is not cosmetic: with
// the directory empty or absent, `go build ./...` fails outright, so a fresh
// clone would not build for anyone who has not run pnpm.
//
// The two requirements genuinely conflict:
//
//   * a clone with no Node must still build, which needs the embedded directory
//     to exist and be non-empty;
//   * the build output must not be committed, which means the adapter has to own
//     the directory's contents.
//
// Restoring the placeholder satisfies both. It runs as part of `pnpm run build`
// rather than as a separate command, so there is no ordering for anyone to get
// wrong and no step for CI to forget.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = resolve(dirname(fileURLToPath(import.meta.url)), '../../internal/webui/dist');

mkdirSync(dist, { recursive: true });

// Ignore everything the build produced, but keep the placeholder itself tracked.
writeFileSync(resolve(dist, '.gitignore'), '*\n!.gitignore\n!.gitkeep\n');

writeFileSync(
	resolve(dist, '.gitkeep'),
	`This placeholder exists so that //go:embed all:dist is satisfied on a machine
without Node, keeping \`go build ./...\` working for a Go-only contributor.

The real build output is written here by \`pnpm run build\` and is not committed.
Do not delete this file: with it gone and no frontend built, the embed directive
matches nothing and the whole module stops compiling.
`
);

console.log('webui: restored the internal/webui/dist placeholder');
