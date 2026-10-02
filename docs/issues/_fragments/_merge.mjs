// Merge the per-round extraction fragments into the four severity files.
// Run: node docs/issues/_fragments/_merge.mjs
//
// Input fragments obey the contract in docs/issues/README.md:
//   ## P0/P1   -> a series of "### <ID> <title>" blocks
//   ## P2/P3   -> table rows: | ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
// It is idempotent: re-running rebuilds the four files from the fragments.

import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..');
const root = join(out, '..', '..');
let head = 'unknown';
try {
  head = execSync('git rev-parse --short HEAD', { cwd: root }).toString().trim();
} catch { /* not a git checkout: keep the placeholder */ }

// Highest priority first: the later the round, the more authoritative its severity.
// Round 9 is an independent audit of HEAD after rc.4 and carries the current
// fix ledger (992710b), so it outranks every earlier round.
// round10.md is not a new audit: it is a hand-maintained register pass that writes
// already-ruled items (S11-1, FO-02) into the register as DECIDED-NONGOAL, so it
// outranks everything (prio -3) and its S11-1 row replaces round9's OPEN one.
const FRAGMENTS = [
  { file: 'round10.md',    round: 10, prio: -3 },
  { file: 'round9.md',     round: 9, prio: -1 },
  { file: 'conformance.md', round: 9, prio: -2 },
  { file: 'round7.md',     round: 7, prio: 0 },
  { file: 'round6.md',     round: 6, prio: 1 },
  { file: 'round5.md',     round: 5, prio: 2 },
  { file: 'rounds2-4.md',  round: 2, prio: 3 },
];

// Same mechanism reported under several IDs by different rounds -> one row.
const ALIAS = new Map(Object.entries({
  'Z18-1': 'G-11', '22-1': 'G-11',              // /readyz fail-open
  'Z10-3': 'G-12',                              // shutdown budget
  'Z12-7': 'Z11-1',                             // readyz poisoning
  'Z18v-2': 'Z14-4',                            // provider TTL on failed discovery
  'Z19V-1': 'Z19-1',                            // value pasted into a *_env name slot
  'A-FE-5': 'P2-20',                            // pnpm audit gate
  // Round 9's own §5 de-duplication (the report recommends one row per root cause):
  'S05-2': 'S14-2',                             // CompleteBind per-binding lock
  'S04-1': 'S01-1',                             // approved device_code is never consumed
  'S04-3': 'S01-2', 'S14-8': 'S01-2', 'S13-10': 'S01-2',  // MemoryDeviceStore/oauth store has no bound
  'S13-3': 'S13-2', 'S14-1': 'S13-2', 'S14-6': 'S13-2', 'S14-7': 'S13-2', // full scan under the store mutex
  'S14-9': 'S10-2',                             // readiness probe panic latch
  'S14-10': 'S04-8',                            // Registry.Register unsynchronised map write
  'S11-5': 'S11-3',                             // Kill Switch client target aborts early
}));

const canonical = (id) => ALIAS.get(id) ?? id;

function sections(text) {
  const out = new Map();
  let cur = null;
  for (const line of text.split(/\r?\n/)) {
    const m = /^##\s+(.*?)\s*$/.exec(line);
    if (m) { cur = m[1]; out.set(cur, []); continue; }
    if (cur) out.get(cur).push(line);
  }
  return out;
}

function parseBlocks(lines) {
  const blocks = [];
  let cur = null;
  for (const line of lines) {
    const m = /^###\s+(.*?)\s*$/.exec(line);
    if (m) { cur = { head: m[1], body: [] }; blocks.push(cur); continue; }
    if (cur) cur.body.push(line);
  }
  return blocks
    .map((b) => ({ ...b, id: canonical((b.head.split(/\s+/)[0] ?? '').trim()) }))
    .filter((b) => b.id);
}

function parseRows(lines) {
  const rows = [];
  // A cell may contain an escaped pipe (`\|`). Split on unescaped pipes only,
  // otherwise the escape turns into a phantom column and breaks the table.
  const KEEP = '\u0000PIPE\u0000';
  for (const line of lines) {
    const t = line.trim();
    if (!t.startsWith('|')) continue;
    const safe = t.replace(/\\\|/g, KEEP);
    const cells = safe.split('|').slice(1, -1)
      .map((c) => c.trim().split(KEEP).join('\\|'));
    if (cells.length < 2) continue;
    if (/^-+$/.test(cells[0]) || /^ID$/i.test(cells[0])) continue; // rule / header
    const id = canonical(cells[0].replace(/\*\*/g, '').trim());
    if (!id) continue;
    const sevCell = cells[1] ?? '';
    const sev = /P2/.test(sevCell) ? 'P2' : /P3/.test(sevCell) ? 'P3' : 'P3';
    rows.push({ id, sev, cells, round: null, prio: null });
  }
  return rows;
}

const blocks = [];
const rows = [];
const seen = new Map(); // id -> prio of the winner

for (const f of FRAGMENTS) {
  const text = readFileSync(join(here, f.file), 'utf8');
  const sec = sections(text);

  for (const b of parseBlocks(sec.get('P0/P1') ?? [])) {
    if (seen.has(b.id) && seen.get(b.id) <= f.prio) continue;
    seen.set(b.id, f.prio);
    blocks.push({ ...b, round: f.round, prio: f.prio });
  }
  for (const r of parseRows(sec.get('P2/P3') ?? [])) {
    if (seen.has(r.id) && seen.get(r.id) <= f.prio) continue;
    seen.set(r.id, f.prio);
    rows.push({ ...r, round: f.round, prio: f.prio });
  }
}

// Round 6 called G-1/G-2/G-3 its blocking three; round 7 reproduced all of them red.
// Round 9 independently named six of its eight Highs "go-live blockers" (§7 step 1);
// the other two Highs (S03-1, S13-5) were conditional P0/P1 and stay P1 here.
const P0_IDS = new Set(['G-1', 'G-2', 'G-3', 'S02-1', 'S08-2', 'S10-1', 'S13-1', 'S14-2', 'S06-1']);

const p0 = blocks.filter((b) => P0_IDS.has(b.id));
const p1 = blocks.filter((b) => !P0_IDS.has(b.id));
const p2 = rows.filter((r) => r.sev === 'P2');
const p3 = rows.filter((r) => r.sev === 'P3');

const now = new Date().toISOString().slice(0, 10);

function header(title, blurb, count, extra = '') {
  return `# ${title}

> ${blurb}
> **条目数：${count}** ｜ 由 \`_fragments/_merge.mjs\` 从各轮抽取结果生成（${now}，HEAD \`${head}\`）。
> 严重度取**对抗性复核后的裁定**；同一机制多编号者已合并，别名写在 ID 列。
${extra}
`;
}

function writeBlockFile(name, title, blurb, items, extra = '') {
  const body = items.map((b) => `### ${b.head}\n${b.body.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd()}`
    + `\n- **首次记录**：第 ${b.round} 轮\n`).join('\n\n---\n\n');
  writeFileSync(join(out, name), header(title, blurb, items.length, extra) + '\n' + body + '\n', 'utf8');
}

function writeTableFile(name, title, blurb, items, extra = '') {
  // Re-escape pipes inside cells: parseRows un-escapes them, so emitting them raw
  // would split the row into extra columns (this had silently corrupted N-04 and
  // Z15-2 in the generated files).
  const cell = (c) => String(c ?? '').replace(/\|/g, '\\|');
  const table = ['| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |', '|---|---|---|---|---|---|']
    .concat(items.map((r) => `| ${r.cells.map(cell).join(' | ')} |`)).join('\n');
  writeFileSync(join(out, name), header(title, blurb, items.length, extra) + '\n' + table + '\n', 'utf8');
}

writeBlockFile('P0-blockers.md', 'P0 · 阻断上线（BLOCKERS）',
  '不修就不能上线。G-1/G-2/G-3 由第七轮在 HEAD 上复跑确认；S02-1/S06-1/S08-2/S10-1/S13-1/S14-2 由第九轮独立审计命名（§7 第 1 步），并在 `992710b` 收口。',
  p0.map((b) => ({
    ...b,
    body: b.body.map((l) => /^-\s*\*\*严重度\*\*/.test(l.trim())
      // Earlier rounds called their three "P1 · 阻断". This register sorts by
      // "does it block go-live", so they live in P0 — say both, so nobody is confused
      // when they trace an entry back to the round-6 report.
      ? '- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）'
      : l),
  })),
  `
> **当前状态（HEAD \`${head}\`）：这 9 条全部 \`FIXED\`，没有未修 P0。**
> G-1/G-2/G-3 由第六轮认定、\`79d7333\` 收口；S02-1/S06-1/S08-2/S10-1/S13-1/S14-2 是第九轮
> 独立审计在 rc.4 之后重新发现的 8 条 High 中的 6 条，由 \`992710b\` 收口。保留在册只为溯源；
> 是否仍有残余，以每条的状态与 \`docs/issues/README.md\` 的统计为准。
`);

writeBlockFile('P1-high.md', 'P1 · 高（HIGH）',
  '低门槛前提（一次登录、一个公开 client、一次匿名连接）即可扩大权限、读他人数据，或破坏生产稳定性。',
  p1,
  `
> 其中 \`Z11-1\`/\`Z11-4\`/\`Z11-5\`/\`Z11-V1\` 是**匿名单机**可触发的跨用户可用性缺陷
> ——按本项目口径（「匿名可触发的 DoS」）它们处在 P1 的上沿；
> 若按上线门槛衡量，可与 P0 一起排期。
>
> **第九轮补充**：\`S03-1\`（return_to 无界）与 \`S13-5\`（内存存储无界）是第九轮 8 条 High 中
> 未被列为"上线阻断"的两条（部署形态相关），同样已在 \`992710b\` 收口。
> 当前 HEAD 上**没有未修的 P0/P1**；第 9 轮判为"上线前应先修"的 13 条 Medium 见
> [\`P2-triage.md\`](P2-triage.md) 的「T0 组」。
`);

writeTableFile('P2-medium.md', 'P2 · 中（MEDIUM）',
  '前提较高，或影响有界但确定。',
  p2);

writeTableFile('P3-low.md', 'P3 · 低 / 提示（LOW）',
  '加固、纵深防御、文档与实现不一致、可维护性。**这一类最大，也最容易被永久搁置。**',
  p3,
  `
> 三个反复出现的形态，建议成批处理而不是逐条修：
> ① **修复只修了一半**（同族只覆盖了一个面）；
> ② **假守卫**（测试结构上不可能失败，或探针永远到不了它声称的路径）；
> ③ **注释断言了实现没有的性质**。
`);

const counts = { P0: p0.length, P1: p1.length, P2: p2.length, P3: p3.length };

// --- 已修复 / 有意不做：从各片段原样收集，避免抽取结果里有东西没归宿 ---
const bullets = (lines) => lines
  .map((l) => l.trim())
  .filter((l) => l.startsWith('- ') && l.length > 4);

const fixedLines = [];
const decidedLines = [];
for (const f of FRAGMENTS) {
  const sec = sections(readFileSync(join(here, f.file), 'utf8'));
  for (const [name, sink] of [['已修复', fixedLines], ['有意不做 / 已裁定', decidedLines]]) {
    const found = [...sec.keys()].filter((k) => k.includes(name.split(' ')[0]));
    for (const k of found) {
      const items = bullets(sec.get(k));
      if (items.length) sink.push(`\n### 第 ${f.round} 轮\n\n${items.join('\n')}`);
    }
  }
}

writeFileSync(join(out, 'fixed.md'),
  `# 已修复（仅供溯源）

> **这里不是待办。** 保留它只为了回答"这条当初为什么存在、后来被哪个 commit 收掉"。
> 由 \`_fragments/_merge.mjs\` 从各轮抽取结果生成（${now}）。
${fixedLines.join('\n')}
`, 'utf8');

const MARK_A = '<!-- BEGIN GENERATED: _fragments 的「有意不做 / 已裁定」 -->';
const MARK_B = '<!-- END GENERATED -->';
const ndPath = join(out, 'not-doing.md');
let nd = readFileSync(ndPath, 'utf8');
const generated = `${MARK_A}
<!-- 以下由 _fragments/_merge.mjs 生成（${now}）；改动请改片段或这里的手写章节，不要只改生成区。 -->

本次各轮抽取到的「有意不做 / 已裁定」条目（原文，未改写）：

${decidedLines.join('\n')}

${MARK_B}`;
if (nd.includes(MARK_A)) {
  nd = nd.replace(new RegExp(`${MARK_A}[\\s\\S]*?${MARK_B}`), generated);
} else {
  nd = `${nd.trimEnd()}\n\n---\n\n## 五、各轮抽取到的裁定条目（生成区）\n\n${generated}\n`;
}
writeFileSync(ndPath, nd, 'utf8');

// --- current-state counts (open vs closed), written next to the fragments so the
// README can quote a number that is regenerated rather than hand-maintained. ---
const blockOpen = (b) => {
  const line = b.body.find((l) => /^-\s*\*\*状态\*\*/.test(l.trim()));
  return line ? !/FIXED/.test(line) : true;
};
const rowOpen = (r) => !/FIXED/.test(r.cells[4] ?? '');
const open = {
  P0: p0.filter(blockOpen).length,
  P1: p1.filter(blockOpen).length,
  P2: p2.filter(rowOpen).length,
  P3: p3.filter(rowOpen).length,
};
const byRound = {};
for (const [sev, items] of [['P0', p0], ['P1', p1], ['P2', p2], ['P3', p3]]) {
  for (const it of items) {
    const r = it.round;
    byRound[r] ??= { total: 0, open: 0 };
    byRound[r].total += 1;
    if (sev === 'P0' || sev === 'P1' ? blockOpen(it) : rowOpen(it)) byRound[r].open += 1;
  }
}
const summary = { generated: now, head, total: counts, open, byRound };
writeFileSync(join(here, '_counts.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');

console.log(JSON.stringify({ ...counts, open, fixed: fixedLines.length, decided: decidedLines.length }));
