# 第 13 轮：低风险批次收口

> 本轮修掉 15 条（提交 43e5d9a）：除零检查、脚本模式位、告警选择器、文档对齐、前端守卫与清理、探针真加固。
> 优先级 -6，覆盖 round11/12。

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| S13-11 | P3 | perfreport divides by the baseline median without a zero check, producing NaN/Inf deltas and a NaN geomean | cmd/perfreport/main.go:355; cmd/perfreport/main.go:373 | FIXED（43e5d9a） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S15-10 | P3 | scripts/backup-keys.sh is committed mode 100644 while the documented invocation runs it directly | scripts/backup-keys.sh:1; docs/operations.md:90-92 | FIXED（43e5d9a） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S15-8 | P3 | Three alert rules keyed on generic go_*/process_* metrics carry no job selector and can fire on unrelated targets | deploy/prometheus/re0auth.rules.yml:304-348; deploy/prometheus/re0auth.rules.yml:4-7 | FIXED（43e5d9a） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| NF-Z07-1 | P3 | `/bind` 归属守卫是单侧的：探针只证明「B 被拒」，无法区分「B 被拒」与「所有人被拒」（守卫空洞，非产品漏洞） | `internal/zzprobe/audit7/z07authsessionlifecycle/handle_binding_test.go` | FIXED（43e5d9a） | 在该探针补一步「A 自己用同一 state 打 callback」的对照，断言其不是 400（夹具下应为 303 `bind_failed`）；依据 `Z07-VERIFIED.md:165-186` |
| Z08V-1 | P3 | 「开放重定向面」的绿是假守卫：内存模式无 IdP，`/auth/{p}/start` 回 404、`/bind` 匿名回 401，探针永远到不了任何重定向 sink（产品无洞，是报告守卫无效） | `internal/zzprobe/audit7/z08frontendbrowser/realproc_test.go` | FIXED（43e5d9a） | 删掉该条「探过没破」，或用已配 provider 的全接线夹具走完 start→callback 再断言 `Location`；依据 `Z08-VERIFIED.md:25`、`Z08-VERIFIED.md:114-128` |
| Z08V-2 | P3 | Z08-3 的「构建产物无 `version.json` 引用」是错的：产物 `chunks/DqohD3-m.js` 确实带 `fetch(.../_app/version.json)` 与版本比对逻辑（方向是低估风险） | `docs/audit-7/findings/Z08-frontend-browser.md:133` | FIXED（43e5d9a） | 更正该事实，并据此给 `_app/version.json` 明确缓存指令；依据 `Z08-VERIFIED.md:26`、`Z08-VERIFIED.md:130-136` |
| VZ16-1 | P3 | 「可达性」守卫只读文件与 build 注释、从不编译：给它想要的 `-tags` 就能变成永久绿 | `internal/zzprobe/audit7/z16guardtestquality/gates_test.go:211-297` | FIXED（43e5d9a） | 守卫加真编译步骤（用真工具链取代 grep）（来源：`Z16-VERIFIED.md:92-100`） |
| VZ16-2 | P3 | 该守卫只认 `//go:build`，旧式 `// +build` 约束被它当成「默认套件」，两侧都兜不住 | `internal/zzprobe/audit7/z16guardtestquality/gates_test.go:260-271` | FIXED（43e5d9a） | 用 `go list -f '{{.TestGoFiles}}'`（真工具链）取代文本扫描，或同时解析 `// +build`（来源：`Z16-VERIFIED.md:102-110`） |
| Z17-6 | P3 | openapi 说 audit 的 `cursor` 是「不透明、非签发即拒」，实现是普通行号且接受任意正整数 | `docs/openapi.yaml:1452-1454`、`internal/httpapi/audit_routes.go:82-89` | FIXED（43e5d9a） | 把描述改成事实，或真做成不透明/签名游标（属裁定：建议只改文档）（来源：`Z17-VERIFIED.md:83-91`） |
| Z18v-3 | P3 | 被复核夹具 `Limiter=nil`、`MaxInFlight=0`，使 Z18-1 的「限流/在途豁免」断言在结构上不可证 | `internal/zzprobe/audit7/z18gohazardsweep/probes_test.go:63-70` | FIXED（43e5d9a） | 填上 `Limiter`/`MaxInFlight` 再断言 200，或删掉该句 |
| Z18v-4 | P3 | `Bulkhead` 绿探针是空守卫：从不触发 `uint(maxConcurrent)` 转换，证不了它要排除的形态 | `internal/zzprobe/audit7/z18gohazardsweep/probes_test.go:325-336` | FIXED（43e5d9a） | 补 `Bulkhead(next, 2)` 下第 3 个并发 `RoundTrip` 被拒/阻塞的探针 |
| Z20V-3 | P3 | 被审报告两条「探过没破」守卫偏弱（逃逸断言不命名 400；归一化守卫是单源夹具），假绿风险 | `internal/zzprobe/audit7/z20authzisolationmatrix/scopegate_test.go:92-96,103-125` | FIXED（43e5d9a） | 逃逸断言命名 400＋零上游调用；归一化守卫至少两条候选源 |
| A-FE-4 | P3 | `web/svelte.config.js` 不存在——kit 配置只活在 `vite.config.ts` 里 | `web/vite.config.ts:46-110`（`web/svelte.config.*` 不存在） | FIXED（43e5d9a） | 在 `web/README.md` 写明「刻意不用 `svelte.config.js`」，或把配置搬回标准位置并让 `webui_test.go` 改读它；加一条「两份 kit 配置即失败」的守卫 — 来源：`docs/audit-5/findings/frontend.md:109（第 5 轮）` |
| A-FE-8 | P3 | 未使用的 `web/src/lib/assets/favicon.svg` 仍是 Svelte 官方 logo | `web/src/lib/assets/favicon.svg:1` | FIXED（43e5d9a） | 删掉该文件或换成真正的品牌标记 — 来源：`docs/audit-5/findings/frontend.md:160（第 5 轮）` |
| A-FE-10 | P3 | 发布产物里有 6 处 `console.warn`，带 `svelte.dev/e/…` 文档链接 | `internal/webui/dist/_app/immutable/chunks/`（构建产物；具体分块名随构建变化） | FIXED（43e5d9a） | 在 `web/scripts/` 加一条产物 grep 守卫（与 `check-bundle-size.mjs` 同风格）；确认不可达则在守卫里显式豁免并写理由 — 来源：`docs/audit-5/findings/frontend.md:200（第 5 轮）` |

## 已修复

- S13-11 — FIXED（43e5d9a）
- S15-10 — FIXED（43e5d9a）
- S15-8 — FIXED（43e5d9a）
- NF-Z07-1 — FIXED（43e5d9a）
- Z08V-1 — FIXED（43e5d9a）
- Z08V-2 — FIXED（43e5d9a）
- VZ16-1 — FIXED（43e5d9a）
- VZ16-2 — FIXED（43e5d9a）
- Z17-6 — FIXED（43e5d9a）
- Z18v-3 — FIXED（43e5d9a）
- Z18v-4 — FIXED（43e5d9a）
- Z20V-3 — FIXED（43e5d9a）
- A-FE-4 — FIXED（43e5d9a）
- A-FE-8 — FIXED（43e5d9a）
- A-FE-10 — FIXED（43e5d9a）
