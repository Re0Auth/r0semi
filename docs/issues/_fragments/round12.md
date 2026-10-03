# 第 12 轮：只读复核后的状态改判

> 依据子代理只读复核（HEAD 6126072）对 5 条 OPEN 行改判：3 条前提不成立、1 条已裁定不做、1 条为工作区清理。
> 优先级 -5，覆盖 round11。

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| S10-5 | P3 · 信息 | [info] Limiter.Check heap-allocates a *rate.Reservation on every request | internal/ratelimit/ratelimit.go:289; internal/ratelimit/ratelimit.go:295 | NOT-A-DEFECT（BenchmarkCheckExistingKey = 0 B/op, 0 allocs/op；ReserveN 被内联，go1.27.1 上不可复现） | 见 `docs/security-audit-9.md` §4（类别：performance） |
| S12-12 | P3 · 信息 | [info] SignIn appends return_to after a URL fragment, unlike the equivalent link() path | web/src/lib/components/SignIn.svelte:50; web/src/lib/components/SignIn.svelte:52 | NOT-A-DEFECT（start_url 无 fragment，前提不可达；round9 _audit/round9/verify/S12.json:82-86 rejected） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S12-2 | P3 · 信息 | [info] Dev root redirect does not match a request that carries a query string | web/vite.config.ts:27; web/vite.config.ts:28 | NOT-A-DEFECT（Vite base 中间件去 query 后 302 并保留 query；round9 S12.json:12-16 实跑 302→308→200） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S15-12 | P3 · 信息 | [info] Backup CronJob writes plaintext database dumps; no age encryption path is wired, unlike scripts/backup.sh | deploy/k8s/backup/cronjob.yaml:59-70; docs/operations.md:125-126 | DECIDED-NONGOAL（docs/issues/not-doing.md:124 备份转储不加密—文档化取舍） | 见 `docs/security-audit-9.md` §4（类别：security） |
| A-FE-11 | P3 | 仓库根有一个名为 `%SC%` 的空目录（未被展开的 Windows 变量） | `%SC%/`（仓库根，空目录，未被 git 跟踪） | FIXED（工作区清理：仓库根 %SC% 空目录已不存在；该目录未被跟踪，无提交记录） | 直接删掉；真实风险是同类笔误落在有内容的路径上 — 来源：`docs/audit-5/findings/frontend.md:224（第 5 轮）` |

## 已修复

- A-FE-11 — FIXED（工作区清理，未跟踪的 %SC% 空目录已删除）
