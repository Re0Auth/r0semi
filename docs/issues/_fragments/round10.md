# 第 10 轮（本仓库 w2-docs 轮）：寄存器裁定标注

> 这**不是**一次新的安全审计，而是把已有裁定回写进寄存器的手工片段。
> 手工维护（不随第九轮报告 `_extract_round9.mjs` 重生成），由 `_merge.mjs` 合并。
> 加入 `_merge.mjs` 的 `FRAGMENTS` 时用 **最低的 `prio`（-3）**，因此本片段的同名条目
> 覆盖第 9 轮抽取结果——这正是本片段存在的理由。

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| S11-1 | P3 | Admin audit detail stores the raw operator account id in `Detail["actor"]`, defeating pseudonym-key destruction | `internal/admin/admin.go:485`、`internal/admin/admin.go:490`；`audit/audit.go:73`、`audit/audit.go:84` | DECIDED-NONGOAL | 按 `not-doing.md` 已有裁定（第 7 轮生成区）：「`admin.*` 的 `detail["actor"]` 记操作员原始 `usr_` — **已裁定（企业审计合规）**」。本轮确认，不作为缺陷开工。已知残余边界：该操作员日后抹除自己的账号不会解除这些行的关联（第 2 轮已记录）。 |

## 有意不做 / 已裁定

- S11-1 — DECIDED-NONGOAL：`admin.*` 的 `detail["actor"]` 记操作员原始 `usr_` —— 已裁定（企业审计合规），不加改动 — 依据：`docs/issues/not-doing.md`（第 7 轮生成区，原文）。
- FO-02 — DECIDED-NONGOAL：探针在 CAS 输掉的分支触发、残留的是入册旧密钥，证据不成立；跨实例 refresh 残余竞态 `BRIEF §5` 已列为有意不做 — 依据：`22-audit5-red-reconciliation.md:202`。
- （更正，Z20-2）raw 透传的 scope 闸门**已不再是**「源的任一资源 scope」：现在的闸门是显式的 `<game>.raw.read`（`internal/httpapi/federation_routes.go` 的 `rawGate`）。第 7 轮生成区里那条「raw 的 scope 闸门是源的任一资源 scope — 文档化决定，不作发现」只描述**旧实现**，不再适用 — 依据：`docs/upstream-protocol.md` §9.1。
