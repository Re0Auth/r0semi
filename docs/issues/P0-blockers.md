# P0 · 阻断上线（BLOCKERS）

> 不修就不能上线。每一条都在 `HEAD = bf81b2a` 上由第七轮独立复跑/读码确认为**仍然存在**。
> **条目数：3** ｜ 由 `_fragments/_merge.mjs` 从各轮抽取结果生成（2026-09-29）。
> 严重度取**对抗性复核后的裁定**；同一机制多编号者已合并，别名写在 ID 列。

> **为什么只有三条**：第七轮**没有**新发现 P0。这三条是第六轮认定「阻断上线」的三项
> （refresh 重放不止损、Postgres 不裁决 refresh 过期、数据库故障时撤销答 200），
> 第七轮用同一批探针在 HEAD 上重跑，**红探针无一转绿**；主代理另逐行核过机制
> （见 `docs/audit-7/findings/00-MAIN-VERIFICATION.md` 的 V-01/V-02/V-10）。
> 它们被放在 P0 而不是 P1，是因为它们决定「能不能上线」，而不是「影响有多大」。


### G-1 refresh token 重放被检测到之后，小偷那条链继续有效
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **上线阻断**：是
- **位置**：`internal/store/memory/oidc.go:211`（`ErrRefreshTokenSpent` 哨兵；返回处 `:556`，Postgres 对应 `internal/store/postgres/oidc.go:340` / `:399`）
- **影响**：refresh 是单次使用 + 轮换。小偷把偷到的第 2 代自己轮换成第 3 代后，合法客户端重放第 2 代（盗窃信号）只被拒，**第 3 代无人撤销**——攻击者保有静默访问直到 30 天 TTL 自然结束。「即时可撤销」卖点反面。
- **修法**：检测到已消费 refresh 重放时撤销该 (client, subject) 全部 refresh/access（RFC 9700 token family 撤销）。注意第 7 轮更正：检测点上被重放那行已被 delete，store 拿不到 subject/client，**必须先在轮换时留族/代号标识或墓碑**，否则修不出覆盖顺序重放的版本。
- **状态**：FIXED（79d7333）；探针已重推为回归守卫
- **证据**：`internal/zzprobe/audit6/z02protocoltoken/refresh_test.go::TestZ02RefreshReplayRevokesTheThiefsGeneration`（红）；`00-MAIN-VERIFICATION.md:249-267`（V-10 读码三点齐备）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:58`
- **首次记录**：第 6 轮


---

### G-2 生产后端（Postgres）的 refresh token 过期从不被裁决，30 天 TTL 只由 15 分钟一轮的 sweep 执行
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **上线阻断**：是
- **位置**：`internal/store/postgres/oidc.go:430`（SELECT 无 `expires_at` 谓词；轮换声明 `:392-401` 同）；对照内存 `internal/store/memory/oidc.go:573`
- **影响**：过期 refresh token 仍能换出**全新 30 天 TTL** 的 access+refresh（TTL 被重置而非拒绝）；sweep 连续失败时窗口继续延长（`cmd/re0auth/main.go:1111` 只打日志）。默认套件全跑内存后端，所以测试永远绿而生产行为不同。
- **修法**：`TokenRequestByRefreshToken` 的 SELECT 与轮换声明加 `expires_at > $n`（`$n` ← `s.now()`，保持单时钟政策）；两后端同形；`clock_test.go` 补「过期 refresh 被拒」。
- **状态**：FIXED（79d7333）；PG 侧端到端形状由 CI 的 postgres:16 定论
- **证据**：`00-MAIN-VERIFICATION.md:70-74`（V-01）；`05-memory-store.md:27-56`（HYPOTHESIS，差 `TEST_DATABASE_URL`）；`internal/zzprobe/audit6/z05memstore/drift_guards_test.go::TestMemoryRefusesAnExpiredRefreshToken`（绿，钉内存拒绝半边）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:75`
- **首次记录**：第 6 轮


---

### G-3 数据库故障时 RFC 7009 撤销回答 200，用户以为被盗令牌已撤销
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **上线阻断**：是
- **位置**：`internal/store/postgres/oidc.go:474`
- **影响**：三个 owner 查找全部以 `err == nil` 为进入条件，任何错误（连接断开、故障切换、`statement_timeout`、ctx 取消）都落穿到 `:530` 的 `return nil` ⇒ 协议层按「未知令牌即成功」答 200 且**不写审计**。客户端按 RFC 7009 不再重试，令牌在库恢复后继续有效到自然过期（refresh 最长 30 天）。安全事件响应路径上的静默失效。
- **修法**：三个查找各接 `noRows(err)` 分类——只有 `pgx.ErrNoRows` 允许落穿；其余返回 `oidc.ErrServerError()`（映射 500，可重试）。照抄同文件 `TokenOwner`（`oauth.go:207`）的形状。
- **状态**：FIXED（79d7333）
- **证据**：`internal/zzprobe/audit6/z04pgstore/revocation_error_probe_test.go::TestRevokeTokenDoesNotReportSuccessWhenTheDatabaseCannotAnswer`（红）、`::TestRevokeTokenClassifiesOnlyNoRowsAsUnknownToken`（红）；`00-MAIN-VERIFICATION.md:76-80`（V-02）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:90`
- **首次记录**：第 6 轮

