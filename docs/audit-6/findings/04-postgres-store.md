# 第六轮 · 区域 04：Postgres 存储（SQL / 事务 / 连接池 / 迁移）

> 审计对象：HEAD `bf81b2a`，工作区干净。范围：`internal/store/postgres/` 全部 38 个文件
> + `migrations/` 全部 22 个迁移。环境：Windows 11，无 Docker、无本地 Postgres——
> 需要真库的结论全部是读码级 + 常量算术，能落成可运行探针的都落了（含以内存 store 为
> 契约对照、以「连不上的 pgxpool」为失败注入的运行时探针）。

## 执行摘要

**7 条发现：P2×1、P3×6；其中 6 条 CONFIRMED（各有一条真实会失败的探针）、1 条 HYPOTHESIS。**
一句话结论：第五轮在本区域的修复把「撤销索引」「排空预算」「设备时钟」三件事各修了一半——
`oidc_devices` 是第七张没索引的撤销表、30s 排空预算叠上 35s HTTP 排空仍然顶穿 45s grace、
设备路径的时钟修好了但消费语句仍不看过期；另有一条本轮新找到的 fail-open：数据库出错时
RFC 7009 撤销把「查不了」当成「不存在」回答 200。回退到第五轮已收录的条目
（PG-001/002/004/005/006/007/008/009/010）的一律不重报。

---

### 04-1 数据库无法应答时，`RevokeToken` 把「查不了」当「不存在」——RFC 7009 撤销对连接失败回答成功（200，且无审计）

- 严重度：**P2 高**
- 不变量：撤销生效 | fail-closed
- 证据：`internal/store/postgres/oidc.go:474-531`。三个 owner 查找（`:478` oidc_access_tokens、
  `:499` oidc_refresh_tokens by id_hash、`:514` by token_hash）全部以 `err == nil` 为进入分支的
  条件，任何错误——连接断开、故障切换、`statement_timeout`、请求 ctx 取消——都落穿三个分支，
  停在 `:530` 的 `return nil`；协议层把它当 RFC 7009 的「未知令牌即成功」回答 **HTTP 200**
  （zitadel/oidc `pkg/op/token_revocation.go` 的 `Revoke` 只对非 nil 的 `*oidc.Error` 报错）。
  三个成功分支里的 `s.record(ctx, "oidc.revoke", …)` 全都不在落穿路径上，所以这条「成功」
  连审计都不留。运行时证据（无 DB、真 pgxpool 指向 `127.0.0.1:1`，连接被拒）：
  `RevokeToken returned success (nil) while every lookup failed with a connection error`。
- 状态：**CONFIRMED**（运行时红探针）
- 影响：Postgres 重启/故障切换/池错误窗口内，用户对被盗令牌的撤销拿到 200「已撤销」，
  客户端按 RFC 7009 不再重试；令牌在库恢复后继续有效到自然过期（refresh 30 天）。
  同窗口内 `admin` 的 SuspendClient/KillSwitch 走 `RevokeTokens`（会返回错误，fail-closed），
  所以这个洞是 RFC 7009 面独有的。对照：同一条路径上 `TokenOwner`（`oauth.go:207-227`）
  用 `noRows()` 做了正确分类——说明这是遗漏而不是策略。
- 探针：`revocation_error_probe_test.go::TestRevokeTokenDoesNotReportSuccessWhenTheDatabaseCannotAnswer`、
  `::TestRevokeTokenClassifiesOnlyNoRowsAsUnknownToken`
- 修法建议：三个查找各接 `noRows(err)` 分类——只有 `pgx.ErrNoRows` 允许落穿到
  「未知令牌即成功」；其余错误 `oidc.ErrServerError().WithParent(err)`（库映射为 500，
  告诉客户端可重试），照抄 `TokenOwner` 的形状。

### 04-2 `GetRefreshTokenInfo` 把数据库错误折叠成 `op.ErrInvalidRefreshToken`，废掉了库的 500 分支

- 严重度：P3 中
- 不变量：撤销生效 | fail-closed
- 证据：`internal/store/postgres/oidc.go:561-569`：`Scan` 出任何错误一律
  `return "", "", op.ErrInvalidRefreshToken`。库的契约（`pkg/op/storage.go:62-64`
  「must return ErrInvalidRefreshToken when presented with a token that is not a refresh token」；
  `token_revocation.go:60-66`）只把这一个哨兵当「换个形状再试」，**任何其他错误都会以
  500 server_error 终止请求**。折叠之后 500 分支不可达：数据库故障时库继续走解密路径、
  拿着解析不了的值调 `RevokeToken`——正好落进 04-1 的落穿，端到端变成 200。运行时证据：
  连接被拒时 `errors.Is(err, op.ErrInvalidRefreshToken) == true`。
- 状态：**CONFIRMED**（运行时红探针）
- 影响：与 04-1 同路径；单独看是把「应答 500」的故障伪装成「这个 refresh token 不存在」，
  使库的错误分层失效。
- 探针：`revocation_error_probe_test.go::TestGetRefreshTokenInfoDistinguishesDBFailureFromUnknownToken`
- 修法建议：`noRows(err) → 哨兵；其余 → 原样返回`，两行。

### 04-3 P2-4/P2-5 的修复漏了第七张表：`oidc_devices` 的 client-only 批量撤销无前导索引，守卫的手写清单也漏了它

- 严重度：P3 中（性能/资源，事件路径）
- 不变量：性能/资源 | 撤销生效
- 证据：`OIDCStore.RevokeTokens`（`oidc.go:1057-1082`）第三步 `revokeMatching(ctx, tx,
  []string{"oidc_devices"}, f)`（`:1075`）在 client-only 过滤下生成
  `DELETE FROM oidc_devices WHERE client_id = $1`。`oidc_devices` 的全部索引：
  PK `device_code_hash`（0008）、表达式唯一索引 `user_code`（0008）、`(subject)`（0012）、
  `(expires_at)`（0017）——**没有 client_id 前导索引**。b35f893 的迁移 0022 补了
  oidc_access_tokens / oidc_refresh_tokens / oauth_access_tokens / oauth_refresh_tokens /
  oauth_codes / oidc_auth_requests 六张；守卫 `TestClientScopedRevokeIsIndexed`
  （revoke_predicate_test.go:32-44）自称列举「every table a client_id-only predicate deletes
  from」，也是这六张。调用方：`admin.SuspendClient` / `DeleteClient` / Kill Switch 的
  `client` 目标（`internal/admin/admin.go:270/288/337`，经 `oauth.TokenAdmins` 扇出到
  `oidcStore.RevokeTokens`）。运行时证据：探针从 Go 源反推表集合（不是手写清单），
  报 `UNINDEXED CLIENT-SCOPED REVOKE: oidc_devices … (migration 0022 covered six tables;
  this is the seventh)`；守卫清单对照探针报 `the guard's hand-written table list omits
  oidc_devices`。
- 状态：**CONFIRMED**（源级红探针；真实 planner 行为需 DB，见「未能到达」）
- 影响：suspend/delete-client/kill-switch-client 的那一个事务里，对 oidc_devices 顺序扫描。
  表大小受设备码寿命 + 15 分钟清扫约束，故是 P3 而非 P2——但 0022 给同样是短寿命行的
  oauth_codes 补索引的理由一字不差地适用于它。
- 探针：`revoke_index_probe_test.go::TestEveryClientScopedRevokeTableHasALeadingClientIndex`、
  `::TestTheClientScopedRevokeGuardCoversTheDerivedTableSet`
- 修法建议：迁移 0023 补 `CREATE INDEX oidc_devices_client_idx ON oidc_devices (client_id)`；
  守卫改为从 `revokeMatching` 调用点反推表集合（探针里的提取器可直接搬走），不再手写清单。

### 04-4 P2-31 的修复只给了预算、没改算术：5s+30s+30s=65s 仍然顶穿 45s grace，排空预算在 k8s 里永远跑不完

- 严重度：P3 中
- 不变量：性能/资源 | 审计链
- 证据：常量算术。`endpointRemovalWait = 5s`（main.go:137）、`shutdownTimeout = 30s`（:127）、
  `auditDrainTimeout = 30s`（auditbatch.go:54）、`terminationGracePeriodSeconds: 45`
  （deployment.yaml:26）。三者是**串行**的：SIGTERM → `beginDrain` → 睡 5s（main.go:829）
  → HTTP drain 最多 30s（:837-849）→ `defer store.close()`（:377，最后执行）→
  `db.Close` → closers → `auditBatcher.Close` → drain（30s 预算）。审计排空只在 HTTP drain
  之后才开始，因为它排空的行来自「HTTP drain 超时后仍停在 enqueue 上的 handler」——
  即预算存在的那种场景（每批吃满 5s auditBatchTimeout）恰恰也是让 HTTP drain 超时的场景。
  最坏栈 65s > 45s：t=45 的 SIGKILL 先于 t=65 的预算到期，「过期拒绝」路径在 k8s 里
  从不运行。修复提交 5cd1690 自己的论据（「8×5s ≈40s 顶穿 45s」）对 30s 同样成立。
  deployment.yaml:21-25 的注释仍然只算 HTTP（「35s total」）。探针输出：
  `shutdown stack: endpointRemovalWait 5s + shutdownTimeout 30s + auditDrainTimeout 30s
  = 1m5s; terminationGracePeriodSeconds = 45s`。
- 状态：**CONFIRMED**（常量算术红探针；真 pod 的 SIGKILL 时序无法本机复现，但算术封闭）
- 影响：数据库慢的关停窗口里，排队中的审计行与在途批次照旧被 SIGKILL 整批丢掉——
  修复把「无界」变「有界」，但没有达成它声称的目标（让 drain 在 grace 内收尾）。
  非 k8s 部署不受影响（没有 45s 上限）。
- 探针：`drain_budget_probe_test.go::TestTheShutdownStackFitsThePodGrace`、
  `::TestTheManifestCommentCountsTheWholeStack`
- 修法建议：三选一：`auditDrainTimeout = grace - removal - http`（=10s）；或把
  `terminationGracePeriodSeconds` 提到 ≥70 并同步 deployment.yaml 注释与 ingress 的等待值；
  或让审计排空与 HTTP drain 并行（把 closer 提前到 drain 前触发，结构性改动）。
  至少要把 deployment.yaml 的 35s 注释改为全栈口径。

### 04-5 已批准的设备码过了 `expires_in` 仍可铸令牌：消费语句不看过期，而库先查 Done 后查 Expires

- 严重度：P3 中
- 不变量：token/scope 签发
- 证据：三段合成。
  ① Postgres 认领语句 `oidc.go:749-755`：`DELETE FROM oidc_devices WHERE device_code_hash
  = $1 AND client_id = $2 AND done = true AND denied = false RETURNING …`——**没有
  expires_at 谓词**（对照同文件 `AuthRequestByCode` 的认领 `:229`
  `AND expires_at > $2`，那是第五轮明确表扬过的形状）。
  ② 内存后端同形（memory/oidc.go:891-899：`d.done && !d.denied` 即删行返回）。
  ③ 库的检查顺序（zitadel/oidc `pkg/op/device.go:313-329`）：`Denied → Done → Expires`，
  **Done 短路在 Expires 之前**，`CreateDeviceTokenResponse` 直接铸新对。
  运行时证据（内存后端 + 注入时钟）：`an approved device authorization was handed back
  as consumable after its expiry`；源级证据：`the claim DELETE has no expires_at predicate`。
  注：`ApproveDevice` 本身查过期（bf81b2a 修的），所以缺口只在「批准后、过期后、清扫前」。
- 状态：**CONFIRMED**（内存契约运行时红探针 + Postgres SQL 源级红探针；PG 侧运行时需 DB）
- 影响：持有 device_code 的一方（合法客户端，或偷到码的一方——用户已批准）可以在码过期后
  铸 access/refresh 对，窗口 = 清扫间隔（15 分钟，`sweepLoop` main.go:405）。
  两个引擎行为一致，所以这不是后端分叉，而是共享缺口（相对 RFC 8628 §3.5 的 expired_token）。
- 探针：`device_expiry_probe_test.go::TestAnApprovedDeviceCodeCannotBeRedeemedAfterItsExpiry`、
  `::TestThePostgresDeviceConsumeClaimChecksExpiry`
- 修法建议：认领 DELETE 加 `AND expires_at > $n`（`$n` ← `s.now()`，与 ApproveDevice/
  AuthRequestByCode 同形），两个后端同改；PG 侧无法在无 DB 下验证，交 CI。

### 04-6 bf81b2a 之后残留的引擎分叉：slow_down 的间隔锚点，内存锚「上一次尝试」、Postgres 锚「上一次放行」

- 严重度：P3 低
- 不变量：两平面分离无关；这里是「两后端一致」这条既定目标（P2-32 的立项理由）
- 证据：内存 `memory/oidc.go:884-889`：被节流的 poll 仍执行 `d.lastPoll = s.now()`——
  窗口从**客户端的每一次尝试**起算；Postgres `oidc.go:773-778`：认领 UPDATE 的谓词
  `last_poll <= $4 - make_interval(secs => $3)` 不成立时 0 行更新，`last_poll` 不动——
  窗口从**上一次被放行的 poll** 起算。运行时证据（注入时钟）：t=0 放行、t=3 被节流、
  t=7.5 仍被节流（7.5 < 3+5，证明锚在 t=3 的尝试上；若锚在 t=0，t=7.5 应放行）。
  两个方向都「≥ interval」，都不违反 RFC 8628 字面；分叉的可见后果：每 3s 轮询的客户端
  在内存部署上被无限节流、在 PG 部署上每 5s 放行一次——同一个客户端、同一个问题，
  两个后端不同答案，这正是 P2-32 立项要消灭的类别（bf81b2a 只修了时钟，没修锚点）。
- 状态：**CONFIRMED**（内存运行时红探针 + PG SQL 源级前提探针）
- 影响：无可达安全后果（节流方向），影响跨引擎行为一致性与一致性测试。
- 探针：`poll_anchor_probe_test.go::TestThePollThrottleAnchorsTheSamePollInBothEngines`（红）、
  `::TestThePostgresPollClaimOnlyMovesLastPollWhenItAdmits`（绿，是前提的钉子）
- 修法建议：裁定一个语义（建议锚「上一次尝试」，内存现状，对滥用方更严），PG 的 UPDATE
  改为无条件写 last_poll（去掉谓词里的 last_poll 条件、改为 SELECT 判定后 UPDATE 或
  `SET last_poll = $4` + 独立判定），两边测试同形。

### 04-7 0022 一类的索引迁移在单个 goose 事务里非并发建四个索引：升级窗口对四张表是写冻结（HYPOTHESIS）

- 严重度：P3 低（HYPOTHESIS）
- 不变量：性能/资源
- 证据：goose v3.28.0 对未声明 `-- +goose NO TRANSACTION` 的迁移在**一个事务**里执行
  （migration_sql.go:30-67）。迁移 0022 含四条普通 `CREATE INDEX`（无 CONCURRENTLY）。
  Postgres 的 `CREATE INDEX` 取 SHARE 锁，与 ROW EXCLUSIVE（INSERT/UPDATE/DELETE）冲突，
  四张表的全部写被阻塞到整个迁移提交。触发面：rc.3→rc.4 这类**在役升级**——滚动更新时
  旧实例仍在写（迁移 advisory 锁只串行化迁移者之间，不保护旧实例的写）；
  oidc_auth_requests/oauth_access_tokens 的行数决定冻结时长。全新部署表为空，无影响。
  第五轮部署区已报过「迁移 >120s 撞 startupProbe」（新实例侧），本条是**旧实例写冻结**，
  机制不同。无 DB 无法测时长。
- 状态：**HYPOTHESIS**（差一个带数据的库 + `pg_locks` 观察；锁语义本身是文档化的 PG 行为）
- 影响：升级窗口内 oauth/oidc 令牌表的写停顿，时长随表规模线性；对小库无感。
- 探针：无（需真库；锁语义为读码结论）
- 修法建议：对这个量级可先记录在 migration-decision 文档（「索引迁移在役升级会短暂冻结
  相关表写，冻结≈建索引时长」）；若表会大，后续索引用 `CREATE INDEX CONCURRENTLY` +
  `-- +goose NO TRANSACTION`（0017-0022 全部同形，需要时一并裁定）。

---

## 回归验证（第五轮修复落地在本区域的四项）

| 修复 | 结论 |
|---|---|
| **P2-4/P2-5 撤销索引（b35f893，迁移 0022）** | 六张表补齐、谓词可 sargable ✓；但 **`oidc_devices` 漏网**（04-3），守卫的手写清单同样漏它 |
| **P2-31 排空预算（5cd1690，auditDrainTimeout=30s）** | 预算存在、`drain` 拒绝路径与日志成形 ✓；但**算术没闭环**——叠上 5s+30s 仍顶穿 45s grace（04-4），manifest 注释未跟上 |
| **bf81b2a 设备时钟（P2-32）** | 三处 SQL 时钟参数化 ✓、clock_test 设备三段 ✓、audit5 探针转绿 ✓；残留：消费语句不查过期（04-5，两个后端共有的既有缺口）与 slow_down 锚点分叉（04-6） |
| **5cd1690 审计批写（P2-1 等）** | `record`/`recordConsent` 不再吞错（slog.Error，log-and-proceed 方向已裁定）✓；enqueue 入队后补 stop 检查——读码确认关闭了「已接受永不回答」窗口，且 audit5 的 `TestAnEnqueueRacingCloseIsAlwaysAnswered` 等四条并发探针全绿 ✓；批写 SQL 形状（SendBatch 单往返、链头 FOR UPDATE、失败扇出）✓；排空预算见 04-4 |

另核过：第五轮后动过 SQL 的修复提交逐处参数化（636a074 的 `DeleteAuthRequest` 先读后删与
`clientIDOfRequest`、bf81b2a 的三处 `$n`、1076cbf 的 `RewrapIfUnchanged` CAS、c6c4602 的
`SendBatch`）——没有任何新的请求值进入 SQL 文本；audit5 的
`TestNoGoSourceBuildsSqlFromARequestValue` 当前也绿。

## 探过没破（攻击过、守住了）

1. **数据库错误下的撤销落穿（运行时）**：探针的池本身正确地报连接失败
   （`revocation_error_probe_test.go` 的 premise：ping 必须失败，否则测试自己喊停）——
   失败注入干净，红的是产品代码的分类，不是池。
2. **ctx 取消中途的事务不会把开着的事务漏进池**：pgx v5.11.0 `pgxpool/conn.go:19-41`——
   `Release()` 检查 `TxStatus() != 'I'` 即销毁连接（服务端回滚、释放锁，包括审计链头的
   FOR UPDATE）；`dbTx.Rollback` 的错误路径也 `conn.die()`（tx.go:221-231）。读码级确认，
   「ctx 取消 → 部分提交/锁悬挂/会话状态污染」三条路都封死。相关方法复核：`appendBatch`、
   `revokeInOneTx`、`AuthRequestByCode`、`CreateAccessAndRefreshTokens` 的 defer
   Rollback 全部无嵌套取连接，不存在「持连接等连接」的自锁形状。
3. **advisory lock 在 panic/ctx 取消下释放**：`postgres.go:348-354` 解锁用
   `context.WithoutCancel`，且 `conn.Close` 兜底（会话级锁随连接断开释放）；顺序（LIFO）
   是解锁先于 Close。与第五轮结论一致，此后未动。
4. **SQL 时钟全量清点（含 round-5 守卫没扫的 account.go）**：
   `clock_inventory_probe_test.go::TestEverySQLDatabaseClockUseIsReviewed`（绿）——
   全部 13 个适配器 .go 文件里 SQL `now()` 只有三处（oidc.go 的 COALESCE 展示回退、
   sessions.go 的相对区间、account.go TouchLogin 的只写时间戳），全部在已裁定清单上。
   这同时把 round-5 时钟探针的文件盲区（只扫 oidc/oauth/sessions 三个）补上了。
5. **撤销索引的六张已修表**：我的反推探针的对照组断言 0021/0022 的六张全部解析得到、
   判定通过——补索引这半边修对了（漏的那半边是 04-3）。
6. **迁移 0022 的 expand/contract**：纯索引增删，无数据迁移，Up/Down 对称，
   无「一版内既加列又依赖」的违例。
7. **readyz/连接池数学（P1-4/P0-3 的修复面）**：`readinessCache`（health.go:111-133）
   单飞 + 1s TTL 正确封住了「匿名打满池」的放大器（锁只包状态、探测在锁外、
   running 期间答缓存值）；durable 部署的 `max_in_flight` 已从池推导
   （`defaultMaxInFlightFor`：max(64, 8×16)=128，config.go:387-394），
   configmap 不再写 512；`poolConfig` 七个边界有测试钉着（pool_test.go 全绿）。
8. **审计 enqueue 的关停竞态（5cd1690 修的另一半）**：入队后的 stop 复查逻辑读码确认
   无窗口；audit5 的四条并发探针（`TestAnEnqueueRacingCloseIsAlwaysAnswered` 等）本轮
   亲跑全绿。
9. **`SetIntrospectionFromToken` / `SetUserinfoFromToken` 的错误方向**：任何数据库错误都
   收敛为 inactive / errNotAnAccessToken（不泄露原因的拒绝），fail-closed ✓。
10. **`GetDeviceAuthorizatonState` 的认领-单次使用**：DELETE…RETURNING 即认领、并发二取
    一 ✓（内存/PG 同形）；`RevokeTokens`/`RevokeGrant` 连带清设备码与未兑换码 ✓。
11. **池耗尽的失败方向**：`pool_exhaustion_test.go`（CI 权威）按 ctx deadline 快速失败、
    释放后恢复；`Sessions.FindCtx` 走请求 ctx 的设计仍然成立。
12. **`Tokens.RevokeTokens`/`PurgeLegacySubject`/`Sessions` 三方法无事务**：第五轮 PG-004
    已收录（低、幂等自愈），不重报；本轮确认它们没有在修复中被改坏。

## 未能到达（本轮环境的残余盲区）

1. **一切需要真 Postgres 的运行时语义**：planner 是否真的选中/弃用某索引（04-3、
   PG-009 仍未闭合）、`make_interval(secs => $3)` 的参数推断（CI 的
   `TestDevicePollingIsThrottled` 权威）、READ COMMITTED 下并发 DELETE 的实际交错、
   迁移建索引的真实锁时长（04-7）。CI 的 postgres:16 是权威验证位。
2. **04-4 的 SIGKILL 时序**：算术封闭（5+30+30>45 是常量事实），但没有真 pod/终止行为
   可复现「t=45 杀死 t=65 的预算」。
3. **04-1/04-2 的协议面端到端形状**：探针打到 store 层（连接失败注入），经 oidchttp 的
   完整 200 响应在无 DB 下不可达；机制链条已由库源码逐行钉死。
4. **04-5 的 PG 侧运行时**：认领 DELETE 的行为只有内存侧可运行；PG 半边是源级断言。
5. **`-migrate-down` 从 0022 出发的实际报错**（PG-002/ADR-0008 既定，未重开）。

## 探针清单（全部新建，未改任何被跟踪文件）

```
internal/zzprobe/audit6/z04pgstore/doc.go                      //go:build !audit6
internal/zzprobe/audit6/z04pgstore/helpers_test.go            //go:build audit6
internal/zzprobe/audit6/z04pgstore/revocation_error_probe_test.go   （红 ×3）
internal/zzprobe/audit6/z04pgstore/revoke_index_probe_test.go       （红 ×2）
internal/zzprobe/audit6/z04pgstore/drain_budget_probe_test.go      （红 ×2）
internal/zzprobe/audit6/z04pgstore/device_expiry_probe_test.go     （红 ×2）
internal/zzprobe/audit6/z04pgstore/poll_anchor_probe_test.go      （红 ×1 + 绿前提 ×1）
internal/zzprobe/audit6/z04pgstore/clock_inventory_probe_test.go   （绿 ×2，探过没破）
```

运行：`go test -tags audit6 -count=1 ./internal/zzprobe/audit6/z04pgstore/...`
（当前 10 红 3 绿；红即证据，绿如实报告）。`gofmt -l` 干净、`go vet ./...` 干净、
`go build ./...` 通过；默认套件（无标签）与 audit5 探针（pgstore 区）均未受影响、保持全绿。
