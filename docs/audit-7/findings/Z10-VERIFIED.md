# 区域 Z10：admin-audit-privacy — 第七轮**对抗性复核**报告（Z10-VERIFIED）

> 复核对象：`docs/audit-7/findings/Z10-admin-audit-privacy.md`（9 条 finding）。
> 立场：证伪优先。凡是我不能独立取得的证据，一律不接受「报告说探针会红」。
> 结论摘要：**9 条里 7 条的机制成立，但严重度/定位有 6 处需要改**：
> 1 条是第六轮 G-12 的重报（且「对修复的反驳」这个框定是错的——从来没有修复），
> 3 条是对既有修法的补充（合法但 надо按补充定位），
> 2 条严重度虚高，报告有 1 处证据陈述与代码不符，另发现 2 个报告漏掉的新洞。

## 范围与方法

**读了什么**：`docs/audit-7/BRIEF.md`；被复核报告全文；第五轮
`scratchpad/audit/findings/admin-audit-privacy.md`（AUD-1…AUD-12）；
`docs/security-audit-5.md` 的复核表；第六轮
`docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md`（逐行核对 G-12、G-17 原文）；
`AUDIT-ISSUES.md` 的 P2-22/P2-31 行；`docs/architecture.md` §4.16–§4.17（含 :636、:652、:659–662）、
`docs/admin.md` §4.2/§5（:101–125、:129–136）；被引用的全部代码行。

**跑了什么**（Windows 11，无 Docker / 无本地 Postgres）：

```sh
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z10adminauditprivacy/...   # 复现被复核者的红/绿
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z10verify/...              # 我自己的复核探针（10 个，全绿）
go vet -tags audit7 ./internal/zzprobe/audit7/z10verify/...                           # exit 0
go build ./...                                                                        # exit 0
go vet ./...                                                                          # exit 0
gofmt -l internal/zzprobe/audit7/z10verify                                            # 空
```

**复核探针目录（新增，未改被复核者的任何文件）**：`internal/zzprobe/audit7/z10verify/`
（`doc.go` 带 `//go:build !audit7`；其余全部 `//go:build audit7`）。全部**不需要数据库**：
它们直接读被测源码文本并断言报告声称的性质，所以「报告写错机制」会在这里变红，而不是被信任。

**方法说明（重要）**：被复核报告有 4 条 finding（Z10-1/2/8/9）的探针在本机 **SKIP**
（`TEST_DATABASE_URL` 未设）。对这类条目，我不满足于「源级读码」，而是：
① 用**独立探针**把「代码机制」重新推导一遍（正则抽取真实函数体 + 断言结构）；
② 用**阴性对照**证明我的检查能看见 bug（`TestZ10VerifySourceChecksCanFail` 喂入伪造源码）；
③ 只把需要真库才能定的那一步留作 HYPOTHESIS，并写清差什么。

**端口**：本区复核是纯静态探针 + 源级读码，没有起动真进程，因此未占用 18002/18052；
被复核者的探针全部在 `httptest` 随机端口上，不冲突。

---

## 一、逐条裁定

| 编号 | 报告声称 | 复核裁定 | 更正后严重度 | 一句话理由 |
|---|---|---|---|---|
| Z10-1 | 跨实例假名缓存使抹除失效 | CONFIRMED（机制）／新增量有限 | **P3** | 机制逐字属实；但这是 AUD-5 同根因的跨进程稳态形态，非新洞；暴露的只是「可关联性」 |
| Z10-2 | 链前伪造未签名行被 `Verify` 判 ok | DOWNGRADED | **P3** | 机制属实；但需要与「能删行/改行」同级的库写权限，且 0013 文档**明写**「迁移前的行按 legacy 计、不假装覆盖」，报告对文档的引用偏了 |
| Z10-3 | 关停栈 65s > grace 45s | **NOT-A-FINDING（重报 G-12）** | P2 | 第六轮 G-12 逐字收录同一栈、同一探针形状；且**不存在**报告所称的「G-12 修复」，其修复建议第 11 条从未实施 |
| Z10-4 | 无会话端口时 Kill Switch 沉默 | CONFIRMED | **P3**（维持） | 机制与不对称属实；`docs/admin.md:120` 已文档化内存模式清不掉会话，可达面仅此一种 |
| Z10-5 | 扫描失败丢弃已完成摘要 | CONFIRMED | **P3**（维持） | 属实且新；但报告的证据陈述有一处**与代码不符**（见下） |
| Z10-6 | `/verify` 与 `/head` 不留痕 | CONFIRMED（对 P2-22 的补充） | **P3** | 属实；第五轮 AUD-7 已把三个端点列为「同样没有审计调用」，但**修法只落了两条**，此条是补齐，合法 |
| Z10-7 | 读数接口可无写侧装配 | CONFIRMED | **P3** | 属实；组合根总是两侧都接，今天不咬人（报告自己也这么说） |
| Z10-8 | admin 行的 client_id 被假名化 | CONFIRMED | **P3** | 属实；client_id 非个人数据、假名确定且 `?subject=` 可查回，信息损失有界 |
| Z10-9 | `Verify` 不校验链头与末行 | DOWNGRADED | **P3** | 机制属实；但「链头被伪造」正是外部锚点存在的理由（`auditchain.go:333-336` 自己写着），比报告说的更弱 |

**总计：CONFIRMED 6（含 1 条「机制成立但增量有限」）／DOWNGRADED 2／NOT-A-FINDING 1。**
**没有一条是「技术机制完全错」**——报告对机制的理解总体是准的；问题集中在**重复、严重度与定位**。

---

## 二、每条的独立证据与理由

### Z10-1 跨实例假名缓存使抹除失效 → CONFIRMED，P2 下调 **P3**

**我独立验证了什么**（`pseudo_source_test.go::TestZ10VerifyPseudonymCacheIsHitBeforeTheDatabaseAndErasureIsProcessLocal`，**绿**）：
从 `internal/store/postgres/auditpseudo.go` 正则抽出 `loadKey` 的真实函数体（字符串/注释已抹空后做花括号平衡），断言
`l.cache[subject]` 的下标位置 < `return cached` < `l.pool.QueryRow(`——即**缓存命中先于唯一一次库查询返回**；
并断言 `Destroy` 体内**没有任何**跨进程原语（`tombstone`/`destroyed`/`notify`/`publish`/`broadcast`/`subscribe`），
整个包只有一处 `delete(l.cache`（= 只驱逐自己的 map），缓存字段 `cache map[string][]byte` 是 per-logger 字段。
报告引用的那句自证注释（`auditpseudo.go:181-182`「a warm cache would keep pseudonymising the subject after the
row that justifies it is gone」）今天仍存在。

**为什么仍下调**：
1. **它不是新洞。** 第五轮 AUD-5 的编号与结论（`scratchpad/audit/findings/admin-audit-privacy.md:188-195`）
   **已经**逐行写了 `loadKey:69-75` 命中不查库、`auditread.go:46-64` 读侧同样走 `loadKey` 且「不校验库行还在不在」。
   报告把增量定位在「复核只覆盖单进程」，这说法**部分是错的**：AUD-5 原文的交错描述里就包含「读侧 `?subject=`
   会解析成功并返回被抹除账号的历史」。Z10-1 真正新增的只是「不需要竞态、是稳态」，这是**同一机制的一个更差形态**，
   不是新机制。按简报 §4.3（前两轮全部发现不许重报），它只能作为对 AUD-5 复核结论的**补充**，而报告也确实这么写了——
   但严重度不该再挂 P2。
2. **影响有界**：泄露的是「可关联性」，前提是攻击者**已经拿到某个 `usr_…`**；假名本身仍是不可逆的 16 字节 base64。
   没有明文泄露，没有跨账号读取。
3. **文档与实现的矛盾是真的，而且应当修文档**：`docs/architecture.md:661-662` 那句「跨进程缓存不破坏擦除…
   与缓存无关」在 `replicas: 2`（`deploy/k8s/base/deployment.yaml:8`）下是错的。这条的**净价值是修正文档**。

### Z10-2 链前伪造未签名行 → DOWNGRADED **P3**

**机制：成立。** 我逐行确认：
- `auditchain.go:270-282`：`row_hash == nil` 且 `!started` ⇒ `Legacy++` + `continue`，**不校验任何东西**；`started` 只在首个非空 `row_hash` 处置位。循环里**没有** `id` 单调性、没有「首个链上行的 id 必须等于某上限」的检查。
- `migrations/0007_audit.sql:10` 是 `bigint GENERATED ALWAYS AS IDENTITY`，Postgres 会拒绝普通显式取值，但
  `OVERRIDING SYSTEM VALUE` 正是为「显式给 GENERATED ALWAYS 列赋值」设计的合法子句；探针的兜底（`INSERT` 后
  `UPDATE audit_events SET id = 0`）在 Postgres 里同样合法（UPDATE 不受 identity 限制）。
- `migrations/0013_audit_chain.sql:26-28` 确实**没有**任何「legacy 行的边界」记录。

**为什么下调**：
1. **报告对文档的引用偏了。** 报告说 0013 的威胁清单「只列了编辑、链中删除、重排、整链重写、尾部删除——插入不在清单里」，
   这对 0013 的注释（`:15-28`）是对的；但项目**在 `docs/architecture.md:636` 明确讨论了这一形状**并给出了设计取舍：
   「迁移前的行 `row_hash IS NULL`，被验证器计为 `legacy` 而**不是**假装覆盖；链从迁移后的第一行开始。」
   即：**「NULL 哈希行 = 迁移前行」这件事是被显式接受的定义**。报告把它写成「没有任何东西记录哪些是迁移前的行」，
   忽略了同一段话里已经承认了这个定义本身不设上限。这是「文档化取舍的**不完整**」，不是「没人想到」。
2. **前提不低**：攻击者需要与「编辑/删除链中行」**同级**的库写权限（而编辑与删除都是被检测的）。他能做的只是
   **增补**：植入一条 NULL 哈希行**不能**被重签（签名密钥在环境里），它的 `row_hash` 永远不会被链覆盖，所以
   它不会破坏后续行的验证；但它会出现在 `GET /v1/admin/audit` 的返回里，并被 `Verify` 计入 `legacy`。
   也就是把「日志的完整性保证」从「改不了」降级为「改不了但**能加**」——对审计取证而言这是**实质**缺陷，但不是鉴权绕过。
3. 因此：P2 → P3，并把「这是有意的 legacy 定义的不完整面」写清；修法（给 `audit_chain` 加
   `legacy_ceiling_id` 之类的有界集合）我同意报告的写法。

**状态**：HYPOTHESIS（差真 Postgres：`OVERRIDING SYSTEM VALUE` 的实际接受面与 NULL 行在 `legacy` 计数里的出现）。

### Z10-3 关停栈 65s > grace 45s → **NOT-A-FINDING**（重报 G-12）

**我独立复现了算术**（`killswitch_source_test.go::TestZ10VerifyShutdownStackStillExceedsThePodGracePeriod`，**绿**，
并打印 `5 + 30 + 30 = 65 vs grace 45`）：从 `cmd/re0auth/main.go` 抽 `endpointRemovalWait=5s`、`shutdownTimeout=30s`，
从 `internal/store/postgres/auditbatch.go` 抽 `auditDrainTimeout=30s`，从 manifest 抽
`terminationGracePeriodSeconds: 45`；manifest 注释仍写 `35s`（`deployment.yaml:22`），CHANGELOG 仍写
`terminationGracePeriodSeconds ≥ 35s`（`CHANGELOG.md:109`）。我还核对了调用顺序（`main.go:802-851` 先
`time.Sleep(5s)` 再 `Shutdown(drainCtx,30s)`；`store.close()` 是 `:377` 的 defer，最后执行），
与 `auditbatch.go:54/177-198` 的 `Close→drain`。

**但这就是第六轮 G-12 原文**。第六轮汇总第 119 行的表格单元逐字写着：
「**k8s 关闭预算与 grace 不自洽**：`5s + 30s + 30s = 65s > terminationGracePeriodSeconds: 45` ⇒ SIGKILL 发生在
审计排空预算到期之前…**我按调用链逐步核实过**：SIGTERM → beginDrain(`main.go:820`) → Sleep(5s)(`:829`) →
Shutdown(30s)(`:837-841`) → serveUntilSignal 返回(`:724`) → deferred `store.close()`(`:377`) → `auditBatcher.Close`
排空(`auditbatch.go:54` 的 `auditDrainTimeout = 30s`)。**而 `deployment.yaml:21-25` 的注释只算到 HTTP 那一段
（写「35s total」）**」，探针两项：`z04/drain_budget_probe_test.go::TestTheShutdownStackFitsThePodGrace`、
`::TestTheManifestCommentCountsTheWholeStack`，状态 **CONFIRMED**。**没有任何一句是新的。**

**报告的两处框定错误**（这是我这条裁定最实质的部分）：
1. 报告称 Z10-3 是「**对 G-12 修复的反驳**」，并把 `commit 5cd1690` 说成「G-12 的修复」。
   `git log -S auditDrainTimeout` 显示该常量是 **`5cd1690` 引入的**（2026-09-28 22:25），而第六轮报告在
   **其后**写成，且 G-12 的描述里就引用了 `auditDrainTimeout = 30s`。第六轮的修复建议第 11 条
   （`auditDrainTimeout` 改 10s 或 grace 提到 ≥70s）**至今未实施**：常量仍是 30s，grace 仍是 45。
   所以「修复叠加了预算但总量没变」是不成立的——**没有修复，只有一条第六轮已记录的未修项**。
2. 报告结论中「探针实跑红」有价值（它给 G-12 多一个可执行的守卫），但按简报 §4.3/§5，
   **G-12 已收录 ⇒ 不得作为本轮新发现重报**。

**给主代理的处置建议**：不采信为 Z10-3 新发现；把「G-12 仍未修 + manifest/CHANGELOG 的 35s 文案仍在说谎」
作为**已知未修项**转交 G-12 的归属方。我有独立证据（上面两个探针）。

### Z10-4 无会话端口时 Kill Switch 对 sessions 半边沉默 → CONFIRMED，维持 **P3**

**独立证据**（`killswitch_source_test.go::TestZ10VerifyKillSwitchReportHasNoSessionUnavailableMarker`，**绿**）：
- `internal/admin/admin.go` 全文件在 `admin` 包内**没有** `SessionsUnavailable`、也**没有** `sessions_unavailable` 字符串；
  `Report` 有 `BindingsUnavailable bool`。
- `KillSwitch` 体里会话半边是 `s.sessions != nil && …`，**没有 else 分支**；绑定半边有
  `else if … { rep.BindingsUnavailable = true }`（`:395-397`）——不对称存在于**同一个函数**里。
- `killDetail`（原始文本）含 `"sessions_revoked"`，不含 `sessions_unavailable`。
- 被复核者的探针控制组我在实跑输出里看到成立（先跑 wired=3 的对照通过，再报 `sessions_revoked=0` + `bindings_unavailable=true` 的 FAIL）。

**为什么维持 P3 而不是更高**：组合根只在**内存模式**传 nil（`main.go:886` `sessions: nil`，
`main.go:935` `sessionRevoker: sessions`），而 `docs/admin.md:120` 已就此事写明「没有持久会话的部署（内存模式）
一条会话都清不掉」——即运维**在文档里**被告知过。缺的确实是那个机器可读的 `"不知道"` 标记，
这是 AUD-9 修法的对应半边，属于一致性/加固，不是新的可达缺陷。

### Z10-5 扫描失败丢弃已完成摘要 → CONFIRMED，维持 **P3**，但**证据陈述有一处错**

**独立证据**（`killswitch_source_test.go::TestZ10VerifyKillSwitchDropsThePartialSummaryInTheHTTPLayer`，**绿**）：
服务端 `KillSwitch` 至少 3 条 `return rep, err` 路径（含 `ErrInvalidTarget`、`ErrBindingsUnavailable`），
`rep.TokensRevoked = removed` 与 `rep.SessionsRevoked = n` 都在 err 之前赋值；HTTP 端
`admin_routes.go:275` 收到 `report, err`，`case err != nil:` 到 `writeProblem` 之间**不出现 `report`**，
而 `default:` 分支 `writeJSON(w, http.StatusOK, report)`。`docs/admin.md:108-109` 的原文承诺
「枚举失败时**返回已完成的摘要与错误**」确实还在。**机制成立、不是重报、P3 合理。**

**但是**：报告 Z10-5 的证据里写「（`tokens_revoked=7`/`sessions_revoked=2` 已从审计行核实服务侧确有这两个数）」
以及探针文案「the counts it already cut (tokens_revoked=7, sessions_revoked=2, **recorded in the audit row**)」
——**审计行里没有 `sessions_revoked`**。见下面的新洞 Z10V-2 与我的探针
`TestZ10VerifyKillSwitchAuditDetailCarriesNoSessionsCount`（绿）。被复核者自己的探针也只断言了
`detail["tokens_revoked"]=="7"`（`killswitch_report_test.go:112-115`），没有断言 `sessions_revoked`。
结论不变（响应确实丢了摘要），但**这条证据陈述必须改**，否则它以讹传讹。

### Z10-6 `/verify` 与 `/head` 不留痕 → CONFIRMED（对 P2-22 的补充），**P3**

**独立证据**（`reads_source_test.go::TestZ10VerifyOnlyThePagedAuditReadIsRecorded`，**绿**）：
`handleAdminAudit` 体内含 `"admin.audit.read"`；`handleAdminAuditVerify`、`handleAdminAuditHead`
体内**都不含** `recordAudit`；且 verify 体内含 `s.auditReader.Verify(`（所以「最宽的读」这一半成立）。
对照：`export_routes.go` 含 `"account.export"` + `s.recordAudit(`（P2-22 的另一半在）。
被复核者的红探针我也实跑复现（`GET /v1/admin/audit` 使事件 2→3，verify 后仍 2，head 后仍 2）。

**为什么这不是重报**：第五轮 AUD-7 确实**提到过** verify/head（`.../admin-audit-privacy.md:273-274` 的代码行
`:44`/`:137`/`:167` 全是「无审计调用」），但 **P2-22 的修法只落了 export 与分页读两条**（`audit_routes.go:121-139`）。
报告把它写成「对 P2-22 修复的补充」是**正确的框定**，我认可。

### Z10-7 读数接口可无写侧装配 → CONFIRMED，**P3**

**独立证据**（`reads_source_test.go::TestZ10VerifyTheAuditReadGuardIsNotRequiredToHaveASink`，**绿**）：
`server.go` 含两条 `Config.Audit requires …` 守卫，**不含** `Config.Audit requires Config.AuditLog`；
`recordAudit` 体内含 `s.auditLog == nil` 后 `return`；组合根含 `apiConfig.Audit =` 与 `AuditLog:`（两侧都接）。
被复核者的 `TestZ10TheAuditReadRecordsAreAcceptedWithNoSinkToWriteThem` 我实跑复现为**红**
（`httpapi.New` 返回 nil error）。**「库层 fail-open、当下不咬人」的定位准确，P3 合理。**

### Z10-8 admin 行的 client_id 被假名化 → CONFIRMED，**P3**

**独立证据**（两个探针，均**绿**）：
- `TestZ10VerifyAdminClientActionsStoreTheClientIDAsTheSubject`：从 `internal/admin/admin.go` 抽出 5 个
  `s.record(ctx, actor, "admin.client.<verb>", <subject>, …)` 调用点，subject 实参全部是 `clientID`；
  并且**没有任何** `admin.client.*` 的 Detail 字面量含 `client_id`（正向对照：`store/postgres/oidc.go` 里确实有
  `client_id` 这个先例）。
- `TestZ10VerifyAdminClientActionsArePseudonymisedByTheDurableSink`：`Record` 体内调
  `l.pseudonymize(ctx, e.Subject)`，且不区分 `cli_`/`ClientID`；`pseudonymize` 只对空 subject 短路，
  随后走 `l.subjectKey`。⇒ 「任何非空 subject 都被假名化，管理面也没有补偿字段」成立。

**维持 P3 的理由**：client_id 不是个人数据，且假名是**确定性**的（`pseudonymOf(key, subject)`），
运维可以对候选 client_id 逐个 `?subject=` 反查（报告自己也这么说）。这是**可用性/合规可读性**问题，
不是隐私泄露；也没有「密钥永不销毁」带来的额外风险（那反而意味着历史一直可查，是可用性的一面）。
与 G-17（PG 设备事件缺 client_id）同族不同面，标注正确。

### Z10-9 `Verify` 不校验链头与末行 → DOWNGRADED **P3**

**机制成立**：`auditchain.go:238-241` 读 `head`；遍历中只比较相邻行（`:292-297`），结束后唯一的 head 检查是
`:318-328` 的 `if v.Chained == 0 && len(head) != 0`——`Chained>0` 时它短路，`prev` 与 `head` 从不比较。
所以 `UPDATE audit_chain SET head_hash = <任意值>` 之后 `Verify` 返回 `ok=true`。

**为什么下调**：链头的**外部锚点**正是为「库内不可判的链状态」存在的（`auditchain.go:333-336` 与
`docs/architecture.md` §4.16 都这么写），而 `auditVerifyLoop` 与 `anchorLoop`（`main.go:409-418`）是两条独立机制。
把一个「只有能改库的人才能伪造、而且伪造后立刻就与真实行哈希不一致」的值说成完整性检查漏判，
比把它说成「多一道廉价的纵深防御没做」要重。修法建议（遍历结束后 `bytes.Equal(prev, head)`）我同意，
且成本极低——但它不改变「这条不需要外部锚点」的表述应当弱化。

---

## 三、本轮复核**新发现**（报告漏掉、我有独立证据）

### Z10V-1 【P3 · 合规/审计完整性】Kill Switch 的**失败路径审计行漏记 `sessions_revoked`**——报告恰好把这条写成反的

- 不变量：fail-loud「绝不把部分清扫说成完整」（`docs/admin.md:102-104` 对 bindings 的要求；`:108-109` 的摘要承诺）。
- 证据（`killswitch_source_test.go::TestZ10VerifyKillSwitchAuditDetailCarriesNoSessionsCount`，**绿**）：
  从 `internal/admin/admin.go` 抽出 3 个带**内联 Detail 字面量**的 `admin.kill_switch` 记录点
  （`:362-364`、`:389-391`、`:407-409`），三者都是 `map[string]string{"tokens_revoked": …}`，**都没有** `sessions_revoked`；
  而成功路径的 `killDetail`（`:462-480`，原始文本核对）**有** `"sessions_revoked"`。
  代码路径：`:351-368` 先清会话并写 `rep.SessionsRevoked = n`；随后绑定半边失败时走 `:388-393` 的记录，
  此时**会话已经被切掉**，但记录里没有这个数。
- 影响：一次「已切 tokens=7/sessions=2、绑定源不可达」的事故，审计行只说 tokens；事后复盘无法从**持久记录**里
  知道会话是否被清。响应侧同样丢（= Z10-5），但这两处是独立的证据面：**报告声称审计行里有 `sessions_revoked`，
  实际没有**。
- 修法：把 `"sessions_revoked": strconv.FormatInt(rep.SessionsRevoked, 10)` 加进三条失败路径的 Detail
  （与 `killDetail` 同款），或统一让失败路径也走 `killDetail`。
- 与被复核报告的关系：**更正 Z10-5 的证据陈述**，并作为独立记录缺口单列。

### Z10V-2 【P3 · 可用性】内部监听器的排空**没有自己的预算**：它排在公网监听器之后共享同一个 30s `drainCtx`

- 证据（源级，逐行）：
  - `cmd/re0auth/main.go:837` 在建 `endpoints` 循环**之前**创建 `drainCtx, cancel := context.WithTimeout(…, timeout)`
    （`timeout` = `shutdownTimeout` = 30s），然后 `:840-849` 用**同一个** ctx 顺序 `Shutdown` 每个 endpoint；
    第一个耗尽预算时后续 `Shutdown` 立即返回 `DeadlineExceeded` → `slog.Error("graceful shutdown did not finish;
    closing connections")` + `ep.server.Close()`。
  - `:709-721`：`cfg.InternalAddr != ""` 时**第二个** endpoint（`metrics.InternalHandler()`，`/metrics`、`/debug/pprof/`）
    追加在后。
  - 因此「35s total」的注释与「两个监听器各 30s」都不是事实：**总量 30s（+ 5s），第二个监听器在第一个吃满时得 0s**。
- 影响：抓取 `/metrics` 的 Prometheus 或被拉的 pprof 在滚动更新那一刻拿到**截断/无响应**（有 `slog.Error`，不算静默）；
  `/metrics` 是 `docs/observability.md` 的告警输入，截断的 scrape 会被计为 scrape 失败。有界、非阻断。
- 为什么报告漏了：Z10-3 只按「5+30+30」算单监听器的栈，没看 `Shutdown` 的**循环**与共享 ctx。
- 修法（裁定在项目）：给每个 endpoint 各自的 deadline（`timeout/len(endpoints)`），或把内部监听器排除在
  排空之外（它没有在途业务请求，直接 `Close` 并记录），或把 `shutdownTimeout` 的语义改成「所有监听器共享的总预算」
  并写进 manifest 注释。

（订正我自己的一处初判：`cmd/re0auth/main_test.go:984-1029` 的 `TestServeUntilSignalDrainsEveryEndpoint`
确实传了**两个** endpoint——它证明 `Shutdown` 会 reach 每个监听器，但它用 `context.Background()` + 5s 预算
且两个 handler 都立刻返回，**没有**覆盖「第一个监听器吃满预算、第二个得 0s」的情形。所以缺的是
**共享预算耗尽**这一条的覆盖，不是「多监听器从没被测过」。）

---

## 四、探过但没破（复核侧的守卫）

1. **被复核者的正对照是真的**（不是空转）：
   - `audit_read_test.go` 的控制组在实跑输出里确实成立（分页读 2→3，verify 2→2，head 2→2），
     且最后有 `t.Fatalf` 级联检查 `admin.audit.read` 事件「至少存在一条」，探针的前提被钉住。
   - `killswitch_report_test.go` 的第二个探针确实断言了三个端口都被调用、审计行 `outcome=error`、
     `detail["tokens_revoked"]=="7"`——所以「服务侧确实有这两个数」这个前提**部分**被证明了
     （tokens 是，sessions 不是：见 Z10V-1）。
   - `postgres_chain_test.go` 两个 DB 探针都在断言前先做**控制组**（`Chained==2` / `Head` 非空），
     并且两条「探针自身失效」路径都会 `Fatal`（`v.Legacy == 0`、`Head` 与植入值不等）。
   - `postgres_cache_test.go` 的控制组是「B 的第一次 Query 必须返回 1 行」，否则 Fatal——
     这正好排除了「过滤条件根本没解析」这种假红。
2. **我的源级检查可失败**：`reads_source_test.go::TestZ10VerifySourceChecksCanFail`（**绿**）把 4 类伪造源码
   （缓存后于查询的 `loadKey`、带跨进程原语的 `Destroy`、带 `client_id` 的管理面 Detail、
   带 `sessions_revoked` 的失败 Detail）喂给同一批判定逻辑，确认它们**都**被识别。没有这一步，
   我上面所有「绿」都可能只是「检查看不见 bug」。
3. **`gofmt`/`vet`/`build` 全绿**，我的探针不在默认套件里（`doc.go` 是 `//go:build !audit7`）。

## 五、未能到达（残余盲区）

1. **真 Postgres 语义**（Z10-1/2/8/9 的运行时确认）：本机无 Docker、无本地 Postgres。
   被复核者的 4 个 DB 探针与我的复核都在这一层止步。要定论需要
   `TEST_DATABASE_URL=… go test -tags audit7 -count=1 -p 1 ./internal/zzprobe/audit7/z10adminprivacy/...`
   （必须**单独跑这个包**：它会 `TRUNCATE audit_events, audit_chain, audit_subject_keys`）。
   我在 Z10-2 里对 Postgres 语义（`OVERRIDING SYSTEM VALUE`、`UPDATE id=0`）只给了语言/文档级论证，
   **没有执行**——这一条我标 HYPOTHESIS 是认真的。
2. **多进程真实验**（Z10-1）：两个 `postgres.DB` 句柄建模两个副本是合理的，但「两个真进程 + 一个库 + 一次抹除」
   本机做不到。
3. **k8s SIGKILL 与 grace 的真实行为**（Z10-3）：只有算术与调用顺序。
4. **SvelteKit 管理前端**：本轮未审（被复核报告也已列为范围外）。
5. **我未复核 `docs/audit-6/findings/03/04/05` 的第六轮区报告原文**（只核对了汇总表的 G-12/G-17 行），
   因此「G-12 是否已在区 04 被更详细地写过」我没排除；但汇总表已足以判定重报。

## 六、判断（不是 finding）

1. **`docs/architecture.md:661-662` 应当直接改写**：把那句「跨进程缓存不破坏擦除…与缓存无关」改成实话
   （「进程内缓存命中不会再查密钥行；多副本下，另一个副本的暖缓存会让被抹除账号的历史在**该副本**上继续可关联，
   直到该缓存被整体丢弃」）。这是本轮成本最低、收益最确定的一处修正。
2. **`docs/architecture.md:636` 的 legacy 定义应当补一句边界**：它已经诚实说了「按 legacy 计、不假装覆盖」，
   差的是「没有任何东西界定 legacy 的上界，因此在链开始之前插入的行也会被计为 legacy」。
3. **`auditDrainTimeout` 的语义（Z10-3/G-12）**：建议采纳第六轮第 11 条的建议之一，并把
   `deployment.yaml:22` 的「35s」与 `CHANGELOG.md:109` 一起改掉——**文档说谎**这一半今天仍然成立，
   这也是 G-12 至今未修最容易被反复重报的原因。
4. **Z10-5 的修法取舍**：把 `report` 塞进 500 响应体会改变错误契约（problem+json 的形状），
   我更倾向「失败路径也写一条 `admin.kill_switch` + `outcome=error` 的记录，Detail 里带
   `tokens_revoked`/`sessions_revoked`/`bindings_error`」——持久记录才是事故复盘的载体，
   响应体的形状不该为一个计数破例。

---

**复核探针目录**：`internal/zzprobe/audit7/z10verify/`（10 个测试函数，全绿；阴性对照在同一包内）
**未修改任何被跟踪文件**（`git status` 仅出现新增的 `internal/zzprobe/audit7/z10verify/`）。
