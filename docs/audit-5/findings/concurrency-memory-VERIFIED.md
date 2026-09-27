# 并发 / 竞态 / 内存存储（CM 区域）审计报告 —— 复核（VERIFIED）

> 复核对象：`docs/audit-5/findings/concurrency-memory.md`（CM-1 … CM-6 + 16 条正面结论）
> 复核者立场：**证伪**。每条都先重跑、再自己算一遍、最后试着构造反例。
> 本轮**没有修改任何被跟踪文件**；新探针全部是新文件：
> `internal/zzprobe/verifycm/{cm12,cm4_growth,cm5_ratelimit,helpers}_test.go`、
> `internal/store/postgres/zzverify_cm_batch_test.go`（后者破了「探针只放新包」的约定，理由见 §3 末）。

---

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|---|---|---|---|---|
| CM-1 | 高 | 低（可维护性/一致性） | **部分成立（机制 CONFIRMED，影响叙述推翻）** | 锁确实跨审计写（重跑证实，临界区多 463ns），但这段代码只在**没有 DATABASE_URL** 时运行，而那时审计 sink 是 `audit.MemoryLogger` 环形缓冲；报告描述的「持久化部署 ⇒ 内存锁横跨 4 次 DB 往返 + 链头行锁」在同一部署里**不可能同时成立** |
| CM-2 | 低 | 低（维持，影响≈0） | **成立但无可观测影响** | 三处确实丢 ctx（重跑：三条断言全失败）；但在唯一会跑这三条路径的部署里 sink 忽略 ctx——实测「已取消的 ctx」既不报错也不延迟，只有换 wiring 才会有影响 |
| CM-3 | 中 | 低（潜在缺陷） | **(a)(b) 成立；(c) 我造出了真 DATA RACE，但生产可达性被推翻** | 我用 `-race` 拿到 `oidcstore.go:222`（读）vs `memory/oidc.go:940`（锁内写）的竞争报告；但生产唯一的持有者只取 `GetID()` 后立刻丢指针（zitadel `auth_request.go:145-150`、`server_legacy.go:165-169`），竞争需要「持有者」存在 |
| CM-4 | 高 | 低（内存模式；若强当生产则中） | **部分成立（事实成立，「无界」与严重度不成立）** | 无人口上限是事实，但增长**有界**：峰值 = 到达率 × `requestTTL`(30min)，我实测 TTL 过后 5000/5000 被 janitor 清空；单地址峰值 ~30 MiB（不 OOM），且内存模式是文档写明的开发/联调形态（k8s 清单实际跑 Postgres） |
| CM-5 | 中 | 低（公平性/有效性，非安全） | **机制成立，解释有两处不成立** | 淘汰确实重置别人预算（重跑 FAIL 如报告所述）；但 ① 注释没写反（`its caller` 就是被淘汰桶的持有者），② 删桶只会**放宽**、永不误拦，且换 key 绕过限流根本不需要淘汰（实测 1000 新 key 1000/1000 放行） |
| CM-6 | 提示 | 提示（状态改为 CONFIRMED） | **机制 CONFIRMED（我复现了 3/6 次运行，≈1/4.5 万调用），「永久」后果在生产不可达** | 6 次运行共 ≈32 万次调用竞速 Close，命中 7 个「已接受永不回答」的调用者；报告的 200 次尝试（50µs 偏移）根本没打到它描述的那个窗口——但它也证明了满队列上的调用者是安全的（700/700 被回答） |

**正面结论抽查**（§4）：抽查 6 条，5 条成立、1 条措辞有小出入、**没有发现假正面**。

---

## 2. 降级 / 推翻的理由（每条给代码引文）

### 2.1 CM-1：机制真，影响叙述是被部署形态推翻的（高 → 低）

**(a) 锁确实被持有——我重跑并量化了。**
`internal/store/memory/oidc.go:978-998`：

```go
func (s *OIDCStore) ApproveDevice(_ context.Context, userCode, subject string, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	...
	s.devices[h] = d
	s.record(context.Background(), "oidc.device.approve", subject, d.clientID, audit.OutcomeOK)  // :996 仍在锁内
	return nil
}
```
`:1004-1019` 的 `DenyDevice` 同形（`s.record` 在 :1017）。我重跑了报告的四个探针（含对照组），输出与报告一致
（`TestControlTokenMintAuditsOutsideTheStoreLock` PASS、两个 holds-the-lock PASS、`TestAnAuditSinkThatReadsTheStoreDeadlocksUnderTheLock` PASS）。
我另外用 grep 逐行核对了「这两个方法是唯一例外」：全文件 8 处 `s.record(` 调用（:436、:514、:576、:595、:607、:996、:1017、:1136），
只有 :996 与 :1017 在锁内，其余六个都在 `s.mu.Unlock()` 之后。**这一半我完全确认。**

**(b) 决定性的反证：这两种部署形态互斥，报告把它们缝在了一起。**
`cmd/re0auth/main.go:783-863` 的 `openStorage`：

```go
if cfg.DatabaseURL == "" {
	store = storage{ ... audit: audit.NewMemoryLogger(), ... durable: false, ... }   // :793
	return store, nil
}
db, err := postgres.Open(...)                                                       // :815
auditLogger, err := db.Audit(cfg.AuditKey)                                          // :826
return storage{ db: db, ... audit: auditLogger, ... durable: true, ... }            // :833-862
```
`main.go:347 logger := store.audit`，`main.go:1170-1198`：

```go
if store.db != nil {
	oidcStore, err = store.db.OIDC(store.clients, postgres.OIDCOptions{ ... Audit: logger, ... })  // :1171
} else {
	mem, err := memory.NewOIDCStore(memory.OIDCOptions{ ... Audit: logger, ... })                   // :1179
	oidcStore = mem; janitor = mem
}
```
于是：
- 「OP store 是内存实现」⇔ `store.db == nil` ⇔ `store.audit` 是 `audit.MemoryLogger`（环形缓冲，`audit/audit.go:144-158`，一次 `memcpy`，无 I/O）；
- 「审计 sink 是 `postgres.AuditLogger`」⇔ `store.db != nil` ⇔ OP store 是 `postgres.OIDCStore`，**`memory.OIDCStore` 根本不会被构造**。
- 全仓库非测试代码里 `memory.NewOIDCStore` **只有这一个调用点**（`main.go:1179`，在 `else` 分支内）；装运的 k8s 清单也确实是 Postgres（`deploy/k8s/base/configmap.yaml:27-29` `driver = "postgres"` + `deployment.yaml:44-56` 注入 `DATABASE_URL`/`RE0AUTH_AUDIT_KEY`）。

所以 CM-1「在**持久化部署**里……内存 OP store 的唯一锁被横跨 1~4 次数据库往返 + 一个全局行锁」这一句是**类别错误**：
在持久化部署里这把锁不存在于该路径上。报告 CM-1 的全部「门槛很低」论证（登录用户反复批准设备授权 → 全进程 OP 操作排队）建立在同一个错误前提上。

**(c) 量化：即使按报告最悲观的方式读，临界区也只有 463 纳秒。**
新探针 `TestCM1TheShippedSinkMakesTheCriticalSectionNanoseconds`（`internal/zzprobe/verifycm/cm12_test.go`），
同一操作 20,000 次取均值，唯一的变量是「有没有 sink」：

```
ApproveDevice per call: with audit.MemoryLogger = 810ns, with no sink = 347ns, delta = 463ns
（复跑：578ns vs 401ns，delta = 177ns —— 量级在数百纳秒）
```

即「锁内审计」在这套代码实际运行的部署里把临界区从 ~350-400ns 拉到 ~600-800ns。512（内存模式 `max_in_flight`）个请求全挤在这把锁后面，
排队代价也在微秒量级——不构成报告所说的可用性缺陷。

**(d) 「回调读 store ⇒ 死锁」是探针制造出来的。**
`guardAudit`（`store_lock_test.go:82-100`）在 `Record` 里回调 `store.Counts()`；报告自己也承认「today's durable sink does not call back into the store」。
两个真实 sink 都不依赖 store：`audit.MemoryLogger.Record`（`audit/audit.go:144-158`）与
`postgres.AuditLogger.Record`（`internal/store/postgres/audit.go:55-86`，只做 `pseudonymize` + `batch.enqueue`）。
所以这是**机制演示**，不是影响。报告引 `main.go:596-601` 的 lifecycle 注释来给这条撑腰也不贴切——那段注释讲的是
「抹除不能依赖它正在解耦的那个日志」的**循环依赖**，与 store 锁的锁序无关。

**结论**：机制 CONFIRMED，严重度**高 → 低**。修法（把 `s.record` 挪到 `Unlock` 之后，照抄 `CreateAccessToken`）我同意，理由是**内部一致性**和消除潜在锁序风险，而不是当前的可用性。

### 2.2 CM-2：成立，但在能跑的部署里可观测影响为零（维持低）

`oidc.go:421`、`:978`、`:1004` 三个方法签名收 `ctx` 却传 `context.Background()`（`:436`、`:996`、`:1017`）；
对照 `CreateAccessAndRefreshTokens`（`:514`）与 `RevokeToken`（`:576`）确实转发调用方 ctx。重跑输出三条断言全失败，与报告一致。

我按 VERIFY-BRIEF 问的「可观测行为」问题做了实验（`TestCM2ACancelledRequestContextChangesNothingWithTheShippedSink`）：
用一个**已经取消**的 ctx 调 `CreateAccessToken`，返回 `<5ms`、`err=nil`——因为 `audit.MemoryLogger.Record` 根本不看 ctx。
也就是说在唯一会跑这段代码的部署里，「丢 ctx」既不能让请求多等，也不能让审计写变「停不下来」（它本来就在纳秒级完成）。

**什么情况下它会变重要**：把内存 OP store 与一个**真正的**持久化 sink 配上（例如将来允许「无 DB 但审计写外部 SIEM/文件」）。
那时 `CreateAccessToken` 的热路径会在客户端断开后继续做不可取消的 I/O；`auditbatch` 的 5s 事务超时与池的 `statement_timeout`（默认 30s，`postgres.go:128`）只能兜底最坏情况。
报告这个「什么情况下才重要」的问题没有正面回答，我补上了。**严重度维持低，但我认为它更接近提示（可维护性）**。

### 2.3 CM-3：机制 CONFIRMED（含真 DATA RACE），生产可达性被推翻（中 → 低）

**(a) 确认并补了下游后果。** `CreateAuthRequest` 直接 `return a`（`oidc.go:353-356`），`AuthRequestByID` 返回 `cloneAuthRequest(a)`（`:367`、`:393-397`）。
我的探针 `TestCM3AWriteThroughTheReturnedValueReachesTheMintedGrant` 不止复现「store 里的记录被改」，而是走到了**下游**：

```
a write through CreateAuthRequest's return value reached the redeemed grant: [account.id phigros.score.read]
（对照：AuthRequestByID 拿到的副本改写后，store 仍是 [account.id]）
```
即：同意页只批准了 `account.id`，但持有创建时那个指针的调用方追加一个 scope，**授权码兑换拿到的就是被追加后的 scope 集**。这比报告写的更有说服力（报告止于「stored scopes changed」）。

**(b) 逐字段核对了 `TokenRequestByRefreshToken`：`oidc.go:526-529` 复制 `Scopes`，`AMR: r.amr`、`Audience: r.audience`、`AuthTime: r.authTime` 是共享**——报告引文准确。补充一条报告没说的：`authTime` 在写入时是**局部变量的地址**（`oidc.go:465-470` 的 `t := r.GetAuthTime(); authTime = &t`），所以一旦被别名改写，改的是 store 记录本身，且会在后续每次 refresh 的 id_token 里继续生效。

**(c) 我造出了真数据竞争——但它需要「持有者」。**
`TestCM3TheReturnedValueIsLiveStoreStateUnderTheRaceDetector` 用 `-race` 得到：

```
WARNING: DATA RACE
Read at 0x00c0001c6140 by goroutine 10:
  github.com/Re0Auth/r0semi/internal/oidcstore.(*AuthRequest).GetSubject()
      internal/oidcstore/oidcstore.go:222
Previous write at 0x00c0001c6140 by goroutine 9:
  github.com/Re0Auth/r0semi/internal/store/memory.(*OIDCStore).CompleteLogin()
      internal/store/memory/oidc.go:940
```
（还有一条 `GetScopes()` 的同类报告。）读的是**探针自己**持有的那个指针。

**为什么这不构成生产可达**：`CreateAuthRequest` 的唯一生产调用者是 zitadel 库的 `Authorize`：
`pkg/op/auth_request.go:145-150` 与 `pkg/op/server_legacy.go:165-169` 都是 `req, err := storage.CreateAuthRequest(...)` 后**只用 `req.GetID()`**（`RedirectToLogin(req.GetID(), ...)` / `NewRedirect(r.Client.LoginURL(req.GetID()))`），指针随即被丢弃；
Re0Auth 自己的生产代码从不调用 `CreateAuthRequest`（只有测试调用）。Re0Auth 侧的 `Consent`/`SetAuthTime`/`CompleteLogin` 传的都是 **id 字符串**（`oidchttp.go:1288`、`main.go:1163`），不是对象。
所以报告 (c) 的自评「HYPOTHESIS，需要一条真的会保留该指针的调用方路径」**方向是对的，但它低估了自己**：竞争不需要新调用方，
只需要**任何**持有者——而现有调用方一个都不是。**结论：机制成立、生产不可达 ⇒ 中降为低（潜在缺陷 + 内部不一致）。**
修法（create 路径也 clone）我同意：一行，且与读路径一致。

### 2.4 CM-4：事实成立，但「无界增长」与「高」都不成立（高 → 低；与 IPv6 组合时见 V-1）

**(a) 报告的算术我独立复核，结论成立且偏保守。**
`TestCM4RealisticPendingRequestCost`（新探针，两条各自用新 store，避免上次测量污染基线）：

```
audited fixture (shared request, no state/nonce/PKCE): 50000 requests retain ~337 bytes each
HTTP-realistic (state, nonce, PKCE challenge, 2 scopes): 50000 requests retain ~415-418 bytes each
realistic/audited per-entry ratio = 1.23-1.24
```
⇒ 报告的 335 B/条**不是夹具灌水**，真实 HTTP 请求（`state`+`nonce`+PKCE+2 scope）反而大 24%，
所以「单地址 90,000 条 ≈ 30 MiB」不是高估。这条我确认。

**(b) 但增长是「有界峰值」，不是「无界增长」。**
- 待决授权请求的 TTL 就是 `requestTTL`：`main.go:1176/1185` 传 `RequestTTL: authorizationRequestTTL`（`config.go:295` = 30 分钟），
  `CreateAuthRequest` 写入 `s.authRequestExpiry[id] = s.now().Add(s.requestTTL)`（`oidc.go:354`），`SweepExpired` 在 `now.After(expires)` 时删除（`:849-854`）。
- 我的探针 `TestCM4ThePeakIsSetByArrivalsTimesTTLNotByTime`：假时钟插入 5,000 条 → 推进 31 分钟后 `SweepExpired()` **5000/5000 全清、store 归零**。
  ⇒ 峰值 = 到达率 × TTL，与「运行多少天」无关。报告标题与「不变量」里的「无界增长」是错的（它自己的「影响」段其实写对了：50×1800）。
- 设备侧报告也说得偏松：设备寿命 10 分钟（`oidchttp.go:161-162`），且 `StoreDeviceAuthorization` **每次插入前**都 `purgeExpiredDevicesLocked`（`oidc.go:756`、`:816-819`）。
  ⇒ 设备表峰值约 50×600 = 3 万条/地址 ≈ 12 MiB，比授权请求更小。
- 「唯一会删记录的是 janitor」也不准确（消费路径会删：`AuthRequestByCode:388-389`、`GetDeviceAuthorizatonState:789-797`、`DeleteAuthRequest`），
  但**没有任何东西删未过期的待决请求**这一结论不变。

**(c) 决定严重度的是部署形态。** `docs/operations-decision.md:43-45`（决策 6）：
> **内存模式不提供生产运维保证。** 没有持久会话索引、没有增量备份、重启即丢失 OP 状态；它用于开发与联调，**生产必须配置 Postgres 与审计 key**。

装运的 k8s 清单正是 Postgres（`configmap.yaml:27-29`）。而这条 DoS **只存在于内存模式**（`memory.OIDCStore` 的 map）。
按 VERIFY-BRIEF 的判据「前提是运维主动打开一个明确标着危险的开关 ⇒ 降级」，这里更强：文档直接写了这个模式不提供生产保证。
单地址峰值 30 MiB 在 512 MiB limit 下不足以 OOM；要 OOM 需要十几个以上地址**持续 30 分钟**满速（每地址 50 req/s）。

**结论**：**中偏低**。我把判定写成「低（内存模式）」，并且明确指出：**报告不能既说「匿名可把进程 OOM」又不说明这需要 N 个地址 × 30 分钟的持续满速**。
除此之外 CM-4 最有价值的其实不是这条 finding，而是它顺带记录的 janitor 在全局锁下扫描的成本（与 performance.md 的 PERF-5 重复，见 §5）。

### 2.5 CM-5：机制成立，两处解释不成立（中 → 低）

**(a) 机制重跑确认。** `internal/ratelimit` 探针：

```
--- FAIL: TestAnArrivalAtCapacityResetsAnotherKeysBudget  (an unrelated key's request reset keyA's spent budget)
--- FAIL: TestEvictionAtCapacityRefundsExhaustedKeys      (1 exhausted keys were handed a fresh burst by one unrelated arrival)
--- PASS: TestCapacityStaysBounded / TestAnIdleBucketIsPreferredToALiveOne   # 对照组
```
`evictLocked`（`ratelimit.go:213-235`）读代码也与报告一致：有界样本 64 → 找不到空闲就无条件删 `fallback`。

**(b) 但探针是 `WithMaxKeys(shardCount)`（每分片 1 个槽）——一个不可能装运的配置。**
我在**默认容量**下量化（`TestCM5AtTheShippedCapEvictionNeedsHundredsOfKeysInOneShard`，用自己实现的 FNV-1a 找同分片 key）：

```
with the shipped default cap (625 keys/shard) one insertion at capacity reset the budget of 1 of the 625
previously-exhausted keys in that shard; ... Anyone has to hold 625 live keys in ONE shard (out of 10000
tracked keys) before any of this can happen, and the count above exceeds 1 only because re-admitting an
evicted key is itself an insertion at capacity, which evicts the next victim in turn
```
⇒ 触发门槛是「同一分片 625 个活跃 key」（默认 `maxKeys=10000`），受害者从随机 64 样本里取第一个（≈均匀），**定向打击需要 ~625 次容量处插入**。
这套前提不是「运维配置」而是「攻击者已经能制造成千上万个 key」。报告在「影响」里承认了随机性，但没有把门槛数字写出来；这个数字决定了它不该按攻击者的能力计价。

**(c) 「注释把后果说反了」是误读。** 原文（`ratelimit.go:210-212`）：
> an idle bucket in it is preferred to a live one: **evicting a live bucket hands its caller a fresh burst**, so it is the outcome to avoid

`its` 指 `a live bucket`——**被淘汰那个桶的持有者**拿到新 burst，正是报告描述的真实后果。只有把 `its caller` 读成「`evictLocked` 的调用者（插入者）」才能得到「说反了」，而插入者无论如何都会新建桶。**这一条子论断我推翻。**

**(d) 「使限流退化成没有限流」方向错。** 桶是**限额**不是授权：删桶只会让某人**多**拿到额度，永远不可能多拦任何人。
而「退化」根本不需要淘汰：per-key 限流本来就被换 key 绕过（`TestCM5EvictionCanOnlyLoosenAndKeyRotationNeedsNoEviction`）：

```
1000/1000 fresh keys admitted with the shipped default limiter and no eviction involved
```
1000 ≪ 10000，全程没有触发任何淘汰。所以被淘汰影响的是**公平性**（别人的额度被清零、限流对老 key 变松），
不是「攻击者绕过」也不是「服务不可用」。**严重度：中 → 低（有效性/公平性缺陷）。** 修法建议（只淘汰 idle、容量处 fail-closed）我同意作为取舍，
但要如实标注：它把代价从「静默放宽」换成「新客户端被拒」，这是裁定而不是修复。

### 2.6 CM-6：机制我复现了；「永久阻塞」在生产不可达（状态 HYPOTHESIS → CONFIRMED，严重度维持提示）

**(a) 报告的探针方法测的不是它描述的窗口。** `TestAnEnqueueRacingCloseIsAlwaysAnswered` 是「起协程 → 睡 50µs → `Close()`」。
50µs 后调用者早已把行塞进 512 深的缓冲队列（`auditbatch.go:114-120`），停在**第二个** select 上等 `item.done`；
这是「行已入队」的情形，而 `drain()`（`:147-156`）+ `Close`（`:196-209`）本来就保证它被回答。
报告描述的窗口在 `b.mu.Unlock()`（`:109`）与 send-select（`:114`）之间，50µs 的偏移**打不到它**。所以那 200 次「全部被回答」对窗口没有证据力。

**(b) 我造了针对该窗口的放大实验，稳定复现。** `internal/store/postgres/zzverify_cm_batch_test.go`，
`TestZZVerifyTheEnqueueCloseWindowSurvivesAmplifiedAttempts`（每个 trial 16 个调用者同时冲 Close，偏移量按 0…31µs 扫）：

```
5 calls ... never answered (of 64000, in 1 trials)      → 63995 answered, 5 hung (in 1 trials)
1 calls ... never answered (of 64000, in 1 trials)      → 63999 answered, 1 hung (in 1 trials)
64000 callers raced Close over 4000 trials: 64000 answered, 0 hung (in 0 trials)
```
即 6 次运行（≈32 万次调用）里命中 3 次（挂起 7 个调用者），约 **1/4.5 万**；而且**成簇出现**——
一次 trial 里能有 5 个调用者同时被孤立（我第一版探针因为「每个 trial 只消费一次 `time.After`」而在这种 trial 上自己挂到
10 分钟测试超时，那次 600s FAIL 本身就是「同一 trial 多个挂起」的旁证）。
于是 CM-6 的机制成立：一个已通过 `closed` 检查、随后被调度器搁置到 `Close()` 全部完成的调用者，
其 select 两个分支同时就绪，随机选到 send ⇒ 行进入再无人读取的队列 ⇒ 永久等 `item.done`。
`internal/store/postgres/audit.go:45-47` 的注释「It is called by DB.Close, after the background loops have been joined, **so no caller can still be enqueueing**」被这条实验证伪（文档与实现不符）。

**(c) 我也证伪了报告最悲观的那一半：满队列上等待的调用者是安全的。**
`TestZZVerifyACallerParkedOnAFullQueueIsAnsweredByClose`（写者卡在 append 里，队列填满 512，700 个调用者）：

```
700 of 700 parked callers were answered by Close (queue depth 512)
```
原因是 `close(b.stop)` 让 `<-b.stop` 就绪、而满队列让 send 分支**不就绪**，select 只有一个就绪分支——先到者胜（Go 的 select 由唤醒方决定哪个 case 完成）。
⇒ 窗口比报告描述的还要窄：它**只**存在于「已过检查、尚未进入 select」的调用者身上。

**(d) 但「真永久」在装运的接线里不存在。** 永久阻塞需要 ctx 永不取消。生产审计调用点的 ctx 我逐个查过
（`oauth/as.go:327`、`tapsign/client.go:198`、`admin/admin.go:434`、`vault/service.go:341`、`auth/auth.go:217`、
`lifecycle/lifecycle.go:299`、`httpapi/identity_routes.go:83`、`postgres/oidc.go:126`）全部是调用方/请求 ctx；
唯一传 `context.Background()` 的三处是内存 OP store（CM-2），而 `auditBatcher` 只存在于有 DB 的部署，那里内存 OP store 不运行（§2.1(b)）。
所以实际后果是：调用者**阻塞到它的 ctx 被取消**——`serveUntilSignal` 在排水超时后 `server.Close()`（`main.go:750-758`）会取消在途请求的 ctx，
随后 `main()` 返回即 `os.Exit`。**危害≈0，但「已接受必被回答」的契约确实被打破**（vault 的 I3 依赖它，方向是 fail-closed，不会静默放行）。
**严重度维持提示，但状态必须从 HYPOTHESIS/未复现改为 CONFIRMED（已复现）**，并写清「可达性受限于 ctx 可取消性」。

---

## 3. 我执行了什么（命令 + 有承载力的输出）

| # | 命令 | 承载输出 |
|---|---|---|
| 1 | `go test ./internal/zzprobe/concurrency/ -count=1 -v` | 四个 CM-1 探针 PASS；`TestSomeAuditPathsDropTheRequestContext` FAIL（三条断言）；single_use 六个探针全 PASS；`~335 bytes each (~32 MiB total)`；`SweepExpired … 1.202ms` |
| 2 | `go test -race ./internal/zzprobe/concurrency/ -count=1` | 无 `DATA RACE`；同样三条 FAIL（CM-2/CM-3a/CM-3b）——与报告「这些缺陷不是数据竞争」一致 |
| 3 | `go test ./internal/ratelimit/ -run 'TestAnArrival\|TestEvictionAtCapacity\|TestAnIdleBucket\|TestCapacityStaysBounded' -count=1 -v` | 两条 FAIL（如报告）、两条对照 PASS |
| 4 | `go test -race ./internal/ratelimit/ ./cmd/re0auth/ -count=1` | `cmd/re0auth` `ok … 62.6s`（无 DATA RACE）；ratelimit 仅两条「发现」FAIL |
| 5 | `go test ./cmd/re0auth/ -run 'TestEveryBackgroundLoop…\|TestTheAnchorLoop…\|TestTheAuditVerifyLoop…' -count=1 -v` | 四个 loop 全部在 cancel 后返回；anchor/verify 启动各跑 1 次 |
| 6 | `go test ./internal/store/postgres/ -run 'TestAnEnqueueRacingClose\|TestACallThatStartsAfterClose\|TestACancelledCallerStillGets\|TestCloseWritesRows' -count=1 -v` | 四条全 PASS（这四条不需要 DB） |
| 7 | `go test ./internal/zzprobe/verifycm/ -count=1 -v` | CM-1 量化 `810ns vs 347ns`（复跑 `578ns vs 401ns`）；CM-3 下游后果 FAIL（写入到达兑换）；CM-4 `337 vs 415 bytes`、TTL 清空 5000/5000；CM-5 默认容量量化 |
| 8 | `go test -race ./internal/zzprobe/verifycm/ -run TestCM3TheReturnedValue… -v` | `WARNING: DATA RACE`：`oidcstore.go:222` vs `memory/oidc.go:940` |
| 9 | `go test ./internal/store/postgres/ -run 'TestZZVerify' -count=1 -v` | CM-6 复现：`63995 answered, 5 hung (in 1 trials)` / `63999 answered, 1 hung` / `64000 answered, 0 hung`；CM-6 安全面：`700 of 700 parked callers were answered` |
| 10 | 静态核对 | 非测试 Go 文件 `time.After(` **0 次**；`time.NewTicker` 恰好 4 处（`main.go:889/920/963/1009`，各自 `defer ticker.Stop()`）+ `auditbatch.go:166` 的 `NewTimer` 同有 defer；`memory.NewOIDCStore` 生产调用点唯一（`main.go:1179`）；`oauth.Registry.Register` 生产调用点唯一（`scope.go:167`，`NewRegistry` 构造期） |

**关于探针位置的一处越界**：`internal/store/postgres/zzverify_cm_batch_test.go` 建在**被测包内**，因为 `auditBatcher` 未导出、无法从外部包触达；
它是**新文件**，没有改动任何人的探针文件或任何被跟踪文件（`git status` 只多出这一个未跟踪文件 + `internal/zzprobe/verifycm/`）。
VERIFY-BRIEF 要求探针放新包，这里做不到，我把偏离写在明处。

---

## 4. 确认的正面结论（抽查 6 条）

| # | 报告结论 | 我的动作 | 结果 |
|---|---|---|---|
| 正1 | 授权码在真 goroutine 竞争下单次使用 | 重跑 `TestAuthorizationCodeIsSingleUseUnderAGoroutineRace`（含 `-race`） | PASS：16 个 goroutine 恰好 1 个成功；反空转断言（赛后不可再兑换）成立 |
| 正3 | refresh 轮换是 claim（判定+删除+两次写入同一临界区） | 重跑 `TestRefreshRotationIsSingleUseUnderAGoroutineRace`（含 `-race`） | PASS：1 胜 15 负且 15 个都拿到 `ErrRefreshTokenSpent`；`oidc.go:501-512` 读码一致 |
| 正4/正5 | device_code 消费单次；并发批准至多 1 个赢家且 subject 是批准者 | 重跑两条探针 | PASS（`done==1`、`missing==15`；`wins<=1` 且 `ok>0`） |
| 正7 | 四个后台循环随 ctx 取消返回（anchor/verify 启动即跑一次） | 重跑 + 读码 | PASS；`main.go:888-903/918-929/961-975/1008-1031` 各自 `defer ticker.Stop()` |
| 正8 | 生产代码里没有「循环里的 `time.After`」、没有未 Stop 的 ticker | 全仓库非测试文件 grep | 确认：`time.After(` = 0；`NewTicker` = 4（都有 defer Stop）；`NewTimer` = 1（有 defer Stop） |
| 正9/(部分) | `vault.Service.Use` 不持锁跨越调用方回调 | 读 `vault/service.go:227-301` | 确认：`Use` 全程无锁，`fn(plain)` 在 :298 直接调用；这是 CM-1 死锁的**反面**证据（键控锁那部分我没有逐行复核） |
| 正10 | `oauth.Registry` 生产里从不运行时改 | grep `\.Register(` | 结论成立，**措辞需修正**：生产调用点是 `scope.go:167`（`NewRegistry` 构造期），不是「只在测试里被调用」 |

**没有发现假的正面结论。** 唯一不精确的是正10 的措辞。

---

## 5. 我未能验证的

1. **所有 Postgres 运行时语义**：本机无 Docker / 无 Postgres。CM-1/CM-2 报告里关于 `pseudonymize` 的 1~4 次往返、链头 `FOR UPDATE` 的代价，
   我**只能读代码**（`auditpseudo.go:69-142`、`auditbatch.go:160-194`），没有实测；但 §2.1(b) 已经让这些数字与内存 store 的锁无关。
2. **`internal/httpapi` 自己的测试套件**：报告说当时因别的代理的探针文件非法 UTF-8 而跑不动。我本轮没有重试该包（避免和其它代理的中间态纠缠），
   httpapi 层的并发只有读码证据。
3. **持久化部署的真实执行**：`go test ./cmd/re0auth/` 的 `openStorage` 走 DB 分支需要真库，无法执行；§2.1(b) 是**分支结构**层面的读证据
   （单一 `if store.db != nil` 同时决定 OP store 与 audit sink），我认为它比任何运行证据都强，但它仍是「读；未执行」。
4. **CM-6 的命中率**：6 次运行（每次 4000 trial × 16 并发 = 64,000 次调用）里 3 次命中共 7 个挂起调用者，
   即命中率约 1/4.5 万，且成簇出现（单 trial 最多 5 个）。这是「可复现」的量化，不是精确概率模型——调度器/GC 相位显然在影响它。
5. **CM-3(c) 的生产交错**：我没有、也无法证明生产里存在持有该指针的调用者——恰恰相反，我证明了当前没有。若将来出现新调用方，本结论失效。
6. **`BRIEF.md` 在我开工时不存在**（`read` 报 not found、`glob **/BRIEF.md` 零命中），我在写报告前才读到它（文件头自述「曾被某个代理误删过一次，由主代理重建」）。
   `crypto-VERIFIED.md` 的 V-5 已记录同一现象，我不重复计数。

---

## 6. 新发现（复核时顺手看到）

### V-1（**我认为 CM-4 的放大前提被低估**）：限流按 `/128` 分桶，单个 IPv6 主机即可拿到「N 个地址」的线性放大

- 读证据：`clientaddr.go:23-36` —— 对端不受信时直接 `return addr.String()`（也就是**完整 /128**，不是 /64 前缀）；
  `middleware.go:349` 的限流键 = `plane + "|" + clientAddr`；`configmap.yaml:25` 默认 `trusted_proxies = ["10.0.0.0/8"]`，直连攻击者无法自选键。
- 后果：CM-4 的算式「N 个地址 ⇒ N × 30 MiB」不需要 N 台机器——一个持有 IPv6 /64 的主机可以轮换 2^64 个源地址，
  每个地址各拿 50 req/s 的独立预算；`maxKeys = 10000` 也拦不住，因为到达容量后新 key 会被**淘汰式接纳**（`ratelimit.go:213-235`，正是 CM-5 的机制）。
  单机按 2~5k req/s 计，30 分钟窗口即可累积 4~9 百万条 ≈ 1.7~3.7 GB，远超 k8s 默认 512Mi limit（`capacity-planning.md:104`）。
- 判定：**严重度被低估**——但影响仍被「内存模式不提供生产运维保证」（`operations-decision.md:43-45`）限制。
  如果主代理决定把内存模式当作一种可上线的部署形态（`architecture.md:513`/`oidc-decision.md` P4b 的措辞支持这种读法，PERF-5 也这么认为），
  那么 CM-4 应该是**高**，而 CM-5 的「容量处静默放宽」就从公平性问题升级为这条 DoS 的**使能条件**——两条应当合并看。
- 证据等级：**读；未执行**（要执行需要构造带 `Limiter` 的 httpapi 环境并伪造 `RemoteAddr`，本轮没做）。
- 修法方向：对 IPv6 按 /64 聚合分桶（`netip.Prefix` 截断），或对「协议平面 + 匿名端点」单独设更严的配额；这是裁定。

### V-2：CM-2 缺了「什么情况下才重要」的答案

已在 §2.2 给出：把内存 OP store 与持久化 sink 接线是唯一路径；我加了实验证明当前可观测影响为零。

### V-3：`audit.go:45-47` 的注释与实现不符

「after the background loops have been joined, so no caller can still be enqueueing」——`serveUntilSignal` 在排水超时后 `server.Close()`（`main.go:750-758`）
会留下仍在跑的 handler，所以 CM-6 的前提成立。建议把注释改成「…so no *loop* can still be enqueueing」并把 `enqueue`/`Close` 的竞态记录下来。

### V-4：正10 的措辞（`Register` 的生产调用点）

见 §4 表：结论对的，引文不对。

---

## 7. 结论摘要（给主代理）

CM-1/CM-2 的影响叙述必须按**部署形态**重写：`memory.OIDCStore` 与 `postgres.AuditLogger` 在同一部署里互斥（`main.go:1170-1198`、`memory.NewOIDCStore` 生产调用点唯一），
装运清单跑 Postgres；因此「内存 store 的锁横跨 DB 往返」不成立，实测锁内审计只多数百纳秒（463ns / 177ns）。
CM-4 的「无界」应改为「有界峰值 = 到达率 × 30min TTL × 地址数」，严重度降到低（除非按 V-1 把内存模式当生产，那时是单机可触发的 DoS，应为高）。
CM-5 的机制成立但方向被说反了两处，应降为低。CM-6 的机制**我复现了**（3/6 次运行、≈1/4.5 万调用），状态应改为 CONFIRMED、严重度维持提示（「永久」需要不取消的 ctx，装运路径没有）。
CM-3 的别名缺陷成立（我还补了下游后果与一条真 DATA RACE 报告），但当前无调用方持有该指针 ⇒ 低。
