# 并发 / 竞态 / 对象生命周期 / 内存存储 审计报告

> 区域缩写 **CM**（concurrency & memory）。证据标准按 BRIEF §3：每条发现要么有**真的跑过的测试**，
> 要么**读代码到行**，并标注 CONFIRMED / HYPOTHESIS。本轮**没有修改任何被跟踪文件**，
> 探针文件全部保留在下方列出的路径里。

## 范围与方法

**读了**：`internal/store/memory/*.go`（全部，`oidc.go` 1316 行逐行读完）、`cmd/re0auth/main.go`
（含 `serveUntilSignal`、四个后台循环、`loopGroup`）、`cmd/re0auth/config.go`（限流与在途上限默认值）、
`internal/httpapi/{middleware,clientaddr,server}.go`、`internal/ratelimit/ratelimit.go`、
`internal/observability/observability.go`、`internal/federation/{refresh,binding,bind,unbind,revocation,killswitch}.go`、
`internal/oidchttp/oidchttp.go`（发现缓存、`ServeHTTP` 路由）、`audit/audit.go`、
`internal/store/postgres/{audit,auditbatch,auditpseudo,postgres}.go`、
`internal/oidcstore/oidcstore.go`、`vault/{repo,service}.go`、`oauth/{client,scope}.go`、
`internal/store/memory/{device_decision,oidc,oidc_index,oidc_sweep}_test.go`（避免重复既有 pin）。

**跑了**（全部在本机真的执行过）：

```
go test ./internal/zzprobe/concurrency/ -count=1 -v
go test -race ./internal/zzprobe/concurrency/ -count=1
go test -race ./internal/store/memory/ ./internal/federation/ ./internal/oidchttp/ ./internal/ratelimit/ ./cmd/re0auth/ -count=1
go test ./internal/store/postgres/ -run 'TestAnEnqueueRacingClose|TestACallThatStartsAfterClose|TestACancelledCallerStillGets|TestCloseWritesRows' -v -count=1
```

- **`-race` 可用**（`CGO_ENABLED=1`，gcc 在 PATH）：`internal/store/memory`、`internal/federation`、
  `internal/oidchttp`、`cmd/re0auth`（修掉我自己探针里的一处统计竞态后）**全部 ok，无 DATA RACE**
  （`internal/ratelimit` 的失败是我故意让守卫失败的那两条，不是竞态告警）。
  **我的并发探针在 `-race` 下也没有任何 DATA RACE**——因为这些缺陷都是「判定与写入不在同一次加锁内」
  的**逻辑**交错，不是数据竞争，这正是 BRIEF 说的「竞态检测器看不见」的那一类。
- **跑不了**：`internal/httpapi` 自己的测试套件。跑的时候另一个子代理的探针文件
  `internal/httpapi/zzprobe_adminpriv_test.go` 处于写入中间态（`illegal UTF-8 encoding`），
  该包编译不过，我**没有碰它**。所以 httpapi 层的会话/中间件并发我只做到了读代码。
- 全部 Postgres 路径（审计批处理在真库上的耗时、链头行锁、sweep、审计读 API）**只有读代码到行**，
  本机没有 Postgres。`internal/store/postgres` 的那四条 batcher 探针不需要数据库（用桩 `appendFn`），
  已真实执行。

**没有**跑 `go test ./...`，**没有**动 git，**没有**改任何被跟踪文件。

---

## 发现

### CM-1 内存 OP store 在**持有全局唯一锁**时同步写审计：`ApproveDevice` / `DenyDevice`

- 严重度: 高
- 类别: 可用性 | 性能
- 不变量/性质: 「一个组件自己的锁不得跨越到另一个组件的同步 I/O」（也即 BRIEF 问的
  callback-under-lock / lock-held-across-I/O）
- 证据: `internal/store/memory/oidc.go:978-998`（`ApproveDevice`：`s.mu.Lock(); defer s.mu.Unlock()`
  包住整个函数，`s.record(...)` 在 **996 行**、仍在临界区内）与 `:1004-1019`（`DenyDevice`，**1017 行**）。
  对照：同文件的 `CreateAccessToken`(:433-436)、`CreateAccessAndRefreshTokens`(:501-514)、
  `RevokeToken`(:556-610)、`RevokeGrant`(:1099-1136) 都是**先解锁再记审计**——这两个方法是唯一的例外。
  实测（跑过的测试，含对照组）：

  ```
  --- PASS: TestControlTokenMintAuditsOutsideTheStoreLock      (0.00s)  # 对照：CreateAccessToken 不在锁内审计
  --- PASS: TestApproveDeviceHoldsTheStoreLockAcrossTheAuditWrite (0.50s) # 发现：锁被持有
  --- PASS: TestDenyDeviceHoldsTheStoreLockAcrossTheAuditWrite    (0.50s) # 发现：锁被持有
  --- PASS: TestAnAuditSinkThatReadsTheStoreDeadlocksUnderTheLock (2.00s) # 回调需要同一把锁 → 死锁
  ```

  探针的判据是行为而非时序猜猜：审计 sink 在 `Record` 里**回调 store 的 `Counts()`**（它需要同一把
  `s.mu`），被测操作在另一个 goroutine 里进入 `Record` 后阻塞；对照组（`CreateAccessToken`）的
  `Counts()` 立刻返回，两个发现项的 `Counts()` 在 500ms 内**永不返回**，释放审计回调后立刻返回。
- 状态: CONFIRMED（已执行；锁的持有由「同一把锁的另一次获取能否完成」证明）
- 影响: 在**持久化部署**里，审计 sink 是 `postgres.AuditLogger.Record`，它在 `Record` 内先做
  `pseudonymize`（缓存未命中时是 `SELECT audit_subject_keys` → `INSERT … ON CONFLICT` → 再 `SELECT`，
  见 `internal/store/postgres/auditpseudo.go:69-142`），再把行交给 `auditbatch`（`BEGIN` →
  `SELECT … FOR UPDATE` 锁 `audit_chain` 单行 → `INSERT` → `COMMIT`，见 `auditbatch.go:160-194` 与
  architecture.md §4.16）。也就是说**内存 OP store 的唯一锁被横跨 1~4 次数据库往返 + 一个全局行锁**。
  这把锁是 OP 的全部：每次 `/oauth/authorize`、`/oauth/token`、`/oauth/introspect`、
  `/v1/grants`、Kill Switch 的 `RevokeTokens`、以及 janitor 的 `SweepExpired` 都在它后面排队。
  门槛很低：**一次登录**的账号就能反复「创建设备授权 → 批准」，每次批准都把全进程的 OP 操作卡在一个
  审计追加后面（审计追加本身又是全进程串行的）。这是「把服务自己拖慢/拖死」的形状，不是数据泄露。
  次生风险：锁序固定为 **store 锁 → 审计锁**；`internal/lifecycle` 的注释已经承认
  「审计 → vault 查询 → 审计」这条回路必须靠绕开 `vault.Service` 来避免，一旦有第二个审计 sink
  或 vault 侧回调读 store，就是硬死锁（探针已证机制）。
- 修法建议: 把 `s.record(...)` 移到 `s.mu.Unlock()` 之后（`CreateAccessToken` 的写法照抄即可），
  ctx 用调用方传进来的那个；返回值不受影响（审计错误本来就被 `record` 吞掉）。
- 复现/守卫: `internal/zzprobe/concurrency/store_lock_test.go`
  `TestApproveDeviceHoldsTheStoreLockAcrossTheAuditWrite`、`TestDenyDeviceHoldsTheStoreLockAcrossTheAuditWrite`、
  `TestAnAuditSinkThatReadsTheStoreDeadlocksUnderTheLock`（对照 `TestControlTokenMintAuditsOutsideTheStoreLock`）。

### CM-2 三条请求路径把 `context.Background()` 交给审计 sink

- 严重度: 低
- 类别: 可用性 | 可维护性
- 不变量/性质: 「请求路径上的出站/落盘调用必须继承请求的取消与截止时间」
- 证据: `internal/store/memory/oidc.go:436`（`CreateAccessToken`）、`:996`（`ApproveDevice`）、
  `:1017`（`DenyDevice`）——三个方法**都收到了 `ctx`，却把它丢掉换成 `context.Background()`**；
  同文件 `CreateAccessAndRefreshTokens`(:514) 与 `RevokeToken`(:576) 用的是调用方的 ctx。
  实测（断言的是「应当转发」，因此**当前代码上失败**）：

  ```
  --- FAIL: TestSomeAuditPathsDropTheRequestContext
      store_lock_test.go:168: CreateAccessToken did not forward the request context: value=<nil> err=<nil>
      store_lock_test.go:180: ApproveDevice did not forward the request context: value=<nil> err=<nil>
      store_lock_test.go:187: DenyDevice did not forward the request context: value=<nil> err=<nil>
  ```

  对照（同一条测试内先跑）：`CreateAccessAndRefreshTokens` 确实转发了带标记、且已取消的 ctx
  （`value=marker err=context.Canceled`），所以「没转发」是这三条路径自己的选择，不是探针没跑到。
- 状态: CONFIRMED（已执行）
- 影响: 在持久化部署里，`CreateAccessToken` 是 `/oauth/token` 的热路径：客户端断开后，审计 sink 里
  那句 `pseudonymize` 的 `SELECT`（+ 首次的 `INSERT`）**不再有任何取消或截止时间**，只能靠池上的
  `statement_timeout`（默认 30s）兜底。对 `ApproveDevice`/`DenyDevice` 同理。反过来，`auditbatch`
  的**事务**刻意用 `context.WithoutCancel` 脱离调用方（`auditbatch.go:187`，这是有意的 I3 语义），
  所以「不把 ctx 传下去」并不是实现事务脱离的手段——两者是两件事，这里是纯粹丢掉了上层取消。
- 修法建议: 三处改为传 `ctx`（方法签名已经有它）；`auditbatch` 的脱离语义不用动。
- 复现/守卫: `internal/zzprobe/concurrency/store_lock_test.go` 的 `TestSomeAuditPathsDropTheRequestContext`。

### CM-3 内存 OP store 有三处按引用交出内部记录（copy-on-return 别名）

- 严重度: 中
- 类别: 安全 | 可维护性
- 不变量/性质: 「store 交出去的值不得是它自己持有的可变状态」（写入必须经过锁）
- 证据（三条，探针都断言了「应当复制」，因此在当前代码上失败）：

  **(a) `CreateAuthRequest` 直接把 store 里的 `*oidcstore.AuthRequest` 交出去**
  （`oidc.go:346-356` 建对象入 map 后 `return a`），而 `AuthRequestByID` 交的是 `cloneAuthRequest(a)`
  （`oidc.go:367`，:393-397）——同一份数据，读路径复制、创建路径不复制。
  ```
  --- FAIL: TestCreateAuthRequestDoesNotHandItsRecordToTheCaller
      alias_test.go:68: a caller's write to the value CreateAuthRequest returned changed the store's record: subject="usr_attacker"
      alias_test.go:72: a caller's write to the returned record's scope slice changed the stored scopes: [phigros.score.read]
  ```
  同一条测试里先断言 `AuthRequestByID` 返回的是副本（改写它不影响 store）作为对照，证明探针确实
  走到了两条路径。**旁证**：`oidcstore.AuthRequest` 是实现 `op.Storage` 契约的类型，而库拿到的
  请求对象会被跨请求带着走；`oidcstore.RefreshRequest` 上的 `SetCurrentScopes`（`oidcstore.go:247`）
  说明「调用方会改写拿到的请求对象」在这个代码库里是既定事实。

  **(b) `TokenRequestByRefreshToken` 复制了 `Scopes`，但没有复制 `AMR`、`Audience` 和 `auth_time` 指针**
  （`oidc.go:526-529`：`Scopes: append([]string(nil), r.scopes...)` 是复制，而 `AMR: r.amr`、
  `Audience: r.audience`、`AuthTime: r.authTime` 是共享）。
  ```
  --- FAIL: TestTokenRequestByRefreshTokenDoesNotHandOutItsSlices
      alias_test.go:120: the returned AMR slice aliases the stored record: [amr_rewritten]
      alias_test.go:132: the returned Audience slice aliases the stored record: [aud_rewritten]
      alias_test.go:145: the returned auth_time aliases the stored record: 2030-01-01 00:00:00 +0000 UTC
  ```
  `auth_time` 是 id_token 里那个「人多早认证过」的声明，被别名改写等于改写会话新鲜度；
  同一条测试里 `Scopes` 的对照断言通过，说明复制与否是逐字段的疏忽而不是整体设计。

  **(c) 由此产生的数据竞争（HYPOTHESIS，未构造生产路径）**：`CompleteLogin` 在锁内写
  `a.Subject`/`a.Scopes`/`a.IsDone`（`oidc.go:940-942`），`SetAuthTime` 写 `a.AuthTime`（:920）；
  而 (a) 交出去的指针是**同一个对象**，持有者读它时**没有这把锁**。两条 HTTP 请求（发起 authorize
  与提交同意）在同一个 auth request 上天然可以重叠。要证实它需要一条真的会保留该指针的调用方路径；
  本机只证明了「指针确实外泄」，没有证明现网一定并发读到。**要证实它需要**：让某个 handler 或中间件
  从 `CreateAuthRequest` 的返回值上读 `GetSubject()`，同时另一个请求调 `CompleteLogin`，用 `-race` 跑。
- 状态: (a)(b) CONFIRMED（已执行）／(c) HYPOTHESIS
- 影响: 任何调用方对返回值的写入都会**绕过 store 的锁**直接改 store 状态：改 `Subject` 会让
  `requestBySubject` 索引与实际记录不一致（`CompleteLogin` 的 `previous` 取的是被改写后的值，
  于是 `remove(previous, id)` 删不到东西），改 `Scopes` 会改掉这次授权实际签发的 scope 与
  `Grants()` 展示；改 `auth_time` 会改 id_token 的声明。当前调用方（zitadel 库与 httpapi）只读不写，
  所以这是**潜在**缺陷而不是已发生的越权——但它同时是「读路径复制、创建路径不复制」的内部不一致，
  下一个人写一行 `authReq.Scopes = …` 就会静默污染 store。
- 修法建议: (a) `CreateAuthRequest` 也 `return cloneAuthRequest(a), nil`（一行）；
  (b) `AMR`/`Audience` 各 `append([]string(nil), …)`，`auth_time` 复制一份 `time.Time` 再取地址。
  两处都与文件里已有的写法一致，不涉及裁定。
- 复现/守卫: `internal/zzprobe/concurrency/alias_test.go` 的
  `TestCreateAuthRequestDoesNotHandItsRecordToTheCaller`、`TestTokenRequestByRefreshTokenDoesNotHandOutItsSlices`。

### CM-4 内存 OP store 没有任何人口上限：**匿名**请求即可无界增长

- 严重度: 高（匿名可触发的资源耗尽）
- 类别: 可用性 | 安全
- 不变量/性质: 「未认证调用方不得能以零成本无界增长任何索引/映射」
- 证据（跑过的测试；HTTP 边界，全程无会话 cookie、无 bearer、无 client secret，只有一个公开 `client_id`）：

  - 200 次匿名 `GET /oauth/authorize?...` → `store.Counts().AuthRequests == 200`（无上限、无淘汰）。
  - 100 次匿名 `POST /oauth/device_authorization`（表单里只有 `client_id` 与 `scope`）→
    `store.Counts().Devices == 100`。
  - 单条成本实测：`100000 pending requests retain ~335 bytes each (~32 MiB total)`。
  - 唯一会删记录的是 janitor 的 `SweepExpired`（`cmd/re0auth/main.go:888-903`，间隔
    `opJanitorInterval = 5 * time.Minute`），它只删过期记录——探针
    `TestTheJanitorOnlyRemovesExpiredRecords` 断言未过期记录一条都不动（假时钟推过 30 分钟后才删）。
  - 相关常量：`authorizationRequestTTL = 30 * time.Minute`（`cmd/re0auth/config.go:295`）、
    设备授权 `Lifetime: 10 * time.Minute`（`internal/oidchttp/oidchttp.go:162`）、
    默认限流 `50/s`、突刺 `100`／地址（`cmd/re0auth/config.go:300-301`）、内存模式在途上限 512。
  - 代码到行：`OIDCStore` 的 `authRequests`/`authRequestExpiry`/`codes`/`accessTokens`/
    `refreshTokens`/`devices`/`userCodes` 七个 map（`oidc.go:40-46`）在构造时无容量上限，
    写入路径（`CreateAuthRequest` :353-355、`StoreDeviceAuthorization` :761-765）也没有任何计数或拒绝分支。

- 状态: CONFIRMED（已执行）
- 影响: 单个地址在默认限流下、一个 30 分钟窗口内可累积 **50×1800 = 约 9 万条**待决授权请求
  ≈ **30 MiB**；限流键是 `plane|客户端地址`（`middleware.go:349`），所以 N 个地址线性放大
  （1000 个地址 ≈ 30 GiB）。这些成本**全部发生在任何凭据出现之前**，并且伴随 GC 压力与
  `SweepExpired` 的线性扫描成本（实测 10 万条时整锁扫描 **约 1.0ms**，本身可接受，
  但它随人口线性增长且整段持锁，见 `oidc.go:843-878`）。同一项目对**自己的**内存结构是有上限标准的：
  审计 `MemoryLogger` 是 10,000 条环形缓冲（`audit/audit.go:102`），限流器 10,000 桶
  （`ratelimit.go:18`），假名缓存 4096（`auditpseudo.go:32`）——OP store 是唯一没有上限的那个。
  注意这不是「内存模式重启即丢」那条文档化的取舍：那条说的是**持久性**，与「匿名调用方能把进程 OOM」是两件事。
- 修法建议: 给 `authRequests`（及其 code/device 同理）加一个显式上限：超过即按最旧淘汰或直接拒绝
  （协议面回标准错误，`temporarily_unavailable` 是现成的），并把上限与「超限后会发生什么」写进启动
  WARNING 行；建议同时把「按地址计数」而不是只有全局上限，否则单地址仍可挤掉所有其他人的在途请求。
- 复现/守卫: `internal/zzprobe/concurrency/growth_test.go` 的
  `TestUnauthenticatedAuthorizeGrowsTheStoreWithoutBound`（HTTP 可达性）、
  `TestPendingRequestsCostMemoryAndTheSweepHoldsTheLock`（单条成本与 sweep 成本）、
  `TestTheJanitorOnlyRemovesExpiredRecords`（唯一删除者只删过期）。

### CM-5 限流器在容量处淘汰**活跃**桶，等于重置别人的预算

- 严重度: 中
- 类别: 安全 | 可用性
- 不变量/性质: 「一个 key 的到达不得影响另一个 key 的预算」
- 证据: `internal/ratelimit/ratelimit.go:213-235` 的 `evictLocked`：先在一个**有界样本**（`evictionScan = 64`）
  里找空闲（`now-lastSeen > ttl`）的桶删除；找不到就把样本里的第一个键当 `fallback` **无条件删掉**。
  在容量处每个桶的 `lastSeen` 都很新（都是活跃流量），所以 `fallback` 分支就是常规路径。
  实测（确定性交错，不依赖 `-race`）：

  ```
  --- FAIL: TestAnArrivalAtCapacityResetsAnotherKeysBudget
      zzprobe_concurrency_test.go:72: an unrelated key's request reset keyA's spent budget: the rate limit is per arrival, not per key
  ```

  该探针把 `maxKeys` 设成 `shardCount`（每分片 1 个槽），于是机制裸露：keyA 用掉 burst=1 后被拒 →
  **无关的 keyB 到达**（它必须要在同一分片）→ keyA 再次被放行，因为它的桶被 B 的插入删掉了。
  对照：`TestAnIdleBucketIsPreferredToALiveOne` 证明空闲桶优先这条策略本身是真的在工作；
  `TestCapacityStaysBounded` 证明上限本身被遵守（`size() ≤ maxKeys+shardCount`），
  所以缺陷不是「无界增长」，而是「淘汰谁」。
  第二条探针在 `perShard=4` 下用「一次到达让 N 个已耗尽 key 重新被放行」计数（实测 N 随
  map 迭代顺序在 1~3 之间波动，因为被淘汰 key 的**再次到达本身又是一次容量处插入**，
  会级联淘汰下一个活跃桶）。
- 状态: CONFIRMED（已执行，确定性）
- 影响: 在桶表到达容量时，「每 key 预算」不再是硬界：任何新 key 的到达都会把某个活跃桶删掉，
  被删者的下一次请求拿到满满一个 burst。受害者是随机挑的（Go map 迭代随机化），所以**单个**攻击者
  无法定向把某个受害者的桶清掉；但反过来说，**自己**的桶也一样会被别人清掉，而任何能大量制造 key
  的一方（分布式/代理池）都能让容量处长期处于淘汰状态，使限流退化成「没有限流」。
  另外 `evictLocked` 的注释把后果说反了：「evicting a live bucket hands its caller a fresh burst」——
  拿到新 burst 的**不是插入者**（它反正会新建桶），而是**被淘汰那个 key 的持有者**。
  文档里「eviction is O(1) at capacity」这句是成立的（扫描有界），但它没有覆盖这个安全后果。
- 修法建议: 让淘汰只删 `idle` 桶；容量处找不到空闲桶时，**新 key 以空桶入场**（fail-closed，
  即新桶首次请求就不放行），或者直接把该请求拒绝。这样「活跃桶的预算」不再可能被第三方重置，
  而内存仍然有界。若认为「容量处拒绝新客户端」代价过大，那是一个需要裁定的取舍（见文末判断），
  但不应保留现在这种「静默把别人的预算清零」的行为。
- 复现/守卫: `internal/ratelimit/zzprobe_concurrency_test.go` 的
  `TestAnArrivalAtCapacityResetsAnotherKeysBudget`（主证据，确定性）、
  `TestEvictionAtCapacityRefundsExhaustedKeys`、`TestAnIdleBucketIsPreferredToALiveOne`（对照）、
  `TestCapacityStaysBounded`（对照）。

### CM-6 审计批处理的 `enqueue` 与 `Close` 之间存在「已被接受但永不被回答」的窗口

- 严重度: 提示
- 类别: 可用性 | 可维护性
- 不变量/性质: 「被接受的调用必须在有限时间内得到回答（成功或失败）」
- 证据（**读代码到行**；探针 200 次尝试**没有**命中，故列为假说）：
  `internal/store/postgres/auditbatch.go:96-128` 的 `enqueue` 先在 `b.mu` 下读 `closed`（:107-112），
  **释放锁之后**才 select 到队列（:114-120）：

  ```go
  b.mu.Lock(); closed := b.closed; b.mu.Unlock()      // (1)
  if closed { return errors.New(...) }
  select { case b.queue <- item:                      // (2) 队列是带缓冲的，立即成功
           case <-b.stop: return errors.New("closed") }
  select { case err := <-item.done: …; case <-ctx.Done(): … }
  ```

  `Close()`（:198-209）置 `closed`、关 `stop`、等 writer 排空并返回。若调用方在 (1) 与 (2) 之间被抢占、
  且抢占持续到 `Close()` 全部完成，它的 select 两个分支**同时就绪**，Go 等概率随机选：
  选中 (2) 就落进一个再也不会有人读的队列，随后**永久阻塞在 `<-item.done`**——如果它的 ctx 不会取消
  （正是 CM-2 里那三条路径给的 `context.Background()`），那就是真永久。
  可达性：`cmd/re0auth/run` 里 `store.close()`（= `DB.Close` → `AuditLogger.Close` → `batcher.Close`）
  在 **join 循环之后**执行，但 `serveUntilSignal` 在 30s 排水超时时会 `server.Close()` **强制断开连接、
  留下仍在跑的 handler**（`main.go:750-758`），所以「请求还没结束而审计已经被关」是可达状态。
  实测：`TestAnEnqueueRacingCloseIsAlwaysAnswered`（200 次、50µs 偏移）**全部被回答**，
  `--- PASS`，即**没有复现**——窗口在 (1) 与 (2) 之间只有几条指令，而 `Close` 要做的事多得多，
  抢占正好落在那里的概率极低。
- 状态: HYPOTHESIS（机制读代码成立；未复现）
- 影响: 若命中：进程已在退出路径上，实际危害接近零（`main` 返回即 `os.Exit`）；真正的危害是把
  「已接受必被回答」这条契约变成概率性的，而这正是 `audit.Logger` 契约（`audit/audit.go:35-39`）
  与 `vault.Use` 的 I3 fail-closed 所依赖的东西。
- 修法建议: 把 (1)(2) 合并到同一个临界区里（用 `b.mu` 保护「入队」而不只是「读 closed」），
  或让 `Close` 与 `enqueue` 通过同一个 `select` 语义化协调（例如 `Close` 关 `stop` 后再等一个 drain
  周期才置 `closed`）；再或者给 `item.done` 一个「writer 已停」的兜底回答。
- 复现/守卫: `internal/store/postgres/zzprobe_concurrency_test.go` 的
  `TestAnEnqueueRacingCloseIsAlwaysAnswered`（守卫，当前通过）、
  `TestACallThatStartsAfterCloseIsRefused`（边界对照）、
  `TestACancelledCallerStillGetsItsRowWritten`（「调用方放弃后行仍落库」的正面语义）、
  `TestCloseWritesRowsThatWereAlreadyQueued`（`Close` 排空而不是丢行）。

---

## 探过但没破的（这些也应变成守卫）

1. **授权码在真实 goroutine 竞态下是单次使用**：16 个 goroutine 用 barrier 同时兑换同一个 code，
   恰好 1 个成功（`AuthRequestByCode` 把「查到」本身当作 claim，`oidc.go:376-391`，判定与两次删除在同一临界区）。
   探针 `TestAuthorizationCodeIsSingleUseUnderAGoroutineRace`。
2. **同一个 auth request 被两次同意（双击）不会变成两次授权**：两个 code（`SaveAuthCode` 是
   无条件覆盖写，没有谓词）并发兑换时仍只有 1 次成功——因为赢家会 `deleteRequestLocked`，
   第二个 code 找不到它的 request。探针 `TestASecondCodeForOneAuthRequestIsNotASecondGrant`。
3. **refresh 轮换是 claim 而不是 check**：16 个 goroutine 拿着同一个 refresh token 并发轮换，
   恰好 1 个成功、其余 15 个都拿到 `ErrRefreshTokenSpent`（判定 + 删除 + 两次写入在
   `oidc.go:501-512` 的**一次**加锁内）。探针 `TestRefreshRotationIsSingleUseUnderAGoroutineRace`。
   这是 BRIEF 第 2 问里唯一一个「判定与写入确实同锁」的正面答案。
4. **device_code 的消费是单次**：批准后 16 个并发轮询里恰好 1 个看到 `Done`，其余 15 个
   「找不到记录」（`oidc.go:788-798` 在同一临界区内判定 + 删除）。这比现有的顺序 pin
   （C3-2）强，因为它证明的是「不可能两个轮询都 mint」。探针
   `TestDeviceCodeApprovalIsConsumedExactlyOnceUnderAGoroutineRace`。
5. **设备批准并发只有一个人能赢，且赢家 subject 一定是某个批准者**：`ApproveDevice` 的谓词
   （`d.done || d.denied || 过期` → `ErrDeviceNotFound`）与写入同锁，探针
   `TestConcurrentDeviceApprovalsProduceOneApprover` 观察到至多 1 次成功、状态里的 subject ∈ {usr_a, usr_b}。
   （与第三轮 C3-3 同源，此处只是把结论钉在并发形状上。）
6. **撤销在并发下既幂等又不破坏索引**：8 个并发 Kill Switch（`TokenFilter{}`）之后
   `Counts()` 的 access/refresh 都是 0，`Grants()` 为空。`RevokeTokens` 先**拷贝键集合**再删
   （`oidc.go:1153-1157` 的注释与 `accessKeysLocked` 等），避免了「边 range 边删索引内层 map」的风险；
   而 `TerminateSession`/`RevokeGrant` 确实边 range 内层 map 边删（`oidc.go:538-547`、:1100-1109），
   Go 允许在 range 中删除，且外层索引删除不影响正在 range 的内层 map——**成立，但值得留在守卫里**。
7. **四个后台循环都随 ctx 取消而返回，且各自的 ticker 都被 `defer Stop()`**：
   `opJanitorLoop`/`sweepLoop`/`anchorLoop`/`auditVerifyLoop` 逐一验证
   （`cmd/re0auth/zzprobe_conc_loops_test.go`），并且 `anchorLoop`/`auditVerifyLoop`
   在**启动时各跑一次**（不是只等第一个 tick），与 architecture.md §4.16 的说法一致。
8. **全仓库生产代码里没有「循环里的 `time.After`」，也没有未 Stop 的 ticker**：非测试文件中
   `time.After` 出现 0 次，定时器只有 `main.go` 的 4 个 `time.NewTicker`（都有 `defer ticker.Stop()`）
   与 `auditbatch.go:166` 的每批一个 `time.NewTimer`（同样 defer Stop）。`go func` 也只在
   `main.go`（serve + 4 个循环，全部进 `loopGroup`）、`killswitch.go:135`（有界 worker，`wg.Wait()` 收口）、
   `auditbatch.go:84`（由 `Close` 收口）出现。
9. **没有找到锁序倒置**：`federation.keyedMutex`（`refresh.go:223-246`）在 `k.mu` 下维护 refs、
   `e.mu` 才是业务锁，解锁函数先放 `e.mu` 再碰 `k.mu`，refs 归零才删条目，无泄漏、无自锁；
   `refreshBinding`/`Unbind`/`CascadeRevoke`/`shredBinding` 都取**同一把** per-binding 锁，
   `refreshRejected` 明确避免重入；持锁期间只碰到 binding store（叶子锁）与 vault/审计，
   没有反向路径持有它们再取 keyed 锁。`vault.Service.Use`（`vault/service.go:227-300`）**不持任何锁**
   跨越调用方回调，所以「vault.Use 回调里调 store」不会自锁（这正是 CM-1 里那种死锁的反面例子）。
10. **`oauth.Registry` 是无锁的，但生产里从不运行时改它**：`Register` 只在测试里被调用
    （`oauth/as_test.go`），`byScope` 的读路径 `Get`/`Resolve` 无锁是正确的——**这条要留守卫**，
    因为将来任何一处运行时 `Register` 都会让 discovery/consent/设备页读到并发写的 map。
11. **指标标签基数有界**：`observability.go` 的 method/grant_type/error code 三个自由值都有
    `normalize*` 归一化（:502-536），唯一的自由标签对 `(game, source)` 有「只能是配置过的源」的约束
    注释；度量本身没有无界增长。
12. **`oidchttp.discoveryCache` 只有 2 个固定键**（两条 discovery 路径都归一到 `OIDCDiscoveryPath`，
    `oidchttp.go:228-244`），且只缓存 200——不是「按请求路径缓存」的无界 map。
13. **审计假名缓存有界**（4096 后整体丢弃，`auditpseudo.go:144-151`）；`subjectKey` 会为任何
    subject 建行，但生产里流入审计的 subject 都是服务自己签发的 `usr_…`，攻击者不能自选。
14. **出站响应体全部被关闭**（`federation/service.go:509/544`、`revocation.go:85`），
    所以 `bulkheadBody` 的并发槽不会因为忘关 body 而泄漏。
15. **copy-on-return 做对了的那几处**（作为 CM-3 的对照，防止修 (a)(b) 时改错方向）：
    `AuthRequestByID`（:367）、`DeviceByUserCode`（:968 用 `d.state()`）、
    `SetIntrospectionFromToken`（:713 复制 scopes）、`Grants`（:1076-1081 复制值语义）、
    `federation.MemoryBindingStore.List/ListAll`（都新建切片）、`oauth.MemoryClientRegistry.List`
    （新建切片；但 `Get` 返回的 `Client` 结构体里 `RedirectURIs`/`Scopes` 两个切片仍是共享的——
    与 CM-3 同类、影响更小，因为库只比较不修改，**未单列**）。
16. **`internal/httpapi` 的限流键不可被调用方自选**（除非部署把 `trusted_proxies` 配错，这是文档化前提）：
    `clientAddr` 只在对端属于受信代理时才看 `X-Forwarded-For`，且从右往左走到第一个不受信跳
    （`clientaddr.go:23-75`）。

## 未能到达（残余盲区）

- **所有 Postgres 路径都没有执行**（本机无 Docker、无 Postgres）。受影响最直接的是 CM-1 的
  代价核算（1~4 次往返与链头行锁）——它是**读代码到行**，不是实测；`auditbatch` 的四条探针用桩
  `appendFn`，绕开了真库。`internal/store/postgres/sweep.go`、审计读 API 的分页缓存、
  `Sessions.SweepExpired` 的并发行为都未在本机验证。
- **`internal/httpapi` 自己的测试套件本轮跑不了**：当时另一个子代理的
  `internal/httpapi/zzprobe_adminpriv_test.go` 是非法 UTF-8（写入中间态），该包编译失败。
  我没有碰那个文件。因此 httpapi 层的会话存储/中间件并发只有读代码证据。
- **没有用 pprof / goroutine dump 抓泄漏**。CM-6 之外的 goroutine 泄漏结论都来自「每个 `go func`
  都有 ctx 或 channel 收口」的代码清点与逐循环的返回探针，不是运行时快照对比。
- **CM-3(c) 的数据竞争未构造生产路径**（只证明了指针外泄）。
- **没有跑 e2e / Playwright / 一致性套件**：它们与并发判定无关，且需要浏览器/DB。
- **`-race` 看不见本报告的大多数缺陷**：CM-1/CM-4/CM-5 是锁粒度与容量策略问题，
  CM-2 是上下文传播，CM-3 需要在探针里主动制造所有权限，都不是数据竞争。
  本报告里唯一的 `-race` 结论是「在 `memory`/`federation`/`oidchttp`/`cmd/re0auth` 上、
  在既有测试与我的探针下，没有检测到数据竞争」。

## 判断（文档化决定可否质疑，不是 finding）

- **限流器在容量处该如何失败，是一个裁定**：我给出的修法（活跃桶不可淘汰、新 key 在容量处以空桶入场）
  会把「容量耗尽」的代价从「静默重置别人的预算」转成「新客户端被拒」。另一种选择是保留淘汰、
  但把上限提高到「同时活跃 key 数」之上并显式记一条指标。两条都要有人定，我不替你定。
  这属于 CM-5 的**处置选择**，不影响 CM-5 作为缺陷成立。
- **内存 OP store 用一把全局互斥锁**：这是它所有并发性质（CM-1 的连锁代价、CM-4 的扫描成本）的
  共同根因。按账号/token hash 分片是更大的改动，属于路线裁定，不是这一轮该顺手做的事；
  但 CM-1 的修法（不要在被锁住的区段里做 I/O）**不需要**等待那个裁定。
- **审计是同步的、且在数据面关键路径上**：这是 `audit.Logger` 契约与 I3 的刻意设计
  （architecture.md §4.16），单独出现不是缺陷；本报告只针对「它在**别人的锁**里面被调用」这一点。
- **内存模式重启即丢**这条文档化取舍不覆盖 CM-4：丢数据是持久性问题，「匿名可把进程 OOM」不是。
  我把它当 finding 而不是 judgement，理由写在 CM-4 的「影响」里。
