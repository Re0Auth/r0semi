# 区域 Z15：性能 / 容量 / 内存 / 分配 — 第七轮审计报告

## 范围与方法

**范围**：全仓的**每操作分配量**与**复杂度类**。重点读 `internal/store/postgres/{sweep,postgres,oidc,auditbatch}.go`、
`internal/store/memory/oidc.go`、`internal/ratelimit/`、`internal/compress/`、`internal/httpapi/middleware.go`、
`internal/observability/observability.go`、`internal/oidchttp/oidchttp.go`、`postgres/migrations/*.sql`、
`cmd/re0auth/main.go` 的后台循环、`deploy/k8s/base/deployment.yaml`；对照了第五轮 PERF-1…PERF-12、
第六轮汇总、本轮 Z07/Z09/Z10/Z13，避免重报。

**方法**：只引**确定性**口径——`testing.AllocsPerRun` 的 allocs/call 与 `B/op`、同进程内两种规模的比值；
不引绝对墙钟（20 核、多代理并行）。每条断言写成不变量方向（违规即 FAIL），并配阳性对照；
对照不过 = 仪器坏了而不是结论成立。跨后端只比复杂度类，不比跨进程 ns。

**探针**：`internal/zzprobe/audit7/z15performancecapacity/`（`doc.go` 带 `!audit7`，测试带 `audit7`），6 探针 4 红 2 绿。

```sh
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z15performancecapacity/...
go build ./... ; go vet ./... ; go vet -tags audit7 ./internal/zzprobe/audit7/z15performancecapacity/...  # 全 exit 0
gofmt -l internal/zzprobe/audit7/z15performancecapacity/   # 空
```

FAIL 的四个：`TestZ15MemoryDeleteAuthRequestScalesWithEveryPendingCode`、`TestZ15SweepDeletesAreUnboundedAndAtomic`、
`TestZ15JanitorBenchmarkGuardIsVacuousAtSmallIterationCounts`、`TestZ15CompressionNegotiationAllocatesPerConfiguredCoding`。

---

## 发现

### Z15-1 过期清扫没有「每轮有界推进」：十条 `DELETE` 全无 `LIMIT` 且**同一事务**，只能「全删或全不删」；撞 30 s 语句超时后每个 tick 重试同一份越积越大的工作

- 严重度：**P2 中**（维护路径活性；「永远扫不掉」需真实库的积压规模；失败只落 Warn ⇒ §6 取本档上限）
- 类别：性能 / 可用性 ｜ 不变量：**性能·资源**——定时维护每轮必须做出**有界**推进，积压跨轮消化。
- 证据（执行过，FAIL；源级 + 行级）：
  - `postgres/sweep.go:26-37` 10 张表；`:59-66` 每表 `DELETE FROM %s WHERE %s < $1`，**无 `LIMIT`**；
    `:51`/`:67` 十条删除共用**一个** `Begin` 与**一个** `Commit`。
  - `cmd/re0auth/main.go:405` `sweepLoop(..., 15*time.Minute)`；`main.go:1101-1116` 失败只 `slog.Warn("expiry sweep failed")` 后 `continue`，下个 tick 重试同样语句。
  - 超时来自池：`postgres/postgres.go:128` `StatementTimeout: 30s`，每连接设 `RuntimeParams["statement_timeout"]`（`:235-246`）。
  - 实测：`CONFIRMED (source level): 1 DELETE template (10 tables) carries no LIMIT; LIMIT present=false; one transaction=true`。
    探针先证明 LIMIT 探测器能区分有/无 LIMIT，再要求解析出 10 条表项与循环形状，否则报「仪器坏了」。
  - 阳性对照：`memory/oidc.go:945-980` 是**逐条**删除，内存后端天然有界推进，Postgres 不是。
  - 十张表的 `expires_at` 索引齐备（`0001:65,76`、`0003:43`、`0008:30,40,50,65`、`0012:34,35`、`0017:13`，
    有 `sweep_test.go:TestEverySweptTableHasADeadlineIndex` 守着），所以问题不是「无索引顺序扫描」。
- 状态：**CONFIRMED（源级：无 LIMIT + 单一事务）**；**HYPOTHESIS**：单轮积压删除 > 30 s ⇒ 整笔回滚 ⇒
  该轮 `removed=0`、下轮重试（期间还在变大）⇒ 清扫**永久停摆**。需要真实 Postgres。
- 影响：一次长停机/故障期写入/连续 sweep 失败后，积压只能「一次全删（长事务、WAL 峰、撞 autovacuum）或永远删不掉」；
  停摆期间表持续增长，`docs/operations.md` 的保留期承诺失效。失败信号是 Warn + `exit 0`，
  `observability.go:109-139` 的 15 条业务指标里**没有** sweep 计数 ⇒ 停摆在告警面不可见
  （「失败只打日志」已由第六轮 G-2 记录，此处只作严重度依据，不重报）。
- 探针：`TestZ15SweepDeletesAreUnboundedAndAtomic`（红）
- 修法：每表改成有界批 `DELETE ... WHERE ctid IN (SELECT ctid FROM t WHERE expires_at < $1 LIMIT $2)`，
  以「每轮条数/时长预算」循环到 0；**每表一个事务**；导出 `sweep_removed_total` / `sweep_failed_total`。
- 相关编号：与 **G-2** 相关但不同（G-2 = 过期只由 sweep 裁决 + 失败只打日志；本条 = 每轮推进无界且原子）。第五轮 PERF 未覆盖。

---

### Z15-2 `BenchmarkTokenLifecycleWithJanitor` 的守卫在固定迭代数下**不可达**：`-benchtime=200x` 报 `peak_records=0` 且 **exit 0**，像一条「population 为零」的绿行

- 严重度：**P3 低/提示**（测量仪器缺陷；但「报成功、计数为 0、退出码 0」是 §6 要求升档的形态）
- 类别：可维护性 / 性能 ｜ 不变量：**性能·资源**——基准报告的容量界必须是它真测过的，守卫不得因迭代不足静默不执行。
- 证据（执行过，FAIL）：
  - `memory/oidc_bench_test.go:79-91`：采样 `store.Counts().Records()`、时钟推 31 天、
    `b.Fatal("the janitor found nothing to remove")` 全部在 `if i%sweepEvery == sweepEvery-1` 内，`sweepEvery=1024`（`:61`）。
  - 实测（真跑该基准并解析输出）：`peak_records: 2000x -> 2048 ; 200x -> 0`（200x 退出码 0）。
  - 反空转：2000x 必须给出非零 peak（2048）才继续，否则判「仪器坏了」。
- 状态：**CONFIRMED**
- 影响：`make bench`（默认 `1s`）在快机上能跨过 1024；但任何**固定次数**运行（`-benchtime=Nx`，本仓库探针与 `perfreport` 都用）
  打印 `peak_records 0`，会被读成「population 从未增长」。PERF-11 已指出该 fixture 回避真实保留形态；
  本条是更硬的缺口：连守卫本身都可以不跑。
- 探针：`TestZ15JanitorBenchmarkGuardIsVacuousAtSmallIterationCounts`（红）
- 修法：判据改成与 `b.N` 成比例（`|| i == b.N-1`，小 N 时至少跑一次 sweep+采样），或
  `if b.N < sweepEvery { b.Fatalf("benchtime too small to reach the janitor: N=%d", b.N) }`——宁可失败也别报 0。
- 相关编号：**对 PERF-11 的补充**（同一基准、不同机制）。

---

### Z15-3 内存 store 的 `DeleteAuthRequest` 在**全局锁**下遍历**全部待兑换 code**，而 Postgres 走 `oidc_codes(request_id)` 索引定向删除——同一协议操作两个后端复杂度不同，且它在授权码兑换路径上

- 严重度：**P3 低/提示**（仅内存后端，ADR-0006 决策 6 称其不提供生产保证 ⇒ 同第五轮对 PERF-5/6 的口径；
  但它落在**令牌签发**路径，且是同类的**第三处**未记录实例）
- 类别：性能 ｜ 不变量：**性能·资源**——按 id 解引用哈希索引记录应 O(1)，两个后端对同一 `op.Storage` 方法复杂度同类。
- 证据（执行过，FAIL + 读码到行）：
  - `memory/oidc.go:449-468`：`s.mu` 下 `for k, c := range s.codes { if c.requestID == id { delete(...) } }`；
    `s.codes` 按 `TokenHash(code)` 键控（`:43`/`:445`），**无 requestID 索引**，只能全表扫（扫的是所有人的未兑换 code）。
  - 频率：zitadel `pkg/op/token.go:50`（`CreateTokenResponse`）在 request 实现 `AuthRequest` 时**每次**调 `DeleteAuthRequest` ⇒ **每次授权码兑换**。
  - 对照：`postgres/oidc.go:288-299` 是定向 `DELETE ... WHERE id = $1`；`0012_indexes.sql:13`
    `CREATE INDEX oidc_codes_request_idx ON oidc_codes (request_id)` 正是为该查找而建。两后端不等价。
  - 实测（`Counts()` 为 O(1) 阳性对照；先断言 store 真有 N 条 code，且被测调用不改 population）：

    ```
    control Counts():              500 codes -> 0s       ; 50000 codes -> 0s
    DeleteAuthRequest(absent id):  500 codes -> 2.407µs  ; 50000 codes -> 256.576µs  (x106.6)
    ```
- 状态：**CONFIRMED**（不依赖真实库）
- 影响：内存模式下兑换一个 code 的代价随「他人 10 分钟窗口内未兑换的 code 数」线性增长，且持有每个已认证请求都要拿的 `s.mu`。
  PERF-5（`SweepExpired`）、PERF-6（`StoreDeviceAuthorization`）已记录同 store 另两处；本条是第三个实例，
  也是唯一**有 Postgres 对照实现却缺索引**的（内存侧只差一个 `codeByRequest map[string]string`）。
- 探针：`TestZ15MemoryDeleteAuthRequestScalesWithEveryPendingCode`（红）
- 修法：加 `codeByRequest`（requestID→TokenHash(code)），在 `SaveAuthCode`/`AuthRequestByCode`/`SweepExpired`
  三处与 `s.codes` 同一临界区维护；`DeleteAuthRequest` 变成一次 map 查找。**不要**改成延后到 sweep 删（语义变更）。
- 相关编号：**PERF-5/PERF-6 的同类第三例（新，非重报）**。

---

### Z15-4 `negotiate` 快速路径对**每个已配置 coding 重新 `strings.Split` 一次头部**：出厂 `[zstd, gzip]` 下最常见的 `Accept-Encoding: gzip` 每次请求白付一次切分

- 严重度：**P3 低/提示** ｜ 类别：性能 ｜ 不变量：**性能·资源**——一次请求解析一次头部，解析成本不应随**服务端** coding 数增长。
- 证据（执行过，FAIL）：
  - `compress.go:180-193`：无 `;`/`*` 的快速路径里 `offered(name)` 每调一次就 `strings.Split(header, ",")` 一次，
    而它按**服务端偏好**对每个 coding 调一次（`:189-193`）⇒ 客户端只写后面的 coding 时，前面的每个都要付一次切分。
    通用路径（`:199` `parseAcceptEncoding`）只解析一次。
  - 出厂接线 `httpapi/server.go:342-343` `Encodings: compress.Default()`，`encodings.go:40-42` = `[zstd, gzip]`
    ⇒ 正是「客户端写 gzip、zstd 在前」的最坏形状。
  - 实测（含「前置不匹配 coding 必须恰好 +1」的仪器对照）：`1 coding=16.0 allocs/req, 2 codings=17.0 (delta 1.0)`。
- 状态：**CONFIRMED**（真 handler + AllocsPerRun，出厂 coding 集）
- 影响：每次可压缩响应多 1 次小切片分配。业务面 SLO 是 p99 < 1 s，单请求 µs 级（PERF-12 已量化整条固定开销 ~30-40 allocs/req），
  这 1 alloc 不在预算内；记它是因为**成本随服务端配置增长**，将来加 `br` 会放大，而修法只有三行。
  同源小浪费：通用路径每次 `make(map[string]float64)`（`:245`），`qOf` 只查 2-4 个键。
- 探针：`TestZ15CompressionNegotiationAllocatesPerConfiguredCoding`（红）
- 修法：快速路径先切一次成 `[]string`（或手写 token 扫描）再 `EqualFold` 匹配；`offered` 接受预切切片。
- 相关编号：无（PERF-11 第 5 条只讲压缩端到端 CPU，未涉协商分配）。

---

## 探过但没破的（也应变成守卫）

1. **限流准入路径零分配**：`Check(tracked key): allocs/call=0.0, 0 B/op`，与 `ratelimit.go:69-82`
   「写死 FNV 以免每请求分配」一致。探针 `TestZ15RateLimiterCheckAllocatesNothing`（绿，含「真被放行且被跟踪」反空转）。
   这是每请求每平面唯一要过的锁，0 alloc 是它的设计承诺，应保留守卫。
2. **注册表列表读不交出内部切片**：覆写 `Sources("phigros")[0]` 后下一次读仍是 `src-00`。
   探针 `TestZ15RegistryListingCannotMutateTheRegistry`（绿）。日志里的 `4 allocs / 2360 B/op`
   是第五轮 **PERF-8** 已记录的「复制+排序」子项，**不重报**，只留数字便于复核。
3. **限流桶表在键喷射下有界**：复读 `ratelimit/zzprobe_concurrency_test.go:TestCapacityStaysBounded` 与
   `zzprobe/verifycm/cm5_ratelimit_test.go`（CM-5 量化）已覆盖，未重复探。
4. **压缩不对 4 MiB body 二次缓冲**：`compress.go:360-369` 首个 ≥minSize 的写直接进编码器，PERF-11 第 5 条已记录，复读确认成立。
5. **GOMEMLIMIT 已设且方向正确**：`deployment.yaml:60-61` `384MiB` / `:105` limit `512Mi`（PERF-1 建议已落地），未重测标定。

## 未能到达（残余盲区）

1. **真实 Postgres 的一切**（无 Docker/无本地 PG）：Z15-1 的「撞 timeout 后永久停摆」只能读码+算术；
   删除计划、长事务对 autovacuum 的影响、`sessions.go:148-153` 孤儿反连接的真实代价均未测。需 CI 的 `postgres:16`。
2. **GOMEMLIMIT 标定**：`384MiB` 与 `512Mi` 间那 128MiB 是否容得下 runtime+池+审计缓冲+数据面 64 MiB 在途 body，
   需真进程内存压力实测；本机 32GB 且并行代理多，做不出可引用的结论。
3. **连接池标定**：`postgres.go:125-131`（16/2）与 `max_in_flight=max(64,16×8)=128` 是否需重标，依赖真实往返延迟；
   PERF-8 已给「16 连接 × 12-15 往返」的算术，我无条件验证。
4. **`-race` 未跑**（会破坏本区的 ns 比值口径）；有竞争的路径已由第五/六轮探针覆盖。
5. 未跑全仓 `go test ./...`（简报 §2），只跑本目录与目标包定向基准。

## 判断（文档化决定可否质疑，不是 finding）

1. **内存模式按 ADR-0006 决策 6 排除生产保证**，故 Z15-3 定 P3。但**默认测试套件全跑内存后端**（第六轮 G-1 的教训）：
   只在内存后端成立的锁内 O(n) 既不会被生产掩盖、也不会被测试发现，只在有人拿内存模式跑较大流量时暴露。
   建议在决策 6 里写明「内存后端的复杂度类不保证与 Postgres 等价」。
2. **PERF-8 的 `Sources()` 复制+排序今天仍未修**：返回只读快照 + 构建期预排序即可，同时满足上面第 2 条守卫。
   不是新发现，只提醒它未闭环。
