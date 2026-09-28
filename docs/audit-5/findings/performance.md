# 性能 / 容量 审计报告

> 审计对象：`.`（Re0Auth，Go 1.27）。
> 本机事实：Windows 11，**没有 Docker、没有本地 Postgres**，Go 1.27.1 在 PATH，
> `E:\` 之外同时有约 11 个审计子代理在编译/跑测试。
> **因此：所有绝对 ns/op 都不作为容量数字引用**（机器有负载）。本文只引用三类数字：
> ① `B/op`、`allocs/op`（结构量，与机器负载无关）；② 同一次运行内的**相对倍数**；
> ③ **复杂度/量纲**（O(什么)、每请求往返次数、每记录字节数）。
> 每条结论都标注 CONFIRMED（跑过 / 行级确证）或 HYPOTHESIS。

## 范围与方法

**读了什么**（行级）：`internal/httpapi/{server,middleware,responses,v1_routes,grants_routes,
session_routes,export_routes,audit_routes,federation_routes,binding_routes,health,clientaddr}.go`、
`internal/oidchttp/oidchttp.go`、`internal/store/memory/oidc.go`、`internal/store/postgres/
{oidc,oauth,audit,auditchain,auditbatch,auditpseudo,auditread,sweep,sessions,federation,postgres}.go`、
`internal/ratelimit/ratelimit.go`、`internal/compress/compress.go`、`internal/federation/{service,refresh,
binding,missing,federation}.go`、`internal/oidcstore/oidcstore.go`、`httpclient/{outbound,retry}.go`、
`vault/{service,envelope}.go`、`cmd/re0auth/{main,config}.go`、`cmd/perfreport/main.go`、`Makefile`、
`.github/workflows/perf.yml`、`deploy/k8s/base/deployment.yaml`、`docs/{capacity-planning,slo,
resilience-decision,observability-decision,security-audit-2,security-audit-3}.md`。

**跑了什么**（全部命令与关键输出在下面各条里）：

```
go test -run '^$' -bench 'BenchmarkBusinessPlaneBearerMe|BenchmarkProtocolIntrospect|BenchmarkProtocolDiscovery' \
        -benchmem -benchtime=300x ./internal/httpapi/
go test -count=1 -run '^$' -bench BenchmarkIntrospectHandler -benchmem -benchtime=200x ./internal/oidchttp/
go test -count=1 -run '^$' -bench BenchmarkIntrospect    -benchmem -benchtime=200x ./internal/store/memory/
go test -count=1 -run '^$' -bench BenchmarkProbe -benchmem -benchtime=100x ./internal/zzprobe/perf/
go test -count=1 -run 'TestProbe|TestMemStore' -v -timeout 20m ./internal/zzprobe/perf/
go test -count=1 -run 'TestPerfProbe' -v -timeout 10m ./internal/store/postgres/
CGO_ENABLED=1 go test -race -count=1 -run TestConcurrentUseIsSafe ./internal/ratelimit/   # 通过
```

**没跑、也跑不了**：`make perf`（40 分钟，且本机在跑别的审计，40 分钟的数字是垃圾）；
任何 Postgres 路径（无 DB）；`make load`（`load_test.go` 自己会在 Windows 上耗尽临时端口，
文档 §1 也记了这件事——我只引用文档里那张表，不重跑）。

**行号时效性**：本次审计期间，其它审计代理正在改 `internal/httpapi/server.go`、
`internal/oidchttp/oidchttp.go` 等已跟踪文件（`git status` 显示 M）。本文的行号是**读取当时**的；
其中被本文最常引用的两处已在收尾时复核仍指向同一代码：`server.go:606`（plane 标签）、
`oidchttp.go:1173`（`Introspect`）。若日后行号漂移，以函数名/符号名检索为准。

**新增探针**（只新建文件，未改任何已跟踪文件）：
- `internal/zzprobe/perf/hotpath_test.go` —— 用**公开 API** 按 `cmd/re0auth` 的方式组合出完整服务器
  （memory OP + oidchttp + federation + vault + 一个可阻塞的 stub Doer），测真正的 httpapi 组合路径。
- `internal/zzprobe/perf/memstore_test.go` —— 内存 OP store 的 janitor / 设备授权 / 每 grant 字节数。
- `internal/store/postgres/zzprobe_perf_test.go` —— 审计批处理（`newAuditBatcher`）与审计链校验的**每行成本**。
  （Postgres 包内的探针，因为 `newAuditBatcher` 未导出；该目录下没有别人的 `zzprobe_*` 文件。）

---

## 发现

### PERF-1 数据面的「在途请求数 × 响应体」没有联合上限：默认配置下光响应缓冲就要 708 MiB，超过 512 MiB 的容器 limit
- 严重度: **阻断上线**
- 类别: 性能 / 可用性
- 不变量/性质: 「进程的最大常驻内存 ≤ 容器 limit」——目前没有任何一个旋钮或文档把
  `server.max_in_flight` 与 `federation.maxBody` 联系起来。
- 证据（CONFIRMED，实测）：
  - `internal/zzprobe/perf/hotpath_test.go:TestProbeInFlightBytesPerDataPlaneRequest`
    把 32 个 raw 代理请求**停在**上游读中间（每个都已读完 4.19 MB 体、持有自己的缓冲），
    停下来做一次 `runtime.GC()` 后读 live heap：
    ```
    body=4193280 bytes; live heap +185727880 bytes over 32 in-flight requests = 5803996 bytes/request
      max_in_flight= 64  ->    354 MiB of live response buffers alone
      max_in_flight=128  ->    708 MiB of live response buffers alone
      max_in_flight=512  ->   2834 MiB of live response buffers alone
    ```
    （`-run TestProbeInFlightBytesPerDataPlaneRequest -v`。）
  - 单请求分配量同样可观：`BenchmarkProbeRawProxy4MiB` = **10 022 610 B/op、252 allocs/op**
    （4.19 MB 的体，`io.ReadAll` 的几何增长把 2× 的垃圾一起算上）。
  - 默认值来源：`cmd/re0auth/config.go:311-312,329-338`（durable = `max(64, max_conns×8)` = **128**；
    内存模式 = **512**）、`cmd/re0auth/main.go:459-460`（出站 bulkhead 256，够不着）、
    `internal/federation/service.go:23`（`maxBody = 4<<20`）、`internal/federation/service.go:517,545`
    （两处 `io.ReadAll(io.LimitReader(...))` —— 都是**整体缓冲**，不是流式）。
  - `docs/capacity-planning.md:104-106` 自己承认「在途请求数 × 平均响应体是堆压力的主项」，
    但没有算这个乘法，也没有把两个数绑起来；k8s limit 是 `512Mi`（`deploy/k8s/base/deployment.yaml`）。
- 状态: CONFIRMED
- 影响: 一个慢（或挂起）的上游 + 128 个并发客户端（或一个刷子）= 128 × 5.8 MiB 的活缓冲，
  进程被 OOMKill。OOMKill 不是优雅退出：内存模式的会话/绑定、正在排队的审计行全部丢失；
  而且这只挡**入站**——出站 bulkhead 256 > 入站 128，所以永远不是先挡的那一层。
- 修法建议（裁定）: 需要一个**按字节**的共享预算，而不是只按请求数。最小改法：
  把 `max_in_flight` 按 plane 拆（数据面单独一个小上限，例如 16），并把 `maxBody` 降到
  512 KiB 级别；更好的改法是「在途 body 字节总量」信号量（进 ReadAll 前按 `Content-Length`
  预扣、流式转发时按块归还）。**要裁定的是**「整体缓冲以便把 >4 MiB 判成错误而不是截断体」
  这个决定（`internal/federation/service.go:510-527`）：它的替代方案是
  `Content-Length` 已知时预判 + 流式转发 + 中途超限直接断连，同样能保住「不把截断体当完整体」。
  这是裁定，不是 bug。
- 复现/守卫: `internal/zzprobe/perf/hotpath_test.go:TestProbeInFlightBytesPerDataPlaneRequest`
  （带反空转断言：每请求 live heap 必须 ≥ 体长的一半，否则说明探针没停在它声称的位置）、
  `:BenchmarkProbeRawProxy4MiB`。

### PERF-2 数据面单请求最长可到 80 s，而 `WriteTimeout` 是 60 s：客户端拿到的是断连而非错误体
- 严重度: **高**
- 类别: 可用性 / 性能
- 不变量/性质: 「每个响应都有明确的、客户端可解释的结束」——超时被截断成断连后，客户端无法区分
  「服务挂了」和「上游太慢」。
- 证据（CONFIRMED，行级算术 + 相对量）：
  - `cmd/re0auth/main.go:109`：`writeTimeout = 60 * time.Second`，注释明确说它是「为了覆盖出站客户端
    自己的 deadline」。但出站预算**不是**一个 20 s：
    - `internal/federation/service.go:228` 是**候选源循环**：每个资源可能有多个 active source
      （`candidates()` 返回全部声明了该资源的非 retired 源，`service.go:305-335`），
      每个候选单独走一遍 `trySource`（`service.go:278-300`）。
    - `internal/federation/refresh.go:193-210`：`callWithRefresh` 在取数前可能先刷新一次
      （`refreshBinding`，一次 token 交换），若取数拿到 401 则**再强制刷新一次并再取一次**。
    - 每次出站调用都受 `OutboundConfig.Timeout` = 20 s 约束（`httpclient/outbound.go:261`、
      `cmd/re0auth/main.go:459-460`），且 `Token()` 用的是同一个客户端。
  - 于是**单个候选**的最坏值是 20(刷新) + 20(取数) + 20(强制刷新) + 20(再取数) = **80 s**，
    已经超过 60 s；两个候选就是 160 s。
  - 附带澄清：任务书里假设的「20 s with retries」在本进程里**不存在**——`httpclient.Retry`
    只有 `cmd/referencesource` 用（`grep -rn "httpclient.Retry("`），re0auth 的出站客户端没有包重试。
    但上面的刷新/候选相乘起到了同样的效果。
  - 没有 handler 级总超时：整条链只有 `ReadTimeout` 30 s / `WriteTimeout` 60 s
    （`cmd/re0auth/main.go:705-718`），而入站 `max_in_flight` 只限**数量**不限**时长**，
    128 个慢请求可以各占 80 s 的一个 goroutine + 一个池连接 + 一个出站许可。
- 状态: CONFIRMED（算术在代码里闭合；绝对时长未实测，因为需要真上游/真 DB）
- 影响: 慢上游期间，数据面请求在 60 s 后连接被关，客户端拿到 `EOF`/`unexpected EOF`
  （若已开始写 body 则是**半截 body**）；同时服务端仍在为这个已经没人在等的请求工作，
  继续占着连接池、出站许可和审计批队列。运维侧看到的是「偶发 502/EOF，没有日志」。
- 修法建议: 在 handler 上装一个**总预算**（例如 25 s，明显小于 `WriteTimeout`），
  在候选循环里按剩余预算分配每次出站的 deadline（`context.WithTimeout` 包住 `Fetch`），
  预算耗尽就返回 `upstream_unavailable`。顺手把 `WriteTimeout` 的注释从「覆盖出站 deadline」
  改成「覆盖候选数 × 单源预算」。
- 复现/守卫: 代码路径 `cmd/re0auth/main.go:109` + `internal/federation/service.go:228,278` +
  `internal/federation/refresh.go:193-210`；建议加一条按剩余预算分配 deadline 的测试，
  用 stub Doer 记录每次尝试的 deadline 之和 ≤ 预算。

### PERF-3 审计批处理的 1 ms 收集窗口是「先审计后交付」路径的延迟下限；链头写入的吞吐天花板 = 64 / commit RTT
- 严重度: **高**
- 类别: 性能
- 不变量/性质: 不变式 I3（审计先于凭据交付，`vault/service.go:287-298`）把审计写放进了
  数据面读、令牌签发、撤销的关键路径；这条路径的延迟与吞吐必须被文档化并可观测。
- 证据（CONFIRMED，实测 + 行级）：
  - `internal/store/postgres/auditbatch.go:31-46`：`auditMaxBatch=64`、`auditBatchWait=1ms`、
    `auditBatchTimeout=5s`、队列 512；`flush()`（:160-194）**先开一个 1 ms 定时器再收行**，
    只有当批次满 64 才提前结束。
  - `TestPerfProbeAuditBatchLatencyFloor`（commit 即时返回）：
    `append with an instant commit: mean=1.577ms worst=1.98ms (batcher window=1ms)`
    → **每一个被审计的请求至少要等这个窗口**（实测均值 1.58 ms，因为窗口之后还有两次
    channel 传递与调度）。
  - `TestPerfProbeAuditBatchIsSingleWriter`（64 个并发写者，批次总是填满 64）：
    ```
    commit=1ms   3200 rows in  50 batches over    79ms =  40668 rows/s (avg batch 64.0, ceiling  64000 rows/s)
    commit=5ms   3200 rows in  50 batches over   269ms =  11900 rows/s (avg batch 64.0, ceiling  12800 rows/s)
    commit=20ms  3200 rows in  50 batches over  1.018s =   3144 rows/s (avg batch 64.0, ceiling   3200 rows/s)
    ```
    → **吞吐 = 64 / commit RTT，单写者，加并发无法提高**。而链头是 `audit_chain.only_row`
    的 `FOR UPDATE`（`auditchain.go:152-153`），行锁是**数据库全局**的，所以这个上限是
    **整个部署**的，不是每副本的（这一点 `docs/capacity-planning.md:128-139` 说对了，
    但它只给了「看拐点」，没给公式，也没给「每请求 +1 ms」这个常数）。
- 状态: CONFIRMED
- 影响: ① 数据面读、令牌签发、撤销的 p50 不可能低于 1 ms + commit RTT（实测下限 1.58 ms）；
  ② 审计写是全部署串行点，吞吐随 commit RTT 线性下降（Postgres commit ~2-5 ms → 13k-32k 行/s
  全部署）；③ `auditBatchTimeout=5s` 一到，批次失败 → 被审计的操作**失败关闭**（这是好的方向），
  表现为 5xx 风暴而不是排队。④ 关键：`re0auth_audit_append_duration_seconds` 是**唯一**能看到
  这件事的信号，而它在数据面 SLO 里不出现（`docs/slo.md` 的 S4 只有 HTTP 直方图）。
- 修法建议: 把窗口做成可配置或自适应（队列有积压就立即 flush，即 `len(queue)>0` 时不再等），
  并在 `docs/capacity-planning.md §4` 写上 `吞吐 ≈ auditMaxBatch / commit RTT` 与
  「每个 audited 请求 +auditBatchWait」这两条，让「加副本有没有用」这个问题有公式可算。
- 复现/守卫: `internal/store/postgres/zzprobe_perf_test.go:TestPerfProbeAuditBatchLatencyFloor`
  （断言均值 ≥ 窗口：若有人删掉窗口，这条会失败并要求同步文档）、
  `:TestPerfProbeAuditBatchIsSingleWriter`、`:BenchmarkPerfProbeAuditBatchCeiling`。

### PERF-4 `GET /v1/admin/audit/verify` 是全表同步扫描，从约一千万行起就不可能完成：S5 的「大表分支」永远只能报 error
- 严重度: **高**
- 类别: 可用性 / 合规（S5 是硬目标）
- 不变量/性质: S5「审计链完整性恒为 0 failed」要求校验**能跑完**；跑不完时
  `result="error"`（`cmd/re0auth/main.go:979-1002`），而文档自己把 error 定义为 S5 的盲区
  （`docs/slo.md:20-21`）。
- 证据（CONFIRMED，实测每行成本 + 行级）：
  - `TestPerfProbeVerifyExtrapolation`：`verify: 1.467µs/row, 681394 rows/s single core`，
    外推（**纯 CPU，不含从 Postgres 读行**）：
    ```
    1e+05 rows: 0s / 1e+06 rows: 1s / 1e+07 rows: 15s / 1e+08 rows: 2m27s
    ```
  - `internal/store/postgres/auditchain.go:199`：`verifyStatementTimeout = 45 * time.Second`；
    `Verify`（:220-331）用 `SELECT ... FROM audit_events ORDER BY id`（:243-247）读**每一行**，
    而且**每次开机就跑一次**（`cmd/re0auth/main.go:961-963` 的 `auditVerifyLoop` 先执行
    `verifyOnce` 再进 ticker），随后每 6 小时一次；同一条路径挂在一个**同步 HTTP 端点**上
    （`internal/httpapi/audit_routes.go:137-159`，`AuditReader.Verify`）。
  - 也就是说：1e7 行时 CPU 已经吃掉 45 s 预算的三分之一，加上把每行 10 列读出来、
    `canonical()` 每行再分配一个 `bytes.Buffer`（`auditchain.go:56-82`），实际穿线远早于 1e8 行。
- 状态: CONFIRMED（每行成本实测；交叉行数未在真库上验证）
- 影响: ① 表一大，S5 从「硬目标」变成一个永远在报警的 `error` 序列
  （`Re0AuthAuditVerifyError`），运维学会忽略它 = 链被改动也看不见；
  ② 每次滚动发布、每次 CrashLoop 重启都会立刻再跑一次全表扫描，占一个池连接最多 45 s，
  正好在 `maxUnavailable: 0` 的窗口里和 `/readyz` 抢连接；
  ③ 同步端点本身也是「一个 operator 手滑就能给 DB 施压 45 s」的形状。
- 修法建议: 改成分段校验：持久化 `(last_verified_id, last_verified_hash)`（可作为
  `audit_chain` 的第二列），每次只校验新增行，并用锚点循环（已有，1 小时）覆盖尾部；
  或者把 verify 从同步端点改成后台任务 + 缓存结果（端点只读结果）。任一改法都需要
  一次裁定，因为「校验到哪一行」本身是新的持久状态。
- 复现/守卫: `internal/store/postgres/zzprobe_perf_test.go:TestPerfProbeVerifyExtrapolation`
  （断言 1e8 行的估计值 > 45 s，若哪天每行成本降 10 倍，这条会失败并要求更新容量说明）、
  `:BenchmarkPerfProbeVerifyRowCost`。

### PERF-5 内存模式：janitor 在**单一全局锁**下扫描全部存活记录，而存活量由 30 天 refresh TTL 决定
- 严重度: **中**（内存模式；但项目把内存模式当作真 OP 的一种部署形态，文档也拿它做容量上界）
- 类别: 性能 / 可用性 / 文档一致性
- 不变量/性质: 「扫除的成本由扫描间隔界定」——实际由**最长 TTL × 到达率**界定。
- 证据（CONFIRMED，实测 + 行级）：
  - `internal/store/memory/oidc.go:843-878`：`SweepExpired` 在 `s.mu` 下依次遍历
    `authRequestExpiry`/`codes`/`accessTokens`/`refreshTokens`/`devices`，全部是 O(记录数)。
  - `TestMemStoreSweepIsProportionalToLiveRecords`：
    ```
    records=  40000  sweep=   1.041ms  per_record=  26ns
    records= 200000  sweep=   6.014ms  per_record=  30ns
    ```
  - `TestMemStoreSweepStallsConcurrentRequests`（8 个并发 introspect 者，测最差单请求延迟）：
    ```
    records= 100128 requests=  155241  sweep=     3.9ms  worst_before=   1.124ms  worst_during=     3.9ms
    ```
    → 扫描时长**原封不动**变成并发请求的最差延迟（store 的锁就是每个已认证请求要拿的那把锁）。
  - 存活量：`refreshTTL = 30*24h`（`memory/oidc.go:307`），`opJanitorInterval = 5min`
    （`cmd/re0auth/main.go:80`）。**扫除间隔只界定「过期后多久被删」，不界定存活量**；
    30 天内签发的 grant 都还在（每条 2 个记录）。
  - 项目自己的基准**恰好绕开了这一形态**：`internal/store/memory/oidc_bench_test.go:60-88`
    每 1024 条把假时钟推进 31 天，于是每次扫除都「有活干」、population 永远归零，
    注释还写着「population stays bounded by the sweep interval, not by how long the process
    has been running」——对 refresh token 这句是**错的**。
  - 内存量：`TestMemStoreBytesPerGrant`：`heap=44616800 bytes for 50000 grants (100000 records):
    892 bytes/grant, 446 bytes/record`，外推
    `at 1 grants/s, 30 days = 5.18e+06 records = 2206 MiB of store`。
- 状态: CONFIRMED
- 影响: ① 内存模式下 janitor 每 5 分钟制造一次与 store 锁等长的全局停顿（10 万记录 ≈ 3.9 ms，
  260 万记录 ≈ 78 ms，10 grants/s 时 ≈ 780 ms），期间**所有**已认证请求排队；
  ② 保留量按 30 天增长：512 MiB limit 大约只能承受 **每 4 秒 1 次授权**（892 B/grant ×
  30 天）；超过就是 OOMKill，而没有任何文档/告警说这件事；
  ③ `docs/capacity-planning.md:102-106` 把内存主项说成「连接缓冲与并发请求的响应体」，
  对内存模式是错的。
- 修法建议: 把过期判断改成按 deadline 有序的结构（每个 TTL 一个最小堆/分桶），或把扫除分片
  并把删除移出锁；`docs/capacity-planning.md §3` 补上内存模式的保留量模型与算例；
  `oidc_bench_test.go` 的 fixture 增加一个**不推时钟**的 population 场景（真实形态）。
- 复现/守卫: `internal/zzprobe/perf/memstore_test.go:TestMemStoreSweepIsProportionalToLiveRecords`、
  `:TestMemStoreSweepStallsConcurrentRequests`、`:TestMemStoreBytesPerGrant`
  （三条都带反空转断言：population 必须真的到位，且 swept 必须为 0——证明扫的是全表而不是碰巧命中）。

### PERF-6 内存模式 `StoreDeviceAuthorization` 每次插入前扫描全部 device 记录：O(live) 且持全局锁，10 分钟窗口内 N 次到达 → O(N²) 总扫描量
- 严重度: **中**
- 类别: 性能（内存模式）
- 不变量/性质: 「插入一个设备授权码的成本与已有设备数无关」。
- 证据（CONFIRMED，实测 + 行级）：
  - `internal/store/memory/oidc.go:753-767`：`StoreDeviceAuthorization` 先调
    `purgeExpiredDevicesLocked`（:818-828，遍历 `s.devices` 全表），且在 `s.mu` 下。
  - `TestMemStoreDevicePurgeIsPerInsert`：
    `StoreDeviceAuthorization: 0s/call at ~200 live, 259µs/call at ~20400 live`
    → 插入成本随存活设备数线性增长（约 250×）。
  - 对照：Postgres 版是**单条 INSERT + 唯一索引冲突判定**（`internal/store/postgres/oidc.go:636-647`），
    没有扫描。两个后端在这一点上不等价。
  - 设备 TTL 是 10 分钟（`oidchttp.go:161-166`），所以「存活集」= 10 分钟窗口内的到达量；
    一个 client（或一群地址）以 100/s 打 `/oauth/device_authorization` → 窗口内 6 万条，
    每次插入扫 6 万条（≈ 2 ms）且**在全局锁内**，等于把整个 store 拖慢到毫秒级。
- 状态: CONFIRMED
- 影响: 内存模式下，一个已注册 client 就能把 store 全局锁打成一串 2 ms 的持有段，
  所有已认证请求的延迟一起上去；限流是**按地址**的（`server.rate_limit` 默认 50/s burst 100），
  多地址即可放大。不构成数据泄露，是可用性。
- 修法建议: 把过期清理从插入路径挪到 janitor（内存版原本就有 5 分钟 janitor 调 `SweepExpired`），
  或按 expiresAt 分桶；插入路径只做一次 map 写入。
- 复现/守卫: `internal/zzprobe/perf/memstore_test.go:TestMemStoreDevicePurgeIsPerInsert`。

### PERF-7 每个已认证 `/v1` 请求在「解析自己签发的 opaque 令牌」上分配约 12 KB，**仍在延迟预算余量内**
- 严重度: **低（提示）** — 这是一条成本观察，不是缺陷：没有 SLO/CI 门槛被它触及，见下「影响」。
- 类别: 性能
- 不变量/性质: 业务面每请求成本预算：令牌解析应当是常数级的小操作，而不是通用 JWE 解析。
- 证据（CONFIRMED，实测 + 行级 + profile；**只引同一次运行内的分配口径**）：
  - `internal/oidchttp/bench_test.go:BenchmarkIntrospectHandler`（隔离：解密 bearer + store 查询）：
    `12208 B/op`、`131 allocs/op`；
    同一个令牌在 store 层的成本（`internal/store/memory/oidc_bench_test.go:BenchmarkIntrospect`）
    是 `192 B/op`、`4 allocs/op`。
    → **每请求分配约 12 KB，其中 store 查询占约 1.6%**（`B/op` / `allocs/op` 与负载无关，可跨
    二进制引用）。ns 数**不**并排引用：两个基准来自不同测试二进制、不同负载，比值不成立。
  - 端到端：`BenchmarkBusinessPlaneBearerMe` = **19.3 µs/op、14 910 B/op、180 allocs/op**；
    `-memprofile` + `go tool pprof -top -sample_index=alloc_space` 归因
    `oidchttp.(*Handler).Introspect` 累计 23 557 kB / 2000 次 = **11.8 kB/请求**，
    其中 `go-jose/v4/json.Unmarshal` 3.8 kB、`rawHeader.merge`、`reflect.unsafe_New`、
    `base64.DecodeString`、`aes.New`/`gcm.New` 各占一截。
  - 原因在依赖里：zitadel 的 `aes256GCMCrypto` 用 `jose.ParseEncrypted(...)` + `jwe.Decrypt()`
    解析 compact JWE（`$GOMODCACHE/github.com/zitadel/oidc/v3@v3.51.3/pkg/op/crypto.go:51-83`），
    即「JSON 头反序列化 + 反射 + base64 + AES-KW unwrap + AES-GCM」——而我们的令牌
    实际上只是一个 AES-256-GCM 加密的 `id:subject` 串，**只有本服务会读它**。
  - 另外 `Encrypt` 里是**每次调用都 `jose.NewEncrypter`**（同文件 :52），令牌签发路径也吃这个。
- 状态: CONFIRMED（机制与分配口径）。**「97%」这一条已撤回**：它是两个跨进程基准的 ns 比值，
  违反报告自己定的「只引同一次运行内的相对倍数」，不构成结论。
- 影响（**账目算清**）：每请求约 12 KB 分配、约 10 µs 级 CPU。但业务面的 SLO 是
  **S4: p99 < 1 s**（`docs/slo.md`），而单请求处于 **µs 级**——距 1 s 预算还有
  **约 10⁴ 倍以上余量**。CI **不按阈值卡基准**（ADR-0007 决策 5，`.github/workflows/perf.yml`），
  所以这条**没有任何门槛被触及**。量级推演（非当前负载）：10k RPS ≈ 120 MB/s 分配速率、
  约 11% 一个核心（未计 GC）——只有在业务真到达那个量级时才值得立项，见「修法建议」。
- 修法建议（本报告的建议：**维持原状**）：继续使用 go-jose 这一大厂背书的 JWE 标准库，
  享受其算法固定（`A256GCMKW`+`A256GCM`）与解析硬化；**不改代码**，也不自造加密轮子
  （`docs/dependencies.md` §1「密码学不自己写」）。
  - 为什么不在此时动：`op.WithCrypto`/`op.NewCompositeCrypto`（`oidchttp.go:190-196`）确实是
    可替换的缝，但 ① 自写 `Encrypter/Decrypter` 把安全属性换成自己的几十行，代价是密码学风险；
    ② 缓存 `jose.Encrypter` 对解密路径一点没省；③ 换令牌载体（纯随机串 + DB/Redis 查找）是
    **语义变更**，要每次请求一次额外往返，且丢掉令牌自证 `id:subject` 的抗篡改——更大的架构决定，
    且从未被论证。
  - **立项门槛（备忘）**：仅当业务量真的上到「分配/延迟进入 SLO 预算」时再立项，届时优先讨论
    「换令牌语义（随机串 + Redis/DB 查找）」，而不是自造 AES-GCM。
- 复现/守卫: `internal/oidchttp/bench_test.go:BenchmarkIntrospectHandler`（项目自己的基准，
  我把它的数字与 store 层的 `BenchmarkIntrospect` 并排读，只取 `B/op`/`allocs/op`）；端到端见
  `internal/httpapi/bench_test.go:BenchmarkBusinessPlaneBearerMe`。

### PERF-8 数据面每请求成本实测：210 allocs / 29.7 KB（4 KiB 上游体），比被基准覆盖的 `/v1/me` 贵约 2 倍；Postgres 模式下每请求另有 7 次往返
- 严重度: **中**
- 类别: 性能
- 不变量/性质: 「被基准覆盖的路径 = 热路径」——目前覆盖的不是最贵的路径。
- 证据（CONFIRMED，实测 + 行级查询计数）：
  - `BenchmarkProbeDataPlaneResource`（真实 federation Service + vault + stub Doer，4 KiB 活体）：
    `26 705 ns/op  29 652 B/op  209 allocs/op`；raw（4 KiB）：`232 allocs/op`；
    raw（4 MiB）：`10.0 MB/op`（PERF-1）。
  - 同一个探针里 `/v1/me` = 184 allocs / 19.7 KB（含 fixture 的 `httptest.NewRequest`），
    与项目自己的 180 allocs / 14.9 KB 一致。
  - Postgres 模式下一次规范化数据面读的**调用数**（行级）：
    `Bindings.Get` 1 次（`store/postgres/federation.go:20-33`）→
    `vault.Use` → `Vault.Get` 1 次 + **审计写 1 个事务**（`SELECT head FOR UPDATE` +
    批量 INSERT + `UPDATE audit_chain`，`auditchain.go:152-182`，事务内 4 条语句）→
    出站 1 次 HTTP。若触发刷新再 +2（binding 读 + 更新）+ 1 次上游 token 交换。
  - `/oauth/token`（授权码）：`AuthorizeClientIDSecret`→`Clients.Get`（1）、
    库的 client 解析再一次 `Get`（1）、`AuthRequestByCode` 事务 4 条
    （`postgres/oidc.go:186-217`）、`CreateAccessAndRefreshTokens` 事务 3-5 条（:339-373）、
    审计事务 4 条 → 约 **12-15 次往返**；内存模式实测 `BenchmarkProbeTokenExchange`
    = **637 µs、38 645 B/op、394 allocs/op**（本机有负载，看 B/op 与 allocs）。
  - 次要但真实的每请求浪费：`Registry.Sources(game)` 每次调用都**复制 + 排序**
    （`internal/federation/federation.go:234-238`），而一次数据面读会调它两次
    （`service.go:206-213` 的 `ResourceScope` 与 `service.go:305-335` 的 `candidates`）；
    `candidates()` 还额外 `sort.SliceStable`（反射，`service.go:333`）。
    `rawDownloadName` 每请求构造一个 `[]byte`；`addVary` 每响应一次 `append`+`Join`。
- 状态: CONFIRMED
- 影响: 数据面是**最贵**的路径，却是唯一没有任何基准覆盖的路径（见 PERF-9b）。
  它的 postgres 往返数是 `/v1/me`（1 次）的 ~10 倍，且在 `max_conns=16` 下，
  16 个池连接 × 12-15 次往返 ≈ 每秒几百次数据面请求就把池排满。
- 修法建议: 给数据面一个基准（已经有 `BenchmarkProbeDataPlaneResource` 可作起点）；
  `Sources()` 的复制+排序改成构建期预排序 + 返回只读切片；
  `Grants`/`Resolve` 这类小切片排序换成 `slices.SortFunc`。
- 复现/守卫: `internal/zzprobe/perf/hotpath_test.go:BenchmarkProbeDataPlaneResource`、
  `:TestProbeHotPathAllocationBudget`。

### PERF-9 容量文档与实测/实现不一致（四处）
- 严重度: **中**（launch risk：运维按文档算容量会算错）
- 类别: 可维护性 / 合规（文档即发布物）
- 证据（CONFIRMED，行级）：
  - **(a) 同一文档自相矛盾**：`docs/capacity-planning.md:20` 的表把 `server.max_in_flight`
    默认值写成 **512**，而同一文件 §4（:113）写「缺省值 = max(64, max_conns × 8)（默认池 16 → **128**）」。
    实现站在 §4 这边（`cmd/re0auth/config.go:302-312,329-338`：durable 派生 128，
    内存模式 512）。表里那行是错的。
  - **(b) 「三个基准对应三条热路径」已过期**（`docs/capacity-planning.md:28-29`）：
    `make bench` 现在跑 `./...` 的全部基准，`perf.yml:76-88` 自己写着「16 条结果/次」。
    更重要的缺口：**没有任何基准覆盖 `/oauth/token`（实测 394 allocs / 38.6 KB，是所有被
    覆盖路径里最贵的）与数据面**，而 `docs/capacity-planning.md` 的容量画像
    （`load_test.go`）只打 `/v1/me` 与 `/oauth/introspect` 两个端点。
  - **(c) §3 的内存模型对内存模式是错的**：见 PERF-5（真正主项是 OP store 的 30 天保留）。
  - **(d) §4 只说「看拐点」，没有公式**：见 PERF-3（实测天花板 = 64/commit RTT，
    每请求 +1 ms）。
- 状态: CONFIRMED
- 影响: 按文档算「一个副本能扛多少」时，(a) 会把入站并发算错 4 倍，(b) 会把数据面与签发路径
  完全排除在容量画像之外，(c) 会让内存模式的扩容决策基于错误的内存模型。
- 修法建议: 改这四处；把本报告的三个探针里能长期保留的两个（审计批天花板、数据面分配）
  接进 `make perf` 的基准集合，让 (b) 的缺口有人守。
- 复现/守卫: 行级引用如上；`internal/zzprobe/perf/*` 与
  `internal/store/postgres/zzprobe_perf_test.go:*` 可作为新基准的来源。

### PERF-10 S4（业务面 p99 < 1 s）与数据面 20 s 单源预算不自洽，且信号不可区分
- 严重度: **低**
- 类别: 可维护性 / 可用性（SLO 自洽性）
- 证据（CONFIRMED，行级）：`docs/slo.md:14` 定义 S4 为
  `http_request_duration_seconds{plane="business"}` 的 p99 < 1 s；`plane` 标签由
  `httpapi/server.go:606` 的 `planeOf` 给出，`/v1/games/...` 与 `/v1/me` **共用同一个序列**
  （`internal/observability/observability.go:97-102` 只有 plane/method 两个标签）。
  而数据面单源预算是 20 s（PERF-2），最坏更大。
- 状态: CONFIRMED
- 影响: 一个慢数据源就能把业务面 p99 推过 1 s，触发 `Re0AuthSlowRequests`，
  而运维从这个指标**无法**判断是认证读变慢还是代理源变慢；反过来，如果只按 S4 判扩容，
  会被代理尾延迟牵着加副本，而副本对上游慢毫无帮助。
- 修法建议: 给 `http_request_duration_seconds` 增加一个受控的 `route` 标签
  （按注册的 pattern 归一，例如 `/v1/games/{game}/{resource}`；**不要**用原始路径），
  或把数据面的上游延迟（已有 `upstream_fetch_duration_seconds`）写进 S4 的分母说明里。
  这是裁定：加标签会改变现有看板与告警选择子。

### PERF-11 基准作为测量仪器的缺口（不是「没有断言」——项目明确不 gate，那是刻意的）
- 严重度: **低**
- 类别: 可维护性
- 证据（CONFIRMED，行级）：`Makefile:44-51`、`docs/capacity-planning.md`、
  `internal/observability/observability.go`（ADR-0007 决策 5：CI 不按阈值卡基准）。
  我逐条看了 16 条基准，**仪器本身是合格的**：`BenchmarkBusinessPlaneBearerMe` 把
  `Handler()` 提出循环（注释里说明路由注册曾是最大消耗）、`BenchmarkGrantsAtScale` 断言
  `len(grants)==1`、`BenchmarkTokenLifecycleWithJanitor` 断言 sweep 有活干、
  `TestLoadProfile` 有 `total < 100` 的反空转下限、`perfreport` 对「什么都没测到」会失败。
  真正的缺口是**覆盖**：
  1. 无 `/oauth/token`（签发/刷新/轮换，实测最贵：394 allocs）；
  2. 无数据面（4 MiB 体、vault、审计批、出站）；
  3. `BenchmarkTokenLifecycleWithJanitor` 的 fixture 回避了真实保留形态（PERF-5）；
  4. 容量画像只有两个端点，`/v1/grants`、`/v1/bindings`、同意页、`/healthz`、404 无并发画像；
  5. 压缩只有 `internal/compress` 的单写基准，没有端到端：我实测 4 MiB gzip 让单请求
     从 1.68 ms → 5.69 ms（**相对 3.4×，机器有负载，只当倍数看**），即每 4 MiB 响应
     约 4 ms 的 deflate CPU —— 在 1 CPU limit 下，这本身就是每秒约 250 个响应的上限；
  6. 空闲/后台成本没有被测：进程空闲时只有 4 个 loop（15 min sweep、1 h anchor、
     6 h verify、内存模式 5 min janitor）在 ticker 上阻塞等待，CPU 应为 0——
     **这是探过没破的**（见下节）；真正的空闲风险是 PERF-4 的「启动即全表校验」。
- 状态: CONFIRMED
- 修法建议: 见 PERF-9(b)。另外 `perfreport` 的 Reading notes 说审计链基准「run against a
  real Postgres service」，但 `make perf`（本地等价命令）没有 `TEST_DATABASE_URL`，
  本地跑时它们是 skip——报告里不会出现 skip 行，这条 note 在本地是误导（`perf.yml` 里有
  service，所以 CI 是对的；本地不对）。

### PERF-12 每请求固定开销的明细（含 404 与探针）
- 严重度: **提示**
- 类别: 性能
- 证据（CONFIRMED，实测；**未扣 fixture**：每个 case 都重建 `httptest.NewRequest`，
  约 20-25 allocs / 5-6 KB 是夹具的）：
  ```
  404 (browser plane)                  status=404 body=10     bytes/req=  6112.3 allocs/req=  34.0
  404 (/v1 subtree)                    status=404 body=193    bytes/req=  6827.6 allocs/req=  40.1
  /healthz                             status=200 body=3      bytes/req=  5896.2 allocs/req=  28.0
  /.well-known/openid-configuration    status=200 body=1190   bytes/req=  6194.6 allocs/req=  30.1
  GET /v1/me (opaque bearer)           status=200 body=88     bytes/req= 19670.2 allocs/req= 184.2
  GET /v1/me (invalid bearer)          status=401 body=236    bytes/req=  7332.3 allocs/req=  48.2
  GET /v1/games/phigros/score          status=200 body=4102   bytes/req= 35702.1 allocs/req= 221.4
  GET /v1/games/.../raw (4KiB)         status=200 body=4102   bytes/req= 35987.4 allocs/req= 232.4
  ```
  逐项（行级）：`withRequestContext` 每请求 2 次 `crypto/rand`（12 B + 16 B）+ 2 次 hex +
  1 次 `context.WithValue` + 1 次 `r.WithContext` 复制（`middleware.go:136-156`）；
  `clientAddr` 一次 `SplitHostPort` + `netip.ParseAddr` + `String()`
  （`clientaddr.go:23-36`，**每个请求都跑，包括 404**）；`withAccessLog` 10 个 attr +
  Info 级一行（`middleware.go:245-267`，20k RPS ≈ 2-4 MB/s 日志）；`withSecurityHeaders` 4-5 次 `Set`；
  metrics 4 次 `WithLabelValues`（`observability.go:288-300`）。
  一个**好**的细节：`/healthz`、`/readyz` 被访问日志降到 debug 且豁免限流/在途上限
  （`health.go:69-77`），探针不会把桶打空、也不会把日志刷满。
- 状态: CONFIRMED
- 影响: 404/探针这类无成本路径被服务端自己花了 ~15-20 allocs / 数百 ns；
  不构成风险，但在 S1（可用性）被扫描流量打的时候，固定开销 × 扫描 QPS 是真实的 CPU 消耗。
- 修法建议: 低优先。若要做：`traceIDFromTraceparent` 用 `strings.Cut`
  而不是 `strings.Split` + 3 次 `hex.DecodeString` + `strings.Repeat`（仅带 traceparent 时）；
  `clientAddr` 对探针/静态资源短路。**不建议**为此改动架构。

---

## 探过但没破的（这些也应变成守卫）

1. **压缩中间件对 4 MiB 不二次缓冲**：raw 4 MiB + `Accept-Encoding: gzip` 时
   `B/op` 从 10.02 MB → 10.63 MB（只多了 deflate 输出与池化 writer），
   说明 `compress.go:365-369` 的「首次 Write 已 ≥ minSize 就直接进编码器」这条路径是对的。
   关联到 BREACH 的设计（协议面不压缩）也在线（`server.go:327-329` 用同一个 `planeOf`）。
2. **限流器确实每次只拿一把 shard 锁**：`ratelimit.go:179-202` 一次 `shardFor` + 一次
   `s.mu.Lock`（内部 `rate.Limiter` 另有 3 次自己的锁，但分片 16，不构成全局争用）；
   `Check` 同时给出 verdict + 三个 header，文档 §「一次调用一把锁」成立。
   容量极限路径（到 maxKeys 后的插入）是有界扫描（`evictionScan=64`），不是全表
   （`ratelimit_test.go:BenchmarkCheckAtCapacity` 就是这个性质的仪器）。
3. **`/v1/grants` 没有 N+1**：Postgres 是 1 条 UNION ALL + 1 条批量 name 查询
   （`postgres/oidc.go:818-885`）；内存版用 subject 索引，与总 token 数无关
   （`memory/oidc.go:1025-1084`，`BenchmarkGrantsAtScale` 钉住）。
4. **审计分页是 keyset 不是 OFFSET**（`auditread.go:75-84`），
   Kill Switch 的绑定扫描也是 keyset（`federation.go:109-126`），
   两者都不会随表增长而变慢到平方级。
5. **全部 10 张被 sweep 的表都有 expires_at 索引**：`oauth_codes`/`oauth_device_authorizations`
   （0012）、`oauth_access_tokens`/`oauth_refresh_tokens`（0001）、`oidc_*`（0008）、
   `oidc_devices`（0017 补的）、`federation_bind_flows`（0003）、`sessions`（0004）、
   `session_subjects.created_at`（0019）→ `sweep.go:26-37` 的 `DELETE ... WHERE col < $1`
   是范围扫描，不是每 15 分钟一次全表扫描。**这一条我原本怀疑是容量杀手，读完迁移后否掉了。**
6. **没有每请求 `regexp.MustCompile`**（全仓只有测试文件里有 `MustCompile`）。
7. **没有无 `LimitReader` 的 `io.ReadAll`**：federation 两处都有上限
   （`service.go:517,545`）。
8. **空闲成本接近 0**：4 个后台 loop 都在 `time.Ticker` 上阻塞，不轮询、不持有锁；
   metrics collector 只在 scrape 时跑函数。唯一的空闲期风险是 PERF-4（启动即全表校验）。
9. **`-race` 在这台机器上可用**（`CGO_ENABLED=1 go test -race ... ./internal/ratelimit/` 通过），
   但本报告没有跑全仓 `-race`（会与其他 agent 的探针互相干扰，且不在我的区域内）。
   —— 所以本文的并发结论**没有**竞态检测器背书，它们是「锁的粒度」分析。

## 未能到达（残余盲区）—— 必须写

- **没有 Postgres**：所有「每请求多少次往返」「哪个索引会被选中」「`FOR UPDATE` 的实际排队
  长度」「`Verify` 的流式读取速度」都只是**读代码**。审计批的 commit RTT 是我用 `time.Sleep`
  注入的参数（这正是它能被当成自变量列表的原因），**不是**真实 Postgres 的 commit 延迟。
- **没有真实上游**：数据面的探针用 stub Doer，所以 DNS/TLS/内核 socket 缓冲/真实代理链
  都不在 29.7 KB 与 10.0 MB 里；PERF-2 的 80 s 最坏值是算术，不是观测。
- **没有绝对容量数字**：本机同时有约 11 个审计代理在编译/跑测试，`ns/op` 不可引用。
  我能给出的绝对量只有：`B/op`、`allocs/op`、每记录字节数、复杂度、往返次数、
  以及同一次运行内的相对倍数。
- **`make perf` 与 `make load` 未跑**（前者 40 分钟且在负载下无意义，后者会在 Windows 上
  耗尽临时端口——文档 §1 自己记了）。因此 `docs/capacity-planning.md` 引用的
  「237 824 requests / 23 782.4 req/s」我既没有复现也没有否证：它没有 commit、
  没有日期，**按发布物的标准它只是一段无法追溯的文字**（见 PERF-9）。
- **配额/`RLIMIT_NOFILE` 与 `process_open_fds`**：Postgres 池 16/socket 之外，
  出站 `MaxIdleConnsPerHost=64`、`MaxIdleConns=256`（`httpclient/outbound.go:53-63`），
  256 个出站 socket + 128 个入站 + 16 个 DB 连接是 fd 预算的下界；容器的 ulimit 我在
  本机无法验证，k8s manifest 也没有 `ulimits` 段。这是 HYPOTHESIS：
  `Re0AuthFileDescriptorsHigh`（>0.8×max_fds）在 256 出站并发下可能比预期更早触发。

## 判断（文档化决定可否质疑，不是 finding）

1. **「数据面整体缓冲以区分 4 MiB 边界」**（`internal/federation/service.go:510-527` 的注释）
   在语义上是对的（截断的 NDJSON/CSV 仍然是合法文本，只有长度能判），但它的代价是
   **每个在途请求 5.8 MiB**，而配置里没有任何东西把这两个数联系起来（PERF-1）。
   我认为这个决定**值得重新裁定**：先用 `Content-Length` 预判、再流式转发、中途超限直接
   断连（而不是回 502），可以保住「不把截断体当完整体」这条性质，同时把峰值内存从
   4 MiB/请求降到 socket 缓冲级别。这是裁定，不是 bug。
2. **内存模式被当作真 OP 的一种部署形态**（ADR-0001 P4b），但它的保留量模型
   （30 天 refresh × 每 grant 892 B）与容器 limit 的关系没有任何文档或告警覆盖，
   而默认 `max_in_flight=512`（内存模式）在 4 MiB 体下是 2.8 GiB。若内存模式只用于开发，
   应该在文档里写死这一点；若它会被用来跑真实流量，PERF-5/6 必须先修。
3. **`federationMaxConcurrent = 256` 大于入站默认 128**：出站 bulkhead 在默认配置下
   永远不是先挡的那一层，它更像是「防止某个源被我们的重试打爆」的上限，而不是容量上限。
   这不是缺陷，但文档 §4 把它和 `max_in_flight` 并列讨论时，会让读者以为两个上限会互相
   制约（实际是 256 > 128，永远不制约）。建议在 §4 里点明这个不等式。

---

## 附：探针与命令索引

| 探针 | 文件 | 测什么 |
|---|---|---|
| `TestProbeHotPathAllocationBudget` | `internal/zzprobe/perf/hotpath_test.go` | 8 条路径的 bytes/req 与 allocs/req |
| `TestProbeInFlightBytesPerDataPlaneRequest` | 同上 | 在途请求的 live heap（PERF-1） |
| `BenchmarkProbeDataPlaneResource` / `BenchmarkProbeRawProxy4MiB` / `BenchmarkProbeRawProxy4MiBGzip` | 同上 | 数据面分配与压缩 CPU 倍数 |
| `BenchmarkProbeTokenExchange` / `BenchmarkProbeIntrospect` | 同上 | 未被覆盖的写路径与协议面读 |
| `TestMemStoreSweepIsProportionalToLiveRecords` / `TestMemStoreSweepStallsConcurrentRequests` / `TestMemStoreBytesPerGrant` / `TestMemStoreDevicePurgeIsPerInsert` | `internal/zzprobe/perf/memstore_test.go` | 内存 store 的扫除、停顿、保留量（PERF-5/6） |
| `TestPerfProbeAuditBatchLatencyFloor` / `TestPerfProbeAuditBatchIsSingleWriter` / `BenchmarkPerfProbeAuditBatchCeiling` | `internal/store/postgres/zzprobe_perf_test.go` | 审计批窗口与天花板（PERF-3） |
| `TestPerfProbeVerifyExtrapolation` / `BenchmarkPerfProbeVerifyRowCost` | 同上 | 链校验每行成本与外推（PERF-4） |

所有探针只新建文件，未修改任何已跟踪文件，未触碰 git 状态。
