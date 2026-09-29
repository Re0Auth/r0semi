# 区域 11：韧性 / 限流 / 并发上限 / DoS 面 — 第七轮审计报告

## 范围与方法

- **读**：`internal/ratelimit/ratelimit.go`、`internal/httpapi/{middleware,clientaddr,health,server,federation_routes}.go`、
  `internal/compress/*.go`、`httpclient/*.go`、`cmd/re0auth/{main,config}.go`、`internal/federation/service.go`、
  `deploy/k8s/base/*.yaml`、`docs/operations*.md`。
- **跑**：`go test -tags audit7 -count=1 [-race] ./internal/zzprobe/audit7/z11resiliencedos/...` → **5 红 / 4 绿**，
  `-race` 无竞态报告。真进程黑盒未用（见「未能到达」）。
- **夹具**：`miniAPI`（真 `Handler()` 链 + 桩 seam）与 `dataAPI`（真 federation + 真上游）。
- 本区探针目录在本轮开始时已有 3 条红探针、无报告：我复跑并修正了其中两条**探针自身的缺陷**，新增 2 条，
  并复核了 Z11-2 与 Z09-4 的区别。本区**未发现**键可归调用方、跨平面归桶、解压炸弹或 TE/CL 走私。

## 发现

### Z11-1 匿名调用方一次 connect-then-hangup 就把「本副本 ready」写成 503：探针豁免 + 派生调用方 ctx ⇒ 健康实例被摘出流量

- 严重度：**P1 高**（可用性；失败**静默**——原因只进 `slog.Debug`）
- 类别：可用性；不变量：fail-closed 且「探针不因负载失败」
- 证据（执行过，FAIL）：`readyz_poison_test.go:93-110`：未认证 `GET /readyz` 的连接在检查运行中关闭 →
  `cached dependency result="context canceled", next /readyz = 503`；TTL 过后同一端点恢复 200（对照）。
  机制：进程级 `readinessCache` 用 `health.go:122` 的 `context.WithTimeout(r.Context(), …)`；net/http 在客户端连接关闭时
  取消 `r.Context()`，于是 `context.Canceled` 被当作检查结果**缓存 1 秒**并被所有调用方共享（`health.go:111-133`）。
  可达性：生产仅 Postgres 部署有探针（`main.go:860-864`），探针免限流也免并发（`health.go:151-166`）⇒ 无配额；
  出厂 `readinessProbe failureThreshold 3 / periodSeconds 5` ⇒ 15s 内摘除端点。每秒钟只运行一次检查，
  攻击者以不限速的速率抢占「触发者」，几乎每次都是它。
- 状态：**CONFIRMED**（真中间件链 + 真 TCP 挂断；依赖调用是 300ms 桩，见「未能到达」）
- 影响：一个匿名连接/秒让健康实例持续答 503，kubelet 摘除端点 → 整体不可用；默认日志级别看不到原因。
- 探针：`readyz_poison_test.go::TestZ11CallerCancellationPoisonsTheSharedReadinessResult`（红）；
  `::TestZ11ConcurrentReadinessCallsAreAllAdmitted`（绿，豁免的阳性对照）
- 修法建议：检查改用 `context.WithoutCancel(r.Context())`（或 `context.Background()`）+ `readinessTimeout`。
  **这是裁定**：共享缓存是全进程的，调用方取消从来不是它的语义。
- 相关编号：与 G-11（`running` 分支答 200）同一类「探测结果与真实状态脱钩」的**另一侧**；不是重报。

### Z11-2 上游字节预算在「写响应体之前」就释放：预算约束的是读，不是被持有的 body（P0-3 修复不全）

- 严重度：**P2 中**（需一次登录 + 一个会返回大 body 的源 + 慢读客户端；但后果是容器内存越界）
- 类别：性能/资源；不变量：`held <= MaxBufferedBytes`（`service.go:46-54` 明文声明的容量公式）
- 证据（执行过，FAIL）：`heldbody_test.go:162-180`。预算设为**恰好一次 raw 预留**（`maxBody+1`）：
  对照：一个「头已到、body 不发」的在途读占满预算，第二个并发读 = **503**（预算生效）；
  发现：8 个「body 已读完、正在 `w.Write`」的请求各持 4 MiB（32 MiB 存活），预算自报空闲，
  **再一个满额读 = 200（4 194 304 字节）**，违反 8 倍。
  机制：`service.go:725-729` 在 `rawFetch` 里 `acquire` 并 `defer release`（release 在函数返回时发生），
  `federation_routes.go:296-297` 之后才写 body，慢读客户端把这次写阻塞到 `writeTimeout`（60s）。
  出厂：预算 64 MiB、`limits.memory 512Mi`、`max_in_flight` 派生 **128**（`config.go:387-393`）
  ⇒ 512 MiB 存活 body 对 64 MiB 预算，正好顶满 limit。
- 状态：**CONFIRMED**
- 影响：持 token 的调用方用少量并发 + 慢读即可把堆推到 limit 之上 → OOMKill，丢掉全部在途请求；
  预算的指标/告警在事发时报告「空闲」。- 探针：`heldbody_test.go::TestZ11ABodyOutlivesTheReservationThatAdmittedIt`（红，对照已修好：早先版本把桩读同步发出，
  两个请求根本不重叠，测到的是 20s 超时而非预算）
- 修法建议：把预留的生命周期挂到 **body 的持有者**——`RawResult` 携带 `release`，由 handler 在 `w.Write` 后调用
  （或在 `handleGameRaw` 里 `defer`），而不是在 `rawFetch` 返回时释放；或按「已读 + 已写字节」计费。
- 相关编号：**对 P0-3 修复的补充**。与 Z09-4（预算全局先到先得、sleepers 挤掉别人的读）**不是同一条**：
  Z09-4 是「读进行中的预留归谁」，本条是「预留消失而 body 还在」，修法不同。

### Z11-3 调用方写的 `X-Request-Id` 无长度/字符集上限，被原样回显进响应头并写进访问日志

- 严重度：**P2 中**（无门槛、可被 /64 放大；若日志管道本身截行则为 P3）
- 类别：可用性/资源；不变量：日志量不由调用方决定
- 证据（执行过，FAIL）：`requestid_test.go:54-69`。一次未认证请求 `X-Request-Id: <60 000 字节>`：
  `status=404 echoed=60000 bytes logged=60157 bytes`（普通请求约 150 字节）。
  `middleware.go:138-142` 直接 `r.Header.Get("X-Request-Id")` 无校验/截断，`:142` 回显、`:262` 入日志；
  服务的唯一上限是 `MaxHeaderBytes = 64 KiB`（`main.go:122`）。
- 状态：**CONFIRMED**
- 影响：单地址 50 req/s（`config.go:348-349`）≈ **3 MiB/s** 访问日志；`/64` 去掉上界 ⇒ 磁盘/日志管道被打满，
  且 60 KiB 响应头本身是 400× 放大。
- 探针：`requestid_test.go::TestZ11ACallerChosenRequestIDIsEchoedAndLoggedInFull`（红）
- 修法建议：只在 `len <= 128` 且字符集 `[A-Za-z0-9._-]` 时采信，否则生成新的；回显与日志都用清洗后的值。
- 相关编号：无。第五/六轮未收录 `X-Request-Id`。

### Z11-4 桶表可被单个 IPv6 /64 填满，之后**所有**新客户端共用一个兜底桶并被 429：fail-closed 方向被转成对他人的拒绝服务

- 严重度：**P1 高**（匿名、单机；按简报 §6「匿名可触发的 DoS」的口径可上调 P0）
- 类别：可用性；不变量：限流的「换个键买不到配额」不能以牺牲无关客户端为代价
- 证据（执行过，FAIL；**出厂默认 10 000 键 / 16 分片**）：`ratelimit_saturation_test.go:85-137`。
  仅用 `2001:db8:ff::/64` 内的地址：`10000 tracked keys（整张表）`；随后 5 个全新键（三个平面、IPv4/IPv6 各一）全部
  `allowed=false shared=true`；而攻击者自己已跟踪的键仍 `shared=false` 且被服务。
  机制：键 = `planeOf(path) + "|" + addr`（`middleware.go:349`），`addr` 是单个 /128（`clientaddr.go:70-82`）；
  `ratelimit.go:199-215` 在分片满且 `reclaimLocked` 找不到「丢掉不损失任何东西」的桶
  （`reclaimWindow = max(ttl 10min, burst/rate)`，`:135-141`）时，让新键落入**该分片唯一的 overflow 桶**——
  它不属于任何客户端，可被任意未跟踪的键花掉。
  维持成本：10 000 个地址各每 10 分钟发 1 次即保持表满（16.7 req/s 总量）；排空 16 个 overflow 桶 =
  16 个地址 × 50 req/s（各自限额之内）。
- 状态：**CONFIRMED**（分片覆盖用同一 /64 前缀的 10 000 个键证明；见「未能到达」）
- 影响：任何**新**客户端（新 IP、重新拨号、NAT 出口变化）在三个平面上都拿 429：登录/授权/数据面一起不可用；
  已被跟踪的客户端不受影响。进程不崩、探针照常 200，k8s 不重启也不摘除。
- 探针：`ratelimit_saturation_test.go::TestZ11OneIPv6Slash64DeniesEveryNewClient`（红）；
  `::TestZ11AtCapacityTheTableStaysBounded`（绿：表确实有界、确实不退配额）
- 修法建议（裁定）：① overflow 桶**按调用方分摊**（每键一个小桶 + LRU/计数上限）；
  ② 或只拒绝**重复进入** overflow 的客户端；③ 或地址归一化对 IPv6 按 /64 归并——**与 P0-4 相反方向**的取舍：
  更粗地合并合法客户端，但把「单机 = 10000 键」降成 1。三条都要改 `operations-decision.md:49` 的措辞。
- 相关编号：**对第五轮 P0-4 修复 / 复核项 CM-V1 的补充**。P0-4 修的是「喷键买配额」（已成立，见绿探针），
  CM-V1 记的是「/64 让键空间放大到单机可触发」；**未记录的是**：修好后这份放大变成对**第三方**的拒绝服务，
  且兜底桶可被持续排空。文档化的那一半（兜底桶存在）不作为发现。

### Z11-5 并发上限全进程一个信号量、且没有按调用方分摊：一个地址拿住所有槽位，其他客户端全 503，而探针仍 200

- 严重度：**P1 高**（匿名、单机；同样可按简报 §6 上调 P0）
- 类别：可用性；不变量：并发上限与限流必须**联合**约束「一个调用方能在途多少」
- 证据（执行过，FAIL）：`inflight_test.go:69-90`。`max_in_flight = 2` + 出厂限流形状（50/s, burst 100）：
  同一地址 2 个 socket 各发 `Content-Length: 65536` 只给 1 字节 → 占住两槽（只花掉 100 burst 中的 2 个）；
  来自**另一个源地址**（127.0.0.2，另一个限流桶）的普通请求 = **503 server busy**；同时 `/healthz = 200`、`/readyz = 200`。
  机制：`middleware.go:393-419` 一个进程级 `make(chan struct{}, s.maxInFlight)`，`isProbe`（`health.go:164`）只豁免两个探针路径；
  它包在限流器**外面**（`server.go:621-624`），槽位在限流判断之前占用。限流按秒计：
  50/s × `ReadTimeout` 30s（`main.go:116`）= 1 500 > `max_in_flight` **128** ⇒ 一个地址 ~5 req/s 即可持续占满。
- 状态：**CONFIRMED**（httptest 无 ReadTimeout，探针窗口比生产更长；机制与出厂数字逐行核对）
- 影响：一个匿名地址（约 130 个 socket、~5 req/s）让所有其他客户端在两个平面上持续 503；探针全绿 ⇒
  编排器不摘除、不重启，故障对运维不可见地持续。
- 探针：`inflight_test.go::TestZ11OneAddressCanHoldEveryInFlightSlot`（红）
- 修法建议（裁定）：① 槽位按 (plane, client) 分摊（每客户端上限 = `maxInFlight` 的一个分数 + 共享余量）；
  ② 或把限流令牌绑在 **in-flight** 上而不是到达上；③ 至少给「慢 body」一个远短于 `ReadTimeout` 的期限。
- 相关编号：与第五轮 CS-1/P1-4（`/readyz` 豁免）同源，但被攻击对象是**普通客户端**而非连接池；不是重报。

### Z11-6 `ResponseHeaderTimeout` 的默认值（30s）高于出站客户端默认 `Timeout`（20s），与它自己的注释相反

- 严重度：**P3 低/提示**；类别：可维护性/诊断；不变量：错误必须能指认失败的那一阶段
- 证据（源级，`file:line`）：`httpclient/outbound.go:36-39` 要求它「should sit below the client's overall Timeout so the
  error names the headers rather than the deadline」，但 `DefaultTransportConfig`（`:53-63`）给 30s，而
  `defaultOutboundTimeout = 20s`（`:261`）；`cmd/re0auth/main.go:492-507` 只设 `Timeout: 20s` 和
  `TransportConfig{DenyPrivateAddresses}` ⇒ 出厂组合就是 30s > 20s。凡是「上游挂住不发头」的请求都由整体期限先触发，
  错误退化为 `context deadline exceeded`，而不是可区分的 headers 期限。
- 状态：**CONFIRMED（源级）**（不改行为，仅需把默认改成例如 15s；无探针——两常量一注释即可判定）
- 影响：慢源与全站超时在日志/指标上不可区分；无安全影响。
- 相关编号：无。

## 探过但没破的（也应变成守卫）

1. **路径拼写买不到第四个桶**：32 种拼写（`/oauth//token`、`/v1/%2e%2e/oauth/token`、`/oauth%2Ftoken`、大小写变体……）
   在两面桶都花光后**全部** 429；`planeOf` 与路由器一致。`ratelimit_guard_test.go::TestZ11PathSpellingCannotBuyAFourthBucket`（绿）。
2. **只有 `/healthz` 与 `/readyz` 精确匹配才豁免**：`/healthz/`、`/readyz%2F`、`/Healthz`、`/readyz%20` 都不继承豁免
   （第一发 404、第二发 429）；**此探针本轮被我修好**：它原先共用一个 burst=1 的浏览器面桶。
   `::TestZ11ProbesAreTheOnlyExemptPaths`（绿）。
3. **桶表有界且不退配额**：5000 个不同键后 `Size()` 仍 = 上限；`::TestZ11AtCapacityTheTableStaysBounded`（绿）。
4. **`/readyz` 不因负载失败**：`max_in_flight=1` 下 32 并发全部 200；`::TestZ11ConcurrentReadinessCallsAreAllAdmitted`（绿）。
5. **超时栈完整**（源级）：`ReadHeaderTimeout 10s / ReadTimeout 30s / WriteTimeout 60s / IdleTimeout 120s / MaxHeaderBytes 64 KiB`
   （`main.go:115-122`），`dataPlaneTimeout 45s < writeTimeout`（`TestDataPlaneTimeoutFitsInsideTheWriteTimeout`）。
6. **无解压炸弹面**（源级）：全仓非测试代码没有任何入站 `gzip/zstd/flate` 解码；请求体上限 `oauth.MaxFormBytes = 64 KiB`
   且按声明长度先拒（`oauth/bodylimit.go:14-27`，413 实测）。
7. **无请求走私面**（源级）：出站 raw 请求由 `service.go:701-706` 新建，只带 `Authorization`/`Accept`；入站 TE/CL 由 net/http 归一。

## 未能到达（残余盲区）

1. **无 Docker / 无本地 Postgres**：`store.db.Ping` 与真 kubelet 循环没跑；Z11-1 用 300ms 桩依赖
   （真实 Ping ~1ms，只会让「发完立刻挂断」更需要赢竞态，不会取消这条路径）。
2. **Z11-4 没在真实 /64（10 000 个源地址）上打**：用同一 `/64` 前缀的 10 000 个键证明分片覆盖（hash 输入一致），
   但「一台机器能否绑定 10 000 个地址」未在本机验证。
3. **Z11-2/Z11-5 的内存后果没在 512Mi 容器里触发**：32 MiB/2 槽位是机制证据，OOMKill 是算术推论。
4. `-race` 只覆盖本区探针（无竞态报告）；`bufferBudget`/熔断器 host map 的竞态仍由第六轮背书。
5. 真进程端口 18101 未启（本区结论都走真中间件链）。

## 判断（文档化决定可否质疑，不是 finding）

- `operations-decision.md:49`「桶满不淘汰活桶、新键共用一个兜底桶」的**方向**对（换键不该买配额），
  我质疑的是**分摊粒度**：兜底桶应是「每键一份很小但有界」的配额，而不是 625 个分片各一个公共池。
- ADR-0009 的半开并发度 N、`Retry-After` 抖动、`Bulkhead` 许可活到 body 关闭：按文档实现，无异议。
- 探针豁免（`health.go:151-166`）是必要裁定；Z11-1 证明的是它的**输入**（调用方 ctx）不该进共享缓存。
