# 区域 Z11：韧性 / 限流 / 并发 / DoS — 第七轮**对抗性复核报告**

> 复核对象：`docs/audit-7/findings/Z11-resilience-dos.md`（Z11-1…Z11-6）
> 复核者探针：`internal/zzprobe/audit7/z11verify/`（`//go:build audit7`，未改被复核者任何文件）
> 复核命令：`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z11resiliencedos/...`
> （复跑：**5 红 / 4 绿，与报告一致**）与 `.../z11verify/...`；`go build ./...`、`go vet ./...` exit 0。

## 一、逐条判定

| 编号 | 判定 | 严重度 | 一句话理由 |
|---|---|---|---|
| Z11-1 | **CONFIRMED** | **P1** | 机制复现；且可达性比报告更强（1ms 依赖 8/8、瞬时依赖 5/8 命中）。**但与本轮 Z12-7 是同一机制、同一代码路径**（对方 P2），应合并为一行而非双计 |
| Z11-2 | **CONFIRMED（源级）** | **P2** | 缺陷成立（`service.go:729` 在 `rawFetch` 返回时 release，`federation_routes.go:297` 之后才写 body）；**但探针的「body 被持有」前提在本机不成立**——见 §二 |
| Z11-3 | **CONFIRMED** | **P2** | 复跑一致：`echoed=60000 logged=60157`；`middleware.go:138-142/262` 逐行核对无误 |
| Z11-4 | **CONFIRMED** | **P1** | 用**真中间件链**独立复现 429（`ratelimit_http_test.go`，阳性对照 401）；是对 P0-4/CM-V1 修复的补充，已按简报 §4.4 标注，不算重报 |
| Z11-5 | **CONFIRMED** | **P1** | 机制与出厂数字逐行核对（`server.go:621-624`、`main.go:116/775-779`）；但「无按调用方分摊」本身是 `operations-decision.md:40` 的文档化裁定，新意只在校「一个地址饿死所有人 + 探针全绿」 |
| Z11-6 | **CONFIRMED** | **P3** | 常量确实与自己的注释相反（`outbound.go:36-39/60` vs `:261`、`main.go:493`）；**但报告的影响句写错了**——见 §三 |

## 二、Z11-2：探针没有证明它声称的东西（复核更正）

我只信可复现的量。`z11verify/heldbody_live_test.go` 在**同一进程**里给同一个测量加了阳性对照：
先把 48 个 4 MiB 切片**故意持有**，同一测量函数读出 **192.0 MiB**（仪器不瞎）；随后换成
48 个「只读到响应头就不再读、并把接收缓冲压到 4 KiB」的真实 TCP 慢读者：

```
control: 48 deliberately-live 4 MiB slices moved HeapAlloc by 192.0 MiB
control: one stalled read outstanding; a second concurrent read = 503   ← 预算确实只容一次预留
at measurement time: 48 of 48 raw handlers have returned (access log)   ← 访问日志是 handler 返回时才写的
48 slow readers ... after a forced GC HeapAlloc moved by 0.8 MiB; 48 x 4194304 bytes would be 192.0 MiB
live 4 MiB bodies attributable to the delta: ~0 of 48
with those 48 slow readers outstanding and a 4194305-byte budget, one more full-cap read = 200
```

即：**48 个 handler 全部已返回**，4 MiB 全被本机内核 socket 缓冲吸收（Windows 回环 + 自动调窗），
进程堆里没有它们。被复核报告自己的打印（8 个 body 只涨 4.2 MiB）正是同一个现象，但它的正文仍写成
「8 个…各持 4 MiB（32 MiB 存活）」——这句话在 Windows 上不成立。

**结论不变的地方**：缺陷在源码层成立，且与本机缓冲无关——`defer s.buffers.release(reserve)` 在
`rawFetch` 返回时执行（`service.go:725-729`），而 body 直到 `handleGameRaw` 写完才失去引用
（`federation_routes.go:296-297`）。在本机**没有**写阻塞窗口，所以预算为空是「读已结束」，不是
「body 还被持有」；在 Linux（出厂目标）慢读客户端会让 4 MiB 写阻塞，那时 body 的确会被持有，
512 MiB 的算式才成立。故判 P2 维持，但证据等级应从「探针测到了」降为「源级 CONFIRMED + 平台推论」。

## 三、Z11-6：影响句与 Go 标准库不符

`httpclient/outbound.go:36-39` 的注释要求 `ResponseHeaderTimeout` 低于 `Timeout`，`DefaultTransportConfig`
给 30s，而出厂 `Timeout: 20s`——两常量确实矛盾。但报告写的「错误退化为 `context deadline exceeded`，
而不是可区分的 headers 期限」**是错的**：`C:\Program Files\Go\src\net\http\client.go:749` 在整体期限
先到时把错误写成 `"(Client.Timeout exceeded while awaiting headers)"`，仍然点名了 headers 阶段。
所以这条只剩「默认值与自己的注释不一致」这一 P3 事实，无安全/诊断损失。（`transport.go:2935` 的
`net/http: timeout awaiting response headers` 是另一条路径。）

## 四、Z11-1：可达性实测，以及本轮内重复

`z11verify/readyz_race_test.go` 每一轮都等到 TTL 过期，再「发完立刻挂断」，然后由**另一条新连接**
读 `/readyz`：

```
dependency instant (0s)  : 5/8 hangup cycles poisoned the next /readyz (checks=8, cancelled=5)
dependency 1ms (pgx Ping) : 8/8 hangup cycles poisoned the next /readyz (checks=8, cancelled=8)
dependency 300ms (原探针) : 8/8 hangup cycles poisoned the next /readyz (checks=5, cancelled=5)
```

报告「未能到达」#1 说真实 1ms Ping「只会让『发完立刻挂断』更需要赢竞态」——**实测恰好相反**：
1ms 依赖下 8/8 命中，连 0s 依赖都有 5/8。机制 `health.go:122`（`context.WithTimeout(r.Context(), …)`）
与缓存 `:111-133` 复核无误，出厂探针 `periodSeconds 5 / failureThreshold 3`（`deploy/k8s/base/deployment.yaml:96-100`）
也核对无误。**唯一要改的是记账方式**：`docs/security-audit-7.md` 与 `findings/Z12-config-startup-observability.md`
把**同一条机制**记成 Z12-7（P2）与 Z11-1（P1）两条；两者探针不同、代码路径相同，应合并一条。

## 五、新发现

### Z11-V1 探针豁免绕过了两道上限，却**绕过不了会话中间件**：一个匿名 Cookie 让每次 `/healthz`、`/readyz` 都变成一次连接池往返
- 严重度：**P1 高**（可用性；前提是一次未认证请求 + 一个任意 Cookie）
- 不变量：`docs/operations.md:171-183` 的裁定——「探针永远不因为忙而失败，**代价是它必须便宜**」，
  且「换来的是**每个副本每秒最多一次**数据库往返，而不是按请求数增长」
- 证据（`probe_session_store_test.go`，真 `auth.Manager` + 真 `httpapi` 链 + 计数 `scs.Store`）：
  ```
  control: 5 cookie-less /readyz requests caused 0 store lookups (want 0)
  control: one /v1/me with the cookie caused 1 store lookups (want 1)     ← 仪器在路径上
  finding: 20 cookie-bearing /readyz requests (limiter burst 1, max_in_flight 1)
           = statuses map[200:20], 20 session-store lookups
  ```
  机制：`server.go:616-624` 的顺序是 `inFlight → rateLimit → bodyLimit → sessions → canonicalPath → root`，
  `isProbe` 只豁免前两者（`health.go:164`、`middleware.go:335/399`），**会话中间件照跑**；
  带非空 Cookie 时 scs v2.9.0 `session.go:147 → data.go:59-68` 必然 `doStoreFind`，生产实现是
  `internal/store/postgres/sessions.go:75-82` 的一条 `SELECT … FROM sessions`（取一条池连接）。
  `readinessCache` 只压住**就绪检查**那一次往返，压不住这条按请求数增长的往返。
- 影响：匿名者用任意 Cookie 打 `/readyz`（免限流、免并发上限）即可按请求数驱动池往返；并发不受
  `max_in_flight` 约束 ⇒ 池排队，正常登录/授权请求被饿。认证用户持有效 Cookie 时 scs 还会因
  `IdleTimeout>0` 把每次探针都标成 `Modified` ⇒ 每请求一次写。
- 探针：`internal/zzprobe/audit7/z11verify/probe_session_store_test.go::TestZ11VProbePathStillHitsTheSessionStore`（红 = 有洞）
- 修法建议（裁定）：`isProbe` 的豁免也要跳过 `sessions.LoadAndSave`（把探针挂在会话中间件之外），
  或对带 Cookie 的探针请求走限流；不要把「探针便宜」的责任推给 `readinessCache`。
- 与既有编号：**对 P1-4/CS-1 修复的补充**（修的是就绪检查那一次往返，漏了会话这一次），不是重报。

## 六、其余复核结论（探过没破 / 假绿检查）

- Z11-4 的绿探针是真的：`For 5000 keys Size()==16`，且 `reclaimLocked` 不会退配额（逐行核对）。
- Z11-3 的探针无法被「日志管道会截行」反驳：`logged=60157` 是**本进程实际写出的字节数**。
- 假绿检查：`TestZ11ConcurrentReadinessCallsAreAllAdmitted` 用 `Ready=nil`，只测到 `isProbe` 的豁免形状，
  没有承重的依赖调用；我的 §五 探针用了真 `Ready` 且同样 `MaxInFlight=1`，20 次全 200，豁免成立。
- `ratelimit_http_test.go::TestZ11VOverflowStarvesThroughTheRealMiddleware`（绿=已确认）：
  空限流器下 `/v1/me`=401（阳性对照），被一个 /64 填满并排空兜底桶后 =429
  `rate_limited` —— Z11-4 从此不再只是直接调 `Check` 的内部证据。

## 七、未能到达

1. 无 Docker / 无 Postgres：§五 的「池往返」止于计数 Store + `postgres/sessions.go:75-82` 读码；
   Z11-1 的真 `pgxpool.Ping` 仍不可跑（我用 1ms 桩把可达性做成了 8/8，比原探针更强）。
2. Z11-2 的「写阻塞 ⇒ body 存活」在本机**无法**出现（48/48 写完成）；要展示它需要 Linux 目标或
   可设 SO_SNDBUF 的监听器——我把这一点作为证据更正写进 §二，而不是假装测过。
3. Z11-4「一台机器能否出示 10 000 个 /64 源地址」未验证（需 `IPV6_FREEBIND` 或配置地址）。
4. 端口 18102 未用：本区所有结论都能在真中间件链上取到，真进程（内存模式的 `Ready=nil`）对本区
   的探针/会话结论没有增量。

## 八、判断（文档化决定，不是 finding）

- `operations-decision.md:40`「max_in_flight 是并发硬上限，与配额无关」与 Z11-5 的「无按调用方分摊」
  是同一句话。Z11-5 的**新意只应**表述为「一个地址可据此饿死所有其他客户端，且探针全绿」；把它
  写成「上限没有分摊」本身是在报文档化决定。§五 同理：「探针必须便宜」是已写下的裁定，漏的是
  **实现没有把会话那次往返算进『便宜』**。
- 如果采纳 §五 的修法，`docs/operations.md:177-183` 的「每副本每秒最多一次数据库往返」需要同步改成
  「就绪检查每副本每秒最多一次；**探针请求本身不触碰会话存储**」。
