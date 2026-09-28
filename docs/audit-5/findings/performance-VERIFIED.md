# 性能/容量审计报告 —— 对抗性复核（performance-VERIFIED）

复核对象：`docs/audit-5/findings/performance.md`（PERF-1 … PERF-12）。
复核者立场：**证伪**。凡我确认的，都给**我自己重跑的命令与承重输出**；凡我降级/推翻的，都给代码/文档引证。

## 0. 复核环境与方法论修正

- Windows 11 / Go 1.27.1。全部命令**实际执行**；未跑 `go test ./...`；未改任何已跟踪文件；未碰别人的探针。
- 我的探针：`internal/zzprobe/verifyperf/verify_perf_test.go`（新包，只含 `_test.go`）。设计上**它为推翻报告而写**：
  `TestVerifyInFlightAttribution`（把 PERF-1 的"每请求 5.8 MB"拆成"随并发线性项"与"固定项"，并做 body 扫描）、
  `TestVerifyInFlightWhoHoldsTheBytes`（`MemProfileRate=1` 的精确 inuse profile + `debug.FreeOSMemory` 对照）、
  `TestVerifyInFlightAfterTheReadIsTheSameQuestion`（同一请求停在**读完之后**，而不是读中间）、
  `TestVerifyRawPathRefreshAmplification`（用慢上游把 PERF-2 的 20 s × N 变成可观测的墙钟时间）。
  探针不修改任何已跟踪文件；`gofmt`/`go vet` 干净。
- **`docs/audit-5/BRIEF.md` 仍然不存在**（全仓库 `*BRIEF*` 零命中，`docs/audit-5/` 下只有
  `findings/`、`probes/`、`runtime/`）。所以"不得报告的文档化非目标"清单我只能用
  `docs/operations-decision.md`（ADR-0006）§决策 / §已知残余风险、`docs/security-audit-2.md:61-67` 代替。
  这直接影响 PERF-4/5/6 的"已知非发现"判定强度，我在各条里写明用了哪份替代清单。
- **报告的一处自述已过期**：报告开头写"其它审计代理正在改 `internal/httpapi/server.go`…行号是读取当时的"。
  我这轮实测：报告引用的行号（`main.go:109`、`main.go:459-460`、`service.go:23,517,545`、`auditbatch.go:31-46`、
  `auditchain.go:199`、`config.go:311-312,329-338`、`middleware.go:136-156`、`health.go:69-77`、`server.go:606`）
  **全部命中它所说的代码**，没有漂移。

---

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|----|----|----|----|----|
| PERF-1 | 阻断上线 | **阻断上线（结论保留，数字错，且错得偏低 4 倍）** | **部分成立** | 5.8 MB/请求我原样复现且**确认是每请求线性项**（n=1…32 平坦，边际 5.79–5.81 MB）；但报告把「派生默认 128」和「k8s 512Mi limit」配在一起，而**出厂 k8s configmap 与配置样例都显式写 `max_in_flight = 512`** ⇒ 正确的乘积是 **2834 MiB（5.5× limit）**，不是 708 MiB |
| PERF-2 | 高 | **高** | **CONFIRMED（实测）** | 我用慢上游实测：一个 raw 请求真的发出 **4 次串行出站调用**（token→resource→token→resource，484 ms ≈ 4 × 121 ms）；`httpclient.Retry` 确实只有 `cmd/referencesource` 用 |
| PERF-3 | 高 | **低** | **部分成立（降级）** | 1 ms 窗口与 `64/commit RTT` 天花板成立且我复跑确认，但**机制与"看拐点"判据都已写在 `capacity-planning.md §4`、告警 `Re0AuthAuditAppendSlow`（slo.md:59）也已点名它是"先审计后交付"的串行上限**；标题后半"每一个被审计的请求至少要等这个窗口"被报告自己的饱和数据推翻（批满 64 时窗口被完全摊掉） |
| PERF-4 | 高 | **低** | **已知非发现** | `docs/operations.md:171-182` 已写明「45 s 也扫不完的规模，那是要上增量校验点」，`main.go:96-99` 复述同一条；报告的"修法建议"就是文档已有的处置。且标题"从约一千万行起就不可能完成"被它自己的表推翻（1e7 = 13–15 s，仅预算 1/3） |
| PERF-5 | 中 | **低** | **部分成立（降级）** | 扫除是 O(live) 且持全局锁——我复跑确认；但 ①内存模式**明确不提供生产运维保证**（ADR-0006 决策 6），②外推用的是"每 grant 2 条记录保留 30 天"，而 **accessTTL = 1 h**（`memory/oidc.go:306`）⇒ 保留量高估 2 倍，③"没有任何文档/告警说这件事"被 `Re0AuthMemoryHigh`（slo.md:65）与 `capacity-planning.md:104` 推翻 |
| PERF-6 | 中 | **低** | **部分成立（降级）** | 代码确证（`StoreDeviceAuthorization` 在 `s.mu` 下先全表 `purgeExpiredDevicesLocked`，`memory/oidc.go:753-756,818-828`），探针 0s→333 µs@2 万也复现；但同样只存在于 ADR-0006 排除生产保证的内存模式 |
| PERF-7 | 低（提示） | **低** | **CONFIRMED（读 + 库源码）** | `token.go:138` 确实是 `Crypto.Encrypt(tokenID+":"+subject)`，`aes256GCMCrypto` 确实是 `jose.ParseEncrypted`+`Decrypt`、`Encrypt` 每次 `jose.NewEncrypter`；`op.WithCrypto`/`NewCompositeCrypto` 在 v3.51.3 存在且接口只有 `Encrypt/Decrypt(string)(string,error)`，接缝**可用**。**「97%」已撤回**：来自两次**不同进程**的基准，违反报告自己定的"只引同一次运行的相对倍数"；成立的是分配口径（每请求约 12 KB，store 占约 1.6%），且在 S4（p99 < 1 s）余量内（µs 级，约 10⁴ 倍），无门槛被触及 |
| PERF-8 | 中 | **中** | **部分成立** | `B/op`/`allocs/op` 全部复现（209→210、252、394→395、`/v1/me` 180 allocs/14 887 B 对报告 14 910）；`Sources()` 每次复制+排序二次调用确证（`federation.go:234-238`+`service.go:207,306`）；但 12–15 次 Postgres 往返只有"读；无 DB 执行" |
| PERF-9 | 中 | **低** | **部分成立** | (d) 成立；(b) 的"已过期"不成立（`capacity-planning.md:25` 自己就写 `-bench . ./...`），只剩覆盖缺口；(c) 成立但引文被截取；(a) **判断方向错**——见 PERF-1，出厂配置真的写 512，不能断言"表里那行是错的" |
| PERF-10 | 低 | **低** | **CONFIRMED（读）** | `planeOf` 把 `/v1/*` 一律判为 business（`middleware.go:489-497`），而 `http_request_duration_seconds` 只有 `plane`/`method` 两个标签（`observability.go:97-102`） |
| PERF-11 | 低 | **低** | **部分成立** | "刻意不 gate"是事实（ADR-0007 决策 5、`Makefile:44-51`），覆盖缺口成立；"三个基准对应三条热路径已过期"与 9(b) 同一处误判 |
| PERF-12 | 提示 | **提示** | **CONFIRMED（复现）** | 8 条路径的 `bytes/req`、`allocs/req` 与报告的偏差 ≤1%；`newRequestID` 12 B rand、`newTraceID` 16 B rand（`middleware.go:315-321,214-220`）确证（仅在客户端未带头时触发，探针正是这种情况） |

---

## 2. 我降级或推翻的条目（本文件最重要的一节）

### 2.1 PERF-1：结论站得住，但那个 708 MiB 配错了默认值——真正出厂配置下是 2834 MiB

**(a) 测量与归因：报告的方法是对的，我推不翻它。**
我自己重跑报告的命令，数字逐字节复现：

```
hotpath_test.go:526: body=4193280 bytes; live heap +185723736 bytes over 32 in-flight requests = 5803867 bytes/request
  max_in_flight=128  ->    708 MiB ...
```

然后我做报告没做的事——**变化并发数，看它是不是每请求项**（`TestVerifyInFlightAttribution`）：

```
n=  1  live heap delta=     5766368  per-request=  5766368 B (5.50 MiB)
n=  4  live heap delta=    23134736  per-request=  5783684 B (5.52 MiB)
n= 16  live heap delta=    92831032  per-request=  5801940 B (5.53 MiB)
n= 32  live heap delta=   185609936  per-request=  5800310 B (5.53 MiB)
marginal per added request, n=1->4: 5789456 B ; n=4->16: 5808025 B ; n=16->32: 5798682 B
```

n=1 就是 5.77 MB —— **没有固定项**，所以 5.8 MB 不是"进程总量 ÷ 32"，报告把"32 个在途请求的活堆增量 ÷ 32"当作每请求成本，**方法成立**。
`debug.FreeOSMemory()` + GC 后数字只变 -32 B/request，所以它也不是"sweeper 没扫完的垃圾"，而是**真的可达**。
**归因的形态**也对：`MemProfileRate=1` 的精确 inuse profile 里，前 10 条 stack 全是
`io.ReadAll → federation.(*service).rawFetch (service.go:517)`，没有第二条业务路径。

**(b) 但"5.8 MB"是**停在读中间**的数字，读完只有 4.19 MB —— 描述要收窄。**
`TestVerifyInFlightAfterTheReadIsTheSameQuestion`（把同样的 8 个请求停在**响应写**里，此时上游已读完）：

```
body=4193280 bytes, 8 requests parked in the response write (read complete):
  live heap +33567016 = 4195877 B/request; the bytes handed to Write are 4193280
```

即：**读完之后每请求 4.00 MiB（= maxBody + 0.04%）**；停在 `io.ReadAll` 中间是 **5.80 MiB**。
差出来的 ~1.6 MB 是 `io.ReadAll` **已被取代的几何增长数组**在该阻塞点仍被判为可达（profile 里能看到同一调用点
在 81 920 / 114 688 / 172 032 / 253 952 / 385 024 / 573 440 / 851 968 / 1 278 002 / 1 916 928 各有一份活对象）。
报告把 5.8 MB 全称作"响应缓冲"并不准确，但**对它描述的场景（上游挂住、请求停在读里）5.8 MB 恰是正确口径**——
所以这不是算错，而是"数字绑定在一个没写出来的前提上"。这条我标 **部分成立（数字口径需写明）**，不推翻。

**(c) 但把 128 和 512Mi limit 配在一起是错的，而且错在安全方向。**
报告找"默认值"的地方是 `docs/capacity-planning.md §4`（`:113`，派生默认 = `max(64, max_conns×8)` = 128）。
**出厂的两份部署配置都显式写死了 512**，派生默认根本不生效：

- `deploy/k8s/base/configmap.yaml:24`：`max_in_flight    = 512` —— 而**同一套 manifest** 的
  `deployment.yaml:85-87` 就是 `resources: … limits: { cpu: "1", memory: 512Mi }`（报告 quote 的那个 limit），
  `:43-46` 的 `DATABASE_URL` 来自 secret ⇒ durable，`env` 里**没有** `RE0AUTH_MAX_IN_FLIGHT` 覆盖；
- `config/re0auth.example.toml:46`：`max_in_flight = 512`，而 `:39-43` 的注释自己解释"不写才是 128，内存模式是 512"——
  也就是说**样例文件在解释完 128 之后紧接着写下了 512**。
- 实现确认这条路径：`config.go:470-471`（文件里有值就用它）与 `config.go:577-580`（`< 0` 才派生）。

所以对"它引用的那个 512Mi 容器"而言，正确的乘积是 **512 × 5.80 MiB = 2834 MiB ≈ 5.5 × limit**
（报告自己的表里也列了 2834，只是没意识到出厂配置就走那一行）。**结论（在途请求数 × 4 MiB 体没有联合上限、
默认部署会因为响应缓冲把 limit 打爆）不仅活着，而且被低估了 4 倍**；但 708 MiB 这个数字与它引用的部署不自洽。
判决写法：**结论 CONFIRMED，数字需改为 2834 MiB，且必须把"128 是缺省派生值、出厂配置显式设为 512"写清楚**。

**(d) 4 MiB 体是可达的，报告没说全的地方是"必须先有 source"。**
- 上限来源：`internal/federation/service.go:23` `maxBody = 4<<20`；raw 路径**整体缓冲**
  （`service.go:517` 的 `io.ReadAll(io.LimitReader(...))`），返回值 `RawResult.Body` 就是那个数组，直到
  `federation_routes.go:253` 写出去——中间没有第二份拷贝。
- **不改变这个数的东西**：`withBodyLimit`（`middleware.go:107-122`）只包**请求**体（`oauth.LimitFormBody`），
  是 413 而不是响应上限；压缩层在没有 `Accept-Encoding` 时不参与（报告自己的"探过没破 #1"：gzip 只把 4 MiB 从
  10.02 MB/op 变成 10.63 MB/op，没有第二次缓冲）。我复跑：`4MiB gzip 10 648 535 B/op vs 4MiB 10 023 174 B/op`。
- **可达性前提**：`/v1/games/{game}/sources/{source}/raw/...` 需要 ①运维在 `[[sources]]` 里配 `raw_base`
  （`config.go:187-204,752-788`，**k8s base configmap 里一个 source 都没有**），②一个已绑定该源、且令牌带
  `phigros.score.read` 一类 scope 的**已认证用户**（`federation_routes.go:201-221` 的 scope 闸门），
  ③上游真的返回 ~4 MiB。攻击者**不能**选体大小，但"这个端点就是为大体量原生 API 存在的"，所以大响应体是常态而非刁钻配置。
  报告写"一个刷子"是对的（按地址限流 50/s burst 100，`configmap.yaml:22-23`，多地址或持续 10 s 即可堆到 512 在途）。
- **报告没提的一个有利事实**：部署里**没有任何地方设置 `GOMEMLIMIT`/`GOGC`**（我在 `deploy/`、`docs/`、`config/`
  全量搜零命中），所以 Go 运行时不会自己去尊重 512Mi cgroup limit —— OOMKill 之前没有任何软着陆。这支持它的阻断级判定。

**(e) 报告自己的守卫太弱**：探针只断言 `perRequest ≥ body/2`（`hotpath_test.go:522`），
5.8 MB 和 2.1 MB 都能过。真正该钉的是"≥ 1.2 × body"（我在探针里用 `io.ReadAll` 的 cap 做对照：4 MiB 体下
cap=4 194 304，实测 5 797 688，ratio 1.38；64 KiB/512 KiB/1 MiB 体的 ratio 只有 1.06/1.03/1.13）。

### 2.2 PERF-2：算术我实测走了两遍，它是**真的**；报告还漏掉了让它更硬的一环

报告说"20(刷新)+20(取数)+20(强制刷新)+20(再取数)=80 s"。我用一个**每次都回答、但每次慢 120 ms** 的上游，
把"4 次串行"从算术变成墙钟事实（`TestVerifyRawPathRefreshAmplification`，单个 raw 请求）：

```
client request finished in 484ms with status 503 (upstream answers after 120ms each)
  outbound call 1: POST /oauth/token      TokenEndpoint  (took 121ms)
  outbound call 2: GET /api/big           resource       (took 121ms)
  outbound call 3: POST /oauth/token      TokenEndpoint  (took 121ms)
  outbound call 4: GET /api/big           resource       (took 121ms)
upstream saw 4 calls
```

`484 ms ≈ 4 × 121 ms` ⇒ **四次调用严格串行，不是并发**。这四次调用的每一次在出厂配置下都受同一个客户端的
`Timeout: 20s`（`main.go:459-460`，Doer 与 HTTPClient 指同一个 `federationClient`；
`httpclient/outbound.go:249-250,316-318` 还把 bulkhead 排队也计入该 deadline）⇒ **单请求 80 s 是可达的紧上界**。
补充确证：

- 报告的"`httpclient.Retry` 没接进 re0auth"：`grep httpclient.Retry(` 全仓只命中 `cmd/referencesource/main.go:143`
  与 `internal/zzprobe/federation/httpclient_test.go`。**成立**。
- 报告的"没有 handler 级总超时"：`internal/httpapi` 无 `http.TimeoutHandler`（grep 零命中），
  `main.go:713-718` 只有 `ReadHeader/Read/Write/Idle`。**成立**。而且 `WriteTimeout` 是**连接写**deadline，
  不会取消 `r.Context()`：60 s 后 handler 继续跑完，客户端拿到的是"没有任何响应"（headers 也写不出去），
  报告"客户端拿到 EOF / 半截 body"里的"半截"只在已经 flush 过一部分时成立——主路径是**空响应**，
  这比它的括号说法更干净，但**不改变结论**。
- **报告漏了的一环（让它更难被乐观解释掉）**：breaker 不是这个场景的缓解。
  `httpclient/circuitbreaker.go:76-78` 明确"A 4xx 是请求方的问题…不记录"，而 80 s 的形状正是
  **慢 token 交换（transport 超时）+ 快 401（4xx，算成功、把连续失败计数清零）**交替四次。
  所以即使并发很多，也不会因为熔断而变快——这一点报告没写，写上去它的触发性论证会更硬。
- 唯一要收窄的表述：`candidates()` 循环（`service.go:228`）只属于 `Fetch`（规范化路径）；
  **`Raw` 是 `registry.Get` 单源**（`service.go:357`）。所以"两个候选 160 s"是规范化路径的算术，
  而 80 s 单请求在 raw 路径上就成立——报告把两者混在同一段里陈述，读起来像 raw 也有候选循环。**算术都对，归属要分开写。**

### 2.3 PERF-3：机制已被文档化 + 标题后半被报告自己的数据推翻 ⇒ 降级为低

**成立的部分**（我复跑，`go test -run TestPerfProbe -v ./internal/store/postgres/`）：

```
append with an instant commit: mean=1.513ms worst=1.712ms (batcher window=1ms)
commit=1ms   3200 rows in 50 batches over 81ms = 39401 rows/s (avg batch 64.0, ceiling 64000 rows/s)
commit=20ms  3200 rows in  1.0s = 3147 rows/s (avg batch 64.0, ceiling 3200 rows/s)
```

`auditbatch.go:31-46` 的 `auditMaxBatch=64`/`auditBatchWait=1ms`/`queue=512`、`:160-178` 的
"先开 1 ms 定时器再收行"、`:122-127` 的 `enqueue` 等 `item.done`——**都确证**，所以"1 ms 在 I3 路径上"成立。

**降级理由一：几乎每一环都被文档化了。**
- `docs/capacity-planning.md:131-139` 已写：并发写被合并进一个事务、**"链头锁与往返各付一次/批（上限 64 行或 1 ms 的收集窗口）"**、
  单写者语义、以及"它是否已再次成为瓶颈"的判据（`re0auth_audit_append_duration_seconds` 与
  `BenchmarkAuditAppend` 并行 ns/op 拐点）。报告自己承认引文"说对了"，只是"没给公式"。
- `docs/slo.md:59` 的 `Re0AuthAuditAppendSlow` 告警原文就把这个数字定义为
  **"审计与「先审计后交付」路径的串行上限"**。所以报告影响④"唯一能看到这件事的信号，而它在 SLO 里不出现"
  **不成立**：信号在 §4 与告警里都点名了。（S4 只有 HTTP 直方图这一点是对的，但那是 S4 的定义问题 = PERF-10。）
- `auditbatch.go:33-34` 的注释本身就写着"A millisecond is far below any client-visible latency"——这是**有意决定**，
  报告的量测确认了这个决定的代价（1.5 ms），这有价值，但它是"确认"，不是"发现"。

**降级理由二：标题后半与报告自己的证据矛盾。**
标题/影响①写"**每一个**被审计的请求至少要等这个窗口"。但 `flush()` 的 gather 循环在批满 64 时**立即**结束
（`auditbatch.go:169-178`），而同一份探针文件里的 `TestPerfProbeAuditBatchIsSingleWriter` 实测
`avg batch 64.0`、达到率 ≈ 天花板——**即饱和时窗口被完全摊掉，代价是 0**。所以正确的说法是：
"**队列空时到达的请求**要付 1 ms；持续负载下 p50 由 commit RTT 支配"。这条修法建议里的
"按剩余预算/自适应窗口"因此也失去了"每请求 +1 ms"的紧迫性。

### 2.4 PERF-4：这是**已知非发现**，且标题的 1e7 被它自己的表推翻

**先确认它的测量**（我复跑）：

```
verify: 1.342µs/row, 744926 rows/s single core, statement timeout 45s
  1e+07 rows: 13s of CPU alone     1e+08 rows: 2m14s of CPU alone
```

**但它的"发现"部分已经在两份文档里写死了**：
- `docs/operations.md:171-175`：
  "**校验本身有超时，而且是单独放宽的**：`GET /v1/admin/audit/verify` 是全表遍历，它在一个事务里把
  `statement_timeout` 临时抬到 45s… 所以**校验失败先分清是"链有问题"还是"遍历没跑完"**：后者记的是 `result="error"`，
  由 `Re0AuthAuditVerifyError` 告警… **真到了 45s 也扫不完的规模，那是要上增量校验点，而不是继续抬超时。**"
- `docs/operations.md:181-182`：**"扫不完时的正解是增量校验点（上一条），不是更频繁的重扫。"**
- `cmd/re0auth/main.go:96-99`（`auditVerifyInterval` 的注释）复述同一条，并直接指向 `docs/operations.md`。
- `docs/slo.md:19-21` 已经把 `error` 定义为"S5 的**盲区**…所以它单独告警（`Re0AuthAuditVerifyError`），
  而不是并进 `failed`"。

也就是说：报告的**影响①（S5 变成永远报警的 error 序列）与修法建议（持久化 `last_verified_id`/`last_verified_hash`
做增量校验点）与文档已经写下的处置逐字重合**。按 VERIFY-BRIEF §2，这必须标 **已知（非发现）**。
残留的、有价值的部分只有一个数：**每行成本 1.34–1.47 µs**，把文档里模糊的"45 s 也扫不完的规模"具体化成
"纯 CPU 约 3×10⁷ 行"（含读行更早）。这个数值得回填进 operations.md §那一段，但它不改变任何决定。

**标题还要纠正**：`从约一千万行起就不可能完成` 与它自己的表冲突（1e7 → 13–15 s，只吃掉 45 s 预算的 1/3），
而它自己的守卫断言的是 **1e8**（`zzprobe_perf_test.go:171-175`）。正确的量化说法是
"纯 CPU 在约 3×10⁷ 行处穿过 45 s；含 10 列 Scan 与行传输更早，未测"。

**顺带确认两条报告说得对的行级事实**：`auditchain.go:220-232` 的 `Verify` **确实持有一个事务**
（`l.pool.Begin` + `SET LOCAL statement_timeout=45s`）⇒ "占一个池连接最多 45 s"成立；
`:243-247` 是 `SELECT ... ORDER BY id` 的**逐行 `rows.Next()` 流式读**（不是一次性 buffer），
所以报告"读每一行"没错，但"`Verify` 会先缓冲整个结果集"这种担心不成立。
可达性：该端点**只对 allowlist 管理员开放**（`operations.md:195-196`、admin 平面），所以③"operator 手滑给自己施压 45 s"
是自伤；真正自动化的那条是 `main.go:385` 的 `loops.Go(func(){ auditVerifyLoop(...) })` ——
它在**监听器起来之前就作为 goroutine 起跑**（不阻塞启动），所以影响②"每次滚动发布/重启立刻跑一次全表扫描"成立，
但"抢连接"只是 1 条连接的竞争，量级很小。

### 2.5 PERF-5 / PERF-6：内存模式被 ADR 排除在生产保证之外，而且外推高估 2 倍

**先确认代码与探针**（我复跑，全部 PASS）：

```
records=  40000  sweep=       1ms  per_record=  25ns
records= 200000  sweep=   7.852ms  per_record=  39ns
records= 100128 requests=  174519  sweep=     3.518ms  worst_before=   1.698ms  worst_during=   5.099ms
StoreDeviceAuthorization: 0s/call at ~200 live, 333µs/call at ~20400 live
heap=44589440 bytes for 50000 grants (100000 records): 892 bytes/grant, 446 bytes/record
```

`SweepExpired` 在 `s.mu` 下顺序扫 5 张 map（`memory/oidc.go:843-878`）、`StoreDeviceAuthorization` 在
`s.mu` 下先 `purgeExpiredDevicesLocked` 全表扫（`:753-756,818-828`）——**代码确证**，PERF-6 的 O(live)/O(N²) 成立。

**降级理由一：这不是生产部署形态，而且是明文写下的决定。**
`docs/operations-decision.md`（ADR-0006）决策 6：
> **6. 内存模式不提供生产运维保证。** 没有持久会话索引、没有增量备份、重启即丢失 OP 状态；
> **它用于开发与联调，生产必须配置 Postgres 与审计 key。**

`docs/operations.md:168` 同向（内存模式没有链、没有 `Head()`）。报告用自己的理由
"项目把内存模式当作真 OP 的一种部署形态，文档也拿它做容量上界"来维持"中"——前半句（ADR-0001 P4b：引擎同一套）
是真的，但**后一个推论被 ADR-0006 决策 6 直接否掉**：`capacity-planning.md §1` 用内存模式是为了让基准**可跑**
（`Makefile:44-45` 注释：基准跑在内存存储上），并把内存数字称作"**上界**"，不是为了给内存模式的容量背书。
按 VERIFY-BRIEF §3 的判据（"前提是运维主动打开一个明确标着危险的开关 ⇒ 严重度要降"），**中 → 低**。

**降级理由二（更硬的技术反驳）：PERF-5 的保留量外推高估 2 倍。**
探针 `memstore_test.go:297-301` 的外推是 `records = perSecond * 86400 * 30 * 2`——把**每 grant 两条记录都算作保留 30 天**。
但 `memory/oidc.go:306-307`：`accessTTL = time.Hour`、`refreshTTL = 30 * 24 * time.Hour`。
稳态下长期存在的只有 refresh 记录（access 记录只有最近 1 小时那一小撮，在 30 天尺度上是零头）。
所以正确的是 `records ≈ perSecond × 86400 × 30`（再乘 per-record 446 B）：
**1 grant/s 时约 1 103 MiB，不是 2 204 MiB**；512 MiB 的可持续速率约为**每 2.2 秒 1 次授权**，
不是报告写的"每 4 秒 1 次"。结论方向不变（内存模式确实装不下一个月的签发量），但**数字要除 2**。

**降级理由三：报告说"没有任何文档/告警说这件事"，不对。**
`docs/slo.md:65` 有 `Re0AuthMemoryHigh`（`process_resident_memory_bytes` > 400MiB，warning），
`docs/capacity-planning.md:104` 明说这个阈值"比 limit 略低，先于 OOMKill 报警"。
所以"超了就是 OOMKill 且没人会发现"不成立；没有被文档化的是**保留量模型**（892 B/grant × 30 天），
这才是它可以留给文档的部分（修法建议本身是合理的）。

**PERF-5 里我确认为真的两条**：① 项目自己的 `BenchmarkTokenLifecycleWithJanitor` 夹具确实每 1024 条推进 31 天
（`oidc_bench_test.go:60-88`），注释 "population stays bounded by the sweep interval" 对 refresh token 是**误导性的**
（真正界定存活量的是 TTL，sweep 间隔只界定"过期后多久被删"）；② `capacity-planning.md §3` 的堆模型
不含内存模式的保留量。
**探针的一处自身缺陷**：`TestMemStoreSweepStallsConcurrentRequests` 的 `worst` 是**全程最大值且从不重置**
（`memstore_test.go:188,193`），`after` 必然 ≥ `before`，所以这个"停顿"仪器**结构上不可能失败**——它给的是量级
（3.5–5.1 ms vs 1.7 ms），不能当"隔离了扫除期间"的证据。结论由代码（sweep 持 `s.mu`）与第一条探针支撑，仍然成立。

### 2.6 PERF-7：机制、库、接缝我都核了，全部成立；「97%」应撤回，改为分配口径 + 预算余量

读（`$GOMODCACHE/github.com/zitadel/oidc/v3@v3.51.3/pkg/op/crypto.go`）：
```go
type Encrypter interface { Encrypt(string) (string, error) }
type Decrypter interface { Decrypt(string) (string, error) }
func (c *aes256GCMCrypto) Encrypt(s string) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.A256GCMKW, Key: c.key, KeyID: c.keyId}, nil)   // :52 每次调用
func (c *aes256GCMCrypto) Decrypt(s string) (string, error) {
	jwe, err := jose.ParseEncrypted(s, []jose.KeyAlgorithm{jose.A256GCMKW}, []jose.ContentEncryption{jose.A256GCM})   // :76
	decrypted, err := jwe.Decrypt(c.key)
```
`op/token.go:138`：`return crypto.Encrypt(tokenID + ":" + subject)` —— 报告"opaque 令牌就是一个加密的 `id:subject` 串"**逐字成立**。
`op.go:683`：`func WithCrypto(crypto Crypto) Option`；`NewCompositeCrypto(encrypter, decrypters []Decrypter)`
是导出构造；`internal/oidchttp/oidchttp.go:190-196` 已经在用 `op.WithCrypto(op.NewCompositeCrypto(...))`。
**所以"`op.WithCrypto` 是可替换的缝"不是猜想，是现成接口**（自己实现 AES-GCM+base64url 只要满足两个单方法接口）。
报告没说的两点：①这条缝**不只管 bearer**，`op/auth_request.go:614` 也用同一个 Crypto 加密 auth request ID，
换格式要连它一起双读；②"保留 JWE 但缓存 `jose.Encrypter`"这个选项帮助有限（签发路径省一点，**解密路径
`ParseEncrypted` 一点没省**）。

**「97%」应撤回，改为分配口径 + 预算余量**：11 423 ns（`internal/oidchttp/bench_test.go` 的
`BenchmarkIntrospectHandler`）与 340.5 ns（`internal/store/memory/oidc_bench_test.go` 的 `BenchmarkIntrospect`）
来自**两个不同的测试二进制、两次不同负载的运行**，这正好违反报告开头自己定的"只引用同一次运行内的相对倍数"。
**同一份证据里与负载无关的那一半成立**：12 208 B/op vs 192 B/op（store 占 1.6%）、131 allocs/op vs 4——
每请求约 12 KB 分配，大头是 go-jose 的 JWE 解析。但把账算全：单请求是 **µs 级**，业务面 SLO 是
**S4: p99 < 1 s**（`docs/slo.md`），余量约 **10⁴ 倍**；CI **不按阈值卡基准**（ADR-0007 决策 5）。
**所以 PERF-7 是成本观察，不是缺陷，无门槛被触及**；裁定是**维持原状**——继续用 go-jose 标准库，
不自造加密轮子（`docs/dependencies.md` §1）。仅当业务量上到「分配/延迟进入 SLO 预算」时再立项，
届时优先讨论「换令牌语义（随机串 + Redis/DB 查找）」，而非自写 AES-GCM。

### 2.7 PERF-9：四条里两条要改口径

- **(a) 方向错**（与 PERF-1 同一处）：`capacity-planning.md:20` 的表写 512，`:113` 写"缺省值 = max(64, max_conns×8)=128"。
  报告断言"实现站在 §4 这边、表里那行是错的"。实际上 **`deploy/k8s/base/configmap.yaml:24` 与
  `config/re0auth.example.toml:46` 都显式写 `max_in_flight = 512`**，派生默认在出厂部署里根本不生效。
  真相是"两个数在说两件不同的事（派生默认 vs 出厂取值），文档没说清"，而不是"其中一个错"。这一处判断错位
  直接造成了 PERF-1 的 708 MiB。**部分成立，但结论要反过来写。**
- **(b) "已过期"不成立，覆盖缺口成立**：`capacity-planning.md:25` 同一节里自己就写着 `make bench` 的实际命令是
  `go test -run '^$' -bench . -benchmem ./...`（`Makefile:51` 一致），`:28-29` 那句是在说**三个具名基准各自对应哪条热路径**，
  不是"全仓只有三个基准"。真正的缺口（无 `/oauth/token`、无数据面）成立且有价值。
- **(c) 成立但引文被截取**：`:105-106` 原文是"**Go 堆之外**的主要占用来自连接缓冲与并发请求的响应体；
  …所以「在途请求数 × 平均响应体」是堆压力的主项"。前半句讲的是**堆外**，后半句才是堆内判断；
  错的是后半句在内存模式下的普适性（30 天保留量才是主项），报告按整句引用略过了这个转折。
- **(d) 成立**：`§4:131-139` 给的是机制+拐点判据，没有闭式公式；`64/commit RTT` 是新增量。

### 2.8 跨条目的测量有效性检查（报告自定的规矩守得怎样）

报告开头声明"绝对 ns/op 不作为容量数字引用"，只引 ①`B/op`/`allocs/op` ②同一次运行的相对倍数 ③复杂度/量纲。
**但 PERF-3/4/5/6 的四条结论都消费了绝对时长**：1.577 ms（批窗口）、1.467 µs/row（外推）、
1.041 ms/6.014 ms（sweep）、259 µs/call（设备插入）。
- 其中三个是**稳健**的：批窗口 1.5 ms 对 1 ms 常量（1.5× 余量，负载解释不掉）；sweep 与设备插入用的是
  **倍数**（40k→200k 记录、200→20400 live，25 ns→39 ns、0 s→333 µs），比值与负载无关。
- **只有一个结论真正依赖一个不可复现的绝对时间**：PERF-4 的 `1.467 µs/row × 1e8 > 45 s`。
  本机同时有十几个代理，这个数可以差 2–3 倍；我的复跑是 1.342 µs/row（1e8 ≈ 2m14s）。
  **它活下来的原因是余量足够大**（要推翻需快 3 倍以上），但它守卫的断言只覆盖 1e8；
  报告若真要把"阈值 ≈ 1e7 行"写进文档，那个阈值就不可复现（±3×）。
- **PERF-1 的核心数字不受负载影响**：它是 `HeapAlloc` 差值，且我用 n=1..32 的线性性验证过。
  **PERF-7/8/12 的承重证据（`B/op`、`allocs/op`）与负载无关**，我逐条复现。

---

## 3. 我确认的条目：我实际执行了什么

| ID | 我执行的命令 | 承重输出行 |
|----|----|----|
| PERF-1(测量) | `go test -count=1 -run TestProbeInFlightBytesPerDataPlaneRequest -v ./internal/zzprobe/perf/` | `live heap +185723736 bytes over 32 in-flight requests = 5803867 bytes/request` |
| PERF-1(归因，我的) | `go test -count=1 -run TestVerifyInFlightAttribution -v ./internal/zzprobe/verifyperf/` | `n=1 … per-request=5766368 B`；`n=32 … 5800310 B`；`marginal n=16->32: 5798682 B`（**无固定项**） |
| PERF-1(口径，我的) | `go test -count=1 -run TestVerifyInFlightAfterTheReadIsTheSameQuestion -v ./internal/zzprobe/verifyperf/` | `parked in the response write (read complete): live heap +33567016 = 4195877 B/request`（**读完只有 4.00 MiB**） |
| PERF-1(持有者，我的) | `go test -count=1 -run TestVerifyInFlightWhoHoldsTheBytes -v ./internal/zzprobe/verifyperf/` | 精确 inuse profile 前 10 stack 全是 `io.ReadAll → rawFetch (service.go:517)`；`debug.FreeOSMemory` 后仅 −32 B/request（**不是未清扫垃圾**） |
| PERF-2(串行次数，我的) | `go test -count=1 -run TestVerifyRawPathRefreshAmplification -v ./internal/zzprobe/verifyperf/` | `finished in 484ms … call 1 POST /oauth/token (121ms) / call 2 GET /api/big (121ms) / call 3 POST /oauth/token (121ms) / call 4 GET /api/big (121ms)` |
| PERF-2(Retry 未接线) | `grep -rn "httpclient\.Retry\("` | 仅 `cmd/referencesource/main.go:143` + 一个探针文件 |
| PERF-3 | `go test -count=1 -run 'TestPerfProbe' -v ./internal/store/postgres/` | `mean=1.513ms worst=1.712ms (batcher window=1ms)`；`avg batch 64.0`、`ceiling 64000 rows/s` |
| PERF-4 | 同上 | `verify: 1.342µs/row, 744926 rows/s`；`1e+07 rows: 13s`、`1e+08 rows: 2m14s` |
| PERF-5/6 | `go test -count=1 -run 'TestMemStore' -v ./internal/zzprobe/perf/` | `records=200000 sweep=7.852ms per_record=39ns`；`~20400 live → 333µs/call`；`892 bytes/grant, 446 bytes/record` |
| PERF-7(库) | 读 `$GOMODCACHE/…/v3@v3.51.3/pkg/op/{crypto.go,token.go,op.go}` | `token.go:138 crypto.Encrypt(tokenID + ":" + subject)`；`crypto.go:76 jose.ParseEncrypted`；`op.go:683 WithCrypto` |
| PERF-8/12(分配量) | `go test -count=1 -run '^$' -bench BenchmarkProbe -benchmem -benchtime=50x ./internal/zzprobe/perf/` | `RawProxy4MiB 10023174 B/op 252 allocs/op`；`DataPlaneResource 29447 B/op 210 allocs/op`；`TokenExchange 39363 B/op 395 allocs/op` |
| PERF-8/12(端到端) | `go test -count=1 -run '^$' -bench 'BenchmarkBusinessPlaneBearerMe' -benchmem -benchtime=300x ./internal/httpapi/` | `14420 ns/op 14887 B/op 180 allocs/op`（报告 14 910 B/op / 180 allocs ✓） |
| PERF-9(k8s 默认) | 读 `deploy/k8s/base/{configmap,deployment}.yaml` + `config/re0auth.example.toml` | `configmap.yaml:24 max_in_flight = 512`；`deployment.yaml:87 limits: {cpu: "1", memory: 512Mi}` |

---

## 4. 我未能验证的

1. **任何需要真实 Postgres 的观察**（无 Docker、无本机 Postgres）。仍只有行级证据，逐条标"读；无 DB 执行"：
   PERF-3 的"commit RTT 2–5 ms"（探针是 `time.Sleep` 注入的参数，报告也承认）、PERF-4 的"把 10 列读出来的成本"
   （流式 vs 缓冲我只读到 `rows.Next()` 循环，没测过 pgx 在大表上的真实读取速率）、PERF-8 的"12–15 次往返"。
2. **4 MiB 体从真实上游到达**：我用 stub Doer，DNS/TLS/socket 缓冲不在数里（报告同样承认）。
   PERF-1 的 5.8 MB 因此是"服务端自己持有的字节"，真实进程还多一份内存侧的 socket 缓冲。
3. **PERF-2 的 80 s 我没有真的等 80 s**：我证明的是"4 次严格串行出站调用" + 行级读到 20 s deadline
   与"两者共用一个客户端"。把 20 s 换成实测需要真挂住的上游，且会让测试跑 80 s×N。
4. **`make perf` / `make load` 未跑**（同报告；40 分钟且在十几个代理的负载下无意义）。
   所以 `capacity-planning.md:50` 的 `237824 requests / 23782.4 req/s` 我既未复现也未否证。
5. **`-race` 未用于本区域**（我的结论都是确定性计数与堆测量，不依赖竞态检测器）。
6. **PERF-11 的 `perfreport` "Reading notes 在本地是误导"** 这条我没核（要跑 `make perf` 才看得到渲染结果）。
7. **`BRIEF.md` 缺失**（见第 0 节）：如果真正的简报里还钉了别的"不得报告项"，我可能漏判一条"已知"。

---

## 5. 我在复核中发现的新问题（`V-<n>`）

### V-1 （修正 PERF-1 与 PERF-9(a)）出厂部署的 `max_in_flight` 是 512，不是 128：正确的内存乘积是 2834 MiB

- `deploy/k8s/base/configmap.yaml:24`：`max_in_flight    = 512`（同一套 manifest 的 `deployment.yaml:87`
  就是 `memory: 512Mi`，`:44` 的 DATABASE_URL 使其为 durable）。
- `config/re0auth.example.toml:46`：`max_in_flight = 512`，紧跟在其 `:39-43` 的说明
  "Leave this out and a durable deployment gets max(64, max_conns × 8) instead (128 with the default pool of 16)" 之后。
- 实现：`config.go:470-471`（文件有值即采用）、`:577-580`（仅在 `< 0` 时派生）。
- 乘上我复现的 5.80 MB/请求：**512 × 5.80 MiB = 2834 MiB ≈ 5.5 × 512Mi limit**。
- 严重度影响：PERF-1 的阻断级判定**更站得住**，但它的数字必须改；PERF-9(a) 的"表里那行是错的"
  要改成"表与 §4 在说两件不同的事（出厂取值 vs 派生默认）"。
- 附带：部署里**没有 `GOMEMLIMIT`/`GOGC`**（`deploy/`、`docs/`、`config/` 全量零命中），
  所以 Go 运行时不会尊重 cgroup limit；"设一个 GOMEMLIMIT"是最便宜的临时缓解（但它不硬约束活堆，
  报告提的按字节预算仍是正解）。

### V-2 （量化 PERF-1 的口径）5.8 MB 里只有 4.19 MB 是"响应缓冲"，另 1.6 MB 是 `io.ReadAll` 被取代的增长数组

同一请求停在两个位置，差 1.6 MB（38%）：

```
停在 io.ReadAll 中间（报告的探针位置）:  5 800 000 B/request
停在响应写里（上游已读完）:              4 195 877 B/request = 4.00 MiB
```

精确 inuse profile 显示后者是**一份** `[]byte`（`rawFetch → io.ReadAll`），前者在 81 920 B … 1 916 928 B
等多个尺寸上**各有 8 个活对象**（8 个在途请求各一份）。对 OOM 场景（上游挂住 = 请求停在读里）报告的 5.8 MB 是对的，
但"整体缓冲的代价是每请求 5.8 MB"这句话应当写成"每请求至少 4.19 MB，停读期间实测 5.80 MB"。
**这条对修法有直接影响**：报告建议的①流式转发能省掉全部；而一个便宜的中间改法
（`Content-Length` 已知时 `Grow`/预分配一次 buffer）只能省掉那 1.6 MB 里的部分，省不掉 4 MiB 本体。

### V-3 （推翻 PERF-3 标题后半）饱和时 1 ms 窗口的代价是 0，不是"每请求 +1 ms"

`auditbatch.go:169-178`：批满 `auditMaxBatch=64` 时 gather 立即结束，定时器被丢弃。
报告自己的 `TestPerfProbeAuditBatchIsSingleWriter` 就是反证：`avg batch 64.0`、达到率 = `64/commit` 天花板。
所以"每一个被审计的请求至少要等这个窗口"只对**队列空时**到达的请求成立；持续负载下约束是 commit RTT +
排队，不是 1 ms。文档里要写的是两条**分开**的结论（低负载 +1 ms 地板；高负载 64/RTT 天花板）。

### V-4 （补强 PERF-2）熔断器不是这个场景的缓解：401 是 4xx，被明确排除在失败之外并把计数清零

`httpclient/circuitbreaker.go:76-78`：
> Only failures that say something about the upstream count: a transport error the caller did not cause, or a 5xx.
> **A 4xx is the request's problem … so neither is recorded.**

而 80 s 的形状恰恰是"慢 token 交换（transport 超时）+ 快 401（4xx，记为成功）"交替四次
（我的探针输出就是 `oauth/token`(121 ms) → `/api/big` 401(121 ms) → `oauth/token`(121 ms) → `/api/big` 401(121 ms)）。
所以**不会因为"同一个源连续失败 5 次"而熔断**，报告"128 个慢请求可以各占 80 s"这一条不需要因为熔断而打折。
（唯一会熔断的形状是"资源端点也挂住"，那时请求会在 20 s 处就结束，而不是 80 s。）

### V-5 （PERF-5 的数字修正）内存模式保留量被高估 2 倍

`memory/oidc.go:306-307`：`accessTTL = time.Hour`、`refreshTTL = 30*24h`；
`memstore_test.go:297-300` 的外推按"每 grant 2 条记录 × 30 天"算。
稳态下 30 天窗口里只有 refresh 记录留存 ⇒ 正确值 ≈ **446 B/refresh 记录**：
1 grant/s → ~1 103 MiB（不是 2 204 MiB），512 MiB 可持续 ≈ **每 2.2 秒 1 次授权**（不是每 4 秒）。
方向不变，数字要改；顺带建议探针把外推式写成"1 小时内的 access 记录 + 30 天内的 refresh 记录"。

### V-6 （探针缺陷）`TestMemStoreSweepStallsConcurrentRequests` 结构上不可能失败

`memstore_test.go:188/193` 的 `before`/`after` 都是同一个**从不重置**的 running max，
所以 `worst_during ≥ worst_before` 恒成立，这个"停顿"仪器无法证伪自己（也没有"对照组"）。
它给出的 3.5–5.1 ms 量级与 `sweep=3.5 ms` 一致，结论由代码（`SweepExpired` 持 `s.mu`）支撑，
但报告在附录里把它与"带反空转断言"的两条并列，是**高估了它的证明力**。修法：两段之间重置 `worst`。

### V-7 （PERF-4 的量化修正）"从约一千万行起就不可能完成"应为"纯 CPU 约 3×10⁷ 行"

用报告自己的数（1.467 µs/row）与我的复跑（1.342 µs/row），纯 CPU 穿过 45 s 的行数是
`45 s / 1.34–1.47 µs ≈ 3.1–3.4 × 10⁷`；而报告标题写 1e7（它自己的表：1e7 → 13–15 s = 预算的 1/3）。
如果要把阈值写进 `operations.md`，必须写"数量级 10⁷–10⁸，按每行成本实测换算"，
因为每行成本在本机负载下可差 2–3 倍（这也违反报告"不引绝对时长"的自我约束）。

---

## 6. 我认为**被低估**的严重度

1. **PERF-1 的规模被低估 4 倍**（见 V-1）：报告按派生默认 128 算出 708 MiB，而出厂配置是 512，
   ⇒ 2834 MiB。它自己给出的结论（"需要一个按字节的共享预算，而不是只按请求数"）不但成立，
   而且**在出厂配置下 1 秒就能被打破**（一次 512 并发的慢上游）。若要保留"阻断上线"，这是它最硬的形态。
2. **PERF-2 的触发性被低估**：报告把它写成"实际是算术、未实测"，但熔断器**不会**救它（V-4），
   而 401 会让失败计数归零；同时 `max_in_flight` 只限数量不限时长（`middleware.go:393-418`），
   所以"上游变慢"这一个正常运维事件就能同时产生 512 条 80 s 的占位。
   我认为它的严重度**高**是对的，写法上应当把"熔断能兜住"这个直觉先明确否掉。

---

## 附：我的探针与命令索引

| 探针 | 文件 | 测什么 / 试图推翻什么 |
|---|---|---|
| `TestVerifyInFlightAttribution` | `internal/zzprobe/verifyperf/verify_perf_test.go` | PERF-1 的 5.8 MB 是每请求线性项还是被摊薄的全局量（n=1/4/16/32 + 四档 body） |
| `TestVerifyInFlightWhoHoldsTheBytes` | 同上 | 谁拿着这些字节（`MemProfileRate=1` 精确 inuse profile + `debug.FreeOSMemory` 对照） |
| `TestVerifyInFlightAfterTheReadIsTheSameQuestion` | 同上 | 停在"读完"而不是"读中间"时的每请求占用（4.00 MiB vs 5.53 MiB） |
| `TestVerifyRawPathRefreshAmplification` | 同上 | PERF-2 的"四次串行出站调用"是否真的串行、真的有四次 |

```
gofmt -l internal/zzprobe/verifyperf/            # 空
go vet ./internal/zzprobe/verifyperf/            # 空
go test -count=1 -run TestVerify -v -timeout 15m ./internal/zzprobe/verifyperf/
```

未修改任何已跟踪文件；未改被复核的报告；未碰其它代理的探针。
