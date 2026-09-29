# 区域 Z15：性能 / 容量 / 内存 / 分配 — 第七轮**对抗性复核**

复核对象：`docs/audit-7/findings/Z15-performance-capacity.md`（下称「报告」）、
被复核探针 `internal/zzprobe/audit7/z15performancecapacity/`。
复核探针：`internal/zzprobe/audit7/z15verify/`（`doc.go` + `verify_test.go`，均带 `//go:build audit7`；
**未改**被复核者任何文件，未改任何被跟踪文件）。

## 方法与命令

- 逐条读报告引用的 `file:line`；亲自跑被复核探针并核对「红的理由」与报告声称一致。
- 另写 5 个**独立**探针（不复用被复核 fixture，避免同一仪器缺陷同时骗过两处）。
- 未起真进程：本区结论全是确定性 `allocs/op`、源级形状与基准子进程，端口 18502 用不上。

```sh
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z15performancecapacity/...   # 4 红 2 绿，与报告一致
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z15verify/...                # 4 绿 1 红（红=新发现）
go build ./... ; go vet ./... ; go vet -tags audit7 ./internal/zzprobe/audit7/z15verify/...  # 全 exit 0
gofmt -l internal/zzprobe/audit7/z15verify/                                             # 空
```

被复核探针实测（复现报告数字）：`DeleteAuthRequest` 500→50000 codes：2.376µs→243.162µs（**x102.3**，
报告 x106.6）；`peak_records: 2000x→2048 ; 200x→0`（200x 退出码 0）；
压缩 `1 coding=16.0 / 2 codings=17.0（delta 1.0）`；sweep 形状 `10 tables, LIMIT present=false, one transaction=true`。

---

## 逐条裁定

### Z15-1 CONFIRMED，P2 维持 — 但**阳性对照是错的**

- 形状属实：`postgres/sweep.go:26-37` 10 表、`:59-66` 每表 `DELETE FROM %s WHERE %s < $1` **无 LIMIT**、
  `:51`/`:67` 共用一个事务；`postgres.go:128` `StatementTimeout: 30s` + `:235-246` 每连接 RuntimeParams
  （statement_timeout 是**按语句**计的）；`main.go:405` 15 分钟一轮、`:1101-1116` 失败只 Warn+continue。
- 告警面缺口核实：`internal/observability/observability.go` 与 `deploy/prometheus/re0auth.rules.yml`
  **零个** "sweep" 字样（grep 空）⇒ 停摆确无可查询序列。与主验证 V-19 结论一致。
- **「一个事务」是文档化决定**：`sweep.go:42-45` 自述「a sweep is a single consistent step…retry is always safe」。
  报告把它列为缺陷论证的一部分；主验证 V-19 已裁定「该注释回答的是安全、不是推进」，核心增量（无每轮有界推进）
  因此成立。**但**报告的修法「**每表一个事务**」直接推翻该决定，按简报 §5/§7 这部分应写成「判断」，不应混进 finding。
- **仪器的对照不成立（复核新证据）**：报告用 `memory/oidc.go:945-980` 当「逐条删除 ⇒ 内存后端天然有界推进」的阳性对照。
  我的独立探针 `TestZ15VMemorySweepRemovesWholePopulationInOneCall` 证明：**一次** `SweepExpired()` 调用就把**整个**
  过期总体删完并持全局锁——`1000 → removed 1000 (remaining 0)`、`100000 → removed 100000 (remaining 0)`。
  「逐条」是删除粒度，不是「每轮有界」；该后端与 Postgres 在**同一不变量**上同样违规（也即 PERF-5）。
  该对照不能支持本条声称的不变量（源级事实仍成立）。
- 状态/严重度：源级 CONFIRMED、停摆 HYPOTHESIS 已如实标注；P2 维持（需大积压作前提，无指标独立支持 P2）。

### Z15-2 CONFIRMED，P3 维持 — 证据比报告写的**更硬**

- 独立复现（`TestZ15VJanitorGuardUnreachableBelow1024`，不用被复核者的解析器）：
  `2000x → 2048 peak_records`，`200x → 0 peak_records`，两次均 exit 0；`oidc_bench_test.go:81-91`
  的采样/sweep/`b.Fatal` 全在 `i%1024==1023` 内。
- **报告的一处事实错误**：它说「本仓库探针与 **perfreport** 都用 `-benchtime=Nx`」。`cmd/perfreport` 从不传
  benchtime（grep 空）。真正用 200x 的是 **CI 自己**：`.github/workflows/ci.yml:394-405`
  `go test -run '^$' -bench . -benchmem -benchtime=200x ./... | tee bench.txt`，其门禁只数 `ns/op` 行数 ≥3
  （`grep -c 'ns/op'`），**从不读 peak_records**。⇒「绿 CI 上印着 0 的容量界」比报告所述更确凿。
- 定级：P3 维持（纯测量仪器缺陷，无运行时/安全影响）。按 §6「报成功/计数 0/exit 0」的口径可辩 P2，我不越权升。
  属 **PERF-11 补充**（`docs/audit-5/findings/performance.md:381-405` 第 3 条），非重报。

### Z15-3 CONFIRMED，P3 维持

- 机制逐项核实：`memory/oidc.go:450-461` 在 `s.mu` 内 `for k,c := range s.codes`；`:445` 按 `TokenHash(code)` 键控、
  无 requestID 索引；zitadel `pkg/op/token.go:50`（`CreateTokenResponse`）确在 `request.(AuthRequest)` 成立时
  **每次**调 `DeleteAuthRequest`；`postgres/oidc.go:288-308` 定向 `DELETE FROM oidc_codes WHERE request_id=$1`，
  索引 `0012_indexes.sql:13` 存在。报告写 `:288-299` 而 DELETE 在 `:300`——行号微差，机制无误。
- 非重报：PERF-5(`SweepExpired`)/PERF-6(`StoreDeviceAuthorization`) 是另外两个方法，本条是**第三例**
  （且是唯一「Postgres 有索引、内存没有」的一例）。P3 与第五轮对内存后端的既定口径一致。

### Z15-4 CONFIRMED，P3 维持 — 归因已被我更硬地锁定

- 独立测量 `TestZ15VCompressionSplitScalesPerConfiguredCoding`：客户端 `gzip` 放最后，服务端 coding 数
  n=2/3/4 的 delta = **1.0 / 2.0 / 3.0**（恰为 n−1）⇒ 确认是「按服务端偏好对**每个** coding 重新 `Split` 一次」，
  而非任何一次性开销。路由对照：`gzip;q=1.0`（通用路径）=19.0 vs 快速路径 17.0 ⇒ 测的确实是 `compress.go:180-193` 快速路径。
- **被复核探针的「阳性对照」结构上是空的**：`if delta<1 {t.Fatalf} ; if delta>=1 {t.Errorf}` 覆盖全部实数，
  该测试**永远红**，无法区分「仪器坏」与「发现成立」。我的独立探针补了真对照（n 线性）。
- 报告同段一句带过的通用路径 `make(map[string]float64)`（`:245`）也是可测的每请求分配：带 `;q=` 的头部比
  快速路径**多 2 allocs/req**（map+切片）。可作 Z15-4 的量化补充，不单列。
- P3 维持：单请求 1 次小切片分配属噪声级（对照 PERF-12 的 28-40 allocs/req 固定开销），但成本随**服务端配置**增长、
  修法三行，作 P3 提示合规。

---

## 新发现

### Z15V-1（P2）会话清扫与 Z15-1 跑在**同一个 15 分钟循环**上，同样无界

- 证据（红）：`internal/zzprobe/audit7/z15verify/verify_test.go::TestZ15VSessionsSweepIsAlsoUnbounded`
  → `Sessions.SweepExpired: 2 DELETE statements, LIMIT present=false; same sweepLoop closure calls
  db.SweepExpired=true sessions.SweepExpired=true`。
- 机制：`cmd/re0auth/main.go:942-951` 的 `sweep` closure 依次调 `db.SweepExpired` 与 `sessions.SweepExpired`，
  由 `:405` 的 `sweepLoop(..., 15*time.Minute)` 驱动；`postgres/sessions.go:144`
  `DELETE FROM sessions WHERE expiry < $1` 与 `:148-151` 的相关子查询 anti-join（清 `session_subjects` 孤儿）
  **都无 `LIMIT`**。报告只把 anti-join 代价放进「未能到达」，未报这是**第二处无界维护删除**。
- 与 Z15-1 的差别（定级依据）：两句各自 autocommit，不是 all-or-nothing；第一句成功即已有推进 ⇒
  「永久停摆」弱于 Z15-1。但单句撞 30 s `statement_timeout` 时该句整句回滚、第二句永不执行（孤儿索引行持续累积），
  仍是「维护每轮必须有界推进」这条不变量的违规。故 P2（前提高），与 Z15-1 同级但弱于它。
- 修法：同 Z15-1（`ctid IN (SELECT ctid … LIMIT $2)` 的有界批 + 每表/每句独立提交 + `sweep_*_total` 计数），
  anti-join 也要分批。相关编号：**Z15-1 的同族补漏**，非第二至六轮重报（第六轮仅记「失败只打日志」/内存 janitor）。

---

## 严重度复核与重报/误报检查

- **无虚高**：最高 P2（Z15-1，与主验证 V-19 一致），其余 P3；Z15V-1 P2。
- **无误报文档化决定**：Z15-1 的「一个事务」确为文档化决定（`sweep.go:42-45`），但报告的核心增量是无界推进；
  唯一越界处是**修法**直接推翻该决定（应为「判断」）。
- **无第二至六轮重报**：PERF-8/11/12 真实存在且引用准确（`docs/audit-5/findings/performance.md:381-435`；
  索引引用 `0001:65,76 / 0003:43 / 0008:30,40,50,65 / 0012:34,35 / 0017:13` 逐条核对全中）；G-2 已显式区分。
- **绕过缺口的检验**：4 条红探针的「红」都源自被断言的不变量方向，且各带阳性对照（除 Z15-4 的对照我已在上面证伪）。

## 探过没破（复核过的绿，无桩）

1. 被复核的 2 绿我复跑并读了夹具：`RateLimiter.Check` 0 allocs 带 anti-vacuity（真放行 + `Size()==1`）；
   `Registry.Sources` 快照独立（覆写后不复现）。**均走真实代码，无替身桩**，不存在「夹具用桩造成的假绿」。
2. `GOMEMLIMIT=384MiB`（`deployment.yaml:60-61`）/ `limits.memory=512Mi`（`:105`）确认在位。
3. `compress.go:360-369` 首个 ≥minSize 的写直入编码器、无二次缓冲（复读，与 PERF-11 第 5 条一致）。
4. 独立探针 `TestZ15VCIRunsBenchmarksAt200x`、`TestZ15VMemorySweepRemovesWholePopulationInOneCall` 绿——分别是
   Z15-2 语境与 Z15-1 对照的**加固守卫**。

## 未能到达（残余盲区）

1. 无 Docker/本地 PG：Z15-1/Z15V-1 的「撞 timeout 后停摆」仍只有源级 + 算术；删除计划、长事务对 autovacuum 的影响、
   anti-join 在真实 `session_subjects` 上的执行计划均未测。需 CI 的 `postgres:16`。
2. GOMEMLIMIT/连接池标定：本机 32GB 且多代理并行，做不出可引用的内存/往返结论（同报告）。
3. 未跑 `-race`（会破坏 ns 比值口径），未跑全仓 `go test ./...`（简报 §2）。
