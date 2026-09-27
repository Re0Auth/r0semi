# 配置 / 组合根与启动路径 / 可观测性 —— 对抗性复核（config-startup-disclosure-VERIFIED）

复核对象：`docs/audit-5/findings/config-startup-disclosure.md`（CS-1 … CS-10）。
复核者立场：**证伪**。凡我确认的，都在第 3 节给出我自己跑的命令与那一行承重输出；凡我降级或推翻的，第 2 节给出代码/文档引证。

## 0. 复核环境与三处方法论说明

- Go 1.27.1 windows/amd64。未跑 `go test ./...`，未改任何已跟踪文件，未碰他人的探针文件。
- 我的探针（**新包，只含 `_test.go`**）：`internal/zzprobe/verifyconfig/verify_listen_test.go`、
  `verify_process_test.go`。第二个文件**启动真的 `cmd/re0auth` 二进制**（`TestMain` 里 `go build -o <temp>`），
  读它真的写下的日志。这是本轮唯一的加强手段：报告里若干结论原本只有「测试进程内的 handler」或「读代码到行」。
- **`docs/audit-5/BRIEF.md` 不存在**（`Get-ChildItem scratchpad -Recurse` 只有 `findings/`、`probes/`、
  `runtime/`、`VERIFY-BRIEF.md`）。所以「不得报告的文档化非目标」清单我无法照它核对，只能用
  `CHANGELOG.md`、两份 security-audit、ADR（`docs/operations-decision.md` 等）与被审代码注释代替。
  这影响「已知（非发现）」这一列的强度，我在每条里说明用了哪份替代清单。
- **工作区有别人的未提交改动**（`git diff --stat`：`internal/federation/unbind.go`、`internal/httpapi/server.go`、
  `CHANGELOG.md` 等 8 个文件）。我读过 `unbind.go` 的 diff：它改的是「源从配置移除后仍可解绑」，
  **token_class 的读法一字未动**（仍是 `src.TokenClass == tokenClassLongLived` 否则算可撤销）。行号取自当前工作区。
- 任务提示里说的两个 PowerShell 陷阱我直接绕开了：所有动态实验都写在 Go 测试里，没有用 PowerShell 拼命令行。

---

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|----|----|----|----|----|
| CS-1 | 高 | **中高** | **部分成立** | 两个豁免 + 「每请求一次池往返」都成立（真进程实测限流豁免；`pgxpool.Ping` 源码确认取连接做一次往返），但「几百并发就占满池」只在 DB 往返 ≳1ms 时成立（同机健康 DB 要 ~10⁴ req/s），且报告修法①的 503 分支会**重新引入**代码明确要避免的「探针洪水把健康实例摘出轮转」。 |
| CS-2 | 中 | **低** | **部分成立（安全部分推翻）** | 同端口共存我复现了，但运维面**始终只在 loopback**：报告说「`curl localhost:8080` 落到运维面」，实测方向相反（`localhost`→**公网面**，`127.0.0.1`→运维面）；通配×通配拼写相撞时 OS 直接拒绝第二个 bind（fail-closed）；`CHANGELOG.md:70-75` 已把「唯一检查是不等于 addr」记为被替换掉的旧检查。 |
| CS-3 | 中 | 中 | **CONFIRMED** | 真进程接受 `["0.0.0.0/0","::/0"]` 且日志**一个字都没提**；伪造 `X-Forwarded-For: 203.0.113.77` 真的进了访问日志的 `client=` 字段。项目对 `expose_internal`/`allow_private_addresses` 都要显式承认，只有它没有任何闸门。 |
| CS-4 | 中 | 中 | **CONFIRMED** | 真进程分别以 `long_live` / 缺省 / `session` 三种写法正常启动；对照 `storage.driver="mysql"` 退出 1。`upstreamkit` 与 conformance 校验同一枚举而服务端不校验，且错误方向是「静默把 unsupported 变成 done」。 |
| CS-5 | 中 | 中 | **CONFIRMED** | 真进程实测：`DATABASE_URL` 已设、日志却写 `because="no DATABASE_URL"`；`RE0AUTH_STORAGE_DRIVER=postgres` 完全无效；**照 README 快速开始 `cp` 的示例配置 + 不设 `DATABASE_URL` 直接拒绝启动**（与 README.md:30 相反）。 |
| CS-6 | 低 | 低 | **CONFIRMED** | 真进程**完整**启动日志（含 `listening` 与 `internal surface listening` 两行，报告的探针从未走到）里，8 个开关一个都没出现。唯一边界：`internal surface listening addr=…` 本身把生效的内部监听地址打了出来。 |
| CS-7 | 中 | **低** | **CONFIRMED（降级）** | 真进程实测：一次抓取 + 两次 pprof（合计 20.6 KB 响应）产生 **0 字节**日志，公网 3 次请求产生 3 行。机制成立，但它是**取证缺口**而非暴露面，前提是「已经能到 9090」。 |
| CS-8 | 低 | 低 | **部分成立（读；无 DB）** | `drain()` 里 `flush` 的 `<-b.stop` 分支确实总是就绪，但 `select` 在「队列有货」与「stop 已关」之间**随机**选择，期望每批 ~2 行，不是报告说的「每行一个事务」；「没有总预算」这个结论不变。 |
| CS-9 | 低 | 低 | **CONFIRMED** | 全仓 grep：`RE0AUTH_DATABASE_URL` 在 `*.go` 里 **0** 处，在 `docs/` 里 **1** 处（`docs/runbooks.md:27`）；`RE0AUTH_STORAGE_DRIVER` 全仓 **0** 处。 |
| CS-10 | 提示 | 提示 | **CONFIRMED** | 示例文件里 `# Environment override:` 恰 **7** 行，代码里读取的 `RE0AUTH_*` 是 **18** 个名字，差集与报告列的完全一致。 |

---

## 2. 我降级、限定或推翻的部分（本文件最重要的一节）

### 2.1 CS-1：机制 CONFIRMED，但「高」的两个支点都撑不住，且修法①与代码自己的理由冲突

**（a）探针证明了什么。** 我重跑了 `go test ./internal/zzprobe/startup/ -count=1 -v`（全绿），承重两行：

```
startup_probe_test.go:175: 8 /readyz requests were served with the rate bucket already empty
startup_probe_test.go:228: 32 concurrent /readyz calls were all admitted while max_in_flight=1 was saturated;
                           peak concurrency inside the readiness check = 32
```

这个夹具（`blockingReady`）**替换掉了真正的就绪函数**，所以它证明的只有「中间件放行」，不证明「每次调用取一条池连接」——
报告自己也是这么标注的（「durable 部署下每次调用取一条池连接是 `file:line` 读到，无 DB 未执行」）。我补上那条链的**源码级**证据：

- `internal/httpapi/health.go:44` `s.ready(ctx)` ← `cmd/re0auth/main.go:774` `return store.db.Ping`
  ← `internal/store/postgres/postgres.go:268` `db.pool.Ping(ctx)`
  ← `pgxpool@v5.11.0/pool.go:850-857`：`c, err := p.Acquire(ctx); defer c.Release(); return c.Ping(ctx)`
  ← `pgx/v5@v5.11.0/pgconn/pgconn.go:2162`：`return pgConn.Exec(ctx, "-- ping").Close()`。
  即：**一次池连接获取 + 一次真实网络往返**（语句是注释，服务端几乎不做工作，但往返是真的）。

**（b）真进程实测（我执行的）。** `/readyz` 在公网监听器上、匿名、200；同一地址上 `/v1/me` 已经 429：

```
verify_process_test.go:287: 10 anonymous GET /readyz on the public listener all returned 200
                           while GET /v1/me on the same address returned 429
```

所以「公网可达」与「限流豁免」都是真的。补充两条报告没写的**支持**证据：
- `deploy/k8s/base/ingress.yaml:21` 是 `path: /`（Prefix）且**没有任何 nginx 限流注解** ⇒ 基线部署里
  `/readyz` 从公网直达，上游也没有限流。（报告在「判断」里假设「入口反代必有限流」——基线并不成立。）
- 「限流豁免」确实已被文档化：`docs/operations.md:121`、`docs/api-design.md:369-372`、
  `docs/security-audit-2.md:299`、`README.md:158`。但**「免并发上限」与「每请求一次池往返」的并集没有任何文档**：
  我 grep 了 `docs/**` 与 `README.md` 的全部 `healthz|readyz` 命中（7 处），没有一处提到 `max_in_flight` 与探针的关系。
- `cmd/re0auth/main.go:388-391` 的注释说明作者的心智模型是**反向**的：「连接池是 `/readyz` 唯一以 503 报告的依赖，
  把它导出，好让事故里有运维该看的数字」——即池饱和是 `/readyz` 的**输出**，不是它的**后果**。

**（c）量化：要多少请求/秒。** 默认值逐条落实：池 `MaxConns = 16`
（`internal/store/postgres/postgres.go:125`）；durable 的并发上限 `max(64, 16×8) = 128`
（`cmd/re0auth/config.go:305-337`，`maxInFlightPerConn=8`、`minMaxInFlight=64`）；限流 50/s、burst 100
（`cmd/re0auth/config.go:300-301`）；k8s 基线把 `max_in_flight` 写成 512（`deploy/k8s/base/configmap.yaml:24`）。
每次 `/readyz` 占用一条池连接的时间 ≈ DB 往返 L，所以**池容量 ≈ MaxConns / L 次/秒**，攻击者要「占满」必须
持续提出 ≥ 16/L 次/秒：

| DB 往返 L | 需要的持续请求速率 | 评注 |
|---|---|---|
| 0.2 ms（同机） | ~80 000 /s | 不可能来自单一主机，且已超过服务自身 HTTP 处理上限 |
| 1 ms（同集群） | ~16 000 /s | 单一 VM + keep-alive 可达（约 10–50 Mbps），但要求服务器本身能吐 1.6 万 req/s |
| 5 ms（跨 AZ） | ~3 200 /s | 便宜 |
| DB 卡住（无响应直到 2s 界） | **8 /s** | 16 条连接各被占住 2s；此时每个探针还会让该连接被 pgx 判废，触发重建 |

**结论**：报告「几百个并发连接就能让池持续被占满」在 L ≳ 1ms 或 DB 已经变慢时成立，在「同机、健康的 DB」下不成立；
「攻击成本近乎为零」是夸大。但**恰恰在 DB 已经吃力的那一刻，攻击成本塌缩到每秒个位数请求**——这条放大效应报告只在
「每个请求最多占住 2s」一句里隐含，没有点出它才是真正承重的场景。所以我不推翻它，但把它从「高」放到「中高」，
并要求把前提写明。

**（d）修法与代码自己的理由。** 报告的修法②（把依赖检查改成 1s 背景缓存）与文档化理由**兼容**；
修法①（包内信号量，「满了直接返回上一次结果/**503**」）**不兼容**：`internal/httpapi/health.go:69-77` 的注释写明
豁免的理由是「饱和的桶不能把正在服务的实例摘出轮转」，而一个返回 503 的信号量正好会把**探针洪水**变成
「这个实例不健康」并把流量切走——即重新引入这段代码被写出来要避免的失败形态（这次的触发者恰好是攻击者，
但负载均衡器不知道这个区别）。所以这条不是「漏洞」，是**裁定**：我在第 6 节按「判断」处理，
并且只支持「不得超过上一次结果 / 超时返回旧值」的那种界。

### 2.2 CS-2：共存是真的，「运维面进了公网」是假的——方向还反了

**（a）共存我复现了，并且补上了报告缺的那一问：谁应答。**
`internal/zzprobe/verifyconfig/verify_listen_test.go`（我的探针，两个监听器各自应答自己的名字）：

```
public listener bound 0.0.0.0:59966 (resolved [::]:59966)
bind 127.0.0.1   :59966 -> SUCCEEDED, resolved to 127.0.0.1:59966
bind [::1]       :59966 -> SUCCEEDED, resolved to [::1]:59966
bind localhost   :59966 -> SUCCEEDED, resolved to 127.0.0.1:59966
after binding 127.0.0.1:59966 as OPS:
  GET 127.0.0.1:59966   -> OPS
  GET localhost:59966   -> PUBLIC        <-- 报告说这里会落到运维面，实测相反
```

真进程版本（`addr = "0.0.0.0:P"` + `internal_addr = "localhost:P"`，配置被接受、**无需任何承认**）：

```
config-startup…: msg="internal surface listening" addr=127.0.0.1:58754 endpoints="/metrics, /debug/pprof/"
                 msg=listening addr=[::]:58754 issuer=http://localhost:58754 version=dev
verify_process_test.go:329: GET 127.0.0.1:58754/metrics -> 200 (the operational handler answers on the IPv4 loopback)
verify_process_test.go:331: GET 127.0.0.1:58754/healthz -> 404 (the public health probe is NOT there)
verify_process_test.go:338: GET [::1]:58754/healthz -> 200   /  GET localhost:58754/healthz -> 200   (public)
verify_process_test.go:343: GET [::1]:58754/metrics -> 404, /debug/pprof/ -> 404, /debug/pprof/heap -> 404
```

即：共存成立，但**运维面只在 IPv4 loopback**；`localhost`/`::1` 走的是**公网 handler**。报告那句
「本机 `curl http://localhost:8080/v1/me` 会按具体绑定落到**运维面** handler」在本机是**错的**（Go 的
dialer 对 `localhost` 先试 `::1`，通配监听器接住了）。反过来成立的是另一种伤害：**公网 API 在 `127.0.0.1` 上
消失了**（`/healthz` 在 127.0.0.1 上是 404）——这是运维困惑/可用性，不是泄露。

**（b）通配×通配的拼写会 fail-closed，不是静默共存。** `addr="0.0.0.0:P"` + `internal_addr=":P"`
（正是报告举的「同一 socket 两种拼写」）：

```
bind :53804       -> REFUSED: listen tcp :53804: bind: Only one usage of each socket address … 
bind 0.0.0.0:53804-> REFUSED: …
bind [::]:53804   -> REFUSED: …
```

真进程上就是 `die("internal listen")`：**启动失败**，不是「两个监听器」。（报告第 107-114 行的分析其实自己
也写了「`0.0.0.0` 与 `:P` 是同 socket」，但把它归到「等价拼写全部通过」这一句里，读者会以为它们能共存。）

**（c）有没有任何不承认的配置会把运维面放到公网接口？我找过了，没有。** 载荷的四种组合：
1. 公网通配 + loopback 运维 ⇒ 运维只在 loopback（实测）；2. 通配×通配 ⇒ OS 拒绝（实测）；
3. 运维面是 `0.0.0.0` ⇒ `internalAddrIsLocal` 判非本地 ⇒ 必须有 `expose_internal=true`（`cmd/re0auth/config.go:522-529`，实测有效）；
4. 运维面是别的 hostname ⇒ 同样要承认。
`internalAddrIsLocal` 的保守方向也成立：只有 `127.0.0.0/8`、`::1`、`localhost` 算本地，而我实测
`net.Listen("tcp","localhost:0")` **确实绑到 127.0.0.1**（`verify_listen_test.go:159`），
所以 `localhost` 这个捷径与 bind 行为**一致**，不是漏洞。

**（d）这是不是已知的？** 是，而且项目自己写过：`CHANGELOG.md:70-75`
「**此前唯一的检查是「不等于 `server.addr`」，于是把 `/metrics` 与 `/debug/pprof/` 交给网络只需要写错一个地址**」，
并说新闸门是 `expose_internal` + loopback 分类。`docs/architecture.md:568-573` 与
`config/re0auth.example.toml:64-75` 同理。报告的残余（字符串比较）是**旧检查的残留精度问题**，
而它声称的「文档承诺不是结构性的」不成立：`api-design.md:366` 承诺的是「这些端点无法经公网端口到达」，
那是**按 handler** 成立的（公网 handler 对 6 条运维路径一律 404，我的真进程测试也逐个确认），不是按地址字符串成立的。

**判定**：机制 CONFIRMED、安全影响**推翻**、严重度 **中 → 低**。剩下的是校验宽松 + 运维困惑，
建议保留「用 `netip` 归一化后比较」的修法（成本极低），但不要按「运维面可能上公网」来定级。

### 2.3 CS-3：保留「中」，但把理由钉在项目自己的约定上

校验缺失是读代码到行（`parseTrustedProxies` 只查可解析性，`cmd/re0auth/config.go:869-888`），
我用真进程再确认了后果链的两端：

```
trusted_proxies=["0.0.0.0/0","::/0"] was accepted by the real loader and the process serves normally
the startup log never mentions "trusted_proxies" / never mentions "0.0.0.0/0"
access log line: … level=INFO msg=request method=GET path=/v1/me status=401 … client=203.0.113.77
```

`client=203.0.113.77` 是攻击者自填的头（`internal/httpapi/middleware.go:264` 写访问日志、`:349` 做限流键），
所以「日志里的客户端地址变成调用方自选」与「限流桶变成调用方自选」两端都实测成立。

**它是不是「已文档化」？** 一半是：`config/re0auth.example.toml:48-55`「Leave this empty unless Re0Auth sits
behind your own reverse proxy」、`docs/api-design.md:149`「列表过宽等于把选择权又交回调用方」。文档**警告**了，
但**没有禁止**，而同一份代码在别的地方禁止了：

- `expose_internal`：非 loopback 必须显式承认（`config.go:522-529`）；
- `allow_private_addresses`：示例文件第 218-219 行自己写「它和 `expose_internal` 是同一个形状、同一个理由」；
- `parseTrustedProxies` 的注释自己说「一个被悄悄跳过/被不同处理的**打字错误**正是那种『看起来应用了其实没有』的设置」——
  也就是作者**知道**「trusts everybody」这个失效模式，却只守住了「解析失败」这一半。

所以按简报的判据（前提不是「运维主动打开一个明确标着危险的开关」，而是「写了一个看起来合理但使设置失效的取值」），
**严重度不降，保留中**。精确化一句话：`0.0.0.0/0`/`::/0` 不是「另一个宽列表」，它是**唯一能让这条设置变成空操作**
的取值——修法只拒 `Bits()==0` 即可，不必裁定 `10.0.0.0/8` 算不算宽（k8s 基线自己用它）。

### 2.4 CS-4：CONFIRMED，比报告说的更该修（同一枚举在别处是被校验的）

读代码到行：`internal/federation/federation.go:141-175`（`NewRegistry` 只看 `game`/`name`/`issuer` 与重复源，
`TokenClass` 一个字都没看）、`internal/federation/revocation.go:30-31`
（`// tokenClassLongLived marks a source credential that cannot be revoked per client.` /
`const tokenClassLongLived = "long_lived"`）、`internal/federation/unbind.go:74` 只做 `==` 比较，
其余一切（含 `""`）走 `revokeUpstream`。
**同一枚举在仓库另一处是被拒绝的**：`upstreamkit/discovery.go:116` 与
`upstreamkit/conformance/conformance.go:156-157`（`token_class = %q, want revocable or long_lived`）。
这条报告没写，它加强了「校验缺失是不一致」的论证。

真进程（我的探针，闭掉报告探针绕过了 TOML 解码这一环）：

```
the real server started with a typo of long_lived: … 
the real server started with the value omitted: …
the real server started with an invented third value: …
control: storage.driver = "mysql" -> exit 1: msg="cannot start" stage=config
         err="storage.driver \"mysql\" must be \"memory\" or \"postgres\""
```

**影响路径**（我读到的关键一行）：`unbind.go:80` → `revokeUpstream` → `revocation.go:86-88`
`if resp.StatusCode >= 300 { return error }` ⇒ **任何 2xx 都算成功** ⇒ `RevocationDone`；
而 RFC 7009 §2.2 要求撤销端点对**未知/无效** token 也回 200。所以「一个只能发主密钥的源」只要有一个
符合 RFC 的撤销端点，错误声明就会产出一个**真·假的成功**：kill switch 的 `bindingOutcome` 里
`unsupported` 计数为 0（`internal/federation/killswitch.go:184-191` 只在 `RevocationUnsupported`/`Unavailable`
时计数），`revoked=1` 照旧。这是简报里「静默失败 ⇒ 升」的形态，但前提是**运维自己写错了声明**
（`docs/upstream-protocol.md:131`、`docs/source-onboarding.md:140` 都把「如实声明」写成了数据源的义务），
且没有任何攻击者参与。所以我判：**保留中**（不升到高，因为不是攻击面；不降到低，因为失败是静默且发生在事故响应路径上）。

### 2.5 CS-5：CONFIRMED——真进程、真日志，而且报告只说对了一半

真进程（无配置文件、`DATABASE_URL` 设为不可达 DSN），我引的**原样**日志行：

```
time=… level=WARN msg="storage is in-memory: a restart loses sessions, bindings and pending requests" because="no DATABASE_URL"
time=… level=WARN msg="audit log is in-memory; records do not survive a restart"
```

同一进程里 `DATABASE_URL=postgres://user:pass@db.internal:5432/re0auth?sslmode=disable` 确实非空
（是我设的，探针也断言过）。这条日志在**误导运维去查一个他们刚设过的变量**，这正是「必须在上线前改对」的那类。

对照（同一变量、有 `[storage]`）证明 driver 只来自文件：

```
control: with [storage] driver = "postgres", exit=1,
  msg="cannot start" stage=storage err="postgres: ping: failed to connect to `user=user database=re0auth`:
  hostname resolving error: lookup db.internal: no such host"
```

`RE0AUTH_STORAGE_DRIVER`：我不仅 grep（全仓 0 处），还**设了它**跑真进程：
`with DATABASE_URL AND RE0AUTH_STORAGE_DRIVER=postgres set, the real process is still in-memory:
… because="no DATABASE_URL"`。所以「只靠环境变量的部署无法持久化」是实测结论。

**报告说漏的一半（我补上，方向相反也同样不成立）**：SECURITY.md:10-12 的两句都把 `DATABASE_URL`
当成开关，而真实开关是 `[storage] driver` / `dsn_env`。所以**第一句也不成立**：`[storage] driver="postgres"`
+ `dsn_env="MY_DSN"` 时，`DATABASE_URL` 不存在而九个存储端口全是持久的。也就是说这条不是「后半句错」，
而是「整句的模型错：`DATABASE_URL` 不是选择器」。

README 的快速开始确实自相矛盾，我用**仓库里那份真的示例文件**跑出来了：

```
the shipped example config with NO DATABASE_URL -> exit 1:
  msg="cannot start" stage=config err="storage.dsn_env names \"DATABASE_URL\", which is not set"
the same file WITH DATABASE_URL -> exit 1: stage=storage … lookup db.internal: no such host
```

即 `cp config/re0auth.example.toml` 之后「不设 `DATABASE_URL` 也能跑」（README.md:30）**是错的**，
它会拒绝启动并点名 `DATABASE_URL`。报告这一条（CS-5 影响段的最后一颗）成立且比它说的更干净。

内存模式的连带后果我也确认了机制：`cmd/re0auth/main.go:376-386` 的锚点循环与链校验循环都依赖
`store.auditHead` / `auditVerifier(store.audit)`，而内存 sink 是 `audit.NewMemoryLogger()`（`main.go:793`）
不实现 `chainVerifier` ⇒ 两条控制都不启动；真进程日志里 8 行、**没有任何 `audit chain` 行**（我断言过）。

### 2.6 CS-6：CONFIRMED，而且我拿到了报告的探针从未拿到的两行

报告的 CS-6 探针走的是 `-rotate-keys`（在监听器之前返回）和 `addr="not-an-address"`（`die("listen")` 早退），
所以它的「对照」列表里 `internal surface listening`、`listening` 其实**都不在捕获日志里**。我用真进程补齐：

```
msg="configuration file" path=…            WARN msg="storage is in-memory…" because="no DATABASE_URL"
WARN msg="audit log is in-memory…"         INFO msg="registered downstream client" client_id=cli type=public
WARN msg="no identity provider is configured; nobody can sign in"
INFO msg="authorization engine" engine=openid-provider store=memory
INFO msg="operator plane enabled" admins=1
WARN msg="account erasure cannot clear per-account sessions…"
INFO msg="internal surface listening" addr=127.0.0.1:63991 endpoints="/metrics, /debug/pprof/"
INFO msg=listening addr=[::]:63990 issuer=http://127.0.0.1:63990 version=dev
```

逐字段搜索（配置文件把 8 个开关都设成最弱值：`cookie_secure=false`、`rate_limit=0`、`max_in_flight=0`、
`trusted_proxies=["0.0.0.0/0"]`、`introspection_clients=["wide_open_resource_server"]`、
`allow_private_addresses=true`、`internal_addr` 已设、`[admin].subjects` 非空）：
`cookie_secure`/`trusted_proxies`/`rate_limit`/`max_in_flight`/`expose_internal`/`allow_private`/
`introspection_clients`/`reauth`/`internal_addr` **全部缺席**，只有 `admins` 在场。
两个边界应当写进报告：① 内部监听地址**是被打出来的**（`internal surface listening addr=…`），所以
「pprof 有没有绑到 `0.0.0.0`」其实可以从这一行事后核对；② `store=memory` 也是打出来的（与 CS-5 联动）。
这不改变「8 个开关没有生效摘要」的结论，**低**合适。

### 2.7 CS-7：机制 CONFIRMED，**严重度中 → 低**

真进程（`internal_addr` 已设，默认限流），承重两行：

```
GET /metrics -> 200, 9518 bytes ; /debug/pprof/heap -> 200, 4447 bytes ; /debug/pprof/goroutine?debug=1 -> 200, 6687 bytes
after a scrape and two pprof dumps the process wrote 0 bytes of log: ""
the same three requests through the public listener produced 3 log lines
```

机制无异议（`internal/observability/observability.go:541-546` 是裸 mux，`main.go:653` 用 `newServer` 只配超时）。
降级理由是**前提**：要留下不了痕，攻击者必须先能到 9090；基线上那是 NetworkPolicy 的事（deploy-ops 的 DEP-13），
而报告自己也把界写成「不是远程可利用，而是取证缺口」。取证价值高≠严重度高，按简报第 3 节的判据应记**低**。
（如果复核者按「pprof 是最敏感的运维面、必须留痕」加权，保留中也有理由——这是一个裁定点，不是事实分歧。）
另外我确认了「没有文档把它写成有意决定」：`docs/operations-decision.md`（ADR-0006）只讲「不持久化运行的日志、
靠指标告警」，`docs/operations.md:122-128` 只讲绑定与承认，`docs/api-design.md` 只讲公网访问日志不含 query。

### 2.8 CS-8：结论成立，机制描述要改一处

`internal/store/postgres/auditbatch.go`：`Close()` 先 `close(b.stop)`（`:207`）再等 `stopped`；
`run()` 在 `<-b.stop` 上转入 `drain()`（`:135-137`）；`drain()` 对每一项调 `flush(item)`（`:147-156`）；
`flush` 的收集循环里 `case <-b.stop: break gather`（`:175-176`）此时**总是就绪**。
报告由此得出「每行一个事务」。但同一 `select` 里 `case item := <-b.queue` 通常也同时就绪，
Go 在多个就绪分支间**随机**选择，所以期望批量 ≈2 行（不是 1 行），最坏 512 行×5s（`auditBatchTimeout`，`:41`）
要按 ~256 个事务算。**量级不变**（都在分钟级，远超 `terminationGracePeriodSeconds: 45`
与 `shutdownTimeout = 30s`），所以结论与「低」都不动；但「每行一个事务」这句应当改掉，
否则别人照它算预算会算错一倍。

### 2.9 CS-9 / CS-10：按原样成立，改了措辞

- `RE0AUTH_DATABASE_URL`：`*.go` **0** 处、`docs/runbooks.md:27` **1** 处。而且它与 CS-5 叠加的方式比报告写的
  更糟：runbook 让人去找一个**不存在的**变量名，启动日志让人去查一个**刚设过**的真变量名，两条误导指向不同方向。
- CS-10 的差集我逐名核对（示例文件里 `# Environment override:` 恰 7 行：`MAX_IN_FLIGHT`、`TRUSTED_PROXIES`、
  `INTERNAL_ADDR`(+`INTERNAL_EXPOSE`)、`INTROSPECTION_CLIENTS`、`ADMIN_SUBJECTS`、`ADMIN_REAUTH_WINDOW`、
  `ALLOW_PRIVATE_UPSTREAMS`；代码里读到 18 个 `RE0AUTH_*`），与报告列的一致。
  一处小修正：`RE0AUTH_STORAGE_{MAX,MIN}_CONNS`/`_{CONNECT,STATEMENT}_TIMEOUT` 在示例文件第 108-111 行**是被提到的**，
  只是没有 `# Environment override:` 前缀——「标了」比「标注了」更准确。取值仍是**提示**。

---

## 3. 我实际执行了什么（命令 + 承重输出）

```text
go test ./internal/zzprobe/startup/ -count=1 -v          → ok（11 条全绿；含 CS-1/CS-7 的承重两行）
go test ./internal/zzprobe/verifyconfig/ -count=1 -v     → ok 6.313s（我的 8 条真进程/真 socket 探针）
grep('RE0AUTH_STORAGE_DRIVER') 全仓                      → 0 处（.go 与 docs 均无）
grep('RE0AUTH_DATABASE_URL')   全仓                      → *.go 0 处；docs/runbooks.md:27 1 处
```

| 我验证的断言 | 承重输出（原样） |
|---|---|
| CS-1 限流豁免（真进程） | `10 anonymous GET /readyz on the public listener all returned 200 while GET /v1/me on the same address returned 429` |
| CS-1 「每请求取一条池连接」 | `pgxpool@v5.11.0/pool.go:851 c, err := p.Acquire(ctx)` + `pgconn.go:2163 return pgConn.Exec(ctx, "-- ping").Close()` |
| CS-1 真进程可达性 | `with an unspent bucket the public listener answers 404 for /metrics`（公网面无运维面）；`GET /readyz → 200` |
| CS-1 上游也没有限流 | `deploy/k8s/base/ingress.yaml:21 path: / pathType: Prefix`，无 `limit-rps` 注解 |
| CS-2 共存 + 谁应答 | `GET 127.0.0.1:58754/metrics -> 200` / `GET 127.0.0.1:58754/healthz -> 404` / `GET [::1]:58754/healthz -> 200` / `GET [::1]:58754/metrics -> 404` |
| CS-2 通配相撞 fail-closed | `bind :53804 -> REFUSED: … Only one usage of each socket address` |
| CS-2 localhost 的 bind 与分类一致 | `net.Listen("tcp","localhost:0") resolved to 127.0.0.1:53805` → `localhost binds loopback` |
| CS-3 真进程接受 | `trusted_proxies=["0.0.0.0/0","::/0"] was accepted … the startup log never mentions "trusted_proxies"` |
| CS-3 后果（日志被自选） | `msg=request method=GET path=/v1/me status=401 … client=203.0.113.77` |
| CS-4 真进程接受 | 三个变体各自 `the real server started with …`；对照 `storage.driver = "mysql" -> exit 1` |
| CS-4 枚举别处被校验 | `upstreamkit/conformance/conformance.go:157 token_class = %q, want revocable or long_lived` |
| CS-5 误导性警告 | `level=WARN msg="storage is in-memory: …" because="no DATABASE_URL"`（同进程 `DATABASE_URL` 非空） |
| CS-5 环境变量不存在 | `with DATABASE_URL AND RE0AUTH_STORAGE_DRIVER=postgres set, the real process is still in-memory` |
| CS-5 README 反例 | `the shipped example config with NO DATABASE_URL -> exit 1: err="storage.dsn_env names \"DATABASE_URL\", which is not set"` |
| CS-5 内存模式无审计链控制 | `no audit-chain line appears in the log of this in-memory run (8 lines total)` |
| CS-6 完整启动日志 | 10 行全文（见 2.6）；9 个开关名 `ABSENT`，只有 `admins` 在场 |
| CS-7 内部面零日志 | `after a scrape and two pprof dumps the process wrote 0 bytes of log: ""` / `the public listener produced 3 log lines` |
| CS-8 排空无总预算 | `auditbatch.go:135-137,147-156,175-176`（读）+ `:41 auditBatchTimeout = 5s`、`:46 auditQueueDepth = 512` |

---

## 4. 我未能验证的

- **任何 Postgres 行为**（本机无 Docker、无 Postgres）：CS-1 的「池真的被占满 / 真请求开始等待」、
  CS-8 的 512 行排队 + 慢库交错、`/readyz` 真实的 `pool.Ping` 时延。CS-1 的量化因此是
  **源码 + 算术**（`MaxConns/L`），不是测量；我在第 2.1 节把每种 L 的前提都写明了。
  要证实需要 `TEST_DATABASE_URL` + 一个人为拖慢 ping 的注入口。
- **Linux 上第二个 bind 是否失败**：报告说 Linux 会 fail-closed（`EADDRINUSE`），本机只有 Windows，
  无法执行。我没能证伪；这属于「读，未执行」。
- **集群侧**：`expose_internal` + NetworkPolicy 的实际网控效果（deploy-ops 的 DEP-13 负责），
  以及 IPv6 相关的策略语义（见 V-1 的边界）。
- **`loadConfig` 里 `RE0AUTH_ADMIN_REAUTH_WINDOW` 等键我在真进程里没有逐个穷举**；CS-6 用配置文件覆盖了
  8 个开关，`[admin].reauth_window` 走的是默认值（报告用的是环境变量）。
- **没有跑 `go test ./...`**（按简报要求），因此「我的探针不干扰其他区域」只到「我这一个包全绿」这一层；
  另外工作区里有别人的未提交改动，我只核对了与本次结论相关的那两个文件的 diff。

---

## 5. 新发现（复核时顺手看到的）

### V-1 [提示] `0.0.0.0:P` 在 Go/Windows 上其实绑成 `[::]:P`（双栈通配），任何「只按 IPv4 写」的控制都不覆盖它

我实测（`verify_listen_test.go`）：

```
public listener bound 0.0.0.0:59966 (resolved [::]:59966)
bind [::]:53804 -> REFUSED: listen tcp 0.0.0.0:53804: bind: Only one usage …   # 报错文本里 0.0.0.0 与 [::] 被当成同一个
```

`deploy/k8s/base/configmap.yaml:12-13` 的 `addr = "0.0.0.0:8080"` 与 `internal_addr = "0.0.0.0:9090"`
因此**同时在 IPv6 通配上监听**——真进程日志里就是 `addr=[::]:9090` / `listening addr=[::]:63714`
（我的两次真进程启动都能看到 `[::]`）。后果：任何用 **IPv4 CIDR** 表达的守卫（防火墙规则、
NetworkPolicy 的 `ipBlock: 0.0.0.0/0`、`docs` 里「只放行 10.0.0.0/8」这种写法）**不覆盖 IPv6 通配**。
基线本身**不受影响**：`deploy/k8s/base/networkpolicy.yaml:13-23` 用的是 `namespaceSelector`（不是网段），
所以这条是「给别的编排系统/别的控制方式的提示」，不是现状漏洞。判据很简单：换掉 NetworkPolicy 的实现方式时，
必须确认新控制对 `[::]:9090` 同样成立。

### V-2 [观察，非缺陷] 桶打满后，公网上**任何**路径（含不存在的）都回 429 而不是 404

真进程实测：`after the bucket is empty, GET /metrics on the public listener -> 429 (the limiter answers
before the mux does)`。限流器在路由之前（`middleware.go:331-338` 在 mux 之外），所以一个耗尽了自己预算的
调用者看不到 404/405 的任何信息——这是**信息更少**的方向，安全上无害；但排障时「`curl` 回 429 而不是 404」
会让人以为路径存在。与 CS-6 的「生效摘要」是同一类可观测性问题，我没把它算成发现。

---

## 6. 判断（不是发现，但影响这些条目的定级）

1. **CS-1 的修法必须区分「返回旧值」与「返回 503」。** 返回 503 的信号量会把探针洪水变成
   「这个实例不健康」，正是 `internal/httpapi/health.go:69-77` 那段注释要避免的形态（在第 2.1 节 (d) 说明）。
   只做「背景 1s 缓存 + 读缓存」或「超预算时回上一次结果」的界是安全的；原报告把两种写法并列写在一句里，
   复核时会被读成「信号量满了回 503 也行」。**这是裁定，不是漏洞。**
2. **CS-3 的「多宽算宽」也是裁定，但 `Bits()==0` 不是。** 拒 `0.0.0.0/0`/`::/0` 与 k8s 基线用的
   `10.0.0.0/8` 不冲突，所以最小改法可以立刻落；要不要连 `10.0.0.0/8` 一起要求承认，请另裁。
3. **CS-7 的定级取决于「取证缺口算不算安全问题」。** 我按简报的判据降到低；如果项目把
   「pprof 调用必须可追责」写成不变量，那它就该是中，并且应当写进 `docs/operations.md` 的运维面一节
   （现在文档里没有任何一处说内部面不留痕是有意的）。
4. **CS-5 的修法里，`RE0AUTH_STORAGE_DRIVER` 值得单独确认设计意图。** 示例文件第 13 行承诺
   「environment > this file > built-in default」，而 `storage.driver` 是唯一决定「这个部署持不持久」的键，
   却没有任何环境覆盖——支持它（或明确写「driver 只能来自文件，因为它是持久性声明」）都能消除这条不一致，
   但后者要写进文档，否则 SECURITY.md 的模型仍然是错的（见 2.5 的「第一句也不成立」）。
