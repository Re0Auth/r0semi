# 配置 / 组合根与启动路径 / fail-closed / 可观测性 / 跨切面错误处理 审计报告

> 区域缩写 **CS**（config-startup）。探针文件：
> `cmd/re0auth/zzprobe_startup_test.go`、`internal/zzprobe/startup/{startup_probe_test.go,surface_probe_test.go,protocol_probe_test.go}`。
> 全部只新增文件，未改任何已跟踪文件。

## 范围与方法

**读过（全文）**：`internal/config/{config.go,logging.go}`、`cmd/re0auth/config.go`（992 行）、
`cmd/re0auth/main.go`（1452 行）、`internal/observability/observability.go`、
`internal/httpapi/{responses.go,middleware.go,health.go,server.go,clientaddr.go,admin_routes.go,federation_routes.go,plane_test.go}`、
`internal/oidchttp/oidchttp.go`、`config/re0auth.example.toml`（每一行）、`config/referencesource.example.toml`、
`audit/audit.go`、`internal/store/postgres/{audit.go,auditbatch.go}`、`vault/rotate.go`、
`cmd/re0auth/{main_test.go,exit_test.go,secret_env_test.go,inflight_test.go,adversary_test.go}`、
`internal/observability/artifacts_test.go`、`deploy/k8s/base/{configmap.yaml,deployment.yaml,networkpolicy.yaml}`、
`README.md`、`SECURITY.md`、`docs/{operations.md,operations-decision.md,observability-decision.md,api-design.md,security-audit-2.md,security-audit-3.md,runbooks.md,slo.md}`。

**跑过（真执行，本机 Windows 11 / Go 1.27.1）**：

```sh
go test ./cmd/re0auth/ -run TestProbe -count=1 -v -short        # 10 条，全通过
go test ./cmd/re0auth/ -run TestProbeInternalListenerWriteTimeoutTruncatesAProfile -v -timeout 200s   # 61s
go test ./internal/zzprobe/startup/ -count=1 -v                 # 11 条，全通过
go test -race ./internal/zzprobe/startup/ -count=1              # ok（本机 cgo 可用，-race 跑得起来）
go test -race ./cmd/re0auth/ -run TestProbe -count=1 -short      # ok
```

**跑不了（本机事实，逐条影响结论）**：没有 Docker、没有 Postgres ⇒ **一切持久化路径只有「读代码到行」**
（`/readyz` 的真实 `Ping`、审计批次在关闭时的排空、`/metrics` 的 pool collector、迁移时序）。
没有 bash（`Get-Command bash` 无结果）⇒ `scripts/backup-keys.sh` 的正则结论只能是 HYPOTHESIS。
没有集群 ⇒ NetworkPolicy / `expose_internal` 的部署断言未测（另有 deploy-ops 区域专责）。
按简报要求**没有**跑 `go test ./...`（其他代理的探针在同一工作区）。

**与已发布审计/其他区域的关系**：`[admin].allow` 键名错、`internal_addr` 默认 `:9090` 的说法错
（`docs/runbooks.md:9,11`、`docs/slo.md:79`）已被 `findings/deploy-ops.md` 的 DEP-09/DEP-10 覆盖，**本报告不重复**。
主代理 `_main-runtime-findings.md`「已排除的候选」里写了「`internal_addr` 与 `addr` 相同 → 拒绝」——
那句话对**逐字相同**成立，CS-2 说的是**等价拼写**，是同一条检查的漏网面，不是重复。

---

## 发现

### CS-1 `/readyz` 同时免限流与免并发上限，而它每次调用都做一次数据库往返；匿名可打满连接池

- 严重度: **高**
- 类别: 可用性 / 性能（兼安全：可被匿名触发的资源耗尽）
- 不变量/性质: 「有界的对外工作量」——公网上每一个无凭据可到达的端点都应有一个上限
- 证据:
  - `internal/httpapi/health.go:75-77` `isProbe` 是唯一判据；`middleware.go:335-338`（限流器豁免）、
    `middleware.go:399-402`（并发上限豁免）都用它。
  - `internal/httpapi/health.go:37-53` 的 `handleReady` **每请求**调用 `s.ready(ctx)`；
    组合根把它接到连接池：`cmd/re0auth/main.go:770-775` → `store.db.Ping`
    （`internal/store/postgres/postgres.go:268` → `pool.Ping`，即**取一条池连接并做一次往返**）。
  - `internal/httpapi/health.go:14` 唯一的界是 `readinessTimeout = 2 * time.Second`。
  - 已执行（`go test ./internal/zzprobe/startup/ -run TestProbeReadyzBypassesTheLimiterAndTheInFlightCap -v`）：
    ```
    8 /readyz requests were served with the rate bucket already empty
    32 concurrent /readyz calls were all admitted while max_in_flight=1 was saturated;
    peak concurrency inside the readiness check = 32
    ```
    即：桶里 0 个令牌时 `/readyz` 照常 200；`max_in_flight=1` 且槽位被真实请求占满时，
    32 个并发 `/readyz` 全部进入了就绪探测（受控对照：同一时刻的 `/v1/me` 得到 503）。
  - 第二条探针（`TestProbeReadyzHoldsItsCallerForTheFixedTwoSeconds`）实测：
    `holds its readiness check ... for 2.002s`。
- 状态: **CONFIRMED**（限流/并发豁免与 2s 保持是执行过的；「durable 部署下每次调用取一条池连接」
  是 `file:line` 读到，无 DB 未执行）
- 影响: 任何匿名调用者可以不受限流（`rate_limit` 是每地址每平面一个桶，但对 probe 完全不判）、
  不受 `max_in_flight` 约束地并发请求 `/readyz`。每个请求占住一条池连接最多 2s；
  默认池 16（`config/re0auth.example.toml:108`）、并发上限 128。
  几百个并发连接就能让池持续被占满，使**真实**请求排队/503——攻击成本近乎为零，
  而 `rate_limit` 在任何其它路径上都会先拒掉它。文档只论证了「限流豁免」
  （`docs/operations.md:121`、`docs/api-design.md:369-373`），没有论证「免并发上限 + 做 I/O」。
- 修法建议: 保留两个豁免（去掉会在洪水时把健康实例摘出轮转），但给**探测自身**加界：
  ① 一个包内信号量（如 8）只圈住 `s.ready(ctx)`，满了直接返回上一次结果/503；
  ② 或把依赖检查改成后台 1s 一次的缓存结果，`handleReady` 只读缓存（DB 往返从 O(n) 降到 O(1)/s）。
  两者都不改 `/readyz` 的线格。
- 复现/守卫: `internal/zzprobe/startup/startup_probe_test.go`
  `TestProbeReadyzBypassesTheLimiterAndTheInFlightCap`、`TestProbeReadyzHoldsItsCallerForTheFixedTwoSeconds`。
  与 deploy-ops 的阅读差异记录在文末「判断」。

### CS-2 「内部监听器必须与 `server.addr` 不同」只是字符串比较；等价拼写全部通过，且本机证明两个监听器可以同号并存

- 严重度: 中
- 类别: 安全（纵深防御）/ 可维护性
- 不变量/性质: 「运维面不在公网监听器上」——文档把它当成结构性保证
- 证据:
  - `cmd/re0auth/config.go:511-514`：`cfg.InternalAddr != "" && cfg.InternalAddr == cfg.Addr`
    ——**逐字比较**，两条路径都不做 `host:port` 归一化。
  - 已执行（`go test ./cmd/re0auth/ -run 'TestProbeInternalAddr' -v`）：
    ```
    addr="0.0.0.0:19090" internal_addr=":19090" both accepted: the same socket under two spellings
    addr=127.0.0.1:19091 internal_addr=localhost:19091 accepted with no acknowledgement
    ```
    第二行还绕过了**另一条**检查：`config.go:845-863` 的 `internalAddrIsLocal` 认为
    `localhost` 是 loopback（`config.go:852-854`），于是 `config.go:522` 的 `expose_internal`
    承认要求根本不触发。
  - 已执行（`TestProbeTwoListenersOnOnePort`，同一台机器）：
    ```
    bind :60613          after 0.0.0.0:60613 -> refused (… Only one usage of each socket address …)
    bind 127.0.0.1:60613 after 0.0.0.0:60613 -> SUCCEEDED: two listeners on one port number
    bind [::1]:60613     after 0.0.0.0:60613 -> SUCCEEDED
    bind localhost:60613 after 0.0.0.0:60613 -> SUCCEEDED
    ```
  - 文档把它当保证：`config/re0auth.example.toml:66-68`「It must differ from `addr`: a separate
    listener is the whole reason these endpoints are not reachable through the public one」。
- 状态: **CONFIRMED**
- 影响: 在 Windows 上（Go 的 `net.Listen` 允许「更具体的地址」与 `0.0.0.0:P` 共存），
  `addr = "0.0.0.0:8080"` + `internal_addr = "localhost:8080"` 会让**两个 `http.Server` 同在 8080 端口**：
  公网监听器在全部接口上，运维面在回环上。端口相同意味着「本机 `curl http://localhost:8080/v1/me`」
  会按具体绑定落到**运维面 handler**（`/metrics` 与 `/debug/pprof/*`），即运维面真的与公网面
  共用一个端口号——文档承诺的「独立监听器」不是结构性的，只是「地址字符串不同」。
  反向（`internal_addr` 是 `0.0.0.0`、`addr` 是回环）在 `expose_internal=true` 下被接受，此时
  `addr` 的 loopback 默认值与运维面的全网卡绑定叠加，会得到「API 只在回环、pprof 在全网卡」的部署。
  在 Linux 上第二个 bind 会失败并拒绝启动（fail-closed），所以这是**平台相关的**不一致而不是普遍漏洞。
- 修法建议: 把检查从「字符串」改成「解析成 `netip.AddrPort` 后比较」：先 `net.SplitHostPort`，
  host 为空或 `0.0.0.0`/`::` 视为通配，`localhost` 解析成 `127.0.0.1` 与 `::1` 两组再比较；
  无法解析的地址直接拒绝（`internalAddrIsLocal` 已经是这个保守方向）。顺带把
  「`localhost` 等价于哪个地址」与 bind 的实际行为对齐，或干脆要求 `internal_addr` 必须是字面 IP。
- 复现/守卫: `cmd/re0auth/zzprobe_startup_test.go`
  `TestProbeInternalAddrEqualityIsOnlyAStringComparison`、`TestProbeTwoListenersOnOnePort`。

### CS-3 `server.trusted_proxies` 接受「信任全世界」的前缀，且启动不记录生效值

- 严重度: 中
- 类别: 安全（配置 fail-open）
- 不变量/性质: 「调用方不能自选限流桶」（`docs/api-design.md:145-149`）
- 证据:
  - `cmd/re0auth/config.go:869-888` 的 `parseTrustedProxies` 只校验**可解析性**，没有任何宽度检查。
  - 已执行（`TestProbeTrustedProxiesAcceptAUniversalPrefix`）：
    ```
    trusted_proxies = [0.0.0.0/0 ::/0]: every peer is a trusted proxy, so every caller's
    X-Forwarded-For is believed and the per-address limiter is caller-chosen
    ```
    （受控对照：`not-a-network` 会被拒，所以探针确实走到了这条检查。）
  - 后果链读到行：`internal/httpapi/clientaddr.go:32-35` →`forwardedClient`（`:40-75`），
    然后 `middleware.go:349` 用它做限流键、`middleware.go:264` 把它写进访问日志（也即运维看到
    「这个地址在刷接口」的地址）。
  - 文档自己警告过这条：「列表过宽等于把选择权又交回调用方」（`config/re0auth.example.toml:52-55`、
    `docs/api-design.md:149`），但实现里没有任何东西拦住它——和「非法条目拒绝启动」并列的
    那条守卫（同样在 `parseTrustedProxies` 里）成立，唯一没被拦的恰好是让它失效的那个值。
- 状态: **CONFIRMED**（校验缺失）；影响面在真实部署里取决于入口是否有反代（HYPOTHESIS 部分）
- 影响: 一份写了 `trusted_proxies = ["0.0.0.0/0"]`（或 `10.0.0.0/0`、`::/0`）的配置上线后，
  每个调用者只要带一个 `X-Forwarded-For` 就能给限流器一串新桶（单地址 50/s → 无上限），
  并且让日志/审计里的「客户端地址」变成调用方自填的字符串。这条与 deploy-ops 的 DEP-13
  （基线 `10.0.0.0/8` + NetworkPolicy 失效）是同一后果的两个入口：DEP-13 是「网控失效」，
  本条是「配置校验不拦」。
- 修法建议: 在 `parseTrustedProxies` 里拒绝 `Bits() == 0` 的前缀（`0.0.0.0/0`、`::/0`），
  并在启动日志里把生效的前缀数**与是否包含空前缀**打出来（见 CS-6）。
  是否也要拒 `10.0.0.0/8` 属于裁定（k8s 基线自己用它），所以最小改法是只拒「全部地址」这一档。
- 复现/守卫: `cmd/re0auth/zzprobe_startup_test.go` `TestProbeTrustedProxiesAcceptAUniversalPrefix`。

### CS-4 `sources[].token_class` 既不校验也不给默认值：一个错字把「不可撤销」的源变成「可撤销」

- 严重度: 中
- 类别: 安全（配置 fail-open）/ 合规（撤销承诺）
- 不变量/性质: I4「撤销真的生效」；以及项目自己的规则「无法被满足的约束不得被当作不存在」
- 证据:
  - `cmd/re0auth/config.go:752-788`（`loadSources`）把 `token_class` 原样塞进 `federation.Source`；
    `internal/federation/federation.go:141-175`（`NewRegistry`）只校验 `game`/`name`/`issuer` 非空与重复源，
    **完全不看 `TokenClass`**。
  - 唯一的读点在 `internal/federation/unbind.go:74-82`：
    `if src.TokenClass == tokenClassLongLived { … RevocationUnsupported } else { 真的去调上游撤销 }`。
    即 `""`、`"long_live"`、`"Revocable"`、`"session"` 与 `"revocable"` **同义**。
  - 已执行（`TestProbeTokenClassIsNeitherValidatedNorDefaulted`）四种输入全部被接受：
    ```
    a typo of long_lived: accepted with TokenClass="long_live" …
    omitted entirely: accepted with TokenClass="" …
    an invented third value: accepted with TokenClass="session" …
    ```
    （受控对照：同一加载器对 `storage.driver = "mysql"` 是拒绝的，说明它确实在管自己的枚举值。）
  - 文档把它当作运维必须诚实声明的字段：`config/re0auth.example.toml:267-269`
    「"revocable" … or "long_lived" … Declaring it honestly is what lets Re0Auth describe the source accurately」；
    代码注释同义（`unbind.go:75-77`「quietly reporting success would defeat it」）。
- 状态: **CONFIRMED**（未校验 + 未默认）；「上游 200 就算撤销成功」这一步是读代码到行
- 影响: 一个真正只能发主密钥、无法按 client 撤销的源，如果运维把 `token_class` 写错或漏写，
  Re0Auth 就去调 `RevocationEndpoint` 并把结果报成 `done`（`unbind.go:133-137`），
  用户界面与 `revocations_total` 都会显示「已通知上游撤销」——而那个源根本没有可撤销的东西。
  事故响应者据此认为上游会话已断。这是 I4 意义上的 fail-open，方向与 `status`
  （未知值经 `federation.go:53-62` 的 `statusRank` 落到「retired」，fail-closed）相反。
- 修法建议: 在 `NewRegistry` 里加白名单（`""`/`revocable` → revocable，`long_lived` → long-lived，
  其它一律拒绝并要求写明），并在 `config/re0auth.example.toml` 里把默认值写出来
  （该文件第 11 行自己承诺「EVERY FIELD HAS A DEFAULT」）。
- 复现/守卫: `cmd/re0auth/zzprobe_startup_test.go` `TestProbeTokenClassIsNeitherValidatedNorDefaulted`。

### CS-5 设了 `DATABASE_URL` 但配置里没有 `[storage]` 段 ⇒ 静默内存模式，而警告把原因报成「没有 DATABASE_URL」

- 严重度: 中
- 类别: 可用性 / 合规-隐私（审计链消失）/ 文档与实现不一致
- 不变量/性质: I5 fail-closed；以及「一个看起来持久的部署必须是持久的」
- 证据:
  - `cmd/re0auth/config.go:543-551`：driver 只来自文件；`dsn_env` 为空时 `driver = "memory"`，
    下一行 `case "memory": cfg.DatabaseURL = ""` —— **环境里的 `DATABASE_URL` 被主动丢弃**。
    全文没有 `RE0AUTH_STORAGE_DRIVER`（`grep -r RE0AUTH_STORAGE_DRIVER` 命中 0 处），
    所以**只靠环境变量的部署根本没有办法变成持久化部署**。
  - 已执行（`TestProbeDatabaseURLAloneStaysInMemoryAndTheWarningBlamesIt`）：
    ```
    control: a config WITH [storage] accepted DATABASE_URL and moved on to opening the pool
    DATABASE_URL="postgres://user:pass@db.internal:5432/re0auth?sslmode=disable" is set in this
      process, and loadConfig cleared it: the deployment is in-memory
    the warning: level=WARN msg="storage is in-memory: a restart loses sessions, bindings and
      pending requests" because="no DATABASE_URL"
    ```
    同一进程里 `DATABASE_URL` 非空，而 `cmd/re0auth/main.go:874-881` 的 `reportDurability`
    写死了 `because="no DATABASE_URL"`。
  - 文档说反了：
    - `SECURITY.md:10-12`「With no `DATABASE_URL`, every store falls back to memory … With Postgres
      set, the nine storage ports and the audit log are durable.」——后半句不成立。
    - `README.md:20`（快速开始第 2 步就是 `export DATABASE_URL=…`）、`README.md:30`
      「不设 `DATABASE_URL` 也能跑」——而快速开始同时让人 `cp config/re0auth.example.toml`，
      那份文件里 `[storage] driver = "postgres"`，于是**不设 `DATABASE_URL` 会直接拒绝启动**，
      与这句相反（这句在缺 `[storage]` 的配置上才成立）。
  - 内存模式的连带后果读到行：`RE0AUTH_AUDIT_KEY` 不再必填（`config.go:604-614`），
    审计 sink 变成 `audit.MemoryLogger`（`cmd/re0auth/main.go:793`，10 000 条环形缓冲），
    于是 `auditVerifier` 为 nil、6 小时自检不跑、锚点循环不启动（`main.go:376-386`、`1407-1420`）——
    「审计链自洽」这条控制在这个部署上根本不存在。
- 状态: **CONFIRMED**
- 影响: 运维按 README/SECURITY.md 的说明设置 `DATABASE_URL`、不写 `[storage]`（合法：示例文件说
  「every field has a default, write only what differs」），得到的是一个**重启即丢会话/绑定/OP 状态、
  且审计日志没有链、没有锚点、没有定期校验**的实例，而启动日志给出的原因是
  「没有 DATABASE_URL」——运维看到的是自己刚刚设过的变量名，于是去查一个不存在的问题。
- 修法建议: 三件小事：① `reportDurability` 的 `because` 按实际原因取值
  （`driver is not "postgres" in the config file` / `no DATABASE_URL`）；
  ② 支持 `RE0AUTH_STORAGE_DRIVER`（与文件里的其它键同等的环境优先级，示例文件第 13 行已承诺
  「environment > this file > built-in default」）；③ 把 SECURITY.md / README 的两句话改成
  「durability is selected by `[storage] driver`（或 `RE0AUTH_STORAGE_DRIVER`）」。
- 复现/守卫: `cmd/re0auth/zzprobe_startup_test.go` `TestProbeDatabaseURLAloneStaysInMemoryAndTheWarningBlamesIt`。

### CS-6 启动日志不公布任何一个安全开关：运维无法从日志判断生效姿态

- 严重度: 低
- 类别: 可观测性 / 可维护性
- 不变量/性质: 「生效配置必须可被运维核对」（尤其在一个把「看起来应用了其实没应用」当作主要敌人的项目里）
- 证据:
  - 已执行（`TestProbeStartupLogOmitsEverySecuritySwitch`）：把 `cookie_secure`、
    `RE0AUTH_TRUSTED_PROXIES=0.0.0.0/0`、`RE0AUTH_INTERNAL_EXPOSE=true`、
    `RE0AUTH_ALLOW_PRIVATE_UPSTREAMS=true`、`rate_limit=0`、`max_in_flight=0`、
    `RE0AUTH_INTROSPECTION_CLIENTS=wide_open_resource_server`、`reauth_window=0` 全部设成
    「与默认不同且都指向更弱」的值，驱动真实 `run()`，捕获到的完整日志是：
    ```
    INFO  configuration file            path=…
    WARN  storage is in-memory: …       because="no DATABASE_URL"
    WARN  audit log is in-memory; records do not survive a restart
    INFO  key rotation complete         scanned=0 rewrapped=0 already_current=0
    WARN  there was nothing to rotate; …
    ```
    八个字段**一个都没出现**（探针逐个断言并打印）。第二条探针（
    `TestProbeNoSecretIsEchoedAtStartup/the_serving_path`）走了更强的路径，完整日志也只有：
    `configuration file` / `storage is in-memory` / `audit log is in-memory` /
    `registered downstream client client_id=cli type=confidential` / `authorization engine …` /
    `account erasure cannot clear per-account sessions …`。
  - 对照：真正重要但**已被**打印的有 `audit log` driver、`authorization engine` store、
    `operator plane enabled admins=<count>`、`internal surface listening`、`listening`。
- 状态: **CONFIRMED**
- 影响: 一次「这个实例是不是把 pprof 绑到 0.0.0.0 了」「限流还开着吗」「XFF 到底信不信」的核对，
  在日志里找不到答案，只能回读配置文件（而配置文件与环境的覆盖关系又不是一眼可见的，
  见 CS-5 与 `config/re0auth.example.toml` 的「Environment override」注释只有部分键有）。
  这与项目反复强调的「一个看起来应用了其实没应用的设置」是同一类风险。
- 修法建议: 在 `cmd/re0auth/main.go` 的启动序列里加**一行**结构化的、无秘密的生效摘要：
  `slog.Info("effective configuration", "cookie_secure", …,
  "rate_limit", …, "max_in_flight", …, "trusted_proxies", len(…),
  "allow_private_upstreams", …, "internal_addr", …, "expose_internal", …,
  "introspection_clients", len(…), "admin_reauth_window", …)`。
  这些字段全部不是秘密（`config/re0auth.example.toml` 里就是明文示例），
  而 CS-3 的「空前缀」也正好在这里可被看见。
- 复现/守卫: `cmd/re0auth/zzprobe_startup_test.go` `TestProbeStartupLogOmitsEverySecuritySwitch`、
  `TestProbeNoSecretIsEchoedAtStartup`（后者同时是「这条摘要不得带秘密」的反向守卫）。

### CS-7 内部监听器（`/metrics` + `/debug/pprof/*`）没有任何访问日志：谁抓过堆、谁做过 60s CPU profile 无从查证

- 严重度: 中
- 类别: 可观测性 / 安全（取证）
- 不变量/性质: 「安全相关的访问必须留痕」——公网面每个请求都有一行，运维面一行也没有
- 证据:
  - `internal/observability/observability.go:541-546` `InternalHandler()` 返回一个**裸 mux**
    （`/metrics` + `registerPprof`），既没有访问日志也没有任何 slog 调用点；
    `cmd/re0auth/main.go:647-659` 用 `newServer(metrics.InternalHandler())` 起第二个监听器，
    `newServer`（`main.go:705-719`）只配超时，不装任何中间件。
  - 已执行（`TestProbeInternalSurfaceRequestsAreNotLogged`）：把进程默认 slog 换成捕获器，
    经内部 handler 请求 `/metrics`、`/debug/pprof/heap`、`/debug/pprof/goroutine?debug=1`
    （三者都断言 200 且 body 非空）之后：
    ```
    a prometheus scrape and two pprof dumps produced 0 bytes of log
    ```
    对照：同样 3 次经公网 handler 的 `/v1/me` 产生了恰好 3 行 `msg=request`（探针里断言了行数，
    否则这条比较是空转）。
  - 公网面对这些路径一律 404（`TestProbeOperationalSurfaceIsNotOnThePublicListener` 逐个断言了
    `/metrics`、`/debug/pprof/`、`heap`、`profile`、`cmdline`、`goroutine`），所以**唯一**能做
    pprof 的地方就是那个不留痕的监听器。
- 状态: **CONFIRMED**
- 影响: `deploy/k8s/base/configmap.yaml`（第 11-20 行）把运维面绑在 `0.0.0.0:9090` 并靠
  NetworkPolicy 限定来源；一旦那条网控失效（deploy-ops DEP-13 的整个场景），
  能把 `/debug/pprof/heap`、`/debug/pprof/goroutine?debug=2` 抓走的 Pod 不会在日志里留下任何证据。
  同样地，`/metrics` 的抓取也不进黄金指标（`re0auth_http_requests_total` 看不到内部面），
  于是一份「谁的 CPU profile 让延迟升高」的复盘没有数据。
  界：必须先能到 9090，所以不是远程可利用，而是**取证缺口**。
- 修法建议: 给内部监听器套一个极简访问日志（`slog.InfoContext`，字段 `path`/`status`/`remote`，
  不记 query），或至少对 `/debug/pprof/` 子树记录每个请求（profile 的 `seconds` 参数值得记）。
  这条不引入任何新面，只是让已有的面可被追责。
- 复现/守卫: `internal/zzprobe/startup/surface_probe_test.go`
  `TestProbeInternalSurfaceRequestsAreNotLogged`、`TestProbeOperationalSurfaceIsNotOnThePublicListener`。

### CS-8 关闭路径里唯一没有总时间上界的阶段是审计批次排空，而 manifest 的 45s 宽限期只算了 HTTP 的 30s

- 严重度: 低
- 类别: 可用性（可维护性/部署）
- 不变量/性质: I3 的「审计可写」在关闭时不丢行，但关闭本身必须仍在编排器的宽限内
- 证据（读代码到行；本机无 DB，未执行）:
  - `cmd/re0auth/main.go:344` `defer store.close()` 与 `:366-369` `defer func(){ stopLoops(); loops.Wait() }()`
    ——LIFO 决定顺序是「先停循环并 join，再关存储」，而 `store.close` 对持久化部署是
    `postgres.DB.Close`（`internal/store/postgres/postgres.go:254-263`），它先同步调用
    `AuditLogger.Close`（`audit.go:48-52`）→ `auditBatcher.Close`（`auditbatch.go:198-208`）→ `run()` 走 `drain()`
    （`:147-156`）。**排空是做了的**，这一点是对的，且顺序正确。
  - 但 `drain()` 对队列里每一项调 `b.flush(item)`，而 `flush` 的收集循环里有
    `case <-b.stop: break gather`（`:175-176`）——`stop` 此时已经关闭，于是**每行一个事务**；
    每个事务的界是 `auditBatchTimeout = 5s`（`:41`），队列深度 `auditQueueDepth = 512`（`:46`）。
    即最坏情况是 512 次「链头行锁 + 往返」，每次最长 5s 的**串行**预算，而这一段没有任何总上界。
  - 部署侧把 45s 的宽限期解释成「比服务自己的 30s drain 更长」：
    `deploy/k8s/base/deployment.yaml:21-23`。
- 状态: **HYPOTHESIS**（无 Postgres，无法构造 512 行排队 + 慢库的交错；
  要证实需要 `TEST_DATABASE_URL` + 一个人为拖慢 `appendBatch` 的注入点）
- 影响: 数据库在关闭瞬间不可用时，进程可能在 SIGTERM 之后远超 `terminationGracePeriodSeconds`
  才退出（每次 5s × 行数），被编排器 SIGKILL——那些行本来也写不下去，所以**不丢已经提交的审计**，
  但会让「优雅关闭」在事故时表现为「卡住」。运维可以再发一次 SIGTERM 强杀
  （`main.go:314-317` 已经把默认信号处理恢复，这条是对的）。
- 修法建议: 给排空一个总预算（如 `context.WithTimeout(…, 5*time.Second)` 包住 `AuditLogger.Close`，
  或在 `Close` 里按 `drain` 的截止时间放弃剩余行并 `slog.Error` 报告丢了几行）；
  或者让 `drain` 在被 stop 后仍然按批（把 `flush` 的 `<-b.stop` 分支改成只在首次收集后生效）。
  顺带把 manifest 的注释改成「45s > HTTP 30s + 审计排空预算」。
- 复现/守卫: 无（无 DB）。建议的守卫：`auditbatch_test.go` 里加一条
  「Close 之后 `drain` 仍然成批」的断言，和一条「排空超预算时返回错误并报告行数」的断言。

### CS-9 文档引用的两个键名/变量名在实现里不存在

- 严重度: 低
- 类别: 可维护性（运维文档即合同）
- 不变量/性质: 「文档描述的行为必须存在」
- 证据（读代码到行 + 全仓 grep）:
  - `docs/runbooks.md:27` 让 Re0AuthHighErrorRate 的处置步骤「检查 `RE0AUTH_DATABASE_URL`」；
    `grep -r RE0AUTH_DATABASE_URL --include=*.go` **0 命中**。真实变量是 `DATABASE_URL`
    （`cmd/re0auth/config.go:408`），或配置里 `storage.dsn_env` 命名的那个名字——正因如此
    运维文档不能写死一个名字，这条本身就该改成「检查 `[storage] dsn_env` 指名的变量」。
  - 同类但**已由 deploy-ops（DEP-09/DEP-10）覆盖**，此处列出只为完整性：`docs/runbooks.md:9` 与
    `docs/incident-response.md:21` 的 `[admin].allow`（真实键 `[admin].subjects`，
    且未知键会被严格解码拒绝启动）、`docs/runbooks.md:11` 与 `docs/slo.md:79` 的
    「`server.internal_addr` 默认 `:9090`」（真实默认是**不监听**）。
- 状态: **CONFIRMED**
- 影响: 事故处置时按文档去找一个不存在的环境变量；`RE0AUTH_DATABASE_URL` 这个名字还会让人
    以为自己设对了（他们设的是 `DATABASE_URL`），与 CS-5 的误导性警告叠加。
- 修法建议: 改写 `docs/runbooks.md:27` 为「检查配置里 `storage.dsn_env` 指名的变量（默认
  `DATABASE_URL`）与 Postgres 的 `max_connections`」。
- 复现/守卫: 无自动守卫；建议在 `internal/archtest` 里加一条「文档中出现的
  `[a-z].` TOML 键与 `RE0AUTH_*` 变量名必须在 schema/代码里存在」的扫描（deploy-ops 也提了同类守卫建议）。

### CS-10 `config/re0auth.example.toml` 的「Environment override」注释只覆盖部分键，且 `storage.driver` 根本没有环境变量

- 严重度: 提示
- 类别: 可维护性
- 不变量/性质: 文档作为合同（本项目把示例配置的注释当契约）
- 证据（逐键比对 `cmd/re0auth/config.go` 与 `config/re0auth.example.toml`）:
  - 文件第 13 行声明「Precedence is: environment > this file > built-in default」，并且对
    **部分**键给出了 `# Environment override:` 行（`max_in_flight`、`trusted_proxies`、
    `internal_addr`/`expose_internal`、`introspection_clients`、`admin.subjects`、
    `admin.reauth_window`、`allow_private_addresses`）。
  - 实际存在但**未标注**的环境覆盖：`RE0AUTH_ISSUER`（`config.go:405`）、`RE0AUTH_ADDR`（`:404`）、
    `RE0AUTH_COOKIE_SECURE`（`:395`）、`RE0AUTH_RATE_LIMIT` / `RE0AUTH_RATE_LIMIT_BURST`（`:445-452`）、
    `RE0AUTH_KEK_ID`（`:407`）、`RE0AUTH_CLIENT_ID` / `RE0AUTH_CLIENT_NAME`（`:641-642`）、
    `RE0AUTH_STORAGE_{MAX,MIN}_CONNS` / `_{CONNECT,STATEMENT}_TIMEOUT`（`:929-940`）——
    后四项在 storage 段里是标了的，前几项没有。
  - 反向（更值得写进去的）：`storage.driver` **没有任何**环境覆盖（CS-5），
    而它在示例文件里是唯一决定「这个部署持不持久」的键。
  - 「EVERY FIELD HAS A DEFAULT」（第 11 行）对 `client.redirect_uris` 与 `client.scopes` 也不完整：
    省略时默认是 `issuer + "/callback"` 与 `["account.id"]`（`config.go:643-650`），
    这两个默认值在示例文件里一个字都没有。
- 状态: **CONFIRMED**（逐键比对；`grep` 与 `file:line` 可复核）
- 影响: 一个想「只用环境变量、不写配置文件」的部署会以为 `storage.driver` 能被环境覆盖
  （第 13 行的总规则这么说），于是得到 CS-5 的内存模式；同时 `RE0AUTH_RATE_LIMIT` 这种
  直接影响限流生效的变量在文件里查不到，运维会以为限流只能靠文件。
- 修法建议: 要么给每个键补 `# Environment override:`（推荐，成本是十几行注释），
  要么把第 13 行的总规则改成「secrets and per-deployment settings come from the environment;
  see each key's Environment override line」，并补 `RE0AUTH_STORAGE_DRIVER`。
- 复现/守卫: 建议加一条守卫：解析 `cmd/re0auth/config.go` 里的 `os.Getenv("RE0AUTH_*")` 集合与
  示例文件里出现的 `Environment override:` 名字集合，两者差集必须为空（或必须在白名单里）。

---

## 探过但**没**破的（这些也应变成守卫）

1. **启动不泄露任何秘密。** `TestProbeNoSecretIsEchoedAtStartup` 把 KEK / audit key / OIDC token key /
   OIDC signing key / client secret / IdP secret / source secret 都设成可识别的值，分别驱动
   「`-rotate-keys` 路径」（到达 `key rotation complete`）与「服务路径」（到达
   `registered downstream client`），断言这些值及其可打印前缀都不在捕获到的日志里 — 通过。
   全仓 `slog` 调用点我逐个看过（`grep -n 'slog\.(Debug|Info|Warn|Error|LogAttrs)'` 共 67 处），
   没有任何一处拼接配置结构体或密钥；`%+v` 只出现在 `_test.go` 里。
2. **没有「为了方便打印完整生效配置」的路径。** `cmd/re0auth` 里没有任何
   `slog.*(…, cfg)` / `fmt.Printf("%+v", cfg)`；`settings` 的字段只在启动摘要式日志里被**逐个取值**。
3. **协议平面在恶意输入下仍然是 OAuth JSON。** `TestProbePostOnlyProtocolEndpointsAlwaysAnswerOAuthJSON`
   把 `/oauth/token|introspect|revoke|device_authorization` 用 POST/PUT ×
   {JSON body、无 Content-Type、text/plain、无 boundary 的 multipart、坏百分号编码、空 body、
   二进制垃圾、未知/缺失 grant_type} 共 26 种组合打了一遍，每一次都是 4xx/5xx + JSON + `error`
   字段，且 `error_description` 里没有 `ErrorType=`/`Parent=`。这同时回答了「`serveOAuth` 的
   `switch` 让 `isToken` 分支遮住 `normalizeOAuthFailure` 是否可被利用」——**今天不可达**：
   畸形 body 由库写成 OAuth JSON，动词错误在 `oidchttp.go:430` 之前就被 405 JSON 挡掉。
   建议把这条走查固化（它是 `plane_test.go` 那份「按方法走」走查的 POST 半边的补集）。
4. **协议平面动词矩阵。** `TestProbeProtocolEndpointsRefuseEveryUnlistedVerb`：8 个端点 × 8 个动词，
   所有未列动词都是 405 + JSON + `error`，在预检之前发生（`oidchttp.go:430-434`）。
5. **日志注入与响应头拆分不可达。** `TestProbeAttackerRequestIDCannotForgeALogLineOrAHeader`：
   进程内路径（绕过 transport 校验）给 `X-Request-Id` 塞 `\n`/`\r`/ESC，
   slog 把它整体引号化（`request_id="req_x\nINFO server up\rX-Injected: yes\x1b[31m"`，日志仍是一行，
   没有裸 ESC）；原始 socket 路径下，带裸 CR 或 ESC 的请求头被 **Go 的 transport 直接 400**，
   带头部内空格的值被原样接受但日志里仍引号化。
   残余（提示级）：`X-Request-Id` 无字符集/长度校验、原样回显（`middleware.go:138,142`），
   调用方可以自选一个关联句柄——已有 `TestRequestIDIsEchoed` 把它当作契约钉住，
   影响限于「支持流程里可以冒充别人给的 request id」，未升级为发现。
6. **运维面不在公网监听器上。** `TestProbeOperationalSurfaceIsNotOnThePublicListener`：
   6 条路径全 404，且 body 里没有 `go_goroutines`/`goroutine profile`；
   同时先断言内部 handler 对 `/metrics`、`/debug/pprof/` 确实 200（反空转）。
7. **探针端点不带缓存、不带版本。** `TestProbeHealthEndpointsAreNoStoreAndLeakNothing`：
   `/healthz`、`/readyz` 的 body 恰为 `ok\n` / `not ready\n`，`Cache-Control: no-store`，
   无 `Server` 头，body 里没有 `re0auth `/`dev`/`v0.`/`go1.`；依赖错误只进 DEBUG 日志
   （`health.go:44-50`），503 body 里没有 `context`/`deadline` 字样。
8. **操作面不可能被「无允许列表地挂载」。** `TestProbeOperatorPlaneIsRefusedWithoutAnAllowlist`：
   `Config.Admin` 非 nil + `Admins` 为空被 `httpapi.New` 拒绝（`server.go:262-264`），
   组合根也只在 `len(cfg.adminSubjects) > 0` 时设置它（`main.go:557`）；
   `admin.subjects` 里的空串被丢弃（`config.go:662-674`），`*` 只是一个谁也匹配不到的集合成员
   （`adminAllowed map[account.UserID]bool`）。即「没有 `admin.subjects` ⇒ 挂成 permit-all」不成立。
9. **严格解码覆盖了「凭空发明的段」和几种空段。**
   `TestProbeInventedAndEmptySectionsAreRefused`：`[oidc]`（schema 里不存在，最像会被发明的段）
   → 拒绝并点名 `oidc`；空 `[vault]` + 未设 `RE0AUTH_KEK` → 拒绝；
   `driver = "postgres"` + 未设 `dsn_env` 指名的变量 → 拒绝并点名该变量；
   `statement_timeout = "30"` → 拒绝并要求 duration。重复键与重复表也由 TOML 解码器拒绝
   （`TestProbeDuplicateTOMLKeys`：`Key 'server.issuer' has already been defined.`）。
   ——没有任何「未知键被静默忽略」的入口。
10. **媒体里说的「§1 假设 `internal_addr == addr` 被拒」是逐字成立的**；还有
    `expose_internal` 对非 loopback 地址的承认要求（`config.go:522-529`）成立且保守
    （`internalAddrIsLocal` 覆盖 127/8、`::1`、`localhost`，其余一律算可达）。
11. **`/metrics` 的标签是有界的。** 我按 `observability.go` 的每个 `Observe*` 与标签逐条核对，
    并看了 `upstream_fetches_total` 的全部调用点（`internal/federation/service.go:239-403`
    全部用 `result.Source`/`src.Name`/`registry` 里的名字），`grant_type`/`error`/`method`/`plane`
    都有归一化；无界标签没有找到。
12. **优雅关闭的覆盖面是对的。** `serveUntilSignal`（`main.go:732-762`）对 endpoints 切片逐个
    `Shutdown`，公网与内部监听器共用同一个 `drainCtx`；`TestServeUntilSignalDrainsEveryEndpoint`
    已经钉住「两个监听器都被关掉」。第二个 SIGTERM 会强杀（`main.go:314-317` + `stop()` 恢复默认处理），
    `run()` 的 defer 顺序（循环 join → 池关闭）也正确 —— 包括审计批次排空确实被调用（CS-8）。
13. **exit code 语义正确。** `main` 是唯一 `os.Exit`（`exit_test.go` 的 AST 守卫），
    `run()` 的错误一律非 0，干净关闭返回 0；`-migrate-down` 无 DSN 时 `die(...)`（`main.go:1066-1068`）。
14. **`-rotate-keys` 走的是与服务器相同的配置校验**（`loadConfig` → KEK → 持久化时 audit key →
    DB/advisory lock），并且 `vault.Rotate` 是幂等且 fail-closed 的
    （`vault/rotate.go:102-119` 甚至会验证「换了材料但没换 `kek_id`」并明确报错）。
    它**不**要求 `RE0AUTH_OIDC_*`（那在 `openOIDC` 里，位于 rotate 返回之后）——
    这是合理的（轮换不该依赖 OP 密钥），但意味着 `re0auth -rotate-keys && systemctl restart`
    的第二步可能因为 OP 密钥缺失而失败；内存模式轮换只打一条 WARN 并退出 0（`main.go:1092-1094`）。
15. **`-version` 只打印版本**（`main.go:231-234`：`fmt.Println("re0auth", version)`），
    且在任何配置/日志初始化之前返回。
16. **假说被证伪并保留为守卫**：我曾假设内部监听器共用公网的 `writeTimeout=60s` 会截断
    `?seconds=61` 的 CPU profile。实测（`TestProbeInternalListenerWriteTimeoutTruncatesAProfile`，
    61 秒）结果是 **200 + 917 字节完整 gzip**——Go 的写超时只让「会阻塞的写」失败，
    能进 socket 缓冲的 body 不受影响。所以本条不是发现；探针保留，因为它钉住了
    「比写超时更长的 profile 仍然完整」这个运维依赖的性质。

---

## 未能到达（残余盲区）—— 必须写，并说清为什么

- **一切 Postgres 路径**（本机无 Docker、无 Postgres）：`/readyz` 真实的 `pool.Ping` 行为、
  CS-8 的审计排空交错、`/metrics` 的 `db_pool_*` collector、连接池耗尽时的表现、
  `statement_timeout` 与审计批次 5s 预算的相互作用。这些只有 `file:line`。
  要证实 CS-8 需要 `TEST_DATABASE_URL` + 一个能人为拖慢 `appendBatch` 的注入点。
- **集群侧**：`expose_internal` + NetworkPolicy 的「部署真的实现了网控」这一步（deploy-ops DEP-13
  负责），以及 `trusted_proxies = ["10.0.0.0/8"]` 在真实 ingress 下的 XFF 形态。
- **`scripts/backup-keys.sh:62` 的正则回退（HYPOTHESIS，未执行）**：当 `RE0AUTH_BIN` 不可执行时，
  「这份配置声明了机密变量吗」用的是
  `grep -Eq '(client_secret_env|kek_env)[[:space:]]*='`，而不是解码器。TOML 允许带引号的键
  （`"kek_env" = "MY_KEK"`、`"client_secret_env" = "GH"`），此时名字与 `=` 之间隔着 `"`，
  正则不匹配 ⇒ 脚本会以「只有四把固定密钥」的模式继续，写出一个**看起来完整**、却漏掉
  IdP / 数据源 client secret 的备份，而 `docs/operations.md:100-101` 承诺过
  「宁可没有备份，也不要一个看起来完整的备份」。（KEK 被重命名那种情况恰好被
  `write_key RE0AUTH_KEK` 的「未设置就中止」兜住，所以只有非 KEK 的声明会漏。）
  **本机没有 bash，无法执行验证**；要证实需要一台有 bash 的机器跑上面两行 grep。
- **`-race` 的边界**：本机 `CGO_ENABLED=1`，`-race` 跑得起来（我的两个探针包都过了 -race），
  但我没有用 `-race` 跑别人区域的并发用例。
- **没有跑 `go test ./...`**（按简报要求），因此「我的探针不干扰其他区域」只验证到
  「`go test ./cmd/re0auth/` 与 `./internal/zzprobe/startup/` 全绿」这一层。
- **第三方 op 库的日志**未重审（第四轮已闭环，本轮只沿用结论）。
- **`-migrate-down` 在「无可回退迁移」时的退出码**未验证：`postgres.MigrateDown`
  （`postgres.go:399-407`）依赖 goose 的 `provider.Down`，goose 在空版本表上的行为我没能从代码断定，
  也没有 DB 可跑。如果它返回「nothing to do」而不是错误，`re0auth -migrate-down` 会以 0 退出且什么都没做
  ——那是「exit 0 而没做成事」的一个候补入口。要证实需要一次 `TEST_DATABASE_URL` 的空库运行。

---

## 判断（文档化决定可否质疑，不是 finding）

1. **`/readyz` 的两个豁免是文档化决定，但文档只论证了其中一个。** `docs/operations.md:121`、
   `docs/api-design.md:369-373` 与 deploy-ops 的第 592 行都把「免限流」当成正确取舍
   （桶满不能把健康实例摘出轮转），我同意那个论证。我的分歧只在**并集**：
   免限流 + 免并发上限 + 每请求一次池往返，这三件事同时成立时，匿名调用者可以不给
   自己花任何预算地占住池。所以 CS-1 的修法不是取消豁免，而是给**探测自身**加一个界。
   如果裁定认为「入口反代必有限流，所以不必管」，那也应该把这条假设写进
   `docs/operations.md` 的部署前提里（现在没有）。
2. **`vault/rotate.go:74` 用 `_ = s.record(...)` 丢弃轮换事件的审计错误。** 按
   `docs/architecture.md:591`（admin 面：「审计失败不回滚已发生的安全动作，只告警」）与
   `:610`（抹除路径：「审计失败即失败」），项目是**按面**定政策的；轮换属于哪一面没有写。
   所以这不是一条 finding，而是一条待写成政策的裁定：如果轮换事件也属于「必须留痕」那一类，
   就该把 error 返回（`rotateAndReport` 会以非 0 退出）；如果属于「事后记录」那一类，
   就该在 `Rotate` 的注释里写明。同类还有 `internal/store/{memory,postgres}/oidc.go` 的
   `record()`（令牌/设备事件 best-effort）——它们在「动作已经完成」这一点上与 admin 的先例一致，
   我按先例不报。
3. **`trusted_proxies` 的宽度该不该由代码裁定。** CS-3 的修法我建议只拒「`0.0.0.0/0`/`::/0`」
   这一档（等于没配备忘），但严格说「多宽算宽」是部署决定（k8s 基线自己用 `10.0.0.0/8`）。
   若裁定为「不拒，只告警」，那至少要让它出现在启动日志里（CS-6），
   否则这条设置与 CS-5 的 `driver` 是同一类「看起来应用了」的沉默。
4. **内部监听器没有访问日志**：我没在文档里找到任何「刻意不记录运维面访问」的说明，
   所以按 CS-7 报为发现；如果它其实是（未记录的）有意选择，那它至少缺少一句
   「pprof 的调用不留痕是已知边界」——与威胁模型其它条目的写法保持一致。
