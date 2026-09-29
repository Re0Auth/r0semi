# 区域 Z12：配置 / 启动 / 可观测性 / 关闭 — 第七轮审计报告

> `HEAD = bf81b2a`。探针：`internal/zzprobe/audit7/z12configstartupobservability/`（`//go:build audit7` + `doc.go` 带 `!audit7`）。
> 验证：`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z12configstartupobservability/...` → **11 个探针函数，9 红 / 2 绿**。
> `go build ./...` exit 0，`go vet ./...` exit 0，`gofmt -l` 干净，被跟踪文件零修改。

## 范围与方法

读了 `cmd/re0auth/{config,main}.go`（全文）、`internal/config/*`、`internal/observability/observability.go`、
`internal/httpapi/{health,clientaddr,server}.go`、`internal/ratelimit/ratelimit.go`、`oauth/client.go`、
`config/re0auth.example.toml`、`deploy/k8s/base/{configmap,deployment}.yaml`，以及前轮台账
（`docs/security-audit-{5,7}.md`、`AUDIT-ISSUES.md`、`cmd/re0auth/zzprobe_startup_test.go` 的 CS-1…CS-10）。
跑了：真二进制黑盒（`TestMain` 构建一次）+ 进程内 `httpapi` 全接线 `httptest.Server` + 真 `ratelimit`。
本机无 Docker / 无本地 Postgres ⇒ 涉及真实库的结论标 HYPOTHESIS。

## 发现

### Z12-1 缺 `id:` 前缀的 `RE0AUTH_OIDC_RETIRED_TOKEN_KEYS` 把密钥原文打进启动日志
- 严重度 P2 · 类别 安全 · 不变量 凭据封存 · 状态 CONFIRMED
- 证据（红探针，真二进制）：`main.go:1410` `fmt.Errorf("...entry %q must be id:base64", part)`，`part` 是整段（含密钥材质）；
  只有「漏 `id:` / id 为空」会走到它，那正是「只粘贴密钥」的形状。
  ```
  --- FAIL: TestZ12RetiredTokenKeyIsEchoedIntoTheStartupLog
      stage=oidc err="RE0AUTH_OIDC_RETIRED_TOKEN_KEYS entry \"WjEyLVJFVElSRUQtVE9LRU4tS0VZLU1BVEVSSUEAAAA=\" must be id:base64"
  ```
  阳性对照：合规 `z12-old:<base64>` 走到 `stage=listen` 且日志**不含**密钥。
- 影响：退役令牌密钥仍是活密钥（解密轮换前签发的全部不透明 access token）。CS-8 的 planted 集合恰好没这个变量 ⇒ 该路径从未被守卫覆盖。
- 修法：消息只报位置/形状；CS-8 守卫补 plant 该变量。关联：对 **CS-8** 覆盖面的补充。

### Z12-2 `-rotate-keys` 扫到 0 条时退 0，恰好满足文档写下的放行闸门
- 严重度 P2 · 类别 安全/可用性（静默，退出码 0）· 不变量 fail-closed · 状态 CONFIRMED
- 证据（红探针，真二进制、内存模式，`exit=0`）：
  ```
  key rotation run finished: scanned=0 rewrapped=0 already_current=0 skipped=0
  there was nothing to rotate; is the configured storage the one holding credentials?
  ```
  `rotationReport`（`main.go:1209-1231`）把 `Scanned == 0` 只当文案，`complete=false` ⇒ 返回 nil。
  `config/re0auth.example.toml:232-233` 的闸门是「直到打印 `rewrapped=0 skipped=0` **且退出 0**」，空运行已满足。
- 影响：`RE0AUTH_STORAGE_DRIVER=memory` 或指错存储时，「没有要轮换的」与「这存储不持凭据」不可区分；照文档删 retired 会把真库记录留在旧键。
- 探针：`z12loader_test.go::TestZ12RotateKeysExitsZeroHavingScannedNothing`（红）；修法：`Scanned == 0` 时非零退出。
- 关联：**对 k-V1 的补充**——k-V1 前提是非空存储 + 迟到写入，本条是**空存储**这一更早分支，其「无条件告警」建议不覆盖退出码。

### Z12-3 首个 seed 之后 `[client]` 的任何改动都被静默忽略
- 严重度 P1 · 类别 安全（认证边界）· 不变量 fail-closed · 状态 CONFIRMED
- 证据（红探针，真 `oauth.ClientRegistry`，即组合根传的那个接口）：
  ```
  --- FAIL: TestZ12SeedClientNeverReconcilesTheConfiguredClient
      deployment asks type="confidential" redirect=[https://newapp.example/callback] scopes=[account.id phigros.profile.read]
      registry still answers type="public" redirect=[https://app.example/callback] scopes=[account.id]
  ```
  `seedClient`（`main.go:1583-1591`）`Get` 成功即 `return nil`，只打 `downstream client already registered`。
- 影响：① 给 `client.secret_env` 加秘密以为首方客户端变机密，实际仍是公开客户端（内省守卫会对它 401）；② 改 `redirect_uris` 后回调走旧地址；③ scopes 既不能加也不能收。日志只在**第一次**启动说 `registered`。
- 探针：`z12seedclient_test.go::TestZ12SeedClientNeverReconcilesTheConfiguredClient`（红）
- 修法：`Get` 命中后比对 type/redirects/scopes/secret-hash，不一致**拒绝启动**并点名字段。**这是一次裁定**（会改上线流程）。
- 关联：无（第五/六轮无此编号）。Postgres 侧为读码级（同一接口，无 reconcile 调用）。

### Z12-4 文件里配的列表无法被环境清空（`RE0AUTH_ADMIN_SUBJECTS=""` ≠ 无人）
- 严重度 P2 · 类别 安全/可维护性 · 不变量 fail-closed · 状态 CONFIRMED
- 证据（红探针，真二进制）：
  ```
  --- FAIL: TestZ12FileConfiguredListsCannotBeClearedFromTheEnvironment
      日志：level=INFO msg="operator plane enabled" admins=1（文件 subjects=["usr_operator"]）
  ```
  阳性对照：无 `[admin]` 段时同一环境不挂操作平面。机制：`config.go:799`（admin）、`:564`、`:655` 都用
  `if v := TrimSpace(os.Getenv(...)); v != ""`，空串 = 未设置；相邻的 `rate_limit` 特意用指针区分「缺省」与「显式 0」。
- 影响：三个安全列表都不能从环境收窄到空；最重的是 admin——运维以为清空了 allowlist，`/v1/admin` 仍挂着且无任何日志说明空值被忽略。
- 探针：`z12loader_test.go::TestZ12FileConfiguredListsCannotBeClearedFromTheEnvironment`（红）
- 修法：与 `rate_limit` 同形的「区分缺省与显式空」，或在启动日志公布三个列表的**生效长度**（顺带收口 CS-6）。
- 关联：无。与 CS-5 同族（「看起来应用了」），但 CS-5 是驱动选择。

### Z12-5 `-migrate-down` 先跑整套 serving 期校验，缺审计链密钥就无法回滚
- 严重度 P3 · 类别 可用性（恢复路径）· 不变量 fail-closed · 状态 CONFIRMED
- 证据（红探针，用 stage 度量）：`stage=config err="RE0AUTH_AUDIT_KEY is required when the audit log is durable (32 bytes, base64 or hex)"  exit=1`
  阳性对照：补上该键后同命令走到 `stage=migrate-down`（真连库）。机制：`run()` 在 `main.go:332` 无条件 `loadConfig`，
  `main.go:369-371` 才分发；而 `migrateDownAndReport`（`main.go:1158-1166`）只把 DSN + `ConnectTimeout` 交给 `MigrateDown`。
- 影响：迁移失败后的恢复动作依赖一整套与之无关的密钥（KEK、audit key、两个 OIDC 密钥）；轮换/丢失期间无法回滚。
- 探针：`z12migratedown_test.go::TestZ12MigrateDownRequiresTheServingTimeSecrets`（红）
- 修法：给 `loadConfig` 一个「只解析 DSN/池」的模式（仍拒绝它真用得到的坏值）。**这是一次裁定**。
- 关联：对第五轮 `config-startup-disclosure.md:484-486`（该子命令退出码未验证）的补充——退出码是 1，但**拒绝的理由**与回滚无关。

### Z12-6 `rate_limit = NaN` 被接受，并让限流器**放行一切**
- 严重度 P2 · 类别 安全（限流失效）· 不变量 fail-closed · 状态 CONFIRMED
- 证据（红探针：先证明真进程接受该拼写，再测真 `ratelimit`）：
  ```
  RE0AUTH_RATE_LIMIT=nan was accepted: the run reached stage=listen
  1000 sequential requests: finite(50/s,burst100)=100 NaN=1000 +Inf=1000
  ```
  机制：`config.Float` = `strconv.ParseFloat`（收 `NaN`/`Inf`）；`loadConfig` 只挡 `< 0`（`config.go:512-522`），NaN 与任何比较为 false
  ⇒ 穿过负值、`== 0`、`burst < 1` 三道；`buildLimiter`（`main.go:224-229`）`NaN <= 0` 也是 false ⇒ 装了限流器。
  内部：NaN ≠ `rate.Inf`，走常规 `reserveN`，`tokens=NaN`，`x/time/rate` 的 `!(tokens < 0)` 为 true ⇒ 每次都允许。
- 影响：一个 `nan` 拼写（TOML 或环境）静默关掉按地址负载卸载；文档里「关掉」的唯一拼写是 `0`，负值会被拒。
- 探针：`z12limiterargs_test.go::TestZ12NonFiniteRateLimitIsAcceptedAndDisablesTheLimiter`（红）
- 修法：`loadConfig` 加 `math.IsNaN/IsInf` 拒绝并点名该键。关联：无。

### Z12-7 `/readyz` 缓存可被一个挂断的匿名调用者污染成 503（方向与 G-11 相反）
- 严重度 P2 · 类别 可用性（探针语义）· 不变量 fail-closed 的边界 · 状态 CONFIRMED
- 证据（红探针，真 `httpapi` 全接线；依赖桩是「健康但慢 150ms」的真实往返形状）：
  ```
  --- FAIL: TestZ12ReadyzIsPoisonedByACallerThatHangsUp
      /readyz = 503 "not ready" after one anonymous caller hung up
  ```
  对照（同一探针）：无挂断时 200 且依赖 `cancelled == 0`；挂断后 `cancelled > 0` ⇒ 503 来自**那次取消**而非依赖故障。
  `readinessCache.check`（`health.go:111-133`）用**触发者自己的 `r.Context()`** 派生 `probeCtx`，把取消错误连同 `checkedAt` 写进缓存，
  于是 `readinessTTL` 内每个探测都拿 503；探针又免限流、免并发上限（`health.go:151-166`），调用者零成本。
- 影响：匿名者反复「打开即关闭」`/readyz` 即可让 k8s 把该实例摘出 Service（多副本部署可被匿名削减容量）。
- 探针：`readyz_test.go::TestZ12ReadyzIsPoisonedByACallerThatHangsUp`（红）
- 修法：用与调用者生命周期无关的上下文跑检查，或取消类错误不写缓存。
- 关联：**与 G-11 / P1-4 是同一条代码路径的三个面，不构成重报**——G-11 = `running` 分支用零值答 200（fail-open）；
  P1-4/CS-1 = 免限流 + 每请求一次池往返；本条 = `fresh` 分支把**被取消**的结果缓存成 503。三者修法互不覆盖。

### Z12-8 位置参数从不检查：漏掉横线的 flag 被静默忽略
- 严重度 P3 · 类别 可用性/可维护性 · 不变量 fail-closed · 状态 CONFIRMED
- 证据（红探针，真二进制）：`main()` 只调 `flag.Parse()`（`main.go:259`），**从不看 `flag.Args()`**；Go 的 Parse 在第一个非 flag 处停止。
  ```
  --- FAIL: TestZ12TrailingArgumentsAreSilentlyIgnored
      [-version rotate-keys] / [-version migrate-down] / [-version unexpected-positional-argument] 全部 exit 0
  ```
  阳性对照：`-version` 本身 exit 0 且打印一行。
- 影响：runbook / systemd unit / k8s `command:` 把 `-rotate-keys` 写成 `rotate-keys`，进程**照常起服务**（运维以为做了轮换）。
- 探针：`z12limiterargs_test.go::TestZ12TrailingArgumentsAreSilentlyIgnored`（红）
- 修法：`if flag.NArg() > 0 { ...; os.Exit(2) }`。关联：无。

### Z12-9 文件里的池大小被截断到 int32，环境变量路径却拒绝越界值
- 严重度 P2 · 类别 可用性/正确性 · 不变量 fail-closed · 状态 CONFIRMED
- 证据（红探针，真二进制，以 config/storage 哪个 stage 拒绝为度量）：
  ```
  --- FAIL: TestZ12PoolSizesAreTruncatedToInt32
      max_conns = 4294967297 走到 stage=storage（被读成 1）
      min_conns = 4294967296 被读成 0，作为「不保留热连接」静默接受
  ```
  阳性对照：`max_conns = 0` 在 `stage=config` 被点名拒绝；`16` 走到 `stage=storage`。
  机制：`resolvePool`（`config.go:1062-1067`）`int32(*section.MaxConns)`（MinConns 同形）；相邻的环境路径 `envInt32` 用 `strconv.ParseInt(raw, 10, 32)`。
- 影响：池大小是最容易写错量级的数字；`4294967297` 得到 1 连接的池（而不是拒绝），`min_conns` 截断方向是静默变 0，两者都无日志。
- 探针：`z12loader_test.go::TestZ12PoolSizesAreTruncatedToInt32`（红）
- 修法：先做 `math.MinInt32/MaxInt32` 范围检查，或把该字段声明为 `*int32`。关联：无。

## 探过但没破的（也应变成守卫）

1. `z12dsn_test.go::TestZ12DSNPasswordIsNotEchoedIntoTheStartupLog`（绿）：5 种 DSN 形态（不可达 / 端口非数字 / 无主机 / 未知 scheme /
   keyword-value 键错）都走到 `stage=storage` 且日志不含口令。CS-8 只覆盖良构 DSN，这 5 条补上驱动错误路径。
2. `z12surface_test.go::TestZ12InternalSurfaceIsSeparateFromThePublicOne`（绿，真进程 18201/18251）：公网 `/metrics`、`/debug/pprof/`、
   `/debug/pprof/goroutine` 全 404；内部 `/metrics` 200（含 `go_goroutines`、`re0auth_http_requests_total`）、`/debug/pprof/` 200；内部不挂 `/readyz`、`/v1/me`。
3. 未知 TOML 键 / 重复键 / 虚构段一律拒绝（`config.go:43-51` 的 `md.Undecoded()`；CS-7/CS-10 仍绿）；`internal_addr` 的「必须不同」+「必须本机」两道闸门保守（CS-2 仍绿）。
4. `trusted_proxies = ["0.0.0.0/0"]` 加 acknowledgement 后是**安全的无操作**：`clientaddr.go:104-110` 在「最右跳仍在列表内」时回落 peer。
5. `/readyz` 的**工作量**有界：`health.go:111-120` 的 `running` 闸门保证每 TTL 至多一次真检查；默认值全部指向安全侧
   （`internal_addr` 空、`client_addr_header="none"`、`trusted_proxies` 空、`allow_private_addresses=false`、两个列表为空）。

## 未能到达（残余盲区）

1. 无本地 Postgres / 无 Docker：Z12-9 只到「`stage=storage` 可达」，未用真库确认 `pgxpool` 实际池大小；Z12-3 的持久后端为读码级。权威位是 CI 的 `postgres:16`。
2. Z12-7 在真实 `pgxpool.Ping` 上的窗口长度未测（用 150ms 依赖桩代替；`cancelled > 0` 已确证取消是触发点）。
3. SIGTERM/SIGINT 关闭路径未做真进程黑盒：本轮探针都在监听器之前返回（`-rotate-keys`、`not-an-address`），
   `endpointRemovalWait` 的 5s 与两监听器排空顺序**没有实跑**（G-12/Z10V-2 的地盘，避免重报）。
4. `SIGHUP` 无任何 handler（`main.go:341` 只注册 SIGINT/SIGTERM）⇒ 默认动作终止进程；是否需要「重载配置」是裁定而非缺陷。
5. TOML 的 `nan` 字面量是否被 BurntSushi 解析成 NaN 未实跑（Z12-6 用环境变量路径确证）。`SetupLogging` 与真实 collector 的交互未测。

## 判断（文档化决定可否质疑，不是 finding）

1. 「环境 > 文件 > 默认」对列表类键事实上不成立（Z12-4 机制）。若裁定「空串即未设置是 Go 常识」，至少应把这条例外写进
   `config/re0auth.example.toml` 的 Precedence 段，并让启动日志公布生效列表长度。
2. `-print-secret-env` 打印变量**名**不是值，安全；其行格式是 `scripts/backup-keys.sh` 依赖的接口。
3. `-version` 在配置缺失时也工作（`main.go:264-267`）是刻意的；内存模式也要求两个 OIDC 密钥（`config/re0auth.example.toml:186-188` 已写明理由）。
4. `-rotate-keys` / `-migrate-down` 无二次确认（第五轮 `_main-runtime-findings.md:328` 已记录），本轮不重报。
