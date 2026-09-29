# 区域 19：密钥与敏感数据的全生命周期 — 第七轮审计报告

## 范围与方法

**读码**：`vault/` 全部、`internal/store/postgres/{vault,audit,auditchain,auditpseudo,postgres}.go`、
`cmd/re0auth/{config,main}.go`、`internal/config/{config,logging}.go`、`internal/wiring/keys.go`、
`internal/observability/observability.go`、`audit/audit.go`、`internal/auth/auth.go`、`idp/idp.go`、
`internal/federation/{bind,binding,refresh,revocation,service}.go`、`httpclient/outbound.go`、`scripts/backup-keys.sh`。

**跑过**：本区探针（6 个测试文件，5 红 1 绿）；`go test -run TestAdversarialProtocolErrorsDoNotLogCredentials ./internal/oidchttp/`
（GREEN，复核既有守卫）；`go build ./...`、`go vet ./...`（exit 0）；`go vet -tags audit7 ./internal/zzprobe/audit7/z19secretslifecycle/...`（exit 0）。

**真进程夹具**：`TestMain` 现编 `./cmd/re0auth`，内存模式起服于 `127.0.0.1:18901`（内部面 `18951`），
环境剥掉一切 `RE0AUTH_*`/`DATABASE_URL`。探针目录：`internal/zzprobe/audit7/z19secretslifecycle/`。

**重叠声明**：Z19-1 与区 12 的启动回显条目相邻但**不同站点、不同错误形状**；Z19-2 落在 `idp/`（区 14 范围含 RP，
若他们报同一处请合并）。

---

## 发现

### Z19-1 `*_env` 约定无人校验，把密值粘进变量名时启动错误把密值原文打进日志（配置回显的第二条通道）

- 严重度：P2 中
- 类别：安全 / 合规-隐私
- 不变量：凭据封存 | fail-closed（错误路径不得成为泄漏路径）
- 证据：`internal/config/config.go:57-66` — `Secret(envName, field)` 在目标变量未设置时返回
  `%s names %q, which is not set`，`%q` 就是**从配置文件里读来的那个字符串**；`cmd/re0auth/main.go:303-304`
  把它交给 `slog.Error("cannot start", "stage", "config", "err", …)`。整个 schema 的规矩是
  「配置文件绝不写密值，只写环境变量名」（`internal/config/config.go:3-7`、`cmd/re0auth/config.go:30-32`），
  但**没有任何一处校验这个名字的形状**。把值粘到名字位（`client_secret_env = "<secret>"`、
  `kek_env = "<base64 KEK>"`）正是这个约定邀请的错法。真进程复现（已执行，FAIL，四个密钥位全红）：
  ```
  level=ERROR msg="cannot start" stage=config err="vault.kek_env names \"Z19-KEK-VALUE-PASTED-INTO-THE-NAME-9d2c\", which is not set"
  err="client.secret_env names \"Z19-UPSTREAM-CLIENT-SECRET-4b71\", which is not set"
  err="idp.github.client_secret_env names \"Z19-IDP-CLIENT-SECRET-77ae\", which is not set"
  err="sources[0].client_secret_env names \"Z19-AUDIT-KEY-VALUE-1f0d\", which is not set"
  ```
  同族第二条（校验面）：`cmd/re0auth/config.go:1037` `entry %q …` 同样原文回显文件里的自由文本
  （探针 `TestZ19ConfigValidationDoesNotEchoFileValues`，FAIL）。对照组：名字合法但未设置时只回显名字。
- 状态：CONFIRMED（真进程黑盒）
- 影响：一次运维粘贴错误就把**活密钥**（KEK / 上游 client secret / IdP secret）写进进程日志——管道里还有
  log 收集器、SIEM，保留期远长于审计日志。进程 fail-closed 退出，所以不会自愈，也不会重复刷屏。
- 探针：`tomlecho_test.go::TestZ19SecretEnvNameHoldingTheSecretValueIsEchoed`（红）、
  `tomlecho_test.go::TestZ19ConfigValidationDoesNotEchoFileValues`（红）
- 修法建议：`config.Secret`（以及 `cmd/re0auth/config.go:1037` 一类 `%q` 站点）回显前先判形状：
  名字必须匹配 `^[A-Za-z_][A-Za-z0-9_]*$`，否则只报 `field`（"names a variable whose name is not a valid
  environment variable name; refusing to repeat it"）。与区 12 的两条回显条目一起收成「启动错误的回显纪律」。
- 是否与既有编号相关：无直接对应。**与 G-21/G-23 同一不变量、机制不同**：那两条是 slog attr 与错误文本里的
  身份，这条是**配置文件的值**被当成环境变量名回显；CS-8 守卫与区 12 的探针只种**环境**里的值，看不到它。

### Z19-2 凭据进 URL：QQ 取用户信息把 access token 放进查询串，`net/http` 的 `url.Error` 再把整条 URL 连同 token 交给调用方

- 严重度：P3 低/提示（当前唯一调用方丢弃该错误；机制成立且离线可复现）
- 类别：安全 / 可维护性
- 不变量：凭据封存（跨边界 emit 的最小暴露面）
- 证据：`idp/idp.go:651`、`:670-673` 构造
  `https://graph.qq.com/oauth2.0/me?unionid=1&access_token=<token>` 与
  `…/user/get_user_info?fmt=json&access_token=<token>&oauth_consumer_key=…&openid=…`；
  `getText`（`:710-722`）用 `%w` 包装 `hc.Do` 的错误，而 `http.Client.Do` 返回 `*url.Error`，
  其 `Error()` 就是 `Get "<完整 URL>": <cause>`。离线复现（自注入必然失败的 Transport，不触网，已执行，FAIL）：
  ```
  control (GitHub, Authorization header): idp: request: Get "https://api.github.com/user": z19 probe: transport refused
  DISCLOSURE error: idp: request: Get "https://graph.qq.com/oauth2.0/me?unionid=1&access_token=Z19-QQ-ACCESS-TOKEN-6ff3": …
  ```
  项目自己在同类问题上更谨慎：`httpclient/outbound.go:288-292` 的 `NoCrossHostRedirects` 故意只留
  host（注释明说「this error is logged, and a URL on the wire here can carry a code or a token」）。
- 状态：CONFIRMED（离线进程内；错误形状由 Go 标准库决定）
- 影响：今天 `auth.go:669-673` 把该错误丢掉、只回一个有界 `code`，所以**尚未**落日志；但活的上游 token
  已住进一个 `error` 值（连同堆里的字符串），离 `slog.Error("…","err",err)` 只差一行调用方代码，
  而本项目在失败路径上正是这么做的（`bind.go:208-211`、`unbind.go:124`）。
- 探针：`qqurl_test.go::TestZ19QQUserInfoCarriesTheAccessTokenInTheURLError`（红；GitHub 头传递为对照）
- 修法建议：QQ 的旧式 API 必须收查询参数，无法避免；把**回显**管住即可——`getText` 包装错误时剥掉查询串
  （与 `NoCrossHostRedirects` 同一纪律），或在源头用一个不回显 URL 的 `Transport` 错误。
- 是否与既有编号相关：无。第五轮 P2-14 是脚本侧 DSN 进 argv；本条是出站请求 URL 里的上游 token。

### Z19-3 `vault.Use` 的四条失败路径把自己的审计写入丢掉（`_ =`），而同一 sink 上的成功路径是 fail-closed

- 严重度：P3 低/提示
- 类别：安全（可观测性/审计完整性）
- 不变量：fail-closed（I3 的邻域）| 凭据封存
- 证据：`vault/service.go:247-252`（repo 失败/未找到）、`:269-271`（凭据被未配置的 KEK 包着）、
  `:278-280`（unwrap 失败）、`:288-290`（解密失败）全部 `_ = s.record(…)`；而成功路径在
  `:296-303` 是 fail-closed（I3，注释明说「If the audit log is unavailable we fail closed rather than
  proceed unaudited」）。进程内复现（已执行，FAIL；对照组是同一 sink 上的成功路径确实拒绝）：
  ```
  control (success path, sink down): vault: audit: z19 probe: audit sink unreachable
  CONFIRMED: vault.Use on a missing credential returned vault: credential not found and recorded nothing
  DISCLOSURE: vault.Use detected a credential wrapped by an unconfigured key, returned
    vault: taptap:usr_orphan was wrapped by key "kek-that-was-deleted", … and dropped its
    `vault.use/error` audit event because the write failed and the error was discarded (vault/service.go:269)
  ```
- 状态：CONFIRMED（进程内，外部包用真 `vault.NewService`+`MemoryRepo`）
- 影响：「这条记录被一个本部署已经没有的 KEK 包着」正是运维删完退役键后最需要看到的信号，也正是
  `-rotate-keys` 的门槛想防的事；审计 sink 抖动与它撞在一起时这条记录静默消失。成功路径同 sink 会拒绝
  放行，所以这是**不对称**而非成文策略。该错误文本自身也带原始 `usr_`（G-21 已录，不重报）。
- 探针：`vaultaudit_test.go::TestZ19VaultUseFailurePathsDropTheirAuditRecord`（红）
- 修法建议：与 `Enroll`/`Revoke`/成功 `Use` 同一纪律：`record` 失败即 `errors.Join(err, aerr)`
  （**不能只回审计错误**——调用方依赖 `errors.Is(err, vault.ErrNotFound)`）。
- 是否与既有编号相关：**对第六轮 03-2（G-19 家族：`Rotate` 的审计写入被 `_ =` 丢掉）的补充**——
  同一条纪律缺口在同一个包的热路径上还有四个站点；那条只点了 `Rotate`（运维动作），这四条在数据面上。

### Z19-4 `-rotate-keys` 可以用「同料不同 id」的新 KEK 报出一次成功的轮换，而被判退役的那把钥匙仍然能开每一个记录

- 严重度：P2 中（**失败是静默的**：命令打印 `rewrapped=N` 并 exit 0，运维据此删除退役键）
- 类别：安全
- 不变量：凭据封存 | 撤销生效（泄露 KEK 的唯一补救是轮换）
- 证据：`vault/service.go:112-130` 的 `WithRetiredKeys` 只比较 **id**（`:119-122` 与当前 `KeyID()` 相同才拒），
  **从不比较密钥材料**。于是 `vault.retired[0].kek_id = "kek-2"` 指向与当前 KEK **同样的 32 字节**时：
  轮换把 `kek_id` 列从 `kek-1` 改成 `kek-2`、`wrapped_dek` 用同一材料重新包一遍、报告
  `{Scanned:1 Rewrapped:1 AlreadyCurrent:0 Skipped:0}`。进程内复现（已执行，FAIL；对照组换成不同材料后
  退役键确实打不开）：
  ```
  control (distinct material): the retired key cannot open the re-wrapped DEK
  DISCLOSURE: rewrapped=1 … while the retired key STILL unwraps every re-wrapped record, because the
    "new" KEK is the same 32 bytes under a different id (rotation={Scanned:1 Rewrapped:1 AlreadyCurrent:0 Skipped:0})
  ```
  命令面是读码即可断定：`cmd/re0auth/main.go:1209-1230` 在 `Skipped==0` 时返回 `incomplete=false`，
  `rotateAndReport`（`:1181-1192`）因此只 `slog.Info` 并返回 nil ⇒ exit 0，且会打印那句
  「run until rewrapped=0 skipped=0, then remove the retired key」（`:1226-1229`）。
- 状态：CONFIRMED（进程内，`vault` 真实现；"exit 0" 那半为源级确定性，见上）
- 影响：`docs/threat-model.md` §6.0 把轮换当作 KEK 泄露的唯一补救（「rotation is what stops a leaked key
  from applying to what is written afterwards」）。运维以为补救完成、把退役键删出配置，而**保护整个 vault
  的仍是泄露的那串字节**。前提是一次配置错误（同一值配进两个 `kek_env`），与 G-22 同类，但后果重得多且无信号。
- 探针：`keyreuse_test.go::TestZ19RotationAwayFromReusedKeyMaterialIsSilent`（红）
- 修法建议：`WithRetiredKeys` 在 id 检查之外加材料同一性检查——给 `KeyWrapper` 加
  `Fingerprint() [32]byte`（如 `HMAC-SHA256(domain, kekBytes)`，不暴露 KEK），启动时两两比对并拒绝启动。
- 是否与既有编号相关：**对第六轮 G-22（三把 32 字节密钥可共用同一个值、无提示）的补充/加强**。
  G-22 说的是 KEK/OP token key/audit key 三角色的复用，后果是「一次泄露=全部角色」；本条是**轮换语义内**的
  复用，后果是「安全补救静默无效」。若主代理判定为重复，请按 G-22 的加强条目合并，不要单列。

---

## 探过但没破的（也应变成守卫）

1. **真进程凭据全量日志围栏**（`apilog_test.go::TestZ19CredentialBatteryDoesNotReachTheProcessLog`，GREEN）：
   内存模式真服上打 7 类请求（code/refresh/introspect/revoke/device poll/带 Bearer 的 `/v1/me`/坏 client 的
   authorize），种下 9 个可识别值（KEK、OP token key、签名键、client secret、被呈上的 code/refresh/bearer/
   device_code/state），**3482 字节日志里一个都没有**。
2. **第三方库走进程默认 slog 的通道已由既有守卫钉住**：
   `internal/oidchttp/adversary_test.go::TestAdversarialProtocolErrorsDoNotLogCredentials`（tracked，
   本轮实跑 GREEN）钉住 `pkg/op/error.go` 的 `oidc_error` 与 `pkg/oidc/authorization.go` 的 `LogValue`
   （只记 scope/response_type/client_id/redirect_uri，不记 code_challenge/state）。未重复造。
3. **metrics label 有界**（读码 + 既有测试）：`game`/`source` 只在 `federation/service.go:416`
   `candidates()` 过了 `registry.Sources(game)` 之后才进 `ObserveUpstreamFetch`；`provider` 是配置名或字面
   `"unknown"`（`auth.go:571/622`）；`grant_type`/`error`/`method` 在 `observability.go:502-536` 归一化。
4. **`-print-secret-env` 只打印角色+变量名**（`cmd/re0auth/config.go:412-442`）：不解析、不回显值；
   `scripts/backup-keys.sh:57-60` 也只取名字，值写进 0600 文件（`umask 077`，`:72`）。
5. **`vault` 的错误文本不泄漏密文/明文材料**：`vault/repo.go:29` 的 `Identity.String()` 只带
   provider+subject（`usr_` 见 Z19-3 末注，属 G-21）；`internal/store/postgres/vault.go` 的 `%w` 包装只带
   pg 错误（pgx v5.11 的 `PgError.Error()` 只含 message+SQLSTATE，不含参数）。顺带：pgx v5.11 的
   `ParseConfigError.Error()` 经 `redactPW` 脱敏，区 12 的 DSN 条目在本版本上实际泄漏面比想象的窄。

## 未能到达

1. **真实 Postgres 运行时**：本机无 Docker/无本地库。Z19-3 的生产形态（审计链写失败而队列写仍成功）与
   Z19-4 的命令面（需库里先有 `kek-1` 包的记录，内存模式重启即丢）只有进程内/源级证据；标 CONFIRMED
   是因为结论不依赖库：`_ = s.record` 与「只比 id 不比材料」都是源级确定的。
2. **多实例/多进程交错**：k8s Secret 两个 key 同值的真实部署不可达；只在进程内建模了同一序列。
3. **`-rotate-keys` 在真库上的退出码**：需要 seeded vault；源级推导见 Z19-4（`incomplete==false` 分支确定成立）。
4. **KEK/token key/audit key/per-subject key 的内存驻留与零化**：`vault.Scrub` 只覆盖 DEK 与明文；
   `settings.KEK`/`RetiredKEKs[].KEK`/`cfg.AuditKey`/`oidcTokenKey` 解出的 `[]byte`、每 subject key、
   以及 `aes.NewCipher` 的密钥调度都不被擦除。Go 无稳定的「内存是否仍含该字节」观测，无法用探针证明；
   威胁模型 §6.0 与 `scrub.go:5-12` 已把它写成 best effort + memguard 才是强保证，按简报第 5 节记在「判断」。
5. **`/debug/pprof/heap` 里的 KEK**：内部面 + `expose_internal` 已是文档化运营面，不重复。

## 判断（不是 finding）

- 「配置文件只写变量名」这条约定值得配一条**机器强制的名字形状校验**：它同时解决 Z19-1、让
  `-print-secret-env` 的输入可信，并让「值粘错位置」在配置阶段而不是日志里被发现。
- **内存零化**：`Scrub` 的 best-effort 边界是诚实且正确的取舍（`scrub.go:21-25` 记了「三份复制、其中一份
  少了 KeepAlive」的历史）。要更强只有 memguard 从头接管分配，本项目规模不值得。
- **QQ 的查询串**：QQ Connect 旧式 API 就这么设计，改协议不可能；建议只收「错误回显」这一半。
