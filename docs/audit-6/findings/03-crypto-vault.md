# 区域 03 密码学：vault 信封加密 / KEK / 轮换 / 密钥生命周期 —— 第六轮审计报告

## 执行摘要

- **发现 5 条，全部 P3（低/提示级），无 P0/P1/P2**；每条都有会失败的探针（CONFIRMED）。
- 一句话结论：**第五轮在这个区域打掉的主要面（AAD 绑定、nonce、kek_id 选择、轮换 lost-update、
  zeroization、fail-closed）在当前 HEAD 上全部守住**——P1-1/P1-2 的 CAS 修复经本轮新写的回归探针
  （并发入册存活 + 收敛闸门 + 真进程命令面）验证为**修对、修全**；剩下的是修复边上没收干净的缝：
  轮换自己的审计写入失败被丢弃（03-2）、Enroll 的「先落库后审计」在绑定路径上留下孤儿密钥（03-3）、
  vault 身份命名空间有歧义（03-1）、vault 错误文本把 `usr_…` 送进进程日志的一个第五轮守卫看不见的通道（03-4）、
  三把密钥共用同一 32 字节不被提示（03-5）。
- 第五轮仍红的 `TestProbeNoSlogCallCarriesAnAccountIdentifier`（日志带账号标识）**确认仍红、机制未变**，
  归属建议 observability 区（k1/k6 的 7 处 attr 站点）；我区域补充的是**错误文本通道**（03-4），
  那是 attr 守卫结构上看不到的另一半。
- 探针：`internal/zzprobe/audit6/z03crypto/`（18 个测试，5 红 13 绿，`-race` 下同样结果、无 DATA RACE）。
  运行：`go test -tags audit6 -count=1 ./internal/zzprobe/audit6/z03crypto/...`

**范围与读码**：`vault/` 全部 12 个文件（envelope/repo/service/rotate/scrub + 全部测试，含 audit5 探针）；
`internal/core/`（key/context/app/component/scope/errors/doc + 测试）；`internal/wiring/`（core 的唯一使用方，
不在生产路径）；`cmd/re0auth/` 的 `loadConfig`/`openVault`/`rotateAndReport`/`rotationReport`/OIDC 三把密钥装载；
`internal/oidcstore/`（Signer/ValidateSigner/RandomValue）；`internal/oidchttp` 的 CompositeCrypto 接线；
`internal/federation/` 的 binding/refresh/unbind/killswitch（vault 的全部生产调用方）；
`internal/store/postgres/vault.go`（RewrapIfUnchanged 的 CAS）；`audit/`（Logger 契约）；
`internal/store/postgres/auditbatch.go`（I3 的落库语义）。跑过：本区探针（15）、`go test ./vault/`、
`go test -run TestRotationReport ./cmd/re0auth/`、`go test -tags audit5 ./internal/zzprobe/crypto/...`（确认仍红项）、
`go build ./...`、`go vet ./...`（全仓，均 exit 0）。

---

## 发现

### 03-1 vault 身份命名空间有歧义：`game + "." + source` 无字符校验，两个不同的 (game, source) 共享同一凭据行——跨源令牌串用、一方的解绑把另一方的密钥撕掉

- 严重度：P3 低/提示（若部署真用带点命名，后果按 P2 计；触发需要运营者配置出撞名的一对源）
- 不变量：凭据封存 | 账号隔离
- 证据：`internal/federation/binding.go:76-78`——`BindingIdentity(b) = vault.Identity{Subject: b.User,
  Provider: b.Game + "." + b.Source}`。`federation.NewRegistry`（`federation.go:141-191`）对 name 只查
  非空与 `sourceKey`（`game + "/" + name`，`federation.go:147-149`）去重——**"/" 拼接有撞名检查，
  "." 拼接没有**。`cmd/re0auth/loadSources` 也不做字符集校验。于是
  `{game:"phigros", source:"official.beta"}` 与 `{game:"phigros.official", source:"beta"}`
  都被注册表接受，却映射到**同一个** vault 身份 `{usr_…, "phigros.official.beta"}`。
  真实绑定流程复现（`internal/zzprobe/audit6/z03crypto/binding_namespace_test.go::TestProbeBindingProviderNamespaceCollides`，
  已执行，FAIL）：
  ```
  CONFIRMED: the credential of (phigros, official.beta) reads "token-for-cid-B" — the token bound
  to the OTHER source is served under this binding: two distinct sources share one vault row
  CONFIRMED: after unbinding (phigros.official, beta) the credential of (phigros, official.beta)
  no longer opens (exists=false, <nil>): one source's unbind crypto-shredded another source's
  credential — they share one vault row
  ```
  对照组在同测试里：注册表**拒绝** "/" 拼接的撞名（`{a/b, c}` vs `{a, b/c}` → duplicate source），
  不撞名的两个绑定各自持有各自的令牌。
- 状态：CONFIRMED
- 影响：后绑的源覆盖先绑的源的凭据；此后**所有经绑定 A 的读取拿的是源 B 的上游令牌**（按
  `withAccessToken` 的路径，该令牌被呈给源 A 的端点——对 A 背后的运营方构成跨源令牌泄露）；
  任一方的 Unbind/注销都会把另一方仍在用的密钥 crypto-shred 掉（`unbind.go:91` 对共享身份 `Revoke`）。
  由于 `replicas: 2` 场景下这表现为"随机哪个绑定成功取决于写入顺序"，排查代价高。
  需要 operator 配置出带点的名字对才触发——协议文档的示例命名（`phigros` / `next-phi`）不含点，
  但**没有任何东西禁止**，且威胁模型自己把 provider 写成 `phigros.taptap` 形状（`docs/threat-model.md:167`）。
- 探针：`binding_namespace_test.go::TestProbeBindingProviderNamespaceCollides`
- 修法建议：在 `NewRegistry` 校验 `Game`/`Name` 的字符集（排除 `.` 与 `/`，或与 sourceKey 的分隔符对齐），
  让撞名在启动期 fail-closed——注册表已经为 "/" 拼接做了同类去重，补上 "." 这一半即可；
  注意**不能**直接改 `BindingIdentity` 的拼接符（AAD 绑定存量密文，改动等于作废全部凭据）。

### 03-2 `Rotate` 把自己的审计写入失败扔掉（`_ =`），而 P1-1 修复新加的注释恰恰说这条 trail 是运维删退役键前要看的

- 严重度：P3 低/提示
- 不变量：fail-closed | 撤销生效（删退役键的闸门依赖审计 trail）
- 证据：`vault/rotate.go:78-91`——修复引入 `outcome = error (skipped>0)` 的同一行块里，写事件仍是
  `_ = s.record(ctx, audit.Event{Action: "vault.rotate_keys", …})`（`:82`）。而 `:76-78` 的注释写着
  「**that trail is what an operator consults before deleting the retired key**」。同一个 sink 让
  `Enroll`/`Use`/`Revoke` 全部 fail-closed（`service.go:223-231`、`:298-303`、`:323-328`），
  唯独 Rotate 静默。探针（已执行，FAIL）：
  ```
  a rotation whose audit write failed reported success: {Scanned:1 Rewrapped:1 AlreadyCurrent:0 Skipped:0};
  the same sink makes Enroll/Use/Revoke fail closed, and the rotate_keys trail is what an operator
  consults before deleting the retired key
  ```
  （`rotation_test.go::TestProbeRotationAuditFailureIsSwallowed`：审计 sink 全程不可写，轮换照常完成、
  返回 nil 错误、Rewrapped=1。）
- 状态：CONFIRMED
- 影响：审计链故障期间（postgres 模式下 batch 超时/链头行锁竞争——`vault_credentials` 写入仍可成功）
  跑的每一次 `-rotate-keys` 都是 exit 0、无审计行、无日志。命令输出仍然真实（这是它没到 P2 的原因），
  但「查审计确认轮换完成再删键」的运维路径（runbooks 依赖）会看到**什么都不存在**——与「轮换从未跑过」
  无法区分。与第五轮 P2-1（OP store 吞审计）同类，但触发面窄（运维动作、非热路径）。
- 探针：`rotation_test.go::TestProbeRotationAuditFailureIsSwallowed`
- 修法建议：把 `Rotate` 的最终审计事件改为与 Enroll/Use/Revoke 同一纪律（返回错误，让
  `rotateAndReport` 以非零退出报告「轮换发生了但未被记录」；轮换幂等，重跑无害）；至少 `slog.Error`
  ——注意 vault 是库，回 `err` 更符合它自己的 I3 姿态。

### 03-3 `Enroll` 先落库后写审计：审计写失败时凭据已存好、调用方却被告知失败——绑定路径既不回滚也不记日志，留下一个只有账号抹除能清的可解密上游令牌

- 严重度：P3 低/提示
- 不变量：凭据封存 | fail-closed（半成功语义）
- 证据：`vault/service.go:209-231`——`repo.Put`（凭据已持久化）在前，`s.record`（审计）在后，
  失败即 `return err`。`internal/federation/bind.go:191-196`：`storeBindingSecret` 出错直接
  `return Binding{}, flow, err`——**没有回滚、没有日志**；对照**同一条路径的兄弟分支**
  （`bind.go:198-213`，`bindings.Put` 失败）：显式尝试 `s.vault.Revoke` 回滚、失败则
  `slog.ErrorContext("could not roll back a bind's vault secret; a secret is left with no binding")`
  并 `errors.Join`。真实绑定流程复现（已执行，FAIL）：
  ```
  CONFIRMED: the bind reported failure (vault: audit: probe: audit sink unreachable) yet stored a
  decryptable upstream token ("token-for-cid-A") that no binding row points at and only an account
  erasure clears; the sibling failure path rolls the secret back and joins the residue into the
  error, this path does neither. Operator log at the time: ""
  ```
  （`binding_namespace_test.go::TestProbeBindAuditFailureStrandsTheUpstreamToken`；对照组：同一夹具换
  可用审计 sink 时绑定成功。）
- 状态：CONFIRMED
- 影响：审计 sink 故障窗口内的**每一次绑定尝试**都会留下这种孤儿（触发面比第五轮 FO-02 的跨实例
  微秒窗口宽得多：审计链故障以秒计）；用户看到绑定失败，重试会自愈（`Put` 整行替换），但放弃重试的
  那条上游令牌只有 `lifecycle` 的 `vault.DeleteSubject` 能清——正是 `bind.go:199-207` 注释自己
  称为 defect 的残留类。另注：`refresh.go:122-127` 的注释对这一支的自评（"secret was not stored"）
  在审计失败时不成立（密钥已存、行已更新，配对其实一致），该支实际无害，仅注释不准确。
- 探针：`binding_namespace_test.go::TestProbeBindAuditFailureStrandsTheUpstreamToken`
- 修法建议：与兄弟分支对齐——`CompleteBind` 在 `storeBindingSecret` 失败时尝试 `vault.Revoke` 回滚、
  失败则 slog + `errors.Join`（复用 `bind.go:198-213` 的现成形状）；或在 vault 层给 Enroll 提供
  「审计失败即撕掉刚写的行」的补偿。

### 03-4 vault 的错误字符串内嵌原始 `usr_…`（`Identity.String()`），经 `-rotate-keys` 的 die 路径与 unbind/cascade 的 warn 路径进进程日志——第五轮 attr 守卫看不见的通道

- 严重度：P3 低/提示
- 不变量：账号隔离（隐私：`usr_…` 与假名化的审计行去关联后的日志残留）
- 证据：`vault/repo.go:29`——`Identity.String() = Provider + ":" + Subject`。`vault/service.go:273-274`
  的 Use 错误与 `vault/rotate.go:113-116/126-127/131` 的轮换错误都用 `%s`/`%v` 渲染
  `Identity`/`rec.Identity`。这些文本进进程日志的现成路径：`cmd/re0auth/main.go:304`
  （`die("rotate keys", err)` → `slog.Error("cannot start", "stage", …, "err", failure.err)`）、
  `internal/federation/unbind.go:124`（`slog.Warn("upstream revocation could not open the binding
  secret", …, "err", err)`）、`internal/httpapi/binding_routes.go:236`（cascade 失败 warn 带 err）。
  探针（已执行，FAIL，两条断言都红）：
  ```
  a vault Use error string carries the raw account id ("vault: taptap:usr_victim was wrapped by
  key \"kek-1\", which is not configured; declare it as a retired key …")
  a vault rotation error string carries the raw account id ("vault: rotate: taptap:usr_victim was
  wrapped by key \"kek-1\", …"); -rotate-keys logs this text verbatim on its failure path
  ```
  第五轮的静态守卫（`source_log_guard_test.go`）只匹配 **slog attr 的 key**（`user=`/`subject=`），
  结构上覆盖不到错误文本通道。
- 状态：CONFIRMED
- 影响：与第五轮 k1/k6 同一不变量（原始 `usr_…` 落进保留期更长的进程日志，假名密钥销毁够不到），
  但机制不同：这里不需要任何 attr——只要运维跑一次碰到未配置 KEK 的 `-rotate-keys`，或一次
  unbind/cascade 打不开密钥，`usr_…` 就整段进日志。可达性均为错误路径。
- 探针：`use_aad_test.go::TestProbeVaultErrorsCarryTheRawSubject`
- 修法建议：vault 的错误里用形状代替身份（如 `provider:usr_…` 截成 `provider:<subject-len>`，
  或只报 provider + kek_id——运维定位行需要的其实只有这两个）；与 k1/k6 的 7 处 attr 站点
  一起归 observability 收口。

### 03-5 三把 32 字节密钥可以共用同一个值：`RE0AUTH_KEK == RE0AUTH_OIDC_TOKEN_KEY`（乃至 `RE0AUTH_AUDIT_KEY`）被无提示接受

- 严重度：P3 低/提示
- 不变量：凭据封存（密钥分离）
- 证据：`cmd/re0auth/config.go:719-751`（KEK）与 `cmd/re0auth/main.go:1385-1397`（token key）各自
  只校验长度/格式，互不比较。真进程复现（已执行，FAIL）：
  ```
  CONFIRMED: the server serves with RE0AUTH_KEK and RE0AUTH_OIDC_TOKEN_KEY set to the same 32 bytes,
  and the startup log says nothing about the reuse. One compromise of that value is then
  simultaneously the vault's KEK leak and the opaque-token encryption key leak; the log: …
  ```
  （`process_test.go::TestProbeKeyMaterialSharedAcrossRolesIsAccepted`：KEK 与 token key 同值启动并
  serving，启动日志对复用只字未提。）
- 状态：CONFIRMED
- 影响：纯卫生——HMAC（audit key）与 AES-GCM（KEK/token key）之间没有已知代数关联，跨用途复用
  不构成具体攻击；危害是把「一次泄露 = 一个角色」放大成「一次泄露 = 全部三个角色」，且没有任何
  信号告诉运维自己配错了。文档（config 样例 :190/:213/:200）各自生成，但没有强制。
- 探针：`process_test.go::TestProbeKeyMaterialSharedAcrossRolesIsAccepted`
- 修法建议：`loadConfig` 解析完三把密钥后做两两比较，相同即拒绝启动（与「kek_id 不许复用」同一
  纪律；或至少 Warn）。

---

## 第五轮修复的回归验证（本轮核心工作之一）

### P1-1 / P1-2（1076cbf，轮换窄写/CAS）——修对、修全

- **窄写**：`RewrapIfUnchanged`（`vault/repo.go:85-104` 接口 + `internal/store/postgres/vault.go:110-120`
  `UPDATE … SET wrapped_dek, kek_id, updated_at WHERE … AND wrapped_dek = $3`）只动信封三列。
  本轮新探针 `rotation_test.go::TestProbeRotationRewritesOnlyTheEnvelope`（GREEN）断言
  Nonce/Ciphertext/Meta 逐字节不变、WrappedDEK 变、KEKID 换新。
- **并发入册存活 + Skipped 语义**：`rotation_test.go::TestProbeRotationCASSurvivesAConcurrentEnroll`
  （GREEN）——在 CAS 窗口内注入一次并发 Enroll：本轮报 `{Scanned:1 Rewrapped:0 Skipped:1}`，
  新凭据存活可读，**重跑收敛到 `rewrapped=0 skipped=0 AlreadyCurrent=1`**。第五轮 k2 的静默回滚
  不复存在。
- **命令面**（真进程，`process_test.go::TestProbeRotateKeysReportsTheGateOnAnEmptyVault`，GREEN）：
  `-rotate-keys` 在空库上 exit 0，输出含 `scanned=0 rewrapped=0`、**无条件**的门槛句
  `rewrapped=0 skipped=0` 与 `retired KEKs are configured` 警告。`skipped>0` ⇒ 非零退出由
  `cmd/re0auth/rotation_report_test.go`（既有测试）与本轮真进程探针共同覆盖。
- **文档三步改四步**：`README.md:45-69`、`config/re0auth.example.toml:228-247` 均写明第 3 步门槛
  「跑到 rewrapped=0 skipped=0 且退出码 0」并解释两条原因。✓
- **没修全的残余**（第五轮 k3/k4，均已收录，不重报，仅记录仍在）：
  - k3 的「轮换中途出错时一条审计都不写」（`rotate.go:52-54/66-68` 直接 return，不落
    `vault.rotate_keys`）**仍在**；本轮 03-2 是它的邻缝（成功路径的审计写失败被丢）。
  - k4 的「config 层不去重 retired kek_id」仍在（`config.go:756-775` 只查空与撞当前 id；
    库侧 `WithRetiredKeys` 会拒，报错带 id 但不带 `vault.retired[N]` 位置）。

### P2-32（bf81b2a，设备时钟）——修对（读码级 + 既有测试）

- `internal/store/postgres/oidc.go` 三条设备 SQL（poll 的 `last_poll` 写与谓词、`ApproveDevice` 的
  `expires_at` 谓词与 `auth_time` 戳）已全改 `$n` 参数 ← `s.now()`；reviewed `now()` 清单 3→1
  （剩 `COALESCE(auth_time, now())` 展示性回退，按原裁定保留）。`clock_test.go` 新增设备三段守卫
  （CI 的 postgres:16 权威）。vault 不在此路径；与本区交叉的结论：**没有引入新洞**。
  运行时语义（真实库上 `$n` 与索引的行为）本机不可达，见「未能到达」。

### 5cd1690（审计与抹除链路收口）涉及 vault 的部分——修对

- **P2-3**：`auth.Manager.EndSession`（`auth.go:210-217`，销毁会话、不写 `auth.logout`）；
  抹除路径改用它（`account_routes.go:75-81`），注释明确说明「auth.logout 会带 raw usr_ 让 sink
  重铸钥匙」。lifecycle 的顺序（先写 `account.delete` 记录、后销毁假名钥匙，
  `lifecycle.go:262-283`）与 `Detail` 不含账号 id（`:295-316`）均成立。✓
- **P2-1**：OP 两 store 的审计失败改为 `slog.Error`（不带 subject）；vault 维持 fail-closed
  （本轮 `use_aad_test.go::TestProbeUseFailsClosedWhenTheAuditSinkIsDown`，GREEN，外部包复验 I3）。
  audit batcher 的 enqueue/close 窗口与 30s drain 预算（`auditbatch.go:109-154/170-198`）读码确认在位。
- **P2-22**：export/admin-audit 读操作各留一条审计（`audit_routes.go`/`export_routes.go`，
  Subject 记发起者）——属 admin 区，本轮只确认其不与 vault 的 I3 冲突（不冲突）。

### 第五轮仍红探针的归属确认（主代理点名项）

`internal/zzprobe/crypto/source_log_guard_test.go::TestProbeNoSlogCallCarriesAnAccountIdentifier`
本轮实跑仍 FAIL，7 处与第五轮完全一致（行号随修复漂移）：

```
internal/admin/admin.go:499           attr subject=subject      <- 审计写失败时；合法 admin 请求可达
internal/auth/auth.go:231             attr subject=e.Subject     <- 登录/登出审计写失败
internal/federation/bind.go:208       attr user=string(...)      <- 绑定回滚失败
internal/federation/refresh.go:155    attr user=string(...)      <- 拒绝路径撕密钥失败
internal/federation/refresh.go:160    attr user=string(...)      <- 拒绝路径删行失败
internal/httpapi/account_routes.go:80  attr user=string(...)      <- 抹除后会话清理失败（k1 主现场）
internal/httpapi/binding_routes.go:57 attr user=string(...)      <- 列绑定失败
```

- **机制**：全部是 `slog` **attr 形式**的 `usr_…` 进进程日志；除 `admin.go:499`（合法运维请求 + 审计
  sink 故障）与 `account_routes.go:80`（抹除后的会话清理故障）外都在错误路径。
- **影响**：假名密钥销毁（`auditpseudo.go:Destroy`）够不到进程日志；`docs/threat-model.md:256`
  「除本服务外无人持久化 usr_ 与自然人身份的对应」被本服务自己的日志持续推翻。
- **归属建议**：observability 区（这是日志卫生/隐私收口，不是密码学缺陷；修法是统一改记形状，
  如 k1 修法建议的 `"self", bool` / 只记 action）。注意该条在 `AUDIT-ISSUES.md` 的 P0–P3 表里
  **没有**单列编号（k1/k6 未被收进汇总表），本轮从 crypto 角度确认它仍真实存在。
- **crypto 区的补充**：即便修掉这 7 处 attr，**错误文本通道**（本轮 03-4）仍然敞开——
  守卫本身（AST 只匹配 attr key、跳过 `_test.go`）结构上到不了它。两半要一起收。

---

## 探过没破（攻击过但守住的，含探针名）

全部为本轮实跑、GREEN（`go test -tags audit6 -count=1 ./internal/zzprobe/audit6/z03crypto/...`）：

1. **并发入册 vs 轮换交错**（`TestProbeRotationCASSurvivesAConcurrentEnroll`）：CAS 窗口内的并发
   Enroll 存活、Skipped 计数、重跑收敛——P1-1/P1-2 修复成立。
2. **轮换只动信封**（`TestProbeRotationRewritesOnlyTheEnvelope`）：Nonce/Ciphertext/Meta 逐字节不变。
3. **AAD 双层绑定身份**（`TestProbeAADRejectsRowTransplants`，外部包重做第五轮的换行测试）：
   DEK 信封与载荷密文各自绑定 (subject, provider)，三个方向的搬运全部解不开。
4. **`vault.Use` 不跨锁回调**（`TestProbeUseCallbackRunsNoVaultLockHeld`）：在 Use 的明文窗口内重入
   repo（Get/Put/List/Exists/RewrapIfUnchanged，含同身份的 CAS）全部完成、10 秒无死锁——
   MemoryRepo 的锁在 Get 返回前释放，新代码（refresh 的 keyed lock 在 vault 调用**之外**）未破坏该不变量。
5. **nonce 新鲜度**（`TestProbeNoncesAreFreshThroughTheRealPath`）：同一明文同一密钥 128 次入册，
   KEK 层与载荷层 nonce 均无重复（每记录独立 DEK，生日界内随机 nonce 安全）。
6. **I2 零化**（`TestProbeUseZeroizesWhatItHandedOut`）：Use 返回后回调拿到的 slice 逐字节为 0。
7. **I3 fail-closed**（`TestProbeUseFailsClosedWhenTheAuditSinkIsDown`）：审计 sink 不可用 ⇒
   fn 不被调用、错误返回。
8. **KEK 解析的接受面**（`TestProbeKEKEncodingVariantsEachStartTheServer`，真进程）：padded base64、
   raw base64（43 字符）、hex（64 字符）全部起服务——第五轮修的「hex 分支是死代码」没有回归。
9. **KEK 解析的拒绝面**（`TestProbeKEKMalformedValuesRefuseStartup`，真进程）：尾随空格、
   URL-safe base64、31 字节全部 exit 1 且报错点名 KEK。
10. **尾随换行被容忍且同一材料**（`TestProbeKEKTrailingNewlineIsTolerated`，真进程）：Go 的
    `base64.DecodeString` 忽略 `\r`/`\n`，CI secret 带尾换行不是坑（解码后的材料与无换行时相同）。
11. **启动日志不回显密钥材料**（`TestProbeStartupLogDoesNotEchoKeyMaterial`，真进程）：KEK、
    token key、签名密钥三个值都不出现在 serving 进程的完整日志里。
12. **`-rotate-keys` 空库收敛语义**（`TestProbeRotateKeysReportsTheGateOnAnEmptyVault`，真进程）：
    exit 0 + 门槛句 + retired 警告，见回归验证节。
13. **retired 与当前 kek_id 冲突拒绝启动**（`TestProbeRotateKeysRefusesARetiredKeySharingTheCurrentID`，
    真进程）：`is the current key's id`，fail-closed。
14. **kek_id 只在启动构造的 map 里选**（读码 + 第五轮 `kekid_test.go` 本轮实跑 GREEN）：
    `""`/未知 id/大小写变体全部 `not configured`，能写库者无法指向自控密钥。
15. **密钥不经子进程继承**（grep 级）：生产代码零 `exec.Command`（仅 archtest 与探针），
    无子进程可继承 `RE0AUTH_KEK`。
16. **`-race`**：本区全部探针在 `-race` 下重跑，除 5 条发现外无 DATA RACE。

## 未能到达（本轮环境到不了的）

1. **Postgres 运行时语义**：`RewrapIfUnchanged` 的 bytea 比较在真实并发下的行为、ListPage 游标与
   库排序（collation）在非 ASCII 主体上的交错、以及触发 03-2/03-3 生产形态所需的「审计链写失败而
   `vault_credentials` 写入仍成功」的分叉——本机无 Docker/无本地库，全部只有读码级证据；
   CI 的 postgres:16 是权威（`clock_test.go` 的设备三段同理）。
2. **多实例真实交错**：P1-1 的「旧键 pod 在写、新键 pod 在转」需要两个进程共享一个库；本轮只在
   进程内用 hookRepo 建模了同一交错。
3. **KMS-backed KeyWrapper**：接口存在（`KeyWrapper`），仓库内无实现，无从探测。
4. **Linux 部署面上的 env 泄漏**：`/proc/self/environ` 等对 `RE0AUTH_KEK` 的可见性属部署面
   （k8s Secret 注入），本机不可达；已确认本进程自身不 spawn 子进程。
5. **audit key == KEK 的同值复用**（03-5 的第三对）：内存模式不要求 audit key，真进程探针只覆盖了
   KEK == token key；audit key 的同值比较留给 postgres 部署验证（机制与已证的两把相同）。
