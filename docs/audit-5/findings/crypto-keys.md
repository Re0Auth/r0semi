# 密码学正确性与密钥生命周期 审计报告

## 范围与方法

**读全的文件**：`vault/envelope.go`、`vault/service.go`、`vault/repo.go`、`vault/rotate.go`、`vault/scrub.go`（+ 全部测试）；
`tapsign/client.go`（含 `Verify`/`Rotate`/`Revoke`）；`taptapoauth/client.go`（MAC 签名）与 `tapsign/credential.go`；
`internal/oidcstore/oidcstore.go`；`internal/oidchttp/oidchttp.go`；`internal/store/postgres/auditchain.go`、`audit.go`、
`auditpseudo.go`、`auditbatch.go`、`vault.go`、`sessions.go`、`migrations/0007_audit.sql`、`0013_audit_chain.sql`、`0014_audit_pseudonyms.sql`；
`audit/audit.go`；`internal/config/config.go`；`cmd/re0auth/config.go`、`cmd/re0auth/main.go`（密钥装载、轮转、OP 装配）；
`internal/auth/auth.go`；`oauth/as.go`、`oauth/client.go`、`oauth/tokens.go`、`oauth/device.go`、`oauth/http.go`；
`internal/ratelimit/ratelimit.go`；`internal/httpapi/middleware.go`、`device_routes.go`、`account_routes.go`、`binding_routes.go`、
`admin_routes.go`、`server.go`；`internal/observability/observability.go`；`httpclient/outbound.go`、`retry.go`；`internal/federation/binding.go`。
第三方读：`zitadel/oidc v3.51.3` 的 `pkg/op/crypto.go`、`pkg/op/device.go`、`pkg/crypto/crypto.go`；`alexedwards/scs@v1.4.1` 的 `session.go`。

**跑过的命令**（全部实际执行）：

```sh
go build ./vault/... ./tapsign/... ./internal/oidcstore/... ./internal/store/postgres/... ./oauth/... ./taptapoauth/...   # EXIT=0
go vet  ./vault/ ./internal/zzprobe/crypto/                                                                              # EXIT=0
go test ./vault/ -count=1                                                # ok（含新增探针）
go test ./internal/store/postgres/ -count=1                              # ok（含新增探针，纯函数层，无需 DB）
go test ./oauth/ ./internal/oidcstore/ -count=1                          # ok
go test ./internal/zzprobe/crypto/ -count=1 -v                           # 2 条 FAIL，见 k1/k6（这就是发现本身）
```

**跑不了的**：

- `go build ./...` 与 `go build ./internal/auth/...`（后者经由 `cmd/re0auth` 依赖 `internal/httpapi`）**当前不可用**，
  原因不在本次范围：工作树里另一个代理留下的 `internal/httpapi/zzprobe_adminpriv_test.go:3:30: illegal UTF-8 encoding`
  是**非法 UTF-8 文件**，`go` 在解析阶段就拒绝整个包。我没有动它。
- `-race`：需要 cgo，未运行；因此本报告**没有**任何并发结论由竞态检测器背书（k2 的复现是确定性的交错，不依赖 race）。
- **无 Docker、无本地 Postgres**：所有落盘/事务语义只能读代码到行，逐条标「读；无 DB 执行」。
- 内存后端与纯函数层的断言都真跑过。

**探针文件**（全部新建，未改任何已跟踪文件）：

- `vault/zzprobe_crypto_test.go` —— AAD 绑定、版本绑定、nonce 新鲜度、层间隔离
- `vault/zzprobe_zeroize_test.go` —— 零化边界
- `internal/store/postgres/zzprobe_crypto_test.go` —— 审计链 canonical / HMAC 域分离 / 假名（**不需要 DB**）
- `internal/zzprobe/crypto/rotate_lifecycle_test.go` —— 轮转与在线服务并发、部分失败、只重封装
- `internal/zzprobe/crypto/oidc_keys_test.go` —— OP 两把密钥的重叠轮换与 kid 冲突
- `internal/zzprobe/crypto/kekid_test.go` —— `kek_id` 的密钥选择语义
- `internal/zzprobe/crypto/entropy_test.go` —— `user_code` 熵与攻击者预算（算出来的）
- `internal/zzprobe/crypto/audit_labels_test.go` —— 域分离标签
- `internal/zzprobe/crypto/source_log_guard_test.go` —— 静态日志守卫（AST 扫全仓库）

---

## 发现

### k1 账号抹除后，`usr_…` 仍被写进**进程日志**，假名密钥销毁够不到它
- 严重度: 中
- 类别: 合规/隐私
- 不变量/性质: 「抹除后无法再把审计行关联到自然人」（threat-model §9、architecture §4.17 的**明确承诺**）
- 证据: `internal/httpapi/account_routes.go:54-74` —— `s.deleter.DeleteAccount(...)` 先跑完，
  `internal/lifecycle/lifecycle.go:258-263` 的 `Pseudonyms.Destroy` 是**最后一步**；之后 `:68-73`
  在 `SignOut` 失败时 `slog.Warn("could not clear the session after account erasure", "user", string(user), "err", err)`。
  此时**主体 id 已无假名密钥可解**，但这行日志把原始 `usr_…` 写进了应用日志。
- 状态: CONFIRMED（行级确证 + 静态守卫真跑失败，见下）
- 影响: 攻击者/运维实际得到的东西是**对消的**：审计库里那一行再也解不出是谁，而进程日志里躺着一个明文
  `usr_…`，与「发生了一次账号抹除、什么时候」的上下文在**同一条日志行**上。日志通常比数据库走得更远
  （journald / Loki / 容器日志 / SIEM，保留期与访问权都与 DB 不同），所以威胁模型写的那条前提
  「除本服务外无人持久化 `usr_` 与自然人身份的对应」**被本服务自己的日志推翻了**。
  注意这**不属于**已记录的残余「机制落地（迁移 0014）之前的行保留原始 `usr_`」——这行的写入者就是机制本身。
- 修法建议: 这行日志里删掉 `"user"` 属性（它唯一的用途是相关性，而同一条行已有 `request_id`）；
  若要保留可关联性，用 `lifecycle` 的做法（`Detail` 里记形状而不是 id）。同一类共 7 处，见 k6。
- 复现/守卫: `internal/zzprobe/crypto/source_log_guard_test.go::TestProbeNoSlogCallCarriesAnAccountIdentifier`
  （已执行，FAIL，输出见 k6）

### k2 `-rotate-keys` 会**静默覆盖**轮转期间新入册的凭据（在线服务时的数据丢失）
- 严重度: 高
- 类别: 安全（数据丢失/正确性）
- 不变量/性质: 轮转只改信封、不动载荷（`vault/rotate.go` 的文档与 I2）；且「新写入的凭据不会被旧数据盖掉」
- 证据: `vault/rotate.go:91-137`。逐条：`:93` 遍历**读到的**记录 → `:120` 用旧 KEK 解出 DEK → `:130-131`
  改 `WrappedDEK`/`KEKID` → `:133` `s.repo.Put(ctx, rec)` 把**整条记录**写回。
  `rec` 里的 `Nonce`/`Ciphertext`/`Meta`/`CreatedAt` 都是**读的时候**的值。
  Postgres 适配器 `internal/store/postgres/vault.go:80-94` 的 `ON CONFLICT DO UPDATE` **无条件覆盖**
  `version, wrapped_dek, kek_id, nonce, ciphertext, meta, created_at, updated_at` 全部字段
  （「读；无 DB 执行」）。
  `cmd/re0auth/main.go:56-57, 408-409` 说明 `-rotate-keys` 是**一次运行完就退出的进程**，
  文档（main.go:1078-1082）只解释「它不该与已服务的服务器竞争」，**没有任何机制阻止它**：
  运维的常规做法恰恰是「新旧 KEK 都配置的一份新配置起一个进程跑 `-rotate-keys`」，此时旧 pod 还在服务。
  复现（已执行，FAIL）：
  ```
  rotate_lifecycle_test.go:137: CONFIRMED: rotation overwrote a concurrently enrolled secret with the
  stale payload; rotation reported {Scanned:1 Rewrapped:1 AlreadyCurrent:0} (success).
  The user's newer credential is gone and nothing reported it.
  ```
  测试用了 `hookRepo`，在轮转自己的 `Put` 之前（即页面已读、写入未落）插入一次 `Enroll`，
  这正是 live server 能产生的交错。对照组（无并发写入）同一 `Put` 会走到 `AlreadyCurrent` 分支，
  所以「通过」不可能来自没跑到那条路径。
- 状态: CONFIRMED
- 影响: 交错窗口为**读完一页到写完该页**。Postgres 路径 `rotatePageSize = 200`，
  所以窗口是「一整页的写往返时间」，不是一条记录的往返。命中后：
  用户/数据源在窗口内刚写入的 `Ciphertext` 被旧密文覆盖，`WrappedDEK`/`KEKID` 却是**新的**，
  AES-GCM 会拒绝（AAD 匹配、DEK 换了 ⇒ tag 不匹配），于是这个绑定**永久不可读**，
  而 `-rotate-keys` 打印 `rewrapped: N`、审计写 `vault.rotate_keys / ok`、退出码 0。
  唯一暴露是**下一次用户调用**报「unwrap DEK / decrypt credential」。
  这直接影响 `federation` 侧：refresh 赢家刚写进 vault 的上游令牌会被盖掉。
- 修法建议: 让轮转的重封装**只写它真正改的字段**——给 `Repo` 加窄方法（如
  `RewrapDEK(ctx, id, wrapped, kekID, updatedAt)`）或让 `Put` 支持「只更信封」变体；
  若必须复用 `Put`，则用 CAS（把读到的 `WrappedDEK` 作为谓词：
  `UPDATE ... WHERE subject=$1 AND provider=$2 AND wrapped_dek=$3`），0 行受影响即**重读重试**，
  并在结果里报出「被并发写入跳过」的条数。同时把 `-rotate-keys` 的文档改成
  「可以先跑，但必须在**无人服务**的窗口内，或改为不覆盖整条记录」。
- 复现/守卫: `internal/zzprobe/crypto/rotate_lifecycle_test.go::TestProbeRotationOverwritesARecordEnrolledDuringTheRun`

### k3 轮转**没有原子性也没有检查点**，半途失败后销毁退役 KEK 就是永久数据丢失；而失败现场**不进审计**
- 严重度: 中
- 类别: 可用性 / 可维护性
- 不变量/性质: 密钥轮换的「可安全重跑、失败可见」
- 证据: 逐条 `Put`，无事务、无「已处理到哪」的持久记录（`vault/rotate.go:42-69` 的分页游标只在**内存**里）。
  `vault/rotate.go:74-82` 的 `vault.rotate_keys` 审计事件在**全部完成后**才写一次；失败路径
  `:52-54/:66-68` 直接 `return out, err`，**一次审计都不写**。
  `cmd/re0auth/main.go:1083-1096` 只在 `scanned == 0` 时警告，失败时 `die("rotate keys", err)` 只进进程日志。
  内存后端的 `Put` 全量替换（`vault/repo.go:121-126`）所以同样的失败语义在本地可复现。
  复现（已执行）：
  ```
  rotation aborted after 1 records: {Scanned:2 Rewrapped:1 AlreadyCurrent:0},
    err=vault: rotate: persist taptap:usr_b: context deadline exceeded
  CONFIRMED (by construction): 2 of 3 credentials are lost if the retired key is removed after a
    partial rotation, and -rotate-keys reports the partial run as an error only in the process's own log
  ```
  以及 `TestProbeRotationIsNotAtomicAcrossRecords`：
  ```
  CONFIRMED: a rotation that fails on its first write produces no audit event at all, so the operator's
    log cannot distinguish 'no rotation was attempted' from 'a rotation changed rows and then died'
  ```
- 状态: CONFIRMED
- 影响: 运维拿到的信号只有「进程以非零码退出 + 一行 stderr 日志」。他不知道**已经改了多少条**、
  也不知道**退役 KEK 现在还能不能删**。文档/启动警告（`main.go:402-406`）确实说了「跑完再删」，
  但它无法区分「跑完了」与「跑了一半」。真实危害是**永久凭据丢失**：把 `vault.retired` 撤掉之后，
  失败点之后的记录在所有配置下都解不开（`TestProbeRotationPublishesPartialProgressOnFailure` 断言了这一半），
  而这一步通常是「轮转完毕的收尾动作」，最容易被顺手做掉。次生：某条记录被写坏 `kek_id`
  会让**整次轮转在它那里中止**，后续页一条都不处理（`TestProbeRotateRefusesAKEKIDItCannotUnwrap`，
  已执行）——单行污染 = 全量轮转停摆。
- 修法建议: ①每条（或每批）处理完写一条审计行（含游标），让「跑到哪」可查、可续跑；
  ②失败时也写一条 `vault.rotate_keys / error` 并带上 `scanned`/`rewrapped`；
  ③`-rotate-keys` 结束时**无条件**打印混合状态警告（`already_current + rewrapped != scanned` 时）；
  ④长期解法是令重封装幂等且可续跑（配合 k2 的窄写）。
- 复现/守卫: `.../rotate_lifecycle_test.go::TestProbeRotationPublishesPartialProgressOnFailure`（打印部分真相）
  与 `::TestProbeRotationIsNotAtomicAcrossRecords`（打印部分真相 —— 这条是断言「不存在」，
  已先断言了失败确实发生，即反空转要求满足）；`kekid_test.go::TestProbeRotateRefusesAKEKIDItCannotUnwrap`

### k4 `vault.retired` 里的**重复 `kek_id`** 不被拒绝，报错指向错误的位置
- 严重度: 低
- 类别: 可用性 / 可维护性
- 不变量/性质: 配置错误必须在它真正出错的地方被报出来
- 证据: `cmd/re0auth/config.go:619-638` 的循环只检查 `kek_id == ""` 与 `kek_id == cfg.KEKID`，
  **不去重**，全部塞进 `cfg.RetiredKEKs`。`cmd/re0auth/main.go:1044-1055` 把它们逐个
  `NewLocalKeyWrapper(...)` 后交给 `vault.WithRetiredKeys`，而后者在 `vault/service.go:123-125`
  以 `vault: retired key %q is declared twice` 报错。结果：启动失败，但错误文本指向**库内部**，
  而 `config.go` 已经知道这是 `vault.retired[0]` 与 `vault.retired[1]` 的重复。
- 状态: CONFIRMED（读；行级。`WithRetiredKeys` 的重复检测已有既有测试 `TestWithRetiredKeysRejectsBadConfigurations` 覆盖库侧，
  缺的是**配置侧**的同一检查）
- 影响: 纯可用性/可维护性：fail-closed 方向正确，进程不会带错配置启动。代价是运维看到
  「declared twice」却不知道是哪两行，而 `retired` 是轮转期间**最容易被复制粘贴**的一段配置。
- 修法建议: 在 `config.go:619` 的循环里加一个 `seen := map[string]int{}`，重复即
  `fmt.Errorf("%s.kek_id %q is already declared as vault.retired[%d]", field, retired.KEKID, seen[...])`。
- 复现/守卫: 无独立探针（无执行必要：行级即可断定，且库侧的守卫已存在）

### k5 轮转**确实**只重封装、不解密载荷 —— 用计数 KeyWrapper 证明
- 严重度: 提示
- 类别: 安全（正面结论）
- 不变量/性质: `vault/rotate.go` 文档「DEK 不变，载荷密文从不被触碰，不产生明文」
- 证据: `internal/zzprobe/crypto/rotate_lifecycle_test.go::TestProbeRotationDoesNotDecryptPayloads`
  （已执行，PASS）：用 `countingWrapper` 计数，一条记录、一次轮转得到 `wrap=0 unwrap=1`。
  `vault/rotate_test.go:77-85` 既有守卫另外断言 `Ciphertext` 与 `Nonce` 逐字节不变。
- 状态: CONFIRMED
- 影响: 这是好的那半边：轮转期间明文不进内存，所以「轮转被观测」这条攻击面不存在。
  **注意它只在没有并发写入时成立**（k2）。
- 修法建议: 无。
- 复现/守卫: 同上

### k6 同一类日志泄漏共 **7 处**，静态守卫会持续抓到
- 严重度: 低（除 k1 外）
- 类别: 合规/隐私
- 不变量/性质: 前一轮钉住的「令牌不进日志」守卫**覆盖不到** `cmd/`、`internal/admin`、`internal/auth`、
  `internal/federation`、`internal/httpapi` 里的 `slog` 调用（第二轮把守卫做在**审计 sink** 与**协议平面**上）
- 证据: `internal/zzprobe/crypto/source_log_guard_test.go::TestProbeNoSlogCallCarriesAnAccountIdentifier`
  （AST 扫全仓库，已执行，FAIL）输出：
  ```
  internal/admin/admin.go:442           attr subject=subject
  internal/auth/auth.go:218             attr subject=e.Subject
  internal/federation/bind.go:208       attr user=string(...)
  internal/federation/refresh.go:155    attr user=string(...)
  internal/federation/refresh.go:160    attr user=string(...)
  internal/httpapi/account_routes.go:73 attr user=string(...)      <- k1
  internal/httpapi/binding_routes.go:57 attr user=string(...)
  ```
  逐条可达性：`admin.go:442` 在 `s.record` 的审计写入失败时触发；操作员发
  `POST /v1/admin/kill_switch {"target":"subject","subject":"usr_…"}` 是**合法请求**
  （`internal/httpapi/admin_routes.go:265-266`），审计一旦写失败，目标账号 id 进日志。
  `auth.go:218` 在登录/登出的审计写失败时触发；`federation/bind.go:208`、`refresh.go:155/160`
  在回滚/撤销失败时触发；`binding_routes.go:57` 在列绑定失败时触发。
  守卫**不含**凭据类 key（`token`/`secret`/`verifier`/`dek`…）：那些一处都没命中，与第二轮的结论一致。
- 状态: CONFIRMED
- 影响: 除 k1 外都在**错误路径**上，所以不能被匿名触发；但它们把「永久 id ↔ 自然人」的对应
  送进保留期更长的应用日志，且都不受假名密钥销毁影响。`admin.go:442` 是**合法运维请求**触发的，
  范围最大（一次 `admin.*` 调用都可能命中）。
- 修法建议: 统一改成「形状而非 id」：`slog.Error("admin audit record failed", "action", action, "err", err)`
  （`action` 已足够定位），或记 `"self", bool`。然后把这条静态守卫并进常规套件——
  它是本区域唯一能覆盖 `cmd/` 的机制。
- 复现/守卫: `internal/zzprobe/crypto/source_log_guard_test.go::TestProbeNoSlogCallCarriesAnAccountIdentifier`

### k7 收回的**令牌加密密钥**允许复用当前 id；`CompositeCrypto` 不按 id 查表（无解密预言机）
- 严重度: 提示
- 类别: 安全（正面结论 + 一处不一致）
- 不变量/性质: 与签名 kid 同级的「id 冲突必须拒绝」
- 证据: `cmd/re0auth/main.go:1253-1273` 的 `oidcRetiredTokenKeys` 只校验 `id != ""` 与 32 字节，
  **不检查与 `CryptoKeyID`（`main.go:1206` 硬编码 `"re0auth"`）冲突**。而签名侧
  `oidcstore.ValidateSigner`（`oidcstore.go:71-83`）明确拒绝重复 kid。
  已执行（PASS，纯记录）：
  ```
  TestProbeRetiredTokenKeyIDsAreNotValidatedLocally: CONFIRMED: a retired token key reusing the
    current key id is accepted and used; ids are advisory here because CompositeCrypto tries every
    key. Not a vulnerability (no lookup by id happens)...
  ```
  原因是 `zitadel/oidc v3.51.3 pkg/op/crypto.go:103-111` 的 `CompositeCrypto.Decrypt` 是
  「按序试每一把，谁能认证就用谁」——**没有任何地方按 `kid` 选密钥**。
  `TestProbeTokenDecryptionIsKeyOrderIndependent`（已执行，PASS）对 3 种密钥顺序都成功，
  且「密钥集不含正确密钥」时的错误信息**不含任何 key id**（因此没有预言机可供攻击者选择密钥）。
- 状态: CONFIRMED
- 影响: 不是漏洞：攻击者无法用 `kid` 引导解密、无法从失败信息里读密钥身份。
  实际影响是**运维一致性**——同一套轮换流程对签名 key 会 fail-closed、对令牌 key 不会，
  一个复制粘贴来的 `RE0AUTH_OIDC_RETIRED_TOKEN_KEYS` 可以用错的 id 混过去而没有任何提示。
- 修法建议: 在 `oidcRetiredTokenKeys()` 里加一条与签名侧对齐的检查（拒绝 `id == "re0auth"`、
  拒绝重复 id），报错文本与 `ValidateSigner` 保持一致；或者反过来在 `oidchttp.New` 里拒绝
  `RetiredTokenKey.ID == CryptoKeyID`，让**库**也守这条不变量。
- 复现/守卫: `internal/zzprobe/crypto/oidc_keys_test.go::TestProbeRetiredTokenKeyIDsAreNotValidatedLocally`
  + `::TestProbeTokenDecryptionIsKeyOrderIndependent` + `::TestProbeCompositeCryptoOverlap`

### k8 零化：vault **真的**擦掉了它交出去的那个缓冲；Go 的残余如实记录
- 严重度: 提示
- 类别: 安全（正面结论 + 边界声明）
- 不变量/性质: `vault.Use` 的回调作用域（I2）、`Scrub` 的文档
- 证据: 全部已执行、PASS：
  - `vault/zzprobe_zeroize_test.go::TestProbeScrubZeroesTheBackingArrayItWasGiven` —— `Scrub` 对手上那块 `[]byte` 是真写零。
  - `::TestProbeUseZeroizesThePlaintextItHandedOut` —— 回调里拿到的那个 slice 在 `Use` 返回后**逐字节为 0**
    （`vault/service.go:285` 的 `defer Scrub(plain)` 确实作用在交给回调的同一块内存上）。
  - `::TestProbeUseZeroizesEvenWhenTheCallbackFails` —— 回调返回错误也擦（`service.go:298-300`）。
  - `::TestProbeEnrollDoesNotRetainTheCallersSecretBytes` —— `Enroll` 不保留调用方 slice（密封进新缓冲），
    也不去写调用方的内存。
  - `::TestProbeUseDoesNotZeroizeTheCallersCopy` —— 回调自己拷走的副本**不在** `Scrub` 射程内（这正是残余）。
- 状态: CONFIRMED
- 影响: 正面：vault 的这一半是名副其实的。
  **残余（不可修，如实记录）**：①Go 无法保证零化 —— GC 可能已经复制过、`runtime.KeepAlive`+`//go:noinline`
  使意图有约束力但不可能覆盖全部副本（`vault/scrub.go:5-31` 的文档已经说实话）；
  ②`internal/federation/binding.go:104-112` 的 `json.Unmarshal(plaintext, &secret)` 会为
  `AccessToken`/`RefreshToken` 造出**不可擦除的 Go string**，活到 GC 回收为止 —— 该文件 `:92-103`
  的注释已经把这个残余写清楚了，我不重复报告为发现；
  ③DEK 走 `defer Scrub(dek)`（`service.go:275`）与 `rotate.go:109/125`，同样只覆盖 vault 自己那一份。
- 修法建议: 无（要么接受，要么引入 memguard 这类从分配就接管的方案，成本大于收益）。
- 复现/守卫: `vault/zzprobe_zeroize_test.go` 的 5 条

---

## 探过但没破的（这些也应变成守卫）

以下每条都是**真的跑过**的（除标注「读」的两条），PASS 即结论；每条都先有对照组，所以「通过」不是「没跑到」。

1. **AAD 把身份绑死在两层上**（`vault/zzprobe_crypto_test.go::TestProbeEnvelopeAADPreventsMovingACiphertext`，PASS）。
   三个方向的搬运都失败：①把 A 的 `WrappedDEK` 换到 B 的行上；②把 A 的 `Nonce+Ciphertext` 换到 B 的行上（B 用自己的信封）；
   ③同一 subject 不同 provider 之间换载荷。对照组：未动过的两条记录都能正常打开。
   （第二轮已记「vault AAD 两层都把身份绑住」，但**没有**做成「交换两行」的测试；现在有了。）
2. **`recordVersion` 参与两层 AAD**（`::TestProbeRecordVersionIsInTheAAD`，PASS）。
   把行里的 version 字节改成 0/2/255 之后解密全部失败。
   **降级结论**：`vault/rotate.go`/`service.go` 里对 `rec.Version` 的使用是**单一**的 ——
   它只进 AAD，不存在「按 version 选一条更弱的路径」的分支（`service.go:255`、`rotate.go:95`）。
   因此攻击者能改的 version 只会让解密失败，不能选中任何旧格式。这是**结构上**没有降级面，
   而不是「有分支但足够安全」。
3. **AAD 编码无歧义**（`::TestProbeAADIsInjective`，PASS）：`("a","bc")` 与 `("ab","c")`、
   `("usr_1taptap","")` 与 `("usr_1","taptap")` 都不碰撞。
4. **nonce 每次加密都新**（`::TestProbeNoncesAreFresh`，PASS）：DEK 层与 KEK 层各 512 次同明文加密，
   nonce 无重复。GCM 下这是最要命的一条，值得常驻。
   （`envelope.go:96-102/126-140` 用 `io.ReadFull(rand.Reader, nonce)` 并**检查错误**；全仓库 grep
   `math/rand`/`rand.Intn`/`rand.Seed`/`UnixNano` 作熵 结果为**零命中**，唯一两处 `math/rand` 在他人测试文件里。
   `rand.Read` 的返回值全仓库只有 2 处忽略，都在**测试夹具**里：`internal/httpapi/oidc_wiring_test.go:50`、
   `internal/oidchttp/oidchttp_test.go:33`——不影响生产，但值得统一改成 `io.ReadFull` 或检查 err。）
5. **两层之间不靠 AAD 标签隔离，靠密钥隔离**（`::TestProbeAADIsIdenticalAcrossTheTwoLayers`，PASS）。
   值得知道的**事实**：`service.go:179/193` 与 `:255/277` 用的是**同一串** AAD
   `bindingAAD(version, subject, provider)`，没有层标签。当前不构成问题（KEK 与 DEK 不同密钥），
   但如果将来把两层换成同一把密钥、或允许 KEK 与 DEK 混用，AAD 不会拦。
   **建议把层标签并进 AAD**（`bindingAAD(version, "kek", subj, prov)` / `"payload"`）——一次性改动，
   但它会**使所有存量密文不可读**，所以只能随下一次 KEK 轮换一起做，不是顺手改的事。记为**判断**。
6. **`kek_id` 只在已配置的密钥里选，攻击者写库无法指向自己控制的密钥**
   （`internal/zzprobe/crypto/kekid_test.go::TestProbeKEKIDSelectsOnlyAmongConfiguredKeys`，PASS）。
   `""`/`"attacker-key"`/`"kek-1 "`/`"KEK-1"`/`"kek-1\x00"` 全部报
   `wrapped by key %q, which is not configured`（fail-closed 且运维可读）。原因是结构性的：
   `vault/service.go:256` 的 `s.keys[rec.KEKID]` 是**启动时构造的 map**，行里没有通往新密钥的路。
   能写库的攻击者得到的只是可用性（让某条记录不可读，或让轮转停摆 —— 见 k3），
   与直接删掉那一行等价。
7. **OP 两把密钥的重叠轮换行为与文档一致**
   （`oidc_keys_test.go::TestProbeCompositeCryptoOverlap`，PASS）：当前密钥**只**加密
   （退役密钥读不出新铸的令牌）；退役密文在当前+退役的组合下能解；当前密钥单独解不出旧令牌
   （这正是退役密钥必须留着的原因）。`threat-model §6.0.1` 的两段描述逐条成立。
   另：`::TestProbeTokenKeyIsA256GCMDirectJWE` 打印出**攻击者可读**的令牌头
   `{"alg":"A256GCMKW","enc":"A256GCM","iv":...,"kid":"the-kid","tag":...}` ——
   里面只有算法与 kid，没有 tokenID、没有 subject，符合预期。
8. **kid 冲突在**签名**侧被拒**（`::TestProbeSignerRejectsAmbiguousKeySets`，PASS）：
   当前 kid 与退役 kid 重复、两个退役 kid 重复、退役缺公钥、空 kid、1024 位密钥**全部被拒**，
   错误文本可定位；对照组（合法集合）通过，且 `KeySet()` 里 kid 唯一、当前密钥排第一、
   发布的都是 `*rsa.PublicKey`。所以「退役公钥与当前 kid 相同会让验证选错密钥」这条**不成立**。
9. **会话 / CSRF / state / 授权码 / 设备码 / 一次性令牌的熵**
   （读 + `entropy_test.go`）：`auth.Manager` 用 `scs`（`scs@v1.4.1/session.go:806-808` 是 32 字节 `crypto/rand`）；
   CSRF = `randomToken(32)` = 256 bit（`auth.go:229,726-731`，`crypto/rand` 失败即 panic —— 对不可恢复的熵失败是正确处置）；
   上游 state = `randomToken(24)` = 192 bit（`auth.go:583`）；`oauth.newToken()` 32 字节
   （`as.go:353-359`，认证码与设备码共用，均检查 err）；`oidcstore.RandomValue()` 32 字节
   （`oidcstore.go:389-395`，认证请求 id）；`admin.newSecret()` 32 字节、`newClientID()` 8 字节；
   `federation.newBindID()` 16 字节；`account.NewUserID()/NewIdentityID()` 16 字节；
   `federation.newBindingGeneration()` 8 字节随机（避免重绑回到 1）；
   `httpapi.newRequestID()` 12 字节 / `newTraceID()` 16 字节。
   **全部用 `crypto/rand`，全部传播错误**（除上面第 4 条点名的两处测试夹具）。
10. **`user_code` 熵与攻击者预算（算出来的，不是引注释）**
    （`entropy_test.go::TestProbeUserCodeEntropyAndAttackerBudget` 与 `::TestProbeNormalizationIsTheOnlyThingThatNarrowsTheSpace`，PASS）：
    字母表 20 个字符（`oauth/device.go:31 = "BCDFGHJKLMNPQRSTVWXZ"`，我逐字符数过）、8 位有效字符 ⇒
    **20^8 = 25600000000 = 34.575 bit**（`device.go:463-477` 用拒绝采样，无偏）。
    归一化只做「大写 + 去空格 + 去连字符」（`device.go:481-483`；内存侧 `memory/oidc.go:748-750` 同构），
    所以连字符**不带**熵，搜索空间就是 20^8；我另外用 400 组不同码验证归一化不会把两个不同的码并成一个。
    以出厂限流（`cmd/re0auth/config.go:300-301`：`defaultRateLimit = 50` rps、`defaultRateLimitBurst = 100`，
    键是 `plane|client-address`，`middleware.go:349`；`/v1/device/verification` 在 business 平面且**不会被豁免**）
    计算：**单地址 / 60 秒 = 3100 次尝试 ⇒ P(命中) = 1.21e-07**；**单地址 / 整个 10 分钟 TTL = 30100 次 ⇒ 1.18e-06**。
    要拿到 1% 的概率需要 **≈ 8505 个源地址**（每个 30100 次），而限流器的 map 进程内上限是 10000 个键
    （`internal/ratelimit/ratelimit.go` 的 `defaultMaxKeys`）——攻击者自己就会把桶挤掉。
    结论：**有限流时安全**（并且 `DescribeDeviceAuthorization` 只对 `Pending` 且未过期的码应答，
    `oauth/device.go:317-322`，所以不是长期存在的预言机；探测还需要一个**已登录账号**，
    `device_routes.go:52-55`）。
    **无限流时（`server.rate_limit = 0`，配置明确允许）** 单地址可以跑满 20^8：此时唯一的界是「一次猜测
    = 一个已登录会话 + 一次 DB 查询」，34.6 bit 从「不可行」变成「一台机器几天到几周」。
    这是**已有文档化开关的后果**，我按简报要求写成「判断」而不是 finding；
    但它足够具体，值得在 `docs/` 里把「关限流会同时关掉设备码的在线猜测界」写明。
11. **常量时间比较：该用的一处不缺**（读；逐处核对）。
    `oauth/client.go:108-114` 客户端密钥 = `sha256` + `subtle.ConstantTimeCompare`；
    `oauth/as.go:336-343` PKCE S256 = `subtle.ConstantTimeCompare`（先比长度这一点无害，challenge 长度是公开的）；
    `auth/auth.go:235-242` CSRF = `subtle.ConstantTimeCompare`；`auth/auth.go:617` 上游 state = `subtle.ConstantTimeCompare`；
    `internal/store/postgres/auditchain.go:305` 审计签名 = `hmac.Equal`。
    其余的 `==`/`strings.EqualFold` 逐条判定为**可接受**，理由写明而不是笼统放过：
    - `oauth/client.go:159-166` `AllowsRedirect`、`:248-255` `AllowsScope`、`:311-313` 客户端 id/status：
      比的是**公开标识**，且客户端 id 的保密性不是设计前提；
    - `oauth/device.go:161/180` 等 user_code 查表：34.6 bit 的**穷举**是威胁，不是时序；
    - `internal/store/postgres/auditread.go:64` 的 `?subject=` 先 HMAC 再入库、`auditchain.go:292/299` 的
      `bytes.Equal` 比的是**链哈希**（公开值）；
    - 会话/token/授权码的查表是「按 `sha256(value)` / `TokenHash(value)` 查哈希表」
      （`oauth/tokens.go:290-296`、`internal/store/postgres/sessions.go:44-47`）——
      按简报，**哈希表查找不是要报的比较**，我明确不报。
12. **审计链的 canonical 形式与域分离**（`internal/store/postgres/zzprobe_crypto_test.go`，全部 PASS）：
    - `::TestProbeCanonicalIsDeterministicAndTotal`：同一行 64 次逐字节一致（对照组）；11 种字段变更
      （action/subject/provider/outcome/时间 ±1µs/detail 值/detail 键/±1 项/nil vs 空）**每一种都改变哈希**。
    - `::TestProbeCanonicalConcatenationIsUnambiguous`：对每一对相邻字段做「把字节搬过边界」
      （`("a","bc")` vs `("ab","c")`，含 detail 的键/值、键的边界）都不同 —— **长度前缀是真的起作用**（`auditchain.go:86-91`）。
    - `::TestProbeCanonicalDetailOrderIsNormalised`：128 次打乱 `Detail` 迭代顺序哈希不变
      （`auditchain.go:71-75` 的 `sort.Strings` 是承重的），且 `detail` 的**项数**也被承诺
      （`writeLenPrefixed(&b, strconv.Itoa(len(keys)))`）。
    - `::TestProbeHashInputFieldsAreReproducibleUnderTheStoredEncoding`：空串 / 空格 / `\n` / `\x00` /
      日文 / 组合字符 vs 预组合字符 / PRECOMPOSED 与非预组合 / 4096 字节长串 —— 9 种互不碰撞。
      这正是简报问的 unicode 归一化面：**Go 侧不做任何归一化**（字符串就是字节序列），
      `é` 与 `e+U+0301` 是两个不同的输入、得到两个不同的哈希，这是一致的行为而不是漏洞。
    - **时间戳**：写入路径 `audit.go:60-63` 做 `UTC().Truncate(time.Microsecond)`，canonical 里
      `auditchain.go:65` 用 `UTC().UnixMicro()`。两处**对同一精度**，所以「写进去的」与「读回来算的」一致。
      我把「为什么不能用 `RFC3339Nano`」也钉进测试（`audit_labels_test.go::TestProbeCanonicalTimestampPrecision`）。
      **一处「读；无 DB 执行」的提醒**：`Truncate` 只在 `Record` 里，若将来有人直接调
      `appendBatch`（同包内）传入纳秒时间，`canonical` 会按微秒哈希而 Postgres 会保留纳秒 ⇒ 该行**自己验不过自己**。
      当前唯一的调用者是 `Record`（经 `auditbatch.go` 的 batcher），所以这只是「不要把 appendBatch 变成公开入口」的守卫建议。
    - **NULL vs 空串**：`detail` 列是 `jsonb NOT NULL DEFAULT '{}'`（`migrations/0007_audit.sql:16`），
      且 `Record` 把 nil 归一成 `map[string]string{}`（`audit.go:65-68`），两者哈希相同（我断言了这一点）。
      `subject`/`provider` 是 `NOT NULL DEFAULT ''`，`prev_hash` 允许 NULL 但在链内总是写值。
    - **浮点数**：`detail` 是 `map[string]string`，Go 侧没有浮点，也没有浮点格式化 —— 这一类歧义在这个 schema 下不存在。
    - **长度扩展 / 第二原像**：`chainHash = SHA-256(prev ‖ canonical)`（`auditchain.go:94-99`）确实容许长度扩展，
      但**不可利用**：攻击者要伪造的是 `signature = HMAC-SHA256(key, row_hash)`（`:108-110`），
      他不知道 key，而长度扩展只能造出「另一个哈希」，造不出「另一个合法 MAC」。
      `audit_events_row_hash_idx` 还是 `UNIQUE`（`0013_audit_chain.sql:36-37`），第二原像另有 DB 层拦截。
      第二原像本身需要 SHA-256 碰撞，不成立。
    - **域分离**：`auditSignatureLabel` / `auditSubjectIndexLabel` / `auditPseudonymLabel` 三个常量
      **互不相同、非空、互不为前缀**（`zzprobe_crypto_test.go` 与 `audit_labels_test.go` 各断言一次），
      且 `mac()`（`auditpseudo.go:40-45`）把 label 写在消息之前、label 是固定串，
      所以**攻击者只能控制 msg 时无法移动用途边界**。同一个 msg 在三个 label 下产出三个不同 MAC，
      MAC 不可跨用途互换；去掉 label 的裸 HMAC 与签名值不同（证明 label 真被套上了）；
      换一把 chain key 签名不同。`hmac.Equal` 用于验签（`:305`）。
      审计 key **没有被用于别处**：`l.key` 只进 `mac()`，而 `mac()` 只有这四个调用点
      （sign / subjectIndex / pseudonymOf 走的是**每 subject 的独立 key**，`pseudonymOf(key, ...)` 的第一个参数是那把 key，不是 `l.key`）。
    - **假名与索引不是彼此**（`::TestProbeSubjectIndexIsNotThePseudonym`，PASS）：
      `subjectIndex` 不泄露 subject 文本、是 18 字节 raw-url base64、长度与常数一致；
      同一个 subject 换 key 得不同假名、同一 key 下不同 subject 得不同假名；
      假名长度 = `pseudonymBytes`(16) 的 base64 长度。
    - `::TestProbeCheckSubjectKeyRefusesWrongLengths`（0/1/16/31/33/64 全拒、32 通过）与
      `::TestProbeWriteLenPrefixedIsInjective`（含 `("", "a")` vs `("a", "")`、`"\x00"` vs `"\x00\x00"`）PASS。
    - `::TestProbeVerifyAndHeadAgreeOnGenesis`：`auditGenesis` 是 0 字节，`chainHash(nil, c) == chainHash(auditGenesis, c)`
      —— 这是 `Verify`（`auditchain.go:286-291` 判 `len(prevHash) != 0`）与迁移 `0013` 写入的 `'\x'::bytea` 之间的那处约定。
13. **Postgres 会话表按 `sha256(cookie)` 存**（`sessions.go:18-19, 44-47`，读）：表泄漏不是一组可用 cookie。
    自省路径（`oidchttp.go:1173-1182`）对解不开的令牌返 `Active: false` 而**不是** error —— 正确方向（不把例行无效令牌变成 500）。
14. **MAC 上游调用（taptapoauth）**（读；行级）：`taptapoauth/client.go:252-277` 的签名字符串
    `ts\nnonce\nmethod\npath?query\nhost\nport\n\n` 逐字段拼接，端口有 http/https 默认值，
    `hmac.New(sha1.New, macKey)` 写全、base64 标准编码。**HMAC-SHA1 是上游协议规定**，不是本项目的选择；
    这里没有比较（是签名方），所以没有常量时间问题。`nonce` 是 32 bit 十进制（`:367-372`）——
    RFC 6750 语义下 nonce 不需要保密，32 bit 足够抗重放（时间戳 ts 一起进签名）。
15. **`config` 的秘密解析不泄露值**（读；行级）：`internal/config/config.go:57-66` 的 `Secret()`
    在错误里只放**变量名**（`%s names %q, which is not set`），不放值；`cmd/re0auth/config.go:800-831`
    的 `decodeKey32` 只在长度错时报「must be 32 bytes, base64 or hex」。

---

## 未能到达（残余盲区）

> 每条都说清为什么以及需要什么才能到达。

1. **Postgres 落盘与事务语义：全部只有「读；无 DB 执行」**。本机无 Docker、无 Postgres，
   所以下列论断没有执行证据，只有行级证据：
   - `auditRow.canonical()` 的输入在 pgx → jsonb → Go 往返后是否**逐字节**不变（尤其 detail 里出现
     `\x00` 或非法 UTF-8 时 jsonb 的行为，以及 jsonb 的键排序是否真的只由 Go 侧 `sort.Strings` 决定）；
   - `ts.Rotate()` 的 `Put` 真的覆盖了 `nonce`/`ciphertext`/`meta`/`created_at`（k2 的核心前提）——
     我是从 `vault.go:83-91` 的 `DO UPDATE SET` 列表读出来的，**没有**在真实表上观察过；
   - `audit_chain` 行级锁 + `RETURNING` 的串行化在并发写下的分叉行为（`batcher` 的批量语义同此）。
   **要证实**：`E2E_DATABASE_URL` 指向任意 Postgres（CI 已有 `postgres:16` service，
   `docs/security-audit-2.md` 记录了这件事），或补一条只读的 pgx 往返测试。
2. **`-race` 未运行**（需要 cgo）。k2 是**确定性**交错复现，不依赖检测器；但
   「`vault.Service` 在多 goroutine 下除 repo 外无共享可变状态」这一点没有检测器背书。
3. **审计假名密钥销毁之后的再关联**：`Destroy` 只删 `audit_subject_keys` 一行（`auditpseudo.go:173-187`），
   而 `subjectKey`（`:115-142`）在**没有行时会铸一把新的**。所以「抹除之后的某个 `Record` 又写了这个 subject」
   会重建链接。我**没有找到**这样一条路径（抹除的顺序让账号行、会话、令牌、绑定都没了），
   也**没有**做成失败测试，所以这只是**假说**。
   **要证实**：构造「抹除后仍有代码路径以该 subject 写审计」的场景，或直接断言
   `Destroy` 之后 `loadKey` 永不再铸新键（需要一把「已销毁」的标记，当前 schema 没有）。
4. **`internal/httpapi` 整个包当前无法编译**（他人留下的非法 UTF-8 探针
   `internal/httpapi/zzprobe_adminpriv_test.go`），所以 k1 的**动态**复现（起 `httptest` 走
   `DELETE /v1/account` 并捕获 `slog`）做不了。我用静态 AST 守卫替代（已执行、已失败），
   行级证据也已齐。**要证实动态版本**：先让那个文件可解析，再在 `internal/httpapi` 里加
   `slog.SetDefault(capture)` + 一个 `SignOut` 失败的 session store stub。
5. **`upstreamkit` / `cmd/referencesource` 的日志面**没有单独做完。
   我 grep 过它们的 `slog` 调用：`cmd/referencesource/main.go` 只有 stage/err/path/addr/issuer 之类，
   `upstreamkit` 本身不 slog（只把 `client_secret` 当**入参**用）。没有发现凭据进日志，
   但**没有**逐条读完这两个包的全部错误文本（它们的 `Errorf` 里带 `boundDetail` 上游文本，
   那是另一片（韧性/SSRF）的面）。**要证实**：按第二轮对 Zitadel 的做法，把上游响应文本的整流路径走一遍。
6. **`taptapoauth` 的 MAC 与 `tapsign` 的 `X-LC-Session` 是否可能进中间件日志**：
   `tapsign/client.go:125` 把会话令牌放 `X-LC-Session` 头。我没有找到任何记录请求头的
   `slog`/RoundTripper（`httpclient/` 里唯一的日志面是 `NoCrossHostRedirects` 那个**只含 host** 的错误），
   所以结论是「没有」，但这是**穷举式否定**，其可信度取决于我对全仓库 slog 调用的扫描 —— 那条扫描是
   k6 的守卫，它是完整的（AST 级，覆盖全部 .go 文件）。
7. **`recoverBrowser/recoverProtocol/recoverBusiness` 把 `panic` 值整条写进日志**
   （`middleware.go:510/529/549`）。一个携带凭据的 panic 值会进日志。我没有找到会产生这种 panic 的路径，
   所以不报为发现，只记在这里。**要证实**：构造一个 `panic(vault.Record{...})` 之类的路径。
8. **`X-Request-Id` 由调用者提供、未经边界化就进日志与响应头**（`middleware.go:138-142`，
   只有 `newRequestID()` 生成的才形如 `req_<hex>`）。伪造换行即可污染日志行；理论上也能撑爆日志。
   同类问题在 `taptapoauth/client.go:335-343` 被显式处理过（`boundDetail` 去 `\r\n` 并截断 200 rune），
   而请求 id 这一处**没有**。它**不是秘密**、也不算我这一区间的密码学问题，故不报为 finding；
   若主代理要收，它属于「日志质量/可维护性」。**要证实**：`X-Request-Id: "x\nlevel=ERROR msg=forged"` 一个请求。

---

## 判断（文档化决定可否质疑，不是 finding）

1. **「KEK 来自环境变量、KMS 未实现」**：`vault/envelope.go:36-51` 的注释与 `threat-model §6.0`
   已经把「进程被攻破即可读」「KMS 买的是可恢复性与可归因，不是预防」写对了。我**不改**这个裁定，
   只补一条实测结论：`LocalKeyWrapper` 的 KEK 在进程内是 `cipher.AEAD` 里的**扩展密钥**，
   `kek` 那个 `[]byte` 参数本身没有被 vault 保留（`NewLocalKeyWrapper` 没有存它）——
   所以「进程内存被 dump」的收益是 AES 轮密钥，不是 KEK 原文。这不改变裁定（轮密钥同样能解密），
   但比文档描述的稍窄一点。
2. **层标签缺席（见「探过但没破」第 5 条）**：建议 `bindingAAD` 加 `"kek"`/`"payload"` 标签，
   但**不能顺手做**——它会作废全部存量密文。应作为**下一次 KEK 轮换的附带项**提出，
   而不是当作 bug 修。这是裁定，不是发现。
3. **`server.rate_limit = 0` 会同时撤掉 `user_code` 的在线猜测界**（见「探过但没破」第 10 条）。
   配置项本身是文档化的，我不主张改它的语义；主张的是**文档要说清这个副作用**：
   34.6 bit 在有 50 rps 的界下是安全的，在没有界下不是。属于文档与实现一致的裁定。
4. **`user_code` 保持 20^8 而不是加长**：RFC 8628 §6.1 把「8 字符 / 20 符号」列为**在限流且短寿命成立时**
   足够的一档，这正是本部署的形状（10 分钟 TTL + 5 秒轮询节流 + 只对 `Pending` 应答 + 需要已登录会话）。
   我认为无需改动；若要更保守，加到 9 位（38.9 bit）的成本只是用户多敲一个字符。
5. **`appendBatch` 的可见性**（见「没能到达」里那条微秒/纳秒提醒）：不要把它变成公开入口。
   属于可维护性裁定。
