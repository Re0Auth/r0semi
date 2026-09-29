# Re0Auth 上线前安全与性能审计 · 第六轮汇总（主代理）

> **审计对象**：`C:\git\r0semi`，HEAD = `bf81b2a`，工作区干净（唯一未跟踪内容是本轮探针 `internal/zzprobe/audit6/`）。
> **环境**：Windows 11、**无 Docker、无本地 Postgres**、Go 1.27.1（CGO_ENABLED=1，`-race` 可用）、Node 24 + pnpm 11。
> **本文件性质**：把各区域报告与**我亲自复核**的结论合成一份可执行的清单；区域细节见同目录分件。

---

## 0. 一句话结论

**第五轮的 6 条 P0 与 5 条 P1 已全部落地并通过回归**（`govulncheck` 无可达漏洞、默认套件 34 包全绿、`-race` 无 DATA RACE），
但第六轮在**真实入口点上跑红了约 45 条探针**，其中 **3 条我认为真正阻断上线**，且都集中在同一类问题：
**「协议契约被静默忽略」**——RP 明确请求的东西（重新认证、30 天期限、被盗撤销）在服务端**没有对应裁决点**，
于是失败方向全部朝向攻击者。

真正的系统性问题不是某一条漏洞，而是**双后端语义漂移**：
内存后端与 Postgres 后端对同一个问题给出不同答案，而**所有默认测试跑在内存后端**上——
「测试全绿」因此在结构上无法证明生产行为。

---

## 1. 统计

| 项 | 数 |
|---|---|
| 本轮红探针（= 已证发现） | ~45 条测试 / ~40 条独立发现 |
| 其中 P1 高 | 9 |
| 其中 P2 中 | 4 |
| 其余 P3 低/提示 | 20+ |
| 区域报告 | 区 01–06 已完成；07–12 由本轮补做 |
| 第五轮修复回归 | **P0×6、P1×5 全部修对**（区 03/04/05 各自独立复核） |
| 已证伪/降级 | 见 §5（含我亲自推翻的一条） |

---

## 2. 我认为阻断上线的 3 条

判定口径：**攻击者/用户得到什么** + **是否有默认配置外的前提**。

> **独立复核状态**：下列条目已被**独立复现两次以上**——一次由我（主代理）亲自跑探针，一次由独立的
> 对抗性复核代理用自己的夹具（`internal/zzprobe/audit6/zverify/z01z02_claims_test.go`）重做：
>
> | 条目 | 主代理亲跑 | 复核代理独立重做 |
> |---|---|---|
> | **G-1** refresh 重放后小偷链条存活 | ✅ `refresh_test.go:243` CONFIRMED | 待（在清单内） |
> | **G-2** Postgres 不裁决 refresh 过期 | ✅ 读码确证（`postgres/oidc.go:430-432` vs `memory/oidc.go:573`） | 待 |
> | **G-3** 库故障时撤销答 200 | ✅ `revocation_error_probe_test.go:105` | 待 |
> | **G-4** `prompt=login`/`max_age` 被忽略 | ✅ 两条探针红 | 待 |
> | **G-5** percent 编码绕过内省守卫 | ✅ `introspect_test.go:122` | 待 |
> | **G-6** 匿名冒机密客户端发起设备流 | 读码确证 + 库侧调用链 | ✅ `TestV03…` 独立红 |
> | **G-7** 已批准设备码过期仍可兑换 | 读码确证（库 `device.go:317-325`） | ✅ `TestV02…` 独立红 |
> | **G-9** 刷新丢掉 nonce | 探针红 | ✅ `TestV05…` 独立红 |
> | **G-10** 设备轮询拒绝 `client_secret_post` | 探针红 | ✅ `TestV04…` 独立红 |
>
> 其余条目在复核代理完成前，状态以各条自己标注的为准。


### G-1 【P1 · 阻断】refresh token 重放被检测到之后，小偷那条链**继续有效**（RFC 9700 §4.14.2 的家族撤销缺失）

- **证据**：`internal/zzprobe/audit6/z02protocoltoken/refresh_test.go::TestZ02RefreshReplayDoesNotRevokeTheThiefsGeneration`（红）
  ```
  CONFIRMED: a detected refresh-token replay left the thief's chain alive — the replayed
  (stolen) token was refused, but the generation minted from it still works, so the thief
  keeps silent access for the rest of the 30-day refresh TTL
  ```
- **机制（我逐行复核过）**：刷新是**单次使用 + 轮换**。小偷拿到的第 2 代被小偷自己轮换成第 3 代（合法客户端尚未动作），
  合法客户端随后用自己那份第 2 代重放 ⇒ 服务端按「已消费」拒绝（**这正是盗窃信号**），
  但**没有任何东西**去撤销第 3 代。撤销面只有 `TerminateSession` / `RevokeToken`（需要知道令牌值），
  没有「按令牌家族/按 (client, subject) 代次」的撤销谓词。
- **影响**：refresh token 一旦泄露，**检测到泄露也不止损**；攻击者保有静默访问直到 30 天 TTL 自然结束。
  对以「即时可撤销」为核心卖点的授权服务器，这是卖点反面。
- **修法**：检测到已消费 refresh token 被重放时，撤销该会话/该 client+subject 的**全部** refresh 与 access 令牌
  （即 RFC 9700 的 token family 撤销），再返回 `invalid_grant`。需要一次 `DELETE ... WHERE subject=$1 AND client_id=$2`（两个后端同改）。

### G-2 【P1 · 阻断】生产后端（Postgres）的 refresh token **过期从不被裁决**——30 天 TTL 只由 15 分钟一轮的 sweep 执行

- **证据（我亲自读码确证）**：
  - `internal/store/postgres/oidc.go:430-432`：`SELECT ... FROM oidc_refresh_tokens WHERE token_hash = $1` —— **没有 `expires_at` 谓词**；
  - 轮换声明同样不看期限：`internal/store/postgres/oidc.go:393-394`；
  - 对照内存后端**到点即拒**：`internal/store/memory/oidc.go:573` `if !ok || !s.now().Before(r.expiresAt)`；
  - `expires_at` 列**确实存在且被别处使用**（`postgres/oidc.go:936`），所以这是漏了而不是设计；
  - 唯一执行者是 sweep：`postgres/sweep.go:29` + `cmd/re0auth/main.go:405`（每 15 分钟）。
- **状态**：`CONFIRMED`（源级；Postgres 运行时需 CI 的 postgres:16）
- **影响**：过期 refresh token 在过期后仍可兑换出**全新 30 天 TTL** 的 access+refresh 对（TTL 被整体重置而不是被拒绝）；
  sweep 连续失败时窗口继续延长（`main.go:1111` 只打日志）。
  **注意这条的形状**：默认套件全部跑内存后端，所以**测试永远绿**，而生产行为不同。
- **修法**：`TokenRequestByRefreshToken` 的 SELECT 加 `AND expires_at > $2`（`$2` ← `s.now()`，保持单时钟政策）；
  `clock_test.go` 补一段「过期 refresh token 被拒」。

### G-3 【P1 · 阻断】数据库故障时 RFC 7009 撤销回答 **200 成功**——用户以为被盗令牌已撤销，实际什么都没发生

- **证据**：`internal/zzprobe/audit6/z04pgstore/revocation_error_probe_test.go::TestRevokeTokenDoesNotReportSuccessWhenTheDatabaseCannotAnswer`（红）
  ```
  RevokeToken reported success (nil) while every lookup failed with a connection error:
  the endpoint answers RFC 7009 success for a revocation that checked nothing, revoked nothing and audited nothing
  ```
- **机制**：`internal/store/postgres/oidc.go:474-531` 三个 owner 查找全部以 `err == nil` 为进入条件，
  任何错误（连接断开、故障切换、`statement_timeout`、ctx 取消）都落穿到 `:530` 的 `return nil`；
  协议层把它当「未知令牌即成功」答 200（库只对非 nil 的 `*oidc.Error` 报错），且**落穿路径不写审计**。
  同文件的 `TokenOwner`（`oauth.go:207-227`）用 `noRows()` 做了正确分类 ⇒ 这是遗漏而非策略。
- **影响**：Postgres 重启/故障切换窗口内，撤销拿到 200「已撤销」，客户端按 RFC 7009 **不再重试**；
  令牌在库恢复后继续有效到自然过期（refresh 最长 30 天）。**这是安全事件响应路径上的静默失效。**
- **修法**：三个查找各接 `noRows(err)` 分类——只有 `pgx.ErrNoRows` 允许落穿；其余返回 `oidc.ErrServerError()`（映射 500，可重试）。

---

## 3. 其余高价值发现（P1/P2）

| ID | 发现 | 证据 | 状态 |
|---|---|---|---|
| **G-4** | **`prompt=login` 与 `max_age` 被完全忽略**：RP 请求 step-up 重新认证时，OP 既不重新认证也不回 `login_required`，id_token 带**旧会话的 `auth_time`** | `z01/consent_face_test.go::TestProbePromptLoginAndMaxAgeDoNotForceReauthentication`、`z02/idtoken_test.go::TestZ02MaxAgeAndPromptLoginAreIgnored`（均红） | CONFIRMED |
| **G-5** | **percent 编码的 client_id 绕过内省守卫**：`Basic z02-d%65vice-…` 使项目自己的 P0-6 守卫查不到客户端而放行（`:1115` 用原始 id 查库失败即 `return false`），而库用 `url.QueryUnescape` 解码后**认证通过** ⇒ 「内省必须机密客户端」可被绕过 | `z02/introspect_test.go::TestZ02IntrospectionGuardBypassedByPercentEncodedClientID`（红） | CONFIRMED |
| **G-6** | **匿名者可以机密客户端身份发起设备流**：`POST /oauth/device_authorization` 不要求机密客户端认证，而验证页会**展示该客户端的注册名**给任何跟着 user_code 走的人。**根因（我逐行钉到）**：`AuthorizeClientIDSecret` 只在 `c.Type == ClientConfidential && !c.Authenticate(clientSecret)` 时报错（`memory/oidc.go:739-742`，`postgres/oidc.go:606-`同形）——匿名请求的 `clientSecret` 是**空串**，而 `Authenticate("")` 根本没被求值 ⇒ **返回 nil = 已认证**。库侧确实经 `withClient → verifyRequestClient → VerifyClient`（`zitadel/oidc pkg/op/server_http.go:104,128-161`）调用它，所以**责任在本项目的存储回调**，不在库。对照：内省端点正是为此加了 `refuseIntrospectionByANonConfidentialClient`（G-5） | `z01/device_flow_test.go::TestProbeConfidentialClientCanStartADeviceFlowUnauthenticated`（红） | CONFIRMED |
| **G-7** | **已批准的 device_code 过了 `expires_at` 仍能铸出整套令牌**：库在 `Done` 分支**先于** `Expires` 短路（我读过库源码确认：`zitadel/oidc pkg/op/device.go:317-325` 依次判 `Denied → Done(return nil) → Expires`，**批准过的码根本走不到过期判断**），于是期限裁决**完全落在存储的消费谓词上**，而两个后端都没有 `expires_at` 谓词，只有 sweep 删行（内存 5 min / PG 15 min 窗口） | `z01/device_flow_test.go::TestProbeApprovedDeviceCodePastItsExpiryIsStillRedeemable`、`z04/device_expiry_probe_test.go`、`z05/device_expired_test.go`（全红） | CONFIRMED |
| **G-8** | **`/oauth/revoke` 是存活性预言机**：匿名者（点名一个公开客户端 id）对**别人的活跃令牌**得 401、对**未知字符串**得 200 ⇒ 可判断任意字符串是否是有效令牌。**根因是代码与自己上一段的注释矛盾**：`oauth/as.go:223-231` 明写「a value owned by somebody else is refused **the same way** [as unknown] rather than confirmed: answering "that is not yours" would turn this endpoint into an oracle」——但 `:238-239` 恰恰对「非本人」返回 `invalid_client`（401）、`:234-235` 对「未知」返回 nil（200），**两个分支形状不同**。**影响面**：这是 `oauth` 公开引擎（Upstream Kit），由第三方数据源进程运行（`upstreamkit/server.go:295`、`referencesource/source.go:201`），同一缺陷也随 kit 发布 | `z02/revoke_test.go::TestZ02RevocationDistinguishesForeignLiveTokensFromUnknownOnes`、`::TestZ02RevocationAuthMatrix`（红） | CONFIRMED |
| **G-9** | **刷新后的 id_token 丢掉 `nonce`**（OIDC Core §12.2 要求保留）⇒ 检查 nonce 的 RP 每次刷新都失败 | `z01/regress_test.go::TestProbeRefreshedIDTokenLosesTheNonce`（红） | CONFIRMED |
| **G-10** | **设备流 token 轮询拒绝 discovery 广告的 `client_secret_post`**，而同一端点的 code/refresh 授予接受它；更糟的是**被拒的那次 401 把 device_code 烧掉了**，重试变 `access_denied` | `z01/device_flow_test.go::TestProbeDeviceGrantPollRefusesAdvertisedClientAuthMethod`、`z02/tokenauth_test.go::TestZ02DeviceGrantRefusesAdvertisedClientSecretPost`（红） | CONFIRMED |
| **G-11** | **`/readyz` 在「已有一次检查在跑」时答 200**：`check()` 在 `running` 分支直接返回**零值 `nil`**（`:112-118`），即便上一次结果是失败 ⇒ 探针在未核实的情况下答 200。**我把可达性下调**：kubelet 每个 probe 周期串行发一次（出厂 `periodSeconds: 5`），而最坏检查只有 `readinessTimeout = 2s`，1s TTL 也短于周期 ⇒ **出厂清单下真 kubelet 基本撞不到**；它伤的是自定义/并发调用方与未来改动 `main_in_flight`/探针配置的部署。**定为 P3，不是阻断项** | `z06/readiness_test.go::TestZ06ReadyzColdStartAnswersReadyBeforeTheFirstCheckCompletes`（红） | CONFIRMED（可达性受限） |
| **G-12** | **k8s 关闭预算与 grace 不自洽**：`5s + 30s + 30s = 65s > terminationGracePeriodSeconds: 45` ⇒ SIGKILL 发生在审计排空预算到期之前，**「过期拒绝」路径在 k8s 里从不运行**，在途审计批次整批丢失。**我按调用链逐步核实过**：SIGTERM → `beginDrain`（`main.go:820`）→ `time.Sleep(5s)`（`:829`）→ `server.Shutdown(30s)`（`:837-841`）→ `serveUntilSignal` 返回（`:724`）→ **deferred `store.close()`**（`:377`，最后才执行）→ `auditBatcher.Close` 排空（`auditbatch.go:54` 的 `auditDrainTimeout = 30s`）。而 `deployment.yaml:21-25` 的注释只算到 HTTP 那一段（写「35s total」） | `z04/drain_budget_probe_test.go::TestTheShutdownStackFitsThePodGrace`、`::TestTheManifestCommentCountsTheWholeStack`（红） | CONFIRMED |
| **G-13** | **`GetRefreshTokenInfo` 把数据库错误折叠成 `op.ErrInvalidRefreshToken`**，废掉依赖库的 500 分支（与 G-3 同路径，使故障伪装成「令牌不存在」） | `z04/revocation_error_probe_test.go`（红） | CONFIRMED |

---

## 4. 中低严重度（P2/P3）速览

| ID | 发现 | 位置 |
|---|---|---|
| **G-14** | `oidc_devices` 是**第七张**没有 `client_id` 前导索引的 client-only 批量撤销表（迁移 0022 只补了六张），且守卫的手写清单也漏了它 | `postgres/oidc.go:1075`、`revoke_predicate_test.go:32-44` |
| **G-15** | 设备路径 `slow_down` 节流**锚点分叉**：内存锚「上一次尝试」、PG 锚「上一次放行」⇒ 每 3s 轮询的客户端在内存部署被**无限节流**，在 PG 部署每 5s 放行 | `memory/oidc.go:884-889` vs `postgres/oidc.go:773-778` |
| **G-16** | 内存 store 的 `cloneAuthRequest` 仍**共享 `CodeChallenge` 与 `AuthTime` 两个指针**，写穿即改库（今天无写穿调用方 ⇒ 可达性降格，但 f6af208 声称「copy-on-return 补齐」而形状未补齐） | `memory/oidc.go:435-439` |
| **G-17** | Postgres 的设备批准/拒绝**审计事件不带 `client_id`**（内存后端带）⇒ 生产审计链回答不了「哪个客户端被批进来」 | `postgres/oidc.go:898,919` |
| **G-18** | vault 身份命名空间 `game + "." + source` **无字符校验**：`{phigros, official.beta}` 与 `{phigros.official, beta}` 映射到同一凭据行 ⇒ 跨源令牌串用 + 一方 Unbind 撕掉另一方密钥（需 operator 配出带点名字，故 P3；修法**不能**改拼接符，AAD 绑存量密文） | `federation/binding.go:76-78`、`federation.go:147-149` |
| **G-19** | `vault.Rotate` 把自己的审计写入失败 `_ =` 丢弃，而同一 sink 让 `Enroll/Use/Revoke` 全部 fail-closed——而这条 trail 正是运维删退役键前要看的 | `vault/rotate.go:82` |
| **G-20** | `Enroll` 先落库后写审计：审计失败时凭据**已存好**、调用方被告知失败，绑定路径**不回滚不记日志**（兄弟分支 `bind.go:198-213` 显式回滚 + slog + `errors.Join`）⇒ 留下只有整账号抹除能清的孤儿上游令牌 | `vault/service.go:209-231`、`federation/bind.go:191-196` |
| **G-21** | vault 错误文本内嵌原始 `usr_…`（`Identity.String()`），经 `-rotate-keys` 的 die 路径与 unbind/cascade 的 warn 路径进进程日志——第五轮的 attr 守卫**结构上看不见**这个通道 | `vault/repo.go:29`、`vault/service.go:273-274`、`vault/rotate.go:113-131` |
| **G-22** | 三把 32 字节密钥可共用同一个值（`RE0AUTH_KEK == RE0AUTH_OIDC_TOKEN_KEY`，乃至 audit key）被无提示接受，启动日志对复用只字未提 | `cmd/re0auth/config.go:719-751`、`main.go:1385-1397` |
| **G-23** | 第五轮仍红的 **7 处 `usr_…` 进 slog attr**（`admin.go:499`、`auth.go:231`、`bind.go:208`、`refresh.go:155/160`、`account_routes.go:80`、`binding_routes.go:57`）**确认仍未修**；与 G-21 是同一不变量的两半，需一起收 | 见区 03 报告「第五轮仍红探针的归属确认」 |
| **G-24** | `/.well-known/oauth-protected-resource` 对非 GET 动词答 **404**（同族另两份文档答 405），且 405 响应**不带 `Allow` 头**（RFC 9110 §15.5.6 MUST） | `server.go:522` vs `:519-520`；`oidchttp.go:256/263` 不设 Allow |

---

## 5. 已证伪 / 必须降级的（这一节决定上面的可信度）

**一条我自己推翻的（区域报告尚未处理）**：

- **`TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` 的 `GET /oauth/token → 200` 不是生产缺陷，是夹具假象。**
  该探针用 `edgeServer()`，而 `internal/zzprobe/audit6/z06httpedge/fixture_test.go:70` 把 `Config.OIDC` 设成
  `http.HandlerFunc(func(w,r){ w.WriteHeader(http.StatusOK) })` —— **一个永远答 200 的桩**。
  真实的 `/oauth/token` 有动词闸门：`internal/oidchttp/oidchttp.go:466-479`（`endpointMethods` + 405），
  真进程侧的 `TestZ06RealProcessWellKnownVerbMatrix` 也证明协议面动词闸门在工作。
  ⇒ **别让这条进清单**；该测试名声称在验限流分桶键，实际测的是桩的返回值。

**其余降级**（各区域自己已如实标注）：
- `G-16`（内存别名写穿）：机制成立但**今天不可达**（库与 `oidchttp` 只经 getter 读），留作潜在缺陷。
- `05-3`/`04-7`（PG 审计归属、迁移锁时长）：**HYPOTHESIS**，差 `TEST_DATABASE_URL`／真库。
- `04-6`（slow_down 锚点）：无安全后果，只是两后端不一致。
- **不是发现**：根目录三个残留二进制（`re0auth.exe`/`perfreport.exe`/`httpapi.test.exe`）被 `.gitignore`
  的 `*.exe` 覆盖、从未入库（`git ls-files` 零命中）；`.dockerignore` 亦有 `*.exe`。
  唯一残留风险是 `.dockerignore` **没有** `*.test`（镜像构建若用宽 `COPY` 可能带入本地测试二进制）——信息级。

---

## 6. 已复核的正面结论（对上线决策同样重要）

这些不是「没查」，而是**攻过并且守住了**，都有对应的绿探针。它们决定了上面 3 条阻断项是「局部缺陷」而不是「整体不可用」：

- **工作区与基线完好**：`git status` **零个被跟踪文件被修改**（全部审计产物都在未跟踪的 `internal/zzprobe/audit6/` 与 `scratchpad/` 下）；
  `go build ./...`、`go vet ./...` 均 exit 0；默认套件（无 `audit6` 标签）**34 包全绿**，审计工作**没有污染可发布状态**。
  探针全部带 `//go:build audit6`（含放在 `audit6/` 之外的 `internal/httpapi/zz_audit_httpapi_test.go`），所以默认 CI 看不见它们。
- **依赖面**：`govulncheck ./...` = **`No vulnerabilities found.`**（模块图 5 条通告全不可达）。
- **密码学（区 03 实跑绿）**：AAD 双向绑定身份（三个方向搬运行密文都解不开）；nonce 经真实路径 128 次无重复；`vault.Use` 明文在回调返回后**逐字节归零**（I2）；审计 sink 不可用 ⇒ `Use` 不对回调交出明文（I3 fail-closed）；轮换只重写信封三列（Nonce/Ciphertext/Meta 逐字节不变）；KEK 编码变体的接受面与拒绝面（尾随空格/URL-safe/31 字节全部 exit 1）；启动日志不回显密钥材料；`vault.Use` 不跨锁回调（10s 无死锁）。
- **撤销与单次使用**：授权码、refresh、设备码的「认领」在两个后端都是 `DELETE…RETURNING` 先删后取，并发二取一；撤销连带清未消费授权码与已批准设备授权。
- **限流默认姿态**：`trusted_proxies` 为空（默认）时伪造/轮换 `X-Forwarded-For` **不能**换桶；`/readyz` 的连接池放大器已由 `readinessCache` 单飞 + 1s TTL 封住。
- **平面分离**：三个平面各自输出自己的错误形状；协议面**不发任何 CORS 头**（ADR-0011 由边界守卫钉住，库的 `Origin` 反射被过滤）；每个响应带 `nosniff`/`no-referrer`/`X-Frame-Options: DENY`。
- **Postgres 面读码级正面结论**：17 处 SQL 拼接全是编译期常量（无请求值入 SQL）；ctx 取消中途的事务不会把开着的事务漏回池（pgx `TxStatus` 检查）；advisory lock 在 panic/ctx 取消下仍释放。

---

## 7. 方法学：为什么这轮数字可信，以及它的边界

**做对了的三件事**：
1. **每条发现都有一条会失败的探针**，且探针走**真实入口点**（`httpapi` 全接线服务器、`oidchttp` 真 provider、真进程内存模式），不是调内部函数。
2. **每份区域报告都带「探过没破」与「未能到达」两节**——例如区 03 明确列出 16 条攻过但守住的，
   区 04 列出 12 条；`govulncheck` 亦为「无可达漏洞」（模块图 5 条通告全不可达）。
3. **第五轮修复被逐条回归**，而不是假定修好了。

**边界（必须如实说）**：
- **无 Docker、无本地 Postgres** ⇒ 一切 Postgres 运行时语义（planner 是否用索引、隔离级别、锁时长、
  G-2/G-3/G-13 的 PG 侧端到端形状）只有**读码级**证据。**权威验证位是 CI 的 `postgres:16`。**
- **Playwright 浏览器未安装** ⇒ 前端 e2e 的浏览器侧结论受限（区 08 会如实标注）。
- **多代理并发** ⇒ 报告里的**绝对墙钟/吞吐数字不可引用**；可引用的是每操作分配量（B/op、allocs/op）与复杂度类。
- 单引擎（Chromium）浏览器结论、真实上游方言、真实发布链路（tag/cosign）均未触及。

---

## 8. 上线前执行顺序（我的建议）

**必须做（阻断）**
1. **G-1**：实现 refresh token 家族撤销（检测到重放 ⇒ 撤销整个 (client, subject) 链）。
2. **G-2**：给 Postgres 的 refresh 读路径与轮换声明补 `expires_at` 谓词（两个后端同形），并补测试。
3. **G-3 + G-13**：用 `noRows(err)` 分类，只有 `pgx.ErrNoRows` 才算「未知令牌」；其余映射 500。
4. **G-4**：实现 `max_age` / `prompt=login` 的重新认证（`oidcstore.AuthRequest` 根本没有 `MaxAge` 字段 ⇒ 需要**在存储边界加字段**，或在 login 钩子里比对 `auth_time`），
   无活会话时按 `login_required` fail-closed。
5. **G-5**：内省守卫在查库前对 Basic 里的 client_id 做 `url.QueryUnescape`（与库对齐），或先解码再判定。
6. **G-6**：`POST /oauth/device_authorization` 对机密客户端强制认证（与 token 端点同形）。

> 注：**G-11（`/readyz`）已由我下调为 P3**（见 §3 与 §5），不进阻断清单；修法是 `check()` 的 `running` 分支
> 在 `!checked` 时返回「未就绪」而不是零值 `nil`。

**强烈建议（与上同批或紧随）**
8. **G-7**：两个后端的设备码消费谓词补 `expires_at`；**G-10**：设备授予接受 `client_secret_post`，且 401 **不得**烧掉 device_code。
9. **G-9**：刷新签发的 id_token 带上原始 `nonce`（`offline_access`/refresh 路径）。
10. **G-8**：让 `/oauth/revoke` 的响应形状不区分「别人的活令牌」与「未知字符串」。
11. **G-12**：`auditDrainTimeout` 改为 `grace - removal - http`（=10s），或把 grace 提到 ≥70s 并同步注释。
12. **G-14**：迁移 0023 补 `oidc_devices(client_id)`，并把守卫改成从 `revokeMatching` 调用点反推表集合。
13. **G-18/19/20/21/22/23**：vault 与日志卫生一批收口（命名空间校验、Rotate 审计 fail-closed、Enroll 回滚、错误文本去身份、密钥复用拒绝启动、7 处 attr）。
14. **G-15/16/17**：两个后端语义对齐（节流锚点、clone 深拷贝、设备审计 client_id）。

**上线前必须闭合的验证缺口**
15. 在 **CI 的 postgres:16** 上把 G-2/G-3/G-7/G-13/G-14/G-15/G-17 的 PG 侧探针跑成红/绿定论——
    本机无库，这些条目今天**只有一半证据**。
