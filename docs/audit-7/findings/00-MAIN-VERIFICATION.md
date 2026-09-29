# 主代理独立复核日志（第七轮）

> 审计对象 `C:\git\r0semi`，HEAD = `bf81b2a`，工作区被跟踪文件零改动。
> 本文件记录**主代理亲自读码/亲自跑探针**得到的结论，用于给区域报告定锚。
> 区域报告见同目录 `<区号>-*.md`，复核报告见 `<区号>-VERIFIED.md`。

## 0. 基线修复（开工前必须做的一件事）

- **事实**：开工时 `go build ./...` / `go vet ./...` / `go test ./...` **全红**，原因是一个
  **未被 git 跟踪**的遗留探针 `internal/store/postgres/zz_audit_keyrotation_test.go:9` 含
  **非法 UTF-8**（`E3 80 3F`，本应是 `E3 80 8D`，即 `」` 的最后一字节被替换成 `?`）。
- **为什么严重**：Go 扫描器在**应用 `//go:build` 约束之前**就要解码整个文件，
  所以**一个被 build tag 排除的文件里的非法 UTF-8 能让整个模块编译失败**
  （这也正是第五轮简报里记过的事故形状）。
- **处置**：字节级修复那一处（`E3 80 3F` → `E3 80 8D`），未删除文件、未改任何被跟踪文件。
  修复后 `go build`/`go vet` exit 0，默认套件 **34 包全绿**。
- **归类**：过程性缺陷（不是产品漏洞，因为该文件未被跟踪、不会进 CI）。但它解释了为什么
  「上一轮结束时全绿」与「本轮开工即全红」可以同时为真。

## 1. 我亲自跑过的第六轮探针（红 = 证据，全部在本机实测）

命令：`go test -tags audit6 -count=1 -v ./internal/zzprobe/audit6/<区>/`

### 区 02（令牌面）
| 探针 | 结果 | 对应第六轮编号 |
|---|---|---|
| `TestZ02RefreshReplayDoesNotRevokeTheThiefsGeneration` | **FAIL** | G-1 |
| `TestZ02MaxAgeAndPromptLoginAreIgnored`（prompt=login / max_age=1 / max_age=0 三例） | **FAIL** | G-4 |
| `TestZ02IntrospectionGuardBypassedByPercentEncodedClientID` | **FAIL** | G-5 |
| `TestZ02RevocationDistinguishesForeignLiveTokensFromUnknownOnes` | **FAIL** | G-8 |
| `TestZ02RevocationAuthMatrix` | **FAIL** | G-8 |
| `TestZ02DeviceGrantRefusesAdvertisedClientSecretPost` | **FAIL** | G-10 |
| `TestZ02IDTokenClaimsAcrossGrants` | **FAIL** | G-9 相关 |
| `TestZ02RefreshReplayAndExpiry` / `TestZ02IntrospectionRefusesPublicClients` / `TestZ02RefreshCannotEscalateScope` / `TestZ02UserinfoRequiresALiveAccessToken` / `TestZ02CodeExchangeGuardsHold` / `TestZ02GrantTypeDispatchRefusesUnadvertised` | PASS | 守住 |

### 区 04（Postgres store）
| 探针 | 结果 | 对应 |
|---|---|---|
| `TestAnApprovedDeviceCodeCannotBeRedeemedAfterItsExpiry` | **FAIL** | G-7 |
| `TestThePostgresDeviceConsumeClaimChecksExpiry` | **FAIL** | G-7 |
| `TestTheShutdownStackFitsThePodGrace` / `TestTheManifestCommentCountsTheWholeStack` | **FAIL** | G-12 |
| `TestThePollThrottleAnchorsTheSamePollInBothEngines` | **FAIL** | G-15 |
| `TestRevokeTokenDoesNotReportSuccessWhenTheDatabaseCannotAnswer` | **FAIL** | G-3 |
| `TestRevokeTokenClassifiesOnlyNoRowsAsUnknownToken` | **FAIL** | G-3 |
| `TestGetRefreshTokenInfoDistinguishesDBFailureFromUnknownToken` | **FAIL** | G-13 |
| `TestEveryClientScopedRevokeTableHasALeadingClientIndex` / `TestTheClientScopedRevokeGuardCoversTheDerivedTableSet` | **FAIL** | G-14 |
| `TestEverySQLDatabaseClockUseIsReviewed` / `TestTheClockPolicyHasNoSecondUnjudgedDeadlineWriter` | PASS（见 §3） | — |

### 区 06（HTTP 边界）
| 探针 | 结果 | 对应 |
|---|---|---|
| `TestZ06ReadyzColdStartAnswersReadyBeforeTheFirstCheckCompletes` | **FAIL** | G-11 |
| `TestZ06RealProcessWellKnownVerbMatrix` / `TestZ06WellKnownVerbMatrixCoversEveryDocument` | **FAIL** | G-24 |
| `TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` | FAIL，但**第六轮已自证是夹具假象**（夹具把 `Config.OIDC` 设成永远答 200 的桩）⇒ **不进清单** | — |
| 其余（body limit、压缩、探针端点、不计 header 上限、Slowloris 真实进程） | PASS | 守住 |

### 区 01（协议授权）
| 探针 | 结果 | 对应 |
|---|---|---|
| `TestProbePromptLoginAndMaxAgeDoNotForceReauthentication` | **FAIL** | G-4 |
| `TestProbeApprovedDeviceCodePastItsExpiryIsStillRedeemable` | **FAIL** | G-7 |
| `TestProbeConfidentialClientCanStartADeviceFlowUnauthenticated` | **FAIL** | G-6 |
| `TestProbeDeviceGrantPollRefusesAdvertisedClientAuthMethod` | **FAIL** | G-10 |
| `TestProbeRefreshedIDTokenLosesTheNonce` | **FAIL** | G-9 |
| `TestProbeASuccessfulCodeExchangeWritesAConsentDenyAuditEvent`、`TestProbeProtocolOnlyScopesCannotBeApproved`、`TestProbeProtocolOnlyDeviceFlowCannotBeApproved`、`TestProbePromptNoneWithASessionRendersTheConsentUI` | **FAIL** | 区 01 自报 |
| 六个 `TestRegression*`（id_token sub、畸形参数、redirect_uri 变体、PKCE、码单次使用、request 参数） | PASS | 第五轮修复守住 |

## 2. 我亲自读码确证/更正的技术机制

### V-01 `G-2` 成立（读码级，我自己核过）
`internal/store/postgres/oidc.go:430-436` 的 `TokenRequestByRefreshToken` SELECT **没有 `expires_at` 谓词**；
对照 `internal/store/memory/oidc.go:573` **有**（`!s.now().Before(r.expiresAt)`）。
轮换声明（`postgres/oidc.go:392-401` 的 `DELETE FROM oidc_refresh_tokens WHERE token_hash = $1`）同样不看期限。
⇒ 生产后端上，过期 refresh token 仍能换出**整套新令牌并把 TTL 重置为 30 天**；唯一执行者是 15 分钟一轮的 sweep。

### V-02 `G-3` 成立（读码级）
`internal/store/postgres/oidc.go:474-531`：三个属主查找（`:478`、`:499`、`:514`）全部以 **`err == nil`** 为进入条件，
任何错误（连接断开、故障切换、`statement_timeout`、ctx 取消）都落穿到 `:529-530` 的 **`return nil`**
⇒ 协议层按 RFC 7009「未知令牌即成功」答 **200**，且落穿路径**不写审计**。
同文件 `TokenOwner`（`oauth.go:207-227`）用 `noRows()` 做了正确分类 ⇒ 这是遗漏，不是策略。

### V-03 `G-6` 成立，但**根因被第六轮写错了**（重要更正）
第六轮把它归因为「本项目 `AuthorizeClientIDSecret` 对空 secret 不求值」。
**实际根因在库里**：
- `zitadel/oidc v3.51.3 pkg/op/client.go:155-194` 的 `ClientIDFromRequest` 返回
  `(clientID, authenticated, err)`：Basic 成功 ⇒ `authenticated=true`；**没有 Basic 头**时
  回退到表单里的**未认证** `client_id` 并返回 `authenticated=false`。
- `pkg/op/device.go:138` 的 `ParseDeviceCodeRequest` 把它**丢弃**：`clientID, _, err := ClientIDFromRequest(r, o)`。
- 于是 `POST /oauth/device_authorization` 对**任何**（含机密）客户端都不要求认证。
  本项目的 `AuthorizeClientIDSecret`（`memory/oidc.go:731-743`）**根本不在这条路径上**。
- **修法必须落在本项目边界**（`internal/oidchttp`）：在把请求交给库之前，对机密客户端强制认证。
  第六轮给的修法方向（“与 token 端点同形”）仍然对，但**不能**靠改 `AuthorizeClientIDSecret` 修。

### V-04 `G-7` 成立：`Done` 短路发生在过期判断之前（两面都缺谓词）
- 库：`pkg/op/device.go:301-327` 的 `CheckDeviceAuthorizationState` 依次
  `Denied`（317）→ **`Done` 直接 `return state, nil`（320-322）**→ `time.Now().After(state.Expires)`（323-325）。
  **已批准的码根本走不到过期判断。**
- Postgres 消费谓词 `internal/store/postgres/oidc.go:749-755`：
  `DELETE ... WHERE device_code_hash=$1 AND client_id=$2 AND done=true AND denied=false` —— **无 `expires_at`**。
- 内存消费谓词 `internal/store/memory/oidc.go:891-900`：`if d.done && !d.denied { delete; return st, nil }` —— **同样无期限判断**。
- **两端对称的一点**：*批准*那一侧**都**判期限（内存 `:1094`、Postgres `:880` 的 `expires_at > $3`）
  ⇒ 精确的形状是「**批准判期限、消费不判期限**」。
- ⇒ 过期时间在「批准」与「哨兵/sweep 删行」之间的窗口内**完全不被裁决**。

### V-05 `G-10` 机制确证：设备授予与 code/refresh 走的是**两套客户端认证**
- 令牌端点分派：`pkg/op/token_request.go:46-79`；device 分支在 `:70-74`。
- 设备轮询用 `ClientIDFromRequest`（`device.go:217`，**只认 Basic 与 JWT assertion**），
  再用 `clientAuthenticated != IsConfidentialType(client)`（`device.go:235`）判机密客户端。
- 于是 `client_secret_post` 在 device 授予上必然 401，而 discovery 广告它是支持的；
  且该 401 发生在消费谓词**之后**（`CheckDeviceAuthorizationState` 在 `:226` 已先跑）⇒ device_code 被烧掉。

## 3. 我新发现的一条（不在第二至六轮任何清单里）

### N-01 两个后端的 sweep 都用一个**假的**不变量为自己开脱
- Postgres：`internal/store/postgres/sweep.go:10-13`
  > “an expired row is one a lookup already refuses… A lookup does refuse these — the OP checks a token's deadline…”
- 内存：`internal/store/memory/oidc.go:935-944`
  > “A lookup already refuses an expired record… A record is removed only once a lookup would already refuse it,
  > so a sweep can never revoke something still in use.”
- **实测/读码反例**：
  - Postgres `oidc_refresh_tokens` 的读路径（V-01）**不判期限**；
  - 两个后端的**设备消费**路径（V-04）**都不判期限**。
- **影响**：这段注释是「按期限删行是安全的」这一论证的全部依据；它对**大多数**表成立，
  但对上面两处不成立 ⇒ 审阅者会据此认为「过期即不可用」，从而把 G-2/G-7 的窗口判为无风险。
  删除方向本身仍然安全（删除比读取更严），**不安全的是被它掩盖的读路径**。
- **修法**：把两处读路径补上期限谓词（= G-2/G-7 的修法），并把注释改成
  「除 refresh 读路径与设备消费路径外，lookup 到点即拒」并加一条守卫测试：
  对**每一张** sweep 表断言「过期行在 sweep 之前就已经被读路径拒绝」。
- **严重度**：P2（文档/不变量与实现不符，且掩盖了两条 P1）。**状态**：CONFIRMED（读码级 + 上表红探针）。

### N-02 刷新令牌路径的「数据库故障」被**无条件**折叠成 `400 invalid_grant`，且**在 store 层修不掉**
- **本项目两处都吞掉原始错误**：
  - `internal/store/postgres/oidc.go:434-436`：`if err := ...Scan(...); err != nil { return nil, errors.New("postgres: invalid refresh token") }` —— **连 wrap 都没有**；
  - `internal/store/memory/oidc.go:574`：`return nil, errors.New("memory: invalid refresh token")`。
  两者对 `pgx.ErrNoRows`（令牌确实不存在/已轮换）与「连接断开、故障切换、`statement_timeout`、ctx 取消」**给出同一个错误**。
- **库把它变成 400**：`zitadel/oidc v3.51.3 pkg/op/token_refresh.go:144-152` 的 `RefreshTokenRequestByRefreshToken`
  **无条件** `return nil, oidc.ErrInvalidGrant().WithParent(err)` —— **任何** store 错误都是 `invalid_grant`（400）。
- **为什么这不是 G-13 的重复**：G-13 走的是 `token_revocation.go:47-51`，那里库**会**检查
  `errors.Is(err, ErrInvalidRefreshToken)`，否则回 `ErrServerError`（500）⇒ 在**撤销**路径上
  「store 正确分类」**能**修好语义。而**刷新**路径上 `token_refresh.go:150` 是硬编码的，
  **本项目改 store 也换不来 500** ⇒ 两条同根但**可修性不同**，修法与归因都必须分开写。
- **影响**：Postgres 故障/切换期间，**合法**的 refresh token 对客户端表现为「已失效」（`invalid_grant`）。
  按 OAuth 最佳实践，客户端会**丢弃 refresh token 并强制用户重新登录**；而库恢复后该令牌其实仍然有效。
  刷新是所有长会话的**热路径**，所以这是可被一次短暂数据库抖动放大的用户可见故障，
  并且**没有任何指标/日志**把它与「令牌真的无效」区分开。
- **修法（最小可行）**：① store 先做分类（`pgx.ErrNoRows` → 无效，其余 `fmt.Errorf("...: %w", err)` 保留）；
  ② 因为库仍然会把它变 400，所以必须在**本项目边界**补一条可观测性：
  在 `internal/httpapi`/`oidchttp` 的 `/oauth/token` 前置对 refresh 授予做「store 分类错误」的计数与告警，
  或直接依赖 `readyz`/池健康在故障时把实例摘掉；③ 把「库在该路径硬编码 invalid_grant」作为**依赖限制**
  记入 `docs/dependencies.md`（与 G-13 同节）。
- **严重度**：P2（可用性/错误语义；安全上是 fail-safe 方向，但会造成大范围强制重登与令牌被客户端丢弃）。
- **状态**：CONFIRMED（读码级；两侧代码路径都已逐行核对）。

### N-03 第五轮 P2-1 的修复只覆盖了 OP store；**公开引擎 `oauth/` 仍然完全静默地吞掉审计失败**
- **对照**（我逐行读的两侧）：
  - OP store（两个后端）在 P2-1 之后**会打日志**：
    `internal/store/postgres/oidc.go:129-140` 与 `internal/store/memory/oidc.go:323-334`
    都是 `if err := s.audit.Record(...); err != nil { slog.Error("oidc audit record failed", ...) }`，
    注释还写明「an audit record that vanishes without a trace is the one outcome this project does not accept」。
  - 公开引擎：`oauth/as.go:338-346` 的 `record` 是
    `_ = s.audit.Record(ctx, audit.Event{...})` —— **无日志、无指标、无返回值**，调用方**无法知道**审计丢了。
    它被 `oauth/as.go` 的签发/撤销等路径使用。
- **可达性（我核过，避免夸大）**：`grep` 显示 `cmd/re0auth/main.go` **不引用** `wiring.`/`KeyAS`/`oauth.Service`
  ⇒ **Re0Auth 自己的 OP 进程不跑这个引擎**；它服务的是 **Upstream Kit**（第三方数据源进程，
  `upstreamkit/server.go:51` 的 `OAuth oauth.Service`）与演示源 `cmd/referencesource`。
- **影响**：第三方数据源按 Kit 部署后，其 AS 的审计事件（含撤销）在 sink 故障时**静默丢失**，
  运维看不到任何信号——这正是 P2-1 认定「不可接受」的那个形状，只是发生在另一个引擎里。
  对 Re0Auth 自己的上线**不构成阻断**（OP 路径已修），但它是**随 Kit 一起发布的缺陷**，
  且 P2-1 的修复清单漏了它。
- **修法**：`oauth/as.go` 的 `record` 照抄 OP store 的形状（`slog.Error` + 计数指标），
  并把 P2-1 的守卫扩到 `oauth/` 包的调用点。
- **严重度**：P3（对 Re0Auth 上线无阻断；对 Kit 使用者是审计完整性缺口）。**状态**：CONFIRMED（读码级）。

### V-06 `G-12` 成立，算术与调用链我逐行核过
- `cmd/re0auth/main.go:724` → `serveUntilSignal(ctx, shutdownTimeout=30s(:127), endpointRemovalWait=5s(:137), ...)`；
  内部顺序是 `beginDrain()`(:820) → `time.Sleep(5s)`(:829) → `Shutdown(drainCtx)`(:837-849)。
- **审计排空在 HTTP 排空之后**：`store.close()` 是 `main.go:377` 的 **deferred**，只在 serveUntilSignal 返回后执行，
  它进而调用 `auditBatcher.Close`，其预算是 `auditbatch.go:54` 的 `auditDrainTimeout = 30s`。
- `deploy/k8s/base/deployment.yaml:22-26` 的注释与配置：`terminationGracePeriodSeconds: 45`，
  而注释只算了 HTTP 那一段（“5s + 30s = 35s total”）。
- **最坏 5 + 30 + 30 = 65s > 45s** ⇒ SIGKILL 发生在审计排空预算到期**之前约 10s**；
  「预算到期则拒绝未写队列行」的那条路径在 k8s 里**从不运行**，在途审计批次整批丢失。
- 加分项：`auditbatch.go:48-53` 的注释**自己承认**了这种叠加（“~40s on top of the HTTP drain and
  outlasts the pod's terminationGracePeriodSeconds”），却仍把数选成 30s ⇒ 不是没意识到，是**数没对齐**。
- **严重度**：P1（每次滚动更新/驱逐都静默丢失审计行；审计链因此在 k8s 上永不可信）。

### V-07 `G-11` 与区域 22 的 `22-1` 是**同一条**代码路径；我按出厂清单裁定了可达性
- 两处指的是同一段：`internal/httpapi/health.go:111-118` 在 `c.running==true` 时返回 `c.err`，
  而 `c.checked==false`（**从未产生过结论**）时 `c.err` 是零值 `nil` ⇒ `handleReady` 回 `200 ok`。
- 区域 22 的独立探针（`z22reconcile/readiness_test.go::TestZ22ReadinessAnswersReadyWhileTheFirstCheckIsRunning`，红）
  证明了它**确定性地**成立（对照：真正跑检查的那次拿 503）。
- **我把判定钉在出厂清单上**：`deploy/k8s/base/deployment.yaml:86-100` 同时定义
  `startupProbe`（打 **/healthz**，`periodSeconds: 5`，`failureThreshold: 24`）与
  `readinessProbe`（打 `/readyz`，`periodSeconds: 5`）。**k8s 在 startupProbe 成功之前不跑 readinessProbe**，
  而探测是**串行**的、间隔 5s、单次检查 ≤ `readinessTimeout`(2s)
  ⇒ **kubelet 自己撞不到** `checked==false && running==true` 这条分支。
- ⇒ **第六轮的 P3 判定对出厂清单成立**；区域 22 的 P2 只有在 `/readyz` 存在**并发消费者**
  （外部 LB 健康检查、ServiceMonitor、值班并发 curl）时才成立。
- **修法两者一致且便宜**：`c.running && !c.checked` 时**fail-closed**（回 503/`not ready`），
  绝不拿零值 `nil` 当结论；这不动 TTL 取舍，也不因负载 shed。
- **归属**：这是 **G-11**，**不是新发现**（区域 22 已如实标注它是「对 P1-4 修复 `0e6b701` 的补充」）。
  报告里按「同一发现、两种严重度、按出厂清单取 P3」呈现，并保留其独立探针作为守卫。
- **附带确认**：该清单已按第五轮要求设了 `GOMEMLIMIT=384MiB`（`:60-61`）且镜像**不再**用 `latest`
  （`:44` 钉 `v0.0.0-rc.3`）⇒ 第五轮 B-3 的一半与 DEP-V3 已落地。

### N-04 全部安全探针（184 个文件）**不在 CI 里**——CI 一次 `-tags` 都没有
- **事实**：`.github/workflows/ci.yml` 全文 **0 处 `-tags`**（`Select-String -Pattern '\-tags'` 计数 0），
  主测试步骤是 `go test -race -p 1 -timeout 300s -covermode=atomic ./...`（`ci.yml:158-162`），
  即**默认构建标签**。
- **被排除在外的量**：按第一行 `//go:build` 统计，
  **`audit5` 标签 101 个 Go 文件** + **`audit6`/`audit7` 标签 83 个 Go 文件** = **184 个**，
  而全仓非测试 Go 源码只有 475 个文件、29424 行 ⇒ 探针语料与生产代码**同量级**，却从不参与任何门禁。
- **直接后果（本轮实证）**：
  - 19 个 `audit5` 探针**至今仍红**且无人归因，直到本轮才逐条分类（区域 22）；
  - 第六轮约 45 个红探针**不阻断任何合并**；
  - 反过来说，**第五轮那 35 个修复提交也没有任何一条探针在 CI 里为它们兜底**——
    「修好了」与「没修回去」在 CI 眼里是同一件事。
- **为什么这不是「探针只是手工工具」**：项目自己的方法论写死了
  「a finding is not a finding until a test can fail on it」（`scratchpad/audit5/BRIEF.md` §3、
  `audit7/BRIEF.md` §3），并把这些探针当作**证据本体**留在仓库里。
  证据不进 CI，就只剩「当时跑过一次」这一条弱保证；上面 19 条红探针就是这条弱保证的代价。
- **修法**：在 CI 增加一个作业，把**全部** `-tags audit5|audit6|audit7` 的探针包**按已知绿集合**跑起来
  （红的那 19 条要么修、要么明确标记为 `t.Skip` 并写明原因/编号，不要靠标签藏起来），
  或者把「已结案」的探针改写成对**修复后行为**的断言并纳入默认套件。
- **严重度**：P2（保证/过程；本身不是运行时漏洞，但它让所有 P0/P1 修复**没有回归防线**）。
- **状态**：CONFIRMED（`ci.yml` 计数 + 文件计数 + 基线/探针运行结果三方一致）。

### V-08 区域 07 的 `Z07-2`（抹除审计谎报成功，P1）我逐行核过——**代码注释在为这个缺陷辩护**
- `internal/lifecycle/lifecycle.go:262`：`res.PseudonymDestroyed = d.cfg.Pseudonyms != nil` ⇒ 配了销毁器即为 **true**。
- `:269`：`d.record(ctx, actor, subject, audit.OutcomeOK, res, "")` —— **这条记录已把 `pseudonym_destroyed=true` 序列化进去**，
  而它写在 `Destroy` **之前**。
- `:277-283`：`Destroy` 失败时**只**把 `res.PseudonymDestroyed = false` 并 `return ... fmt.Errorf(...)`，
  **不再写第二条记录**，也**没有**走 `d.fail(...)` ⇒ 审计里**没有** `OutcomeError`、没有 `failed_at`。
- **注释（`:257-261`）正是这个缺陷的来源**：它论证「record 先写、flag 之后再复位；返回 nil 的路径上 flag 就是真相」——
  对**调用方拿到的 Result** 成立，但那条记录**已经落库**，对**日志**不成立。
- 且 `internal/httpapi/account_routes.go:62-63` 的 500 文案承诺
  「the audit log records the step that failed」——**对这一条是假的**。
- **结论**：P1 成立（合规/隐私；这是唯一一条在假名密钥存在期间仍可归因到被抹除账号的记录，而它写的是成功）。

### V-09 区域 09 的 `Z09-1`（`status` 无词汇表闸门，P2）我逐行核过
- `internal/federation/federation.go:53-62` 的 `statusRank` 对未知值走 `default: return 2`（**排名**有兜底）。
- 但 `NewRegistry`（`:141-191`）只对 `Status` 做 `"" → active`（`:162-164`），**没有 `default: return error`**。
- **同一个函数里就有正确样板**：`token_class`（`:173-180`）有显式 switch + 拒绝启动，
  注释（`:165-172`）逐字写明理由——「a typo like `long_live` would otherwise be silently read as revocable」。
  **同一条理由对 `status` 完全适用，却没有被应用**；而排除判据在别处是精确字符串比较
  （`src.Status == StatusRetired`）⇒ `"Retired"` / `"retired "` / `"disabled"` 全部落进「可服务」。
- **结论**：P2 成立，性质是**修复不全**（对 CS-4/`token_class` 修复的补充），不是新需求。

### V-10 头号阻断 `G-1` 我独立核过，并把机制说得比第六轮更准
- **哨兵存在**：`internal/store/memory/oidc.go:211` 与 `internal/store/postgres/oidc.go:340` 都定义
  `ErrRefreshTokenSpent = oidc.ErrInvalidGrant().WithDescription("refresh token was already rotated")`，
  并在轮换声明处返回（`memory:556` / `postgres:399`）。
- **但全仓 grep 的结果是决定性的**：`ErrRefreshTokenSpent` 的引用只有三类——
  两处**定义**、两处**返回**，以及 `internal/store/{memory,postgres}/oidc_test.go`
  与 `internal/zzprobe/concurrency/single_use_test.go` 里的**测试**。
  **没有任何生产代码消费它**：没有家族撤销、没有 `TerminateSession`、没有审计事件、没有指标。
  ⇒ 盗窃信号被生产出来又被丢掉。
- **第六轮的说法需要一处收紧**：真正「按原样重放已消费令牌」时，那一行在轮换时已被 `delete`，
  所以 `TokenRequestByRefreshToken` 查不到 → 返回的是普通 invalid_grant，
  **连 `ErrRefreshTokenSpent` 都走不到**（该哨兵主要覆盖**并发轮换竞态**）。
  也就是说：**顺序重放与「随机坏令牌」在服务端不可区分**，这比「检测到但不止损」还要弱一档。
- **对修法的直接影响（这是我要强调的）**：在**检测点**上，被重放令牌的那一行已经不存在了，
  因此 store **拿不到它的 subject/client**（内存与 Postgres 都是先删后判）。
  所以「撤销该 (client, subject) 的整条链」**无法在现有数据模型上就地实现**，
  必须先在轮换时留下**族/代号标识或已消费令牌的墓碑**（或让 refresh 值本身携带族 id）。
  修 G-1 时要按这个顺序做，否则会写出一个看不出问题但覆盖不到顺序重放的修复。
- **状态**：CONFIRMED（读码级：定义/返回/引用三点齐备）。

### V-11 `G-4` 我独立核过：`prompt=none` **有**实现，`prompt=login` / `max_age` **完全没有**
- **有的一半**：`internal/oidchttp/oidchttp.go:950-972` 对 `prompt=none` 无会话时经 redirect 回
  `error=login_required`；`"none login"` 这类矛盾组合回 `invalid_request`（`:956`）。
  `internal/oidchttp/oidchttp_test.go:236-294` 钉住了这两条。⇒ 第五轮 P2-24 确实修好了。
- **没有的一半**：全仓 grep `MaxAge` 只命中**测试**与**会话 cookie 的 MaxAge**，
  **生产代码零命中**；`prompt=login` 也没有任何裁决点。
  `internal/zzprobe/audit6/zverify/z01z02_claims_test.go:123-126` 自己写明：
  「The op.AuthRequest interface the library hands back has no MaxAge/Prompt field」，
  且 pending request 的 `AuthTime` 在 `prompt=login&max_age=0` 下仍是**未设**。
- **结论**：CONFIRMED。会话存活时 `prompt=login` 既不重新认证也不回 `login_required`，
  id_token 带**旧会话的 `auth_time`**；`max_age` 完全不被读取。
- **对修法的直接影响**：因为 `oidcstore.AuthRequest`（`internal/oidcstore/oidcstore.go`）
  **没有 `MaxAge`/`Prompt` 字段**，这不是「在钩子里比较 auth_time」能解决的——
  必须**先在存储边界加字段**（或把这些参数存进 auth request 记录），再在会话/登录钩子里裁决；
  无活会话时按 `login_required` fail-closed。

### V-12 区域 13 的 `Z13-1`（备份目录不被忽略，P2）我实测确认
- `.gitignore` 与 `.dockerignore` 对 `backup` / `dump` / `.age` 的匹配数**都是 0**（实跑 grep）。
- 而 `scripts/backup.sh:12` 与 `scripts/backup-keys.sh:23` 的默认输出目录都是 `dir="${1:-./backups}"`。
- ⇒ 不带参数跑备份，会在**仓库根**写出明文数据库转储与密钥 env 文件，而这两个文件类型**既不会被 git 忽略、
  也不会被 Docker 构建上下文忽略**（`git add .` / 宽 `COPY` 都能带走）。
- 与第五轮 DEP-03/04（「转储世界可读」）的关系：那一半是**权限位**，这一半是**忽略规则**——
  同一处运维动作的两个不同缺口，故非重报。
- **严重度**：P2 成立（凭据/数据外泄路径；前提是运维在仓库根跑过备份脚本）。
- **状态**：CONFIRMED（读 `.gitignore`/`.dockerignore` + 脚本默认值实查；`./backups` 当前不存在）。

### V-13 区域 08 的 `Z08-5` 我核过（P2 成立，但性质是"部署成本"而非安全）
- `internal/webui/webui.go:145-146`：`_app/immutable/` 前缀一律 `Cache-Control: public, max-age=31536000, immutable`。
- 而会话中间件（alexedwards/scs 的 `LoadAndSave`）会给**每个**响应加 `Vary: Cookie`；
  探针 `internal/zzprobe/audit7/z08frontendbrowser/realproc_test.go:203-208` 在**组合后的真二进制**上
  断言"同时含 `immutable` 与 `Vary: Cookie`"即失败 ⇒ 共享缓存必须按 Cookie 分键，`immutable` 名存实亡。
- 与第六轮 A-FE-9 一族的关系：那组讲的是**构建不可复现/缓存投毒**（已被推翻），本条是**响应头之间的语义冲突**，
  非重报。
- **我的定级意见**：安全影响为零，纯部署成本 ⇒ 若复核要压到 P3，我不反对；但"失败是静默的"（没有任何日志/指标）
  支持保留在 P2 下沿。

### V-14 区域 13 的 `Z13-3` 需要一处精确化（我读 `Dockerfile` 与 `Makefile` 后）
- `Dockerfile:74` 有 `COPY LICENSE NOTICE /` ⇒ **运行镜像里确实带着 Go 侧归属（LICENSE + NOTICE）**。
  所以若把它读成"镜像完全没有归属文本"那是错的（第五轮 SUP-2 的表述正是那个方向，且已被更正）。
- **缺的是 npm 那半**：`Makefile:215-221` 的 `npm-attribution` 目标产出
  `dist/re0auth_<ver>_npm-attribution.json`，并由 `Makefile:226,229` 挂进 `checksums` / `release`，
  但 **Dockerfile 不 `COPY` 它**。
- 另两处相关事实（供复核定级）：`Makefile:207-209` 的注释自己写明"NOTICE 覆盖 Go 模块，SPA 也是第三方代码，需要同样归属"；
  `checksums: sbom npm-attribution`（`:226`）说明该 JSON 是 checksums 的**前置**，但**没有守卫**断言它被 `SHA256SUMS` 真正收录
  （即 Z13-6）。
- **结论**：`Z13-3` 成立但**范围要写准**（缺 npm 清单，不是缺全部归属）；`Z13-6` 是"缺守卫"而非"确定没覆盖"。

### V-15 区域 09 的 `Z09-4`（全局先到先得的缓冲预算，P2）我读码算清了
- `internal/federation/service.go:60-64` 的 `bufferBudget` **只有 `limit` 与 `held` 两个字段**
  ⇒ **没有按 subject/client 分摊的任何结构**，预算是全局先到先得。
- 常量：`defaultMaxBufferedBytes = 64 << 20 = 67 108 864`（`:30`）、`maxBody = 4 << 20 = 4 194 304`（`:24`）。
- `reserveFor`（`:108-113`）：声明长度为正且小于读上限时预留 `长度 + 1`，**否则预留整个读上限**。
  `+1` 是**故意的**（用来发现"body 比声明的长一个字节"），不是 bug——但它造成了 raw 与归一化两条路径的**预留差 1 字节**。
- **算术（可复核）**：raw 路径预留 `maxBody + 1 = 4 194 305`；
  `15 × 4 194 305 = 62 914 575`，剩余 `67 108 864 − 62 914 575 = 4 194 289`；
  而归一化读在长度未知时要预留 `4 194 304` —— **差 15 字节** ⇒ 被 shed。
  第 16 个 raw sleeper 自己也放不进来（会超限），所以"15 个在途"正是下界。
- `acquire`（`:71-82`）**从不排队**，满了即 `ErrBufferBudget`（方向与 P0-3 一致，是刻意的）。
- **结论**：P2 成立。与 P0-3/B-3 的关系是**同一处代码的相反方向**：那次把"无界"改成"有界且会 shed"，
  本条指出该界**没有分摊**——一个调用方可以凭自己的在途量决定**别人**的成败。
- **修法确实是裁定**（按调用方配额 / 按已读字节预留 / 首字节期限三选一），且无论选哪条，
  `Config.MaxBufferedBytes` 的注释都应写明"这是全局先到先得的预算"。

### V-16 区域 09 复核新发现的 `Z09V-1`（共享熔断器跨账号，P2）我核过，且它**是文档化决定未记录的后果**
- **按 host 分键属实**：`httpclient/circuitbreaker.go:118` 的 `hosts map[string]failsafe.Executor`，
  `:122` `executorFor(req.URL.Host)`，`:135-163` 每 host 一个 executor。
  `:112-113` 的注释自述是"judged against its own source"（**按源**，不是按账号）——这本身是**有意**的。
- **401 计入 host 失败属实**：`breakerFailure`（`:196-204`）把 `>=500` 或 `==401` 判为失败。
- **但这是被明确文档化的决定**：`:181-195` 的长注释逐字论证了为什么要算 401
  （"a source whose tokens cannot be refreshed costs two or four round trips per request, forever,
  and never trips a breaker that does not count 401"），
  并说明 `WithFailureThreshold(5)` 是**最近五次的比例** ⇒「只有最近五次**全**失败才开闸，而这正是该被跳过的源」。
- **因此本条的准确表述是**：`P1-3`（第五轮有意把 401 纳入熔断）的**理由只论证了"源的健康"**，
  没有记录它的后果——在一个多租户 OP 里，**一个账号**的上游凭据失效（被源撤销、无 refresh）
  就是连续 5 个 401，而熔断器是**按 host 共享**的 ⇒ 该源的**所有其他账号**在冷却期内被 `ErrCircuitOpen` 直接拒绝
  （复核的探针实测：受害者读从 200 变 `circuit breaker is open`，且 **upstream calls 不增**）。
- **上界（复核已诚实标注）**：窗口是最近 5 次，任何一次成功都会压住它 ⇒ 这是"突发/安静源"型攻击，不是必然成功；
  冷却 `Cooldown` 自限。**故 P2 成立但不应上调**；若只按"别的用户被牵连"看，P3 也说得通。
- **修法要点**：把 401 的语义**按调用方分流**（401 不进 host 熔断，改为按 **binding** 计失败——
  `keyedMutex` 已经按 binding，可同构），P1-3 的目标（避免永久 401 源吃满超时）用"同一 binding 连续 N 次 401 ⇒ 该 binding 冷却"达成。

### V-17 区域 09 的 `Z09-2`（归一化读静默截断，P3）我核过，并钉死了那条豁免理由为什么是假的
- **两条路径的不对称（逐行）**：
  - raw（`internal/federation/service.go:725-736`）：预留 `maxBody+1` → `io.LimitReader(..., maxBody+1)` →
    **`if len(body) > maxBody { return ErrResponseTooLarge }`**。
  - 归一化（`:760-775`）：预留 `maxBody` → `io.LimitReader(..., maxBody)` → 只查 `StatusCode != 200` 与 `json.Valid(body)`，
    **从不比较 `len(body)` 与 `maxBody`**。`io.LimitReader` 截断时**不报错**。
- **豁免理由原文（`:718-719`）**：「The normalized path cannot have this problem: its body has to parse as JSON,
  and a cut one does not.」——**这句是假的**：`json.Valid` **接受尾随空白**，
  所以「一个完整 JSON 值 + 大量空白」被从空白中间切断后仍然 `Valid`，
  于是下游拿到 `200` + 被截断的 body，而**没有任何提示**（`fetchResource` 直接 `return json.RawMessage(body)`）。
- **状态**：CONFIRMED（源级；其报告另有真 HTTP 面实测：上游写 5 242 902 B、cap 4 194 304，
  调用方拿到 4 194 304 且 `status=200 json.Valid=true`，而 raw 对照组回 502）。
- **修法（一行级）**：照抄 raw 的两行——`io.LimitReader(resp.Body, maxBody+1)` +
  `if len(body) > maxBody { return nil, ErrResponseTooLarge }`；`reserveFor` 已按 `readCap` 参数化，传 `maxBody+1` 即可。
- **归属**：是对第四轮 `18fed92`（raw 五处 fail-open）修复的**补充**——同一类缺陷只修了 raw 一侧，
  且为该侧写的理由同样覆盖不了另一侧。

### V-18 区域 09 复核的两条新发现我都读码确认了（`Z09V-2` 破坏性、`Z09V-3` 跨 origin）
**`Z09V-2`（存储读故障被当成"版本没动"，从而撕掉可能仍有效的绑定）**
- 判据只有一句（`internal/federation/refresh.go:142-145`）：
  `if latest, err := s.bindings.Get(...); err == nil && latest.Version != spent.Version { return latest, nil }`
  —— 只有「**读成功**且版本动了」才放过；**`err != nil` 与「版本没动」一起落进破坏性分支**。
- 破坏性分支确实是破坏性的：`:151` `s.vault.Revoke(...)` → `:159` `s.bindings.Delete(...)`
  ⇒ 绑定行被删、vault 密钥被 crypto-shred。
- `:133-141` 的注释把意图讲得很清楚（"a version that moved past the one we spent means somebody else won"），
  **但它默认了重读成功**——这正是缺陷所在：存储故障不是"版本没动"的证据。
- 生产可达性（复核已核）：`internal/store/postgres/federation.go:20-33` 只把 `noRows` 映射成 `ErrNotBound`，
  连接池/连接故障按原样返回；内存后端不会返回这种错误 ⇒ 对内存模式不可达。
- **状态**：服务层 CONFIRMED / 生产触发 HYPOTHESIS（差真库）。**修法**：非 `ErrNotBound` 的错误向上返回，
  不要进破坏性分支。**定级意见**：复核给 P3（需两个条件同时成立）；考虑到后果是**数据丢失且不可逆**
  而触发只是一次基础设施抖动，我认为 **P3 偏保守**，报告里保留 P3 但注明这一分歧。

**`Z09V-3`（`Issuer = "//evil.example"` 时 `/bind` 302 到另一个 origin）**
- `internal/federation/bind.go:150`：`authURL := s.oauthConfig(src).AuthCodeURL(...)` —— URL 完全来自 `src`。
- 而 `internal/federation/federation.go:144` 对 `Issuer` **只查非空**（`s.Issuer == ""`），
  不要求 scheme/host ⇒ `//evil.example` 通过；`AuthorizationEndpoint` 变成 `//evil.example/oauth/authorize`（`:152-153`）。
- **同一文件里就有正确样板**：`validateRawBase`（`:207-220`）对 `RawBase` **确实**校验 scheme/host，
  只是没有对 `Issuer` 用同一条规则。
- 浏览器把 `//evil.example/...` 解析成 host=`evil.example` ⇒ **开放重定向/钓鱼面**（不泄漏凭据，但把绑定登录交给第三方 origin）。
- **状态**：CONFIRMED（源级；复核另有执行级探针）。**修法**：`NewRegistry` 对 `Issuer` 要求
  `Scheme ∈ {http,https} && Host != ""`（顺带封住 `?`/`#` 吞掉资源路径的那一半）。

### V-19 区域 15 的 `Z15-1`（清扫无每轮有界推进，P2）我读码确认，并补上"为什么没人会发现"
- **形状属实**：`internal/store/postgres/sweep.go:50-68` —— `pool.Begin` 之后对 `expiredTables`（**10 张表**）
  逐条 `DELETE FROM %s WHERE %s < $1`，**没有 LIMIT**，全部在**同一个事务**里，最后才 `Commit`。
  ⇒ 只能"全删或全不删"；一旦这一坨工作撞上语句超时，**每个 tick 重试的是同一份（且仍在增大的）工作**。
- **"一个事务"是文档化的**：`:42-45` 的注释自述理由是"a sweep is a single consistent step…
  Every delete is idempotent regardless, so a retry after a failure is always safe"。
  **这句是真的，但它回答的是"安全"，没回答"能不能推进"** —— 本条的增量正是后者：
  **没有每轮有界推进（bounded progress）**，失败会无限重试同一份越积越大的工作。
- **我补的证据（可观测性缺口）**：`cmd/re0auth/main.go:1111` 只有
  `slog.Warn("expiry sweep failed", "err", err)` —— **没有指标、没有计数器**。
  因此 `deploy/prometheus/re0auth.rules.yml` **无法对清扫失败告警**（它没有可查询的序列）。
  这与项目对「失败是静默的」的一贯口径一致：这里不是完全静默，但**在运维面上等同于静默**。
- **重报风险（我核过）**：第五轮 `PERF-4` 是**审计链 `Verify` 的全库扫描**（并因 `operations.md:171-182`
  已给出"增量校验点"而被降为"已知非发现"）；本条是**过期清扫 `SweepExpired`**，对象与谓词都不同，
  且 `operations.md` 没有覆盖它 ⇒ **不是重报**（复核可再确认）。
- **状态**：CONFIRMED（源级；探针 `performance_probe_test.go` 亦断言了那条 Warn 的存在）。
- **定级**：P2 合理（维护路径活性）；若判定"需要真实积压规模才能触发"则可压到 P3，
  但**没有指标**这一点独立支持 P2。

### V-20 区域 14 的两条安全 P2 我都读码确认了（`Z14-3` jwks_uri 未钉、`Z14-4` 缓存回退使 TTL 失效）
**`Z14-3`（`jwks_uri` 不与 issuer 绑定）**
- `idp/idp.go:483-505` 的 `pinToIssuer` **只钉 `authURL` 与 `tokenURL`**（`u.Scheme != issuer.Scheme || u.Host != issuer.Host` 即拒）。
- `:459-465` 的注释把威胁讲得很清楚——"A discovered endpoint is pinned to the issuer's scheme and host.
  The document is the thing an attacker controls in a mix-up or a hijacked-discovery scenario"——
  **但它只覆盖了两个端点**。
- **项目自己的探针就承认了另一半**：`idp/zz_audit_rp_test.go:289-309`
  (`TestZZAuditRPForeignJWKSURIComesFromTheDocument`) 的注释写着
  "the half that is not pinned: the trust anchor for id_token signatures is whatever `jwks_uri` the discovery
  document says"，并**实测**：把 `jwks_uri` 指到**另一个 origin**、用那把**外部密钥**签的 token **验签通过**。
- ⇒ 能左右 discovery 响应的一方（同一前提已是 RP-3 的条件）可让 RP 信任自控密钥，从而在
  `iss` 仍等于配置 issuer 的前提下**伪造任意 `sub`**。修法与 `validateRawBase`/`pinToIssuer` 同形：
  把 `jwks_uri` 也钉到 issuer 的 origin。
- **状态**：CONFIRMED（源级 + 项目自有探针的执行级描述）。

**`Z14-4`（失败回退使 provider TTL 失效）**
- `idp/idp.go:619-637`：缓存命中且未过 TTL 才直接返回；**重新 discovery 失败时，
  `:627-631` 直接 `return c.discovered, nil`**（把**旧 provider** 继续用）。
- 而旧 provider 内部握着**已缓存的 JWKS**，所以**退役的签名密钥在 discovery 持续失败期间一直验签成功**
  ——RP-2 修复引入的 TTL 边界**只在 discovery 成功时**成立。
- `:615-618` 的注释是**有意**的取舍（"a failed re-discovery must not clear the working cache…
  the alternative is a login outage whenever the issuer's discovery endpoint has a bad minute"）。
  **未记录的正是安全侧后果**：窗口从"15 分钟"变成"issuer 的 discovery 坏多久"（可无限期）。
- **修法建议**：给回退设一个**上界**（例如超过 N×`providerTTL` 仍失败则拒绝验签或以告警降级），
  并把这条取舍写进 `docs/dependencies.md`。
- **状态**：CONFIRMED（源级；`docs/dependencies.md` 未记此后果）。

### V-21 区域 12 的新 P1 `Z12-3`（首个 seed 之后 `[client]` 改动被静默忽略）我读码确认
- `cmd/re0auth/main.go:1583-1591`：`seedClient` 先 `clients.Get(ctx, cfg.clientID)`，
  **`err == nil`（已存在）时只打一条 `slog.Info("downstream client already registered")` 然后 `return nil`**。
- 其后才是构造新 client（`:1593-1601`）与 `Create`（`:1605`）——**只对"不存在"的情况执行**。
  ⇒ **redirect URI、client secret、客户端类型、scope、显示名全部停留在首次 seed 的值**，之后改配置文件**不生效**。
- 注释（`:1580-1582`）确认这是有意的："Re-running the process must not fail, so an existing registration is left untouched rather than overwritten."
  —— 意图（幂等启动）合理，**但它没有说"配置与库里的不一致"**，所以失败是**静默**的。
- **影响（为什么它在认证边界上）**：典型操作是"加一个回调地址 / 轮换 client secret / 收紧 scope"。
  轮换 secret 的场景最重：运维以为旧 secret 已退役，实际**旧 secret 仍然有效**；收紧 scope 同理不生效。
  反向（加 redirect URI）不生效只是配置错误，但**删 redirect URI 不生效**会把一个本该撤销的回调地址留在白名单里。
- **定级意见**：同意 **P1**（认证边界 + 静默 + 操作者极可能以为生效）。若复核认为"日志至少印了 `already registered`"
  而想压到 P2，我接受，但必须在**启动时显式比对并告警配置差异**，否则这条日志不构成可发现性。
- **状态**：CONFIRMED（源级）。

### V-22 区域 21 的 `Z21-2`（迁移 Down 摧毁审计链证据，P2）我读 SQL 确认，并把形状说得更准
- `internal/store/postgres/migrations/0013_audit_chain.sql`：
  - **Up**（`:30-48`）：加 `prev_hash` / `row_hash` / `signature` 三列 + 唯一索引 + `audit_chain` 链表头 + genesis 行。
  - **Down**（`:50-55`）：`DROP TABLE audit_chain` → `DROP INDEX` → `DROP COLUMN signature/row_hash/prev_hash`。
- **关键（比报告更进一步）**：Down 把**已签名/已链接的哈希整体丢掉**，Down 之后再跑 Up 只会重建**空列**
  ⇒ 链**无法重建**，而且**无法区分「从未入链」与「入过链又被拆掉」**：
  往返之后每一行都是 NULL 哈希，`Verify`（`auditchain.go:270-282`）会把它们**全部计 `Legacy` 并 `ok=true`**。
- **与 `Z10-2` 复合**：`Z10-2` 说的是「链首之前的 NULL 哈希行被接受」；这里提供了一种**批量制造**这种行的方法，
  且**一次 Down→Up 就完成**、不留任何日志。⇒ 两者叠加后，**「审计链防篡改」这条 S5 属性可以在无人察觉的情况下被整体拆除**。
- `0014_audit_pseudonyms.sql` 的 Down（`:41-42`）只 `DROP TABLE audit_subject_keys` —— 它销毁的是**假名密钥**
  （此后无法把审计行按 subject 关联，也无法完成后续抹除的关联性证明），性质与 0013 那半不同，
  故**以 0013 为这条的主证据**。
- **状态**：CONFIRMED（读 SQL 至行）。**修法**：在 Down 之前要求显式的破坏性确认（或让 Down 拒绝执行并提示
  "tamper-evidence 一旦拆除不可恢复，请用备份恢复"），并把这条写进 `docs/runbooks.md`
  与 `docs/migration-decision.md`；`Verify` 也可以增加一个"链头表存在但历史行全为 NULL"的异常判据。
- **归因**：第六轮 `04-7` 讲的是**建索引的写冻结**，与本条不是同一件事；第五轮 `PG-002` 讲的是
  `-migrate-down` 的报错文本 —— 故本条不是重报。

### V-23 区域 11 的两条 P1（并发槽位与桶表被单机耗尽）我都读码确认了
**`Z11-5`（并发上限全进程一个信号量，无按调用方分摊）**
- `internal/httpapi/middleware.go:393-405`：`sem := make(chan struct{}, s.maxInFlight)`，
  然后 `case sem <- struct{}{}: defer func(){ <-sem }()`。
  **一个进程级的带缓冲 channel 当信号量，对所有调用方共享**，没有任何按地址/主体的键控。
- ⇒ 单个地址可以占满全部 `maxInFlight` 个槽位（出厂 512），其他调用方全被 shed；
  而探针的 `isProbe` 判定在限流器与在途上限**之前**（第五轮已确认）⇒ **探针仍答 200**，
  于是"实例看起来健康，但真实用户全 503"。**匿名、单机可触发**。
- **状态**：CONFIRMED（源级）。

**`Z11-4`（桶表被单个 IPv6 /64 填满后，所有新客户端共用兜底桶）**
- `internal/ratelimit/ratelimit.go:199-215` 的 `bucketLocked`：
  键已存在 → 用它的桶；否则若 `len(s.buckets) >= perShard()` **且** `reclaimLocked` 失败
  → `:205-209` **返回该分片的共享 `overflow` 桶**。
- `reclaimLocked`（`:226-240`）只丢弃**空闲 ≥ `reclaimWindow`**（= max(refillWindow, ttl)）的桶，
  且扫描上限 `reclaimScan` ⇒ **装满"活跃"桶的分片无法为任何人腾位**。
- ⇒ 攻击者先用大量不同键把分片填满（**单个 IPv6 /64 足够**），再把这个**共享** overflow 桶打空，
  此后**所有新的诚实客户端**（包括正常用户）都从这个空桶拿 429。
- **这是文档化的取舍吗？** 部分：`:196-198` 的注释明确说这是"the fail-closed direction, and it is what stops
  'vary your key' from being a way to buy quota"；`:100-101` 的 `Size()` 注释也承认
  "at the cap new clients stop having budgets of their own"。
  **未记录的是后果的方向**：fail-closed 的代价被**转移给第三方**，而第五轮 P0-4 的修复目标只是"不让换键买配额"。
- **状态**：CONFIRMED（源级；区域报告另有执行级探针）。
- **定级**：P1 合理（匿名、单机、影响他人可用性）；若按简报"匿名可触发的 DoS"口径，P0 也说得通。
  **修法方向**：溢出桶按**调用方**分片（或对"表已满"做显式降级 + 告警），而不是让全部分片的新键共享一个桶。

### V-24 区域 11 的 `Z11-1`（匿名把就绪打成 503，P1）我读码确认——`/readyz` 两个方向现在都由我亲自验证
- `internal/httpapi/health.go:94`：`handleReady` 调 `s.readiness.check(r.Context(), s.ready)`
  —— **上下文来自调用方**。
- `:122-129`：
  `probeCtx, cancel := context.WithTimeout(ctx, readinessTimeout)` → `err := probe(probeCtx)` →
  **`c.err = err; c.checkedAt = now; c.checked = true`** —— **把这次（可能因调用方断连而失败的）结果整段缓存**。
- ⇒ 一个匿名调用方做一次 **connect-then-hangup**，`r.Context()` 立即取消 ⇒ DB ping 以 ctx 错误失败
  ⇒ **该失败被写进缓存**，在 `readinessTTL` 内**所有**后续 `/readyz`（包括编排器的）都拿 503。
- **放大器**：`/readyz` 是**探针豁免**的（不在限流器与在途上限之内，第五轮已确认）
  ⇒ 匿名者可任意、反复触发；而 `deployment.yaml` 的 readinessProbe 是
  `periodSeconds: 5, failureThreshold: 3` ⇒ **只需把它持续按住，健康实例就会被摘出流量**。
- **可发现性**：原因只进 `slog.Debug`（`:98`），默认日志级别下**不可见**。
- **与 `G-11` 的关系**：同一份 `readinessCache` 的**相反方向**——G-11 是"没结论时 fail-open"，
  本条是"把调用方造成的失败当成结论缓存下来"。**两个方向我现在都亲自读码确认过**
  （G-11 见 V-07 与 §5.15），这正是 §5.15 主张"需要一个显式三态 + 不派生自调用方 ctx 的检查上下文"的第一手依据。
- **状态**：CONFIRMED（源级；区域报告另有真进程探针）。

### V-25 区域 12 的 `Z12-6`（非有限 `rate_limit` 被接受，P2）我读码确认，并补上更干净的那个字面量
- **解析层接受非有限值**：`internal/config/config.go:103` 是 `strconv.ParseFloat(raw, 64)`，
  而它**按文档接受 `NaN`、`Inf`、`+Inf`、`-Inf`**（`-0` 亦如此）。
- **校验层对 NaN 全部失效**（`cmd/re0auth/config.go:512-522`）：
  `case cfg.RateLimit < 0` → **NaN 时为 false**；`case cfg.RateLimit == 0` → **false**；
  `case cfg.RateLimitBurst < 1` → burst 有默认值 100，也为 false。
  ⇒ **一个 `NaN` 的 rate_limit 通过全部校验**。
- **建限流器时同样落空**：`cmd/re0auth/main.go:225-228` 的 `if cfg.RateLimit <= 0` → **NaN 时 false**
  ⇒ 不会走"禁用限流"的分支，而是真的 `ratelimit.New(NaN, 100)`（`ratelimit.go:162` `rate.Limit(perSecond)`）。
- **两个字面量的后果（我区分开）**：
  - **`+Inf`** 是最干净的一例：`rate.Limit(+Inf)` 等于库的 `rate.Inf`，
    语义是**"永远允许"** ⇒ 限流被彻底关掉，而配置读起来像一个具体数字。
  - **`NaN`** 的裁决由库的内部算术决定（比较与累加在 NaN 下全为 false）⇒
    **未定义/未指定**；区域探针实测把它推向"放行一切"，复核另有独立探针在做同一件事
    （`z12verify/verify_limiter_rate_test.go`）。无论落在哪一侧，"接受一个 NaN 速率"都不该发生。
- **修法（一行级，方向与既有口径一致）**：在解析后加 `math.IsNaN(v) || math.IsInf(v, 0)` 即拒，
  并把 `case cfg.RateLimit < 0` 改成 `!(cfg.RateLimit > 0 || cfg.RateLimit == 0)` 之类的**非 NaN 安全**判据；
  这属于 `Z12-*` 一族"配置面 fail-closed 缺口"的典型成员。
- **状态**：CONFIRMED（源级；区域报告与复核各有执行级探针）。

### V-26 区域 16 的 `Z16-2`（gosec 白名单让门禁永不对真实命中报警，P2）我读 `.golangci.yml` 确认
- `.golangci.yml` 里 `linters` 启用了 `- gosec`，但 `settings.gosec.includes` 只列了**五条**：
  `G304`（变量做文件路径）、`G401`（弱加密原语）、`G402`（TLS 跳过校验）、`G404`（`math/rand`）、`G501`（弱加密包 import）。
- 在 golangci-lint 里 `gosec.includes` 是**白名单**（限制为这些规则），**不是**"在默认集上追加"
  ⇒ **其余全部 gosec 规则从不运行**。
- **本项目特别相关的两条被排除掉的规则（我点出来，因为这正是本轮反复发现的形状）**：
  - **`G104`（未处理的错误）** —— 正是本轮的主题：`_ = s.audit.Record(...)`、
    `if err == nil` 落穿、`err` 只记日志不返回……**没有任何静态门禁在看它**。
  - **`G107`（URL 来自可变输入）** —— 与 SSRF/URL 拼接一族（`FO-03`/`FO-04`/`Z09V-3`）相关。
- **注释给出的理由是合理的**（TapTap 的 MAC 真的需要 HMAC-SHA1；配置装载真的会打开来自 flag 的路径；
  `G101` 会在公开 OAuth 端点 URL 与测试夹具上误报）—— 所以"不用全量"是**判断**，
  但**白名单的选法**把 G104/G107 一起丢了，而这两条恰恰是本项目最需要的。
- **修法**：把 `G104`（至少对非测试代码）与 `G107` 加回 `includes`，
  对已知误报点用**具名 `//nolint` 并写明理由**（项目已经在用这个模式），而不是靠白名单整体关掉。
- **状态**：CONFIRMED（读配置至行）。

### V-27 区 20（授权隔离矩阵）的覆盖核对：主代理亲自核了一层，并更正了一次误判
> **记录更正（重要）**：我一度判断 wave3 的 Z20 代理"静默失败"（因为它迟迟没有产物目录），
> 于是另派了一个审计子代理接手。**该判断是错的**：原代理并没有死，只是慢，
> 它最终写出了 `docs/audit-7/findings/Z20-authz-isolation-matrix.md`（1:57:31）。
> 接手的那位子代理主动报告了这次**并发冲突**（它看到原代理的探针与报告在实时增长），
> 我因此改为：让它**不碰**报告路径与既有探针目录，把独立结论写到
> `Z20-INDEPENDENT-CROSSCHECK.md` 与 `internal/zzprobe/audit7/z20independent/`；
> 另有一名专门的复核者写 `Z20-VERIFIED.md`。
> **方法论教训（值得记进流程）**：在并行多代理编排里，**"没有产物" 既可能是失败，也可能只是慢**；
> 由主代理据此**重新派活**会造成**同路径多写者竞态**（"last writer wins"）。
> 正确的判据不是"目录是否存在"，而是**该代理是否仍在活动**（文件 mtime / 进程 / 心跳），
> 且任何补派都应当**换一条不冲突的产物路径**。

- **六个句柄类端点的归属判据是一致的**（`Bound` **且** `OwnerMatches`）：
  - `authorization_routes.go:74-77`（同意句柄）
  - `device_routes.go:108-109`（设备 user_code）
  - `federation_routes.go:386-388`（绑定 state）
  这三处正是"同一浏览器里第二个账号能否消费第一个账号的句柄"的那一族。
- **`federation_routes.go:378-385` 的注释记录了修复史**：这一处**曾经漏了 `OwnerMatches`**（第二轮 A2-1），
  于是第二个账号能消费句柄与 flow 行，造成**受害者自己无法完成绑定**的跨账号拒绝服务；现已补上，
  且拒绝形状与"未知句柄"相同（避免确认句柄存在）。
- **对应的对抗性守卫在仓**：`internal/httpapi/adversary_test.go:161-172`
  （`TestAdversarialBindCallbackRejectsAnotherAccount`）。**注意它上方 161-171 的注释是"发现描述"的旧文本**
  （读起来像缺陷仍在），而代码已经修好 ⇒ 只是注释陈旧，不是缺陷（符合本轮"注释与实现相反"的总主题，
  但方向无害，记为**提示**）。
- **联邦读路径的 subject 来自令牌而非请求参数**：`federation_routes.go:125` 与 `:268` 都是
  `User: account.UserID(info.Subject)` ⇒ **跨主体读在这条路径上结构上不可能**
  （没有"用别人的 subject 读"的入口）。
- **结论（主代理侧）**：在我覆盖到的这几族里，**隔离矩阵是成立的**；这正是"探过没破"的价值。
  完整的矩阵结论见区域 20 报告（原代理产出），独立交叉核对见 `Z20-INDEPENDENT-CROSSCHECK.md`。

### V-22 更正（复核 `Z21-VERIFIED.md` 纠正了我这条的两处说法）
- **我说对的部分**：`0013:50-55` 的 Down 丢掉 `audit_chain` 与三个哈希列；Down 后再 Up 只重建**空列**；
  `Verify`（`auditchain.go:270-282`）把 NULL `row_hash` 只计 `Legacy` 且 `v.OK=true`，
  而 `v.Legacy` **只被自增、从不参与判定**。这些复核逐段确认。
- **我要更正的两处**：
  1. **我把 `0014` 也算了进来 —— 那是错的**：`0014` 的 Down 只 `DROP TABLE audit_subject_keys`，
     **完全不碰链**；它真正的后果是一条独立的新发现（**`Z21V-1`**：每账号假名密钥全丢 ⇒
     同一账号的审计史被静默劈成两个假名，`?subject=` 此后只回一半）。
  2. **"静默"说过头了**：`cmd/re0auth/main.go:1090-1094` 在 OK 分支会打
     `slog.Info("audit chain verified", "legacy", N)`，且 `/v1/admin/audit/verify` 的响应带 `legacy`。
     真正静默的是**没有东西把「`0013` 之后才上线的库里 `legacy>0`」当成回归**——
     这个表述我接受，写进报告时已改成这一句。
- **我还要接受一处"我低估了"**：可达性**比我写的更强** —— `87f4ad9` 之后**新建**的库里**没有版本 5 这一行**
  （Up 应用 1,2,3,4,6…22），对它 `-migrate-down` 一路可用，而**即将上线的首次部署正是这种库**
  ⇒ ADR-0008 §4 那条成文运维动作会一路走到 `0013`。我原先把可达性描述为"需要操作者主动回退"，
  方向没错但**分量说轻了**。
- **另接受**：`Z21-1` 的机制**被复核推翻**（goose 的 Down 一次一个版本且与版本行同事务，
  正常路径不可能把同一段 Down 跑第二遍）⇒ 从"第二次退会硬报错"降为纯加固项。

### V-28 区域 19 复核新增的 `Z19V-1`（DSN 走名字位被回显，P2）我读码确认，并说清它与 `Z19-1` 是**同一个洞**
- `internal/config/config.go:57-66` 的 `Secret(envName, field)`：
  - `envName == ""` → `"%s is required"`（只回显**字段名**，安全）；
  - `os.Getenv(envName) == ""` → **`"%s names %q, which is not set"`** —— **回显的是 `envName` 本身**。
- 平时这条报文是**有帮助的**（"你说的是 FOO，但 FOO 没设"）。问题在于 **`envName` 是操作者从配置文件里写进来的、且没有任何形状校验**
  （`storage.dsn_env` 在 `cmd/re0auth/config.go:149` 只是一个 `string`，`:686-694` 直接把它交给 `Secret`）。
- ⇒ **把 DSN 原文（含口令）粘进 `dsn_env` 这个"名字位"** 时（操作者以为自己在填 DSN），
  启动失败报文就会把 `postgres://user:pass@…` **原样打进日志**。这就是 `Z19-1` 的形状（`*_env` 名字位塞值），
  只是换了一个字段与一条报文。
- 另需注意 `:109-112` 那条"缺 `@` 主机"的形态也走同一条回显路径（复核报告的点名），机制一致。
- **结论**：`Z19-1` 与 `Z19V-1` **应当作为同一条修复项处理**：给所有 `*_env` / `dsn_env` 值加**环境变量名形状校验**
  （或在报文里只写"该字段应当是一个变量名"，绝不回显其值）。三条泄露通道
  （`Z19-1` 的 `*_env`、`Z19V-1` 的 `dsn_env`、`Z12-1` 的 `RE0AUTH_OIDC_RETIRED_TOKEN_KEYS` 缺 `id:` 前缀）
  合起来说明这是一个**统一的错误呈现策略问题**，而不是三处独立失误。
- **状态**：CONFIRMED（读码级）。
- **定级意见**：同意 P2（凭据进日志；触发需要操作者一次常见的手误——把值填进名字位）。

### V-29 区域 11 的 `Z11-2`（字节预算在写响应体之前就释放，P2）我顺着调用链核过
- **读侧确实有预算**：`internal/federation/service.go:725-729`（raw）与 `:760-764`（归一化）都是
  `reserve := reserveFor(...)` → `if !s.buffers.acquire(reserve) { return …, ErrBufferBudget }`
  → **`defer s.buffers.release(reserve)`**，然后才 `io.ReadAll`。
- **但 body 的生命周期比这长**：这两个函数把 body **放进返回值**交出去
  （raw 是 `RawResult{Body: body}`，归一化是 `json.RawMessage(body)`），
  而真正写给客户端的地方在**更外层**：`internal/httpapi/federation_routes.go:141`（`w.Write(result.Data)`）
  与 `:297`（`w.Write(result.Body)`）。
- ⇒ **`release` 在 `w.Write` 之前就已经执行**（defer 在 fetch 函数返回时运行）⇒
  预算约束的是**读**，不是**被持有的 body**；一个慢读客户端可以让 body 在内存里停留到 `TotalTimeout`（45 s），
  而这期间预算已显示为 0。N 个这样的客户端可同时在内存里持有 N × `maxBody`，
  **而联合不变量（在途 × body）恰好在这段时间里不成立**。
- **与 P0-3/B-3 的关系**：这是同一处代码的**第三种**缺口形状——
  P0-3 把"无界"改成"有界且会 shed"（`Z09-4` 指出该界**没有分摊**），
  本条指出该界**挂在错误的区间上**（读相而不是持有相）。三者应作为**一次**重新推导
  `MaxBufferedBytes` 的工作项（写清它约束的是哪一段时间）。
- **状态**：CONFIRMED（源级，读码至调用点）。**定级**：同意 P2（需一次登录 + 一个会返回大 body 的源 + 慢读客户端；
  但后果是容器内存越界，而清单的 limit 是 512Mi）。

### V-30 区域 08 的前端静态服务：我逐行读了 `internal/webui/webui.go`，五条机制成立
一个函数（`Handler`）与一个 `switch`（`setCacheHeaders`）就把区 08 的多数发现解释完了：
- **`Z08-1`（缺失 asset 回 200 + shell，不是 404）**：`webui.go:119-121`
  —— `if name == "" || name == "." || !isFile(fsys, name) { name = "index.html" }`。
  一个**不存在的** `_app/immutable/entry/start.<hash>.js` 当然不是文件 ⇒ 落进这一支 ⇒
  **以 200 交出 shell**。（包注释 `:90-93` 自己说明了这个取舍：客户端路由需要它，
  也正是这个 handler 必须钉在自己前缀上的原因。）
- **`Z08-2`（shell 标 `no-cache` 却没有任何校验器，永远不可能 304）**：
  `:148` 只设 `Cache-Control: no-cache`；载体是 `http.ServeFileFS`，
  而 `embed.FS` 的 `ModTime` 是零值 ⇒ 不会有 `Last-Modified`，本包也不设 `ETag`
  ⇒ 每次导航都要重新下整份 shell。
- **`Z08-3`（除 `_app/immutable/` 与 `index.html` 外没有任何 `Cache-Control`）**：
  `setCacheHeaders`（`:143-150`）的 `switch` **只有这两个分支**，其余文件**完全不设头**（连 `no-store` 都没有）。
- **`Z08-4`（Range 能把 shell 的字节切片当成缺失 asset 的 206 返回）**：
  缺失名先被改写成 `index.html`（`:120`），再交给 `http.ServeFileFS`（`:129`）——
  它**支持 Range**，而这一层没有任何"不给 shell 做 Range"的判据 ⇒ 机制成立。
- **`Z08-5`（`_app/immutable/` 标 `immutable` 却带 `Vary: Cookie`）**：`:145-146` 设 `immutable`；
  `Vary: Cookie` 来自会话中间件（见 V-13）⇒ 共享缓存必须按 Cookie 分键，`immutable` 名存实亡。
- **正面结论（应当保留为守卫）**：包注释 `:8-12` 明确"never injects data, never templates,
  never rewrites the shell"——这与第五轮 A-FE-* 的多条绿探针一致，也解释了为什么前端面**没有**服务端注入类缺陷。
- **状态**：五条均 CONFIRMED（源级）。区 08 的独立复核者仍在跑，最终裁定以 `Z08-VERIFIED.md` 为准。

## 4. 已排除（**不要**报成新发现）

- `postgres/oidc.go:834` 的 `auth_time = COALESCE(auth_time, now())` 用了数据库 `now()`：
  **第六轮已按 P2-32 裁定为「display-only 回退，无期限裁决读它」**，
  并由 `clock_inventory_probe_test.go` 的三条豁免清单盯住。**不是新发现。**
- `TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` 的红：夹具桩假象（第六轮 §5 已自证）。
- 根目录残留二进制（`re4auth.exe`/`perfreport.exe`/`httpapi.test.exe`）：被 `*.exe` gitignore 覆盖、从未入库。
