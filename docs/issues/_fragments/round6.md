# 第 6 轮 · 抽取结果

> 审计对象 HEAD = `bf81b2a`。第 7 轮在 `docs/audit-7/findings/00-MAIN-VERIFICATION.md` §1
> 用同一批探针在 HEAD 上复跑，结论是**第 6 轮的红探针全部仍红**（无修复落地）。
> 该结论记录的是第七轮审计当时那个 HEAD；此后落地的修复以各条目的 `状态` 为准
> （P0 三条 G-1/G-2/G-3，以及 G-4/G-5/G-6/G-12，均已在本仓库修复）。环境无 Docker、
> 无本地 Postgres，需要真库才能定论的标 `OPEN-PG`（权威验证位是 CI 的 `postgres:16`）。

## P0/P1

### G-1 refresh token 重放被检测到之后，小偷那条链继续有效
- **严重度**：P1 · 阻断
- **上线阻断**：是
- **位置**：`internal/store/memory/oidc.go:211`（`ErrRefreshTokenSpent` 哨兵；返回处 `:556`，Postgres 对应 `internal/store/postgres/oidc.go:340` / `:399`）
- **影响**：refresh 是单次使用 + 轮换。小偷把偷到的第 2 代自己轮换成第 3 代后，合法客户端重放第 2 代（盗窃信号）只被拒，**第 3 代无人撤销**——攻击者保有静默访问直到 30 天 TTL 自然结束。「即时可撤销」卖点反面。
- **修法**：检测到已消费 refresh 重放时撤销该 (client, subject) 全部 refresh/access（RFC 9700 token family 撤销）。注意第 7 轮更正：检测点上被重放那行已被 delete，store 拿不到 subject/client，**必须先在轮换时留族/代号标识或墓碑**，否则修不出覆盖顺序重放的版本。
- **状态**：FIXED（79d7333）；探针已重推为回归守卫
- **证据**：`internal/zzprobe/audit6/z02protocoltoken/refresh_test.go::TestZ02RefreshReplayRevokesTheThiefsGeneration`（红）；`00-MAIN-VERIFICATION.md:249-267`（V-10 读码三点齐备）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:58`

### G-2 生产后端（Postgres）的 refresh token 过期从不被裁决，30 天 TTL 只由 15 分钟一轮的 sweep 执行
- **严重度**：P1 · 阻断
- **上线阻断**：是
- **位置**：`internal/store/postgres/oidc.go:430`（SELECT 无 `expires_at` 谓词；轮换声明 `:392-401` 同）；对照内存 `internal/store/memory/oidc.go:573`
- **影响**：过期 refresh token 仍能换出**全新 30 天 TTL** 的 access+refresh（TTL 被重置而非拒绝）；sweep 连续失败时窗口继续延长（`cmd/re0auth/main.go:1111` 只打日志）。默认套件全跑内存后端，所以测试永远绿而生产行为不同。
- **修法**：`TokenRequestByRefreshToken` 的 SELECT 与轮换声明加 `expires_at > $n`（`$n` ← `s.now()`，保持单时钟政策）；两后端同形；`clock_test.go` 补「过期 refresh 被拒」。
- **状态**：FIXED（79d7333）；PG 侧端到端形状由 CI 的 postgres:16 定论
- **证据**：`00-MAIN-VERIFICATION.md:70-74`（V-01）；`05-memory-store.md:27-56`（HYPOTHESIS，差 `TEST_DATABASE_URL`）；`internal/zzprobe/audit6/z05memstore/drift_guards_test.go::TestMemoryRefusesAnExpiredRefreshToken`（绿，钉内存拒绝半边）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:75`

### G-3 数据库故障时 RFC 7009 撤销回答 200，用户以为被盗令牌已撤销
- **严重度**：P1 · 阻断
- **上线阻断**：是
- **位置**：`internal/store/postgres/oidc.go:474`
- **影响**：三个 owner 查找全部以 `err == nil` 为进入条件，任何错误（连接断开、故障切换、`statement_timeout`、ctx 取消）都落穿到 `:530` 的 `return nil` ⇒ 协议层按「未知令牌即成功」答 200 且**不写审计**。客户端按 RFC 7009 不再重试，令牌在库恢复后继续有效到自然过期（refresh 最长 30 天）。安全事件响应路径上的静默失效。
- **修法**：三个查找各接 `noRows(err)` 分类——只有 `pgx.ErrNoRows` 允许落穿；其余返回 `oidc.ErrServerError()`（映射 500，可重试）。照抄同文件 `TokenOwner`（`oauth.go:207`）的形状。
- **状态**：FIXED（79d7333）
- **证据**：`internal/zzprobe/audit6/z04pgstore/revocation_error_probe_test.go::TestRevokeTokenDoesNotReportSuccessWhenTheDatabaseCannotAnswer`（红）、`::TestRevokeTokenClassifiesOnlyNoRowsAsUnknownToken`（红）；`00-MAIN-VERIFICATION.md:76-80`（V-02）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:90`

### G-4 `prompt=login` 与 `max_age` 被完全忽略，id_token 带旧会话的 `auth_time`
- **严重度**：P1
- **位置**：`internal/oidchttp/oidchttp.go:950`（只有 `prompt=none` 分支；`MaxAge` 生产代码零命中）
- **影响**：RP 请求 step-up 重新认证时，OP 既不重新认证也不回 `login_required`，id_token 携带**旧会话的 `auth_time`**。`max_age` 完全不被读取。
- **修法**：`oidcstore.AuthRequest` 没有 `MaxAge`/`Prompt` 字段 ⇒ 需**先在存储边界加字段**再在会话/登录钩子裁决；无活会话时按 `login_required` fail-closed。不是「钩子里比较 auth_time」能解决的。
- **状态**：FIXED（4658066）
- **证据**：`internal/zzprobe/audit6/z01protocolauth/consent_face_test.go::TestProbePromptLoginAndMaxAgeDoNotForceReauthentication`（红）、`z02/idtoken_test.go::TestZ02MaxAgeAndPromptLoginAreIgnored`（红）；`00-MAIN-VERIFICATION.md:28,60,269-283`（V-11）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:111`

### G-5 percent 编码的 client_id 绕过内省守卫
- **严重度**：P1
- **位置**：`internal/oidchttp/oidchttp.go:1107`（守卫；放行点 `:1115`）
- **影响**：`Basic z02-d%65vice-…` 使守卫用原始字节查库失败即 `return false`，而库 `url.QueryUnescape` 解码后认证通过 ⇒「内省必须机密客户端」（P0-6 / PROTO-4 的唯一修法）被一行绕过。未误配时攻击者只读到自己的令牌；名单一旦含公开客户端即等价 PROTO-4 复活。
- **修法**：守卫在查库前对 Basic 里的 client_id 做 `url.QueryUnescape`（与库对齐），或先解码再判定；并收紧 `return false` 的宽容语义（查不到/非机密直接 401，`client_assertion` 路径进守卫前显式拒绝）。
- **状态**：FIXED（4658066）
- **证据**：`internal/zzprobe/audit6/z02protocoltoken/introspect_test.go::TestZ02IntrospectionGuardBypassedByPercentEncodedClientID`（红）；`_audit/protocol.md:31-107`（P-01，红探针 `TestZZAudit_IntrospectionPublicClientGuardIsBypassedByPercentEncoding`）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:112`

### G-6 匿名者可以机密客户端身份发起设备流
- **严重度**：P1
- **位置**：`internal/oidchttp/oidchttp.go:576`（项目边界；机制在库 `pkg/op/device.go:138` 丢弃 `ClientIDFromRequest` 的 `authenticated`）
- **影响**：`POST /oauth/device_authorization` 对任何（含机密）客户端都不要求认证，而验证页会把该客户端的**注册名**展示给任何跟着 user_code 走的人。第 7 轮更正：本项目 `AuthorizeClientIDSecret` 不在这条路径上，**不能靠改它来修**。
- **修法**：在 `internal/oidchttp` 把请求交给库**之前**对机密客户端强制认证（与 token 端点同形）。
- **状态**：FIXED（4658066）
- **证据**：`internal/zzprobe/audit6/z01protocolauth/device_flow_test.go::TestProbeConfidentialClientCanStartADeviceFlowUnauthenticated`（红）；`00-MAIN-VERIFICATION.md:82-92`（V-03 根因更正）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:113`

### G-12 k8s 关闭预算与 grace 不自洽，在途审计批次整批丢失
- **严重度**：P1
- **位置**：`cmd/re0auth/main.go:137`（`endpointRemovalWait=5s`）、`:127`（`shutdownTimeout=30s`）、`internal/store/postgres/auditbatch.go:54`（`auditDrainTimeout=30s`）、`deploy/k8s/base/deployment.yaml:26`（`terminationGracePeriodSeconds: 45`）
- **影响**：三者串行，最坏 5+30+30=65s > 45s ⇒ SIGKILL 发生在审计排空预算到期**之前约 10s**；「过期拒绝」路径在 k8s 里从不运行，滚动更新/驱逐时在途审计行静默丢失，审计链在 k8s 上不可信。
- **修法**：`auditDrainTimeout` 改为 `grace - removal - http`（=10s），或把 grace 提到 ≥70s 并同步注释；至少把 `deployment.yaml:21-25` 的「35s total」注释改为全栈口径。
- **状态**：FIXED（657d2f0）
- **证据**：`internal/zzprobe/audit6/z04pgstore/drain_budget_probe_test.go::TestTheShutdownStackFitsThePodGrace`（红）、`::TestTheManifestCommentCountsTheWholeStack`（红）；`00-MAIN-VERIFICATION.md:174-185`（V-06，定级 P1）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:119`

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| G-7 | P2 | 已批准的 device_code 过了 `expires_at` 仍能铸出整套令牌（库 `Done` 短路先于 `Expires`；两后端消费谓词都无期限判断） | `internal/store/postgres/oidc.go:749` | FIXED（4dff4a3） | 两后端消费谓词补 `expires_at`（PG 的 DELETE 加 `AND expires_at > $n` ← `s.now()`） |
| G-8 | P2 | `/oauth/revoke` 是存活性预言机：匿名者对别人的活跃令牌得 401、对未知字符串得 200 | `oauth/as.go:223` | FIXED（4dff4a3） | 让响应形状不区分「别人的活令牌」与「未知字符串」（`oauth/as.go:234-239` 与 `:223-231` 自相矛盾） |
| G-9 | P2 | 刷新后的 id_token 丢掉 `nonce`（OIDC Core §12.2 要求保留），检查 nonce 的 RP 每次刷新都失败 | `internal/oidcstore/oidcstore.go`（`RefreshRequest` 无 nonce 字段；探针 `internal/zzprobe/audit6/z01protocolauth/regress_test.go:394`） | FIXED（17914d4） | refresh 路径签发的 id_token 带上原始 nonce（两 store 需持久化） |
| G-10 | P2 | 设备流 token 轮询拒绝 discovery 广告的 `client_secret_post`，且被拒的 401 把 device_code 烧掉 | `pkg/op/device.go:217`（机制）/ `:235`；修法在 `internal/oidchttp` 边界 | FIXED（4dff4a3） | 设备授予接受 `client_secret_post`，且 401 **不得**先跑消费谓词烧掉 device_code |
| G-11 | P3 | `/readyz` 在「已有一次检查在跑」且**从未产生结论**时答 200（`running` 分支返回零值 `nil`） | `internal/httpapi/health.go:111` | OPEN | `c.running && !c.checked` 时 fail-closed 回 503；已下调 P3（出厂清单下 kubelet 撞不到） |
| G-13 | P2 | `GetRefreshTokenInfo` 把数据库错误折叠成 `op.ErrInvalidRefreshToken`，废掉库的 500 分支 | `internal/store/postgres/oidc.go:561` | FIXED（79d7333） | `noRows(err) → 哨兵；其余原样返回（wrap）`；与 G-3 同批收口 |
| G-14 | P3 | `oidc_devices` 是第七张没有 `client_id` 前导索引的 client-only 批量撤销表，守卫手写清单也漏了它 | `internal/store/postgres/oidc.go:1075`、`internal/store/postgres/migrations/0022_bulk_revoke_client_indexes.sql` | OPEN | 迁移 0023 补 `oidc_devices(client_id)`；守卫改为从 `revokeMatching` 调用点反推表集合 |
| G-15 | P3 | 设备路径 `slow_down` 节流锚点分叉：内存锚「上一次尝试」、PG 锚「上一次放行」 | `internal/store/memory/oidc.go:884` vs `internal/store/postgres/oidc.go:773` | OPEN | 裁定一个语义（建议锚「上一次尝试」），PG 改为无条件写 `last_poll`；无安全后果 |
| G-16 | P3 | 内存 `cloneAuthRequest` 仍共享 `CodeChallenge`/`AuthTime` 两个指针字段，写穿即改库 | `internal/store/memory/oidc.go:435` | OPEN | 两字段深拷贝；机制成立但今天无写穿调用方（可达性已降格，留作潜在缺陷） |
| G-17 | P3 | Postgres 的设备批准/拒绝审计事件不带 `client_id`（内存带） | `internal/store/postgres/oidc.go:898`（deny `:919`） | OPEN-PG | 两处 UPDATE 改 `RETURNING client_id`；生产审计链回答不了「哪个客户端被批进来」 |
| G-18 | P3 | vault 身份命名空间 `game + "." + source` 无字符校验，两个 (game, source) 映射同一凭据行 | `internal/federation/binding.go:76` | OPEN | `NewRegistry` 校验 `Game`/`Name` 字符集 fail-closed；**不能**改拼接符（AAD 绑存量密文） |
| G-19 | P3 | `vault.Rotate` 把自己的审计写入失败用 `_ =` 丢弃，而 Enroll/Use/Revoke 全 fail-closed | `vault/rotate.go:82` | OPEN | 与 Enroll/Use/Revoke 同纪律（返回错误，让 `rotateAndReport` 非零退出）；轮换幂等，重跑无害 |
| G-20 | P3 | `Enroll` 先落库后写审计：审计失败时凭据已存、调用方被告知失败，绑定路径不回滚不记日志 | `vault/service.go:209`、`internal/federation/bind.go:191` | OPEN | 与兄弟分支 `bind.go:198-213` 对齐：失败尝试 `vault.Revoke` 回滚，失败则 slog + `errors.Join` |
| G-21 | P3 | vault 错误文本内嵌原始 `usr_…`，经 `-rotate-keys` die 路径与 unbind/cascade warn 路径进进程日志 | `vault/repo.go:29`、`vault/service.go:273`、`vault/rotate.go:113` | OPEN | 错误里用形状代替身份（只报 provider + kek_id）；attr 守卫结构上看不见这个通道 |
| G-22 | P3 | 三把 32 字节密钥可共用同一值被无提示接受（KEK == token key，乃至 audit key） | `cmd/re0auth/config.go:719`、`cmd/re0auth/main.go:1385` | OPEN | `loadConfig` 解析完三把密钥后两两比较，相同即拒绝启动（或至少 Warn） |
| G-23 | P2 | 第五轮仍红的 7 处 `usr_…` 进 slog attr，确认仍未修 | `internal/admin/admin.go:499`、`internal/auth/auth.go:231`、`internal/federation/bind.go:208`、`internal/federation/refresh.go:155/160`、`internal/httpapi/account_routes.go:80`、`internal/httpapi/binding_routes.go:57` | FIXED（6665193） | 统一改记形状（`"self", bool` / 只记 action）；与 G-21 是同一不变量的两半，一起收 |
| G-24 | P2 | `/.well-known/oauth-protected-resource` 对非 GET 动词答 404（同族另两份文档答 405），且 405 不带 `Allow` 头（RFC 9110 §15.5.6 MUST） | `internal/httpapi/server.go:509-535`；`internal/oidchttp/oidchttp.go:270-296` | FIXED（本轮） | 三份 well-known 文档的动词闸门同形：httpapi 的 `onlyMethods` 给 protected-resource 405+`Allow: GET, HEAD`，oidchttp 的 `methodNotAllowed` 给两份 discovery 同形 405+`Allow`（集合取自拒绝它的同一张表）；守卫：`audit6/z06httpedge` 的 `TestZ06WellKnownVerbMatrixCoversEveryDocument`、`audit6/zverify` 的 `TestV12*` |
| 04-7 | P3 | 0022 一类索引迁移在单个 goose 事务里非并发建索引：在役升级窗口对相关表是写冻结 | `internal/store/postgres/migrations/0022_bulk_revoke_client_indexes.sql` | OPEN-PG | 记录在 migration-decision；表会大时改 `CREATE INDEX CONCURRENTLY` + `-- +goose NO TRANSACTION`（0017-0022 同形） |
| P-02 | P3 | 设备流批准不检查 `ExplicitConsent`，与同意面不对称（机制在、闸门缺） | `internal/httpapi/device_routes.go:114`、`internal/store/memory/oidc.go:1086` | OPEN | `ApproveDevice`（含 Postgres）在 `Resolve` 后调 `RequireExplicitConsent` 并把 `explicit` 一路传下去；今天目录无此类 scope 故不可达 |
| P-03 | P3 | discovery 缓存无 Host 维度：动态 issuer 下一次伪造 Host 永久固定两份文档 | `internal/oidchttp/oidchttp.go:346`（缓存键）；`serveDiscovery` `:293` | OPEN | 缓存键改 `IssuerFromRequest(r) + path`，或 `Config.Issuer == ""` 时禁用缓存；生产强制 issuer 必填故限动态形态 |

## 已修复（仅 ID + 一句话，供溯源）

- G-24 — 三份 well-known 文档的动词闸门同形：405 + `Allow`（httpapi `onlyMethods`、oidchttp `methodNotAllowed`）；`TestZ06WellKnownVerbMatrixCoversEveryDocument` 由红转绿 — 本轮
- （无）第 7 轮在 HEAD=`bf81b2a` 复跑第 6 轮全部红探针仍红，**第 6 轮无发现被修复**（`00-MAIN-VERIFICATION.md:20-66`）。
- B-1 — 第五轮阻断项 id_token 缺必需 `sub`；第 6 轮实测已修（`_audit/protocol.md:206`）。
- B-2 — id_token 可在 `/oauth/userinfo` 当 access token 用；第 6 轮实测已修（`_audit/protocol.md:207`）。
- PROTO-1 — 不可解析 body 吞 `ParseForm` 错误绕过设备 scope 闸门；已修（`_audit/protocol.md:208`）。
- PROTO-4 — 内省白名单含公开客户端 ⇒ 无凭据读任意 token；**主体已修**（守卫被转义绕过另记 G-5）（`_audit/protocol.md:209`）。
- PROTO-5/6/7/9/10 — discovery 不撒谎、`prompt=none` 落地、`form_post` 拒绝带 `iss`、POST+query 拆分拒绝、userinfo 判据；均已修（`_audit/protocol.md:210-214`）。
- P1-1/P1-2 — vault 轮换窄写/CAS（lost-update）；第 6 轮新探针验证「修对、修全」（`03-crypto-vault.md:173-193`）。
- P2-32 — 设备路径单时钟（bf81b2a）；三处 SQL 参数化，未引入新洞（`03-crypto-vault.md:195-201`）。
- G-9 — 刷新签发的 id_token 保留原 nonce（OIDC Core §12.2）：`RefreshRequest`/`NonceOf`、两个 store 在 refresh 行上持久化并随轮换继承、`SetUserinfoFromRequest`、迁移 `0026`；audit6 里原本断言「刷新后没有 nonce」的探针翻转为断言保留 — `17914d4`
- G-23 — 6 处原始 `usr_…` 不再进 slog（admin/auth/federation bind+refresh/httpapi binding_routes；第 7 处 account_routes 由 k1 收掉）；audit5 静态守卫由红翻绿 — `6665193`
- G-13 — `GetRefreshTokenInfo` 现在把 `noRows` 报成哨兵、其余报 `oidc.ErrServerError`（库的 500 分支恢复可达）；经查在 `79d7333` 随 G-3 一并修掉，注册表此前陈旧 — `79d7333`
- G-7 — 已批准但过期的 `device_code` 不再换到令牌：库先判 `Done` 再判 `Expires`，两个 store 同时收紧消费谓词并修掉「`Done=true` 的 fall-through」（memory 删除后 `Done=false`，postgres 过期时补删再清 `Done`） — `4dff4a3`
- G-8 — `/oauth/revoke` 不再当存活性预言机：他人的活令牌与未知字符串同样 200、都不删；公共引擎与两个 store 的 `RevokeToken` 同步 — `4dff4a3`
- G-10 — 设备码轮询接受自己广告的 `client_secret_post`，且认证失败不再烧码：`internal/oidchttp` 在库的消费谓词之前先认证机密客户端 — `4dff4a3`

## 有意不做 / 已裁定

- `TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` — 该探针的 `GET /oauth/token → 200` 是夹具假象（`edgeServer()` 把 `Config.OIDC` 设成永远答 200 的桩），**不是生产缺陷，不进清单** — 依据：`docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md:146`
- 根目录残留二进制（`re0auth.exe`/`perfreport.exe`/`httpapi.test.exe`）— 被 `.gitignore` 的 `*.exe` 覆盖、从未入库，**判定「不是发现」**（唯一信息级风险：`.dockerignore` 没有 `*.test`）— 依据：`docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md:157`
- O-9 — `end_session` / `id_token_hint` / PAR / 动态客户端注册 / Session Management **明确不做、不广告** — 依据：`docs/oidc-decision.md:45`
- O-3 — userinfo 不以 `openid` 为闸门：任何活访问令牌都回 `sub`，`openid` 只约束 id_token；这是**有意**的（PROTO-10 判为已证伪）— 依据：`docs/oidc-decision.md:37`
- O-6 — refresh token 总是签发，`offline_access` 是兼容性空操作（接受但不要求、不报错、不对外呈现）— 依据：`docs/oidc-decision.md:41`
- D-3 / D-2 — v1 不做 DPoP（并已从 AS 元数据移除广告）、access token 保持不透明引用令牌 — 依据：`docs/api-design.md:12-13`
