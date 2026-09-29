# 区域 20：授权隔离矩阵（主体 × 客户端 × scope × 资源）— 第七轮审计报告

## 范围与方法

读了 `oauth/{as,client,scope,grants,device,tokens,service,http}.go`、
`internal/oidchttp/oidchttp.go`（含 zitadel/oidc v3.51.3 `pkg/op/*` 依赖源码）、
`internal/oidcstore/oidcstore.go`、`internal/store/{memory,postgres}/oidc.go`、
`internal/httpapi/{v1,grants,binding,federation,admin,authorization,device,account,identity,session,idp,export}_routes.go`、
`internal/httpapi/{server,middleware}.go`、`internal/federation/*.go`、`internal/admin/admin.go`、
`internal/auth/auth.go`、`config/re0auth.example.toml`、`docs/upstream-protocol.md` §7/§9。

探针（`internal/zzprobe/audit7/z20authzisolationmatrix/`，全部 `//go:build audit7`；`fixture_test.go` 用
**导出面**搭真栈：`httpapi.New`＋真 OP（`oidchttp.New`＋`memory.NewOIDCStore`）＋真数据面
（`federation.NewService`）＋真上游 httptest）。令牌走真 authorize→consent(`CompleteLogin`)→callback→
`/oauth/token`；命令：`go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z20authzisolationmatrix/...`
→ 4 红 / 6 绿。`go build ./...`、`go vet ./...`（含 `-tags audit7`）exit 0，`gofmt -l` 干净，未改任何被跟踪文件。

## 发现

### Z20-1 每一次成功的授权码兑换都写一条 `oidc.consent.deny`（两后端），且字段全空
- 严重度：P2 中 ｜ 类别：合规/隐私（审计完整性）｜ 不变量：撤销生效/审计忠实
- 证据（实跑，红）：`TestZ20SuccessfulCodeExchangeWritesASpuriousConsentDeny`
  ```
  a SUCCESSFUL code exchange recorded oidc.consent.deny:
      subject="" outcome=denied detail=map[client_id:]
  ```
  机制：AUD-3（本轮修复，commit `636a074`）让 `DeleteAuthRequest` 无条件记
  `oidc.consent.deny`（`memory/oidc.go:449-467`，postgres `oidc.go:287-311`）。但库在
  **成功**路径也调它——`op.CreateTokenResponse` 铸完令牌后删 auth request（zitadel/oidc
  `pkg/op/token.go:50`）；而 `AuthRequestByCode` 已经把行删掉（`memory:418-433`、
  postgres `DELETE ... RETURNING` `:240-249`），所以事件里 subject 与 `client_id` 都是空串。
  阳性对照：`TestZ20ARealRefusalStillRecordsTheEvent`（真拒绝→1 条 deny 且带 `client_id`）、
  approve 事件带 `client_id`+`scopes`（同探针断言）。
- 影响：拒绝流被污染——每成功登录一条假「用户拒绝」，与真拒绝只差「字段是否为空」。
  事故响应者按 `oidc.consent.deny` 统计「用户拒绝授权」时得到 1:1 的假阳性；
  同一授权的 approve 与 deny 同时存在，日志自相矛盾。
- 修法：只在前置条件成立时记 deny——`DeleteAuthRequest` 先读 `done`/`subject`，
  `subject == ""` **且** 行已不存在时按「已兑换的清理」记 `oidc.consent.exchange`
  （或不记），仅当行存在且 `!done` 时记 `oidc.consent.deny`。postgres 同理（在同一个 tx 里
  `SELECT ... FOR UPDATE` 后判定）。
- 探针：`consent_audit_test.go::TestZ20SuccessfulCodeExchangeWritesASpuriousConsentDeny`（红）
- 相关：AUD-3 引入的新洞；provenance：工作区已有一条同形状的第六轮探针
  `internal/zzprobe/audit6/z01protocolauth/audit_deny_test.go`（自称 01-2），但该条**不在**
  任何第六轮报告里（`_audit/protocol.md` 只有 P-01…P-03；`00-LAUNCH-READINESS-CONSOLIDATED.md`
  的 G-1…G-24 无此条），也不在本轮 `docs/security-audit-7.md` 的任何表中。

### Z20-2 raw 透传的闸门按「源」判、不按「资源」判 ⇒ 用户不授予的 scope 仍读得到该资源
- 严重度：P2 中 ｜ 类别：安全 ｜ 不变量：token/scope 签发、账号隔离
- 证据（实跑，红）：`TestZ20RawPassthroughIgnoresWhichResourceTheScopeNames`
  ```
  normalized GET /v1/games/phigros/scores            (profile-only token) -> 403
  raw        .../raw/resources/scores               (account.id token)   -> 403   [对照]
  raw        .../raw/resources/scores               (score token)        -> 200   [对照]
  raw        .../raw/resources/scores               (profile token)      -> 200  {"marker":"Z20-SCORES"}
  ```
  配置：源 `fake` 的 `raw_base` = 它的 issuer（`config/re0auth.example.toml:365` 展示的形态，
  raw_base 就是源的原生 API 根），于是 raw 路径与归一化路径**指向同一个 URL**
  （探针里上游只被访问 `/resources/scores` 两次）。闸门是 `sourceScopes` 的「持有该源**任一**
  资源 scope」＋`hasAnyScope`（`httpapi/federation_routes.go:223-236,245-265`），
  而归一路径要求的是**每个**候选源的**该资源** scope（同文件 `:105-122`）。
- 影响：用户在同意页明确不给 `phigros.score.read`（或只授 profile），客户端照样能通过
  `/raw/resources/scores` 读到同一份成绩数据；归一化路径的 403 被同一数据的另一个入口绕过。
  前提：该源声明了 `raw`（这是产品的公开能力，`docs/upstream-protocol.md` §9）。
- 修法：raw 闸门至少按「与归一化同一判据」收口——对 `{path}` 做资源名归一化后要求该资源的
  scope；或引入显式 `<game>.raw.read`（当前代码注释自认是 future work，
  `docs/upstream-protocol.md` §9 只说「鉴权/转发/限流/provenance」，未声明 raw 为**源级**闸门）。
- 探针：`scopegate_test.go::TestZ20RawPassthroughIgnoresWhichResourceTheScopeNames`（红）
- 相关：第四轮空的 scope 集闸门修复的**补充**（那次修的是「无 scope 声明 ⇒ 不检查」，
  不同一形状）；与 Z09-1/Z09-3 无关。

### Z20-3 设备面的同意决策审计不带 scope（AUD-3 只覆盖了交互面）
- 严重度：P3 低 ｜ 类别：合规/隐私（审计完整性）
- 证据（实跑，红）：`TestZ20DeviceApprovalAuditOmitsTheGrantedScopes`
  ```
  the device approval records no scopes: detail=map[client_id:cli]
  ```
  `ApproveDevice` 只调 `s.record(ctx,"oidc.device.approve",subject,d.clientID,…)`
  （`memory/oidc.go:1104`），而交互面 `CompleteLogin` 走 `recordConsent` 记 `Detail["scopes"]`
  （`:1055-1060`）。设备面恰是 **narrowing** 发生的地方（`NarrowScopes`，
  `memory/oidc.go:1384-1406`），请求集与授予集可以不同。
- 影响：日志答不出「这个账号通过设备流批了哪些 scope」——AUD-3 承诺的正是这个问句。
- 修法：`ApproveDevice` 改走 `recordConsent(..., d.scopes, OK)`。
- 探针：`consent_audit_test.go::TestZ20DeviceApprovalAuditOmitsTheGrantedScopes`（红）
- 相关：AUD-3 的完整性缺口（其 changelog 明写「含 client_id 与批准的 scopes」）；
  与 G-17（postgres 侧缺 client_id）同族但不同字段。

### Z20-4 【反驳 P-02】设备批准入口**确实**执行 ExplicitConsent
- 严重度：P3 低 ｜ 类别：可维护性（错误结论会导致错误的修法）
- 证据（实跑，绿＋源级）：`consent_audit_test.go::TestZ20DeviceApprovalEnforcesExplicitConsent`
  ——用一条**真的**带 `ExplicitConsent` 的目录（`oauth.NewRegistry(DefaultDescriptors()+…phigros.secret.read)`）
  经真 `/oauth/device_authorization` 取 user code，再走设备路由的那一次调用
  （`httpapi/device_routes.go:114` → `DeviceStore.DecideDeviceAuthorization`）：
  带勾选 → 通过；不勾 → `access_denied`。源：`memory/oidc.go:1397-1402`
  `Resolve` 后 `oidcstore.RequireExplicitConsent(descriptors, explicit)`（postgres `:1217` 同形）。
- 影响：P-02 的「设备面缺闸门」不成立 ⇒ 按其建议再加一道会重复；真正的缺口只是**没有测试**
  与「目录里还没有 ExplicitConsent scope」。
- 修法：把 P-02 改判为「已具备、缺守卫」，加一条带 ExplicitConsent 目录的设备面测试。
- 相关：**反驳 P-02**（第六轮区 01）。

### Z20-5 【补充/更正 G-8】生产 OP 的 `/oauth/revoke` 也是存活性预言机
- 严重度：P3 低 ｜ 类别：安全 ｜ 不变量：撤销生效、fail-closed
- 证据（实跑，红）：`revocation_oracle_test.go::TestZ20RevocationIsALivenessOracleForForeignTokens`
  ```
  revoke an unknown string        -> 200
  revoke another client's live AT -> 401 {"error":"invalid_client","error_description":"token was not issued for this client"}
  ```
  即：匿名（公开 client id 不是凭据，Basic 里空 secret 即可）能对任意字符串二值判定
  「本服务签发过且仍活着吗」。阳性对照 `TestZ20RevocationRefusesToDeleteAnotherClientsGrant`：
  外来令牌**不会被删**，所有者仍能撤销（核心隔离是好的）。
- 影响：确认预言机。项目自己把这条定为缺陷（`oauth/as.go:223-239` 逐字写明「不得确认」），
  但本轮之前只记在**公开引擎**（kit/第三方源）上；**部署面**（zitadel `Revoke` 路径 +
  `memory.RevokeToken:619-622,649-655` 的 `ErrInvalidClient`，`LegacyServer`/`Revoke` 的
  `RevocationError` 把 unknown 映回 200）从未被修也未被记。
- 修法：让「别人的活令牌」与「未知串」同形——一律 200 且不泄漏归属（内部仍需拒绝删除，
  只是响应形状统一），或按 RFC 7009 只对**本人**令牌报错。
- 相关：**对 G-8 的补充**（影响面漏了部署面）。

### Z20-6 【反驳 P-01 的影响面】转义拼写绕过内省守卫后**什么也拿不到**
- 严重度：P3 低 ｜ 类别：合规/隐私（结论严重度被夸大）
- 证据（实跑，绿＋源级）：`introspection_refutation_test.go::TestZ20AllowlistedPublicClientDisclosesNothingEvenEncoded`
  ```
  plain public caller            -> 401 {"error":"invalid_client","error_description":"introspection requires a confidential client"}
  percent-encoded public caller  -> 200 {"active":false}
  ```
  机制：守卫确实被绕过（`c%6ci` 让 `refuseIntrospectionByANonConfidentialClient` 查不到客户端而放行，
  库侧 `url.QueryUnescape` 后认证通过），但 `filterIntrospection`（`oidchttp.go:1208-1234`）
  拿到的 caller 是 `callerClientID` —— **同样是原始字节**，既不等于令牌的 `client_id`、
  也不命中 `introspectionClients[caller]`，于是响应在出口被改写成 `{"active":false}`。
- 影响：P-01 的「若该公开客户端名下有一枚令牌，返回就是 `active=true`，危害与 PROTO-4 相同」
  **不成立**：白名单与判等两处都按原始字节，转义拼写永远命中不了。残留只是状态码差异（200 vs 401）。
  仍建议做 P-01 的修法（解码后再查库），并把 `introspection_clients` 的
  「必须是机密客户端」在**启动期**校验（`cmd/re0auth/config.go:654-662` 只做 trim/append，
  `main.go:1345` 直接透传；当前只有运行期守卫）。
- 相关：**反驳 P-01 的影响段**（机制段保留）。

## 探过但没破的（也应变成守卫）

- 跨客户端的**刷新/兑换**身份互换：code、refresh、device_code 都要求 `code.ClientID == client.ID`
  （`as.go:175,202`；`memory/oidc.go:877`），公开客户端用 Basic 冒充机密客户端在 device 轮询被
  `clientAuthenticated != IsConfidentialType` 拒绝。
- 跨客户端的**撤销**：外来令牌不被删（`TestZ20RevocationRefusesToDeleteAnotherClientsGrant`，绿）。
- 归一化路由的 scope 归属：`ResourceRequirements`（要求**每个**候选源的该资源 scope）与
  `Fetch` 用同一个 `candidates()`；换源/退役源在两面一致（`TestZ20NormalizedGateRequires…`，绿）。
- raw 的 game/source 绑定与路径逃逸：未知源 404、`..%2f` 400，上游零调用
  （`TestZ20RawPassthroughIsBoundToTheSourceThatIsNamed`，绿）。
- 会话面写操作与资源归属：grants/bindings/identities/export/erasure 全部 `sessions.User` 取主体；
  consent/device/bind 句柄都是 `Bound`＋`OwnerMatches` 双条件（`auth.go:349-364`）。
- scope 归一化**不更宽松**：`requestedScopes` 读全部 `scope` 值＋`duplicatedParam` 拒重复；
  `StandardOIDCScope` 是精确白名单；refresh 只能收窄（`ValidateRefreshTokenScopes`）。
- `AllowedClients`/`ExplicitConsent` 在 authorize 入口不咨询，但在两个批准入口都咨询
  （`ApproveAuthorization`、`DecideDeviceAuthorization`）⇒ 只失败闭合，不提权。
- `MissingBindings`（P2-17 修后）用与 `candidates` 同款判据；非规范目录（两个资源名共享一个 scope）
  下它会对「另一个资源名」判为已满足，但那是注释里已声明的口径（未列为发现）。

## 未能到达（残余盲区）

- **Postgres 侧全部只有读码级证据**：无本地 PG/Docker，Z20-1/Z20-3 的 postgres 分支
  （`postgres/oidc.go:287-311` 与 `ApproveDevice`）按 `file:line` 标源级；`TEST_DATABASE_URL` 是权威位。
- 真实浏览器/OIDC RP 的同意页交互（`/app/consent`）未跑：探针驱动到句柄与决策 API 为止（无 Playwright）。
- 多副本/多实例下的隔离（跨实例 refresh 家族、Kill Switch 跨副本）未触；本机单进程内存模式。
- `cmd/re0auth` 真进程黑盒（19001）未启用：本轮结论全部由进程内真栈取得，未额外验证监听/中间件叠加。

## 判断（文档化决定，不是 finding）

- `docs/upstream-protocol.md` §9 只把 raw 说成「鉴权/转发/限流/provenance」，没有把「raw 是**源级**
  粗闸门」写成明示决定；若团队裁定「raw 走源级闸门是有意的」，Z20-2 应降为「判断」并补进该文档——
  但归一化路径 403 与 raw 200 读同一份数据，这个不对称本身仍应被记录。
- Permit `introspection_clients` 里放公开客户端：即便加了启动期校验也只是纵深防御；
  Z20-6 表明今天的出口改写已是有效回退。
