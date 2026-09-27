# RP（Re0Auth 作为 OAuth/OIDC 客户端）审计报告

## 范围与方法

**读到的**（端到端，逐行）：
- `idp/idp.go`（651 行全部）：内置五个 provider 表、`Registry`/`Client`、`AuthCodeURL` / `Exchange` /
  `Identity`、`identityFromIDToken`、`identityFromUserInfo`、`oidcProvider`、`idTokenVerifier`、`fetchQQ`、
  `getJSON`/`getText`。
- RP 的真实调用点：`internal/auth/auth.go`（会话、state/nonce/verifier 的存取、`handleStart`/`handleCallback`、
  `Bind`/`OwnerMatches`/`Unbind`）、`cmd/re0auth/main.go:416-446`（组合根的 idp registry 与 auth handler）、
  `cmd/re0auth/config.go:704-750`（`[idp.*]` 解析）。
- 同意交互接缝：`internal/authorization/interaction.go`、`internal/httpapi/authorization_routes.go`、
  `internal/oidchttp/oidchttp.go:109-133/1206-1300`、`cmd/re0auth/main.go:1157-1168`（login hook 绑定含会话的请求上下文）。
- 依赖语义（**读模块缓存源码到行**，标注为「读」）：`coreos/go-oidc/v3 v3.21.0` 的
  `oidc/verify.go`（iss/aud/exp/nbf/alg 校验）、`oidc/oidc.go`（discovery 的 issuer 等值校验与算法过滤）、
  `oidc/jwks.go`（JWKS 缓存、kid 未命中时的重取、失败时的语义）、`golang.org/x/oauth2@v0.37.0/pkce.go`。

**跑到的**（真实执行）：
- 探针包 `internal/zzprobe/protocol/rp/`（**只新增**，未改任何已跟踪文件）。
- `go test ./internal/zzprobe/protocol/rp/ -v`：**12 FAIL / 28 PASS**（40 个探针；FAIL 即下面各条的
  「测试能失败」。反复运行计数稳定）：
  ```
  --- FAIL: TestRPDiscoveredAuthorizationEndpointIsNotPinnedToTheIssuer
  --- FAIL: TestRPDiscoveredTokenEndpointReceivesTheClientSecret
  --- FAIL: TestRPDiscoveryWithoutAuthorizationEndpointYieldsARelativeLoginURL
  --- FAIL: TestRPRealMicrosoftBuiltInIssuerCannotDiscover
  --- FAIL: TestRPConsentApprovalRedirectIsReplayable
  --- FAIL: TestRPConsentDecisionConcurrency
  --- FAIL: TestRPLoginStateIsBoundToItsProvider
  --- FAIL: TestRPLoginLeavesNoFlowValuesInTheSession
  --- FAIL: TestRPAzpNamingAnotherClientIsAccepted
  --- FAIL: TestRPAzpMissingWithMultipleAudiencesIsAccepted
  --- FAIL: TestRPAzpMismatchSingleAudienceIsAccepted
  --- FAIL: TestRPRetiredSigningKeyKeepsVerifyingAfterRotation
  ```
- `go test -race ./internal/zzprobe/protocol/rp/ -v`：**在本机可用**（与简报的预期相反，`-race` 跑得起来），
  输出中没有任何 `WARNING: DATA RACE`。所以本文的可并发结论有竞态检测器背书，其余为单线程证据。
- 真实网络：直接用真实 Microsoft discovery 端点跑通了「内置 issuer 无法 discovery」这一条（见 RP-4），
  Google discovery 从本机超时（见「未能到达」）。

**跑不了的**：无 Docker、无本地 Postgres ⇒ 所有 Postgres 侧（`internal/store/postgres/oidc.go` 的
`CompleteLogin`）没有执行，同意接缝的探针只跑在内存 store 上，已有明确标注。真实 GitHub/Google/Discord/QQ/微软
**令牌交换**没有执行（没有凭据）；所有「伪造 id_token」的探针都对着本地的 fake OP，已在探针里写清。

---

## 发现

### RP-1 id_token 的 `azp` 完全不校验：多受众令牌（含指向别的客户端的 azp）被当作本客户端的身份接受

- 严重度: 高
- 类别: 安全
- 不变量/性质: OIDC Core 3.1.3.7 第 4/5 条 —— `aud` 多值时必须存在 `azp`，且 `azp` 必须等于本客户端；
  单 `aud` 时若存在 `azp` 也必须指向本客户端。RP 必须只接受「发给本客户端」的 id_token。
- 证据:
  - 探针（`go test ./internal/zzprobe/protocol/rp/ -run TestRPAzp -v`，三条全部 FAIL）：
    ```
    idtoken_test.go:70: RP accepted an id_token whose azp is another client:
        sub="victim-of-another-client" aud=[cid other-client] azp=other-client (control sub="rp-user-1")
    idtoken_test.go:91: RP accepted a multi-audience id_token with no azp: sub="no-azp-subject" aud=[cid other-client]
    idtoken_test.go:111: RP accepted an id_token whose azp ("someone-else") is neither the audience nor this client: sub="rp-user-1"
    ```
    同一次运行里的对照（`TestRPControlOIDCLoginSucceeds`）PASS，且断言了 `discovery/jwks/token` 都被走到、
    `userinfo` 一次都没被调用 —— 即上面三条确实走到了 `identityFromIDToken` 而不是空转。
  - 行级：`idp/idp.go:536-542` 构造验证器时只传了 `&oidc.Config{ClientID: c.oauth.ClientID}`；`azp` 这个 claim 在
    `idp/idp.go` 里**一次都没出现**（`oidcClaims` 结构体 `idp.go:479-485` 只有 sub/name/email/picture/nonce）。
  - 读依赖确认职责在包外：`go-oidc v3.21.0` 的 `oidc/verify.go:250-259` 自己写着
    「This check DOES NOT ensure that the ClientID is the party to which the ID Token was issued」，
    只做 `slices.Contains(t.Audience, config.ClientID)`。
- 状态: CONFIRMED
- 影响: 上游只要会把调用方要求的受众（`audience` / `resource` 参数、Keycloak 的 audience mapper 之类）并进 `aud`，
  攻击者用自己的客户端在**同一 issuer** 上取得一份「受害者 sub + aud 含本服务 client_id + azp=攻击者客户端」的
  id_token，就能把它喂给 `/auth/<provider>/callback`（`internal/auth/auth.go:656` → `Identity`），
  RP 会以该 `sub` 建号/登录 —— 即**跨客户端令牌重放变成账号接管**，而 RP 已经付了 PKCE + 签名 + iss/aud 的钱。
  前提必须说清：需要上游允许客户端侧扩展 `aud`（否则攻击者拿不到含本服务 client_id 的令牌），
  以及受害者曾在攻击者的客户端上登录过该上游；在「自定义 OIDC provider」被明确支持（Keycloak/Authentik，
  `cmd/re0auth/config.go:717-727`）的部署里，这个前提不苛刻。不满足前提时该条为「纵深防御缺失」。
- 修法建议: 在 `identityFromIDToken` 里自己判：`claims.Audience` 长度 >1 时 `azp` 必须存在且等于 `ClientID`；
  `azp` 存在时必须等于 `ClientID`（`oidc.IDToken` 暴露了 `Audience`，但没暴露 `azp`，最省事是在
  `oidcClaims` 里加 `AZP string \`json:"azp"\`` 一并解出后校验）。
- 复现/守卫: `internal/zzprobe/protocol/rp/idtoken_test.go` 的 `TestRPAzpNamingAnotherClientIsAccepted`、
  `TestRPAzpMissingWithMultipleAudiencesIsAccepted`、`TestRPAzpMismatchSingleAudienceIsAccepted`。

### RP-2 JWKS 缓存没有 TTL、也不看 `kid` 之外的变化：被吊销/轮换掉的签名密钥仍然一直验签成功

- 严重度: 中
- 类别: 安全
- 不变量/性质: 上游的密钥撤销/轮换必须对验证方生效；「已经不在 JWKS 里的密钥签出的 id_token」必须被拒。
- 证据:
  - 探针（`go test ./internal/zzprobe/protocol/rp/ -run TestRPRetiredSigningKey -v`）：
    ```
    idtoken_test.go:147: RP accepted an id_token signed by a key removed from the JWKS:
        sub="attacker-with-the-retired-key" (jwks fetches before=1 after=1)
    ```
    流程：先正常登录一次（缓存写入 k1，JWKS 取 1 次）→ 上游轮换（k2 签名、JWKS 只公布 k2）→
    用**已下线的 k1** 签一份 id_token → RP 接受；`jwks` 取用次数 before=1/after=1，说明**连一次重取都没有发生**。
  - 行级：`go-oidc` 的 `oidc/jwks.go:163-170` 命中缓存即 `return`，从不检查 TTL；`:176-189` 只在
    「没有缓存密钥能验通」时才 `keysFromRemote`；`:220-222` `if err == nil { r.cachedKeys = keys }` —— 失败不清缓存
    （这点是好事，见「探过但没破的」）。同目录的 `idp/idp.go:521-533` 把 `oidc.Provider`（含 discovery 文档与
    endpoints）也永久缓存在 `c.discovered`，进程生命周期内不再重读。
- 状态: CONFIRMED
- 影响: 「密钥泄露 → 上游轮换密钥」这条事故响应对 RP 无效：只要攻击者用泄露的旧私钥签 id_token，且在他之前没有任何
  合法用户拿着新 kid 的令牌来验（那才会触发一次重取并替换缓存），他就能一直伪造任意 `sub` 通过 RP 的验证。
  同理，上游把 `jwks_uri` 换到新部署后 RP 也不会跟随（可用性）。触发重取只需一次合法登录，所以窗口是有限的，
  但「撤销不生效」这个性质本身是确定的。
- 修法建议: 给 JWKS 加一个显式刷新边界：把 `oidc.NewRemoteKeySet` 换成本地实现（缓存 + TTL，例如 15 分钟或
  `Cache-Control`），或按 kid 变化主动刷新（定期 `provider.Verifier(...)` 重建 keyset）；同时把
  `c.discovered` 也加上 TTL。判据：撤销后最长 TTL 内必须不再接受旧密钥。
- 复现/守卫: `internal/zzprobe/protocol/rp/idtoken_test.go` 的 `TestRPRetiredSigningKeyKeepsVerifyingAfterRotation`。

### RP-3 自定义 OIDC provider 的端点不与 issuer 绑定：登录可被导向任意 origin，且 `client_secret` 与授权码会被投递到该 origin

- 严重度: 中
- 类别: 安全
- 不变量/性质: discovery 只能描述 issuer 自己；token 端点必须与 configured issuer 同源，否则 RP 不得把
  `client_secret`（Basic 头）与 authorization code 发给它；授权端点同理（浏览器不能被交给第三方 origin）。
- 证据:
  - 探针（`go test ./internal/zzprobe/protocol/rp/ -run 'TestRPDiscovered' -v`，两条 FAIL）：
    ```
    builtin_test.go:49: the discovery document moved the login off the issuer's origin:
        https://evil.example/authorize?client_id=cid&code_challenge=...&redirect_uri=https%3A%2F%2Fre0auth.test%2Fauth%2Fauthentik%2Fcallback&...&state=st
        (issuer http://127.0.0.1:60653)
    builtin_test.go:89: the client secret (Basic Basic Y2lkOnRvcC1zZWNyZXQ=) went to the discovered token endpoint on another origin
    builtin_test.go:95: the authorization code was posted to another origin:
        code=code-1&code_verifier=verifier-1&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fre0auth.test%2Fauth%2Fauthentik%2Fcallback
    ```
    第二次探针有对照：先断言 `AuthCodeURL` 仍在 issuer 上（说明 discovery 确实跑了），再让 discovery 只把
    `token_endpoint` 指到另一个 origin，然后真实抓到对方服务器收到的 `Authorization: Basic Y2lkOnRvcC1zZWNyZXQ=`
    （即 `cid:top-secret`）与 `code=code-1`。
  - 行级：`idp/idp.go:425-436`（`oauthConfig` 直接 `cfg.Endpoint = provider.Endpoint()`）、
    `idp.go:299-301`（issuer 只来自配置）；`Exchange` `idp.go:411-420` 用该端点做交换。
    注意 issuer 本身**是**被校验的（`go-oidc oidc/oidc.go:331-336` 与 `verify.go:237-246`），所以这不是
    mix-up，而是「端点未钉在 issuer 上」。
- 状态: CONFIRMED
- 影响: 能左右 discovery 响应的一方（明文 http 的自建 issuer、被劫持的 DNS/证书、被攻破的上游）可以把
  登录页换到自己的 origin（受害者看到的是「Re0Auth 把你交给 X」），并**收到长期有效的 client_secret**
  与每一次登录的 authorization code。杀伤力大于「他反正能改 JWKS」这一点在于：`client_secret` 是长期凭据，
  在被撤换/停止篡改之后仍然可用。
- 修法建议: 对配置里只给了 issuer 的 provider，要求 discovery 的 `token_endpoint`/`jwks_uri`/`authorization_endpoint`
  与 issuer 同 scheme+host（不同源即拒绝启动/拒绝该次登录），并在文档里说明「自建 IdP 请显式配置 auth_url/token_url」；
  额外把 http issuer 收窄为显式开关（现在是 `upstream.allow_private_addresses` 只管私网地址，不管明文）。
- 复现/守卫: `internal/zzprobe/protocol/rp/builtin_test.go` 的 `TestRPDiscoveredAuthorizationEndpointIsNotPinnedToTheIssuer`、
  `TestRPDiscoveredTokenEndpointReceivesTheClientSecret`。

### RP-4 内置 `microsoft` 的 issuer 在真实端点上必然 discovery 失败：微软登录一定以 `identity_failed` 收场

- 严重度: 中
- 类别: 可用性 / 正确性
- 不变量/性质: 内置 provider 的默认配置必须能完成一次登录；用户授权之后不应该必然失败。
- 证据:
  - 真实网络（`go test ./internal/zzprobe/protocol/rp/ -run TestRPRealMicrosoft -v`，FAIL）：
    ```
    builtin_test.go:167: control (tenant issuer) fails only at the token:
        idp: microsoft: verify id_token: oidc: malformed jwt: illegal base64 data at input byte 0
    builtin_test.go:185: the built-in Microsoft provider cannot complete any login:
        idp: microsoft: discovery failed: oidc: issuer URL provided to client
        ("https://login.microsoftonline.com/common/v2.0") did not match the issuer URL returned by provider
        ("https://login.microsoftonline.com/{tenantid}/v2.0")
    ```
    对照用的是同一台机器、同一个真实端点、只把 issuer 换成租户 URL
    （`https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0`）：discovery 成功，
    错误只剩「我喂的假 JWT 解不开」——所以失败原因就是 issuer 不匹配，不是没有网络。
  - 独立复核（同一事实，另一条命令）：
    `Invoke-WebRequest https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration` →
    `issuer = https://login.microsoftonline.com/{tenantid}/v2.0`（真是一个带占位符的字面量）。
  - 行级：内置 issuer `idp/idp.go:142` `"https://login.microsoftonline.com/common/v2.0"`；
    discovery 在 `idp.go:527`（`oidc.NewProvider`，其 issuer 等值校验在 `go-oidc oidc/oidc.go:331-336`）；
    而 `AuthCodeURL` 会因为内置端点齐全（`idp.go:427-429` 提前返回、`idp.go:138-141`）**不触发 discovery**，
    所以用户会被正常送到微软、完成授权，回来后 `identityFromIDToken`（`idp.go:492`）才发现 discovery 失败，
    在 `internal/auth/auth.go:657-660` 落成 `identity_failed`。
- 状态: CONFIRMED
- 影响: `[idp.microsoft]` 只填 client_id/secret（文档里最自然的写法）时，微软登录 100% 失败，而且是在用户已经
  授权之后失败；运维看不到任何配置错误提示（`identity_failed` 是通用码）。有租户 id 的部署可以通过
  `issuer=.../<tenant>/v2.0` 绕过，但内置默认值本身不可用，且没有任何文档/.example 提到这一点。
- 修法建议: 把内置 issuer 改成不可用作默认的显式要求（启动时若 `[idp.microsoft]` 未给 issuer 就报错并提示需要租户
  URL），或遵循 go-oidc 为 Azure 准备的 `oidc.InsecureIssuerURLContext`（`oidc.go:87-104` 的注释就是为微软写的）
  并配上「多租户模式下 iss 校验放宽到什么程度」的明确裁定；不能默默保留一个必然失败的默认值。
- 复现/守卫: `internal/zzprobe/protocol/rp/builtin_test.go` 的 `TestRPRealMicrosoftBuiltInIssuerCannotDiscover`
  （需要网络；断网时 `reachable` 会 skip 并说明原因）。

### RP-5 discovery 缺 `authorization_endpoint` 时，RP 把「相对登录 URL」交给浏览器

- 严重度: 低
- 类别: 可用性
- 不变量/性质: 交给浏览器的登录 URL 必须是绝对 http(s) URL，且落在配置的 issuer 上。
- 证据:
  - 探针（FAIL）：
    ```
    builtin_test.go:113: the RP handed the browser a non-absolute login URL
      "?client_id=cid&code_challenge=...&nonce=nonce&redirect_uri=https%3A%2F%2Fre0auth.test%2Fauth%2Fauthentik%2Fcallback&response_type=code&scope=openid+email+profile&state=st"
      (discovery omitted authorization_endpoint)
    ```
  - 行级：`idp/idp.go:427-435` —— 只要 `AuthURL` 为空就交给 discovery，而 `provider.Endpoint()` 原样回传空字符串；
    `internal/auth/auth.go:602` 把这个字符串直接 `http.Redirect`。
- 状态: CONFIRMED
- 影响: 一次「登录」变成把浏览器重定向回本站 `/auth/authentik/start?client_id=...`（相对 Location 解析在当前路径上），
  用户看到的是原地打转或 404，运维只会在 metrics 里看到 `provider_unavailable`/无记录。没有跨站影响（同源），
  所以仅是可用性/可诊断性。恶意上游想要「把浏览器带到别处」的版本已由 RP-3 覆盖。
- 修法建议: 发现端点后做一次最小校验：`authorization_endpoint`/`token_endpoint` 必须非空且能被 `url.Parse` 成带
  scheme+host 的绝对 URL，否则视为 provider 不可用（`provider_unavailable`），不要把它交给浏览器。
- 复现/守卫: `internal/zzprobe/protocol/rp/builtin_test.go` 的 `TestRPDiscoveryWithoutAuthorizationEndpointYieldsARelativeLoginURL`。

### RP-6 指向错误 provider 的 callback 会先清空流程再比对 provider：一次被拒的回调烧掉待完成的登录

- 严重度: 低
- 类别: 可用性
- 不变量/性质: 一个被拒绝的请求不应改变服务端状态；只有「属于这次流程」的回调才能消费它。
- 证据:
  - 探针（FAIL）：
    ```
    e2e_test.go:314: the refused callback consumed the pending flow:
        github callback = 400 loc="" body="invalid state\n"
    ```
    即：`/auth/github/start` 拿到 state S → 用 S 打 `/auth/discord/callback`（拿到 400，符合预期）→ 再用 S 打
    `/auth/github/callback` 却变成 400 `invalid state`。
  - 行级：`internal/auth/auth.go:627`（`h.clearFlow(ctx)`）在第 629-633 行的 `flowProvider != string(provider)`
  比对**之前**执行。
- 状态: CONFIRMED
- 影响: 部署里有多个 provider（或前端按名称拼错了回调地址）时，一次走错门就把这次登录作废，用户必须从头再来；
  同时 `provider_mismatch` 这个诊断码在第一次之后就再也观察不到（第二次变成 `invalid_state`），排障信息被抹掉。
  攻击者无法主动触发（需要知道会话内的 state），所以不构成安全问题。
- 修法建议: 把 provider 比对（以及 error/code 的存在性检查）移到 `clearFlow` 之前，只在「这是本流程的回调」确认后
  才消费会话里的流程状态。
- 复现/守卫: `internal/zzprobe/protocol/rp/e2e_test.go` 的 `TestRPLoginStateIsBoundToItsProvider`
  （前半段是正常性质，后半段是这条）。

### RP-7 同意批准返回的 redirect 可重放：每次访问都新签一个 authorization code，只有先被兑换的那份算 grant

- 严重度: 低
- 类别: 安全 / 可用性
- 不变量/性质: 一次同意只应产生一个授权码；返回给前端的「下一步 URL」被再访问一次不应改变可兑换状态。
- 证据:
  - 探针（FAIL）：
    ```
    consent_test.go:248: the approval redirect was replayable: two visits produced two authorization codes
    (随后同一测试 t.Logf 记录兑换结果) first code -> 200, second code -> 400
    ```
    （`TestRPConsentApprovalRedirectIsReplayable`：批准后连续两次 GET 同一个
    `/oauth/authorize/callback?id=<X>`，两次都 302 到客户端 redirect_uri 且 `code` 不同；随后兑换：
    第一份 200，第二份 400。）
  - 并发版本（`TestRPConsentDecisionConcurrency`，FAIL）：
    ```
    consent_test.go:331: 2 of 8 concurrent decisions succeeded; distinct redirects=1
    consent_test.go:355: one consent produced 3 distinct authorization codes: map[...:1 ...:1 ...:1]
    ```
    8 个并发决策请求里 2 个返回 200 且**同一个** redirect（另 6 个 404，即 Unbind 已生效）；
    跟随那个 redirect 三次得到三份不同的码。
  - 行级：`internal/store/memory/oidc.go` `SaveAuthCode` 以 `oauth.TokenHash(code)` 为 key 逐条插入（不覆盖同一
    auth request 的旧码），`AuthRequestByCode` 在兑换时删除该码**并删除 auth request** —— 所以第一份兑换成功、
    其余全部失效。
- 状态: CONFIRMED
- 影响: 「一次同意 = 一份 grant」没有被破坏（这一点另有落盘守卫
  `internal/zzprobe/concurrency/single_use_test.go:TestASecondCodeForOneAuthRequestIsNotASecondGrant`，我不重复主张）。
  实际影响有两个且都有界：(1) 浏览器/中间件只要多取一次那个 URL（刷新、后退、链接预览、杀毒/网关的 URL 预取），
  先被取走的那份码就抢掉唯一兑奖机会，客户端拿到的最后一份码变成死码 → 用户做完同意却拿到登录失败；
  (2) 每次访问都在 store 里多留一条指向已删 auth request 的死码，直到请求 TTL（默认 30 分钟）才随 janitor 清理。
  与 audit-3 的 C3-2（设备流每次轮询都 mint 一对新令牌）同属「批准不是幂等」这一族，此处在授权码路径复现。
- 修法建议: 让 `/oauth/authorize/callback` 对同一个 auth request 幂等：若该 request 已 `Done` 且已有码，则重定向到
  同一个码（而不是 `SaveAuthCode` 一个新码），或在生成新码前先 `DeleteAuthCodeByRequest`。
- 复现/守卫: `internal/zzprobe/protocol/rp/consent_test.go` 的 `TestRPConsentApprovalRedirectIsReplayable`、
  `TestRPConsentDecisionConcurrency`。

### RP-8 登录完成后会话里仍留着 `flow_nonce`（`flowKeys` 漏了 `keyFlowNonce`）

- 严重度: 提示
- 类别: 安全（卫生）/ 可维护性
- 不变量/性质: 一次登录结束后，浏览器会话里不应再留这次流程的任何字段。
- 证据:
  - 探针（FAIL，直接 dump 会话字节）：
    ```
    e2e_test.go:542: the completed login left flow_nonce in the session (flowKeys omits keyFlowNonce):
      "...\x04\nflow_nonce\x06string\f-\x00+gspGaXWpkedBBmnooTQg4SRb4IuYjuJAnMr5DV5Sq58\x04csrf\x06string..."
    ```
    同一次 dump 里 `flow_state`/`flow_verifier`/`flow_provider`/`flow_mode`/`flow_return_to` 都已消失，
    只有 `flow_nonce`（带着这次流程的 nonce 值）留在 `usr`/`auth_time`/`csrf` 旁边。
  - 行级：`internal/auth/auth.go:41` 定义 `keyFlowNonce`，但 `:44` 的 `flowKeys` 没有它；
    `clearFlow`（`:708-712`）只删 `flowKeys` 里的 key。
- 状态: CONFIRMED
- 影响: 目前没有可利用性：nonce 本来就随授权 URL 出现在浏览器地址栏，下一次 `/auth/*/start`（`:592`）会覆盖它，
  且回调必须先过 state 检查。报出来是因为它是「清理列表与写入列表不一致」的实例——这类不一致下一次就会变成真问题
  （例如将来给 flow 加一个真正的秘密字段）。
- 修法建议: 把 `keyFlowNonce` 加进 `flowKeys`；更好的做法是把 flow 字段集中成一个 `flowKeys = []string{...}` 并用它
  同时做写入和清理（或让 `clearFlow` 遍历一个与写入同源的列表），避免两边再漂移。
- 复现/守卫: `internal/zzprobe/protocol/rp/e2e_test.go` 的 `TestRPLoginLeavesNoFlowValuesInTheSession`。

### RP-9 身份「关联（link）」不要求近期认证：任何有效会话都能把新的上游身份绑到账号上

- 严重度: 中
- 类别: 安全
- 不变量/性质: 会改变账号长期可登录身份集的操作，必须要求「最近认证过」——与管理员面 `reauth_window` 同一条理由。
- 证据:
  - 行级（机制确证）：`internal/auth/auth.go:575-580`，`mode == "link"` 的唯一门槛是
    `if _, ok := h.manager.User(r.Context()); !ok { 401 }`；回调里（`:662-680`）同样只要求
    `h.manager.User(ctx)` 存在。`sessions.AuthenticatedAt`（`auth.go:134-144`）已经在会话里，但**除管理面外无人使用**：
    `internal/httpapi/admin_routes.go:89-92` 是唯一的 `time.Since(at) > s.adminReauth` 检查点，
    配置项只有 `[admin].reauth_window`（`cmd/re0auth/config.go:679-693`）。
  - 删链同样只要求 CSRF：`internal/httpapi/identity_routes.go:48-51`。
  - 我的探针只证明了「link 在已登录会话里可完成、且不会切换账号」（`TestRPLoginModeComesFromTheSessionNotTheQuery` PASS），
    **没有**用假时钟去证明「一个月前的会话也能 link」——所以这半条是 HYPOTHESIS，写法见下。
- 状态: HYPOTHESIS（机制 CONFIRMED；「旧会话也能 link」未执行验证）
- 影响: 会话被盗（或共享终端未登出）之后，攻击者做一次 link 把自己控制的上游身份挂到受害者账号上，
  受害者改密码/登出都拔不掉这条入口：之后攻击者用自己的 GitHub 账号即可直接登录该账号，直到有人发现并手工解绑。
  相比之下管理面认为「15 分钟内没重新登录就不许写」，账号面却对同等持久性的操作没有任何时效要求。
  要证实它需要什么：用注入的时钟（`auth.Options` 没有 Now 钩子，需要给 `Manager` 加一个可注入时钟或直接把
  `auth_time` 写成过去时间后走一次 link）跑一遍 `/auth/github/start?mode=link` + callback，观察是否仍然 200。
  按上面读到的代码，答案会是「仍然 200」。
- 修法建议: 在 `handleStart` 的 `mode == "link"` 分支复用 `AuthenticatedAt`：超过一个可配置窗口（例如
  `[auth].link_reauth_window`，默认与 `admin.reauth_window` 一致）就要求重新登录再 link，返回一个前端能识别的
  失败码（类似 `reauth_required`）。这是裁定（要不要引入新配置），不是纯实现问题。
- 复现/守卫: 目前只有读代码的证据；建议的守卫是 `internal/auth` 里的
  `TestLinkRequiresAFreshAuthentication`（需要给 Manager 注入时钟）。

---

## 探过但没破的（这些也应变成守卫）

每条都有跑过的探针；**对照组都在同一次运行里通过**，所以「被拒绝」不是没跑到。

1. **state：CSPRNG + 绑定浏览器会话 + 单次使用**。
   `TestRPLoginStateFromAnotherBrowserIsRefused`（攻击者开的流程，受害者浏览器完成 → 400，且受害者没有被登录；
   同一浏览器自我完成 → 303 并真的登录）、`TestRPLoginStateIsSingleUse`（同一 callback 重放 → 非 303，会话用户不变）、
   `TestRPLoginStateIsBoundToItsProvider`（跨 provider 被拒；见 RP-6 的副作用）。
   生成方式：`internal/auth/auth.go:583` → `randomToken(24)` = `crypto/rand` 24 字节（`auth.go:726-732`，失败即 panic）。
   **登录 CSRF / 账号固定两种方向都不成立**：state 在服务端会话里，攻击者既读不到别人的 state，也无法把自己的
   state 写进受害者的会话（cookie 边界）。
2. **nonce：生成、发送、校验、且不可为空**。`TestRPMissingNonceClaimIsRejected`（上游完全不带 nonce → 拒；
   带对 → 通过）、`TestRPEmptyExpectedNonceIsFatal`（期望空 nonce → 拒，`idp/idp.go:505` 的 `nonce == ""` 短路）。
   nonce 生成同 `oauth2.GenerateVerifier`：`golang.org/x/oauth2@v0.37.0/pkce.go:27-38`，`crypto/rand` 32 字节。
3. **无 id_token ⇒ 失败关闭，且不回落 userinfo**。`TestRPNoIDTokenDoesNotFallBackToUserinfo`：
   token 端点只返回 access_token → `Identity` 报错，且 fake OP 的 `/userinfo` 命中次数为 **0**（对照组有真 id_token 时
   也断言了 info=0，即这条路径本来就是零调用）。`TestRPEmptySubjectIsRejected`（`sub:""` → 拒）。
4. **alg 固定：`none` 与 HS256 都被拒**。`TestRPAlgNoneIsRejected`（手写 `alg:none` JWT → 拒）；
   `TestRPHS256WithPublishedSymmetricKeyIsRejected`（上游 discovery 广告 `["RS256","HS256"]` 且在 JWKS 里公布自己的
   `oct` 密钥 → 用它签的 HS256 令牌仍被拒）。机制（读依赖）：`go-oidc oidc/oidc.go:180-191, 337-342` 会把 discovery 的
   算法表按白名单过滤（HS256/none 不在其中），`verify.go:295-316` 只在
   `InsecureSkipSignatureCheck` 时才允许 `none`，而 `idp/idp.go:541` 从未设置该选项。
5. **跨 provider 的密钥不能互相验证**。`TestRPOneProvidersKeyDoesNotVerifyAtAnother`：B 用自己的私钥签一份
   `iss=A` 的 id_token 喂给 A 的 verifier → 拒（对照：A 自己的往返成功）。
6. **JWKS 抓取失败不会清缓存、也不会降级**。`TestRPJWKSFailureDoesNotClearTheCache`：先验通一次（缓存 k1）→
   `/jwks` 改 500 → 未知 kid 的令牌被拒，且断言了「确实触发了重取」（计数器增长）→ 之后带 k1 的正常登录仍然成功
   （缓存没被清）。机制：`go-oidc oidc/jwks.go:220-222` 只在成功时替换缓存、`:176-179` 失败直接返回错误。
   （注意这与 RP-2 是同一段代码的两个方向：失败方向是安全的，成功方向没有时效。）
7. **discovery 的 issuer 必须与配置的 issuer 等值**。`TestRPDiscoveryIssuerMismatchIsRejected`：discovery 广告另一个
   issuer → `AuthCodeURL`/`Identity` 全拒，且断言 discovery 真的被请求过；对照（issuer 正确）通过。
   机制：`go-oidc oidc/oidc.go:331-336`；`verify.go:237-246` 再用 discovery 的 issuer 校验 id_token 的 `iss`
   （含 Google 的 `accounts.google.com` 特例）。**mix-up / issuer 混淆不成立**。
8. **PKCE：S256 且 verifier 与 challenge 对应**。`TestRPSendsS256PKCEAndTheMatchingVerifier`：断言授权 URL 带
   `code_challenge_method=S256`、`nonce=`、且 `redirect_uri` 正是配置的 `https://re0auth.test/auth/google/callback`；
   然后断言 token 请求里的 `code_verifier` 与生成 challenge 用的同一个 verifier 逐字相等、`grant_type=authorization_code`。
   没有发现任何绕过 PKCE 的路径（OIDC 与 userinfo 两条路都走同一个 `Exchange`）。
9. **redirect_uri 只来自配置**。`TestRPProviderNameIsValidatedBeforeItReachesAURL`（`../evil`、`a/b`、`evil.example`、
   `Google`、`-lead`、`_lead`、空、含空格 → 全部在 `NewRegistry` 被拒；合法自定义名通过）+
   `TestRPLoginProviderSegmentCannotEscape`（`/auth/nope/start`、`/auth/a%2Fb/start`、`/auth/..%2F..%2Fevil/start`、
   `/auth/GitHub/start`、`/auth/github%00/start`、`/auth/%2e%2e/start` 都不会被解析成别的 provider）。
   行级：`idp/idp.go:320` 用配置名拼 `RedirectURL`，路径段只用于 map 查表（`idp.go:350-353`）。
10. **`return_to` 不能出站**。`TestRPLoginReturnToCannotLeaveTheOrigin`：`//evil.example`、`https://evil.example/`、
    `/\evil.example`、`/%09/evil.example`、`\\\\evil.example`、`evil.example`、`https://evil.example@127.0.0.1/`、
    `//evil.example/\\@127.0.0.1` —— 解析后的 scheme+host 必须与本站一致（不只看字符串，因为 `/%09/evil.example`
    里含 `evil.example` 却仍是同源路径）；对照：`/app/dashboard?x=1` 被原样保留。守卫实现是 `internal/safeurl`。
11. **上游给的 `error`/`error_description`/`error_uri` 不被反射**。`TestRPLoginProviderErrorIsNotReflected`：
    用 `<script>alert(1)</script>` 与 `javascript:` 作为三个参数值 → 响应体与 Location 都不含它们，且断言了确实走到
    「上游拒绝」分支（Location 带 `error=access_denied`，常量，`internal/auth/auth.go:471-486, 634-644`）。
12. **`mode` 是服务端状态**。`TestRPLoginModeComesFromTheSessionNotTheQuery`：登录流程的 callback 带 `&mode=link`
    仍然只是登录（会话真的被登录）；link 流程的 callback 带 `&mode=login` 仍然只是 link（会话账号不变、
    `/v1/identities` 变成两条）。`TestRPLinkModeRequiresASignIn`：未登录 `mode=link` → 401，对照登录 start → 302。
13. **同意接缝的所有权/CSRF/一次性**。`TestRPConsentHandleIsUsableByItsOwnBrowser`（已登录浏览器 → authorize →
    view 200 → approve 200 → 跟随 redirect 后客户端 `https://app.example/cb` 真的收到 code 与 state；随后 handle 变 404）、
    `TestRPConsentHandleFromAnotherBrowserIsRefused`（另一个浏览器读/决策都是 404，而 owner 仍能读）、
    `TestRPConsentDecisionNeedsTheSessionsCSRFToken`（无 token 403、别的会话的 token 403、自己的 token 200）。
    与 `internal/httpapi/consent_owner_test.go` 的既有结论一致（那条是「A 的 handle 不能被 B 用」，我这边是
    「另一个浏览器 + 跨会话 CSRF」两个方向）。
14. **token 请求不会被上游的跨站重定向拐走**。`TestRPUserinfoRedirectToAnotherOriginIsRefused`：userinfo 端点回 302
    到另一个 origin → 登录失败，且对方服务器收到的 `Authorization` 里**没有**那个 access token（对照：不重定向时登录成功）。
    防护来自 `httpclient.NoCrossHostRedirects`（`httpclient/outbound.go:283-320`），组合根确实装了它
    （`cmd/re0auth/main.go:424-427`）。
15. **默认出站客户端挡住私网 discovery（SSRF 面）**。`TestRPDefaultOutboundClientRefusesLoopbackDiscovery`：
    不注入 HTTPClient 时，指向 `127.0.0.1` 的 issuer 在 dial 阶段被拒，错误是
    `httpclient: refusing to connect to 127.0.0.1:60661: 127.0.0.1 is not a public address`。
16. **`sub` 按 provider 命名空间隔离**。`TestRPSubIsNamespacedByProvider`：同一个 `shared-subject` 在 `alpha`/`beta`
    两个 provider 下是两个账号，`FindByIdentity("beta", "shared-subject")` 在 alpha 已建号时查不到。
    行级：`idp/idp.go:461`（`ident.Provider = c.provider`）在 `Identity` 里无条件覆盖上游可控字段。
17. **`iat` 完全不校验**（观察，非缺陷主张）。`TestRPFutureIssuedAtIsAccepted`：`iat` 写成一年后仍然通过
    （`go-oidc verify.go` 里没有 iat 检查）。影响面很窄（上游时钟错乱/重放窗口），记录为提示级事实；
    `exp`/`nbf` 由 `verify.go:262-284` 检查，`nbf` 有 5 分钟 leeway，`exp` 没有任何 skew 宽限 ——
    本机时钟比上游快几秒就会登录失败，属于可用性提示，未单列为发现。

---

## 未能到达（残余盲区）

1. **Postgres 侧没跑**。同意接缝的探针全部跑在 `internal/store/memory` 上（本机无 Docker/无 Postgres）。
   `internal/store/postgres/oidc.go:741` 的 `CompleteLogin` 与 `SaveAuthCode`/`AuthRequestByCode` 的 SQL 语义
   我只读到函数边界，RP-7 的「第一份码吃掉唯一 grant 机会」在 PG 下是否一致**未验证**（需要 DB）。
2. **QQ 流程只有读代码，没有执行**。`fetchQQ`（`idp/idp.go:546-579`）依赖 `definition.qqMeURL` / `qqUserInfoURL`，
   而 `Credentials`（`idp.go:179-199`）**没有**对应字段，出包外无法把这两个 URL 指向 fake server
   （`idp.go:72-73` 的注释「parameterized so tests can point them at a fake server」只对包内测试成立）。
   所以我既没能跑通 QQ 的 JSONP 解析（`stripJSONP` `idp.go:582-592`），也没能验证它的 openid/unionid 语义。
   顺带记两件读到的、无裁定的事：QQ 的 access_token 走 **URL query**（`idp.go:547, 566-569`，QQ 的 API 就这样，
   修不了，但会进上游/中间件日志）；`me` 响应里的 `client_id` 没有被用来核对令牌是否属于本应用
   （`idp.go:551-564` 只校验 openid/unionid 非空）。
3. **真实 provider 的令牌交换未执行**（无凭据）：GitHub/Discord/Google/QQ/微软的 token 端点、真实 JWKS、
   真实 id_token 都没有碰过。RP-4 是唯一用了真实端点的条目，且只用了 discovery。
4. **Google 的 discovery 从本机超时**（`Invoke-WebRequest https://accounts.google.com/.well-known/openid-configuration`
   → `NETFAIL: The operation has timed out`），所以「Google 的 issuer 与内置值一致」这条只有读依赖的证据
   （`go-oidc oidc/verify.go:17-19, 243` 专门为 Google 的 `accounts.google.com` 例外），没有实测。
5. **多租户/多 issuer 的部署形态没覆盖**：`Registry` 每次登录只用一个固定 issuer（`c.discovered` 缓存），
   我没有测过「同一 provider 名同时服务多个租户」这种部署（代码里也不支持）。
6. **`federation`（数据源侧的上游 OAuth 客户端）不在本次范围**，它另有一套 `BeginBind`/`CompleteBind` 的 state/PKCE
   （`internal/federation/bind.go:150-160`），我没有审计，也不对它的结论负责。
7. **RP-9 的时钟维度未验证**（HYPOTHESIS 已注明原因）：`auth.Manager` 没有可注入时钟，无法在不改生产代码的前提下
   把 `auth_time` 做旧。

---

## 判断

1. **RP-1/RP-3 都是「包装层该补、库明确不补」的类型**。go-oidc 在 `verify.go:250` 自己写明了不做 azp 判定，
   在 `oidc.go:87-104` 写明了 Azure 的 issuer 例外，在 `jwks.go` 里明确只做「命中即返回」的缓存。
   引用这些不是甩锅，而是说：`idp` 作为唯一的 RP 包装层，是这些性质的**唯一**归属地，写在 `idp` 里最省事也最难漂移。
2. **RP-4 我不接受「这是配置问题」的说法**。内置默认值不可能成功、失败发生在用户授权之后、失败信息是通用码 ——
   这三件事合起来是「发布产物本身不安全/不可用」，不是运维要背的知识。要么把 issuer 变成必填并启动即报错，
   要么按 go-oidc 的 Azure 例外显式放宽并写进裁定文档。
3. **RP-7 的严重度我刻意压到「低」**，因为「一次同意 = 一份 grant」这条更重要的性质由 store 层
   （`internal/zzprobe/concurrency/single_use_test.go`）与既有测试守住，我不重复主张；剩下的「死码 + 先取走的码抢走
   唯一机会」是真实但有限的可用性问题。若团队认为「可重放的重定向」本身就该在协议层消除（OAuth 2.1 的
   "one-time use" 语境），那可以升格处理。
4. **「RP 只信任上游」的边界是刻意设计，不是缺陷**：对 GitHub/Discord/QQ 这类没有 OIDC 的 provider，
   `identityFromUserInfo`（`idp.go:468-477`）就是「上游说什么就是什么」，唯一的技术保护是 TLS + 出站地址守卫
   （探过但没破 #15）。真正需要警惕的是**把非 OIDC provider 配成 OIDC**（`Credentials.Issuer` 可以给 GitHub/QQ 加
   issuer，`idp.go:188-195, 299-301`）——那会让原本走 userinfo 的登录改走 discovery + JWKS，等于把信任根从
   「HTTP 响应」换成「另一个 discovery 端点」，属于运维决策，我把它列为判断而非发现。
5. **`-race` 在本机可用**（简报预期相反）：`go test -race ./internal/zzprobe/protocol/rp/` 正常编译运行，
   输出无 data race 报告。但我的并发结论只覆盖「同意决策 8 并发」与「-race 下重放探针」，其余边界
   （如 `Manager.Bind` 的队列淘汰、`OwnerMatches` 与 `Unbind` 的竞态）只有单线程证据。
