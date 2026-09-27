# KIT 区域 审计报告（`upstreamkit/`、`upstreamkit/conformance/`、`oauth/`）

## 范围与方法

**读了什么（端到端）**
- `upstreamkit/server.go`、`upstreamkit/discovery.go`、`oauth/bodylimit.go`（被 kit 复用）。
- `upstreamkit/conformance/conformance.go`。
- `oauth/as.go`、`oauth/tokens.go`、`oauth/grants.go`、`oauth/scope.go`、`oauth/client.go`、
  `oauth/device.go`、`oauth/http.go`、`oauth/service.go`。
- 为确认可达性与调用方契约，另外读了：`internal/store/postgres/oauth.go`（Postgres 侧 store）、
  `internal/federation/revocation.go`（Re0Auth 侧怎么调 cascade）、`internal/admin/admin.go`（secret 怎么生成）、
  `internal/httpapi/server.go`（`no-store` 在别处怎么加的）、`docs/security-audit-2.md`、`docs/security-audit-3.md`
  的相关小节。

**跑了什么**
```
go vet ./internal/zzprobe/protocol/kit/
go test ./internal/zzprobe/protocol/kit/ -v
go test -race ./internal/zzprobe/protocol/kit/
```
- **`-race` 可用**：本机跑通了，全程无 `DATA RACE` 报告（见 `## 探过但没破的` 一节的说明；断言仍不依赖它）。
- 42 个测试函数：**32 PASS / 10 FAIL**，每个 FAIL 都是一条能失败的断言。
  每条「被拒绝/不存在」的断言前面都有一条**对照组先成功**（`TestA0_`、`TestE2_`、`TestE5_`、`TestE6_` 的
  control 分支、`TestF1_`、`TestG1_` 的控制项）。
- **没有跑** `go test ./...`。

**跑不了的（标注见各条）**
- 所有 Postgres 路径：本机无 Docker、无本地 Postgres，**读代码到行**，逐条标「读；无 DB 执行」。
- 生产 HTTP 组合根 `internal/httpapi` 的完整装配（`newFullEnv`/`newFullConfig`）：本区域的两条关键路径
  （`/oauth/*` 的数据源侧）在 `cmd/referencesource` 里是**独立的源服务器**，Re0Auth 自己**不挂** `upstreamkit`
  的 cascade 端点、也**不挂** `oauth/` 的设备端点，所以用包自己的 `httptest` 更贴近真实调用方
  （`internal/federation/revocation.go:72-80` 就是那个调用方）。

---

## 发现

### KIT-1 生成的 `/oauth/cascade_revocation` 完全不认证：无凭据、未知 client_id 都直达钩子并回 200

- 严重度: 高
- 类别: 安全
- 不变量/性质: 「一个请求只能声明一个客户端身份，且该身份必须经过校验」——被破坏到「身份根本不读」。
  文档自己立的性质也破了：「广告了必须实现」是对的，但**实现必须真的守住**它签下的东西
  （这是「登出所有设备」，是源能做的**最响**的一件事）。
- 证据:
  - `upstreamkit/server.go:318-339`（`handleCascadeRevocation`）：`clientID, clientSecret := oauth.ClientCredentials(r)`
    之后**直接**把两者塞进 `CascadeRevocationRequest` 交给 `s.hooks.CascadeRevoke`，**没有**任何
    `AuthenticateClient`、`clients.Get` 或 secret 比对。对比 `handleToken`（`server.go:239-254`）把认证交给
    `s.hooks.OAuth.Exchange`，`handleAuthorize` 交给 `DescribeAuthorization`——**只有 cascade 这一条路是本文件自己写的，
    而它是唯一没有认证逻辑的一条**。
  - 运行证据：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestE1_|TestE3_|TestE2_|TestE4_' -v
    TestE1: anonymous POST /oauth/cascade_revocation -> 200  (hook calls=1)
            hook received ClientID="" ClientSecret="" token="a-token-the-attacker-came-by"
    TestE3: an unknown client id ("no-such-client") was forwarded ... and answered 200
    TestE2: authenticated cascade -> 200            <- 对照组：带凭据也成功，端点没坏
    TestE4: token with no client identity -> 401    <- 对照组：同文件里 /oauth/token 是拒绝的
    ```
  - 真实调用方**确实**会带 Basic（`internal/federation/revocation.go:78-79`），所以这不是「客户端本来就不发凭据」的
    借口问题；线上路径会带凭据，**但这个服务端不看**。
- 状态: CONFIRMED
- 影响: 任何能到达该 endpoint 的人，只要**拿到（或猜到、或以任何方式得到）源签发的 token 值**，就能让源
  结束该 token 所属的**整段上游会话**——按 `docs/upstream-protocol.md` 与 `server.go:74-79` 自己的描述，
  这会把用户从**所有设备**上踢下来，包括手里那台。攻击者不需要注册过任何 client、不需要知道任何 secret、
  甚至不需要一个合法的 client_id。Re0Auth 会因此把绑定删掉、把 vault 里的密钥撕掉
  （`internal/federation/revocation.go:146-153`）——**用户的绑定被一次伪造请求摧毁，且不可重试**。
  另外 `s.hooks.CascadeRevoke` 收到的 `ClientID`/`ClientSecret` 为空串，一个诚实的源实现无法据此判断调用者是谁。
- 修法建议: 在 `handleCascadeRevocation` 里、调用钩子之前做一次客户端认证，与 `/oauth/token` 同源：
  ```go
  if err := s.hooks.OAuth.AuthenticateClient(r.Context(), clientID, clientSecret); err != nil {
      writeProtocolError(w, r, err); return
  }
  ```
  （`oauth.Service.AuthenticateClient` 已存在，`service.go:120-123` 也正是为「要求一个已注册客户端、但不带 grant 的端点」
  而设的。）如果设计上本就打算让源自己认证，那 `CascadeRevocationRequest` 就该改成携带
  `*http.Request` 或明确的验证回调，而不是两个**看起来已被校验**的字符串——现在这两个字段的形状在骗人。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的
  `TestE1_CascadeRevocationNeedsNoAuthentication`、`TestE3_CascadeRevocationAcceptsAnUnknownClient`；
  对照组 `TestE2_CascadeRevocationAcceptsCredentials`、`TestE4_TokenEndpointRequiresClientAuth`。

### KIT-2 一次请求可以声明两个客户端身份：Basic 与表单互不校验，谁被采用只由「哪个非空」决定

- 严重度: 中
- 类别: 安全
- 不变量/性质: RFC 6749 §2.3「一次请求**只能**使用一种客户端认证方式」；以及更重要的下游性质
  「请求里出现的 client_id 与请求实际以哪个客户端记账，是同一个」。
- 证据:
  - `oauth/http.go:33-38`（`ClientCredentials`）：Basic 存在就**整体**采用 Basic，表单字段**完全不读、不比对**；
    反之亦然。两个身份不一致时不拒绝。
  - 运行证据（同一请求里 Basic=`conf`+正确 secret，表单写 `pub`+**错误**的 secret）：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestA2_' -v
    Basic=conf + form=pub(wrong secret) -> 200
    {"access_token":"gt7BNDehUXBcLeoGydb0wmWdIYVQthMmJkGMJPgP75k",...,"scope":"account.read",...}
    two client identities in one request were accepted; RFC 6749 §2.3 permits exactly one
    ```
    这里 Basic 胜出，所以记账与鉴权一致（**没有**跨客户端提权），但请求**同时**声明了另一个客户端且无人反对。
  - 对照：同一个 kit 上公开客户端带任意 `client_secret` 也是 200（`TestA3_`）——因为公开客户端
    `secretHash` 为空，`oauth/as.go:320` 的 `auth && c.Type == ClientConfidential` 直接短路，
    **secret 字段从不被读**。也就是说「表单里的 client_secret」在两条路径上都是装饰性的。
- 状态: CONFIRMED
- 影响: 本轮**没能**用它提升权限（Basic 的 secret 仍然必须正确，见「探过但没破的」G4）。
  真正的风险是**协议级歧义被下游继承**：任何在 kit 前面的代理/WAF/日志/RFC 7009 风格的中间件，
  若按「表单里的 client_id」或「表单里的 client_secret」判断，就会与 kit 的判断不一致——
  这正是 `docs/security-audit-3.md` A3-4 在 `internal/oidchttp` 里修过的同一类洞（那边第四轮已裁定为
  「一个请求只能声明一个客户端身份」并落了守卫 `TestAdversarialDeviceAuthorizationRefusesTwoClientIdentities`）。
  **同一个裁定还没有落到公开库 `oauth` 上**，而 `oauth` 正是数据源侧在用的那个引擎。
- 修法建议: 把 `internal/oidchttp` 已落地的规则搬进 `oauth.ClientCredentials`：Basic 与表单
  `client_id` 同时出现且不一致 → 返回一个可判定的「拒绝」信号（例如 `(id, secret, err)`），
  由调用方转成 `invalid_client`；两边一致时按任一边的行。即使所求 scope 恰好是 Basic 那一方注册过的也要拒。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的 `TestA2_FormAndBasicMayDisagree`（FAIL）；
  对照组 `TestA0_ControlConfidentialExchangeSucceeds`。

### KIT-3 被 suspend（乃至被删除）的客户端，其已签发令牌仍然 active，并且能读数据面

- 严重度: 高
- 类别: 安全
- 不变量/性质: `oauth/client.go:33-39` 自己写下的性质：「A suspended client is not "denied": it is reported as
  unknown by **every protocol entrance**」。实际是「every protocol entrance **except the token itself**」。
- 证据:
  - `oauth/as.go:253-271`（`Introspect`）只查 `s.tokens.GetAccess`，**从不**问 `s.clients`。
  - `upstreamkit/server.go:379-399`（`authorize`）的整条判据就是 `Introspect` + `hasScope`。
  - 运行证据：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestA4_|TestA5_|TestE10_' -v
    TestA4: control: AuthenticateClient after suspension = oauth: invalid_client: unknown client   <- 入口确实拒了
            control: Refresh after suspension            = oauth: invalid_client: unknown client
            Introspect of a suspended client's access token: active=true subject=usr_probe_subject client=conf
              scopes=[account.read phigros.profile.read]
    TestA5: Introspect after the client row was deleted: active=true subject=usr_probe_subject
    TestE10: /account with a SUSPENDED client's token -> 200 {"subject":"usr_probe_subject"}
             (对照组：/account with account.read -> 200；无 token -> 401)
    ```
  - 交付形态是**端到端**的：`/account` 与 `/resources/{name}` 就是拿这个 `Introspect` 当唯一判据。
- 状态: CONFIRMED
- 影响: 运维「暂停一个客户端」这一动作对**已经发出去的令牌完全无效**，最长可达配置的
  `AccessTokenTTL`（默认 1 小时，`oauth/service.go:157`），更关键的是它**不撤销**任何东西——
  `revoke`/`Refresh` 会拒（因为要 `clients.Get`），但 bearer 令牌照用。攻击者收益取决于暂停的动机：
  若暂停是因为该客户端凭据怀疑泄露，暂停不减少任何现有访问；用户与运维都会得到「已经掐掉了」的错觉
  （端点全部返回 `invalid_client`，唯独数据面照旧 200）。`ClientAdmin.Delete` 同理，而且更彻底——
  客户端行没了，`Introspect` 甚至无法知道该问谁。
- 修法建议: 两条最小改法，任选其一（推荐第一条，因为它是把判据放在唯一的收口处）：
  1. `service.Introspect` 在返回 `Active: true` 之前调 `s.clients.Get(ctx, at.ClientID)`；
     取不到（含 suspended，`MemoryClientRegistry.Get`/postgres `Clients.Get` 都已把 suspended 折叠成 not found）
     就回 `TokenInfo{Active:false}`。代价是每次内省多一次 client 读——可加一个短 TTL 缓存。
  2. 把 `ClientAdmin.SetStatus/Delete` 改成同时吊销该 client 的全部令牌
     （`TokenAdmin.RevokeTokens(TokenFilter{ClientID: id})` 已经存在，`oauth/tokens.go:112-116`）。
     注意这条只对新发的暂停生效，且需要 `ClientAdmin` 实现方记得做，属于更深一层的约定。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的
  `TestA4_SuspendedClientTokensStayLive`、`TestA5_DeletedClientTokensStayLive`、
  `TestE10_DataPlaneRequiresTokenAndScope`（末段用 suspend 后的令牌打 `/account`）。

### KIT-4 失败的兑换会把授权码烧掉：知道 code 就足以让合法客户端拿不到令牌

- 严重度: 中
- 类别: 可用性 / 安全（拒绝服务）
- 不变量/性质: 「授权码单次使用」被实现成了「第一次**尝试**即消费」，而不是「第一次**成功**兑换即消费」；
  于是「谁消费」与「谁有权消费」解耦了。
- 证据:
  - `oauth/as.go:165`：`code, err := s.tokens.ConsumeCode(ctx, req.Code)` 在
    `code.ClientID != client.ID`（:175）、`code.RedirectURI != req.RedirectURI`（:178）、
    `verifyPKCE(...)`（:181）**之前**执行。`MemoryStore.ConsumeCode`（`tokens.go:202-213`）与
    postgres 版（`internal/store/postgres/oauth.go:36-57`，`DELETE ... RETURNING`）都是无条件删除。
  - 运行证据：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestC1_|TestC2_' -v
    TestC1: attacker exchange with a bad verifier: oauth: invalid_grant: PKCE verification failed
            legitimate exchange afterwards:  oauth: invalid_grant: authorization code is unknown or already used
    TestC2: wrong client / wrong redirect / wrong verifier / missing redirect
            -> 每一种之后，「完全正确」的那次兑换都变成 unknown or already used
    ```
- 状态: CONFIRMED
- 影响: code 在重定向（浏览器地址栏、Referer、日志、客户端本地存储、同机恶意 App 注册的 redirect）里会泄露，
  而**不需要** code_verifier、也不需要任何客户端凭据，第三方只要发一次 POST 就能把受害客户端的登录流程
  永久打断。这是**低成本的定向拒绝服务**：一次请求 ≈ 一个用户一次登录失败，用户看到的是「授权码无效」，
  没有任何东西告诉他/运维「有人拿这个 code 试过」。同一形状也适用于 refresh token
  （`as.go:192` 先 `ConsumeRefresh`，:202 才比 client_id；`oauth/zz_probe_test.go` 已经记过这条）。
- 修法建议: 把消费移到所有绑定校验**之后**，或者保留「失败即烧」但**区分可观测性**：
  - 最小改动：先 `GetCode`（新增一个只读方法，与 `TokenOwner` 同一形状）→ 校验 client/redirect/verifier
    → 全通过后再 `ConsumeCode` 并核对返回值一致（幂等保护）。因为这中间有窗口，需要 store 侧提供
    「校验通过才删除」的原子操作，例如 `ConsumeCodeIf(ctx, value, predicate)`；postgres 可以做成
    `DELETE ... WHERE token_hash=$1 AND client_id=$2 AND redirect_uri=$3 RETURNING ...`，一行 SQL 且原子。
  - 无论怎么改，都要**同时**给失败加信号：失败但 code 存在 → 记一条审计（现在 `record` 只在成功路径上，
    `as.go:156`），否则这条 DoS 永远不可见。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的 `TestC1_FailedExchangeConsumesTheCode`（FAIL）；
  `TestC2_AllBindingFailuresBurnTheCode`（PASS，钉住现状与错误文案，改法落地后应改成断言「失败后 code 仍可用，除非三次都错」）。

### KIT-5 authorize 不校验 `code_challenge` 的形状：1 个字符的挑战也发码，而这张码永远换不出令牌

- 严重度: 中
- 类别: 可用性
- 不变量/性质: 「授权端点在发出授权码之前，必须验证请求里所有会影响兑换的字段是合法的」——
  PKCE 的 `code_challenge` 是其中唯一一个**只在兑换时才被使用**的字段，所以它是唯一一个
  「authorize 不检查就没人检查」的字段。
- 证据:
  - `oauth/as.go:104-106`：`describe()` 只断言 `req.CodeChallenge == ""` 与
    `req.CodeChallengeMethod != "S256"`，**没有**长度/字符集校验（S256 的结果必然是
    43 字符的 base64url，`crypto/sha256` 32 字节 → `RawURLEncoding` 43 字符）。
  - 运行证据：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestC4_' -v
    std/url padded   ACCEPTED at authorize ...  -> the code it minted is unredeemable: PKCE verification failed
    truncated        ACCEPTED at authorize ...  -> ... unredeemable
    uppercase        ACCEPTED at authorize ...  -> ... unredeemable
    one char         ACCEPTED at authorize ...  -> ... unredeemable
    empty            rejected at authorize: oauth: invalid_request: PKCE with S256 is required   <- 对照组：空值确实被拒
    ```
    注意「对照组」：`empty` 被拒证明探针确实走到了 `describe()` 的那条判断上，不是没跑到。
- 状态: CONFIRMED
- 影响: 一个把 `code_challenge` 传成 padded base64（`=` 结尾）、或大小写被上游改动、或截断的客户端，
  会先被**带去同意页**（用户看到并授权了一次），拿到 code，然后在兑换时失败——用户白授权一次，
  客户端只看到 `invalid_grant: PKCE verification failed`，而真正的原因是它在 authorize 阶段就该被拒。
  叠加 KIT-4 之后更糟：**失败的那次兑换把 code 烧了**，用户必须重新走一遍完整登录+同意。
  这不是权限绕过（兑换时校验是严格的、常数时间的：`as.go:336-343` 用 `subtle.ConstantTimeCompare`），
  而是一条确定可复现的可用性/诊断缺陷。
- 修法建议: 在 `describe()` 里加一条形状校验，与兑换侧的判据同源：
  ```go
  if len(req.CodeChallenge) != 43 { /* invalid_request */ }
  for _, r := range req.CodeChallenge { /* base64url 字母表 */ }
  ```
  更好的做法是把「挑战是否合法」抽成一个函数，authorize 与 exchange 共用，
  避免两处判据漂移（这正是本文件 `http.go` 开头反对的那种复制）。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的 `TestC4_PKCEChallengeShapeIsNotValidated`（FAIL）。

### KIT-6 `RestoreClient` 跳过重定向 URI 校验，authorize 会照单全收一个 `javascript:` 重定向

- 严重度: 中
- 类别: 安全
- 不变量/性质: 「注册到客户端的 redirect_uri 永远不可能是一个浏览器会解释的文档」——
  `oauth/client.go:168-178` 的 `forbiddenRedirectSchemes` 明确把它写成不变量，但只在 `NewClient` 生效。
- 证据:
  - `oauth/client.go:180-192` 的注释是**故意**的（「a URI already in the registry was accepted under whatever
    policy was in force when it was written」），但 `AllowsRedirect`（:159-166）是纯字符串相等，
    所以在 authorize 路径上**没有任何第二道检查**：
    `describe()`（`as.go:101-103`）→ `AllowsRedirect` → 通过。
  - 运行证据：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestB3_|TestB2_' -v
    TestB2: NewClient refused "javascript:alert(1)": the javascript: scheme is never a redirect target
            NewClient refused "data:text/html,x" / "file:///etc/passwd" / "http://example.com/cb" / ... 9 条全拒
            （对照组：http://127.0.0.1:8080/cb 被接受，证明循环体真的跑到了判据）
    TestB3: DescribeAuthorization ACCEPTED client restored whose registered redirect is
            [javascript:alert(document.cookie)]
    ```
- 状态: CONFIRMED
- 影响: 谁能写进 registry，谁就能决定 authorize 把 code 送到哪里。本条本身**不是**直接 XSS：
  `upstreamkit/handleAuthorize`（`server.go:234-236`）用 `http.Redirect` 发 `Location: javascript:...`，
  现代浏览器在 `Location` 上不执行 `javascript:`（它只在用户点击/`<a href>` 时才执行），**所以我没有把它写成
  阻断上线**。真正的风险面有两个：(a) 一个把授权响应渲染成链接或用自己的前端跳转的源实现，
  会把这条 URI 变成存储型 XSS；(b) `docs` 与 `NewClient` 让读者以为「registry 里的重定向 URI 都是安全的」，
  而 `RestoreClient` 是持久化 registry（postgres `Clients.Get` → `scanClient` → `RestoreClientWithStatus`，
  `internal/store/postgres/oauth.go:443-447,549-569`）**唯一的**读取路径，所以这句话对生产库是假的。
- 修法建议: 不要在 `RestoreClient` 里拒绝（会按注释说的那样让一个收紧的规则变成起不来的部署），
  而是在**用它之前**加一道与 `NewClient` 同源的检查：
  - 在 `Client.AllowsRedirect` 里先对 `uri` 跑 `validRedirectURI`（它已经存在，且是纯粹的函数），
    不合法直接 false。这一处收口同时覆盖 `DescribeAuthorization`、`Authorize` 与 kit 的 `/oauth/authorize`。
  - 加一条启动自检：`ClientAdmin.List` 的结果里任何 `RedirectURIs` 不通过 `validRedirectURI` 就记一条
    error 级审计/日志，让「历史遗留的坏行」可见而不是静默可用。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的
  `TestB3_RestoreClientSkipsRedirectValidation`（FAIL）；对照组 `TestB2_RegistrationRefusesDangerousRedirects`（PASS）。

### KIT-7 conformance 不对客户端认证做任何断言：一个声明 `client_secret_basic` 却谁都不认证的源，零 error 通过

- 严重度: 中
- 类别: 可维护性 / 合规
- 不变量/性质: 「conformance 是 spec 的可执行形态」——它必须能对它所断言的每一条性质**失败**。
  实测它对「客户端认证」这一整类性质**完全无断言**，于是它给出的「合规」是假保证。
- 证据:
  - `upstreamkit/conformance/conformance.go:183-205`：`checkOAuthMetadata` 只读
    `code_challenge_methods_supported` 与 `response_types_supported`，**读了但从不使用**
    `token_endpoint_auth_methods_supported`（契约里根本没这个字段）。
  - 全套流程里唯一带客户端身份的请求是**未知客户端**（`checkAuthorizeRejectsUnknownClient`、
    `checkTokenRejectsBadGrant`、`checkRevocationEndpoint`、`checkCascadeEndpoint` 一律用
    `client_id: "conformance-unknown-client"`）。**没有任何一步**先拿一个合法凭据做出成功请求、
    再用错误凭据断言失败。
  - 运行证据（对照组 F1 先证明这套断言并非空转）：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestF1_|TestF2_|TestF3_' -v
    TestF1: [error] authorize.rejects_unknown_client: redirected (status 302) instead of returning an error
            [error] token.rejects_bad_grant: a bogus grant was accepted with status 200
            errors=2 warnings=0 skipped=2      <- 对照组：套件确实会失败
    TestF2: a source that authenticates nobody: errors=0 warnings=0
            token with no client identity at all -> 200
              {"access_token":"minted-without-any-client-auth",...}
            a source that declares client_secret_basic and authenticates nobody passes
              conformance with zero errors
    TestF3: the suite DID post to the cascade endpoint with an unknown client id and no Basic auth,
            and the endpoint answered 200 ... cascade check verdict: PASS
    ```
    F3 特别说明问题所在：套件**确实**打了 cascade 端点（且用的是未知 client），
    但它唯一看的是 `resp.StatusCode == 404`（`conformance.go:295-297`）——**200 就算通过**。
    所以一个「谁拿着 token 都能结束会话」的端点（正是 KIT-1 里那个真实存在的形状）在 conformance 里是 PASS。
- 状态: CONFIRMED
- 影响: 三方源（以及 Re0Auth 自己的参考源 `cmd/referencesource`）可以用
  `TestReferenceUpstreamPassesConformance` 那类调用拿到「合规」结论，而这个结论**不覆盖**
  `docs/upstream-protocol.md` 里 Re0Auth 最依赖的那条信任假设（「源会认证它的客户端」）。
  这与 `BRIEF.md` 描述的反空转要求恰好相反：一个不能失败的 conformance suite 是假保证。
- 修法建议: 加两组带状态的检查，都只需一个已注册客户端：
  1. **认证存在性**：`checkRevocationEndpoint` / `checkCascadeEndpoint` 补充「用未知 client_id 打已宣告的端点，
     必须是 4xx（401/400），不能是 2xx」。这是一条**无需任何秘密**的断言，成本为零，能立刻抓住 KIT-1。
  2. **认证必要性**：`Options` 增加 `ClientID`/`ClientSecret`（可选），提供时跑
     `checkTokenRejectsBadCredentials`：先用正确凭据换一次（断言 200，作为对照），
     再用错误 secret 换一次（断言 401 `invalid_client`）。并在 `checkOAuthMetadata` 里把
     `token_endpoint_auth_methods_supported` 读出来、与「实际接受的认证方式」比对。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的
  `TestF2_ConformanceIgnoresClientAuthentication`、`TestF3_ConformancePassesAnUnauthenticatedCascade`（两条 FAIL）；
  对照组 `TestF1_ConformanceDetectsAnObviousNonConformance`（PASS）。

### KIT-8 小体积上限在无 `Content-Length`（chunked / gzip）时回 `400 malformed form body` 而不是文档承诺的 `413`

- 严重度: 低
- 类别: 可用性 / 可观测性
- 不变量/性质: `oauth/bodylimit.go:9-14` 与 `upstreamkit/server.go:152-158` 共同声明的性质：
  「超限的请求体拿到一个 OAuth 形态的 413」。实际上只有声明了 `Content-Length` 的那一类拿到 413。
- 证据:
  - `oauth/bodylimit.go:27-35`：`r.ContentLength > MaxFormBytes` 只覆盖「声明了长度」的情况；
    长度未知（chunked，`ContentLength == -1`）时走 `http.MaxBytesReader` 分支。
  - `upstreamkit/server.go:240-243` / `:296-299` / `:319-322`：`r.ParseForm()` 一旦报错就
    一律回 `400 invalid_request "malformed form body"`。而 Go 标准库的
    `parsePostForm`（`$GOROOT/src/net/http/request.go:1306-1312`）在 `io.ReadAll` 出错时
    **丢弃已读到的字节并返回该错误**，于是 `MaxBytesError` 就变成了这个 `ParseForm` 错误。
  - 运行证据：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestE6_|TestE6b_|TestE8_' -v
    control small body -> 401 {"error":"invalid_client","error_description":"unknown client"}
    declared oversize (Content-Length)      -> 413 {"error":"invalid_request","error_description":"request body too large"}
    chunked oversize (no Content-Length)    -> 400 {"error":"invalid_request","error_description":"malformed form body"}
    gzip oversize (151 wire bytes)          -> 400 {"error":"invalid_request","error_description":"malformed form body"}
    TestE6b: grant_type hidden past the cap -> 400 malformed form body
             control, same body under the cap -> 200  <- 对照组：同形状、体量合法时确实成功
    ```
- 状态: CONFIRMED
- 影响: **没有绕过**——`TestE6b_` 证明把 `grant_type` 藏到 64 KB 之后并不会执行
  （上限确实封住了攻击面，只是回错了错误）。真实影响是运维与客户端两侧的**误分类**：
  一个超限请求在被限流的协议面上记为「malformed form body」，进入 4xx 客户端错误指标、
  不产生 413 计数，于是「有人在灌大 body」这件事在 `Re0Auth` 与源两侧的仪表盘上都看不见。
  调用方也无法区分「我的表单写错了」与「我的 body 太大了」——而后者是可修的。
- 修法建议: `withBodyLimit` 之外，把 `ParseForm` 的错误分类后再回答：
  ```go
  if err := r.ParseForm(); err != nil {
      if _, tooBig := errors.As(err, new(*http.MaxBytesError)); tooBig {
          writeOAuthError(w, r, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
          return
      }
      ...400 malformed...
  }
  ```
  或者更彻底：在 `LimitFormBody` 里把 body 换成自己的 reader（记录是否触发上限），
  让 `ParseForm` 的错误在语义上可分。三个调用点（token / revoke / cascade）共用一个小 helper。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的 `TestE6_BodyLimitVariants`（FAIL，第 2 段）；
  对照组 `TestE6b_BodyLimitHasNoBypass`（PASS，钉住「没有绕过」这条更重要的性质）。

### KIT-9 两份 well-known 文档都没有 `Cache-Control`：过期的发现文档可以被中间层长期钉住

- 严重度: 低
- 类别: 合规 / 可用性
- 不变量/性质: 「发现文档与代码说的是同一件事」——一旦文档被缓存，这句话就变成「缓存里的文档与代码说的是同一件事」。
- 证据:
  - `upstreamkit/server.go:169-185`：`handleDiscovery` 与 `handleOAuthMetadata` 只 `writeJSON`，
    **没有** `Cache-Control`，也**没有** `Vary`；只有 `handleToken` 的成功路径设了
    `no-store`（`server.go:259-260`、`:280-281`）。
  - 运行证据：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestE7_|TestE8_' -v
    /.well-known/re0auth-upstream              200 Cache-Control="" Vary=""
    /.well-known/oauth-authorization-server    200 Cache-Control="" Vary=""
    token error response: 400 Cache-Control="no-store"     <- 对照组：这个服务在别处是会设的
    ```
  - 对照：Re0Auth 自己的平面在 `internal/httpapi/responses.go:102,117` 与 `server.go:343` 都设了
    `no-store`，`internal/httpapi/health.go:64` 亦然——**同一仓库里，kit 是唯一漏掉的那一处**，
    所以这不是「风格不同」，而是这一处没跟上。
- 状态: CONFIRMED
- 影响: 发现文档会随部署变化（`Issuer`、`scopes_supported`、`resources`，以及
  `cascade_revocation_endpoint` 的**出现与消失**）。源与 Re0Auth 之间常有一个反向代理；
  没有指令时中间层可以按启发式长期缓存，把 Re0Auth 指向一个**已被移除的端点**或**已经不再支持的 scope**。
  最坏形态是可复现的：一条被缓存的 `cascade_revocation_endpoint` 指向一个已经关掉的钩子，
  Re0Auth 侧 `handleCascadeRevocation` 会回 404（`server.go:323-326`），
  而 `internal/federation/revocation.go:142-144` 把它当成失败——但在那之前，
  `httpapi/binding_routes.go:96` 已经把「这个源支持全部登出」展示给用户了。
- 修法建议: 在两处 `handleDiscovery` / `handleOAuthMetadata` 加
  `w.Header().Set("Cache-Control", "no-store")`（与 Re0Auth 平面一致，最简单、最安全）；
  若希望允许缓存，则显式写 `Cache-Control: public, max-age=<短>` 并补 `Vary: Host`
  （文档里的 URL 目前来自配置而非请求，所以 `Vary` 是为将来防 Host 污染的纵深防御）。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的 `TestE7_DiscoveryCacheHeaders`（FAIL）。

### KIT-10 `ClientAdmin.Delete` 只删客户端行，不删它的令牌，于是「客户端已删除」与「它的授权还在」同时成立

- 严重度: 低
- 类别: 合规/隐私 / 可维护性
- 不变量/性质: `oauth/grants.go:33-42` 声明的性质：「grant exists exactly as long as the client holds a usable
  token, so revoking one is just deleting them, and there is no second source of truth」。
  `ClientAdmin.Delete` 制造了第二个真相：客户端没了，令牌还在，而用户侧的授权列表
  （`Grants`/`ClientNames`）会继续把它们列出来。
- 证据:
  - `oauth/client.go:423-428`（`MemoryClientRegistry.Delete`）：只 `delete(r.byID, id)`；
    `internal/store/postgres/oauth.go:515-518`（`Clients.Delete`）：`DELETE FROM oauth_clients WHERE id = $1`。
    `oauth/client.go:318-320` 的 doc 只说「Deleting an absent client is not an error」，**没有**说
    （也**没有**做）令牌的处理。
  - 运行证据：
    ```
    go test ./internal/zzprobe/protocol/kit/ -run 'TestA6_|TestA5_' -v
    TestA6: token rows for the subject after ClientAdmin.Delete: 2
    TestA5: Introspect after the client row was deleted: active=true subject=usr_probe_subject
    ```
    两条合起来：删完之后，令牌行还在（2 条），而且**仍然 active**——但没有任何东西能再告诉
    用户或运维「这 2 条属于谁」，除非靠 `ClientNames`（它刻意不隐藏 suspended，
    `client.go:357-374`，但已删除的行连名字都没有了）。
- 状态: CONFIRMED
- 影响: 与 KIT-3 是同一条根因的**另一个出口**，单独列出来是因为修法不同：KIT-3 是「读的时候要不要问 client」，
  本条是「写的时候要不要连带删」。组合后的形态是「一个运维以为已经彻底移除的客户端，仍持有一小时的
  可读数据面令牌，且授权列表上是一条没有名字的记录」。**不是**跨账号读写，所以定低。
- 修法建议: 让 `ClientAdmin.Delete` 的契约包含令牌清理（这与 `ClientAdmin` 接口注释里
  「the operations an operator uses to review and revoke clients」一致）：实现里调用
  `TokenAdmin.RevokeTokens(ctx, TokenFilter{ClientID: id})`（`oauth/tokens.go:112-116` 已存在），
  或在文档里明确写「Delete 不撤销令牌」并把清理责任交给调用方。
  若采纳 KIT-3 的修法 1（Introspect 问 client），本条的**安全**后果自动消失，但
  「孤儿令牌行」的合规/可维护性问题仍在，所以两条都值得留。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` 的
  `TestA6_DeleteClientLeavesTokenRows`（FAIL）。

---

## 探过但没破的

以下每一条都**先跑通了对照组**再断言被拒/未被破坏。它们的价值是变成守卫。

1. **`code_challenge` 的比较本身是严格的**（`TestC3_`）：`verifier == challenge`（即 `plain` 攻击）被拒；
   `code_challenge_method=plain` 在 authorize 就被拒；机密客户端**也**被要求 PKCE（比 RFC 7636 更严）。
   比较走 `subtle.ConstantTimeCompare`（`as.go:336-343`），长度不等会立即失败且不泄漏前缀。
2. **scope 无法通过参数形状被偷渡**（`TestD1_`，9 种形状）：逗号分隔、重复参数、`scope[]`、
   大写、换行/制表符分隔、逗号后缀全部 400 `invalid_scope` 或**只保留原本已授予的 scope**；
   放**query** 里的 `scope` 完全不被读（`PostFormValue` 只看 body）。
   对照：同形状的合法 refresh 成功 200。
3. **omitted 与 explicitly-empty 的 scope 集合行为一致**（`TestD2_`）：`nil` 与 `[]Scope{}` 都保留
   原有 scope 集合（`account.read phigros.profile.read`），不会静默降级成空集；
   `[]Scope{""}` 被明确拒绝（`invalid_scope`）。
4. **未注册 scope 与目录外 scope 都被拒**（`TestD3_`）：窄客户端要 `phigros.profile.read` →
   `invalid_scope: client is not registered for ...`；`not.in.catalogue` 与 `ACCOUNT.READ` →
   `unknown scope`。对照：它要自己的 `account.read` 成功。
5. **令牌的 scope 恒等于授权码的 scope**（`TestD4_`）：`CodeExchangeRequest` 里**根本没有**
   scopes 字段，这是结构上不可能而不是靠判断——这条的价值是防止将来有人给它加一个字段。
6. **重定向 URI 的匹配是逐字节相等**（`TestB1_`，12 种变体）：追加 query/fragment、尾斜杠、
   `../`、`%2e%2e`、userinfo `@`、大写 host、大写 scheme、默认端口 `:443`、`%63b` 路径编码、
   双斜杠、空值——**全部**被 `invalid_request: redirect_uri is not registered` 拒绝。
   注意 `handleAuthorize`（`server.go:234-236`）用的 `resp.RedirectURI` 就是被校验过的那个值，
   不存在「成功重定向校验了、错误重定向没校验」的分裂：错误路径 `writeProtocolError`
   发生在**任何**重定向之前。
7. **注册期的重定向 URI 校验是有效且完整的**（`TestB2_`，9 种危险形态）：`javascript:`、`data:`、
   `file:`、非 loopback 的 `http`、带 userinfo、带 fragment、无 scheme、`app:`（非反向 DNS）
   全部被 `NewClient` 拒绝；合法的 `http://127.0.0.1:8080/cb` 通过。
8. **revoke 的归属校验成立**（`TestG1_`）：未知 token → 幂等成功（无错误）；
   别人的 access/refresh token → `invalid_client`；自己的 → 成功且之后 `Introspect` 为 `active=false`；
   secret 错 → `invalid_client`。并且**失败的撤销没有副作用**：另一方的令牌仍然 `active=true`
   （这条断言正是「上次修好的那个洞没有再回来」）。
9. **Basic 的百分号解码不会造成跨客户端认证**（`TestG4_`）：**这是我本轮先立后破的一条假说。**
   我原本推断「secret 里的 `+` 与空格是同一个等价类」，会形成可互相认证的碰撞。
   实测**否定**：A(secret `a+b`) 用 `a+b` 上线解成 `a b` 后按 client id `A` 认证**失败**；
   B(secret `a b`) 用 `a%2Bb` 解成 `a+b` 后按 `B` 认证**失败**；
   `AuthenticateClient(A, "a b")` 与 `AuthenticateClient(B, "a+b")` 都返回
   `invalid_client: invalid client credentials`。真正存在的只是一个正确性后果：
   含 `+` 的 secret **必须**编码成 `%2B`，不编码（`a+b`）会解成空格而失败，错误是本轮认定
   不可区分（同样的 `invalid_client`）。而且生产里的 secret 由
   `internal/admin/admin.go:461-467` 生成为 64 字符 hex，**不含** `+`/`%`，所以实际不可达。
   我把这条写成了守卫（`TestG4_BasicPercentDecodingDoesNotCrossAuthenticate`），防止将来有人
   把 `unescapeForm` 改成更激进的规范化。
10. **令牌熵与不可枚举性**（`TestG3_`）：64 对令牌、128 个值**零重复**，每个 access token
    解 base64url 后恰好 32 字节（`newToken`，`as.go:353-359`），**零个**共享的 8 字符前缀
    （计数器/时间戳结构会立刻显形）。刷新令牌与访问令牌各自独立生成、各自独立哈希。
11. **设备流的三个已知修复确实还在**（静态复核，`oauth/device.go`）：读—判—写已被拆成
    `RecordPoll`（只动 `last_poll`）与 `RecordDecision`（带 `status = 'pending'` 谓词，
    `device.go:206-219`），第一决定即最终；`describeScopes`（:415-430）同时查目录与
    `client.AllowsScope`，所以 A1-1 那条「签发未注册 scope」没有在库里复活；
    `DecideDeviceAuthorization` 的 `granted` 必须 ⊆ `rec.Scopes`（:380-384），
    且显式空批准被拒而不是被升格成全量（:375-379）。**没有**报为新发现。
12. **discovery 与实际服务一致**（`TestH1_`，有/无 cascade 钩子各一轮）：
    - 有钩子 → `cascade_revocation_endpoint` 被宣告；无钩子 → **不**被宣告
      （`server.go:117-124` 以钩子而非配置为准，这是对的设计）。
    - metadata 里宣告的 `authorization_endpoint` / `token_endpoint` / `revocation_endpoint`
      逐个 POST 都不是 404（405 / 400 / 401），即「宣告了但没实现」没发生。
    - `token_class`、`grant_types_supported`（`authorization_code`,`refresh_token`）、
      `code_challenge_methods_supported`（`S256`）、`token_endpoint_auth_methods_supported`
      （`client_secret_basic`,`client_secret_post`,`none`）与实现一致；
      设备流**没有**被宣告，而 kit 也**确实**不挂设备端点（`server.go:139-150`），一致。
    - `TestH2_`：metadata 里**没有** cascade 字段，而 discovery 里有 —— 漏掉是安全的
      （不宣告就不会被相信），但两处文档由两段代码各自手写，属于会漂移的形状（提示级，
      见「判断」）。
13. **`-race` 可用**：`go test -race ./internal/zzprobe/protocol/kit/` 在 Go 1.27.1 本机跑通，
    42 个测试全跑、**零 `DATA RACE`**。但请注意：本轮的每一条结论都是**确定性**复现的
    （单线程、固定时钟、固定夹具），所以**没有**任何一条安全结论依赖竞态检测器背书。

---

## 未能到达（残余盲区）

1. **Postgres 侧 store 只能读代码到行**（本机无 Docker、无本地 Postgres）。以下每条标
   **读；无 DB 执行**：
   - `internal/store/postgres/oauth.go:36-57` `ConsumeCode` 的 `DELETE ... RETURNING`：
     **读；无 DB 执行** —— 我据此判定 KIT-4（失败即消费）在 Postgres 上同样成立，
     因为删除语句里没有任何谓词。这条对 KIT-4 的**结论**是必要的，且是我无法执行的部分。
   - `internal/store/postgres/oauth.go:207-227` `TokenOwner`：**读；无 DB 执行** ——
     KIT-3 的「暂停后仍 active」不依赖它（不查 client 行），但 G1 的归属校验在生产上走的正是它。
   - `internal/store/postgres/oauth.go:443-447` `Clients.Get` 的
     `WHERE id = $1 AND status <> 'suspended'`：**读；无 DB 执行** —— 这是 KIT-3 修法 1
     在生产上能生效的前提（suspended 会被折叠成 not found）。
   - `internal/store/postgres/oauth.go:365-395` `RecordPoll` / `RecordDecision`：**读；无 DB 执行** ——
     设备流丢失更新的修复在 PG 侧的形式（`status = 'pending'` 谓词 + `RowsAffected`）我读了，
     没跑。
   - `internal/store/postgres/oauth.go:288-327` `revokeMatching` / `revokePredicate` 的
     **字符串拼接 SQL**：我读到表名全是编译期常量、只有列名与占位符被拼、值一律走参数，
     所以判定不是注入；**读；无 DB 执行**，没有跑过。
2. **`upstreamkit` 的 body 上限在 HTTP/2 下未实测**。httptest 的默认 server 是 HTTP/1.1；
   我压了「声明长度」与「chunked」两条路，**没有**跑 h2（需要 TLS + `http2.Transport`）。
   读代码判断：`http.MaxBytesReader` 与协议版本无关，h2 的 DATA 帧同样走 `r.Body`，
   所以上限应当成立；但这是**推断，不是证据**。
3. **`upstreamkit/conformance` 对真实第三方源的运行**未做：探针用的是自造的
   `httptest` 伪源。所以「这个套件在生产网络条件下（重定向、TLS、代理）是否稳定」
   我**没有**证据可说。
4. **`oauth/` 作为公开库的外部使用者**不可见。`oauth/device.go` 的设备端点**不在**本仓库的
   任何组合根上（`cmd/re0auth` 只装配 `oauth.TokenAdmins`、`NewMemoryClientRegistry`、`NewClient`；
   kit 不挂设备端点），所以我对设备流的结论全部是**库层**的；一个外部使用者是否会用错
   `DeviceStore` 的新方法形状，我无法探到。
5. **KIT-6 的浏览器行为**：我断言现代浏览器不在 `Location:` 上执行 `javascript:`，
   这是**常识而非本轮实测**。我没有浏览器可跑（`pnpm test:e2e` 需要 Chromium）。
   所以 KIT-6 的严重度是基于「(a) 会渲染成链接的前端实现 与 (b) registry 安全性声明为假」
   这两条可核对的理由定的，而不是基于「已确认的 XSS」。
6. **`ClientCredentials` 在 multipart 表单下的行为**未测：`r.PostFormValue` 会触发
   `ParseMultipartForm`，而 `LimitFormBody` 只包了 `r.Body`；理论上 `multipart` 的
   10 MB 上限仍然生效（`MaxBytesReader` 在前），但 `upstreamkit` 的 endpoint 没有
   `Content-Type` 白名单，所以一个 `multipart/form-data` 请求会走到哪条分支**我没跑**。
   读 `ParseForm` 的顺序判断它最终仍受 64 KB 约束，属**推断**。
7. **协议面 401 不带任何 challenge**：`oauth/as.go:315,321` 回 `invalid_client`，
   `upstreamkit/server.go:447-458` 把它转成 401，而 `writeOAuthError` 只在
   `status == http.StatusUnauthorized` 时加 `WWW-Authenticate: Basic realm="oauth"`
   （`server.go:435-437`）—— 也就是说 `handleToken` / `handleRevoke` / `handleCascadeRevocation`
   这些**客户端认证**端点的 401 **没有** `WWW-Authenticate`。这是从代码读到的确定性事实，
   但我在跑完测试后才注意到，**没有**为它写断言，所以不作为 finding 报出（它与
   `docs/security-audit-3.md` A3-3「协议面 401 不带 Bearer challenge」是同一形态，
   严重度最多为「提示」，且我没有证据说明它有实际后果）。若要补守卫，
   在 `TestE4_` 里加一条 `resp.Header.Get("WWW-Authenticate") != ""` 即可。

---

## 判断

- **`RestoreClient` 不校验重定向 URI 是文档化决定**（`oauth/client.go:180-192` 写清了理由：
  收紧的规则不该让部署起不来）。我把它写成了 finding（KIT-6），但**不是**在质疑这个决定本身——
  我质疑的是「决定不校验」被实现成了「authorize 路径上没有任何替代检查」。
  若维护者认为「registry 的写入方是可信任的运维」是接受的风险，那 KIT-6 应降为「提示」，
  并应在 `client.go` 的注释里补一句「因此 authorize 路径不再做第二道检查」——
  现在注释只说了不校验，读的人不会知道**没有别人**在补。
- **`Grants` 的「令牌即授权」是文档化决定**（`oauth/grants.go:33-42`）。
  KIT-10 报的是 `ClientAdmin.Delete` 与这条决定**不一致**（令牌留下了、授权列表还在列），
  不是报这条决定本身。
- **`/v1/admin/*` 未认证返回 401、`raw` 透传不解析 body、不实现 DPoP/PAR/`end_session`/
  动态客户端注册/CORS 等**，都是文档化决定，本轮**没有**报。
- **两份 well-known 文档由两段代码各自手写**（`server.go:169-185` 的 map 与
  `discovery.Discovery` 结构体）。这本身不是缺陷，本轮只报它导致的**具体**后果
  （KIT-9 的缓存头缺失；`TestH2_` 显示的 cascade 字段不对称）。若将来要消除这一类风险，
  正确做法是让 metadata 从 `Discovery` **派生**（`cascade_revocation_endpoint` 与
  `re0auth_upstream_version` 除外），而不是再加一份手工映射——但那是一次重构，
  属于裁定，不该顺手做。
- **`Introspect` 不接收调用者身份**（`oauth/as.go:253`）本身是设计选择——kit 用它当内部判据，
  且它**不**是 RFC 7662 端点。本轮**没有**把它当 finding；只在 `TestG2_` 里记下
  「一旦有人把它接到一个公开的 introspect 端点，它会泄漏任意 token 的 subject/client/scopes」，
  作为将来接线的注意项。
