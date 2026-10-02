# 区域 14：Upstream Kit / RP �?/ TapTap 适配 �?第七轮审计报�?
## 范围与方�?
读了 `upstreamkit/{server,discovery}.go`、`upstreamkit/conformance/conformance.go`（全�?8 �?check）�?`oauth/{as,client,scope,grants}.go`、`idp/idp.go`、`referencesource/{taptap,source,cascade}.go`�?`tapsign/*`、`taptapoauth/client.go`、`internal/federation/revocation.go`、`docs/upstream-protocol.md`�?�?round-5/6 台账排除重报。探针目�?`internal/zzprobe/audit7/z14kitrptaptap/`�? �?test 文件 + `doc.go`�?全部 `//go:build audit7`）。真进程：`httptest` 起真实的 `upstreamkit.Server` / `idp.Client` /
`referencesource.Source`，从 HTTP 入口驱动；RP 侧用可控 fake OP（`fakeop_test.go`）�?
```
go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z14kitrptaptap/...   # 6 �?/ 7 绿（每红有对照）
go build ./...   # exit 0
go vet ./...     # exit 0
gofmt -l internal/zzprobe/audit7/z14kitrptaptap/   # �?```

�?Docker / 无本�?Postgres：依赖真实库的形态只有读码级证据（见「未能到达」）�?
---

## 发现

### Z14-1 级联撤销失败�?refresh token 已被消费，Re0Auth 的「重试」永远打不到上游
- 严重度：**P2 �?*（可用性；状态不可恢复，但报 500 非静默）／类别：可用性、协议一致�?- 不变量：撤销失败时保留绑定与凭据**就是为了重试**（`internal/federation/revocation.go:110-116`�?  `docs/upstream-protocol.md:165-166`）�?- 证据（探针失败）�?  ```
  cascade #1: 500 server_error (RevokeUpstream calls=1)
  cascade #2: 500 server_error (RevokeUpstream calls=1)
  the credential is still in the source's vault after both attempts: true
  --- FAIL: TestZ14FailedCascadeBurnsTheRefreshTokenSoTheRetryNeverReachesUpstream
  ```
  绑定凭据还在（Re0Auth 什么都没删），但第二次再也解不�?subject�?- 机制：`referencesource/cascade.go:52-55` �?`tokenSubject`，其 `:80-86` �?*破坏�?*�?  `tokens.ConsumeRefresh`，`:59-65` 才调 `RevokeUpstream`。上游失�?�?`vault.Revoke` 不执行�?  Re0Auth 不删绑定，但 token 已死。重试时 `preferredToken`（`revocation.go:67-75`）送的还是它�?- **文档自相矛盾**：`docs/upstream-protocol.md:162` 允许源消�?token（「Re0Auth 紧接着就会把绑定删掉」）�?  `:165-166` 又要求失败时凭据可重试；`upstreamkit/server.go:85-86` 同样�?"MAY consume it: the binding
  is removed either way"——失败路径上 "either way" 不成立。参考实现照做了 `:162`�?- 状态：**CONFIRMED**（真进程 + �?endpoint�?- 影响：上游一次坏分钟之后，该绑定的「登出全部设备」永久不可用，除非解�?重绑（要用户重新扫码）；
  用户反复点都�?500，无自愈路径�?- 修法：先非破坏性解�?subject（新增「lookup refresh 不消费」或改用 access token），
  上游成功后再消费/作废；并�?`server.go:85-86`、`upstream-protocol.md:162` 改成
  「仅在调用成功后 MAY consume；失败时令牌仍须可解析」。是否要求可重试是裁定，但两种行为不能同时被文档允许�?- 探针：`cascade_test.go::TestZ14FailedCascadeBurnsTheRefreshTokenSoTheRetryNeverReachesUpstream`（红�?- 相关：无既有点名；与 KIT-1 修复（`b5f01da`，端点先认证）同端点但不同机制，非重报�?
### Z14-2 一致性套件对 `/oauth/revoke` 认证零断言：谁都能吊销的数据源被判 compliant（对 KIT-7 修复的补充）
- 严重度：**P2 �?*（假 PASS；套件是可执行规范）／类别：可维护性、安全（生态）
- 不变量：`docs/upstream-protocol.md` §6.1 要求撤销端点先认证；KIT-7 的修复把这一条只加到�?cascade�?- 证据（探针失败）�?  ```
  unauthenticated /oauth/revoke hits=1; suite findings: [cascade.absent(skipped), data.skipped]
  conformance reported zero errors for a source whose /oauth/revoke answers 200 to a request
  with no credentials and client_id="conformance-unknown-client".
  --- FAIL: TestZ14ConformancePassesARevocationEndpointThatAuthenticatesNobody
  ```
  对照 `TestZ14ControlConformanceDetectsAnObviousNonConformance` PASS（套件会对明显非合规�?error）�?- 机制：`conformance.go:253-265` 唯一判据�?`if resp.StatusCode == 404`—�?*其余任何状态码都算通过**�?  相邻�?`checkCascadeEndpoint`（`:294-313`）送同样的「无凭据 + 未知 client」却要求 401/4xx�?  `checkTokenRejectsBadGrant`（`:233-251`）同样不带凭据、只要求�?2xx�?- 状态：**CONFIRMED**（红 + 阳性对照）
- 影响：手写（不用 kit）的数据源忘了在 `/oauth/revoke` 认证，套件全绿；RFC 7009 §2.1 要求认证�?- 修法：`checkRevocationEndpoint` 对无凭据�?POST 断言�?2xx（与 cascade 同形），
  `token.rejects_bad_grant` 加「未�?client + 无凭据」判据。属补齐 KIT-7 修复范围，非新裁定�?- 探针：`conformance_test.go::TestZ14ConformancePassesARevocationEndpointThatAuthenticatesNobody`（红�?- 相关�?*�?KIT-7（round-5，未修）修复不全的补�?*；KIT-7 本体不重报�?
### Z14-3 `jwks_uri` 不与 issuer 绑定：能左右 discovery 的一方让 RP 信任自己的签名密钥，伪造任�?sub（对 RP-3 修复的补充）
- 严重度：**P2 �?*（前提同 RP-3：控�?discovery 响应）／类别：安�?- 不变量：discovery 只能描述 issuer 自己；「谁的签名算数」必须来�?issuer �?origin�?- 证据（探针失�?+ 双向对照）：
  ```
  issuer=http://127.0.0.1:57825 jwks_uri=http://127.0.0.1:57826/jwks discovery=1 issuer-jwks-hits=0
  the RP verified and accepted an id_token signed by a key served from http://127.0.0.1:57826
  ... took sub="sub-forged-by-another-origin".
  --- FAIL: TestZ14DiscoveryJWKSURIIsNotPinnedToTheIssuer
  ```
  `issuer-jwks-hits=0`：RP 根本没碰 issuer �?JWKS。`TestZ14ControlForeignKeyAgainstTheIssuerJWKSIsRejected`
  PASS 证明同一密钥�?`jwks_uri` 同源时被�?�?接受只来�?`jwks_uri` 被改指向�?- 机制：`idp/idp.go:486-509` �?`pinToIssuer` 只查 `authorization_endpoint`/`token_endpoint`�?  `oauthConfig`（`:466-481`）也�?pin 这两个。`jwks_uri` �?go-oidc 从文档原样取�?  （`oidc/oidc.go:172,261`），`idTokenVerifier`（`idp.go:640-646`）用的就是该 keyset�?- 状态：**CONFIRMED**（真 RP + 可控 discovery�?- 影响：`60de35d` 关掉端点劫持（偷 client_secret/授权码）后，控制 discovery 的一方仍可用自己的私钥签一�?  `sub` 任意、`aud=cid`、`nonce` 匹配�?id_token，被接受�?*任意用户**——等价账号接管，�?RP-3 更直接�?- 修法：`pinToIssuer` 纳入 `jwks_uri`（空值跳过），并接到 `oidcProvider`/`idTokenVerifier` 路径�?  显式配置 `jwks_uri` 允许跨源（与 auth_url/token_url 同语义）�?- 探针：`rp_test.go::TestZ14DiscoveryJWKSURIIsNotPinnedToTheIssuer`（红�?- 相关�?*�?RP-3 修复（`60de35d`）的补充**：pin �?2 个端点、漏了第 3 个；RP-3 不重报�?
### Z14-4 provider 缓存 TTL �?discovery 失败时失效：退役密钥在故障期间无限期验签成功（�?RP-2 修复的补�?反驳�?- 严重度：**P2 �?*（窗口从 15 分钟变成「故障持续多久」）／类别：安全
- 不变量：RP-2 修复的目标——退役密钥必须在有界时间内停止验签（`idp/idp.go:32-35`）�?- 证据（探针失�?+ 对照）：
  ```
  attempt 1/2/3: ACCEPTED sub="attacker-with-the-retired-key" with the retired key
  after discovery recovered, the retired key was refused
  TTL (time.Nanosecond) elapsed, but a retired key was accepted 3/3 times while discovery was failing
  --- FAIL: TestZ14ProviderTTLIsDefeatedByAFailingRediscovery
  ```
  对照 `TestZ14ControlTheProviderTTLCacheRetiresARotatedKey` PASS�?*discovery 可达�?* TTL 生效 �?红只来自失败分支�?- 机制：`idp/idp.go:619-637` 失败�?`if c.discovered != nil { return c.discovered, nil }`（`:627-631`）�?  被保�?provider �?go-oidc `RemoteKeySet` 缓存**�?TTL**，只�?kid 未命中重取（`jwks.go:163-179`）�?  discovery 一直失�?�?`time.Since(discoveredAt) < providerTTL` 每次都假、每次都走失败分支，`discoveredAt` 永不前进�?  最后一次成功文档里的密钥无限期有效�?- 状态：**CONFIRMED**（真 RP + 状态翻转）
- 影响：与 RP-2 相同的后果（泄露/退役私钥持续伪�?`sub`），�?*没有上界**�?- 修法：复用旧 provider 的同时保留其年龄，超过硬上界（如 `2×TTL`）即 fail-closed；或用可注入 keyset 做显式重取�?- 探针：`rp_test.go::TestZ14ProviderTTLIsDefeatedByAFailingRediscovery`（红�?- 相关�?*�?RP-2 修复（`60de35d` �?TTL）的反驳/补充**；RP-2 不重报�?
### Z14-5 只配 `auth_url`（未�?`token_url`）时显式端点被静默丢�?- 严重度：**P3 �?*（配置正确性；无跨源后果，但违反文档并给误导建议）／类别：可维护�?- 不变量：`idp/idp.go:181-183` �?auth_url/token_url 是显式覆盖；`pinToIssuer` 的错误信息（`:503-505`�?  让运维「显式配�?auth_url/token_url」�?- 证据（探针失�?+ 对照）：
  ```
  auth_url=.../real-authorize was configured; the browser got "/authorize"; discovery calls=1
  --- FAIL: TestZ14HalfExplicitEndpointIsSilentlyDiscarded
  ```
  对照 `TestZ14ControlBothExplicitEndpointsAreHonoured` PASS：两个都�?�?`/real-authorize`、discovery 0 次�?- 机制：`oauthConfig`（`idp/idp.go:466-481`）提前返回要�?`AuthURL != "" && TokenURL != ""`（`:468`）；
  否则 discovery �?`cfg.Endpoint = endpoint`（`:479`）整体覆盖�?- 状态：**CONFIRMED**（真 RP�?- 影响：登录静默走别的端点（无日志/报错）；跨源时报错内容恰是「请设置你已经设置过的东西」�?- 修法：任一非空即进入显式模式，discovery 只填空字段；可选地对显式端点跨源打日志�?- 探针：`rpconfig_test.go::TestZ14HalfExplicitEndpointIsSilentlyDiscarded`（红�?- 相关：无�?
### Z14-6 参考数据源�?TapTap 登录完成不绑定浏览器：加�?poll URL 即可以攻击者身份登录（会话固定�?- 严重度：**P3 �?*（`referencesource` 不入发布产物；机制确定）／类别：安全
- 不变量：一次登录只改变**发起它的浏览�?*的会话�?- 证据（探针失�?+ 两条对照）：
  ```
  victim poll: 200 {"state":"confirmed","subject":"openid_attacker_z14"}
  a browser that only loaded GET /login/taptap/poll?id=lgn_... was logged in as "confirmed/openid_attacker_z14"
  --- FAIL: TestZ14AnotherBrowserGetsLoggedInByThePollURL
  ```
  对照 1：发起者确实完成（`TestZ14ControlTheRealTapTapLoginCompletesForTheBrowserThatStartedIt` PASS）；
  对照 2（同测试内）：未�?`id` 后该浏览器仍 `anonymous/`。用的是**真实**路由与真�?`TapTapLogin`
  （仅�?enroller/redeemer 换假实现）�?- 机制：`referencesource/taptap.go:129-136` �?attempt id 交给发起方前端；`GET /login/taptap/poll?id=`
  （`:108-110,219-226`）按�?id 推进；`referencesource/source.go:293-304` �?`establish` **无条�?*
  覆盖调用者会话（不检查调用者是否已登录、attempt 属于谁）。cookie �?`SameSite=Lax`（`source.go:newSessions`），
  跨站顶层 GET 会带上�?- 状态：**CONFIRMED（源�?+ 执行级，真路由）**；跨站那半步未用浏览器验证�?- 影响：受害者被带到�?GET 后其数据源会话变成攻击者账号；若随即在 Re0Auth 完成 bind/consent�?  受害者账号被绑到攻击者游戏账号（登录 CSRF）。攻击者不直接读受害者数据�?- 修法：challenge 时把 attempt id 写入会话、poll 时比对；或校�?`Sec-Fetch-Site`/同源 `Origin`�?- 探针：`refsrc_test.go::TestZ14AnotherBrowserGetsLoggedInByThePollURL`（红�?- 相关：无（与 RP-9 不同，这是登录完成侧的会话固定）�?
---

## 探过但没破的（应留成守卫�?
1. RP �?nonce/azp 校验（`idp/idp.go:579-594`）真实生效：nonce 必填、多受众�?azp 必填且须命名本人�?2. `safeurl.RelativePath`（`safeurl/safeurl.go:34-52`）挡�?`//host`、`\`、控制字节、绝�?URL�?3. kit 生成�?`/oauth/cascade_revocation` 真的先认证（`upstreamkit/server.go:336-342`）：匿名/未知 client 401�?4. kit authorize 强制 PKCE S256（`oauth/as.go:104-106`）、redirect_uri 精确匹配（`:101-103`）�?   `Exchange` 比对 code.ClientID/redirect_uri/verifier（`:175-183`）�?5. `taptapoauth` MAC 签名拼装正确（`client.go:252-277`）；错误文本�?`boundDetail`（`:330-343`）去 CR/LF、截�?200 rune�?6. `tapsign` 不泄露凭据：会话令牌只进 `X-LC-Session`（`client.go:124-126`），审计只写 `ObjectID`（`:197-211`）�?7. 套件本身是活的：`checkDiscovery`/`checkOAuthMetadata` �?`upstreamkit.NewDiscovery` 的校验一致，无假 PASS 面�?
## 未能到达（残余盲区）

1. KIT-4 �?Postgres 形态（`DELETE ... RETURNING` 无绑定谓词）及一切需真实 DB 的语义：�?Docker/�?Postgres，只有读码级证据�?2. Z14-4 的「无限期」是逻辑推导：探针能证失败期间仍接受，但无真实上�?可注入时钟去跨越 15 分钟默认 TTL�?3. Z14-6 的跨站场景未构造：�?Playwright，Lax cookie 在真实导航中的携带未验证�?4. 真实 TapTap / Microsoft 端点未联网打；RP-4 的微软默�?issuer 未复测（`60de35d` 已改为启动即失败）�?5. 一致性套�?data �?scope 执行强度（`conformance.go:365-372` 接受 200 �?403）需真实 access token，未单列�?
## 判断（文档化决定可否质疑，不�?finding�?
1. 「源可以消费级联令牌」这个裁定本身合理，问题只在**时机**：消费必须在上游确认之后。Z14-1 反对实现时机，不反对允许消费�?2. 保留�?provider（`idp.go:627-631`）的动机我认同（坏一分钟不该让登录全挂），但「保留」与「无限期信任旧密钥」是两件事，需要硬上界�?3. Z14-6 �?P3 是因�?`referencesource` 不入发布产物；若把它当模板对外发布，该条应升 P2 并在合并前修掉�?