# 协议平面审计报告 —— 复核（对抗性证伪）

> 复核对象：`docs/audit-5/findings/protocol.md`（PROTO-1…11、RP-1…9、KIT-1…10，共 30 条）。
> 复核者立场：**尽力推翻**。原报告一句话经得起复核，胜过十条没人验过的。
> 证据标准同 BRIEF §3；本文件只新建文件，未修改任何已跟踪文件，也未改动被复核的报告与别人的探针。
>
> **总判定：30 条全部复现（三个探针包重跑，FAIL 集合与报告逐条一致），但 3 条严重度需下调
> （RP-1、KIT-1、KIT-3），1 条需要合并（PROTO-11 与 concurrency-memory 的 CM-4），
> 2 条的证据表述需更正（RP-4 的「没有任何文档提到」、KIT-1 的「任何能到达该端点的人」）。
> 未发现原报告把「已文档化的决定」当成 finding 的情况（逐条 grep 过 4 份审计文档 + 8 份 ADR）。**

## 0. 我执行了什么（全部命令与关键输出）

```sh
# ① 三个探针包重跑：FAIL 集合与报告完全一致（8 / 12 / 13）
go test -count=1 -v ./internal/zzprobe/protocol/     # 8 FAIL
go test -count=1 -v ./internal/zzprobe/protocol/rp/  # 12 FAIL
go test -count=1 -v ./internal/zzprobe/protocol/kit/ # 13 FAIL

# ② -race 可跑且无 DATA RACE（复核「探过但没破」第 11 条）
go test -race -count=1 ./internal/zzprobe/protocol/  # 同 8 条 FAIL，无 "WARNING: DATA RACE"

# ③ 我自己的复核探针（新建包，只含 _test.go）
go test -count=1 -v ./internal/zzprobe/verifyprotocol/   # 全 PASS（含 RP-1 的证伪探针）
```

我新建的探针：`internal/zzprobe/verifyprotocol/fixture_test.go`、`spotcheck_test.go`、
`rp_delivery_test.go`（独立重建的夹具：真 `oidchttp.New` + httptest + 内存 OP store；
RP 侧用真 `auth.NewHandler` + `httpapi.New` + 假 OIDC provider）。**没有复用原报告的夹具**，
所以抽检结论不继承它的 bug。

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|---|---|---|---|---|
| PROTO-1 | 高 | 高（维持） | **确认（复现 + 机制逐条核对）** | `requestParams` 吞掉 `ParseForm` 错误 + 首/后续调用不对称 + `Get` 取首值而库取末值，三条我都在行级核过；A1-1 的修复确实被绕过 |
| PROTO-2 | 阻断上线 | 阻断上线（维持） | **确认** | `SetUserInfo` 是赋值（`pkg/oidc/token.go:158-168`）、`sub` 带 omitempty（`:39`）、两 store 的 `SetUserinfoFromScopes` 均 no-op；与 `docs/account-model.md:19` 的书面承诺相反，**不是**已知边界 |
| PROTO-3 | 中 | 中（维持） | **确认（探针 PASS 记录事实，可复现）** | 未逐行重读库回落路径；探针输出与报告一致 |
| PROTO-3b | 中 | 中（维持） | **确认（我自己重跑，含对照）** | 探针先断言业务平面已死（反空转）再断言 userinfo 仍 200；与 PROTO-3 同根同修，分列合理（改动可只挡 JWS 而不查过期） |
| PROTO-4 | 高 | 高（维持） | **确认（机制逐条核对）** | `AuthorizeClientIDSecret` 对非机密客户端直接 `nil`（memory:678-681）、库把「无错」当已认证（`token_intospection.go:55-62`）、`filterIntrospection:941` 只看白名单键；配置/文档从未要求机密 ⇒ **非**已文档化边界 |
| PROTO-5 | 低 | 低（维持） | 确认（探针复现） | 覆盖方向确实搞反 |
| PROTO-6 | 中 | 中（维持） | **确认** | 库 `ValidateAuthReqPrompt` 只做「none 必须单值」+「login→max_age=0」，全仓无 `login_required`；O-9 列举的不做项里**没有** `prompt=none` ⇒ 非已文档化决定 |
| PROTO-7 | 低 | 低（维持） | 确认（探针复现，含 query 模式对照） | — |
| PROTO-8 | 低 | 低（维持） | 确认 + 我核实「生产不可达」 | `cmd/re0auth/config.go:412-413` 强制 issuer 非空；缓存按路径、无 TTL（`oidchttp.go:259-283, 307-330`） |
| PROTO-9 | 低 | 低（维持）**但影响需更正** | 部分成立 | 「凭据进 URL」成立；**Re0Auth 自己的访问日志不记 query**（`middleware.go:231-235, 257`），ADR-0005 第 3 条的理由写的是「**代理**日志」，故影响只剩中间层/浏览器侧 |
| PROTO-10 | 提示 | 提示（维持） | 确认 | 判断而非缺陷的定位正确（被 `TestUserinfoReturnsOnlySub` 钉住） |
| PROTO-11 | 提示 | **中（与 CM-4 合并）** | 重复报告 | 与 `concurrency-memory.md` CM-4 同一资源、同一测量；两份报告给同一现象 提示 vs 高，需一次合并定级 |
| RP-1 | 高 | **低（做纵深防御）** | **部分推翻** | 代码事实成立（`azp` 全仓未读），但**投递路径不成立**：RP 只从自己那次 code 交换的响应里拿 id_token，攻击者无法把令牌喂进去（我的探针实测） |
| RP-2 | 中（任务书误记高） | 中（维持） | 确认（机制读库源码到行） | `jwks.go:163-170` 命中即返回、`:176-189` 未命中才重取、`:220-222` 失败不清缓存；除进程重启**无失效途径**；被吊销的旧密钥需「上游泄露+轮换」前提 ⇒ 中，不是高 |
| RP-3 | 中（任务书误记高） | 中（维持） | 确认 + 可达性收紧 | 端点确实不钉 issuer；但 issuer **只**来自运维配置（`config.go:721-727`，无 https 要求），远程攻击者无法重定向 discovery ⇒ 「运维把 issuer 配到被劫持/自建的 origin」前提成立，报告已如实写明 |
| RP-4 | 中 | 中偏低（维持） | **部分成立（实测复现，但一条证据表述被推翻）** | 真网络复现「内置 issuer 必然 discovery 失败」；但「**没有任何文档/.example 提到这一点**」是错的：`config/re0auth.example.toml:250-254` 就给了 `<tenant>` 写法 |
| RP-5 | 低 | 低（维持） | 确认（探针复现） | — |
| RP-6 | 低 | 低（维持） | 确认（探针复现） | `clearFlow` 在 provider 比对之前（`auth.go:627` vs `:629`）逐行核实 |
| RP-7 | 低 | 低（维持） | 确认（探针复现，含并发） | 作者已刻意压级，理由成立 |
| RP-8 | 提示 | 提示（维持） | 确认（探针复现，dump 出 `flow_nonce`） | `flowKeys`（`auth.go:44`）确实漏 `keyFlowNonce`（`:41`） |
| RP-9 | 中 | 中（维持，仍为 HYPOTHESIS） | 机制确认、时间维度未验证 | `auth.go:575-580` 唯一门槛是「已登录」；`AuthenticatedAt` 只有管理面用（`admin_routes.go:89-92`）|
| KIT-1 | 高 | **中** | **部分推翻** | kit 的端点自身不认证属实；但**参考源在钩子里认证**（`referencesource/cascade.go:48` `AuthenticateClient`）、协议文档规定携带 Basic（`docs/upstream-protocol.md:151-156`）、真调用方确实带（`federation/revocation.go:78-79`）⇒ 「任何人拿到 token 就能摧毁绑定」对唯一在仓实现**不成立** |
| KIT-2 | 中 | 中（维持） | 确认（探针复现；作者已声明未观察到提权） | — |
| KIT-3 | 高 | **中** | 部分成立 | `oauth/as.go:253-271` 确实不问 `s.clients`（且与 `client.go:33-38` 自己的注释矛盾）；但**仓内唯一的 SetStatus 调用者 `internal/admin` 同时 `RevokeTokens`**（`admin.go:238-246`）⇒ 影响被抵消，只在第三方源自建 admin 时成立，窗口 ≤ access TTL |
| KIT-4 | 中 | 中（维持） | 确认（探针复现） | 定向 DoS + 失败不写审计，两条证据都在 |
| KIT-5 | 中 | 中（维持） | 确认（探针复现） | 非权限绕过，作者已声明 |
| KIT-6 | 中 | 中（维持） | 确认（探针复现；浏览器行为免责已写） | `AllowsRedirect` 纯字符串比较，`RestoreClient` 故意不校验 |
| KIT-7 | 中 | 中（维持） | 确认（探针复现） | conformance 对认证零断言、cascade 只判 404 |
| KIT-8 | 低 | 低（维持） | 确认（探针复现） | — |
| KIT-9 | 低 | 低（维持） | 确认（探针复现） | 同仓别处都设了 `no-store` |
| KIT-10 | 低 | 低（维持） | 确认（探针复现） | 与 KIT-3 同一处缺口的表现 |

## 2. 降级 / 推翻的理由（复核最有价值的部分）

### 2.1 RP-1：`azp` 未校验是真的，但「喂给 callback ⇒ 账号接管」不成立（高 → 低）

**先说成立的部分**（我重跑并额外自建探针确认）：

- `idp/idp.go:541` 只传 `&oidc.Config{ClientID: c.oauth.ClientID}`；`oidcClaims`（`:479-485`）
  不含 `azp`，全文件无 `azp`。
- 库侧：`go-oidc v3.21.0 oidc/verify.go:248-259` 只做 `slices.Contains(t.Audience, ClientID)`，
  注释自己写明「This check DOES NOT ensure that the ClientID is the party to which the ID Token
  was issued」。同一函数还检查 `iss`（`:237-246`）、`exp`/`nbf`（`:262-284`）、`alg`（`:295-316`）；
  **不检查 `azp`、不检查 `iat`**。报告的这张清单是准确的。
- 我的探针 `TestVerifyRDTokenEndpointTokenWithForeignAzpIsAccepted` 复现了代码事实：
  同一 issuer 签发的 `azp="other-client"`、`aud=["cid","other-client"]`、`sub="victim-of-another-client"`
  的 id_token 被接受，并建出该 sub 的账号与会话。

**被推翻的部分是投递**。报告写：「攻击者……取得一份（受害者 sub + aud 含本服务 client_id +
azp=攻击者客户端）的 id_token，就能把它喂给 `/auth/<provider>/callback`（`internal/auth/auth.go:656`
→ `Identity`），RP 会以该 sub 建号/登录」。但 `auth.go:605-660` 的 callback **只读
`state` 与 `code`（外加上游的 `error`）**，id_token 永远是这一行拿到的：

```go
token, err := client.Exchange(ctx, code, verifier)   // auth.go:651 —— 自带 client_secret + PKCE verifier
ident, err := client.Identity(ctx, token, nonce)     // auth.go:656
```

`Exchange`（`idp/idp.go:411-420`）是**服务端到服务端**的令牌交换：凭据是本服务的 `client_id/secret`，
PKCE verifier 来自会话（`auth.go:591,624`），code 绑定在上游注册给本服务的 `redirect_uri` 上。
`Identity` 在整个生产代码里**只有这一个调用点**（全仓 grep `Identity(ctx` 只命中这里）。因此，
攻击者手里的 id_token 无从进入验证器；能进入验证器的 token 只能由上游**在响应本服务那次交换时**签发，
而那次交换带着本服务的 nonce（`idp.go:505-507` 强制比对，`:508-510` 强制 sub 非空）。

我的证伪探针把这一点做成了可失败的断言（`internal/zzprobe/verifyprotocol/rp_delivery_test.go`）：

```
$ go test -count=1 -v -run 'TestVerifyRPCallbackCannotBeHandedAnIDToken' ./internal/zzprobe/verifyprotocol/
    rp_delivery_test.go:328: a request-supplied id_token was ignored: callback answered 303 "/?error=identity_failed"
--- PASS
```

做法：真浏览器栈（`/auth/oidcx/start` → 真 callback 路由），伪造的 id_token **带上这次流程真实的
nonce**、`aud=["cid","other-client"]`、`azp="other-client"`、`sub="victim-of-another-client"`，
以 `?code=stolen-code&state=<真 state>&id_token=<伪造>` 提交；同时断言这次交换真的发生了
（`/token` 命中 ≥1，form 里 code 与 `code_verifier` 都对），而会话没有因为请求里的 id_token 而被登录。
对照 `TestVerifyRDTokenEndpointTokenWithForeignAzpIsAccepted` 让上游在**交换响应**里返回同一枚令牌，
登录成功 —— 于是上面那条断言测的是投递，不是流程坏了。

**残余的真实路径**（这部分我要说清楚，避免把结论推成「azp 不用修」）：要让验证器看到一枚「发给别的
客户端」的令牌，只有两条：
(a) 上游自己的令牌端点在本服务的交换上返回了外客户端令牌 —— 那是**信任根本身**在作恶/坏掉，
   此时它也能直接伪造 `azp=cid`，`azp` 检查收益≈0；
(b) 上游不把 code 绑定到客户端（即上游自己有洞），攻击者把自己的 code 递给本服务 callback，
   而本服务以**自己的**凭据兑换成功、上游按原授权请求的 nonce 签发令牌。
   这条链**能**被 `azp` 检查掐断 —— 但它需要上游先有一个洞，且 `nonce` 仍需与攻击者自己的
   本服务会话一致（攻击者能控制，因为他自己就是那个会话）。

所以：**`azp` 检查仍值得补**（OIDC Core §3.1.3.7 是 MUST，一行 JSON 字段 + 三行判断），
但它是**纵深防御**，不是「跨客户端令牌重放 = 账号接管」，因为本服务**不收**别人递来的 id_token。
报告把前提写成「上游允许客户端侧扩展 `aud`」并不够 —— 缺的是「并且这枚令牌能被交到本服务的验证器手里」，
而这一步在当前代码里不可达。**定级：低（纵深防御），修法建议保留。**

> 附带：报告 RP 段的「探过但没破」里有一条**反证**直接支持我的结论——`TestRPNoIDTokenDoesNotFallBackToUserinfo`
> 与 `TestRPEmptyExpectedNonceIsFatal` 说明 «无 id_token ⇒ 失败关闭»、«nonce 不可为空» 都是被钉住的性质。
> 既然 nonce 是绑定的、且令牌只能来自本服务自己的交换，那么「拿到别人的令牌」这一步在协议上就被 nonce
> 与交换归属挡在门外 —— 报告自己承认 nonce 绑定成立，却没有把它代入 RP-1 的影响推理。

### 2.2 KIT-1：kit 端点确实不认证，但「任何人」被推翻（高 → 中）

成立：`upstreamkit/server.go:140-149` 无条件挂载 `POST /oauth/cascade_revocation`；
`handleCascadeRevocation`（`:318-339`）把 `oauth.ClientCredentials(r)` 的结果**原样**转给钩子，
文件内没有任何 `AuthenticateClient`/`clients.Get`/secret 比对 —— 而同一个文件的
`handleToken`/`handleRevoke`/`handleAuthorize` 都把认证交给 `s.hooks.OAuth.*`。探针 `TestE1_`/`TestE3_`
复现：匿名 POST → 200，钩子收到 `ClientID=""`。这些都对。

被推翻的是影响句：「任何能到达该端点的人，只要拿到源签发的 token 值，就能让源结束该 token 所属的
整段上游会话……用户的绑定被一次伪造请求不可逆摧毁」。**仓内唯一实现 cascade 的源自己认证**：

```go
// referencesource/cascade.go:47-50
// Re0Auth is a registered client; this is not an open endpoint.
if err := s.as.AuthenticateClient(ctx, req.ClientID, req.ClientSecret); err != nil {
    return err
}
```

而且这个客户端是**机密**客户端（`referencesource/source.go:189-192` `oauth.ClientConfidential` + secret），
`AuthenticateClient`（`oauth/as.go:89-92`）走 `s.client(..., auth=true)`，机密客户端必须 secret 正确
（`as.go:320-322`）。协议文档也把 `Authorization: Basic`（`docs/upstream-protocol.md:153`）写成请求的一部分，
真调用方确实会带（`internal/federation/revocation.go:78-79`）。子审计片段（`_fragment_kit.md:38-80`）
与合并稿都没读这一段，`referencesource/cascade.go` 里的 `upstreamkit.CascadeRevoke` 钩子是唯一
在仓内的实现，且它做了正确的事。

所以真实的严重度是：**公开库把「谁认证」这件事留给钩子，用一个形状像「已校验凭据」的字段
（`ClientID`/`ClientSecret`）交给第三方源，而套件（KIT-7）又不会因为源不认证而报错。**
一个漏写 `AuthenticateClient` 的第三方源会得到一个「无认证 + 不可逆」的端点。
这是**契约未强制执行 / 假字段形状骗人**，不是「发布产物里一个人人可打的破坏性端点」。
**定级：中**。修法建议（kit 内加一次 `AuthenticateClient`）仍然正确且零成本；若维持现状，
至少要在 `upstreamkit.Hooks.CascadeRevoke` 的注释里写出「钩子必须自行认证
`ClientID/ClientSecret`，否则端点是开放的」——现在那句注释只讲了「设了才广告」。

### 2.3 KIT-3：库契约确实被违，但影响被 admin 抵消（高 → 中）

成立：`oauth/as.go:253-271` 的 `Introspect` 只查 `s.tokens.GetAccess` 与过期，从不问 `s.clients`；
而 `oauth/client.go:33-38` 自己写着「A suspended client …… is reported as unknown by **every**
protocol entrance, because a ClientRegistry.Get returns ErrClientNotFound for it」——
库的书面不变量被自己的一个方法破坏，这是真问题（探针 `TestA4_`/`TestA5_` 复现）。

但影响句需要收紧。`SetStatus`/`Delete` 在**仓内**只有一个调用者：
`internal/admin`，而它每次都连带吊销令牌：

```go
// internal/admin/admin.go:237-246
if err := s.clients.SetStatus(ctx, clientID, oauth.ClientSuspended); err != nil { ... }
removed, err := s.tokens.RevokeTokens(ctx, oauth.TokenFilter{ClientID: clientID})
```

`docs/admin.md:39` 与 `:74` 都把「暂停/删除客户端」定义为「吊销其全部令牌」，主服务侧的
`internal/admin/admin_test.go:145-164`（`TestSuspendHidesClientAndRevokesOnlyItsTokens`）还断言了
「暂停后该客户端 0 条令牌，邻居的 2 条不动」。
所以报告写的「运维点了暂停 → 令牌还活着、数据面照旧可读」在**本仓的组合**里不成立：
组合根（`internal/admin`）在 `Introspect` 之前就把令牌删了。剩下的真实暴露面是
**第三方源**用 `oauth.NewService` + 自己的 admin（只 `SetStatus`，不 `RevokeTokens`）时，
access token 最长再活一个 access TTL（默认 1h），并且**没有任何信号**。
**定级：中**（库契约缺陷 + 一个可选的静默失效路径），并把「修 `Introspect`」与
「文档写清 SetStatus 不吊销令牌」二者取一。

### 2.4 PROTO-11 与 CM-4 是同一件事（提示 vs 高 → 合并为中）

`protocol.md` PROTO-11（提示）与 `concurrency-memory.md` CM-4（高）测的是同一个资源、同一条路径：
匿名 `GET /oauth/authorize` 每次 `CreateAuthRequest`、30 分钟 TTL、janitor 只删过期。
两边都实测了「200 条匿名请求 → 200 条待决记录」，CM-4 还多测了单条成本（约 335 B）、
默认限流 50/s 与在途上限 512。

定级的分歧来自「是否算 DoS」：

- 单地址在默认限流下 30 分钟窗口内上界是 `50 × 1800 ≈ 9 万条 ≈ 30 MiB` ——**有界**，
  不构成本机 OOM；要放大到危险量级需要 `N` 个来源地址（1000 地址 ≈ 30 GiB），
  这是「按地址限流的共性」，不是本部署独有的洞；
- 但「未认证请求零成本增长无上限 map」这条性质本身确实被破坏，且失败是**静默**的
  （不进 413/限流计数，sweep 只删过期），BRIEF §7 对静默失败要求升格。

**合并判定：中。** PROTO-11 的「提示」过低（它自己也承认斜率 = 速率 × 1800s），CM-4 的「高」
过高（单地址有界、需要分布式来源）。两份报告必须收敛到一条，否则容量规划与验收清单会各记一次。

### 2.5 RP-4：事实成立，但「没有任何文档提到」被推翻

内置 `microsoft.issuer = "https://login.microsoftonline.com/common/v2.0"`（`idp/idp.go:142`）
与真实 discovery 返回的 `https://login.microsoftonline.com/{tenantid}/v2.0` 不等 ⇒ discovery 必然失败。
我独立重跑（真网络，本机可达）：

```
$ go test -count=1 -v -run TestRPRealMicrosoft ./internal/zzprobe/protocol/rp/
builtin_test.go:167: control (tenant issuer) fails only at the token: idp: microsoft: verify id_token: oidc: malformed jwt: …
builtin_test.go:185: the built-in Microsoft provider cannot complete any login: idp: microsoft: discovery failed:
    oidc: issuer URL provided to client ("https://login.microsoftonline.com/common/v2.0")
    did not match the issuer URL returned by provider ("https://login.microsoftonline.com/{tenantid}/v2.0")
--- FAIL: TestRPRealMicrosoftBuiltInIssuerCannotDiscover
```

「失败发生在用户已授权之后」也成立（`AuthCodeURL` 因内置端点齐全而不触发 discovery，
`idp.go:427-429`）。但报告与片段都写「**没有任何文档/.example 提到这一点**」，这一条是错的：

```
# config/re0auth.example.toml:250-254
# Pointing a provider at a self-hosted or proxied endpoint:
# [idp.microsoft]
# issuer            = "https://login.microsoftonline.com/<tenant>/v2.0"
```

`.example` 里就有可用的写法（只是没写「不填这个就一定失败」，而且示例注释把它归类成
「自建或反代端点」）。所以这条的准确表述是：**内置默认值不可能成功 + 失败静默通用码 + 文档没把
「必须给租户 URL」写成要求**，而不是「没有任何文档提过」。**维持中（在这条链条上真的损失是
可用性 + 排障）**，但请把证据句改掉，否则评审会以「文档命名有」为由整条驳回。

### 2.6 需要更正的一句：PROTO-9 的「访问日志」

报告 PROTO-9 的影响句是「会让长期有效的 refresh token 与 client_secret 落进**代理/网关**访问日志、
浏览器历史与 Referer」，并在不变量里引 ADR-0005 第 3 条（`凭据不再进入 URL 与访问日志`）。
我核过两边：

- **Re0Auth 自己的访问日志不记 query**：`internal/httpapi/middleware.go:231-235` 明确写着
  「The path is logged; the query string is not.」，日志字段只有 `r.URL.Path`（`:257`）。
  所以若有人把影响句读成「Re0Auth 的日志会存下 refresh_token」，那是错的；
- ADR-0005 第 3 条的**理由段**（`docs/protocol-hardening-decision.md:40`）写的正是
  「凭据会进 URL、**代理日志**与浏览器历史」，与报告的用词一致。

结论：报告的用词没有错（它写的是代理/网关），但既然这一条的全部杀伤力都在中间层，
建议在影响里补一句「本服务自己的访问日志已刻意排除 query（middleware.go:231-235）」，
并把「POST 到带 query 的 URL 不进入浏览器历史」这半个理由删掉（POST 表单 action 带 query
时，浏览器历史是否记录取决于浏览器，报告把它当确定事实偏强）。**严重度维持低。**

## 3. 确认的（我执行了什么 + 那一行有承载力的输出）

| 我复核的条目 | 命令 | 承载力的输出 |
|---|---|---|
| 全区域可复现 | `go test -count=1 -v ./internal/zzprobe/protocol/...` | 8 / 12 / 13 条 FAIL，与报告逐条一致 |
| 「-race 可跑且无竞态」 | `go test -race -count=1 ./internal/zzprobe/protocol/` | 同 8 条 FAIL，输出中无 `WARNING: DATA RACE` |
| PROTO-3b | `-run TestProbeUserinfoIgnoresExpiryAndRevocation -v` | `tokens_test.go:242: userinfo accepted an EXPIRED access token: 200 map[sub:usr_probe]` / `:260 … REVOKED … 200` |
| PROTO-6 | `-run TestProbePromptNoneIsIgnored -v` | `discovery_test.go:99: prompt=none answered 302 "/login?authRequestID=…"`（对照：无 prompt 同样 302） |
| PROTO-9 | `-run TestProbeTokenEndpointAcceptsItsParametersFromTheQueryString -v` | `parseform_test.go:154: the token endpoint served an exchange whose code, secret and verifier were all in the URL: {"access_token":"eyJ…","scope":"account.id",…}` |
| RP-4 | `-run TestRPRealMicrosoft -v`（真网络） | 见 §2.5 的报错原文（含 tenant 对照通过 discovery） |
| 「redirect_uri 精确匹配」（**换了我自己的 13 个变体**） | `go test -run TestVerifyRedirectURIExactnessWithNewVariants ./internal/zzprobe/verifyprotocol/` | 13 个全部 400 且 **Location 为空**；其中 `cb/../cb`、`client.example./cb`、`CB?`、`CB#`、`cb;x=1`、`%00`、制表符等是原报告没试过的语义等价形态 |
| 「redirect_uri 在令牌端点也精确」（换变体） | 同上文件 `TestVerifyTokenEndpointRedirectURIStaysExact` | 5 个子用例：exact 通过、四个变体全部非 200 |
| 「refresh 不能提权」（**换了我自己的 10 个变体**） | `-run TestVerifyRefreshCannotEscalateWithUnlistedVariants` | 10 个变体无一返回未授予的 scope；子集刷新对照 200 |
| 「JWKS 只含公开参数」+ 我加的性质 | `-run TestVerifyJWKSIsPublicOnlyAndMatchesTheSigningKid` | 无 `d/p/q/dp/dq/qi`、唯一 kid、`kty=RSA`/`alg=RS256`，且 **id_token 头的 kid 与 JWKS 公布的 kid 一致** |
| PROTO-3b 的反空转（我补的） | `-run TestVerifyUserinfoRefusesGarbageBearer` | 无 bearer / 垃圾 bearer / 翻改密文 → 非 200；真令牌 → 200（证明 200 不是「什么都不看」） |
| ADR-0005 第 15 条（JWKS 缓存头） | 读码 | `internal/oidchttp/oidchttp.go:525-526` 对 `/oauth/keys` 设 `public, max-age=300`，与 discovery 同 |
| RP-1 的电闸 | 我的探针 `TestVerifyRPCallbackCannotBeHandedAnIDToken` | `rp_delivery_test.go:328: a request-supplied id_token was ignored: callback answered 303 "/?error=identity_failed"`，且 `/token` 确实收到 `code`+`code_verifier` |
| RP-1 的代码事实（对照组） | 我的探针 `TestVerifyRDTokenEndpointTokenWithForeignAzpIsAccepted` | `confirmed at unit level: an id_token with azp=other-client and aud=[cid other-client] is accepted as this client's identity` |
| KIT-1 的反证 | 读码 `referencesource/cascade.go:47-50`、`source.go:189-192`、`oauth/as.go:89-92,320-322` | 参考源是真认证机密客户端的；`_fragment_kit.md` 与合并稿都没有这一页 |
| KIT-3 的反证 | 读码 `internal/admin/admin.go:237-246`、`docs/admin.md:39,74`、`admin_test.go:157-160` | 暂停 = 暂停 + `RevokeTokens(TokenFilter{ClientID})`，且已有测试断言「暂停后 0 条令牌」 |
| 是否「已文档化的决定」 | grep `docs/*.md` × {`prompt`、`login_required`、`introspection_clients`、`suspend/暂停`、`SetUserinfo`、`ParseForm`、`cascade_revocation`} | 只有 `introspection_clients` 有 ADR（只要求「显式登记」，**未**要求机密）、只有 `suspend` 有 ADR（定义为「连同吊销令牌」）⇒ PROTO-4/PROTO-6/`PROTO-1`/`PROTO-2` **都不是**已记录边界；**KIT-3 的载体（suspend 语义）是已文档化决定**，只是 kit 的 `Introspect` 没实现它 |

## 4. 我未能验证的

1. **Postgres 侧**：本机无 DB、无 Docker。PROTO-2/PROTO-4/KIT-3-KIT-4-KIT-10 的 PG 分支我只有读码
   （报告已逐条标「读；无 DB 执行」），**未执行**。这削弱的是「生产同形」这一半，不削弱内存侧结论。
2. **真实上游 IdP 的令牌交换**：没有 GitHub/Google/Keycloak 凭据，RP-1/RP-2/RP-3 的上游行为
   只能在假 OP 上构造。我的证伪探针因此也只能证明「本服务不接受投递」，不能证明「某个真实上游
   不会破坏自己的 code 绑定」——后者本就不是本仓可控的性质，我在 §2.1 已把它写成残余前提。
3. **RP-9 的时间维度**：`auth.Manager` 无可注入时钟，我没有执行「一个月前的会话也能 link」，
   只能确认机制与报告一致（报告自己标 HYPOTHESIS，定性正确）。
4. **RP-7 的 PG 语义**：`SaveAuthCode`/`AuthRequestByCode` 的 SQL 我只读到函数边界（与报告同）。
5. **KIT-6 的浏览器行为**：`javascript:` 重定向是否可执行属常识，未实测（与报告同）。
6. **微软 / Google 真实 discovery 之外的真实端点**：只跑了 RP-4 需要的两条 URL。
7. **行号的新鲜度**：工作树在我复核期间**有未提交改动**（`internal/oidchttp/oidchttp.go`、
   `internal/httpapi/server.go`、`internal/federation/unbind.go`、`CHANGELOG.md` 等，按 BRIEF §2
   这些改动在审计开始前就存在，不是我的）。我引用的 `file:line` 全部取自**我读的那一刻**的文件内容，
   若别人随后改动这些文件，行号可能漂移（符号名与函数名不会）。我未执行任何 `git checkout/restore/stash`。

## 5. 新发现（复核时顺手看到的）

### V-1 `KIT-1` 的「真调用方带凭据」被误读成「服务端不看」——参考源认证、套件不检查，二者叠加才是真问题

`_fragment_kit.md:60-61` 用 `internal/federation/revocation.go:78-79` 论证「线上路径会带凭据，
但这个服务端不看」。前半句对，后半句漏了一层：**这个「服务端」是钩子，而唯一在仓的钩子实现
（`referencesource/cascade.go:48`）是看的**。真正该修的是两处，而不是一处：
① kit 在调钩子前 `AuthenticateClient`；② `upstreamkit/conformance`（`conformance.go:287-297`）
把「未知 client_id + 无 Basic 打到已宣告的 cascade 端点仍 200」判为 PASS。只做 ① 会让
「第三方源忘了认证」这件事继续对套件不可见（KIT-7 已覆盖 ② 的一半，但它没把 cascade 这一条
与 KIT-1 的严重度绑定起来）。

### V-2 被复核报告的内部不一致：RP-2/RP-3 在报告里是「中」，而派工单把它们当「高」处理

`protocol.md` 与 `_fragment_rp.md` 都写 RP-2/RP-3 = **中**；派给我的任务描述里写的是 **[高]**。
若验收清单是按派工单的严重度建的，会出现「报告说中、清单说高」的错位。建议主代理以报告为准并回填。

### V-3 探针质量：两处断言比我自己的写法更弱，值得在清理时加固

- `internal/zzprobe/protocol/discovery_test.go:166-168` 用**子串**判断 JWKS 是否含私钥
  （`strings.Contains(body, "\"d\"")` 等）。这既会漏（`"oth"`、`"x5c"`、非 RSA 的 `"k"` 都不查），
  也会在下一次加字段时误报。我在自己的包里改成了解析后逐字段判 + kid 一致性 + 签名头 kid 对齐。
- `TestProbeFormPostAuthorizationResponseHasNoIss` 用 `strings.Contains(page, "iss")` 决定是否
  skip（`:55`）。今天恰好不误命中，但任何一个含 `iss` 子串的文案（例如 `missing`）都会让这条
  探针**静默 skip**（BRIEF §7：失败静默 ⇒ 升格）。建议改成解析 `<input name="iss">`。
  （这两条是**探针**问题，不是产品问题，故不列 V 之外。）

### V-4 一个我试过但没能推翻的方向（记录为守卫）

我试图证明 `requestParams` 的错误吞掉（PROTO-1 根因）还能在**别的**入口造出提权：
`/oauth/token` 上唯一的第一遍调用检查就是 `duplicatedParam`（`oidchttp.go:440`），
其余检查（PKCE 语法 `:448`、双身份 `:462`、`validateAuthorize` `:476`、设备 scope `:482`）
都发生在第二遍之后、看到真实参数。也就是说**重复参数检查是唯一被这一个 body 关掉的闸门**——
与报告的结论一致。我尝试让重复 `refresh_token`/`client_id`/`redirect_uri` 通过该不对称造成
「校验看第一个、使用看最后一个」，没有找到能换来新权限的构造（令牌交换侧的客户端身份来自
HTTP Basic，库不读表单 `client_id`；code/refresh 的归属由库自己绑定）。**未能推翻。**

## 6. 我认为被**低估**的

1. **PROTO-2 与 PROTO-3 的组合**：报告把 PROTO-2 记为阻断上线（对），把 PROTO-3 记为「今天无泄漏，
   修完 PROTO-2 即变活的身份 bearer」（也对），但两条**分开**写会让读者漏掉那个递进关系：
   当前唯一阻止「任意持有 id_token 的第三方在 `/oauth/userinfo` 换到 `usr_`」的东西，
   就是 PROTO-2 这个 bug 本身。修 PROTO-2 的那次提交必须**同时**落地 PROTO-3/3b 的修法，
   否则会当场制造一个「未认证方可用 id_token 当 bearer 换身份」的洞。
   报告在 PROTO-2 的修法里写了「修完立刻激活 PROTO-3/3b」——建议把这句话提到**两条的标题级**。
2. **KIT-3 的静默性**：`Introspect` 不回看 client status 是**静默**的（端点全部报 `invalid_client`，
   唯独数据面照旧，运维会以为已经掐掉）。按 BRIEF §7「失败静默 ⇒ 升格」的规则，
   我把它降到中（因为仓内 admin 抵消了后果），但**只要有人用 `oauth.NewService` + 自己的 admin，
   它就是高**——所以修法里「要么改 Introspect、要么在 `SetStatus` 文档里写清」必须二选一，不能留白。
3. **PROTO-11 的「提示」与 CM-4 的「高」必须合成一条中**（§2.4），否则两份报告对同一现象的
   定级会被评审当成「两份都不准」。

## 7. 判断（不是 finding）

1. RP-1 的修法建议（在 `oidcClaims` 加 `AZP` 并实现 §3.1.3.7 的 `aud` 长度规则）**应该做**，
   即使它在本装配下只是纵深防御：它是 OIDC 的 MUST，成本 5 行，而且 `idp` 是公开库的一部分
   （第三方把 `idp.Client.Identity` 用在别的投递形态上时，这条检查就是唯一的防线）。
   建议在报告里把「高」改成「低（纵深防御）」并把理由写成「本装配下不可达，但库的公开 API 不保证这点」。
2. KIT-1 的修法建议（kit 内认证）**应该做**，且应当顺手把 `Hooks.CascadeRevoke` 的注释改成
   「钩子必须自行认证；kit 不代认证」——现在的注释与 `CascadeRevocationRequest` 的字段形状
   会让人以为已经被校验过（片段自己写的「这两个字段的形状在骗人」是对的，只是它由此推出的
   严重度超出了它验证过的范围）。
3. RP-4 不应以「文档里其实有」被驳回，但也不该以「没有任何文档提过」立论；
   正确的立论是「**内置默认值 + 静默通用码** ⇒ 发布产物用最自然的配置必然失败」。
