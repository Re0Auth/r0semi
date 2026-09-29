# Re0Auth 第六轮审计 · 区域 01：OAuth2/OIDC 协议实现与令牌生命周期

审计对象：`HEAD = bf81b2a`（工作区另有未跟踪的 `internal/zzprobe/audit6/`，为其他区域代理的探针）。
环境：Windows 11、无 Docker、无本地 Postgres、go1.27.1。库源码：`C:\Users\r-0semi\go\pkg\mod\github.com\zitadel\oidc\v3@v3.51.3`。
探针：`internal/oidchttp/zz_audit_protocol_test.go`、`internal/oidchttp/zz_audit_introspect_seam_test.go`（新建，均带 `//go:build protocolaudit`，未改动任何被跟踪文件）。

---

## 一句话结论

**本区域第五轮的全部协议面阻断项（B-1、B-2、PROTO-1、PROTO-4、PROTO-5/6/7/9/10）在本 HEAD 上逐条实测已修好且守得住；本轮只找到 1 条新的、可复现的守卫绕过（内省公开客户端守卫被 percent-encoding 绕过，数据面暴露极小，P3）和 1 条第五轮记为 P3 至今未修的进程级缺陷（动态 issuer 下 discovery 缓存无 Host 维度，P3），其余 20 条攻击全部被挡住写进「已证伪」。**

### 按严重度的发现计数

| 严重度 | 新增 | 第五轮遗留未修 | 合计 |
|---|---|---|---|
| P0 阻断 | 0 | 0 | 0 |
| P1 高 | 0 | 0 | 0 |
| P2 中 | 0 | 0 | 0 |
| P3 低/提示 | 2 | 1 | 3 |
| 已证伪/排除 | — | — | 21 条 |

- 新增：`P-01`（内省守卫 percent-encoding 绕过）、`P-02`（设备流批准不查 `ExplicitConsent`，与同意面不对称）
- 第五轮遗留：`P-03`（discovery 缓存无 Host 维度，即 PROTO-8）
- 探针总览（`go test -tags protocolaudit -run TestZZAudit_ ./internal/oidchttp/`）：**红 2 / 绿 24 / 跳过 1**。

---

## 发现

### [P3] P-01 内省端点「公开客户端必须拒绝」的守卫可被 percent-encoding 一行绕过

- **不变量**：token/scope 签发 · 凭据封存 · fail-closed
- **状态**：**CONFIRMED**（红探针 `TestZZAudit_IntrospectionPublicClientGuardIsBypassedByPercentEncoding`）
- **严重度判定**：绕过成功，但**拿不到别人的令牌**——`filterIntrospection` 的归属比较用的是**已解码**的 caller id（`oidchttp.go:1230`），所以攻击者最终仍只看到自己的令牌。它绕过的是「公开客户端一律拒绝」这条明确写下、且是 PROTO-4 唯一修法的守卫（价值在下一条的部署形态下放大）。故记 P3 而非 P1。

**证据（file:line）**

- 守卫本体：`internal/oidchttp/oidchttp.go:1107-1122`
  ```go
  func (h *Handler) refuseIntrospectionByANonConfidentialClient(w http.ResponseWriter, r *http.Request, form url.Values) bool {
      id, _, _ := r.BasicAuth()               // ← 原始字节，没有 url.QueryUnescape
      if strings.TrimSpace(id) == "" {
          id = strings.TrimSpace(form.Get("client_id"))
      }
      if id == "" {
          return false                        // ←「无法证明 ⇒ 交给库」，这是绕过点
      }
      c, err := h.clients.Get(r.Context(), id) // ← 用原始字节查注册表
      if err != nil || c.Type == oauth.ClientConfidential {
          return false                        // ← 查不到 ⇒ 放行
      }
      writeOAuthJSONError(...)
      return true
  }
  ```
- 库对同一凭证的读法（先解码再查表）：`pkg/op/client.go:118-126`
  ```go
  clientID, err = url.QueryUnescape(clientID)
  ...
  if err := storage.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil { ... }
  ```
- 公开客户端的 `AuthorizeClientIDSecret` 恒返回 nil（"已认证"）：`internal/store/memory/oidc.go:739-742`
  ```go
  if c.Type == oauth.ClientConfidential && !c.Authenticate(clientSecret) { ... }
  return nil
  ```

**机制**

`Authorization: Basic base64("zz-pub-%37A…:")` 这类**带 percent 转义**的公开客户端 id：

1. 守卫用 `r.BasicAuth()` 取到**未解码**的 `zz-pub-%37A…`，`clients.Get` 查不到 ⇒ `err != nil` ⇒ 走 `return false`（注释里那支「无法证明它是非机密的，交给库决定」）；
2. 库 `ClientBasicAuth` 先 `url.QueryUnescape` 得到真实的 `zz-pub-z…`，查得到、且是公开客户端 ⇒ `AuthorizeClientIDSecret` 返回 nil ⇒ `authenticated = true`；
3. 于是**一个没有任何秘密的公开客户端**拿到了内省调用权。用普通（未转义）拼写时，同一条请求会被 401 `invalid_client` 拒绝。

**复现**

```
go test -count=1 -run TestZZAudit_IntrospectionPublicClientGuardIsBypassedByPercentEncoding ./internal/oidchttp/ -v
```
```
zz_audit_protocol_test.go:400: plain public id      -> 401 {"error":"invalid_client","error_description":"introspection requires a confidential client"}
zz_audit_protocol_test.go:412: percent-encoded id   -> 200 {"active":false}
--- FAIL: TestZZAudit_IntrospectionPublicClientGuardIsBypassedByPercentEncoding
```

放大形态（同一根因，探针 `TestZZAudit_IntrospectionPublicAllowlistEntryIsBypassedByPercentEncoding`，实测**绿**，因为它检查的是「读到了别人的令牌没有」，而这次没读到）：`Config.IntrospectionClients` 的注释（`oidchttp.go:88-95`）明确承诺「名单里的每一项必须是机密客户端，否则该端点就是匿名跨客户端令牌读取器」——而这层保护**只由这条守卫提供**。一个被误配进名单的公开客户端，用 percent-encoded 拼写即可完整恢复第五轮 PROTO-4 的跨客户端读取能力。本次探针里实测只拿到自己令牌（`active=false`），因为该公开客户端名下没有对应的令牌；若它名下有一个 token，返回就是 `active=true`，因此「误配 + 转义」的组合下危害等级与 PROTO-4 相同。

**影响**

- 今天（未误配）：一名无凭据的调用者能以一个公开客户端身份调用内省端点，读到自己的令牌状态；数据面无损失，但一条明文承诺的安全控制事实上失效。
- 误配（名单含公开客户端，或名单项的 id 含 `-`、`.` 之外的常见字符）：等价于 PROTO-4 复活，任意 token 的 `active/scope/sub/client_id/exp` 可被无凭据读取。
- 任何后续把「读调用方身份」写进协议面前置检查的代码都会继承同一个不对称：项目读原始字节、库读解码后的值。

**修法**

在守卫里用与库相同的读法解析调用方身份，二者只能有一处解码：

```go
id, _, _ := r.BasicAuth()
if decoded, err := url.QueryUnescape(id); err == nil {
    id = decoded
}
```

并且更稳妥的是删掉 `return false` 那一支的宽容语义：内省端点的授权就是「调用方是不是机密客户端」，用 `form.Get("client_id")` 得到的 id 若查不到、或不是机密客户端，应直接 401，而不是交给库；`client_assertion` 路径要在进守卫前显式拒绝（当前它也被这一支放行，见「已证伪/未成立」中的分析）。

---

### [P3] P-02 设备流批准不检查 `ExplicitConsent`，与同意面不对称（机制在，闸门缺）

- **不变量**：token/scope 签发 · fail-closed
- **状态**：**READ**（读码级确认；探针无法变红，因为默认目录里没有任何 `ExplicitConsent` scope，见下）

**证据（file:line）**

- 同意面**有**这道闸门：`internal/oidchttp/oidchttp.go:1584-1594`
  ```go
  ticked := make(map[oauth.Scope]struct{}, len(explicit))
  for _, sc := range explicit { ticked[sc] = struct{}{} }
  for _, d := range descriptors {
      if d.ExplicitConsent {
          if _, ok := ticked[d.Scope]; !ok {
              return "", &oauth.Error{Code: "access_denied", ...}
          }
      }
  }
  ```
- 设备面**没有**：`internal/httpapi/device_routes.go:114-115` 把 `body.Explicit` 原样传给 engine；`internal/store/memory/oidc.go:1086-1106` `ApproveDevice` 只用它做闸门以外的窄化检查，全程不碰 `registry`：
  ```go
  func (s *OIDCStore) ApproveDevice(ctx context.Context, userCode, subject string, scopes []string) error {
      s.mu.Lock(); defer s.mu.Unlock()
      h, ok := s.userCodes[normalizeUserCode(userCode)]; ...
      if d.done || d.denied || !s.now().Before(d.expiresAt) { return oauth.ErrDeviceNotFound }
      d.done = true; d.subject = subject; d.authTime = s.now()
      if scopes != nil { d.scopes = append([]string(nil), scopes...) }
      s.devices[h] = d
      s.record(ctx, "oidc.device.approve", subject, d.clientID, audit.OutcomeOK)
      return nil
  }
  ```
  `oidchttp.Handler` 里也没有对应的 `ApproveDevice` 包装（`internal/oidchttp/oidchttp.go` 只实现 `ApproveAuthorization`/`DenyAuthorization`）。
- 设备侧确实**有**的建设是 `ExplicitConsent` 之外的两道：批准会经 `DescribeDeviceAuthorization → describeScopes → Registry.Resolve` 校验 `AllowedClients`（`internal/store/memory/oidc.go:420`、`oauth/scope.go:217-235`），并在创建时经 `validateDeviceAuthorization` 校验客户端注册（`oidchttp.go:1091`）。

**机制**

`Descriptor.ExplicitConsent` 的语义是「必须逐项勾选，绝不能被打包进 select-all」（`oauth/scope.go:103-105`）。同意面通过 `ApproveAuthorization` 内联实现它；设备面把「批准」的语义交给 `ApproveDevice`，而那里只做了「不得放宽」的检查（`internal/store/memory/oidc.go:1100-1102`）与 `Resolve`（管 `AllowedClients`）。因此一旦目录里出现第一个 `ExplicitConsent` scope，**同一份授权经设备流可以在没有任何 explicit 勾选的情况下被批准**，而经同意面会被 `access_denied` 拒绝。

**影响**

- 今天为零：`oauth.DefaultDescriptors()`（`oauth/scope.go:132-155`）不含 `ExplicitConsent`，`oauth/scope_test.go:31` 还断言「内置目录里不得出现 ExplicitConsent scope」，所以本机的探针无法变红。
- 这是一个**未来性缺陷**：机制已经写在类型里、注释里、同意面里、设备 store 里（`oauth/device.go:391` `checkExplicit` 在**被弃用的**手搓引擎上实现了它，OP 侧的 `memory.OIDCStore.ApproveDevice` 没有），四处分歧。第一个给目录加上 critical scope 的提交会静默地在设备流上开后门，而现有测试（只测同意面）不会红。

**修法**

在 `memory.OIDCStore.ApproveDevice`（以及 postgres 对应实现）里 `Resolve` 之后调用现有的 `oidcstore.RequireExplicitConsent(descriptors, explicit)`，并把 `explicit` 从 `internal/httpapi` 的 `DeviceDecision` 一路传下去——`oidchttp.Handler.ApproveAuthorization` 已经是这么做的，设备侧照抄即可。另加一条断言：任何 `ExplicitConsent` descriptor 必须在**两个**批准入口各有一条红过的测试。

---

### [P3] P-03 discovery 缓存无 Host 维度，动态 issuer 下一次伪造 Host 永久固定两份文档（第五轮 PROTO-8，未修）

- **不变量**：两平面分离 · fail-closed
- **状态**：**CONFIRMED**（红探针 `TestZZAudit_DiscoveryCacheIsHostBlind`）

**证据（file:line）**

- 缓存按路径键、无 TTL、无 Host 维度：`internal/oidchttp/oidchttp.go:346-365`（`discoveryCache.get/put` 用 `path` 做键）、`:293-317`（`serveDiscovery` 读/写缓存）、`:253-267`（`RFC8414Path` 被重写成 `OIDCDiscoveryPath`，所以**一次投毒同时覆盖两份文档**）
- 动态 issuer 的来源：`:192-195`（`cfg.Issuer == "" ⇒ op.IssuerFromHost("")`）、`:1264-1272`（`issuerFor` 用 `provider.IssuerFromRequest(r)`）
- 生产是否可达：`cmd/re0auth/config.go:471` 强制 `server.issuer` 必填，所以生产是静态 issuer，本机只能以 `oidchttp.Config{Issuer: ""}` 形态复现
- 响应头：`:304` `Cache-Control: public, max-age=300`（把错误的 issuer 也交给中间缓存）

**复现**

```
go test -count=1 -run TestZZAudit_DiscoveryCacheIsHostBlind ./internal/oidchttp/ -v
```
```
zz_audit_protocol_test.go:857: issuer for attacker.example = http://attacker.example
zz_audit_protocol_test.go:858: issuer for real.example     = http://attacker.example
--- FAIL: TestZZAudit_DiscoveryCacheIsHostBlind
```

**机制**

第一次请求带 `Host: attacker.example` 时，`IssuerFromRequest` 渲染出 `issuer=http://attacker.example`，该 200 文档被按 `OIDCDiscoveryPath` 缓存**一生**。此后任何 Host（含真实域名）都拿到这份 `issuer`、`authorization_endpoint`、`jwks_uri` 全指向攻击者主机的文档，直到进程重启。

**影响**

限动态 issuer 形态。同一形态还会污染授权响应的 `iss`（`withIssuer`，`oidchttp.go:621-625`）与设备流的 `verification_uri`（库 `pkg/op/device.go:113-129` 用 `IssuerFromContext`），因此这不是「文档写错」而是「元数据与 `iss` 一起被固定成攻击者的值」——对按 discovery 自举的 RP 是 mix-up 前提。生产配置拒绝空 issuer，故记为 P3（误导性默认 + 未来形态）。

**修法**

缓存键改为 `IssuerFromRequest(r) + path`，或在 `Config.Issuer == ""` 时直接禁用缓存（`serveDiscovery` 里一个 `if h.issuer == ""` 即可），并保持 `Cache-Control` 与「文档是否可缓存」一致。

---

## 已证伪 / 排除的嫌疑

以下每一条都是**本轮亲手打过并守住**的，附探针名（绿），供复核代理直接复用而不是重打。

### 第五轮阻断项的复核（本区域全部实测已修）

| 编号 | 断言 | 本轮结论 | 探针 |
|---|---|---|---|
| B-1 | `id_token` 缺必需 `sub`（两个 store 的 `SetUserinfoFromScopes` 是空实现） | **已修，实测**。`id_token.sub == usr_zz`；`internal/store/memory/oidc.go:755-758`、`internal/store/postgres/oidc.go:630` 均 `userinfo.Subject = userID` | `TestZZAudit_RegressionIdTokenCarriesSubject` |
| B-2 | `id_token` 可在 `/oauth/userinfo` 当 access token 用 | **已修，实测**。`isCompactJWS` 前置拒绝（`oidchttp.go:590-595`）+ `SetUserinfoFromToken` 要求行活着（`memory/oidc.go:770-790`）。id_token → **401**；`/v1` 用的 `Handler.Introspect`（`oidchttp.go:1484-1515`）对 id_token 也返回 `Active:false`（JWS 过不了 AES-GCM 解密） | `TestZZAudit_RegressionIdTokenIsNotABearerAtUserinfo`、`TestZZAudit_IntrospectRejectsAnIDToken` |
| PROTO-1 | 不可解析 body 吞掉 `ParseForm` 错误 ⇒ 设备流 scope 闸门被绕过 | **已修，实测**。`requestParams` 返回 `(nil,false)` ⇒ 400（`oidchttp.go:855-860`、`505-510`）；闸门读**全部** scope 值（`requestedScopes`，`:871-877`）。`x=%zz` 与 `client_id=narrow&scope=phigros.score.read` 两种拼写均拒绝了 | `TestZZAudit_RegressionDeviceScopeGateHolds` |
| PROTO-4 | 内省白名单含公开客户端 ⇒ 无凭据可读任意 token | **主体已修**（新发现 P-01 是它的守卫被转义绕过，见上） | `TestZZAudit_RegressionIntrospectionRefusesPublicCallers`、`TestZZAudit_IntrospectionPublicAllowlistEntryIsBypassedByPercentEncoding`(绿) |
| PROTO-5 | discovery 为内省广告 `client_secret_post` 而该端点只认 Basic | **已修，实测**。文档现为 `introspection_endpoint_auth_methods_supported:["client_secret_basic"]`，与实际一致 | `TestZZAudit_DiscoveryDoesNotLie` |
| PROTO-6 | `prompt=none` 未实现，静默认证被 302 到登录页 | **已修，实测**。无会话时走注册 redirect 带 `error=login_required`（`validateAuthorize`，`oidchttp.go:954-980`） | `TestZZAudit_ConfidentialClientNeedsPKCE`（同一路径）、包内 `TestPromptNoneRequiresASession` |
| PROTO-7 | `response_mode=form_post` 的响应不带 `iss` 而 discovery 广告支持 | **已修，实测**。`response_mode != "query"` 一律经 redirect 拒绝且响应本身带 `iss`（`oidchttp.go:938-947`）；discovery 广告 `response_modes_supported:["query"]` 与之一致 | `TestZZAudit_DiscoveryDoesNotLie`（fragment 模式实测 302 + `iss`） |
| PROTO-9 | 令牌端点只挡 GET 不挡「POST+查询串」 | **已修，实测**。`endpointMethods` 单值 POST 时任何非空 `RawQuery` 直接 400（`oidchttp.go:489-493`）。本区域实测：`/oauth/introspect`、`/oauth/device_authorization`、`/oauth/token` 的 query 形态全部 400 | `TestZZAudit_SplitQueryAndBodyCannotSmuggleTwoIdentities`、`TestZZAudit_DeviceScopeSplitAcrossQueryAndBody` |
| PROTO-10 | userinfo 对没有 `openid` 的令牌也返回 `sub` | **不是缺陷**：RFC 7662/OIDC 都要求活跃令牌的 `sub` 可见；`SetUserinfoFromToken` 只发布 token 行里**存着的** subject，且要求 caller 断言与之相等（`memory/oidc.go:782-788`），没有任何 scope 面信息可借 | `TestZZAudit_UserinfoRequiresALiveAccessToken` |
| PROTO-11 | 匿名 `/oauth/authorize` 每次分配 pending 请求 | **已修，实测**（30 min TTL + sweep，`memory/oidc.go:391`、`:945-980`），且匿名入口本来就无法完成同意 | — |

### 本轮新打的攻击，全部未成立

1. **redirect_uri 匹配（编码 / 大小写 / `..` / 尾部斜杠 / fragment / 端口 / localhost 别名）** —— `RegisteredRedirect` 是 `r == uri` 严格字节比较（`oauth/client.go:170-177`），`validateAuthorize` 用它（`oidchttp.go:927`）；库侧 token 端点再比一次 `tokenReq.RedirectURI != authReq.GetRedirectURI()`（`pkg/op/token_code.go:66`），且库里存的正是注册表里的字符串。实测 6 种变体全 400，回环端口 `53123 → 53999`、`127.0.0.1 → localhost` 全 400。**注意**：库的 native 分支其实会忽略回环端口（`pkg/op/auth_request.go:387-392` `equalURI` 只比 Path+RawQuery），是本包装的严格匹配在兜底，这一点值得保留成回归测试。
   探针：`TestZZAudit_LoopbackPortIsNotIgnored`、`TestZZAudit_CodeExchangeRequiresExactRedirectAndVerifier`（9 种 redirect/verifier 组合，只放行精确组合）
2. **PKCE 降级** —— `validateAuthorize` 要求 `challenge != "" && method == "S256"`（`oidchttp.go:986-1014`）+ `validPKCEValue` 43–128 unreserved（`:1238-1252`）。`plain`/无 method/`S512`/小写 `s256`/42 字符/129 字符/带空格 7 种全拒（302 + `error=invalid_request`）。
   探针：`TestZZAudit_PKCECannotBeDowngraded`
3. **机密客户端无 PKCE** —— 包装强制（OAuth 2.1），库自己只对 `AuthMethodNone` 要（`pkg/op/token_code.go:108-113`），包装的这条更严并生效。
   探针：`TestZZAudit_ConfidentialClientNeedsPKCE`
4. **code 与客户端的绑定 / 单一使用（含并发）** —— 库先比 `client.GetID() != authReq.GetClientID()`（`pkg/op/token_code.go:60-62`），store 的 `AuthRequestByCode` 把「查到」本身当领取（`memory/oidc.go:418-433`）。实测：外来客户端 400 `invalid_grant`；4 路并发兑换恰好 1 个 200、3 个 `invalid code`。
   探针：`TestZZAudit_CodeIsBoundToItsClient`、`TestZZAudit_CodeSingleUseUnderConcurrency`
5. **refresh 提权 / 收窄** —— `ValidateRefreshTokenScopes` 要求请求 scope 是**已批准集合**的子集（`pkg/op/token_refresh.go:84-95`），并且写入 store 的 scope 已剔除 `offline_access`（`memory/oidc.go:543`，`oidcstore.WithoutOfflineAccess`）。实测 6 种拼写（未知 scope、超集、大小写、前后空白、tab 分隔）全 400 `invalid_scope`。
   探针：`TestZZAudit_RefreshCannotWidenScope`
6. **query/body 拆分的重复参数** —— Go 的 `ParseForm` 把 query 与 body 合并进 `r.Form`，所以拆分在 `r.Form` 里就是两个值，`duplicatedParam`（`oidchttp.go:1302-1309`）先一步拒绝；GET/POST 双身份与双 scope 实测均 400。
   探针：`TestZZAudit_SplitQueryAndBodyCannotSmuggleTwoIdentities`、`TestZZAudit_DeviceScopeSplitAcrossQueryAndBody`
7. **userinfo 接受的令牌类型与存活校验** —— 活跃 access token 200；撤销后 401；未知 bearer 401；refresh token 401；JWS 形状 401（`oidchttp.go:590-595`）。全部带 `WWW-Authenticate: Bearer error="invalid_token"` 与 `Cache-Control: no-store`。
   探针：`TestZZAudit_UserinfoRequiresALiveAccessToken`
8. **未实现的 grant 不会落到别的 handler** —— `client_credentials` / `token-exchange` / `jwt-bearer` / `password` / `implicit` / 空 六种全 400（`unsupported_grant_type` 或 `invalid_request`）。
   探针：`TestZZAudit_UnimplementedGrantsAreRefused`
9. **id_token 声明正确性** —— 实测 `iss` = issuer、`aud` = [client]、单 audience 时 `azp` = client、`nonce` 原样回显、`at_hash` = base64url(SHA-256(access)[:16])、`c_hash` = base64url(SHA-256(code)[:16])、`sub`/`exp`/`iat`/`auth_time` 齐备（OIDC Core §3.1.3.6 逐项核对）。刷新得到的 id_token 丢失 `nonce` 是**正确的**（`CreateIDToken` 只对 `AuthRequest` 注入 nonce，`pkg/op/token.go:207-210`），且不出现「旧 nonce 冒充新认证」。
   探针：`TestZZAudit_IDTokenClaimCorrectness`、`TestZZAudit_RefreshedIDTokenClaims`
10. **`id_token` 只在有 `openid` 时下发** —— `sanitizeTokenResponse`（`oidchttp.go:1358-1386`）对 code 与 device 两条 grant 实测都剥掉了 id_token（`scope=account.id` 时响应里没有 `id_token` 字段）。
    探针：`TestZZAudit_IDTokenOnlyWithOpenID`
11. **设备流的 scope 闸门与轮询节流** —— 未注册 scope 一律 400 `invalid_scope`；`slow_down` 由 store 的 `lastPoll` 锚点实现（`memory/oidc.go:884-889`），已批准记录**单次消费**（第二次 poll 400）。
    探针：`TestZZAudit_DeviceAuthorizationRequiresRegisteredScope`、`TestZZAudit_DeviceCodeExpiryIsEnforced`
12. **RFC 8252 private-use scheme 的 redirect** —— 我原本怀疑库的 native 分支（`pkg/op/auth_request.go:383` 的 `if !isLoopback { refuse }`）会拒掉 `com.example.app:/cb`，**实测不成立**：注册与授权都成功（302 → 登录页）。`isCustomSchema` 分支先命中。写入「已证伪」以免后人重复。
    探针：`TestZZAudit_PrivateUseSchemeRedirectIsRefused`（名字保留，现在是正向守卫）
13. **`duplicatedParam` 的语义** —— 它遍历 `url.Values` 的每个 key，任何多值即拒；`authorize` 允许 query 形态但也一并检查，所以 authorize 上不存在「gate 看第一个、库取最后一个」的口子。
14. **userinfo 的 JWS 兜底无法被绕开** —— 库的 `getTokenIDAndSubject` 在解密失败时回退到 `VerifyAccessToken`（JWS），而 `oidc.DecryptToken` 是 TODO 直接返回入参（`pkg/oidc/verifier.go:110-112`）。包装的 `isCompactJWS`（`strings.Count(s,".")==2`）与库的 `ParseToken`（必须 3 段，`pkg/oidc/verifier.go:114-125`）判据完全重合；本 OP 的 access token 是 compact JWE（恒 4 个点），与 2 点形状不可能碰撞；`bearerOf` 与库的 `getAccessToken` 取值顺序一致（header → `access_token` 参数），不存在「检查一个、使用另一个」；`access_token` 只能出现在 body，因为 POST+query 被 `oidchttp.go:489-493` 拒掉。
15. **撤销端点（RFC 7009）不接受匿名调用** —— `ParseTokenRevocationRequest` 在无 Basic 且无 `client_id` 时 401；有 `client_id` 但非 `AuthMethodNone` 且无 secret 时 401（`pkg/op/token_revocation.go:119-138`）。
16. **device grant 的客户端归属** —— `CheckDeviceAuthorizationState` 把调用方 clientID 传给 store（`pkg/op/device.go:310`），`memory.GetDeviceAuthorizatonState` 校验 `d.clientID != clientID`（`memory/oidc.go:877`）。跨客户端取 device_code 不成立。

### 明确的残余盲区（本环境到不了）

- **Postgres 后端全部运行时语义**：无本地 Postgres，`internal/store/postgres/oidc.go` 的 `SetUserinfoFromScopes`/`SetUserinfoFromToken`/`ApproveDevice` 只做了读码级核对（B-1 的修法在那里确实存在，见 `:620-674`），未实跑。
- **真实浏览器的 mix-up / iframe 行为**：`prompt=none` 与 `iss` 的 RP 侧校验无法在本机端到端验证（Playwright 浏览器未安装）。
- **`client_assertion`（private_key_jwt）路径**：项目没有 `GetKeyByIDAndClientID` 的可用实现（`memory/oidc.go:836-838` 直接返回 "JWT profile grant is not supported"），所以这条路径无法驱动到「认证成功」，只能读码判断（见 P-01 修法里提到的那一支同样被守卫放行，但库随后会因验签失败而 401）。
- **`AllowedClients` 在 authorize 入口不被咨询**（`internal/oidcstore/oidcstore.go:182-191` 的 `IsScopeAllowed` 只查目录 + 客户端注册）：同意面会经 `ApproveAuthorization → Registry.Resolve` 补上（`oidchttp.go:1580`），设备面会在 `describeScopes` 补上（`memory/oidc.go:420`），因此只是「入口放行进 auth request、批准时才失败」的不对称，**不构成提权**；且 `oauth/scope.go:109` 的 `AllowedClients` 在默认目录里没有任何使用者（`oauth/scope.go:132-155`），判为已证伪而非发现。

---

## 附：探针清单与运行方式

探针带 `//go:build protocolaudit`，所以**默认套件保持全绿**（已实测 `go test -count=1 ./internal/oidchttp/` → ok），两条红探针只在显式带标签时运行：

```
go test -tags protocolaudit -count=1 -run TestZZAudit_ ./internal/oidchttp/ -v
```

| 探针 | 结果 | 归属 |
|---|---|---|
| `TestZZAudit_RegressionIdTokenCarriesSubject` | 绿 | B-1 复核 |
| `TestZZAudit_RegressionIdTokenIsNotABearerAtUserinfo` | 绿 | B-2 复核 |
| `TestZZAudit_IntrospectRejectsAnIDToken` | 绿 | B-2 的 /v1 侧面 |
| `TestZZAudit_RegressionDeviceScopeGateHolds` | 绿 | PROTO-1 复核 |
| `TestZZAudit_RegressionIntrospectionRefusesPublicCallers` | 绿 | PROTO-4 复核 |
| `TestZZAudit_IntrospectionPublicClientGuardIsBypassedByPercentEncoding` | **红** | **P-01** |
| `TestZZAudit_IntrospectionPublicAllowlistEntryIsBypassedByPercentEncoding` | 绿 | P-01 的影响面 |
| `TestZZAudit_IntrospectionGuardReadsRawBasicID` | 跳过 | 该 id 无 `z`/`z` 外可编码字符；机制由上面红探针直接证明 |
| `TestZZAudit_LoopbackPortIsNotIgnored` | 绿 | redirect 匹配 |
| `TestZZAudit_SplitQueryAndBodyCannotSmuggleTwoIdentities` | 绿 | PROTO-9 / 重复参数 |
| `TestZZAudit_DeviceScopeSplitAcrossQueryAndBody` | 绿 | PROTO-9 / 重复参数 |
| `TestZZAudit_ConfidentialClientNeedsPKCE` | 绿 | PKCE |
| `TestZZAudit_PKCECannotBeDowngraded` | 绿 | PKCE |
| `TestZZAudit_CodeExchangeRequiresExactRedirectAndVerifier` | 绿 | 绑定与 PKCE |
| `TestZZAudit_CodeIsBoundToItsClient` | 绿 | code 绑定 |
| `TestZZAudit_CodeSingleUseUnderConcurrency` | 绿 | 并发兑换 |
| `TestZZAudit_UserinfoRequiresALiveAccessToken` | 绿 | userinfo 存活 |
| `TestZZAudit_UnimplementedGrantsAreRefused` | 绿 | grant 派发 |
| `TestZZAudit_DiscoveryDoesNotLie` | 绿 | RFC 8414/9207 一致性 |
| `TestZZAudit_DiscoveryCacheIsHostBlind` | **红** | **P-03** |
| `TestZZAudit_DeviceCodeExpiryIsEnforced` | 绿 | RFC 8628 |
| `TestZZAudit_DeviceAuthorizationRequiresRegisteredScope` | 绿 | 设备 scope 闸门 |
| `TestZZAudit_PrivateUseSchemeRedirectIsRefused` | 绿 | redirect 匹配 |
| `TestZZAudit_IDTokenClaimCorrectness` | 绿 | OIDC Core §3.1.3.6 |
| `TestZZAudit_RefreshedIDTokenClaims` | 绿 | OIDC Core §12.2 |
| `TestZZAudit_IDTokenOnlyWithOpenID` | 绿 | O-2 |
| `TestZZAudit_RefreshCannotWidenScope` | 绿 | OAuth 2.1 §6 |

- 未改动任何被跟踪文件；探针新增在 `internal/oidchttp/`（与包内既有测试同一 package，复用已有的 `noRedirect` 与 `newFixture` 约定而不复制它们）。
- 报告写入 `C:\git\r0semi\_audit\protocol.md`。
