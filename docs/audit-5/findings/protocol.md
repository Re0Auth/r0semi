# 协议平面（OIDC / OAuth 正确性与滥用抗性）审计报告

> 审计对象：`.`（Re0Auth）。区域：**协议平面** —— OIDC / OAuth 正确性与滥用抗性。
> 本文件由协议平面审计子代理撰写。**只新建文件，未修改任何已跟踪文件**。
>
> **三块工作**：① 本作者：`internal/oidchttp` + `internal/oidcstore` + 两个 OP store + `pkg/op` 接缝；
> ② 平行子代理 A：`idp/`（RP 侧）+ `internal/authorization`（结论 `RP-*`）；
> ③ 平行子代理 B：`upstreamkit/` + `upstreamkit/conformance/` + `oauth/` 公开引擎（结论 `KIT-*`）。
> 两位子代理的探针包我都**独立重跑过**（RP 12 条 FAIL、KIT 13 条 FAIL，与各自发现条数对应），
> 并抽检了最吃重的几处代码；其完整原文分别在 `_fragment_rp.md`、`_fragment_kit.md`。

## 范围与方法

### 读了什么（端到端）

| 文件 | 说明 |
|---|---|
| `internal/oidchttp/oidchttp.go`（1335 行） | 薄封装：路由、方法表、重复参数、PKCE 语法、scope 门槛、内省过滤、错误归一化、discovery 裁剪、`Introspect`/`ApproveAuthorization`/`DenyAuthorization` |
| `internal/oidchttp/oidchttp_test.go`、`adversary_test.go`、`filter_introspection_test.go`、`fuzz_test.go`、`bench_test.go` | 已有夹具与**已钉住的性质**（避免重复报告） |
| `internal/oidcstore/oidcstore.go` | `Signer`/`KeySet`、`ProviderClient`（`AuthMethod`/`IsScopeAllowed`）、`AuthRequest`/`RefreshRequest`、`StandardOIDCScope`、`NarrowScopes`、`WithoutOfflineAccess` |
| `internal/store/memory/oidc.go`、`internal/store/postgres/oidc.go` | 两个 `op.Storage` 实现（只在内存模式执行；PG 只读代码到行） |
| `oauth/client.go`、`oauth/scope.go`（`oauth.As` 的其余部分由另一子代理负责） | 客户端注册、`AllowsRedirect`（精确比较）、`Authenticate`（sha256 + `subtle.ConstantTimeCompare`）、`validRedirectURI` |
| `docs/oidc-decision.md`、`docs/threat-model.md`、`docs/security-audit-2.md`、`docs/security-audit-3.md`、`docs/protocol-hardening-decision.md`（ADR-0005）、`docs/api-design.md`、`docs/account-model.md` | 契约与已裁定项 |
| 库：`$(go env GOMODCACHE)/github.com/zitadel/oidc/v3@v3.51.3/pkg/op/*`、`pkg/oidc/*` | `CreateRouter`（本封装真正走的注册路径，**不是** `LegacyServer`）、`Exchange`、`CodeExchange`、`RefreshTokenExchange`、`DeviceAccessToken`、`Introspect`、`Revoke`、`Userinfo`、`auth_request.go`、`token.go`、`device.go`、`client.go`、`token_request.go`、`discovery.go`、`crypto.go`、`config.go`、`server_legacy.go`、`server_http.go`、`pkg/oidc/verifier.go`、`pkg/oidc/token.go` |

### 跑了什么

```sh
go test ./internal/zzprobe/protocol/ -v
go test -race ./internal/zzprobe/protocol/         # 可跑（本机 cgo 可用），无 DATA RACE
```

探针包：`internal/zzprobe/protocol/`（9 个文件，27 个探针函数，含 70+ 子用例）。全部通过真实入口打：
`oidchttp.New(...)` + `httptest.NewServer` + 内存 `memory.NewOIDCStore`，即生产装配的同一形状
（差异只有内存/Postgres 后端与 Host 派生的动态 issuer）。**从未跑 `go test ./...`。**

本机跑不了：**Postgres 后端**（无 DB、无 Docker）——凡涉及 PG 的结论均逐条标「读；无 DB 执行」。

### 结果概览

```sh
$ go test ./internal/zzprobe/protocol/ -v          # 摘录
--- FAIL: TestProbeUnparsableBodyDefeatsTheDeviceScopeGate
--- FAIL: TestProbeUnparsableBodyDefeatsTheDuplicateParameterRefusal
--- FAIL: TestProbeIDTokenIsMissingTheSubjectClaim
--- FAIL: TestProbeDeviceFlowIDTokenIsAlsoMissingTheSubject
--- FAIL: TestProbeUserinfoIgnoresExpiryAndRevocation
--- FAIL: TestProbeDiscoveryAdvertisesClientSecretPostForIntrospection
--- FAIL: TestProbePromptNoneIsIgnored
--- FAIL: TestProbeFormPostAuthorizationResponseHasNoIss
# 其余（含大量子用例）PASS —— 见「探过但没破的」

$ go test ./internal/zzprobe/protocol/rp/         # 平行子审计（RP-*）：12 FAIL / 28 PASS
$ go test ./internal/zzprobe/protocol/kit/        # 平行子审计（KIT-*）：13 FAIL / 32 PASS
```

**本区失败的 8 条就是 8 条发现**（探针即复现；另有 2 条「记录事实」型探针以 PASS 形式承载
PROTO-3 与 PROTO-4 的**被接受**证据）。全区域合计 **30 条条目**（PROTO 11 + RP 9 + KIT 10），
其中 RP-9 为 HYPOTHESIS、PROTO-3b 与 PROTO-3 同根（一次改动可同时封掉）；
PROTO-1 与 PROTO-2 在产物上等价于阻断上线。

---

## 发现

### PROTO-1 不可解析的 body 关掉「重复参数」检查 → 设备流 scope 闸门被绕过，未注册 scope 走到**活令牌**

- 严重度: **高**（等同第二轮 A1-1 的收益，且其修复被绕过；裁定见下）
- 类别: 安全
- 不变量/性质: ①「未被批准/未注册的 scope 不得签发」；④ ADR-0005 第 4 条「重复参数一律拒绝」；⑥「一个检查写在薄封装里，就要检查封装的每一条入口」
- 证据（已执行，FAIL）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeUnparsableBodyDefeatsTheDeviceScopeGate -v
  dupbypass_test.go:129: the unparsable-body device request answered 200
      {"device_code":"DzTXnW6GXjOr24tBKRV9RQ","user_code":"MLWF-RRHK",...}
  dupbypass_test.go:143: the stored device authorization carries scopes [phigros.score.read]
  dupbypass_test.go:146: a client registered only for account.id obtained a device authorization for "phigros.score.read"
  dupbypass_test.go:165: the minted token's scope is "phigros.score.read"
  dupbypass_test.go:182: the live token introspects as active=true client=probe-device-6eff165af03d scopes=[phigros.score.read]
  ```

  最小请求（`probe-device-*` 是**公开**客户端，只注册 `account.id`）：

  ```http
  POST /oauth/device_authorization?client_id=probe-device-...&scope=account.id&scope=phigros.score.read
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 5

  x=%zz
  ```

  根因在**两条**合起来：

  1. `internal/oidchttp/oidchttp.go:723-731`：

     ```go
     func requestParams(r *http.Request) url.Values {
         if err := r.ParseForm(); err != nil {
             return url.Values{}      // ← 第一次调用吞掉整个参数集
         }
         return r.Form
     }
     ```

     `net/http` 的 `ParseForm` 在**body 解析失败时仍会把查询串写进 `r.Form`**，并返回错误；同时它把
     `r.PostForm` 置为非 nil 的空表。因此：**`serveOAuth` 里的第一次调用**（`oidchttp.go:440` 的
     `duplicatedParam(requestParams(r))`）拿到**空表**，重复参数检查静默通过；而**第二次及以后**的调用
     （PKCE 语法 `:448`、双身份 `:462`、`validateDeviceAuthorization` `:482`）`ParseForm` 返回
     `nil`，读到查询串里的**真实参数**。一个攻击者可自选「让第一次调用失败」的 body，就关掉了第一条检查。

     这条 net/http 语义**已单独执行确证**（不依赖 Re0Auth）：

     ```
     $ go test ./internal/zzprobe/protocol/ -run TestProbeParseFormIsErrorOnceThenNil -v
     parseform_test.go:240: first ParseForm: err="invalid URL escape \"%zz\"" form=map[scope:[account.id phigros.score.read]]
                            second: err="" form=map[scope:[account.id phigros.score.read]]
     ```

     同一查询串、只换 body，OP 的答案就不同：

     ```
     $ go test ./internal/zzprobe/protocol/ -run TestProbeUnparsableBodyChangesWhatTheOPValidates -v
     parseform_test.go:287: well-formed body: 400 {"error":"invalid_request","error_description":"duplicate parameter: scope"}
     parseform_test.go:288: unparsable body:  302 "/login?authRequestID=W6gCtqNHqx9t5MtlODzML0jeoBj4CHZnxWwBT_dMFUo"
     ```

     而「第一次调用空、后续调用有值」这条不对称为何成立，也从 wrapper 自己的行为里看得到：一条
     **带重复参数**且 body 不可解析的请求，没有落在重复参数检查上，而是落在了**第二次**调用才生效的
     PKCE 语法检查上：

     ```
     $ go test ./internal/zzprobe/protocol/ -run TestProbeUnparsableBodyHidesParametersFromThePreFlights -v
     parseform_test.go:104: duplicates through an unparsable body answered 400:
         {"error":"invalid_request","error_description":"code_verifier must be 43-128 unreserved characters"}
     ```

  2. 库的 `schema` 解码器对同名多值取**最后一个**（`docs/security-audit-2.md` 已记下这一语义），而
     `internal/oidchttp/oidchttp.go:872` 的闸门只看**第一个**：

     ```go
     rawScope := form.Get("scope")                       // 第一个：account.id
     if bad := h.scopeProblem(client, strings.Fields(rawScope)); bad != "" { ... }
     ```

     库随后把 `phigros.score.read`（最后一个）**原样入库**（`pkg/op/device.go:101`
     `StoreDeviceAuthorization(ctx, clientID, deviceCode, userCode, expires, req.Scopes)`），
     正是第二轮 A1-1/A3-2 与第四轮刚刚堵掉的那条路。

- 状态: **CONFIRMED**（已执行；内存后端。PG 侧同一段封装代码，`validateDeviceAuthorization` 与
  `duplicatedParam` 与后端无关，故结论同样成立；PG 未执行）
- 影响: 一个只被注册到 `account.id` 的下游客户端，用一条 body 不可解析的请求，就为**任意目录内 scope**
  （只要受害者绑定了对应数据源）拿到设备授权，人类同意页会如实列出该 scope（受害者可见），批准后拿到
  `scope=phigros.score.read` 的**活 access token**，可直读该受害者的游戏数据。与 A1-1 的收益完全一致。
- 修法建议（最小改法，两处都要）：
  1. `requestParams` 不得吞掉解析错误：解析失败即**整个请求 400**（`invalid_request`），或至少让调用方拿到
     「不可信」标记并 fail-closed。这是根因，且 `ParseForm` 的缓存语义使「同一个函数在不同调用点看到不同参数」
     这一现象本身就该被消除。
  2. 闸门/白名单类检查必须针对**全部值**（`r.Form["scope"]` 逐个检查，或拒绝任何多值），不得用 `Get`；
     同样的写法 `validateAuthorize:810` 也在用。
- 附带后果（同一根因，独立断言）: 在 `/oauth/authorize` 上做同样的事**不**提权，但会**静默把授权收窄为空集**：

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeUnparsableBodyDefeatsTheDuplicateParameterRefusal -v
  dupbypass_test.go:72: a request with a duplicated `scope` was accepted because its body was unparsable: 302 "/login?authRequestID=5Rw..."
  dupbypass_test.go:89: the accepted auth request carries scopes [] (the pre-flight checked "account.id")
  dupbypass_test.go:97: the grant silently became EMPTY (ADR-0005 point 2 forbids an empty scope set)
  ```

  即 ADR-0005 第 2 条（「显式空集 ≠ 省略，绝不静默」）在一处可达路径上被违反。
- 复现/守卫: `internal/zzprobe/protocol/dupbypass_test.go` —
  `TestProbeUnparsableBodyDefeatsTheDeviceScopeGate`、
  `TestProbeUnparsableBodyDefeatsTheDuplicateParameterRefusal`；
  根因侧另有 `internal/zzprobe/protocol/parseform_test.go` —
  `TestProbeParseFormIsErrorOnceThenNil`、`TestProbeUnparsableBodyChangesWhatTheOPValidates`

### PROTO-2 **所有 `id_token` 都没有 `sub`**（OIDC Core 要求 REQUIRED）

- 严重度: **阻断上线**
- 类别: 合规/隐私 + 安全（下游会退化成「所有用户同一个身份」）
- 不变量/性质: OIDC Core §2「ID Token 的 `sub` 为 REQUIRED」；ADR-0001 **O-4**（`sub` = `usr_…`）；
  `docs/account-model.md:19`「向下的 `id_token` / `userinfo` **默认只携带 `sub`**」；
  `docs/api-design.md` D-6；threat-model A8/B7
- 证据（已执行，FAIL）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run 'TestProbeIDTokenIsMissingTheSubjectClaim|TestProbeDeviceFlowIDToken' -v
  idtokens_test.go:40: authorization_code: the id_token has no `sub` claim at all
      (claims: [iat client_id c_hash iss aud auth_time nonce azp at_hash exp])
  idtokens_test.go:56: refresh_token: the id_token has no `sub` claim at all
  idtokens_test.go:74: userinfo carries sub=usr_probe while the id_token does not        ← 对照：不是"到处都没有身份"
  lifecycle_test.go:515: the device flow's id_token has no `sub` either (claims: [at_hash iss aud exp iat auth_time azp client_id])
  ```

  机制（`file:line`，且**两个 store 完全相同**）：

  1. `pkg/op/token.go:216-254` `CreateIDToken`：

     ```go
     scopes := client.RestrictAdditionalIdTokenScopes()(request.GetScopes())
     ...
     } else if len(scopes) > 0 {
         userInfo := new(oidc.UserInfo)
         err := storage.SetUserinfoFromScopes(ctx, userInfo, request.GetSubject(), request.GetClientID(), scopes)
         ...
         claims.SetUserInfo(userInfo)      // ← 用 userInfo 覆盖 claims
     }
     ```
  2. `pkg/oidc/token.go:158-168` `SetUserInfo` 是**赋值**、不是合并：`t.Subject = i.Subject`。
  3. 本项目的 `SetUserinfoFromScopes` 是**有意的 no-op 桩**：
     `internal/store/memory/oidc.go:685-687` 与 `internal/store/postgres/oidc.go:576-579`
     （`// implements op.Storage (deprecated upstream; no-op)`），所以 `userInfo.Subject == ""`，
     于是 `t.Subject = ""`，而 `TokenClaims.Subject` 带 `omitempty`（`pkg/oidc/token.go:218`），
     `sub` 就从 JSON 里消失。
  4. 两个「免于被清掉」的出口都不适用：`removeUserinfoScopes` 只去掉 `profile/email/address/phone`
     （`pkg/op/token.go:269-283`，授权集里总有 `openid`/`account.id`/`offline_access`），
     而空 scope 分支在这条路上不成立。

  三条发 `id_token` 的路径（授权码 `CreateTokenResponse`、刷新、设备 `CreateDeviceTokenResponse`）全部命中。
- 状态: **CONFIRMED**（已执行）。PG 侧：`SetUserinfoFromScopes` 同样是 no-op（读代码到行），
  因此**生产（Postgres）同样没有 `sub`**；PG 未执行。
- 影响:
  1. **标准 RP 无法用这张 id_token 完成登录**：`sub` 缺失是硬性不合规，严格的 OIDC 客户端直接拒绝，
     宽松的客户端把 `sub` 当 `""`——**把本部署的全部用户映射到同一个空身份**（以 `sub` 做客键的 RP
     会把 A 的数据当 B 的显示，即下游的跨账号混淆）。OIDC 平面的**交付物就是这张断言**，所以产品意义上
     这是发布阻断项。
  2. 与 `userinfo` 出现**同一部署两个答案**（userinfo 有 `sub`，id_token 没有），RP 侧只能靠 userinfo 兜底，
     这正是 O-2/`at_hash` 想避免的形态。
  3. **为什么两轮审计都没抓到**：`internal/oidchttp/oidchttp_test.go:551-600` 的 `TestIDTokenClaims`
     逐条断言了 `iss`/`azp`/`aud`/`nonce`/`auth_time`/`at_hash`/`c_hash` —— **唯独没有断言 `sub`**；
     `internal/httpapi/device_routes_test.go:212` 只断言「id_token 非空」。全仓库（含 e2e）没有一处断言
     `sub` 出现在 id_token 里。这是「守卫看起来很全，缺的正是最该有的一项」。
- 修法建议: 让两个 store 的 `SetUserinfoFromScopes` 填上 subject（`userinfo.Subject = subject`，各 2 行），
  这是最小且正确的改法（该回调本来就是库用来填充 UserInfo 的接缝，`SetUserinfoFromToken` 里已有同款赋值）；
  顺手把 `TestIDTokenClaims` 补成断言 `claims["sub"] == "usr_1"`。**注意：修完立刻激活 PROTO-3 / PROTO-3b。**
- 复现/守卫: `internal/zzprobe/protocol/idtokens_test.go` — `TestProbeIDTokenIsMissingTheSubjectClaim`、
  `lifecycle_test.go` — `TestProbeDeviceFlowIDTokenIsAlsoMissingTheSubject`

### PROTO-3 `id_token` 被当作 Bearer access token 接受（JWS 回落），且**无法撤销**

- 严重度: 中（今天 `sub` 为空故无泄漏；**PROTO-2 一修即变成活的身份 bearer**）
- 类别: 安全
- 不变量/性质: ⑤「凭据containment / 令牌类型不可混用」；RFC 6750 §3 的「受保护资源只接受本 AS 签发的
  access token」；OIDC Core「id_token 不是访问凭据」
- 证据（已执行，PASS 但记录的是**被接受**这一事实）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeNonAccessTokenJWS -v
  idtokens_test.go:123: the id_token is accepted as a bearer access token: 200 map[] (subject empty only because PROBE 6 dropped it)
  idtokens_test.go:153: business-plane introspector: id_token active=false, access_token active=true
  ```

  机制：所有读取路径都过 `pkg/op/userinfo.go:91-108` `getTokenIDAndSubject`，它在 JWE 解密失败后
  **回落到** `VerifyAccessToken`（`pkg/op/userinfo.go:103`），而 `VerifyAccessToken` 的第一步
  `oidc.DecryptToken` 是 `return tokenString, nil // TODO: impl`（`pkg/oidc/verifier.go:110-112`），
  于是**普通 JWS 直接进入验签**：`CheckIssuerWithISSVerifier`（`iss` 相同）+ `CheckSignature`
  （用**本 OP 自己的 JWKS**，正是签 id_token 的钥匙）+ `CheckExpiration`（1 小时）。
  id_token 三项俱全、没有 `jti`，因此 `SetUserinfoFromToken(ctx, info, "", subject, ...)`
  被调到，而本项目的实现**不看 tokenID、只写 subject**（`internal/store/memory/oidc.go:691-694`）。
- 状态: **CONFIRMED**（已执行）
- 影响:
  - id_token 成为 `/oauth/userinfo` 的**bearer 凭据**：RP 会把 id_token 存进 localStorage、发给自己的后端、
    写进日志——任何拿到它的第三方都能拿它换 `sub`（今天为空；PROTO-2 修好后即 `usr_…`）。
  - **撤销够不到它**：`/oauth/revoke` 走 `getTokenIDAndSubjectForRevocation` → JWTID 为空 →
    `RevokeToken("", subject, clientID)` 匹配不到任何行 → 走 RFC 7009「未知令牌即成功」→ **200，什么都没删**，
    而 id_token 在 1 小时内继续有效（实测：先撤销整个 grant（refresh token），access token 立刻 401，
    id_token 仍然 200）。
  - 边界（实测）：业务平面的 `oidchttp.Introspect` 只做 AES 解密、**没有** JWT 回落，所以 `/v1/*` 拒收
    id_token（`active=false`）。混淆被限制在协议平面自己的 `userinfo`。
- 修法建议: 让「用户可见凭据」这条读取路径不接受 JWS —— 最小改法是 `SetUserinfoFromToken` 校验 tokenID
  非空且命中存储（一次查表即可，同时天然挡住 JWT 回落），或在 `oidchttp` 里对 `userinfo` 的 bearer
  先做一次 `provider.Crypto().Decrypt` 判定。（不要指望 `pkg/oidc.DecryptToken` —— 它上游是 TODO。）
- 复现/守卫: `internal/zzprobe/protocol/idtokens_test.go` — `TestProbeNonAccessTokenJWSIsAcceptedAtUserinfo`

### PROTO-3b `/oauth/userinfo` **不检查令牌是否还活着**：过期与已撤销的 access token 照样返回 `sub`

- 严重度: 中
- 类别: 安全（撤销/过期没有生效）
- 不变量/性质: ④「撤销必须真的生效」；RFC 6750「受保护资源必须验证令牌仍然有效」；
  `docs/threat-model.md` D4 下游撤销「删除该客户端为该账号持有的全部令牌」的**意图**
- 证据（已执行，FAIL，用假时钟把 1 小时 access TTL 走完）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeUserinfoIgnoresExpiryAndRevocation -v
  tokens_test.go:242: userinfo accepted an EXPIRED access token: 200 map[sub:usr_probe]
  tokens_test.go:260: userinfo accepted a REVOKED access token: 200 map[sub:usr_probe]
  ```

  同一 token 的两个读者**结论相反**且都已断言（反空转对照写在探针里）：
  业务平面的 `Introspect` 在两种情况下都回 `active=false`（它查行的 `expires_at`），而 `userinfo` 回 200。

  机制：`pkg/op/userinfo.go:36-48` 把**解密出来的** `tokenID` 与 `subject` 一起交给
  `SetUserinfoFromToken(ctx, info, tokenID, subject, origin)`，而本项目的实现
  （`internal/store/memory/oidc.go:691-694`；PG 同形 `internal/store/postgres/oidc.go:583-586`，
  **读；无 DB 执行**）**完全忽略 tokenID**、只把 subject 抄进响应：既不查行，也不看过期，也不看撤销。
- 状态: **CONFIRMED**（已执行；PG 为读代码到行）
- 影响: 用户「解除某下游应用授权」（`DELETE /v1/grants/{client_id}`）或用完 Kill Switch 之后，
  任何**已经持有**该 access token 字符串的一方，仍能拿它向 `/oauth/userinfo` 换到该账号的 `sub`——
  而同一批令牌在业务平面上确实已经死了。于是「已切断」的报告与协议平面的一扇门不一致。
  过期同理：bearer 凭据在 userinfo 上的有效期 = 密文被保存多久。
- 修法建议: 与 PROTO-3 **同一处、同一个改法**——`SetUserinfoFromToken` 必须先按 tokenID 命中存储
  （一次查表，顺便得到 client/scope/expiry），取不到即 401。这同时封掉 PROTO-3（id_token 回落时
  tokenID 为空），所以两条发现只需一次改动。
- 复现/守卫: `internal/zzprobe/protocol/tokens_test.go` — `TestProbeUserinfoIgnoresExpiryAndRevocation`

### PROTO-4 内省白名单里只要有一个**公开客户端**，任何人（无凭据）就能读**任意** token 的 scope/subject

- 严重度: 高（前提是配置项内容，而配置/文档从未要求「必须是机密客户端」）
- 类别: 安全
- 不变量/性质: ①「客户端身份」；RFC 7662 §2.1；ADR-0005 第 10 条（内省默认只看自己的 token）
- 证据（已执行，PASS 记录的是**成功读到**）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeIntrospectionAllowlistWithAPublicClientIsAnonymousRead -v
  seam_test.go:62: public client "probe-device-5c92945f1b98" read another client's token:
      active=true scope=openid account.id phigros.score.read sub=usr_probe
  ```

  请求（无任何凭据正确性要求）：

  ```http
  POST /oauth/introspect
  Authorization: Basic base64("probe-device-<id>:")     # 空 secret 也行
  token=<另一个客户端签发的 access token>
  ```

  机制（两条都必需）：
  1. `internal/store/memory/oidc.go:670-682`（PG 同形：`internal/store/postgres/oidc.go:562-574`）：

     ```go
     if c.Type == oauth.ClientConfidential && !c.Authenticate(clientSecret) {
         return oidc.ErrInvalidClient()...
     }
     return nil      // ← 非机密客户端：任何 secret（含空）都放行
     ```
  2. 库把「nil」当作已认证：`pkg/op/client.go:109-130` `ClientBasicAuth` →
     `pkg/op/token_intospection.go:55-62` `ParseTokenIntrospectionRequest` 只要求 `authenticated == true`。
     于是「认证」退化为「这个 id 存在且是公开客户端」。
  3. `internal/oidchttp/oidchttp.go:900-905` `callerClientID` 取 Basic 用户名，`filterIntrospection`
     （`:919-945`）只在**白名单里**才放行跨客户端结果——白名单是 `Config.IntrospectionClients`，
     由 `cmd/re0auth/config.go:106-109/533-539`、`config/re0auth.example.toml:88-90` 直接来自配置，
     **没有任何一处过滤或提示「必须机密」**（`docs/api-design.md:46` 也只要求「显式列出」）。

  对照（同一探针内）：带机密客户端做白名单时，错 secret → 401；不在白名单 → `active=false`；
  不存在的 client_id → 401。说明上面读到的确实是「白名单 + 公开客户端」而非「认证缺失」。
- 状态: **CONFIRMED**（已执行；内存后端。PG 的 `AuthorizeClientIDSecret` 同一判据，读代码到行）
- 影响: 配置里一旦出现一个公开客户端 id（对 CLI/桌面客户端而言这是最自然的形态，且公开客户端 id
  本来就印在客户端二进制与授权请求 URL 里），**任何能访问内省端点的匿名者**即可用 `Basic <公开id>:x`
  读走部署内任意 token 的 `active/scope/sub/client_id/exp`——即「谁在用哪些 scope、属于哪个 `usr_`」，
  跨客户端的信息泄露。
- 修法建议: 三选一（建议 1+2）——(1) 白名单只接受**机密**客户端：`New()` 里过滤掉非机密 id，
  或在 `filterIntrospection` 要求「调用方是机密客户端且已认证」，但 wrapper 手里没有「已认证」这一事实，
  故更彻底的是 (2) 在 `Introspect` 里判定调用方身份而不是复用库的「authenticated」位；
  (3) 至少把这一要求写进 `Config.IntrospectionClients` 注释、配置示例与 `docs/api-design.md` §内省。
- 复现/守卫: `internal/zzprobe/protocol/seam_test.go` —
  `TestProbeIntrospectionAllowlistWithAPublicClientIsAnonymousRead`（+ 同文件两条对照）

### PROTO-5 discovery 为内省端点广告 `client_secret_post`，而该端点只认 HTTP Basic

- 严重度: 低
- 类别: 可维护性 / 安全（元数据不真实）
- 不变量/性质: ADR-0005 第 5 条「发现文档只声明真实能力」
- 证据（已执行，FAIL）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeDiscoveryAdvertisesClientSecretPostForIntrospection -v
  seam_test.go:161: discovery advertises [client_secret_basic client_secret_post] for introspection
  seam_test.go:172: introspection refused a documented client_secret_post authentication:
      401 {"error":"invalid_client","error_description":"Unauthorized"}
  ```

  机制：`internal/oidchttp/oidchttp.go:385-387` **主动覆盖**了库的诚实答案
  （库 `pkg/op/discovery.go:196-204` `AuthMethodsIntrospectionEndpoint` 只给 `[basic]`），
  而内省端点的表单结构里根本没有 `client_secret` 字段：`pkg/op/client.go:137-140` `clientData`
  只有 `client_id` + `client_assertion`，`ParseTokenIntrospectionRequest` 走的就是它。
  对照（同一探针）：同样的 POST 形状在 `/oauth/revoke` **可用**（`pkg/op/token_revocation.go:83-88`
  确实解 `client_secret`），证明探针请求本身没问题。
- 状态: **CONFIRMED**（已执行）
- 影响: 按 discovery 协商的 RP/资源服务器会选 `client_secret_post`，拿到 401，且没有任何文档解释原因；
  这类「广告了做不到的能力」正是 ADR-0005 第 5 条要消除的形态（只不过这次是**覆盖方向搞反**：
  把库的正确值改成了错的）。
- 修法建议: 把 `introspection_endpoint_auth_methods_supported` 改回 `["client_secret_basic"]`，
  或真的在 wrapper 里补一层表单 secret 认证（成本更高，不建议）。
- 复现/守卫: `internal/zzprobe/protocol/seam_test.go` — `TestProbeDiscoveryAdvertisesClientSecretPostForIntrospection`

### PROTO-6 `prompt=none` 被完全忽略：静默认证被重定向到交互式登录页，而不是 `error=login_required`

- 严重度: 中
- 类别: 合规/隐私（协议正确性）
- 不变量/性质: OIDC Core §3.1.2.1「`prompt=none` 且未认证 ⇒ **MUST** 返回 `login_required`」
- 证据（已执行，FAIL）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbePromptNoneIsIgnored -v
  discovery_test.go:99: prompt=none answered 302 "/login?authRequestID=dQhPIOWhj-M2fzO2t_5v62x2uAPx3-BYgX9SUdTcp1s"
  discovery_test.go:102: prompt=none redirected the browser to the interactive login page instead of error=login_required
  ```

  全仓库检索：`internal/` 下**没有任何**一处提到 `prompt` 或 `login_required`（`grep -r prompt internal/` 只命中
  库自身的 `ValidateAuthReqPrompt`，而它只把 `prompt=login` 映射成 `max_age=0`，
  `pkg/op/auth_request.go:281-292` 对 `none` 不做任何事）。校验链
  `validateAuthorize`（`internal/oidchttp/oidchttp.go:759-821`）也不看 `prompt`。
- 状态: **CONFIRMED**（已执行）
- 影响: 用隐藏 iframe / 后端发起静默认证的标准 RP 拿不到 `login_required`，而是让**隐藏框架里渲染出 OP 的登录页**
  （用户看到不明来源的登录框，且 RP 侧把它当成一次普通失败或干脆超时）；同时那条 pending 授权请求会一直挂着
  （TTL 30 分钟，见 PROTO-11），能被后续误批准。
- 修法建议: 在 `validateAuthorize` 里处理 `prompt=none`：无有效会话时**按 RFC 6749 §4.1.2.1 通过已校验的
  redirect_uri 回 `error=login_required`**（带 `state` 与 RFC 9207 `iss`，与现有 PKCE 拒绝同一形状）；
  这需要 wrapper 能问到「这个浏览器有没有会话」——`Config` 目前没有这个钩子，属需要**裁定**的接口改动，
  故建议与 `internal/httpapi` 的会话层一起决定，而不是顺手改。
- 复现/守卫: `internal/zzprobe/protocol/discovery_test.go` — `TestProbePromptNoneIsIgnored`

### PROTO-7 `response_mode=form_post` 的授权响应**不带** RFC 9207 `iss`，而 discovery 广告「支持 iss」

- 严重度: 低
- 类别: 安全（mix-up 防护）/ 合规
- 不变量/性质: ADR-0005 第 6 条「授权响应带 `iss`，成功与失败都带」；RFC 9207
- 证据（已执行，FAIL）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeFormPost -v
  discovery_test.go:58: the form_post authorization response has no `iss` parameter:
      <form method="post" action="https://client.example/cb">
      <input type="hidden" name="state" value="state-probe"/>
      <input type="hidden" name="code" value="eyJhbGciOiJBMjU2R0NNS1ci..."/>
  discovery_test.go:77: query mode: https://client.example/cb?code=...&iss=https%3A%2F%2Fissuer.probe&state=state-probe
  ```

  机制：`internal/oidchttp/oidchttp.go:512-516` 只在 `3xx` 的 `Location` 上注入 `iss`
  （`isAuthorizationResponse(...) && bw.status >= 300 && bw.status < 400`），而 form_post 由库渲染成
  **200 的 HTML 表单**（`pkg/op/auth_request.go:519-525` → `AuthResponseFormPost`）。
  同时 discovery 里 `authorization_response_iss_parameter_supported: true`
  （`internal/oidchttp/oidchttp.go:375`），且 discovery **完全没有** `response_modes_supported` 字段
  （库的 `DiscoveryConfiguration` 不含它），所以客户端既拿不到 iss，也无法从元数据知道 form_post 存在。
- 状态: **CONFIRMED**（已执行）
- 影响: 唯一在意 `iss`（防 mix-up）的那类客户端，在 form_post 模式下恰好拿不到它，而它已经从元数据得知
  本 AS 支持 iss——无声的能力缺口。
- 修法建议: 要么在 `serveOAuth` 里对 form_post 的 200 HTML 也注入 `iss`（要改 HTML，不如），
  要么按 ADR-0005 第 5 条**只声明真实能力**：`authorization_response_iss_parameter_supported` 与
  「接受 `response_mode=form_post`」二者取一（建议：拒绝 `response_mode != ""`，因为 discovery 从未广告任何
  response mode，这是最小且自洽的改法）。
- 复现/守卫: `internal/zzprobe/protocol/discovery_test.go` — `TestProbeFormPostAuthorizationResponseHasNoIss`

### PROTO-8 动态 issuer + discovery 进程级缓存：**一次伪造 Host 的请求永久固定两份发现文档**

- 严重度: 低（**生产不可达**：`cmd/re0auth/config.go:412-413` 强制 `server.issuer` 非空；
  仅影响 wrapper 自己文档化的「dynamic deployments」与全部测试夹具）
- 类别: 安全（缓存投毒）
- 不变量/性质: ⑥「能被一个匿名请求永久改变的状态」
- 证据（已执行，PASS 记录事实）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeDiscoveryIsCachedFromTheFirstRequestsHost -v
  seam_test.go:265: first fetch (Host: attacker.example) -> issuer=http://attacker.example
      authorization_endpoint=http://attacker.example/oauth/authorize jwks_uri=http://attacker.example/oauth/keys
  seam_test.go:275: every later fetch is answered with the attacker's issuer, including jwks_uri=http://attacker.example/oauth/keys
  seam_test.go:297: the RFC 8414 alias serves the same poisoned document: issuer=http://attacker.example
      cache-control="public, max-age=300"
  ```

  机制：`internal/oidchttp/oidchttp.go:259-283` 的 `discoveryCache` **只按路径**缓存、无 TTL、无 Host 维度，
  而 `New()` 在 `Config.Issuer == ""` 时用 `op.IssuerFromHost("")`（`:169-172`），文档里的每个 URL 都从
  **首个请求的 Host** 派生。附带两点：(a) RFC 8414 别名与 OIDC 文档**共用同一个缓存键**
  （`serveDiscovery` 对两者都按 `OIDCDiscoveryPath` 查/写），所以一次投毒覆盖**两份**文档；
  (b) 首条响应带 `Cache-Control: public, max-age=300`，会被中间缓存带走。
  （`TestDiscoveryIsServedFromCache` 断言的是「别名没有自己的键」，这句话为真，但它掩盖了「别名读的是
  OIDC 的键」这一实际后果。）
- 状态: **CONFIRMED**（已执行，动态 issuer 形状）
- 影响: 在动态 issuer 部署上，任何人用一个伪造 `Host`（或 `Forwarded: host=`）的首个请求，就把全部署的
  discovery（含 `jwks_uri`、`authorization_endpoint`）指向自己的域名，直到进程重启；后续客户端据此
  把授权请求与验签请求发往攻击者。生产二进制里 `server.issuer` 必填，因此这条**不是**现网的洞，但它是
  wrapper 明确支持的一种部署形态，且测试套件全用这一形态，掩盖了静态 issuer 路径的覆盖。
- 修法建议: 缓存键加入 `IssuerFromRequest(r)`（或：`Config.Issuer == ""` 时直接禁用 discovery 缓存，
  并在 `New()` 里对「动态 issuer + 缓存」这一组合给出明确裁定）。
- 复现/守卫: `internal/zzprobe/protocol/seam_test.go` — `TestProbeDiscoveryIsCachedFromTheFirstRequestsHost`

### PROTO-9 令牌端点只挡 GET、不挡「POST + 查询串」，凭据仍可进入 URL 与访问日志

- 严重度: 低
- 类别: 安全（纵深防御）
- 不变量/性质: ADR-0005 第 3 条的动机本身——「凭据不再进入 URL 与访问日志」
- 证据（已执行，PASS 记录事实）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeTokenEndpointAcceptsItsParametersFromTheQueryString -v
  parseform_test.go:153: the token endpoint served an exchange whose code, secret and verifier were all in the URL:
      {"access_token":"eyJhbGciOiJBMU...","expires_in":3600,"scope":"account.id","token_type":"Bearer"}
  parseform_test.go:169: a long-lived refresh token was accepted from the query string: 200
  ```

  机制：`endpointMethods`（`internal/oidchttp/oidchttp.go:1021-1030`）只约束 HTTP 方法，而
  `requestParams`/库的 `r.Form` 同时接受 body 与查询串（`pkg/op/token_request.go:104-152`）。
  对照（同探针）：同一个请求用 GET → 405（A3-1 的修复仍然成立）。
- 状态: **CONFIRMED**（已执行）
- 影响: 一个把参数放进查询串的客户端（或中间件重写、或被诱导的行为）会让**长期有效的 refresh token 与
  client_secret 落进代理/网关访问日志、浏览器历史与 Referer**——ADR-0005 第 3 条正是为消除这一点而
  禁掉 GET 的，而这条路径同为「凭据在 URL 里」，只是方法合法。
- 修法建议: 对 POST 的 `token`/`introspect`/`revoke`/`device_authorization`，要求 `r.URL.RawQuery` 为空
  （或至少要求 `client_secret`/`refresh_token`/`code`/`token` 不得来自查询串），拒绝时回 OAuth JSON 400。
  代价是拒绝一类非标准但可用的请求——属**可接受的收紧**，与 ADR-0005 第 3/4 条同向。
- 复现/守卫: `internal/zzprobe/protocol/parseform_test.go` — `TestProbeTokenEndpointAcceptsItsParametersFromTheQueryString`

### PROTO-10 `userinfo` 对**没有 `openid`** 的令牌也返回 `sub`（O-2 只堵住了 id_token 那一扇门）

- 严重度: 提示
- 类别: 合规/隐私
- 不变量/性质: O-2 的**意图**（未请求 `openid` 就不给身份断言）
- 证据（已执行，PASS 记录事实）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeUserinfoAnswersWithoutOpenIDScope -v
  seam_test.go:230: a token whose scope is "account.id" yields userinfo map[sub:usr_probe]
  ```

  `sanitizeTokenResponse` 按 O-2 剥掉无 `openid` 的 `id_token`（`:1047-1075`），但
  `pkg/op/userinfo.go` 全程不看 scope，本项目 `SetUserinfoFromToken` 只写 subject。
- 状态: **CONFIRMED**；**这是被现有守卫固定的形状**——`internal/oidchttp/oidchttp_test.go:304-333`
  `TestUserinfoReturnsOnlySub` 用的 scope 恰好是 `account.id phigros.score.read`（无 `openid`）并断言 200。
  所以本报告把它记为**判断**而非缺陷（见文末）。
- 影响: 一个从未走过 OpenID 同意路径的 RP，仍能从另一个端点拿到同一 `sub`；O-2 的实际强度低于其表述。
- 修法建议: 若要把 O-2 贯彻到端点级，`SetUserinfoFromToken` 需要拿到 scope（库只传 tokenID/subject，
  所以得在 `oidchttp` 层先 `Decrypt` + 查存储判 scope）；这属于**裁定**，不要顺手改。
- 复现/守卫: `internal/zzprobe/protocol/seam_test.go` — `TestProbeUserinfoAnswersWithoutOpenIDScope`

### PROTO-11 匿名 `GET /oauth/authorize` 每次分配一条 pending 授权请求（TTL 30 分钟）

- 严重度: 提示
- 类别: 可用性
- 不变量/性质: 「匿名输入不得产生无界状态」
- 证据（已执行，PASS 记录测量）:

  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeAnonymousAuthorizeAllocatesPendingRequests -v
  grants_test.go:139: 200 unauthenticated GETs -> 200 pending auth requests held for the request TTL (0 -> 200 records)
  ```

  `GET /oauth/authorize` 在**没有任何会话**的情况下也会 `CreateAuthRequest`
  （`pkg/op/auth_request.go:145`），`requestTTL` 默认 30 分钟
  （`internal/store/memory/oidc.go:286-289`），期间 `SweepExpired` 不会回收（同探针断言）。
  公开客户端的 `client_id` 与其注册的 redirect URI 都是公开值，PKCE challenge 由攻击者自算。
- 状态: **CONFIRMED**（已执行；数字是实测的，不是推算）
- 影响: 每条约数百字节、绑定 30 分钟；斜率 = 请求速率 × 1800s。**已被两道闸门限制**：
  `internal/httpapi` 的 `Config.Limiter`（按客户端地址）与 `MaxInFlight`（`server.go:69-75` 明确写着
  「applied to both planes」）。因此这是「有界但确定」的放大，而不是可击垮进程的洞；分布式来源下无界则是所有
  按地址限流的共性。记为提示，供容量规划引用。
- 修法建议: 若要把斜率压平，可对「没有任何会话 cookie 的 authorize」加更紧的桶，或缩短**未登录**请求的 TTL
  （`RequestTTL` 目前对两者同一值）。
- 复现/守卫: `internal/zzprobe/protocol/grants_test.go` — `TestProbeAnonymousAuthorizeAllocatesPendingRequests`

---

## 库与薄封装之间的接缝清单（本题要求枚举）

审计方法：以 `op.NewProvider` 真正走的注册路径为准（`pkg/op/op.go:258-299` `NewProvider` →
`CreateRouter`，**不是** `RegisterLegacyServer`/`LegacyServer` 那一套；后者的方法在本装配下是**死代码**，
见条目 12）。逐条给出「库做什么」/「封装假设什么」/「现状」。

| # | 接缝 | 库的行为（`file:line`） | 封装的假设 | 结论 |
|---|---|---|---|---|
| 1 | 端点方法约束 | `CreateRouter` 用 chi `HandleFunc` 注册，**无方法约束**（`pkg/op/op.go:126-149`）；`Exchange` 用 `r.FormValue` 取值（`pkg/op/token_request.go:45`） | `endpointMethods` 一张表统一 405（`oidchttp.go:430`） | **已覆盖**（A3-1/A3-2 的修复 + `TestEveryProtocolEndpointRefusesUnlistedMethods`）。**但覆盖依赖参数集相同 → 见 PROTO-1** |
| 2 | `ParseForm` 错误语义 | 库的 handler 再调一次 `r.ParseForm`，因 `r.PostForm` 已非 nil 而**返回 nil**（`net/http/request.go` 的缓存逻辑），然后从 `r.Form`（含查询串）解码（`pkg/op/token_request.go:109-116`） | `requestParams` 把「解析失败」当成「没有参数」（`oidchttp.go:723-731`） | ❌ **未覆盖 → PROTO-1**（第一次调用与后续调用看到不同参数集） |
| 3 | 客户端身份解析 | `ClientBasicAuth` = **Basic 优先**，`url.QueryUnescape` 解码后 `AuthorizeClientIDSecret`（`pkg/op/client.go:109-130`） | 双身份一律 400；`callerClientID` 用 Basic 原值（未 unescape） | **基本覆盖**。残余：`callerClientID` 不做 `QueryUnescape`（仅 `TrimSpace`），两者只在客户端 id 含 `%xx`/空白时分歧；实测的三端点双身份守卫成立（探针 8）。**未观察到可利用路径** |
| 4 | 公开客户端的「认证」 | `AuthorizeClientIDSecret` 对非机密客户端直接 nil（本项目 store），库信任它（`pkg/op/token_intospection.go:60`） | 「已认证」= 客户端身份可信 | ❌ **未覆盖 → PROTO-4** |
| 5 | `id_token` 的 claim 组装 | `CreateIDToken` 用 `storage.SetUserinfoFromScopes` 填充的 `UserInfo` **覆盖** `Subject`（`pkg/op/token.go:241-254` + `pkg/oidc/token.go:158`） | 本项目的 no-op 桩是安全的（上游已弃用该回调） | ❌ **未覆盖 → PROTO-2** |
| 6 | 「不是 access token 的 JWS」 | `oidc.DecryptToken` 是 `return tokenString, nil` 的 TODO（`pkg/oidc/verifier.go:110-112`），于是 JWS 进入 `VerifyAccessToken`（`pkg/op/verifier_access_token.go:32-59`，**不校验 aud**） | 只有本 AS 加密过的引用令牌能过 `getTokenIDAndSubject` | ❌ **未覆盖 → PROTO-3** |
| 7 | PKCE 在兑换时的强制 | `AuthorizeCodeClient` **对所有客户端**无条件调 `AuthorizeCodeChallenge`（`pkg/op/token_code.go:83-87`）。**但** `LegacyServer.CodeExchange` 只在 `AuthMethodNone` 或 verifier 非空时检查（`pkg/op/server_legacy.go:234-238`） | 兑换一定校验 verifier | **本装配下成立**（探针 10 断言「无 verifier 必须失败」）。⚠️ 一旦改用 `RegisterLegacyServer`，机密客户端即可无 verifier 兑换 → 保留探针作回归 |
| 8 | 重复参数 | 库的 `schema` 解码器对多值取**最后一个**（`docs/security-audit-2.md` 已记录）；`r.FormValue` 取第一个 | `duplicatedParam` 一律拒绝（`oidchttp.go:440`） | **形态上覆盖**，但可被 PROTO-1 关掉；且「第一个 vs 最后一个」的分歧正是 PROTO-1 的放大器 |
| 9 | redirect_uri 校验 | `checkURIAgainstRedirects` 精确匹配 + 可选 `RedirectURIGlobs`（`pkg/op/auth_request.go:316-334`；glob 仅当客户端实现 `HasRedirectGlobs`，`ProviderClient` 未实现） | 精确匹配，且在 wrapper 层先行拒绝（`validateAuthorize`） | **已覆盖**（探针 9：19 种扩展全部 400 且**不重定向**） |
| 10 | 作用域过滤 | `ValidateAuthReqScopes` **静默删除**越界 scope 且仅在输入为空时报错（`pkg/op/auth_request.go:296-312`） | wrapper 先拒（O-7） | **已覆盖**（A1-3 修复 + 探针 10/13）；空集后果见 PROTO-1 附带项 |
| 11 | 刷新时的作用域 | `ValidateRefreshTokenScopes` 只做子集检查（`pkg/op/token_refresh.go:84-95`） | 刷新不得提权 | **已覆盖**（探针 11：11 种写法全部拒绝或收窄） |
| 12 | `LegacyServer` 全族 | `RegisterLegacyServer` 才用（`pkg/op/server_legacy.go`），本装配不用 | —— | **死代码**，但它是公开 API：条目 7 的差异留在库里，且它 `authenticateResourceClient`（`:360-374`）与 package 级 `Introspect` 不共用（前者不要求 `cc.ClientSecret != ""`）。属**判断**项 |
| 13 | discovery 的能力集 | 库广告能用的一切（implicit/hybrid、`end_session`、private_key_jwt、完整 claims 列表）（`pkg/op/discovery.go:36-68`） | `stripUnsupportedDiscoveryFields` 逐项裁剪/覆盖 | **大体覆盖**；两处偏差：`introspection_..._auth_methods` 覆盖**过头**（PROTO-5）、`response_modes_supported` 缺失而 form_post 仍被接受（PROTO-7） |
| 14 | CORS | 库用 `rs/cors` 反射任意 Origin 且 `Allow-Credentials: true`（`pkg/op/op.go:75-97`，`CreateRouter:132-134`） | `corsFreeWriter` 在边界剥头（`oidchttp.go:227`，ADR-0011） | **已覆盖**（wrapper 自己写了原因注释） |
| 15 | `end_session` 路由 | 库在**默认路径** `/end_session` 注册（未被 `WithCustomEndSessionEndpoint` 覆盖，`op.go:31/145`） | 「不在 `/oauth/` 前缀下的都不转发」 | **已覆盖**（`ServeHTTP` 落到 default → 404 OAuth JSON）；探针 17 顺带断言所有**被广告**的端点都真的存在 |
| 16 | 动态 issuer 与 `Forwarded` | `IssuerFromHost` 会读 `Forwarded: host=`（`pkg/op/config.go:88-129`） | 生产由 `Config.Issuer` 固定 | **生产已覆盖**；动态形态见 PROTO-8 |
| 17 | 令牌加密容器 | 不透明令牌实际是 **JWE**（`A256GCMKW`+`A256GCM`，`pkg/op/crypto.go:51-84`），compact 头明文含 `alg/enc/kid/iv/tag`；`CompositeCrypto.Decrypt` 依次试各密钥、**不看头里的 kid** | threat-model §6.0.1 写作「AES-GCM 加密 `tokenID:subject`」 | **无安全问题**（头只泄露 key id；kid 不参与选择密钥，因此不存在「用错密钥」的构造）。列为文档措辞不一致（提示） |

---

## 发现（续）：`idp/`（re0auth 作为 OAuth/OIDC **客户端**）（RP-*）

> **来源与核验**：由本轮另一个**平行子审计代理**完成（片段原文 `docs/audit-5/findings/_fragment_rp.md`，
> 探针包 `internal/zzprobe/protocol/rp/`）。本报告作者**独立重跑了该探针包**：
> `go test ./internal/zzprobe/protocol/rp/` → **12 条 FAIL**（对应下面 9 条发现，RP-1 由 3 条、RP-3 由 2 条、
> RP-7 由 2 条、RP-6 由 1 条断言构成），且**含一条真实网络用例**（RP-4）在本机确实失败。
> 我另外**抽检了最吃重的两处代码**并确认无误：
> `idp/idp.go:536-542`（验证器只传 `&oidc.Config{ClientID: …}`，而 `oidcClaims`（`idp.go:479-485`）
> 只有 sub/name/email/picture/nonce —— 全包没有一处提到 `azp`）、
> `idp/idp.go:521-533`（`c.discovered` 进程级缓存，无 TTL、无失效），
> 并确认 `identityFromIDToken`（`idp.go:505-510`）**确实**校验 `nonce` 与 `sub` 非空（即「nonce 绑定」与
> 「无 id_token ⇒ 失败关闭」两条成立，见下方守卫清单）。

### RP-1 `id_token` 的 `azp` **完全不校验**：多受众令牌（含 `azp` 指向别的客户端）被当作本客户端的身份接受

- 严重度: 高 ｜ 类别: 安全
- 不变量/性质: OIDC Core §3.1.3.7 —— `aud` 多值时必须存在 `azp` 且等于本客户端；单 `aud` 时若存在 `azp` 也必须指向本客户端
- 证据（已执行，三种形状全 FAIL）: RP 接受 `azp=other-client` 的令牌（`sub="victim-of-another-client"`）、
  接受无 `azp` 的多受众令牌、接受 `azp="someone-else"`；对照组 `TestRPControlOIDCLoginSucceeds` PASS
  且断言 discovery/JWKS/token 都被走到、userinfo 零调用（证明不是空转）。
  行级：`idp/idp.go:541` 只传 ClientID；`azp` 在 `idp/idp.go` 中**一次都没出现**。
  依赖侧：`go-oidc v3.21.0 oidc/verify.go:250-259` 自己写明「**不保证** ClientID 是签发对象」，只做 `aud` 包含检查。
- 状态: CONFIRMED（子审计执行；本报告已重跑）
- 影响: 若上游允许客户端扩展 `aud`（`audience`/`resource` 参数、Keycloak audience mapper），攻击者可用自己的客户端
  在同一 issuer 上取得「受害者 `sub` + `aud` 含本服务 client_id + `azp`=攻击者客户端」的 id_token，
  喂给 `/auth/<provider>/callback` 即以受害者身份建号/登录 —— **跨客户端令牌重放升级为账号接管**。
  前提：上游允许扩展 `aud`，且受害者曾在攻击者客户端登录过同一上游；在「自定义 OIDC provider」被明确支持的部署
  （Keycloak/Authentik，`cmd/re0auth/config.go:717-727`）里门槛不高。前提不满足时退化为纵深防御缺失。
- 修法建议: 在 `identityFromIDToken` 自行判定 `azp`（`oidcClaims` 加 `AZP` 字段），与 `aud` 长度规则一并实现。
- 复现/守卫: `rp/idtoken_test.go` — `TestRPAzpNamingAnotherClientIsAccepted`、
  `TestRPAzpMissingWithMultipleAudiencesIsAccepted`、`TestRPAzpMismatchSingleAudienceIsAccepted`

### RP-2 JWKS / discovery 缓存**没有 TTL**：被轮换（撤销）掉的签名密钥一直验签成功

- 严重度: 中 ｜ 类别: 安全
- 不变量/性质: 上游的密钥撤销/轮换必须对验证方生效
- 证据（已执行）: 正常登录一次（缓存 k1，JWKS 取 1 次）→ 上游轮换为 k2（JWKS 只公布 k2）→
  用**已下线的 k1** 签 id_token → RP 接受；且 JWKS 取用计数 before=1/after=1，**连一次重取都没发生**。
  行级：`go-oidc oidc/jwks.go:163-170`（命中缓存即返回，无 TTL）、`:176-189`（只在没有缓存密钥能验通时才远程取）；
  同目录 `idp/idp.go:521-533` 把 discovery 文档也永久缓存。
- 状态: CONFIRMED
- 影响: 「密钥泄露 → 上游轮换」这条事故响应对 RP 无效：攻击者用泄露的旧私钥签 id_token 可一直伪造任意 `sub`，
  直到有合法用户拿新 kid 的令牌触发一次重取（窗口有限，但「撤销不生效」本身确定）；上游换 `jwks_uri` 后 RP 也不跟随。
- 修法建议: 给 JWKS/`c.discovered` 加显式刷新边界（TTL 或按 kid 变化主动重建 keyset）。
- 复现/守卫: `rp/idtoken_test.go` — `TestRPRetiredSigningKeyKeepsVerifyingAfterRotation`

### RP-3 自定义 OIDC provider 的**端点不与 issuer 绑定**：登录可被导向任意 origin，`client_secret` 与授权码被投递给它

- 严重度: 中 ｜ 类别: 安全
- 不变量/性质: discovery 只能描述 issuer 自己；token 端点必须与配置 issuer 同源，否则不得把 `client_secret` 与 code 发给它
- 证据（已执行）: 让 discovery 只把 `authorization_endpoint`/`token_endpoint` 指向另一个 origin，
  RP 就把浏览器送到 `https://evil.example/authorize?...`，并把 `Authorization: Basic <cid:top-secret>` 与
  `code=code-1&code_verifier=...` 真的发到对方服务器（探针抓到了）。
  行级：`idp/idp.go:425-436`（`cfg.Endpoint = provider.Endpoint()` 原样采纳）、`idp.go:299-301`、`idp.go:411-420`。
  注意 issuer 本身**是**被校验的（`go-oidc oidc/oidc.go:331-336`），所以这不是 mix-up，而是「端点未钉在 issuer 上」。
- 状态: CONFIRMED
- 影响: 能左右 discovery 的一方（明文 http 自建 issuer、DNS/证书被劫持、上游被攻破）拿到**长期有效的 client_secret**
  与每一次登录的 authorization code —— 这比「他反正能改 JWKS」更重，因为 secret 在停止篡改之后仍然可用。
- 修法建议: 对只给 issuer 的 provider，要求 discovery 端点与 issuer 同 scheme+host，不同源即拒绝。
- 复现/守卫: `rp/builtin_test.go` — `TestRPDiscoveredAuthorizationEndpointIsNotPinnedToTheIssuer`、
  `TestRPDiscoveredTokenEndpointReceivesTheClientSecret`

### RP-4 内置 `microsoft` 的 issuer 在真实端点上**必然** discovery 失败：微软登录必定以 `identity_failed` 收场

- 严重度: 中 ｜ 类别: 可用性 / 正确性
- 证据（已执行，**真实网络**）: 内置 issuer `https://login.microsoftonline.com/common/v2.0` 与真实 discovery 返回的
  `https://login.microsoftonline.com/{tenantid}/v2.0` 不等 → `discovery failed`；
  对照（同一台机器、同一端点、只把 issuer 换成租户 URL）discovery 成功。
  行级：`idp/idp.go:142`（内置值）、`idp.go:527`、`idp.go:427-429`（内置端点齐全时不触发 discovery）——
  因此用户会被正常送到微软、授权成功后回来才失败（`internal/auth/auth.go:657-660` 落成通用码 `identity_failed`）。
- 状态: CONFIRMED
- 影响: 只填 client_id/secret（文档里最自然的写法）时微软登录 100% 失败，且失败发生在用户已授权之后，
  运维看不到「配置错在哪」。内置默认值是**发布产物本身不可用**，不是运维知识。
- 修法建议: `[idp.microsoft]` 未给 issuer 就启动报错并要求租户 URL；或按 go-oidc 的 Azure 例外
  （`oidc.InsecureIssuerURLContext`）显式放宽并把放宽程度写进裁定文档。
- 复现/守卫: `rp/builtin_test.go` — `TestRPRealMicrosoftBuiltInIssuerCannotDiscover`（断网会 skip 并说明）

### RP-5 discovery 缺 `authorization_endpoint` 时，RP 把**相对登录 URL**交给浏览器

- 严重度: 低 ｜ 类别: 可用性
- 证据: discovery 省略该字段 → RP 交给浏览器 `"?client_id=...&state=st"`（相对串）。行级：`idp/idp.go:427-435`
  （`provider.Endpoint()` 原样回传空串）、`internal/auth/auth.go:602` 直接 `http.Redirect`。同源，无跨站影响。
- 状态: CONFIRMED
- 修法建议: 发现端点后校验 `authorization_endpoint`/`token_endpoint` 非空且绝对，否则记为 provider 不可用。
- 复现/守卫: `rp/builtin_test.go` — `TestRPDiscoveryWithoutAuthorizationEndpointYieldsARelativeLoginURL`

### RP-6 指向错误 provider 的 callback **先清空流程再比对 provider**：一次被拒的回调烧掉待完成的登录

- 严重度: 低 ｜ 类别: 可用性
- 证据: 用 github 的 state 打 `/auth/discord/callback` → 400（预期），随后用同一 state 打
  `/auth/github/callback` → 也变成 400 `invalid state`。行级：`internal/auth/auth.go:627`
  的 `clearFlow` 在 `:629-633` 的 provider 比对**之前**。
- 状态: CONFIRMED
- 影响: 多 provider 部署下一次走错门就作废本次登录；`provider_mismatch` 诊断码第二次再也观察不到。攻击者无法主动触发。
- 修法建议: 把 provider 比对（及 code/error 存在性检查）移到 `clearFlow` 之前。
- 复现/守卫: `rp/e2e_test.go` — `TestRPLoginStateIsBoundToItsProvider`

### RP-7 同意批准返回的 redirect **可重放**：每次访问都新签一个 authorization code

- 严重度: 低 ｜ 类别: 安全 / 可用性
- 证据: 批准后连续两次 GET 同一个 `/oauth/authorize/callback?id=X` → 两次都 302 且 `code` 不同，
  兑换时第一份 200、第二份 400。行级：`internal/store/memory/oidc.go` 的 `SaveAuthCode` 以码哈希为 key 逐条插入
  （不覆盖同一 auth request 的旧码），而 `AuthRequestByCode` 兑换时删码并删 auth request。
  并发版本（`TestRPConsentDecisionConcurrency`，`-race`）8 个并发决策全部 200。
- 状态: CONFIRMED（PG 侧未验证，见盲区）
- 影响: 「一次同意 = 一份 grant」**没有**被破坏（另有既存落盘守卫）；实际影响有界：
  (1) 浏览器/网关只要多取一次那个 URL（刷新、后退、链接预览、URL 预取），先被取走的码就抢掉唯一兑奖机会，
  客户端拿到的是死码 → 用户做完同意却登录失败；(2) 每次访问多留一条指向已删 auth request 的死码，直到请求 TTL。
- 修法建议: 让该回调对同一 auth request 幂等（已 `Done` 且有码就重定向到同一个码），或生成新码前先删旧码。
- 复现/守卫: `rp/consent_test.go` — `TestRPConsentApprovalRedirectIsReplayable`、`TestRPConsentDecisionConcurrency`

### RP-8 登录完成后会话里仍留着 `flow_nonce`（`flowKeys` 漏了 `keyFlowNonce`）

- 严重度: 提示 ｜ 类别: 安全（卫生）/ 可维护性
- 证据: dump 会话字节可见 `flow_nonce` 与 `usr`/`auth_time`/`csrf` 并存，而同流程的
  `flow_state`/`flow_verifier`/`flow_provider`/`flow_mode`/`flow_return_to` 都已清掉。
  行级：`internal/auth/auth.go:41` 定义 `keyFlowNonce`，`:44` 的 `flowKeys` 没有它，`clearFlow`（`:708-712`）只删列表里的 key。
- 状态: CONFIRMED（**当前不可利用**：nonce 本就出现在地址栏，下次 start 会覆盖它）
- 影响: 记录的是「写入列表与清理列表不一致」这一类漂移 —— 下次给 flow 加真正的秘密字段时就会变成真问题。
- 修法建议: 把 `keyFlowNonce` 加进 `flowKeys`，并让写入与清理共用同一个列表。
- 复现/守卫: `rp/e2e_test.go` — `TestRPLoginLeavesNoFlowValuesInTheSession`

### RP-9 身份「关联（link）」**不要求近期认证**：任何有效会话都能把新的上游身份绑到账号上

- 严重度: 中 ｜ 类别: 安全
- 证据（行级确证机制）: `internal/auth/auth.go:575-580` 的 `mode == "link"` 分支唯一门槛是「已登录」；
  回调 `:662-680` 同样只要求 `h.manager.User(ctx)` 存在。`sessions.AuthenticatedAt` 已在会话里，
  但**只有管理面**用它（`internal/httpapi/admin_routes.go:89-92` 的 `adminReauth`，配置项 `[admin].reauth_window`）。
- 状态: **HYPOTHESIS**（机制确证；「一个月前的会话也能 link」**未执行验证**——`auth.Manager` 没有可注入时钟，
  探针只能证明「已登录会话可完成 link，且不会切换账号」）→ 要证实它需要给 `Manager` 注入时钟后走一次
  `/auth/github/start?mode=link` + callback，按读到的代码答案会是「仍然 200」
- 影响: 会话被盗（或共享终端未登出）后，攻击者做一次 link 把自己控制的上游身份挂到受害者账号上，
  受害者改密码/登出都拔不掉，之后攻击者用自己的 GitHub 账号即可直接登录该账号。
- 修法建议: link 分支复用 `AuthenticatedAt`，超过可配置窗口要求重新登录（这是裁定：要不要新配置项）。
- 复现/守卫: 目前只有读代码证据；建议守卫 `internal/auth` 的 `TestLinkRequiresAFreshAuthentication`

> RP 区域另有 **17 项「探过但没破」**（state 的 CSPRNG+会话绑定+单次使用；nonce 生成/发送/校验且不可为空；
> **无 id_token ⇒ 失败关闭且 userinfo 零回退**（探针断言 userinfo 命中 0 次）；`alg=none` 与 HS256 混淆都被拒；
> 跨 provider 密钥不互验；**JWKS 抓取失败不清缓存**（与 RP-2 是同一段代码的安全方向）；
> discovery 的 issuer 等值校验（mix-up 不成立）；PKCE S256 + verifier 对应；`redirect_uri` 只来自配置且
> provider 名无法越界；`return_to` 不能出站；上游 `error_description` 不被反射；`mode` 来自会话而非查询；
> 同意手柄的 owner/CSRF/一次性；出站不跨站重定向；默认出站客户端拒绝私网 discovery（SSRF 面）；
> `sub` 按 provider 命名空间隔离）与 **7 项残余盲区**（详见 `_fragment_rp.md`）。
> 其中一条**观察**值得记入：`iat` 完全不校验（`TestRPFutureIssuedAtIsAccepted`），`exp` 无 skew 宽限，
> 上游与本机时钟差几秒即登录失败 —— 均为提示级。

---

## 发现（续）：`upstreamkit/` + `oauth/` 公开引擎（KIT-*）

> **来源与核验**：这一节由本轮的**平行子审计代理**完成（片段原文见
> `docs/audit-5/findings/_fragment_kit.md`，探针包 `internal/zzprobe/protocol/kit/`）。
> 本报告作者**独立重跑**了该探针包，确认其可复现：
> `go test ./internal/zzprobe/protocol/kit/` → **13 条 FAIL 断言**（对应下面 10 条发现，
> 其中 KIT-1/KIT-3/KIT-7 各由 2–3 条断言构成），其余 32 条 PASS（即守卫）。
> 另外我**抽检了三条最吃重的代码位置**并确认无误：`upstreamkit/server.go:318-339`
> （`handleCascadeRevocation` 全程没有任何认证，直接把 `clientID/clientSecret` 转给钩子，
> 而 `handleToken`/`handleRevoke` 把手上的凭据交给 `s.hooks.OAuth.*` 去认证）、
> `oauth/as.go:253-271`（`Introspect` 只查 `tokens.GetAccess` 与过期，**从不**查 `s.clients`）、
> `upstreamkit/conformance/conformance.go:287-297`（cascade 检查唯一判据是 `404`，200 即 PASS）。
> 其余推理我未逐行复核，故按其原文如实转述；凡它标明「读；无 DB 执行」的 Postgres 部分保持该标注。
>
> **影响面定位（重要）**：这些代码属于**数据源侧**——本仓库的参考源（`cmd/referencesource`）与任何
> 使用公开库 `oauth/` + `upstreamkit/` 的第三方源。Re0Auth 自己的 OP 不挂这些端点（`cmd/re0auth` 的
> 组合根里没有它们），所以 KIT-* 的严重度是**对部署者与第三方源**的，而不是对 `auth.re0auth` 现网的。

### KIT-1 生成的 `/oauth/cascade_revocation` **完全不认证**：无凭据或未知 client_id 都直达钩子并回 200

- 严重度: 高 ｜ 类别: 安全
- 不变量/性质: 「一个请求只能声明一个经过校验的客户端身份」
- 证据: `upstreamkit/server.go:318-339` `handleCascadeRevocation` 取 `oauth.ClientCredentials(r)` 后
  **直接**把两者塞进 `CascadeRevocationRequest` 交给钩子，没有任何 `AuthenticateClient`/`clients.Get`；
  同文件 `/oauth/token`（`:239-254`）与 `/oauth/authorize` 都把认证交给钩子。实测：
  `TestE1_` 匿名 POST → **200**，钩子收到的 `ClientID=""`/`ClientSecret=""`；`TestE3_` 未知 client_id → 200；
  对照组 `TestE2_`（带凭据）200、`TestE4_`（`/oauth/token` 无身份）401。真实调用方
  `internal/federation/revocation.go:78-79` **确实**会带 Basic——服务端不看。
- 状态: CONFIRMED（子审计已执行；本报告已重跑该断言）
- 影响: 任何能到达该端点的人，只要拿到源签发的 token 值，就能让源结束该 token 所属的**整段上游会话**
  （把用户从所有设备踢下线）；Re0Auth 随后会删除绑定并撕掉 vault 密钥（`internal/federation/revocation.go:146-153`），
  用户绑定被一次伪造请求不可逆摧毁。攻击者不需要注册任何 client。
- 修法建议: 调钩子前先 `s.hooks.OAuth.AuthenticateClient(r.Context(), clientID, clientSecret)`
  （`oauth/service.go:120-123` 已有该方法），失败即 `writeProtocolError`。
- 复现/守卫: `internal/zzprobe/protocol/kit/kit_probe_test.go` —
  `TestE1_CascadeRevocationNeedsNoAuthentication`、`TestE3_CascadeRevocationAcceptsAnUnknownClient`

### KIT-2 一次请求可声明两个客户端身份（Basic 与表单互不校验）

- 严重度: 中 ｜ 类别: 安全
- 不变量/性质: RFC 6749 §2.3「一次请求只能使用一种客户端认证方式」；且「请求里声明的 client_id 与实际记账的客户端相同」
- 证据: `oauth/http.go:33-38` `ClientCredentials` 只要 Basic 存在就整体采用 Basic，表单字段**不读不比对**，
  反之亦然。实测 `TestA2_`：Basic=`conf`+正确 secret、表单 `pub`+**错误** secret → 200。
  对照 `TestA0_` 诚实路径成功。**未观察到提权**（Basic 胜出且其 secret 必须正确）。
- 状态: CONFIRMED
- 影响: 协议级歧义被下游继承——任何按「表单里的 client_id」判断的代理/WAF/日志，会与 kit 的判断不一致；
  这正是 `internal/oidchttp` 第四轮裁定过的同一形状（那边已落守卫），而**该裁定没有落到公开库 `oauth`**。
- 修法建议: 把 oidchttp 的规则搬进 `oauth.ClientCredentials`：Basic 与表单不一致 → 可判定的拒绝信号。
- 复现/守卫: `kit_probe_test.go` — `TestA2_FormAndBasicMayDisagree`

### KIT-3 被 suspend（乃至被删除）的客户端，其已签发令牌仍 `active`，并能读数据面

- 严重度: 高 ｜ 类别: 安全
- 不变量/性质: `oauth/client.go:33-39` 自述「suspended client ... is reported as unknown by **every protocol entrance**」
  ——实际是 every entrance **except 令牌本身**。
- 证据: `oauth/as.go:253-271` `Introspect` 只查 `s.tokens.GetAccess`，**从不**问 `s.clients`；
  `upstreamkit/server.go:379-399` 的数据面判据就是 `Introspect` + scope。实测 `TestA4_`：
  暂停后 `AuthenticateClient`/`Refresh` 都被拒，但 `Introspect` 仍 `active=true`
  且 `/account` 200；`TestA5_`：删掉客户端行后令牌仍 active。
- 状态: CONFIRMED
- 影响: 运维「暂停客户端」对已发出的令牌完全无效（最长一个 access TTL，默认 1 小时），
  且端点全部报 `invalid_client` 造成「已经掐掉」的错觉，唯独数据面照旧可读。
- 修法建议: `service.Introspect` 在返回 active 前调 `s.clients.Get(ctx, at.ClientID)`（suspended 已折叠成
  not found），取不到即 `active=false`；或在 `ClientAdmin.SetStatus/Delete` 里连带 `RevokeTokens(TokenFilter{ClientID})`。
- 复现/守卫: `kit_probe_test.go` — `TestA4_SuspendedClientTokensStayLive`、`TestA5_DeletedClientTokensStayLive`、`TestE10_DataPlaneRequiresTokenAndScope`

### KIT-4 失败的兑换会**先消费**授权码：知道 code 就能让合法客户端永久拿不到令牌

- 严重度: 中 ｜ 类别: 可用性 / 安全（定向 DoS）
- 不变量/性质: 「授权码单次使用」被实现成「第一次**尝试**即消费」，于是「谁消费」与「谁有权消费」解耦
- 证据: `oauth/as.go:165` 的 `ConsumeCode` 在 client 绑定（:175）、redirect（:178）、PKCE（:181）校验**之前**；
  两个 store 的消费都是无条件删除（内存 `tokens.go:202-213`；PG `internal/store/postgres/oauth.go:36-57`
  `DELETE ... RETURNING`，**读；无 DB 执行**）。实测 `TestC1_`：攻击者用错 verifier 兑换 →
  `invalid_grant: PKCE verification failed`，随后**完全正确**的那次兑换变成
  `authorization code is unknown or already used`；`TestC2_` 四种绑定失败都能烧掉 code。
- 状态: CONFIRMED（PG 侧为读代码到行）
- 影响: 无需 verifier、无需任何凭据，一次 POST 就能把一个用户的一次登录打断（低成本的定向 DoS），
  而失败路径**不写审计**（`record` 只在成功路径，`as.go:156`），运维看不见。
- 修法建议: 把消费移到全部绑定校验之后，或提供带谓词的原子消费
  （PG：`DELETE ... WHERE token_hash=$1 AND client_id=$2 AND redirect_uri=$3 RETURNING ...`）；并给失败加审计信号。
- 复现/守卫: `kit_probe_test.go` — `TestC1_FailedExchangeConsumesTheCode`

### KIT-5 authorize 不校验 `code_challenge` 形状：1 个字符的挑战也发码，而该码永远换不出令牌

- 严重度: 中 ｜ 类别: 可用性
- 不变量/性质: 「发码前必须校验所有影响兑换的字段」；`code_challenge` 是唯一「authorize 不查就没人查」的字段
- 证据: `oauth/as.go:104-106` 只断言非空与 `method == S256`；实测 `TestC4_`：padded 标准 base64、
  截断、大写、**一个字符**的 challenge 都在 authorize 被接受，而它们铸出的码全部
  `PKCE verification failed`；对照组 `empty` 在 authorize 被拒（证明探针走到了该判断）。
- 状态: CONFIRMED
- 影响: 客户端先被带去同意页（用户白授权一次）才在兑换失败；叠加 KIT-4 后 code 被烧，用户必须重走全流程。
  **不是**权限绕过——兑换侧比较是常数时间且严格（`as.go:336-343`）。
- 修法建议: 在 `describe()` 加形状校验（S256 的结果必然是 43 字符 base64url），并与兑换侧共用同一函数。
- 复现/守卫: `kit_probe_test.go` — `TestC4_PKCEChallengeShapeIsNotValidated`

### KIT-6 `RestoreClient` 跳过重定向校验，authorize 会照单全收 `javascript:` 重定向

- 严重度: 中 ｜ 类别: 安全
- 不变量/性质: `oauth/client.go:168-178` 把「重定向永远不是浏览器会解释的文档」写成了不变量，但它只在 `NewClient` 生效
- 证据: `oauth/client.go:180-192`（注释**故意**不校验）＋ `AllowsRedirect`（:159-166）纯字符串相等 ⇒
  authorize 路径上没有任何第二道检查；持久化 registry 的**唯一**读取路径正是 `RestoreClientWithStatus`
  （`internal/store/postgres/oauth.go:443-447,549-569`）。实测 `TestB3_`：restored 客户端带着
  `javascript:alert(document.cookie)` 通过 `DescribeAuthorization`；对照组 `TestB2_` 证明 9 种危险形态在注册期全被拒。
- 状态: CONFIRMED（**浏览器行为属常识，未实测**：作者据「现代浏览器不在 `Location:` 上执行 `javascript:`」定级）
- 影响: 谁能写进 registry，谁就决定 authorize 把 code 送到哪里。(a) 把授权响应渲染成链接/自行前端跳转的源实现
  会得到存储型 XSS；(b) 「registry 里的重定向 URI 都安全」这句话对生产库是假的。
- 修法建议: 在 `Client.AllowsRedirect` 里先跑一遍已存在的 `validRedirectURI`（纯函数，一处收口覆盖三个调用点）；
  加启动自检把历史遗留的坏行记为 error 级日志。
- 复现/守卫: `kit_probe_test.go` — `TestB3_RestoreClientSkipsRedirectValidation`

### KIT-7 conformance 对客户端认证**零断言**：声明 `client_secret_basic` 却谁都不认证的源零 error 通过

- 严重度: 中 ｜ 类别: 可维护性 / 合规（假保证）
- 不变量/性质: 「conformance 是 spec 的可执行形态」——它对所断言的每条性质都必须能失败
- 证据: `upstreamkit/conformance/conformance.go:183-205` 读了 `token_endpoint_auth_methods_supported`
  却从不使用；全套流程唯一带客户端身份的请求都是**未知客户端**（`conformance-unknown-client`），
  没有任何一步先成功、再用错凭据断言失败；`checkCascadeEndpoint`（`:295-297`）唯一判据是
  `status == 404`，**200 就算 PASS**。实测 `TestF2_`：一个「谁都不认证」的源
  `errors=0 warnings=0`，无身份令牌 200；`TestF3_`：套件确实打了 cascade 端点、确实用了未知 client，
  判定仍 PASS。对照组 `TestF1_` 证明套件本身会失败（`errors=2`）。
- 状态: CONFIRMED
- 影响: 三方源与参考源可以拿到一份**不覆盖**「源会认证它的客户端」这条核心信任假设的「合规」结论；
  一个不能失败的 conformance suite 是假保证（与 BRIEF 的反空转要求正相反）。
- 修法建议: 加两条零成本断言：未知 client_id 打已宣告端点必须 4xx（能立刻抓住 KIT-1）；
  `Options` 增加可选 `ClientID/Secret` 时跑「正确凭据 200 / 错误凭据 401」对照。
- 复现/守卫: `kit_probe_test.go` — `TestF2_ConformanceIgnoresClientAuthentication`、`TestF3_ConformancePassesAnUnauthenticatedCascade`

### KIT-8 无 `Content-Length`（chunked/gzip）的超限 body 回 `400 malformed form body` 而非承诺的 `413`

- 严重度: 低 ｜ 类别: 可用性 / 可观测性
- 证据: `oauth/bodylimit.go:27-35` 只在 `r.ContentLength > MaxFormBytes` 时给 413，长度未知时走
  `http.MaxBytesReader`，其 `MaxBytesError` 被 `ParseForm` 包装成普通错误 →
  `upstreamkit/server.go:240-243/296-299/319-322` 一律 400。实测 `TestE6_`：
  declared → 413；chunked → 400；gzip（151 wire bytes）→ 400。
- 状态: CONFIRMED（**没有绕过**：`TestE6b_` 证明把 `grant_type` 藏到 64 KB 之后不会执行）
- 影响: 上限封住了攻击面，但「有人在灌大 body」这件事在两套仪表盘上都不可见（不进 413 计数），
  调用方也无法区分「表单写错」与「body 太大」。
- 修法建议: 对 `ParseForm` 的错误做 `errors.As(*http.MaxBytesError)` 分类后再回答 413。
- 复现/守卫: `kit_probe_test.go` — `TestE6_BodyLimitVariants`（对照组 `TestE6b_` 钉住「无绕过」）

### KIT-9 两份 well-known 文档都没有 `Cache-Control` / `Vary`

- 严重度: 低 ｜ 类别: 合规 / 可用性
- 证据: `upstreamkit/server.go:169-185` 只 `writeJSON`；实测 `TestE7_`：两份文档
  `Cache-Control=""`、`Vary=""`，而同服务其它响应（token 错误）是 `no-store`。
  同仓库 `internal/httpapi/responses.go:102,117` 与 `health.go:64` 都设了 `no-store`——kit 是唯一漏处。
- 状态: CONFIRMED
- 影响: 发现文档随部署变化（含 `cascade_revocation_endpoint` 的出现与消失）。中间层可长期缓存，
  把 Re0Auth 指向已被移除的端点；用户侧却已经把「该源支持全部登出」展示出去了
  （`internal/httpapi/binding_routes.go:96`）。
- 修法建议: 两处补 `Cache-Control: no-store`（或显式 `public, max-age=<短>` + `Vary: Host`）。
- 复现/守卫: `kit_probe_test.go` — `TestE7_DiscoveryCacheHeaders`

### KIT-10 `ClientAdmin.Delete` 只删客户端行、不删其令牌

- 严重度: 低 ｜ 类别: 合规/隐私 / 可维护性
- 证据: `oauth/client.go:423-428`、`internal/store/postgres/oauth.go:515-518` 都只删客户端行；
  实测 `TestA6_`：删除后该 subject 的令牌行仍有 2 条，且 `TestA5_` 显示仍 `active`。
  与 `oauth/grants.go:33-42`「令牌即授权、不存在第二个真相」冲突。
- 状态: CONFIRMED
- 影响: 「一个运维以为已彻底移除的客户端，仍持有一小时的可读令牌，且授权列表上是一条没有名字的记录」。
  不是跨账号读写，故低。
- 修法建议: 让 `Delete` 的契约包含令牌清理（`RevokeTokens(TokenFilter{ClientID: id})` 已存在），
  或明确写进文档把责任交给调用方。
- 复现/守卫: `kit_probe_test.go` — `TestA6_DeleteClientLeavesTokenRows`

> KIT 区域另有 **13 项「探过但没破」**（重定向逐字节严格 12 变体、注册期 URI 校验 9 形态、
> revoke 归属校验与失败无副作用、scope 偷渡 9 形状全无效、omitted/empty scope 不降级、
> 令牌熵与不可枚举性、PKCE 常数时间且 `plain` 被拒、设备流三处旧修复仍在、discovery 与实现一致……）
> 与 **7 项残余盲区**（PG 全部只读；HTTP/2 下 body 上限未实测；conformance 未对真实第三方源跑过；
> 设备端点不在本仓库组合根上；KIT-6 的浏览器行为属常识；multipart 行为未测；协议面 401 无 challenge
> 未写断言故未列为 finding）。完整清单见 `_fragment_kit.md`。

---

## 探过但没破的（这些也应变成守卫）

全部为**已执行**的探针，且都先跑对照组确认路径真的走到（反空转）：

1. **redirect_uri 精确匹配 19 种扩展全部被拒，且拒绝形状正确**（400 JSON、**绝不重定向**）：
   追加 query / 追加 fragment / `../` / 结尾斜杠 / 前缀 / 大小写折叠 host / `:443` / 其它端口 /
   `https→http` / `userinfo@` / `%63b` 路径 / `%2e` 主机 / `//` / 反斜杠 / 首尾空白 / 换行 / 大写 scheme / 空串。
   令牌端点侧对已存 redirect_uri 也是精确比较（`?x=1` 扩展 → `invalid_grant`）。
   → `TestProbeRedirectURIMustMatchExactlyAndRefusalsDoNotRedirect`
2. **授权码生命周期**：单次使用（重放失败）；绑定到客户端（另一个**持有自己正确 secret** 的机密客户端换不到）；
   绑定 verifier（错 verifier → 400）；**缺 verifier → 400**；失败兑换会烧掉 code（fail-closed，
   与 ADR-0005 第 8 条一致，代价是知道 code 的人可 DoS 它 —— 记录方向，不主张改）。
   → `TestProbeAuthorizationCodeLifecycle`
3. **刷新不能提权**：11 种写法（越界 scope、逗号、JSON 数组样、尾随空白/换行、tab、`scope[]`、
   大写 `OPENID`、`offline_access` 单独、组内重复）全部拒绝或收窄；子集刷新可用且报告准确；
   **无 `openid` 的刷新不发 id_token**；重复 `scope` 参数在正规请求下 400。
   → `TestProbeRefreshGrantCannotWidenScope`
4. **客户端认证**：`client_secret_basic` 与 `client_secret_post` 在令牌端点都可用；机密客户端空 secret/错
   secret → 401（含 `WWW-Authenticate: Basic`）；公开客户端**不能**冒充机密客户端（它拿不到 scope 检查之外的
   东西）；未知 client_id → 401。
   → `TestProbeClientAuthenticationAtTheTokenEndpoint`
5. **双身份规则在 `token`/`introspect`/`revoke` 上都成立**（三个用例全部 400；且诚实路径——只用 Basic、
   或两处写同一客户端——仍然可用）。注意：这条规则在 `adversary_test.go` 里**只钉了设备端点**，
   本探针补上另外三处。
   → `TestProbeTwoClientIdentitiesAreRefusedOnTheAuthenticatedEndpoints`
6. **设备流绑定**：无 `client_id` → 400/401；未批准轮询 → `authorization_pending`；**别的客户端拿别人的
   `device_code` 轮询 → `access_denied`（不泄露、不签发）**；立刻二次轮询 → `slow_down`。
   → `TestProbeDeviceFlowClientBinding`
7. **不支持的授权类型/响应类型都干净失败**：jwt-bearer、client_credentials、token-exchange、password、
   空 grant_type、带 `client_assertion` 的请求 —— 全部 4xx（**无 500**）、OAuth JSON、且**不吐任何 token**；
   六种 `response_type` 变体全部经**已注册的** redirect_uri 回错误（无 open redirect、无 `code`）。
   → `TestProbeUnsupportedGrantsAndResponseTypesFailCleanly`
8. **discovery 广告的端点都真的存在**，且其失败一律保持协议平面形状（JSON + `error`）。
   → `TestProbeAdvertisedEndpointsExistAndTheJWKSIsPublicOnly`
9. **JWKS 只含公开参数**（无 `d`/`p`/`q`）、`kty=RSA`/`alg=RS256`、`kid` 非空且**不重复**
   （`ValidateSigner` 的重名检查在装配层，本探针从产物侧再钉一次）。
   → `TestProbeAdvertisedEndpointsExistAndTheJWKSIsPublicOnly`
10. **form_post 的 HTML 转义**：授权响应页由 `html/template` 渲染（`pkg/op/auth_request.go:643-678`），
    实测注入面是空的——`code`/`state` 是 base64url/JWE，`error_description` 来自库的固定文案；
    页面带 `Cache-Control: no-store`。**没有 XSS 面**（唯一仍开着的口子是 PROTO-7 的 `iss` 缺失）。
11. **`-race` 可跑**，全套探针无 DATA RACE（含并发设备轮询、并发刷新场景下的既有守卫）。
    `go test -race ./internal/zzprobe/protocol/` → 只有上表 7 条断言失败，无竞态告警。
12. **公开客户端在 `device_authorization` 上带任意 Basic 仍被接受**（记录为形状）：库要到**令牌**那一步才用
    `clientAuthenticated != IsConfidentialType(client)`（`pkg/op/device.go:235-238`）拒绝，因此这类客户端
    会拿到一个**永远换不出令牌**的 device_code。属互通陷阱（低），未单列发现。
13. **不透明令牌的形状与键行为**（`TestProbeOpaqueAccessTokenShape`，PASS）：令牌是 5 段 compact JWE，
    明文头只有 `{"alg":"A256GCMKW","enc":"A256GCM","iv":…,"kid":"probe","tag":…}`（**不泄露 subject**）；
    翻改密文、截断（尾部/中间/只留 4 段）、`alg` 改写为 `dir` 一律被拒（AEAD 认证 + go-jose 的算法白名单）；
    用**另一把 32 字节 key** 加密的令牌被拒；加密是**随机化**的（同一明文两次密文不同 ⇒ 无相等性预言机，
    `pkg/op/crypto.go:51-72` 用 `jose.NewEncrypter` 生成随机 CEK+IV）；明文确实形如
    `<43 字符 tokenID>:usr_probe`（可用 `Config.CryptoKey` 直接解出，说明**持有那把 key 即持有全部令牌的
    可读性** —— 与 threat-model §6.0.1 的边界一致，非新问题）；**轮换契约成立**：
    新 key + `RetiredTokenKeys` 旧 key 能解出旧令牌，只有新 key 则拒绝。
14. **`CompositeCrypto` 按顺序试密钥、不看头里的 `kid`**（`pkg/op/crypto.go:103-112`，读代码到行 +
    上面第 13 条的实测佐证）：因此不存在「改写 kid 让令牌用错密钥解出」的构造，`kid` 只用于运维对账。
    （代价是文档把令牌描述成「AES-GCM 加密 `tokenID:subject`」而实际是 JWE —— 措辞不一致，提示级。）

---

## 未能到达（残余盲区）

1. **Postgres 后端**：本机无 Postgres、无 Docker，全部走内存 `memory.NewOIDCStore`。
   PG 侧本报告中**唯一的实质差异点**是 PROTO-2 的 `SetUserinfoFromScopes`（`internal/store/postgres/oidc.go:576-579`
   同样是 no-op → 生产同样缺 `sub`，**读代码到行**）与 PROTO-4 的 `AuthorizeClientIDSecret`
   （`internal/store/postgres/oidc.go:562-574`，判据逐字相同，**读代码到行**）。其余发现（PROTO-1/5/6/7/8/9）
   全部落在与后端无关的 `internal/oidchttp` 一层。**这些 PG 结论均未执行。**
2. **`idp/`（re0auth 作为 RP）与 `upstreamkit/`＋`oauth/` 引擎**：由同一轮的另外两个并行子代理负责，
   结论见本文件 `RP-*` 与 `KIT-*` 两节。我已**独立重跑**他们的探针包（RP 12 条 FAIL / KIT 13 条 FAIL，
   与他们的发现条数对应），并抽检了 RP-1/RP-2 与 KIT-1/KIT-3/KIT-7 的关键代码位置；其余推理未逐行复核。
   他们各自的残余盲区与判断在其片段文件里，我没有吸收全部细节。
3. **浏览器 e2e（Playwright/Chromium）**：未运行，因此「真实 RP 用这张没有 `sub` 的 id_token 会怎样」
   只到「标准要求 + 库行为」这一层，没有端到端录像。
4. **密钥轮换在活令牌上的行为**（`RetiredTokenKeys` / `RetiredSigningKeys` 的实际重叠）需要装配层
   （`cmd/re0auth`）才能构造，本探针只在 `oidchttp.Config` 层构造单密钥；`CompositeCrypto` 的
   「不看 kid、按顺序试」语义**读代码到行**（`pkg/op/crypto.go:103-112`），未构造跨密钥用例。
5. **`oauth/` 遗留引擎的设备决策/存储**（第三轮已修）与 **`upstreamkit` 生成面的客户端认证**未由本作者覆盖。
6. **限流参数的实际默认值**（`internal/httpapi` 的 `Limiter` 由 `cmd/re0auth` 决定）：本报告只证明
   PROTO-11 的斜率存在，**没有**证明线上默认桶能吸收多少。

---

## 判断（文档化决定可否质疑，不是 finding）

1. **`introspection_clients` 的语义应收紧为「机密客户端」**：现在配置与文档（`config/re0auth.example.toml:88-90`、
   `docs/api-design.md:46`、`docs/protocol-hardening-decision.md` 第 10 条）只说「显式登记」，没有说明
   「登记一个公开客户端 = 匿名可读全量内省」。PROTO-4 是这条决定的**后果**，不是决定本身；
   若维持现状，至少要把这句话写进配置注释与文档。
2. **`prompt=none` 需要一个裁定**：实现它要引入「wrapper 能问会话」的接口（PROTO-6 的修法），
   这与 O-9「不实现 Session Management」并不冲突（`prompt=none` 是授权请求参数，不是 session management），
   但确实扩大 wrapper 与 `internal/httpapi` 的耦合面。**建议单独裁定，而不是顺手实现。**
3. **`response_mode` 该不该接受**：库支持 `query`/`fragment`/`form_post`，discovery 一个都没广告。
   本报告倾向「拒绝非空 `response_mode`」（最小、自洽），但这会拒掉一批真实客户端（它们的默认可能是
   `form_post`）；若保留 `form_post`，就应广告 `response_modes_supported` 并补 `iss`（PROTO-7）。
4. **`userinfo` 在没有 `openid` 时也返回 `sub`（PROTO-10）**：这是**被测试固定**的形状
   （`TestUserinfoReturnsOnlySub` 用的就是无 `openid` 的 scope），可以辩称「`sub` 是 OAuth 数据授权的一等
   内容，不是 OIDC 专属」。但那样 O-2 的表述（「无 `openid` 绝不返回身份断言」）就过强了，
   应改成「只约束 `id_token`」。二者取一，别让文档与测试互相打脸。
5. **`LegacyServer` 是公开库里的第二套语义**：`pkg/op/server_legacy.go:234-238` 对机密客户端跳过 PKCE 校验，
   而 `oauth/` 与 `upstreamkit/` 是公开库、外部使用者可能用 `RegisterLegacyServer` 形态。
   与本项目无关，但它是「薄封装假设库行为」这一课的最新例证（接缝清单条目 12）。
6. **RP 区域的三条判断**（详见 `_fragment_rp.md`）：(a) RP-1/RP-3 属于「go-oidc 明确不补、包装层必须自己补」
   的类型（`verify.go:250` 自述不做 azp 判定、`oidc.go:87-104` 的 Azure 例外、`jwks.go` 的命中即返回缓存）；
   (b) RP-4 不应被当作配置知识，而应让内置默认值启动即报错或显式裁定放宽；
   (c) 「把非 OIDC provider 配成 OIDC」（给 GitHub/QQ 也填 issuer）会把信任根从 HTTP 响应换成另一个 discovery 端点，
   属运维决策 —— 记为判断而非发现。
7. **KIT 区域的两条判断**：`Introspect` 不接收调用者身份（`oauth/as.go:253`）是设计选择，只要它永远不被接到
   公开的 introspect 端点上；两份 well-known 文档由两段代码各自手写，会漂移，正确做法是让 metadata 从
   `Discovery` 结构体派生（一次重构，属裁定）。

---

## 文件与守卫

新增探针（**只新建，未改任何已跟踪文件**）：

- `internal/zzprobe/protocol/fixture_test.go` —— 夹具（真实 `oidchttp.New` + httptest + 内存 store，
  机密/公开/窄范围三个客户端，`withIntrospection` 用于在同一部署上切换内省白名单）
- `internal/zzprobe/protocol/dupbypass_test.go` —— **PROTO-1**
  （`TestProbeUnparsableBodyDefeatsTheDeviceScopeGate`、`TestProbeUnparsableBodyDefeatsTheDuplicateParameterRefusal`）
- `internal/zzprobe/protocol/idtokens_test.go` —— **PROTO-2 / PROTO-3 / 双身份守卫**
  （`TestProbeIDTokenIsMissingTheSubjectClaim`、`TestProbeNonAccessTokenJWSIsAcceptedAtUserinfo`、
  `TestProbeTwoClientIdentitiesAreRefusedOnTheAuthenticatedEndpoints`）
- `internal/zzprobe/protocol/seam_test.go` —— **PROTO-4 / PROTO-5 / PROTO-8 / PROTO-10**
  （`TestProbeIntrospectionAllowlistWithAPublicClientIsAnonymousRead`、
  `TestProbeConfidentialAllowlistEntryStillNeedsItsSecret`、`TestProbePublicClientIDIsNotASecret`、
  `TestProbeDiscoveryAdvertisesClientSecretPostForIntrospection`、
  `TestProbeUserinfoAnswersWithoutOpenIDScope`、`TestProbeDiscoveryIsCachedFromTheFirstRequestsHost`）
- `internal/zzprobe/protocol/discovery_test.go` —— **PROTO-6 / PROTO-7 / 端点真实性守卫**
  （`TestProbeFormPostAuthorizationResponseHasNoIss`、`TestProbePromptNoneIsIgnored`、
  `TestProbeAdvertisedEndpointsExistAndTheJWKSIsPublicOnly`）
- `internal/zzprobe/protocol/lifecycle_test.go` —— 守卫 + 设备流 id_token
  （`TestProbeRedirectURIMustMatchExactlyAndRefusalsDoNotRedirect`、`TestProbeAuthorizationCodeLifecycle`、
  `TestProbeRefreshGrantCannotWidenScope`、`TestProbeClientAuthenticationAtTheTokenEndpoint`、
  `TestProbeDeviceFlowClientBinding`、`TestProbeDeviceFlowIDTokenIsAlsoMissingTheSubject`）
- `internal/zzprobe/protocol/parseform_test.go` —— **PROTO-9** 与 `ParseForm` 接缝 / PROTO-1 的根因
  （`TestProbeUnparsableBodyHidesParametersFromThePreFlights`、
  `TestProbeTokenEndpointAcceptsItsParametersFromTheQueryString`、
  `TestProbeParseFormIsErrorOnceThenNil`、`TestProbeUnparsableBodyChangesWhatTheOPValidates`）
- `internal/zzprobe/protocol/tokens_test.go` —— **PROTO-3b** 与不透明令牌形状守卫
  （`TestProbeUserinfoIgnoresExpiryAndRevocation`、`TestProbeOpaqueAccessTokenShape`）
- `internal/zzprobe/protocol/grants_test.go` —— **PROTO-11** 与授权类型守卫
  （`TestProbeUnsupportedGrantsAndResponseTypesFailCleanly`、`TestProbeAnonymousAuthorizeAllocatesPendingRequests`）
- `internal/zzprobe/protocol/debug_test.go` —— 一次性诊断（`TestDebugIDTokenBearer`，定位 PROTO-2 用；
  可删）
- `internal/zzprobe/protocol/rp/` —— **RP-1 … RP-9** 的探针（平行子审计；`idtoken_test.go`、`builtin_test.go`、
  `consent_test.go`、`e2e_test.go`、`fakeop_test.go`）
- `internal/zzprobe/protocol/kit/` —— **KIT-1 … KIT-10** 的探针（平行子审计；`kit_probe_test.go`）

跑法：`go test ./internal/zzprobe/protocol/ -v`、`go test ./internal/zzprobe/protocol/rp/ -v`、
`go test ./internal/zzprobe/protocol/kit/ -v`（都可加 `-race`，本机可用且无 DATA RACE）。
`go test ./internal/archtest/` 会因这些新包报 "unregistered module package"，按简报这是预期的。
