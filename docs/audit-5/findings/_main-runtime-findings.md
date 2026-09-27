> **本文件由主代理所有。任何子代理都不要删除或改写它。** 它记录了主代理在**真实进程/真实测试**上
> 核实过、且已排除「构建产物不一致」「端口占用」等测量伪影的发现。若你发现它是空的或缺失，
> 说明有人误删了它——请报告，不要重建。

# 主代理独立发现（已核实）

四个发现都属于同一类：**文档化的不变量被打破，而现有守卫在结构上看不见它**。
其中 M-RT-3 是**阻断上线**级。

---

## M-RT-3 【阻断上线】`id_token` 里**没有 `sub` 声明**：OIDC Core §2 的必需声明被静默抹掉

- 严重度: **阻断上线**
- 类别: 安全（身份）+ 协议正确性
- 状态: **CONFIRMED（已执行 + 根因到行）**

### 证据（已执行）

`internal/zzprobe/protocol/idtokens_test.go`（协议审计代理所写，主代理复跑确认）：

```
$ go test ./internal/zzprobe/protocol/ -run TestProbeIDTokenIsMissingTheSubjectClaim -v
=== RUN   TestProbeIDTokenIsMissingTheSubjectClaim
    idtokens_test.go:40: authorization_code: the id_token has no `sub` claim at all
        (claims: [iss exp nonce client_id at_hash c_hash aud iat auth_time azp])
    idtokens_test.go:56: refresh_token: the id_token has no `sub` claim at all
        (claims: [iat auth_time azp client_id at_hash iss aud exp])
    idtokens_test.go:74: userinfo carries sub=usr_probe while the id_token does not
--- FAIL: TestProbeIDTokenIsMissingTheSubjectClaim (0.08s)
```

`sub` 在**两条**签发路径（授权码兑换、刷新）上都缺失；而 `userinfo` 正确返回 `usr_probe`，
所以「先拿 token、再调 `/v1/me`」这种测试链**看不出**这个问题——这正是它活到今天的原因。

运行时旁证（本机真进程，`GET /.well-known/openid-configuration`）：

```json
"claims_supported":["sub"]
```

发现文档**只广告 `sub` 这一个声明**，而它就是唯一没被发出的那个。
来源：`internal/oidchttp/oidchttp.go:159` `SupportedClaims: []string{"sub"}` 与 `:381`。

### 根因（读代码到行——本次审计最精确的一条）

1. `github.com/zitadel/oidc/v3@v3.51.3` `pkg/op/token.go:211`
   `claims := oidc.NewIDTokenClaims(issuer, request.GetSubject(), …)`
   —— **此处 `sub` 是对的**：re0auth 的 `CompleteLogin` 已在
   `internal/store/memory/oidc.go:940` 设好 `a.Subject`，
   `oidcstore.AuthRequest.GetSubject()` 于 `internal/oidcstore/oidcstore.go:222` 返回它。
2. 同文件 `pkg/op/token.go:241-254` 紧接着：
   ```go
   } else if len(scopes) > 0 {
       userInfo := new(oidc.UserInfo)
       err := storage.SetUserinfoFromScopes(ctx, userInfo, request.GetSubject(), request.GetClientID(), scopes)
       if err != nil { return "", err }
       …
       claims.SetUserInfo(userInfo)     // ← 这行把 sub 抹掉
   }
   ```
   而 `pkg/oidc/token.go:158-159` 的 `SetUserInfo` 第一句就是 `t.Subject = i.Subject`。
3. re0auth 两个 store 的 `SetUserinfoFromScopes` 都是**空实现**：
   - `internal/store/memory/oidc.go:685-687`
     ```go
     // SetUserinfoFromScopes implements op.Storage (deprecated upstream; no-op).
     func (s *OIDCStore) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
         return nil
     }
     ```
   - `internal/store/postgres/oidc.go:577-581` 同样。

于是 `userInfo.Subject` 为空 → `claims.SetUserInfo(userInfo)` 把**刚刚正确设好的 `sub` 覆盖成空串**
→ `TokenClaims.Subject` 的 `json:"sub,omitempty"` 把它从 token 里抹去。

`len(scopes) > 0` 在每次真实签发里都成立（`openid` / `account.id` 都在），
所以这不是边缘路径，是**默认行为**。

### 那条「deprecated upstream; no-op」注释是错的

注释假定该回调不再被调用。`v3.51.3` 的 `CreateIDToken` **正在调用它**，而且它是签发路径上
唯一会写 `UserInfo` 的地方（另一处 `SetUserinfoFromRequest` re0auth 未实现，走不到）。
`SetUserinfoFromToken`（`memory/oidc.go:691`）倒是正确设了 subject——但那一路只在
`/oauth/userinfo` 上跑，**不在签发路径上**。两条路径的注释与实现互相矛盾，这就是洞所在。

### 修法（两行）

两个 store 把空实现改成与 `SetUserinfoFromToken` 一致：

```go
func (s *OIDCStore) SetUserinfoFromScopes(_ context.Context, userinfo *oidc.UserInfo, subject, _ string, _ []string) error {
    userinfo.Subject = subject
    return nil
}
```

（只写 `sub`，不写 `profile`/`email`，与 O-3「只暴露 sub」一致——`claims_supported` 已经这么承诺了。）

### 影响

1. **OIDC Core §2 违规**：`sub` 是 ID Token 的必需声明。严格的 RP 直接拒收（登录失败）；
   宽松的 RP 若拿 `id_token.sub` 当用户主键，会把**所有用户归并到同一个空身份**——
   在 RP 侧构成账号混淆/越权，而 re0auth 这边看不到任何异常。
2. 与 `docs/threat-model.md` A8、`docs/architecture.md` §4.4、`docs/oidc-decision.md` O-4 的
   **全部描述相反**，也让 `claims_supported:["sub"]` 成为一句假话。
3. 这是**发布门禁级**的：这个 OP 存在的意义就是「下游一次 OIDC 接入，同时拿到『这是谁』」。
   今天「这是谁」那半边是空的。

### 守卫建议

断言 id_token 里 `sub` **等于已登录的 `usr_…`**（不是只断言 key 存在，那会空转），
并断言 `SetUserinfoFromToken` 与 `SetUserinfoFromScopes` 对同一 subject 给出同一个 `UserInfo.Subject`。

---

## M-RT-4 【高】`id_token` 可以在 `/oauth/userinfo` 当**访问令牌**用（令牌类型混淆）

- 严重度: 高（**当前被 M-RT-3 掩盖，修好 M-RT-3 当天就会显形**）
- 类别: 安全
- 状态: **CONFIRMED（读代码到行；M-RT-3 修复后即可执行复现）**

### 证据（读三方库到行 + 与 M-RT-3 的交互）

`github.com/zitadel/oidc/v3@v3.51.3`：

- `pkg/op/userinfo.go:91-108` `getTokenIDAndSubject`：
  ```go
  tokenIDSubject, err := userinfoProvider.Crypto().Decrypt(accessToken)   // 不透明令牌走这条
  if err == nil { …; return splitToken[0], splitToken[1], true }
  accessTokenClaims, err := VerifyAccessToken[*oidc.AccessTokenClaims](ctx, accessToken, …)  // ← 回退
  if err != nil { return "", "", false }
  return accessTokenClaims.JWTID, accessTokenClaims.Subject, true
  ```
- `pkg/oidc/verifier.go:110-112`：
  ```go
  func DecryptToken(tokenString string) (string, error) {
      return tokenString, nil // TODO: impl
  }
  ```

re0auth 的不透明 access token 由 `provider.Crypto().Decrypt` 解；**id_token 是 JWS，解不开**，
于是走**回退**：当 JWT 解析、用**本 OP 自己的签名公钥**验签。id_token 正是本 OP 签的，
验签通过 → 返回 `(jti="", sub=<id_token 的 sub>)` → 库调
`SetUserinfoFromToken(…, subject, …)`（`internal/store/memory/oidc.go:691`）→ `userinfo.Subject = ` 该 subject。

**今天这条回不来**：M-RT-3 把 `sub` 抹成空串，所以 `Bearer <id_token>` 现在的响应是 `200 {}`。
M-RT-3 一旦按上面两行修好，**同一个请求立刻返回 `200 {"sub":"usr_…"}`**。
两条 bug 互相掩盖，值得单独记一笔。

### 影响

- **数据面 `/v1/*` 不受影响**（已核）：`internal/httpapi/middleware.go:570` 的 `withBearer` 走
  `oidchttp.Handler.Introspect`，它只调 `provider.Crypto().Decrypt`（见 `oidchttp.go` 内
  `func (h *Handler) Introspect`），**没有** JWT 回退 → id_token 会被判 `Active:false`。
  所以这不构成对 `/v1` 的越权。
- 受影响的是 `/oauth/userinfo`：一个**发给 RP 的** id_token 成了该端点上的有效凭据。
  单看收益有限（RP 本来就能用自己的 access token 调 userinfo），但真实风险有三条：
  1. **令牌类型混淆**：id_token 不是 bearer access token，OIDC §16.3 / RFC 9068 的区分被抹掉；
  2. id_token 常被前端（SPA）存进 `localStorage`、被 RP 写进日志或塞进 URL ——
     它的泄露面**远宽于** access token，而这里它变成了可用凭据；
  3. 任何**第三方** client 的 id_token（`aud` 是该 client，不是 userinfo 端点）同样可用。
- 归因：这是三方库 `DecryptToken` TODO 桩 + 回退逻辑的组合。re0auth 的封装修不了库，
  但**可以**在 `internal/oidchttp` 的 userinfo 前置检查里拒掉三段式 JWT 形状的 bearer
  （不透明令牌不是 JWT），代价极小。这一条应作为**判断**记入 `docs/dependencies.md`。

### 守卫建议

`internal/oidchttp/adversary_test.go` 加一条：拿真实签发的 `id_token` 当 `Authorization: Bearer`
调 `/oauth/userinfo`，断言 **401**。**必须在 M-RT-3 修复之后写**，否则它会因为「返回 `200 {}`」假通过。

---

## M-RT-2 【中】`/.well-known/*` 完全不受动词矩阵约束：任意方法回 200 + 文档

- 严重度: 中（文档化不变量被破坏 + 守卫缺口）
- 类别: 安全（契约）+ 可维护性
- 状态: **CONFIRMED（已执行）**

### 证据（已执行，本机真进程）

```
GET/HEAD/POST/PUT/DELETE/PATCH/OPTIONS/TRACE /.well-known/openid-configuration
    -> 200 application/json   （七种非 GET 动词全部 200，且返回完整发现文档）
GET/HEAD/POST/PUT/DELETE/PATCH/OPTIONS/TRACE /.well-known/oauth-authorization-server
    -> 200 application/json

GET/HEAD /.well-known/oauth-protected-resource   -> 200 application/json
POST/PUT/DELETE/PATCH/OPTIONS/TRACE（同一路径）  -> 404 application/json
```

### 与工作区里**未提交**的 CHANGELOG 直接冲突

`CHANGELOG.md`（未提交）写着：

> 「每个端点声明自己的动词，未列出的动词一律 `405`：协议面新增一张 `endpointMethods` 表
> （「已知端点」也由它派生）…… 其余收 `POST`；`PUT`/`DELETE`/`PATCH`/`OPTIONS` 等一律回
> `405` 的 OAuth 错误体，不再落到库或某个没有方法策略的分支。」
>
> 「两面的动词矩阵都从 `specRoutes` / `endpointMethods` 自动派生，各有一条逐一断言的守卫测试。」

### 根因（读代码到行）

- `internal/oidchttp/oidchttp.go:1021-1030` 的 `endpointMethods` 表**只列 `/oauth/*`**，
  没有两份 `/.well-known/*` 文档。
- `internal/oidchttp/oidchttp.go:228-244` 的 `ServeHTTP`：两份发现文档在
  `case r.URL.Path == RFC8414Path` / `== OIDCDiscoveryPath` 里**直接**交给 `serveDiscovery`，
  **完全不查那张表**；只有 `strings.HasPrefix(r.URL.Path, "/oauth/")` 那一路才进 `serveOAuth`。
- 405 守卫在 `internal/oidchttp/oidchttp.go:430`，它**在 `serveOAuth` 里面**，所以发现文档走不到。
- `default` 分支（`:236-244`）对未知 `/.well-known/*` 回 404——这解释了为什么
  `/.well-known/unknown` 形状是对的，而两份**真实**文档对任意动词都 200。

### 为什么守卫看不见它

与 M-RT-1 同源：**断言与实现从同一张手写表派生**。表里没列到的路径，
实现不会拦、守卫也不会测。这是「守卫与被守卫对象共用同一个假设」的典型案例，
也正是项目第三轮审计总结的教训 2。

### 影响

- 让 CHANGELOG 里那条**已经写下**的不变量在协议面上有一个洞——而这份 CHANGELOG 正准备随发布公开。
- `TRACE` 被 200 应答：现代浏览器与中间件层面基本无影响，但它是「服务了哪些动词」这一事实的偏离，
  会让以动词矩阵为审计依据的走查给出错误结论。
- **不是数据泄露**：发现文档完全公开、对所有调用者内容相同、不读会话、不写状态。

### 修法建议

把两份 `/.well-known/*` 文档纳入 `endpointMethods`（GET/HEAD，其余 405 OAuth 形状），
并把守卫改成**从 `http.ServeMux` 的实际注册表反推**，而不是从手写表反推——
否则下一个新端点会以完全相同的方式漏掉。

---

## M-RT-1 【中】业务平面会返回 `text/html` 307（三平面契约泄露）

- 严重度: 中（契约/守卫缺口；无直接可利用性）
- 类别: 安全（不变量）+ 可维护性
- 状态: **CONFIRMED（已执行，本机真进程）**

### 证据

```
$ curl -s -D - -o NUL "http://127.0.0.1:8080/v1//me"
HTTP/1.1 307 Temporary Redirect
Content-Type: text/html; charset=utf-8
Location: /v1/me

# 同一时刻，内网监听器上的指标
re0auth_http_requests_total{method="GET",plane="business",status="307"} 2   # 请求前
re0auth_http_requests_total{method="GET",plane="business",status="307"} 3   # 请求后
```

这条响应**被记成业务平面**（限流器与指标都按业务平面处理它），身体却是 `net/http` 的
`text/html` 重定向页，不是 problem+json。

同样成立：`GET //v1/me` → 307 `text/html`；`GET //oauth/token` → 307 `text/html`。
对照：`GET /v1/./me`、`GET /v1/x/../me`、`GET /%2e%2e/v1/me` → 401 `application/problem+json`（形状正确）。

### 根因（读代码）

`internal/httpapi/server.go` 的 `Handler()` 把 `root`（一个 `http.ServeMux`）放在最内层。
`net/http` 的 `ServeMux` 会在**任何 handler 之前**，对非规范请求路径（双斜杠、`.`/`..` 段）
发出 301/307 重定向——这段响应不经过 `writeProblem`、`writeOAuthError`、`handleNotFound` 中的任何一个。
而 `planeOf(r.URL.Path)`（`internal/httpapi/middleware.go:489-503`）对 `/v1//me` 判为 `planeBusiness`，
判定与响应形态因此不一致。

### 为什么现有守卫看不见

`internal/httpapi/plane_test.go` 的走查从 `specRoutes()` 派生路径，而它们都是**规范路径**；
清理重定向只在非规范路径上触发，走查在结构上永远走不到。
与第三轮审计教训 2 完全同形。

### 影响

- 破坏 `docs/api-design.md` §1/§6 与 `server.go` 包注释写明的「三平面各自形状」不变量。
- 业务平面客户端（读 problem+json 的 API 消费者）在非规范路径上拿到 HTML。
- **不构成开放重定向**：`Location` 是 mux 清理出的相对路径，不由调用方控制。
- **不构成 CSRF 绕过**：本服务的 CSRF 是 `X-CSRF-Token` 头，跨站表单设不了。

### 修法建议

在 `root` **外面**再包一层：`r.URL.Path` 与规范化结果不同时自己发 307，
并按 `planeOf` 用对应平面的写出器渲染。守卫要改成从 `http.ServeMux` 实际注册表 +
一组非规范路径上走查，而不是只走 `specRoutes()` 的规范路径。

---

## 已排除的候选（**不是**发现；记下来以免有人重复踩）

- **`GET /app/_app/immutable/entry/*.js` 返回 index.html（`text/html`）**：最初以为是 SPA 回退
  吞掉静态资源的真缺陷。核实后是**测量伪影**——审计期间有子代理重跑了前端构建
  （`internal/webui/dist` mtime 23:55:21），而我当时运行的二进制编译于 23:52:15，
  嵌入的是构建前那份 `dist`，于是新哈希文件名在旧 embed 里查不到、回退到 index.html。
  重新构建二进制后即正常（`dist/_app/immutable/assets/*.css` 当时就已正确返回
  `text/css` + `max-age=31536000, immutable`，正是因为 CSS 内容未变、哈希未变）。
  **教训**：任何「静态资源返回了 HTML」的观测，先核对二进制与 `dist` 的时间戳。
- **`/v1/admin/*` 在未配置管理员时回 404**：符合文档（允许列表为空则整个平面不挂载）。
- **协议面未回显 `Origin`**：实测带 `Origin: https://evil.example` 的 GET 与 `OPTIONS` 预检，
  **没有任何 `Access-Control-Allow-*` 头**，与 `docs/cors-decision.md`（ADR-0011）一致。
  `/.well-known/*` 与 `/oauth/{userinfo,keys}` 上的 `Vary: Origin` 是提供方库内部 CORS
  中间件留下的痕迹，但没有 ACAO 就没有跨源授权——**不构成 CORS 暴露**。
- **会话 cookie 名**：`internal/auth/auth.go` 在 `Secure: true` 时用 `__Host-r0semi_session`，
  否则用 `r0semi_session`；与 `docs/architecture.md` §4.8 一致（非 Secure 前缀在明文 HTTP 下
  本来也无法使用）。**不是文档漂移**。
- **前端 CSP**：`internal/webui/dist/index.html` 的 `<meta http-equiv="content-security-policy">`
  确实存在（小写属性名，大小写敏感的正则匹配不到），内容为
  `default-src 'self'; connect-src 'self'; font-src 'self'; img-src 'self' data:; object-src 'none';
  script-src 'self' 'sha256-…'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'none'`，
  与 HTTP 头的 `frame-ancestors 'none'` 合起来正是文档描述的「两层各自拿自己需要的」。
  无 `unsafe-inline`/`unsafe-eval` 的 `script-src`；SPA 里没有原生 `<form>`，故 `form-action 'none'` 安全。
- **限流**（真跑过，正确）：伪造 `X-Forwarded-For` **不能**换桶——固定 XFF 与轮换 XFF 两轮突发
  都在**第 101 个请求**开始 429（`rate_limit_burst = 100`）；并发 1920 请求时 shed 1523。
  429 的形状也对：业务面 `application/problem+json` + `code=rate_limited`，
  协议面 `{"error":"temporarily_unavailable"}`，两者都带 `Retry-After: 1` 与
  `RateLimit-Remaining: 0`。探针：`internal/zzprobe/livecheck`（`ratelimit` / `burst` / `reject`）。
- **启动期配置校验**（真跑过，全部 fail-closed，退出码 1，消息精确）：
  缺 `RE0AUTH_ISSUER` / `RE0AUTH_KEK` / `RE0AUTH_OIDC_TOKEN_KEY` / `RE0AUTH_OIDC_SIGNING_KEY` 各自拒绝；
  `RE0AUTH_KEK` 非 32 字节拒绝；`RE0AUTH_OIDC_TOKEN_KEY` 非 32 字节拒绝；
  **1024 位 RSA 签名密钥拒绝**（`signing key must be at least 2048 bits, got 1024`）；
  非 PKCS#8 的签名密钥拒绝；`server.internal_addr` 与 `addr` 相同拒绝；
  `internal_addr` 绑非 loopback 而未 `expose_internal=true` 拒绝；`trusted_proxies` 非法条目拒绝；
  非法 TOML 拒绝并给出精确行列；**没有配置文件时进入「environment only」模式**（README 第二种写法成立）；
  显式 `-config` 指向不存在的文件才拒绝。
  `-version` 打印 `re0auth dev`；`-print-secret-env` 在无配置文件时明确报错而不是猜。
- **`X-Request-Id` 被原样采纳**（客户端可自定义）：属**低**severity 观察而非缺陷——
  Go 的 `net/http` 在写响应头时会剥掉 CR/LF（实测 `evil\r\nX-Injected: 1` 被截成 `evil`，
  未发生响应头注入）。代价是 `request_id` 不是可信关联标识；建议加
  `^[A-Za-z0-9_.-]{1,64}$` 校验或一律自生成。
- **`-migrate-down` 无二次确认**：`cmd/re0auth/main.go:1065-1076` 只要求 `DATABASE_URL`，
  回滚一步后退出。`docs/migration-decision.md`（ADR-0008）已把「回滚故事是恢复备份，不是 down」
  写清楚，属**已文档化的运维动作**，记为判断而非缺陷。
