# HTTP 边缘审计报告（路由 / 中间件 / 会话 / CSRF / 限流 / 请求解析）

> 区域缩写：**HE**（HTTP Edge）。审计对象：`internal/httpapi`、`internal/auth`、`internal/account`、
> `internal/ratelimit`、`internal/compress`、`internal/webui`，以及 `cmd/re0auth/main.go` 的 HTTP 服务器构造。

## 范围与方法

**读过并逐行核对的文件**（全部读到行）：

- `internal/httpapi/`：`server.go`、`middleware.go`、`responses.go`、`clientaddr.go`、`health.go`、
  `discovery.go`、`session_routes.go`、`account_routes.go`、`admin_routes.go`、`audit_routes.go`、
  `authorization_routes.go`、`binding_routes.go`、`device_routes.go`、`export_routes.go`、
  `federation_routes.go`、`grants_routes.go`、`identity_routes.go`、`idp_routes.go`、`v1_routes.go`
- `internal/auth/auth.go`（`Manager`、CSRF、`/auth/{provider}/{start,callback}`）、`internal/account/account.go`
- `internal/ratelimit/ratelimit.go`、`internal/compress/compress.go`、`internal/webui/webui.go`
- `internal/oidchttp/oidchttp.go`（为第 5 条的 CORS/Cache 判定跨包核对）
- `internal/safeurl/safeurl.go`（`return_to` 的守卫）
- `oauth/bodylimit.go`
- `cmd/re0auth/main.go`（`newServer`、超时常量、`internal_addr` 监听器）

**跑了什么**

```sh
go vet ./internal/httpapi/                 # 通过（注意：期间他人探针文件曾令本包编译失败，见「未能到达」）
go test ./internal/httpapi/ -run 'TestZZProbe' -v -count=1 -timeout 300s
```

`-race`：本机需要 cgo，**未运行**；本报告不含任何由竞态检测器背书的并发结论。
Postgres 路径：本机无 DB，**全部未执行**（本次范围内也几乎没有 Postgres 专属结论）。

**探针文件**（只新建，未修改任何已跟踪文件）：
`internal/httpapi/zzprobe_httpedge_test.go` —— 同包（需要 `planeOf`、`newFullConfig`、`newOPBackend`、
`newTestEnv` 等未导出符号），文件名带 `zzprobe_httpedge`，与同目录他人的
`zzprobe_adminpriv_test.go`、`zzprobe_mrt_test.go` 无命名冲突。全部测试函数名以 `TestZZProbe` 开头。

**跑了 18 个探针，3 个失败**——即下面列出的 HE-1、HE-2、HE-4（HE-1 的两条探针中有一条作为守卫通过）。
另有一条 `TestZZProbeMrtEquivalentsAreAntiVacuous`（HE-10）是本次复核后补的，通过。

**关于编译中断（我的责任，已修）**：`zzprobe_httpedge_test.go` 一度缺 `context` 导入
（报告方看到的 `zzprobe_httpedge_test.go:1091:28: undefined: context`），
期间 `internal/httpapi` 整体编译不过，会同时打断别人的 `go test`/`go vet`/`-race`。
这是我的文件、我的错误，已修；`go vet ./internal/httpapi/` 与
`go test -c ./internal/httpapi/` 当前都返回 0。我随后把「改完立刻编译」作为每次编辑的固定动作。

**关于 `docs/audit-5/` 下的删除（我核查过，不是我）**：我在 `docs/audit-5/` 下
**创建过**一个临时 Go 模块目录 `docs/audit-5/_urlprobe/`（为了实测 net/http 对
`%2F`、`;`、`//`、`./` 的解码行为），并在用完**删除了它自己**：

```powershell
Remove-Item -Recurse -Force ".scratchpad\audit\_urlprobe"
```

除此之外我在 `scratchpad/` 下没有执行过任何删除或改写。三点核对：

1. PowerShell 5.1（本机 `5.1.26100.9444`）**把 `[`/`]` 当字面量**，对不含通配符的字面路径
   不做展开。我用一个同名包含 `[` 的路径实测过：
   ```
   after: urlprobe=False zzprobe=True     # 只删了目标，同名"通配"路径仍在
   ```
2. 同一个下午若那条命令真的展开了通配，`internal/zzprobe`（内含 17 个子目录）、
   `vault/zzprobe_crypto_test.go`、`oauth/zz_probe_test.go` 会一起消失；它们**至今都在**。
3. 我的报告文件 `findings/http-edge.md` 的时间戳是 `0:15:41`，而
   `findings/_main-runtime-findings.md` 与 `runtime/re0auth.exe` 的时间戳都比它**更早**
   （`runtime/re0auth.exe` 是 `23:57:44`，且当前仍在）。也就是说这两个对象在我写出报告之前
   就已经存在（或已经缺失并被恢复），我没有任何时机会删掉它们。

结论：**我没有删除 `_main-runtime-findings.md`，也没有删除 `docs/audit-5/runtime/` 下的任何东西**；
`runtime/` 现存内容与我第一次列目录时看到的不一致，但那个变化不是我的操作造成的。
我把 `docs/audit-5/**` 当只读共享输出目录对待，唯一例外是我自己建的 `_urlprobe`（已删）。
`zzprobe_mrt_test.go` 也**不是我写的**（创建时间 `0:01:11`，比我读到该 findings 文件的时刻还早；
我的探针是 `zzprobe_httpedge_test.go`，创建于 `23:53:51`），因此我没有以它的名义主张任何东西，
也没有修改它——其断言由我自己的 HE-10 在**我的**文件里独立覆盖。

---

## 发现

### HE-1 限流的分桶键由调用方决定，桶上限又允许任意淘汰活桶 —— 限流可被完全绕过，且会重置诚实客户端的配额

- 严重度: **高**
- 类别: 安全
- 不变量/性质: 「按客户端地址限流」这条唯一的入站节流对一类部署完全失效；
  且限流器会把自己承诺维护的桶丢弃，并给下一个请求一个**全新满额桶**
- 证据:

  分桶键在 `internal/httpapi/middleware.go:349`：
  `key := planeOf(r.URL.Path).String() + "|" + s.clientKeyOf(r)`；
  `clientKeyOf` → `clientAddr`（`internal/httpapi/clientaddr.go:23`）在**对端落在 `trustedProxies` 内**时
  采用 `X-Forwarded-For`，否则用对端地址。`server.TrustedProxies` 就是反代部署的设置。

  另一头是键的上限（`internal/ratelimit/ratelimit.go`）：`defaultMaxKeys = 10_000`、`shardCount = 16`
  （`perShard() = 625`），插入新键时调 `evictLocked`（`:213`）：样本只有 `evictionScan = 64` 条，
  首选「超过 TTL（10 分钟）的桶」，**找不到就删迭代器给出的第一个键**（`:232-234`）。
  新桶一律以满 burst 创建（`:147`）。于是：

  1. **键空间不是调用方能耗尽的**：每个新键 = 一次免费请求；
  2. **到了上限之后**，每次新键既淘汰一个**活桶**（可能是别人的），又给自己发一个满额桶。

  实测（`TestZZProbeRateLimitKeySpaceIsUncapped`，`ratelimit.New(0.001, 1)` 即「一千秒一个令牌」，
  经由真实 `Handler()`，对端 `10.1.2.3` 在信任列表内）：

  ```
  control: 同一地址第 1 次 = 401，第 2 次 = 429        # 限流确实接上了
  one peer, 20000 distinct X-Forwarded-For values, rate=0.001/s: admitted=20000 refused=0
  ```

  **一条 TCP 连接、零等待，拿到 20000 次放行**；配置的速率是「每 1000 秒 1 次」。

  对照（`TestZZProbeRateLimitIsFailClosedUnderAKeySpray`，不配信任列表）：`map[401:1 429:49]` ——
  默认姿态是对的，所以这不是「fail-open」，而是「配置了反代之后分桶键归调用方」。

  附带一半（`TestZZProbeRateLimitSprayResetsAnHonestClientsBucket`，20 次独立试验）：

  ```
  6/20 trials: another client's key spray discarded the victim's exhausted bucket and
               served it as if it had spent nothing
  ```

  机制完全确定（一次 `delete` 落在受害者桶上，下一次请求就得到满额桶），命中与否取决于
  64 条随机样本里有没有那条键；20 次试验里 6 次命中。**诚实客户端刚被 429 的桶会被另一个客户端
  的键喷洒重置**，而限流器对此没有任何记录。

- 状态: **CONFIRMED**（两条都有实际执行的测试）
- 影响: 攻击者实际得到的是「无限次请求」而不是「每 1000 秒 1 次」。限流是这组昂贵端点上**唯一**的
  节流手段（`/oauth/token`、`/oauth/device_authorization`、`/oauth/introspect`、`/oauth/authorize`、
  `/v1/games/.../raw/{path...}` 的上游代理、`/v1/account/export` 的全量聚合、`/v1/admin/*`），
  于是它同时是：①密码/授权码/设备码的暴力破解成本归零；②上游与数据库的成本放大（每个被放行的请求
  都会真的走到 handler 并做一次上游调用或一次查询）；③审计归因可被伪造（访问日志里的 `client=`
  正是这个键，`middleware.go:264`）。第二半的收益是让**别的**客户端失去配额上限（可以让某个 NAT
  出口下的所有人被 429，也可以反过来把受害者刚用完的额度还给他）。
  注意这不是「洪水」级别的 DoS：键空间被 10000 封顶，内存是**有界**的
  （`maxKeys` 生效，且 `evictLocked` 每次插入最多扫 64 条，插入成本不随表大小增长），
  所以它是一条**绕过**，不是一条**放大器**。
- 修法建议: 分桶键不要包含任何调用方控制的字符串。
  - 最小改法：`clientKey` 在信任链解析失败或结果不可信时**退回对端地址**（现在是「整条链不信→退回对端」，
    已经对；问题在于**可信**的那一半本身产出的是调用方写的值）——也就是说，只要反代是**追加**而不是
    **覆盖** XFF，这个设计就成立不了。可选的收敛方向：
    (a) 增加 `server.client_addr_header`（默认 `none`，可选 `x-forwarded-for`）并对配置的信任网络
    只取**最右侧**一条（由最近的代理写入），忽略左侧的全部内容；
    (b) 或者把限流键换成**服务端能自己算的东西**（连接五元组 + 认证后的 client/user），
    这与 `api-design.md` §2.7「按 client/user 的配额模型尚未定义」正好是同一次裁定；
    (c) 无论如何，`ratelimit` 的淘汰**绝不能删活桶**：达到上限时应拒绝新键（fail-closed，新键共用
    一个兜底桶），而不是删掉别人已经花掉的额度。删活桶等于把「限流」变成「每 10 分钟重置一次」。
- 复现/守卫: `internal/httpapi/zzprobe_httpedge_test.go`
  `TestZZProbeRateLimitKeySpaceIsUncapped`（**当前失败** = 有洞）、
  `TestZZProbeRateLimitSprayResetsAnHonestClientsBucket`（当前通过，试验数为 20 时命中 6 次——
  它是一个**概率性守卫**，失败即代表淘汰路径连一次都没命中）、
  `TestZZProbeRateLimitIsFailClosedUnderAKeySpray`（通过 = 默认姿态正确）。

---

### HE-2 授权响应与登录跳转都不带 `Cache-Control`，而它们的 `Location` 里是授权码与授权请求句柄

- 严重度: **中**
- 类别: 安全 / 合规
- 不变量/性质: 「凡是承载令牌、会话或 PII 的响应都必须 `no-store`」——`api-design.md` §1 对
  `token` 响应写了这条，§2.5 对业务面写了这条，但**3xx 授权响应不在任何一张表里**。
  这是一条契约漏掉的格子，不是有人违反契约。
- 证据: `internal/oidchttp/oidchttp.go:521-527` 的 Cache 策略只覆盖
  `introspection`/`userinfo`/`keys`（外加 `isToken`），**不含** `authorize`。实测
  （`TestZZProbeAuthorizationRedirectCarriesNoCacheDirective`）：

  ```
  login redirect:        302 Location="/login?authRequestID=2GOA81UXe4KbF75nspuhGYufK-7A_uuBFQhFfz7O41Y"
                              Cache-Control="" Pragma=""
  authorization response: 302 Location="https://app.example/cb?code=eyJhbGciOiJBMjU2R0NN...&iss=...&state=st"
                              Cache-Control="" Pragma=""
  ```

  两条都是 `internal/oidchttp` 的 `bufferedWriter` 直接 flush 出去的，没有任何缓存指令。
  对照：同一函数对 `/oauth/token`、`/oauth/introspect`、`/oauth/userinfo` 显式设了 `no-store + Pragma`。
- 状态: **CONFIRMED**（实际执行）
- 影响: 授权码是**单次使用**的短寿命密钥；`authRequestID` 是能被换成授权码的句柄。
  它们出现在 302 的 `Location` 里，而 302 属于 RFC 9111 §3 「heuristic freshness」的适用范围：
  浏览器与中间缓存**可以**在没有显式指令时按启发式缓存它（Chrome/Firefox 对 302 默认不缓存，
  但企业代理与某些 CDN 会）。缓存键是 URL，不含 `Set-Cookie`，也没有 `Vary`：一个共享缓存若缓存了
  这条响应，下一个人用不可能的 URL 去取就拿到别人的 `code`。纵深防御层面这也不是空话——
  `Referrer-Policy: no-referrer` 是全局的、`Cache-Control` 不是，后者恰好是**唯一**能覆盖
  「浏览器把 Location 留在本地」的手段。
- 修法建议: 在 `serveOAuth` 的 Cache 策略里加一条：`isAuthorizationResponse(r.URL.Path)` 时对
  3xx 也设 `Cache-Control: no-store`（`/oauth/authorize` 与 `/oauth/authorize/callback` 都算，
  成功与失败都算）。这是一行改动，且与已有的 `isAuthorizationResponse` 判据同源。
  另外建议把这条写进 `docs/api-design.md` §3 的表里——它现在是隐形的。
- 复现/守卫: 同文件 `TestZZProbeAuthorizationRedirectCarriesNoCacheDirective`（**当前失败**）。

---

### HE-3 `X-Forwarded-For` 的完整性判定与主流反代默认行为不一致：原样转发的反代下，限流 Bucket 归调用方所有

- 严重度: **中**（部署相关；配置得当则不存在）
- 类别: 安全 / 可用性
- 不变量/性质: 「只有对端是我们自己的代理时才信 XFF，且从右往左取第一个不可信的」这条规则，
  在**代理是追加而不是覆盖** XFF 时结论相反：从右往左会走到调用方自己写的那条。
- 证据: `internal/httpapi/clientaddr.go:60-67` 的从右往左遍历本身是对的；
  问题在它的**前提**——「最右侧那条是离我们最近的代理写下的」。这个前提只在
  「信任网络上只有我们自己的代理，且它**覆盖** XFF」时成立。
  nginx 的 `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`、Traefik 与 Cloudflare
  的默认行为都是**追加**。此时 `X-Forwarded-For: <攻击者写的任意值>, <真实客户端>`，
  服务端取到的是**最右侧不可信地址 = 真实客户端**（这没错）；但攻击者如果**只**写一个值、
  且真实客户端地址被代理写在它右边，取的仍然是真实地址——真正的破坏发生在**代理只追加、不写真实地址**
  的配置上（例如 `X-Forwarded-For: $http_x_forwarded_for, $remote_addr` 写反、或上层 CDN 已经写过）。

  更直接的一条：`clientaddr.go` **只**读 `X-Forwarded-For`，完全不看 `X-Real-IP` / `Forwarded` /
  `X-Client-IP` / `CF-Connecting-IP`（`TestZZProbeClientAddrIgnoresOtherForwardingHeaders` 逐条确认，
  15 个变体：`unknown`、`host:port`、`[2001:db8::1]`、前后空白，全部按预期忽略或在信任时正确解析）。
  这**是**正确的收紧，但反过来也意味着：一个部署若在反代上按 `X-Real-IP` 传真实地址、而反代**不**写 XFF，
  限流会退化成「所有客户端共用一个桶」——即下一条。
- 状态: **CONFIRMED**（边界行为逐条实测）；「某个真实反代怎么写 XFF」是 **HYPOTHESIS**，
  本次没有起 nginx/Caddy/HAProxy 去验（见「未能到达」）。
  要证实：起一个 `proxy_set_header X-Forwarded-For $http_x_forwarded_for`（纯追加）的反代，
  从客户端发两次不同 XFF，断言服务端拿到的是客户端写的那条。
- 影响: 若成立，HE-1 的第一半在**没有任何错误配置**的部署上就成立；
  若不成立（代理覆盖 XFF），HE-1 仍通过桶淘汰这一半成立，但需要一个能选地址的上游。
- 修法建议: 同 HE-1 (a)。另建议在 `docs/api-design.md` §2.7 的「地址怎么算」里明确写出
  对反代的要求：**必须覆盖 `X-Forwarded-For`，而不是追加**，并给出 nginx 的正确写法
  （`proxy_set_header X-Forwarded-For $remote_addr;`）。现在那句话只说「列表过宽等于把选择权交回调用方」，
  但没有说代理该覆盖。
- 复现/守卫: `TestZZProbeClientAddrIgnoresOtherForwardingHeaders`（守卫，通过）。

---

### HE-4 编码路径下的业务面 404 绕过了 `/v1` 那一层的 `no-store` 与 panic 恢复器

- 严重度: **低**
- 类别: 安全 / 可维护性
- 不变量/性质: 「平面判定只有一处定义」在**错误形状**上成立，在**中间件覆盖**上不成立：
  同一平面有两条不同的响应路径，一条带平面的包装、一条不带。`server.go` 的注释
  （`handleNotFound` 上方，`:683-697`）正是为解决这个问题写的，它解决了形状，没解决包装。
- 证据: `server.go:506` 是 `root.Handle("/v1/", s.businessPlane())`，而 `businessPlane()`
  在 `:661` 用 `withNoStore(mux)` 与 `recoverBusiness` 包住 mux。Go 的 mux 按**转义后**的路径匹配，
  所以 `/v1%2Fnope` 不匹配 `/v1/`，落到 `root.HandleFunc("/", s.handleNotFound)`；
  而 `handleNotFound` 按 `planeOf(r.URL.Path)`（已解码）判为业务面，于是回 problem+json ——
  **但不再经过 `withNoStore`，也不经过 `recoverBusiness`**。实测
  （`TestZZProbeEncodedBusinessPathSkipsThePlaneWrappers`）：

  ```
  /v1/nope         -> 404 "application/problem+json" Cache-Control="no-store"
  /v1%2Fnope       -> 404 "application/problem+json" Cache-Control=""
  /v1%2F..%2Fme    -> 404 "application/problem+json" Cache-Control=""
  /v1%2Fme         -> 404 "application/problem+json" Cache-Control=""
  ```

  同一平面、同一状态码、几乎同一 body，只有缓存指令不同。panic 那一半同理：
  `handleNotFound` 上方的注释说「最外层 recoverBrowser 兜住」，兜住是兜住了，但答案会是
  **text/plain 500 而不是 problem+json 500** —— 即 `docs/api-design.md` §6 明确要求的
  「业务面的 panic → problem+json 500」在编码路径上不成立。
- 状态: **CONFIRMED**（缓存指令，已执行）；panic 形状是 **HYPOTHESIS**
  （读代码到行：`server.go:698-710` 的 `handleNotFound` 不在 `recoverBusiness` 内，
  `recoverBrowser` 用 `http.Error`）。
- 影响: 直接收益很小——404 的 body 只有固定文案与回显给调用方自己的路径，没有 PII。
  真实代价是**不变量不再是一条**：任何依赖「业务面必然 `no-store`」的审计（含第 2 轮 A5-4 的守卫
  与第 4 轮 raw 那条）都必须知道存在一条例外路径。这是「未来某条 handler 重新打开旧洞」的同款
  结构性缝隙，只是这次缝隙在路由器边界上。
- 修法建议: 把 `withNoStore` 提升到平面级而不是 mux 级——即 `handleNotFound` 在
  `case planeBusiness:` 分支里先 `w.Header().Set("Cache-Control", "no-store")`（或在
  `withNoStore` 里按 `planeOf` 判定，让 `/v1/*` 的两种拼写走同一段代码）；
  同时给 `handleNotFound` 的 business 分支套一层 `recoverBusiness` 语义（最省事的做法是把
  `handleNotFound` 的两个分支委托给已有的平面写出器，并让 `recoverBrowser` 在 panic 时按
  `planeOf` 而不是固定 text/plain 作答）。
- 复现/守卫: 同文件 `TestZZProbeEncodedBusinessPathSkipsThePlaneWrappers`（**当前失败**）。

---

### HE-5 会话 Cookie 的受众是整个源（`Path=/`），会被送到 `/oauth/*` 与 `/v1/*`

- 严重度: **提示**
- 类别: 安全（纵深防御）
- 不变量/性质: 「凭据只在需要它的路径上出现」
- 证据: `internal/auth/auth.go:111` `sm.Cookie.Path = "/"`（`Domain` 未设置，
  `Secure` 由部署声明，`SameSite=Lax`，`HttpOnly`）。实测两条部署模式下的真实 `Set-Cookie`
  （`TestZZProbeSessionCookieAttributes`，真实登录流程，非构造函数读取）：

  ```
  secure=false: r0semi_session=...; Path=/; Max-Age=7201; HttpOnly; SameSite=Lax
  secure=true : __Host-r0semi_session=...; Path=/; Max-Age=7201; HttpOnly; Secure; SameSite=Lax
  ```

  `__Host-` 前缀的浏览器契约全部满足（有 `Secure`、`Path=/`、无 `Domain`），这一点是对的；
  但 `Path=/` 意味着浏览器会把会话 cookie 发给 `/oauth/token`、`/oauth/authorize`、
  `/v1/games/.../raw/{path...}` 等**完全不需要它**的路径。
- 状态: **CONFIRMED**（头值已执行）
- 影响: 会话 cookie 出现在更多请求里 ⇒ 更多日志/代理/上游可能看到它。最值得注意的是
  `raw` 透传：它是唯一把**外部内容**带回本源、且内容由配置的数据源控制的响应
  （`docs/api-design.md` §4 已经为它单独加了 CSP + `attachment`，理由正是「它落在持有会话 cookie
  的源上」）。会话 cookie 跟着这条请求走，是同一类担忧里唯一还没被处理的一格。
  另外：`__Host-` 前缀**要求** `Path=/`，所以不能简单改成 `Path=/app` 而不放弃前缀——
  这是一个真正的取舍（要么全局路径 + `__Host-`，要么收窄路径 + 放弃前缀），不是随手可改的。
- 修法建议: 建议改 `Path=/app`（浏览器面）并保留 `Secure`/`HttpOnly`/`SameSite=Lax`，
  明确放弃 `__Host-` 前缀；或者保留现状，把「会话 cookie 会发给 `/oauth/*`」这一条写进
  `docs/browser-plane-decision.md` 或 `docs/account-model.md` 的明确边界里。
  属于需要裁定的取舍，不宜由审计顺手改。
- 复现/守卫: 同文件 `TestZZProbeSessionCookieAttributes`（同时钉住 `__Host-` 契约、
  `HttpOnly`、`SameSite`，以及**注销后同一 cookie 不再能通过 `/v1/sessions/current`**——
  后者已执行并通过）。

---

### HE-6 `/oauth/protected-resource` 与 `.well-known` 的成功响应是 `application/json`，而它们的失败是 problem+json

- 严重度: **提示**
- 类别: 可维护性 / 兼容性
- 不变量/性质: 「协议平面不得输出 problem+json」。守卫
  （`internal/httpapi/plane_test.go` 的 `assertOAuthPlane`）只在 `rec.Code >= 400` 时断言，
  所以 200 响应上的 `Content-Type` 从未被检查。
- 证据: `internal/httpapi/server.go:496` 把 `GET /.well-known/oauth-protected-resource` 交给
  `handleResourceMetadata`，后者用 `writeJSON`（业务面写出器，`responses.go:115`）→
  `Content-Type: application/json`。而同一命名空间下的**所有其他**失败（含
  `/.well-known/oauth-protected-resource/x` 与 `.../`）由
  `internal/oidchttp/oidchttp.go:243` 的 `writeOAuthJSONError` 以
  `{"error":"invalid_request",...}` 作答。实测（`TestZZProbeEncodedAndOddSpellingsKeepTheirPlane`
  与 `TestZZProbePlaneShapeHoldsForEveryMethodAndSpelling`）：

  ```
  GET /.well-known/oauth-protected-resource   -> 200 application/json   (RFC 9728 资源元数据)
  GET /.well-known/oauth-protected-resource/  -> 404 application/json {"error":"invalid_request",...}
  GET /.well-known/oauth-protected-resource/x -> 404 application/json {"error":"invalid_request",...}
  ```

  并且 `POST` 到该路径会得到 Go mux 自己写的 **405 problem+json**
  （`mux.go` 的 `writeError` → `Error(w, StatusText(405), 405)`，Content-Type 为
  `application/problem+json`）——这是整个协议平面上**唯一**一处 Go 标准库在服务端之前
  替我们决定的错误形状。两者都是「协议平面上的非 OAuth 形状」，但用户实际收益为零，
  所以只列提示。
- 状态: **CONFIRMED**（三种拼写/方法实测）
- 影响: 一个严格按平面解析的客户端在这一条路径上会看到与其它 `/.well-known/*` 不同的
  `Content-Type`，并在 405 上看到 problem+json。RFC 9728 说资源元数据的媒体类型是
  `application/json`，所以 200 那半**可能是对的**；但既然平面判定已经声明
  「`/.well-known` 全是协议面」，就应当要么明确把这条路径的行写进
  `docs/api-design.md` §3 并说明它为什么是个例外，要么让它在 `s.oidc` 里（或至少让 405 走平面的写出器）。
- 修法建议: 二选一：①在 `docs/api-design.md` §3 的表里写清 protected-resource 是 RFC 9728
  的资源元数据、成功体是 `application/json`（并在 `assertOAuthPlane` 里为它开一个有注释的白名单），
  同时把 405 的 `Content-Type` 覆写成 `application/json`；②更彻底：把该端点也交给
  `s.oidc`，由它统一写出。推荐 ①，因为改动面最小且不需要动协议实现。
  另外建议把 `plane_test.go` 的走查从「只断言 4xx」扩成**同时断言 200 的 Content-Type**，
  这正是它今天看不见这一格的原因。
- 复现/守卫: `TestZZProbeEncodedAndOddSpellingsKeepTheirPlane`、
  `TestZZProbePlaneShapeHoldsForEveryMethodAndSpelling`。

---

### HE-7 会话/授权跳转之外的 307 由 Go mux 生成，无 `Content-Type` 也无缓存指令

- 严重度: **提示**
- 类别: 可维护性
- 不变量/性质: 「平面判定驱动全部失败形状」——mux 自己生成的临时跳转不经过任何平面写出器。
- 证据: 实测（`TestZZProbeEncodedAndOddSpellingsKeepTheirPlane`，18 拼写 × 2 方法）：

  ```
  GET  /oauth//token   -> 307 Location="/oauth/token"  Content-Type="text/html; charset=utf-8"
  POST /oauth//token   -> 307 Location="/oauth/token"  Content-Type=""
  GET  /v1//me         -> 307 Location="/v1/me"        Content-Type="text/html; charset=utf-8"
  POST /v1//me         -> 307 Location="/v1/me"        Content-Type=""
  ```

  6 个拼写 × 2 方法 = 12 次跳转，全部是同一平面内的路径规范化（**跨平面不存在**：
  `/v1/../oauth/token` 这类我逐一验证过，目标仍在原平面）。GET 时 Go 会给一个
  `text/html` 的 `<a href>` 体（`http.Redirect` 的行为），POST 时无体。
- 状态: **CONFIRMED**（实际执行，日志中逐条打印）
- 影响: 无安全后果（301 一条都没有，全是 307，且无跨平面）。列出来是因为它与 HE-4 同源：
  「路由器与平面判定的边界」是这套设计里唯一没有单一出口的地方，而它已经产出过一条真发现
  （`handleNotFound` 的编码路径分支）。把这两条放在一起看，修法也应当是同一处。
- 修法建议: 不需要为 307 做任何事；但如果按 HE-4 的建议把平面包装提升到路由器边界，
  这些跳转自然也在平面里。
- 复现/守卫: 同上。

---

### HE-8 会话不绑定设备/方法，`SameSite=Lax` 允许顶层跨站 GET 携带会话，而 `/oauth/authorize` 是 GET 且以 302 离开本源

- 严重度: **低**
- 类别: 安全（需更高前提）
- 不变量/性质: 会话的作用域应当与它授权的动作匹配；GET 不应有安全后果。
- 证据（读代码到行 + 边界实测）：

  1. `internal/auth/auth.go:110`：`SameSite=Lax`。Lax 允许**跨站顶层导航**携带 cookie，
     这正是 `POST /oauth/authorize` 在第二轮被修成「方法无关预检」所要防的形态之一。
  2. `GET /oauth/authorize`（`internal/oidchttp/oidchttp.go:476` → `validateAuthorize`）在**没有会话**
     的标准形状下，把浏览器 302 到 `/login?authRequestID=<id>` 或 `/app/consent?id=<id>`
     （`newOPBackend` 的 login 钩子即此形状；实测 `TestZZProbeAuthorizationRedirectCarriesNoCacheDirective`
     看到 `/login?authRequestID=...`）。**该 id 此刻只是句柄**，任何人都还不能用它换取任何东西。
  3. 但**有会话**时（`cmd/re0auth` 的 login 钩子会把 id `sessions.Bind(ctx, "authz", id)`，
     `internal/httpapi/authorization_routes.go:55` 的 `authzBindKind` 与之一致），
     `consentHandle`（`:72-81`）只查 `Bound` + `OwnerMatches` —— **不查返回地址、不查 Referer、
     不把「授权请求最初是被谁发起的」写进记录**。也就是说，一个跨站顶层导航
     `https://op/oauth/authorize?...` 会让受害者的浏览器带着会话走完全程，
     并在 `Location` 里把 `authRequestID`（或最终 `code`）交给**攻击者控制的 Referer 链**。
  4. 唯一的屏障是 `Referrer-Policy: no-referrer`（`middleware.go:84`，全平面生效）与
     `SameSite=Lax` 本身；这两条都已实测存在（`TestZZProbeRootRedirectCarriesItsQuerySafely`
     钉住了根跳转不会把 `?next=//evil.example` 之类的查询当成新源）。
- 状态: **HYPOTHESIS**。**端到端不可在无浏览器下证明**：探针覆盖的是
  「①会话 cookie 的属性、②`/oauth/authorize` 在有无会话时分别写什么 `Location`、
  ③根跳转与登录跳转不会把查询串里的第三方 URL 当成跳转目标、④全局 `Referrer-Policy: no-referrer`
  确实在响应头上」。**没有**覆盖的是浏览器是否会在某个真实场景下把 Referer 发出去
  （那需要 Chromium 与一个真实跨站页面，本机未跑 `pnpm test:e2e`）。
  要证实它需要：一个攻击者页面，其中 `<img src="https://op/oauth/authorize?...">`
  （或顶层导航），以及服务端在授权请求上记录/校验发起方；然后断言 cookie 与 Referer 是否外泄。
  按 `docs/oidc-decision.md` 的取舍（不做 PAR、不做 Session Management），
  「授权请求不绑定发起方」很可能是有意接受的残余——所以它更可能是一条**判断**而不是发现。
- 影响: 若成立，攻击者可能拿到受害者的一次授权码；缓解链（Lax + no-referrer + PKCE 必须由
  客户端持有 verifier）让这条路径很难走通——**它需要攻击者同时是客户端**，
  而那时它本就有 redirect_uri 与 client_id。
- 修法建议: 不建议为它引入 PAR（那是明确不做的决定）。最小动作是把这条残余**写下来**：
  在 `docs/oidc-decision.md` 的 O-9 或 `docs/threat-model.md` §9 加一句
  「授权请求不绑定发起方，跨站顶层导航会为已登录用户创建一条绑在本浏览器上的授权请求；
  缓解是 SameSite=Lax + 全局 no-referrer + PKCE」。
- 复现/守卫: 无（假说）。相关已通过守卫：`TestZZProbeRootRedirectCarriesItsQuerySafely`、
  `TestZZProbeSessionCookieAttributes`。

---

### HE-9 管理员可请求的审计 `limit` 没有服务端上限

- 严重度: **提示**
- 类别: 性能
- 不变量/性质: 已授权调用不应能用一个查询参数决定服务端的一次分配量。
- 证据: `internal/httpapi/audit_routes.go:54-61`：`strconv.Atoi` 后只校验 `limit < 1`，
  **不设上限**，直接赋给 `audit.Query.Limit` → `auditReader.Query`（Postgres 侧即一条 `LIMIT n`）。
  一个已认证的管理员可以发 `GET /v1/admin/audit?limit=2147483647`。同一文件对
  `cursor`/`since`/`until` 的校验都很严（含第三轮 B3-3 的零值拒绝），只有 `limit` 没有上界。
- 状态: **CONFIRMED**（读代码到行；本机无 DB，未执行 Postgres 侧）。
  为什么不需要执行就能断定：校验只比较下界，`q.Limit` 未经任何钳制就进入查询构造，
  这是本文件内可枚举完的一小段代码。
- 影响: 单次调用即可让进程与数据库分配与传输与 `limit` 成正比的内存/带宽。
  前提是**已经是管理员**（本部署的 `Admins` 允许列表），所以收益有限；但审计读取端点
  **不要 CSRF**（设计如此，`docs/api-design.md` §4 明确写了「只读的 GET 除外」），
  这意味着它可以被一次单纯的顶层导航触发——于是「管理员被诱导打开一个链接」
  就能变成一次内存/带宽压力事件。这正是「GET 无副作用」这条隐含前提在分配量上的例外。
- 修法建议: 在 `audit_routes.go` 加一个与 store 默认页大小一致的上限
  （例如 `maxAuditPage = 1000`，超出则 400 `invalid_request`），
  并把它写进 `docs/openapi.yaml` 的 `limit` 约束（现在文档只写了 `minimum: 1`）。
- 复现/守卫: 无（读代码到行；Postgres 侧不可达）。

---

### HE-10 两处「路由器与平面判定的边界」的独立复核（含对照组与指标标签，均已实测）

- 严重度: **提示**（本身不是新洞；它是 HE-4 与 HE-7 的**非空转证据**，
  以及 `docs/audit-5/findings/_main-runtime-findings.md` 那两条运行时发现的独立复核）
- 类别: 可维护性
- 不变量/性质: 同一平面上由两个不同组件（Go mux 与 `planeOf` 驱动的包装）分别作答时，
  两者的答案必须可区分、且必须落在同一个平面里。
- 证据: `TestZZProbeMrtEquivalentsAreAntiVacuous`，三个子测试各自带**对照组**，
  所以「两条路径碰巧长得一样」无法让它通过：

  1. **双斜杠与点段是 307，不是落空**（对照：`/v1/nope` 必须**不**跳转）：
     ```
     control  /v1/nope      -> 404 "application/problem+json"
     /v1//nope          -> 307 Location="/v1/nope"          Content-Type="text/html; charset=utf-8"
     /v1/./nope         -> 307 Location="/v1/nope"          Content-Type="text/html; charset=utf-8"
     /v1/../v1/nope     -> 307 Location="/v1/nope"          Content-Type="text/html; charset=utf-8"
     /oauth//token      -> 307 Location="/oauth/token"      Content-Type="text/html; charset=utf-8"
     /oauth/./token     -> 307 Location="/oauth/token"      Content-Type="text/html; charset=utf-8"
     ```
     每条都额外断言两件事：`planeOf(Location) == planeOf(raw)`（跳转**没有跨平面**，
     这是真正的安全性质），以及 GET 的体是 HTML（`http.Redirect` 的行为）而
     `Cache-Control` 为空——即这条响应完全由 Go 决定，不带本服务的任何指令。
  2. **转义斜杠走上另一条路**（对照：`/v1/nope` 必须真正带 `no-store`，否则比较无意义）：
     ```
     control  /v1/nope     -> 404 "application/problem+json" Cache-Control="no-store"
     escaped  /v1%2Fnope   -> 404 "application/problem+json" Cache-Control=""
     ```
     断言的是**两者不同**：形状相同（这一半做对了）而指令不同（这一半漏了）。
  3. **指标标签的后果**（`Config.Metrics` 打开，抓 `metrics.Handler()` 的文本）：
     ```
     /v1//nope   -> re0auth_http_requests_total{method="GET",plane="business",status="307"} 4
     /v1%2Fnope  -> re0auth_http_requests_total{method="GET",plane="business",status="404"} 3
     ```
     两条路径都按业务面记账——这**不是**缺陷（标签与错误形状一致，正是设计意图），
     但它说明「同平面两条路径」这件事在运维视图上也是同一个平面，
     所以 HE-4 的修法不会改变任何已有面板。
- 状态: **CONFIRMED**（实际执行，三个子测试全绿）
- 影响: 无新增可利用面。交付物是：HE-4 与 HE-7 现在有了一条**能失败**的守卫
  （把 `no-store` 补上、或让 mux 的跳转也走平面写出器，这条测试就会变绿），
  以及 `_main-runtime-findings.md` 那两条运行时发现在 HTTP 边界上被独立复核过一遍。
- 修法建议: 同 HE-4（把平面包装提升到路由器边界）。HE-7 不需要改。
- 复现/守卫: `internal/httpapi/zzprobe_httpedge_test.go`
  `TestZZProbeMrtEquivalentsAreAntiVacuous`（当前三个子测试**全绿**）。
  其中子测试 2 的判据是「两条拼写**必须**给出不同的 `Cache-Control`」：
  等 HE-4 修好（两边都带 `no-store`）时它会失败并提示改判据——
  那正是它作为守卫的用法，也是它与只打日志的探针的区别。

---

## 探过但没破的（这些也应变成守卫）

以下每条都是**实际跑过**的，探针都在 `internal/httpapi/zzprobe_httpedge_test.go` 里：

1. **CSRF 覆盖是完整的。** 逐条走 13 个非 GET 的会话态路由，每个路由**一台全新的已登录服务**
   （否则前一条路由的副作用——`sign_out` 销毁会话、`DELETE /v1/account` 抹除账号——
   会让后面全部变成「没有会话」的 401，这正是本探针第一版给出的**假绿**）。
   实测：7 条真正走到 CSRF 检查的路由里，**无 token 与错 token 一律 403**，0 条未强制：
   ```
   POST   /v1/sessions/sign_out                  valid=204 wrong=403 absent=403
   POST   /v1/device/decision                    valid=404 wrong=403 absent=403
   POST   /v1/authorization_requests/{id}/decision valid=404 wrong=403 absent=403
   DELETE /v1/grants/{client_id}                 valid=204 wrong=403 absent=403
   DELETE /v1/identities/{id}                    valid=404 wrong=403 absent=403
   DELETE /v1/account                            valid=200 wrong=401 absent=401
   DELETE /v1/bindings/{game}/{source}           valid=200 wrong=403 absent=403
   POST   /v1/bindings/{game}/{source}/cascade_revocation valid=400 wrong=403 absent=403
   ```
   （`DELETE /v1/account` 的 `wrong=401` 是**修法正确的证据**：错 token 没有抹掉账号，
   所以下一条请求仍有会话；`valid=200` 才是那一次真的抹除了。）
   未走到的 6 条是 `/v1/admin/*`（本 Config 的 `Admins` 是 `usr_admin`，当前账号不是管理员 ⇒ 404）：
   它们**读代码到行**全部经由 `requireAdminWrite`（`admin_routes.go:77-98`），
   该函数先 `requireAdmin` 再 `ValidCSRF` 再 `adminReauth`。
2. **跨站表单打不到任何写端点。** 42 次尝试（每个非 GET 路由 × `application/x-www-form-urlencoded`
   / `text/plain` / `multipart/form-data`），**0 次被接受**。原因是所有写端点都解 JSON 体
   （`json.NewDecoder` 对表单体失败 ⇒ 400），且写请求需要 `X-CSRF-Token`
   ——**自定义头是跨站表单永远设不上的**。这是结构性成立，不只是「碰巧」。
3. **平面契约在 168 组「拼写 × 方法」上零泄漏。** 24 个路径拼写 × 7 个方法
   （含 `PUT/PATCH/OPTIONS/DELETE/HEAD` 打到已知路径、未知方法、`/.well-known` 子树的各种写法），
   按 `planeOf` 分类逐条断言「协议面不出 problem+json / 业务面不出 `{error}` / 浏览器面两者都不出」。
4. **编码与怪异拼写不改变平面。** 18 个拼写 × 2 方法：`/oauth%2Ftoken`、`/oauth%2F`、
   `/.well-known%2Fopenid-configuration`、`/%2Ewell-known%2F...`、`/oauth/./token`、`/oauth//token`、
   `/oauth/../oauth/token`、`/v1%2Fme`、`/v1%2F..%2Fme`、`/v1;foo`、`/oauth;foo/token`、
   `/V1/me`、`/OAuth/token`、`/.well-known/oauth-protected-resource/{,/x}`。
   全部按**解码后**的路径落进自己的平面（`/v1;foo` 与 `/V1/me` 落进浏览器面是正确行为：
   它们不匹配命名空间）。**没有 `%00`、`%2e%2e` 之类的绕过**。
5. **客户端地址解析不接受别的头。** 15 个变体：`X-Real-IP`、`Forwarded`、`X-Forwarded-Host`、
   `X-Client-IP`、`CF-Connecting-IP`（全部忽略）；`X-Forwarded-For: unknown`、
   `198.51.100.9:4444`、`[2001:db8::1]`（全部退回对端）；`  198.51.100.9  `
   （前后空白被 `TrimSpace` 正确接受）。**只有 `X-Forwarded-For` 在信任时生效**。
6. **不配信任列表时，伪造 XFF 无法自选桶。** `map[401:1 429:49]` —— 50 个不同 XFF
   全部落在对端的同一个桶里。这是默认姿态正确的直接证据。
7. **panic 不逃逸、也不泄露内部。** 注入一个**永远 panic 的 `OIDC`**（真实
   `recoverProtocol` 与 `recoverBrowser`）与一个**在 introspector 里 panic 的实现**
   （真实 `recoverBusiness`）：全部 500，形状各自正确
   （协议面 `{"error":"server_error","error_description":"internal error"}`、
   业务面 problem+json `internal_error`），且响应体不含 panic 值、`goroutine `、`.go:`、
   `Re0Auth`、`runtime.`、`r0semi/internal` 中的任何一个。panic 值只进日志（`slog.Error`）。
8. **敌意查询串不触发 panic。** 31 个 GET 路由 × 17 个敌意值
   （`?limit=-1`、`?limit=0`、`?limit=999999999999999999999`、`?before=-1`、`?cursor=-1`、
   `?since=0001-01-01T00:00:00Z`、`?until=0001-01-01T00:00:00Z`、`?user_code=%00%ff`、
   `?source=%00`、`?return_to=%2f%2fevil.example`、`?limit=%2d1`、`?limit=+1` …）
   = 527 次请求：**0 个 5xx，0 次 panic 逃逸**。第三轮 B3-3 的零值时间界修复在 HTTP 边界上确实生效。
9. **413 在三个平面上都是自己的形状。** `/oauth/token` → OAuth JSON；
   `/v1/me` → problem+json；`/auth/github/callback`、`/bind`、`/app/`、`/nope` → `text/plain`。
   声明长度与 chunked（无 `Content-Length`）两条路径都测过（后者在既有
   `bodylimit_test.go` 里）。
10. **`return_to` 不能把浏览器带离本源。** 21 个敌意值 × 2 个入口
    （`/auth/{provider}/start`、`/bind`，后者实测在无会话时直接 401，够不到跳转逻辑）：
    `//evil.example`、`/\evil.example`、`\\evil.example`、`https://evil.example`、`https:/evil.example`、
    `http:evil.example`、`javascript:alert(1)`、`data:text/html,...`、`%2f%2fevil.example`、
    `/%2f%2fevil.example`、`/%5cevil.example`、`/\t/evil.example`、`/\n/evil.example`、
    `/\r\nX-Injected: 1`、`/app/consent\nSet-Cookie: a=b`、`///evil.example`、`/./\evil.example`、
    `..%2f..%2fevil.example`、`""`、`/app/`、`/app/consent?id=1`。
    `/auth/{provider}/start` 的 `Location` **恒为 IdP 的 authorize URL**（`return_to` 只进会话，
    由 `safeurl.RelativePath` 过滤）；`/bind` 在无会话时 401。**零开放跳转**。
    根路径的 `{/$}` 跳转同样：`?next=//evil.example`、`?x=%0d%0aSet-Cookie:+a=b`、
    `?u=https://evil.example` 全部只被拼进 `/app/?...` 的查询串，`Location` 不离开本源。
11. **注销是真的服务端失效。** `POST /v1/sessions/sign_out` 返回 204 之后，**同一个会话 cookie**
    访问 `/v1/sessions/current` 得到 401（`TestZZProbeSessionCookieAttributes` 两条部署模式各跑一次）。
    不是「只清 cookie」。
12. **`__Host-` 前缀的浏览器契约满足。** `Secure: true` 时名字为 `__Host-r0semi_session`，
    带 `Secure`、`Path=/`、无 `Domain`、`HttpOnly`、`SameSite=Lax`；`Secure: false` 时不使用前缀
    也不发 `Secure`。两条都实测。
13. **限流器自身的内存有界。** `maxKeys` 生效（键数封顶 10000），
    `evictLocked` 每次插入最多扫 64 条（插入成本不随表大小增长），
    桶的容量上限是 `maxPooledResponseBytes` 之外的固定小结构。它**不**是放大器，
    这一点我特意确认过，因为 HE-1 很容易被误读成「喷键就能打爆内存」。
14. **`.well-known` 子树的方法矩阵是完整的。** `/oauth` 与 `/.well-known` 的命名空间根、
    未知子路径、尾斜杠拼写，7 个方法各走一遍，全部落在协议面形状里（除 HE-6 记的那一条例外）。

---

## 未能到达（残余盲区）

1. **限流键表在「稳定态」下的行为没有定量刻画。** 我实测了「超上限后继续喷键」的结果
   （HE-1），但没有测「键数正好在上限附近反复震荡时一个诚实客户端的存活率」。
   要证明它需要读 `Limiter.size()`（未导出，探针包外不可达），或改用同包探针。
   当前证据是 20 次试验里 6 次命中，足以支持「会重置」，不足以给出「多久重置一次」。
2. **没有起真实反代。** HE-3 的「nginx/Traefik/Cloudflare 默认追加 XFF」是**文档知识**，
   本机没有 nginx/Caddy/HAProxy，也没有 Docker。要证实它需要一次真实代理的往返。
3. **浏览器层的行为全部未执行。** `SameSite=Lax` 在跨站顶层导航下是否真的带 cookie、
   `Referrer-Policy: no-referrer` 在真实浏览器里是否真的屏蔽 Referer、
   `__Host-` 前缀是否真的被浏览器强制——三条都只验证了响应头，没有验证浏览器。
   `pnpm test:e2e` 需要 Chromium，本机未确认是否安装，本次未跑。
   这是 HE-5 / HE-8 的残余。
4. **Postgres 模式全部未执行**（本机无 DB）。本次范围内只有 HE-9 与 Postgres 有关
   （审计 `LIMIT`），已标注为读代码到行。
5. **`-race` 未运行**（需要 cgo）。本报告没有并发结论依赖它；
   HE-1 的淘汰路径是单线程可复现的确定性行为（我实际反复跑过，并在报告里给出了试验比例，
   不是为了掩盖不确定性）。
6. **`ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`/`MaxHeaderBytes`
   只是读了 `cmd/re0auth/main.go:107-114` 与 `:705-719`（10s/30s/60s/120s/64KiB），
   没有做 Slowloris 或 header 洪水的实测。这些值看起来都合适，
   但「设置得当」与「实测扛得住」是两件事，本报告只主张前者。
7. **查询串没有条数上限这件事只观察了后果（不崩），没有测成本。**
   `?p0=v&p1=v&...` 到 20000 条仍然 400（`client_id is required`），
   说明 `duplicatedParam` 与 `ParseForm` 都正常工作；但没有测这个成本是否构成
   CPU 放大（单请求的解析是 O(n)，而请求速率由 HE-1 那个可以绕过的限流器管着）。
8. **同目录他人探针曾令本包编译失败，期间我的探针无法运行。**
   期间出现过 `zzprobe_adminpriv_test.go:352:13: undefined: zzAdmSigner`
   与 `:571:43: cannot use other (variable of struct type account.User) as account.UserID`，
   以及 `internal/store/postgres/postgres.go` 的 `undefined: hasAccountColumn`。
   我**没有**修改任何他人的文件；等它们自愈后重跑了全部探针（报告中的结果来自修复后的运行）。
   如果某个探针在最终清理时消失了，其结论仍可由报告中的命令复现。

---

## 判断（文档化决定可否质疑，不是 finding）

1. **「限流按客户端地址分桶，而非按 client/user」**（`docs/api-design.md` §2.7）本身不是缺陷，
   但 HE-1 说明这个决定的**实现**把「地址」做成了「调用方声明的地址」。
   ADR-0006 说「按 client/user 的配额模型尚未定义」——现在有了一个具体的理由去定义它：
   地址这个键在信任代理后面不可靠，在 NAT 前面不公平，而 `client_id` 与 `usr_` 都是服务端认过的。
2. **`SameSite=Lax` 而不是 `Strict`** 是合理取舍（Strict 会打断从 IdP 回来的第一次跳转），
   不质疑。HE-5 / HE-8 只是把它的残余写清楚。
3. **会话 cookie 用 `Path=/`** 与 `__Host-` 前缀是一个真正二选一的取舍（见 HE-5 的修法），
   不质疑现状。
4. **`max_in_flight` 默认关闭**（`Config.MaxInFlight` 为零即不装）：对一个「昂贵的入站是常态」
   的服务，默认打开会更安全，但默认值的选择属于运营裁定。
5. **审计读取端点不要 CSRF**（`docs/api-design.md` §4）在「只读」的前提下是对的；
   HE-9 只说明这个前提在「分配量」上有一个例外。
6. **`X-Forwarded-For` 一律忽略**（不配置就等于没有反代）是正确的默认，
   但文档没有要求反代**覆盖**而不是追加该头（HE-3 的修法）。这属于文档缺口，不是实现缺陷。
7. **把本次发现的守卫落成常规套件**：HE-1 的两条探针当前是**失败的测试**，
   按本项目的规矩（「发现 = 一条会失败的测试」）它们应当在修复后搬进
   `internal/ratelimit/` 与 `internal/httpapi/` 的常规套件（例如
   `TestLimiterNeverHandsBackABucketItEvicted`、`TestLimiterRefusesAKeyItCannotTrack`），
   而不是留在会随时间腐烂的探针文件里。
