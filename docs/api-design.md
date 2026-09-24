# r0semi 对外 API 设计（v1）

> 状态：已定稿（v1 契约）。实现必须以此为准；偏离需先改本文件。
> 上游依据：[architecture.md](./architecture.md)、[threat-model.md](./threat-model.md)。
> **机器可读的 v1 契约是 [openapi.yaml](./openapi.yaml)**（覆盖 `/v1`（含 `/v1/device/verification`））。它与实际路由**双向强一致**，由 `internal/httpapi/openapi_test.go` 断言；本文与它冲突时，以能通过测试的那个为准。

## 0. v1 已定决策

| # | 决策 |
|---|---|
| D-1 | **全站统一 `snake_case`**（字段名、参数、JSON key） |
| D-2 | **不透明 access token + Introspect**（RFC 7662）；不做 JWT AT，换取即时撤销。**唯一的 JWT 是 `id_token`**（见 D-6） |
| D-3 | **v1 不做 DPoP**（RFC 9449）：只签发普通 Bearer。曾一度在 AS 元数据里广告 DPoP，已移除——广告了却只发普通 Bearer 是**静默降级**（见 §2.10） |
| D-4 | **单域名**（如 `re0auth.r0semi.net`），但代码路由树内部**严格划清 `/oauth/` 与 `/v1/` 上下文边界** |
| D-5 | **不提供上游凭据导出端点**：要导出的**原始平台**凭据（如 TapTap stoken）在数据源手里，本地无物可导；本地那份**源签发**的令牌则永不交给下游（两层区分见 §5）。需要上游原生 API 时走 `raw` 透传 |
| D-6 | **采纳 OIDC**：Re0Auth 是 OpenID Provider。`id_token` 仅在请求含 `openid` 时签发，`sub` = `usr_`；`userinfo` 默认只回 `sub`，email 永不返回；服务 OIDC discovery（保留 RFC 8414 别名）。ADR 见 [oidc-decision.md](./oidc-decision.md) |

---

## 1. 两个平面，两套规则

| | **协议平面** | **业务平面** |
|---|---|---|
| 路径 | `/oauth/*`、`/.well-known/*` | `/v1/*` |
| 规范 | RFC 6749 / 7636 / 8628 / 7009 / 7662 / 8414，**照抄，不发挥**。RFC 9449 (DPoP)：**明确不做**，见 D-3 决策条目 | 本文件风格指南 |
| 请求编码 | `application/x-www-form-urlencoded` | JSON |
| 错误体 | `{"error","error_description"}` | RFC 9457 `application/problem+json` |
| 缓存 | `token` 响应必须 `Cache-Control: no-store` | 全部 `no-store`（见下） |

**铁律**：协议平面不得为了"风格统一"改动报文——那会让所有标准客户端库失效。

**协议平面的失败一律是 OAuth JSON。** 库自己写的某些失败是 `text/plain`（未认证的 `introspect`、
`userinfo` 就是），而一个平面两种格式等于没有契约。`oidchttp` 因此**缓冲并归一化**任何不带 `error`
字段的 4xx/5xx，保留库自己设的 `WWW-Authenticate`（RFC 6750 的 challenge）。描述用状态文本，
**不转述库的内部信息**（`ErrorType=… Parent=…` 属于日志，不属于线上契约）。
`internal/httpapi/plane_test.go` 的走查把「非 JSON 失败」判为失败，并且**按方法**走
（`POST /oauth/authorize` 在其中：库注册该端点时不带方法约束）。

**业务平面全部 `no-store`。** 这张表的「按资源语义」曾经落空——业务面一个 `Cache-Control` 都没有。
但这里每个响应都是**认证后的按人数据**：会话引导与 admin 客户端列表下发 CSRF token，账号导出是某个人
账号的全部内容。既没有 `Vary`，中间缓存也就没有任何键能区分两个账号。

**第三个面**：`/auth`、`/bind`、`/consent`、`/app` 以及未知路径**不属于任何平面**——它们是浏览器导航，
格式是纯文本或重定向。见 §6 与 [browser-plane-decision.md](./browser-plane-decision.md)。

---

## 2. 业务平面风格指南（`/v1`）

### 2.1 传输与编码
- 仅 HTTPS；`Content-Type: application/json`；响应按 `Accept-Encoding` 协商 **zstd / gzip**
  （br 暂缓），服务端偏好 `zstd > gzip`，客户端 q 值优先；低于 1 KiB 不压。
  **协议面（`/oauth/*`）不压**：报文小、必须 `no-store`，且 token 响应含秘密不可变换（BREACH）。
- 请求体 UTF-8，字段一律 `snake_case`。

### 2.2 ID
带前缀的不透明字符串：`usr_`、`cli_`、`enr_`、`grt_`、`req_`。
可读、可校验、日志中可辨类型，且未来更换底层 ID 方案不破坏契约。

### 2.3 时间
一律 RFC 3339 UTC：`created_at`、`updated_at`、`expires_at`。

### 2.4 错误模型（RFC 9457）

`Content-Type: application/problem+json`：

```json
{
  "type": "https://r0semi.dev/errors/scope_not_granted",
  "title": "Missing required scope",
  "status": 403,
  "detail": "This token does not include 'phigros.score.read'.",
  "instance": "/v1/games/phigros/scores",
  "code": "scope_not_granted",
  "required_scope": "phigros.score.read",
  "request_id": "req_01J..."
}
```

- `type` 指向可点击文档；`code` 是稳定机器码；`request_id` 用于排查。
- `401` = 令牌缺失/无效（必须带 `WWW-Authenticate: Bearer error="invalid_token"`）；
  `403` = 令牌有效但 scope 不足，必须带 `WWW-Authenticate: Bearer error="insufficient_scope"`，
  能指名单个 scope 时附 `scope="…"`。raw 透传按「该源任一资源 scope」粗粒度门禁，故省略 `scope=`。
  这是 RFC 6750 §3.1 区分「令牌不行」与「令牌太窄」的唯一标准手段——没有它，标准客户端只能看到
  一个裸 403，无法从协议层知道该去申请哪个 scope。
- 初始错误码目录：

| code | status | 含义 |
|---|---|---|
| `invalid_request` | 400 | 参数错误 |
| `unauthenticated` | 401 | 缺少/无效令牌 |
| `invalid_token` | 401 | 令牌被撤销或过期 |
| `scope_not_granted` | 403 | 令牌缺少所需 scope |
| `credential_not_found` | 404 | 该 provider 未托管凭据 |
| `not_found` | 404 | 资源不存在 |
| `conflict` | 409 | 状态冲突 |
| `idempotency_key_reused` | 409 | 幂等键复用于不同请求体 |
| `rate_limited` | 429 | 限流 |
| `not_acceptable` | 406 | 客户端拒绝了所有可用内容编码且禁止 identity |
| `upstream_unavailable` | 502 | 上游不可用 |
| `explicit_consent_required` | 403 | critical scope 未逐项同意 |
| `internal_error` | 500 | 服务端内部错误 |

### 2.5 分页
游标分页，禁止 offset：

```
GET /v1/games/phigros/scores?limit=50&cursor=<opaque>
{ "data": [ ... ], "pagination": { "next_cursor": "...", "has_more": true } }
```

列表用 `{data, pagination}` 信封；单项直接返回资源对象，不再套壳。

### 2.6 幂等

**规划中，尚未实现。** 设计意图：写操作（`POST` / `DELETE`）接受 `Idempotency-Key` 头；
同一键 + 同一请求体 → 重放缓存的响应；同一键 + 不同请求体 → `409 idempotency_key_reused`。

当前实现**不接受这个头**；`idempotency_key_reused` 这个 code 也已从错误目录中删除——
一个发不出来的错误码就是一句半衰期很长的谎，和它一起删的还有 `credential_not_found`、`conflict`。
真正需要它的写端点目前只有三个（`DELETE /v1/grants/{client_id}`、`DELETE /v1/bindings/{game}/{source}`
与 `DELETE /v1/account`）。
**三个都做了别的选择：** grants 撤销**本来就是幂等的**（删令牌，删两次结果一样，返回 204）；
断开连接则**必须返回结果体**——数据源那一半做了什么，用户得知道，一个只有状态码的 204 反而会把话说少；
账号抹除同样返回结果体，而且它的每一步都设计成幂等，重试安全，所以「重复请求」是**正确行为**而非需要拦掉的错误。
因此这个机制应当**等一个真正无法天然幂等、且结果单一的写操作出现时再落地**。

### 2.7 限流

超限返回 `429`（业务面 problem+json，协议面则是对应的 OAuth 错误）+ `Retry-After`。
**目前已实现的只有这一部分。**

`RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` 尚未实现：当前限流器按**客户端地址**
分桶，而非按已认证的客户端，这三个头的语义因此还没有确定的归属。等按客户端限流落地时再一并加上。

**地址怎么算**（`server.trusted_proxies` / `RE0AUTH_TRUSTED_PROXIES`）：默认取**对端地址**，
`X-Forwarded-For` 一律忽略——否则调用方自填一个头就能自选分桶，限流形同虚设。只有当对端落在
配置的**可信代理**网络里时才读该头，并从**右往左**跳过可信代理，取第一个不可信的地址（最右侧那条是
离我们最近的代理写下的，左侧是它被告知的）。头里出现无法解析的条目则整条链都不信、退回对端地址。
列表为空是默认，也是没有反代时的正确答案；列表过宽等于把选择权又交回调用方。

### 2.8 可观测
每个响应带 `X-Request-Id`；接受 W3C `traceparent`；problem 回带 `request_id`。

### 2.9 版本与弃用
路径 `/v1`，只做增量、不破坏。弃用用 `Deprecation` + `Sunset`（RFC 8594）头，并记录 changelog。

### 2.10 认证：Bearer（v1 不做 DPoP）
- `Authorization: Bearer <AT>`（RFC 6750）。
- **v1 不实现 DPoP（RFC 9449）。** AS 元数据**不再广告** `dpop_signing_alg_values_supported`：
  广告了却只发普通 Bearer，客户端会以为自己拿到了发送者约束令牌——那是静默降级，正是本项目在别处
  极力避免的。将来要做 DPoP，必须同时实现证明校验（`jkt` 绑定、`Introspect` 的 `cnf`、`ath`）并改回广告；
  验签必须用成熟 JOSE 库，绝不手写。

---

## 3. 协议平面（`/oauth`、`/.well-known`）

| 方法 | 路径 | 规范 | 说明 |
|---|---|---|---|
| `GET` | `/oauth/authorize` | RFC 6749 §4.1 | 浏览器跳转；仅 `response_type=code`；强制 PKCE S256 |
| `POST` | `/oauth/token` | RFC 6749 §4.1.3 / §6 / RFC 8628 §3.4 | `authorization_code` + `refresh_token` + `device_code`；`Cache-Control: no-store` |
| `POST` | `/oauth/revoke` | RFC 7009 | 永远返回 `200`（幂等） |
| `POST` | `/oauth/introspect` | RFC 7662 | 资源服务器使用 |
| `POST` | `/oauth/device_authorization` | RFC 8628 §3.1 | CLI/桌面设备码（**已实现**） |
| `GET` | `/v1/device/verification` | RFC 8628 §3.3 | 设备流验证页：需登录，且把 user code 绑到当前浏览器会话 |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 | 授权服务器元数据 |
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery 1.0 | OIDC 元数据；与 RFC 8414 文档内容一致（O-1） |
| `GET` | `/.well-known/oauth-protected-resource` | RFC 9728 | 资源元数据 |
| `GET` | `/oauth/userinfo` | OIDC Core §5.3 | Bearer；默认只返回 `sub`，email 永不返回（O-3） |
| `GET` | `/oauth/keys` | OIDC Discovery §3 | JWKS（`id_token` 的 RS256 公钥） |

硬约束：
- PKCE S256 强制，**对所有客户端（含 confidential）**——这是 OAuth 2.1 的要求；库只对 public
  client 强制，故在 `validateAuthorize` 里独立兜底。禁 implicit、禁 ROPC；重定向 URI 精确匹配。
- discovery 的 `scopes_supported` 必须包含 OIDC 核心 scope `openid` 与 `offline_access`
  （OIDC Discovery 1.0 §3：`openid` MUST 支持，OpenID Core 定义的 scope SHOULD 列出）。
  少列不会让库出错（它照样接受），但会毁掉 RP：严格按 `scopes_supported` 协商的客户端永远不会
  请求 `openid`，也就永远拿不到 `id_token`。**被接受却没声明**，与「声明了却没实现」是同一类意外。
- `authorize` 响应带 `iss`（RFC 9207）防混淆。
- `id_token` **仅在请求含 `openid` scope 时**返回；否则响应中不得出现 `id_token`（O-2）。
- `end_session` / `id_token_hint` / PAR / 动态客户端注册 / Session Management **不实现、不广告**（O-9）。
- `token` 响应头：`Cache-Control: no-store`、`Pragma: no-cache`。
- 标记 `explicit_consent` 的 scope 必须在同意页单独列出并要求逐项勾选（内置目录当前没有这样的 scope，机制保留）。

---

## 4. 业务平面端点（`/v1`）

原则：**数据导向，不做透明代理**。返回 r0semi 自己的稳定结构，不透传上游原始 JSON。

| 方法 | 路径 | scope | 说明 |
|---|---|---|---|
| `GET` | `/v1/me` | `account.id` | r0semi 账号（`usr_` id、显示名） |
| `GET` | `/v1/identities` | 会话 | 本账号已链接的 IdP 身份 |
| `DELETE` | `/v1/identities/{id}` | 会话 + CSRF | 解绑一个身份（I-2 守护，最后一个返回 `409 last_identity`） |
| `DELETE` | `/v1/account` | 会话 + CSRF + 显式确认 | **抹除本账号**：解绑并撤上游 → 撕碎 vault 凭据 → 撤销全部令牌 → 清会话 → 清在途请求 → 删账号行。**不可逆**；200 带「删了什么」的 body |
| `GET` | `/v1/account/export` | 会话 | **导出本账号数据**（profile / identities / bindings / grants），**不含任何凭据**；`Content-Disposition: attachment` |
| `GET` | `/v1/games/phigros/me` | `phigros.profile.read` | 游戏内档案（rks 等） |
| `GET` | `/v1/games/phigros/scores` | `phigros.score.read` | 成绩列表（游标分页） |
| `GET` | `/v1/games/phigros/b30` | `phigros.b30.read` | B30 |
| `GET` | `/v1/grants` | 会话 | 本账号当前的授权（**由活着的令牌推导**，见下） |
| `DELETE` | `/v1/grants/{client_id}` | 会话 + CSRF | 撤销某下游（本地撤销，幂等，204） |
| `GET` | `/v1/bindings` | 会话 | 本账号已连接的数据源（**不含任何凭据**） |
| `DELETE` | `/v1/bindings/{game}/{source}` | 会话 + CSRF | 断开某数据源（撕碎 vault 密文 + 删绑定 + 调源撤销），**200 带 body** |
| `POST` | `/v1/bindings/{game}/{source}/cascade_revocation` | 会话 + CSRF + 显式确认 | 请求数据源**登出全部设备**；源不支持则 409；**失败则什么都不删** |
| `POST` | `/v1/device/decision` | — （会话 + CSRF + handle 绑定） | 批准/拒绝一个设备流 `user_code`（RFC 8628） |

| `GET` | `/v1/sources` | — （公开） | 本部署提供的全部数据源（供「可连接」列表用） |
| `GET` | `/v1/games/{game}/sources` | — （公开） | 该游戏的数据源、能力与 `token_class` |
| `GET` | `/v1/games/{game}/{resource}` | 资源对应 scope | 归一化数据；`?source=` 可 pin（已实现，见 architecture.md §4.9） |
| `GET` | `/v1/games/{game}/sources/{source}/raw/{path...}` | 该源任一资源 scope（粗粒度） | 逐字透传源的原始 API；状态码/Content-Type/body 不改 |

> 具体游戏的资源名与 scope 由 `/v1/games/{game}/sources` 公布，无需在下游硬编码。

### 授权列表的两个决定

**一、它由令牌推导，不单独存一份同意记录。** 一条授权 = “某客户端此刻还能以你的身份做什么”，
实现上就是该 subject 名下仍然有效的令牌按 client_id 聚合。

好处是只有一个事实来源：**撤销就是删令牌**，不存在“同意表说已撤销、令牌表还能用”这种可能出现分歧的状态。
代价要写明：**列表显示的是“当前访问”而不是“历史同意”**。某个应用最后的 refresh token 也过期后，
它会从列表上消失——因为它确实什么也做不了了。一份存下来的同意记录会继续显示它；这里不会，这是故意的。

**二、它要会话，不要 bearer。** 最初设计写的是 `account.id`，改掉了。用 bearer 调这个端点，
等于让**一个客户端看到用户的其他客户端**——这对它没有任何用处，用户也从未同意交出这个信息。
唯一的消费者是账号页，它本来就有会话。

> enrollment / 扫码托管已迁出 Re0Auth，成为**参考数据源**的一部分（见 architecture.md §4.10）。

### 账号抹除（`DELETE /v1/account`）

PIPL / GDPR 要求「可删除」，这就是那个端点。它的编排在 `internal/lifecycle`，顺序是有讲究的：

1. **先解绑并撤上游**——binding 的凭据还在手里时才能告诉数据源「忘掉这个令牌」。先删本地记录就再也没有筹码去撤上游了。
2. **再撕碎 vault**——按 `subject` 删掉**整行**（`vault_credentials` PK 首列就是 subject，走索引）。删整行而非只置空 `WrappedDEK` 是关键：`Identity` 与 `Meta` 是明文 PII（上游 openid/unionid/objectId），只置空密钥等于「密文不可解但 PII 还在」——一次自称成功、实则没有的抹除。
3. **撤销全部令牌 → 清会话 → 清在途请求**（OP 的 auth request/code/device、federation 的 bind flow，以及**迁移遗留**的旧引擎表）。
4. **最后删账号行**（identities 走外键级联）。

还有**第 5 步，顺序不能动**：**销毁审计假名密钥**。审计日志是 append-only 且带链的（architecture.md §4.14），
所以不删行——而是删掉那把让「`usr_…` → 假名」可计算的密钥（§4.15）。行还在、链仍通过，但再没人能把它们关联到你。
它必须排在**「写完 `account.delete` 事件」之后**：那条事件本身也是关于这个账号的审计记录，
先销毁密钥的话，sink 会为新事件**新造一把密钥**——恰好把刚断开的关联接回去。

**每一步都幂等**，所以中途失败后重试是安全的、也是预期的恢复方式；错误里会注明卡在哪一步。

**为什么需要 `acknowledge`：** 和 `cascade_revocation` 同一个理由——不可逆动作不能让一个裸 `DELETE` 触发，调用方必须把后果写出来（常量 `deletes_my_account`）。

**响应为什么不是 204：** 请求返回时账号和会话都已经没了，调用方**无法自己核实**删没删干净。结果体逐 store 报告删了什么，这是它唯一能拿到的交代。

**`session_scoped` 为什么是个布尔：** 内存部署无法按 subject 枚举会话（只有「全部登出」）。`sessions: 0` 和「根本无法清」必须区分开，否则前者是事实、后者是缺口，却长得一模一样。

**为什么不在 `accounts_users` 上补 16 张外键：** 那些表**确实**没有外键（只有 `accounts_identities` 有），所以删账号行会静默留下孤儿。补外键是更大的改动、有历史数据的爆炸半径；这里改用**测试**守住：一个从 `information_schema` 动态取出所有带 `subject`/`user_id` 列的表、逐一断言清零的集成测试，外加一个**不依赖数据库**的静态检查（解析 migration，任何新增的带 subject 列的表若没在删除路径里登记就构建失败）。漏一张表就是合规 bug，所以两处都要机器化。

### 账号数据导出（`GET /v1/account/export`）

PIPL / GDPR 的「可携带」那一半。返回一份 JSON：`profile`、`identities`、`bindings`、`grants`，
外加一个 `notice`。

**它和 §5 说的「不导出上游凭据」不矛盾，因为是两件事**——§5 说的是**把凭据交给下游客户端**（那是转发凭据的信使，不做）；
这里是**把用户自己的数据交给用户自己**。两者唯一的交集是：这份导出**同样不含凭据**，理由见下。

**凭据为什么仍然排除：** binding 的 upstream access/refresh token 是**活密钥**，写进下载文件等于把导出物变成和 vault 一样敏感的东西，
而用户的诉求是「我有哪些数据」，不是「给我一把能冒充我的钥匙」。Re0Auth 也**没有**平台口令可导（§5 的两层表）。
`notice.credentials_excluded` 把这件事写进**文档本身**：一份静默省略的导出看起来是完整的，这一份明说它省略了什么。

**反泄漏是结构性保证，不是靠审查：** 导出的 identities / bindings / grants 直接复用
`/v1/identities`、`/v1/bindings`、`/v1/grants` **同一个 view 构造函数**（`identityViews` / `bindingViews` / `grantViews`）。
那些端点本来就被测试钉住「不含凭据」，所以导出不可能长出一个列表页没有的字段——只有一个地方决定「一条记录对外长什么样」。
测试上再加一道：先往 vault 里塞一个**已知明文**的 upstream token，再断言它**不出现**在导出字节里（且断言 binding 本身**出现**，否则就是空转）。

**每个 section 恒在**，没有数据就是空数组：文档形状不随账号持有多少东西而变，下游解析不必判空。

**只读、会话作用域**，所以不需要 CSRF；`Content-Disposition: attachment` 让浏览器保存而不是渲染它。

### 管理面（`/v1/admin`）

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/v1/admin/clients` | 全部客户端（含 `suspended`）；审核 inventory |
| `POST` | `/v1/admin/clients` | 注册客户端；secret 仅返回一次 |
| `POST` | `/v1/admin/clients/{client_id}/suspend` | 暂停并吐销其令牌 |
| `POST` | `/v1/admin/clients/{client_id}/activate` | 恢复（**不**恢复令牌） |
| `DELETE` | `/v1/admin/clients/{client_id}` | 删除注册并吐销令牌；幂等 |
| `POST` | `/v1/admin/kill_switch` | 按 `all`/`client`/`subject`/`bindings` 批量吐销（`all` 含会话与绑定；清会话需持久会话，内存模式下清不掉） |
| `GET` | `/v1/admin/audit` | 读审计日志：`?subject=`（账号 id，服务端翻成假名）/`?action=`/`?since=`/`?until=`/`?limit=`/`?cursor=` |
| `GET` | `/v1/admin/audit/verify` | 走一遍记录链，报告第一处对不上的行（`legacy` 报告链建立前的行数） |

会话 + CSRF（**只读的 `GET` 除外**——审计读端点不要 CSRF）。管理员是**配置允许列表里的 `usr_…`**（`[admin].subjects` / `RE0AUTH_ADMIN_SUBJECTS`），
不是角色；列表为空则整个平面不挂载。非管理员（含已登录的）访问得到 `404`。
完整契约与边界（四个 target 各切什么、为什么 `client` 不碰绑定、以及 `subject` 清会话依赖
会话索引）见 [admin.md](./admin.md)。审计读端点另需一个能读的 sink，见 [admin.md](./admin.md) §5.1。

---

## 5. 为什么没有“导出上游凭据”端点

曾规划过 `POST /v1/credentials/taptap/export`（critical scope + 逐项同意 + 强制审计），
把底层 TapTap session token 交给下游。**v1 不实现它，因为这个端点已无物可导。**

「无物可导」要成立，得先把**两层**上游凭据分清——这是最容易读岔的一处：

| 层 | 例子 | 谁持有 | re0auth 能看到吗 |
|---|---|---|---|
| **原始平台凭据** | TapTap 的 `sessionToken`（stoken） | **数据源自己**的 vault | 从不持有，也从不接触 |
| **源签发的令牌** | 源自己的 AS 签发的 access / refresh token | **re0auth 的 vault**（信封加密，键 `Provider = "<game>.<source>"`） | 持有；明文只在 `vault.Use` 的窗口内出现，且只用于调用源 |

绑定表（`BindingStore`）对两层都**只存元数据**（`token_type` / `expiry` / `has_refresh` / `version`），
凭据本体在 vault 里、永不进绑定表。于是：

- **该导出的那个根本不在本地**：被要求导出的「底层 stoken」在数据源手里，导出它只能是虚构的。
- **在本地的那一个也不能给**：源签发的令牌在有效期内是能取数、能续期的凭据，交给下游等于把这一层
  降级成转发凭据的信使，撤销、审计与 provenance 一起失守。

所以需要上游原生 API 的下游走 **raw 透传**（§4 的
`GET /v1/games/{game}/sources/{source}/raw/{path...}`）：Re0Auth 用它自己手里那份令牌去调源，
逐字透传上游语义，下游**只拿到数据、拿不到令牌**，且随时可按绑定撤销。

若将来确有“下游必须直接调数据源”的场景，正确做法是新增一个**按源的**导出 scope
（形如 `<game>.<source>.token.read`），并配套同意 UI、审计与弃用路径——**而不是复用这个旧名字**。

**机制保留**：`Descriptor.ExplicitConsent` 与 `Risk` 仍在，仍能表达“这个 scope 必须单独勾选”；
内置目录当前不含此类 scope，`oauth/scope_test.go` 有测试守住这一点（防止一个提供不了的能力又爬回目录）。

> **别和 `GET /v1/account/export` 搞混**（§4）。那是**把用户自己的数据交给用户自己**，本节说的是
> **把凭据交给下游客户端**。前者已实现，且同样不含凭据；后者不做。名字里都有 “export”，语义相反。

---

## 6. 单域名下的路由边界

```
re0auth.r0semi.net
├── /.well-known/…        协议元数据（标准位置）
├── /oauth/…              协议平面：form 编码 + OAuth 错误格式
├── /auth/…               IdP 客户端平面 + 上游绑定回调（/auth/upstream/{game}/{source}/callback）
├── /bind                 数据源绑定入口（需登录）→ 跳上游 authorize
├── /healthz、/readyz     运维探针：纯文本，不属任何平面，免限流
├── /consent              前端 SPA 路由（后端不渲染 HTML）
└── /v1/…                 业务平面：JSON + problem+json（含授权交互 API）
```

**这个 host 上没有运维指标面。** `/metrics` 与 `/debug/pprof/` **不在**上表，因为它们不挂在公网监听器上，
而是挂在 `server.internal_addr` 指定的**独立内部监听器**（不配置即不提供）。pprof 会导出进程内部状态，
把它放在公网端口上等于公开它；单独一个监听器是「只限内部 / 管理端」这条要求的**结构性**保证，而不是
一句约定。两者都在 `/v1` 与两平面的错误格式之外，见 [architecture.md](./architecture.md) §4.11。

**运维探针**：`GET /healthz`（存活）只要进程能应答就返回 `200 ok`；`GET /readyz`（就绪）在依赖可用时返回 `200`，
否则 `503 not ready`——有数据库时检查连接池，内存模式无物可查即恒就绪。两者都是纯文本、**不属任何平面**
（编排器读状态码，不读 body），且**免于限流**：桶被打满时不能反过来让存活探针失败而重启一个健康进程、
或让就绪探针把一个正在服务的实例摘出轮转。依赖的具体错误只进日志、不进响应体——该端点在无凭据下可达，
错误里可能带内网主机名。存活**只**看进程本身：依赖挂了就重启一个没出问题的进程，是把一次故障变成重启循环。

授权交互 API 与账号模型见 [account-model.md](./account-model.md) §5–§7。

实现：`internal/httpapi`（v1 已实现上述边界与两套错误写出器）。

实现约束（防串味）：

- **分类是正向的，只有一份。** `planeOf(path)` 明确命名每个平面：协议 = `/oauth` + `/.well-known`；
  业务 = `/v1`；**其余一律是浏览器面**。以前用 `isProtocolPath` 那种「不是协议就是业务」的负向写法，
  曾让 `/auth`、`/bind` 与**所有未知路径**被误判为业务平面——后果不是难看，而是**运维调限流会改变
  这些页面的 wire 契约**。
- **浏览器面（第三个面）**：`/auth/…`、`/bind`、`/consent`、`/app/…` 以及未知路径。这些 URL 由人
  通过浏览器导航到达，失败是**纯文本或重定向**，**禁止** problem+json，**禁止** `{error,error_description}`。
  `/auth/` 的既有 `http.Error` 与 `/bind` 的失败路径即此格式；`/consent`、`/app/*` 由 SPA 提供 HTML。
  未知路径也是纯文本 404——**在浏览器里输入错的 URL 应该像 404，而不像 API 错误**；`/v1` 子树的
  catch-all 仍然回 problem+json，API 客户端的笔误落在那儿。
- 平面判定**只有一处定义**，它同时驱动错误写出、限流/体积上限的形状、panic 恢复的形状，以及压缩层
  是否可变换（`compress.Config.Eligible`）。两处定义正是 `/.well-known/*` 一度「对一个是协议面、
  对另一个是业务面」的原因。
- **panic 也必须落在自己的平面里**：协议面的 panic → OAuth 500；业务面 → problem+json 500；浏览器面
  → 纯文本 500（由最外层兜住，因此也覆盖共享中间件里的 panic）。
- 两组路由使用**独立的错误写出器**与**独立的认证语义**；共享的只有 trace / 限流 / TLS 中间件。
- 协议平面中间件**禁止**输出 problem+json；业务平面中间件**禁止**输出 `{error,error_description}`。
- 两者的路由注册互不可见，由代码结构直接保证（不同包 / 不同 Router 实例挂载）。
- `oauth` 组件只依赖 `oauth.clients` / `oauth.tokens` / `audit`；`/v1` 资源层另起一层用 `Introspect` + vault 实现，不反向依赖协议层。

> 决策背景与权衡见 [browser-plane-decision.md](./browser-plane-decision.md)（ADR-0003）；
> 同意句柄的所有权校验见 [consent-binding-decision.md](./consent-binding-decision.md)（ADR-0004）。

---

## 7. 开发者体验（DX 是一等公民）

1. **OpenAPI 3.1 为唯一真源** → 生成 TS / Go / Python SDK、Postman 集合、mock server。
2. **沙箱环境**（`sandbox.*`）+ 固定测试账号。
3. **错误码目录**：每个 `type` URI 一个页面。
4. **Webhook**（后续）：`grant.revoked`、`credential.expired`，HMAC 签名，让下游及时失效缓存。

---

## 8. v1 未定 / 后续

- DPoP（RFC 9449）的引入时机与 `DPoP-Nonce` 语义：v1 不做，见 §2.10。
- PAR（RFC 9126）与动态客户端注册（RFC 7591）的引入时机。
- Webhook 的事件模型与重试语义。
- 导出令牌形态：直接返回明文 JSON，还是包一层可立即清零的结构（后者更安全，但需评估客户端适配成本）。
