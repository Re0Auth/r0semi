# r0semi 对外 API 设计（v1）

> 状态：已定稿（v1 契约）。实现必须以此为准；偏离需先改本文件。
> 上游依据：[architecture.md](./architecture.md)、[threat-model.md](./threat-model.md)。
> **机器可读的 v1 契约是 [openapi.yaml](./openapi.yaml)**（覆盖 `/v1`（含 `/v1/device/verification`））。它与实际路由**双向强一致**，由 `internal/httpapi/openapi_test.go` 断言；本文与它冲突时，以能通过测试的那个为准。

## 0. v1 已定决策

| # | 决策 |
|---|---|
| D-1 | **全站统一 `snake_case`**（字段名、参数、JSON key） |
| D-2 | **不透明令牌 + Introspect**（RFC 7662）；不做 JWT AT，换取即时撤销 |
| D-3 | **v1 不做 DPoP**（RFC 9449）：只签发普通 Bearer。曾一度在 AS 元数据里广告 DPoP，已移除——广告了却只发普通 Bearer 是**静默降级**（见 §2.10） |
| D-4 | **单域名**（如 `re0auth.r0semi.net`），但代码路由树内部**严格划清 `/oauth/` 与 `/v1/` 上下文边界** |
| D-5 | **不提供上游凭据导出端点**：re0auth 不持有上游凭据，无物可导。需要上游原生 API 时走 `raw` 透传，而不是交出令牌（见 §5） |

---

## 1. 两个平面，两套规则

| | **协议平面** | **业务平面** |
|---|---|---|
| 路径 | `/oauth/*`、`/.well-known/*` | `/v1/*` |
| 规范 | RFC 6749 / 7636 / 8628 / 7009 / 7662 / 8414 / 9449，**照抄，不发挥** | 本文件风格指南 |
| 请求编码 | `application/x-www-form-urlencoded` | JSON |
| 错误体 | `{"error","error_description"}` | RFC 9457 `application/problem+json` |
| 缓存 | `token` 响应必须 `Cache-Control: no-store` | 按资源语义 |

**铁律**：协议平面不得为了"风格统一"改动报文——那会让所有标准客户端库失效。

---

## 2. 业务平面风格指南（`/v1`）

### 2.1 传输与编码
- 仅 HTTPS；`Content-Type: application/json`；响应启用 gzip / br。
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
- `401` = 令牌缺失/无效（必须带 `WWW-Authenticate`）；`403` = 令牌有效但 scope 不足。
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
真正需要它的写端点目前只有两个（`DELETE /v1/grants/{client_id}` 与 `DELETE /v1/bindings/{game}/{source}`）。
**两个都做了别的选择：** grants 撤销**本来就是幂等的**（删令牌，删两次结果一样，返回 204）；
断开连接则**必须返回结果体**——数据源那一半做了什么，用户得知道，一个只有状态码的 204 反而会把话说少。
因此这个机制应当**等一个真正无法天然幂等、且结果单一的写操作出现时再落地**。

### 2.7 限流

超限返回 `429`（业务面 problem+json，协议面则是对应的 OAuth 错误）+ `Retry-After`。
**目前已实现的只有这一部分。**

`RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` 尚未实现：当前限流器按**客户端地址**
分桶，而非按已认证的客户端，这三个头的语义因此还没有确定的归属。等按客户端限流落地时再一并加上。

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
| `GET` | `/oauth/consent` | — | 同意页（浏览器） |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 | 授权服务器元数据 |
| `GET` | `/.well-known/oauth-protected-resource` | RFC 9728 | 资源元数据 |
| `GET` | `/.well-known/jwks.json` | — | 若未来引入 JWT（当前不签发） |

硬约束：
- PKCE S256 强制；禁 implicit、禁 ROPC；重定向 URI 精确匹配。
- `authorize` 响应带 `iss`（RFC 9207）防混淆。
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

---

## 5. 为什么没有“导出上游凭据”端点

曾规划过 `POST /v1/credentials/taptap/export`（critical scope + 逐项同意 + 强制审计），
把底层 TapTap session token 交给下游。**v1 不实现它，因为这个端点已无物可导。**

架构演进后，**re0auth 不持有任何上游凭据**：上游令牌存进**数据源自己的 vault**，re0auth 侧的绑定
只存元数据（`token_type` / `expiry` / `has_refresh` / `version`）。本地没有可导出的凭据，
“导出”只能是虚构的。

需要上游原生 API 的下游走 **raw 透传**（§4 的 `GET /v1/games/{game}/sources/{source}/raw/{path...}`）：
它给出同样的数据、逐字透传上游语义，**不交出令牌**——令牌始终留在源侧，仍可按绑定撤销。

若将来确有“下游必须直接调数据源”的场景，正确做法是新增一个**按源的**导出 scope
（形如 `<game>.<source>.token.read`），并配套同意 UI、审计与弃用路径——**而不是复用这个旧名字**。

**机制保留**：`Descriptor.ExplicitConsent` 与 `Risk` 仍在，仍能表达“这个 scope 必须单独勾选”；
内置目录当前不含此类 scope，`oauth/scope_test.go` 有测试守住这一点（防止一个提供不了的能力又爬回目录）。

---

## 6. 单域名下的路由边界

```
re0auth.r0semi.net
├── /.well-known/…        协议元数据（标准位置）
├── /oauth/…              协议平面：form 编码 + OAuth 错误格式
├── /auth/…               IdP 客户端平面 + 上游绑定回调（/auth/upstream/{game}/{source}/callback）
├── /bind                 数据源绑定入口（需登录）→ 跳上游 authorize
├── /consent              前端 SPA 路由（后端不渲染 HTML）
└── /v1/…                 业务平面：JSON + problem+json（含授权交互 API）
```

授权交互 API 与账号模型见 [account-model.md](./account-model.md) §5–§7。

实现：`internal/httpapi`（v1 已实现上述边界与两套错误写出器）。

实现约束（防串味）：

- 两组路由使用**独立的错误写出器**与**独立的认证语义**；共享的只有 trace / 限流 / TLS 中间件。
- 协议平面中间件**禁止**输出 problem+json；业务平面中间件**禁止**输出 `{error,error_description}`。
- 两者的路由注册互不可见，由代码结构直接保证（不同包 / 不同 Router 实例挂载）。
- `oauth` 组件只依赖 `oauth.clients` / `oauth.tokens` / `audit`；`/v1` 资源层另起一层用 `Introspect` + vault 实现，不反向依赖协议层。

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
