# r0semi 对外 API 设计（v1）

> 状态：已定稿（v1 契约）。实现必须以此为准；偏离需先改本文件。
> 上游依据：[architecture.md](./architecture.md)、[threat-model.md](./threat-model.md)。

## 0. v1 已定决策

| # | 决策 |
|---|---|
| D-1 | **全站统一 `snake_case`**（字段名、参数、JSON key） |
| D-2 | **不透明令牌 + Introspect**（RFC 7662）；不做 JWT AT，换取即时撤销 |
| D-3 | **v1 不做 DPoP**（RFC 9449）：只签发普通 Bearer。曾一度在 AS 元数据里广告 DPoP，已移除——广告了却只发普通 Bearer 是**静默降级**（见 §2.10） |
| D-4 | **单域名**（如 `re0auth.r0semi.net`），但代码路由树内部**严格划清 `/oauth/` 与 `/v1/` 上下文边界** |
| D-5 | `taptap.stoken.read` 导出端点：**`POST` + 强制审计 + 默认不授予任何客户端** |

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
所有写操作（`POST` / `DELETE`）接受 `Idempotency-Key` 头。
同一键 + 同一请求体 → 重放缓存的响应；同一键 + 不同请求体 → `409 idempotency_key_reused`。
**撤销、托管、导出 stoken 必须支持幂等重试。**

### 2.7 限流
响应头 `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset`；
超限 `429`（problem+json）+ `Retry-After`。

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
| `GET` | `/device` | RFC 8628 §3.3 | 设备流验证页：需登录，且把 user code 绑到当前浏览器会话 |
| `GET` | `/oauth/consent` | — | 同意页（浏览器） |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 | 授权服务器元数据 |
| `GET` | `/.well-known/oauth-protected-resource` | RFC 9728 | 资源元数据 |
| `GET` | `/.well-known/jwks.json` | — | 若未来引入 JWT（当前不签发） |

硬约束：
- PKCE S256 强制；禁 implicit、禁 ROPC；重定向 URI 精确匹配。
- `authorize` 响应带 `iss`（RFC 9207）防混淆。
- `token` 响应头：`Cache-Control: no-store`、`Pragma: no-cache`。
- 同意页必须把 `taptap.stoken.read` 单独列出并要求逐项勾选。

---

## 4. 业务平面端点（`/v1`）

原则：**数据导向，不做透明代理**。返回 r0semi 自己的稳定结构，不透传上游原始 JSON。

| 方法 | 路径 | scope | 说明 |
|---|---|---|---|
| `GET` | `/v1/me` | `account.id` | r0semi 账号（`usr_` id、显示名） |
| `GET` | `/v1/me/identities` | `taptap.account.id` | 已链接上游身份（openid/unionid） |
| `GET` | `/v1/games/phigros/me` | `phigros.profile.read` | 游戏内档案（rks 等） |
| `GET` | `/v1/games/phigros/scores` | `phigros.score.read` | 成绩列表（游标分页） |
| `GET` | `/v1/games/phigros/b30` | `phigros.b30.read` | B30 |
| `POST` | `/v1/credentials/taptap/export` | `taptap.stoken.read` | 导出 stoken（critical，见 §5） |
| `GET` | `/v1/grants` | `account.id` | 本账号已授权的下游 |
| `DELETE` | `/v1/grants/{client_id}` | `account.id` | 撤销某下游（本地撤销，幂等） |
| `POST` | `/v1/device/decision` | — （会话 + CSRF + handle 绑定） | 批准/拒绝一个设备流 `user_code`（RFC 8628） |

| `GET` | `/v1/games/{game}/sources` | — （公开） | 该游戏的数据源、能力与 `token_class` |
| `GET` | `/v1/games/{game}/{resource}` | 资源对应 scope | 归一化数据；`?source=` 可 pin（已实现，见 architecture.md §4.9） |
| `GET` | `/v1/games/{game}/sources/{source}/raw/{path...}` | 该源任一资源 scope（粗粒度） | 逐字透传源的原始 API；状态码/Content-Type/body 不改 |

> 具体游戏的资源名与 scope 由 `/v1/games/{game}/sources` 公布，无需在下游硬编码。

> enrollment / 扫码托管已迁出 Re0Auth，成为**参考数据源**的一部分（见 architecture.md §4.10）。

---

## 5. `taptap.stoken.read` 导出约定

- **`POST` 而非 `GET`**：密钥不得出现在 URL、访问日志、浏览器历史、缓存。
- `Cache-Control: no-store`。
- 需要客户端被显式注册该 scope，且用户在同意页逐项勾选（`explicit_consent_required`）。
- 每次调用强制写审计（subject / client / request_id）。
- 响应一次性返回明文 stoken；服务端不为其建立任何缓存。
- **默认不授予任何客户端**；作为"数据 scope 覆盖不了"的兼容逃生口，规划弃用路径。

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
