# Re0Auth 上游协议（v1）

> 状态：已定稿（v1 契约）。上游（数据源）实现此契约即可接入 Re0Auth 生态。
> 定位见 [positioning.md](./positioning.md)；对下游的 API 见 [api-design.md](./api-design.md)。
>
> **实现状态**：`/.well-known/re0auth-upstream`、consent、raw 透传、conformance suite 均已实现
> （`upstreamkit` + `upstreamkit/conformance`）；**发现驱动的源注册表**尚未实现
> （现为静态配置）。本文是 v1 契约。

## 0. 范围

本协议规定**数据源（游戏后端）**必须提供什么，才能被 Re0Auth 聚合、授权并转发给下游。它由三部分组成：

1. **授权契约** —— 数据源必须对外暴露一个符合规范的 OAuth 2.0 授权服务器面（自研 / 现成库 / Kit 生成均可）；
2. **数据契约** —— 数据源必须按规范化 schema 提供其声明的资源；
3. **发现契约** —— 数据源必须自描述（游戏、能力、scope、令牌性质）。

## 1. 术语

| 术语 | 含义 |
|---|---|
| **游戏 game** | 如 `phigros` |
| **数据源 source** | 一个独立、可单独授权与调用的数据提供方，对外暴露一个 OAuth 2.0 AS 面。同一游戏可有多个源（官方 / 社区 A / 社区 B） |
| **资源 resource** | 源内的一个数据集合，如 `profile`、`scores`、`b30` |
| **绑定 binding** | `(usr_, game, source)` → 该源发放的令牌 |
| **令牌性质 token_class** | 该源令牌是 `revocable` 还是 `long_lived`，决定 Re0Auth 的存储与诚实标注 |

**授权粒度 = 每个 `(usr_, source)` 一次。** 同一游戏的不同源各自独立授权。

## 2. 拓扑

```
玩家 ──IdP 登录──> Re0Auth ──OAuth Client──> 数据源 A (phigros, 官方)
下游 ──AT────────> Re0Auth ──OAuth Client──> 数据源 B (phigros, 社区)
                              └─归一化 / raw─> 下游
```

Re0Auth 对**下游**是授权服务器，对**数据源**是 OAuth 客户端。TapTap 不在本协议范围内——它是数据源自己要处理的地基。

## 3. 准入判据：合规 = 三件事

一个合规数据源必须同时满足：

- **对外暴露**一个 OAuth 2.0 授权服务器面（§5）；
- **按规范化 schema 提供其声明的资源**（§8）；
- **发布一份自描述发现文档**（§4）。

三者缺一，Re0Auth 就不会把它登记为可用源。

**判据只看暴露面，不看内部实现。** 具体：

- AS 面可以**自研**、用**现成 OAuth 库**、或由 **Upstream Kit 生成**——三者等价，Re0Auth 无法也不会区分。
- 数据源**不需要原生就是 OAuth 2.0**。终端用户在其侧的登录方式（账号密码、设备码、TapTap、其它 OAuth）
  完全自由；Kit 以 `Consent` 钩子承接这一职责（§5）。
- 底层平台（如 TapTap）的协议**不在判据内**。其 device-code 等方言（`client_id` 为 AppID、`secret_type=hmac-sha-1`、
  MAC 令牌、无 PKCE）不构成标准 AS，需由数据源另做或由 Kit 生成一层。
- 判据中**机器可验**的部分由 conformance suite 覆盖（§13）；套件只检查暴露面，不检查实现。

## 4. 发现契约

数据源必须暴露：

```
GET {source_base}/.well-known/re0auth-upstream
```

```json
{
  "re0auth_upstream_version": 1,
  "game": "phigros",
  "source": "next-phi",
  "display_name": "Next Phi Backend",
  "oauth": {
    "issuer": "https://api.next-phi.example",
    "authorization_endpoint": "https://api.next-phi.example/oauth/authorize",
    "token_endpoint": "https://api.next-phi.example/oauth/token",
    "revocation_endpoint": "https://api.next-phi.example/oauth/revoke"
  },
  "token_class": "revocable",
  "scopes_supported": ["account.read", "phigros.profile.read", "phigros.score.read"],
  "resources": [
    {"name": "profile", "schema": "re0auth.phigros.profile/1", "scope": "phigros.profile.read"},
    {"name": "scores",  "schema": "re0auth.phigros.scores/1",  "scope": "phigros.score.read"}
  ],
  "raw": {"base": "https://api.next-phi.example/v1", "openapi": "https://api.next-phi.example/openapi.json"},
  "contact": "mailto:admin@next-phi.example"
}
```

- `re0auth_upstream_version`：整数主版本，见 §13。
- `token_class`：`revocable` | `long_lived`（§6）。**必须如实声明**，Re0Auth 依据它做存储策略与对外标注。
- `resources[].schema`：该资源遵循的规范化 schema 标识（§8）。
- `resources[].scope`：保护该资源的 canonical scope（§7）。
- `raw`：可选。声明后 Re0Auth 才能提供原始透传（§9）。

## 5. 授权契约（OAuth 2.0 profile）

数据源必须**对外暴露**一个 OAuth 2.0 授权服务器面（自研 / 现成库 / Kit 生成均可），并满足：

| 要求 | 级别 | 说明 |
|---|---|---|
| Authorization Code + PKCE (S256) | **MUST** | Re0Auth 作为客户端始终使用 PKCE；数据源必须支持 S256 |
| 精确匹配 redirect_uri | **MUST** | Re0Auth 的回调固定为 `{re0auth_issuer}/auth/upstream/{source}/callback` |
| Token endpoint | **MUST** | 返回 `access_token`、`token_type`、`expires_in`；可续期时返回 `refresh_token` |
| Revocation endpoint (RFC 7009) | **MUST** | `token_class=revocable` 时撤销必须生效 |
| 级联撤销端点 | **MAY** | 能把用户从上游会话登出时才有；声明即承诺（§6.1） |
| 刷新令牌轮换 | **SHOULD** | `token_class=revocable` 时 |
| Discovery（RFC 8414） | **MAY** | 允许仅在 re0auth-upstream 文档内联端点 |
| `account.read` → 账号标识 | **MUST** | 稳定的上游账号标识（openid / subject），用于绑定去重 |

**数据源负责其终端用户的认证与同意。** Re0Auth 作为客户端只发起授权请求；用户在数据源侧如何登录
（账号密码、设备码、其它 OAuth）完全由数据源决定。Kit 以 `Consent` 钩子暴露这个职责。
**数据源原生是否使用 OAuth 2.0，与本判据无关。**

**Re0Auth 不发明新的授权协议**：它只要求数据源**暴露**一个正当的 OAuth 2.0 AS。因此数据源可以用现成的
OAuth 库实现，也可以直接用 Upstream Kit 生成——两者对 Re0Auth 完全等价。

## 6. 令牌性质与绑定模型

```json
"token_class": "revocable"
```

| token_class | 含义 | Re0Auth 存储 | 撤销 |
|---|---|---|---|
| `revocable` | 有 scope、可过期、可通过 revocation endpoint 吊销 | 存储 refresh token（信封加密） | 调数据源 revocation → 解绑 |
| `long_lived` | 不可按客户端撤销、长效（等价于万能钥匙） | 存储该令牌（信封加密，高危标注） | 丢弃令牌；如数据源有级联撤销则调用（§6.1） |

- 绑定键 = `(usr_, game, source)`。
- 令牌**永久不返回给下游**，没有任何例外。需要上游原生 API 时用 §9 的 raw 透传，而不是交出令牌。
- 数据源必须**如实**声明 `token_class`；Re0Auth 会在同意页与文档中展示该性质。

### 6.1 级联撤销（可选能力）

RFC 7009 只能让数据源**忘记一个令牌**。有些场景要的是**把这个人从上游账号上登出**——
旧 session 立即失效、**所有设备都要重新登录**，包括用户手里那台。这是两件事，协议必须分开说。

数据源在 discovery 里声明它具备该能力：

```json
"oauth": {
  "revocation_endpoint": "https://api.next-phi.example/oauth/revoke",
  "cascade_revocation_endpoint": "https://api.next-phi.example/oauth/cascade_revocation"
}
```

**只有真的实现了才允许出现这个字段。** 广告了却做不到，与广告 DPoP 却只发普通 Bearer 是同一类谎，
而 Re0Auth 正是依据它决定要不要给出「登出全部设备」这个按钮。

```
POST {cascade_revocation_endpoint}
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))

token=<Re0Auth 持有的令牌>&token_type_hint=refresh_token
```

- **请求体与 RFC 7009 同形，效果不同。** 令牌**不是**被撤销的对象，它是「要结束谁的会话」的凭据。
  数据源从中解出 subject，然后作废**上游的登录本身**。
- 优先发 refresh token：它标识的是持续授权而不是一小时，而访问令牌可能已经过期。
- `token_type_hint` **只是提示**。因猜错而拒绝的数据源，会被记在它自己账上。
- 数据源**可以**消费掉这个令牌——Re0Auth 紧接着就会把绑定删掉。
- 若上游返回了替代凭据（例如 TapTap 的 `refreshSessionToken` 会返回新 session token），
  **必须丢弃**。留下它等于：用户在自己所有设备上被登出，而数据源悄悄持有活着的会话——一次伪装成登出的劫持。
- 上游不可达时**必须返回错误**，不能返回 200。Re0Auth 收到错误时**什么都不删**，
  因为 vault 里的凭据是重试的唯一手段；此时删掉它，用户就永远做不成他想做的事了。

Kit 侧：`Hooks.CascadeRevoke` 非 nil 时端点与 discovery 字段一起出现，为 nil 时一起消失。
`referencesource` 的 TapTap 登录实现了它（旋转 session token 并丢弃替代品）。

## 7. Scope 词汇表

规范化 scope 文法：`<game>.<resource>.<action>`，`action ∈ {read, write}`；另有全局 `account.read`。

| scope | 含义 |
|---|---|
| `account.read` | 上游账号标识 |
| `<game>.profile.read` | 游戏内档案 |
| `<game>.score.read` | 成绩数据 |
| `<game>.<resource>.write` | 预留 |

- 数据源 **MUST** 接受它声明资源对应的规范化 scope；**MAY** 支持扩展（`<game>.<resource>.<action>.<ext>`）。
- **聚合 scope（如 `scores.read`）是 Re0Auth 专有的下游便利**，数据源**不会**收到它——Re0Auth 会把它拆解成逐游戏的 scope 再发给数据源。
- **名称映射**：Re0Auth 的下游 scope 与数据源 canonical scope 不必同名，映射表由 Re0Auth 的源注册表维护。
  已知特例：下游 `account.id` ↔ 上游 `account.read`。
- 这样下游的 scope 稳定，不受数据源差异影响。

## 8. 数据契约（规范化）

数据源对每个声明的资源，必须提供符合规范化 schema 的响应。

- **schema 标识**：`re0auth.<game>.<resource>/<major>`，随 `resources[]` 声明。
- **传输**：JSON，`snake_case`，RFC 3339 时间。
- **列表**：游标分页，`{ "data": [...], "pagination": {"next_cursor": "...", "has_more": true} }`。
- **错误**：RFC 9457 `application/problem+json`（§11）。
- **限流**：`RateLimit-Limit` / `Remaining` / `Reset`。

示例（v1 草拟，正式定义在 OpenAPI 中）：

```json
// re0auth.phigros.profile/1
{ "game": "phigros", "user_id": "usr_xxx", "display_name": "…", "rks": 12.34 }

// re0auth.phigros.scores/1  （列表项）
{ "song_id": "…", "difficulty": "IN", "score": 1000000, "accuracy": 100.0, "rating": 15.3, "achieved_at": "2025-01-01T00:00:00Z" }
```

**规范化是 Re0Auth 的"观点"**，不是中立的。需要中立时用 raw（§9）。

数据源必须提供的规范化端点：

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/account` | `{subject, display_name?}`（需 `account.read`） |
| `GET` | `/resources/{name}` | 返回 `resources[]` 中声明的资源（需对应 scope） |

错误用 `problem+json`；未知资源返回 `404`。

## 9. Raw 透传

数据源可声明 `raw`，暴露自己的原始 API。Re0Auth 将其实现在：

```
GET /v1/games/{game}/sources/{source}/raw/{path...}
```

- Re0Auth **逐字转发**，不修改 body、不重命名字段、不重排——**彰显中立性**。
- raw 不受 schema 保证；下游选择 raw 即接受与上游耦合（上游一改就可能崩）。
- Re0Auth 只负责鉴权、转发、限流与 provenance。

## 10. Provenance 与降级

**来源永远可见、绝不静默换源。**

- 每个归一化 / raw 响应带响应头 `Re0Auth-Source: <source>`。
- 下游**指定了源**（`?source=`）时：该源不可用 → 直接返回 `503 source_unavailable`，**不得替换**。
- 下游**未指定源**时：Re0Auth 可挑选一个可用源，但响应 **MUST** 带 `Re0Auth-Source`；
  若首选源被跳过，另带 `Re0Auth-Degraded: true`。
- 源的声明周期：`active → degraded → retired`，通过源注册表与 `Sunset` 头告知消费者。

## 11. 错误模型

- **归一化路径**：`application/problem+json`，`code` 使用 [api-design.md](./api-design.md) §2.4 的目录，外加：

| code | status | 含义 |
|---|---|---|
| `source_not_bound` | 409 | 该源尚未绑定，见 §12 引导 |
| `source_unavailable` | 503 | 指定的源当前不可用（不替换） |
| `source_retired` | 410 | 源已下线 |

- **raw 路径**：原样透传上游的 HTTP 状态与 body（由数据源定义）。

## 12. 下游侧契约（简要）

完整见 [api-design.md](./api-design.md)。要点：

```
GET /v1/games/{game}/{resource}                         归一化（可选 ?source=）
GET /v1/games/{game}/sources                            列出源、能力、状态（公开）
GET /v1/games/{game}/sources/{source}/raw/{path...}     原始透传
```

**未绑定引导**：当用户尚未绑定所需源时，返回

```json
{
  "type": "https://r0semi.dev/errors/source_not_bound",
  "code": "source_not_bound",
  "game": "phigros",
  "source": "next-phi",
  "bind_url": "https://re0auth.r0semi.net/bind?game=phigros&source=next-phi&return_to=…"
}
```

下游把用户导到 `bind_url` 完成绑定后重试。这正是 account-model §7 的"渐进式绑定"：授权页发现缺绑定 → 就地跳数据源 OAuth → 回来继续。

> 已实现：`GET /v1/games/{game}/sources`、`GET /v1/games/{game}/{resource}`、
> `GET /v1/games/{game}/sources/{source}/raw/{path...}`（raw 透传）、
> `409 source_not_bound` + `bind_url`（及绑定流程）、多源仲裁与 `Re0Auth-Degraded`（见 architecture.md §4.9）。

## 13. 版本与一致性测试

- `re0auth_upstream_version`：**整数主版本**。加法演进不升主版本；破坏性变更升主版本 + 过渡期。
- **conformance suite** 随 Upstream Kit 发布，覆盖：发现文档、OAuth 元数据（PKCE S256）、
  未知客户端不得被重定向、token 拒绝非法 grant、撤销端点存在；提供 `AccessToken` 时另测
  `/account`（需鉴权 + 返回 subject）与每个声明资源。
  **交互式授权流程**无法在无用户/无测试客户端时自动验证，故与数据面检查解耦。
- 数据源通过套件后，才能被登记为兼容源。

> 参考实现：`upstreamkit`（Kit）+ `upstreamkit/conformance`（套件）。

## 14. Upstream Kit 最小合规清单

一个后端要成为**合规数据源**，至少做到：

> **注**：清单中的 AS 面**不需要原生实现**——自研、现成库或 Kit 生成均算达成。后端原有的认证
> （TapTap、设备码、账号密码…）通过 Kit 的 `Consent` 钩子接入即可。

- [ ] `GET /.well-known/re0auth-upstream` 返回合法发现文档（§4）
- [ ] **对外暴露** OAuth 2.0 AS 面：`authorize`（code + PKCE S256）、`token`（+ refresh）、`revoke`
- [ ] 接受其声明的规范化 scope（§7）
- [ ] `account.read` 返回稳定上游账号标识（§5）
- [ ] 按声明实现规范化资源 schema（§8）
- [ ] `problem+json` 错误 + 限流头
- [ ] `token_class` 如实声明；`revocable` 时撤销真正生效
- [ ] 若声明 `cascade_revocation_endpoint`，该端点确实存在（conformance 的 `cascade.present`）；不声明则 Re0Auth 不提供该操作
- [ ] （可选）`raw` API + OpenAPI，以支持中立透传（§9）
- [ ] 通过 conformance suite（§13）

> Kit 的目标：把以上从"读一份协议自己实现"降为"装一个组件、填几个 hook"。
> 这是整个标准化能否启动的关键杠杆。
