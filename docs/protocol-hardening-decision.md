# ADR-0005：协议面对抗审计后的收紧

> 状态：**已接受**。
> 背景：一轮只读对抗审计在授权码、scope、方法、发现文档、
> 内省与密钥处理上找到若干缺口。本文记录每一项的取舍与落地，避免下次审计重新争论。
> 相关：[oidc-decision.md](./oidc-decision.md)（ADR-0001）、[api-design.md](./api-design.md)、
> [threat-model.md](./threat-model.md)。

## 决策

1. **撤销必须覆盖“还没兑换的能力”。** Kill Switch 的 token 撤销同时删除该
   subject/client 的 pending 授权请求与授权码；授权码是可变现凭据，只清 token 表会让事故响应
   产生“已隔离但还能恢复访问”的假象。两个 OP store 与遗留引擎的 `oauth_codes` 同步处理。
2. **scope 的省略与显式空集不同。** 省略 `scopes` = 批准全部请求；显式 `[]` = 批准零项，
   返回 `400 invalid_request`，绝不静默升级为全部。授权码流与设备流共用同一语义。
3. **敏感端点只接受 POST。** `token`、`introspect`、`revoke`、`device_authorization` 的非 POST
   返回 OAuth JSON 405；凭据不再进入 URL 与访问日志。`authorize`/`userinfo` 保留标准 GET。
   **并且参数只从请求体取**：这些 POST-only 端点拒绝非空查询串（`400 invalid_request`），因为
   `r.Form` 会把查询串并进表单，一个「方法合法、参数在 URL」的请求曾把 code / refresh token /
   client_secret 送进 URL 与中间层日志——同一处暴露，换了一扇门。`authorize` 除外：它的参数
   本来就合法地放在查询串里（GET 形态）。
4. **重复参数一律拒绝。** 库只取最后一个值，会让校验与使用看到不同的值；协议入口对重复参数
   返回 `400 invalid_request`。
5. **发现文档只声明真实能力。** 覆写库默认的 `response_types_supported`、`grant_types_supported`、
   `claims_supported` 与各端点认证方法；删除未实现的注册、检查会话、加密/私钥 JWT 能力。
   内省端点只广告 `client_secret_basic`：库的 `ClientIDFromRequest` 表单结构没有 `client_secret`
   字段，投递的 secret 从不被读取，广告 `client_secret_post` 只会让按文档协商的客户端撞上 401。
6. **授权响应带 RFC 9207 `iss`**，成功与失败都带；同时广告
   `authorization_response_iss_parameter_supported`。**这条只在 `query` 响应模式下成立**：`iss`
   是 Location 头的改写，而 `form_post` 是库渲染的 200 HTML 表单，永远不经过它。所以本服务
   **只提供 `query`**（discovery 广告 `response_modes_supported: ["query"]`），`form_post` 在
   `authorize` 前置检查里被拒（回客户端一个带 `iss` 的重定向错误）。「接受 form_post 再往库生成的
   HTML 里注 `iss`」被否决：那是改写库的渲染产物，比只收 query 脆。ADR-0005 §5 与 §6 由此一致。
7. **PKCE 按 RFC 7636 校验语法**：challenge 与 verifier 均为 43–128 unreserved 字符。
7b. **PKCE 强制的唯一例外是显式豁免的客户端。** `[client] allow_missing_pkce = true`（或
    `[[clients]]` 中某个客户端的同名字段，或 `RE0AUTH_CLIENT_ALLOW_MISSING_PKCE` 对主客户端）
    把一个客户端注册为免 PKCE，供 OIDF 认证套件这类无法发送 `code_challenge` 的客户端使用。该字段
    默认 false（零值即强制），被纳入启动漂移检查（文件与已注册行不一致 → 拒绝启动），启用时打日志，
    且每次豁免真正生效时再记一条 WARN。豁免只覆盖“没有 challenge”：带了 challenge 仍必须是合法
    S256；且仅对**机密客户端**有效——公开客户端没有 secret，省掉 PKCE 等于授权码可被任何看到它的
    人兑换，启动即拒绝（对 `[client]` 与每个 `[[clients]]` 条目同样成立）。
    OIDF Basic OP 与强制 PKCE 的冲突、以及为什么选择逐客户端开关，见
    [docs/conformance.md](./conformance.md)。
8. **授权码先读取并校验全部绑定，通过后再原子消费。** 兑换先 `GetCode`（非破坏性读）判断过期、
   客户端、`redirect_uri` 与 PKCE，全部通过才 `ConsumeCode`（单条原子删除），并只从被认领的那条记录
   签发。单次使用与并发双兑换窗口仍由那次原子删除关闭（只有赢得 DELETE 的请求会签发）；失败的那次
   不再烧掉 code，并补一条 `oauth.exchange_failed` 审计。过期码当场被拒，不依赖 sweep。
9. **refresh token 重放是 `400 invalid_grant`**，不是 `500 server_error`。
10. **内省默认只允许查看自己的 token。** 资源服务器需在
    `server.introspection_clients` / `RE0AUTH_INTROSPECTION_CLIENTS` 中显式登记；跨 client 查询
    返回 `active=false`，不泄露任何 token 事实。
10b. **内省只接受机密客户端。** 该端点的授权判据就是客户端认证，而公开客户端没有可用来认证的秘密
    （id 不是凭据：它印在客户端二进制与每条授权请求 URL 里），注册表对非机密客户端恒返回“已认证”。
    因此调用方不是机密客户端时一律 401 `invalid_client`，与白名单无关；白名单条目也只对机密客户端
    有意义。第五轮审计 P0-6：白名单里出现一个公开 client id 曾等于向匿名者开放任意 token 的读取。
11. **撤销一个令牌即撤销同授权链的配对令牌**（RFC 7009 §2.1）。
12. **设备流接受标准 OIDC scope**（`openid`/`profile`/`email`/`offline_access`）：展示只渲染
    catalogue scope，协议 scope 保留进 grant；并按 RFC 8628 §3.5 实现轮询节流（`slow_down`）。
13. **`auth_time` 取会话真实登录时间**，不是同意决策时间。会话在 `SignIn` 时记录，登录 hook
    写回授权请求；`prompt=login` / `max_age` 要求新鲜认证而会话不满足时，登录边界先经 IdP
    重新登录，`CompleteLogin` 只在记录时间满足该请求时才完成，否则 `login_required`——同意
    决策本身不算一次认证，绝不把决策时钟写进 `auth_time`（第九轮 S02-1）。
14. **签名密钥集启动即校验**：至少 2048 位、kid 非空且不重复；否则拒绝启动。
15. **缓存策略显式化**：内省与 userinfo `no-store`；JWKS 与 discovery `public, max-age=300`。

## 理由与被拒方案

- **为什么拒绝 GET 兼容**：库把 GET 当可用兑换路径，凭据会进 URL、代理日志与浏览器历史；
  标准要求 POST，兼容一个错误的方法只会让错误长期存活。
- **为什么显式空集报错而不是签发零 scope token**：`openid` 等协议 scope 会自动附加，
  “零 scope” token 没有清晰语义；报错让客户端的错误可见。
- **为什么内省用白名单而不是拒绝跨 client**：资源服务器本来就需要查看别人签发的 token；
  默认关闭 + 显式登记是正向枚举，而不是“非 A 即 B”的隐含规则。
- **为什么 `active=false` 而不是 401**：调用方已通过客户端认证，401 会把它误导向“重试认证”；
  `active=false` 是 RFC 7662 里“不可用”的诚实答案，且不泄露 token 是否存在。
  **前提是“已通过客户端认证”为真**：对公开客户端那条认证是空转的（见决策 10b），所以在那里
  401 才是诚实的答案——它不是“权限不足”，而是“你没有可以用来认证的东西”。
- **为什么授权码在「校验通过后」才删除**：旧形状（读取时即删除）把「第一次尝试」当成「第一次成功兑换」，
  于是不需要 verifier 或客户端凭据、只要知道 code 就能把它烧掉，构成低成本定向 DoS（第五轮 KIT-4）。
  改为非破坏性读取 → 全部绑定校验 → 原子消费后，并发双兑换窗口仍由那次原子删除关闭（只有赢得 DELETE
  的请求会签发），而失败不再有副作用，并有 `oauth.exchange_failed` 审计。OP 面（`internal/oidchttp` +
  `OIDCStore.AuthRequestByCode`，consume-on-read）仍是同一形状，属另一引擎的同族项。

## 后果

- 依赖库的宽松行为（GET、重复参数、自动 discovery、内省无策略）被包装层覆盖；升级
  `zitadel/oidc` 时需要重跑 `internal/oidchttp` 的对抗测试。
- 新配置项 `server.introspection_clients` 必须有文档与示例；未配置时资源服务器看不到跨 client token。
- `auth_time` 依赖会话里的登录时间；无会话的纯设备流仍以同意时间为准（设备流本身没有浏览器登录）。

## 测试锚点

- `internal/oidchttp/adversary_test.go`：方法、重复参数、PKCE 语法、`iss`、内省边界、
  client auth challenge、discovery 真实性。
- `internal/store/memory`、`internal/store/postgres`：授权码单次消费/过期、整链撤销、
  pending 码撤销、设备 scope 与轮询节流、`auth_time` 保留。
- `oauth`：授权码绑定失败不消费（KIT-4 回归守卫）、并发双兑换只成功一次、
  `oauth.exchange_failed` 审计；`internal/zzprobe/protocol/kit` 的 `TestC1_`/`TestC2_` 端到端压同一条路。
- `internal/httpapi/plane_test.go`：浏览器面压缩拒绝形状。
- `internal/oidcstore`：scope 收窄语义、签名密钥校验。
