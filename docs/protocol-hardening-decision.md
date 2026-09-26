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
4. **重复参数一律拒绝。** 库只取最后一个值，会让校验与使用看到不同的值；协议入口对重复参数
   返回 `400 invalid_request`。
5. **发现文档只声明真实能力。** 覆写库默认的 `response_types_supported`、`grant_types_supported`、
   `claims_supported` 与各端点认证方法；删除未实现的注册、检查会话、加密/私钥 JWT 能力。
6. **授权响应带 RFC 9207 `iss`**，成功与失败都带；同时广告
   `authorization_response_iss_parameter_supported`。
7. **PKCE 按 RFC 7636 校验语法**：challenge 与 verifier 均为 43–128 unreserved 字符。
8. **授权码在查询时即被消费，并检查过期。** 消除并发双兑换窗口；过期码不依赖 sweep 才失效。
9. **refresh token 重放是 `400 invalid_grant`**，不是 `500 server_error`。
10. **内省默认只允许查看自己的 token。** 资源服务器需在
    `server.introspection_clients` / `RE0AUTH_INTROSPECTION_CLIENTS` 中显式登记；跨 client 查询
    返回 `active=false`，不泄露任何 token 事实。
11. **撤销一个令牌即撤销同授权链的配对令牌**（RFC 7009 §2.1）。
12. **设备流接受标准 OIDC scope**（`openid`/`profile`/`email`/`offline_access`）：展示只渲染
    catalogue scope，协议 scope 保留进 grant；并按 RFC 8628 §3.5 实现轮询节流（`slow_down`）。
13. **`auth_time` 取会话真实登录时间**，不是同意决策时间。会话在 `SignIn` 时记录，登录 hook
    写回授权请求。
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
- **为什么授权码在读取时删除**：失败会烧掉 code，但这是 fail-closed 方向；一次失败要求用户
  重新授权，比并发双兑换可接受。

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
- `internal/httpapi/plane_test.go`：浏览器面压缩拒绝形状。
- `internal/oidcstore`：scope 收窄语义、签名密钥校验。
