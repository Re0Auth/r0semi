# ADR-0003：第三个面——平面判定与浏览器面的错误格式

> 状态：**已接受**。落地：`internal/httpapi/middleware.go`（`planeOf`）、
> `internal/httpapi/server.go`、`internal/httpapi/federation_routes.go`，
> 测试见 `internal/httpapi/plane_test.go`。

## 1. 背景

服务对三种消费者说话，而契约只写了两条：

| 面 | 路径 | 谁在看 | 失败格式 |
|---|---|---|---|
| 协议面 | `/oauth`、`/.well-known` | 标准 OAuth/OIDC 客户端库 | `{error,error_description}` |
| 业务面 | `/v1` | JSON 客户端（下游工具、前端） | RFC 9457 problem+json |
| **浏览器面** | `/auth`、`/bind`、`/consent`、`/app`、未知路径 | **人**（浏览器导航） | **从未决定** |

第三条一直存在，只是没人写下它。后果不是"格式难看"，而是一个**真实缺陷**：共享中间件用
`isProtocolPath(path)`（只匹配 `/oauth/` 与 `/.well-known/` 前缀）来选错误形状，于是
`/auth/login`、`/bind`、`/foo` 一律落到"不是协议 → 就是业务"的兜底分支，被写成 problem+json。

**于是运维调 `RateLimit` 会改变用户看到的 wire 契约。** 分类是事故，不是决定。

同源的两处次生问题：

- 平面判定有**两份**。压缩层的 `Eligible` 是 `!strings.HasPrefix(path, "/oauth/")`，判定式却是
  `/oauth/` **或** `/.well-known/` 前缀。两者在 `/.well-known/*` 上不一致，于是
  `Accept-Encoding: identity;q=0` 会让一个 OIDC discovery URL 返回 **406 problem+json**。
- 判定式要求尾斜杠，所以客户端最自然构造的 `{issuer}/oauth` 被判成业务面子。

## 2. 决策

**一、分类改为正向的，且只有一处定义。**

```go
planeOf(path): /oauth + /.well-known → 协议面
               /v1                  → 业务面
               其余                  → 浏览器面
```

每个命名空间连**根**一起匹配（`/oauth`、`/.well-known`、`/v1`）。负向写法（"不是协议就是业务"）
正是漏洞本身：它把**未来**加的任何路径都默认归给业务面。

**二、浏览器面的格式被明确决定：纯文本或重定向。**

- **禁止** problem+json，**禁止** `{error,error_description}`。
- 已有的 `http.Error` 用法（`internal/auth` 八处、`/bind`）从此是**符合契约**的，而不是"没人管"。
- `/consent`、`/app/*` 由 SPA 返回 HTML，本就不渲染后端错误页。
- **未知路径也是纯文本 404。** 在浏览器里输入错的 URL 应该像 404，而不像 API 错误。`/v1` 子树有
  自己的 catch-all，仍然回 problem+json——API 客户端的笔误落在那儿，格式正确。
- **不采用**把 `/auth` 迁移到 JSON：这些响应是人在浏览器导航里看的，塞 JSON 换不到任何东西。

**三、一份判定式驱动全部**：错误写出、限流 429、体积上限 413、panic 恢复 500，以及压缩层是否可变换。
`/.well-known/*` 从此对压缩层也是协议面，即**不压**——与 §2.1「协议面不压」一致，之前那个例外是判定式
不一致造成的。

**四、`/bind` 的失败改为一句通用纯文本。** 原先它复用业务面的 `writeFederationError`（404/409/502 各有
细分）。对跟随链接的人来说，"未知源 / 源已退役 / 客户端未配置"都是"这个链接不能用"；细节属于日志，
不属于导航响应。状态码不再是 5xx/409 的细分，统一 400。

## 3. 后果

- **行为变更（有意）**：`/auth/*`、`/bind`、`/foo`、`/v2/me` 的 429 / 413 / 404 从 problem+json 变为纯文本。
  断言旧行为的既有测试随之更新：`TestFrontendMountDoesNotSwallowAPIRoutes` 的 `/nope` 一行改成
  `text/plain`——它真正要证的是"挂载没吞掉非 SPA 路径"，这一条没有放松。
- **panic 不再丢连接**：新增三个恢复器（协议面 OAuth 500 / 业务面 problem+json 500 / 浏览器面纯文本 500），
  并**补上日志**——原来的业务面恢复器吞掉 panic 且不记录，崩溃会变成谜案。
- 浏览器面不再可压缩（`/.well-known/*` 亦然）。代价是 discovery 文档少了一次压缩，收益是判定式只有一份。
- 以后新增任何非 `/oauth`、非 `/v1` 的路径，**默认落到浏览器面**——这是刻意的：新面必须被明确命名，
  而不是悄悄继承业务面的格式。

## 4. 测试

`internal/httpapi/plane_test.go`：三张路径表（协议 / 业务 / 浏览器）各走一遍，断言各自的形状；
每张表都带**反空转下限**（失败计数不足即失败）。另有：
`TestProtocolPlaneIsNeverCompressedNorRefused`（含 `Accept-Encoding` 维度）、
`TestBrowserPlaneNeverAnswersWithAPlaneError`（router + limiter 两个方向）、
`TestPanicRecoveryAnswersInTheRightShape`。

## 5. 受影响文档

- [api-design.md](./api-design.md)：§1 铁律下新增第三面一句、§3 删除失效的 `GET /oauth/consent` 行、
  §6 补齐浏览器面契约与正向判定式
- [consent-binding-decision.md](./consent-binding-decision.md)（ADR-0004）：同一批发现的另一半
- `internal/httpapi/frontend_test.go`、`ratelimit_test.go`、`security_headers_test.go`：断言随格式变更更新
