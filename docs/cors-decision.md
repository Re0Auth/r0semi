# ADR-0011：CORS——同源部署，不开放跨源

> 状态：**已接受**。
> 背景：仓库里此前没有任何关于 CORS 的书面策略，而 `rs/cors` 只是 `zitadel/oidc` 的**传递**依赖
> （`go.mod` 里标着 indirect）。写这份 ADR 时实测发现：那条假设不只是"没写下来"——库**已经**在
> 它自己的端点上按请求 `Origin` 回 `Access-Control-Allow-Origin: <origin>` 与
> `Access-Control-Allow-Credentials: true`（探测 `/.well-known/oauth-authorization-server`
> 与 `POST /oauth/token` 即可复现）。也就是说此前的实际姿态是**对一个没人选择过的、面向所有来源的
> 隐式 CORS 策略**，且没有任何东西会注意到它变化。
> 相关：[architecture.md](./architecture.md) §4.5（三个面）、[browser-plane-decision.md](./browser-plane-decision.md)（ADR-0003）、
> [protocol-hardening-decision.md](./protocol-hardening-decision.md)（ADR-0005）。

## 决策

**不实现 CORS，也不依赖它。** 浏览器面（`/app/*`、`/auth/*`、`/bind`）与协议面（`/oauth/*`、
`/.well-known/*`）都按**同源**部署假定：服务不发出任何 `Access-Control-Allow-*` 头，也不处理
预检 `OPTIONS`。这是决定，由下面那条守卫钉住。

## 理由

1. **没有这个需求。** 浏览器面是服务自己 `go:embed` 的 SPA，同源；协议面的调用方是**后端的**
   RP 与数据源，不是网页脚本。令牌端点本来就不该被浏览器里的第三方脚本直接 `fetch`——
   公开客户端的正确形状是重定向 + PKCE，而那条路不经过 CORS。
2. **CORS 是"放行谁"的问题，而答案会退化成"所有人"。** 一个授权服务器一旦开始按 `Origin` 放行，
   就等于把"哪些站点可以对着 `/oauth/*` 发请求"变成一份需要维护的名单；默认拒绝的代价只是
   "跨源前端请走后端"，收益是不必维护这份名单，也不必承担名单写错一次的后果。
3. **默认值已经安全。** 浏览器默认拒绝跨源读取响应；什么都不做就是拒绝，而"加上 CORS"永远是
   一次**放宽**，应当由一个新决定来授权，而不是由某次顺手改动带来。

## 代价与残余

- **跨源 SPA 客户端走不通**（例如想把同意页嵌进别人的站点）。这属于**明确不做**：同意页存在的
  意义就是让用户在**本服务**的页面上做决定。真需要嵌入时开新 ADR，要回答的是"谁可以把它嵌进去"
  （以及 `frame-ancestors` 怎么配合），而不是笼统地加 `Access-Control-Allow-Origin: *`。
- **`rs/cors` 仍在依赖树里**（zitadel 的传递依赖），所以"有 CORS 能力"与"用了 CORS"是两件事。
  守卫只看**响应**，不看依赖树——这正是要钉住的东西：能力可以存在，行为必须没有。
- 非浏览器客户端（服务端 RP、数据源、CLI）完全不受影响：它们不发 `Origin`，也不读 CORS 头。

## 守卫

`internal/httpapi` 的 `TestServerEmitsNoCORSHeaders`：带 `Origin` 的请求打到三个面的代表路由
（含协议面与业务面的 `OPTIONS` 预检），断言响应里没有任何 `Access-Control-Allow-*` 头。

这条守卫**先失败过一次**：它上线时立刻抓到库回的那些头（见背景）。实现随之落在
`internal/oidchttp` 的 `ServeHTTP` 边界（`corsFreeWriter`，`WriteHeader` 与 `Write` 都过滤，
因为不显式调 `WriteHeader` 的响应也会由 Go 隐式提交头），于是 discovery 与 `/oauth/*` 两条
缓冲出口都被覆盖，将来新增的分支也一样。

它再次变红的时候，要么是有人加了 CORS 中间件，要么是某个依赖又开始代我们回这些头——
两种都该先来读这一页。

## 重新评估的触发条件

- 出现**真实的**第一方跨源前端（不是"顺便想前后端分离"，而是部署上确实不同源）；
- 或某个标准客户端的浏览器形态要求预检（那时优先考虑它是否能改走重定向 + PKCE）。

发生时开新 ADR，明确**放行谁的 origin**、以及 `Credentials` 与 `Vary: Origin` 的处理，
而不是把开关交给某个默认值。
