# r0semi 架构设计（v0.1）

> 状态：草案。上层依据：[threat-model.md](./threat-model.md)、[account-model.md](./account-model.md)。
> 本文部分采纳 *A Programming Paradigm for Spatiotemporal Composability*（Cordis）的工程模式，
> 并对 Go 语言无法承载的部分做明确裁剪。裁剪理由见 §2。

## 1. 设计目标与原则

1. **能力最小化可强制**：组件只能访问它显式声明的依赖，未声明访问是错误，不是"自觉"。
2. **副作用确定性回收**：组件卸载/禁用/吊销时，其全部副作用（含内存中的明文 stoken）按 LIFO 回滚。
3. **依赖驱动激活（fail-closed)**：依赖不可用时组件进入 INACTIVE，而不是带病运行或降级放行。
4. **静态、可复现**：v1 不支持运行时加载第三方代码；构建产物可复现、可签名。
5. **进程即信任边界**：只有第一方可信组件进进程内；第三方一律进程外。

## 2. 对 Cordis 模式的采纳 / 改造 / 拒绝

| 概念 | 决策 | 说明 |
|---|---|---|
| Revertible effects（effect 携带 inverse，LIFO 回滚） | **采纳** | 用于资源回收与明文零化 |
| Reactive coeffects（声明依赖，依赖变更驱动 activate/deactivate） | **采纳** | fail-closed 的运行时基础 |
| Capability confinement（`inject` = 能力申请，未声明访问报错） | **采纳** | 本架构最大的安全收益 |
| Acquisition / Emission 边界（§6.1） | **采纳** | 区分可逆的 acquire 与不可逆的 emit，指导撤销设计 |
| Coeffect isolation（同一 key 按 realm 解析） | **采纳（后续）** | 多租户 / 测试沙箱 realm；v1 未实现 |
| Coeffect interception（访问时细粒度策略） | **采纳（后续）** | 动态策略，不改依赖图即可调整 |
| Service broker / 服务多路复用（§6.2） | **采纳** | 多上游适配器 + 适配器灰度替换 |
| Declarative 配置 + 增量 reconcile | **部分采纳** | 采纳声明式配置与 reconcile；不采纳 HMR |
| Hot Module Replacement / 运行时加载代码 | **拒绝** | Go 无法卸载模块；且动态代码与可复现/最小攻击面冲突 |
| 形式化 calculus / 元理论 | **拒绝** | 只取工程模式，不引入形式系统 |
| 第三方组件进程内运行 | **拒绝** | 语言级 confinement 对恶意代码无效（论文 §6.3 自陈） |

## 3. 核心抽象（v1 已实现：`internal/core`）

```
Key[T]                                   // 强类型、带命名空间的能力键
  Ref() -> KeyRef                        // (namespace, name)，可比，用作存储身份
  Provide(ctx, value) -> Disposer        // 发布能力（受 Provides 声明约束，本身是 effect）
  Get(ctx) -> (T, error)                 // 读取依赖（受 Inject 声明约束）
  MustGet(ctx) -> T                      // Get 的 panic 版本，供 Apply 使用

Context
  Effect(fn) -> Disposer                 // fn 返回 inverse；卸载时按 LIFO 依次执行
  Disposed() -> bool
  Component() -> string

Component
  Name     string
  Provides []KeyRef                      // 可发布的能力（超出即 ErrUndeclared）
  Inject   []KeyRef                      // 可读取的能力（超出即 ErrUndeclared）
  Apply    func(ctx, cfg) -> (Disposer, error)

Fiber（组件实例）
  状态：INACTIVE -> LOADING -> ACTIVE -> UNLOADING -> INACTIVE；失败为 FAILED
  target: 每个已声明依赖当前解析到的 provider 身份；变化即触发 reload/重试
```

实现要点：

- 键身份是 `(namespace, name)`；类型参数只提供编译期安全，不参与运行时身份。
- `App.reconcile` 把组件图驱动到不动点：依赖满足即加载，不再满足即卸载。
- 失败（Apply 返回错误或 panic）→ 先回滚已安装的 effect → `FAILED`，依赖它的组件保持 INACTIVE。
- `Isolate` / `Intercept` 在 v1 **未实现**（见 §8）。

效果与依赖都经由 context；context 之外的访问一律失败。

> **生产接入状态（如实说明）**：`internal/core` 与 `internal/wiring` 已实现并有测试，但目前
> 只有 `oauth` 这一个组件被装配进去；`cmd/re0auth` 的生产组合根仍直接 `NewService(...)`。
> 因此 I1（能力封闭）/ I5（fail-closed）在库层各自成立，但尚未由 core 作为生产部署的门禁。
> 把组合根整体迁入 core 是 §8 的待决事项。

## 4. 组件清单与依赖图

| 组件 | 职责 | Provides | Inject |
|---|---|---|---|
| `http` | 出站 HTTP 客户端 | `http.client` | — |
| `store` | Postgres、迁移 | `store.sql` | — |
| `audit` | 审计（**sink**） | `audit.log` | `store.sql` |
| `ratelimit` | 限流 | `ratelimit` | `store.sql` |
| `clients` | 下游应用注册表 | `oauth.clients` | `store.sql` |
| `oauth` | 授权服务器：authorize/token/refresh/revoke/introspect | `oauth.as` | `oauth.clients`, `oauth.tokens`, `audit.log` |
| `consent` | 授权同意页 | — | `oauth.clients`, `oauth.as` |
| `admin` | 应用注册 / 审核 / 吊销 / Kill Switch | — | `store.sql`, `oauth.clients`, `oauth.as`, `audit.log` |

依赖图（边 `a ──> b` 表示 a 向 b 提供能力；单向、无环）：

```
store ──> audit ──> oauth
store ──> ratelimit ──┐
store ──> clients ────┴──> oauth ──> consent / admin
audit ────────────────────> oauth
```

`audit` 是 sink：任何被审计的组件都不得被 `audit` 依赖，否则成环 → 论文 §6.5，
成环组件将永久 INACTIVE（`App.Check` 会静态报出）。

> **数据源侧不在本表。** 原 `vault` / `upstream.tapsign` / `upstream.taptap.oauth` / `enrollment`
> 已迁出 Re0Auth：它们现在属于**参考数据源**（`referencesource`），并作为公开库
> （`vault` / `tapsign` / `taptapoauth`）供任何数据源复用。**Re0Auth 自身不再持有任何凭据。**

> **包分层（v1 公开化）**：`audit`、`httpclient`、`idp`、`oauth`、`upstreamkit`(+`conformance`)、`vault`、`tapsign`、`taptapoauth`
> 是**公开库**，不依赖 `internal/`，可被**进程外的独立服务**（数据源）导入。Re0Auth 自己的库（`oauth`）
> 不自带能力键——key 与 `core.Component` 装配统一声明在 `internal/wiring`，因为**库不该耦合 DI 容器**。
> 已验证：外部模块 import 这些库编译通过，且传递依赖中无 `internal/`。

### 4.1 vault（已迁至公开包 `vault`，供参考源使用）

vault 是一个**与游戏 / 上游无关的通用加密凭据库**。它只对外暴露一个能力 `vault/crypto`：

```go
Service interface {
    Enroll(ctx, Identity{Subject, Provider}, secret, meta) error
    Use(ctx, Identity, func(secret []byte) error) error   // 明文只在回调作用域内存在
    Revoke(ctx, Identity) error                            // crypto-shredding
    Exists(ctx, Identity) (bool, error)
}
```

- **信封加密**：每个凭据一个随机 DEK（AES-256-GCM），DEK 由 KEK 包裹
- **落盘不加密的部分**（PII，见 threat-model §6.1）：`Identity`（查找键）与 `Meta`（上游 openid/unionid）
  按设计明文。它们不是密钥，但属个人数据；需要时把 `Meta` 纳入密文即可（它目前只写不读）。
  （`KeyWrapper`；默认进程内，KMS 适配器尚未实现，见 threat-model §6.0）；AAD 绑定 `(subject, provider)`，密文无法在身份间搬移。
- **撤销 = crypto-shredding**：删除被包裹的 DEK，密文即使残留也不可解。
- **I2**：明文只通过 `Use` 的回调暴露，回调返回后立即零化（无论回调是否出错）。
- **I3**：`Use` 在把明文交给回调**之前**先落审计；审计不可用则拒绝使用（fail-closed）。
- **多游戏扩展**：`Provider` 对 vault 不透明。新增游戏 / 上游 = 新增一个 provider 值
  + 一个负责该凭据编解码的适配器组件，vault 本身不变。

依赖：`store/credentials`（记录持久化；端口 `vault.Repo` 由 vault 定义，未来的 `store` 组件实现它）
与 `audit/log`。KEK 通过 `Config.KeyWrapper` 注入，因为它是**外部信任边界**（可能是 KMS/HSM，默认是本地 KEK），不是能力。

### 4.2 TapTap 内建账户适配器（已迁至公开包 `tapsign`）

上游凭据是 TapTap 内建账户的 `sessionToken`（民间称 "stoken"）。适配器把它连同定位它所需的
标识一起托管：

```go
type Credential struct {          // 一个 provider 的私有凭据形态，vault 对它不感知
    SessionToken string `json:"session_token"`
    ObjectID     string `json:"object_id"`
}
```

操作（均以 `vault.Use` 取得明文后发起）：

- `Verify`：`GET /1.1/users/me`（`X-LC-Session`）验证存活。
- `Rotate`：`PUT /1.1/users/<objectId>/refreshSessionToken`，返回新 token（用于受控轮换）。
- `Revoke`：上述旋转后**丢弃新 token**，使全部上游登录失效（见 threat-model §7）。

关键约束：上游返回 **403 即视为“凭据已死”**（被动失效检测）；`Revoke` 的幂等目标定义为
“旧 token 已失效”（重试遇 403 即算达成）；绝不在用户未明确同意时触发上游撤销。

实现：公开包 `tapsign`（`NewService(cfg, doer, logger)`）。`Config{BaseURL, AppID, AppKey}` 来自参考源的
`config/referencesource.example.toml`（`[taptap]` 段；cn 为主，global 端点在同段注释里作为备选）；
凭据编解码（`Credential.Encode` / `DecodeCredential`）由该包拥有，vault 不感知。
`ErrInvalidCredential` 是 401/403 的统一信号。

### 4.3 enrollment：设备码换取 sessionToken（已迁至公开包 `taptapoauth`；编排在参考源）

对照 Next-Phi-Backend 查证后的完整链路，**用户无需手抄 stoken**：

```
1. POST {device_code_endpoint}          form: client_id=AppID, response_type=device_code,
   <- {device_code, verification_url,        scope=basic_info, version=1.2.0,
       user_code, interval, expires_in,       platform=unity, info={"device_id":...}
       qrcode_url}
2. 展示 verification_url / qrcode_url 二维码，用户用 TapTap 扫码确认
3. POST {token_endpoint} 轮询            form: grant_type=device_token, code=device_code,
   未确认 -> {success:false, data:{error:"authorization_pending"|"AUTHORIZATION_WAITING"|"slow_down"}}
   已确认 -> {success:true, data:{kid, mac_key}}
4. GET {user_info_endpoint}?client_id=AppID
   Header: Authorization: MAC id="..",ts="..",nonce="..",mac=".."
   签名串: "{ts}\n{nonce}\nGET\n{path?query}\n{host}\n{port}\n\n"，密钥 = mac_key，HMAC-SHA1
   <- {success:true, data:{openid, unionid}}
5. POST {leancloud_base_url}/users       JSON: authData.taptap={kid, mac_key, openid, unionid, ...}
   <- {sessionToken, objectId}            <- 就是 stoken，加轮换所需的 objectId
```

落地拆分：

- 公开包 `taptapoauth`：步骤 1–4。
  `Start` 返回 `DeviceAuth`（含 `Interval` / `ExpiresAt` 与可直接编码成二维码的 `VerificationURL`），
  `Poll` 未确认时返回 `ErrAuthorizationPending`，确认后返回 `tapsign.TapTapToken`。
- `tapsign.Service.Redeem`：步骤 5，把 `TapTapToken` 换成 `Credential{SessionToken, ObjectID}`。

编排现在属于**参考数据源**（`referencesource.TapTapLogin`）：`POST /login/challenge`
返回 `{id, verification_url, user_code, interval_seconds, expires_at}`，`GET /login/poll`
按 `interval` 节流轮询上游，未确认返回 `pending`，确认后 `Redeem` + `vault.Enroll` 并建立
**源自己的会话**。凭据存于 `(openid, "taptap")`——即**源的账号**；TapTap 的 `openid`/`unionid`
与 LeanCloud `objectId` 沉淀为**凭据元数据**（见 account-model.md）。
待确认会话仅存内存（重启即失效，用户重新扫码），不持久化任何临时 device code。

> 注意身份差异：Re0Auth 旧的 `internal/enrollment` 以**已登录的 `usr_`** 为主键（TapTap 账号只作元数据）；
> 源侧反过来——**TapTap 账号就是源账号**，subject 是登录的产物。这是把枚举迁到源侧必须做的改写。

### 4.4 授权服务器（OpenID Provider）（v1 已实现：`oauth`；引擎迁移中）

> **ADR-0001：Re0Auth 升格为 OpenID Provider。** 本节描述的手写 `oauth` 引擎将被
> `github.com/zitadel/oidc/v3/pkg/op` 替换（Phase 1–4，见 [oidc-decision.md](./oidc-decision.md)）。
> 契约已更新：`id_token`（**仅请求 `openid` 时**）、`userinfo`、JWKS、OIDC discovery、
> `offline_access` 语义，并新增两把密钥（签名私钥、令牌加密密钥）。

对下的核心契约。MVP 采用**不透明 access token + introspect**（而非 JWT）：即时可撤销，无需 JWT
密钥轮换，且资源服务器与 AS 是同一服务。**唯一的 JWT 是 `id_token`。**

- **Scope 分级**：`<provider>.<resource>.<action>`，每个 scope 带 `Risk` 与 `ExplicitConsent`。
  `Registry.Resolve` 在签发前校验 scope 已知且对该客户端合法。
- **客户端**：`public`（桌面 / CLI，强制 PKCE S256、无 secret）与 `confidential`（secret 只存
  SHA-256，常量时间比对）；重定向 URI 精确匹配。
- **授权码流程**：`Authorize`（已认证 subject + 已同意 scope）→ 一次性 code（绑定 client /
  redirect / PKCE）→ `Exchange`。
- **令牌**：不透明 AT（默认 1h）+ RT（默认 30d），**每次刷新轮换**；`Refresh` 只允许收窄 scope。
- **设备流（RFC 8628，v1 已实现）**：`BeginDeviceAuthorization` 发 `device_code` + 人类友好 `user_code`
  （`BCDF-GHJK`，去掉元音与易混字符，分隔符不敏感）+ `verification_uri`；`PollDeviceAuthorization` 按
  `interval` 节流，返回 `authorization_pending` / `slow_down` / `access_denied` / `expired_token`；
  用户在前端 `/app/device` 页登录后由 `DecideDeviceAuthorization` 批准或拒绝（可收窄，critical scope 必须逐项勾选）。
  **不强制**：授权码流不受影响。设备码状态走独立的 `DeviceStore`，不触碰令牌存储。
- **撤销 / 自省**：`Revoke` 幂等（RFC 7009）；`Introspect`（RFC 7662）返回 `Active` / subject / scopes。
- **危险 scope 的强制**：`Authorize` 要求任何标记 `ExplicitConsent` 的 scope 必须出现在请求的 `Explicit`
  列表中，否则 `access_denied`，且客户端必须被显式注册该 scope。
  **内置目录当前不含此类 scope**（re0auth 不持有上游凭据，无可导出的东西，见 api-design.md §5）；
  机制保留，并由测试用**合成 scope**覆盖——测试不该依赖产品 scope 的语义。

MVP scope 目录：`account.id`、`taptap.account.id`、`phigros.profile.read`、`phigros.score.read`、
`phigros.b30.read`。provider 包通过 `Registry.Register` 追加自己的 descriptor。

> 尚未实现：资源服务器（真正返回用户 ID / 代理成绩的端点）。
> AS 只负责签发与校验带 scope 的令牌；资源端点在下一层用 `Introspect` + vault 实现。
> **不会实现的**：上游凭据导出端点——re0auth 不持有上游凭据，见 api-design.md §5。

### 4.5 HTTP 层与两平面路由（v1 已实现：`internal/httpapi`）

它不是 core.Component（是系统最外层），而是 `New(Config) (*Server, error)` + `Handler()`。

```
re0auth.r0semi.net
├── /.well-known/oauth-authorization-server    RFC 8414
├── /.well-known/oauth-protected-resource      RFC 9728
├── /app/…     前端 SPA（`go:embed` 进二进制；`/app/consent`、`/app/device`、`/app/grants`、`/app/sources`）
├── /oauth/…   协议平面：form 编码 + OAuth 错误 + recoverProtocol
└── /v1/…      业务平面：JSON + problem+json + recoverBusiness
```

**只有三个挂载点，而且前端被钉在自己的前缀上。** 前端是客户端路由，未知路径会回落到 SPA shell 而不是 404，
所以它一旦挂在 `/`，API 的 404 就会变成 HTML。`/app/` 的前缀也因此**必须**与 `web/vite.config.ts` 的
`paths.base` 一致——这种不一致不会报错，只会静默路由不到任何东西，所以由测试直接比对那个配置文件。

已实现：`POST /oauth/token`（authorization_code / refresh_token / device_code，支持 Basic 与 post 客户端认证）、
`POST /oauth/device_authorization` + `GET /v1/device/verification` + `POST /v1/device/decision`（RFC 8628 设备流）、
`POST /oauth/introspect`（要求客户端认证）、`POST /oauth/revoke`、`GET /v1/me`（Bearer + scope 校验）、
`GET /v1/grants` + `DELETE /v1/grants/{client_id}`（会话；下游撤销，见 api-design.md）、
`GET /v1/sources`（公开）、`GET /v1/bindings` + `DELETE /v1/bindings/{game}/{source}`（会话；断开数据源，
并尽量让源按 RFC 7009 撤销它签发的令牌）、
`POST /v1/bindings/{game}/{source}/cascade_revocation`（会话 + 显式确认；请求数据源作废整段上游会话）、
两个发现端点。`GET /oauth/authorize` 走 `authz.Begin` → 重定向到同意页；`GET /bind` 走 `federate.BeginBind`。

**断开的本地一半总是发生。** 数据源宕机、坏掉或拒不配合，都不能阻止用户把它从自己的账号上摘下来；
上游那一半是尽力而为，结果（`done` / `unsupported` / `unavailable` / `nothing`）随响应一起回去，
因为“在这边断开了，但那边还留着”与“已全部清理”是两句不同的话。

**一条授权不是存下来的实体，而是“该账号名下仍有效的令牌按 client_id 聚合”。** 好处是撤销就是删令牌，
不存在“同意表说已撤销、令牌表还能用”这种两个真相源互相矛盾的状态；代价是列表显示的是**当前访问**而非历史同意，
某个应用最后的 refresh token 也过期后它会从列表上消失。理由写在 api-design.md。

RFC 8628 的 `verification_uri` 指向**人类页面** `/app/device`（`oauth.Config.VerificationPath`），
而不是给它供数据的 JSON 端点 `/v1/device/verification`——这两个东西指向同一个对象但没有理由共用路径。

### 4.6 前端（`web/` + `internal/webui`）

SvelteKit 2 + Svelte 5 + Tailwind v4，`adapter-static` 输出到 `internal/webui/dist`，由 `//go:embed` 嵌进二进制，
挂在 `/app/`。`ssr = false`，纯客户端渲染。

**为什么是纯静态而不是 SSR**：每个页面在 `/v1` 回答之前都是空的，而 `/v1` 要的是浏览器自己的会话 cookie。
服务端渲染就得转发那个 cookie，也就是在链路上再放一份会话。更根本的是，它会让“同意页到底写了什么”
有**两处**答案（服务端渲染一处、浏览器获取一处），而两者迟早会不一致——偏偏就是那个靠“关于授予了什么值得信任”
才能成立的页面。

**为什么前端必须钉在 `/app` 前缀**：它是客户端路由，未知路径回落 SPA shell 而不是 404。挂在 `/` 上，
API 的每个 404 都会变成 HTML。前缀与 `web/vite.config.ts` 的 `paths.base` 必须一致，而这种不一致不会报错，
只会静默路由不到任何东西，所以 `internal/webui/webui_test.go` 直接读那个配置文件来比对。

**CSP 分两层，各自拿自己需要的东西**：

| 层 | 谁发 | 内容 | 为什么在那 |
|---|---|---|---|
| HTTP 头 | `internal/webui` | `frame-ancestors 'none'` 等 | `frame-ancestors` **在 meta 标签里会被忽略**，所以必须走头 |
| `<meta>` | SvelteKit（`kit.csp` mode `hash`） | `script-src 'self' 'sha256-…'` | 内联 bootstrap 脚本的 hash 每次构建都变，只有构建方能算出来 |

因此 `script-src` 里**没有** `'unsafe-inline'`。两套策略按**交集**生效。

**未构建前端也不能让 `go build` 失败**：`//go:embed all:dist` 要求目录存在且非空，而 `adapter-static` 会先清空输出目录。
两者直接冲突——前者要新克隆就能编译，后者要独占那个目录的内容。
解法是让占位文件由 `npm run build` 在构建后自己重新写回（`web/scripts/restore-dist-placeholder.mjs`），
而不是做成一个可以被遗忘的独立步骤。占位目录里没有 `index.html`，所以“`index.html` 存在”就是“真的构建过”的证明，CI 据此断言。

### 4.7 浏览器端到端（`web/e2e`，Playwright）

11 个测试，驱动真实 Chromium 跑完同意页与设备流。它们自己 `go build` 一个 re0auth、起一个假身份提供方，
并把客户端注册的 redirect URI 也交给同一个假服务，这样浏览器给出的授权码能直接从地址栏读出来。

**没有任何测试专用的登录后门。** 假身份提供方是在**网络边界**上假的，不是把登录绕过去：PKCE、码交换、
建号、会话 cookie、CSRF token、绑定到会话的 handle，全部是发货代码。一个有后门的套件只能证明那条
永远不跑的登录路径。

它做的事不止“页面看起来对”：每个用例都跟到客户端**最终拿到什么**——同意页点完会把 code 换成 token，
再用那个 token 调 `/v1/me`。而“取消勾选一个 scope”会同时断言两次：token 里没有它，且同一个路由
从 409（有 scope、无绑定）变成 403（scope 被拒）——**缩小范围是服务端强制的，不是复选框强制的**。

**它抳出了一个其他所有测试都看不见的 bug**，值得记在这里：

HTTP 头和 `<meta>` 同时存在时，**两个 CSP 都强制执行**。`internal/webui` 原来在头里把整个策略又说了一遗，
包括不带 hash 的 `script-src 'self'`；SvelteKit 的 meta 用 hash 放行它自己的内联 bootstrap 脚本，头不放行，
于是头赢了，应用自己的启动脚本被封，页面**全白**。单元测试全程都在看头的值，所以什么也没发现。
修法就是回到设计本意：头只带 `frame-ancestors 'none'`（因为浏览器在 meta 里忽略它），其余归构建方。
`internal/httpapi/frontend_test.go` 现在断言头**不得**重述 `script-src` 等指令。

**限流**（`internal/ratelimit`，基于 `golang.org/x/time/rate`）：可选的 `Config.Limiter` 在会话中间件之外
先拦住超预算的调用方；按客户端地址分桶、空闲驱逐。**两个平面各自的错误形态**：`/oauth/*` 与 `/.well-known/*`
返回 OAuth 错误，其余返回 `problem+json` 的 `rate_limited`。

**出站韧性**（`httpclient.Retry`，基于 `cenkalti/backoff/v4`）：指数退避 + 抖动，认 `Retry-After`，
**默认只重试幂等方法**（POST 不隐式重放）。选型见 [dependencies.md](./dependencies.md)。

关键不变量（由 `internal/httpapi` 测试守护）：**协议平面绝不输出 problem+json，业务平面绝不输出
`{error,error_description}`**；两平面各有独立子 mux、错误写出器与 panic 恢复，仅共享 request-id 中间件。

### 4.6 /auth 平面与会话（v1 已实现：`idp`、`internal/account`、`internal/auth`）

- `idp`：r0semi 作为 GitHub / Google / Discord / QQ / 微软 的 OAuth 客户端
  （`golang.org/x/oauth2`，强制 PKCE S256），把回调规范化为 `Identity{Provider, Subject, ...}`。
  **OIDC 提供方（Google / 微软）走 `coreos/go-oidc`**：对 `id_token` 验签名（issuer JWKS）、issuer、
  audience、过期与 **nonce**（调用方必须把 `AuthCodeURL` 的 nonce 回传给 `Identity`）；
  无 `id_token` 则**失败关闭**，绝不退回 userinfo。非 OIDC 提供方（GitHub / QQ）继续用 userinfo，
  QQ 走 JSONP + 非标准 profile API。发现（discovery）懒加载并缓存，失败不缓存。
- `internal/account`：`usr_` 的唯一分配者，强制三条账号不变量（平权 / 底线 / 隔离，见 account-model.md §2）。
- `internal/auth`：基于 `alexedwards/scs` 的服务端会话（`__Host-` HttpOnly Cookie + 登录时轮换）、
  CSRF（会话内同步令牌 + `X-CSRF-Token`）、`/auth/{provider}/start|callback` 处理器。
- `httpapi` 在配置 `Sessions` / `Accounts` / `Auth` 时挂载 `/auth/`、包上会话中间件，
  并提供 `GET /v1/sessions/current`、`POST /v1/sessions/sign_out`。

### 4.7 授权交互 API（v1 已实现：`internal/authz` + `httpapi`）

把 `/oauth/authorize` 从 stub 变成真实浏览器流程，同时把安全判断全部留在服务端：

- `GET /oauth/authorize`（协议平面）：校验并 `authz.Begin` 建立服务端 pending 请求（handle），
  把 handle 绑定到当前浏览器会话，302 到前端 `/consent?id=<arq_...>`。
  客户端未知 / 重定向非法 → JSON OAuth 错误；scope 非法 → 302 回客户端 `error=invalid_scope`。
- `GET /v1/authorization_requests/{id}`（业务平面，需登录 + 会话绑定）：返回客户端名与 scope 描述
  （含 `risk` / `explicit_consent`）、`csrf_token`，以及 `missing_bindings`——请求的 scope 中
  还需要但尚未连接的数据源，每项带服务端拼好的 `bind_url`（`return_to` 指回同一 handle）。
- `POST /v1/authorization_requests/{id}/decision`（需登录 + CSRF）：`{decision, scopes, explicit}`；
  批准 → `authz.Approve` → `oauth.Authorize` 签发 code → 返回**服务端拼好的** `redirect_to`。
- **渐进式绑定**：同意页在 `missing_bindings` 非空时禁用批准并引导连接；绑定回调回到同一
  pending handle（`authorizationRequestTTL` 需长于 federation 的绑定 TTL）。取消勾选某个 scope
  即可解除它对应的绑定要求。
- `authz.Approve` 只允许**收窄** scope，并把 `explicit` 交给 AS 复核 critical scope；
  handle 单次使用、短时效、绑定浏览器。

### 4.8 Upstream Kit 与一致性测试（v1 已实现：`upstreamkit`）

数据源（游戏后端）接入生态的工具链：

- `upstreamkit`：协议类型（发现文档 / canonical scope / `token_class`）+ 可挂载的 HTTP 服务
  （`/.well-known/re0auth-upstream`、`/oauth/*`、`/account`、`/resources/{name}`），复用 `oauth`
  作为 OAuth 核心；游戏相关的部分（用户认证 / 同意、账号、资源）由 hooks 提供。
- `upstreamkit/conformance`：可执行的一致性套件，对任意数据源产出 findings
  （error / warning / skipped）；带 `AccessToken` 时额外检查数据面。
- 参考上游在测试中由 Kit 构建并通过套件。**把真实 TapTap 适配器包装为数据源需要先把凭据
  从 re0auth 移到数据源侧**，属后续工作。

### 4.9 数据联邦层（v1 已实现：`internal/federation`）

re0auth 的数据面：把下游对某个游戏资源的请求，映射到一个已绑定的上游数据源，并返回该源的规范化载荷。

- **源注册表**：静态配置 `Source{Game, Name, Issuer, TokenClass, Resources[{Name, Schema, Scope}]}`。
- **绑定**：`(usr_, game, source)` → **元数据**（`BindingStore`：`HasRefresh`/`Expiry`/`Version`）
  **+ 上游令牌**（`vault`，信封加密，键 `Provider = "<game>.<source>"`）。
  **绑定表里没有任何凭据**。交互式流程：
  `GET /bind?game=&source=&return_to=`（需登录）→ 跳上游 authorize（PKCE）→
  `GET /auth/upstream/{game}/{source}/callback` → 令牌入 vault、元数据入绑定表。
  flow 绑定浏览器会话、单次使用、短时效。
- **拉取**：`Fetch(user, game, resource, source?)` → 选源 → 取绑定 → 在 `vault.Use` 的明文窗口内
  调 `{issuer}/resources/{name}`（带 Bearer）→ 逐字返回其 JSON。
- **令牌刷新**：绑定接近过期时主动刷新；上游 401 时强制刷新并重试一次。按 binding 串行
  （keyed mutex）避免轮换竞争（用单调递增的 `Version` 识别“别人已轮换”）；refresh 被拒（`invalid_grant`）
  则**删除绑定元数据与 vault 密文**，回到“引导绑定”。
- **多源仲裁**：源有 `active/degraded/retired` 状态。未 pin 时按「active → degraded」顺序尝试、跳过 retired；
  首个失败而后续成功 → `Re0Auth-Degraded: true`。**pin 的源绝不替换**（失败即失败；retired → `410 source_retired`）。
- **raw 透传**：`GET /v1/games/{game}/sources/{source}/raw/{path...}` 逐字转发源的原始 API
  （状态码、Content-Type、body 均不改），供需要上游原生方言的消费者使用。
- **HTTP**：`GET /v1/games/{game}/sources`（公开发现，含状态与 raw 支持）、
  `GET /v1/games/{game}/{resource}`（AT + scope）。响应带 `Re0Auth-Source`，降级时附 `Re0Auth-Degraded`。

> 已知粗粒度处：raw 的 scope 门禁用的是“该源任一资源 scope”，专用 `<game>.raw.read` 为后续工作。

### 4.10 参考数据源（切片 1–4 已实现：`referencesource` + `cmd/referencesource`）

第一个**独立数据源**，也是 Upstream Kit 的实战验证。它把待验证的命题写成了代码：
**后端原生登录无需是 OAuth 2.0，仍能成为合规数据源**——因为 OAuth 2.0 AS 面由 Kit 生成。
它同时验证了反面：源的登录**本身是 OAuth**（Google/GitHub）也一样成立。

- **源拥有两样 Re0Auth 永不可见的东西**：**会话**与 **vault**。每个 `Login` 只需产出一个 `Principal`；
  由源的 `establish` 统一把凭据存进 vault（键 = 源自己的账号）、把 subject 写入会话。
- **`Login` 接缝**：`Mount(mux, establish)`。已实现两种，可同时启用：
  - `TapTapLogin`：TapTap 设备码/扫码（`taptapoauth` + `tapsign.Redeem`），
    路由 `POST /login/taptap/challenge`、`GET /login/taptap/poll`；
  - `SocialLogin`：标准 OAuth IdP（Google/GitHub/Discord/QQ/微软），复用公开包 `idp`，
    路由 `GET /login/{provider}/start|callback`，PKCE + 单次 state，subject 按 provider 命名空间化（`google:123`）。
- **`Authenticator` 接缝**：对应 Kit 的 `Consent` 钩子；源只**读自己的会话**。
  未登录 → access_denied，绝不编造身份。`Logins` 优先于静态 `Auth`（防止加了登录面却仍用 demo 身份）。
- **凭据归属**：主键是**源自己的账号**，**不是** Re0Auth 的 `usr_`。
  资源读取走 `vault.Use` 的明文窗口（回调内有效、返回即零化）。
- **端到端已验证**：`federation` 作为 OAuth 客户端，对该源跑通
  登录（扫码 / 社交 OAuth）→ `BeginBind`(PKCE) → authorize（经 `Consent` 读会话）→ token 交换 → `Fetch`，
  并过 conformance suite。真实 TapTap / Google 方言由注入的假上游端到端驱动，不需外网。
- **进程边界**：`cmd/referencesource` 能作为真进程跑；`TAPTAP_CLIENT_ID`、`GOOGLE_CLIENT_ID`、`GITHUB_CLIENT_ID`
  各自启用一种登录面。它**与 Re0Auth 不共享任何代码路径、数据库或凭据库**。

> 切片 3–4（已完成）：Re0Auth 已删 `/v1/enrollments`、`internal/enrollment`、`internal/vault` 与旧 TapTap 适配器；
> `vault`/`tapsign`/`taptapoauth`/`idp` 提升为公开库，随参考源一同发布；`referencesource` 也已提到顶层。

### 4.11 组合根与持久化（v1 进行中：`cmd/re0auth` + `internal/store/postgres`）

**`cmd/re0auth` 是组合根**：从 TOML 文件 + 环境变量读配置（见 `config/re0auth.example.toml`），
装配全部组件，起两个 HTTP 平面。它的存在是为了让存储适配器有一个**真实调用者**，而不是只被测试调用。
启动时把仍在内存的部件**大声说出来**：

```
WARNING: no DATABASE_URL; every store is in-memory -- a restart loses sessions, bindings and pending requests
```

设了 `DATABASE_URL` 后，同一行变成：

```
storage: every port is persistent (accounts, tokens, device authorizations, clients, vault credentials, bindings, bind flows, sessions, authorization requests)
```

“哪些部分是持久的”绝不能靠猜。

**配置约定**：文件只放结构（端点、驱动、哪些 provider/源存在），**密钥只来自环境**——文件写的是
变量名（`*_env`），不是值。优先级为 **环境 > 文件 > 默认值**；校验 fail-closed，缺密钥/缺 issuer/Kek 长度
不对，都拒绝启动。共享辅助在 `internal/config`，因为密钥解析语义在两个二进制里各写一份必然漂移。

**Postgres 适配器**（`internal/store/postgres`）落在接口包**之外**，因为公开库（`oauth`、`vault`）
不能依赖数据库驱动。**9 个存储端口全部已落地**：`account.Store`、`oauth.Store`、`oauth.DeviceStore`、
`oauth.ClientRegistry`、`vault.Repo`、`federation.BindingStore`、`federation.BindFlowStore`、
`scs.Store`（会话）、`authz.Store`（待授权请求）。**后端持久化到此收尾。**

| 关注点 | 做法 |
|---|---|
| 迁移 | `embed.FS` 内嵌 SQL + `schema_migrations` + `pg_advisory_lock`（多实例同时启动不打架） |
| 令牌落盘 | 全部按键 `sha256(value)`，**明文永不入库**；测试直接查表断言。
  会话 cookie 同理（`sessions.token_hash`）——否则一张表泄露就是一整套可用会话 |
| 凭据落盘 | 只存不透明密文材料；测试驱动真实信封加密写表，再把整行 dump 出来搜明文（并防空断言） |
| 单次使用 | 一条 `DELETE ... RETURNING`（授权码 / refresh / bind flow；比内存实现**更难写错**） |
| 账号 I-3 隔离 | `UNIQUE (provider, subject)`，唯一冲突 → `ErrIdentityTaken` |
| 账号 I-2 底线 | 事务内 `SELECT ... FOR UPDATE` 锁用户行后再计数 |
| 账号 I-1 平权 | `primary_identity` 仅为展示指针，解绑时重指最早的存活身份 |
| 客户端密钥 | 只存摘要（`bytea`）；`oauth.RestoreClient` 从库里重建 |
| 绑定表不能持有凭据 | Go 结构体无令牌字段 + 测试从 `information_schema` 断言无 token/secret 类列 |

**测试分层**：单元测试继续用 `Memory*`（任何平台、不需数据库）；Postgres 适配器测试由
`TEST_DATABASE_URL` 门控，未设则 `t.Skip`；**权威验证跑 Linux CI**（`ubuntu-latest` + `postgres:16` 服务，
`.github/workflows/ci.yml`）。CI 里若变量缺失则**直接失败**，不允许静默跳过；并单独 verbose 跑一遍，
让日志逐条证明测试真的执行了（`ok` 在 skip 与 pass 两种情况下长得一样）。

**两个端口刻意不对 handle 做哈希**，因为哈希在那里保护不了什么：`authz_requests.id` 设计上就出现在
浏览器 URL 与服务器日志里，且 HTTP 层另外把它绑定到创建它的会话，偷到 handle 在别处也无用。
分类写在各自的迁移注释与 threat-model §6.1 里。

会话额外做了一件事：`scs.Store` 的接口**不带 context**（scs 不传），所以适配器用 `context.Background`；
过期会话在 `Find` 时按 scs 语义当作“未找到”并顺手删除，另有 15 分钟一次的 `SweepExpired` 定期清理
（`Find` 只清那些还会被访问的）。待授权请求同样有 sweep。

> 本地开发：`docker run -e POSTGRES_PASSWORD=x -p 5432:5432 postgres:16`，然后
> `TEST_DATABASE_URL=postgres://postgres:x@localhost:5432/postgres?sslmode=disable go test ./internal/store/postgres/`。

> 本地开发：`docker run -e POSTGRES_PASSWORD=x -p 5432:5432 postgres:16`，然后
> `TEST_DATABASE_URL=postgres://postgres:x@localhost:5432/postgres?sslmode=disable go test ./internal/store/postgres/`。

## 5. 安全不变量（必须由测试守护）

- **I1 能力封闭**：未声明的 key 访问必须报错；CI 中静态审计每个组件的 `Inject` 集合。
- **I2 明文零化**：所有解密出的明文 stoken 必须登记为 effect，其 inverse 为零化；禁止明文离开 acquire 作用域。
- **I3 先审计后 emit**：跨越 emission 边界前先持久化审计（withholding）。
- **I4 补偿幂等**：跨边界动作必须提供幂等补偿（如撤销级联到 TapTap）；补偿失败必须可见、可重试。
- **I5 fail-closed**：依赖不可用 → 组件 INACTIVE，绝不降级放行。
- **I6 无动态代码**：v1 不加载运行时第三方代码；第三方适配器走进程外 gRPC。

`go test ./...` 共 204 项（本机默认）+ 11 项 Postgres 集成测试（未设 `TEST_DATABASE_URL` 时跳过，在 Linux CI 执行），
覆盖的安全不变量：

| 不变量 | 测试 |
|---|---|
| I1 | `core`: `TestUndeclaredCapabilityIsRejected`, `TestProvideRequiresDeclaration`；`vault`: `TestComponentCapabilityDeclaration` |
| I2 | `core`: `TestEffectRunsLIFO`, `TestDisposerIsIdempotent`, `TestZeroizeOnUnload`；`vault`: `TestUseZeroizesPlaintext`, `TestUseZeroizesOnCallbackError` |
| I3 | `vault`: `TestUseAuditsBeforeCallback`, `TestUseFailsClosedWhenAuditFails`；`tapsign`: `TestRotateReturnsReplacement`, `TestRevokeDiscardsReplacement` |
| I4 | `tapsign`: `TestRevokeIsIdempotentOnInvalid`（目标 = 旧 token 已失效，403 即达成） |
| I5 | `core`: `TestFailClosedMissingProvider`, `TestReactiveActivationAndDeactivation`, `TestDuplicateProviderFailsClosed`, `TestCycleStaysInactive`, `TestPanicInApplyFailsClosed`；`vault`: `TestComponentInactiveWithoutRepo`, `TestComponentFailsWithoutKeyWrapper`；`tapsign`: `TestComponentInactiveWithoutHTTP`, `TestComponentFailsWithoutConfig`；`wiring`: `TestComponentInactiveWithoutTokens`, `TestComponentFailsWithoutIssuer` |
| 平面隔离 | `httpapi`: `TestTokenErrorUsesOAuthFormat`, `TestBusinessErrorUsesProblemFormat`, `TestUnknownEndpointsArePlaneSpecific`, `TestInsufficientScopeIsForbidden` |
| 账号 I-1/I-2/I-3 | `account`: `TestUnlinkRejectsLastIdentity`, `TestLinkRejectsIdentityOwnedByAnotherUser`；`auth`: `TestLinkRejectsTakenIdentity`, `TestLinkAddsIdentityToCurrentUser` |
| 授权交互 | `authz`: `TestApproveIssuesUsableCode`, `TestApproveCannotWidenScope`, `TestApproveEnforcesExplicitConsent`, `TestApproveIsSingleUse`；`httpapi`: `TestAuthorizationInteractionEndToEnd`, `TestAuthorizationHandleIsBoundToBrowser`, `TestDecisionRequiresCSRF` |
| 上游协议 | `upstreamkit`: `TestReferenceUpstreamPassesConformance`, `TestKitAuthorizeFlow`；`conformance`: `TestMissingAccountScopeIsAnError`, `TestBadTokenClassIsAnError`, `TestAuthorizeRedirectingUnknownClientIsAnError`, `TestTokenAcceptingBadGrantIsAnError` |
| 数据联邦 | `federation`: `TestFetchReturnsSourcePayload`, `TestBindFlow`, `TestFetchRefreshesExpiredBinding`, `TestConcurrentRefreshHappensOnce`, `TestFetchFallsBackAndMarksDegraded`, `TestPinnedSourceIsNotSubstituted`, `TestRawPassthroughIsVerbatim`, `TestActiveBeatsDegraded`；`httpapi`: `TestGameResourceDataPlane`, `TestSourceBindingEndToEnd`, `TestGameRawAndDegraded` |
| 其他 | 信封 / 身份绑定 / provider 隔离；403 被动失效检测；MAC 签名（`TestMACAuthorizationSignsDocumentedString`） |

端到端：`referencesource` 的 `TestTapTapLoginEndToEnd` 用 httptest 假 TapTap + 真实 vault，
打通 `TapTapLogin.Start/Poll → tapsign.Redeem → vault.Enroll → 源会话 → Consent → federation.Fetch` 全链路。

`oauth` 覆盖授权码全流程、PKCE、code 单次使用、scope 收窄 / 拒绝、
critical scope 强制显式同意、refresh 轮换、撤销幂等、令牌过期。

`internal/httpapi` 用 `httptest` 跑完整 HTTP 往返：发现端点、授权码兑换、
`/v1/me` 的 Bearer + scope 校验、自省 / 撤销、以及两平面错误格式互不泄漏。

`internal/auth` 用假 IdP + Cookie jar 跑完整登录/绑定往返：start 生成 PKCE、callback 兑换并落地会话、
`identity_taken` 拒绝、`return_to` 防开放重定向、CSRF 令牌校验。

`internal/httpapi` 的 `TestAuthorizationInteractionEndToEnd` 用一套假 IdP 跑通**全栈**：
登录 → `/oauth/authorize` → 同意页数据 → 决策 → 换码 → `/v1/me`。

## 6. 进程边界与部署

- **进程内（可信）**：`core`、`store`、`vault`、`audit`、`oauth`、`admin`、第一方适配器。
- **进程外（不可信 / 隔离）**：第三方下游集成、可能被利用的解析类组件、KMS/HSM（**若部署接入**，外部服务）。
- 跨进程访问按论文 §6.2 设计为**异步契约**；进程外 bridge 在宿主侧是一个普通 fiber，
  其能力可被 attenuation（收窄）。

## 7. 配置与编排

- 声明式配置（TOML，见 `config/re0auth.example.toml`）描述服务与数据源，作为"系统加载了什么"的唯一权威记录。
- 增量 reconcile：按字段变化采取最小扰动操作；不引入 HMR。
- 禁用某组件 = 该 fiber unload，其 effect 按 LIFO 回滚。

## 8. 已决事项与待决问题

**已决（v1）**：

1. **core 自研**：实现为 `internal/core` 的极薄内核，只做 Effect + Provide/Inject + 生命周期
   + 能力封闭校验；拒绝 HMR、运行时加载代码、通用插件系统。见 §3。
2. **Key 身份**：强类型泛型 `Key[T]` 包装 `(namespace, name)`；`reflect.Type` 不参与身份，
   避免同一能力的多个声明点因类型不同而分裂。
3. **不做动态拦截**：v1 仅静态能力声明（`Provides` / `Inject`）；`Isolate` / `Intercept`
   留待后续版本。

**待决**：

1. 进程外 bridge 的协议与鉴权（mTLS？DPoP？）。
2. 补偿动作（TapTap 撤销）的幂等键与重试队列设计。
3. isolation / interception 的引入时机与形态。
4. core 的可观测性：fiber 状态是否导出为指标，`App.Check` 结果是否作为 CI 门禁。

## 9. 参考

- Yifan Shi, Wei Zhang, Tianyi Cui. *A Programming Paradigm for Spatiotemporal Composability*.
  arXiv:2608.25512v1. <https://arxiv.org/abs/2608.25512>
  **本文档中所有「论文 §x.y」均指此文。**
  （论文本体不再随仓库分发：arXiv 不授予第三方再分发权，且会让仓库体积无谓增大。请从上述链接获取。）
