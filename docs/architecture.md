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

> **两种裁剪（Go vs Rust）**：同一篇论文在姊妹项目 r0semi-mp（Rust）里被裁到编译期——
> 空间可组合性用 trait 契约 + 组合根 + 依赖方向矩阵，时间可组合性用 RAII + 重启即换，运行时成本为零。
> 本项目**采纳了运行时机制**，因为 Go 没有 RAII/Drop，也没有类型级封闭（只有包级 `internal/`）。
> 但采纳运行时 ≠ 生产必须启用它：`core` 的生产接入决策见
> [core-runtime-decision.md](./core-runtime-decision.md)（ADR-0002）。

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
> 把组合根整体迁入 core 是 §8 的待决事项；**该决策已定：ADR-0002 决定 v1 不迁入**，
> 改由 `internal/archtest` 强制依赖方向，重新评估的触发条件见
> [core-runtime-decision.md](./core-runtime-decision.md) §5。

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
| `admin` | 应用注册 / 审核 / 吊销 / Kill Switch（**已实现**，见 §4.14） | `admin` | `oauth.clients`, `oauth.tokens`, `audit.log` |

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

> **包分层（v1 公开化）**：`audit`、`httpclient`、`idp`、`oauth`、`upstreamkit`(+`conformance`)、`vault`、`tapsign`、`taptapoauth`、`referencesource`
> 是**公开库**，不依赖 `internal/`，可被**进程外的独立服务**（数据源）导入。Re0Auth 自己的库（`oauth`）
> 不自带能力键——key 与 `core.Component` 装配统一声明在 `internal/wiring`，因为**库不该耦合 DI 容器**。
>
> 这条边界**不是自觉，是机器强制的**：`internal/archtest` 用 `go list` 读真实导入图，在 `go test ./...`
> 与 `make check` 里断言——公开库（含传递依赖）不得触及 `internal/`；`internal/store/postgres` 只许
> 组合根 `cmd/*` 导入；`internal/core` 不依赖任何内部包；**新增顶层包必须在 `internal/archtest` 登记**，
> 否则 CI 直接失败（"先更新表再合并"）。新增业务模块的落点见
> [core-runtime-decision.md](./core-runtime-decision.md) §7。

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
- **账号级擦除 = 按 subject 删整行**（`vault.Repo.DeleteSubject`）。没有「每账号密钥」可以销毁——DEK 是
  **每条记录一个**、按 `(Subject, Provider)` 寻址、包裹后就存在该行里——所以「擦除一个账号」就是删掉它名下的每一行。
  删**整行**而非只置空 `WrappedDEK` 是有意的：`Identity` 与 `Meta` 是明文 PII，只置空密钥会留下 PII，
  变成一次自称成功、实则没有的抹除。subject 是 `vault_credentials` PK 首列，这条删除走索引。
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

### 4.4 授权服务器（OpenID Provider）（已实现）

> **ADR-0001：Re0Auth 是 OpenID Provider。** 本层由
> `github.com/zitadel/oidc/v3/pkg/op` 提供（`internal/oidchttp` + OP store）。**生产与内存模式都走 OP**
> （ADR-0001 P4b）：有数据库时 state 落在 `internal/store/postgres` 的 `OIDCStore`，无数据库时落在
> `internal/store/memory`；两者共享 `internal/oidcstore` 的签名密钥、客户端适配与同意策略。契约见
> [oidc-decision.md](./oidc-decision.md)：
> `id_token`（**仅请求 `openid` 时**）、`userinfo`、JWKS、OIDC discovery；`offline_access` 作为兼容性空操作；
> 两把密钥（RS256 签名私钥、32B 令牌加密密钥）由 `RE0AUTH_OIDC_SIGNING_KEY` / `RE0AUTH_OIDC_TOKEN_KEY` 配置，
> **两种模式都必填**（缺一拒绝启动）。
> 手写 `oauth` 包仍是 **Upstream Kit（数据源侧）** 的 AS 引擎，不再是 re0auth 的授权引擎。

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
  **内置目录当前不含此类 scope**（re0auth 手里没有**原始平台**凭据，无可导出的东西，见 api-design.md §5）；
  机制保留，并由测试用**合成 scope**覆盖——测试不该依赖产品 scope 的语义。

MVP scope 目录：`account.id`、`taptap.account.id`、`phigros.profile.read`、`phigros.score.read`、
`phigros.b30.read`。provider 包通过 `Registry.Register` 追加自己的 descriptor。

> **资源服务器（数据面）已实现**：`GET /v1/me` 返回身份，`GET /v1/games/{game}/{resource}`
> 代理读取源侧的归一化载荷，`GET /v1/games/{game}/sources/{source}/raw/{path...}` 逐字透传源的
> 原生 API；两者都要求 Bearer + 对应 scope。实现落在 `internal/federation`（绑定 / 取回 / 刷新）
> 与 `internal/httpapi`（路由 / 门禁），不是「下一层」。
>
> **但它只代理、不拥有数据**：没有配置源、或用户尚未绑定该源时，数据面什么都不给
> （`source_not_bound` / 空列表），所谓「代理成绩」是把源的 JSON 原样返回。上游凭据由数据源
> 自己持有，re0auth 只托管源签发的令牌。
> **不会实现的**：上游凭据导出端点——要导出的**原始平台**凭据在数据源手里，而本地那份**源签发**的
> 令牌永不交给下游，见 api-design.md §5。

### 4.5 HTTP 层与三平面路由（v1 已实现：`internal/httpapi`）

它不是 core.Component（是系统最外层），而是 `New(Config) (*Server, error)` + `Handler()`。

```
re0auth.r0semi.net
├── /.well-known/oauth-authorization-server    RFC 8414
├── /.well-known/oauth-protected-resource      RFC 9728
├── /app/…     前端 SPA（`go:embed` 进二进制；`/app/consent`、`/app/device`、`/app/grants`、`/app/sources`）
├── /oauth/…   协议平面：form 编码 + OAuth 错误 + recoverProtocol
├── /v1/…      业务平面：JSON + problem+json + recoverBusiness
└── /auth/、/bind、/app/…、未知路径  浏览器平面：纯文本或重定向（browser-plane-decision.md）
```

**每个命名空间单独挂载，而且前端被钉在自己的前缀上。** 前端是客户端路由，未知路径会回落到 SPA shell 而不是 404，
所以它一旦挂在 `/`，API 的 404 就会变成 HTML。`/app/` 的前缀也因此**必须**与 `web/vite.config.ts` 的
`paths.base` 一致——这种不一致不会报错，只会静默路由不到任何东西，所以由测试直接比对那个配置文件。

已实现：`POST /oauth/token`（authorization_code / refresh_token / device_code，支持 Basic 与 post 客户端认证）、
`POST /oauth/device_authorization` + `GET /v1/device/verification` + `POST /v1/device/decision`（RFC 8628 设备流）、
`POST /oauth/introspect`（要求客户端认证）、`POST /oauth/revoke`、`GET /v1/me`（Bearer + scope 校验）、
`GET /v1/grants` + `DELETE /v1/grants/{client_id}`（会话；下游撤销，见 api-design.md）、
`GET /v1/sources`（公开）、`GET /v1/bindings` + `DELETE /v1/bindings/{game}/{source}`（会话；断开数据源，
并尽量让源按 RFC 7009 撤销它签发的令牌）、
`POST /v1/bindings/{game}/{source}/cascade_revocation`（会话 + 显式确认；请求数据源作废整段上游会话）、
两个发现端点。`GET /oauth/authorize` 由 OP（`internal/oidchttp`）处理，经 `Login` 钩子重定向到同意页；`GET /bind` 走 `federate.BeginBind`。

**断开的本地一半总是发生。** 数据源宕机、坏掉或拒不配合，都不能阻止用户把它从自己的账号上摘下来；
上游那一半是尽力而为，结果（`done` / `unsupported` / `unavailable` / `nothing`）随响应一起回去，
因为“在这边断开了，但那边还留着”与“已全部清理”是两句不同的话。

**一条授权不是存下来的实体，而是“该账号名下仍有效的令牌按 client_id 聚合”。** 好处是撤销就是删令牌，
不存在“同意表说已撤销、令牌表还能用”这种两个真相源互相矛盾的状态；代价是列表显示的是**当前访问**而非历史同意，
某个应用最后的 refresh token 也过期后它会从列表上消失。理由写在 api-design.md。

RFC 8628 的 `verification_uri` 指向**人类页面** `/app/device`（`oauth.Config.VerificationPath`），
而不是给它供数据的 JSON 端点 `/v1/device/verification`——这两个东西指向同一个对象但没有理由共用路径。

**限流**（`internal/ratelimit`，基于 `golang.org/x/time/rate`）：可选的 `Config.Limiter` 在会话中间件之外
先拦住超预算的调用方；按客户端地址分桶、空闲驱逐。**三个平面各自的错误形态**：`/oauth/*` 与 `/.well-known/*`
返回 OAuth 错误，`/v1/*` 返回 `problem+json` 的 `rate_limited`，浏览器路径是纯文本。

**出站韧性**（`httpclient`，基于 `failsafe-go`）：重试（指数退避 + 抖动，认 `Retry-After`）、按上游 host 的
熔断器、出站 bulkhead 三件套。**策略在本仓库、机制在库里**：**默认只重试幂等方法**（POST 不隐式重放），
429/502/503/504 可重试而 500 不可，这些规则仍在 `httpclient`；循环、退避调度与熔断状态机来自库。
bulkhead 的许可覆盖整段响应体（直到 body 关闭），不是只覆盖到响应头。选型、被否的方案与三处语义变化见
[resilience-decision.md](./resilience-decision.md)（ADR-0009），依赖表见 [dependencies.md](./dependencies.md)。

关键不变量（由 `internal/httpapi` 测试守护）：**协议平面绝不输出 problem+json，业务平面绝不输出
`{error,error_description}`，浏览器平面两者都不输出**；三个平面各有独立子 mux、错误写出器与 panic 恢复，仅共享 request-id 中间件。

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
解法是让占位文件由 `pnpm run build` 在构建后自己重新写回（`web/scripts/restore-dist-placeholder.mjs`），
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

### 4.8 /auth 平面与会话（v1 已实现：`idp`、`internal/account`、`internal/auth`）

- `idp`：r0semi 作为 GitHub / Google / Discord / QQ / 微软 的 OAuth 客户端
  （`golang.org/x/oauth2`，强制 PKCE S256），把回调规范化为 `Identity{Provider, Subject, ...}`。
  **OIDC 提供方（Google / 微软）走 `coreos/go-oidc`**：对 `id_token` 验签名（issuer JWKS）、issuer、
  audience、过期与 **nonce**（调用方必须把 `AuthCodeURL` 的 nonce 回传给 `Identity`）；
  无 `id_token` 则**失败关闭**，绝不退回 userinfo。非 OIDC 提供方（GitHub / QQ）继续用 userinfo，
  QQ 走 JSONP + 非标准 profile API。发现（discovery）懒加载并缓存，失败不缓存。
  除内置 5 家外，`[idp.<name>]` + `issuer` 可声明**任意 OIDC provider**（自建 Keycloak / Authentik /
  任何用 Passkey 登录的 OP）：端点从 discovery 得到，`id_token` 用 issuer 的 JWKS 验签，按钮名来自
  `display_name`。provider 名会被校验为单个 URL 路径段，因为它同时是身份命名空间。
- `internal/account`：`usr_` 的唯一分配者，强制三条账号不变量（平权 / 底线 / 隔离，见 account-model.md §2）。
- `internal/auth`：基于 `alexedwards/scs` 的服务端会话（`__Host-` HttpOnly Cookie + 登录时轮换）、
  CSRF（会话内同步令牌 + `X-CSRF-Token`）、`/auth/{provider}/start|callback` 处理器。
- `httpapi` 在配置 `Sessions` / `Accounts` / `Auth` 时挂载 `/auth/`、包上会话中间件，
  并提供 `GET /v1/sessions/current`、`POST /v1/sessions/sign_out`。

### 4.9 授权交互 API（v1 已实现：`internal/oidchttp` + `internal/authorization` + `httpapi`）

把 `/oauth/authorize` 变成真实浏览器流程，同时把安全判断全部留在服务端。`/oauth/authorize` 本身由
OP（`internal/oidchttp`，zitadel 引擎）处理，`httpapi` 只负责同意页三个端点：

- `GET /oauth/authorize`（协议平面，OP）：校验客户端与 redirect_uri，建立服务端 pending auth request，
  经 `Login` 钩子把 handle 绑定到当前浏览器会话，302 到前端 `/app/consent?id=<opaque>`。
  未知 scope → 302 回客户端 `error=invalid_scope`（`internal/oidchttp` 在库静默丢弃前先拒绝，O-7）；
  客户端未知 / 重定向非法 → JSON OAuth 错误。
- `GET /v1/authorization_requests/{id}`（业务平面，需登录 + 会话绑定）：返回客户端名与 scope 描述
  （含 `risk` / `explicit_consent`）、`csrf_token`，以及 `missing_bindings`——请求的 scope 中
  还需要但尚未连接的数据源，每项带服务端拼好的 `bind_url`（`return_to` 指回同一 handle）。
- `POST /v1/authorization_requests/{id}/decision`（需登录 + CSRF）：`{decision, scopes, explicit}`；
  批准 → `oidchttp.ApproveAuthorization`（收窄 scope + 复核 critical scope）→ `CompleteLogin` →
  返回 **服务端拼好的** `redirect_to`（指向 OP callback，由它签发 code 并 302 回客户端）。
- **渐进式绑定**：同意页在 `missing_bindings` 非空时禁用批准并引导连接；绑定回调回到同一
  pending handle（`authorizationRequestTTL` 需长于 federation 的绑定 TTL）。取消勾选某个 scope
  即可解除它对应的绑定要求。
- handle 单次使用、短时效、绑定浏览器；收窄规则由 `internal/oidcstore` 的 `NarrowScopes` /
  `RequireExplicitConsent` 统一实现，两种 OP store 共用一份。

### 4.10 Upstream Kit 与一致性测试（v1 已实现：`upstreamkit`）

数据源（游戏后端）接入生态的工具链：

- `upstreamkit`：协议类型（发现文档 / canonical scope / `token_class`）+ 可挂载的 HTTP 服务
  （`/.well-known/re0auth-upstream`、`/oauth/*`、`/account`、`/resources/{name}`），复用 `oauth`
  作为 OAuth 核心；游戏相关的部分（用户认证 / 同意、账号、资源）由 hooks 提供。
- `upstreamkit/conformance`：可执行的一致性套件，对任意数据源产出 findings
  （error / warning / skipped）；带 `AccessToken` 时额外检查数据面。
- 参考上游在测试中由 Kit 构建并通过套件。**真实 TapTap 适配器已迁到数据源侧**：
  `referencesource` 用 `taptapoauth` + `tapsign` 完成 TapTap 登录与凭据兑换，Re0Auth 侧不再持有
  原始平台凭据（见 §4.12 与 threat-model.md）。

### 4.11 数据联邦层（v1 已实现：`internal/federation`）

re0auth 的数据面：把下游对某个游戏资源的请求，映射到一个已绑定的上游数据源，并返回该源的规范化载荷。

- **源注册表**：静态配置 `Source{Game, Name, Issuer, TokenClass, Resources[{Name, Schema, Scope}]}`。
- **绑定**：`(usr_, game, source)` → **元数据**（`BindingStore`：`HasRefresh`/`Expiry`/`Version`）
  **+ 上游令牌**（`vault`，信封加密，键 `Provider = "<game>.<source>"`）。
  **绑定表里没有任何凭据**。交互式流程：
  `GET /bind?game=&source=&return_to=`（需登录）→ 跳上游 authorize（PKCE）→
  `GET /auth/upstream/{game}/{source}/callback` → 令牌入 vault、元数据入绑定表。
  flow 绑定浏览器会话、单次使用、短时效。回调**同时校验会话与账号归属**
  （`Bound` + `OwnerMatches`，与同意、设备决策两处一致）：只查会话的话，同一浏览器里切换账号的
  第二个账号可以消费掉第一个账号的手柄与 flow 行，让原账号无法完成自己的绑定。
- **拉取**：`Fetch(user, game, resource, source?)` → 选源 → 取绑定 → 在 `vault.Use` 的明文窗口内
  调 `{issuer}/resources/{name}`（带 Bearer）→ 逐字返回其 JSON。
- **令牌刷新**：绑定接近过期时主动刷新；上游 401 时强制刷新并重试一次。按 binding 串行
  （keyed mutex）避免**进程内**轮换竞争。跨进程（多实例共享一个库）靠**原子 Version 比较**：
  写回走 `BindingStore.PutIfVersion`（单条条件 UPDATE），读到的版本没变才写得进去，于是两个进程
  不可能都从 N 写成 N+1，输的一方改为读回赢家的那份。refresh 被拒（`invalid_grant`）**不再直接删绑定**：
  一次性 refresh token 会让“输了竞争”和“凭据真的死了”都长成 `invalid_grant`，所以先重读——版本动过
  说明别人赢了、他的令牌才是活的；版本没动才删元数据与 vault 密文，回到“引导绑定”。**残余**：
  两个进程若在赢家落库之前同时重读，仍可能都判为已死而各删一次；彻底消除需要租约（lease），暂缓。
- **`Version` 是代次标识，不是计数器**（第二轮审计后）。它被分配为**随机 64 位**而非 `1`，因为
  「版本动过 = 别人赢了」这个判断是 refresh 被拒时唯一的证据。重绑若回到 `1`，一个陈旧的 refresh
  就会看到「还是 1」、判定凭据已死，进而**删掉用户刚重连的绑定**并撕毁其密钥。随机代次让「重绑」
  与「轮换」在该判断下等价——两者都意味着**旧凭据不再是当前那份**，这才是事实。
- **CAS 在前，写 vault 在后**（第二轮审计后）。反过来写会在两处出错：输的一方已经覆盖了赢家写进 vault
  的令牌（两个存储各说各话）；更糟的是与 `Unbind` 竞争时会把刚被撕毁并删除的绑定的密文**写回来**——
  绑定行没了，`ListAll` 看不见，Kill Switch 重试也够不到，只有整账号抹除能清掉。
- **`Unbind` / `CascadeRevoke` / `shredBinding` 取同一把键锁**（第二轮审计后）。它们原本不取锁，
  于是可以与一个已经读过绑定的 refresh 交错，造成上面那条「复活」。取锁后两者有序：要么 refresh 先跑完、
  这次清掉它的结果；要么这次先跑完、refresh 的重读发现无可刷新。
- **`Unbind` 区分「没有密钥」与「打不开密钥」**（第二轮审计后）。后者（KEK 未配置、审计写入被拒、
  解密失败）原本塌缩成 `RevocationNothingToDo`——调用方与 Kill Switch 计数器被告知无需动作，
  而**一个撤销请求都没发出**，上游令牌继续有效。现在报 `RevocationUnavailable` 并带上原因。
- **多源仲裁**：源有 `active/degraded/retired` 状态。未 pin 时按「active → degraded」顺序尝试、跳过 retired；
  首个失败而后续成功 → `Re0Auth-Degraded: true`。**pin 的源绝不替换**（失败即失败；retired → `410 source_retired`）。
- **raw 透传**：`GET /v1/games/{game}/sources/{source}/raw/{path...}` 逐字转发源的原始 API
  （状态码、Content-Type、body 均不改），供需要上游原生方言的消费者使用。
- **HTTP**：`GET /v1/games/{game}/sources`（公开发现，含状态与 raw 支持）、
  `GET /v1/games/{game}/{resource}`（AT + scope）。响应带 `Re0Auth-Source`，降级时附 `Re0Auth-Degraded`。

> 已知粗粒度处：raw 的 scope 门禁用的是“该源任一资源 scope”，专用 `<game>.raw.read` 为后续工作。

### 4.12 参考数据源（切片 1–4 已实现：`referencesource` + `cmd/referencesource`）

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

### 4.13 组合根与持久化（v1 进行中：`cmd/re0auth` + `internal/store/postgres`）

**`cmd/re0auth` 是组合根**：从 TOML 文件 + 环境变量读配置（见 `config/re0auth.example.toml`），
装配全部组件，起两个 HTTP 平面。它的存在是为了让存储适配器有一个**真实调用者**，而不是只被测试调用。
启动时把仍在内存的部件**大声说出来**：

```
WARNING: no DATABASE_URL; every store is in-memory -- a restart loses sessions, bindings and pending requests
```

设了 `DATABASE_URL` 后，同一行变成：

```
storage: every port is persistent (accounts, clients, vault credentials, bindings, bind flows, sessions, OP tokens, OP device authorizations)
```

“哪些部分是持久的”绝不能靠猜。内存模式下**引擎不变**（仍是 OpenID Provider），只是 OP 的 state
（授权请求、code、令牌、设备授权）落在内存：

```
WARNING: no DATABASE_URL; every store is in-memory -- a restart loses sessions, bindings and pending requests
```

**配置约定**：文件只放结构（端点、驱动、哪些 provider/源存在），**密钥只来自环境**——文件写的是
变量名（`*_env`），不是值。优先级为 **环境 > 文件 > 默认值**；校验 fail-closed，缺密钥/缺 issuer/Kek 长度
不对，都拒绝启动。共享辅助在 `internal/config`，因为密钥解析语义在两个二进制里各写一份必然漂移。

**Postgres 适配器**（`internal/store/postgres`）落在接口包**之外**，因为公开库（`oauth`、`vault`）
不能依赖数据库驱动。存储端口（全部已落地）：`account.Store`、`oauth.ClientRegistry`、`vault.Repo`、
`federation.BindingStore`、`federation.BindFlowStore`、`scs.Store`（会话），以及 OpenID Provider 的
`op.Storage` + `op.DeviceAuthorizationStorage`（其 Postgres 与内存两个实现共享 `internal/oidcstore` 的
签名密钥、客户端适配与同意策略）。**后端持久化到此收尾。**

| 关注点 | 做法 |
|---|---|
| 迁移 | `embed.FS` 内嵌 SQL + goose + `pg_advisory_lock`（多实例同时启动不打架）；兼容性与回滚见 [migration-decision.md](./migration-decision.md)（ADR-0008） |
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

**OP 的 auth request id 刻意不对 handle 做哈希**，因为哈希在那里保护不了什么：`oidc_auth_requests.id` 设计上就出现在
浏览器 URL 与服务器日志里，且 HTTP 层另外把它绑定到创建它的会话，偷到 handle 在别处也无用。
分类写在迁移注释与 threat-model §6.1 里。

会话额外做了一件事：`scs.Store` 的接口**不带 context**（scs 不传），所以适配器用 `context.Background`；
过期会话在 `Find` 时按 scs 语义当作“未找到”并顺手删除，另有 15 分钟一次的 `SweepExpired` 定期清理
（`Find` 只清那些还会被访问的）。OP 的过期授权请求 / code / 设备授权在读取时按过期处理，并且**同一 15 分钟
sweep 也会删除 OP 表中已过期的行**（`internal/store/postgres/sweep.go`）；内存模式的 janitor 同理。

**进程生命周期**：`cmd/re0auth` 在 `SIGTERM`/`SIGINT` 时**优雅关闭**——先停止接受新连接，给在途请求最多 30s
完成，再关闭剩余连接；后台清扫循环（会话 `SweepExpired`、内存 OP janitor）绑在同一个 signal context 上，
随进程一起取消，不越过进程存活。HTTP server 设了 `ReadHeaderTimeout` / `ReadTimeout` / `WriteTimeout` /
`IdleTimeout` 与 64 KiB 的 `MaxHeaderBytes`；`WriteTimeout` 取 60s 而非更短，是因为数据面要代理上游响应，
必须大于出站客户端自己的 20s 期限，否则会把一次合法的慢读截断。运维探针 `/healthz`、`/readyz` 见
[api-design.md](./api-design.md) §6。

**运维面在独立的内部监听器上**（`server.internal_addr` / `RE0AUTH_INTERNAL_ADDR`，空即不启用）：
`/metrics`（Prometheus 黄金指标 —— 流量 / 错误 / 延迟 / 在途 —— 加上**业务与安全信号**：登录结果、
令牌签发与错误、撤销、上游读取与刷新、vault 操作、审计链校验、设备流与运维动作，见
`internal/observability` 与 [observability-decision.md](./observability-decision.md)（ADR-0007）；
再加 Go 运行时与进程采集器）与 `/debug/pprof/`。它**必须与 `addr` 不同**（配置校验强制）：单独一个监听器
正是「这些端点无法经公网端口到达」的保证，而 pprof 会导出进程内部状态（goroutine 转储、堆、CPU profile），
把 `internal_addr` 指向公网地址就是把它们公开。它按与主监听器同一套超时启动，并在同一个信号上优雅关闭
（`serveUntilSignal` 现在接收一组 endpoint，两者一起排空）。

> 本地开发：`docker run -e POSTGRES_PASSWORD=x -p 5432:5432 postgres:16`，然后
> `TEST_DATABASE_URL=postgres://postgres:x@localhost:5432/postgres?sslmode=disable go test ./internal/store/postgres/`。

### 4.14 管理面（v1 已实现：`internal/admin` + `httpapi`）

应用注册 / 审核 / 吊销 / Kill Switch。完整契约见 [admin.md](./admin.md)。要点：

- **管理员 = 配置允许列表里的 `usr_…`**（`[admin].subjects` 或 `RE0AUTH_ADMIN_SUBJECTS`），
  不是角色表，也不可自我提权。列表为空时整个 `/v1/admin/*` **不挂载**；已登录但不在列表里的账号
  访问它得到 `404`，与一个不存在的路径无区别。
- 逻辑在 `internal/admin`，只依赖两个窄端口：`Clients`（`oauth.ClientAdmin` + `ClientRegistry`）
  与 `Tokens`（`oauth.TokenAdmin` 批量删除），外加可选的 `SessionRevoker`。因此同一套逻辑既跑 Postgres
  也跑内存，HTTP 层与存储无关。
- **暂停 = 从协议入口消失**：注册表 `Get` 对 `suspended` 返回 `ErrClientNotFound`，与未注册无差别；
  只有 `GET /v1/admin/clients` 还看得见它。停用先于删令牌，失败方向安全。
- 每个动作写审计，`Detail["actor"]` 是发起管理员。审计失败**不回滚**已发生的安全动作，只告警。
- Kill Switch 覆盖令牌、会话与数据源绑定（`all` / `client` / `subject` / `bindings`）；绑定半边对每条绑定
  本地必断，并尽源所能调撤销/级联，见 admin.md §4.2。按账号清会话需要一个会话→账号索引
  （`session_subjects`，登录时写入、注销时移除、过期由 sweep 清理）；没有它只能整体清会话。
  **Kill Switch 不是删除**：它是可逆意图的应急切断，账号行、identities、vault 密文都还在，账号还能重新登录。

### 4.15 账号抹除（v1 已实现：`internal/lifecycle`）

`DELETE /v1/account` 的编排。它与 §4.14 的 Kill Switch **刻意分开**：Kill Switch 是运维应急切断，
抹除是用户对自己数据的终局处置，两者要清的 store 高度重叠但语义与审计不同。

- **为什么需要单独一个包：** 一个账号的数据散在十几张表里，而**只有 `accounts_identities` 有指向账号的外键**。
  直接删 `accounts_users` 会静默留下令牌、vault 行、绑定、在途请求的孤儿。必须有人逐个 store 点名、并规定顺序，
  这段编排就是 `internal/lifecycle.Deleter` 的全部价值。
- **顺序（外→内，上游优先）**：bindings（撤上游 + 撕 vault + 删行）→ vault `DeleteSubject` → tokens →
  sessions → flows → OP/legacy 状态 → 账号行。**每一步幂等**，中途失败即停、可重试，错误注明卡在哪一步。
- **为什么走 repo 层而不走 `vault.Service`：** `vault.Service` 的每个操作都会自记审计（I3），
  抹除路径若通过它去取/清伪名密钥，就会形成「审计 → vault 查询 → 审计」的递归。直接删行绕开这条回路，
  加密擦除的效果一样（包裹的 DEK 就在行里）。
- **审计失败即失败**（与 §4.14 的 admin 相反）：抹除是用户主动、可重试的请求，一次无法留痕的抹除比一次失败的抹除更糟。
- **完整性靠测试守住**，不补 16 张外键：`TestAccountDeletionLeavesNoOrphans`（需 Postgres，动态扫
  `information_schema` 里所有含 `subject`/`user_id` 列的表，逐一断言清零）+
  `TestEverySubjectColumnIsHandledByErasure`（无需数据库，解析 migration，新增的带 subject 列的表若没登记就构建失败）。
  `audit_events` 是**显式豁免**：它 append-only，抹除走的是假名化而非删除（已实现，见 §4.17）。

### 4.16 审计完整性（v1 已实现：`internal/store/postgres/auditchain.go`）

审计表「append-only」原本只是**约定**，不是控制：迁移里没有 trigger、没有权限限制，任何有表权限的角色都能改行。
现在每一行都承诺前一行、并用**不在数据库里**的密钥签名（迁移 `0013`）：

```
row_hash  = SHA-256(prev_hash ‖ canonical(row))
signature = HMAC-SHA256(key, row_hash)
```

- **串行化是必需的**：单行 `audit_chain` 表在每次追加的整个事务里被 `FOR UPDATE` 锁住。没有它，两个并发插入会各自读到同一个前驱，链就**分叉**了。审计不是热路径，串行化的代价可以接受。
- **`canonical` 必须确定性**：`detail` 的键要**排序**（Go 的 map 迭代顺序是随机的，不排序则每次算出不同的哈希，行会通不过自己的校验），时间戳要**截断到微秒**（那是 `timestamptz` 实际存的精度，哈希纳秒值会在读回时对不上）。前导域名标签防止与其它用途的哈希撞车，长度前缀防止字段边界歧义。`auditchain_test.go` 有专门的测试钉住这三点。
- **能挡什么，不能挡什么**（写在迁移注释里，因为**夸大的完整性控制比没有更糟**）：
  - 改行 → `row_hash` 重算不出来
  - 链中间删行 / 换序 → 后一行的 `prev_hash` 指向空
  - **重写整条链** → 哈希可以重算，但**签名伪造不出来**（密钥不在库里）
  - **从尾部删行 → 就地验证挡不住**。截断在没有外部锚点（把链头送去另一个系统）时不可见——尾部只是变短，剩余每一环都仍成立。`GET /v1/admin/audit/head` 把当前链头以十六进制暴露给外部系统，由部署方发布到库外的另一处存储；不发布则维持原有的较弱保证。导出侧由 `GET /v1/admin/audit` 读 API 承担（供 SIEM 拉取）。
- **签名逐行做，不是定期对链头做**：每行都签比只签周期性链头更强，且少一张表。原计划里的 `audit_chain_checkpoints` 因此没有落地。
- **迁移前的行** `row_hash IS NULL`，被验证器计为 `legacy` 而**不是**假装覆盖；链从迁移后的第一行开始。另外，**链开始之后**再出现无哈希的行会被判为违规——否则攻击者把某行的哈希清空就能把它降级成「legacy」跳过。
- **内存模式没有链**：`audit.MemoryLogger` 是环形缓冲，本身就不是防篡改结构，给它加链是自欺。链是**持久化 sink 的属性**，因此 `RE0AUTH_AUDIT_KEY` 只在持久化部署里必填。

### 4.17 审计主体假名化（v1 已实现：迁移 `0014` + `auditpseudo.go`）

审计日志几乎每一行都点名一个账号，所以它自己就是一座个人数据仓库，「抹除账号」如果不动它，
那个人的轨迹就留在原地。但它是 **append-only 且带链**的（§4.16），不能删行——删行会破坏链。

解法是**假名化 + 销毁密钥**：

```
idx       = HMAC(audit_key, "…subject-index/1" ‖ subject)   -- 查找键
key       = 32 随机字节                                      -- 每 subject 一把
pseudonym = HMAC(key, "…pseudonym/1" ‖ subject)              -- 写进 audit_events.subject
```

- **抹除 = 删掉 `audit_subject_keys` 里那一行**。行没了，谁都算不出该 subject 的假名——包括本服务。
  审计行一个字都不动，**链仍然校验通过**。这就是「擦除但不改写历史」。
- **不存原始 subject**：`idx` 是**带密钥**的哈希，所以这张表里没有账号 id；没有环境里的密钥，
  也无法为某个候选 subject 反算出 `idx` 去查。
- **顺序是语义的一部分**：销毁密钥**必须**排在「写完 `account.delete` 审计事件」**之后**。
  否则写那条事件时查不到 key，sink 会**新造一把**——恰好把这一步要断开的关联又接回去。
  `lifecycle` 里有测试钉住这个顺序（`TestDeleteAccountDestroysThePseudonymKeyLast`）。
- **销毁之后**同一 subject 若再来事件（例如某个陈旧会话），会拿到**新的** key、**不同的**假名，
  因此与旧行失去关联——这正是想要的。
- **跨进程缓存不破坏擦除**：每个进程缓存 subject→key 以避免每次写审计都查库，
  但假名是确定性的，缓存命中也只是继续产出同一个假名；不可关联性来自**密钥行不存在**，与缓存无关。
- **诚实的边界**：
  - **迁移前的行保留原样**（原样就是当时的 `usr_…` 或空）。没有回填——回填要么使 0013 写在旧值上的哈希失效，
    要么需要一个启动期的 Go 数据迁移。这是一次性的边界，写在这里而不是假装没有。
  - **抹除前**，整库 dump 仍能把**在世账号**的审计行关联回去，因为 dump 里同时有密钥和账号 id。
    但那份 dump 同时也含有该账号的 identities 与 email——**它本来就是全量的**。假名化不是「不被脱库」的替代品，
    它交付的是**可抹除**。

## 5. 安全不变量（必须由测试守护）

- **I1 能力封闭**：未声明的 key 访问必须报错。**实测边界**：运行时校验位于 `core`（由 `core` 测试守护），
  但 `core` 在 v1 **不承载生产装配**（ADR-0002），所以它是**库层属性**；生产里被机器强制的同类约束是
  **包级依赖方向**，由 `internal/archtest` 在 CI 执行。两者粒度不同：前者管"能力键"，后者管"谁 import 谁"。
- **I2 明文零化**：所有解密出的明文 stoken 必须登记为 effect，其 inverse 为零化；禁止明文离开 acquire 作用域。
- **I3 先审计后 emit**：跨越 emission 边界前先持久化审计（withholding）。
- **I4 补偿幂等**：跨边界动作必须提供幂等补偿（如撤销级联到 TapTap）；补偿失败必须可见、可重试。
- **I5 fail-closed**：依赖不可用 → 组件 INACTIVE，绝不降级放行。
- **I6 无动态代码**：v1 不加载运行时第三方代码；第三方适配器走进程外 gRPC。

`go test ./...` 覆盖全部 Go 包（含 Postgres 集成测试；未设 `TEST_DATABASE_URL` 时集成测试跳过，在 Linux CI 执行），
覆盖的安全不变量。**注意**：I1 / I5 的**运行时**守护在 `core`，而 `core` 未进生产（ADR-0002）；
生产里被机器强制的是**包级依赖方向**，见 `internal/archtest`：

| 不变量 | 测试 |
|---|---|
| I1 | `core`: `TestUndeclaredCapabilityIsRejected`, `TestProvideRequiresDeclaration`；`vault`: `TestComponentCapabilityDeclaration` |
| I2 | `core`: `TestEffectRunsLIFO`, `TestDisposerIsIdempotent`, `TestZeroizeOnUnload`；`vault`: `TestUseZeroizesPlaintext`, `TestUseZeroizesOnCallbackError` |
| I3 | `vault`: `TestUseAuditsBeforeCallback`, `TestUseFailsClosedWhenAuditFails`；`tapsign`: `TestRotateReturnsReplacement`, `TestRevokeDiscardsReplacement` |
| I4 | `tapsign`: `TestRevokeIsIdempotentOnInvalid`（目标 = 旧 token 已失效，403 即达成） |
| I5 | `core`: `TestFailClosedMissingProvider`, `TestReactiveActivationAndDeactivation`, `TestDuplicateProviderFailsClosed`, `TestCycleStaysInactive`, `TestPanicInApplyFailsClosed`；`vault`: `TestComponentInactiveWithoutRepo`, `TestComponentFailsWithoutKeyWrapper`；`tapsign`: `TestComponentInactiveWithoutHTTP`, `TestComponentFailsWithoutConfig`；`wiring`: `TestComponentInactiveWithoutTokens`, `TestComponentFailsWithoutIssuer` |
| 依赖方向 | `internal/archtest`: `TestPublicLibrariesDoNotDependOnInternal`, `TestDatabaseAdapterIsConfinedToCompositionRoots`, `TestKernelHasNoInternalDependencies`, `TestEveryModulePackageIsRegistered` |
| 平面隔离 | `httpapi`: `TestTokenErrorUsesOAuthFormat`, `TestBusinessErrorUsesProblemFormat`, `TestUnknownEndpointsArePlaneSpecific`, `TestInsufficientScopeIsForbidden` |
| 账号 I-1/I-2/I-3 | `account`: `TestUnlinkRejectsLastIdentity`, `TestLinkRejectsIdentityOwnedByAnotherUser`；`auth`: `TestLinkRejectsTakenIdentity`, `TestLinkAddsIdentityToCurrentUser` |
| 授权交互 | `oidchttp`: `TestConsentInteraction`, `TestIDTokenGating`, `TestUserinfoReturnsOnlySub`；`oidcstore`: `NarrowScopes` / `RequireExplicitConsent` 由两个 store 共用；`httpapi`: `TestAuthorizationInteractionEndToEnd`, `TestAuthorizationHandleIsBoundToBrowser`, `TestDecisionRequiresCSRF` |
| 上游协议 | `upstreamkit`: `TestReferenceUpstreamPassesConformance`, `TestKitAuthorizeFlow`；`conformance`: `TestMissingAccountScopeIsAnError`, `TestBadTokenClassIsAnError`, `TestAuthorizeRedirectingUnknownClientIsAnError`, `TestTokenAcceptingBadGrantIsAnError` |
| 数据联邦 | `federation`: `TestFetchReturnsSourcePayload`, `TestBindFlow`, `TestFetchRefreshesExpiredBinding`, `TestConcurrentRefreshHappensOnce`, `TestFetchFallsBackAndMarksDegraded`, `TestPinnedSourceIsNotSubstituted`, `TestRawPassthroughIsVerbatim`, `TestActiveBeatsDegraded`；`httpapi`: `TestGameResourceDataPlane`, `TestSourceBindingEndToEnd`, `TestGameRawAndDegraded` |
| 账号抹除 | `lifecycle`: `TestDeleteAccountClearsEveryStoreInUpstreamFirstOrder`, `TestDeleteAccountStopsAtTheFailingStep`, `TestDeleteAccountFailsWhenTheRecordCannotBeWritten`, `TestDeleteAccountWithoutASessionRevokerSaysSo`；`vault`: `TestDeleteSubjectShredsEveryProviderOfOneAccount`；`memory`: `TestPurgeSubjectRemovesRequestsCodesAndDevices`, `TestPurgeSubjectLeavesOtherAccountsAlone`；`postgres`: `TestAccountDeletionLeavesNoOrphans`（需 DB）, `TestEverySubjectColumnIsHandledByErasure`（无需 DB）；`httpapi`: `TestDeleteAccountEndToEnd`, `TestDeleteAccountRequiresTheAcknowledgement`, `TestDeleteAccountRequiresCSRF`, `TestDeleteAccountIsAbsentWhenNotConfigured` |
| 账号导出 | `httpapi`: `TestExportAccountOmitsCredentials`（先塞入已知明文再断言其不出现，反空转）, `TestExportAccountSaysCredentialsAreExcluded`, `TestExportAccountIncludesTheAccountShape`, `TestExportAccountRequiresASession` |
| 审计完整性 | `postgres`: `TestAuditCanonicalIsDeterministic`（反空转：去掉键排序即失败）, `TestAuditCanonicalIsUnambiguous`, `TestAuditCanonicalCoversEveryField`, `TestAuditChainHashLinksToPredecessor`, `TestAuditSignatureDependsOnTheKey`, `TestNewAuditLoggerRejectsABadKey`（以上无需 DB）；`TestAuditChainRecordsAndVerifies`, `TestAuditChainCatchesDeletion`, `TestAuditChainCatchesAReSignWithTheWrongKey`, `TestAuditVerifyCountsLegacyRows`, `TestAuditVerifyRejectsAnUnchainedRowAfterTheChain`（需 DB）；`cmd/re0auth`: `TestAuditKeyIsRequiredOnlyWhenDurable` |
| 审计假名化 | `postgres`: `TestPseudonymIsStableForOneKey`, `TestPseudonymDependsOnThePerSubjectKey`, `TestAuditHashesAreDomainSeparated`, `TestSubjectIndexDependsOnTheAuditKey`, `TestPseudonymCacheIsBounded`, `TestDestroyRejectsAnEmptySubject`（以上无需 DB）；`TestAuditPseudonymisesSubjectAndUnlinksOnDestroy`（假名稳定 → 销毁后链仍通过 → 再写不得复用旧假名）, `TestAuditLeavesAnEmptySubjectEmpty`（需 DB）；`lifecycle`: `TestDeleteAccountDestroysThePseudonymKeyLast`（顺序：先记录后销毁，反空转）, `TestDeleteAccountReportsAFailedPseudonymDestroy`, `TestDeleteAccountWithoutPseudonymsStillWorks` |
| 审计读取 | `postgres`（需 DB）: `TestAuditQueryResolvesTheSubjectFilter`（假名翻译，否则过滤为空）, `TestAuditQueryOnAnUnknownSubjectIsEmptyAndSideEffectFree`（读不建密钥）, `TestAuditQueryAfterDestroyReturnsNothing`（行仍在、链仍通过、查不到）, `TestAuditQueryPagesWithoutGapsOrRepeats`, `TestAuditQueryClampsThePageSize`；`httpapi`: `TestAdminAuditIsHiddenFromNonAdmins`, `TestAdminAuditRequiresASession`, `TestAdminAuditPassesFiltersThrough`（解析后不得丢过滤条件）, `TestAdminAuditRejectsMalformedParameters`, `TestAdminAuditReturnsEntriesAndPagination`, `TestAdminAuditOmitsTheCursorOnTheLastPage`, `TestAdminAuditVerifyReportsTheChain`, `TestAdminAuditReportsAReadFailure`, `TestAdminAuditIsAbsentWhenNotConfigured`, `TestAuditRequiresAnAllowlist` |
| 其他 | 信封 / 身份绑定 / provider 隔离；403 被动失效检测；MAC 签名（`TestMACAuthorizationSignsDocumentedString`） |

端到端：`referencesource` 的 `TestTapTapLoginEndToEnd` 用 httptest 假 TapTap + 真实 vault，
打通 `TapTapLogin.Start/Poll → tapsign.Redeem → vault.Enroll → 源会话 → Consent → federation.Fetch` 全链路。

`oauth` 覆盖授权码全流程、PKCE、code 单次使用、scope 收窄 / 拒绝、
critical scope 强制显式同意、refresh 轮换、撤销幂等、令牌过期。

`internal/httpapi` 用 `httptest` 跑完整 HTTP 往返：发现端点、授权码兑换、
`/v1/me` 的 Bearer + scope 校验、自省 / 撤销、以及三个平面错误格式互不泄漏。

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
   **生产接入决策：v1 不接入**，见 [core-runtime-decision.md](./core-runtime-decision.md)（ADR-0002）。
2. **Key 身份**：强类型泛型 `Key[T]` 包装 `(namespace, name)`；`reflect.Type` 不参与身份，
   避免同一能力的多个声明点因类型不同而分裂。
3. **不做动态拦截**：v1 仅静态能力声明（`Provides` / `Inject`）；`Isolate` / `Intercept`
   留待后续版本。
4. **依赖方向机器闸门**：`internal/archtest` 强制公开库 ⊥ `internal/`、数据库适配器只许组合根导入、
   `core` 不依赖内部包、新增顶层包须登记。见 §4 与
   [core-runtime-decision.md](./core-runtime-decision.md) §7。

**待决**：

1. 进程外 bridge 的协议与鉴权（mTLS？DPoP？）。
2. 补偿动作（TapTap 撤销）的幂等键与重试队列设计。
3. isolation / interception 的引入时机与形态。
4. core 的可观测性：fiber 状态是否导出为指标，`App.Check` 结果是否作为 CI 门禁。
   **部分已决**：依赖方向的 CI 门禁已由 `internal/archtest` 落地；`core` 自身的可观测性随其生产接入
   一并推迟（ADR-0002），接入前不再是待办。（这里说的是 `core` **组件图自身**的指标；服务层面的黄金指标
   与 pprof 已由 §4.13 的内部监听器提供。）
5. 旧引擎在 Postgres 侧的遗留表与适配器：`oauth_codes` / `oauth_access_tokens` /
   `oauth_refresh_tokens` / `oauth_device_authorizations`（迁移 0001 / 0006）以及
   `internal/store/postgres` 的 `Tokens` / `Devices`，在 P4b 之后已无生产调用者。
   删除它们需要一次丢表的迁移与对应测试的调整，留待下一次存储清理；
   `Authz` 与 `authz_requests`（迁移 0005）已在 P4b 一并删除。

## 9. 参考

- Yifan Shi, Wei Zhang, Tianyi Cui. *A Programming Paradigm for Spatiotemporal Composability*.
  arXiv:2608.25512v1. <https://arxiv.org/abs/2608.25512>
  **本文档中所有「论文 §x.y」均指此文。**
  （论文本体不再随仓库分发：arXiv 不授予第三方再分发权，且会让仓库体积无谓增大。请从上述链接获取。）
