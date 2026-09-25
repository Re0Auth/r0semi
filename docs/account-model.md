# r0semi 账号与凭据模型（v1）

> 状态：已定稿（v1 契约）。实现必须以此为准；偏离需先改本文件。
> 相关：[api-design.md](./api-design.md)、[architecture.md](./architecture.md)、[threat-model.md](./threat-model.md)。

## 0. 核心原则

1. **外部 IdP 是唯一账号体系**。r0semi **不自建**邮箱、密码或 Passkey。
   登录只回答"屏幕前的人是谁"。
2. **身份与凭据彻底分离**。
   - `usr_...` 是 r0semi 账号；
   - 第三方 IdP 身份（GitHub/Google/Discord/QQ/微软）是挂在该账号下的**身份**；
   - TapTap `sessionToken` 等**原始平台凭据由数据源自己持有**，Re0Auth 不接触、不托管；
     Re0Auth 的 vault 只保存**数据源签发的派生令牌**（federation 绑定产生）。旧文档曾把
     TapTap `sessionToken` 写成 r0semi 账号名下的托管资产，那是迁移前的模型，已作废。
3. **登录 ≠ 托管**。没有托管任何凭据的账号也是完全合法的账号。

**Re0Auth 现在是 OpenID Provider**：`usr_...` 就是 OIDC 的 `sub`（随机、稳定、伪匿名）。
向下的 `id_token` / `userinfo` **默认只携带 `sub`**；email **永不**作为 claim 返回（I-3 的延伸）。
详见 [oidc-decision.md](./oidc-decision.md) O-3 / O-4。

## 1. 数据模型

```
User (usr_...)
├── identities[]                      外部 IdP 身份
│     provider       "github" | "google" | "discord" | "qq" | "microsoft" | <自定义 OIDC 名>
│     subject        IdP 的稳定 sub / openid      ← 身份键
│     display_name
│     email?         仅作展示，不参与任何判定
│     avatar_url?
│     linked_at
│     last_login_at
├── primary_identity_id               仅展示用，无特权
└── bindings[]                        数据源绑定（vault，按来源命名空间）
      identity  (usr_..., "<game>.<source>")
      meta      { display_name, scopes, ... }   ← 上游元数据，不含凭据
      secret    数据源签发的派生令牌密文
```

**身份键 = `(provider, subject)`。** 绝不用 email、username 或昵称作为键：它们会变、
会回收，QQ 等平台甚至不返回 email。

**绑定键 = `(usr_, "<game>.<source>")`**，例如 `phigros.taptap`。Re0Auth 只持有该数据源
为这次绑定签发的令牌；TapTap `sessionToken` 等原始凭据留在数据源侧，Re0Auth 的 vault 中
不存在它们。上游身份标识（openid/unionid 等）由数据源持有，Re0Auth 侧不落库。

## 2. 三项安全不变量（强制）

| 编号 | 不变量 | 说明 |
|---|---|---|
| **I-1 平权认证** | 所有已链接身份在登录鉴权上**完全等价** | `primary_identity_id` 只影响展示（"以 X 建档"），**不授予任何权限**。禁止任何"仅主账号可登录 / 可管理 / 可找回"的逻辑。 |
| **I-2 底线守护** | 任何时刻 `len(identities) >= 1` | 禁止解绑最后一个身份，杜绝孤儿账号。 |
| **I-3 显式隔离防劫持** | 绑定一个已属于其它 `usr_` 的身份 → **拒绝** | 禁止基于 email / 姓名 / 头像的隐式自动合并。 |

为什么 I-1 重要：没有密码时，唯一的找回途径就是"换一个已链接身份登录"。若把某个身份
抬成特权根，主 IdP 一旦丢失（封号、回收、用户遗忘），账号连同托管的凭据一起报废。
I-2 + I-3 合起来同时堵死"特权主账号死锁"和"自动合并劫持"两条经典路径。

## 3. 登录 / 绑定 / 解绑

| 动作 | 前提 | 行为 |
|---|---|---|
| **登录** sign in | 无会话 | 身份已存在 → 进入其 `usr_`；身份不存在 → **新建 `usr_` 并链接该身份**（此时它成为 `primary`） |
| **绑定** link | **已登录** | 走新 IdP 授权，把新身份链到**当前 `usr_`**；若该身份已属于其它 `usr_` → 拒绝（I-3） |
| **解绑** unlink | 已登录 | 仅当解绑后剩余身份 ≥ 1（I-2）；若被解绑的是 `primary`，重新指派为最早剩余身份 |

**登录与绑定必须在 UI 与 API 上明确区分**，否则用户会无意识地创建第二个账号。

## 4. 账号碰撞与碎片化

典型事故：

```
手机上用 GitHub 登录      → 新建 usr_A，绑定了 TapTap 数据源
电脑上用 Google 登录      → 该身份从未用过 → 又新建 usr_B
用户："我的 TapTap 呢？"
```

v1 的处理：

- 登录页必须清晰标注"**登录**"与"**绑定到当前账号**"是不同动作；
- 已登录状态下发起 IdP 授权，默认进入**绑定**语义；
- 绑定一个已占用身份 → **拒绝**，提示"请先登录该账号解绑"；
- **不做**账号合并。合并会引发绑定归属冲突（两个 `usr_` 各自的绑定如何取舍），
  需要双方强控制证明，v1 一律延后（见 §9）。

## 5. `/auth` 平面：r0semi 作为 IdP 的 OAuth 客户端

> `/oauth/*` 现在是一个完整的 OpenID Provider（见 [oidc-decision.md](./oidc-decision.md)）；
> 本节是**反方向**：r0semi 作为**外部 IdP 的客户端**。两者是不同的代码上下文。

这与 `/oauth/*`（r0semi 作为授权服务器）是**两回事**，必须分属不同代码上下文。

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/auth/{provider}/start?mode=login\|link&return_to=...` | 服务端记录流程状态，302 到 IdP 授权端点 |
| `GET` | `/auth/{provider}/callback?code=&state=` | 校验 `state`、兑换 token、拉取用户信息、落地会话、302 回前端 |

`{provider}` 既可以是内置的 `github` / `google` / `discord` / `microsoft` / `qq`，也可以是 `[idp.<name>]`
里以 `issuer` 声明的**任意 OIDC provider**（自建 Keycloak / Authentik / 任何用 Passkey 登录的 OP）。
自定义 provider 的端点由 OIDC discovery 得到，`id_token` 用 issuer 的 JWKS 验签，按钮上的名字来自
`display_name`。**因此“用 Passkey 登录”不需要 Re0Auth 自己实现 Passkey**——把用户交给一个支持
Passkey 的 OP 即可；Re0Auth 仍不持有也不验证任何密码/密钥。provider 名会被限制为单个 URL 路径段，
因为它同时是身份命名空间 `(provider, subject)` 的一部分。
| `GET` | `/v1/sessions/current` | 当前会话与已链接身份（含 `primary_identity_id`） |
| `POST` | `/v1/sessions/sign_out` | 登出（清 Cookie、失效服务端会话） |
| `GET` | `/v1/identities` | 列出已链接身份（**已实现**，会话） |
| `DELETE` | `/v1/identities/{id}` | 解绑（I-2 守护，**已实现**，会话 + CSRF） |

流程状态（`state`、`mode`、`return_to`、PKCE verifier、nonce）**全部存服务端**，
由 `state` 关联；回调时校验，不接受客户端回传的 `mode`/`return_to`。

- `return_to` 只允许**同源相对路径**，防开放重定向。
- 登录**无法发起**（如自定义 OIDC provider 的 discovery 不可达）时，**不返回裸 502**，而是 303 回
  `return_to?error=provider_unavailable`，由前端给出可读提示。provider 拒绝（`error=access_denied`）
  同样回 `return_to?error=…`；因此 `return_to` 为空时需要 `/` → `/app/` 的跳转**带上 query**，否则原因会丢。
- IdP 采用 Authorization Code + PKCE；`state` 单次使用、短时效。
- provider 具体细节（scope、QQ unionid、微软 tenant）属实现，不改变本节契约。

## 6. 会话

- 登录成功后下发 **同域 HttpOnly Cookie**：`__Host-r0semi_session`，
  `Secure`、`SameSite=Lax`、`Path=/`。会话 id 不透明，服务端存储。
- 登录、绑定、解绑等权限变化时**轮换**会话 id。
- 写操作（`/v1/*` 的 POST/DELETE）需 CSRF 防护：`SameSite=Lax` 之外，
  要求自定义头（如 `X-CSRF-Token`），跨站表单无法伪造。
- 会话与 OAuth 的 access token 是两套东西：前者面向浏览器，后者面向下游。

## 7. 授权流程组合（渐进式绑定）

```
GET /oauth/authorize?...
  后端校验 client / redirect_uri / scope / PKCE
  → 建服务端 pending 授权请求（handle），绑定浏览器 Cookie
  → 302 到前端 /consent?id=<handle>

前端 /consent
  ├─ GET /v1/authorization_requests/{id}
  │     401 未登录 → 展示 5 大金刚一键登录 → /auth/{p}/start?mode=login&return_to=/consent?id=...
  │     200 → 渲染同意页（scope 列表，critical 逐项勾选）
  │           同时返回 missing_bindings：需要但尚未连接的数据源
  │
  ├─ 若 missing_bindings 非空（且对应 scope 仍被勾选）
  │     → 同意页显示“需要先连接数据源”，批准按钮禁用
  │     → 走 federation 的绑定流程（/bind → 数据源 authorize → 回调，见 §4.9）
  │     → 完成后回到同一 handle 的同意页，重新加载后 missing_bindings 消失
  │     → 取消勾选某个 scope 也可以解除它对应的绑定要求
  │
  └─ POST /v1/authorization_requests/{id}/decision
        {decision:"approve"|"deny", scopes:[...], explicit:[...]}
        → 后端校验 subject/scope/explicit → oauth.Authorize 签发 code
        → 返回 {redirect_to:"https://client/cb?code=...&state=..."}
```

要点：

- **所有安全判断在后端**：pending 请求绑定会话，`explicit` 由后端复核，`redirect_to`
  由后端按注册的 `redirect_uri` 生成，前端不得自行拼接。
- 授权请求 handle 单次使用、短时效（30 分钟，需长于绑定流程）、绑定浏览器会话，防止"A 的请求被 B 批准"。
- **渐进式绑定已实现**：`GET /v1/authorization_requests/{id}` 返回 `missing_bindings`（含服务端拼好的
  `bind_url`），同意页据此提示并禁用批准；绑定后回到同一 handle。绑定的是**数据源**
  （`federation` 的 `/bind` 流程），凭据由数据源自己持有。

> 已实现：`internal/oidchttp`（OP 授权请求 + 同意决策，state 存 OP store）+ `httpapi` 路由，见 architecture.md §4.7。
> 扫码托管已迁出 Re0Auth，成为数据源自己的登录面（见 architecture.md §4.10）。
> 数据源的绑定流程（`/bind` → 上游 authorize → `/auth/upstream/.../callback`）同样已实现（§4.9）。

## 8. 凭据命名空间

- vault 的 `Identity{Subject: usr_..., Provider: "<game>.<source>"}`。
- 保存的是数据源为这次绑定签发的派生令牌；原始平台凭据（TapTap `sessionToken`、
  LeanCloud `objectId` 等）只在数据源侧，Re0Auth 没有可导出的凭据（D-5）。
- 新增游戏 / 上游 = 在 `sources` 中新增一个数据源与对应 scope，vault 结构不变。

## 9. v1 明确不做 / 后续

- **账号合并（merge）**：延后。需要双方强控制证明与凭据归属规则。
- **基于 email 的自动关联**：永久不做。
- 多身份策略（如强制要求 ≥2 身份以便找回）作为可选的安全增强，后续再评估。
- 5 大 IdP 客户端与 `/auth` 平面**已实现**（`idp`、`internal/auth`，见 architecture.md §4.6）；
  账号存储 `internal/account` 已强制 §2 三条不变量。真实 IdP 的 Client ID / Secret 需在部署时配置。
- 除内置 5 家外，`[idp.<name>]` + `issuer` 可接**任意 OIDC provider**（自建 Passkey / Keycloak /
  Authentik）：端点走 discovery，`id_token` 走 JWKS 验签，不验密码。
