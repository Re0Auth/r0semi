# r0semi 威胁模型与信任边界（v0.3）

> 状态：草案。本文档优先于代码，任何架构/协议决策都必须能在此文档中找到依据。
>
> **v0.3 的关键修订**：Re0Auth 采纳 OIDC，升格为 OpenID Provider（身份联邦 + 数据授权）。
> 新增对下游的 `id_token` / `userinfo` / JWKS / OIDC discovery，以及两把新密钥（签名私钥、令牌加密密钥）。
> 决策与契约见 [oidc-decision.md](./oidc-decision.md)（ADR-0001）。
>
> **v0.2 的关键修订**：r0semi 从“凭据经纪（自己托管上游凭据）”改为**授权与互通层**。
> 上游平台凭据的托管方是**数据源**，r0semi 从不接触它。v0.1 把 r0semi 写成 stoken 的托管者，
> **那条信任边界已不存在**；本文档的资产、边界、密钥层级与撤销模型据此重写。

## 1. 定位：两个独立持有者

r0semi 是**身份与授权层**：对下游是 OpenID Provider（OIDC）兼 OAuth 2.0 授权服务器，对数据源是 OAuth 2.0 客户端。
它**不是凭据金库，也不是身份来源**（身份仍来自外部 IdP）。

系统里有**两个各自独立的凭据持有者**，各有一份自己的 vault：

| 持有者 | 持有 | 从不持有 |
|---|---|---|
| **re0auth** | 数据源签发的**绑定令牌**（有 scope、可撤销） | 上游平台凭据（TapTap `stoken`） |
| **数据源**（每个源一份，可独立部署、可自托管） | 上游平台凭据（如 TapTap `stoken`） | 其它源的凭据；re0auth 的下游令牌 |

三条核心契约：

1. **下游永远接触不到任何凭据**——只拿到短寿命、带 scope 的访问令牌。
2. **re0auth 侧**：绑定令牌的明文只在调用数据源的那一刻存在。
3. **数据源侧**：上游平台凭据的明文只在调用上游平台的那一刻存在。

> **TapTap 是数据源的地基，不是 r0semi 的依赖。** r0semi 不参与"数据源 ↔ 上游平台"这条边界，
> 也无权触发该侧的上游撤销。这是 v0.1 与 v0.2 最本质的区别。

## 2. 资产分级

| 编号 | 资产 | 持有者 | 敏感度 | 备注 |
|---|---|---|---|---|
| A1 | 上游平台凭据（TapTap `stoken`） | **数据源** | 最高 | 长效、不可细粒度授权、泄露即账号沦陷。**re0auth 不持有** |
| A2 | **绑定令牌**（数据源签发的 AT/RT） | re0auth | 高 | 有 scope、可撤销；泄露可在源侧按绑定撤销 |
| A3 | Vault 记录中的 `Identity` / `Meta` | 两边 | 中高 | **非密钥但属 PII，明文落盘**（见 §6.1） |
| A4 | Vault DEK / KEK | 两边 | 最高 | 分别保护 A1（源侧）与 A2（re0auth 侧）。**KEK 目前由环境变量提供、驻留在进程内**（§6.0） |
| A5 | 用户身份 / 成绩数据 | 两边 | 高 | 个人数据，受合规约束 |
| A6 | re0auth 的 AT / RT / client_secret | re0auth | 中高 | 短寿命、可撤销 |
| A7 | 审计日志 | 两边 | 高 | 完整性要求（防篡改） |
| A8 | OIDC 身份声明（`id_token` / `userinfo` 的 `sub`） | re0auth | 中高 | 对下游暴露账号身份；`sub` 是伪匿名的 `usr_`（oidc-decision.md O-4） |
| A9 | OP 签名私钥（RS256）与令牌加密密钥（32B AES-GCM） | re0auth | 最高 | 新增密钥面：泄露可伪造 `id_token` / 解出不透明令牌。与 A4 同等对待（§6.0） |

## 3. 信任边界

| 边界 | 说明 | 信任级别 |
|---|---|---|
| B1 玩家 ↔ re0auth | 登录与同意。玩家在此看到"谁在用、用了哪个源" | 传输层加密，客户端不可信 |
| B2 下游客户端 ↔ re0auth AS | 桌面 / CLI / Web 均为 public client | **完全不可信**，无 client_secret |
| B3 re0auth ↔ 数据源 | 双向 OAuth 2.0：对下是 AS；对上用授权码 + PKCE 绑定 | 数据源可信，但仍受上游协议约束（发现、scope、`token_class`） |
| B4 数据源 ↔ 上游平台（TapTap） | 上游凭据明文的**唯一**接触路径。**re0auth 不是当事方，无法审计** | 由数据源自行承担 |
| B5 应用 ↔ Vault（及其 KEK） | 密钥边界（两边各一份，互不可见） | 解封需鉴权 + 审计；KEK 可轮换。**默认 KEK 在进程内，KMS 适配器尚未实现**（§6.0） |
| B6 | 运营者 / 内部人员 | 公共实例的最高权限 | **不受信任**，最小权限 + 全程审计 |
| B7 | 下游 RP ↔ OP 的 OIDC 端点 | authorize / token / userinfo / keys / discovery。`userinfo` 与 `id_token` 会把 A8 交给下游；端点本身沿用 B2 的 PKCE + 精确 redirect 约束 | 客户端不可信 |

## 4. 风险形态

v0.1 断言"泄露点从 N 降到 1"。**修订后这话只对一半**，必须拆开看：

| | 现状（每个下游工具各存一份 stoken） | 本架构 |
|---|---|---|
| 下游持有的凭据 | 长效 stoken | **短寿命、带 scope、可撤销的 AT** |
| 上游凭据的份数 | N（每个工具一份） | **每个数据源一份**——不是 1，但也不再随下游数量增长 |
| 上游凭据泄露的影响面 | 该工具的用户 | 该数据源的用户（**相关性风险下降**） |
| re0auth 自身的单点 | — | **仍然存在**：它持有全部绑定令牌与身份数据 |
| 安全下限由谁决定 | 最差的那个下游工具 | re0auth 的 opsec **+ 每个数据源的 opsec** |

结论：**下游侧的暴露面显著下降**（不再分发长效凭据，换发可撤销的短令牌）；**上游侧的相关性风险下降**
（凭据分布在各源，而不是人人一份），代价是必须逐个信任数据源。re0auth 本身仍是单点，但它持有的
A2/A3 可撤销、可审计、可细分，**暴露半径小于 stoken**。

## 5. 关键设计决策（ADR 摘要）

- **D1 公共实例**：提供官方公共实例以获得网络效应（自托管作为可选能力保留）。**但它不托管上游凭据**——
  上游凭据在数据源手里，公共实例被攻破不会直接泄露 A1。
- **D2 永不返回任何凭据**：任何 scope、任何 API 都不得返回 A1 或 A2。下游获得的是数据型 API 或
  端点白名单内的代理结果。曾经规划过的"导出 stoken"端点已删除，理由见 [api-design.md](./api-design.md) §5。
- **D3 信封加密**：每凭据独立 DEK，DEK 由 KEK 封装，载荷由 DEK 加密；每次解封都鉴权 + 审计，**两边各自一套**。
  KEK **可以轮换**。KEK 放在哪里（进程内还是 KMS）是**可选的部署选择**，不是这个决策的一部分——见 §6.0。
- **D4 两层撤销**：下游撤销是纯本地的（只失效 re0auth 的 AT/RT）；上游撤销（作废全部 `sessionToken`）
  必须由**数据源**执行——re0auth 没有 stoken，也无权触发。见 §7。
- **D5 Kill Switch（范围已修正）**：re0auth 能做的是一键作废全部**绑定**（丢弃绑定令牌 + 调各源的
  revocation endpoint），以及**对每个支持级联撤销的源发起登出请求**；它**不能**自己作废上游登录——
  那需要上游的凭据，而它没有。要连上游一起清，必须各数据源配合暴露该能力。
  **实现状态（v1）**：`POST /v1/admin/kill_switch` 已实现令牌、会话与**数据源绑定**三部分；
  绑定半边对每条绑定**本地必断**（撕碎 vault 密文 + 删行），并尽源所能调 revocation / 级联撤销，
  源不支持或不可达会如实报告（`bindings.unsupported` / `bindings.unavailable`），不会假装成功。
  按账号清会话依赖 `session_subjects` 索引（登录时写入、注销时移除），无索引的部署只能整体清会话。
  见 [admin.md](./admin.md) §4.2。
- **D6 采纳 OIDC**：Re0Auth 升格为 OpenID Provider（身份联邦 + 数据授权），玩家仍由外部 IdP 登录。
  新增 `id_token` / `userinfo` / JWKS / OIDC discovery 与两把新密钥（A8/A9）。决策与契约见
  [oidc-decision.md](./oidc-decision.md)（ADR-0001）。
- **D7 能力封闭的生产边界（ADR-0002）**：`core` 的运行时能力封闭在 v1 **不是生产门禁**，只是库层属性，
  且只覆盖**能力键访问**，不是沙箱（进程内第三方本就被拒绝，见 [architecture.md](./architecture.md) §2）。
  生产里被机器强制的同类约束是**包级依赖方向**（`internal/archtest`）。见
  [core-runtime-decision.md](./core-runtime-decision.md)。

## 6. 密钥层级

两个持有者各有一套，互不可见；KEK 各自独立：

```
数据源侧                          re0auth 侧
KEK（进程外，不可导出）            KEK（进程外，不可导出）
      └── 每凭据 DEK (AES-256-GCM)      └── 每凭据 DEK (AES-256-GCM)
                └── stoken 密文 (落库)            └── 绑定令牌密文 (落库)
```

- **任一侧**数据库单独泄露 ⇒ 无法解密：KEK 不在库里的任何一行。
- DEK 解封必须经由该侧的身份，并写入审计。
- **两边的 KEK 必须不同**：共用一个 KEK 会让一边的沦陷同时打开另一边的凭据。
- **KEK 可轮换**：`re0auth -rotate-keys` 用当前 KEK 重新封装每条记录的 DEK，**不解密也不重写载荷**，
  于是被泄露的旧 KEK 可以退役。

### 6.0 今天实际实现到哪一步（重要）

**只有进程内实现。`KeyWrapper` 没有 KMS/HSM 适配器，也没有任何云 SDK 依赖。**
KEK 来自环境变量（`RE0AUTH_KEK`），与密文、与进程同生共死。

| | 数据库单独泄露 | KEK 泄露（库未泄露） | 进程被攻破 |
|---|---|---|---|
| **现状**（KEK 在环境变量里） | **解不开** ✅ | 全部可读 ❌ | 全部可读 ❌ |
| 接入 KMS 之后 | 解不开 ✅ | 解不开 ✅ | **仍然可读** ⚠️ |

**最后一行是关键，而且常被说反。** 进程被攻破时，攻击者本来就能**用进程自己的身份去调 KMS 解密**。
KMS 买到的不是"防止解密"，而是另外三样：

1. KEK 材料**不在进程里**，因此不能被导出后在**将来的备份**上离线复用；
2. 每次解封**可审计、可限速、可告警**；
3. 密钥**可停用**——对活着的进程也能切断。

也就是说 KMS 是**可恢复性与可归因**，不是**预防**。它被列为"评估过但暂不引入"
（[dependencies.md](./dependencies.md)）：持续成本高（云依赖、计费、厂商锁定、自托管变复杂），
而用户无感知。**自托管不需要它；官方公共实例需要。**
- 明文在内存中的生命周期最小化，用后立即擦除。

### 6.0.1 OpenID Provider 的两把密钥（A9）

OP 另有两把密钥，**与 KEK 同级**，且有数据库时**强制要求配置**（缺一即拒绝启动，与 KEK / issuer 同样 fail-closed）：

| 密钥 | 环境变量 | 作用 | 泄露后果 |
|---|---|---|---|
| RS256 签名私钥 | `RE0AUTH_OIDC_SIGNING_KEY`（PKCS#8 DER，base64） | 签 `id_token` | 可伪造任意 `id_token` |
| 令牌加密密钥（32B AES-GCM） | `RE0AUTH_OIDC_TOKEN_KEY`（base64） | 加密不透明 access token（`tokenID:subject`） | 可解出 access token 的引用 ID |

**不设则拒绝启动。** 临时生成会让一次重启把全部 access token 变成不可读、全部 `id_token` 失效——那是静默降级，不是容错。

**轮换是双密钥重叠，不是就地替换：**

- 签名私钥：新 key 签发，旧**公钥**继续在 JWKS 发布（`RE0AUTH_OIDC_RETIRED_SIGNING_KEYS=kid:base64PKIX,...`），
  因此存量 `id_token` 仍可验证。等最长 `id_token` 寿命过去后移除旧公钥。
- 令牌加密密钥：新 key 加密，旧 key 继续解密（`RE0AUTH_OIDC_RETIRED_TOKEN_KEYS=id:base64,...`），
  因此存量 access token 仍可 introspect。等最长 access token 寿命过去后移除旧 key。

两者都只是**让泄露不再适用于之后写入的东西**，不能撤销已泄露的旧密钥对存量令牌的影响——与 KEK 轮换的边界一致（§6.0）。

### 6.1 落盘时不加密的部分（PII 定性）

凭据记录里有两块**按设计不加密**，因为它们要在没有 KEK 的情况下可用：

| 字段 | 内容 | 定性 | 落盘泄露的后果 |
|---|---|---|---|
| `Identity{Subject, Provider}` | `usr_` / 源账号 + 数据源命名（如 `phigros.next-phi`） | **非密钥，但属个人数据** | 泄露"某人绑定了哪些游戏 / 数据源" |
| `Record.Meta` | 上游 openid / unionid / LeanCloud objectId | **非密钥，但属 PII** | 泄露上游身份标识，可与其它泄露关联 |
| `federation_bind_flows.pkce_verifier` | 绑定时的一次性 PKCE verifier | **短期密钥（无法哈希）** | **单独无用**：还需授权码，而授权码只发给已注册的 redirect URI。TTL ≤ 绑定 TTL（默认 10 分钟）、单次使用、`DELETE ... RETURNING` 取走即删 |
| `oidc_auth_requests.id` | OP 授权请求的 handle | **不是密钥** | 设计上就出现在浏览器 URL 与服务器日志里，且被绑定到创建它的会话 |

**绑定表本身不能持有凭据**：`federation_bindings` 只存元数据（`token_type` / `expiry` / `has_refresh` /
`version`），Go 结构体里也没有令牌字段，并有测试从 `information_schema` 断言表里不存在
token / secret / credential / password / verifier 这类列。

前两块是**明文**，代码注释（`vault.Identity`、`vault.Record.Meta`）已如实标注。若部署的合规要求覆盖元数据，
处置方式是把 `Meta` 一并纳入密文（它目前**只写不读**，改动面很小）。

同样，**下发令牌（`oauth.Store`）、绑定令牌（re0auth 的 vault）、会话 cookie（`sessions`）
都不落明文**：前两者分别按键 `sha256(value)` 与信封加密，后者也按键 `sha256(cookie)` 查表。

## 7. 撤销：三种粒度，分属两个持有者

上游是 TapTap 内建账户（LeanCloud / TDS）体系。以下结论**属于数据源要面对的上游语义**——
re0auth 不参与其中（它没有 stoken）。查证结果：

- `sessionToken` **每个用户在每个应用内唯一**，即民间所称的 "stoken"。它**长期有效，直到用户主动登出**。
- 服务端**没有**"登出"或"按会话撤销"接口。唯一能作废它的方式是
  `PUT /1.1/users/<objectId>/refreshSessionToken`：调用后**旧 sessionToken 立即失效，
  所有持有它的登录均收到 403**，并返回一个新的 sessionToken。
- 该接口可用**当前 sessionToken**（`X-LC-Session`）或应用 **Master Key** 调用。
- 修改密码后若开启"强制客户端重新登录"，也会重置 sessionToken。

因此撤销分成三层：

| 层 | 由谁执行 | 触发 | 动作 | 影响 |
|---|---|---|---|---|
| **下游撤销** | re0auth | 用户解除某个下游应用的授权（`DELETE /v1/grants/{client_id}`） | 删除该客户端为该账号持有的全部令牌 | 只影响该下游应用；**已实现** |
| **绑定撤销** | re0auth | 用户断开某个数据源（`DELETE /v1/bindings/{game}/{source}`） | 擦除 vault 密文 + 删除绑定元数据 + 调源的 revocation endpoint（RFC 7009） | 只影响该用户与该源；**已实现**。上游那一半是尽力而为，结果随响应返回 |
| **上游撤销**（级联） | **数据源**（Re0Auth 只能请求） | 用户在连接页显式确认（`POST /v1/bindings/{game}/{source}/cascade_revocation`） | 数据源用其会话凭据调上游的注销/轮换接口，**丢弃返回的新 token**；Re0Auth 随后销毁 vault 密文并删除绑定 | 作废全部上游登录，**包括用户自己设备上的登录**。**已实现**：Re0Auth 请求，数据源执行；参照数据源用 TapTap 的 `refreshSessionToken` 实现 |

关键设计约束：

1. **默认绝不调上游撤销**。调一次就会把用户自己的手机登录踢下线。
2. **不保留旋转后的新 token**。若保留，等于静默劫持会话并把用户踢出，不可接受。
   故上游撤销后，**源侧** vault 条目标记 dead、擦除 DEK，用户必须重新托管。
3. **不使用 Master Key**。当前 token 足以完成旋转；Master Key 权限过大，不应引入。
4. **补偿幂等性（I4）**：`refreshSessionToken` 本身不幂等，但把目标定义为"旧 token 已失效"
   就是幂等的——重试遇到 403 即视为达成（响应丢失导致的重复旋转无害，因为新 token 本就要丢弃）。
5. **被动失效检测**：任何上游调用返回 403 → 判定 stoken 已失效 → 标记条目 dead 并要求重新托管。
   **这一条属于数据源**；re0auth 侧对应的信号是源返回 401/403 → 删除绑定并要求重新绑定。

对 consent 文案的要求：任何会触及上游撤销的操作，必须明说"将导致你本机也需要重新登录"；
且必须由**持有凭据的那一方**执行，不能由 re0auth 代劳。

## 8. 剩余待验证问题

以下问题关于**数据源 ↔ TapTap**这条边界（re0auth 不在其中）：

1. ~~民间所称 "stoken" 是否即 `sessionToken`~~ **已确认**。
2. ~~上游 host / App ID / App Key 的配置方式~~ **已确认**：cn 端点为主、global 作为备选，
   见 `config/referencesource.example.toml` 的 `[taptap]` 段。
3. `refreshSessionToken` 的限流与并发语义（并发旋转同一用户时的最终状态）。
4. 客户端 SDK 的 `Logout()` 是否会在服务端作废 sessionToken，还是仅清本地缓存？
   （文档无对应 REST 端点，倾向后者。若是前者，用户在自己设备上登出即让数据源的托管失效，
   必须依赖 403 被动检测。）
5. ~~TapTap OAuth2 设备码流程与 `sessionToken` 的关系~~ **已查证**（见 architecture.md §4.3）：
   设备码 → token → MAC 签名取账号 → LeanCloud `/users`（authData.taptap）→ **直接返回 sessionToken**。
   因此数据源侧的“一次性托管”可做成扫码 + 轮询，无需用户手抄 stoken。

在验证前，上游适配器按"行为显式、失败可见、可重试"设计。

## 9. 开放风险与治理

- **运营者信任**：公共实例的信任锚是运营方，需要透明度报告、warrant canary、第三方安全审计、密钥多人控制。
- **数据源信任**：架构把上游凭据分散到各源，代价是**每个源的 opsec 都成为安全下限的一部分**。
  `token_class` 与发现文档是唯一的结构化手段，用于如实标注一个源到底提供了什么。
- **Kill Switch 的范围**：re0auth 只能作废绑定；跨源的上游注销需要各源配合（§5 D5）。
- **raw 透传的边界**：`/v1/games/{game}/sources/{source}/raw/{path...}` 逐字转发源的原始 API。
  **若某个源自己的原生 API 会返回凭据，raw 会把它原样透出去**——那是源的缺陷，re0auth 无法识别也无法阻止
  （它不解析 body，这正是 raw 的契约）。登记一个源时应把这一点考虑进去。
- **KEK 的驻留位置**：默认是环境变量 + 进程内。数据库泄露解不开，但**KEK 泄露或进程被攻破即全部可读**，
  且 KMS 适配器尚未实现（§6.0）。这不是"以后再补的漏洞"，而是一条**必须明确告知部署者**的边界。
- **司法/合规**：PIPL（及可能的 GDPR）要求告知同意、最小化、可删除、泄露通报；同时需评估
  TapTap / Phigros ToS 对凭据共享的约束。**「可删除」已落地**：`DELETE /v1/account`（`internal/lifecycle`，
  见 architecture.md §4.13）逐 store 抹除一个账号并加密擦除其 vault 凭据。**审计日志也已处理**：
  它 append-only 且带链（§4.14），所以不删行，而是**主体假名化 + 销毁假名密钥**（§4.15）——
  抹除后那些行仍在、仍能校验，但无法再关联到人。**两条明确边界**：① 该机制落地**之前**写入的审计行保留原始
  `usr_…`，不回填；② 「不可关联」的前提是**除本服务外无人持久化 `usr_` 与自然人身份的对应**。
  这两条都必须告知部署者。数据导出见 `GET /v1/account/export`（只含元数据，不含凭据）。
- **事故响应预案**：检测到泄露 → 触发 re0auth 侧 Kill Switch（作废全部绑定）→ 通告各数据源 →
  复盘。
- **身份声明的相关性风险**：`id_token` / `userinfo` 让下游能把同一 `sub` 关联到同一账号（它本就是同一账号）。
  缓解：`sub` 伪匿名、默认零附加 claim、email 永不返回（oidc-decision.md O-3 / O-4）。
- **OP 密钥**：签名私钥泄露 ⇒ 可伪造 `id_token`；令牌加密密钥泄露 ⇒ 可解出不透明令牌。
  两者纳入 §6.0 的密钥管理与轮换；当前同样只有进程内实现，必须如实告知部署者。
- **未实现的 OIDC 面**：`end_session`、`id_token_hint`、PAR、动态客户端注册、Session Management 明确不做
  （O-9），避免广告一个提供不了的能力。
