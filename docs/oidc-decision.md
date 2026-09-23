# ADR-0001：采纳 OpenID Connect，Re0Auth 升格为 OpenID Provider

> 状态：**已接受（Phase 0）**。本文是定位变更的正式记录，取代
> [positioning.md](./positioning.md) 中"不做身份"的旧表述。
> 证据来自两个 spike：`docs/zitadel-oidc-spike.md`（引擎可行性）与 `spike/fosite`（对照）。
> 代码迁移见 §6；**本文定稿后，Phase 1 才开始改代码。**

## 1. 决策

Re0Auth 从"纯 OAuth 2.0 授权服务器"变为 **OpenID Provider（OP）+ 数据授权层**：

- **对下游**：标准 OIDC。下游一次接入，同时拿到"这是谁"（`id_token` / `userinfo`）与
  "能读什么"（带 scope 的 access token）。
- **对玩家**：身份仍来自外部 IdP（GitHub / Google / Discord / QQ / 微软）。Re0Auth 只做
  **身份联邦（broker）**，**不自建密码 / 邮箱 / Passkey**。

一句话：**Re0Auth 成为音游数据域的 OIDC 提供方（身份联邦）+ 数据授权层。**

## 2. 为什么

1. **采用风险是本项目最大的风险**（[positioning.md](./positioning.md) §9 第一条）。
   OIDC 最大的实际价值不是协议本身，而是**每种语言 / 框架都有现成的 RP 客户端**。
   下游从"读 OAuth 文档接一套"变成"填 issuer + client_id"。对"标准需要两边都到场"的冷启动，
   这是最直接的一脚。
2. **它强化而非稀释原定位**：身份仍交给外部 IdP，Re0Auth 只是把"身份"和"数据授权"合并到**一次 OIDC 接入**里。
   没有自建账号体系，[account-model.md](./account-model.md) 的三条不变量（I-1/I-2/I-3）原样成立。
3. **技术与依赖都已验证可行**（`spike/zitadel-oidc`）：设备码流原生支持、不透明引用令牌模型契合、
   仍只用 go-jose/v4、构建图 264 包（对照 fosite 490）。

## 3. 契约（v1 起生效）

| # | 决策 |
|---|---|
| O-1 | **发现**：服务 `/.well-known/openid-configuration`（OIDC Discovery 1.0）；**同时**保留 `/.well-known/oauth-authorization-server`（RFC 8414），两者内容一致。纯 OAuth2 客户端不受影响。 |
| O-2 | **`id_token` 只在请求含 `openid` scope 时签发**；不含 `openid` 时**绝不**返回。签名 RS256，公钥在 JWKS。 |
| O-3 | **`userinfo`**（`GET /oauth/userinfo`，Bearer）：默认只返回 `sub`。**email 永不返回**（[account-model.md](./account-model.md) I-3 的延伸）。展示型 claims（`name` / `picture`）留待将来独立的 `profile` scope，单独决策。 |
| O-4 | **`sub` = Re0Auth 的 `usr_...`**：随机、稳定、伪匿名。 |
| O-5 | **access token 仍是不透明引用令牌 + introspect**（[api-design.md](./api-design.md) D-2 不变）；`id_token` 是唯一的 JWT。 |
| O-6 | **refresh token 总是签发**。`offline_access` 是**兼容性空操作**：客户端带上它不报错、不要求、也不对外呈现（token `scope` / introspect / grants 都不含它）；仅内部用它触发 refresh token 的签发。是否将来收紧为“必须显式请求”留待后续。 |
| O-7 | **scope 语义不变**：未知 / 未授权的 scope → `invalid_scope`，**不是静默丢弃**（库默认会静默丢弃，迁移必须补校验）。 |
| O-8 | **设备码流（RFC 8628）保持**，由 OP 原生提供。 |
| O-9 | **明确不做**：`end_session`（RP-Initiated Logout）、`id_token_hint`、PAR（RFC 9126）、动态客户端注册（RFC 7591）、OIDC Session Management。不广告、不实现。 |

## 4. 引擎

- 采用 **`github.com/zitadel/oidc/v3/pkg/op`**（legacy `Storage` API）。
- 手写 `oauth/` 引擎退役；业务平面的 introspect 改为通过 OP 的令牌存储 / `AccessTokenVerifier`。
- 依据：[zitadel-oidc-spike.md](./zitadel-oidc-spike.md)。对照 fosite 的结论：zitadel 在依赖、
  设备流、令牌模型上全面更优，且是 OIDC 原生。

## 5. 后果（必须接受）

1. **PII 面扩大**：`id_token` / `userinfo` 把账号身份暴露给下游。缓解：`sub` 伪匿名、默认零附加 claim、
   email 永不返回。
2. **两把新密钥**：OP 签名私钥（RS256）与不透明令牌加密密钥（32 字节 AES-GCM）。
   纳入密钥管理与轮换（对照 [threat-model.md](./threat-model.md) §6.0 的诚实边界）。
3. **refresh token 保持总是签发，`offline_access` 被当作兼容性空操作**：接受但不要求、不报错、不对外呈现；仅内部用于触发 refresh token。是否将来收紧为“必须显式请求”留待后续。
4. **新端点面**：`userinfo` / `keys`(JWKS) / OIDC discovery。`end_session` 不实现。
5. **库的现实**：稳定 API 是 legacy `Storage`；新的 `Server` API 到 v4 前标注 experimental。我们押 legacy，
   并在架构文档中记录这一依赖风险。
6. **必须门控 `id_token`**：zitadel 在授权码流**无条件**发 `id_token`（无 `openid` 也发，非合规）。
   迁移必须在库外包一层，无 `openid` 时剥掉。

## 6. 迁移阶段

| 阶段 | 内容 | 状态 |
|---|---|---|
| **P0** | 本文 + 定位 / 威胁 / 契约文档修订 | ✅ 已完成 |
| P1 | 生产 `op.Storage` 适配现有 Postgres 端口（`oidc_*` 表、客户端接缝、scope 门禁、审计） | ✅ 已完成 |
| P2a | `internal/oidchttp`：协议面 handler（端点对齐 `/oauth/*`、OIDC discovery + RFC 8414 别名、JWKS、userinfo、id_token 门控）+ 端到端测试 | ✅ 已完成 |
| P2b | 接入 `internal/httpapi`：`Config.OIDC` 替换协议面 + 业务面 introspection 桥（OP 令牌经 `/v1/me` 验证）+ 端到端测试 | ✅ 已完成 |
| P3a | `/v1/device/*` 与 `/v1/grants` 改走 OP 存储（`GrantStore` / `DeviceStore` 接缝）+ 测试 | ✅ 已完成 |
| P3b | 同意交互接缝（`internal/authorization`）；OP 同意适配；`cmd/re0auth` 在有数据库时翻转默认引擎为 OP（login hook 负责把请求绑到会话） | ✅ 已完成 |
| P4a | CI 在 OpenID Provider 引擎上跑浏览器 e2e；README / architecture 同步引擎说明 | ✅ 已完成 |
| P4b | 给 OP store 一个内存实现（`internal/store/memory`），使 re0auth 在生产与内存模式都走 OP；删掉 `httpapi` 旧协议面、`internal/authz` 与旧引擎接线（`oauth` 包仍作为 Upstream Kit 的引擎保留） | ✅ 已完成 |

## 7. 受影响文档

- [positioning.md](./positioning.md)：一句话定位、角色、非目标
- [threat-model.md](./threat-model.md)：资产、边界、ADR D6、开放风险
- [api-design.md](./api-design.md)：协议平面端点、决策 D-6
- [account-model.md](./account-model.md)：`usr_` ↔ `sub`、claims 策略
- [architecture.md](./architecture.md)：§4.4 授权服务器引擎替换
- [README.md](../README.md)：对外一句话描述
