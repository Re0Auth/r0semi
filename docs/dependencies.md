# 依赖与选型（v1）

> 原则：**协议与密码学不自己写；差异化逻辑自己写。**
> 前者错一次就是安全事故，后者正是本项目存在的理由。

## 1. 已采用的成熟库

| 库 | 用在哪 | 为什么是它 |
|---|---|---|
| `golang.org/x/oauth2` | `idp`（对外 IdP 客户端）、`federation`（对上游 AS 的客户端、PKCE） | OAuth 2.0 客户端的既成标准；`S256ChallengeOption` 等 |
| `github.com/coreos/go-oidc/v3` | `idp` 的 OIDC 提供方（Google / 微软） | 验 `id_token` 的签名（issuer JWKS）、issuer、audience、过期；discovery 缓存。**OIDC 是被攻得最多的点，绝不自己写** |
| `github.com/go-jose/go-jose/v4` | 间接：随 `go-oidc` 进来；测试里签 `id_token` | **只有一套 JOSE 栈**。DPoP/JWT 若将来要做，必须用它，绝不用第二套（如 `jwx`） |
| `github.com/alexedwards/scs/v2` | `internal/auth`（re0auth 会话）、`referencesource`（源侧会话） | 服务端会话、Cookie 属性、登录时轮换 |
| `golang.org/x/time/rate` | `internal/ratelimit`（按 key 令牌桶），`httpapi` 限流中间件 | 标准令牌桶。**注意它内部用真实时钟，不要和注入的假时钟混用**（会静默算错补充速率） |
| `github.com/cenkalti/backoff/v4` | `httpclient.Retry`（上游重试装饰器） | 成熟的指数退避 + 抖动策略；**只重试幂等方法**，POST 默认不重放 |
| `github.com/jackc/pgx/v5` (+`pgxpool`) | `internal/store/postgres` | Postgres 驱动。选它而不是 `database/sql` 是因为 v5 的泛型行扫描（`CollectRows`/`RowToStructByName`）能直接消除大量手写 `Scan` 错误 |

## 2. 刻意手写（用标准库就是"成熟库"）

| 位置 | 说明 |
|---|---|
| `vault` 信封加密 | `crypto/aes` + `crypto/cipher` 的 AES-256-GCM **就是**正解；AAD 带版本号 + 长度前缀防拼接歧义。换 Tink 只是多一层 |
| `oauth` 的 PKCE 校验、令牌生成 | `crypto/sha256` + `crypto/subtle` + `crypto/rand`，标准做法 |
| `internal/auth` CSRF | 会话内同步令牌 + 常数时间比较，标准模式；无需 `gorilla/csrf` |
| `taptapoauth` MAC 签名、QQ JSONP | **上游方言**，无库可用 |
| `internal/core` 组件运行时 | 研究产物（能力封闭 / effect-LIFO）；换 `fx` / `wire` 会丢掉正是要论证的性质 |
| `problem+json` | 无主流 Go 库，手写可 |

## 3. 评估过但暂不引入

| 候选 | 结论 |
|---|---|
| `ory/fosite`（OAuth 2.0 AS 引擎） | **方向赞成，时机未到**。它会接管协议引擎（含 PAR、mTLS、设备流、DPoP 支持），我们保留 scope 风险分级 / 显式同意 / 审计 withholding / 两平面纪律。但它要求实现约 10 个 storage 接口——套在内存存储上是白写，**应与真实持久化存储一起做**。因 `oauth.Service` 已是唯一接缝，替换不外溢 |
| `hashicorp/go-retryablehttp` | HTTP 重试的**专用**方案（认 `Retry-After`、幂等方法、包 `*http.Client`），比通用退避更贴场景。本项目选了 `backoff` 是因为它更贴合 `httpclient.Doer` 这个装饰器接缝；若将来重试逻辑变复杂，可换成它 |
| `github.com/awnumar/memguard` | 解决"Go 无法保证清零"。目前 `zeroize` + `runtime.KeepAlive` 是尽力而为，**这一限制应在 threat-model 中如实承认** |
| `jackc/pgx/v5` + `sqlc` | **已引入 `pgx`**（`internal/store/postgres`）。尚未引入 `sqlc`：目前查询不多，手写 pgx 更直接；查询量上来后再上代码生成 |
| `BurntSushi/toml` / `knadh/koanf` | 加载 `config/*.toml` 时引入；目前配置走环境变量 |

## 4. 反面教训（写下来避免重犯）

- **元数据不能撒谎。** 曾广告 `dpop_signing_alg_values_supported` 却从不校验 DPoP 证明——客户端会以为拿到了发送者约束令牌，实际是普通 Bearer（静默降级）。现已删除广告，并有测试锁定。
- **假时钟不能和真实时钟混用。** `x/time/rate` 内部读真实时钟；给限流器注入假时钟会让补充速率静默算错。测试改回真实短间隔。
- **重试不能重放非幂等请求。** `httpclient.Retry` 默认只重试 GET/HEAD/OPTIONS/TRACE。
