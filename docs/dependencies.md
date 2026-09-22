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
| `github.com/pressly/goose/v3` | `internal/store/postgres` 的迁移执行 | 成熟的 SQL 迁移库：标准 `-- +goose Up/Down` 注解、按版本排序与乱序检测、advisory-lock session locker，并自带 `goose_db_version` 版本表。**不校验已应用迁移文件的内容**（goose 无 checksum），所以它换掉的是手写 runner，不是"内容完整性"保证 |
| `github.com/zitadel/oidc/v3` | `internal/store/postgres` 的 `op.Storage`（ADR-0001：OpenID Provider） | OIDC 原生：设备码流（RFC 8628）内置、不透明引用令牌模型、`AuthRequest` 由实现者拥有（scope 收窄/同意可挂载）。**稳定 API 是 legacy `Storage`，新版 `Server` API 到 v4 前 experimental**。仍只用 `go-jose/v4`，不引第二套 JOSE（对照 fosite 见 [oidc-decision.md](./oidc-decision.md)） |
| `github.com/BurntSushi/toml` | `internal/config` 与 `cmd/*` 加载 `config/*.toml` | TOML 的事实标准。配置来源只有文件和环境变量两类，不需要 koanf 那样的多来源合并层 |
| `gopkg.in/yaml.v3` | **仅测试**：`internal/httpapi` 解析 `docs/openapi.yaml`，断言 spec 与实际路由双向一致 | YAML 的事实标准。**只在 `_test.go` 里被引用，不进任何二进制** |

关于 `yaml.v3` 的两点交代：

- **为什么不是 JSON。** 把 spec 写成 JSON 可以用 `encoding/json` 解析，**零新依赖**。放弃是因为 JSON 没有注释，而这份 spec 里“为什么这个 op 是这样”“为什么这里不广告 DPoP”这类注释和代码一样重要。一个不能解释自己的 spec 很快会变得与代码不符。
- **代价是诚实的。** `yaml.v3` 的 `go.mod` 声明 `go 1.11`，属于**未裁剪**模块，`go mod tidy` 因此会把它的测试依赖（`github.com/kr/text`、`github.com/rogpeppe/go-internal`）作为 `// indirect` 拖进模块图。它们**不被编译进任何产物**（`go build ./cmd/...` 的二进制不含 `yaml`），代价仅在 `go.mod` 里多两行。

关于 `goose` 的一点交代：

- **它的测试依赖会进 `go.sum`。** `goose` 的测试用到 `modernc.org/sqlite` 等，`go mod tidy` 会在 `go.sum` 留下若干行；它们不在任何产物的构建图里（`go build ./cmd/...` 不含），代价与 `yaml.v3` 同类。
- **它不做 checksum。** goose 只记录“哪个版本应用过”，不记录“应用时文件长什么样”。检测已应用迁移被篡改需要 Atlas 或自加校验列；当前接受这一边界，因为它本来就不是完整性机制。

## 2. 刻意手写（用标准库就是"成熟库"）

| 位置 | 说明 |
|---|---|
| `vault` 信封加密 | `crypto/aes` + `crypto/cipher` 的 AES-256-GCM **就是**正解；AAD 带版本号 + 长度前缀防拼接歧义。换 Tink 只是多一层 |
| `oauth` 的 PKCE 校验、令牌生成 | `crypto/sha256` + `crypto/subtle` + `crypto/rand`，标准做法 |
| `internal/auth` CSRF | 会话内同步令牌 + 常数时间比较，标准模式；无需 `gorilla/csrf` |
| `taptapoauth` MAC 签名、QQ JSONP | **上游方言**，无库可用 |
| `internal/core` 组件运行时 | 研究产物（能力封闭 / effect-LIFO）；换 `fx` / `wire` 会丢掉正是要论证的性质。**v1 不接入生产**，见 [core-runtime-decision.md](./core-runtime-decision.md)（ADR-0002） |
| `problem+json` | 无主流 Go 库，手写可 |
| 运行日志 | 标准库 `log/slog`。级别、结构化字段、handler 可换，都是它本来就有的；
**与 `audit.Logger` 刻意不合并**——审计是领域记录（有完整性要求），日志是运维诊断，
合到一起意味着审计记录会跟着运维调低的日志级别一起消失 |

## 3. 评估过但暂不引入

| 候选 | 结论 |
|---|---|
| `ory/fosite`（OAuth 2.0 AS 引擎） | **评估后未采用。** spike（`spike/fosite`）证实两点致命代价：（a）**不实现 RFC 8628 设备码流**；（b）把 75 个 indirect 依赖、第二套 JOSE（go-jose/v3）与 logrus/grpc/OTel 拉进构建图。最终选择 OIDC 原生的 `zitadel/oidc/v3`（§1），依据见 [oidc-decision.md](./oidc-decision.md) |
| `hashicorp/go-retryablehttp` | HTTP 重试的**专用**方案（认 `Retry-After`、幂等方法、包 `*http.Client`），比通用退避更贴场景。本项目选了 `backoff` 是因为它更贴合 `httpclient.Doer` 这个装饰器接缝；若将来重试逻辑变复杂，可换成它 |
| 云 KMS 适配器（阿里云 KMS / AWS KMS / GCP KMS） | **暂不引入**。`KeyWrapper` 接缝已就位，每个适配器都是一小段代码。**代价是持续的**：云依赖、按次计费、厂商锁定、本地开发与自托管都变复杂。买到的是**可恢复性与可归因**（KEK 不在进程里、解封可审计、密钥可停用），**不是防止解密**——被攻破的进程可以用自己的身份去调 KMS（threat-model §6.0）。自托管不需要；官方公共实例需要 |
| `github.com/awnumar/memguard` | 解决"Go 无法保证清零"。目前 `zeroize` + `runtime.KeepAlive` 是尽力而为，**这一限制应在 threat-model 中如实承认** |
| `jackc/pgx/v5` + `sqlc` | **已引入 `pgx`**（`internal/store/postgres`）。尚未引入 `sqlc`：目前查询不多，手写 pgx 更直接；查询量上来后再上代码生成 |
| `knadh/koanf` | 评估过的配置库。最终选了 `BurntSushi/toml`（见 §1）：配置来源只有文件和环境变量，koanf 的多来源合并是这一层不需要的 |

## 4. 反面教训（写下来避免重犯）

- **元数据不能撒谎。** 曾广告 `dpop_signing_alg_values_supported` 却从不校验 DPoP 证明——客户端会以为拿到了发送者约束令牌，实际是普通 Bearer（静默降级）。现已删除广告，并有测试锁定。
- **假时钟不能和真实时钟混用。** `x/time/rate` 内部读真实时钟；给限流器注入假时钟会让补充速率静默算错。测试改回真实短间隔。
- **重试不能重放非幂等请求。** `httpclient.Retry` 默认只重试 GET/HEAD/OPTIONS/TRACE。
- **`//go:embed` 的目录不能是空的。** 前端构建产物要嵌进二进制，就意味着新克隆必须能编译；
  而 `adapter-static` 每欠构建都会清空输出目录，把为了“新克隆能编译”而放的占位文件删掉。
  两个需求直接冲突，而“让 CI 记得先构建前端”不是解法——那只是一个能被忘掉的顺序。

## 5. 前端依赖（`web/`）

前端只在**构建期**存在。运行时没有 Node，没有 `node_modules`，没有第二份 lockfile 进部署——
产物是静态文件，`go:embed` 进同一个二进制。

| 依赖 | 用在哪 | 为什么是它 |
|---|---|---|
| `svelte` 5 + `@sveltejs/kit` 2 | 整个 `web/` | runes 的响应式模型比“虚拟 DOM + hooks”简单；编译期框架、运行时最小。选 SvelteKit 而不是 Next/Nuxt 是因为输出可以是纯静态文件，恰好是 `go:embed` 需要的形状 |
| `@sveltejs/adapter-static` | 输出到 `internal/webui/dist` | 见 §4 最后一条 |
| `tailwindcss` 4 + `@tailwindcss/vite` | 样式 | v4 的 `@theme` 让设计 token 就是普通 CSS 变量，不用多一层配置对象。对内部实现细节（`--color-ink` 等）的审计，比对一个组件库的源码容易 |
| `svelte-check` | `npm run check` | TS + a11y 静态检查。不放进 CI 的检查等于没有 |
| `@playwright/test` | `web/e2e` | 真浏览器跑同意页与设备流。只有在浏览器里才能发现“每一层各自正确、拼起来却不能用”的那类 bug——比如一个掐死自己 bootstrap 的 CSP。它只在开发/CI 存在，不进产物 |

**刻意不用 `shadcn-svelte` 的 CLI。** 评估过：v1.7 的 `init` 要求交互式选一套 preset（`--preset` 的取值没有非交互的帮助说明），
而它产出的是**复制进仓库、归你所有**的组件——也就是说，手写同样几个组件得到的是同一个东西，还少一层生成器。
对一个同意按钮所在的项目，“少一个依赖”本身就有价值。尾部用的是同一套 idiom（Tailwind + 设计 token + 自有组件），
以后想引入真 CLI 也不会撞车。

**`gopkg.in/yaml.v3` 也是**：它只被 `internal/httpapi/openapi_test.go` 引用，**不进任何二进制**（`go list -deps ./cmd/re0auth` 可以验证）。

### 5.1 反面教训（本阶段新增）

- **两个 CSP 是取交集，不是后者覆盖前者。** HTTP 头与 `<meta>` 同时存在时两个都生效，所以头里多写一句
  “看起来更严”的 `script-src 'self'` 会**静默**覆盖 meta 里构建期算出的脚本 hash，把应用自己的启动脚本封掉。
  症状是全白页，不是一条能看见的策略报错。浏览器测试是唯一能提前发现它的手段。
- **隔离跑能过、全量跑不过 = 共享资源耗尽，不是“换个测试又坏了”。** E2E 从单一地址发请求，被服务端
  按地址限流；修法不是“重跑一下”，而是把限流做成可配置的（顺带补上了一个真实的配置缺口），
  并让 fixture 把 429/5xx 直接打出来——失败旁边那一行必须说出原因。
