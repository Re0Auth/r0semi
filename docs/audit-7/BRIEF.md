# 第七轮上线前审计 · 共享简报（READ-ONLY，所有区域代理必读）

> 本文件是第七轮审计的共享简报。**只读**：任何代理不得修改、移动或删除本文件。
> 你的输出只允许写进两个地方：
> 1. 你的发现报告：`docs/audit-7/findings/<你的区号>-<区名>.md`
> 2. 你的探针：`internal/zzprobe/audit7/<你的区号><区名>/`（**必须**带 `//go:build audit7` 标签）
>
> 除了这两个位置，**不得修改任何文件**（尤其不得改被 git 跟踪的文件）。

## 1. 项目是什么

Re0Auth（模块 `github.com/Re0Auth/r0semi`）：音游数据的**身份与授权层**——一套 OIDC/OAuth
协议（OP 角色）+ 参考实现。玩家用外部 IdP 登录；下游应用做一次 OIDC 接入拿
`id_token`/`userinfo` + 带 scope 的 access token；游戏后端实现「上游协议」
（`docs/upstream-protocol.md`）接入生态。

**技术栈**：Go 1.27（标准库 `net/http`，zitadel/oidc v3.51.3、pgx/v5、go-jose/v4），
SvelteKit 静态前端 `go:embed` 进二进制挂 `/app/*`；Postgres（goose 迁移）或纯内存双后端。

**架构地图**（读码时的路标）：

| 目录 | 作用 |
|---|---|
| `internal/httpapi/` | 公网 HTTP 边界：路由、中间件（限流/并发/头/压缩）、三平面 |
| `internal/oidchttp/` | OIDC OP 协议面（authorize/token/device/introspect/userinfo/revocation/discovery） |
| `internal/oidcstore/` | OP 存储契约 + 令牌编解码（access token 是不透明 compact JWE） |
| `oauth/` | scope 目录与 AS 域逻辑（Upstream Kit 的公开引擎） |
| `internal/federation/` | 数据面：把 `/v1/games/<g>/<r>` 读路由到已绑定的上游源 |
| `upstreamkit/` | 给第三方数据源的服务器骨架 + 一致性套件 |
| `httpclient/` | 出站 HTTP：熔断、重试、超时、字节预算 |
| `vault/` | 信封加密存储上游凭据（KEK→DEK），支持轮换 |
| `internal/store/{memory,postgres}/` | 双后端存储 |
| `internal/{auth,account,admin,lifecycle}` | 会话/账号/管理面/抹除 |
| `internal/ratelimit/` | 令牌桶限流 |
| `idp/`、`tapsign/`、`taptapoauth/` | RP 侧：对接外部 IdP（TapTap 等） |
| `referencesource/` | 演示数据源（不入发布产物） |
| `audit/` | 审计事件与防篡改链 |
| `web/` | SvelteKit 前端源码 |
| `cmd/re0auth/` | 组合根：配置装载、启动、后台循环、生命周期 |
| `deploy/`、`.github/workflows/`、`Dockerfile`、`scripts/`、`Makefile` | 部署与发布链路 |

三个平面（各自必须保持自己的错误形态）：`/oauth/*`+`/.well-known/*` = 协议平面（OAuth JSON 错误）；
`/v1/*` = 业务平面（RFC 9457 problem+json）；`/auth`、`/bind`、`/app/*`、未知路径 = 浏览器平面。

## 2. 环境（**决定你能给出什么证据**）

- **Windows 11，无 Docker，无本地 Postgres**。任何需要真实数据库的测试（`TEST_DATABASE_URL`）
  与容器构建都**不可能**跑——这些领域只给读码级证据，必须标 `HYPOTHESIS` 或写进「未能到达」，
  **绝不假装跑过**。
- Go 1.27.1、gcc 可用（`CGO_ENABLED=1 go test -race` 可用）、Node 24 + pnpm 11（`web/node_modules` 已装）。
  Playwright 浏览器**未安装**，`pnpm e2e` 不保证可跑；失败不算发现。
- 20 逻辑核 / 32GB，**同时有多个审计代理在跑**。不要引用绝对墙钟时间当性能结论；
  可引用的是每操作分配量（B/op、allocs/op，确定性）与复杂度类。
- **真实进程可跑**：`go build ./cmd/re0auth` 后用内存模式（不设 `DATABASE_URL`）可起真进程做黑盒探测。
- shell 是 **PowerShell**（不是 bash）。要精确控制子进程就写 Go 程序或 Go 测试，别依赖 shell 语义。
- **并行代理共用一个工作区**：默认 `go test ./...` 必须保持全绿。你的探针必须放在
  `internal/zzprobe/audit7/<你的目录>/` 且全部带 `//go:build audit7`，这样默认套件看不见它们。
  **不要跑全仓 `go test ./...`**（慢且互相干扰）；跑你自己的：
  `go test -tags audit7 -count=1 ./internal/zzprobe/audit7/<你的目录>/...`
  以及目标包的定向测试。`go build ./...` 与 `go vet ./...` 可以跑。
- **端口分配**：区域 n 的审计真进程用 `127.0.0.1:(17000+100n+1)`，内部面 +50；
  复核代理用 +1 / +51。这是为并行代理不撞端口。

## 3. 证据标准（违反即报告作废）

> **A finding is not a finding until a test can fail on it.**
> （一条发现，必须有一条会失败的东西才算数。）

每条发现必须满足其一：
1. **有一条真的跑过并失败的测试/命令**（贴命令与关键输出）→ 标 `CONFIRMED`；或
2. **读代码到行**（`file:line` + 为什么不需要执行即可断定）→ 标 `CONFIRMED`（源级）
   或 `HYPOTHESIS`（若结论依赖运行时前提，如真实 Postgres/容器/集群）。

**反空转**：任何「某物不存在/被拒绝/没生效」的断言，必须先证明探针真的走到了那条路径
（先断言对照组通过，或故意注入时失败）。**没有阳性对照的「零命中」不算证据。**

**红 = 证据**：探针失败就是发现；探针通过要么说明守住了（写进「探过没破」），
要么说明探针本身是空的（必须排除，不能当正面结论）。

## 4. 必读（按项目自己的方法论）

1. `docs/threat-model.md` — 威胁模型。
2. **前三轮的结论与「有意不做」的清单**（把它们当缺陷报 = 浪费整轮）：
   - `docs/api-design.md` §0/§3（D-1…D-6）、`docs/oidc-decision.md`（O-1…O-9）、
     `docs/dependencies.md` §3、`docs/upstream-protocol.md` §6.1；
   - `docs/cors-decision.md`、`docs/resilience-decision.md`、`docs/core-runtime-decision.md`、
     `docs/authorization-engines-decision.md`、`docs/browser-plane-decision.md`、
     `docs/operations-decision.md`、`docs/observability-decision.md`、`docs/migration-decision.md`。
3. **前两轮的全部发现（不许重报）**：
   - `AUDIT-ISSUES.md` + `docs/security-audit-5.md` + `docs/security-audit-2.md` + `docs/security-audit-3.md`
     —— 第五轮：P0×6、P1×5、P2×33、P3 30+、复核更正 12、探过没破 200+。
   - `docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md`（第六轮汇总，**最该先读**）、
     `docs/audit-6/findings/03-crypto-vault.md`、`04-postgres-store.md`、`05-memory-store.md`、
     `_audit/protocol.md`（第六轮区 01）。
   - 第六轮编号：**G-1…G-24**、**P-01…P-03**、**03-\***、**04-\***、**05-\***、**06-\***。
   - 第五轮编号：**P0-1…P0-6**、**P1-1…P1-5**、**P2-1…P2-33**、**P3-**、以及第二轮
     **A6-\***、**A1-\*** 等。**这些编号一律不得作为新发现重报。**
4. **本轮的核心工作之一**：检查**第五轮/第六轮的修复本身是否修对、修全、是否引入新洞**。
   这类发现**不算重报**，但必须显式写明「这是对 <编号> 修复的补充/反驳」，并给出修复前后的对照。
5. 项目自带的审计方法论文档（技能定义 + 探针参考清单，位于本机私有工具目录，**不在版本控制内**）。

## 5. 明确「有意不做」的事（report as finding = 作废）

不做 DPoP；不做 `end_session`；不做 PAR；不做动态客户端注册；不做 Session Management；
不做 CORS（协议面不发任何 CORS 头是有意的）；没有 KMS/HSM 适配器（KEK 来自环境变量）；
`core` 不接入生产组合根；内存模式重启即丢、不承担生产保证；`/v1/admin/*` 未认证返回 401 而非 404；
raw 透传逐字转发不解析 body；vault 的 `Identity`/`Meta` 明文落盘；审计链尾部截断不可检测（无外部锚点）；
迁移 0014 之前的审计行保留原始 `usr_`；跨实例 refresh 的残余竞态。
**若你认为某个文档化决定本身是错的，单独写成「判断」，永远不要写成 finding。**

## 6. 严重度怎么定

- **P0 阻断上线**：未认证的鉴权绕过、跨账号读写、凭据泄露、匿名可触发的 DoS、数据丢失/不可恢复、
  发布产物本身不安全、失败是静默的。
- **P1 高**：低门槛前提（一次登录、一个公开 client）即可扩大权限或读他人数据；
  或生产环境下的稳定性/正确性缺陷。
- **P2 中**：前提较高，或影响有界但确定。
- **P3 低/提示**：加固、纵深防御、文档与实现不一致、可维护性。
- **失败是静默的**（报成功、计数为 0、退出码 0、无日志）⇒ 严重度要**升**。

## 7. 报告格式（写到 `docs/audit-7/findings/<区号>-<区名>.md`，中文）

```markdown
# 区域 <区号>：<区名> — 第七轮审计报告

## 范围与方法
（你读了什么、跑了什么、真进程/测试夹具怎么搭的、探针文件路径）

## 发现

### <区号>-<n> <一句话断言>
- 严重度：P0 阻断 | P1 高 | P2 中 | P3 低/提示
- 类别：安全 | 性能 | 可用性 | 合规/隐私 | 可维护性
- 不变量：token/scope 签发 | 账号隔离 | 两平面分离 | 撤销生效 | 凭据封存 | fail-closed | 性能/资源
- 证据：（命令 + 关键输出，或 file:line + 机制推导）
- 状态：CONFIRMED | HYPOTHESIS（若依赖真实库/容器运行时，必须写清差什么）
- 影响：攻击者/运维实际得到什么；上线后会怎样
- 探针：<测试文件路径>::<测试函数名>（红/绿）
- 修法建议：<最小改法；涉及裁定就说清是裁定>
- 是否与既有编号相关：<无 / 对 G-x / P0-x 修复的补充或反驳>

## 探过但没破的（也应变成守卫）
（每条：攻击形状 + 探针名 + 为什么守住）

## 未能到达（残余盲区）
（如实列出，并说清为什么到不了、需要什么才能到）

## 判断（文档化决定可否质疑，不是 finding）
```

**返回给主代理的最终消息**：≤20 行摘要，每条一行
`<区号>-<n> [严重度] 一句话 (CONFIRMED|HYPOTHESIS)`，加上你的报告路径与探针目录路径。
**不要把整份报告粘回消息里**（会截断）。

## 8. 心态

尽量**多挖**：宁可交出「CONFIRMED 5 条 + HYPOTHESIS 12 条」，也不要只交 2 条而漏掉一片。
但**不要编**：每条都要能被别人按你写的方法核对。找不到洞的地方，把「我探过什么、为什么它成立」
写成守卫建议——那本身就是交付物。
**攻击必须走真实入口点**，例如：
- `internal/httpapi` 的全接线测试服务器（找该包既有的 fixture 构造器）
- `internal/oidchttp` 的真 provider（找该包既有 fixture）
- `go build ./cmd/re0auth` + 内存模式真进程黑盒探测
不要只调内部未导出函数来「证明」协议级结论。
