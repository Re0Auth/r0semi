# 第六轮上线前审计 · 共享简报（READ-ONLY，所有区域代理必读）

> 本文件是第六轮审计的共享简报。**只读**：任何代理不得修改、移动或删除本文件
> （第五轮曾发生简报被误删、非法 UTF-8 打断整仓编译的事故，本轮以规矩防复发）。
> 你的输出只允许写进两个地方：
> 1. 你的发现报告：`docs/audit-6/findings/<你的区号>-<区名>.md`
> 2. 你的探针：`internal/zzprobe/audit6/<你的区号><区名>/`（**必须**带 `//go:build audit6` 标签）

## 项目是什么

Re0Auth（`github.com/Re0Auth/r0semi`）：音游数据的身份与授权层。一套 OIDC/OAuth
协议（OP 角色）+ 参考实现。玩家用外部 IdP 登录；下游应用做一次 OIDC 接入拿
id_token/userinfo + 带 scope 的 access token；游戏后端实现「上游协议」
（`docs/upstream-protocol.md`）接入生态。Go 1.27 后端（标准库 `net/http`，
zitadel/oidc v3.51.3、pgx/v5、go-jose/v4），SvelteKit 静态前端 `go:embed` 进二进制挂 `/app/*`。

**架构速览**（读码时的地图）：
- `internal/httpapi/` — 公网 HTTP 边界：路由、中间件（限流/并发/头/压缩）、三平面（protocol `/oauth`、business `/v1`、app `/app`）
- `internal/oidchttp/` — OIDC OP 协议面（authorize/token/device/introspect/userinfo/revocation/discovery）
- `internal/oidcstore/` — OP 存储契约与令牌编解码（access token 是不透明 compact JWE）
- `oauth/` — scope 目录与 AS 域逻辑
- `internal/federation/` — 数据面：把 `/v1/games/<g>/<r>` 读路由到已绑定的上游源
- `upstreamkit/` — 给第三方数据源的服务器骨架 + 一致性套件
- `httpclient/` — 出站 HTTP：熔断、重试、超时、字节预算
- `vault/` — 信封加密存储上游凭据（KEK→DEK），支持轮换
- `internal/store/{memory,postgres}/` — 双后端存储；`cmd/re0auth` 无 `DATABASE_URL` 时内存模式可整进程跑起来
- `internal/{auth,account,admin,lifecycle}` — 会话/账号/管理面/抹除
- `internal/ratelimit/` — 令牌桶限流
- `idp/` — RP 侧：对接外部 IdP（TapTap 等）
- `tapsign/`, `taptapoauth/` — TapTap 登录/签名
- `referencesource/` — 演示数据源（不入产物）
- `audit/` — 审计事件与防篡改链

## 环境（重要约束）

- **Windows 11，无 Docker，无本地 Postgres**。任何需要真实数据库的测试
  （`TEST_DATABASE_URL`）与容器构建都不可能跑——这些领域只给读码级证据，并在
  报告里标注 `HYPOTHESIS` 或「残余盲区」，绝不假装跑过。
- Go 1.27.1、gcc 16.1（`-race` 可用）、Node 24 + pnpm 11（`web/node_modules` 已装）。
  Playwright 浏览器未安装，e2e 不保证可跑；可尝试但失败不阻塞。
- 机器 20 逻辑核 / 32GB，同时有多个审计代理在跑。**不要引用绝对墙钟时间当性能
  结论**；可引用的是每操作分配量（allocs/op，确定性）与复杂度类。
- **真实进程可跑**：`go build ./cmd/re0auth` 后用内存模式（不设 `DATABASE_URL`）
  可起真进程做黑盒探测。示例密钥生成见 README（PowerShell 下可用
  `[Convert]::ToBase64String((1..32|ForEach-Object{Get-Random -Max 256}))` 造 32 字节 base64）。
- **并行代理共用一个工作区**：默认 `go test ./...` 必须保持全绿（当前基线：全绿）。
  你新增的探针文件必须全部放在你的专属目录并带 `//go:build audit6` 标签，
  这样默认套件与你人的编译互不干扰。

## 必读（按项目自己的方法论）

1. `docs/threat-model.md` — 威胁模型
2. 决策记录（这些是**有意不做**的事，把它们当缺陷报 = 浪费整轮）：
   `docs/api-design.md` §0/§3（D-1…D-6）、`docs/oidc-decision.md`（O-1…O-9）、
   `docs/dependencies.md` §3、`docs/upstream-protocol.md` §6.1
3. `AUDIT-ISSUES.md` — **第五轮全部发现**（P0×6、P1×5、P2×33、P3 30+、
   复核更正 12、探过没破 200+）。已由约 35 个 fix 提交修复（`git log --oneline -40`）。
   **第六轮不许重报第五轮已收录的条目**；但「第五轮的修复本身是否修对/修全/
   引入新洞」是本轮的核心工作之一。
4. 项目自带的审计方法论文档（技能定义 + 探针参考清单，位于本机私有工具目录，
   **不在版本控制内**）— 项目自己的审计方法论与探针目录。
5. 工作区**干净**（HEAD = `bf81b2a`）。基线已由主代理验证：`go build ./...`、
   `go vet ./...`、`go test ./... -count=1` 全绿（34 个包）。审计对象是当前 HEAD；
   结束时不许留下对被跟踪文件的任何改动。

## 方法论（项目规矩，本轮沿用）

- **一条发现必须有一条会失败的测试才算数**（CONFIRMED）；给不出测试的写
  HYPOTHESIS 并说明差什么。攻击必须走**真实入口点**：
  - `internal/httpapi` 的 `newFullEnv` / `newFullConfig`（全接线服务器，无库无网）
  - `internal/oidchttp` 的 `newFixture`（真 provider）
  - 或起真进程（内存模式）做黑盒探测
- 探针放 `internal/zzprobe/audit6/<你的区号><区名>/*_test.go`，第一行
  `//go:build audit6`（`audit5` 标签已被第五轮占用）。包占位 `doc.go` 同样带标签。
  验证方式：`go test -tags audit6 -count=1 ./internal/zzprobe/audit6/<你的目录>/...`
- **红 = 证据**：探针失败（红）就是发现的证据；探针通过（绿）则要么修好了要么是误报——
  如实分类。
- 发现排序按**攻击者得到什么**，不按技术巧妙程度。
- **不许修你发现的东西**（报告先行）；不许弱化任何守卫让测试变绿；
  不许修改任何**被跟踪**文件（`git status` 里的 M 文件尤其别碰）；
  `gofmt -l` 与 `go vet ./...` 必须在你结束时保持干净。
- 报告格式（每条发现）：

```
### <一句话断言>
- 严重度：P0 阻断 | P1 高 | P2 中 | P3 低/提示
- 不变量：token/scope 签发 | 账号隔离 | 两平面分离 | 撤销生效 | 凭据封存 | fail-closed | 性能/资源
- 证据：<复现输出，或 file:line + 机制推导>
- 状态：CONFIRMED | HYPOTHESIS
- 影响：<攻击者得到什么 / 上线后会怎样>
- 探针：<测试文件::测试名（红的）>
- 修法建议：<一句话>
```

报告末尾必须有两节：**「探过没破」**（你攻击过但守住的，含探针名）与
**「未能到达」**（本轮环境到不了的，如实列出）。

## 第五轮已修复的编号（供交叉引用，勿重报）

P0-1 id_token 缺 sub；P0-2 id_token 当 bearer + userinfo 不查活令牌；
P0-3 在途×响应体内存联合预算；P0-4 限流分桶键可归调用方 + 桶满淘汰活桶；
P0-5 不可解析 body 绕过重复参数检查→scope 闸门；P0-6 公开客户端无凭据内省；
P1-1/2 轮换 lost-update；P1-3 数据面超时/熔断；P1-4 readyz 免限流；
P1-5 scope 闸门与选源不一致；P2-1 吞审计失败；P2-2/3 抹除链；
P2-4/5 索引；P2-6/7/8/9/10/11/12/13/14/15/16/17/18/21/22/23/24/25/26/27/28/29/30/31/32；
以及 P3/判断清单的批量收口（见 `git log --oneline -40` 的 fix 提交）。

## 第五轮的残余盲区（本轮同样要如实标注）

Postgres 运行时语义（索引真实使用、隔离级别、超时行为）、容器/镜像层
（CA bundle 符号链接 P2-33）、真实发布链路、真实上游（TapTap/LeanCloud 方言）、
Linux 特定行为（0.0.0.0/8 路由、同端口双 bind）、单引擎浏览器。

## 本轮组织（第六轮执行时补充）

- 17 个区域代理并行（每批 6 个），每个区域完成后由**独立的对抗性复核代理**证伪
  （第五轮经验：12 个区域报告里 30+ 条严重度判定错误、3 条机制完全错误）。
- **端口分配**：区域 n 的审计真进程用 `127.0.0.1:(16000+100n+1)`，内部面 +50；
  复核代理用 +1 / +51。这是为并行代理不撞端口。
- 探针目录与包名：`internal/zzprobe/audit6/z<区号><短名>`（如 `z01protocolauth`），
  目录名 = 包名，全小写字母数字。占位 `doc.go` 用 `//go:build !audit6`，
  测试文件用 `//go:build audit6`（照抄第五轮 `internal/zzprobe/admin/doc.go` 的模式）。
- **不要跑全仓 `go test ./...`**（基线已验证全绿；并行代理在写探针）。
  跑你自己的：`go test -tags audit6 -count=1 ./internal/zzprobe/audit6/<你的目录>/...`
  以及目标包的定向测试。`go build ./...` 与 `go vet ./...` 是安全的，可以跑。
- 主代理在并行跑第五轮探针回归（`-tags audit5`），与你的 audit6 探针互不干扰。
