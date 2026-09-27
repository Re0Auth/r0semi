# Re0Auth 上线前审计 — 共享简报（所有审计子代理必读）

> 本文件由主代理创建。**只读**：不要修改，也不要删除。
> （注意：本文件曾被某个代理误删过一次，由主代理重建。若你发现它缺失，请报告，不要重建。）

## 1. 项目是什么

`.` 是 **Re0Auth**（模块 `github.com/Re0Auth/r0semi`）：音游数据的**身份与授权层**。
它同时是 **OpenID Provider（OIDC）** 与 **OAuth 2.0 授权服务器**，也是**数据联邦代理**。

- **Go 1.27** 后端（约 57k 行，271 个文件），单一二进制。
- 两种存储后端：**Postgres**（`internal/store/postgres`，goose 迁移）或**纯内存**
  （`internal/store/memory`，无 `DATABASE_URL` 时）。**两种模式都跑真正的 OP**。
- 前端：**SvelteKit 2 + Svelte 5 + Tailwind v4**，`adapter-static`，`ssr=false`，
  `go:embed` 进二进制，挂在 `/app/*`。
- 部署：多阶段 `Dockerfile` → `scratch` 非 root；`deploy/k8s/`；Grafana/Prometheus 配置。
- 出站韧性 `httpclient`（failsafe-go）、限流 `internal/ratelimit`、审计链 `auditchain.go`。

三个平面（各自必须保持自己的错误形态）：`/oauth/*`+`/.well-known/*` = 协议平面（OAuth JSON 错误）、
`/v1/*` = 业务平面（RFC 9457 problem+json）、`/auth`、`/bind`、`/app/*`、未知路径 = 浏览器平面（纯文本/重定向）。

## 2. 本机环境事实（**决定你能给出什么证据**）

| 事实 | 后果 |
|---|---|
| **Windows 11，没有 Docker，没有本地 Postgres** | **所有 Postgres/K8s/镜像路径的结论只能是「读代码到行」**，必须逐条标注「读；无 DB 执行」。不要假装跑过。 |
| Go 1.27.1；`go build ./...` / `go vet ./...` / `go test ./...` 基线全绿 | 可以写探针并真的运行。内存后端与 httptest 全部可跑。 |
| **`go test -race` 可用**（CGO_ENABLED=1 + gcc 齐） | 并发论断可以有检测器背书。跑不了就明说。 |
| shell 是 **Windows PowerShell 5.1**，不是 pwsh 7 | `ProcessStartInfo.ArgumentList` 不存在；`param($Args)` 会被自动变量遮蔽——两者已经各制造过一次假结果。要精确控制子进程就写 Go 程序。 |
| Node 24 + pnpm 11 可用；`internal/webui/dist` 除 `.gitignore`/`.gitkeep` 外**全部被 gitignore** | `pnpm run build` **不会**污染被跟踪树；可以构建并检查真实产物。 |
| 工作树**有未提交改动**（`internal/oidchttp`、`internal/httpapi`、`internal/federation/unbind.go`、`CHANGELOG.md`） | **绝对不要** `git checkout` / `commit` / `stash` / `restore` / `clean`。这些改动来自审计开始之前，不是你的。 |

## 3. 证据标准（本项目的规矩，违反即报告作废）

> **A finding is not a finding until a test can fail on it.**

每条发现必须满足其一：①**有一条真的跑过的测试**（贴命令与关键输出）；或 ②**读代码到行**
（`file:line`，并说明为什么不需要执行即可断定）。并明确标 **CONFIRMED** 还是 **HYPOTHESIS**。
假说很有价值，但必须自称假说，并写清「要证实它需要什么」。

**反空转**：任何「某物不存在/被拒绝」的断言，必须先证明探针真的走到了那条路径
（先断言对照组通过，或故意注入时失败）。

## 4. 探针文件的写法

- **首选**：新建**只含测试文件**的包 `internal/zzprobe/<区域>/`。同模块内，可 import `internal/...`，
  且不影响 `go list -deps` 的生产导入图。
- **次选**（需要包内未导出符号）：在被测包加 `zzprobe_<区域>_test.go`，且**必须保持该包能编译**。
  同目录已有别人的 `zzprobe_*` 时不要动它。
- **只新建文件，绝不修改任何已跟踪文件**。探针跑完**保留**（主代理统一清理），
  并在报告里写出完整路径与测试函数名。
- `go test ./internal/archtest/` 可能因你的探针包报 "unregistered module package" —— **预期，忽略**，
  不要为它改 archtest。
- **不要跑 `go test ./...`**：多个代理同时在树里工作，既慢又互相干扰。只跑你需要的包。
- **绝不删除 `docs/audit-5/**` 下的任何东西**——那是共享输出目录。

## 5. **不要重复报告**（前几轮已覆盖）

必读：`docs/security-audit-2.md`、`docs/security-audit-3.md`、`docs/threat-model.md` §9 与 §6.0/§6.1、
`docs/oidc-decision.md`（O-1…O-9）、`docs/api-design.md` §0 的 D-1…D-6 与 §3/§5、`docs/cors-decision.md`、
`docs/resilience-decision.md`、`docs/dependencies.md` §3、`docs/core-runtime-decision.md`、
`docs/authorization-engines-decision.md`。

**下列是「文档化决定」（deliberate non-goals），报告它们会毁掉整份报告的可信度**：
不做 DPoP、不做 `end_session`、不做 PAR、不做动态客户端注册、不做 Session Management、不做 CORS、
没有 KMS/HSM 适配器（KEK 来自环境变量）、`core` 不接入生产组合根、内存模式重启即丢、
`/v1/admin/*` 未认证返回 401 而非 404、raw 透传逐字转发不解析 body、vault 的 `Identity`/`Meta` 明文落盘、
审计链尾部截断不可检测（无外部锚点）、迁移 0014 之前的审计行保留原始 `usr_`、
跨实例 refresh 的残余竞态。
**若你认为某个文档化决定本身是错的，单独写成「判断」，永远不要写成 finding。**

## 6. 输出格式

写到 `docs/audit-5/findings/<区域>.md`（中文）：

```markdown
# <区域名> 审计报告
## 范围与方法
## 发现
### <ID> <一句话结论>
- 严重度: 阻断上线 | 高 | 中 | 低 | 提示
- 类别: 安全 | 性能 | 可用性 | 合规/隐私 | 可维护性
- 不变量/性质: <被破坏的性质>
- 证据: <file:line 或「命令 + 输出」>
- 状态: CONFIRMED | HYPOTHESIS
- 影响: <攻击者/运维实际得到什么>
- 修法建议: <最小改法；涉及裁定就说清是裁定>
- 复现/守卫: <探针文件路径 + 测试函数名>
## 探过但没破的（也应变成守卫）
## 未能到达（残余盲区）—— 必须写，并说清为什么
## 判断（文档化决定可否质疑，不是 finding）
```

返回给主代理的最终消息：≤15 行摘要（每条一行：`ID [严重度] 一句话 (CONFIRMED|HYPOTHESIS)`）
+ 报告与探针文件路径。**不要把整份报告粘回消息里**（会截断）。

## 7. 严重度怎么定

- **阻断上线**：未认证的鉴权绕过、跨账号读写、凭据泄露、匿名可触发的 DoS、数据丢失/不可恢复、
  发布产物本身不安全。
- **高**：低门槛前提（一次登录、一个公开 client）即可扩大权限或读他人数据；或生产环境下的稳定性/正确性缺陷。
- **中**：前提较高，或影响有界但确定。
- **低/提示**：加固、纵深防御、文档与实现不一致、可维护性。
- **失败是静默的**（报成功、计数为 0、退出码 0）⇒ 严重度要**升**。

## 8. 心态

尽量**多挖**：宁可交出「CONFIRMED 5 条 + HYPOTHESIS 12 条」，也不要只交 2 条而漏掉一片。
但**不要编**：每条都要能被别人按你写的方法核对。找不到洞的地方，把「我探过什么、为什么它成立」
写成守卫建议——那本身就是交付物。
