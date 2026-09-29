# 区域 17：文档 / 契约 / 配置样例漂移 — 第七轮审计报告

## 范围与方法

读：`README.md`、`SECURITY.md`、`CHANGELOG.md`、`config/re0auth.example.toml`、`docs/openapi.yaml`、
`docs/{runbooks,operations,slo,capacity-planning,observability-decision,architecture,incident-response}.md`；
对码：`cmd/re0auth/{config.go,main.go}`、`internal/config/{config.go,logging.go}`、`internal/httpapi/*.go`、
`internal/store/postgres/{postgres.go,auditchain.go}`、`deploy/k8s/*`、`deploy/prometheus/*`。

方法：① 环境变量名「文档 ↔ 代码」双向差集（含 `config/`、`scripts/`、CI）；② openapi 每条 operation 的
响应码 / schema 字段 / enum / 参数 vs handler；③ 文档里的数字与常量逐条对照（默认值、超时、池、上限、端口）；
④ 真进程黑盒：`go build ./cmd/re0auth` 后按 README 的两种启动形态实跑（内存模式，端口 18701）。

探针：`internal/zzprobe/audit7/z17docscontractdrift/`（`docs_probe_test.go` 静态三条、
`startup_probe_test.go` 真进程两条）。命令：

```
go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z17docscontractdrift/...
```

结果：**5 个探针全红**（每条都有阳性对照通过，见下），运行 2.7s。

## 发现

### Z17-1 README 快速开始与随仓库交付的配置样例不兼容：照抄即拒绝启动
- 严重度：P2 中
- 类别：可维护性（可用性：文档承诺的主入口不可用）
- 不变量：fail-closed（这里是 fail-closed 生效，被错的是文档/样例）
- 证据：
  - `README.md:17` `cp config/re0auth.example.toml config/re0auth.toml`；`README.md:19-24` 只导出
    KEK / DATABASE_URL / AUDIT_KEY / 两把 OP 密钥；`README.md:26-27` 直接跑。
  - 样例 `config/re0auth.example.toml:316-322` 是**未注释**的两段：
    `[idp.github] client_secret_env = "GITHUB_CLIENT_SECRET"`、`[idp.google] client_secret_env = "GOOGLE_CLIENT_SECRET"`。
  - `internal/config/config.go:57-66` `Secret()`：变量未设即返回错误；`cmd/re0auth/config.go:832→877-883`
    在 `loadIdP` 里对每个 `client_secret_env` 调用它。顺序上 `loadConfig` 在 `run()` 的
    `cmd/re0auth/main.go:332`，早于监听。
  - 真进程（探针红）：
    `ERROR msg="cannot start" stage=config err="idp.github.client_secret_env names \"GITHUB_CLIENT_SECRET\", which is not set"`
  - 阳性对照（同一次调用 + 补上两个 IdP secret）到达 `stage=storage`，证明失败点就是这条声明。
- 状态：CONFIRMED
- 影响：运维按文档走第一步就失败，且错误指向 IdP 而不是"样例不能直接用"；会浪费一次排障。未泄露、无安全影响。
- 探针：`startup_probe_test.go::TestZ17ReadmeQuickstartCannotStartWithTheShippedExample`（红）
- 修法建议：样例里把 `[idp.github]`/`[idp.google]` 两段注释掉（与 `[idp.authentik]`、`[[sources]]` 同样处理），
  或在 `README.md:16-27` 的片段里补上 `export GITHUB_CLIENT_SECRET=... GOOGLE_CLIENT_SECRET=...`。
- 是否与既有编号相关：无（Z13-7 讲的是产物内容与 README 不符，不是快速开始）

### Z17-2 README 的内存模式片段按原样无法启动（两处独立缺项）
- 严重度：P3 低/提示
- 类别：可维护性
- 不变量：fail-closed
- 证据：
  - `README.md:36-40` 的片段只有 `RE0AUTH_ISSUER=https://re0auth.example` 与 `RE0AUTH_KEK`。
  - `cmd/re0auth/config.go:488-492`：https issuer 且 `cookie_secure` 为假即拒绝启动；无配置文件时
    `CookieSecure` 默认 false（`config.go:453`）。
  - 拿掉前者后暴露后者：`cmd/re0auth/main.go:1381-1393`/`1426-1440` 两把 OP 密钥无条件必填，
    而 `README.md:31-32` 自己写着"无论哪种模式，两把 OP 密钥都必填"。
  - 真进程（探针红，两条独立断言）：逐字复现 → `stage=config err="server.cookie_secure must be true when
    server.issuer is https..."`；片段 + `RE0AUTH_COOKIE_SECURE=true` → `RE0AUTH_OIDC_TOKEN_KEY is required`。
  - 阳性对照（片段 + cookie 标志 + 两把 OP 密钥）`http://127.0.0.1:18701/healthz` 返回 200。
- 状态：CONFIRMED
- 影响：文档里唯一一个"纯环境变量启动"的例子不可用；与 Z17-1 合并会让人以为"内存模式根本跑不起来"。
- 探针：`startup_probe_test.go::TestZ17ReadmeMemorySnippetCannotStart`（红）
- 修法建议：片段补 `RE0AUTH_COOKIE_SECURE=true` 与两把 OP 密钥（或把 issuer 换成 `http://127.0.0.1:8080`，
  并说明 https 必须配 `cookie_secure`）。
- 是否与既有编号相关：无

### Z17-3 SECURITY.md 的"Our own audits"一节已过期：轮数与在盘文档都对不上
- 严重度：P3 低/提示
- 类别：可维护性
- 不变量：无（对外证据陈述）
- 证据：
  - `SECURITY.md:121` 写"Four rounds have been run"；`:122` 写"Two of them were written up as documents,
    and those are the ones on disk"，`:124-130` 只列 `security-audit-2.md` / `security-audit-3.md`。
  - 实际在盘：`docs/security-audit-2.md`、`-3.md`、`-5.md`、`-7.md`（本轮即第七轮）。
  - 探针红：`SECURITY.md says 4 rounds have been run, but docs/security-audit-5.md is on disk (round 5)`，
    同一条对 `-7.md`；并指出这两份文档未被该节提及。
- 状态：CONFIRMED
- 影响：向漏洞报告者传达的"已覆盖范围"陈旧，报告者可能把已审计过的问题当新问题提交，或以为轮数更多/更少。
- 探针：`docs_probe_test.go::TestZ17SecurityDocAuditRoundsAreNotStale`（红）
- 修法建议：改成按实际轮数陈述并列出四份文档；或改为不绑定数字的措辞（"write-ups are listed in
  `docs/security-audit-*.md`"），避免每次审计都要改这一节。
- 是否与既有编号相关：无

### Z17-4 openapi 的 `Binding.token_class` / `Binding.status` 封闭 enum 表示不了 `configured: false` 这一已文档化状态
- 严重度：P3 低/提示
- 类别：可维护性（契约）
- 不变量：业务平面响应形状
- 证据：
  - `docs/openapi.yaml:1828-1834`（`token_class`）enum `[revocable, long_lived]`；
    `:1835-1837`（`status`）enum `[active, degraded, retired]`；同 schema 把 `configured` 列为 required，
    其描述明说"False when the binding outlived the source's entry in this deployment's configuration"。
  - `internal/httpapi/binding_routes.go:23-24`：`TokenClass string \`json:"token_class"\``、
    `Status string \`json:"status"\`` —— **都没有 `omitempty`**；`:82-98` 只在注册表命中时才赋值，
    `configured:false` 时两者留零值 `""`。因此 `GET /v1/bindings` 会输出
    `"token_class":"","status":""`，落在 spec 的封闭 enum 之外。
  - 探针红（对两个字段各报一条）：`openapi Binding.token_class documents enum [revocable long_lived],
    but the field is marshalled unconditionally ... no omitempty ... and is left empty for a binding whose
    source has left the configuration (`configured: false`)`。
- 状态：CONFIRMED（源级：无 `omitempty` ⇒ 零值必上线，属必要条件即可判定）
- 影响：按 spec 生成校验器/客户端的下游会拒绝一条服务端合法产生的响应；与
  `CHANGELOG.md:126-130`（源从配置移除后仍要能列出并可断开）直接冲突——那条要求保留该状态。
- 探针：`docs_probe_test.go::TestZ17OpenAPIBindingEnumAdmitsTheUnconfiguredBinding`（红）
- 修法建议（择一）：给两个字段加 `,omitempty` 并让 `configured:false` 时缺省；或把 enum 加上 `""`
  并写清"源已离开配置时为空"。前者更干净（缺字段本就更像"没有可描述的源"）。
- 是否与既有编号相关：对 `CHANGELOG.md:126-130` 那次改动的补充（该状态被引入，spec 未同步）

### Z17-5 README 指认的"完整键位"样例漏掉 8 个已实现的环境变量覆盖
- 严重度：P3 低/提示
- 类别：可维护性
- 不变量：配置契约
- 证据：
  - `README.md:42`："完整键位、默认值与每段说明见 `config/re0auth.example.toml`"；样例头部
    `:13` 声明优先级 "environment > this file > built-in default"，且几乎每个键旁都有
    `# Environment override: ...` 一行——漏掉的那几个因此看不出是"有意不提"。
  - 探针扫描 `cmd/re0auth/*.go` + `internal/config/*.go` 的 `RE0AUTH_*`（并手工补上由前缀拼出的
    `internal/config/logging.go:32` ← `cmd/re0auth/main.go:296` 的 `SetupLogging("RE0AUTH")`），
    再对 `config/re0auth.example.toml` + `README.md` + `SECURITY.md` + `CHANGELOG.md` + `docs/*.md`
    全文求差，红结果 8 个：
    `RE0AUTH_CLIENT_ID`(config.go:778) `RE0AUTH_CLIENT_NAME`(:779) `RE0AUTH_COOKIE_SECURE`(:453)
    `RE0AUTH_KEK_ID`(:465) `RE0AUTH_LOG_LEVEL`/`RE0AUTH_LOG_FORMAT`(logging.go:32)
    `RE0AUTH_RATE_LIMIT`(:503) `RE0AUTH_RATE_LIMIT_BURST`(:507)。
  - 阳性对照：`RE0AUTH_KEK` 与 `RE0AUTH_MAX_IN_FLIGHT` 同时出现在实现集与文档文本里（证明扫描非空）。
- 状态：CONFIRMED
- 影响：`RE0AUTH_LOG_LEVEL`/`RE0AUTH_LOG_FORMAT` 在**整个仓库的任何文档里**都没有出现，运维无法发现可调日志
  级别/格式；`RE0AUTH_RATE_LIMIT(_BURST)`、`RE0AUTH_COOKIE_SECURE`、`RE0AUTH_KEK_ID` 同。纯环境变量部署
  （README 自己主推的形态）会因此看不出这些开关存在。
- 探针：`docs_probe_test.go::TestZ17ConfigExampleDocumentsEveryImplementedOverride`（红）
- 修法建议：在样例对应键旁补 `# Environment override:` 行（`rate_limit/rate_limit_burst`、`cookie_secure`、
  `[client] id/name`、`vault.kek_id`），并在一处（建议样例头部或 `docs/operations.md`）列出
  `RE0AUTH_LOG_LEVEL`/`RE0AUTH_LOG_FORMAT` 及其取值域（debug/info/warn/error、text/json）。
- 是否与既有编号相关：无

### Z17-6 openapi 说 audit 的 `cursor` 是"不透明、非签发即拒"，实现是普通行号且接受任意正整数
- 严重度：P3 低/提示
- 类别：可维护性（契约）
- 不变量：无（无安全影响）
- 证据：
  - `docs/openapi.yaml:1452-1455`：`pagination.next_cursor` from the previous page. **Opaque; the server
    rejects anything it did not issue.**
  - 实现 `internal/httpapi/audit_routes.go:82-89`：`strconv.ParseInt(raw, 10, 64)`，只拒非整数与 `<1`；
    服务端产出的取值是 `strconv.FormatInt(page.NextBefore, 10)`（`:163`），即十进制行 id。因此
    `?cursor=1` 这类"服务端从未签发过"的值被接受，且它不是不透明值而是可预测的行号。
- 状态：CONFIRMED（源级：`file:line` 即可判定，无需执行）
- 影响：契约措辞与实际行为不符；不会越权（行号本就来自 `id`，且分页仍受查询过滤约束），但按 spec 写
  "客户端不得构造 cursor"的下游会得到相反结论。
- 探针：无专用探针（上一条同一文件同一函数的静态对照已足够；不为此起真进程）
- 修法建议：把描述改成事实（"上一页返回的 `next_cursor`；服务端只校验它是正整数，取值即行 id"），
  或真把它做成不透明/签名游标。属裁定：建议只改文档。
- 是否与既有编号相关：无

## 探过但没破的（也应变成守卫）

- **数字类文档全部对得上**：`capacity-planning.md` 的池默认（16/2/5s/30s）、`max_in_flight` 缺省
  `max(64,16×8)=128`、内存 512、`federationMaxConcurrent=256`、`dataPlaneTimeout=45s`、`maxBody=4MiB`、
  64 MiB 预算、`GOMEMLIMIT=384MiB`、k8s limit 512Mi、`maxSurge:1/maxUnavailable:0`、replicas=2 全部与
  `postgres.DefaultPoolOptions()`、`cmd/re0auth/config.go:347-396`、`main.go:75/117/149`、`service.go:24`、
  `deployment.yaml` 一致；`slo.md:23` 的"6 小时"= `main.go:100`；`operations.md:223` 的"每小时"锚点
  = `main.go:91`；`operations.md:178` 的 `readinessTTL=1s` = `health.go:33`；`operations.md:245` 的
  verify 放宽 `statement_timeout=45s` = `auditchain.go:199/230`。
- **两份发现里提到的 35s/45s 关停数字**：属第六轮 G-12（`security-audit-7.md:120-121`），未重报。
- **openapi 的 operation 集合、`Problem.code` enum、`$ref` 解析**：已有 `internal/httpapi/openapi_test.go`
  三条守卫，本轮未找到漏网；23 条 operation 的响应码与 handler 的 `writeJSON/writeProblem` 逐个对齐
  （含 `DELETE /v1/admin/clients/{id}` 的"幂等"——`MemoryClientRegistry.Delete` 与 `Clients.Delete` 对
  未知 id 都返回 nil，`oauth/client.go:400`、`internal/store/postgres/oauth.go:515`）。
- **其余 schema 字段 vs handler**：`Session`/`Identity`/`ScopeView`/`ClientRef`/`Grant`/`AuditPage`/
  `AuditVerification`/`AdminClient`/`DevicePending`/`FederationSource`/`GameSources` 的 required 与字段名
  全部与 `session_routes.go:39-44`、`identity_routes.go`、`authorization_routes.go:185-198`、
  `admin_routes.go:16-30`、`device_routes.go:70-77`、`federation_routes.go:23-51` 一致；`AuditEntry.outcome`
  enum 与 `audit/audit.go:18-20` 一致。
- **次级配置样例格式**：`RE0AUTH_OIDC_RETIRED_TOKEN_KEYS=id:base64(...32B)` 与
  `RE0AUTH_OIDC_RETIRED_SIGNING_KEYS=kid:base64PKIX` 与 `main.go:1402-1473` 的解析一致；
  `RE0AUTH_OIDC_SIGNING_KEY` 的 "PKCS#8 DER, base64" 与 `:1426-1440` 一致；样例注释里的
  `RE0AUTH_STORAGE_*`、`RE0AUTH_TRUSTED_PROXIES_ANY`、`RE0AUTH_INTERNAL_EXPOSE` 等 env 名全部存在。
- **`RE0AUTH_BIN`/`RE0AUTH_CONFIG`**：出现在 `operations.md:139-142`，由 `scripts/backup-keys.sh:51/64`
  实现，不是无主文档。
- **未知键拒绝**：`internal/config/config.go:43-51` 对 `Undecoded()` 报错；本轮把样例逐键与
  `cmd/re0auth/config.go` 的 struct tag 对照，**没有未知键**。

## 未能到达（残余盲区）

- **真 Postgres 相关**：`[storage]` 段（driver/dsn_env/池）的行为、迁移、审计链在库里的形状，
  本机无 Postgres、无 Docker ⇒ 只做读码对照，未标 CONFIRMED 的运行时结论。
- **k8s 副本/NetworkPolicy 的实际生效**：无集群；`operations.md:191-201` 自己已把"CNI 是否实现
  NetworkPolicy"列为部署方自证项，本轮不重报。
- **grafana 面板内容 vs `runbooks.md` 里点名的面板名**：JSON 需解析后逐 title 比对；因
  `deploy/` 属区 13（已审）且其报告已核对 20 条 `runbook_url` 锚点，本轮未展开。
- **`docs/api-design.md`、各 `*-decision.md` 的 D-x/O-x 取舍**：按简报 §5 属"有意不做"，未作为发现。

## 判断（文档化决定可否质疑，不是 finding）

- `config/re0auth.example.toml` 选择"把常见 IdP 段写成生效状态"（`:316-322`）与它自己"每个键都有默认值、
  只写与默认不同的"的声明相冲突：这两段不是结构示例而是**硬依赖**，使样例不可直接使用。倾向于样例默认
  注释掉它们（与 `[[sources]]` 一致），但这是文档取向裁定，不是缺陷。
- openapi 把 `DELETE /v1/admin/clients/{id}` 的 404 定义为"非管理员"而非"未知 client"，
  使该端点在"未知 id"上没有可表达的语义；配合"幂等"描述尚自洽，故只记录判断，不作发现。
