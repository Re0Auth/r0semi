# 有意不做 · 已裁定（NOT DOING / DECIDED）

> **这份文件不是待办。** 它的唯一作用是**防止同一件事被反复当成缺陷上报**。
> 一条东西进了这里，就说明维护者**知道它存在、并且选择不做**（或已裁定为可接受）。
>
> 如果你认为其中某一条**本身是错的**，请把它写成**判断（judgment）**并附上论证，
> **不要**把它作为新缺陷塞进 `P0`–`P3`。项目前六轮的审计方法论都是这一条
> （见 `docs/audit-7/BRIEF.md` §5、`docs/audit-5/BRIEF.md` §5）。

## 一、协议与产品范围（来自决策记录）

| 事项 | 依据 |
|---|---|
| 不做 **DPoP** | `docs/oidc-decision.md`（O-1…O-10） |
| 不做 **`end_session`**（RP-Initiated Logout） | 同上 |
| 不做 **PAR**（Pushed Authorization Requests） | 同上 |
| 不做**动态客户端注册**（DCR） | 同上 |
| 不做 **Session Management**（`check_session_iframe`） | 同上 |
| **`id_token` 里的非标准 `client_id` 声明保持现状**（第九轮 O-10）：值是 RP 自己请求的 `client_id`，不泄漏新信息，OIDC Core 不禁止多余声明；OIDF Basic OP 的 WARNING 属**已知且接受**的差异，不是待修项 | `docs/oidc-decision.md`（O-10）、`CHANGELOG.md` |
| 第九轮判为**信息级**、复核不再升档的条目（`S06-11` 等） | `P3-low.md` 中标 `[info]` 的行；`docs/security-audit-9.md` §4 |
| **协议面不发任何 CORS 头** —— 这是有意的 | `docs/cors-decision.md` |
| 不接 **KMS/HSM**：KEK 来自环境变量 | `docs/dependencies.md` §3、`docs/operations.md` |
| `internal/core` 的 DI **不接入生产组合根** | `docs/core-runtime-decision.md` |
| **内存模式重启即丢**，不承担生产保证 | `ADR-0006`（决策 6）、`docs/architecture.md` |

## 二、实现形态（有意的取舍）

| 事项 | 为什么不是缺陷 | 依据 |
|---|---|---|
| `/v1/admin/*` 未认证返回 **401 而非 404** | 有意的信息形态 | `docs/api-design.md` §0（D-1…D-6） |
| **raw 透传逐字转发、不解析 body** | 该端点的契约就是"原样" | `docs/upstream-protocol.md` §6.1 |
| **vault 的 `Identity`/`Meta` 明文落盘** | 只有密文部分才需要封存 | `docs/operations.md` |
| **审计链尾部截断不可检测**（无外部锚点） | 已在 `0013_audit_chain.sql:22-24` 与 `architecture.md` §4.16 明确写下 | 同上 |
| 迁移 `0014` 之前的审计行**保留原始 `usr_`** | 重写会破坏 `0013` 的链 | `0014_audit_pseudonyms.sql:31-34` |
| **跨实例 refresh 的残余竞态** | 已知且已记录 | `docs/architecture.md` |
| **`auth_time = COALESCE(auth_time, now())` 用数据库时钟** | 第六轮按 **P2-32（`bf81b2a`）** 裁定为"display-only 回退，无期限裁决读它"；由 `clock_inventory_probe_test.go` 的三条豁免清单盯住 | `docs/audit-6/findings/04-postgres-store.md` |
| **数据面刻意不装重试层** | 绑定刷新是旋转型单次凭据，重试无意义且加剧 churn ⇒ **改文档比加代码正确** | `docs/source-onboarding.md:225` 需改；`docs/resilience-decision.md` 需补 |
| **`sweep` 十条 DELETE 放同一事务** | 自述理由"a single consistent step…retry is always safe"（`postgres/sweep.go:42-45`）。**注意**：它回答的是"安全"，不回答"能不能推进"——后者是 `Z15-1` 的**真缺陷**，已单独入册 | 同上 |
| **gosec 只开一组精选规则**（`G304/G401/G402/G404/G501`） | 注释给了理由（TapM 的 MAC 真需要 HMAC-SHA1、配置装载真会打开 flag 给的路径、`G101` 会在公开 OAuth URL 上误报）。**但**"把 `G104`（未处理错误）与 `G107`（URL 来自可变输入）也关掉"是**判断**，已作为 `Z16-2` 入册 | `.golangci.yml` |
| **内存后端不提供生产保证** ⇒ 对内存后端特有的复杂度/性能问题一律降档 | 第五轮对 `PERF-5`/`PERF-6` 的既定口径 | `ADR-0006` |

## 三、已被复核推翻或降级、**不要**再上报

> 这些是前几轮**报过、后来被证明站不住**的条目。再报一次会毁掉整份清单的可信度。

| 曾经的编号 | 结论 |
|---|---|
| `Z10-3`（关停栈 65s > grace 45s） | **重报** `G-12`，同一栈同一探针；按一条计 |
| `Z18-1`（`/readyz` fail-open） | **重报** `G-11` / `22-1`；合并为一条 |
| `Z08-1/2/4/6`（前端静态服务四条） | **重报**第五轮 `A-FE-9/V-2`、`A-FE-1`、`A-FE-2`、`A-FE-3+V-1` |
| `Z20-5`（部署面 `/oauth/revoke` 预言机） | 机制**已被 `G-8` 的探针覆盖**；要改的只是 `G-8` 的文字把引擎写错了 |
| `Z18v-2` | 与 `Z14-4` 同一条（两个区域独立命中，属加强而非新增） |
| `Z21-1`（迁移 Down 缺 `IF EXISTS` 导致第二次报错） | **机制被推翻**：goose 的 Down 一次一个版本且与版本行同事务，正常路径不可能跑第二遍 ⇒ 纯加固项 |
| `TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` 的红 | **夹具假象**（夹具把 `Config.OIDC` 换成永远答 200 的桩） |
| 第五轮 `FO-02`（refresh 后 vault 残留） | 复核判「已知（非发现）+ 证据不成立」：探针在 **CAS 输掉**的分支触发，残留是入册时那条旧密钥 |
| 第五轮 `P-02`（设备批准入口不查 `ExplicitConsent`） | **被第七轮反驳**：`DecideDeviceAuthorization` 确实执行 `RequireExplicitConsent`，且早于第六轮 HEAD |
| 第五轮 `P-01` 的**影响面**（转义拼写绕过内省守卫） | 机制成立，但**什么也拿不到**（出口改写生效）⇒ 影响段被夸大 |
| `docs/source-onboarding.md:225` 的"指数退避重试" | 是**文档写错**，不是实现缺陷（`FO-05`） |
| 第九轮 §5 列出的同根编号（`S05-2`、`S04-1`、`S04-3`、`S13-3`、`S14-1`、`S14-6`、`S14-7`、`S14-8`、`S14-9`、`S14-10`、`S11-5`、`S13-10`） | **不是独立缺陷**：已按第九轮 §5 合并进 canonical 行（见 `P2-medium.md`/`P3-low.md` 问题列的「§5 合并」注记）；再报一次按重复计 |
| 第 9 轮与第 2–7 轮的**编号体系并存**（`Sxx-yy` vs `G-*`/`Z*`/`KIT-*`） | 同一机制可能有两个 ID；跨轮对应关系未做机械合并，**按机制不要按 ID 判重** |

## 四、判断（可以质疑，但请带论证）

这几条是**维护者明确缩小了范围**、而审计认为应当收回的；它们**不是**缺陷，是待决策项：

1. **`jwks_uri` 不钉在 issuer 上**：修复提交 `60de35d` 的说明写明"JWKS 没有覆盖旋钮，所以只钉两个端点"
   —— 即**有意 scope-out**，但它不在本清单的一、二节里，而第五轮 `_fragment_rp.md:139-141` 的修法建议
   本来就点名了 `jwks_uri`。**建议收回这个 scope-out**（见 `P2-medium.md` 的 `Z14-3`）。
2. **`KIT-6`（`RestoreClient` 不重校验 redirect URI）**：`docs/admin.md:69`、`oauth/client.go:180-192`
   把 registry 写入方视为可信运维。若坚持这个前提，应在 `client.go` 注释里补一句
   "**因此 authorize 路径不再做第二道检查**"——目前注释只说了前半句。
3. **`Z16-2` 的 gosec 白名单**：见二节末行。

---

## 五、各轮抽取到的裁定条目（生成区）

<!-- BEGIN GENERATED: _fragments 的「有意不做 / 已裁定」 -->
<!-- 以下由 _fragments/_merge.mjs 生成（2026-10-02）；改动请改片段或这里的手写章节，不要只改生成区。 -->

本次各轮抽取到的「有意不做 / 已裁定」条目（原文，未改写）：


### 第 9 轮

- `oidcc-server` 的 `client_id` WARNING —— 已知且接受的行为差异，见 `docs/oidc-decision.md` O-10 与 `not-doing.md`。

### 第 7 轮

- Z08-1 / Z08-4 — 重报第五轮 A-FE-9/复核 V-2（缺失 hashed asset 回 200 + SPA shell）与 A-FE-2（Range 把 shell 字节切片当 206 返回，第五轮已判「提示」），机制、修法、后果均已记录 — 依据：`docs/audit-7/findings/Z08-VERIFIED.md:17`、`Z08-VERIFIED.md:20`
- Z08-2 — 重报第五轮 A-FE-1（shell 标 `no-cache` 却无 ETag/Last-Modified，条件请求永远 200 全量），无新事实 — 依据：`docs/audit-7/findings/Z08-VERIFIED.md:18`
- Z08-6 — 重报第五轮 A-FE-3 + 复核 V-1（`scopeViews` 静默丢弃业务注册表不认识的 scope，含设备流第二份实现）；唯一「新」内容是原报告自认不可达的人造分叉注册表配置，仅属 HYPOTHESIS — 依据：`docs/audit-7/findings/Z08-VERIFIED.md:22`
- Z10-3 — 关停栈 5+30+30=65s > grace 45s — 依据：`docs/audit-7/findings/Z10-VERIFIED.md:112`（NOT-A-FINDING，逐字重报第六轮 G-12；且不存在报告所称的"G-12 修复"）
- FO-03 — `IsPublicAddress` 漏 `0.0.0.0/8`（及 `fec0::/10` 等同类缺项）— 前轮已记录，本轮不重报 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:328`
- FO-07 — `ProxyFromEnvironment` 使地址闸门判定代理而非目标 — 第五轮已收录 — 依据：`docs/audit-7/findings/Z09-VERIFIED.md:243`
- 第六轮 03-1 — vault 身份命名空间歧义（`game + "." + source` 无校验）— 第六轮已收录，撤回不报 — 依据：`docs/audit-7/findings/Z09-VERIFIED.md:250`
- 第六轮 — `Issuer` 的 userinfo 形式把用户令牌发到 authority — 第六轮已证，不重报（Z09V-3 是不同后果）— 依据：`docs/audit-7/findings/Z09-VERIFIED.md:254`
- 第五轮判断 — `NewService` 缺省 `HTTPClient` 是"有超时、无地址闸门" — 已记为判断而非发现 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:332`
- 第六轮 — kill switch 清扫不受 `TotalTimeout` 约束 — 已证，不重报 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:336`
- FO-05 — 数据面刻意不重试（`docs/source-onboarding.md:225` 的"指数退避重试"承诺）— 文档化判断，仅建议改文档 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:344`
- raw 透传的 scope 闸门是"源的任一资源 scope" — 文档化决定，不作发现 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:348`
- AUD-4 — 未声明动词 405 且泄露 `Allow`，`docs/admin.md:27`/openapi 与之漂移 — 第五轮已收录，不重报 — 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:382`
- 第六轮 z07 抹除记录探针（销毁前写 `account.delete` + `outcome=ok`）在 HEAD 上仍红 — 第六轮已有同形探针与论证，不列为本轮 finding — 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:389`
- AUD-10 — 内存模式清不掉会话（存活会话 = 存活运维权限）— 第五轮已收录，不重报 — 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:400`
- `admin.*` 的 `detail["actor"]` 记操作员原始 `usr_` — 已裁定（企业审计合规）— 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:404`
- `audit_subject_keys` 不在链上、内容不受签名保护 — 第六轮区 03 已证，不单列（仅在 Z10-2 影响里引用）— 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:407`
- 尾部截断不可检测（无外部锚点）— `migrations/0013` 与 `docs/architecture.md` §4.16 明写的边界 — 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:412`
- Z12V-2 — 非新洞：仅补强 Z12-6（关闭 TOML `nan` 残余盲区，小写被接受、大写被拒），无独立缺陷 — 依据：`docs/audit-7/findings/Z12-VERIFIED.md:158-161`
- Z11-5 的子命题「并发上限没有按调用方分摊」 — 文档化裁定，OPEN 部分只保留「一个地址可据此饿死所有其他客户端，且探针全绿」这一新意 — 依据：`docs/audit-7/findings/Z11-VERIFIED.md:118-121`（`operations-decision.md:40`）
- 兜底桶本身存在（桶满不淘汰活桶、新键共用一个兜底桶） — 文档化的方向正确，不作为发现；Z11-4 只质疑其分摊粒度 — 依据：`docs/audit-7/findings/Z11-resilience-dos.md:94,153-154`（`operations-decision.md:49`）
- 探针豁免（`health.go:151-166`） — 必要裁定，非 finding；Z11-1 证明的是它的**输入**（调用方 ctx）不该进共享缓存 — 依据：`docs/audit-7/findings/Z11-resilience-dos.md:156`
- ADR-0009 半开并发度 N、`Retry-After` 抖动、`Bulkhead` 许可活到 body 关闭 — 按文档实现，无异议 — 依据：`docs/audit-7/findings/Z11-resilience-dos.md:155`
- `-rotate-keys` / `-migrate-down` 无二次确认 — 第五轮已记录，本轮不重报 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:163`
- SIGTERM/SIGINT 关闭路径与两监听器排空顺序未真跑 — G-12/Z10V-2 地盘，避免重报 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:152-153`
- SIGHUP 无任何 handler — 是否需要「重载配置」是裁定而非缺陷 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:154`
- `-print-secret-env` 打印变量**名**不是值 — 安全，非 finding；其行格式是 `scripts/backup-keys.sh` 依赖的接口 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:161`
- `-version` 在配置缺失时也工作 — 刻意行为 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:162`
- 备份转储不加密 — 文档化取舍 — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:229`（`docs/operations.md:125-126`）
- 「备份已停」无告警 — 文档化取舍，第五轮 P2-16/DEP-06 已收录，属未闭合项而非新发现 — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:229-232`
- CI 的 image job 只 build 不 scan — 判断，不认为是漏洞（运行时 scratch + 每 PR 的 `govulncheck`） — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:233-235`
- `scratch` 而非 distroless — 判断，不是发现 — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:236-237`
- `-licenses` 未开 — 范围选择，第五轮 SUP-7 已裁定 — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:190`
- Trivy 按 digest 固定但不属 `uses:`，固定守卫看不到 — 已知范围选择（`docs/dependencies.md` §7） — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:170`
- 原报告「探过但没破 #3」（`restore.sh` 三条 fail-closed 守卫绿） — 被 Z13V-2 推翻：绿来自逐行复核而非执行，不作为守卫计入 — 依据：`docs/audit-7/findings/Z13-VERIFIED.md:87`
- Z14-3 的 scope-out（`60de35d` 明写「JWKS 没有覆盖旋钮，所以只钉两个端点」）—— 该缺口是有意缩小范围，verifier 明确建议**本轮收回该决定**，在此之前必须当成已知缺口而不是已修，故 Z14-3 仍记 OPEN P2 —— 依据：`Z14-VERIFIED.md:57-61`、`Z14-VERIFIED.md:167-169`
- Z15-1 的「一个事务」—— `sweep.go:42-45` 是文档化决定（自述「a sweep is a single consistent step…retry is always safe」）；报告修法「每表一个事务」直接推翻该决定，按简报 §5/§7 该部分应写成「判断」而非混进 finding；核心增量「无每轮有界推进」仍成立 —— 依据：`Z15-VERIFIED.md:36-38`、`00-MAIN-VERIFICATION.md:396-399`
- Z15-3 只定 P3 —— 内存后端按 ADR-0006 决策 6 不提供生产保证（同第五轮 PERF-5/6 口径）—— 依据：`Z15-performance-capacity.md:79`、`Z15-performance-capacity.md:151`
- Z14-6 只定 P3 —— `referencesource` 不入发布产物（与 BRIEF §2/`SECURITY.md` 一致）；若当模板对外发布应升 P2 —— 依据：`Z14-kit-rp-taptap.md:136`、`Z14-VERIFIED.md:87-88`
- Z16-2 的 gosec 子集本身是文档化取舍（`.golangci.yml:43-51`），但其**形状与注释理由不匹配**（注释按「逐条排除」行文、实现是白名单）属裁定项；bench/load/perf「报数不设阈值」也是文档化决定、不质疑 —— 依据：`Z16-guard-test-quality.md:161-162`、`Z16-VERIFIED.md:44-47`、`Z16-VERIFIED.md:136-137`
- Z17 样例选择「把常见 IdP 段写成生效状态」是文档取向裁定、本身不是缺陷（缺陷是 README 与样例不兼容）—— 依据：`Z17-docs-contract-drift.md:191-193`
- Z17-5 与第五轮 CS-10 的重报关系 —— 8 个变量里 6 个（`COOKIE_SECURE`/`RATE_LIMIT(_BURST)`/`KEK_ID`/`CLIENT_ID`/`CLIENT_NAME`）已由 CS-10 逐名记录，只有 `RE0AUTH_LOG_LEVEL`/`LOG_FORMAT` 是新残留；该条整体作 CS-10 的补充，不另立新发现 —— 依据：`Z17-VERIFIED.md:66-79`
- Z18-1 — NOT-A-FINDING：与第六轮 `G-11` 及本轮区域 22 `22-1` 是**同一条代码路径**（`health.go:111-118`，`checked==false` 时拿零值 nil 当结论），第三次重报；严重度按出厂清单 P2→P3 — 依据：`docs/audit-7/findings/Z18-VERIFIED.md:14`、`Z18-VERIFIED.md:176`、`docs/audit-7/findings/00-MAIN-VERIFICATION.md:187`
- Z18v-2 — 重复：`idp` provider TTL 在 discovery 失败时不前进（`:626-633` 返回旧 provider 且不更新 `discoveredAt`）与区域 14 的 `Z14-4` 是同一机制、同一站点，不另开条目 — 依据：`docs/audit-7/findings/Z18-VERIFIED.md:93`、`docs/audit-7/findings/Z14-kit-rp-taptap.md:96`、`00-MAIN-VERIFICATION.md:426`
- Z20-5 — NOT-A-FINDING / REFUTED：生产 OP `/oauth/revoke` 存活性预言机的机制成立，但「部署面从未被记」为假——第六轮 `G-8` 的红探针本体就打在该部署 OP 上（匿名公开 client 形态已覆盖），唯一有效成分是更正 G-8 的散文影响段，归属 G-8 — 依据：`docs/audit-7/findings/Z20-VERIFIED.md:30`、`Z20-VERIFIED.md:68`
- （无编号）`internal/ratelimit/ratelimit.go:116-125` 的 `rate.Limit(0) != rate.Inf` 注释错误＋潜在可回收分支 — 从发布组合根不可达（`cmd/re0auth/main.go:225` 对 `RateLimit<=0` 返回 nil），是「注释写错＋潜在分支」而非缺陷 — 依据：`docs/audit-7/findings/Z18-go-hazard-sweep.md:126`、`Z18-VERIFIED.md:139`
- （无编号）`internal/httpapi/middleware.go:242-255` 用 `context.Background()` 写访问日志 — 有意为之（客户端断开仍要留证据），不作为 finding — 依据：`docs/audit-7/findings/Z18-go-hazard-sweep.md:132`
- （无编号）KEK/token key/audit key/per-subject key 的内存零化（`vault.Scrub` 只覆盖 DEK 与明文） — 文档化为 best effort，Go 无法用探针证明，维持「判断」 — 依据：`docs/audit-7/findings/Z19-secrets-lifecycle.md:162`、`Z19-VERIFIED.md:133`
- （无编号）raw 是「源级粗闸门」这一已文档化的已知取舍（`docs/architecture.md:468` 白纸黑字） — 按简报 §5/§7 应写成判断＋补文档，不构成新 P2 洞（此即 Z20-2 降级依据） — 依据：`docs/audit-7/findings/Z20-VERIFIED.md:27`、`Z20-VERIFIED.md:49`
- （无编号）`introspection_clients` 启动期「必须是机密客户端」校验 — 今天由运行期守卫＋出口改写兜底（Z20-6），补启动期校验只是纵深防御，不改变结论 — 依据：`docs/audit-7/findings/Z20-VERIFIED.md:134`、`Z20-authz-isolation-matrix.md:168`
- FO-02 — DECIDED-NONGOAL：探针在 CAS 输掉的分支触发、残留的是入册旧密钥，证据不成立；跨实例 refresh 残余竞态 `BRIEF §5` 已列为有意不做 — 依据：`22-audit5-red-reconciliation.md:202`
- FO-04 — 既有 KNOWN-OPEN（registry scope 原样收下空白 / 畸形 game·name 被接受）：红是真但已被 FO-04 覆盖，不重报 — 依据：`22-audit5-red-reconciliation.md:181`
- RP-7 — 既有 KNOWN-OPEN（同意重定向可重放 / 并发得三份码）：一次同意仍只产生一份可兑换 grant，只属死码残留级 — 依据：`22-audit5-red-reconciliation.md:193`
- RP-6 — 既有 KNOWN-OPEN（`clearFlow` 在 provider 比对之前执行，走错 provider 的回调烧掉待完成登录）：可用性级、需会话内 state，非安全 — 依据：`22-audit5-red-reconciliation.md:199`
- P1-4 的 audit5 探针（#18、#19）— DECIDED-NONGOAL：P1-4 已由 `0e6b701` 修复，探针断言的是修复前缺陷（#19 的红仅是文档化的 `readinessTTL` 1s 代价） — 依据：`22-audit5-red-reconciliation.md:63`
- k1/k6、FO-03、KIT-2、KIT-4（已修，见 P2-medium）、KIT-5、KIT-6、KIT-7、KIT-8、KIT-9、KIT-10、RP-5、RP-8 — 16 条 `KNOWN-OPEN` 的既有编号，本轮 19 探针归因确认为既有、不重报（含 `RP-7` 覆盖的两条探针） — 依据：`22-audit5-red-reconciliation.md:44`
- ADR-0008「Down 应分可回退 schema 步 / 不可回退完整性步（后者 no-op + 文档化）」与「审计只追加是部署形态而非控制」 — 报告自陈为文档化判断、不是 finding — 依据：`Z21-VERIFIED.md:162`
- §4-1 `postgres/oidc.go:834` 的 `auth_time = COALESCE(auth_time, now())` — 第六轮已按 P2-32 裁定为 display-only 回退、无期限裁决读它，不是新发现 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:659-661`
- §4-2 `TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` 的红 — 夹具把 `Config.OIDC` 设成永远答 200 的桩，属夹具假象，不进清单 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:662`
- §4-3 根目录残留二进制（`re4auth.exe`/`perfreport.exe`/`httpapi.test.exe`）— 被 `*.exe` gitignore 覆盖、从未入库 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:663`
- §0 遗留探针本身 — 该文件未被 git 跟踪、不会进 CI，故不属于产品漏洞 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:17-18`
- G-1 修法与数据模型 — 检测点上被重放行已不存在（先删后判），无法就地撤销整条链，须先留族标识/已消费令牌墓碑 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:262-266`
- G-4 修法与存储边界 — `oidcstore.AuthRequest` 无 `MaxAge`/`Prompt` 字段，须先加字段再在钩子裁决 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:280-283`
- G-6 修法位置 — 必须落在 `internal/oidchttp`，不能靠改 `AuthorizeClientIDSecret` 修 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:91-92`
- Z20 编排更正 — 原「Z20 代理静默失败」判断是错的（只是慢），改走不冲突产物路径；隔离矩阵在覆盖族内成立，完整结论以 `Z20-authz-isolation-matrix.md` 与 `Z20-INDEPENDENT-CROSSCHECK.md` 为准 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:549-578`
- Z21 系列更正 — `0014` Down 不计入 Z21-2（其后果是独立新发现 Z21V-1）；「静默」表述过头，已改为「没有东西把 legacy>0 当回归」；可达性比原写更强；Z21-1 机制被复核推翻，降为纯加固项 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:580-597`
- 陈旧注释（无害提示）— `internal/httpapi/adversary_test.go:161-171` 的注释是「发现描述」旧文本，代码已修好，记为提示非缺陷 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:570-573`
- 04-7（第六轮 KNOWN-OPEN）— 建索引写冻结窗口，Z21-3 只补其时长部分（最坏 0012 一次 9 条）；时长须真 Postgres `pg_locks` 才能定论（OPEN-PG），本轮不重报 — 依据：`docs/audit-7/findings/Z21-VERIFIED.md:63`

### 第 6 轮

- `TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` — 该探针的 `GET /oauth/token → 200` 是夹具假象（`edgeServer()` 把 `Config.OIDC` 设成永远答 200 的桩），**不是生产缺陷，不进清单** — 依据：`docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md:146`
- 根目录残留二进制（`re0auth.exe`/`perfreport.exe`/`httpapi.test.exe`）— 被 `.gitignore` 的 `*.exe` 覆盖、从未入库，**判定「不是发现」**（唯一信息级风险：`.dockerignore` 没有 `*.test`）— 依据：`docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md:157`
- O-9 — `end_session` / `id_token_hint` / PAR / 动态客户端注册 / Session Management **明确不做、不广告** — 依据：`docs/oidc-decision.md:45`
- O-3 — userinfo 不以 `openid` 为闸门：任何活访问令牌都回 `sub`，`openid` 只约束 id_token；这是**有意**的（PROTO-10 判为已证伪）— 依据：`docs/oidc-decision.md:37`
- O-6 — refresh token 总是签发，`offline_access` 是兼容性空操作（接受但不要求、不报错、不对外呈现）— 依据：`docs/oidc-decision.md:41`
- D-3 / D-2 — v1 不做 DPoP（并已从 AS 元数据移除广告）、access token 保持不透明引用令牌 — 依据：`docs/api-design.md:12-13`

### 第 5 轮

- FO-02 — refresh 赢 CAS 后行被删的 vault 残留：探针在 CAS **输掉**的分支触发（删行在 `PutIfVersion` 之前），残留是入册时那条旧密钥；「跨实例 refresh 残余竞态」已列有意不做 — 依据：`docs/issues/not-doing.md:53`、`docs/audit-7/findings/22-audit5-red-reconciliation.md:47`、`docs/security-audit-5.md:313`
- FO-05 — 数据面刻意不装重试层（绑定刷新是旋转型单次凭据）；`source-onboarding.md:225` 的「指数退避重试」是文档写错，不是实现缺陷 — 依据：`docs/issues/not-doing.md:35`、`docs/audit-5/findings/federation.md:214`、`docs/audit-7/findings/22-audit5-red-reconciliation.md:247`
- P2-19 — 不透明 bearer 的 JWE 解析约 12 KB/请求，仍在延迟预算余量内：裁定维持 go-jose 标准库、不自造轮子，仅业务到量级再立项 — 依据：`AUDIT-ISSUES.md:233`、commit `9db3a99`
- （无独立编号；startup 探针 #18/#19）— round-5 P1-4 已由 `0e6b701` 修复；两条探针断言的是修复前的缺陷与 `readinessTTL`（1s）的文档化代价，故判 DECIDED-NONGOAL，不重报 — 依据：`docs/audit-7/findings/22-audit5-red-reconciliation.md:63-64`、`docs/operations.md:171-183`

### 第 2 轮

- FO-02 — 刷新赢得 CAS 后行被删留下的 vault 残留 / 跨实例 refresh 残余竞态：探针在 CAS **输掉**的分支触发，属「已知（非发现）+ 证据不成立」 — 依据：`docs/issues/not-doing.md:53`、`docs/security-audit-5.md:313`、`docs/audit-7/BRIEF.md:108`。
- FO-05 的后半（**数据面刻意不装重试层**）— 绑定刷新是旋转型单次凭据，重试无意义且加剧 churn ⇒ 改文档比加代码正确（待改的只是 `docs/source-onboarding.md:225`）— 依据：`docs/issues/not-doing.md:35`。
- A-FE-7 — 同意页/设备页共用带导航的布局：属**设计裁定**，应按 BRIEF §5 写进「判断」而非 finding — 依据：`docs/audit-5/findings/frontend-VERIFIED.md:29`。
- A-FE-V2 — 缺失的散列资产回 **200 shell** 而非 404：已被钉成性质（连监控/告警假设的后果都写了），不要再作为缺陷上报 — 依据：`docs/security-audit-7.md:302`、`docs/issues/not-doing.md:48`。
- （AUD/第二轮遗留）操作员 `usr_…` 仍进 `admin.*` 审计的 `Detail["actor"]` — 企业审计合规，**有意保留**；残余是该操作员日后抹除自己账号不会解除这些行的关联 — 依据：`docs/security-audit-2.md:42-44`、`docs/security-audit-3.md:286-294`。
- （第三轮判断）未认证的 `/v1/admin/*` 返回 **401 而非 404** — 有意的信息形态，`openapi.yaml` 已文档化 — 依据：`docs/security-audit-3.md:295-296`、`docs/issues/not-doing.md:28`。
- O-9 — 不做 `end_session` / `id_token_hint` / PAR / 动态客户端注册 / OIDC Session Management — 依据：`docs/oidc-decision.md:45`。
- D-3 — v1 不做 DPoP（RFC 9449），只签发普通 Bearer — 依据：`docs/api-design.md:13`、`docs/api-design.md:25`。
- （CORS）协议面不发任何 CORS 头；跨源 SPA 属明确不做 — 依据：`docs/cors-decision.md:32`。
- （密钥）不接 KMS/HSM，KEK 来自环境变量：KMS 买的是可恢复性与可归因，不是预防 — 依据：`docs/threat-model.md:121`、`docs/threat-model.md:136-138`。
- （落盘）vault 的 `Identity`/`Meta` 明文落盘（PII 定性，只写不读）— 依据：`docs/threat-model.md:161-177`。
- （审计）链尾部截断**就地验证挡不住**；改用服务每小时把链头写进日志的锚点，日志不落库外的部署维持较弱保证 — 依据：`docs/architecture.md:634`。
- （审计）迁移 `0014` 之前的审计行**保留原始 `usr_`**，不回填 — 依据：`docs/threat-model.md:255-256`。
- （审计）`auth_time = COALESCE(auth_time, now())` 用数据库时钟 — 第六轮按 P2-32（`bf81b2a`）裁定为 display-only 回退 — 依据：`docs/issues/not-doing.md:34`。
- （运行时）内存模式重启即丢、不承担生产保证 — 依据：`docs/threat-model.md:237-239`、`docs/issues/not-doing.md:22`。
- （数据面）raw 透传逐字转发、不解析 body；源自己返回凭据是源的缺陷 — 依据：`docs/threat-model.md:246-248`。
- （密码学）`server.rate_limit = 0` 会同时撤掉 `user_code`（20⁸ = 34.575 bit）的在线猜测界 — 配置项本身是文档化的，只需把副作用写进文档 — 依据：`docs/audit-5/findings/crypto-keys.md:460-462`。
- （密码学）两层 AAD 缺 `kek`/`payload` 层标签：当前靠密钥隔离，加标签会作废全部存量密文 ⇒ 只能随下一次 KEK 轮换做 — 依据：`docs/audit-5/findings/crypto-keys.md:457-459`。
- （协议）`user_code` 保持 20⁸（8 字符 / 20 符号）：RFC 8628 §6.1 在限流且短寿命下足够 — 依据：`docs/audit-5/findings/crypto-keys.md:463-465`。

<!-- END GENERATED -->
