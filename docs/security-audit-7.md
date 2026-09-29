# 第七轮：上线前安全与性能审计（Re0Auth）

> **审计对象**：`C:\git\r0semi`，`HEAD = bf81b2a`。审计期间**未修改任何被 git 跟踪的文件**
> （唯一例外：开工时修复了一处**未被跟踪**的遗留探针的非法 UTF-8，见 §0）。
> **本机环境**：Windows 11、**无 Docker、无本地 Postgres**、Go 1.27.1（CGO_ENABLED=1，`-race` 可用）、
> Node 24 / pnpm 11、Playwright 浏览器未安装。
> **方法**：继承第二至六轮的全部台账（`AUDIT-ISSUES.md`、`docs/security-audit-{2,3,5}.md`、
> `docs/audit-5/**`、`docs/audit-6/**`、`docs/audit-7/**`），**只报新洞与前轮修复的缺口**；
> 15 个区域由并行子代理审计，每个区域再由**独立的对抗性复核代理**逐条证伪。
> 主代理亲自读码并重跑了第六轮的全部红探针（§2）。

---

## 0. 一句话结论

**当前 `HEAD` 不可上线。** 第六轮认定的阻断项**全部仍然存在**——我在本机逐条重跑，红探针无一转绿；
第七轮又在**新的位置**找到了**同一类**缺陷（期限裁决落在后台 sweep 上、失败被静默、判据只有一个对象上的一半）。
其中最要紧的形状是：

> **「期限 / 撤销 / 失败」这三类裁决，一旦没有落在被读取的那条记录自己身上，就会静默失效。**

这句话在第六轮解释了 G-2（refresh 过期）、G-7（设备码过期）；第七轮证明它同样适用于
`oidc_auth_requests` 的 by-ID 读（Z07-1），并且**两个后端都漏**——而同一份代码的注释却写着
「a lookup refuses an expired one」（`cmd/re0auth/main.go:1325`、`postgres/sweep.go:10-13`、`memory/oidc.go:935-944`）。
**注释断言了实现没有的性质，是这一轮最反复出现的模式。**

### 0.1 本轮归纳出的三个系统性形状（比单条漏洞更重要）

1. **裁决没落在被读取的记录上** ⇒ 期限/撤销静默失效。
   G-2（refresh 过期）、G-7（设备码过期）、**Z07-1**（auth-request by-ID 读，**两个后端都漏**）、
   **Z21-2**（迁移 Down 把已入链的行变成 `Verify` 认可的 legacy 行）。
2. **fail-closed 的代价被转移给第三方** ⇒ 「保护自己」变成「攻击别人」。
   **Z11-4**（桶表被单个 IPv6 /64 填满后，所有新客户端共用兜底桶）、
   **Z11-5**（全进程一个并发信号量，一个地址拿住全部槽位）、
   **Z09V-1**（一个账号的上游凭据失效打开**共享** host 熔断器）、
   **Z09-4**（全局先到先得的缓冲预算，15 个零字节慢读 shed 他人满额读）。
3. **配置与启动面的 fail-closed 缺口同样是静默的**。
   **Z12-3**（首个 seed 之后 `[client]` 改动被忽略）、**Z12-6**（非有限 `rate_limit` 让限流失效）、
   **Z12-1**（密钥原文进启动日志）、**Z12-2**（`-rotate-keys` 扫到 0 条也退 0）、
   **Z19-4**（同料不同 id 的 KEK 让轮换静默空转）、**Z12-7 / Z11-1 / G-11**（`/readyz` 两个方向都可被匿名操纵）。

4. **修复本身成为新缺陷的来源**（本轮最值得记的一条）。
   前几轮的修复**引入了新的洞**或**只修了一半**，而不是没修：
   - **`Z20-1`**：第五轮 AUD-3 为"谁同意了不知道"加审计事件时，把 `oidc.consent.deny` 挂在了
     **成功兑换**的路径上 ⇒ **每次成功兑换都写一条拒绝**（由 `git log -S` 证明该事件此前不存在）。
   - **`G-11` / `22-1`**：第五轮 `P1-4` 修 `/readyz` 成本上限时引入的 fail-open
     （`health.go:111-118` 用零值 `nil` 兜底）。
   - **`Z09-1` / `Z13-3` / `Z14-2` / `Z14-3` / `Z15-1`**：都是**同族修复只覆盖了一部分**
     （`token_class` 修了而 `status` 没修；镜像归属修了 Go 侧没修 npm 侧；`checkCascadeEndpoint` 修了而
     `checkRevocationEndpoint` 没修；`jwks_uri` 被有意 scope-out；raw 路径修了而归一化路径没修）。
   - **`Z21-2`**：`0013` 的 Down 让链元数据不可恢复，而 `Verify` 对 NULL 哈希行只计 `Legacy` 且**从不参与判定**。

   **方法学结论**：**"修复是否修对、修全、是否引入新洞"必须与"有没有修"分开审**——
   本轮的 P2 里有相当一部分**只在修复之后才存在**。

### 0.2 上线前真正的阻断项（按"攻击者/运维实际得到什么"排序）

| 序 | 编号 | 一句话 |
|---|---|---|
| 1 | **G-1** | refresh token 重放被检测到后**不止损**（无 token family 撤销；且检测点上拿不到 subject，**需先加族标识**） |
| 2 | **G-2 / Z07-1** | **Postgres refresh 读路径**与**两个后端的 auth-request by-ID 读路径**不裁决期限（30 天 TTL / 30 分钟句柄失效） |
| 3 | **G-3 / G-13** | 数据库故障时撤销答 **200 成功**、`GetRefreshTokenInfo` 把故障折叠成"令牌不存在" |
| 4 | **Z11-4 / Z11-5** | **匿名单机**可耗尽限流桶表 / 并发槽位，把拒绝服务转嫁给其他用户 |
| 5 | **Z11-1 / Z12-7** | **匿名单机**可把健康副本的 `/readyz` 写成 503（原因只进 `slog.Debug`） |
| 6 | **Z12-3** | `[client]` 的 redirect URI / secret / scope 改动**静默不生效**（secret 轮换的场景最重） |
| 7 | **G-4** | `prompt=login` / `max_age` 被忽略（`oidcstore.AuthRequest` 无字段，**需先改存储边界**） |
| 8 | **G-5 / G-6** | percent 编码绕过内省守卫；匿名可冒机密客户端发起设备流（**修法在边界，不在 store**） |
| 9 | **G-12** | 关停栈 65s > grace 45s ⇒ 每次滚动更新静默丢审计 |
| 10 | **Z07-2** | 抹除失败时**唯一**那条审计记录谎报成功 |
| 11 | **Z21-2** | 一次 `-migrate-down` → up 往返即**静默拆除**审计链防篡改 |
| 12 | **Z13V-2** | **`scripts/restore.sh` 在自身 `set -euo pipefail` 下 100% 无法执行** ⇒ 文档化的唯一恢复路径**从来没跑通过**（第五轮 `P2-11` 的"修复"从未被执行验证）。**备份正确也恢复不了**，这是上线前必须实际演练一次的项目 |

---

## 1. 统计与覆盖

| 项 | 数 |
|---|---|
| 第七轮新增发现（15 个区域报告 + 复核新增 + 主代理 N-01…N-04） | 区域报告合计约 **110 条**；**复核去重与降级后净新增约 95 条**（区 08 一次就砍掉 6 条重报 + 3 条降级） |
| 其中 P1 及以上 | **约 15 条**（见 §0.2 的排序表） |
| 第六轮发现的独立复现 | 红探针 **19 个函数**，我亲自重跑全部为红（§2） |
| 第五轮 `audit5` 红探针归因 | 19 条：KNOWN-OPEN 16 / DECIDED-NONGOAL 3 / REGRESSION 0 / UNCLASSIFIED 0 |
| 历史仍未关闭的条目 | 16 条（第五轮 k1/k6、FO-03/04/05、KIT-2/4/5/6/7/8/9/10、RP-5/6/7/8） |
| 复核**降级/推翻** | 至少 5 条（`Z10-1`/`Z10-2` P2→P3、`Z10-3` 判重发、`Z17-1` P2→P3、`Z18-1` 判重发） |
| 复核**新增**发现 | 约 15 条（Z09V-1/2/3、Z10V-1/2、Z17V-1、Z18v-1…4、NF-Z07-1、22-1、22-2 等） |
| 本轮反空转正面结论 | 每份区域报告都带「探过没破」一节（合计 80+ 条） |

**区域覆盖与产出位置**

| 区 | 主题 | 报告 | 独立复核 |
|---|---|---|---|
| 07 | 会话 / 账号 / 身份 / 抹除 | `.../Z07-auth-session-lifecycle.md` | ✅ `Z07-VERIFIED.md` |
| 08 | 前端与浏览器平面 | `.../Z08-frontend-browser.md` | ✅ `Z08-VERIFIED.md`（**4 条判重报、3 条降级、仅 2 条成立**） |
| 09 | 联邦 / 数据面 / 出站 | `.../Z09-federation-dataplane.md` | ✅ `Z09-VERIFIED.md` |
| 10 | 管理面 / 审计链 / 隐私 | `.../Z10-admin-audit-privacy.md` | ✅ `Z10-VERIFIED.md` |
| 11 | 韧性 / 限流 / 并发 / DoS | `.../Z11-resilience-dos.md` | 进行中 |
| 12 | 配置 / 启动 / 可观测性 | `.../Z12-config-startup-observability.md` | 进行中 |
| 13 | 部署 / CI / 供应链 | `.../Z13-deploy-ci-supplychain.md` | 进行中 |
| 14 | Upstream Kit / RP / TapTap | `.../Z14-kit-rp-taptap.md` | ✅ `Z14-VERIFIED.md` |
| 15 | 性能 / 容量 / 内存 | `.../Z15-performance-capacity.md` | ✅ `Z15-VERIFIED.md` |
| 16 | 守卫与测试质量 | `.../Z16-guard-test-quality.md` | 进行中 |
| 17 | 文档 / 契约漂移 | `.../Z17-docs-contract-drift.md` | ✅ `Z17-VERIFIED.md` |
| 18 | Go 级危险模式全仓扫描 | `.../Z18-go-hazard-sweep.md` | ✅ `Z18-VERIFIED.md` |
| 19 | 密钥与敏感数据生命周期 | `.../Z19-secrets-lifecycle.md` | 进行中 |
| 20 | 授权隔离矩阵 | `.../Z20-authz-isolation-matrix.md` | 复核进行中（+ 独立交叉核对 `Z20-INDEPENDENT-CROSSCHECK.md`）。**过程记录**：我曾误判该区代理"静默失败"并补派，实际它只是慢；补派者被改为写**不冲突的**路径——这是并行编排里"没有产物 ≠ 失败"的实例，教训记在 `00-MAIN-VERIFICATION.md` V-27 |
| 21 | 迁移 / schema / 约束 | `.../Z21-migrations-schema-integrity.md` | 进行中 |
| 22 | `audit5` 红探针逐条归因 | `.../22-audit5-red-reconciliation.md` | 已由主代理核对 |
| — | 主代理独立复核日志（V-01…V-25、N-01…N-04） | `.../00-MAIN-VERIFICATION.md` | — |

---

## 2. 我亲自重跑并确认的第六轮阻断项（**全部仍为红**）

命令：`go test -tags audit6 -count=1 -v ./internal/zzprobe/audit6/<区>/`（本机实跑，输出见 §2 各条）。

| 编号 | 一句话 | 我实测的探针 | 状态 |
|---|---|---|---|
| **G-1** | refresh token 重放被检测到后，**小偷那一代仍然有效**（无 token family 撤销） | `z02/refresh_test.go::TestZ02RefreshReplayDoesNotRevokeTheThiefsGeneration` 红 | CONFIRMED |
| **G-2** | Postgres 的 refresh 读路径（`postgres/oidc.go:430-436`）**没有 `expires_at` 谓词**，30 天 TTL 只由 15 分钟一轮的 sweep 执行 | 读码确证 + `z04` 红 | CONFIRMED |
| **G-3** | 数据库无法应答时 `RevokeToken` 把「查不了」当「不存在」，RFC 7009 撤销**答 200 且无审计** | `z04/revocation_error_probe_test.go` 红 | CONFIRMED |
| **G-4** | `prompt=login` 与 `max_age` 被完全忽略，id_token 带**旧会话的 auth_time** | `z02/idtoken_test.go`、`z01/consent_face_test.go` 红 | CONFIRMED |
| **G-5** | percent 编码的 `client_id`（`Basic z02-d%65vice-…`）绕过「内省必须机密客户端」守卫 | `z02/introspect_test.go:122` 红 | CONFIRMED |
| **G-6** | 匿名者可冒**机密客户端**身份发起设备流；**根因已由我更正**（见 §3.1） | `z01/device_flow_test.go` 红 | CONFIRMED |
| **G-7** | 已批准的 device_code 过了 `expires_at` **仍能铸出整套令牌**（两后端消费谓词都无期限） | `z01`、`z04`、`z05` 红 | CONFIRMED |
| **G-8** | `/oauth/revoke` 是**存活性预言机**（他人的活令牌 401 vs 未知串 200） | `z02/revoke_test.go` 红 | CONFIRMED |
| **G-9** | 刷新后的 id_token **丢掉 nonce**（OIDC Core §12.2） | `z01/regress_test.go` 红 | CONFIRMED |
| **G-10** | 设备授予拒绝 discovery 广告的 `client_secret_post`，且被拒的那次 401 **把 device_code 烧掉** | `z01`、`z02` 红 | CONFIRMED |
| **G-12** | 关停栈 **5s + 30s + 30s = 65s > grace 45s** ⇒ 审计排空预算在 k8s 里跑不完，批次静默丢失 | `z04/drain_budget_probe_test.go` 红 + 我逐行核过（§3.2） | CONFIRMED |
| **G-13** | `GetRefreshTokenInfo` 把数据库错误折叠成 `op.ErrInvalidRefreshToken` | `z04` 红 | CONFIRMED |

**G-11**（`/readyz` 冷启动 fail-open）与 **G-24**（`/.well-known/oauth-protected-resource` 对非 GET 答 404、
405 不带 `Allow`）亦红，但我在 §4.2 按出厂清单把 G-11 维持 P3。
`TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` 的红是**夹具桩假象**（夹具把 `Config.OIDC` 换成永远答 200 的桩），
第六轮已自证，**不进清单**。

### 2.1 `audit5` 红探针的归因（此前无人做）

`go test -tags audit5 -count=1 ./internal/zzprobe/...` 在 HEAD 上有 **19 个红探针函数**。
主代理委派专门子代理逐条归因（报告：`.../22-audit5-red-reconciliation.md`）：

| 类别 | 计数 | 说明 |
|---|---|---|
| KNOWN-OPEN | 16 | 全部映射到既有编号：k1/k6（7 处身份进 slog）、FO-03、FO-04、FO-05、KIT-2/4/5/6/7/8/9/10、RP-5/6/7/8 |
| DECIDED-NONGOAL | 3 | FO-02 与两条 startup 探针（断言的是 P1-4 修复前的旧缺陷） |
| REGRESSION | 0 | — |
| UNCLASSIFIED | 0 | — |

**结论**：第五轮的这些洞**没有在 35 个修复提交里被顺手修掉**，而它们**不进 CI**（见 §4.1），
所以「红了一年也没人发现」是结构性的。

---

## 3. 主代理亲自完成的技术机制更正与复核

### 3.1 `G-6` 成立，但第六轮的根因写错了（**修法位置因此不同**）

第六轮把「匿名者能冒机密客户端发起设备流」归因于本项目的
`AuthorizeClientIDSecret` 对空 secret 不求值。**实际根因在库里**：

- `zitadel/oidc v3.51.3 pkg/op/client.go:155-194` `ClientIDFromRequest` 返回 `(clientID, authenticated, err)`：
  Basic 成功 ⇒ `true`；**没有 Basic 头**时回退到表单里的**未认证** `client_id` 并返回 `false`。
- `pkg/op/device.go:138` 把它**丢弃**：`clientID, _, err := ClientIDFromRequest(r, o)`。
- 所以 `POST /oauth/device_authorization` 对**任何**（含机密）客户端都不要求认证；
  本项目的 `AuthorizeClientIDSecret`（`memory/oidc.go:731-743`）**根本不在这条路径上**。
- **修法必须落在本项目边界**（`internal/oidchttp`），不能靠改 store 回调。

**对照**：设备**轮询**端点反而是对的——`pkg/op/device.go:217,235` 用
`clientAuthenticated != IsConfidentialType(client)` 强制机密客户端认证。这也解释了 G-10
（轮询只认 Basic/JWT assertion，不认 `client_secret_post`）。

### 3.2 `G-12` 的调用链与算术（逐行核过）

`main.go:724` → `serveUntilSignal(shutdownTimeout=30s(:127), endpointRemovalWait=5s(:137))`
→ `beginDrain()`(:820) → `time.Sleep(5s)`(:829) → `Shutdown(...)`(:837-849)；
审计排空发生在**之后**：`store.close()` 是 `main.go:377` 的 **deferred**，它才调用
`auditBatcher.Close`（预算 `auditbatch.go:54` `auditDrainTimeout = 30s`）。
`deployment.yaml:26` grace = 45s，而 `:21-25` 的注释只算 HTTP 那一段（写「35s total」）；
`CHANGELOG.md:108-109` 同样写「≥35s」。**最坏 65s > 45s**。

### 3.3 `G-11` 的可达性裁定（与区域 22 的 `22-1` 是同一条代码路径）

`internal/httpapi/health.go:111-118` 在 `c.running` 为真时返回 `c.err`；
`c.checked == false`（**从未产生结论**）时 `c.err` 是零值 `nil` ⇒ `200 ok`。
区域 22 用确定性探针证明了它（对照：真正跑检查的那次拿 503）。**我按出厂清单裁定**：
`deployment.yaml:86-100` 有 `startupProbe`（打 `/healthz`），**k8s 在 startupProbe 成功前不跑 readinessProbe**，
且探测串行、间隔 5s、单次检查 ≤2s ⇒ **kubelet 撞不到**。故维持 **P3**；
若 `/readyz` 有并发消费者（外部 LB/健康检查）则升 P2。修法：无结论时 **fail-closed**。

---

## 4. 系统性问题（本轮新增，且解释了上面为什么能长期存在）

### 4.1 N-04 全部安全探针（**184 个文件**）不在 CI 里

`ci.yml` 全文 **0 处 `-tags`**；主测试是 `go test -race -p 1 -covermode=atomic ./...`（`:158-162`）。
而被标签排除的探针有 **`audit5` 101 个文件 + `audit6`/`audit7` 83 个**（占非测试源码 475 文件的量级）。
后果：19 条 `audit5` 红探针无人归因；第六轮约 45 条红探针不阻断任何合并；
**「修好了」与「修回去了」在 CI 眼里是同一件事**。
→ 建议新增一个作业跑已知绿集合；红的要么修、要么 `t.Skip` 并写明编号，别靠标签藏起来。**P2。**

### 4.2 N-01 两个后端的 sweep 都用**假的**不变量为自己开脱

`postgres/sweep.go:10-13` 与 `memory/oidc.go:935-944` 都声称「lookup 到点即拒，所以按期限删行安全」。
**反例**：Postgres 的 refresh 读路径（G-2）、两个后端的设备消费路径（G-7）、
两个后端的 auth-request by-ID 读路径（**Z07-1**）都**不判期限**。
删除方向本身仍安全（删比读更严）；不安全的是被它掩盖的读路径。**P2。**

### 4.3 N-02 刷新路径的「数据库故障」被**无条件**折叠成 `400 invalid_grant`，且**在 store 层修不掉**

两个后端都把任何错误塌成一个泛化错误（`postgres/oidc.go:434-436`、`memory/oidc.go:574`），
而库 `pkg/op/token_refresh.go:144-152` **无条件** `oidc.ErrInvalidGrant()`。
于是在 Postgres 抖动期间，**合法**的 refresh token 对客户端表现为「已失效」，
客户端按最佳实践**丢弃令牌并强制重登**。与 G-13 同根但**可修性不同**（撤销路径上库会检查
`errors.Is(err, ErrInvalidRefreshToken)`，刷新路径不会）⇒ 修法与归因必须分开写。**P2。**

### 4.4 N-03 第五轮 P2-1 的修复漏了公开引擎

OP store 在 P2-1 之后**会打日志**（`postgres/oidc.go:129-140`、`memory/oidc.go:323-334`），
而 `oauth/as.go:338-346` 仍是 `_ = s.audit.Record(...)`（**无日志、无指标**）。
该引擎服务 **Upstream Kit**（第三方数据源进程），`cmd/re0auth` 不跑它（已 grep 确认）。
**P3**（对 Re0Auth 上线无阻断，对 Kit 使用者是审计完整性缺口）。

### 4.5 22-2 一条**结构上不可能失败**的假守卫

`internal/zzprobe/federation/raw_test.go:284-317`（`TestProbeRegistryAcceptsPathEscapingNames`）
循环里只有 `t.Logf`，**没有任何断言**；HEAD 运行它 **PASS**，却打印出 `game="../.."`、NUL、换行等全部 `ACCEPTED`。
它被 `docs/audit-5/findings/federation.md:209-210` 当作 FO-04 的证据并列引用
⇒ **FO-04 的 path-escaping 半边在 HEAD 实际上没有守卫**。**P3。**

---

## 5. 第七轮区域发现（新洞）

> 严重度为**区域报告自评**；独立复核代理的裁定随后并入（`<区号>-VERIFIED.md`）。
> `HYPOTHESIS` 一律注明「差什么」。

### 5.1 区 07：会话 / 账号 / 身份 / 抹除（9 条）

| ID | 严重度 | 一句话 | 状态 |
|---|---|---|---|
| **Z07-1** | P2 | `oidc_auth_requests` 的 **by-ID 读/决策路径两个后端都不裁决 TTL**，只有 15 分钟 sweep；过期 90 分钟的同意句柄仍可批准并铸出真实授权码 | CONFIRMED |
| **Z07-2** | **P1** | 抹除链最后一步（销毁假名密钥）失败时，审计里**唯一**那条记录谎报 `outcome=ok` 且 `pseudonym_destroyed=true`，而 500 的文案却承诺「审计记录了失败的那一步」 | CONFIRMED |
| Z07-3 | — | 设备验证页把调用方可控的 `user_code` 拼写绑进浏览器会话，单会话可被灌 ~540KB（上限 32 份） | CONFIRMED |
| Z07-4 | — | CSRF 令牌创建是「后写者赢」竞态：并发首读者拿到服务端不认的令牌 | CONFIRMED |
| Z07-5 | — | 设备决策要求调用方**原样拼写** user_code，而查找是规范化的 ⇒ 同一设备码有两个答案 | CONFIRMED |
| Z07-6 | — | `POST /v1/sessions/sign_out` 把「没有会话」答成 403（CSRF），本平面唯一 | CONFIRMED |
| Z07-7 | — | 账号行已消失、会话仍在：`/v1/sessions/current`、`/v1/account/export` 答 500 而不是丢掉会话 | CONFIRMED |
| Z07-8 | — | link 流程用 `?error=identity_taken` 确认「该外部身份是否已有账号」⇒ 枚举预言机 | CONFIRMED |
| Z07-9 | — | 不可逆的账号抹除**不要求近期重新认证**，而同代码对可逆的管理面写操作要求 | CONFIRMED |

**Z07-1 的价值在于它是 G-2/G-7 的第三个实例**：Postgres 的 `AuthRequestByCode`
（`postgres/oidc.go:220-232`）已被显式修过（注释写「the previous query ignored it」），
而 `AuthRequestByID`（`:207-213`）只有 `WHERE id = $1` —— **只补了 code 路径、漏了 by-ID 路径**。
内存后端同形（`memory/oidc.go:402-410` 不读 `authRequestExpiry`，`AuthRequestByCode` 读）。

### 5.2 区 09：联邦 / 数据面 / 出站（4 条）

| ID | 严重度 | 一句话 | 状态 |
|---|---|---|---|
| **Z09-1** | P2 | `sources[].status` **从不校验**：除字面 `retired` 外任何拼写（`"Retired"`、`"retired "`、`"disabled"`）都被静默当成可服务源，且仍参与**另一个源**的 scope 闸门 | CONFIRMED |
| **Z09-4** | P2 | 上游缓冲预算是**全局先到先得**、且预留发生在收到第一个 body 字节之前 ⇒ **15 个零字节的并发慢读**就能让**其他用户**的满额读全部 503（出厂默认预算下的确定算术） | CONFIRMED |
| Z09-2 | P3 | 归一化读没有「超过上限即拒绝」：4 MiB 的上游体可被**静默截断**后当完整的 200 交回（`json.Valid` 接受尾随空白，故 `18fed92` 为它写的理由不成立） | CONFIRMED |
| Z09-3 | P3 | 已退役的源**仍可被绑定**：`BeginBind`/`CompleteBind` 不检查 `Status`，上游令牌进 vault，而数据面永不使用 | CONFIRMED |

### 5.3 区 10：管理面 / 审计链 / 隐私（9 条）

| ID | 严重度 | 一句话 | 状态 |
|---|---|---|---|
| **Z10-1** | P2 | **跨实例**假名缓存使抹除失效：`Destroy` 只驱逐**本进程**缓存；出厂 `replicas: 2` 下副本 B 仍能按 subject 读出被抹除者的完整审计史并续写旧假名（**反驳第五轮 AUD-5 的降级理由**） | HYPOTHESIS（差真库） |
| **Z10-2** | P2 | 审计链接受**链首之前伪造的未签名行**（NULL 哈希一律计 `Legacy` 并跳过）⇒ 有库写权限者能植入任意条目而 `Verify` 答 `ok` | HYPOTHESIS（差真库） |
| Z10-3 | P2 | = **G-12**（并指出 `CHANGELOG.md:108-109` 的「≥35s」也错） | CONFIRMED |
| Z10-4 | — | Kill Switch 在**没有会话端口**的部署上对 sessions 半边完全沉默：`sessions_revoked: 0` 与「本就没有会话」同形 | — |
| Z10-5 | — | Kill Switch 扫描失败会丢掉已完成摘要（注释与 `docs/admin.md` 承诺「摘要 + 错误」，HTTP 面只给错误） | — |
| Z10-6 | — | P2-22 的修法只覆盖 `GET /v1/admin/audit`；`/verify` 与 `/head` 仍是零记录，而 verify 是**全库扫描** | — |
| Z10-7 | — | 审计读接口可以**没有写侧**地装配成功：P2-22 的两条记录在那种配置下静默变空操作 | — |
| Z10-8 | — | `admin.*` 审计行把 `client_id` 假名化且 `Detail` 无补偿字段 ⇒ 读接口答不出「哪个客户端」 | — |
| Z10-9 | — | `Verify` 不校验链头与最后一行一致：链头指向任何行都不拥有的哈希时仍答 `ok` | — |

---

### 5.4 独立复核后的严重度修正（区域 07 / 09 / 10）

**这是本节最重要的部分：复核把区域报告里的严重度大幅向下修正，避免了清单虚高。**

| 原判 | 复核裁定 | 关键理由 |
|---|---|---|
| **Z07-1** P2 | **CONFIRMED P2** | 独立复现；并补充 PG 侧铁证：`expires_at` 在 Postgres 的**任何 WHERE 里都不出现** |
| **Z07-2** P1 | **CONFIRMED P1** | 独立夹具复现同一红；补充「失败路径连一行 slog 都没有」 |
| Z07-3 P2 | CONFIRMED（机制纠错）P2 | 结果成立并被量化（1 807 500 B），但「上限是 Go 的 ~1MB」错：产品自设 **64 KiB** |
| Z07-4/5/6/7/8/9 | CONFIRMED **P3** | 多条影响机制被更正或降级（Z07-6 前端按 problem code 判定而非 401；Z07-8 必须先能以该身份登录 IdP，影响被夸大） |
| **Z09-1 / Z09-4** P2 | **CONFIRMED P2** | 不升不降；Z09-4 的前提比原报告写的**更宽** |
| Z09-2 / Z09-3 P3 | CONFIRMED **P3** | 维持 |
| **Z10-1** P2 | **DOWNGRADE → P3** | 机制逐字属实，但它是**第五轮 AUD-5 同根因的跨进程稳态形态**，不是新洞；暴露的只是「可关联性」 |
| **Z10-2** P2 | **DOWNGRADE → P3** | 需要与「能删行/改行」同级的库写权限；且迁移 0013 的文档**明写**「迁移前的行按 legacy 计、不假装覆盖」，原报告对文档的引用偏了 |
| **Z10-3** P2 | **NOT-A-FINDING（重报 G-12）** | 与第六轮 G-12 逐字同一栈、同一探针形状；且**不存在**「G-12 修复」，其建议第 11 条从未实施 |
| Z10-4…Z10-9 | CONFIRMED **P3** | Z10-9「链头被伪造」正是外部锚点存在的理由（`auditchain.go:333-336` 自己写着），比原报告更弱 |

### 5.5 区 08：前端与浏览器平面（**复核后仅 2 条成立**，其余为重报或降级）

| ID | 原判 | 复核裁定 | 依据 |
|---|---|---|---|
| ~~Z08-1~~ | P3 | **NOT-A-FINDING（重报）** | 第五轮 `A-FE-9` 的复核发现 **V-2** 已把"缺失散列资产回 200 shell 而非 404"钉成性质（连监控/告警假设的后果都写了）；原报告自称"与既有编号无关"不成立 |
| ~~Z08-2~~ | P3 | **NOT-A-FINDING（重报）** | `A-FE-1` 第五轮已判「低」（shell 无 ETag/Last-Modified 属实，仅残余在违规中介） |
| ~~Z08-3~~ | P3 | **DOWNGRADED（核心重报 + 事实错误）** | 核心（`_app/version.json` 无缓存指令）**重报 V-4**；且"构建产物无 `version.json` 引用"是**错的**（见 `Z08V-2`），只剩 favicon 卫生 |
| ~~Z08-4~~ | P3 | **NOT-A-FINDING（重报）** | `A-FE-2` 已复现"206 半截 shell"并降为**提示**；本条是同根因的交叉点 |
| ~~Z08-5~~ | ~~P2~~ | **DOWNGRADED → P3** | 机制 CONFIRMED（复核独立复现），但**纯共享缓存效率**、需要项目自身不拥有的 CDN/nginx 前提、**安全影响为零** |
| ~~Z08-6~~ | P3 | **NOT-A-FINDING（重报）** | `A-FE-3` + 复核 `V-1` 已完整覆盖 `scopeViews` 静默丢弃与设备流第二份实现；唯一新内容是一个原报告自己承认**不可达**的人造配置 |
| **Z08-7** | P3 | **CONFIRMED P3** | 机制与"消耗设备码"后果经独立读码确认；且 `openapi.yaml:2300-2302` 的 `enum` 与之矛盾 |
| **Z08-8** | P3 | **CONFIRMED P3** | 用**独立脚本 + 真 Chromium**复现：文本转义、`img`=0、`window` 标志为 null，**且探测器有阳性对照**（同一载荷在 `data:` 页里 flag=1） |
| **Z08V-1** | — | **新发现 P3（报告质量）** | 原报告「探过没破」第 20 条的"开放重定向面"是**假守卫**：内存模式下该请求回 404/401，**永远到不了任何重定向 sink** |
| **Z08V-2** | — | **新发现 P3（报告质量）** | `Z08-3` 用来收窄影响的代码事实是错的：构建产物**确实**带着 `version.json` 轮询代码（方向是**低估**） |

> **这是本轮对抗性复核最有价值的一次纠正**：一个看起来"8 条发现"的区域，
> 复核后**4 条判为重报、3 条降级、只有 2 条成立**，且新增的 2 条是**关于报告质量**的。
> 如果不做这一步，报告会带着 6 条**已经在前几轮记录过（并已被降级或定义为性质）**的条目，
> 以及 1 条被高估了一档的 P2。**这也是"不许重报"必须在复核环节真正执行、而不是只在简报里写一遍**的实证。

### 5.6 复核过程中新发现的条目（区域报告漏掉）

| ID | 严重度 | 一句话 |
|---|---|---|
| **Z09V-1** | **P2** | 共享的 **per-host 熔断器**把「一个账号的凭据坏了」当成「源坏了」：5 次 401 读就能让**其他账号**在 30s 内读不到该源（`circuitbreaker.go:122` 以 host 为键，`401` 计入 host 失败——第五轮 P1-3 有意加入，却未记录这一后果） |
| **Z09V-2** | P3 | `refreshRejected` 把「存储读不出来」当成「版本没动」⇒ 一次读故障 + 一次 `invalid_grant` 就撕掉一份**可能仍有效**的绑定 |
| **Z09V-3** | P3 | `Issuer = "//evil.example"` 时 `/bind` 302 到**另一个 origin**（`NewRegistry` 对 `Issuer` 只查非空） |
| **Z10V-1** | P3 | Kill Switch 的失败路径审计行**漏记 `sessions_revoked`**（原报告恰好写成反的） |
| **Z10V-2** | P3 | 内部监听器的排空**没有自己的预算**：排在公网监听器之后共享同一个 30s `drainCtx` |
| **NF-Z07-1** | P3 | `/bind` 归属守卫是**单侧**的：探针只证明「B 被拒」，无法区分「B 被拒」与「所有人被拒」 |

---

### 5.7 区 13：部署 / CI / 供应链（7 条报告 + 2 条复核新增，**含一条 P1 灾难恢复**）

| ID | 严重度 | 复核裁定与一句话 |
|---|---|---|
| **Z13V-2** | **P1（复核新增）** | **`scripts/restore.sh` 在自身 `set -euo pipefail` 下无法执行 ⇒ 文档化的唯一恢复路径 100% 死**。`scripts/restore.sh:29` 的 `local file="$1" sidecar="$file.sha256" want got`：bash 在**执行 `local` 之前**展开全部右值，`set -u` 下 ⇒ `line 29: file: unbound variable`、exit 1，**永远到不了 `:30` 的边车校验**。用真 bash（5.3.9，含 `env -i`）实测确认，并用"拆成两条 `local`"的临时副本证明可通（三条守卫随后全部按预期拒绝）。**第五轮 `P2-11` 的修复从未真正被执行过**（那一轮的复核跑的是修复**前**的版本）⇒ **备份再正确也恢复不了** |
| **Z13V-1** | **P2（复核新增）** | **`.dockerignore` 只覆盖了 `.gitignore` 的一部分**：`.gitignore` 有 `/scratchpad/`、`go.work`、`*.local.toml`、`*.out`、`bench.txt`，而 `.dockerignore` **对这些一个 pattern 都没有**（唯一相关的是根级 `.env`，工作区里的文件叫 `keys.env`）。⇒ **被 git 忽略的本地状态整面进入构建上下文**；`Dockerfile:42 COPY . .` 把它带进 backend 阶段层，远程/云 builder 还会**整体上传 context**。复核实测工作区 `scratchpad/` = 112 文件 / 68.34 MB，其中 `scratchpad/audit7/z08v/keys.env`（UTF-16LE；**该文件已在事后工作区清理中删除**）**含 `RE0AUTH_KEK=<32B base64>` 与 PEM 私钥**（探针产物、非生产密钥，但机制对任何 `*.local.toml`/`go.work` 同样成立）。**`Z13-1` 只报了 `./backups`，实际漏掉的是整个被忽略的本地状态面** |
| **Z13-1** | **P2** | **CONFIRMED** —— 复跑 `git check-ignore`：`backups/*.dump`、`*.env`、`*.age` **全 exit 1**（未被忽略）。触发面是"**裸跑脚本**"（文档化调用都显式传 `/backups`） |
| **Z13-3** | **P2** | **CONFIRMED** —— 运行阶段确无 npm 清单；`Makefile:207-208` 自述"ships inside every binary, archive **and image**"。第五轮 `P2-21` 的**归档半边已修、镜像半边未修** ⇒ 补充成立 |
| **Z13-4** | **P3（umask 半）/ P2（age 半，复核升级）** | 复核**实跑**：`BACKUP_AGE_RECIPIENT` 已设而 `age` 缺失时 exit 1，**`re0auth-keys-*.env` 明文残留**（含 KEK/TOKEN/SIGNING），而 `backup.sh` 同样条件下不留 `.dump` ⇒ age 半与 `P2-14` 同形。**权限位复核拒绝采信**（本机 Git Bash 是 `noacl` 挂载，任何权限位读数都无效）——原报告没把它们当证据是对的 |
| Z13-2 | P3 | **CONFIRMED**（不要升）—— `push` 确在 scan 之前，但 `deployment.yaml:44` 已钉 `v0.0.0-rc.3`、metadata 不再产 `latest` ⇒ `P2-12` 的放大项已消失，残余只是"可拉取的 tag"，且失败不静默 |
| Z13-5 | P3 | **CONFIRMED** —— 独立复现：job 级 `packages: write` **PASS**（门禁只看 workflow 级）。**更强的证据**：仓库里已有一个**真实的** job 级写权限 `codeql.yml:19-22 security-events: write`，门禁从未看见它 ⇒ 它**区分不了合法与越权** |
| Z13-6 | P3 | **CONFIRMED，与 `Z16-4` 重叠（建议合并）** —— 复核补上了原探针缺失的**阳性对照**（改名 `npm-attribution` → 门禁 FAIL；把输出名改成 `../dist/...` → 仍 PASS）。同守卫、同根因（整文件 grep） |
| Z13-7 | P3 | **CONFIRMED** —— `README.md:126-132` 未提 npm 清单、`:160` 仍写"只带二进制与 CA 证书"，而 `Dockerfile:74` 已 COPY LICENSE/NOTICE |

> **区 13 的复核价值**：它新增了本轮**唯一的 P1 运维阻断项**（`Z13V-2`：恢复脚本从未能跑），
> 并把 `Z13-4` 的 age 半**从 P3 升到 P2**（实跑证明明文密钥会残留），
> 还给出了 `Z13-5` 门禁失效的**真实反例**（`codeql.yml` 的 job 级写权限）。
> 同时它**拒绝采信**本机不可靠的权限位证据——这正是"读不到就说不成立"的正面示范。

---

### 5.8 区 14：Upstream Kit / RP 侧 / TapTap（6 条）

| ID | 严重度 | 一句话 |
|---|---|---|
| **Z14-1** | **P2** | 级联撤销失败后 refresh token **已被消费**，Re0Auth 的"重试"永远打不到上游（状态不可恢复；报 500 非静默） |
| **Z14-2** | **P2** | 一致性套件对 `/oauth/revoke` 的**认证零断言** ⇒ 「谁都能吊销」的数据源被判 compliant（可执行规范出现**假 PASS**；对 KIT-7 修复的补充） |
| **Z14-3** | **P2** | `jwks_uri` **不与 issuer 绑定**：能左右 discovery 响应的一方让 RP 信任自己的签名密钥，从而伪造任意 `sub`（对 RP-3 修复的补充） |
| **Z14-4** | **P2** | provider 缓存的 TTL 在 discovery 失败时**失效**：退役密钥在故障期间**无限期**验签成功（把 15 分钟窗口变成"故障持续多久"；对 RP-2 修复的补充/反驳） |
| Z14-5 | P3 | 只配 `auth_url`（未配 `token_url`）时显式端点被**静默丢弃** |
| Z14-6 | P3 | 参考数据源的 TapTap 登录完成**不绑定浏览器**：加载 poll URL 即可以攻击者身份登录（会话固定；`referencesource` 不入发布产物，故 P3） |
| **Z14-V1** | **P3（复核新增）** | **一致性套件用「目标 origin」而非「文档广告的端点」做判据**：`checkRevocationEndpoint` 完全忽略 `disc.OAuth.RevocationEndpoint`（硬编码 `{target}/oauth/revoke`，且**连是不是 URL 都不校验**）；`checkCascadeEndpoint` 只取广告 URL 的 path+query 再拼回 `r.base`（**丢弃 origin**）⇒ **合规的多主机数据源被误判不合规**，反向可让「广告在别处、实际匿名可结束全会话」的级联端点**零 error 通过**——而 Re0Auth 恰恰只打广告的那个 URL。复核探针 3 红 3 绿（含阳性对照） |

---

### 5.9 区 15：性能 / 容量 / 内存（4 条）

| ID | 严重度 | 一句话 |
|---|---|---|
| **Z15-1** | **P2** | 过期清扫**没有「每轮有界推进」**：十条 `DELETE` 全无 `LIMIT` 且在**同一事务**里，只能「全删或全不删」；撞上 30s 语句超时后**每个 tick 重试同一份越积越大的工作**，失败只落 Warn 且**无指标**（`rules.yml` 里零个 sweep 序列） |
| Z15-2 | P3 | `BenchmarkTokenLifecycleWithJanitor` 的守卫在固定迭代数下**不可达**：报 `peak_records=0` 且 **exit 0** |

> **复核对 §5.9 的两处更正（已并入上表）**：
> ① `Z15-1` 的**阳性对照是错的**——报告拿内存后端当"逐条删除 ⇒ 天然有界推进"的对照，
> 而复核的独立探针证明**一次** `SweepExpired()` 就把整个过期总体删完并持全局锁（`1000→0`、`100000→0`）
> ⇒ **两个后端在同一不变量上同样违规**（即第五轮 PERF-5），该对照不成立；另请注意报告的修法
> 「每表一个事务」**推翻了 `sweep.go:42-45` 的文档化决定**，这部分应当写成**判断**而不是 finding。
> ② `Z15-2` 的原始归因写错了工具：用 `-benchtime=200x` 的是 **CI 自己**（`ci.yml:394-405`），
> 不是 `cmd/perfreport`；而 CI 的门禁只数 `ns/op` 行数、**从不读 `peak_records`**
> ⇒ 「绿 CI 上印着 0 的容量界」比原报告所述**更确凿**。
>
> **区 14 的复核结论**：`Z14-1`…`Z14-4` **全部 CONFIRMED、P2 维持**。其中 `Z14-3`（`jwks_uri` 未钉）
> 的复核补充了一个要紧事实：修复提交 `60de35d` 的 message **明写**「JWKS 没有覆盖旋钮，所以只钉这两个端点」
> —— 即该缺口是**有意缩小范围**，但它**不在**简报的"有意不做"清单里，且第五轮 `_fragment_rp.md:139-141`
> 的修法建议本来就点名了 `jwks_uri` ⇒ 应把它作为**判断：这个 scope-out 应当收回**。
| Z15-3 | P3 | 内存 store 的 `DeleteAuthRequest` 在**全局锁**下遍历**全部待兑换 code**，而 Postgres 走 `oidc_codes(request_id)` 索引定向删除 ⇒ 同一协议操作两后端复杂度不同，且它在**授权码兑换路径**上（仅内存后端；ADR-0006 决策 6 不为其提供生产保证） |
| Z15-4 | P3 | `negotiate` 快速路径对每个已配置 coding **重新 `strings.Split` 一次头部**：出厂 `[zstd, gzip]` 下最常见的 `Accept-Encoding: gzip` 每次请求白付一次切分 |

---

### 5.10 区 16：守卫与测试质量（7 条，全部是"门禁看起来在、其实不会响"）

| ID | 严重度 | 一句话 |
|---|---|---|
| **Z16-1** | **P2** | CI 的 `load` 门禁在**"什么都没测"**时仍然绿：**没有任何一步读它的输出** |
| **Z16-2** | **P2** | `gosec` 的 `includes` 是**白名单**（只开 `G304/G401/G402/G404/G501`）⇒ 其余 gosec 规则**从不运行**。其中**`G104`（未处理的错误）**正是本轮反复发现的形状（`_ = …Record(...)`、`err == nil` 落穿、err 只记日志不返回），而**`G107`（URL 来自可变输入）**对应 SSRF/URL 一族 ⇒ **这两条最该开的恰恰被关掉了**（理由本身合理，但选法不对：应加回并用具名 `//nolint` 处理已知误报） |
| **Z16-3** | **P2** | **101 个被跟踪**（含第六轮共 **162 个**）探针文件在任何 CI 门禁之外——**从不被编译 / vet / lint**。这是对 **N-04** 的重要加强：`//go:build auditN` 文件在默认标签下**整个文件被排除出构建**，所以其中的**类型错误从不被发现**（语法/编码错误仍会暴露——Go 为了取 import 会词法扫描整个文件，我开工时那次「非法 UTF-8 打断整仓构建」正是这条路）。**探针可以烂到调用不存在的函数而 CI 全绿。** |
| Z16-4 | P3 | `internal/archtest` 的 Makefile 守卫是整文件 `strings.Contains`：**注释即可满足** |
| Z16-5 | P3 | `ci.yml` 的 fuzz 目标清单靠**手维护**，没有任何守卫保证它完整 |
| Z16-6 | P3 | 又三条"算出结论只打印"的探针（同族新实例，含一条可被假期望骗过） |
| Z16-7 | P3（复核升为 **CONFIRMED** 源级） | 覆盖率 floor 是**全仓一个总数**，它自述要防的"某包烂到 0"**不在其覆盖内** |

> **为什么这一区值得单列**：项目自己的方法论是「一条发现必须有一条会失败的测试才算数」，
> 而这些门禁**结构上不会失败**。Z16-1/2/3 三条 P2 合起来意味着：
> **「测试全绿」这个信号目前无法区分「都通过了」与「根本没跑/没查」。**

---

### 5.11 区 12：配置 / 启动 / 可观测性（9 条，含本轮新 P1）

| ID | 严重度 | 一句话 |
|---|---|---|
| **Z12-3** | **P1** | **首个 seed 之后 `[client]` 的任何改动都被静默忽略** —— 认证边界上的 fail-closed 缺口（改了配置、重启、以为生效，实际仍是旧值） |
| **Z12-1** | **P2** | 缺 `id:` 前缀的 `RE0AUTH_OIDC_RETIRED_TOKEN_KEYS` 把**密钥原文打进启动日志**（凭据封存失败） |
| **Z12-2** | **P2** | `-rotate-keys` 扫到 **0 条**时退 **0**，恰好满足文档写下的放行闸门（"等它报 `rewrapped=0` 再删退役键"变成空转） |
| **Z12-4** | **P2** | 文件里配的列表**无法被环境清空**（`RE0AUTH_ADMIN_SUBJECTS=""` ≠ 无人） |
| **Z12-6** | **P2** | 非有限 `rate_limit` 被接受：`internal/config/config.go:103` 的 `strconv.ParseFloat` 接受 `NaN`/`Inf`，而 `cmd/re0auth/config.go:512-522` 的 `< 0` / `== 0` 与 `main.go:225` 的 `<= 0` **在 NaN 下全为 false** ⇒ 校验全部落空、限流器照装。**`+Inf` 是最干净的一例**（等于库的 `rate.Inf`，语义就是"永远允许"）；`NaN` 则落入库内部算术的未指定行为 |
| ~~**Z12-7**~~ | ~~P2~~ → **与 `Z11-1` 重复（按 P1 计）** | 复核用独立探针量化：**单次**挂断只污染一个 TTL 窗口（`[503 503 503 200 200 200]`，自愈）；但**持续**挂断（~4/s）让每次 kubelet 形状的探测都拿 503（`[503 503 503]`）⇒ 按清单 `periodSeconds: 5 / failureThreshold: 3`，**一个匿名单机连接循环约 15 秒就能把健康副本摘出流量**。机制与 `Z11-1` 同行（`health.go:122`），故按**一条**计 |
| **Z12-9** | **P2** | 文件里的池大小被**截断到 int32**，而环境变量路径**拒绝**越界值 ⇒ 两条配置路径语义不一致 |
| Z12-5 | P3 | `-migrate-down` 先跑整套 serving 期校验，缺审计链密钥就**无法回滚**（恢复路径被自己的校验挡住） |
| Z12-8 | P3 | **位置参数从不检查**：漏掉横线的 flag 被静默忽略 |
| **Z12V-1** | **P3（复核新增；爆炸半径接近 P2）** | **KEK 的解析不遵循文件声明的变量名**：`cmd/re0auth/config.go:721-731` **硬编码 `os.Getenv("RE0AUTH_KEK")` 优先**，只有它为空才读 `vault.kek_env` —— 与全文件用了几十次的 `FirstNonEmpty(env, file)` **顺序相反**。而 `docs/operations.md:138-139` **明写**"`vault.kek_env` 可以改名，**不要假定叫 `RE0AUTH_KEK`**"，且 `-print-secret-env`/`backup-keys.sh` 都按文件读名 ⇒ **两者不一致**。**事故形状**：按文档改名轮换（`kek_env = "RE0AUTH_KEK_2"` + 新 `kek_id`）而编排器仍注入旧名 ⇒ 进程以**旧密钥 + 新 kek_id** 启动、**日志无任何提示**；第一次写入看似成功，之后每次解封都 `authentication failed`**（全账号绑定不可读，只能从备份恢复）** |
| Z12V-3 | P3（复核新增） | `envInt32` 的越界报文**自称"不是整数"**：`cmd/re0auth/config.go:1121-1123` 对 `strconv.ParseInt` 的任何错误统一回 `%s %q is not an integer`，于是 `RE0AUTH_STORAGE_MAX_CONNS=4294967297` 报"不是整数"——**它是整数、只是超出 int32** ⇒ 报文把运维引向"哪里写了非数字"，而真问题是量级/字段类型（同文件 `resolvePool` 的注释说"validate rather than clamp"，而事实是 clamp） |

> **这一区对本轮结论的影响**：`Z12-3`（P1）与 `Z12-6`（`rate_limit=NaN` ⇒ 放行一切）、`Z12-7`
> 合起来说明**配置面本身有独立的 fail-closed 缺口**，而且它们的失败形态都是**静默**的——
> 与 §4 的系统性问题同源。

---

### 5.12 区 11：韧性 / 限流 / 并发 / DoS（6 条报告 + 1 条复核新增；**本区最重**）

| ID | 严重度 | 复核裁定与一句话 |
|---|---|---|
| **Z11-4** | **P1** | **CONFIRMED** —— 桶表可被**单个 IPv6 /64** 填满，之后**所有**新客户端共用兜底桶并被 429（fail-closed 被转成对他人的 DoS）。复核用**真中间件链**独立复现 429（阳性对照 401）⇒ 是对 P0-4/CM-V1 修复的补充 |
| **Z11-5** | **P1** | **CONFIRMED** —— 全进程一个并发信号量。**复核的定性很要紧**：「**无按调用方分摊**」本身是 **`docs/operations-decision.md:40` 的文档化裁定**；本条的新意只在校准后果——**一个地址可饿死所有人，而探针仍全绿** |
| **Z11-1** | **P1** | **CONFIRMED** —— 匿名单机把健康副本的 `/readyz` 打成 503。复核实测**可达性比报告更强**（1 ms 依赖 8/8 命中、瞬时依赖 5/8）。**与 `Z12-7` 同机制、同代码路径（`health.go:122`）⇒ 按一条计**，见 §5.15 |
| **Z11-2** | **P2** | **CONFIRMED（源级）** —— 预算在 `rawFetch` 返回时 release，body 直到 `federation_routes.go:141`/`:297` 的 `w.Write` 才被消费 ⇒ 约束的是**读相**而非**持有相**。**复核更正**：原探针"body 被持有"的**前提在本机不成立**，所以它没证明它声称的东西（源级机制仍成立，与我的 V-29 一致）。**与 `Z09-4` 合看**：P0-3 把"无界"改成"有界且会 shed"，`Z09-4` 指出该界**没有分摊**，本条指出它**挂在错误的区间上** ⇒ 三者应作为**一次**重新推导 `MaxBufferedBytes` 的工作项 |
| **Z11-3** | **P2** | **CONFIRMED** —— 调用方写的 `X-Request-Id` 无长度/字符集上限，被原样回显进响应头并写进访问日志（复跑 `echoed=60000 logged=60157`） |
| Z11-6 | P3 | **CONFIRMED**（常量确实与自己的注释相反），**但复核更正**：原报告的**影响句与 Go 标准库不符**（见 `Z11-VERIFIED.md` §三） |
| **Z11-V1** | **P1（复核新增）** | 探针豁免绕过两道上限，**却绕过不了会话中间件** ⇒ **一个匿名 Cookie 就让每次 `/healthz`、`/readyz` 都变成一次连接池往返**。复核实测：带 Cookie 的 20 次 `/readyz`（`Limiter burst=1`、`MaxInFlight=1`，因为探针豁免）**全部 200 且产生 20 次会话存储查询**；而 `readinessCache` 只压住就绪检查那一次往返。⇒ 把 `G-11`/`CS-1` 一族从"每请求一次 Ping"扩到"**任何匿名者都能用 Cookie 按请求数驱动池往返（认证用户的 Cookie 还会因 `IdleTimeout` 触发写）**" |

> 三条 P1 全部 CONFIRMED，其中两条（`Z11-4`/`Z11-5`）是**匿名单机可触发**的跨用户可用性缺陷——
> 按简报"匿名可触发的 DoS"口径**可上调 P0**。复核同时做了两处必要的**降噪**：
> 把 `Z11-1` 与 `Z12-7` 合并（避免双计），并指出 `Z11-5` 的"无分摊"是**既有裁定**、
> 真正的新内容是**后果的校准**。

### 5.13 区 17：文档 / 契约漂移（6 条）

| ID | 严重度 | 一句话 |
|---|---|---|
| ~~**Z17-1**~~ | ~~P2~~ → **P3**（复核降级） | README 快速开始与随仓库交付的配置样例不兼容：照抄即拒绝启动（`config/re0auth.example.toml:316-322` 有未注释的 `[idp.github]`/`[idp.google]`，而 `internal/config/config.go:57-66` 未设即错） |
| Z17-2 | P3 | README 的内存模式片段按原样**无法启动**（两处独立缺项） |
| Z17-3 | P3 | `SECURITY.md` 的 "Our own audits" 一节已过期：轮数与在盘文档都对不上 |
| Z17-4 | P3 | openapi 的 `Binding.token_class` / `Binding.status` 封闭 enum **表示不了 `configured: false`** 这一已文档化状态 |
| Z17-5 | P3 | README 指认的"完整键位"样例**漏掉 8 个**已实现的环境变量覆盖 |
| Z17-6 | P3 | openapi 说 audit 的 `cursor` 是"不透明、非签发即拒"，实现是**普通行号且接受任意正整数** |

### 5.14 区 18：Go 级危险模式全仓扫描（3 条报告 + 4 条复核新增）

| ID | 严重度 | 一句话 |
|---|---|---|
| ~~**Z18-1**~~ | ~~P2~~ → **P3 / NOT-A-FINDING** | `/readyz` 在"首次就绪检查仍在途中"时 fail-open —— **复核判定这是同一问题的第三次报告**（= 第六轮 G-11 + 第七轮 22-1），故不作为独立发现，统一收口在 §5.15 |
| Z18-2 | P3 | `idp` 把互斥锁**跨网络 I/O 持有**：同一 provider 的并发登录被串行化（机制对，**影响面被复核判为夸大**） |
| Z18-3 | P3 | `oauth.MemoryStore` 把存储的 scope 切片**交出去**：改返回值即改活令牌的授权（机制 CONFIRMED，**可利用性 HYPOTHESIS**） |
| Z18v-1 | P3 | 同族的**第二道门**：`ListBySubject` 的 `GrantRecord.Scopes` 也指向存储数组 |
| Z18v-2 | P3 | `idp` 的 provider TTL 在"发现失败"时不再成立 —— **与 `Z14-4` 是两个区域独立命中同一条**（互相加强，不是重报） |
| Z18v-3 | P3 | 被复核夹具使 `/readyz` 的"限流/在途豁免"断言**在结构上不可证** |
| Z18v-4 | P3 | 一条自述"探过没破"的 Bulkhead 绿探针**是空守卫**，不能为它作证 |

> **`Z18v-2` 与 `Z14-4` 的独立重合值得记一笔**：两个互不相干的区域（Go 危险模式扫描 / Kit-RP）
> 用各自的探针撞到**同一条**「discovery 失败 ⇒ 旧 provider 继续服务 ⇒ 退役密钥无限期有效」。
> 按第五轮的方法学，独立重合**提高**该条的置信度，而不是构成重复报告。

### 5.15 综合：`/readyz` 有**四个独立**的失效模式（跨区收敛）

本轮有四个区域从四个方向撞上同一个端点，把它们放在一起看比单看任一条都更重要：

| 方向 | 编号 | 机制 |
|---|---|---|
| **fail-open**（依赖不可达仍报 ready） | **G-11 / 22-1 / Z18-1** | `health.go:111-118` 在 `running` 为真时返回零值 `err=nil`。**三个区域独立报告了同一机制**（第六轮 G-11、区域 22 的 22-1、区域 18 的 Z18-1），复核正式判定后者为**重报** ⇒ 按**一条**处理 |
| **fail-closed 过头**（健康副本被报 not ready） | **Z12-7 / Z11-1** | 探针豁免 + 派生调用方 ctx ⇒ 一个**挂断的匿名连接**就能把缓存写成 503，且原因只在 `slog.Debug` |

⇒ **同一份 `readinessCache` 既能被匿名"打成就绪"、也能被匿名"打成不就绪"**，
而它的唯一消费者是编排器。这是个**设计层面**的结论，而不是两个独立缺陷：
就绪判定需要一个**显式的三态**（未知/就绪/不就绪）与**不派生自调用方 ctx 的检查上下文**。
**建议：把这一条作为上线前的独立工作项**（它同时是 G-11、Z12-7、Z11-1、Z18-1 的正确收口）。

---

### 5.16 区 21：数据库迁移 / schema / 约束完整性（4 条报告 + 2 条复核新增）

| ID | 严重度 | 一句话 |
|---|---|---|
| **Z21-2** | **P2** | **`0013` 的 Down 摧毁审计链的防篡改证据**：一次 Down→Up 往返即拆掉 S5（**注意：是 `0013`，`0014` 的 Down 不碰链**） |
| Z21-1 | P3（复核降级：**机制写错**） | `0010`/`0011` 的 Down 没有 `IF EXISTS` —— 但 goose 的 Down 是**一次一个版本、且与版本行同事务**，**正常路径上不可能把同一段 Down 跑第二遍** ⇒ 只有"版本表与 schema 漂移"才会踩到，属纯加固项 |
| Z21-3 | P3 | 对第六轮 `04-7` 的补充：单事务非并发建索引是**整个索引家族**（**39 个索引 / 21 个迁移 / `CONCURRENTLY` 与 `NO TRANSACTION` 均为 0**），不是 `0022` 一条 |
| Z21-4 | P3 | 设备码 user code 的唯一性在两张设备表上**不对称**：`oidc_devices` 有 `UNIQUE`，`oauth_device_authorizations` 没有 |
| **Z21V-1** | **P3（复核新增）** | `0014` 的 Down 丢掉**全部每账号假名密钥** ⇒ 同一账号的审计历史被静默**劈成两个假名**，此后 `?subject=` 只回**一半** |
| **Z21V-2** | **P3（复核新增）** | 被报告当作"去掉手写清单"的那条守卫**看不见 `04-3` 的那条语句** —— 它自称能自动抓住 `04-3` 是**假的** |

> **复核对 `Z21-2` 的三处更正（也更正了我自己的 V-22）**：
> ① **可达性比报告写的强得多，不是更弱**——`87f4ad9` 之后新建的库**根本没有版本 5 这一行**
> （Up 应用 1,2,3,4,6…22），对它 `-migrate-down` 一路可用，**而即将上线的首次部署正是这种库**；
> 于是 ADR-0008 §4 那条**成文运维动作**（重复执行 `-migrate-down`）会一路踩到 `0013`。原报告把可达性压在
> "存量库有没有版本 5"上，**方向反了**。
> ② **"不打日志地报 OK"不准确**：`main.go:1090-1094` 在 OK 分支会打
> `slog.Info("audit chain verified", "legacy", N)`，响应也带 `legacy`（`audit_routes.go:57`）。
> 真正静默的是：**没有东西把「0013 之后才上线的库出现 `legacy>0`」当成回归**。
> ③ **严重度不必升**：`0013` 的注释自己就把"清空链元数据 + 链头重置为创世在无外部锚点时不可区分"
> 写成了**文档化边界**；本条的新东西是**触发者**（一次常规回退，而非攻击者）。故 **P2 维持**。

---

> **区 17 复核**：`Z17-1` **由 P2 降为 P3**，理由充分——它是"文档与实现不一致"（简报 §6 明确列为 P3）、
> 无安全影响、fail-closed 生效，代价只是一次排障；且原报告把**同一类**缺陷（`Z17-2`）定为 P3，
> 属内部标准不一致。复核另指出原报告写"与既有编号无关"不准确：第五轮 **CS-5** 已就
> 「照 README 快速开始 `cp` 示例文件会拒绝启动」给出 CONFIRMED 结论，`Z17-1` 是**同一路径上的第二个独立拦路点**
> （IdP secret）、机制是新的、**不构成重报**，但必须写清与 CS-5 相邻。
> **复核新发现 `Z17V-1`**：README 的**参考数据源**快速开始同样照抄即拒绝启动（原报告完全没开这个入口）。

### 5.17 区 19：密钥与敏感数据全生命周期（4 条）

| ID | 严重度 | 一句话 |
|---|---|---|
| **Z19-4** | **P2** | `-rotate-keys` 可以用**「同料不同 id」的新 KEK** 报出一次**成功的轮换**，而被判退役的那把钥匙**仍然能开每一个记录** ⇒ 运维据 `rewrapped=N` + exit 0 删掉退役键（**失败静默**） |
| **Z19-1** | **P2** | `*_env` 约定**无人校验**：把密值粘进变量名时，启动错误把**密值原文打进日志**（配置回显的第二条通道） |
| Z19-2 | P3 | 凭据进 URL：QQ 取用户信息把 access token 放进**查询串**，`net/http` 的 `url.Error` 再把整条 URL 连同 token 交给调用方（当前唯一调用方丢弃该错误，机制成立） |
| Z19-3 | P3 | `vault.Use` 的四条**失败**路径把自己的审计写入丢掉（`_ =`），而同一 sink 上的**成功**路径是 fail-closed |
| **Z19V-1** | **P2（复核新增）** | 与 `Z19-1` **同根**：`internal/config/config.go:57-66` 的 `Secret(envName, field)` 在变量缺失时报 **`%s names %q, which is not set`** —— **回显的是 `envName` 本身**，而 `envName` 来自配置里**未做形状校验**的 `storage.dsn_env`（`cmd/re0auth/config.go:149,686-694`）⇒ **把 DSN 原文（含口令）粘进"名字位"就会把口令打进启动日志** |
| Z19V-2 | P3（复核新增） | `-print-secret-env` 会把"塞进名字位"的值**原样打到 stdout** |

> **区 19 复核结论**：4 条原发现**全部 CONFIRMED、严重度维持**（含 `Z19-4` 的"同料不同 id 轮换静默无效"）。
> 它新增了 `Z19V-1` 这条 P2，使"**启动日志泄露凭据**"这一族从一条变成**两条独立通道**
> （`Z19-1` 的 `*_env` 名字位、`Z19V-1` 的 DSN 缺主机形态），
> 外加 `Z12-1`（`RE0AUTH_OIDC_RETIRED_TOKEN_KEYS` 缺 `id:` 前缀）——
> **三条通道共同说明"启动期解析失败时回显原始输入"是个系统性习惯，而不是三个孤立失误。**

> **`Z19-4` 值得单独一提**：它与第五轮 `P1-1`/`P1-2` 和第六轮 `G-19` 同族（轮换的静默失效），
> 但机制是**新的**——前两条讲的是"写入落在退役键上"与"stale 覆盖"，
> 这条讲的是"**新旧 KEK 密钥材料相同而 id 不同**时，轮换看起来成功但旧钥匙仍然有效"。
> 它的危险在于**它把运维的删除动作变成不可逆的（其实并没有发生的）收口**。

---

### 5.18 区 20：授权隔离矩阵（复核后 2 条 P2 + 4 条 P3，含**一条对前轮结论的反驳成立**）

| ID | 严重度 | 复核裁定与一句话 |
|---|---|---|
| **Z20-1** | **P2** | **CONFIRMED** —— 每一次成功的授权码兑换都写一条 `oidc.consent.deny`（两后端）、字段全空。**复核用逐步隔离证明了时序**（approve/callback 后 `deny=0`，**仅 token 兑换后 +1**），并把库侧唯一调用点钉到 `zitadel/oidc pkg/op/token.go:50`。**关键增量：`git log -S` 证明该 deny 事件此前不存在 ⇒ 这是第五轮 AUD-3（`636a074`）修复时新引入的回归**，不是第六轮重报 |
| **Z20-2** | **P2（条件性）→ 出厂配置下 P3** | **CONFIRMED，但前提要收紧**（两位复核者各自独立得出）：机制成立（两个入口同打 `/resources/scores`），**但只在 `raw_base == issuer` 时**把被扣下的资源交出去；**随仓库交付的示例配置 `config/re0auth.example.toml:363` 把 `raw_base` 设成 `{issuer}/v1`**，此时 raw 路径打的是 `/v1/resources/scores`、**不是**归一化的 `/resources/scores` ⇒ **示例形态下升不到 P2**。另：原报告引的 `config:365` 行号错两位（`363` 才是 `raw_base`） |
| Z20-3 | P3 | **CONFIRMED** —— 设备面同意决策审计不带 scope（内存 `:1104` 无 scopes；**Postgres `:898` 连 `client_id` 都空**，属 G-17 家族） |
| Z20-4 | P3 | **CONFIRMED（反驳成立）** —— `DecideDeviceAuthorization`（内存 `:1397-1402` / Postgres `:1217`）**确实**执行 `RequireExplicitConsent`，且**早于第六轮 HEAD**（`git blame` → `87f4ad91`），生产里 `ApproveDevice` 的唯一调用者就是它 ⇒ **`P-02` 把它当"入口"是错的** |
| ~~Z20-5~~ | — | **两位复核者结论不同，我裁定为 NOT-A-FINDING（但机制真实）**。两位都**独立复现了机制**（未知串 → 200；他人活令牌 → 401 `token was not issued for this client`，且该令牌**未被删**、所有者仍可撤）。分歧只在**新颖性**：一位判定它**已被 `G-8` 覆盖**（`G-8` 自己的探针 `z02/revoke_test.go` 就打在**部署 OP** 上），另一位认为 `G-8` 只记在公开引擎。**我的裁定**：机制已被 `G-8` 的探针覆盖 ⇒ 不作为新发现；**真正要改的是 `G-8` 的影响段把引擎写错了**（应写部署 OP 与公开引擎**两条**） |
| Z20-6 | P3 | **CONFIRMED（反驳成立）** —— 阳性对照：白名单机密客户端得 `active:true/client_id=cli`，同一身份用 `co%6ef` 只得 `{"active":false}` ⇒ 用转义拼写绕过内省守卫后**什么也拿不到**，`P-01` 的影响面确实被夸大（另：`P-01` 正文自称 `:1230` 用解码后的 caller，与源码不符） |
| **Z20V-1** | **P3（复核新增）** | 导出方法 `ApproveDevice`（**两个后端**）**无视 `ExplicitConsent`**：直接调用可放行 critical scope。**今天无路由可达**（`DeviceStore` 缝只暴露 `DecideDeviceAuthorization`）⇒ 属**导出脚枪**，修法是让 `ApproveDevice` 自己 `Resolve + RequireExplicitConsent`，或改非导出 |

> **`Z20-1` 是本轮最值得单独记住的一条**：它是一条**由修复引入的回归**——
> 第五轮为「谁同意了不知道」（AUD-3）加审计事件时，把 `deny` 事件挂在了**成功兑换**的路径上。
> 这正是第二轮至第六轮方法论反复强调、而在实践中极难发现的那一类缺陷：
> **修复本身成为新缺陷的来源**。`git log -S` 是证明它的关键工具。
>
> **探针质量（复核另报，非产品发现）**：被审的
> `TestZ20NormalizedGateRequiresTheScopeOfEveryCandidateSource` 是**空守卫**（只配了 1 个源），
> 复核用**双源**复测证明产品行为其实是正确的（只持任一 → 403；双持 → 200 `source=alpha`），
> 建议把空守卫换成它的双源探针。

> **独立交叉核对（`Z20-INDEPENDENT-CROSSCHECK.md`，21 探针 / 20 绿 1 红）——本区对本轮"探过没破"贡献最大**：
> 它把原报告里**没有命名探针**的矩阵单元格变成了**会失败的东西**，13 个单元格**全部守住**：
> 跨主体数据面读 → 409 且上游零调用（`Z20I-101`）；合法 bearer 打 5 个会话面路由全 401（`102`）；
> 一个浏览器切账号不串数据（`103`）；**同意 / 设备 / 刷新三面都无法加宽 scope**（`104/105/106`，
> 且实测换出的令牌 scope 等于授予集）；**管理面 allowlist 精确相等**——6 种近似拼写（空格/大小写/前后缀/百分号）
> 全 404、未登录 401、非管理员 404（`107`）；公开源列表不泄上游 `client_id`/secret/token（`108`）；
> 同名资源异 scope 时闸门要求**每个**候选源的 scope，只有 `?source=` 能收窄（`109`）；
> 换账号后 **consent/设备句柄都回 404**（无存在性预言机）且设备码仍不可兑换（`112/113`）。
> ⇒ **授权隔离矩阵在生产路径上是成立的**——这是本轮"探过没破"里最有分量的正面结论。

---

## 6. 仍然开放的历史条目（上线前应一并收口）

第五轮台账里**至今未关闭**、且有 HEAD 红探针背书的 16 条：

- **k1 / k6**：7 处身份标识进 `slog` attr（`internal/admin/admin.go:499`、`internal/auth/auth.go:231`、
  `internal/federation/bind.go:208`、`refresh.go:155/160`、`internal/httpapi/account_routes.go:80`、
  `binding_routes.go:57`）。与第六轮 G-23 是同一不变量的两半。
- **FO-03**：`IsPublicAddress` 漏 `0.0.0.0/8`（含 `::ffff:0.x`）⇒ 配 `DenyPrivateAddresses` 时
  `http://0.1.2.3/` 仍可拨号（Linux 上该段可能落本机回环，本机 Windows 无法判定其可利用性）。
- **FO-04**：源注册表不校验 `game`/`name`/`Resources[].Scope`；声明的 scope 含空格时，
  `oauth2` 会 join 成**多个** scope 发给上游（静默扩权）。
- **FO-05**：数据面无重试层，而 `docs/source-onboarding.md:225` 对源承诺「指数退避重试」（文档与实现不符）。
- **KIT-2/4/5/6/7/8/9/10**：Upstream Kit 的表单/Basic 身份不一致、失败的兑换也消费授权码、
  `RestoreClient` 不校验 redirect、PKCE challenge 形状不校验、一致性套件从不验证客户端认证、
  无 `Content-Length` 的超限体塌成 400、两份 well-known 无 `Cache-Control`、删 client 留 token 行。
- **RP-5/6/7/8**：RP 侧 discovery 缺 `authorization_endpoint` 时回相对登录 URL、`clearFlow` 在
  provider 比对之前（走错 provider 烧掉待完成登录）、同一 auth request 可重复签码、`flowKeys` 漏了 `flowNonce`。

**注意**：这些多为 P3，且部分被 `docs/**` 记录为取舍；列出是为了让「上线前还剩什么」有单一出处。

---

## 7. 探过但没破的（正面结论，决定上面的问题是局部而不是整体）

- **第六轮修复回归**：`id_token` 的 `sub`（P0-1）、userinfo 只认活 access token（P0-2）、
  重复参数导致 scope 闸门绕过（P0-5）、公开客户端无凭据内省（P0-6）**均已被守住**——
  我重跑对应 `TestRegression*` 全绿。
- **授权码**：redirect_uri 变体、PKCE 语法与方法、码的单次使用与绑定、`request`/`request_uri` 拒绝——全绿。
- **scope 提升**：刷新不能提权、跨客户端刷新被拒、未注册 scope 被拒——全绿。
- **限流默认姿态**：`trusted_proxies` 为空时伪造/轮换 `X-Forwarded-For` 不能换桶。
- **HTTP 边界**：body 上限（含说谎的 `Content-Length`、chunked、gzip）、压缩拒绝与 `Vary`、
  真实进程的头部上限 / 慢头 / 慢体 / `CONNECT` 拒绝——全绿。
- **审计/密码学**（第六轮区域 03/04/05 实跑）：AAD 双向绑定、nonce 无重复、
  `vault.Use` 明文用后归零且审计不可用时 fail-closed、轮换只重写信封三列。
- **Postgres 读码级**：17 处 SQL 拼接全为编译期常量；撤销/单次使用的认领是 `DELETE ... RETURNING` 先删后取。

---

## 8. 未能到达（残余盲区，必须如实写）

1. **一切 Postgres 运行时语义**（无 Docker / 无本地库）：Z10-1、Z10-2、04-7（索引迁移单事务写冻结）、
   以及 G-2/G-3/G-7/G-13/G-14/G-17 的**端到端**形状，只有读码级证据。
   **权威验证位是 CI 的 `postgres:16`**。
2. **容器/镜像层语义**：基础镜像 CA bundle 是否符号链接（第五轮 DEP-02）、Trivy/cosign/kustomize 的真实行为。
3. **真实发布链路**：无 tag、无 cosign、无网络。
4. **真实上游方言**：联邦探针全用 stub；真实 TapTap/LeanCloud 未跑。
5. **Linux 特定行为**：`0.0.0.0/8` 是否路由到本机回环（FO-03 的可利用性）。
6. **浏览器**：Playwright 浏览器未安装；单引擎结论。真实中介缓存行为未测。
7. **绝对性能数字**：多代理并行 ⇒ 只有**每操作分配量**与复杂度类可引用。
8. ~~**没有 bash**~~ **（已被本轮复核推翻，务必更正）**：本机**有 bash**
   （`C:\Program Files\Git\bin\bash.exe`，**5.3.9**）。原报告把它写成"未能到达"是错的，
   而正是**实跑** `scripts/*.sh` 才发现了 `Z13V-2`（恢复脚本 100% 不可执行）。
   **教训**：把"我以为环境没有某工具"当成盲区，会让整片可验证区域不被验证；
   这一条应当作为审计方法本身的一个缺陷记录下来。**保留项**：本机只有 5.3.9 一个 bash 版本，
   无法判定该行为是否 5.3 特有（若是，`Z13V-2` 降为 P2 兼容性问题，但修法不变）。

---

## 9. 上线前执行顺序（建议）

**必须做（阻断）**
1. **G-1**：实现 refresh token 家族撤销（检测到重放 ⇒ 撤销该 `(client, subject)` 的全部 refresh/access）。
   **排序约束（我读码确认）**：检测点上被重放令牌的那一行**已被删除**，store 拿不到它的 subject/client
   ⇒ **必须先在轮换时留下族/代号标识或已消费令牌的墓碑**，否则写出的修复覆盖不到顺序重放
   （届时「顺序重放」与「随机坏令牌」在服务端不可区分，连 `ErrRefreshTokenSpent` 都走不到）。
2. **G-2 + Z07-1**：把 `expires_at` 谓词补到 **Postgres refresh 读路径** 与
   **两个后端的 auth-request by-ID 路径**（并检查 G-7 的设备消费谓词）——三处同一类。
3. **G-3 + G-13**：用 `noRows(err)` 分类，只有 `pgx.ErrNoRows` 才算「未知令牌」，其余映射 500。
4. **G-4**：实现 `max_age` / `prompt=login` 的重新认证（`oidcstore.AuthRequest` 需加字段）；
   无活会话时按 `login_required` fail-closed。
5. **G-5**：内省守卫在查库前对 Basic 里的 client_id 做 `url.QueryUnescape`。
6. **G-6**：在 `internal/oidchttp` 边界对 `/oauth/device_authorization` 的机密客户端强制认证。
7. **Z07-2**：抹除最后一步失败时补一条 `OutcomeError` 记录，别让唯一那条记录谎报成功。
8. **G-12**：`auditDrainTimeout = grace - removal - shutdown`（=10s）**或** grace 提到 ≥70s；
   同步 `deployment.yaml` 注释与 `CHANGELOG.md`。

**第七轮新增的 P1（与上面同批落地）**
- **Z12-3**：`seedClient` 在客户端已存在时**比对并告警配置差异**（或显式支持更新），
  别让 `[client]` 的 redirect URI / secret / scope 改动**静默失效**——secret 轮换的场景最重。
- **Z11-4 / Z11-5**：限流桶表与并发槽位**按调用方分摊**，并让"键空间耗尽 / 槽位耗尽"
  **不转嫁给他方**（现状是**匿名、单机**可触发；按简报口径可上调 P0）。
- **Z11-1 / Z12-7 / Z18-1 / G-11**：给 `/readyz` 一个**显式三态**（未知/就绪/不就绪）与
  **不派生自调用方 ctx 的检查上下文**（综合见 §5.15；这是四条发现的正確收口）。
- **Z07-2**（已在上方列 7）。

**强烈建议（高/中）**
9. **Z09-1**：`NewRegistry` 对 `status` 做与 `token_class` 同形的白名单校验（拒绝启动）。
10. **Z09-4**：给上游缓冲预算做**按调用方分摊**（或按已读字节预留 / 首字节期限）——涉及裁定。
11. **G-7 / G-10**：设备码消费谓词补期限；设备授予接受 `client_secret_post`，且 401 不得烧掉 device_code。
12. **G-8 / G-9**：`/oauth/revoke` 两种形状统一；刷新签发的 id_token 带上原始 `nonce`。
13. **N-04**：把已结案的安全探针纳入 CI（这是让第 1–8 条不复发的前提）。
14. **Z10-1 / Z10-2（复核后降为 P3）**、**N-01/N-02/N-03、22-1、22-2、Z08-5、Z09V-2/V-3、Z10V-1/V-2、
    FO-03/04/05、k1/k6、KIT-*、RP-***：成批收口（多为 P3，但都是守卫与一致性缺口）。

**上线前必须闭合的验证缺口**

16. 在 CI 的 `postgres:16` 上把 Z10-1/Z10-2/04-7 与 G-2/G-3/G-7/G-13/G-14/G-17 的 PG 侧探针跑成定论。

---

## 10. 附录：复现命令

```sh
# 基线（HEAD bf81b2a，本机全绿）
go build ./... && go vet ./... && go test ./... -count=1

# 第六轮阻断项（全部为红）
go test -tags audit6 -count=1 -v ./internal/zzprobe/audit6/z01protocolauth/
go test -tags audit6 -count=1 -v ./internal/zzprobe/audit6/z02protocoltoken/
go test -tags audit6 -count=1 -v ./internal/zzprobe/audit6/z04pgstore/
go test -tags audit6 -count=1 -v ./internal/zzprobe/audit6/z06httpedge/

# 第五轮红探针（19 条，归因见区域 22）
go test -tags audit5 -count=1 ./internal/zzprobe/...

# 第七轮区域探针
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z07authsessionlifecycle/
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z09federationdataplane/
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z10adminauditprivacy/

# CI 从不设置的标签（证据：ci.yml 里 -tags 计数为 0）
grep -c -- '-tags' .github/workflows/ci.yml   # → 0
```

产物位置：区域报告 `docs/audit-7/findings/*.md`；
探针 `internal/zzprobe/audit7/*/`（全部带 `//go:build audit7`）；
主代理复核日志 `docs/audit-7/findings/00-MAIN-VERIFICATION.md`。
