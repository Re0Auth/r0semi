# 管理面 / 审计日志 / 账号抹除与导出 / 隐私 审计报告

> 区域：`internal/admin`、`internal/lifecycle`、`internal/httpapi`（admin/audit/export/account/identity/device/grants 路由）、
> `audit/`、`internal/store/postgres/audit{read,pseudo,chain}.go`、`internal/observability`。
> 方法：能跑的探针都真的跑了；Postgres 路径**一律标注「读；无 DB 执行」**。

## 范围与方法

**读了什么**（端到端）：`docs/admin.md`、`docs/account-model.md`、`docs/architecture.md` §4.14–§4.17、
`docs/openapi.yaml`（admin/audit/export 段）、`docs/security-audit-2.md`、`docs/security-audit-3.md`、
`internal/admin/admin.go`(+tests)、`internal/lifecycle/lifecycle.go`(+tests)、`internal/httpapi/{admin_routes,audit_routes,export_routes,account_routes,identity_routes,binding_routes,grants_routes,session_routes,server,responses}.go`、
`audit/audit.go`、`internal/store/postgres/{audit,auditread,auditpseudo,auditchain,sessions,oidc,oauth,erasure_test,erasure_schema_test}.go`、
`internal/store/memory/oidc.go`、`vault/{service,rotate}.go`、`internal/auth/auth.go`、`oauth/{as,grants,device}.go`、
`tapsign/client.go`、`internal/observability/observability.go`、`cmd/re0auth/{main,config}.go`、全部 21 个迁移 SQL。

**跑了什么**（本机，Windows 11，无 Docker / 无 Postgres）：

```sh
go test ./internal/httpapi/  -run 'TestZZAdm'      -count=1 -v     # 7 个探针（1 FAIL 组）
go test ./internal/zzprobe/admin/ -count=1 -v                      # 6 个探针
go test ./internal/store/postgres/ -run 'TestZZAdmPseudonymKey' -count=1 -v
go test ./internal/httpapi/ -run 'TestZZAdmEveryAdminRouteIsGatedByTheAllowlist' -count=1 -v
```

**跑不了的**：一切 Postgres 路径（假名化、审计链、`Query`、会话撤销、孤儿扫描）——探针用的是内存 store 与 fake 端口。
`-race` 需要 cgo，本机未启用（CI 以 `-race -p 1` 跑，见 `docs/security-audit-3.md`）。

**过程中的一处干扰（与代码无关）**：本轮期间 `internal/httpapi/zzprobe_httpedge_test.go`（另一位代理的探针）两次处于
半成品状态导致该包 build 失败，我的 `-v` 运行是在它编译通过之后重跑的；我没有改动任何**别人的**文件。

**探针文件**（只新建，未改任何已跟踪文件）：

- `internal/httpapi/zzprobe_adminplane_test.go` — P1–P7（前缀 `zzAdm`）
- `internal/zzprobe/admin/zzadmin_test.go` — P8–P13
- `internal/store/postgres/zzprobe_audit_gap_test.go` — 守卫覆盖缺口（无 DB）
- 清空过程中的一个废文件 `internal/httpapi/zzprobe_adminpriv_test.go` 已删除（PowerShell 改写了它的非 ASCII 字节，
  故重写为纯 ASCII 的 `zzprobe_adminplane_test.go`）。

---

## 发现

### AUD-1 OpenID Provider 存储层的审计写入失败被**静默吞掉**：动作照做、记录丢失、无任何信号

- 严重度: **中**
- 类别: 安全 / 合规
- 不变量/性质: 破坏「失败方向必须被选定」——本项目对审计失败明确选过两次方向（admin/auth=记录并继续；
  vault/lifecycle=失败即拒绝），OP 存储层**两个方向都没选**
- 证据:
  - `internal/store/memory/oidc.go:313-321`、`internal/store/postgres/oidc.go:122-130` 的 `record()` 是
    `_ = s.audit.Record(ctx, ...)`：**既不返回错误，也不打日志**。
  - 它覆盖的事件：`oidc.token`（memory:436,514 / postgres:283,376 —— **每一次 access/refresh 签发**）、
    `oidc.revoke`（memory:576,595,607 / postgres:446,466,482）、`oidc.device.approve`（memory:996 / postgres:789）、
    `oidc.device.deny`（memory:1017 / postgres:810）、`oidc.grant.revoke`（memory:1136 / postgres:930）。
  - 对照：`vault/service.go:289-294` 失败即 return（I3 fail-closed）；`internal/auth/auth.go:210-220` 与
    `internal/admin/admin.go:428-444` 打 `slog.Error` 后继续；`internal/lifecycle/lifecycle.go:246-252` 失败即失败。
  - 同类静默点（公开库/运维路径，一并列出）：`oauth/as.go:326-334`（`oauth.authorize`/`oauth.token`/`oauth.grant.revoke`
    的旧引擎实现）、`vault/rotate.go:74-82`（**KEK 轮转**的审计行）。
  - 探针输出（已执行，FAIL）：
    ```
    zzprobe_adminplane_test.go:383: a device approval (a whole access grant) was performed against a dead
    audit sink: ApproveDevice returned nil and nothing was logged (captured log ""). The action proceeds,
    the record is lost, and no operator signal exists ...
    ```
    反空转对照在同一个测试里：同一个 `zzAdmFailingLogger` 交给 `vault.Service.Enroll` 时**确实**失败，
    所以「静默」不是因为 logger 没失败。
- 状态: **CONFIRMED**（已执行；Postgres 一侧为同一行代码，读）
- 影响: 一次数据库抖动（链头锁等待超时、连接池耗尽、`audit_subject_keys` 读写失败）就会让
  **令牌签发**与**设备批准**（= 一整份访问授权）不留任何记录，而调用方拿到 200、日志里一个字都没有。
  事后无法判断「这段时间的日志是空的」还是「这段时间没发生事」——对一个把审计当合规交付物的服务，
  静默丢失比失败更糟。攻击者若能制造写审计的争用（capacity-planning.md 已说明审计写入是全局串行的），
  就同时获得了「签发令牌不留痕」与「不留任何可检测信号」。
- 修法建议: 最小改法是让 `record()` 至少 `slog.Error`（与 auth/admin 一致，附 action/subject/provider），
  并加一个 `re0auth_audit_write_failures_total{plane}` 计数。要不要**失败即拒绝**是裁定：
  笔者倾向「签发路径记日志 + 计数继续」（否则审计故障会变成协议面不可用），但**绝不能保持现状的沉默**。
  同一改法应推广到 `oauth/as.go`、`vault/rotate.go`。
- 复现/守卫: `internal/httpapi/zzprobe_adminplane_test.go::TestZZAdmProviderAuditFailureIsNeitherReturnedNorLogged`

### AUD-2 抹除的**最后一步**失败后不可重试：账户已删、会话已清、密钥仍在，而错误消息说「可以再试一次」

- 严重度: **中**
- 类别: 合规/隐私 / 可用性
- 不变量/性质: 「抹除是用户主动、可重试的请求」+「假名密钥销毁 = 历史不可关联」
- 证据:
  - 顺序（`internal/lifecycle/lifecycle.go`）：sessions 在第 4 步（:209-216）、账号行在第 7 步（:242-244）、
    `account.delete` 记录在第 8 步（:250-252）、**销毁假名密钥在最后**（:258-263）。
  - 最后一步失败时返回 `"lifecycle: the account was erased but its audit history is still linkable"`，
    HTTP 层把它变成 500 + `"the account could not be erased; it is safe to try again"`
    （`internal/httpapi/account_routes.go:55-61`）。
  - 探针输出（已执行，FAIL）：
    ```
    zzprobe_adminplane_test.go:525: CONFIRMED: the retry is answered 401 "no active session".
    The first response told the caller "it is safe to try again"; trying again is impossible,
    because the erasure revoked the sessions at step 4 and deleted the account row at step 7
    before the pseudonym key step failed at step 8. ...
    ```
    探针的 `Sessions` 端口在撤销时**真的**把调用者自己的会话注销掉（真实部署里
    `postgres.Sessions.RevokeSubjectSessions` 删的正是「该 subject 的全部会话」，调用者那一条在其中），
    所以这不是夹具的产物。同一次运行里 `sessions.called`、`flaky.called` 都被断言为真（反空转）。
- 状态: **CONFIRMED**（已执行）
- 影响: 一次 `audit_subject_keys` 删除失败就留下**永久**残留：账号行没了、身份没了、会话没了，
  但该 subject 的假名密钥还活着。此后凡是能拿到那个 `usr_…` 的人（备份、日志、上面
  `detail["actor"]` 的残余、运维记忆）都能重算假名并读回这个人的全部审计史。
  用户无法再登录，所以**用户侧没有任何补救路径**，仓库里也没有运维侧工具（`ops/` 无对应 runbook）。
  注意这不是「可重试」的常规故障：`DeleteUnser` 幂等是真的，但入口要会话，而会话是这次抹除自己清掉的。
- 修法建议: 二选一（裁定）：(a) 把 `Pseudonyms.Destroy` 提前到**账号行删除之前/`account.delete` 记录之后**的
  独立事务里，并把「未销毁」状态记进结果；(b) 保留现顺序，但给运维一个可重跑的命令
  （`re0auth -destroy-pseudonym usr_…`），并把 HTTP 错误消息改成不说「可以再试」。
  **不建议**只改文案：残留本身仍在。与之配套的最小守卫：`lifecycle_test.go` 加一条
  「最后一步失败后，结果里必须带上 `pseudonym_destroyed=false`」。
- 复现/守卫: `internal/httpapi/zzprobe_adminplane_test.go::TestZZAdmErasureWhoseLastStepFailsCannotBeRetried`

### AUD-3 同意决策（consent approve / deny）**没有审计**：授权的瞬间不在日志里

- 严重度: **中**
- 类别: 合规/隐私
- 不变量/性质: 「安全相关的状态变更留审计」——「用户把账号数据授权给哪个 client、哪些 scope」是这套服务
  最核心的授权事件
- 证据:
  - 生产路径：`internal/oidchttp/oidchttp.go:1288` 批准 → `h.consent.CompleteLogin(...)`；
    `:1296-1311` 拒绝 → 只 `DeleteAuthRequest`。**两者都不写审计**，`oidchttp` 全包无 audit 依赖。
  - 两个 store 的 `record()` 调用点已完整枚举（见 AUD-1 证据），集合是
    `{oidc.token, oidc.revoke, oidc.grant.revoke, oidc.device.approve, oidc.device.deny}`——**没有同意决策**。
  - 对照：被弃用的手写引擎审计同一动作（`oauth/as.go:156` 的 `oauth.authorize`），但它不是组合根装配的引擎
    （`authorization-engines-decision.md`、`cmd/re0auth/main.go:538-542`）。
  - 探针输出（已执行，FAIL）：
    ```
    zzadmin_test.go:365: an account approving client "cli" for scopes [account.id] recorded no audit event:
    the authorization decision - the moment access is granted - is absent from the log ...
    ```
    同一测试先断言 `oidc.device.approve` **是**被记录的（反空转：sink 是接好的、store 确实会记）。
- 状态: **CONFIRMED**（已执行；另有两处行级枚举佐证）
- 影响: 运维无法回答「这个 client 是什么时候、经谁同意、拿了哪些 scope」；**被拒绝**的请求完全无痕。
  用户事后主张「我没批准过这个应用」时，日志没有任何可对照的记录。签发侧有 `oidc.token` 作为部分补偿，
  所以危害有界，但「谁做的决定」这一半确实缺失。
- 修法建议: 在 `oidchttp` 的批准/拒绝两个出口各写一条事件（例如 `oauth.consent.approve` /
  `oauth.consent.deny`，`Subject`=会话账号，`Detail`={client_id, scopes}），经现有的 `audit.Logger`
  注入（`oidchttp.Config` 加一个可选 `Audit`，与 `WithAudit` 同形）。写在 store 层也可，
  但 `oidchttp` 才知道「哪些 scope 被显式勾选」。
- 复现/守卫: `internal/zzprobe/admin/zzadmin_test.go::TestZZAdmConsentDecisionIsNotAudited`

### AUD-4 非管理员用**未声明的动词**访问 `/v1/admin/*` 得到 `405 + Allow`：管理面被广告给「本不该看见它」的人

- 严重度: **低**（文档化不变量的破坏 + 一比特存在性泄露；无数据泄露）
- 类别: 安全 / 可维护性
- 不变量/性质: `docs/admin.md` §0「已登录但不在列表里的账号，访问 `/v1/admin/*` 得到 `404 not_found`，
  **与访问一个不存在的路径毫无区别**」；`docs/openapi.yaml:1415-1420` 同一句话（"the log is not
  advertised to those who cannot read it"）
- 证据:
  - `internal/httpapi/admin_routes.go:57-72` 的 `requireAdmin` 确实答 404，但**它跑不到**：
    `internal/httpapi/server.go:611-661` 的 `businessPlane()` 在内层按方法分派，未声明的动词在
    `:653-655` 由分派层直接答 `405 + Allow`，**任何 handler（因而任何 gate）都没跑**。
  - 探针输出（已执行，FAIL；**44 条**未声明动词探针全部漏出）：
    ```
    zzprobe_adminplane_test.go:143: PUT /v1/admin/audit = 405 Allow="GET, HEAD" for a signed-in NON-admin: ...
    zzprobe_adminplane_test.go:143: POST /v1/admin/kill_switch 系列 → 405 Allow="POST"
    zzprobe_adminplane_test.go:143: PUT /v1/admin/clients/{client_id} = 405 Allow="DELETE"
    zzprobe_adminplane_test.go:153: wrong-verb leak on 44 undeclared-verb probes
    ```
    同一测试的反空转对照：**声明过**的动词对非管理员一律是 `404 / "unknown resource"`（gate 生效），
    所以漏出的是「未声明动词」这一条独立路径，不是 gate 失效。
  - 这是工作树里那条改动的直接后果：CHANGELOG（Unreleased）「每个端点声明自己的动词，未列出的动词一律 `405`：
    …业务面同样改为按方法分派…不再被 `/v1/` 兜底吞成 `404`」。
- 状态: **CONFIRMED**（已执行）
- 影响: 任何已登录（甚至未登录，因为分派早于任何 gate）的调用者，用 `PUT/DELETE/PATCH/OPTIONS/TRACE`
  打任意 `/v1/admin/*` 路径，即可确认**本部署有运维面**并读出**每条路由的方法集合**
  （`Allow: GET, HEAD` / `Allow: POST` / `Allow: DELETE`）。没有数据、没有凭据，故为低。
  与既有裁定（`docs/security-audit-3.md`「判断」：未认证 401 让探测器可知有运维面，保持现状）叠加时要注意
  差别：那条是「匿名者能知道有这块面」，本条的**新**内容是「设计上明确要瞒住的那一类人（已登录非管理员）
  能被 advertised」，且 `405` 连方法集一起给。
- 修法建议: 两条路，取其一（裁定）：(a) 把 `/v1/admin/*` 的鉴权从 handler 提到**分派之前**——
  给 `businessPlane()` 加一个按前缀的 `adminGuard` 包装（`strings.HasPrefix(pattern, "/v1/admin/")`），
  这样未声明动词也先过 gate、答 404；(b) 接受这次泄露并把 `docs/admin.md` §0 与 `docs/openapi.yaml`
  那句话改成实话。若选 (b)，`plane_test.go` 里那条「每个业务路由的未声明动词都是 405」的守卫正好已经
  把现状钉住了，改文档比改行为便宜。
- 复现/守卫: `internal/httpapi/zzprobe_adminplane_test.go::TestZZAdmWrongVerbAdvertisesTheOperatorPlaneToANonAdmin`
  （反向守卫：`TestZZAdmEveryAdminRouteIsGatedByTheAllowlist` 目前 PASS，见「探过但没破」）

### AUD-5 假名密钥销毁与并发审计写入存在竞态：**销毁之后仍可能产出旧假名**，把抹除后的行重新接回历史

- 严重度: **中**（前提：持久化部署；可利用性未验证）
- 类别: 合规/隐私
- 不变量/性质: `docs/architecture.md:654-660` 明写两条：
  ①「顺序是语义的一部分：销毁密钥**必须**排在写完 `account.delete` 之后」；
  ②「**销毁之后**同一 subject 若再来事件…会拿到**新的** key、**不同的**假名，因此与旧行失去关联」，
  并明确断言「**跨进程缓存不破坏擦除**…不可关联性来自**密钥行不存在**，与缓存无关」。
- 证据（全部为「读；无 DB 执行」）:
  - `internal/store/postgres/auditpseudo.go:69-75`：`loadKey` **先查进程内 cache，命中即返回，不查库**。
  - `:115-142`：`subjectKey` 在 cache miss 时读库；库里有就 `remember(subject, key)`（:140）；没有才铸新钥匙。
  - `:144-151`：`remember` 把 `subject→key` 写进 cache。
  - `:173-186`：`Destroy` 删库行**并** `delete(l.cache, subject)`。
  - `internal/store/postgres/audit.go:73-77`：`Record` 在**入队之前**就把 subject 解析成假名，
    所以「解析发生在何时」与「批次何时提交」是两件事。
  - `internal/store/postgres/auditread.go:46-64`：读侧的 `?subject=` 过滤也走 `loadKey`，
    命中 cache 即用它算假名去查——**不校验库行还在不在**。
  - 交错（确定性描述，不需要跑并发）：`Destroy` 的 `DELETE` 与 `delete(cache, subject)` 之间/之后，任意一个
    已经过了 cache miss、正在 `SELECT key ...` 或已经拿到 `key` 的 goroutine 会执行 `remember`，
    于是 **cache 复活**；此外该 goroutine 自己那次 `Record` 会**在销毁之后**用旧假名落一行。
    后果两条：①抹除后新产生的行与旧行**同假名**，`docs/architecture.md:657` 承诺的「不同假名、失去关联」不成立；
    ②此后读侧 `?subject=usr_X` 会解析成功并**返回被抹除账号的历史**，与 `docs/admin.md:130` 和
    `openapi.yaml:1397-1401`（「密钥已销毁 → 过滤解析为空 → 返回空页，这是正确答案」）直接矛盾。
  - 触发窗口的现实性：抹除是用户可自发的长事务（跨十余张表 + 上游 HTTP），期间同一 subject 的在途请求
    （刷新令牌、数据面 `vault.use`、其自身会话的另一次请求）本来就会写审计；攻击者若持有该账号的
    refresh token/陈旧会话，可以**刻意**在用户按下删除时持续开火。
- 状态: **HYPOTHESIS**（未执行：需要真 Postgres + 并发；本机无 DB）
- 影响: 抹除的核心承诺（「再没人能把它们关联到你」）在一种可构造的交错下静默失败，而抹除本身返回 OK；
  更糟的是**缓存复活**会把失败变成**持续**的：此后任何关于该 subject 的事件都继续用旧假名，
  读接口也继续能按 `usr_` 查出被抹除者的历史。泄露的是**关联**（同一假名），不是明文。
- 修法建议: 三处小改，任一处都能关掉这条路径：(a) `loadKey` 命中 cache 时不做 DB 校验是可接受的，
  但 `Destroy` 必须在删行后**再做一次** cache 清理，且引入「已销毁 subject」的墓碑集合
  （`destroyed map[string]struct{}`），`remember` 拒绝写入墓碑中的 subject——这是最小且不依赖时序的修法；
  (b) 让 `subjectKey` 在「库里没有」时**先查墓碑**，只有墓碑为空才铸新钥匙；
  (c) 把 `Destroy` 与「写 `account.delete`」放进同一个持有 subject 锁的临界区，使 in-flight 解析
  要么在销毁前完成、要么在销毁后铸新钥匙（`audit_batch` 已经给了批次级串行点，可作为挂载处）。
  守卫需要 DB：模拟「`Destroy` 与一次 `Record` 交错」——先让一个 goroutine 阻塞在 `SELECT key` 之后的
  钩子上，再执行 `Destroy`，再放行，断言之后写入的行的假名**不等于**销毁前的假名，且
  `Query(Subject: usr_X)` 返回空页。
- 复现/守卫: 未能执行；探针骨架建议放在 `internal/store/postgres/auditpseudo_test.go`（需 `TEST_DATABASE_URL`）。

### AUD-6 抹除的「销毁假名密钥」这一步**两个守卫都看不见**，而且这一步是可选端口

- 严重度: **低**
- 类别: 合规/隐私 / 可维护性
- 不变量/性质: `docs/architecture.md:611-614` 把抹除完整性交给两条守卫：
  `TestAccountDeletionLeavesNoOrphans`（扫 `information_schema` 里所有含 `subject`/`user_id` 列的表）
  + `TestEverySubjectColumnIsHandledByErasure`（解析 migration）
- 证据:
  - 探针输出（已执行，FAIL）：
    ```
    zzprobe_audit_gap_test.go:60: audit_subject_keys is the table that makes an erased account's audit history
    linkable again (idx = HMAC(audit_key, "subject-index/1" || subject), key = the per-subject pseudonym key),
    and no guard observes it: it has no subject/user_id column, so neither the migration parser (14 account-linked
    tables found) nor the information_schema walk in TestAccountDeletionLeavesNoOrphans counts it. Its only
    clearing step is the lifecycle Pseudonyms port, which is optional in lifecycle.New and filled by a runtime
    type assertion in cmd/re0auth. ...
    ```
    探针复用的是**真**守卫的代码路径（`migrationsFS` + `createTableRE` + `hasAccountColumn` + `erasureHandledTables`
    + `accountTablesIgnored`），所以这不是转述。
  - `internal/store/postgres/migrations/0014_audit_pseudonyms.sql:36-39`：列只有 `idx`（带密钥哈希）与 `key`（bytea）——
    两个守卫的判据都是「列名等于 `subject`/`user_id`」，因此**结构性**看不见它。
  - `internal/lifecycle/lifecycle.go:106-112`：`Pseudonyms` 是可选端口，`New` 不校验；
    `cmd/re0auth/main.go:1379-1384` 的 `pseudonymStore` 是运行时类型断言，不满足即返回 **nil（静默）**；
    探针 `TestZZAdmErasureWithoutAPseudonymStoreReportsSuccess`（已执行，FAIL）证明这条配置下
    `DeleteAccount` 返回 **nil 错误 + `OutcomeOK` 的 `account.delete`**，没有任何东西记录「不可关联这一步被跳过」。
- 状态: **CONFIRMED**（已执行，两半都跑了）
- 影响: 这是一条**未来**才咬人的缺口：任何一次重构（给 sink 包一层装饰器、换 store、把 `Pseudonyms` 挪出组合根）
  都会让「抹除 = 不可关联」**静默**退化成「抹除 = 只删了账号行」，而 CI 全绿。
  当下的生产装配是对的，所以影响是「失去守卫」，不是「当下已经在漏」。
- 修法建议: 三件小事：(a) 在 `erasure_schema_test.go` 里加一张**按能力清除**的表清单
  （`audit_subject_keys` → `Pseudonyms.Destroy`），并让静态测试对「既不在 handled、也不在 ignored、
  也不在 capability 清单」的表继续报错；(b) 组合根加一条启动断言：
  `if store.durable && pseudonymStore(store.audit) == nil { return die(...) }`（与 `RE0AUTH_AUDIT_KEY`
  必填同款理由）；(c) `lifecycle.Result` 增加 `PseudonymDestroyed bool`，让「跳过了」这一事实进结果与审计行。
- 复现/守卫: `internal/store/postgres/zzprobe_audit_gap_test.go::TestZZAdmPseudonymKeyTableIsInvisibleToEveryErasureGuard`、
  `internal/zzprobe/admin/zzadmin_test.go::TestZZAdmErasureWithoutAPseudonymStoreReportsSuccess`

### AUD-7 导出（`GET /v1/account/export`）与读取审计日志（`GET /v1/admin/audit`）都不留审计记录

- 严重度: **低**
- 类别: 合规/隐私
- 不变量/性质: 「谁能读到个人数据，要能被回答」——本项目自己的审计包文档写着
  「the durable record of **who accessed what**, and when」（`audit/audit.go:1-3`）
- 证据:
  - 探针输出（已执行，FAIL，两条）：
    ```
    zzprobe_adminplane_test.go:269: GET /v1/account/export left no audit event (actions added: []): a full copy
    of one account's personal data was produced and the log cannot answer who read it
    zzprobe_adminplane_test.go:283: GET /v1/admin/audit left no audit event (actions added: []): an operator can
    read every account's history with no trace of having done so
    ```
    同一测试先断言 `admin.client.register` 与 `auth.identity.unlink` **确实**有记录（反空转：logger 接的是
    同一个对象、事件确实在增长）。
  - 代码：`internal/httpapi/export_routes.go:55-105` 全程无审计调用；`internal/httpapi/audit_routes.go:44`、
    `:137`、`:167`（audit / verify / head）同样没有。`s.auditLog` 只被 `identity_routes.go:79-91` 用了一次。
- 状态: **CONFIRMED**（已执行）
- 影响: 导出是「一次拿走某个账号的全部个人数据」的动作，审计日志读是「一次读遍所有账号的活动」的动作——
  两者都是最该留痕的访问，却都是零记录。合规审计（PIPL/等保的「个人信息处理活动记录」）会直接问这一条。
  无直接攻击者收益，故为低。
- 修法建议: 在 `handleExportAccount` 成功路径写一条 `account.export`（`Subject`=调用者、`Detail`={"bindings":n,"grants":n}）；
  在 `handleAdminAudit` 写一条 `admin.audit.read`（`Detail`={"actor": 操作员 usr_（与 admin.* 同款已文档化例外）,
  "filters":…,"returned":n}）。**注意一个反噬**：导出是 GET，加上审计写入后它就变成一个「跨站 `<img src>` 能触发的
  带副作用请求」（虽然读不到响应）。当前 `withNoStore`（`server.go:676-681`）已经保证它不可缓存，所以 CSRF/缓存
  层面没有风险；若不愿接受「GET 写日志」，改法是要求自定义头（`X-CSRF-Token`）或改成 POST。
- 复现/守卫: `internal/httpapi/zzprobe_adminplane_test.go::TestZZAdmSecurityRelevantActionsLeaveAnAuditEvent`

### AUD-8 Kill Switch 没有清理**在途绑定流程**的端口，而抹除有

- 严重度: **低**（HYPOTHESIS）
- 类别: 安全 / 一致性
- 不变量/性质: `docs/admin.md` §4.2 声称 `subject` 清「该账号的全部」令牌/会话/绑定；
  而一个 pending bind flow **是一个能在事后造出新绑定 + 新上游令牌的能力**
- 证据:
  - `internal/lifecycle/lifecycle.go:40-42` 有 `FlowPurger`，`cmd/re0auth/main.go:609` 装配
    `Flows: store.bindFlows`——抹除会按 user 清掉在途流程。
  - `internal/admin/admin.go:67-70` 的 `Bindings` 端口只有 `RevokeAllBindings`/`RevokeSubjectBindings`
    （`cmd/re0auth/main.go:562` 的 `bindingRevoker`），**没有任何 flow 维度**。
  - 探针输出（已执行，FAIL）：
    ```
    zzadmin_test.go:204: admin.Config cannot purge in-flight bind flows (fields: map[Audit:audit.Logger
    Bindings:admin.Bindings Clients:admin.Clients Now:func() time.Time Sessions:admin.SessionRevoker
    Tokens:admin.Revoker]), while lifecycle.Config can: a `subject`-scoped Kill Switch cuts the account's
    tokens, sessions and bindings and leaves a pending bind flow able to recreate a binding afterwards.
    ```
- 状态: **HYPOTHESIS**（端口不对称已是 CONFIRMED；**可利用性未验证**：完成流程需要浏览器手柄，
  而手柄存在会话里，`subject` 目标在**持久会话**部署下会清掉该账号的会话——那时手柄随之失效，
  所以大概率不可利用。内存模式（清不掉会话，`main.go:621-627` 已警告）下则**可以**：
  Kill Switch 报 `bindings.revoked=N`，之后同一浏览器把流程走完，绑定就回来了。）
- 影响: 事故响应里「已切断数据访问」的报告可能被在途流程悄悄推翻（特别是内存/无持久会话部署）。
  与 erasure 的处置不一致本身就是可维护性问题：两条路对同一个中间状态给了两种答案。
- 修法建议: 若判定要修，最小改法是给 `admin.Bindings` 增加 `PurgeUserFlows(ctx, subject)`（或复用
  `lifecycle.FlowPurger`），在 `KillSwitch` 的 `subject` 分支里调用，并把条数计入 `Report`（新字段
  `flows_purged`）。要证实 HYPOTHESIS，需要一条端到端探针：内存模式 + `/bind` 起流程 →
  Kill Switch `subject` → 走完回调 → 断言 `GET /v1/bindings` 里绑定**又出现了**。
- 复现/守卫: `internal/zzprobe/admin/zzadmin_test.go::TestZZAdmKillSwitchHasNoFlowPurgerWhileErasureDoes`

### AUD-9 Kill Switch `all` 在「无数据源」部署上对 bindings **完全沉默**，而 `bindings` 目标会 fail-loud

- 严重度: **低**
- 类别: 一致性 / 可用性
- 不变量/性质: `docs/admin.md:93-98` 的立场是「绝不把部分清扫说成完整」「不假装成功」
- 证据:
  - 探针输出（已执行，FAIL）：
    ```
    zzadmin_test.go:156: KillSwitch(all) returned a report with no bindings outcome: the answer to
    "were the data-source bindings cut?" is missing entirely, while the `bindings` target refuses with
    ErrBindingsUnavailable so that it never answers a hollow zero (report: {TokensRevoked:0 SessionsRevoked:0
    ClientsSuspended:0 Bindings:<nil>})
    ```
    同一测试的对照：`KillSwitch(bindings)` 确实返回 `ErrBindingsUnavailable`（fail-loud）。
  - 代码：`internal/admin/admin.go:292-294`（只有 `Bindings` 目标拒绝）、`:345-362`（`all` 在
    `s.bindings == nil` 时整段跳过）、`:148-152`（`Report.Bindings` 带 `omitempty`）。
- 状态: **CONFIRMED**（已执行）
- 影响: 事故响应者拿到 `{"tokens_revoked":N,"sessions_revoked":M}`，**无法区分**「这个部署没有绑定」
  与「这个部署清不了绑定」。数字是对的，缺的是那个「不知道」标记——正是该项目在别处刻意避免的形态。
- 修法建议: `Report` 加 `BindingsUnavailable bool`（或在 `all` 且 `bindings==nil` 时返回
  `Bindings: &BindingOutcome{}` 并在 `Detail` 里记 `bindings_unsupported=true`）。属裁定：也可以选择
  在文档里写明「`all` 的 bindings 半边只在配置了数据源时存在」。
- 复现/守卫: `internal/zzprobe/admin/zzadmin_test.go::TestZZAdmKillSwitchAllIsSilentAboutBindings`

### AUD-10 被抹除的账号，其**其余会话**在无持久会话的部署里仍握有完整的运维权限

- 严重度: **低**
- 类别: 安全 / 合规
- 不变量/性质: 抹除 = 「这个账号不再存在」；管理员资格绑定在**会话的 `usr_…`** 上，而不是账号行上
- 证据:
  - 探针输出（已执行，FAIL）：
    ```
    zzprobe_adminplane_test.go:449: an erased account's second session still calls the operator plane
    (GET /v1/admin/clients = 200): erasure removed the account, not the operator capability the allowlist keys on
    ```
    探针先断言两个浏览器在抹除前都是 200（都在允许列表里），再从第一个浏览器执行
    `DELETE /v1/account`，然后从第二个浏览器调 `/v1/admin/clients`。
  - 代码：`internal/httpapi/admin_routes.go:57-72` 只看 `s.sessions.User(ctx)` 是否在 `adminAllowed` 里，
    **从不校验账号行是否还存在**；`internal/httpapi/account_routes.go:68-74` 只登出**当前**这一个会话；
    内存模式 `lifecycle.Config.Sessions` 为 nil（`cmd/re0auth/main.go:607`→`storeRevoker` 在内存模式为 nil）。
- 状态: **CONFIRMED**（已执行；仅内存/无持久会话部署）
- 影响: 运维账号「抹除自己」后，另一台设备上的会话（cookie 未过期）**继续**能暂停/删除客户端、
  执行 Kill Switch、读全量审计日志。抹除在法律上是终局处置，而这里它没有终结权限。
  注意：会话本身存活的残留已被 `cmd/re0auth/main.go:621-627` 的启动警告记录，但**「存活会话 = 存活运维权限」
  这一后果在任何文档里都没有出现**，也没有任何测试。这就是本条的增量。
- 修法建议: 与其修补内存模式，更稳的修法是让 operator gate 多查一次账号存活：
  `requireAdmin` 里加 `if _, err := s.accounts.GetUser(ctx, user); err != nil { 404 }`。
  代价是每个管理请求多一次账号读（内存模式零成本，Postgres 一次主键查询，管理面流量极低）。
  同样的检查也应加在 `/v1/account/export`、`/v1/grants`… 这些「只认会话、不认账号」的读端点上
  （那是另一个区域的题目，此处只登记）。
- 复现/守卫: `internal/httpapi/zzprobe_adminplane_test.go::TestZZAdmErasedOperatorKeepsThePlaneThroughAnotherSession`

### AUD-11 文档与实现漂移：`rotate_secret` 与 `/v1/admin/audit/head` 不在 `docs/admin.md` 的契约表里

- 严重度: **低**
- 类别: 可维护性
- 不变量/性质: `docs/admin.md:3`「实现必须以此为准」——它漏了两个已实现端点
- 证据（读）:
  - `docs/admin.md:35-44` §1 的路由表只列 6 条，缺
    `POST /v1/admin/clients/{client_id}/rotate_secret`（实现在 `internal/httpapi/admin_routes.go:171-191`
    与 `server.go:465`，openapi 有：`docs/openapi.yaml:1225`）。
  - `docs/admin.md:122-145` §5.1 只讲 `/v1/admin/audit` 与 `/verify`，缺
    `GET /v1/admin/audit/head`（`audit_routes.go:167-177`、`server.go:478`、`openapi.yaml:1518`）。
  - `docs/api-design.md:301-308` 的管理面表同样缺这两条。
  - 反向对照：`TestOpenAPIMatchesDeclaredRoutes` 对 openapi 与 `specRoutes()` 是双向断言的，所以
    **spec 没漂**；漂的是两处 Markdown。
- 状态: **CONFIRMED**（读代码到行；列一份清单不需要执行）
- 影响: 运维按 `docs/admin.md` 实施时不知道有密钥轮转端点（或反之，审计 head 端点无人使用）；
  两者都是「文档是运维唯一能看到的面」时才会咬人的问题。
- 修法建议: 把两条路由补进 `docs/admin.md` §1 与 §5.1、`docs/api-design.md` §4 的表；
  更耐久的做法是在 `internal/httpapi/openapi_test.go` 旁边加一条「每个 `admin` tag 的 operation 都出现在
  `docs/admin.md` 的表里」的断言（把 Markdown 当数据读，和 openapi 一样）。
- 复现/守卫: 无探针（文档断言）；建议按上面的方式加守卫。

### AUD-12 `tapsign` 把**上游平台身份**（TapTap openid）当作审计 `Subject` 落库

- 严重度: **提示**
- 类别: 合规/隐私 / 一致性
- 不变量/性质: 审计 `Subject` 的文档语义是「该事件所关于的账号（假名）」
  （`docs/openapi.yaml:1992-1997`：「The pseudonym the log stores for the account this is about. Never the
  account id」）；`docs/account-model.md:46`「上游身份标识（openid/unionid 等）由数据源持有，**Re0Auth 侧不落库**」
- 证据（读）:
  - `tapsign/client.go:146-171`：`Redeem` 用 `tok.OpenID` 初始化 `identity := Credential{ObjectID: tok.OpenID}`；
    `:195-211` 的 `finish` 写 `audit.Event{Subject: cred.ObjectID, Provider: "taptap"}`——
    于是审计行的 subject 是 **TapTap openid**（上游身份键），既不是 `usr_…` 也不是它的假名。
  - 使用方是参考数据源 `cmd/referencesource/main.go:160`（`audit.NewMemoryLogger()`），即「数据源侧」，
    而 account-model 说的「不落库」主语是 Re0Auth；所以这不是对那条契约的直接违反，而是**字段语义**的越界。
  - 若该部署换成 Postgres sink，`Record` 会把这个 openid 当 subject 做假名化并**铸一把密钥行**——
    于是「上游身份」在审计表里留下一个稳定假名（同一 TapTap 账号跨时间可关联）。
- 状态: **CONFIRMED**（读；`tapsign` 不在本轮端到端探针的可执行范围内——它需要一个假 TapTap 上游，
  那是参考源区域的题目）
- 影响: 数据源侧审计里出现一个**跨会话稳定**的上游身份标识，与「审计 subject=账号/假名」的文档语义不符；
  对 Re0Auth 主库无影响（主库不写这个事件）。泄露的是**上游账号的可关联性**，不是凭据。
- 修法建议: 要么改字段（把 openid 放进 `Detail["object_id"]` 并把 `Subject` 留空或填数据源自己的账号 id），
  要么在 `audit.Event` 的文档里承认「Subject 允许是任何主体标识」。属裁定——因为 tapsign 是公开库，
  改它会连带影响参考源与外部使用者。
- 复现/守卫: `tapsign` 现有测试可加一条「`Subject` 出现在 `Detail` 里的形状」断言；本轮未加（避免与其他区域的探针冲突）。

---

## 探过但没破的（这些也应变成守卫）

1. **每条管理路由都过 gate**：从 `specRoutes()` 枚举 `/v1/admin/*` 的全部 9 个 pattern × 声明方法 ×
   三类人群（匿名 / 已登录非管理员 / 操作员）。前两类分别全部 401、全部 `404 unknown resource`；
   第三类全部**没有**被 gate 拦下（反空转：证明探针真的走到了 handler）。
   `TestZZAdmEveryAdminRouteIsGatedByTheAllowlist` 现在 **PASS**，可以直接收编成常规守卫。
2. **不存在自我提权路径**：`adminAllowed` 唯一写入点是 `httpapi.New`（`server.go:280-283`），
   来源是 `Config.Admins`；没有任何 handler 触碰它，也没有任何端点能创建/提升管理员。
3. **允许列表是精确比较**：`map[account.UserID]bool` 查表（`admin_routes.go:67`），无前缀匹配、无大小写折叠、
   无 `strings.Contains`；`cmd/re0auth/config.go:668-673` 只做 `TrimSpace` 并丢弃空条目，空字符串永远不会被
   `sessions.User` 返回（`auth.go:124-130` 对空值返回 `false`），故「配置里一个尾随逗号」不构成绕过。
4. **写操作要 CSRF 且要 step-up**：`requireAdminWrite`（`admin_routes.go:77-98`）先 CSRF 再 reauth；
   没有 `auth_time` 的会话会被拒（fail-closed）。读端点豁免，与文档一致。
5. **审计读取面仍是管理员专属**：非管理员拿到与未知路径**逐字节同形**的 404（`detail="unknown resource"`）；
   未配置 reader 时整个端点不挂载（`server.go:470-480` + `New` 的 allowlist 校验）。
6. **审计读取的过滤条件不是预言机**：`auditread.go:55-63` 在「无假名密钥」时返回的页**带上服务端实际应用的
   `limit`**（B3-2 的修法仍在），与「有密钥但没匹配行」的形状完全一致；`loadKey` 只 SELECT，
   读路径不建密钥（`auditpseudo.go:66-91`）。
7. **导出不含他人数据、不含凭据、不可缓存**：跨账号探针（另一账号有绑定 + 有 grant，导出里
   `bindings` 恰好 1 条、`grants` 恰好 0 条、响应体不含对方的 game/source/usr_），且
   `Cache-Control: no-store`。`TestZZAdmExportCarriesNoOtherAccountAndNoCache` PASS。
8. **上游 openid/unionid 不出现在任何 HTTP 面**：`bindingView`（`binding_routes.go:17-40`）没有 `Meta` 字段，
   导出复用它；vault 的 `meta`（迁移 `0002_vault.sql` 注释明说是 PII）只留在库里。
9. **审计 detail 里没有凭据**：`POST /v1/admin/clients` 返回的明文 secret 与轮转后的新 secret，
   在**任何** `admin.*` 事件的 `subject`/`detail` 值里都不出现（先断言 `detail["actor"]` 确实是操作员 id，
   反空转）。`TestZZAdmRegistrationSecretNeverReachesTheAuditDetail` PASS。
10. **管理事件只记操作员 id，不记被操作账号 id**：Kill Switch `subject` 目标的 `Detail` 里没有那条 `usr_`
    （`TestZZAdmOnlyTheOperatorIdAppearsInAdminDetail` PASS）——即 A5-1 的修法在 admin 面也成立。
11. **指标标签有界**：`normalizeGrantType` / `normalizeOAuthErrorCode` / `normalizeMethod`
    （`observability.go:498-536`）把请求来的值塌成有限集合；`upstream_fetches_total` 的 `game`/`source`
    只来自注册表（`federation/service.go:239,260,273,370,397,402`，`candidates()`/`registry.Get` 先过滤），
    `admin_actions_total` 的 action 是常量。内部监听器默认关闭（配置默认 loopback、非 loopback 需显式
    `server.expose_internal`），故没有匿名可达的基数放大路径。已有 `observability_test.go` 守卫。
12. **Kill Switch 的三种过滤形态都真的清掉了「能力型」中间态**：按 client、按 subject、全量都会删除
    待决授权请求及其 code、已批准/待决的设备授权（内存 `oidc.go:1169-1192`；Postgres `oidc.go:963-968`
    + `revokePendingAuthorizations`）。C3-1 的修法对所有过滤形态生效，不只是空过滤。
13. **停用先于删令牌**（`admin.go:237-247`）：即使删令牌失败，客户端也无法再签发新令牌。
14. **抹除的顺序与幂等**：`account.delete` 记录在销毁密钥**之前**（`lifecycle.go:250-258`），
    与 `TestDeleteAccountDestroysThePseudonymKeyLast` 一致；每步幂等（重试安全）。
15. **导出不能当跨站外泄通道**：它是纯读、同源策略挡住响应体、`Content-Disposition: attachment`、
    `no-store`，且**当前**没有任何副作用（AUD-7 若修掉，这条要重新评估）。
16. **「只认会话」的读端点在账号已删时不会泄露数据**：`/v1/account/export` 与 `/v1/sessions/current`
    在 `GetUser` 失败时回 500（`export_routes.go:63-67`、`session_routes.go:27-31`），
    `/v1/grants`、`/v1/bindings` 对该 subject 派生/列举出的都是空集。

## 未能到达（残余盲区）

1. **全部 Postgres 路径**：假名化（AUD-5）、审计链验证、`Query` 分页/过滤、会话撤销、孤儿扫描、
   凭据列扫描。本机无 DB，**一律只到行**，已在各条标注「读；无 DB 执行」。
   要把 AUD-5 从 HYPOTHESIS 变成 CONFIRMED，需要 CI 的 `postgres:16` 服务 + 一条确定性交错用例
   （可用 `auditbatch.BatchSize=1` 缩小窗口，再加一个 `SELECT key` 之后的钩子）。
2. **并发结论没有竞态检测器背书**：本机 `-race` 需要 cgo，未启用。AUD-5/AUD-8 的可利用性判断因此偏保守。
3. **备份/恢复与 SIEM 导出**：仓库里没有备份代码，`audit/head` 的锚点核对写在 runbook 里但需要外部日志管线。
   「抹除后备份里的副本如何处置」这个问题在本仓库内无法回答（Grafana/Prometheus 配置里有
   `Re0AuthAuditChainBroken` 告警，但审计内容的落盘副本不在其中）。
4. **KEK / `RE0AUTH_AUDIT_KEY` 的真实配置**：未提供环境，`vault` 与审计键只按代码路径判断；
   `secrets.env`（另一个代理的运行目录）我未使用。
5. **管理前端 `/app/admin`**：本轮的证据全部来自 Go 侧；`web/src/routes` 下的管理页未审
   （不在我拿到的文件清单里，且 Svelte 侧的权限判断只是展示层）。
6. **`oauth` 公开库的旧引擎**（`oauth/as.go:326-334` 的静默审计）已登记在 AUD-1，
   但它在 re0auth 装配中不可达（`cmd/re0auth` 只装配 `oauth.TokenAdmins`），所以我没有为它单独立条。
7. **速率限制器状态**：`internal/ratelimit` 的键是客户端地址与分片，不含 subject，故与「抹除」无关；
   未细审（另一区域）。

## 判断（文档化决定可否质疑，不是 finding）

1. **未认证 `/v1/admin/*` 答 401 而不是 404**：`docs/security-audit-3.md`「判断」已裁定保持现状
   （可让探测器得知本部署有运维面）。我不把它当 finding。但要注意 AUD-4 与它**不是同一件事**：
   401 泄露的是「有这块面」，AUD-4 泄露的是「**明确要被瞒住的那一类人**（已登录非管理员）也能看到」，
   且 `405` 连方法集合一起给。若项目认为「匿名可探测」可接受、但「非管理员可见」不可接受，
   那就必须把 gate 提到分派之前（AUD-4 的修法 (a)）——这是一个**一致性裁定**，不是新漏洞。
2. **`admin.*` 的 `detail["actor"]` 记操作员 `usr_…`**：已裁定（企业审计合规），且 `docs/openapi.yaml`
   与 `docs/admin.md` 都写明了。本轮**不重复报告**，只在 AUD-1 的修法里沿用同款「actor 例外」措辞。
3. **管理动作审计失败不回滚**（`admin.go:425-444`）：方向正确（动作已发生，拒绝承认只会让人既没动作也没记录）。
   本条不是 finding；AUD-1 要的是**同一方向**推广到 OP 存储层，而不是把 admin 改成 fail-closed。
4. **`bindings` 目标在无数据源部署上拒绝而不是回零**：方向正确。AUD-9 只针对 `all` 目标的**沉默**，
   两者是同一原则在两个入口上的不一致。
5. **内存模式清不掉会话**（`cmd/re0auth/main.go:621-627` 的启动警告）：文档化了。AUD-10 不重复这一点，
   只报告**没有**被文档化的那半：存活会话 = 存活运维权限（allowlist 只看会话）。
6. **操作员日后抹除自己不会解除 `detail["actor"]` 行的关联**：`docs/security-audit-3.md` 已记录。
   本轮在 AUD-5/AUD-6 里把它当作放大条件引用（因为它给「拿到 `usr_`」提供了一处现成来源），
   但不作为独立 finding。
