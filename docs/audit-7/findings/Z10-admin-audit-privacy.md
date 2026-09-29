# 区域 Z10：admin-audit-privacy（管理面 / 审计链 / 隐私与抹除）— 第七轮审计报告

## 范围与方法

**读了什么**（端到端）：`docs/audit-7/BRIEF.md`；第五轮区域报告
`scratchpad/audit/findings/admin-audit-privacy.md`（AUD-1…AUD-12）与 `docs/security-audit-5.md`（含复核推翻表）；
第六轮 `docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md` 与区 03 的
`internal/store/postgres/zz_audit_keyrotation_test.go`；`docs/threat-model.md`（A7 审计日志）、
`docs/architecture.md` §4.15–§4.17 与 §5、`docs/admin.md`、`docs/security-audit-2.md`、`CHANGELOG.md`。

**代码**：`internal/admin/admin.go`；`audit/audit.go`；`internal/store/postgres/{audit,auditbatch,auditchain,auditpseudo,auditread,postgres,oauth,sessions}.go`
与迁移 `0007/0013/0014`；`internal/httpapi/{server,admin_routes,audit_routes,export_routes,account_routes,identity_routes,authorization_routes,grants_routes,middleware,responses}.go`；
`internal/lifecycle/lifecycle.go`；`internal/auth/auth.go`；`internal/observability/observability.go`；
`cmd/re0auth/{main,config}.go`；`deploy/k8s/base/deployment.yaml`。

**跑了什么**（Windows 11，无 Docker / 无本地 Postgres；探针全部带 `//go:build audit7`，只新建，未改任何被跟踪文件）：

```sh
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z10adminauditprivacy/...
go vet -tags audit7 ./internal/zzprobe/audit7/z10adminauditprivacy/...
go build ./...      # exit 0
go vet ./...        # exit 0
gofmt -l internal/zzprobe/audit7/z10adminauditprivacy   # 空
```

探针目录：`internal/zzprobe/audit7/z10adminauditprivacy/`（`doc.go` 带 `//go:build !audit7`，默认套件看不见）。
夹具是**全接线真 HTTP 服务器**：`httpapi.New` + `auth.Manager` + `internal/testoidc` 真 OIDC 提供方 +
内存存储，`/auth` 流程是浏览器手柄逐跳跑出来的；端口用 18001 段之外（本区全部探针在 `httptest` 随机端口上，无固定端口冲突）。
本轮结果：**9 条 finding（CONFIRMED 5 + HYPOTHESIS 4）**；
探针 14 个测试函数：**红 5 个（含 6 条失败断言）/ 绿 5 个 / 需真库 4 个（本机 SKIP，CI 可判）**。

**范围外**：真实 Postgres 语义（假名化缓存、链校验、admin 读视图）只到源级，见「未能到达」。

---

## 发现

### Z10-1 跨实例假名缓存使抹除失效：被抹除账号的审计历史在**另一个副本**上仍然可读、可续写

- 严重度：**P2 中**
- 类别：合规/隐私
- 不变量：账号隔离 / 抹除后不可关联（`docs/architecture.md` §4.17）
- 证据（读代码到行；探针已在 CI 可红）：
  - `internal/store/postgres/auditpseudo.go:69-75`：`loadKey` **先查进程内 cache，命中即返回，根本不查库**。
    它被写路径（`subjectKey`→`loadKey`，:116）与读路径（`auditread.go:51`）同时使用。
  - `:173-187` 的 `Destroy` 只做两件事：`DELETE FROM audit_subject_keys WHERE idx = $1`，然后
    `delete(l.cache, subject)` —— **它只驱逐执行抹除的那个进程的缓存**。没有墓碑集合，没有失效广播。
  - `docs/architecture.md:652`「抹除 = 删掉 `audit_subject_keys` 里那一行。行没了，**谁都算不出**该 subject 的假名——包括本服务」；
    `:659-660`「**销毁之后**同一 subject 若再来事件…会拿到**新的** key、**不同的**假名」；
    `:661-662`「**跨进程缓存不破坏擦除**…不可关联性来自**密钥行不存在**，与缓存无关」。
    `docs/admin.md:141` 同样承诺「账号被抹除后密钥已销毁，该过滤条件解析为空 → 返回空页」。
  - 第三条断言与代码不符，而且**不需要竞态**：`deploy/k8s/base/deployment.yaml:8` 是 `replicas: 2`，两个进程共用
    一个数据库。副本 B 只要曾经为某个 subject 写过或读过一次审计（`loadKey` 把它记进 `cache`），此后
    副本 A 执行抹除并删掉密钥行，**B 的 cache 仍然持有那把 key**：B 的 `Query(Subject: usr_X)` 照旧返回该账号的全部历史，
    B 的 `Record` 也照旧用**旧假名**写新行，把抹除后的行接回旧历史。
  - 探针：`postgres_cache_test.go::TestZ10SecondInstancesPseudonymCacheSurvivesAnErasureDoneElsewhere`
    （打开两个 `postgres.DB` 句柄模拟两个副本：B 查询一次 → A `Destroy` → 断言 B 的 `Query` 返回空页、
    B 的新行假名与旧行不同）。本机无库 → SKIP；CI（`TEST_DATABASE_URL`）即可判红/绿。
- 状态：**HYPOTHESIS**（源级机制确定；缺真 Postgres 与两个句柄的运行时确认。探针已就位）
- 影响：抹除的核心承诺在**多副本部署**（出厂清单就是 2 副本）下静默失效，而抹除本身返回 200。
  泄露的是「**可关联性**」：拿到某个 `usr_…` 的人（备份、日志、`detail["actor"]` 残余）可以在副本 B 上
  按 subject 读出被抹除者的完整审计轨迹，并继续把新事件挂在同一假名下。B 的缓存不会自行过期——
  只有 `pseudoCacheMax = 4096`（`auditpseudo.go:32,147-149`）撑满时才整体丢弃，所以这不是「窗口」而是**持续状态**。
- 探针：`postgres_cache_test.go::TestZ10SecondInstancesPseudonymCacheSurvivesAnErasureDoneElsewhere`（本机 SKIP，CI 可红）
- 修法建议：最小且不依赖时序的是**墓碑集合**：`AuditLogger` 增 `destroyed map[string]struct{}`，
  `Destroy` 删除库行后写入墓碑，`remember` 拒绝记入墓碑中的 subject，`subjectKey` 在铸新 key 前先查墓碑；
  更强的是让 `loadKey` 的 cache 命中带一个短 TTL（`pseudoCacheMax` 之外再按时间失效），
  或干脆让 cache 只对写路径生效、读路径每次校验库行。**跨进程**的严格修法需要发布/失效通道
  （Postgres `LISTEN/NOTIFY` 或把 cache 降级为 per-request），这是裁定：若不修，
  `docs/architecture.md:661-662` 那句必须改成实话。
- 是否与既有编号相关：**对 AUD-5 复核结论的反驳与补充**。第五轮复核把 AUD-5 从「中」降为「低·部分推翻」，
  理由是「`Destroy` **确实驱逐缓存**」（`docs/security-audit-5.md:306`）——该理由只覆盖**单进程**。
  本条的增量正是复核漏掉的那半：**驱逐的是本进程的缓存**，而 `replicas: 2` 是出厂配置，
  且 `architecture.md:661-662` 专门为「跨进程」写了一句与实现相反的话。

### Z10-2 审计链接受**链前伪造的未签名行**：有库写权限、无审计密钥的攻击者可向日志里塞条目而 `Verify` 判 `ok`

- 严重度：**P2 中**
- 类别：安全 / 完整性
- 不变量：审计链「不能被编辑/删除/重排」（`migrations/0013_audit_chain.sql:15-28`）；A7 审计日志完整性
- 证据（读代码到行；探针已就位）：
  - `internal/store/postgres/auditchain.go:270-282`：`Verify` 把每个 `row_hash == nil` 的行在**链开始之前**
    一律计为 `Legacy++` 并 `continue`；`started` 只在遇到第一个非空 `row_hash` 时置位。
  - `migrations/0007_audit.sql:10`：`id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY`。
    `GENERATED ALWAYS` 只挡默认插入——`INSERT … OVERRIDING SYSTEM VALUE` 正是文档化用来显式给值的子句，
    所以库写攻击者可以把一行未经签名、内容任意的行放在链首**之前**（id 更小）。
  - `migrations/0013_audit_chain.sql:26-28` 把「迁移前的行」定义为「NULL 哈希的行」，**没有任何东西记录
    这些行到底有哪些**（没有 legacy 上限、没有快照 id、没有标记列）。于是「迁移前的行」与「伪造的行」
    在 `Verify` 眼里同形。
  - 0013 的威胁清单只列了编辑、链中删除、重排、整链重写、**尾部删除不可见**——**插入**不在清单里，
    也没有任何测试覆盖「链开始之前插入」。
  - 探针：`postgres_chain_test.go::TestZ10VerifyAcceptsAForgedUnsignedRowBeforeTheChainStarts`
    （写 2 行 → `Verify` 控制组 `ok/chained=2` → `INSERT … OVERRIDING SYSTEM VALUE (id=0, …)` →
    断言 `Verify` 返回 `ok=false`；当前实现会返回 `ok=true, legacy=1`。若服务器/模式拒绝显式 identity，
    探针退回「普通 INSERT 后 `UPDATE … SET id = 0`」，两条路都失败会以明确信息 Fatal）。
- 状态：**HYPOTHESIS**（`OVERRIDING SYSTEM VALUE` 与 NULL 哈希的接受面需要真库执行；本机无库 → SKIP，CI 可判）
- 影响：链的全部价值是「有库写权限的人改不了日志」。这条把它降级为「改不了已有行，但**能加行**」：
  攻击者可以植入一条 `admin.kill_switch` / `oidc.consent.deny` / `account.delete`，内容自选，
  `GET /v1/admin/audit/verify` 答 `ok:true`（只是 `legacy` 计数 +1，而升级过的库里 `legacy` 本来就不是 0）。
  若与 Z10-8（`audit_subject_keys` 不在链上）联用，还能把伪造行伪装成**指定账号**的历史。
- 探针：`postgres_chain_test.go::TestZ10VerifyAcceptsAForgedUnsignedRowBeforeTheChainStarts`（本机 SKIP，CI 可红）
- 修法建议：把「迁移前的行」变成**有界集合**：迁移 0013 已经知道当时 `max(id)`，把它写进
  `audit_chain`（新列 `legacy_ceiling_id bigint NOT NULL`，或迁移时插一行），`Verify` 对
  `id > legacy_ceiling_id AND row_hash IS NULL` 的行判 `ok=false`、`Reason="unchained row above the legacy ceiling"`。
  同时把 0013 的威胁清单补上「插入」这一项。
- 是否与既有编号相关：无（G-1…G-24 无对应项；`TestAuditVerifyRejectsAnUnchainedRowAfterTheChain`
  只钉住「链开始**之后**的 NULL 哈希行」，本条是它的镜像缺口）。

### Z10-3 关停栈 5+30+30 = **65s > grace 45s**：审计排空预算到期之前进程已被 SIGKILL，在途批次静默丢失

- 严重度：**P2 中**（失败是静默的：SIGKILL 不写任何日志 ⇒ 按简报 §6 上调）
- 类别：可用性 / 合规（审计记录丢失）
- 不变量：审计写入的持久性契约（`audit/audit.go:35-39`）；审计批次不丢（`auditbatch.go:170-176` 的意图）
- 证据（算术语义，已用会失败的命令复核）：
  - `cmd/re0auth/main.go:137` `endpointRemovalWait = 5 * time.Second`（`serveUntilSignal` 里的 `time.Sleep`）；
    `:127` `shutdownTimeout = 30 * time.Second`（HTTP `Shutdown` 的上界）；
    `internal/store/postgres/auditbatch.go:54` `auditDrainTimeout = 30 * time.Second`。
  - 顺序：`serveUntilSignal`（main.go:802-848）在**函数体里**先 sleep 再 `Shutdown`（≤30s），返回后
    `run` 的 deferred 才依次执行：`loops.Wait()`（:399-402）→ `store.close()`（:377）→
    `db.Close()`（`internal/store/postgres/postgres.go:250-263`）→ `AuditLogger.Close` → `batcher.Close` → `drain`（≤30s）。
  - 因此最坏 5 + 30 + 30 = **65s**，而 `deploy/k8s/base/deployment.yaml:26` 是
    `terminationGracePeriodSeconds: 45`；`:21-25` 的注释仍写「35s total」（只算了前两项），
    `CHANGELOG.md:108-109` 也仍写「部署方需要确保 `terminationGracePeriodSeconds ≥ 35s`」。
  - 探针（本地可跑、会失败）：`shutdown_budget_test.go::TestZ10TheWholeShutdownStackFitsThePodGracePeriod`
    解析上述四处真实数字并断言 `5+30+30 ≤ grace`：
    ```
    endpointRemovalWait=5s + shutdownTimeout=30s (HTTP drain) + auditDrainTimeout=30s (...) = 65s,
    terminationGracePeriodSeconds=45s
    --- FAIL
    ```
- 状态：**CONFIRMED**（源级算术；探针实跑红。单个批次是否真的丢掉取决于两次排空同时走满，见「影响」）
- 影响：滚动更新（`replicas: 2` + `maxSurge: 1`，每次重启都会走这条路）里，只要 HTTP 排空吃满 30s
  且审计队列还有积压，进程会在排空预算到期**之前**被 SIGKILL：仍在 `queue` 里的调用方永远等不到回答
  （`auditbatch.go:101-154` 的 `enqueue` 契约），记录丢且**无任何日志**——单测/默认套件看不见，
  因为内存模式没有 `Close` 排空问题、而 k8s 的 grace 不参与 `go test`。
- 探针：`shutdown_budget_test.go::TestZ10TheWholeShutdownStackFitsThePodGracePeriod`（**红**）
- 修法建议：三选一（裁定）：① 把 `auditDrainTimeout` 改成 `grace - removal - shutdown`（= 10s）并同步注释；
  ② 把 `terminationGracePeriodSeconds` 提到 ≥70s；③ 把审计排空**移出** `store.close()`，在 HTTP `Shutdown`
  之前用同一个 30s 预算跑（`AuditLogger.Close` 提前调用），这样总量回到 35s。
  无论选哪个，`deployment.yaml:21-25` 与 `CHANGELOG.md:108-109` 的数字必须一起改。
- 是否与既有编号相关：**对 G-12（第六轮）与 P2-31（第五轮）修复的反驳**。commit `5cd1690` 声称
  「auditbatch 的 shutdown 排空加 30s 总预算（否则 512 行 = 8×5s 顶穿 45s grace 被 SIGKILL）」——
  它把**无界**变成了有界，但 30s 仍然**叠加在** 5+30 之后，围栏外的总量没变。

### Z10-4 Kill Switch 在**没有会话端口**的部署上对 sessions 半边完全沉默：`sessions_revoked: 0` 与「该账号没有会话」同形

- 严重度：**P3 低/提示**
- 类别：可用性 / 一致性
- 不变量：fail-loud「绝不把部分清扫说成完整」（`docs/admin.md:93-104`）；
  `lifecycle.Result.SessionScoped` 为同一问题而存在（`internal/lifecycle/lifecycle.go:129-133`）
- 证据（已执行，FAIL）：
  - `internal/admin/admin.go:351-368`：`if s.sessions != nil && (target.All || target.Subject != "")` ——
    端口为 nil 时整段跳过，`Report.SessionsRevoked` 保持 0；`Report`（:167-178）里**没有**任何
    `SessionsUnavailable` 字段，`killDetail`（:462-480）也只记 `sessions_revoked`。
  - 对照：同一个 `Report` 为 bindings 的这一半**已经**有标记（:395-397 的 `BindingsUnavailable`，
    AUD-9 的修法），所以这不是「报表装不下这个区别」。
  - 探针输出（已执行，FAIL）：
    ```
    KillSwitch(all) on a deployment with no session revoker reports sessions_revoked=0 and nothing else: ...
    (report: {"tokens_revoked":7,"sessions_revoked":0,"clients_suspended":0,"flows_purged":0,
              "bindings_unavailable":true})
    ```
    同一测试控制组：`Sessions=&probeSessions{n:3}` 时 `sessions_revoked == 3`（端口真的被调用）。
  - 对 `subject` 形态更尖锐：运维读到「该账号会话数为 0」，而 `docs/admin.md:120` 说明内存模式一条会话都清不掉。
- 状态：**CONFIRMED**（已执行）
- 影响：事故响应者拿到 `{"tokens_revoked":N,"sessions_revoked":0}`，无法区分「这个账号/部署没有会话」
  与「这个部署清不了会话」。数字是对的，缺的是那个「不知道」标记——正是 `bindings_unavailable`
  在同一个响应体里刻意避免的形态，也是 `lifecycle.Result.SessionScoped` 在抹除路径上刻意避免的形态。
- 探针：`killswitch_report_test.go::TestZ10KillSwitchAllIsSilentAboutAMissingSessionRevoker`（**红**）
- 修法建议：`Report` 加 `SessionsUnavailable bool`（`json:"sessions_unavailable,omitempty"`），在
  `s.sessions == nil && (target.All || target.Subject != "")` 时置位，并让它进 `killDetail`；
  与 `BindingsUnavailable` 同款。属裁定：也可以在 `docs/admin.md` §4.2 写明「这两个目标的 sessions 半边
  只在配置了会话端口时存在，且响应不含标记」——但项目在别处明确拒绝这种沉默。
- 是否与既有编号相关：**AUD-9 修法的对应半边**（`docs/admin.md:101-104` 只覆盖 bindings 维度）。

### Z10-5 Kill Switch 的扫描失败会**丢掉已完成的摘要**：注释与 `docs/admin.md` 都承诺「摘要 + 错误」，HTTP 面只给错误

- 严重度：**P3 低/提示**
- 类别：可用性 / 可维护性（文档与实现不一致）
- 不变量：事故响应要的是数字（`docs/admin.md:106-109,125`）
- 证据（已执行，FAIL）：
  - `docs/admin.md:108-109`：「枚举失败时**返回已完成的摘要与错误**，绝不把部分清扫说成完整」。
  - `internal/admin/admin.go:388-393`：绑定扫描失败时**保留** `rep`（`TokensRevoked`/`SessionsRevoked` 已填）
    并与 error 一起返回；但 `internal/httpapi/admin_routes.go:281-282` 在 `err != nil` 分支只写
    problem+json（`internal_error`），**`report` 被丢弃**。
  - 探针输出（已执行，FAIL；`tokens_revoked=7`/`sessions_revoked=2` 已从审计行核实服务侧确有这两个数）：
    ```
    the failed Kill Switch answered {"type":".../internal_error","title":"Internal error","status":500,
    "detail":"the kill switch could not complete",...}: the counts it already cut (tokens_revoked=7,
    sessions_revoked=2, recorded in the audit row) are absent from the response, although
    docs/admin.md §4.2 promises "枚举失败时返回已完成的摘要与错误"
    ```
    控制组断言：三个端口都被调用、审计行 outcome=error 且 `detail["tokens_revoked"]=="7"`。
- 状态：**CONFIRMED**（已执行）
- 影响：一个源不可达就会让响应从「已切 tokens=7/sessions=2，bindings 失败」退化成「Kill Switch 没完成」。
  响应者无法知道已经切了多少，只能重跑（幂等，但代价是再一次上游扫描）。文档与实现不一致本身
  会让运维按错误的契约写工具。
- 探针：`killswitch_report_test.go::TestZ10KillSwitchDropsThePartialSummaryWhenASweepFails`（**红**）
- 修法建议：`handleAdminKillSwitch` 的 `err != nil` 分支把 `report` 一并写进响应
  （例如 `{"error":{...},"report":report}`，状态码保持 500），或在 `admin.Report` 上加
  `Partial bool` + 让 `Report` 随 500 一起返回；同时把 §4.2 的措辞与之一致。
- 是否与既有编号相关：无。

### Z10-6 P2-22 的修法只覆盖 `GET /v1/admin/audit`：`/verify` 与 `/head` 仍是零记录，而 verify 是**全库扫描**

- 严重度：**P3 低/提示**
- 类别：合规/隐私（谁能读到个人数据要能被回答，`audit/audit.go:1-3`）
- 不变量：「最宽的读取本身要留痕」——正是修法自己的理由
- 证据（已执行，FAIL）：
  - `internal/httpapi/audit_routes.go:121-139`：分页读之后写 `admin.audit.read`；注释明写
    「Opening this window is itself auditable: it is the widest read of personal data the service offers」。
  - `:171-193`（verify）与 `:201-211`（head）**没有任何审计调用**——verify 会遍历**每一行**链上记录
    （`auditchain.go:243-247`），比一页读宽得多。
  - 探针输出（已执行，FAIL，两条）：
    ```
    GET /v1/admin/audit/verify walked every chained row (1 covered) and left no audit record (events 2 -> 2),
    while the much narrower paged read of the same log is recorded as admin.audit.read.
    GET /v1/admin/audit/head also left no audit record (events still 2)
    ```
    控制组：同一次运行里 `GET /v1/admin/audit` 确实让事件数从 2 → 3（正对照，见 `audit_read_test.go:60-66`）。
- 状态：**CONFIRMED**（已执行）
- 影响：运维「看这个日志被动过没有」这个动作（以及读链头）在日志里不留痕，而读一页留痕。合规上
  「谁在什么时候扫了全量审计」答不出来；危害有界（verify 只返回计数与首坏 id，不返回内容）。
- 探针：`audit_read_test.go::TestZ10AuditVerifyIsNotRecordedWhileThePagedReadIs`（**红**）
- 修法建议：在 `handleAdminAuditVerify` 与 `handleAdminAuditHead` 各写一条
  （`admin.audit.verify` / `admin.audit.head`，`Detail` 只记形状与结果：`ok`、`chained`、`legacy`），
  与 `admin.audit.read` 同款；如果认为 head 不值一条，至少在 `docs/admin.md` §5.1 写明只有分页读留痕。
- 是否与既有编号相关：**对 P2-22（= 第五轮 AUD-7）修复的补充**：修法落地了 export 与分页读两条，
  漏了同一个 allowlist 上的另外两个读端点。

### Z10-7 审计读接口可以**没有写侧**地装配成功：P2-22 的两条记录在那种配置下静默变成空操作

- 严重度：**P3 低/提示**
- 类别：安全 / 加固（fail-closed 的反面：配置看起来完整，功能悄悄没有）
- 不变量：修法不可静默退化
- 证据（已执行，FAIL）：
  - `internal/httpapi/server.go:146-149`：`AuditLog` 是可选字段，注释自述「a nil logger records nothing」；
    `:297-304` 的校验只要求 `Config.Audit` 需要 `Sessions` 与非空 `Admins`（理由是「读日志就是读所有账号」），
    **不要求写侧存在**。
  - `internal/httpapi/audit_routes.go:19-21`：`recordAudit` 在 `s.auditLog == nil` 时直接 return。
    于是 `Config.Audit != nil, Config.AuditLog == nil` 这一组配置下，`admin.audit.read` 与
    `account.export`（`export_routes.go:106`）两条记录**永远不会发生**，而 `httpapi.New` 返回 nil error。
  - 探针（已执行，FAIL）：`config_test.go::TestZ10TheAuditReadRecordsAreAcceptedWithNoSinkToWriteThem`。
- 状态：**CONFIRMED**（已执行）
- 影响：组合根（`cmd/re0auth/main.go:561,610,673`）总是把同一个 logger 同时接到三个位置，所以**当下不咬人**；
  但这是一个「加上去就掉」的失效模式：任何一处装配漏了 `AuditLog`，P2-22 的修法会**静默**回到修前状态，
  而现有测试（`audit_routes_test.go` 用 stub reader + 显式 logger）看不出来。
- 探针：`config_test.go::TestZ10TheAuditReadRecordsAreAcceptedWithNoSinkToWriteThem`（**红**）
- 修法建议：`httpapi.New` 增加 `if cfg.Audit != nil && cfg.AuditLog == nil { return error }`
  （与 `Config.Audit requires Config.Admins` 同款）；或让 `recordAudit` 在 nil logger 时
  `slog.Error`（至少不静默）。前者更符合项目「配置错就拒绝启动」的既有做法。
- 是否与既有编号相关：**对 P2-22 修复的补充**（修法本身正确，但缺一条与它配套的配置断言）。

### Z10-8 `admin.*` 审计行把 **client_id** 假名化，且 `Detail` 里没有补偿字段：读接口答不出「哪个客户端」

- 严重度：**P3 低/提示**
- 类别：合规/隐私 / 可维护性
- 不变量：审计日志要回答「谁对什么做了什么」（`docs/admin.md:127-129` 明写 `Subject` = 被操作的客户端/账号）
- 证据（读代码到行；探针已就位）：
  - `internal/admin/admin.go:439-447` 的 `auditSubject()` 对 client 目标返回 `clientID`；
    `Register/RotateClientSecret/SuspendClient/ActivateClient/DeleteClient` 也把 clientID 当 Subject。
  - Postgres sink 的 `Record`（`postgres/audit.go:70-76`）把**任何非空 subject**都换成假名
    （`pseudonymize` → `auditpseudo.go:156-165`），于是 `audit_events.subject` 里存的是
    `HMAC(每-subject key, …)` 的 16 字节 base64，**不是 client_id**，而且**没有任何抹除步骤**会销毁
    client 的这把 key（`lifecycle` 只销毁账号的）：所以这里的假名化**不产生隐私收益**，只让读侧失去信息。
  - 补偿字段也不存在：`SuspendClient` 的 Detail 是 `{"actor","tokens_revoked"}`
    （admin.go:271-273）、`Register` 是 `{"type"}`（:240-242）、`Rotate/Activate` 是 nil（:256,280）、
    `Delete` 是 `{"tokens_revoked"}`（:289-291）。对比 `oidc.token` 事件把 `client_id` 放进 Detail
    （`store/postgres/oidc.go:122-130`）。
  - 探针（已就位）：`postgres_admin_view_test.go::TestZ10AdminActionRowsDoNotSayWhichClientTheyAreAbout`
    （经真实 `admin.Service` + 真 Postgres sink 暂停一个客户端，然后 `Query(Action:"admin.client.suspend")`，
    断言该行的 `Detail["client_id"]` 能说出是哪一个）。本机无库 → SKIP。
- 状态：**HYPOTHESIS**（需要真 Postgres 才能观察到假名化后的读视图；本机无库）
- 影响：`GET /v1/admin/audit?action=admin.client.suspend` 返回的 `subject` 是每个人一条不同的
  base64 假名，运维从列表里看不出「被暂停的是哪个客户端」；只能猜 client_id 再 `?subject=` 逐个查询。
  同族问题第六轮已记为 G-17（PG 设备审核事件缺 `client_id`）——本条是 **admin 面**的同一种缺失。
- 探针：`postgres_admin_view_test.go::TestZ10AdminActionRowsDoNotSayWhichClientTheyAreAbout`（本机 SKIP，CI 可红）
- 修法建议：给每个 `admin.*` 事件的 `Detail` 补 `client_id`（`oidc.token` 已有先例），
  或让 `AuditLogger` 对**非账号** subject（`cli_…`）不做假名化——但后者会改 `Subject` 列的语义，
  属裁定，前者最小。
- 是否与既有编号相关：与 G-17 同类不同面（G-17 是设备事件，本条是管理面事件与读视图）。

### Z10-9 `Verify` 不校验链头与最后一行一致：链头指向一个**任何行都不拥有**的哈希时，完整性检查仍答 `ok`

- 严重度：**P3 低/提示**
- 类别：安全 / 完整性
- 不变量：链头是「链推进到哪」的见证（`auditchain.go:234-241`），也是外部锚点要发布的值
- 证据（读代码到行；探针已就位）：
  - `auditchain.go:238-241` 读 `head_hash` 作为「至少写过链」的见证；
    `:318-328` 只在 `v.Chained == 0 && len(head) != 0` 时判失败。
    遍历过程中**从不把最终 `prev` 与读到的 `head` 比较**。
  - 于是 `UPDATE audit_chain SET head_hash = <任意值>` 之后，`Verify` 返回 `ok:true`（`Chained>0`
    使那条守卫短路），而 `Head()` / `GET /v1/admin/audit/head` / `anchorLoop` 的小时行
    （`cmd/re0auth/main.go:410`）会发布一个表里没有的哈希。
  - 探针（已就位）：`postgres_chain_test.go::TestZ10VerifyDoesNotCheckTheHeadAgainstTheLastRow`
    （写 3 行 → 控制组 `Head` 非空 → 植入随机 head → 断言 `Verify` 返回 `ok=false`）。
- 状态：**HYPOTHESIS**（需要真库执行；本机无库 → SKIP，CI 可判）
- 影响：有界——下一次 append 会以这个假 head 为前驱，之后的 `Verify` 会以
  `prev_hash does not match` 报错，外部锚点核对（`docs/operations.md` 的 runbook）也能发现。
  但在「篡改发生」与「有人发现」之间的窗口里，服务自己的完整性检查答 `ok`，而它答 `ok` 的对象
  正是运维唯一会看的那个端点。与尾部截断不同（那是文档化的边界），这一条**不需要外部锚点就能判**，
  却没人判。
- 探针：`postgres_chain_test.go::TestZ10VerifyDoesNotCheckTheHeadAgainstTheLastRow`（本机 SKIP，CI 可红）
- 修法建议：遍历结束后断言 `bytes.Equal(prev, head)`（`prev` 为最后一行 `row_hash`），
  不一致即 `ok=false` + `Reason="the chain head does not match the last row"`；
  同时把「链头被指向不存在的位置」写进 0013 的威胁清单。
- 是否与既有编号相关：无（第六轮 G-12 之外的链完整性项未覆盖此形状）。

---

## 探过但没破的（也应变成守卫）

1. **允许列表是精确比较，不吃大小写/空白/前缀**：`admins` 换成真实 id 的
   `大写 / 前导空格 / 尾随空格 / 加后缀 / 去掉末字符` 五种近失，真管理员一律 `404`；
   同一请求在允许列表含真 id 时 `200`（正对照）。
   `allowlist_test.go::TestZ10AdminAllowlistIsAnExactMatchNotACaseFoldOrPrefix`（**绿**）。
2. **全部 10 条管理路由 × 三类人群都过闸**：匿名 → 全部 401；已登录非管理员 → 全部
   `404` 且 body 是 `unknown resource`（与不存在的路径同形，`docs/admin.md:27` 成立）；
   操作员 → `GET` 的 4 条全部 200（正对照，证明路由确实挂载）。
   `allowlist_test.go::TestZ10EveryAdminRouteIsShutToAnonymousAndNonAdmins`（**绿**）。
   同一条测试里记录的**上下文**（不是本轮的 finding，见「判断」）：匿名 `PUT /v1/admin/clients` = 405
   且 `Allow="GET, HEAD, POST"`——第五轮 AUD-4，至今未修。
3. **审计读取的留痕不含被查值**：`?subject=usr_victim…&action=oidc.token` 之后，
   `admin.audit.read` 的 `Subject` 是操作员、`Detail` 里没有该 `usr_`、也没有被查的 action
   （只记 `subject_filter`/`action_filter` 形状）。
   `audit_read_test.go::TestZ10AuditReadRecordCarriesNoQueriedSubject`（**绿**）。
4. **指标标签有界且不含身份**：在真 scrape 端点里，一个 40 字符的自造方法被塌成
   `method="other"`；暴露里不出现 `X-EVIL`、不出现 `usr_`（正对照：暴露里确实有
   `re0auth_http_requests_total`，所以不是空扫）。
   `metrics_export_test.go::TestZ10ExportedMetricsHaveBoundedLabelsAndNoAccountIdentity`（**绿**）。
5. **导出没有表格势阱、不跨账号、不可缓存**：`Content-Type: application/json`（无 csv）、
   `Content-Disposition: attachment`、`Cache-Control: no-store`、`notice.credentials_excluded=true`、
   响应体中 `usr_` 恰好出现 1 次（调用者自己的）、不含另一个账号的 id。
   `metrics_export_test.go::TestZ10ExportIsAJSONDocumentWithNoSpreadsheetSink`（**绿**）。
   ⇒ 简报里点名的「CSV 注入 / 字段溢出 / 分页逃逸」在本仓库**没有可注入的表格 sink**，导出是纯 JSON 单文档。
6. **canonical 编码无歧义**（读码）：`auditchain.go:56-91` 对每个字段做 4 字节大端长度前缀
   （`writeLenPrefixed`），detail 键排序后连**键数量**一起编码；时间戳归一到
   `UTC().UnixMicro()` 并与 `Record` 的 `Truncate(time.Microsecond)`（`audit.go:60-63`）一致。
   `(a="ab",b="c")` 与 `(a="a",b="bc")` 这类边界无法编码同形。无域名标签也会与其它 HMAC 用途撞车，全集已分离
   （`auditpseudo.go:17-21`）。
7. **链头并发/批次丢失方向正确**（读码）：`appendBatch` 在一个事务里 `SELECT … FOR UPDATE` 锁链头
   （`auditchain.go:151-155`），整批 INSERT 后推进 head，**任一行失败则整批回滚**，每个调用方都拿到该错误
   （`auditbatch.go:237-239`），不会出现「部分成功却报成功」。
8. **`MemoryLogger` 是有界环形**（读码）：`audit/audit.go:143-158` 满载后覆盖最旧，`Events()` 按时间序还原；
   内存模式不承担生产保证（ADR-0006），且启动时 `slog.Warn` 声明不持久（`main.go:384`）。
9. **审计读取的分页钳制在真读者里**（读码）：`auditread.go:29-35` 把 `limit` 钳到 1000、
   `:92-97` 的分配量按**默认页**而非请求值定容，`:110-114` 用「多取一行」判定下一页。
   本机无法用真读者执行（无库），故只到行。
10. **Kill Switch 的三种过滤形态都真的清掉了能力型中间态**（读码 + 第五轮已有覆盖）：
    `admin.go:326-332` 先停用再删令牌；`:404-413` 的 `subject` 会清在途 bind flow；
    `:378-397` 的绑定半边保留 `bindings_unavailable` 标记（AUD-9 的修法在）。
11. **`Destroy` 幂等、空 subject 拒绝**（读码）：`auditpseudo.go:173-176`。
12. **组合根对「持久化但无假名销毁能力」直接拒绝启动**（读码）：
    `cmd/re0auth/main.go:649-659`（AUD-6 的修法②已落地），`Result.PseudonymDestroyed` 也已存在
    （`lifecycle.go:139,262-283`）。

## 未能到达（残余盲区）

1. **一切 Postgres 运行时语义**：本机无 Docker / 无本地 Postgres，所以 Z10-1、Z10-2、Z10-8、Z10-9
   只到源级。四条探针已写好并且**在 CI 的 `postgres:16` 上会给出红/绿定论**：
   ```sh
   TEST_DATABASE_URL=… go test -tags audit7 -count=1 -p 1 ./internal/zzprobe/audit7/z10adminauditprivacy/...
   ```
   （必须**单独跑这一个包**：它会 `TRUNCATE audit_events, audit_chain, audit_subject_keys`，
   与 `internal/store/postgres` 的集成测试并发会互相破坏。）
2. **多副本的真实进程实验**：Z10-1 的探针用「两个 `postgres.DB` 句柄」建模两个进程；
   真正的多进程验证（两个 `re0auth` 进程 + 一个库 + 一次抹除）本机做不到（需要 Docker/编排）。
3. **k8s 的 SIGKILL 行为**：Z10-3 是算术与调用顺序的结论（源级 CONFIRMED），
   真机「SIGKILL 丢掉仍在队的批次」需要一个集群与一个慢库，本机不可达。
4. **`RE0AUTH_AUDIT_KEY` 的真实配置与轮转**：未提供环境；第六轮区 03 的
   `zz_audit_keyrotation_test.go` 已覆盖「换 key 使历史假名全部失联」，
   本轮不重复，只看它与抹除/读视图的交互（未发现新形状）。
5. **管理前端 `/app/admin`**：本轮证据全在 Go 侧；Svelte 侧的权限判断与展示（例如它是否提示
   `bindings_unavailable` / 是否展示假名）未审，属前端区域。
6. **备份/SIEM 管线**：审计内容落到库外的副本如何处置、锚点核对在真实日志管线里的执行，
   本仓库内无法回答（runbook 有步骤，无法执行）。
7. **`-race`**：本机可跑（CGO/gcc 在位），但本区没有并发改写共享状态的探针；
   Z10-1 的跨进程缓存问题不是数据竞态，`-race` 也不会报。

## 判断（文档化决定可否质疑，不是 finding）

1. **AUD-4（未声明动词 405 + `Allow`）在 HEAD 上仍未修**。`docs/admin.md:27` 与
   `docs/openapi.yaml` 仍承诺「已登录但不在列表里的账号访问 `/v1/admin/*` 得到 404，与不存在的路径毫无区别」，
   而实测匿名 `PUT /v1/admin/clients` 得 `405 Allow="GET, HEAD, POST"`、
   `PATCH /v1/admin/audit` 得 `405 Allow="GET, HEAD"`（本报告「探过但没破」第 2 条的 `t.Logf` 输出）。
   它是第五轮已收录项（AUD-4），**按简报 §5 不重报**；这里只登记两件事：
   ① 第七轮确认它仍然存在；② 它同时是**文档与实现的持续漂移**（第五轮给出的修法 (b)「接受泄露并改文档」
   没有执行，所以文档今天是在说谎）。若项目选择接受该泄露，最小动作是改 `docs/admin.md:27` 与 openapi 那句话。
2. **第六轮 z07 的抹除记录探针（`internal/zzprobe/audit6/z07authsession/erasure_audit_test.go`）在 HEAD 上仍红**：
   `lifecycle.DeleteAccount`（`lifecycle.go:262-283`）在**销毁假名密钥之前**就写了
   `account.delete`，且写的是 `outcome=ok` + `pseudonym_destroyed=true`
   （`res.PseudonymDestroyed = d.cfg.Pseudonyms != nil`，:262——此刻销毁还没发生）；
   随后 `Destroy` 失败只把返回值的字段重置为 false（:279），**不再写第二条记录**。
   于是一次「历史仍可关联」的抹除在**持久记录**里长成一次干净的成功，而 HTTP 500 的文案却说
   「审计日志记录了失败的那一步」（`account_routes.go:62-63`）。
   这是对 AUD-2 / P2-2 修复的**补充**（文案改了，记录没改），但第六轮已有同形探针与同形论证，
   按「不许重报」不列为本轮 finding。修法：把 `account.delete` 的写入移到 `Destroy` 之后
   （代价是它对已销毁的 key 写不了——所以更合适的是让失败路径追加一条
   `account.delete` + `outcome=error` + `failed_at="pseudonym"` 的记录，且新记录不得触发铸新 key）。
3. **内存模式清不掉会话**（`main.go:679-685` 的启动警告）是文档化边界；
   AUD-10（存活会话 = 存活运维权限）第五轮已收录，本轮不重报。
   顺带记录：它在本轮的真进程/夹具里依然可达（allowlist 只看会话，不看账号行是否还在），
   修法仍是 `requireAdmin` 里补一次账号存活查询。
4. **`admin.*` 的 `detail["actor"]` 记操作员原始 `usr_`**：已裁定（企业审计合规），
   `docs/admin.md:129` 与 openapi 都写明，本轮不重报。Z10-1/Z10-2 只是把它当**放大条件**引用
   （它给「拿到某个 `usr_…`」提供了一处现成来源）。
5. **`audit_subject_keys` 不在链上、其内容不受签名保护**（第六轮区 03 的
   `internal/store/postgres/zz_audit_keyrotation_test.go::TestAuditSubjectKeyRowIsOutsideTheChain` 已证）：
   替换一个 subject 的 key 行会让读侧 `?subject=` 返回空页，而链仍 `Verify` 通过。
   本条与 Z10-2 组合能把伪造行伪装成指定账号的历史；因第六轮已收录该机制，本轮不单列，
   只在 Z10-2 的影响里引用。
6. **尾部截断不可检测（无外部锚点）**：`migrations/0013` 与 `docs/architecture.md` §4.16 明写的边界，
   本轮不重报；Z10-9 是**另一个**形状（链头与末行不一致，不需要外部锚点就能判），故单列。
