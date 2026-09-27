# 复核：`admin-audit-privacy.md`（管理面 / 审计 / 抹除 / 隐私）

> 复核者角色：**证伪**。原报告 12 条（AUD-1…AUD-12），逐条攻击；另对「探过但没破」的 16 条做了 9 条抽查。
> 本机：Windows 11，无 Docker、无本地 Postgres。Postgres 结论一律「读；无 DB 执行」。
>
> **流程性说明（必须先说）**：任务指定的 `docs/audit-5/BRIEF.md` **在本树里不存在**
> （`Get-ChildItem -Recurse -Filter BRIEF*` 全树无命中，`docs/audit-5/` 下只有 `VERIFY-BRIEF.md`、
> `findings/`、`probes/`、`runtime/`）。因此我**无法**核对共享简报 §「哪些是文档化决定」的那张清单，
> 只能自己去 `docs/` 与代码注释里找。这会损失一类判据（见「我未能验证的」）。
> 我没有修改任何被跟踪文件，也没有改动原报告与任何别人的探针。

---

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|---|---|---|---|---|
| AUD-1 | 中 | **中** | **CONFIRMED（支点需修正）** | 「静默吞掉、两个方向都没选」属实且已执行；但「违反 I3」是推论（I3 成文只覆盖 `vault.Use`），真正的支点是 `audit.Logger` 契约「返回 nil = 可以继续」+ 项目已在三处选定方向而此处一个都没选 |
| AUD-2 | 中 | **中（限持久化部署）** | **部分成立** | 顺序与「it is safe to try again」逐字属实、401 复现属实；但只成立于 durable 部署，且范围应扩到**倒数第二步**（`record` 失败同样不可重试，而它的注释声称可重试） |
| AUD-3 | 中 | **低-中** | **部分成立** | 「同意决策无审计」全路径枚举属实；但「谁同意」这半不成立——`subject` 恒等于 approver（`authorization_routes.go:160` 传的就是会话 `user`）。真正缺口是 **scope 集**与**被拒绝的请求** |
| AUD-4 | 低 | **低** | **CONFIRMED（属已有裁定类）** | 44/44 已执行复现，`docs/admin.md` §0 的 404 承诺确实被绕过；但同一漏出对**匿名者**也成立，与 `security-audit-3.md:295-296` 已接受的「匿名可探测运维面」同类，增量只有「非管理员 + 方法集」 |
| AUD-5 | 中 | **低** | **部分推翻** | 机制被推翻：`Destroy` **确实**驱逐缓存（`auditpseudo.go:183-185`），顺序路径会铸新钥；只有 submicrosecond 竞态能复活缓存，后果还受进程生命期限制。**但**它要证明的那件事以另一条**确定性**路径真的发生（见 V-1） |
| AUD-6 | 低 | **低** | **部分成立（后半推翻）** | 守卫看不见 `audit_subject_keys` 属实；但「可选端口」是**有意的测试缝**（`lifecycle_test.go:425`「a nil Pseudonyms port should be fine」+ `main.go:612-613` 文档化 nil），不是缺陷 |
| AUD-7 | 低 | **低** | **CONFIRMED** | 代码枚举属实；探针含反空转对照且已执行 FAIL |
| AUD-8 | 低/假说 | **低** | **部分成立（保留为残余）** | 端口不对称是事实；报告自己承认持久会话下大概率不可利用，那就该进「残余盲区」而不是发现栏 |
| AUD-9 | 低 | **低** | **CONFIRMED** | `admin.go:292-294` / `:345` / `:151` 逐行属实，报告与实现一致 |
| AUD-10 | 低 | **低** | **部分成立（范围需修正）** | 无持久会话部署已被启动警告文档化；但「存活会话 = 存活运维权限」这半确实没文档化，增量成立。**另：它不止于内存模式**（见 V-3） |
| AUD-11 | 低 | **低** | **CONFIRMED（读；无探针）** | `docs/admin.md` §1/§5.1 确实各缺一条，`openapi.yaml` 两条都有（1225/1518）——漂的是 Markdown，不是 spec |
| AUD-12 | 提示 | **提示** | **CONFIRMED（读；无执行）** | `tapsign/client.go:200` 确以 `cred.ObjectID`（TapTap openid）为 `Subject` |

**小结**：0 条完全推翻，1 条机制被部分推翻（AUD-5），3 条需降级或改述（AUD-3、AUD-5、AUD-6 后半），
其余结论成立。**没有任何一条是纯读代码冒充 CONFIRMED**——报告对「读」与「已执行」的标注经抽查是诚实的。

---

## 2. 降级 / 改述 / 推翻的理由

### AUD-1 —— 结论成立，但我要求换支点（原报告用 I3，站不住）

**先确认事实（这部分报告没错）**：
- `internal/store/memory/oidc.go:313-321` 与 `internal/store/postgres/oidc.go:122-130` 的 `record()` 都是
  `_ = s.audit.Record(...)`，**没有返回值、没有 `slog`**。调用点数量我逐条数过，与报告一致：
  内存 8 处（436、514、576、595、607、996、1017、1136），Postgres 8 处（283、376、446、466、482、789、810、930）。
- **没有指标兜底**：全树 `ObserveAudit*` 只有两个——`ObserveAuditAppend`（`observability.go:423`，**耗时直方图**）
  与 `ObserveAuditVerify`（`:431`，链校验结果）。`docs/observability-decision.md` 也只列 `audit_verify_total`。
  所以「无错误、无日志、无指标」三者同时成立，报告这句不是夸大。
- 探针的反空转对照是真的：同一个 `zzAdmFailingLogger` 交给 `vault.Service.Enroll` 时**确实**失败
  （`zzprobe_adminplane_test.go:349-351`），所以「静默」不是因为 logger 没坏。

**被夸大的部分**：报告主张「违反 I3 先审计后 emit」。但 I3 的**成文范围**是 `vault.Use`：
`docs/architecture.md:140`「I3：`Use` 在把明文交给回调**之前**先落审计」，
`:687` 的 I3 测试表只列 `vault` 与 `tapsign`。而 `:674` 那句 `I3 先审计后 emit` 是同一句话的总纲。
把「签发一个**可撤销**的 access token」（I4 有补偿）算作 emission 是**报告的推论**，不是文档的裁定。

**站得住的支点（我用它替换）**：
1. `audit/audit.go:35-39` 的契约原文是「Implementations must not return until the event is durably
   persisted; **returning nil means "safe to proceed"**」。吞掉错误就是让调用方在**没有拿到那个 nil** 的情况下
   照常继续——这是**契约违反**，不需要 I3 帮忙。
2. 项目对「审计失败怎么办」已经选定过**三次**方向，且都写进了文档：
   - fail-closed：`vault`（`architecture.md:140`）、`lifecycle`（`:610`「审计失败即失败」）、
     **`tapsign`（`tapsign/client.go:203-208` 把审计错误 join 进返回值——报告漏了这一处）**；
   - 记录并继续：`admin`（`admin.md:120`、`architecture.md:591`）、`auth`（`auth.go:206-209`，
     `:218` 的 `slog.Error("auth audit record failed", …)`）。
   OP 存储层是**唯一一个两个方向都没选**的地方。这才是本条的实质：不是「选错了方向」，而是**没选**。
   这条论证不依赖任何推论，且报告自己的「不变量/性质」一行写的正是它——建议把结论行与证据行对齐。

**严重度：维持中。** 失败是静默的（调用方 200、日志空、指标 0），按 VERIFY-BRIEF §3 的判据这要**升**；
但触发前提是「审计写失败」（DB 抖动）而不是攻击者可控——虽然报告举了「制造链头锁争用」这条路，
那属于能力型前提，不是任意攻击者。中是对的。

**一处应加的边界（不改结论）**：内存 store 在 436/996/1017 用的是 `context.Background()`，
所以「ctx 取消导致丢记录」这条不成立于内存模式；Postgres 侧传的是真 ctx。

---

### AUD-2 —— 成立，但只是持久化部署，而且范围少算了一步

**属实**：顺序（sessions `:209-216` → 账号行 `:242-244` → `record` `:250-252` → `Destroy` `:258-263`）与
错误文案逐字对上：`account_routes.go:59` 就是 `"the account could not be erased; it is safe to try again"`。
夹具也不是产物：`zzAdmDestroyingSessions` 的替身对象正是 `postgres.Sessions.RevokeSubjectSessions`
的忠实模型——我读了实现（`internal/store/postgres/sessions.go:186-188`），它删的确实是
`session_subjects` 里该 subject 的**全部**会话，调用方那一条在其中。

**三点必须加的边界**：
1. **只限持久化部署。** 内存模式下 `lifecycle.Config.Sessions` 为 nil（`main.go:607` ← `store.sessionRevoker`
   为 nil，`:621` 为此专门打警告），`Pseudonyms` 也为 nil（`:612-613` 明说内存模式的 sink 不存密钥）。
   所以内存模式**没有**这一步可失败，也没有会话被清掉——报告未写明此条仅 durable，读者会以为普适。
2. **范围应扩到倒数第二步。** `lifecycle.go:246-249` 的注释自称：「the account row is already gone,
   but the caller can retry, DeleteUser is idempotent, and the retry will produce the record」。
   在持久化部署下**这是错的**：第 4 步就把该 subject 的全部会话删了，第 7 步账号行也没了，
   所以 `record` 失败（第 9 步）与 `Destroy` 失败（第 10 步）**同样**不可重试。
   报告只盯住了最后一步，把一个成文于注释的错判漏掉了（见 V-2）。
3. **「不可恢复」要分档。** 用户侧确实没有任何路径（会话没了、账号没了、identity 没了，无法重新登录）。
   运维侧**理论上有**：`postgres.AuditLogger.Destroy(ctx, subject)` 是导出的，运维拿得到库。
   缺的不是能力而是**入口**：全树没有 `destroy-pseudonym` 之类的 CLI（grep 无命中），
   `docs/operations.md` 里对「抹除残留」零命中（grep `残留|无法重试|erased` 无结果）。
   所以准确定性是「**只有知道 usr_ 且能写库的运维能手工补救，而 usr_ 在抹除成功后几乎无处可取**」
   ——报告写的「仓库里也没有运维侧工具」是准确的，但「恢复到不了」应说成「没有实现路径」而不是「不可能」。

**严重度：维持中。** 残留是永久的、静默的（HTTP 只说「可以再试」），且这台 subject 的审计史永远可关联。
唯一让我没往上抬的是：要发生必须**恰好**在最后一步出 DB 错误，而这需要一次真实的写失败。

---

### AUD-3 —— 成立，但「经谁同意」这半是空的，真正的缺口是 scope 与拒绝

**缺失属实，我做了独立枚举（不是转述）**：
- `internal/oidchttp` 全包 grep `audit|Audit` → **只在测试文件里命中**，生产代码零依赖；
- `authorization_routes.go` grep `audit|Audit` → **零命中**；
- `CompletionLogin` 的实现（`memory/oidc.go:932`、`postgres/oidc.go:741`）都是纯状态改写，无审计；
- 两个 store 的 `record()` 调用点全集是
  `{oidc.token, oidc.revoke, oidc.grant.revoke, oidc.device.approve, oidc.device.deny}`——**确无同意决策**。

**报告被削弱的一半**：它写「运维无法回答『这个 client 是什么时候、**经谁**同意、拿了哪些 scope』」，
并把「谁做的决定」当成缺失的一半。但在这个 OP 里 **approver 恒等于 subject**：
`authorization_routes.go:160` 传进去的 `subject` 就是会话里的 `user`，`oidchttp.go:1288` 原样交给
`CompleteLogin`。没有委派、没有代批，所以「经谁同意」不存在信息缺口。

**真正的缺口（也是我维持低-中的理由）**：
1. **scope 集不在任何审计行里**。`oidc.token` 的 `Detail` 只有 `{"client_id": …}`（两个 store 的 `record()` 同形），
   所以「这个账号给这个 client 授了哪些 scope」在日志里查不到；
2. **被拒绝的请求完全无痕**。`DenyAuthorization` 只 `DeleteAuthRequest`（`oidchttp.go:1309`），
   用户事后主张「我没批准过」时，日志里正反两面都空；
3. **替代记录只有一半**：`oidc.token` 能回答「哪个 client 拿到过令牌、什么时候」（client 有、时间有、scope 无），
   `Grants()` 能回答当前的 client+scope（但那是**状态**不是日志，且令牌一撤就没了）。
   所以报告「签发侧有 `oidc.token` 作为部分补偿，危害有界」的自评是**准确且克制**的。

**严重度：中 → 低-中。** 我下调的理由是「替代记录覆盖了 client 与时间，缺的是 scope 与拒绝」，
而不是报告说的「授权的瞬间完全不在日志里」。修法建议（在 `oidchttp` 的批准/拒绝两个出口各写一条）**不受影响**，
照做即可。

---

### AUD-4 —— 复现属实，但它属于已被裁定的那一类，不是新类

**机制属实**（读 + 执行）：`server.go:611-661` 的 `businessPlane()` 在**内层 mux** 就按方法分派：
`:649-656` 未声明动词直接 `405 + Allow`，**任何 handler 都没跑**，因此 `requireAdmin`
（`admin_routes.go:57-72`，非管理员答 404）根本执行不到。执行输出逐条对上：

```
zzprobe_adminplane_test.go:154: wrong-verb leak on 44 undeclared-verb probes
    PUT /v1/admin/audit = 405 Allow="GET, HEAD" for a signed-in NON-admin
    PUT /v1/admin/clients/{client_id} = 405 Allow="DELETE"
--- FAIL: TestZZAdmWrongVerbAdvertisesTheOperatorPlaneToANonAdmin
```
反空转对照也在同一次运行里：已声明的动词对非管理员全部 `404 unknown resource`（9 个 pattern 全覆盖），
对操作员全部到达 handler（200/400/204）。所以漏的是「未声明动词」这条独立路径，**不是 gate 失效**——
报告这点说对了。

**我加的两条限定**：
1. **匿名同形。** mux 之前没有任何鉴权中间件（`return recoverBusiness(s, withNoStore(mux))`，`:661`），
   所以**未登录**调用者同样拿到 `405 + Allow`。这意味着它和
   `docs/security-audit-3.md:295-296`「未认证的 `/v1/admin/*` 返回 401 而非 404…保持现状」是**同一类**：
   项目已经接受过一次「匿名者可确认本部署有运维面」。增量只有两点：对象是「设计上明确要瞒住的那类人」，
   以及 `Allow` 连方法集合一起给。**所以这是与 `docs/admin.md` §0 的文档不一致，不是新的泄露类别**——
   报告在「判断」一节里其实也这么说了，但发现正文的措辞（「管理面被广告给本不该看见它的人」）
   读起来像一个新漏洞。建议正文就照「判断」那节的口径写。
2. **`Allow` 给的是方法集，不是「完整攻击面」**。观察到的是 `GET, HEAD` / `POST` / `DELETE` 三态，
   没有路径级信息、没有参数、没有数据。低是准确的，不要抬。

**严重度：维持低。** 修法建议 (a)（把 gate 提到分派之前）与 (b)（改文档）我都不反对；
补一句：选 (b) 时 `plane_test.go` 那条「未声明动词一律 405」的守卫会**主动阻止**你回头选 (a)，
这话报告也说了，是对的。

---

### AUD-5 —— **机制部分推翻**；但同一件事以一条确定性路径真的发生（V-1）

这条是报告最重的一条（中，声称击败抹除保证），也是我攻击最狠的一条。

**先看代码事实**（`internal/store/postgres/auditpseudo.go`）：
- `loadKey:69-75` 确实**先查缓存、命中即返回、不查库**——报告引对了；
- **但 `Destroy:173-186` 的最后三行是**：
  ```go
  // Drop the cached copy too: a warm cache would keep pseudonymising the subject
  // after the row that justifies it is gone.
  l.mu.Lock()
  delete(l.cache, subject)
  l.mu.Unlock()
  ```
  **`Destroy` 确实驱逐缓存。** 所以报告标题给人的那种读法——「销毁之后写仍产出旧假名」——
  **在顺序情形下是错的**：销毁后的第一次写会 cache miss → `SELECT` → `ErrNoRows` →
  `subjectKey:121-142` **铸一把新 key** → 新假名。既有 DB 测试
  `internal/store/postgres/auditpseudo_test.go:232-244`（`TestAuditPseudonymisesSubjectAndUnlinksOnDestroy` 尾段）专门断言这一点：
  「a write after the destroy reused the destroyed pseudonym」若成立就 Fatal。
  也就是说**顺序路径是被测试钉住的、设计正确的**。

**报告的两条「后果」里有一条是无害的**：它说「该 goroutine 自己那次 `Record` 会在销毁之后用旧假名落一行」。
即使发生，那一行描述的是**销毁之前**发生的事件，用旧假名是**正确**的（销毁前的行都共用一个假名）。
真正算缺陷的只有「**之后新产生的**事件继续用旧假名」这一条。

**唯一能造成后果的交错需要**：某个 goroutine 已经过了 `loadKey:69-75` 的 cache miss、
`SELECT` 在 `Destroy` 的 `DELETE` **提交之前**返回并拿到旧 key，而它的 `remember(subject, key)`（`:89`/`:140`）
落在 `Destroy` 的 `delete(l.cache, subject)`（`:184`）**之后**。从 `Scan` 到 `remember` 只隔
`checkSubjectKey` 与一次 mutex，是**亚微秒**级的窗口——真的存在（可能被抢占），但前提很刁钻，
按 VERIFY-BRIEF §3 属于「前提刁钻 ⇒ 降级」。
**后果还被两件事限制**：(a) 缓存是**进程内**的，进程一重启，密钥行确实没了，保证自动恢复——
报告写「会把失败变成**持续**的」应改成「持续到进程重启」；(b) 需要一条「抹除后仍为该 subject 写审计」的路径，
而抹除清掉了会话、令牌、OIDC 状态、绑定，所以只剩「抹除期间并发在途的请求」这一种。

**严重度：中 → 低，并移入残余（或按报告建议的方式在 CI 里钉住）。** 理由是它是一段需要 Postgres + 精确交错
才成立的窗口，而**它想证明的那个结果用不着竞态**——见 V-1。

---

### AUD-6 —— 前半成立，后半是**有意的测试缝**（推翻）

**前半成立**：`audit_subject_keys` 的列只有 `idx` 与 `key`（`migrations/0014_audit_pseudonyms.sql`），
两个守卫的判据都是「列名等于 `subject`/`user_id`」，所以它**结构性**看不见；探针复用的还是真守卫的
代码路径，输出也对上（`14 account-linked tables found`）。这条我接受。

**后半「可选端口是缺陷」我推翻**，证据是设计自己的话：
- `internal/lifecycle/lifecycle_test.go:425` 明写「**a nil Pseudonyms port should be fine**」——
  这是一个**被测试承认**的合法配置；
- `cmd/re0auth/main.go:612-613` 明写「It is nil in memory mode, where the log is a ring buffer that keeps no keys」
  ——nil 分两种：**内存模式（正确且文档化）**与**durable 模式接线错误（危险）**；
- `pseudonymStore:1379-1384` 的注释解释了为什么用类型断言而不是按存储模式分支：
  「Asking for the capability rather than branching on storage mode keeps that difference where it belongs
  — in the sink」。这是**有理由的设计**，不是随手写的可选参数。

**所以正确的表述是**：「一个 durable 部署如果接线丢失，抹除会静默成功而什么都没销毁，
`lifecycle.New` 与 `Result` 都不记录这件事」——这是**真实的、但注定只咬未来的**缺口（报告自己也这么说），
而不是「可选端口本身是缺陷」。报告的「影响」一节其实写对了口径，但「不变量/性质」与标题把它说成了结构缺陷。
**严重度：低，维持。**

---

### AUD-7 / AUD-9 / AUD-10 / AUD-11 / AUD-12 —— 抽查结果

- **AUD-7（导出与审计读取无审计）成立。** `export_routes.go:55-105` 全程无审计调用；
  `audit_routes.go:44` 起的 `handleAdminAudit` 也没有。执行输出：
  `GET /v1/account/export left no audit event (actions added: [])`。同测试先断言
  `admin.client.register` **有**记录，反空转成立。**低维持。**
- **AUD-9 成立，且报告全对。** `admin.go:292-294` 只有 `bindings` 目标拒绝；
  `:345` 的 `all` 分支整段被 `s.bindings != nil` 包住；`:151` 的 `Bindings` 带 `omitempty`，
  所以 `all` 在无数据源部署上 `Bindings == nil` 且序列化后消失。执行输出与报告的引文一致。**低维持。**
- **AUD-10 成立但要改范围。** `admin_routes.go:62-70` 只看会话里的 `usr_` 是否在 `adminAllowed` 里，
  **从不校验账号行**——代码属实；执行输出 `GET /v1/admin/clients = 200` 属实。
  **但它的前提不止「内存模式」**：见 V-3（`RevokeSubjectSessions` 只认 `session_subjects` 索引，
  而 0011 迁移**没有回填**）。另外报告的增量界定（`main.go:621-627` 的警告只说了「会话清不掉」，
  没说「存活会话 = 存活运维权限」）经我核对**成立**——警告原文只提 sessions 的过期，
  没有任何一句把运维权限串起来，全树也没有对应测试。**低维持**，范围改为「无持久会话 + 索引缺失的升级窗口」。
- **AUD-11 成立（读）。** `docs/admin.md:37-42` 的表只有 6 行，确无 `rotate_secret`；
  §5.1（`:122`）只讲 `/audit` 与 `/verify`，确无 `/head`。而 `openapi.yaml:1225`、`:1518` 两条都有，
  且 `internal/httpapi/openapi_test.go` 是双向断言——**漂的是 Markdown，spec 没漂**，报告这句对。**低维持。**
- **AUD-12 成立（读）。** `tapsign/client.go:197-202` 的 `finish` 把 `cred.ObjectID` 放进 `Subject`，
  而 `Redeem:147` 把失败路径的 `identity` 初始化成 `Credential{ObjectID: tok.OpenID}`——
  于是审计 subject 是**上游 openid**。报告对「这是字段语义越界、不是对 account-model 的直接违反」
  的自我限定是诚实且正确的。**提示维持。**

---

## 3. 我实际跑了什么（命令 + 有承载力的那一行）

```sh
go test ./internal/httpapi/ -run TestZZAdm -count=1 -v
```
- `--- FAIL: TestZZAdmWrongVerbAdvertisesTheOperatorPlaneToANonAdmin`
  → `zzprobe_adminplane_test.go:154: wrong-verb leak on 44 undeclared-verb probes`（AUD-4）
- `--- FAIL: TestZZAdmSecurityRelevantActionsLeaveAnAuditEvent`
  → `:270: GET /v1/account/export left no audit event (actions added: [])`；`:284` 同形（`/v1/admin/audit`）（AUD-7）
- `--- FAIL: TestZZAdmProviderAuditFailureIsNeitherReturnedNorLogged`
  → `:384: … ApproveDevice returned nil and nothing was logged (captured log "")`（AUD-1）
- `--- FAIL: TestZZAdmErasedOperatorKeepsThePlaneThroughAnotherSession`
  → `:449: an erased account's second session still calls the operator plane (GET /v1/admin/clients = 200)`（AUD-10）
- `--- FAIL: TestZZAdmErasureWhoseLastStepFailsCannotBeRetried`
  → `:525: CONFIRMED: the retry is answered 401 "no active session"`（AUD-2）
- `--- PASS: TestZZAdmEveryAdminRouteIsGatedByTheAllowlist`（「探过但没破」#1，且是本报告的**反向**证据）
- `--- PASS: TestZZAdmExportCarriesNoOtherAccountAndNoCache`（「探过但没破」#7）

```sh
go test ./internal/zzprobe/admin/ -count=1 -v
```
- `--- FAIL: TestZZAdmKillSwitchAllIsSilentAboutBindings` → `report: {TokensRevoked:0 SessionsRevoked:0 ClientsSuspended:0 Bindings:<nil>}`（AUD-9）
- `--- FAIL: TestZZAdmKillSwitchHasNoFlowPurgerWhileErasureDoes`（AUD-8，端口不对称那一半）
- `--- FAIL: TestZZAdmErasureWithoutAPseudonymStoreReportsSuccess`（AUD-6 后半）
- `--- FAIL: TestZZAdmConsentDecisionIsNotAudited` → `:365: an account approving client "cli" for scopes [account.id] recorded no audit event`（AUD-3）
- `--- PASS: TestZZAdmRegistrationSecretNeverReachesTheAuditDetail`（#9）
- `--- PASS: TestZZAdmOnlyTheOperatorIdAppearsInAdminDetail`（#10）

```sh
go test ./internal/store/postgres/ -run TestZZAdm -count=1 -v
```
- `--- FAIL: TestZZAdmPseudonymKeyTableIsInvisibleToEveryErasureGuard`
  → `… 14 account-linked tables found … no guard observes it`（AUD-6 前半）
- 注：该包内需 `TEST_DATABASE_URL` 的 DB 测试全部跳过；`auditpseudo.go` / `auditread.go` / `sessions.go`
  的结论一律为**读，无 DB 执行**。

**「探过但没破」抽查（9/16，均为独立核验，不是转述）**：#1（执行 PASS）、#2（grep：`adminAllowed` 的
唯一写入点是 `server.go:280-283`，来源 `cfg.Admins`，无 handler 触碰——成立）、#3（`admin_routes.go:67` 表查 +
`config.go:662-673` 只 TrimSpace 丢空——成立）、#5（执行 PASS，非管理员对已声明动词拿到 `404 unknown resource`）、
#6（`auditread.go:55-63` 无密钥时 `return audit.Page{Entries: []audit.Entry{}, Limit: limit}`——成立）、
#7（执行 PASS）、#9/#10（执行 PASS）、#13（`admin.go:237-247` 先 `SetStatus` 再 `RevokeTokens`——成立）、
#16（`export_routes.go:63-67` 与 `session_routes.go:27-31` 在 `GetUser` 失败时回 500——成立）。
**没有发现假阳性。** 唯一措辞瑕疵：#14 写的「每步幂等（重试安全）」容易被读成「可以重试」——
按 AUD-2/V-2，重试在持久化部署上恰恰不可能；建议改成「每步幂等（重放安全）」。

---

## 4. 我未能验证的

1. **`docs/audit-5/BRIEF.md` 不存在**（见开头）。因此共享简报里那份「哪些是文档化决定、报告它们会毁掉
   整份报告」的清单**我无法核对**。我改用 `docs/architecture.md`、`docs/admin.md`、
   `docs/security-audit-2/3.md`、`CHANGELOG.md` 与代码注释自行判据；如果 BRIEF 里列过
   「审计失败方向」或「405 方法分派」这类条目，我的 AUD-1/AUD-4 判定会偏严（我按「非发现」处理了 AUD-4 的
   匿名半边，正是因为找到了 `security-audit-3.md:295-296` 的裁定）。请主代理补回该文件或确认它确实从未存在。
2. **全部 Postgres 语义**：无 Docker、无本地 Postgres。`loadKey`/`Destroy`/`subjectKey` 的**铸新钥**这一跳
   由 `auditpseudotest.go:232-244` 的既有测试背书，我没有亲自观察；`RevokeSubjectSessions` 的实际删除行为
   只到 SQL 行（`sessions.go:186-188`）。
3. **AUD-4 的匿名半边**我由 `server.go:661` 的中间件链推出（mux 之前无鉴权），**没有执行**——
   `httpapi` 的探针夹具是不导出的，新建包无法复用；我没有为它单独搭一套夹具。
4. **AUD-5 的交错**没有真跑（需要 DB + 钩子）。我的「部分推翻」建立在代码路径与既有 DB 测试的**断言文本**上，
   不是观测。
5. **AUD-8 的可利用性**（内存模式 + 走完在途 bind flow）未验证，与报告同。
6. **`-race` 未用于本轮**：本报告的结论里只有 AUD-5 与竞态有关，而它是 Postgres 内存态的，
   `-race` 对它没有帮助。（任务说明称 `-race` 可用，我确认它能编译，但没有一条待验结论需要它。）

---

## 5. 新发现（复核时顺手看到）

### V-1 【确定性的】抹除成功后，`auth.logout` 又为这个已抹除账号**铸了一把新的假名密钥**（无竞态、每次都发生）

这是 AUD-5 想要证明的那件事的**确定性**版本，也是我对 AUD-5 做「部分推翻」之后必须补上的另一半。
（写完自查时发现 `docs/audit-5/findings/crypto-VERIFIED.md` 的 V-2 已独立记录了同一路径；
我在**没有**依赖它的前提下从 `account_routes.go` → `auth.go` 重新走了一遍，并补验了它未能执行的那一跳的接线。）

路径（持久化部署，逐跳有行号）：
1. `httpapi/account_routes.go:54` 先跑完 `DeleteAccount`；其中
   `lifecycle/lifecycle.go:258-263` 的 `Pseudonyms.Destroy` 是**最后一步**（`:254-257` 特意解释了顺序）；
2. 紧接着 `account_routes.go:68` 调 `s.sessions.SignOut(r.Context())`；
3. `auth/auth.go:187-203`：`SignOut` 在 `:188-191` **先把原始 subject 取出来**（`m.User` 读的是
   请求上下文里的会话值——`auth.go:124-130` 即 `m.sessions.GetString(ctx, keyUser)`，
   **不查库**，所以第 4 步把会话行删掉也不影响这里），再做 `Destroy`，最后
   **无条件** `recordAudit(… audit.Event{Action: "auth.logout", Subject: subject, …})`（`:202`）；
4. **`auth.Manager` 的审计 sink 与 `lifecycle.Pseudonyms` 是同一个对象**：`main.go:347` `logger := store.audit`
   → `:440` `Audit: logger`（auth）与 `:614` `Pseudonyms: pseudonymStore(store.audit)`——**接线确认**；
5. `postgres/audit.go:73` 对该 subject 调 `pseudonymize` → `auditpseudo.go:116-119` 的 `loadKey`
   因行已删（且缓存已被 `Destroy:183-185` 驱逐）返回 `nil, nil` → **`subjectKey:121-142` 铸一把新 key 并 INSERT**。

后果两条，都有成文对照：
- **`audit_subject_keys` 里又有了这个已抹除账号的一行。** 既有 DB 测试
  `internal/store/postgres/auditpseudo_test.go:225-230` 断言的 `keys == 0 after destroy` 在**真实请求序列**下不成立
  （该测试是在 `Destroy` 之后直接读计数、没有再走一次 `SignOut`）。
- **`docs/admin.md:130` / `openapi.yaml:1397-1401` 承诺的「密钥已销毁 → 过滤解析为空 → 返回空页」
  在真实序列下不成立**：`?subject=usr_X` 会解析到**新**假名并返回那条 `auth.logout` 行（非空页）。
  即「该账号已被抹除」这件事**确定性地**可被持有审计 key 的一方读出来。

**诚实的边界**：旧密钥回不来，**旧审计行仍然解不开**，所以这不是「历史重新可关联」，
而是「抹除之后的活动重新可关联 + 抹除这件事本身可被读出来」。**这对 AUD-5 的严重度判断是决定性的**：
想证明的保证确实被破坏，但破坏者是这一步，不是缓存竞态。
**严重度：低-中**（与 crypto-VERIFIED 的 V-2 同档）。修法很小：这条 `auth.logout` 要么在主体已被抹除时
不带原始 subject（用 `lifecycle.go:276-294` 那套「记形状不记身份」的做法），要么在抹除响应里不再写它。

### V-2 AUD-2 的范围少算一步，而 `lifecycle.go` 的注释自己写错了重试故事

`internal/lifecycle/lifecycle.go:246-249` 原文：
> The record is written after every store is clear, so it can state the result rather than a promise.
> A failure to write it fails the erasure: the account row is already gone, but the caller can retry,
> DeleteUser is idempotent, and the retry will produce the record.

在持久化部署下**这段推理是错的**：`account.delete` 的记录是**第 9 步**，而该 subject 的全部会话在**第 4 步**
就被 `RevokeSubjectSessions` 删掉了（报告自己的探针在 `zzprobe_adminplane_test.go:525` 观测到重试得到 401），
第 7 步账号行也已删除、无法重新登录。所以「the caller can retry」不成立于**这一步**，
而不仅仅不成立于报告指出的最后一步。建议把 AUD-2 的标题从「最后一步」改为「账号行删除之后的任何一步
（第 9 步 `record` 与第 10 步 `Destroy`）」；`docs/architecture.md:610`「抹除是用户主动、**可重试**的请求」
这句话的「可重试」也因此只对**前 8 步**成立——这是一处文档漂移，值得顺手记进去。

### V-3 AUD-10 的「存活会话 = 存活运维权限」**不限于内存模式**：`session_subjects` 索引没有回填

- `postgres/sessions.go:179-196`：`RevokeSubjectSessions` **完全依赖** `session_subjects` 索引
  （`DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM session_subjects WHERE subject = $1)`），
  它不去扫 `sessions` 表。
- `auth/auth.go:153-181` 保证**新**会话一定在索引里（`Remember` 失败就 `Destroy` 会话——fail-closed，好设计）。
- **但 `migrations/0011_session_subjects.sql:16-21` 只建表加索引，没有任何回填**；而 `sessions` 表自
  `0004_sessions.sql` 就已存在。**跨 0011 升级的部署里，升级前建立、且在升级后仍有效的会话不在索引里**，
  于是 `DELETE /v1/account`（第 4 步）与 Kill Switch 的 `subject` 目标都**碰不到它们**——
  在**持久化**部署上，一个已抹除账号的会话可以继续持有完整运维权限，直到该会话自然过期。
  窗口是「升级后到这批会话到期」（会话 TTL 量级），且需要真实存在过 0004-but-not-0011 的部署。
- 一个略带讽刺的推论：AUD-2 的补救路径（「用户重试」）恰好**只有在这条索引缺失时才存在**——
  索引外的会话没被第 4 步删掉，用户还能用它重发 `DELETE /v1/account`。
- 建议：AUD-10 的范围改写为「无持久会话部署（已被启动警告覆盖）+ **索引缺失的升级窗口**（未被任何文档覆盖）」，
  后者的修法是给 0011 补一次回填，或让 `RevokeSubjectSessions` 在索引为空时告警/回落到全表扫描。
  这属于新发现，我建议单独立条或并入 AUD-10。

### V-4 AUD-1 的「项目只对审计失败选过两次方向」不准确：是**三处**，而且 `tapsign` 是第四种写法

报告写「本项目对审计失败明确选过两次方向（admin/auth=记录并继续；vault/lifecycle=失败即拒绝）」。
漏了 `tapsign/client.go:195-211` 的 `finish`：它把审计失败**join 进返回值**——
「surfaces an audit failure alongside any operation error, so an unavailable audit log is never silent」。
所以精确表述是：fail-closed 三处（vault、lifecycle、tapsign），log-and-proceed 两处（admin、auth），
OP 存储层**唯一一处两个都没选**。这不削弱 AUD-1，反而**加强**它（先例更密，越显此处是漏网的），
只是报告的证据行写着「两次」，会被细心读者抓到。

### V-5 一处对报告有利、但它没写出来的强化

AUD-1 的探针只对设备批准做了实验。但**同一条代码路径**覆盖 `oidc.token`（每一次 access/refresh 签发，
内存 436/514、Postgres 283/376）。也就是说：同一份静默吞掉的行为，其后果面里包含**协议的令牌签发**，
而那是本服务唯一的对客户端的凭据发放路径。报告在「影响」里写了这一点，但没把「探针只测了设备批准、
签发路径是同一条 `record()` 因此同结论」这个推理链写清楚——建议补一句，否则会被质疑「探针没测签发」。

---

## 6. 我认为**被低估**的

1. **AUD-7（导出 / 审计读取无审计日志）应为中，而不是低。** 报告给低的理由是「无直接攻击者收益」，
   但按本项目自己的口径，审计日志的用途是**回答「谁读了什么」**（`audit/audit.go:1-3` 原文
   「the durable record of who accessed what, and when」），而这两个端点恰好是
   「一次拿走某账号全部个人数据」与「一次遍历所有账号」的动作。更关键的是它**静默**：
   运维无法区分「没人导出过」与「导出不留痕」。同一条报告在 AUD-1 里正确地指出「静默丢失比失败更糟」，
   却在这里只给了低——**同一份报告内的尺度不一致**。修法（`account.export` + `admin.audit.read`）
   成本极低，建议至少标为中低。
2. **AUD-2 的「不可重试」范围**（见 V-2）比报告的「最后一步」宽：从第 9 步起就成立。
   这不改变单条严重度，但改变修法的目标——只改 `Destroy` 的调用位置会漏掉 `record` 那一步。
3. **V-1（确定性重新铸钥）** 应被视为本区域**最重的一条**：它不需要竞态、不需要错误路径，
   在每一次成功的持久化抹除上都发生，并且直接推翻 `docs/admin.md:130` / `openapi.yaml` 的成文承诺。
   报告把它写成了带竞态的 HYPOTHESIS（AUD-5），严重度与可验证性都被**低估**了。
