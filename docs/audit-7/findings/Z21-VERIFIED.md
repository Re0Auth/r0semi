# 区域 Z21：迁移 / schema / 约束完整性 — 对抗性复核报告（第七轮）

> 复核对象：`docs/audit-7/findings/Z21-migrations-schema-integrity.md`（4 条发现 + 7 条「探过没破」）。
> 被复核探针 12 测试 / 3 红 9 绿（已亲跑，红的文案与其报告声称一致）；复核探针
> `internal/zzprobe/audit7/z21verify/`（3 绿 2 红）。本机无 Postgres/Docker，全部证据为读码级 +
> 文本/AST/goose 模块源码；未改被跟踪文件；端口 19102 未用（无需真进程）。
> `go build ./...`、`go vet ./...`、`go vet -tags audit7 ./internal/zzprobe/audit7/...` 均 exit 0。

## 复核方法

1. 逐条真读 `file:line`（不信报告），亲跑被复核探针并比对红输出与报告文案。
2. 「机制」类断言直接读 **goose v3.28.0 模块源码**（Z21-1/Z21-2 的结论完全取决于其 down 语义）。
3. 「探过没破」逐条找假绿：是否走真实路径、对照组是否非空、声称覆盖的是否真覆盖。
4. 反向找新洞：`auditpseudo.go`、`auditread.go`、`oauth/device.go`、`internal/wiring/`。

## 逐条裁定

### Z21-1 → **DOWNGRADED（P3，机制写错）**

- 真的部分：`0010_client_status.sql:15`、`0011_session_subjects.sql:24` 确实是 21 个文件里仅有的两条
  无 `IF EXISTS` 的 `DROP`（我独立复扫确认），报告的行号与对比结论都对。
- **假的部分（机制）**：`-migrate-down` **不可能**把同一段 Down 跑第二遍。goose：
  `provider.go:308-328` `Down(ctx)=down(ctx,true,0)`；`provider.go:454-466` 对 `ListMigrations` 每行
  `getMigration` 后 `runMigrations(...,byOne=true)`；`provider_run.go:119-122` `byOne ⇒ apply =
  migrations[:1]`（每次恰好一个版本）；`provider_run.go:203-219` 把 DDL 与版本行 `Delete` 放进
  **同一个事务**。故一次成功的 Down 原子降一级，下一次执行的是**前一个迁移**的 Down：报告写的
  「再退一次拿到 `column "status" does not exist`」在正常路径上不存在（第二次退的是 0009 的 Down）。
  唯一能踩到的是「版本表与 schema 漂移」（手工改版本表 / 恢复旧 `goose_db_version`）——那正是
  `IF EXISTS` 的正当用途。探针 `migration_shape_test.go:145-146` 的错误文案把这两件事混为一谈。
- 复核探针：`z21verify/down_rerun_test.go::TestGooseDownCannotRerunTheSameSection`（绿，钉 goose 三条前提）、
  `::TestTheTwoUnguardedDownsAreStillThere`（绿，含 0009 的阳性对照）。
- 裁定：观察成立、后果不成立 ⇒ 纯加固项（与其余 19 个文件一致 + 抗版本表漂移），保留 P3。

### Z21-2 → **CONFIRMED（P2），但可达性论证方向错了**

- 机制逐段核对为真：`0013:50-55` Down 丢 `audit_chain` 与逐列链元数据；`0013:30-32` Up 重新 `ADD COLUMN
  bytea`（无 DEFAULT ⇒ 旧行为 NULL）；`0013:48` Up 把链头重新播种为创世 `'\x'::bytea`；任何 Down 都不
  `DELETE`/`TRUNCATE` `audit_events`（我复扫 21 个 Down 段确认，且 `z21verify/audit_cycle_test.go` 把它
  从 SQL 文本推导出来，而不是像被复核探针那样硬编码 `after[i]=chainedRow{}`）。真实 `Verify`
  （`auditchain.go:258-331`）对 NULL `row_hash` 只 `v.Legacy++`（`:280`）、`:318` 的「链头前进过却无链行」
  因链头是空创世而不触发 ⇒ `v.OK=true`。我另证 `auditchain.go` 里 `v.Legacy` **只被自增、从不参与判定**
  （计数为 1），故原地无法发现。
- **更正：可达性比报告写的强得多，不是更弱。** 报告说「PG-002 修掉之前本条基本不可达」。PG-002 只在
  **版本表里真的有 5** 时让 Down 整体失败（`provider.go:459-462` 对每个已应用版本 `getMigration`）。
  而 goose 的 Up 用 `gooseutil.UpVersions`（`resolve.go:39-64`），**库里多出一个 5 不算缺失**，
  所以有 5 的库能启动、只有 Down 失败；关键点在于：**87f4ad9 之后新建的库根本没有 5 这一行**
  （Up 应用的是 1,2,3,4,6…22），对它 `-migrate-down` 一路可用——**即将上线的首次部署正是这种库**。
  于是「按 ADR-0008 §4 重复执行 `-migrate-down`」这条**成文运维动作**（`migration-decision.md:40`）
  就会一路踩到 0013，再现本条后果。报告把可达性压在「存量库是否有 5」这个 HYPOTHESIS 上，方向反了。
- 但**不必升级严重度**：① 0013 注释自己就把「清空链元数据 + 链头重置为创世在无外部锚点时不可区分」
  写成**文档化边界**（`auditchain.go:319-324`），本条的新东西是**触发者**（一次常规回退而非攻击者），
  不是「不可检测」；② `/v1/admin/audit/head` 的外部锚一旦发布，链头退回创世可发现，且 ADR-0008 §3 的
  回滚故事本是「从备份恢复」（链一起回来）。故 P2（确定但有界）成立。
- 需更正的措辞：标题「0013/0014 的 Down 摧毁审计链」——**0014 的 Down 不碰链**（只丢 `audit_subject_keys`，
  真正后果是 Z21V-1）；「不打日志地报 OK」不准确——`cmd/re0auth/main.go:1090-1094` 在 OK 分支打
  `slog.Info("audit chain verified", "legacy", N)`，响应也带 `legacy`（`audit_routes.go:57`）。
  真正静默的是：**没有东西把「0013 之后才上线的库 legacy>0」当成回归**。
- 探针：`audit_chain_cycle_test.go::TestAuditChainSurvivesADownUpCycle`（红，非空转——它的
  `TestAuditVerifyModelIsNotVacuous` 有正反两个对照，`TestDownDoesNotDropAuditRows` 有 0013/0014 文本前提）。
  复核探针：`z21verify/audit_cycle_test.go::TestAuditChainCycleStateIsDerivedFromTheMigrationText`（绿，用 SQL
  推导替代硬编码）。

### Z21-3 → **CONFIRMED（P3）**

- 独立复算：21 个迁移共 **39** 条 `CREATE INDEX`；`NO TRANSACTION` **0**；`CONCURRENTLY` **0**；
  多索引文件 8 个，逐文件计数（0001=4、0008=6、0012=9、0022=4、0006/0007/0009/0021=2，其余=1）与报告
  完全一致（其探针日志亦为 39/0/0）。
- 机制对：普通 `CREATE INDEX` 取 SHARE 锁、与 ROW EXCLUSIVE 冲突，goose 单事务 ⇒ 冻结窗口 = 该文件
  建索引总时长；`0009` 的 `ADD COLUMN … NOT NULL DEFAULT now()` 是 volatile 默认值 ⇒ 全表重写。
  时长部分报告自己标了 HYPOTHESIS，正确。
- 小瑕疵（不影响结论）：`index_transaction_test.go:19-21` 的注释说普通 `CREATE INDEX` 会取
  **ACCESS EXCLUSIVE**，PG 实际取的是 **SHARE**（报告正文写的是 SHARE，正确）。建议只留 SHARE。

### Z21-4 → **CONFIRMED（P3）**

- 行号核对：`0008_oidc.sql:81-82` 是 `CREATE UNIQUE INDEX oidc_devices_user_code_idx … upper(replace(user_code,…))`；
  `0001_init.sql:94-95` 对 `oauth_device_authorizations` 建的是**同名表达式的非唯一索引**；`postgres/oidc.go:726-728`
  把 23505 折回 `op.ErrDuplicateUserCode`；`oauth/device.go:234`（`freeUserCode` 查重）与 `:239`（`SaveDevice` 插入）
  之间无约束；`postgres/oauth.go:337-344` 是裸 INSERT；`:355-361` 是 `GetDeviceByUserCode`。全部成立。
- 补充边界（不改变裁定，但影响「影响」段的现实性）：老的 `oauth` AS 引擎**不在生产组合根里**——
  `oauth.NewService` 只被 `internal/wiring/oauth.go:23` 与测试调用，而 `internal/wiring` 全仓无引用
  （简报亦载明 core 不接入生产组合根）。故暴露面是 **Upstream Kit 的嵌入者 + `postgres.DB.Devices()`**，
  不是旗舰二进制的线上设备流。
- 另：内存后端不只是「同形」，`oauth/device.go:155-163` 的 `SaveDevice` 对 `byUser[...]` 是**无条件覆盖**——
  撞码时是「静默改写映射、让前一条永远查不到」，比 PG 的「扫描先撞到谁」更确定。
- 探针：`usercode_unique_test.go::TestUserCodeUniquenessIsEnforcedOnEveryDeviceTable`（红，带
  `oidc_devices` 阳性对照）。小瑕疵：该探针注释里的行号（`0008:57-60`、`0001:105-106`）是旧的，
  报告里的 81-82/94-95 才对。

## 新发现

### Z21V-1 0014 的 Down 丢掉全部每账号假名密钥：同一账号的审计历史被静默劈成两个假名，`?subject=` 从此只回一半

- 严重度：P3 低（破坏不可逆且静默，但触发需操作者连续回退；与 Z21-2 同一次回退窗口）
- 类别：合规/隐私 | 不变量：审计链（读路径完整性）
- 证据：`0014_audit_pseudonyms.sql:36-39` Up 只 `CREATE TABLE audit_subject_keys(idx PK, key)`（空表），
  `:41-42` Down `DROP TABLE IF EXISTS audit_subject_keys`——**这是全部假名密钥的唯一副本**。
  `auditpseudo.go:69-91` `loadKey` 对「无行」返回 `nil`；`:115-142` `subjectKey` 在 nil 时**新铸随机 32 字节**
  并 `INSERT … ON CONFLICT DO NOTHING` 后重读。`:109-114` 的注释自己写明这条不变量：另一个 key 会
  「give the same account two pseudonyms and split its history in two」，代码为此刻意加了 CAS+重读。
  读路径 `auditread.go:46-65`：`?subject=usr_x` 用**当前** key 算出假名再作绑定参数 ⇒ 回退后再 Up，
  该账号只剩回退之后写入的行，**旧行既查不到也无法重算**，且无错误、无标记；`Verify` 全绿（链本身合法）。
- 状态：CONFIRMED（源级；探针红）
- 影响：运维按文档回退两步（0014→0013）再启动，之后 `/v1/admin/audit?subject=usr_x` 静默少一段历史；
  任何依赖「一个账号一个假名」的下游（导出/SIEM 关联）在回退后会把同一账号当两个主体。
- 与既有编号：与第五轮 **P2-3 / AUD-V1**（`SignOut` 在抹除后重新铸 key）**同一不变量、不同触发**；
  本条不是重报，是对它的补充（那次修的是写路径，这次是迁移 Down）。
- 探针：`z21verify/pseudonym_test.go::TestMigration0014DownDestroysEveryPseudonymKey`（红；Down 一旦改成
  no-op 它就转绿，是「修复检测器」而非只会红的死探针）。
- 修法建议：与 Z21-2 同批——0014 的 Down 改 no-op + 注释；`MigrateDown` 加
  `SELECT 1 FROM audit_subject_keys LIMIT 1` 前置拒退。

### Z21V-2 被报告当作「去手写清单」的守卫**看不见 04-3 那条语句**，它自称能自动抓住 04-3 是假的

- 严重度：P3 低（审计证据质量：一条被列为正面结论的守卫是假绿，且它正是 04-3 唯一的结构性防复发机制）
- 类别：可维护性 | 不变量：无（方法学）
- 证据：`predicate_index_test.go:123-129` 的文档断言「derives every delete/update target the shipped store
  names … would have caught the oidc_devices client_id gap (04-3) without anyone remembering to add the
  table to a list」。但批量撤销语句**不以文本存在**：`postgres/oauth.go:288-298`
  `db.Exec(ctx, \`DELETE FROM \`+table+clause, …)`，table 来自调用点的 `[]string`，clause 由
  `revokePredicate`（`oauth.go:313-327`）用 `fmt.Sprintf("client_id = $%d", …)` 拼出。我用独立探针扫了
  出货源码里**全部反引号字面量**：`DELETE FROM <t> WHERE client_id = $1` 对 revokeMatching 的
  **全部 5 张表**（oauth_access_tokens / oauth_refresh_tokens / oidc_access_tokens / oidc_refresh_tokens /
  oidc_devices）都不存在。守卫之所以「过」了 oidc_devices，是因为它只看得见 `oidc.go:750` 的消费语句
  和 `oidc.go:1016`（device_code_hash / subject 谓词），再被 `indexCoversAny`（`:203-215`，任一谓词列出现在
  任一索引即算覆盖）放过——即报告自己写的「PK 顺序论元」。
- 状态：CONFIRMED（源级 + 探针红）
- 影响：04-3 未修（仓库无 0023，`oidc_devices_client_idx` 不存在），而防它复发的那条守卫在结构上
  不可能发现同类语句；报告把它写进「探过没破 #2」会让读者以为 04-3 有结构性护栏。
- 探针：`z21verify/guard_coverage_test.go::TestTheClientOnlyRevokeStatementsAreInvisibleToALiteralWalkingGuard`（红，
  含「字面量里确实存在 `DELETE FROM oidc_devices`」的阴性对照）。
- 修法建议：守卫改为从 `revokeMatching` 调用点反推 `[]string{…}` 表集合（第六轮 04-3 的修法建议已写过
  同样的话），或让 `revokeMatching` 的 SQL 文本可被静态提取。

## 「探过没破」的复核（逐条）

1. **schema↔代码漂移**：机制**弱**——它把 postgres 包**全部字符串字面量**（含错误消息、散文）取词后做
   集合包含，任何同名列（`status`/`type`/`id`）都会命中；只能证明「这个名字出现过」，不能证明该列被读写，
   且没有「注入一个不存在列必须被抓到」的正对照。**数字有误**：探针日志是 **20 表 / 130 列**，
   报告写「20 表 / 122 列」。裁定：守卫存在但弱，数字需更正。
2. **变更谓词索引覆盖**：见 Z21V-2（假绿）。
3. **Down 只 DROP 自己 Up 建的东西、从不删行**：控组非空（我核了 0013/0014 的 Down 文本）；但只对
   `DROP TABLE/INDEX` 查创建者，**不查 `DROP COLUMN`**（0009/0013/0015/0016 的列都不查）。口径要如实。
4. **版本序列**：真实且非空转（把 `knownMissingVersions` 的 5 与 `provider.go:459` 的失败点对上）。
5. **审计只追加**：AST 侧非空转（`append_only_test.go:114-116` 有失败门槛）。但报告写「无
   GRANT/REVOKE/CREATE TRIGGER/CREATE POLICY」**超出探针检查范围**：`:39` 的 shape 列表是
   `CREATE TRIGGER / CREATE POLICY / ROW LEVEL SECURITY / REVOKE `，**不含 GRANT**（`:32` 提到 "grant"
   却漏进列表）。我独立 grep 全部迁移：确实无任何 `GRANT/REVOKE/TRIGGER/POLICY/RLS` 语句（只有散文），
   故**事实为真、证据项不成立**。
6. **时钟与清扫**：独立复算成立——10 张清扫表的期限列全有前导索引（0001×2、0003×1、0008×4、0012×2、
   0017×1），`sessions.expiry` 也有；`session_subjects.created_at` 走数据库默认值（`sessions.go:202`
   不插该列），故 `:151` 的 `now()` 比较是**同一个时钟**（注释 `:133-135` 已说明）。
7. **迁移锁**：与 `postgres.go:333-371` 一致（独立连接、`WithoutCancel` 解锁、up/down 共用）。成立。

## 未能到达

- 真库语义（`CREATE INDEX` 实际锁时长与 `pg_locks`、并发 `SaveDevice` 交错、真实 `Verify` 返回值）：
  本机无 Postgres/Docker，复核只做到「从 SQL 推导状态 + 复刻判定分支」。
- Z21V-1/V-2 建立在源码事实上，不需真库即可定论；「回退后有多少行被劈开」需要真实部署。
- 端口 19102 未使用：本区复核没有需要真进程的断言。

## 复核者的判断（不是 finding）

1. **ADR-0008 缺少「不可回退步骤」这一类**：Z21-2/Z21V-1 同一根因（`Down` 被当作「撤销我刚应用的这一步」，
   而 0013/0014 的那一步是不可重建的完整性状态）。建议 Down 分两类，完整性类一律 no-op + 文档化。
2. **审计只追加是部署形态而非缺陷**：与报告「判断」一致；没有东西能失败来证明它是缺陷，故不列 finding。
3. **Z21-1 的两处 `IF EXISTS`**：即使不构成可达故障，补齐它仍是零成本的一致性。
