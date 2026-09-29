# 区域 Z21：数据库迁移 / schema / 约束完整性 — 第七轮审计报告

## 范围与方法

读：`internal/store/postgres/migrations/` 全部 21 个 `.sql`（含每个 Down 段）、`postgres.go`、
`migrate_down_test.go`、`migrations_test.go`、`index_guards_test.go`、`revoke_predicate_test.go`、
`sweep.go`/`sweep_test.go`、`auditbatch.go`、`auditchain.go`、`auditpseudo.go`、`auditread.go`、
`oauth.go`/`oidc.go` 的 SQL 文本、`oauth/device.go`、`docs/migration-decision.md`（ADR-0008），
以及 goose v3.28.0 `provider.go` 的 `up`/`down`。另 `git log` 证实
`migrations/0005_authz.sql` 由 `87f4ad9` 删除。

跑：`go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z21migrationsschemaintegrity/...`
→ **12 测试，3 红 9 绿**（红=发现，绿=守卫）。`go build ./...`、`go vet ./...` exit 0，
`gofmt -l` 干净，未改任何跟踪文件。

**本机无 Postgres/Docker**：结论皆为读码级。唯一"运行时"证据是探针按 `auditchain.go:258-331`
逐行复刻 `Verify` 的判定（真实 SHA-256，含阳性对照）。探针内含一个括号/引号感知的 SQL 解析器，
并把 Up/Down 分段——把 schema 当数据断言，而不是手写清单（这正是 04-3 守卫漏掉 `oidc_devices` 的根因）。

---

## 发现

### Z21-1 `0010`/`0011` 的 Down 没有 `IF EXISTS`：重复 `-migrate-down` 的第二步硬报错

- 严重度：P3 低/提示 | 类别：可用性 | 不变量：fail-closed（对"退不动了"的诚实报告）
- 证据：`migrations/0010_client_status.sql:15` = `ALTER TABLE oauth_clients DROP COLUMN status;`；
  `migrations/0011_session_subjects.sql:24` = `DROP TABLE session_subjects;`——均无 `IF EXISTS`。
  21 个文件里其余每个 `DROP TABLE/INDEX` 都带（`0012` 全段、`0013:51-55`、`0015`），所以是遗漏而非风格。
  ADR-0008 §4 明说"要回退多步就重复执行"（`docs/migration-decision.md:40`）。
- 状态：**CONFIRMED**（源级，SQL 文本事实）
- 影响：操作者回退一步后想再退一次，会拿到 `column "status" does not exist` /
  `table "session_subjects" does not exist`，exit≠0，且没有任何一行说明原因。
- 探针：`migration_shape_test.go::TestEveryDownIsSafeOnRerun`（红）
- 修法建议：两处补 `IF EXISTS`。把该探针搬成 `internal/store/postgres` 的无 DB 守卫
  （现有 `TestMigrationFilesAreGooseShaped` 不看 Down 的幂等性）。
- 与既有编号：无（第五轮 PG-002 是"版本 5 让整条 Down 链失败"，机制不同）。

### Z21-2 0013/0014 的 Down 摧毁审计链的防篡改证据：一次 Down→Up 往返即静默拆掉 S5

- 严重度：P2 中（破坏不可逆且**完全静默**；触发需操作者主动回退）| 类别：安全 | 不变量：审计链
- 证据：四段合成。
  ① `0013` Down（`:50-55`）`DROP TABLE IF EXISTS audit_chain` + 逐列 `DROP COLUMN IF EXISTS
  prev_hash/row_hash/signature`——链头与**每一行的链上元数据**都没了；Up（`:30-32`、`:42-48`）
  重建表并把链头重新播种为创世 `'\x'::bytea`，**不从幸存行反推**。
  ② 任何 Down 段都不 `DELETE`/`TRUNCATE` `audit_events`，所以老审计行存活、链字段为 NULL
  （`::TestDownDoesNotDropAuditRows` 的控制组确认它确实读到 0013/0014 的 Down 文本）。
  ③ `auditchain.go`：`row_hash IS NULL` 的行计入 `v.Legacy` 并 `continue`（`:270-281`）；只有
  `started` 之后出现无链行才失败（`:274-279`）。往返后**所有**行都是 legacy、`chained==0`，
  而链头是创世（空），故 `:318-328` 的"链头前进过却无链行"**不触发**，最终 `v.OK = true`。
  探针复刻该状态机给出红判定 + 两个对照（健康链必须过；元数据仍在则必须失败）。
  ④ 更狠但当前不可达：`0007_audit.sql` 的 Down 是 `DROP TABLE IF EXISTS audit_events`——退到 0006
  会整表删除审计日志（不作为本条主张，原因见可达性）。
- 状态：**CONFIRMED**（源码级 + 复刻判定函数的红探针）；可达性见下。
- 影响：退到 0013/0014 之下再启动，重建后历史每一行的 row_hash/signature 永久消失、链头回创世，
  此后新行从创世起链而与历史**分叉**；`/v1/admin/audit/verify` 不打日志地报 OK。"可检测改写"
  这个控制项被静默降级为"只保护 0013 之后新写的行"。
- **可达性（必须一起读）**：goose `provider.down` 先对 `ListMigrations` 的**全部**行做
  `getMigration` 再 `runMigrations`（`provider.go:454-465`）；版本 5 的文件已被删，所以**只要版本表里有 5，
  任何一次 Down 都整体失败、一个版本都不退**（第五轮 PG-002，第六轮已更正措辞）。存量库为何会有 5 属
  HYPOTHESIS（见「未能到达」）。故：**PG-002 修掉之前本条基本不可达；它是紧挨 PG-002 修复的地雷**——
  一旦用"补空壳 0005"式修法修掉 PG-002，这条立刻变成每次回退都踩的真洞。这是我把它写成发现而非
  守卫的原因。
- 探针：`audit_chain_cycle_test.go::TestAuditChainSurvivesADownUpCycle`（红）、
  `::TestAuditVerifyModelIsNotVacuous`（绿，模型阳性对照）、
  `::TestDownDoesNotDropAuditRows`（绿，前提+文本控制组）
- 修法建议：(a) 把 0013/0014 的 Down 改成 no-op 并注释"本步不可回退，回滚=恢复备份"；
  (b) 给 `MigrateDown` 加前置检查——库中存在链上行（`SELECT 1 FROM audit_events WHERE
  row_hash IS NOT NULL LIMIT 1`）时拒绝回退 0013/0014；(c) 至少在 ADR-0008 Consequences 点名此后果。
  另给 `migrations_test.go` 加守卫：Down 段一旦涉及链/假名/审计行必须带显式注记。
- 与既有编号：对 **PG-002** 的补充（PG-002 讲"Down 跑不起来"，本条讲"跑起来之后会怎样"）。

### Z21-3 04-7 的补充：单事务非并发建索引是**整个索引家族**（39 个索引、最坏 0012 一次 9 个），不是 0022 一条

- 严重度：P3 低（时长部分 HYPOTHESIS）| 类别：性能 | 不变量：性能/资源
- 证据：探针从迁移文本直读出三个常量：21 个迁移共 **39 条 `CREATE INDEX`**；**0** 个声明
  `-- +goose NO TRANSACTION`；**0** 条用 `CONCURRENTLY`。goose 把整个 Up 包在一个事务里
  （v3.28.0 `provider.go:468-530`），`CREATE INDEX` 建索引期间持 SHARE 锁（与 INSERT/UPDATE/DELETE
  冲突），故**每条文件的索引总时长**即该文件的写冻结窗口。多索引文件：`0012` 9 条（跨 7 表）、
  `0008` 6 条、`0001` 4 条、`0022` 4 条、`0006/0007/0009/0021` 各 2 条。第六轮 04-7 只点 0022 的 4 条。
  另 `0009` 在同一事务里既 `ADD COLUMN ... NOT NULL DEFAULT now()`（全表重写）又建两条索引。
- 状态：**CONFIRMED**（源级常量事实）/ 时长 **HYPOTHESIS**（需带数据的库 + `pg_locks`）
- 影响：在役滚动升级时（旧实例仍在写；advisory 锁只串行化迁移者之间），0012 一类文件让相关表
  （含 `sessions`/`oauth_*`/`oidc_*`）写阻塞整个建索引时长；全新部署表空，无感。
- 探针：`index_transaction_test.go::TestIndexMigrationsAreNonConcurrentInOneTransaction`（绿守卫：
  钉住"0 NO TRANSACTION / 0 CONCURRENTLY / ≥3 个多索引文件"，前提变即 fail）
- 修法建议：(1) ADR-0008 §2 补一句"索引迁移在役升级会按表规模线性冻结表写，多索引用一个事务"，
  并把 0012/0008 列为已知最坏；(2) 后续索引迁移改 `NO TRANSACTION` + `CONCURRENTLY`（注意失败会留
  invalid 索引）；(3) 拆开 `0009` 这类"加列+建索引同文件"。
- 与既有编号：对第六轮 **04-7** 的补充（结论一致，范围与最坏值更正）。

### Z21-4 设备码 user code 唯一性两表不对称：`oidc_devices` 有 UNIQUE，`oauth_device_authorizations` 没有

- 严重度：P3 低/提示 | 类别：安全（纵深防御）/可维护性 | 不变量：账号隔离（审批落到错误设备流）
- 证据：`0008_oidc.sql:81-82` 是 `CREATE UNIQUE INDEX oidc_devices_user_code_idx ON
  oidc_devices (upper(replace(user_code,'-','')))`，`oidc.go:727-728` 把 23505 映射成
  `op.ErrDuplicateUserCode`；迁移注释自陈"唯一索引就是为了让'已被占用'可被当作约束错误检测到"。
  `0001_init.sql:94-95` 对 `oauth_device_authorizations` 同名表达式建的是**非唯一**索引。旧引擎
  在 Go 里"先查后插"（`oauth/device.go:432-443`），而 `SaveDevice`（`postgres/oauth.go:337-344`）
  是无冲突处理的裸 INSERT；内存后端同形（`oauth/device.go:161` 在查重后才写 map）。
- 状态：**CONFIRMED**（源级 SQL + 两处 Go 形状）；真实并发交错需库
- 影响：两个并发设备授权可能拿到同一 user code（8 字符/20 字母表，概率极低），此后人肉输入该码时
  `GetDeviceByUserCode`（`oauth.go:355-361`）返回先被扫到的行，审批可能落到另一个流。两条流都是玩家
  自己的设备申报，不是跨账号泄露；但它与 OIDC 表的设计意图直接矛盾，修法只是一个唯一索引。
- 探针：`usercode_unique_test.go::TestUserCodeUniquenessIsEnforcedOnEveryDeviceTable`（红，带阳性对照）
- 修法建议：新迁移给该表加表达式 UNIQUE 索引，并让 `SaveDevice` 用 `isUniqueViolation` 走一条明确的
  "重新生成 user code"路径（`freeUserCode` 已有 8 次重试，把重试挂在约束错误上即可）；内存后端同步。
- 与既有编号：无（04-3 是 client_id 前导索引，方向不同）。

---

## 探过但没破的（建议变成守卫）

1. **schema↔代码漂移**：`schema_drift_test.go::TestEverySchemaColumnIsNamedByTheStore` 解析出
   **20 表 / 122 列**，逐列在出货源码（AST 字符串字面量）里查名——**每一列都被点名**；
   `TestNoRequiredColumnIsInvisibleToTheStore`（NOT NULL 且无 DEFAULT 必须被点名）亦绿。
   现有 `credential_columns_test.go` 只看"名字像凭据"的列，这条补上全量口径。
2. **变更谓词的索引覆盖（去手写清单）**：`predicate_index_test.go::
   TestEveryGoMutationPredicateHasALeadingIndex` 用 AST 取出全部 `DELETE FROM`/`UPDATE`，检查谓词列
   是否被索引/表级 UNIQUE 覆盖——13 个可归属语句全过。注意：`oidc_devices` 的 client_id 谓词在探针里
   靠 PK 顺序论元"过关"，所以 **04-3 依然成立**，这条守卫不能替代它。
3. **Down 只 DROP 自己 Up 建的东西、从不删行**：`TestDownDoesNotDropAuditRows` 的
   DELETE/TRUNCATE 扫描零命中，控制组确认它读到了 0013/0014 的 Down 文本（排除扫空气）；
   `TestEveryDownIsSafeOnRerun` 的"DROP 无人创建的对象"零命中。
4. **版本序列**：`TestVersionSequenceHasNoUnexplainedGap` 只允许缺口 5 且打印原因字符串；其余全满。
   原 `TestMigrationFilesAreGooseShaped` 的"严格递增"挡不住删除，这条能。
5. **审计只追加是代码事实**：`append_only_test.go::TestAuditLogHasNoSchemaLevelAppendOnlyGuard` 用 AST
   确认出货代码对 `audit_events` 只有 INSERT（有阳性对照）；迁移里去注释后无
   `GRANT/REVOKE/CREATE TRIGGER/CREATE POLICY`。`audit_events` 不在分区/保留机制里，也不在
   `sweep.go:26-37` 的 10 张清扫表里（探针同时读 `sweep.go` 源校验）。
6. **时钟与清扫**：`0009`/`0015` 的 `DEFAULT now()` 只服务回填/既有行，Go 侧全部显式传时间戳，
   没引入第二时钟；10 张清扫表的期限列全部有索引且由本进程写入。
7. **迁移锁**：独立连接不进池、解锁用 `context.WithoutCancel`、会话级锁随连接关闭兜底
   （`postgres.go:333-371`）；up/down 共用它，不会漂移。

## 未能到达（残余盲区）

1. 一切需真库的运行时语义：planner 是否走 0021/0022 索引、`CREATE INDEX` 真实锁时长与 `pg_locks`
   观察（Z21-3 时长）、并发 `SaveDevice` 交叠成同一 user code（Z21-4）——CI 的 `postgres:16` 是权威位。
2. **Z21-2 端到端**：无库不能真跑 `MigrateDown`×N 再 `Open()`；我复刻的是 `Verify` 的判定函数，
   不是产品代码本身，故"真实 `Verify` 的返回值"仍差一个 DSN。
3. **存量库版本表里到底有没有 5**：`git log` 只证明 `0005_authz.sql` 被删；"删之前有多少部署把它
   应用到仍在役的库"本仓库无法判定（需发布历史/运维记录）。Z21-1/Z21-2 的可达性都悬在这条上。
4. **`adoptLegacyMigrations` 的源表形状**：`postgres.go:428-462` 假定 legacy 表为
   `schema_migrations (version, applied_at)` 且 `version` 形如 `0005_authz.sql`；仓库测试只种 0001-0003。
   若历史版本表形状不同，PG-002 可达性会变——无真实旧库可查。

## 判断（文档化决定可否质疑，不是 finding）

1. **ADR-0008 的"Down 存在但不是回滚故事"在 0013/0014 上不自洽**：§3 说 Down 只服务"撤销我刚应用的
   这一步"，但对审计链来说撤销那一步的代价是不可逆地摧毁防篡改证据（Z21-2），而 §2 的
   expand/contract 只约束 Up。建议把 Down 分两类（可回退的 schema 步骤 / 不可回退的完整性步骤），
   后者一律 no-op + 文档化。是裁定，不是缺陷。
2. **"审计只追加"是约定而非控制**（无 trigger/REVOKE/RLS）。0013 注释已诚实说明"防的是可检测、
   不是阻止"，且"链尾截断不可检测（无外部锚点）"是明文有意不做。这里只作区分：角色权限不需要新架构
   就能收紧（迁移里 `REVOKE DELETE/UPDATE` 或应用改用非属主角色）。写成判断而非 finding，
   因为没有东西能"失败"来证明它——它不是代码缺陷，是部署形态。
