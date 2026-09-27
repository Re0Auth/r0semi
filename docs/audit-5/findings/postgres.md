# Postgres 存储适配器与 schema 审计报告

## 范围与方法

**看过的代码（全部逐行读完）**

- `internal/store/postgres/`：`postgres.go`、`oidc.go`、`oauth.go`、`account.go`、`federation.go`、`sessions.go`、`vault.go`、`sweep.go`、`audit.go`、`auditbatch.go`、`auditchain.go`、`auditpseudo.go`、`auditread.go`（以及包内既有测试 `pool_test.go`、`pool_exhaustion_test.go`、`clock_test.go`、`migrations_test.go`、`migrate_down_test.go`、`sweep_test.go`、`index_guards_test.go`、`revocation_index_test.go`、`revoke_predicate_test.go`、`credential_columns_test.go`、`erasure_schema_test.go`、`erasure_test.go`、`postgres_test.go`、`oidc_test.go`、`auditchain_test.go`、`auditpseudo_test.go`、`auditread_test.go`、`auditbatch_test.go`）。
- `internal/store/postgres/migrations/*.sql`：**全部 20 个**，按版本顺序作为一部 schema 历史读（0001→0021，无 0005；见 `PG-003`）。
- 被实现的端口：`internal/account`、`oauth`（含 `device.go`/`service.go`/`tokens.go` 的 Store 语义）、`vault`、`internal/federation`（`binding.go`/`refresh.go`/`unbind.go` 的 CAS 与顺序）、`internal/oidcstore`。
- 相关调用方，用于判断可达性：`internal/lifecycle/lifecycle.go`、`internal/admin/admin.go`、`internal/federation/refresh.go`、`cmd/re0auth/main.go`（§存储组合根、`-migrate-down`）、`cmd/re0auth/config.go`（池配置解析）、`internal/httpapi/audit_routes.go`。
- 已读前两轮审计的结论（由子代理整理成去重清单）：`docs/security-audit-2.md` 的 A4-1/A5-1/A5-2/A5-3 与「SweepExpired 宽限期」「零长审计密钥」，`docs/security-audit-3.md` 的 B3-1/B3-2/B3-3/C3-1/C3-2/C3-3，以及 `docs/architecture.md` §4.13/§4.15/§4.16/§4.17、`docs/threat-model.md` §6.0/§6.1/§9、`SECURITY.md`。**这些一律不重报**；本报告 §「探过但没破的」里逐条标注了我复核过它们确实成立。

**跑过的命令**

```
go test ./internal/store/postgres/ -run 'TestMigrationFilesAreGooseShaped|TestNoColumnCanHoldACredential|TestEverySubjectColumnIsHandledByErasure|TestSessionSubjectSweepIsIndexed|TestAuditTimeRangeQueryIsIndexed|TestRevokeTokenLookupIsIndexed|TestClientScopedRevokeIsIndexed|TestRevokePredicateIsSargable|TestPoolConfig|TestPoolOptions|TestPoolStats' -v
  → 13 个 DSN-less 守卫全部 PASS（含子测试），包 ok 0.114s

go test ./internal/zzprobe/pgstore/ -v
  → 24 个探针；其中 2 个按设计 FAIL（TestEverySingleColumnPredicateHasALeadingIndex → PG-001，
     TestDevicePathsJudgeExpiryWithTheDatabaseClock → PG-003），其余 22 个 PASS
     （含 5 个反空转 sentinel：目录解析 + 三处「故意改坏副本」+ 时钟分类对照）
```

**跑不了的（残余盲区，必须说清）**

本机 **没有 Docker、没有本地 Postgres**，`TEST_DATABASE_URL` 未设置。因此：

1. **`internal/store/postgres` 的全部集成测试都是 SKIP**，不是 PASS——包括 `TestAccountDeletionLeavesNoOrphans`、`TestSweepExpiredRemovesDatedRows`、`TestRevokeMatchingFilters`、`TestDevicePollingIsThrottled`、`TestSessionsExpiredIsNotFoundAndRemoved`、`TestBindingPutIfVersionIsAtomic`、`TestMigrateDownRollsBackOneStep`、`TestPoolExhaustionFailsFast`。它们只在 CI（`postgres:16` service）里真的执行过。
2. **本报告每一条 Postgres 路径结论都标注「读；无 DB 执行」**，没有一条声称跑过 SQL。
3. `go test -race` 需要 cgo，本轮未跑；本报告不含并发结论的检测器背书。
4. `go build ./...` 当前**不能作为证据**：`internal/httpapi/zzprobe_adminpriv_test.go:3`（**别的代理**新建的探针）是非法 UTF-8，全仓构建会因此失败。我只构建/测试了自己与 `internal/store/postgres` 两个包，均干净。

**探针写法（按简报 §4）**：全部在**新包** `internal/zzprobe/pgstore/`，**只新建文件**；未修改、未删除任何已跟踪文件（`git status` 中 `internal/store/postgres/` 只有别的代理新建的 `zzprobe_*` 文件，`postgres.go` 与 HEAD 逐字节相同）。

进程更正（必须如实记录）：本轮中间我曾给 `internal/store/postgres/postgres.go` 加过一行只增不改的探针导出 `func MigrationsFS() fs.FS`，用来让探针读到该包未导出的 `embed.FS`。**这是违反简报「探针只能新建文件」的做法**：它把一个探针专用的 API 放进发布代码。该行已不存在（`git diff --stat -- internal/store/postgres/postgres.go` 为空，`grep 'func MigrationsFS'` 无匹配），按指令以精确反向编辑处理，未动用 `git checkout`/`git restore`/`git stash`。

**现在的 schema 读取机制（取代了过渡期的副本方案）**：探针**直接从磁盘读** `internal/store/postgres/migrations/*.sql`。`go test` 以包目录为工作目录，所以 `internal/zzprobe/pgstore` 里的常量是

```go
const migrationsDir = "../../store/postgres/migrations"   // helpers_test.go
const adapterDir    = "../../store/postgres"               // source_probe_test.go（读 Go 源码用）
```

读取一律走 `filepath.Glob(filepath.Join(dir, "*.sql"))` + `os.ReadFile`；**没有 embed、没有副本、没有从生产包导出任何东西**。目录是解析器参数（`migrationFilesIn`/`readMigrationIn`/`probeTableColsIn`/`indexLeadingColsIn`），这正是让反空转检查能把同一批解析器指向「被故意改坏的暂存副本」的原因。中间态还曾有过一个 `migrationcopy` 子包（逐字副本 + SHA-256 钉住），**已删除**：读磁盘不需要它。

**反空转证据（`disk_read_probe_test.go`，全部 PASS）**：
1. `TestMigrationsDirectoryResolves`：相对路径解析到 `.internal\store\postgres\migrations`，恰好 20 个 `.sql`，首尾两个文件都含 `-- +goose Up`/`Down`；`TestAdapterDirectoryResolves` 对 5 个 Go 源文件做同样的检查。空路径解析会 `Fatal`，不会变成「处处通过」。
2. `TestProbesFailOnAMutationOfTheIndexSchema`：把真实的 20 个迁移复制到临时目录，**删掉** `0012_indexes.sql` 里的 `CREATE INDEX oauth_codes_subject_idx …`，同一套索引解析器必须报告 `oauth_codes.subject` 不再有前导索引；同时断言同表的 `expires_at` 仍被认为有索引（证明解析是「外科式」而不是整体崩掉）。
3. `TestProbesFailOnAMutationOfTheErasureSchema`：把暂存副本 `0011_session_subjects.sql` 的 `subject text NOT NULL` 改名成 `account_ref text NOT NULL`，守卫检测器必须**不再**标记该表；对照组是未改动的 `oidc_access_tokens` 仍被标记。
4. `TestProbesFailOnAMutationOfTheDownSection`：删掉暂存副本 `0006_grants.sql` 的 `DROP INDEX IF EXISTS oauth_access_tokens_subject_idx;`，Down 解析器必须把它报成「存活」。
5. `TestClockScannerDistinguishesGoAndSQLClocks`：给时钟扫描器喂合成源码，同一行区间内一个 SQL `now()` 与一个 Go `s.now()` 必须被分类到不同侧——否则 PG-003 会得出相反结论。
所有 sentinel 都是双向的：先要求「未改动时通过」，再要求「改一处后失败」；`patchMigration` 在找不到目标字面量时 `Fatal`，所以「变了但没变到」不会被误当成「探针没发现」。

---

## 发现

### PG-001 五条批量撤销/删除谓词在 schema 里没有可用索引，且被现有五个索引守卫全部漏掉
- 严重度: 中
- 类别: 性能
- 不变量/性质: 「每条运维/安全路径上的 DELETE 谓词都有前导列索引可用」（迁移 0012/0017–0021 的既定标准）
- 证据: 探针 `TestEverySingleColumnPredicateHasALeadingIndex` 输出（命令 `go test ./internal/zzprobe/pgstore/ -run TestEverySingleColumnPredicateHasALeadingIndex -v`）：

  ```
  UNINDEXED PREDICATE: oauth_access_tokens.client_id is not the leading column of any index (oauth.go:292 revokeMatching with a client-only filter)
  UNINDEXED PREDICATE: oauth_codes.client_id is not the leading column of any index (oauth.go:198 DeleteBySubjectClient: WHERE subject = $1 AND client_id = $2)
  UNINDEXED PREDICATE: oauth_codes.client_id is not the leading column of any index (oauth.go:242 RevokeTokens (legacy): DELETE FROM oauth_codes + filter)
  UNINDEXED PREDICATE: oauth_device_authorizations.client_id is not the leading column of any index (oidc.go:995 …)
  UNINDEXED PREDICATE: oauth_refresh_tokens.client_id is not the leading column of any index (oauth.go:292 revokeMatching with a client-only filter)
  ```

  读；无 DB 执行。核对的索引清单（`migrations/*.sql` 全部 `CREATE INDEX` / `PRIMARY KEY`）：`oauth_access_tokens` 有 `(expires_at)`、`(subject, client_id)`，**无 `client_id` 前导**；`oauth_refresh_tokens` 同；`oauth_codes` 有 `(expires_at)`（0012:34）、`(subject)`（0012:29），**无 `client_id`**；`oauth_device_authorizations` 有 `(upper(replace(user_code,'-','')))`（0001:94）、`(subject)`、`(expires_at)`（0012:30/35），**无 `client_id`**。
  对照组（证明解析器真在读 schema，不是空转）：`vault_credentials.subject`、`federation_bindings.user_id`、`accounts_identities.(provider,subject)`、`sessions.token_hash` 都被判为有前导索引并通过；`TestKnownUnindexedPredicatesAreStillUnindexed` 里若把 `oauth_codes.subject` 误列为缺口会**立刻失败**（0012 给了它索引），这一条我确实先报错、后改正。

  为什么五个既有守卫全漏：`TestEverySweptTableHasADeadlineIndex` 只查 sweep 表的 `expires_at`；`TestRevokeTokenLookupIsIndexed` 只查 `oidc_refresh_tokens.id_hash`；`TestSessionSubjectSweepIsIndexed`、`TestAuditTimeRangeQueryIsIndexed`、`TestClientScopedRevokeIsIndexed` 各自只查一个列、而且最后一条只覆盖 `oidc_access_tokens`/`oidc_refresh_tokens` 两张表（`revoke_predicate_test.go:29` 的 `for _, table := range []string{...}`）。**守卫集合 = 有人想到的集合**，所以 0021 给 `oidc_*` 补 `client_id` 时，legacy 三张表被对称地漏掉了。
- 状态: CONFIRMED（schema 文本级确证 + 可执行探针；未在数据库上观察执行计划）
- 影响: 谁受害：`admin.SuspendClient`/`DeleteClient`（`internal/admin/admin.go:242`、`:260`，注释明说「failures here mean the purge cannot leave the client able to mint new tokens」）、`KillSwitch(target=client)`（`admin.go:309`），以及账号抹除 `lifecycle.DeleteAccount` 里的 `RevokeTokens(Filter{Subject})`（对 `oauth_codes` 而言 `client_id` 不是过滤列，此条不适用，但同一批 DELETE 仍会扫）。
  每次都是对整表 `DELETE FROM oauth_codes WHERE client_id = $1` 的顺序扫描。三张 legacy 表只在**从手写引擎迁移过来的部署**里有数据（`cmd/re0auth/main.go:539`：`store.legacy` 实现 `oauth.TokenAdmin` 才会并进 `revokers`），全新部署是空表所以无代价——这正是它一直没被发现的第二个原因。真实收益：一次运维/事件响应路径上的全表扫描，且在**同一个连接池**里，池的 `statement_timeout` 默认 30s（`postgres.go:128`），「这一刀没切完」是实打实的结果。
- 修法建议: 加一个迁移（0022 形式），四条语句 + 对应的 Down：`CREATE INDEX oauth_codes_client_idx ON oauth_codes (client_id);`、`CREATE INDEX oauth_access_tokens_client_idx ON oauth_access_tokens (client_id);`、`CREATE INDEX oauth_refresh_tokens_client_idx ON oauth_refresh_tokens (client_id);`、`CREATE INDEX oauth_device_authorizations_client_idx ON oauth_device_authorizations (client_id);`（Down 为四条 `DROP INDEX IF EXISTS`）。同时把 `revoke_predicate_test.go:29` 的表清单从写死的两张表改成 `[]string{"oidc_access_tokens","oidc_refresh_tokens","oauth_access_tokens","oauth_refresh_tokens"}`，让对称性成为守卫而不是记忆。
- 复现/守卫: `internal/zzprobe/pgstore/index_coverage_probe_test.go` → `TestEverySingleColumnPredicateHasALeadingIndex`、`TestKnownUnindexedPredicatesAreStillUnindexed`

### PG-002 Down 迁移链在版本 5 上有一道不可回退的洞，`-migrate-down` 会硬报错退出
- 严重度: 中
- 类别: 可用性 / 可维护性
- 不变量/性质: `docs/migration-decision.md`（ADR-0008 §1/§4）承诺的「每个迁移都有 Down，`-migrate-down` 一次退一步」
- 证据:
  - `internal/store/postgres/migrations/` 里不存在 `0005`；`git log --all --name-status --diff-filter=D -- internal/store/postgres/migrations/` 给出 `D internal/store/postgres/migrations/0005_authz.sql`（提交 `87f4ad9` "feat(oidc): P4b——内存模式同样运行 OpenID Provider"）。`docs/architecture.md:759` 记明「`Authz` 与 `authz_requests`（迁移 0005）已在 P4b 一并删除」——即**删除是有意的**，但「有意的删除」与「版本表里仍留着 5」是两件事。
  - `postgres.go:399-407 MigrateDown` → `withMigrationLock` → `provider.Down(ctx)`。
  - goose v3.28.0 `provider.go:412-458 down()`：`dbMigrations[0].Version == 0` 时直接返回；否则 `for _, dbMigration := range dbMigrations { if dbMigration.Version <= version { break }; m, err := p.getMigration(dbMigration.Version); if err != nil { return nil, err } }`（`provider.go:451-457`）。
  - `provider.go:416 getMigration` → 版本不在文件系统里时返回 `ErrVersionNotFound`（`provider_run.go:422`，`provider_errors.go:11`）。
  - 读；无 DB 执行。**推论**：数据库版本表里若有 005（任何跑过含 0005 的历史版本的部署），则
    - `Down` **一步**从 6 退到 5 会**失败**：`ListMigrations` 返回 0..6，循环第一项是 6，`getMigration(6)` 成功、退掉 6；下一次调用时最高是 5，`getMigration(5)` 找不到文件 → `ErrVersionNotFound` → `postgres: migrate: down: version not found`，`-migrate-down` 走 `die("migrate-down", err)` 退出。
    - **向上**方向不受影响：`provider.Up` 用的是 `internal/gooseutil/resolve.go:18 UpVersions(fsysVersions, dbVersions, …)`，`missing` 只由 `fsysVersions` 里的项构成（`:44-51`），已删文件根本不在 `fsysVersions` 里 → 不算 `missing`、不报错、**也不记日志**（goose 对「库里有、文件没了」的版本在 Up 路径上完全沉默）。
  - 顺带确认这条**不是**普遍问题：`TestLeakedIndexesSitOnTablesThatSurviveTheDown`、`TestCreatedTablesSurviveTheirDown`、`TestNoIndexSurvivesTheFullDownSequence` 三个探针全 PASS，即 20 个 Down 段自洽——**没有一个索引或表会在整链回退后残留导致 re-apply 报 `relation already exists`**（我最初写的更严版本报了 15 条，是因为把「Down 未点名索引但其表被 DROP」也当缺陷；`DROP TABLE` 会带走索引，那一版是错的，已在探针里改正并写下原因）。
- 状态: CONFIRMED（行级确证：本仓库代码 + `migrations/` 目录 + 已解包依赖的 goose 源码 `provider.go:451-457`/`provider_run.go:422`；未在数据库上执行）
- 影响: 任何在 P4b 之前部署过、且此后一贯用 `-migrate-down` 逐级回退的运维，会在退到 6→5 这一步卡死，报 `postgres: migrate: down: version not found` 而**没有任何提示说原因是没有 0005 文件**。`ADRS-0008 §4` 说「要回退多步就重复执行」，照做的人正好撞上；文档给的替代路径是 goose CLI（需要那个已删文件），或者从备份恢复。影响有界（不需要回退的部署完全无感），但「按文档做就会踩」使它值得在下一版发布前处理。
- 修法建议: 三选一，**建议第三个**：(a) 把 `0005_authz.sql` 放回去但内容只剩 `-- +goose Up` / `-- +goose Down` 空段（使 `getMigration(5)` 成功且 Down 是 no-op）——最小、可回退，但违背「不重编号、不复活」的洁癖；(b) 在 `MigrateDown` 里把 `goose.ErrVersionNotFound` 映射成一个明确的操作者错误文案（「版本 5 的迁移文件已在该版本中被删除，无法用 -migrate-down 继续回退；请从备份恢复」），至少让失败可解释；(c) 把「版本 5 是永久停点」写进 `docs/migration-decision.md` 的 Consequences，并在 `-migrate-down` 的 `--help` 里写明。无论选哪个，都应为「文件被删」补一条守卫。
- 复现/守卫: 现有 `internal/store/postgres/migrate_down_test.go:23` **接不住**它——它从最高版本**只退一步**就 `db.Migrate` 回填，永远走不到版本 5。建议新增：无 DB 版断言「每个历史版本号要么有文件、要么在 `docs/migration-decision.md` 的已知停点清单里」（需要一份版本清单，可作为 probe 文件），加上一条需要 DSN 的集成版「连续 `MigrateDown` 到 0 并 `Migrate` 回来」。
- 已知前提（不夸大）: 这条只在**版本表里存在 005 的库**上触发，即曾在 `87f4ad9`（删 0005 的提交）之前部署过、此后一直沿用同一份数据库的部署；本仓库无法判断这样的部署是否存在。触发条件是「连续执行 `-migrate-down` 一路退到 6」，不是每一次回退。我把这两条写在这里，是因为一条含混的严重度声明会毁掉整份报告的可信度。

### PG-003 `ApproveDevice` 用数据库 `now()` 判定过期，而同一个设备授权在 Go 侧用 store 时钟判定——同一条 `expires_at` 被两个时钟裁决
- 严重度: 中
- 类别: 可用性（次要安全面：审批窗口比 UI 显示的更长或更短）
- 不变量/性质: 本项目自己写下的「单时钟」政策——`postgres.go:41-46`、`oidc.go:39-45`、`clock_test.go:9-19`：「每条 deadline 必须由写它的那个时钟裁决，SQL 里也一样」
- 证据:
  - 写者（Go 时钟）：`oidc.go:632-639 StoreDeviceAuthorization` 的 `expires` 参数来自调用方，`oidcstore`/`oidc` 库用进程时钟生成；
  - 读/判者之一（Go 时钟）：`oidc.go:1083` `s.now().After(st.Expires)`（`DecideDeviceAuthorization`）与 `oidc.go:1053`（`DescribeDeviceAuthorization`）；
  - 读/判者之二（**数据库时钟**）：`oidc.go:771` `const pending = \`done = false AND denied = false AND expires_at > now()\``，被 `ApproveDevice`（`oidc.go:772`、`:777`）拼进 `UPDATE oidc_devices …`；`oidc.go:684-687` 的慢轮询判据同样只用 DB 时钟：`SET last_poll = now() … AND (last_poll IS NULL OR last_poll <= now() - make_interval(secs => $3))`。
  - 对照实现：内存后端在**这四个位置全部用 `s.now()`**（`internal/store/memory/oidc.go:783-784` 写并判 `lastPoll`、`:799`、`:986` 判过期、`:991` 写 `authTime`）。两个后端因此**行为不同**。
  - `clock_test.go` 覆盖了 sessions、`SweepExpired`、`AuthRequestByCode`、`Grants` 四处（`:29-99`），**没有覆盖任何设备授权路径**——所以这条政策在设备流上是没有守卫的。
  - 读；无 DB 执行。
- 状态: CONFIRMED（行级确证：两处 SQL 字面量 + 内存后端对照 + 守卫覆盖范围；未在数据库上跑时钟偏移）
- 影响: 具体的坏结果，取 `clock_test.go` 用的同一种偏移（应用时钟比库慢 2 小时，即 app = DB − 2h）：
  1. `expires_at` 由 app 写为 `T_app + TTL`。数据库认为它在 `T_db + TTL = T_app + TTL + 2h` 到期。用户在 app 认为「还有 10 分钟」时点同意：`DecideDeviceAuthorization`（Go 时钟）放行 → 落到 `ApproveDevice` 的 `expires_at > now()`（DB 时钟）→ 但此时 `now()` 仍小于 `expires_at`，**这一步反而通过**；真正不对称的是相反方向：库时钟**超前**（app 落后）时，`now()` 已越过 `expires_at`，于是一次**用户界面上仍然有效的审批被拒**，且返回的是 `oauth.ErrDeviceNotFound` 语义的「设备授权不是待决状态」——用户被告知码无效，而 `DescribeDeviceAuthorization` 刚刚说它有效。这就是 R3 在审计读取器上抓到的同一类「早失效」错误（B3-3 的家族），只是换到了设备面。
  2. `last_poll` 只由 DB 时钟写和判，与 app 无关，偏移下节流间隔会漂移，但仍是节流，影响小于第 1 点。
- 修法建议: 把 `ApproveDevice` 的 `expires_at > now()` 改成 `expires_at > $n`（传入 `s.now()`），`last_poll` 的比较也改成 `$n` + Go 侧计算（`s.now().Add(-oidcstore.DefaultDevicePollInterval)`）。这样设备面与其余路径一致，内存/Postgres 两个后端也不再分叉。然后把 `clock_test.go` 扩到设备路径：在 `WithClock(-2h)` 下断言 `DecideDeviceAuthorization` 与 `ApproveDevice` 对同一条记录给出一致裁决。
- 复现/守卫: 无 DB 可跑的部分已写成 `internal/zzprobe/pgstore/clock_source_probe_test.go` → `TestDevicePathsJudgeExpiryWithTheDatabaseClock`（读源码字面量并断言「设备写入路径只由 Go 时钟裁决」——**当前 FAIL，正是因为这条发现**）；`TestOnlyReviewedStatementsUseDatabaseNow` 是它的对照，列出全部 `now()` 出现处并给每条一个理由，防止新增未审的 DB 时钟用法。

### PG-004 `Sessions` 的三个多写操作没有事务，而同一包内其余全部多写操作都有
- 严重度: 低
- 类别: 可用性 / 数据一致性（幂等自愈，故不高于低）
- 不变量/性质: 同包内一致性：凡是「多语句 = 一个语义结论」的写操作，都在一个事务里（`oauth.go:182-201`、`oidc.go:403-419/893-931/948-973/1013-1047`、`account.go`、`sweep.go:50-70`、`auditchain.go:145-186` 全部如此）
- 证据: 探针 `TestMultiStatementMutationsRunInATransaction`（`go test ./internal/zzprobe/pgstore/ -run TestMultiStatementMutationsRunInATransaction -v`）输出：

  ```
  CONFIRMED NOT ATOMIC: sessions.go RevokeAllSessions issues 3 write(s) with no transaction
  CONFIRMED NOT ATOMIC: sessions.go RevokeSubjectSessions issues 2 write(s) with no transaction
  CONFIRMED NOT ATOMIC: sessions.go SweepExpired issues 2 write(s) with no transaction
  CONFIRMED NOT ATOMIC: oauth.go RevokeTokens issues 2 write(s) with no transaction
  CONFIRMED NOT ATOMIC: oauth.go PurgeLegacySubject issues 3 write(s) with no transaction
  ```

  同一探针的对照组断言上述 6 个文件的 12 个多写方法（`DeleteBySubjectClient`、`RevokeGrant`、`TerminateSession`、`PurgeSubject`、`RevokeTokens`(oidc)、`revokeInOneTx`、`DeleteAuthRequest`、三个 account 方法、`SweepExpired`、`appendBatch`）**确实**含 `.Begin(`，所以「有事务」这一侧不是空转。行级确证：`sessions.go:168-177`（`DELETE FROM sessions` 然后 `DELETE FROM session_subjects`，返回 `tag.RowsAffected()` 只数第一句）、`sessions.go:186-196`（先删 sessions 再删 session_subjects）、`sessions.go:143-155`（先删 sessions 再删孤儿索引行，失败时 `return tag.RowsAffected(), err`）、`oauth.go:236-246`（`revokeMatching` 不带 tx + `DELETE FROM oauth_codes`）、`oauth.go:263-274`（两条 DELETE 无 tx）。读；无 DB 执行。
- 状态: CONFIRMED（源码级确证 + 可执行探针）
- 影响: 中间被打断（本机崩溃、语句超时、context 取消）时留下半应用状态。逐条说清收益：
  - `RevokeSubjectSessions` 在两句之间失败：sessions 行已删、`session_subjects` 索引行还在。后续按 subject 的 Kill Switph 仍会尝试删已不存在的 session（无害），而**孤儿索引行**要等下一次 sweep（15 分钟 + 1 小时宽限，`sessions.go:164`）才收；期间它无害（没有任何读路径会读到没有 session 的索引行）。**结论：收益是「残留不一致窗口」，不是鉴权绕过**——我特意核对了这一点，避免把它写成更高严重度。
  - `RevokeAllSessions` 在两句之间失败：Kill Switch `all` 的 `sessions_revoked` 计数已经返回（`admin.go:329` 用它写报告），但 `session_subjects` 尚未清空——下次按 subject 撤销仍能找到索引，**不会漏掉任何活会话**（活会话已经没了）。
  - `oauth.go RevokeTokens` / `PurgeLegacySubject`：只影响 legacy 表；调用方（`lifecycle`、`admin`）都会返回错误，重试幂等。
- 修法建议: 给这五个方法各加 `tx, err := s.pool.Begin(ctx); defer tx.Rollback(ctx)` 包起来（照抄 `DeleteBySubjectClient` 的形状即可），`RowsAffected` 用同一个 tx 的两条 tag 相加。这是纯机械改动，且能让 `TestMultiStatementMutationsRunInATransaction` 从「记录」升级为「强制」。
- 复现/守卫: `internal/zzprobe/pgstore/atomicity_probe_test.go` → `TestMultiStatementMutationsRunInATransaction`

### PG-005 `deviceState` 的 WHERE 片段是函数参数，唯一挡住注入的是「两个调用点恰好都写常量」
- 严重度: 低（当前无可达缺陷；是形状风险）
- 类别: 安全（纵深防御）
- 不变量/性质: 「进入 SQL 的字符串只能是编译期常量」——这是 `oauth.go:286-287`、`sweep.go:47-49`、`oauth.go:311-312` 三处注释明确立下的规矩
- 证据: `oidc.go:705 deviceState(ctx context.Context, where string, args ...any)`，其 SQL 是 `` `SELECT … FROM oidc_devices WHERE ` + where ``（`oidc.go:710-712`）。这是全适配器里**唯一**一处「SQL 片段作为参数传入」的位置（对照：`auditread.go` 的 `add(column, op, value)` 只接常量列名 + `$n` 占位符，值走参数；`revokePredicate` 只产出列名与 `$n`）。探针 `TestDeviceStateWhereArgumentIsOnlyEverALiteral` 逐个检查调用点：3 处（`oidc.go:693`、`:702`、`:757`），**全部以反引号字面量实参**，当前安全。读；无 DB 执行。
- 状态: CONFIRMED（形状与调用点确证；当前**不是**缺陷，因为三个实参都是常量）
- 影响: 今天没有攻击者收益。风险在于可扩展性：任何第三个调用者把一个由请求值拼出来的字符串传进来，就是一处注入。类型系统、守卫、注释都不阻止它——探针是唯一会失败的检查。我把它写进报告而不写进「探过没破」，是因为「唯一的防线是一个刚好成立的事实」本身值得留一条守卫。
- 修法建议: 换成枚举或闭包：`func (s *OIDCStore) deviceStateByCode(ctx, hash, clientID string)`，把 WHERE 收回函数内部；或保留签名但在里面加 `if where != deviceByCode && where != deviceByUserCode { return nil, errors.New(...) }` 白名单。前者更好（无法误用）。
- 复现/守卫: `internal/zzprobe/pgstore/index_coverage_probe_test.go` → `TestDeviceStateWhereArgumentIsOnlyEverALiteral`；`TestNoGoSourceBuildsSqlFromARequestValue` 扫描 8 个适配器文件里全部 17 处 SQL 字符串拼接，断言每一处都在已复核清单内（表名/列名常量、`clause`/`table`/`where` 三个构建器）。

### PG-006 抹除静态守卫(PG) 看不见 `ALTER TABLE ADD COLUMN`、看不见 `subject`/`user_id` 以外的命名
- 严重度: 低
- 类别: 合规/隐私（守卫覆盖度）
- 不变量/性质: 「任何持有账号引用的表都会在 PR 阶段被 `TestEverySubjectColumnIsHandledByErasure` 拦下」（该测试注释与 `erasure_schema_test.go:35-43` 的自我描述）
- 证据: 探针 `TestErasureGuardSeesEverySubjectColumnInTheRealSchema` 及其同文件输出（`go test ./internal/zzprobe/pgstore/ -run 'TestErasureGuard' -v`）：
  - `TestGuardReproductionAgreesWithTheGuard` PASS：我逐行复刻的检测器（复制 `hasAccountColumn` 的算法）对 14 张账本表的裁决与包内 `erasureHandledTables` ∪ `accountTablesIgnored` 完全一致，**证明下面的缺口不是解析器写错**。
  - `TestErasureGuardMissesAlterTableAddColumn` PASS：`ALTER TABLE some_table ADD COLUMN subject text NOT NULL DEFAULT ''` **不被检测**——守卫只扫 `CREATE TABLE`（`erasure_schema_test.go:59`），而 migrations 里 `ALTER TABLE ADD COLUMN` 已被用过 **8 次**（`TestNoAlterTableAddsASubjectColumnToday` 实测计数：0009×2、0010×1、0013×3、0015×1、0016×1）。也就是说：这条最自然的「给已有表加账号引用」的机制，对 PR 门禁是隐形的。
  - `TestErasureGuardOnlyRecognisesTwoExactColumnNames` PASS：`account_id`、`owner`、`user`、`identity_subject`、`sub` **都不被检测**；对照 `subject`、`user_id` 被检测。
  - `TestErasureGuardIsBlindToAccountIdsInsideJsonAndBlobs` PASS：`audit_events.detail jsonb`、`sessions.data bytea`、`vault_credentials.meta jsonb` 三列都能装账号 id 而守卫按列名推理，**原理上看不进去**。
  - 读；无 DB 执行。注意守卫的集成版（`erasure_test.go:246-249`）用的是同两个列名（`WHERE column_name IN ('subject','user_id')`），所以**两个方向都是同一个盲区**——它能覆盖 `ALTER TABLE` 加出来的列（走 `information_schema`），但同样只认那两个名字。
- 状态: CONFIRMED（可执行探针 + 包内源码行级对照）
- 影响: 一个 PR 可以：给任意已存在表 `ALTER TABLE … ADD COLUMN subject text`，或用 `account_id` 命名一张新表并写入 `usr_…`，而**没有任何 PR 门禁会响**；只有在 CI 里跑到需要 DSN 的 `TestAccountDeletionLeavesNoOrphans` 时才会暴露（该测试的 `subjectOrphans` 只对被抹除账号的那一行计数，所以一个只对**其他**账号泄漏的列仍然合法）。这是「守卫被当成已解决」的典型：A5-3 把守卫从一张表扩到整个 schema，但扩的是**表**的覆盖面，没扩**列名**与**语句类型**的覆盖面。
- 修法建议: 三件小事：(1) 守卫改成解析 `ALTER TABLE … ADD COLUMN` 与 `CREATE TABLE` 两种语句（探针里的 `addColumnRE` 可直接复用）；(2) 列名匹配改为「规范化后包含 `subject`/`user_id`/`account`/`owner`/`user`」并保留显式豁免表（`oauth_clients.id` 之类）；(3) 给 `jsonb`/`bytea` 列加一份**显式登记**（列名 + 理由），新增一个 jsonb 列时强制在 PR 里说明「它不会装账号 id」。这三条都不需要数据库，正是 `erasure_schema_test.go` 已有的形态。
- 复现/守卫: `internal/zzprobe/pgstore/erasure_guard_probe_test.go` → `TestGuardReproductionAgreesWithTheGuard`（对照）、`TestErasureGuardSeesEverySubjectColumnInTheRealSchema`（对照）、`TestErasureGuardMissesAlterTableAddColumn`、`TestErasureGuardOnlyRecognisesTwoExactColumnNames`、`TestErasureGuardIsBlindToAccountIdsInsideJsonAndBlobs`、`TestNoAlterTableAddsASubjectColumnToday`（断言今天确实没有用 ALTER TABLE 加账号列——它是这条缺口的临时护栏）

### PG-007 `secret_hash` 列可存明文而 schema 不拦；`session_subjects.subject` 可存空串
- 严重度: 提示
- 类别: 安全（纵深防御） / 合规/隐私
- 不变量/性质: 「J1 约定：不透明凭据只以摘要入库」（0001 头注释）与「任何持有账号引用的列都不含空值」
- 证据:
  - `oauth_clients.secret_hash bytea`（`0001_init.sql:102`）**没有 CHECK、没有 NOT NULL**；唯一阻止明文入库的是 Go 侧 `oauth.Client.SecretHash()` + `nullableBytes()`（`oauth.go:435`、`oauth.go:594-601`）。列类型是 `bytea`，所以即便有人写入 68 字节的 ASCII 明文，schema 也照收。`credential_columns_test.go:32` 的豁免理由是「sha256 of the client secret」——那是对**当前代码**的描述，不是 DB 保证。读；无 DB 执行。
  - `session_subjects.subject text NOT NULL`（`0011_session_subjects.sql:18`）允许空串；唯一阻止它的是 Go 侧 `Remember` 的调用方。对照：同一张表在语意上「`subject` 为空」等于「这条索引无用」，而空串会让按 subject 的撤销**永远匹配不到**（`sessions.go:192` `WHERE subject = $1` 用非空 subject 调用，所以空串行只是垃圾）。读；无 DB 执行。
  - 复核「`federation_bindings` 不持有凭据列」这一宣传：`0003_federation.sql:13-23` 的全部列为 `user_id, game, source, token_type, expiry, has_refresh, version`——**成立**，唯一命中凭据词表的 `token_type` 存的是 token **类别**（`token_class`），且 `credential_columns_test.go` 已把它登记在豁免表里并说明理由。这一条我确认没有可报的缺陷。
- 状态: CONFIRMED（schema 文本 + Go 侧写路径行级阅读）
- 影响: 攻击者收益为零（当前没有明文写入路径）；运维收益是「一次手写 INSERT / 一次数据修复脚本可以把明文密钥塞进一个叫 `_hash` 的列，没有任何东西会抱怨」。
- 修法建议: 加 CHECK 约束（低风险、幂等）：`ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_secret_hash_is_sha256 CHECK (secret_hash IS NULL OR octet_length(secret_hash) = 32);` 以及 `ALTER TABLE session_subjects ADD CONSTRAINT session_subjects_subject_not_blank CHECK (subject <> '');`。第二条要确认历史数据（迁移前可能有空 subject 行）——**需要裁定**：如果存在空串历史行，改成 `NOT VALID` 再逐步验证。
- 复现/守卫: 无（schema 文本断言，未写探针——写上会产生「今天为真、加约束后仍需维护」的空守卫；建议直接加约束，由迁移本身成为守卫）

### PG-008 审计读取器把整条链走完并全程持有事务，`statement_timeout` 不构成总时长上界
- 严重度: 低
- 类别: 可用性（连接池占用）
- 不变量/性质: `postgres.go:106-109` 对 `statement_timeout` 的说明：「没有任何查询活得比发起它的请求更久。一条超出请求的语句会占住一个后端、可能还有锁，而调用方已经放弃了」
- 证据: `auditchain.go:220-331 Verify`：`tx, err := l.pool.Begin(ctx)` → `SET LOCAL statement_timeout = 45s`（`:229-232`）→ `SELECT head_hash FROM audit_chain`（`:239`）→ **`SELECT … FROM audit_events ORDER BY id`**（`:243-247`，全表、无 LIMIT）→ 逐行在 Go 里重算 SHA-256 + HMAC（`:258-314`）→ 结束时 `defer tx.Rollback`（`:227`）。`verifyStatementTimeout` 注释（`:189-199`）自己写明「Verify 走遍每一行 chained row」，所以 45s 是**单条语句**的上界，不是这个 handler 的时长上界；期间这条连接一直属于该事务（行是流式读的，planner 的游标保持打开）。`internal/httpapi` 的服务端 `writeTimeout` 注释说 60s，所以最坏情况下客户端在 socket 层被切断，而事务与连接还要等 45s 的那条语句超时才归还。读；无 DB 执行。
- 状态: HYPOTHESIS（要证实需要：一个 10^6 量级的 `audit_events` 表 + `GET /v1/admin/audit/verify`，观察 `pg_stat_activity` 里该连接的状态与 `writeTimeout` 触发顺序；本机无 DB 不能做）
- 影响: 审计日志越大，`/v1/admin/audit/verify` 占用连接池的时间越长；池上限 16（`postgres.go:126`）。并发几次 verify（一个操作员点两下、或一个被认证的运维账号反复调用）就能吃掉相当比例的池，与 `ADRS-0008` 的「池是给请求用的」设定冲突。它是认证端点，所以不是匿名 DoS。
- 修法建议: 三种，按代价排序：(1) 把 `Verify` 改成**分批**：按 `id` 区间 `LIMIT n` 循环，每批一个事务、批间释放连接（需要保留 prev_hash 作为跨批状态，但这正是链的性质，天然支持）；(2) 至少把 `SET LOCAL statement_timeout` 的解释写清它**不是**总时长上界，并在 handler 侧加一个比 `writeTimeout` 更小的 context 超时；(3) 承认它并记录在 capacity-planning 里。我倾向 (1)，因为它是唯一让成本与「被验证的行数」成正比而不是与「日志总长」成正比的改法。
- 复现/守卫: 需要 DSN。建议集成探针：插入 N 行后用极小的 `statement_timeout` / 一个短的 ctx 调 `Verify`，断言「ctx 取消后连接在 ≤1s 内回到池里」（`pgxpool.Stat().AcquiredConns()`）。

### PG-009 `oidc_access_tokens` / `oidc_refresh_tokens` 的过期索引在使用它们的那条删除里不可用
- 严重度: 提示
- 类别: 性能
- 不变量/性质: 「每个搜索条件都有可用索引」（0012/0017–0021 的既定标准）
- 证据:
  - `sweep.go:60-61`：`DELETE FROM oidc_access_tokens WHERE expires_at < $1`。索引：`oidc_access_tokens_expires_idx (expires_at)`（`0008_oidc.sql:50`）与 `oidc_access_tokens_subject_issued_idx (subject, issued_at)`（`0009:8`）。按单列条件，planner 会先选行数更少的那个索引；由于 token 表按 subject 增长，`(subject, issued_at)` 的条目数在多数时刻远少于 `(expires_at)`，估计器可能选它，然后把该索引的全部条目读出来过滤 `expires_at`。读；无 DB 执行，**不能断言 planner 一定选错**，所以只报「存在这个可能」。
  - 对照：这张表同时有 `(subject, client_id)`（`0008:51`）与 `(subject, issued_at)`（`0009:8`）两个 subject 前导索引。多索引本身是每写的成本（每 INSERT 维护 4 个索引 + 1 个 PK），不值得报，但说明「补索引时没有回头看已有哪些」。
- 状态: HYPOTHESIS（要证实需要 `EXPLAIN (ANALYZE)` 一条真实体量下的 sweep DELETE；本机无 DB。要证伪只需 `EXPLAIN` 显示选了 `expires_at` 索引——所以我把它标为假说而不是缺陷）
- 影响: 若 planner 选错，每 15 分钟的定时清扫在最大的 token 表上退化。有界（定时任务、单条语句、`statement_timeout` 30s 兜底）。
- 修法建议: 不需要新增索引（`expires_at` 已有）。**先测量**：在真实体量下 `EXPLAIN (ANALYZE, BUFFERS) DELETE FROM oidc_access_tokens WHERE expires_at < now();`。如果确实选了 subject 索引，考虑把 0008 建的单列 `(expires_at)` 与 0009 的 `(subject, issued_at)` 合并考虑，或对 sweep 用 `WHERE expires_at < $1` 的**部分索引**（`WHERE expires_at < ...` 不适合；改为不提索引，交由 sweep 直接走 `(expires_at)`：可加 `SET LOCAL enable_indexscan` 之类不可控）。实际最稳的做法是让 sweep 用 `ctid` 分批删除，或用 `DELETE ... WHERE id_hash IN (SELECT id_hash FROM … WHERE expires_at < $1 LIMIT 1000)` 循环——但**这属于调优，建议先测**。
- 复现/守卫: 需要 DSN；建议在 CI 里加一条 `EXPLAIN` 断言（`bench/` 目录已有 perf 工作流的先例）。

### PG-010 `LookupClientNames` 用 `ANY($1)` 传数组，且这个查询在 `/v1/grants` 的每次请求里跑
- 严重度: 提示
- 类别: 性能
- 不变量/性质: 无（记录一次读路径的规模假设）
- 证据: `oauth.go:478-496`：`SELECT id, name FROM oauth_clients WHERE id = ANY($1)`，`ids` 由调用方从「本次请求里出现过的 client_id 集合」构造（`oidc.go:872-876` 与 `oauth` 侧同形）。`oauth_clients` 是运维规模的表（几十到几百行），`id` 是主键，`ANY` 展开成 `= ANY(ARRAY[...])` 后可以走 PK。整表也就几百行，所以这条**没有实际代价**——我把它写出来是为了把「我检查过这条」留痕，不是缺陷。读；无 DB 执行。
- 状态: CONFIRMED（无缺陷；作为「探过没破」的一部分记录在此以免被当成漏检）
- 影响: 无。
- 修法建议: 无需改。
- 复现/守卫: `TestEverySingleColumnPredicateHasALeadingIndex` 的清单里 `oauth_clients.id` 依赖 PK，已被 `seen >= 25` 的对照组覆盖。

---

## 探过但没破的（这些也应变成守卫）

本节逐条说明**为什么它成立**，以及**哪个探针/测试现在守着它**。前两轮已报并已修的项目另列在最后。

1. **SQL 注入（本轮最花力气的一条）**。适配器共 7 处拼接 SQL：`sweep.go:60`（`expiredTables` 字面量）、`oauth.go:292`（每个调用点传字面量表名切片）、`oauth.go:317/321`（列名 `client_id`/`subject` 字面量 + `$n` 值）、`oidc.go:988/994`（同上）、`auditread.go:43/84`（列名与操作符是常量实参，值走 `$n`，`LIMIT` 也是 `$n`）、`oidc.go:712`（见 PG-005）。**没有任何一处把请求值放进 SQL 文本**。执行证据：`TestNoGoSourceBuildsSqlFromARequestValue` 扫 8 个文件的 17 处拼接并逐处对照已复核清单。另外把 `?since=`/`?until=`/`?cursor=` 的解析点读了（`internal/httpapi/audit_routes.go:54-99`：`limit` 走 `Atoi` 正整校验、`cursor` 走 `ParseInt` 并拒绝 <1、时间走 RFC3339 解析并**拒绝能解析成零值的界**）——B3-3 的修法在这里，且它确实把「零值被当成没有界」这条路堵住了。
2. **续期轮换的 CAS 与单次使用**。`oidc.go:348-357`：先 `DELETE FROM oidc_refresh_tokens WHERE token_hash = $1` 并检查 `RowsAffected()==0 → ErrRefreshTokenSpent`，同事务内再插新对；注释说明 READ COMMITTED 下并发 DELETE 会阻塞后见空。这是正确形状（claim-then-mint）。`oauth.go:105-123 ConsumeRefresh`、`federation.go:197-216 BindFlows.Consume`、`oidc.go:186-222 AuthRequestByCode`（**DELETE 即认领**，且 `expires_at > $2` 用 store 时钟）、`oidc.go:657-703 GetDeviceAuthorizatonState`（**DELETE…RETURNING 即认领**，单次使用）都是同一形状。**没有找到「读后写」的版本**。
3. **I-2 地板检查**：`account.go:143-194` 在一个事务里 `SELECT id FROM accounts_users WHERE id=$1 FOR UPDATE` → 计数 → 删 → 重指 `primary_identity`。锁的是**用户行**，两个并发 unlink 会串行化，不会都看到「还剩 2 个」然后各删一个。I-3 由 `UNIQUE (provider, subject)`（`0001:35`）+ `isUniqueViolation→ErrIdentityTaken`（`account.go:79-82`、`:130-133`）保证，不靠 Go 侧 read-then-write。
4. **审计链头的串行化**：`auditchain.go:152-153` `SELECT head_hash FROM audit_chain WHERE only_row FOR UPDATE` 在同一事务里，之后 `INSERT` 批次 + `UPDATE audit_chain`（`:179-181`）再提交；`auditbatch.go:160-194` 保证一个 goroutine 按入队顺序成批写，所以「同一前驱被两个写者读到」不可能。
5. **sweep 与在途请求的交叠**：`sweep.go` 的每条 DELETE 都以 `< $1`（本进程时钟，`:57`）为条件，而所有读路径都以「未过期」为放行条件（`oidc.go:195`、`oauth/device.go:286`、`oidc.go:600`），所以被扫掉的行其写者已判死——**不会删掉在途请求手里的东西**。`session_subjects` 的宽限窗口问题（第二轮已修）我复核了 `0015` + `sessionIndexGrace = "1 hour"`（`sessions.go:164`）+ `TestSweepSparesAFreshIndexRowAndCollectsAnAgedOne`（`postgres_test.go:1401`）确实成立。`SweepExpired` 用的是 DB `now()` 写、Go 时钟比——但只用于**相对**的 `now() - $1::interval`，偏移抵消，所以这里混用两个时钟无害（这一点值得注意：`sessions.go:132-136` 的注释正是这么说的）。
6. **Down 段的表/索引自洽性**（PG-002 的另一半）：`TestCreatedTablesSurviveTheirDown`、`TestLeakedIndexesSitOnTablesThatSurviveTheDown`、`TestNoIndexSurvivesTheFullDownSequence` 三个探针全 PASS——20 个迁移里每一个 `CREATE TABLE` 都被同文件 Down 的 `DROP TABLE` 覆盖，且没有任何索引会在整链回退后残留。**我最初写的一版报了 15 条「泄漏索引」，是假阳性**（`DROP TABLE` 会带走索引），已在探针里改正并写下原因，此处留痕以免别人重犯。
7. **advisory lock 的释放**：`postgres.go:348-354` `pg_advisory_lock` 后 `defer` 用 `context.WithoutCancel(ctx)` 解锁（`:353`），且 `defer conn.Close(...)`（`:346`）在其后注册、先执行……**顺序上** defer 是 LIFO：`:346` 的 Close 注册更早，所以执行更晚，解锁先跑；即使解锁失败，Close 断开连接时 PostgreSQL 会释放会话级 advisory lock。**panic 也走 defer**，所以「panic 时锁不释放」不成立。
8. **池参数真的到达驱动**：`postgres.go:224-248 poolConfig` + `pool_test.go:19 TestPoolConfigAppliesEveryBound` 断言 7 个边界全部落到 `pgxpool.Config`（含 `statement_timeout=30000`）；生产路径 `cmd/re0auth/config.go:900-906` 用 `DefaultPoolOptions()` 初始化，30s 生效。零值 `PoolOptions{}` 会**故意**保留 `MinConns=0` 与 `StatementTimeout=0`（`postgres.go:144-168` + `pool_test.go:72` 有注释与反空转断言），生产只有 `cmd/re0auth/main.go:815` 一个调用点且字段全填，所以不是缺陷（我在 `internal/httpapi/oidc_wiring_test.go:43` 见到 `PoolOptions{}`——那是测试）。
9. **请求路径上的 context**：全包 `context.Background()` 只出现在 `sessions.go:50/61/98`（`scs.Store` 的非 Ctx 方法，**scs 会优先用 `FindCtx`/`CommitCtx`/`DeleteCtx`**，`sessions.go:39-42` 有编译期断言，`postgres_test.go:967` 断言实现了 `scs.CtxStore`）与 `auditbatch.go:187`、`sessions.go:117` 的 `context.WithoutCancel`（**故意**：丢掉客户端取消但保留自己的 deadline，各自有 5s 上界）。`pool_exhaustion_test.go:18` 证明池耗尽时按 ctx deadline fail-fast。
10. **错误映射不漏、也不由失败变成功**：`postgres.go:473-479` 按 SQLSTATE 判 23505 并映射成 `account.ErrIdentityTaken` / `op.ErrDuplicateUserCode`（不携带驱动错误文本，不泄漏约束名）；`noRows` 只认 `pgx.ErrNoRows`。逐条检查了所有「RowsAffected()==0」：`CompleteLogin`（`oidc.go:749`）、`SetAuthTime`（`:732`）、`RecordPoll`（`oauth.go:373`）、`ApproveDevice`（`oidc.go:784`）、`DenyDevice`（`:807`）、`SetStatus`（`oauth.go:507`）**全部返回错误**，没有一处把它当成功。执行证据：`TestUniqueViolationMappingDropsNoSQLDetail`。**没有找到 fail-open 形状**——这一条我特意找了（简报说这是最高价值），结论是负面的（即未发现）。
11. **schema 常量与扫描**：`vault.version smallint` ↔ Go `byte`（`vault.go:65/92/115`），`federation_bindings.version bigint` ↔ 透过 `int64` 中转以做到位精确（`federation.go:150-167` 有注释），`oauth_device_authorizations.last_poll timestamptz` ↔ `nullTime()`/`*time.Time`（`oauth.go:342`、`:403-406`），`oidc_*.auth_time` ↔ `*time.Time`（`oidc.go:204/230/661`）——**没有一处把可能为 NULL 的列扫进非指针 `time.Time`**，R3 在审计读取器上抓到的那一类在这里不成立（`audit_events` 的 `occurred_at` 是 `NOT NULL`）。`audit.go:63` 把时间 `Truncate(time.Microsecond)` 后再算 hash，`auditchain.go:65` 用 `UnixMicro` 参与 canonical，两者一致；`audit_events.detail jsonb` ↔ `map[string]string`（`auditchain.go:168`）往返一致。
12. **`audit_subject_keys.idx` 不存原始 subject、`Destroy` 幂等、长度校验**（A5-1 家族，已修）以及 **`Verify` 的链头见证**（B3-1，已修）我复核了实现：`auditpseudo.go:53-56` idx 是带密钥哈希；`checkSubjectKey`（`:101-107`）在读路径两处都调用；`auditchain.go:318-328` 用 head 非空而 chained==0 判失败。
13. **`federation_bindings` 不持有凭据列**（承诺复核）：见 PG-007 第二半，**成立**。
14. **`appendBatch` 的失败传播**：`auditchain.go:176` 的 `tx.SendBatch(...).Close()` 无错误 → 后续 `UPDATE` + `Commit` 都在同一事务，`auditbatch.go:191-193` 把同一个 `err` 广播给批次里每个调用者；`enqueue`（`:96-128`）在 ctx 已取消时**先于入队**返回错误，使 `vault.Use` 不会在拿不到确认时交出明文。fail-closed 形状成立。

## 未能到达（残余盲区）—— 必须写，并说清为什么

1. **所有需要 Postgres 的结论都没有执行过。** 本机无 Docker、无 Postgres、`TEST_DATABASE_URL` 未设置，`internal/store/postgres` 的集成测试全部走 `t.Skip`（`postgres_test.go:42-48`）。因此以下都只是行级阅读：并发交叠的实际行为、planner 是否选中我担心的索引（PG-001 的严重度、PG-009）、`Verify` 的实际持有时长（PG-008）、`make_interval(secs => $3)` 在 pgx 参数推断下是否真的成功（我读的是 `oidc.go:687` 与 pgx v5 的 codec 行为，**没有验证**；`TestDevicePollingIsThrottled` 在 CI 里覆盖它，本地 SKIP）、`MigrateDown` 在版本 5 上的实际报错文本（PG-002 我用 goose v3.28.0 的源码 `provider.go:451-457` 推出结论，没有跑过）。
2. **PG-005 的「当前安全」是源码级而非运行时证据**：我读完了 8 个文件的全部拼接点，但正则扫描可能漏掉形如 `fmt.Sprintf` 或跨行拼接的写法——我用 `strings.Contains(line, "`+"|`\"+"`)+人工复核 17 处的方式做了双保险，仍未等价于一次 AST 分析。
3. **探针所读的 schema 与源码都是磁盘上的生产文件**，由 `TestMigrationsDirectoryResolves`（20 个迁移，含首尾文件名与 goose 形状断言）与 `TestAdapterDirectoryResolves`（5 个 Go 源文件的 `package postgres` 断言）证明路径解析正确，并由 `disk_read_probe_test.go` 的四个「故意改坏暂存副本」sentinel 证明解析器会因此失败。**仍未到达的部分**：探针无法察觉生产包改用**别的**加载方式（例如迁移从别处读取）——那种改动不会改变磁盘上这些文件，因此不会让任何 sentinel 变红。
4. **`-migrate-down` 与运行中实例的交叠**：`withMigrationLock` 只串行化**迁移者之间**。一个已在服务流量的实例在新实例/运维跑迁移时继续查询，会在 `DROP COLUMN`/`ADD COLUMN … NOT NULL` 的窗口里看到半迁移 schema（`oauth_clients.status` 被 0010 的 Down 删掉时，旧二进制 `oauth.go:433` 的 INSERT 里点名了 `status` → 必然报错）。`docs/migration-decision.md` §2 把「不得在同一次发布里既加列又依赖它的回填」「删列要延后一版」写成规则，**但没有一条规则禁止 Down 破坏性删列**——而 Down 的定义就是回退。我**无法在本机验证**这个窗口的长度与触发概率，故只作为盲区记录，并把「ADR-0008 §2 应明确覆盖 Down 方向」写成 §判断。
5. **`oauth.Service`（legacy 引擎）在 Postgres 上的完整路径**：`db.Devices()`（`oauth.go:332-395`）在 `cmd/re0auth/` 里**没有任何调用点**（只被 `postgres_test.go:410` 用），所以 `RecordPoll`/`RecordDecision`/`GetDeviceByUserCode` 对生产部署不可达；但 `db.Tokens()`（`oauth.go:21-227`）**是**可达的（`cmd/re0auth/main.go:539-541` 把它并进 `revokers`，`:849` 装进 `store.legacy`）。我按「可达」处理了 `Tokens.RevokeTokens`/`PurgeLegacySubject`，按「不可达但保留」处理了 `Devices`——如果后续有部署把 `Devices()` 接进 HTTP 面，PG-001 里 `oauth_device_authorizations` 相关的两条会立刻变成活路径。
6. **`audit_events` 的容量策略**：表只增不减，`expiredTables`（`sweep.go:26-37`）刻意不含它。`docs/operations-decision.md:22` 提到「需要缩短保留期时正确做法是归档整段（含链锚）后……」——我据此不报「无保留期」，但**没有验证归档脚本存在**（`scripts/` 未在本次范围内读完）。

## 判断（文档化决定可否质疑，不是 finding）

1. **ADR-0008 §2 的 expand/contract 规则没有覆盖 Down 方向。** 规则写的是「一版不得既加列又依赖其回填」「删列/改类型/收紧约束延后一版」。但 `Down` 段本身就是删列/改类型/收紧约束，而 §4 又把 `-migrate-down` 定义为「撤销我刚应用的这一步」的受支持操作。于是出现一条无规则区：**在服务仍在跑的情况下执行一次 `-migrate-down`，就可能让仍在运行的实例与 schema 不兼容**（具体例：0010 的 Down 删 `oauth_clients.status`，而 `oauth.go:433` 的 INSERT 点名了它）。我**不建议**改成「禁止破坏性 Down」（那会破坏 down 的语义），而是建议在 ADR-0008 里补一条：「Down 只在停机窗口或已把流量摘干净后执行；`-migrate-down` 的前置条件是没有任何实例在服务」。这是文档裁定，不是代码缺陷。
2. **`oauth_device_authorizations.user_code` 只有非唯一表达式索引**（`0001:94`），而 `oidc_devices.user_code` 用了 `CREATE UNIQUE INDEX`（`0008:81`），并且在 `StoreDeviceAuthorization`（`oidc.go:640-642`）里把唯一冲突映射成 `op.ErrDuplicateUserCode` 让库重试。legacy 侧的 `oauth.Service.freeUserCode`（`oauth/device.go:432-459`）是「先查再插」：两次并发 `DeviceAuthorization` 可能都通过 `GetDeviceByUserCode` 看到空位，然后都插入——`GetDeviceByUserCode`（`oauth.go:355-361`）会返回其中**任意一行**，于是两个不同设备拿到同一个 user 码，用户批准的是「另一个设备」的授权。**但这张表在当前组合根里没有写者**（`db.Devices()` 无调用点，见盲区 5），所以今天不可达；我据此把它写成判断而不是 finding。如果哪天真把它接上，它是需要立刻修的一条。
3. **`sessions` 表没有把「同一 token 的并发提交」区分开的列**：`Commit` 是 upsert（`sessions.go:120-127`），token 是 scs 生成的随机值，所以并发只可能来自同一个客户端重复请求——无收益，不必改。记录在此以免后续有人把它当成「缺少乐观锁」。
4. **`-migrate-down` 回退后 `provider.Up` 对「库里有版本、文件已删」完全沉默**（见 PG-002 证据链的 goose 代码）。我理解「沉默」是 goose 的取舍，但本项目 `Open()` **无条件** `Migrate()`（`postgres.go:207`），所以一个被误删的迁移文件不会有任何启动期信号。建议在 `Migrate` 里加一句显式核对：读 `goose_db_version` 的全部 `is_applied` 版本，逐个 `provider.GetMigration`（或落到 `p.migrations` 里的版本集合），对不上的记一条 `slog.Error` 并以非零退出——这让「删了一个迁移文件」成为一个响亮的启动失败，而不是一个安静的跳过。这是加固建议，不是缺陷。

---

## 探针文件清单（全部为新建文件，未修改、未删除任何已跟踪文件）

| 文件 | 关键测试函数 |
|---|---|
| `internal/zzprobe/pgstore/helpers_test.go` | 磁盘读取（`migrationsDir` / `migrationFilesIn` / `readMigrationIn` / `probeTableColsIn`）+ 独立 schema 解析器 + `guardAccountColumn`（`erasure_schema_test.go` 检测器的逐行复刻） |
| `internal/zzprobe/pgstore/source_probe_test.go` | `adapterDir`、`classifyNowForTest`、`TestAdapterDirectoryResolves` |
| `internal/zzprobe/pgstore/disk_read_probe_test.go` | `TestMigrationsDirectoryResolves`、`TestProbesFailOnAMutationOfTheIndexSchema`、`TestProbesFailOnAMutationOfTheErasureSchema`、`TestProbesFailOnAMutationOfTheDownSection`、`TestClockScannerDistinguishesGoAndSQLClocks`（反空转） |
| `internal/zzprobe/pgstore/index_coverage_probe_test.go` | `TestEverySingleColumnPredicateHasALeadingIndex`(**FAIL=PG-001**)、`TestKnownUnindexedPredicatesAreStillUnindexed`、`TestNoGoSourceBuildsSqlFromARequestValue`、`TestDeviceStateWhereArgumentIsOnlyEverALiteral` |
| `internal/zzprobe/pgstore/erasure_guard_probe_test.go` | `TestGuardReproductionAgreesWithTheGuard`、`TestErasureGuardSeesEverySubjectColumnInTheRealSchema`、`TestErasureGuardMissesAlterTableAddColumn`、`TestErasureGuardOnlyRecognisesTwoExactColumnNames`、`TestErasureGuardIsBlindToAccountIdsInsideJsonAndBlobs`、`TestNoAlterTableAddsASubjectColumnToday` |
| `internal/zzprobe/pgstore/atomicity_probe_test.go` | `TestMultiStatementMutationsRunInATransaction`、`TestUniqueViolationMappingDropsNoSQLDetail`、`TestTokenTablesHaveNoRowLevelSecurityOrTrigger`、`TestSweepStatementListMatchesExpiredTables` |
| `internal/zzprobe/pgstore/migdown_probe_test.go` | `TestLeakedIndexesSitOnTablesThatSurviveTheDown`、`TestCreatedTablesSurviveTheirDown`、`TestNoIndexSurvivesTheFullDownSequence` |
| `internal/zzprobe/pgstore/clock_source_probe_test.go` | `TestDevicePathsJudgeExpiryWithTheDatabaseClock`(**FAIL=PG-003**)、`TestOnlyReviewedStatementsUseDatabaseNow` |

跑法：`go test ./internal/zzprobe/pgstore/ -v`（无需 DSN）。两个 FAIL 是本报告 PG-001 与 PG-003 的可执行证据（它们故意断言「缺口不存在」，所以现在必然失败）。
报告中的行号引用来自 `oidc.go`/`oauth.go`/`sessions.go` 等**磁盘上的生产源码**（`adapterDir` 已由 `TestAdapterDirectoryResolves` 证明解析正确）。
