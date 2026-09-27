# Postgres 报告复核（对抗性）—— `postgres.md` PG-001 … PG-010

复核者立场：**证伪优先**。本机 Windows 11，无 Docker、无本地 Postgres，`TEST_DATABASE_URL` 未设置，
所以每一条涉及 Postgres 运行时行为的判断仍然只是**读；无 DB 执行**——我不假装跑过 SQL。

## 0. 先说三件影响证据链的事

1. **`docs/audit-5/BRIEF.md` 不存在。** 我只找到 `docs/audit-5/VERIFY-BRIEF.md`（以及
   `findings/`、`probes/`、`runtime/` 三个目录）。按我的任务书，`BRIEF.md` 是必读的「哪些是文档化决定」
   清单；它缺失意味着我**无法核对报告是否重报了已被记录的决定**。我用
   `docs/architecture.md`、`docs/migration-decision.md`、`CHANGELOG.md` 与 `docs/security-audit-{2,3}.md`
   自行顶替。这是共享输出目录的问题，留给主代理处理。
2. **报告里描述的探针套件与现在磁盘上的不一致**（详见 §3.1）。报告写的是「19 个探针 + `migrationcopy/`
   逐字节副本 + SHA-256 钉住」；现在 `internal/zzprobe/pgstore/migrationcopy/` **已被删除**，
   探针改为直接从 `../../store/postgres/migrations` 读盘，测试数变成 27。报告 §「探针文件清单」这一节
   已经过期，而 `migrationcopy` 那一段是报告自己拿来支撑「探针读到的 schema 是真的」的核心论证，
   现在这条论证的载体在仓库里不存在了。
3. **我第一次 `go test ./internal/zzprobe/pgstore/...` 时该包编译失败**（`atomicity_probe_test.go` 与
   `index_coverage_probe_test.go` 缺 `filepath`、`clock_source_probe_test.go` 缺 `itoa`）。
   数分钟后另一位代理补齐了这些 import，`go vet` 干净、包可运行。我把它记下来不是要指控，
   而是因为它决定了这句话的成立范围：**报告声称的「2 FAIL / 17 PASS」我只能在其后一次运行里复现**，
   而报告写就的那一刻这套探针是不可执行的。后文所有「我执行了什么」都以**我实际跑过的那一次**为准。

---

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|---|---|---|---|---|
| PG-001 | 中 | 中（但**四条活、一条假**） | **部分成立** | 索引缺失与「0021 只补 `oidc_*`」都对，四条谓词在 `cmd/re0auth/main.go` 上确实可达；但第 5 条 `oauth_device_authorizations.client_id` **在 Go 源码里根本不存在对应语句**，而报告因此漏掉了一条真的活缺口（`oidc_auth_requests.client_id`）→ 见 V-1。 |
| PG-002 | 中 | 低–中 | **部分成立（机制描述错）** | `getMigration`/`ErrVersionNotFound`/缺 0005 三件事都对；但「先退 6，下一次退 5 才失败」不成立——`down()` 在 `runMigrations` **之前**就把整条 apply 列表建完，所以从 6 出发的**那一次** `-migrate-down` 就整体失败、**一个版本都没退**。ADR-0008 §3 已把回滚故事定义为从备份恢复，故实际影响是工具缺口。 |
| PG-003 | 中 | 低（跨主机时才回升到中） | **部分成立** | 两个时钟确实同时裁决同一条 `expires_at`，单时钟政策确实被破且设备面无守卫；但「被否决的审批」需要**应用主机与 DB 主机的墙钟差超过 TTL 剩余量**，同机部署下两张表用的是**同一个 `now()`**。修法仍然值得做（一句话的改动），但「中」偏高。 |
| PG-004 | 低 | 低 | **CONFIRMED** | 计数与不对称完全对得上（5 个无事务 vs 12 个有）；`Admin` 侧拿到的是非零错误，不静默，孤儿行由 sweep 收，无鉴权越权 → 一致性问题，维持「低」。 |
| PG-005 | 低 | 非发现（代码形状记录） | **已知非发现（形状注记）** | `where` 是 `deviceState` 的形参，但全仓**只有 3 个调用点、3 个都是反引号常量**，且 `deviceState` 未导出、无法被包外调用。当前零收益；留一条守卫是对的，但这是注记不是缺陷。 |
| PG-006 | 低 | 低 | **CONFIRMED** | `createTableRE` 只扫 `CREATE TABLE`，`ALTER TABLE ADD COLUMN` 实测 8 次确实隐形；只认 `subject`/`user_id` 两个名字也对。动态守卫（`information_schema`）在 CI 里兜住了 `ALTER TABLE` 那一半，且同样是两个名字的盲区——严重度维持「低」，但**权威在 CI 不在本地**这句话要写进去。 |
| PG-007 | 提示 | 提示 | **CONFIRMED（信息级）** | `secret_hash bytea` 无 NOT NULL/CHECK、`session_subjects.subject` 允许空串，都是 schema 文本事实；无写入路径，故仍是提示。 |
| PG-008 | 低（HYPOTHESIS） | 提示 + 明标假说 | **CONFIRMED 为假说** | 代码形状（一个事务里全表 `ORDER BY id` + 逐行 HMAC、`statement_timeout` 只约束单条语句）读得出来；但「池被吃掉」需要 10⁶ 行表 + `EXPLAIN`/`pg_stat_activity`，本机无 DB。以 HYPOTHESIS 呈现是诚实的，**保留**。 |
| PG-009 | 提示（HYPOTHESIS） | 提示 | **CONFIRMED 为假说** | 索引双重存在的形状是真的，但 planner 选哪个索引必须 `EXPLAIN ANALYZE`。报告自己已把证伪路径写出来，**保留**。 |
| PG-010 | 提示 | 无缺陷（留痕） | **CONFIRMED 为「探过没破」** | `ANY($1)` 走 PK、`oauth_clients` 是运维规模表，确实无代价。 |

**关于两条「判断」**：见 §4，两条都**确认**（附引文），不是缺陷。

---

## 2. 降级／推翻的理由

### PG-001 —— 索引确实没有，但「五条」里有一条是假的，而且漏了一条真的

**(a) 索引缺失：我手工复核了 schema，报告正确。** 我把 20 个迁移里的 `CREATE INDEX` / `PRIMARY KEY`
全部抽出来，四张 legacy 表的完整索引集合是：

| 表 | 索引 | 来源 |
|---|---|---|
| `oauth_access_tokens` | PK `(token_hash)`；`(expires_at)`；`(subject, client_id)` | 0001:65、0006:20 |
| `oauth_refresh_tokens` | PK `(token_hash)`；`(expires_at)`；`(subject, client_id)` | 0001:76、0006:21 |
| `oauth_codes` | PK `(token_hash)`；`(subject)`；`(expires_at)` | 0012:29、0012:34 |
| `oauth_device_authorizations` | PK `(device_code_hash)`；`(upper(replace(user_code,'-','')))`；`(subject)`；`(expires_at)` | 0001:94、0012:30、0012:35 |

**没有任何一张表的任何索引以 `client_id` 为前导列。** 报告这条成立。

**报告「0021 only added indexes for oidc_*」我也核了：正确。** `0021_token_client_indexes.sql:14-15`
只建了 `oidc_access_tokens_client_idx` 与 `oidc_refresh_tokens_client_idx`；Go 侧对称的三张 legacy
表（`oauth_access_tokens`、`oauth_refresh_tokens`、`oauth_codes`）被漏掉——这个「对称性缺口」的描述准确。

**(b) 可达性——这是报告没有回答的问题，而答案是「不该 downgrade」。**

我原本准备按任务书的假设（`docs/architecture.md` §8.5 说 legacy 表「在 P4b 之后已无生产调用者」）
把它整体降级为潜伏问题。**读代码后这个假设被推翻**：

- `docs/architecture.md:755-757` 确实写着「`oauth_codes` / `oauth_access_tokens` / `oauth_refresh_tokens` /
  `oauth_device_authorizations` … 以及 `internal/store/postgres` 的 `Tokens` / `Devices`，
  **在 P4b 之后已无生产调用者**」。
- 但组合根**仍然把它们接进生产路径**：`cmd/re0auth/main.go:849` 是 `legacy: db.Tokens()`，
  第 539-541 行 `if legacyTokens, ok := store.legacy.(oauth.TokenAdmin); ok { revokers = append(...) }`
  → `revokers` 就是第 542 行的 `tokenRevoker`，它被装进 `admin.Config.Tokens`（`:560`）与
  `lifecycle.Config.Tokens`（`:604`）以及 `lifecycle.Config.Legacy`（`:610`）。
- `Tokens` 实现了 `RevokeTokens`（`oauth.go:236`），因此该类型断言**成立**，legacy 撤销器**在生产里活着**。
- 两条活调用链：
  1. **`Tokens.RevokeTokens`** ← `admin.SuspendClient`（`admin.go:242`）、`admin.DeleteClient`（`:260`）、
     `KillSwitch`（`:309`，`Target.ClientID` 或 `Target.Subject` 非空即触发，只有 `bindings` 目标跳过）。
     它执行 `revokeMatching(ctx, s.pool, []string{"oauth_access_tokens","oauth_refresh_tokens"}, f)`
     （`oauth.go:237`，表名是字面量表）再 `DELETE FROM oauth_codes`+clause（`:242`）。
  2. **`Tokens.PurgeLegacySubject`** ← `lifecycle.DeleteAccount`（`lifecycle.go:234-240`，
     `d.cfg.Legacy != nil` 时必调）。

**所以五条谓词的准确归属是：**

| # | 表.列 | 语句来源 | 生产可达性 |
|---|---|---|---|
| 1 | `oauth_access_tokens.client_id` | `oauth.go:292`（`RevokeTokens`，client-only 过滤） | **活**（Suspend/DeleteClient/KillSwitch client） |
| 2 | `oauth_refresh_tokens.client_id` | `oauth.go:292`（同上） | **活**（同上） |
| 3 | `oauth_codes.client_id` | `oauth.go:242`（`RevokeTokens`，client-only 过滤） | **活**（同上） |
| 4 | `oauth_codes.client_id` | `oauth.go:198`（`DeleteBySubjectClient`，`WHERE subject=$1 AND client_id=$2`） | **活，但只是第二列**：`oauth_codes_subject_idx (subject)` 已经带得住这条，`client_id` 不是它的前导需求——报告自己在清单里注明了这一点，所以这其实是同一张表的**重复计数** |
| 5 | `oauth_device_authorizations.client_id` | 报告称 `oidc.go:995` | **不存在**：`oidc.go:995` 是 `revokePendingAuthorizations` 里的 `DELETE FROM oidc_auth_requests`+clause；全仓没有任何语句对 `oauth_device_authorizations` 按 `client_id` 过滤 |

**结论**：不该按「全部命中死表」大幅降级——三条（去重后）活谓词确实落在运维/事件响应路径上。
但报告的计数有两处问题：第 4 条是重复计数（前导列需求由 `subject` 满足），第 5 条是凭空多出来的
（且带一条指向 `oidc_auth_requests` 的错误引用）。**净效果不是「高估」而是「数目对不上**」，
而它同时**漏掉**了同一类里唯一一条我没在清单上看到的活缺口——见 V-1。

**我尝试的两种推翻**：(i) 假设 legacy 表在生产为空所以索引无所谓——部分成立但不足以降级，
因为空表只对**全新部署**成立，而 `PurgeLegacySubject` 的注释（`oauth.go:248-258`）明说这条路
就是为「从手写引擎迁移过来的部署」写的，那正是表里有数据的部署；(ii) 假设 `Tokens` 没被接上——
被 `main.go:539` 的直接类型断言推翻。

**一处必须说清的残余弱点**：受影响的表**只有迁移过的部署**才有数据；全新部署这四张表是空的，
顺序扫描的代价是常数。报告把这一点写在「已知前提」之外（放在「影响」段的第二句），
我同意它的实质，但严重度「中」的成立范围应写成「迁移部署 + 表有量」。

### PG-002 —— 核心成立，但机制写错了一步，而且「6→5」不是触发点

我对两半都做了行级核对。

**goose 侧：报告引用的代码位置逐行正确。** `github.com/pressly/goose/v3 v3.28.0`
（`go.mod:13`；`GOMODCACHE=C:\Users\r-0semi\go\pkg\mod`）：

- `provider.go:308-328` `Down(ctx)` → `p.down(ctx, true, 0)`——**注意第三个实参是 `0`**。
- `provider.go:454-464`：

  ```go
  var apply []*Migration
  for _, dbMigration := range dbMigrations {
      if dbMigration.Version <= version {   // version == 0
          break
      }
      m, err := p.getMigration(dbMigration.Version)
      if err != nil {
          return nil, err                 // ← 整个 down 在这里就结束了
      }
      apply = append(apply, m)
  }
  return p.runMigrations(ctx, conn, apply, sqlparser.DirectionDown, byOne)
  ```

- `provider_run.go:416-423`：版本不在 `p.migrations` 里就返回 `ErrVersionNotFound`。
- `internal/dialects/postgres.go:44-47` `ListMigrations` = `SELECT version_id, is_applied from %s ORDER BY id DESC`
  ——**返回版本表里的每一行**，不是只有最高版本。

**所以错的细节是**：报告说「退**一步**从 6 退到 5 会失败：循环第一项是 6，`getMigration(6)` 成功、
退掉 6；下一次调用时最高是 5，`getMigration(5)` 找不到文件 → 报错」。实际是 `apply` **先建完再执行**：
从 6 出发的那一次调用里，循环会依次处理 6（成功入列）**然后**处理 5（返回错误），
于是 `p.down` 在 `runMigrations` 之前就返回错误，**第 6 版根本没退**。也就是说失败不是「退了 6 之后卡在 5」，
而是「想退 6 的那一次就整体失败」。后果上这个差别是好的：**不会留下一个半退状态**，
操作者看到的就是一条 `postgres: migrate: down: version not found` 加退出码非零，schema 原封不动。
（反过来说，报告「影响」段里「会在退到 6→5 这一步卡死」的叙述要改成「从 6 向下回退的第一次就失败」。）

**schema 历史侧：确认。** `internal/store/postgres/migrations/` 现在有 20 个文件、无 `0005`
（0001,0002,0003,0004,0006…0021）。`git log --all --name-status --diff-filter=D` 给出
`D internal/store/postgres/migrations/0005_authz.sql`，提交 `87f4ad9`（"feat(oidc): P4b——内存模式同样运行
OpenID Provider"），与 `docs/architecture.md:759`「`Authz` 与 `authz_requests`（迁移 0005）已在 P4b 一并删除」
一致。版本表那一行怎么来的也确认了：`adoptLegacyMigrations`（`postgres.go:413-467`）会把旧
`schema_migrations` 的每个版本无条件写进 `goose_db_version`（`:455-458` 是 `INSERT … WHERE NOT EXISTS`），
而 goose 的 `Up` 在文件存在时会写入 `version_id=5`。**触发条件因此是「该库在 `87f4ad9` 之前
跑过一次 Up」，不是「操作者连续回退两次」。**

**影响判定：这确实是工具缺口（低–中），不是发布风险，理由有两条，都可引：**

1. **ADR-0008 §3 已经把回滚故事定义为从备份恢复**：`docs/migration-decision.md:26-29`
   「**`Down` 存在，但不是回滚故事。** 回滚故事是**从备份恢复**（`scripts/restore.sh`，RPO ≤ 15 分钟，
   RTO ≤ 1 小时）… `Down` 只服务于『撤销我刚应用的这一步』这一具体场景。」
   代码注释也复述了同一句：`postgres.go:395-398`「Down migrations exist for the operator who has to undo
   one step, **not as the rollback story**」。所以「回退到 0005 之前」本来就不是受支持的操作。
2. **初始触发点还要 16 步才到**：当前 head 是 `0021`，fresh DB 上第一次 `-migrate-down` 是 21→20，成功。
   只有**同时**满足「曾在 `87f4ad9` 前迁移过」+「一路退到 5 以下」两个前提才会踩到，
   而上一条已经说明第二个前提不被承诺。

报告把这两条写在「已知前提（不夸大）」里了，这是它写得好的地方；我据此把「中」降到**低–中**。
修法建议里 (c)（把「版本 5 是永久停点」写进 ADR-0008 的 Consequences）是成本最低且不改语义的一条，
我同意；但报告「建议第三个」并列的三选项 (a)（复活 0005 空文件）会与
`docs/architecture.md:759` 的「已删除」叙述冲突，不建议。

**`migdown_probe_test.go` 到底建立了什么、没建立什么**：它**完全没碰** PG-002。
三个测试（现在文件里是**五个**函数，见 §3.1）做的是**纯 DDL 文本自洽性**：
`TestLeakedIndexesSitOnTablesThatSurviveTheDown`（某个 Down 里没点名、且它的表也没被 DROP 的索引是否会活下来）、
`TestCreatedTablesSurviveTheirDown`、`TestNoIndexSurvivesTheFullDownSequence`。我实跑了，三个都 PASS。
它们成立的**唯一**理由是 `DROP TABLE` 会连带删掉索引——报告诚实记录了自己第一版把它写成「15 条泄漏索引」
的假阳性并改正了，这一点值得肯定。但它**不构成**对 PG-002 的任何证据：
它从头到尾没有读 `goose_db_version`、没有读 goose 源码、也没有执行任何迁移。
报告自己在「未能到达」第 1 条里承认了「`MigrateDown` 在版本 5 上的实际报错文本… 没有跑过」——
这是诚实的，但也意味着 **PG-002 的证据全部是读代码 + 读第三方源码，没有任何可执行复现**，
而报告主标题声称它「CONFIRMED（行级确证）」，我同意这个标签，只要「行级」二字不被读成「跑过」。

### PG-003 —— 是真缺陷，但「两个时钟」在任何单机部署里只有一个

我逐个读了四个位置：

- 写者：`oidc.go:632-639 StoreDeviceAuthorization` 的 `expires` 是**调用方传入**的 `time.Time`
  （库 `oidcstore` 用进程时钟算），所以 `expires_at` 这一列的作者是**应用主机的墙上时钟**。
- 判者 A（Go / 应用时钟）：`oidc.go:1083`（`DecideDeviceAuthorization`）与 `oidc.go:1053`
  （`DescribeDeviceAuthorization`），都是 `s.now().After(st.Expires)`。
- 判者 B（**数据库时钟**）：`oidc.go:771` `const pending = \`done = false AND denied = false AND expires_at > now()\``，
  被 `ApproveDevice`（`:772`、`:776`）拼进 `UPDATE oidc_devices`；
  `oidc.go:684-687` 的慢轮询**写和判都只用 DB 时钟**。
- 对照：内存后端在四处全用 `s.now()`——`memory/oidc.go:782-784`、`:799`（`lastPoll`）、
  `:986`（过期判定）、`:991`（`authTime`）。**两个后端行为不同，这一点确认。**

**判断：这是真实的正确性缺陷，不是「两个后端都还算可接受」。** 理由是具体的失败路径：
`DecideDeviceAuthorization`（应用时钟）放行 → 落到 `ApproveDevice`（DB 时钟）→ 若 DB 时钟超前于应用时钟，
`expires_at > now()` 为假 → `RowsAffected()==0` → 返回
`"postgres: device authorization is not pending: %w", oauth.ErrDeviceNotFound`（`oidc.go:784-787`）。
用户看到「码无效」，而同一个码刚刚在 `DescribeDeviceAuthorization` 里被判有效。这是
**可观测的行为矛盾**（UI 说有效、审批被拒、错误文案说码不存在），不是纯风格问题。

**但要量化偏差才诚实**：
- 同机部署（应用与 Postgres 在同一宿主，或同一台 VM 的容器里）**两者共享同一个内核墙上时钟**，
  `now()` 与 `time.Now()` 的读数差是 syscall 往返的微秒级。此时要踩到这条，
  必须**恰好**在 `expires_at` 的最后几微秒点同意——概率上等于噪声。
- 跨主机部署（应用与托管 Postgres 分离）才会有毫秒～秒级偏差；**部署文档与 ADR-0008 都没有禁止跨主机**，
  所以这在生产上是可能的。这时「TTL 剩余量 < 时间差」的窗口是**毫秒级到秒级**，
  而不是报告举例的 2 小时。
- 报告举的 `-2h` 来自 `clock_test.go:21`（`const skew = -2 * time.Hour`）。这是**测试夹具**的偏差量，
  不是生产预期。它成立的前提是 `WithClock` 把 store 时钟整体挪了 2 小时——而
  `WithClock` 的存在理由，`postgres.go:41-45` 写得很直白：「It is injectable (WithClock) because that
  policy is otherwise unassertable: a test cannot skew the database's clock, but it can skew this one」。
  **所以 store 时钟不是「生产里第二个时钟」，它是为了让单时钟政策可断言而留的注入点。**
  这一点削弱了「同一条 `expires_at` 被两个时钟裁决」的戏剧性，但**不推翻**它：
  跨主机墙钟偏差是真实存在的第二个时钟，而 `expires_at` 的作者是应用主机、判者是 DB 主机。

**我尝试的反例**：(i) 找一个使偏差不可能的配置——同机部署确实使偏差可忽略，但这不是文档要求；
(ii) 论证后果是安全的——是的，它**不是**绕过（审批发生在过期之后仍然被拒，方向是安全的一侧），
是可用性 + 误导性错误。故我把「中」降为**低**，并在「低」的说明里注明：跨主机部署时可回到中。
修法（把 `expires_at > now()` 换成 `expires_at > $n`、`last_poll` 比较改 `$n`）是一句话的机械改动，
且能同时消掉两个后端的分叉，**值得做，与严重度无关**。

### PG-004 —— 维持「低」，三条理由都核过了

- 计数与不对称**确认**：我实跑 `TestMultiStatementMutationsRunInATransaction`，输出与报告所粘的五行逐字一致
  （`sessions.go RevokeAllSessions` 3 条写无事务、`RevokeSubjectSessions` 2 条、`sessions.go SweepExpired` 2 条、
  `oauth.go RevokeTokens` 2 条、`oauth.go PurgeLegacySubject` 3 条），且对照组（12 个含 `.Begin(` 的方法）通过。
- 行级复核：`sessions.go:168-177`（`DELETE FROM sessions` 然后 `DELETE FROM session_subjects`，
  返回 `tag.RowsAffected()` 只数第一句）、`:186-194`、`:143-154`、`oauth.go:236-246`、`:259-274`。
  **报告的行号与代码一致。**
- **但「不静默」这一点报告没强调，而它正是压住严重度的关键**：第二句失败时这些方法返回
  `(tag.RowsAffected(), err)`（`sessions.go:152/174/193`），调用方 `admin.KillSwitch` 拿到非零 counts
  **同时**拿到 `err`（`admin.go:313-317` 记 `OutcomeError` 并返回错误）。所以不存在「报成功但没做完」。
- **用户可见性**：孤儿 `session_subjects` 行无害——`sessions.go:148-151` 的 sweep 用
  `NOT EXISTS (SELECT 1 FROM sessions …) AND si.created_at < now() - '1 hour'` 收它，
  期间没有任何读路径会因为「索引行没有对应 session」而出错（活会话已删）。
  **所以维持「低」，并把类别明确写成一致性/卫生，而不是可用性。**

### PG-005 —— 我判它「不是发现」

`oidc.go:705` 的签名是 `func (s *OIDCStore) deviceState(ctx context.Context, where string, args ...any)`，
`oidc.go:710-712` 把它拼进 `SELECT … FROM oidc_devices WHERE `+where。这条描述成立。
但：

- `deviceState` **未导出**，包外无法调用；
- 我实跑 `TestDeviceStateWhereArgumentIsOnlyEverALiteral`，输出「inspected **3** deviceState call sites;
  each passes an inline SQL fragment」——三个调用点分别是 `oidc.go:693`、`:702`、`:757`，
  **全是反引号字面量**（`oidc.go:757` 是 `DeviceByUserCode` 的
  `upper(replace(user_code,'-','')) = upper(replace($1,'-',''))`）；
- 值全部走 `$n` 参数。

一个「只被包内三个常量调用点调用、且未导出」的形参**不是注入面**——攻击者无法提供它的值。
所以这是**代码形状注记**：报告的「低（当前无可达缺陷；是形状风险）」标签本身没错，
但它在「发现」章节里占了一个编号，读者会把 PG-005 记成一条缺陷。建议主代理把它移到
「探过但没破」；严重度实质为零。**顺带纠正报告的两处过期数字**：报告正文说「两个调用点」
（`:693`、`:702`）与「三个实参都是常量」，探针说的是 3 个；现在的代码是 **3 个调用点**。

### PG-006 —— 维持「低」，但必须写明 CI 才是权威

- `erasure_schema_test.go:33` 的 `createTableRE` 是 `(?is)CREATE TABLE (?:IF NOT EXISTS )?(\w+)\s*\((.*?)\);`，
  `:59` 只对它做 `FindAllStringSubmatch`；**没有任何一条语句级解析处理 `ALTER TABLE … ADD COLUMN`**。
- `ALTER TABLE ADD COLUMN` 实测出现 **8 次**（报告说 8 次，正确）：`0009:5`、`0009:6`、`0010:12`、
  `0013:30`、`0013:31`、`0013:32`、`0015:21`、`0016:16`。
  （报告把分布写成「0009×2、0010×1、0013×3、0015×1、0016×1」——数字对，但 0009/0013 之外的分项我核出
  `0015:21` 是 `session_subjects ADD COLUMN created_at`、`0016:16` 是 `oidc_devices ADD COLUMN last_poll`，
  与报告一致。**报告这一处是准确的。**）
- `hasAccountColumn`（`erasure_schema_test.go:92-112`）只认 `subject` 与 `user_id` 两个精确名字。
- **动态守卫确实补齐了「语句类型」这一半**：`erasure_test.go:246-249` 的 `subjectOrphans` 从
  `information_schema.columns` 取列（`column_name IN ('subject','user_id')`），
  **所以 `ALTER TABLE` 加出来的列它是看得见的**；它**看不见**的是「用了别的列名」这一半。
- **CI 权威性确认**：`.github/workflows/ci.yml:33-48` 起 `postgres:16` 服务并设 `TEST_DATABASE_URL`，
  `:198-199` 跑 `go test -race -v -timeout 120s ./internal/store/postgres/`，`:264` 的注释还明说
  「a missing TEST_DATABASE_URL becomes a failure」。所以报告「只有在 CI 里跑到需要 DSN 的测试才会暴露」
  这句是对的，严重度「低」也站得住——但**必须补一句**：动态守卫只对**被抹除的那个账号**计数，
  所以一个只泄漏**其他**账号的列仍然合法（报告 `:148` 写了这一点，准确）。

### PG-008 / PG-009 —— 保留为 HYPOTHESIS，但报告要保证「可证伪路径」比「结论」更显眼

两条都是 HYPOTHESIS，且**都给了明确的证伪实验**（PG-008 看 `pg_stat_activity` + `writeTimeout` 触发顺序；
PG-009 一条 `EXPLAIN (ANALYZE)` 就能推翻）。按 VERIFY-BRIEF §2 的标准，hypothesis 只要有标签就不是问题；
本机无 DB 也确实做不到。**我的判定是「保留，但不要与 CONFIRMED 同列在同一张严重度表里」**——
报告把它们标成「低」和「提示」与 PG-001/PG-003 并排，会让读者误以为它们同等可信。
PG-008 的代码形状我核了：`auditchain.go:220-331` 确实在 `tx` 里 `SELECT … FROM audit_events ORDER BY id`
全表流式读并逐行算 SHA-256 + HMAC，`:229-232` 是 `SET LOCAL statement_timeout = 45s`，
`defer tx.Rollback`（`:227`）——**「45s 是单条语句上界、不是 handler 时长上界」这个推理成立**，
所以即使没有 `EXPLAIN`，它作为「阅读级」结论是可靠的，只是「池被打满」这一步需要测量。
PG-009 我只做了一件事：确认 `oidc_access_tokens` 同时有 `(expires_at)`（0008:50）与
`(subject, issued_at)`（0009:8）两个可选索引——`sweep.go:60` 的 `WHERE expires_at < $1` 确实面临
planner 的索引选择，报告的假说前提是真的。**两条都不应降为「未能到达」**，因为它们提出了后续用一次
`EXPLAIN` 就能判定的具体问题；把它们埋在「未能到达」里才是丢价值。

---

## 3. 确认的（我执行了什么）

### 3.1 探针实跑（关键：报告写成 19 个探针／现在 27 个，且 `migrationcopy/` 已不存在）

```
go test ./internal/zzprobe/pgstore/... -v
```
**我实际跑到的**（节选有承载力的行）：

```
--- FAIL: TestEverySingleColumnPredicateHasALeadingIndex (0.00s)
    index_coverage_probe_test.go:203: UNINDEXED PREDICATE: oauth_access_tokens.client_id …
    index_coverage_probe_test.go:203: UNINDEXED PREDICATE: oauth_codes.client_id … (oauth.go:198 …)
    index_coverage_probe_test.go:203: UNINDEXED PREDICATE: oauth_codes.client_id … (oauth.go:242 …)
    index_coverage_probe_test.go:203: UNINDEXED PREDICATE: oauth_device_authorizations.client_id … (oidc.go:995 …)
    index_coverage_probe_test.go:203: UNINDEXED PREDICATE: oauth_refresh_tokens.client_id …

--- FAIL: TestDevicePathsJudgeExpiryWithTheDatabaseClock (0.00s)
    clock_source_probe_test.go:146: DEVICE DEADLINE JUDGED BY THE DATABASE CLOCK: oidc.go:685: SET last_poll = now()
    clock_source_probe_test.go:146: DEVICE DEADLINE JUDGED BY THE DATABASE CLOCK: oidc.go:687: AND (last_poll IS NULL OR last_poll <= now() - make_interval(secs => $3))`,
    clock_source_probe_test.go:146: DEVICE DEADLINE JUDGED BY THE DATABASE CLOCK: oidc.go:771: const pending = `done = false AND denied = false AND expires_at > now()`
    clock_source_probe_test.go:146: DEVICE DEADLINE JUDGED BY THE DATABASE CLOCK: oidc.go:772: q := `UPDATE oidc_devices SET done = true, subject = $2, auth_time = now()
    clock_source_probe_test.go:146: DEVICE DEADLINE JUDGED BY THE DATABASE CLOCK: oidc.go:776: q = `UPDATE oidc_devices SET done = true, subject = $2, auth_time = now(), scopes = $3
```

→ **FAIL 恰好是 PG-001 与 PG-003 所声称的两个，其余全部 PASS**，所以报告「两个 FAIL 是本报告的
可执行证据」这句**成立**。其余有承载力的 PASS：

```
--- PASS: TestMultiStatementMutationsRunInATransaction
    atomicity_probe_test.go:165: CONFIRMED NOT ATOMIC: sessions.go RevokeAllSessions issues 3 write(s) with no transaction
    atomicity_probe_test.go:165: CONFIRMED NOT ATOMIC: sessions.go RevokeSubjectSessions issues 2 write(s) with no transaction
    atomicity_probe_test.go:165: CONFIRMED NOT ATOMIC: sessions.go SweepExpired issues 2 write(s) with no transaction
    atomicity_probe_test.go:165: CONFIRMED NOT ATOMIC: oauth.go RevokeTokens issues 2 write(s) with no transaction
    atomicity_probe_test.go:165: CONFIRMED NOT ATOMIC: oauth.go PurgeLegacySubject issues 3 write(s) with no transaction

--- PASS: TestKnownUnindexedPredicatesAreStillUnindexed   (5 条 CONFIRMED UNINDEXED)
--- PASS: TestNoGoSourceBuildsSqlFromARequestValue
    index_coverage_probe_test.go:305: scanned 17 SQL string interpolations across 8 adapter files; all are column/table-name constants or the reviewed `clause`/`table`/`where` builders
--- PASS: TestDeviceStateWhereArgumentIsOnlyEverALiteral
    index_coverage_probe_test.go:332: inspected 3 deviceState call sites; each passes an inline SQL fragment
--- PASS: TestNoAlterTableAddsASubjectColumnToday
    erasure_guard_probe_test.go:263: scanned 8 ALTER TABLE ADD COLUMN statements across the migrations
--- PASS: TestErasureGuardMissesAlterTableAddColumn / TestErasureGuardOnlyRecognisesTwoExactColumnNames /
         TestErasureGuardIsBlindToAccountIdsInsideJsonAndBlobs / TestGuardReproductionAgreesWithTheGuard
--- PASS: TestLeakedIndexesSitOnTablesThatSurviveTheDown / TestCreatedTablesSurviveTheirDown /
         TestNoIndexSurvivesTheFullDownSequence
--- PASS: TestMigrationsDirectoryResolves
    disk_read_probe_test.go:116: read 20 migrations from .internal\store\postgres\migrations
--- PASS: TestProbesFailOnAMutationOfTheIndexSchema / …OfTheErasureSchema / …OfTheDownSection /
         TestClockScannerDistinguishesGoAndSQLClocks
```

**反空转对照组现在由 `disk_read_probe_test.go` 的四个 sentinel 承担**
（在临时副本上删一个 `CREATE INDEX`／改名账号列／删一个 `DROP INDEX`／相邻两行放一个 SQL `now()` 与一个
`s.now()`，要求解析器分别失败或分类正确）——**这是对报告原来依赖的 `migrationcopy` SHA-256 方案的改进**，
因为 sentinel 直接证明「解析器会响」，而副本哈希只证明「我读的是这份文件」。
但报告 §「探针文件清单」与「未能到达」第 3 条仍在描述已删除的 `migrationcopy`，**这一段现在无对应物**。

### 3.2 手工核（不依赖探针）

- 从 20 个迁移抽全部 `CREATE INDEX` / `PRIMARY KEY` / `UNIQUE`（脚本按文件解析）：确认四张 legacy 表
  **没有** `client_id` 前导索引，`0021:14-15` 只建了 `oidc_*` 两个 —— 见 §2 PG-001 的表。
- 在 `oauth.go` / `oidc.go` / `admin.go` / `lifecycle.go` / `main.go` 里逐处核对谓词与调用链
  （`main.go:539-542`、`:560`、`:604`、`:610`、`:849`；`admin.go:242/260/309`；`lifecycle.go:234-240`）。
- goose v3.28.0 源码：`provider.go:308-328`、`:454-464`、`provider_run.go:416-423`、
  `internal/dialects/postgres.go:44-47`、`database/dialects.go:146-169`。
- `git log --all --name-status --diff-filter=D -- internal/store/postgres/migrations/` →
  `87f4ad9` 删除 `0005_authz.sql`。
- `.github/workflows/ci.yml:33-48`、`:198-199`、`:264`（Postgres 服务 + 集成测试真的在 CI 里跑）。

### 3.3 「探过但没破」的抽检（任务书最高价值项）—— **三处我都独立核了，没有找到假阴性**

1. **SQL 注入**（报告第 1 条）：报告说「7 处拼接」，探针现在报 **17 处**（因为现在按行扫 `\`+\` / `"+`，
   把 `deviceCols` 之类的列清单拼接也算进来）。我逐处读了关键五处：
   `sweep.go:60`（`expiredTables` 字面量）、`oauth.go:292`（`revokeMatching` 的 `tables []string`，
   调用点 `oauth.go:237` 与 `oidc.go:955`/`:966` 全是字面量表名）、`oauth.go:317/321`
   （`fmt.Sprintf("client_id = $%d")` 只产出列名与占位符位置，值走 `args`）、
   `oidc.go:988/994`（`revokePredicate` 的产物）、`auditread.go:43/84`（列名与操作符是实参常量）、
   `oidc.go:712`（PG-005）。**没有一处让请求值进入 SQL 文本**——报告第 1 条成立。
   *注*：`auditread.go` 与 `revokePredicate` 两处的 `LIMIT`/值都走 `$n`，我也核了。
2. **四个单次使用路径是 claim-then-mint**：我读了 `oidc.go:348-357`（`DELETE FROM oidc_refresh_tokens …`
   再 `RowsAffected()==0 → ErrRefreshTokenSpent`，同事务内 INSERT）、`oauth.go:105-123`、
   `federation.go:197-216`（`DELETE … RETURNING`）、`oidc.go:186-222`（`DELETE FROM oidc_codes
   WHERE code_hash=$1 AND expires_at > $2 RETURNING request_id`，`expires_at > $2` 的实参是 `s.now()`
   ——**这一处正好证明 AuthRequestByCode 用的是 store 时钟，与 PG-003 的对比成立**）、
   `oidc.go:657-703`（`DELETE … RETURNING` 认领）。**五处全部是 DELETE-first，没有找到读后写。**
   报告第 2 条成立（而且它把 `GetDeviceAuthorizatonState` 也算进来，实际是 5 处而非 4 处，对它有利）。
3. **没有 `fail-open` 形状**：我扫了 `internal/store/postgres` 全部 29 处 `RowsAffected()`。
   报告点名的 6 处（`oidc.go:749`、`:732`、`oauth.go:373`、`oidc.go:784`、`:807`、`oauth.go:507`）
   全部 `== 0 → return error`，**确认**；另有报告未点名的 `oidc.go:354`（`ErrRefreshTokenSpent`）、
   `oidc.go:692`（`→ context.DeadlineExceeded` 或返状态）、`account.go:252` 也是 `== 0 → error`。
   剩下三处不是 fail-open：`oauth.go:534`（`> 0 → nil`，否则去区分「不存在」与「公开客户端」，
   两条分支都非 nil）、`federation.go:68` 与 `oauth.go:394`（`== 1` 作为**返回布尔**的 CAS 结果，
   失败返 `false, nil`——这是 `PutIfVersion` 的正确语义，不是把失败当成功）。
   **报告的「没有找到 fail-open」是准确的，我没有找到反例。**

**结论：这三条「探过没破」我三次尝试都没能推翻。** 这是我这次复核里唯一没有产出的攻击面，
按 VERIFY-BRIEF 的要求明确写成「我尝试了 X 与 Y，都没能推翻」。

---

## 4. 两条「判断」的确认

**判断 1：ADR-0008 §2 的 expand/contract 规则没有覆盖 Down 方向 —— 确认。**
`docs/migration-decision.md:18-24` 的规则只约束**正向**发布：
「一个迁移**不得**在同一个发布里既加列又依赖它的回填，也不得删除仍在被上一版本代码读取的列」，
并给出「删列 / 改类型 / 收紧约束 → **延后一个版本**」。而 `Down` 段**本身就是**删列/改类型/收紧约束，
且 §4（`:31-35`）把 `-migrate-down` 定义为受支持的操作。具体例可引：
`0010_client_status.sql:15` 的 Down 是 `ALTER TABLE oauth_clients DROP COLUMN status;`，
而 `oauth.go` 的客户端 INSERT 点名了 `status` 列 → 一个仍在服务的旧实例会在下一次插入时失败。
**这是文档裁定，不是代码缺陷**；报告建议「在 ADR-0008 补一条：Down 只在停机窗口或已把流量摘干净后执行」
是合理且低成本的，我同意。

**判断 2：legacy `oauth_device_authorizations.user_code` 只有非唯一表达式索引，今天不可达 —— 确认。**
`0001_init.sql:94` 是 `CREATE INDEX oauth_device_user_code_idx ON oauth_device_authorizations
(upper(replace(user_code, '-', '')))`（**非 UNIQUE**，且是表达式，只有规范化后的比较能用它），
对照 `0008_oidc.sql:81` 的 `CREATE UNIQUE INDEX oidc_devices_user_code_idx`（UNIQUE）。
「先查再插」的形状也在：`oauth/device.go:432-443 freeUserCode` 调
`s.devices.GetDeviceByUserCode(ctx, code)`，`ErrDeviceNotFound` 才返回该码——
两次并发调用可以都看到空位，然后都插入，而 `GetDeviceByUserCode`（`oauth.go:355-361`）会返回其中任意一行。
**今天不可达也确认**：`Presence` 我扫了全仓，`cmd/re0auth` 里**没有任何** `oauth.Service` /
`oauth.Store` 的赋值点（grep `oauth\.Service|oauth\.New|Store:|oauth\.Store` 在 `cmd/re0auth` 只有
`oauth.NewMemoryClientRegistry()`、`oauth.NewClient(...)`、`sessions` 的 `Store:` 三处无关命中），
`db.Devices()` 的唯一调用点是 `postgres_test.go:410`。所以「写成判断而不是 finding」是正确处置。

---

## 5. 我未能验证的

1. **所有 Postgres 运行时行为**：本机无 Docker、无 Postgres、`TEST_DATABASE_URL` 未设置。
   `internal/store/postgres` 的集成测试全部 SKIP。具体未验证项：PG-002 的实际报错文本
   （我只从 goose 源码推出）、PG-001 的严重度（需要 `EXPLAIN` 看是否走顺序扫描、以及表实际大小）、
   PG-003 的时钟偏差在 pgx 参数推断下 `make_interval(secs => $3)` 是否真的成立、
   PG-008 的池占用时长、PG-009 的 planner 选择。**报告对每一条都标了「读；无 DB 执行」，我认可这个标注。**
2. **`BRIEF.md` 缺失** → 我无法核对「哪些是已被记录的决定」的完整清单。我用四份文档自行顶替，
   但如果有第五份（例如前两轮审计的去重清单）我可能把某个已报过的项目当成新发现（或反之）。
3. **探针包的编译状态在我复核期间被另一位代理改动**。我记录的是我实际跑通的那一次；
   如果现在再跑得到不同结果，那是并行写作的产物，不是我的复核结论。
4. **`TestMigrateDownRollsBackOneStep` 在 CI 里的真实结果**：`migrate_down_test.go:24-30` 在
   `TEST_DATABASE_URL` 未设且 `CI` 为空时 `t.Skip`，我没法在本机触发它，也没法读 CI 的历史运行记录。
   如果它**现在**在 CI 里是红的，那么 PG-002 就已经被 CI 抓住了（严重度要再降）；如果是绿的，
   说明 CI 的库每次都是全新的（无 0005 行）。**这正是决定 PG-002 严重度的那个未知量，我无法闭合它。**

---

## 6. 新发现

### V-1（新，来自 PG-001 的错误引用）：`oidc_auth_requests.client_id` 是一条**活**的、无前导索引的谓词，报告漏了

报告把「第 5 条」写成 `oauth_device_authorizations.client_id`，并引 `oidc.go:995`。**这个引用是错的**：
`oidc.go:995` 位于 `revokePendingAuthorizations` 里，语句是 `DELETE FROM oidc_auth_requests`+clause。
把 `oidc.go:988`/`:994` 与 `revokePredicate`（`oauth.go:313-327`，client-only 时产出 `client_id = $1`）
连起来看，真正被执行的语句是：

- `oidc.go:986-988`：`DELETE FROM oidc_codes WHERE request_id IN (SELECT id FROM oidc_auth_requests`+clause+`)`
- `oidc.go:994`：`DELETE FROM oidc_auth_requests`+clause

当过滤条件是 **client-only**（`Target.ClientID` 非空且 `Target.Subject` 为空，例如
`admin.KillSwitch(Target{ClientID: "cli_x"})` 或 `SuspendClient`）时，**`PUBLIC.oidc_auth_requests` 会收到
`WHERE client_id = $1`**。而该表的全部索引是：PK `(id)`、`oidc_auth_requests_expires_idx (expires_at)`
（`0008:30`）、`oidc_auth_requests_subject_idx (subject)`（`0012:21`）——**没有 `client_id` 前导索引**
（`0008:12-14` 只声明 `id` 为 PK，`client_id` 是普通列）。这是**顺序扫描**，
而且它落在**活路径**上（`OIDCStore.RevokeTokens` 是 `revokePendingAuthorizations` 的调用者，
`main.go:538` 的 `revokers` 第一个元素就是 `oidcStore`）。

**这比报告的第 5 条重要**：`oidc_auth_requests` 是**当前引擎**的表、全新部署也会长起来，
而报告花在它上面的那一条是给了 `oauth_device_authorizations`（那张表反而只被 `PurgeLegacySubject`
的 `subject` 谓词碰过，没有 `client_id` 谓词）。
修法同 PG-001，但迁移 0022 的清单要加上 `CREATE INDEX oidc_auth_requests_client_idx ON oidc_auth_requests (client_id);`
（或按 `0012` 的先例补 `(client_id, subject)`），并把 `revoke_predicate_test.go` 的表清单从两张扩到
`oidc_access_tokens` / `oidc_refresh_tokens` / `oidc_auth_requests` / `oauth_access_tokens` /
`oauth_refresh_tokens` / `oauth_codes`。

### V-2（新）：`oauth_device_authorizations.client_id` 这条「已知缺口」是空守卫

`TestKnownUnindexedPredicatesAreStillUnindexed` 的第 2 条与 `singleColumnPredicates` 的第 9 条
声明了一个**代码里不存在的谓词**。空守卫比没有守卫更坏：它会永久「通过」，
并在有人真的给这张表加上 client 过滤时给出「这条早就知道了」的假安慰。
建议：删掉这两处，或把它们的 `where` 字符串改成真实调用点（现在是编造的）。

### V-3（新，属报告自身的陈旧性）：探针文件清单与「schema 来源」论证都已过期

报告 §「探针文件清单」列出 7 个文件 + `migrationcopy/`（含 `hashes_gen.go` 与 20 个 `.sql` 副本），
并称 `migdown_probe_test.go` 只含 3 个测试。现状（`grep '^func Test'` 得到 25 个顶层测试函数，
分布在 8 个文件）：
`migrationcopy/` **已删除**；`migdown_probe_test.go` 仍是那 3 个测试（这一处报告是对的）；
新增了报告未提及的 `disk_read_probe_test.go`（5 个测试，含 4 个反空转 sentinel）与
`source_probe_test.go`（`TestAdapterDirectoryResolves`）；报告列出的
`atomicity_probe_test.go` 还多出 `TestTokenTablesHaveNoRowLevelSecurityOrTrigger` 与
`TestSweepStatementListMatchesExpiredTables` 两个未被记入清单的测试。
报告「未能到达」第 3 条整段（关于副本哈希的三条保障）现在描述的是一个不存在的机制。
**这不是内容错误，但报告的可信度依赖「探针读到的 schema 是真的」这条论证，而它引的载体没了。**
建议主代理把这一段改成「探针改为直接读 `internal/store/postgres/migrations`，由
`TestMigrationsDirectoryResolves` + `disk_read_probe_test.go` 的四个 sentinel 反空转」。

### V-4（新，属报告编号体系）：PG-007 与 PG-010 混进了「发现」章节

PG-010 报告的自己是「**没有实际代价**……不是缺陷」，PG-007 是「攻击者收益为零」的 schema 加固。
两者都是合法的留痕，但占据「发现」编号会让「本报告 N 条发现」的计数失真
（PG-003 的正文里还有一处笔误：报告 §范围与方法 第 8 行写「无 0005；见 `PG-003`」，
但 `0005` 是 **PG-002** 的内容，交叉引用指错了编号）。
建议：把 PG-007/PG-010 移到「探过但没破」，并修掉 `PG-003` → `PG-002` 的交叉引用。

---

## 7. 我认为被**低估**的一条

**V-1 之外没有。** 若必须挑一条原报告压得过低的，是 **PG-002 的传播面**：
报告把它框成「回退链在版本 5 上有个洞」，但 `down()` 在 `runMigrations` 前建完整条 apply 列表这件事
意味着**任何**被删除过的迁移文件都会让它之前的所有 Down 失效，而仓库里现在**恰好只有一个**这样的洞
（0005）。既然 `adoptLegacyMigrations`（`postgres.go:413-467`）会在**每次** `Open()` 时对照
`schema_migrations`／`goose_db_version` 做一次「库里有、文件没了」的静默比对（`Up` 路径对这类版本
完全不报错，报告自己指出了这一点），**建议加一个非 DB 的守卫**：断言「`goose_db_version` 里会出现的
每个版本号要么有迁移文件、要么在 `docs/migration-decision.md` 的已知停点清单里」。
这不是新缺陷，是把一次性缺口变成机制缺口——也正是报告「修法建议」里 (c) 的更完整形态。

---

## 附：我改了哪些文件

只写了本文件。未修改、未删除任何被跟踪文件，未触碰 `internal/zzprobe/pgstore/**`
（那是另一位代理的探针）与 `docs/audit-5/findings/postgres.md`（被复核的报告）。
