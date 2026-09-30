# ADR-0008：数据库迁移——expand/contract 与回滚

> 状态：**已接受**。
> 背景：迁移在启动时自动执行（`postgres.Migrate`），15 个迁移每个都带 `-- +goose Down`，
> 但此前没有任何 CLI 能触达 down——down 段存在、被测试钉住，却无法运行。本文记录迁移的
> 兼容性规则、回滚策略，以及新增的 `-migrate-down`。
> 相关：[operations.md](./operations.md) §升级、[operations-decision.md](./operations-decision.md)（ADR-0006）、
> [architecture.md](./architecture.md)。

## 决策

1. **迁移在启动时执行，由 goose 的 advisory session locker 串行化。**
   `Open()` 无条件 `Migrate()`：不存在“连上未迁移的库”的受支持路径。多实例启动时，
   `goose/v3/lock` 的 Postgres session locker（`pg_try_advisory_lock` + 重试，锁 ID 仍是
   `migrationLockKey`）保证同一时刻只有一个实例在迁移；在
   `maxUnavailable: 0` 的滚动发布下，第二个实例**等待锁**而不是并行迁移。等待有上界：
   5 秒一次、共 60 次（5 分钟），超过即启动失败——不像阻塞式 `pg_advisory_lock` 那样
   在持锁进程卡住时永久挂起。锁与 goose 都跑在一条独立连接上（不是从池里借的），以免
   继承了属于服务流量的 `statement_timeout`。

2. **同一版本内只做加法（expand/contract）。**
   一个迁移**不得**在同一个发布里既加列又依赖它的回填，也不得删除仍在被上一版本代码读取的列。
   规则：
   - 加表 / 加列 / 加索引 → 可随代码一起发布（旧代码忽略新列）。
   - 回填数据 → **独立**迁移，幂等，可重跑。
   - 删列 / 改类型 / 收紧约束 → **延后一个版本**：先发布不再依赖它的代码，下一版再删。
   理由：滚动发布期间新旧两个二进制同时在跑，schema 必须同时对两者可用。

3. **`Down` 存在，但不是回滚故事。**
   回滚故事是**从备份恢复**（`scripts/restore.sh`，RPO ≤ 15 分钟，RTO ≤ 1 小时）。
   down 迁移会让你丢掉那一列里的数据，而一次失败的发布通常更适合回退到上一份已知良好的转储。
   `Down` 只服务于“撤销我刚应用的这一步”这一具体场景。

4. **新增 `-migrate-down`，只回退一步。**
   `re0auth -migrate-down` 回退最近一次迁移后退出。它是一个**包级函数**
   （`postgres.MigrateDown`），不是 `*DB` 方法：调用它时必须**还没有**打开连接池，因为
   `Open()` 会向上迁移，先开池再回退会被“开池”这个动作本身抵消。回退同样在同一个
   session locker 下、在独立连接上执行。

5. **完整性迁移 0013 / 0014 不可回退：Down 段只留注释，主体为空。**
   `0013_audit_chain.sql` 与 `0014_audit_pseudonyms.sql` 的 `-- +goose Down` 之下
   **不执行任何语句**，并以注释说明原因。它们不是普通的 schema 步骤，而是审计链的
   防篡改属性本身：
   - 0013 的旧 Down 会 `DROP TABLE audit_chain`、`DROP INDEX audit_events_row_hash_idx`，
     并从 `audit_events` 删掉 `signature` / `row_hash` / `prev_hash`；其 Up 再把三列加回
     （存活行的值全部为 NULL）并把链头重置为创世哈希。一次 Down→Up 往返之后，历史行
     全部读作 `Legacy`，链头回到创世，**`Verify` 依然返回 `OK=true`**——被摧毁的证据
     却报告健康。这不是“回滚了一列数据”，而是抹掉了这一列存在的理由。
   - 0014 的旧 Down 会 `DROP TABLE audit_subject_keys`，那是每个主体伪名密钥的**唯一**
     副本。删除它会把每个活跃主体的伪名历史一分为二：下一次审计写入找不到密钥、
     重新随机生成一个，旧行与新行再也无法关联，`?subject=usr_…` 只返回新行，
     静默截断且 `Verify` 无从察觉。
   两者都**无法**通过重新 Up 恢复，因此回滚故事只有一个：**从备份恢复**（§3、
   `scripts/restore.sh`）。`postgres.MigrateDown` 在调用 `provider.Down` 之前先执行
   `refuseAuditChainRollback`：当 goose 版本为 13 或 14 **且** `audit_events` 中存在
   `row_hash IS NOT NULL` 的行时直接报错拒绝，并提示改用备份恢复；数据库里没有已入链
   的行（全新库、从未写入过审计行）时不拦截，`-migrate-down` 照常可用。
   对绕过 `MigrateDown`、直接用 goose CLI 的运维者，空 Down 段本身就是那道控制。
   **Up 段必须保持幂等**：goose 对“执行了零条语句”的 Down 段同样会删除版本行，
   下一次 `Open()` 会重跑 Up；因此 0013 用
   `ADD COLUMN IF NOT EXISTS` / `CREATE UNIQUE INDEX IF NOT EXISTS` /
   `CREATE TABLE IF NOT EXISTS`，创世链头用
   `INSERT ... ON CONFLICT (only_row) DO NOTHING`（保留存活的真实链头而不是改回创世），
   0014 用 `CREATE TABLE IF NOT EXISTS`。少了幂等，重启就是
   `column/relation already exists` 的硬失败，且迁移中途卡住 advisory lock。

## 后果

- 破坏性变更需要两阶段发布（先发兼容代码，再删 schema），发布计划里要留出这一版。
- `-migrate-down` 一次一步；要回退多步就重复执行，或在明确知道后果时用 goose CLI。
- 每次发布前先做一次备份（见 [operations.md](./operations.md) §升级）。
- **0013 / 0014 是不可回退的完整性步骤**：它们的 Down 不执行任何 DDL，`MigrateDown`
  在链上已有 `row_hash IS NOT NULL` 的行时拒绝回退这两版。这条规则要挡住的后果是：
  旧 Down 会把全部历史行变成 `Legacy`，而 `Verify` 依然报告 `OK=true`。即便有人绕过
  `MigrateDown` 直接跑 `goose down`，空 Down 段也只是删掉版本行、不改动 schema，
  下一次 `Open()` 幂等重跑 Up，链保持完好。真需要撤掉它们时，恢复上一份已知良好的
  备份，不要试图撤销 schema。
- 这两版的 **Up 必须保持幂等**（`IF NOT EXISTS` + `ON CONFLICT DO NOTHING`）。空 Down
  段会让版本行消失、下次启动重跑 Up；非幂等 Up 会把一次无害的回退变成重启硬失败。
  `TestAuditIntegrityMigrationsCannotBeRolledBack` 与
  `TestAuditChainSurvivesADownUpCycle` 钉住这两点。

## 测试锚点

- `internal/store/postgres/migrations_test.go`：每个迁移文件都是 goose 形状（`Up` + `Down`、版本严格递增）；
  `TestAuditIntegrityMigrationsCannotBeRolledBack` 钉住 0013/0014 的空 Down、两个 Up 的幂等形态，
  以及 `MigrateDown` → `refuseAuditChainRollback` 的接线（无需数据库）。
- `internal/store/postgres/migrate_down_test.go`：`MigrateDown` 恰好回退一步，`Migrate` 能重新应用；
  `TestMigrateDownRefusesToDestroyTheAuditChain` 在独立 schema 里驱动版本 12/13/14 的拒绝判定
  （需 `TEST_DATABASE_URL`）。
- `internal/zzprobe/audit7/z21migrationsschemaintegrity/`：`TestAuditChainSurvivesADownUpCycle` 直接读
  0013 的 Down 判定红/绿，`TestDownDoesNotDropAuditRows` 断言两个 Down 不执行任何 DDL。
- `internal/zzprobe/pgstore/migdown_probe_test.go`：整段 Down 序列的护栏，带 ADR-0008 §5 的
  non-rollbackable 豁免集（`audit_chain`、`audit_subject_keys`、`audit_events_row_hash_idx`）。
