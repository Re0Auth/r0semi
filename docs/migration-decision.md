# ADR-0008：数据库迁移——expand/contract 与回滚

> 状态：**已接受**。
> 背景：迁移在启动时自动执行（`postgres.Migrate`），15 个迁移每个都带 `-- +goose Down`，
> 但此前没有任何 CLI 能触达 down——down 段存在、被测试钉住，却无法运行。本文记录迁移的
> 兼容性规则、回滚策略，以及新增的 `-migrate-down`。
> 相关：[operations.md](./operations.md) §升级、[operations-decision.md](./operations-decision.md)（ADR-0006）、
> [architecture.md](./architecture.md)。

## 决策

1. **迁移在启动时执行，由 advisory lock 串行化。**
   `Open()` 无条件 `Migrate()`：不存在“连上未迁移的库”的受支持路径。多实例启动时，
   `pg_advisory_lock(migrationLockKey)` 保证同一时刻只有一个实例在迁移；在
   `maxUnavailable: 0` 的滚动发布下，第二个实例**等待锁**而不是并行迁移。锁与 goose 都跑在
   一条独立连接上（不是从池里借的），以免继承了属于服务流量的 `statement_timeout`。

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
   `Open()` 会向上迁移，先开池再回退会被“开池”这个动作本身抵消。回退同样在 advisory lock 下、
   在独立连接上执行。

## 后果

- 破坏性变更需要两阶段发布（先发兼容代码，再删 schema），发布计划里要留出这一版。
- `-migrate-down` 一次一步；要回退多步就重复执行，或在明确知道后果时用 goose CLI。
- 每次发布前先做一次备份（见 [operations.md](./operations.md) §升级）。

## 测试锚点

- `internal/store/postgres/migrations_test.go`：每个迁移文件都是 goose 形状（`Up` + `Down`、版本严格递增）。
- `internal/store/postgres/migrate_down_test.go`：`MigrateDown` 恰好回退一步，`Migrate` 能重新应用
  （需 `TEST_DATABASE_URL`）。
