# 变更记录

> 这份文件记录**部署者与下游需要知道的变化**：破坏性变更、配置/密钥/迁移上的影响、协议面
> 行为的改变、以及操作性要求的变化。逐条提交级细节不在这里——那由提交历史（Conventional
> Commits，破坏性变更带 `!`）与每个 tag 的 release notes 承担；**为什么**这么改记录在
> `docs/*-decision.md` 的 ADR 里。升级步骤见 [docs/operations.md](docs/operations.md)
> 的「升级」一节，它的第一步就是先读这里与受影响的 ADR。

## Unreleased

- **破坏性（仅影响直接使用公开库 `oauth` 的代码）**：`oauth.DeviceStore` 的
  `UpdateDevice(ctx, DeviceAuthorizationRecord)` 拆成两个字段级方法——
  `RecordPoll(ctx, deviceCodeHash, at)` 与
  `RecordDecision(ctx, deviceCodeHash, DeviceDecision) (bool, error)`。
  原因：整条写回让一次轮询可以把落在读之后的**决定**抹回 pending，且两次并发决定会互相覆盖。
  实现者需改这两个方法（`MemoryDeviceStore` 与 Postgres 侧已改）；HTTP 面与配置不受影响。
  背景见 [docs/security-audit-3.md](docs/security-audit-3.md) 与本条对应的提交。
- **过期判定改为单时钟**：Go 写的时间戳（会话、授权码、OP 令牌）一律由进程时钟判定，
  数据库 `DEFAULT now()` 写的仍由数据库判定。副本与数据库之间无需再对齐到亚秒——但仍建议 NTP；
  排障见 [docs/operations.md](docs/operations.md) 的「可观测与排障」。

## v0.0.0-rc.1

预发布，用来把 **tag → CI → 产物** 这条链路端到端跑通一次（可下载产物的构成见 README
「发布产物」）。它不是可以部署的版本：

- 项目定位仍是迭代期，**未达生产可用**——见 README 顶部的警告与
  [SECURITY.md](SECURITY.md) 里逐条列出的已知限制。
- 三把密钥与 issuer 必填、缺一即拒绝启动；持久化部署还多一把审计链密钥。
