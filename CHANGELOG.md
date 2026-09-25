# 变更记录

> 这份文件记录**部署者与下游需要知道的变化**：破坏性变更、配置/密钥/迁移上的影响、协议面
> 行为的改变、以及操作性要求的变化。逐条提交级细节不在这里——那由提交历史（Conventional
> Commits，破坏性变更带 `!`）与每个 tag 的 release notes 承担；**为什么**这么改记录在
> `docs/*-decision.md` 的 ADR 里。升级步骤见 [docs/operations.md](docs/operations.md)
> 的「升级」一节，它的第一步就是先读这里与受影响的 ADR。

## Unreleased

## v0.0.0-rc.1

预发布，用来把 **tag → CI → 产物** 这条链路端到端跑通一次（可下载产物的构成见 README
「发布产物」）。它不是可以部署的版本：

- 项目定位仍是迭代期，**未达生产可用**——见 README 顶部的警告与
  [SECURITY.md](SECURITY.md) 里逐条列出的已知限制。
- 三把密钥与 issuer 必填、缺一即拒绝启动；持久化部署还多一把审计链密钥。
