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

- **协议面不再返回 CORS 头**（discovery 与 `/oauth/*`）：库此前按请求 `Origin` 回
  `Access-Control-Allow-Origin` 与 `Access-Control-Allow-Credentials: true`，与服务同源的部署无关，
  但对任何来源都生效。现在这些头被去掉，同源客户端不受影响；跨源前端请看
  [docs/cors-decision.md](docs/cors-decision.md)（ADR-0011，含重新评估的触发条件）。

- **审计链改为持续校验**：新增一个后台循环，启动时与之后每 6 小时走一遍整条记录链，
  结果计入 `re0auth_audit_verify_total{result=…}`。此前校验只在运维手工调用
  `GET /v1/admin/audit/verify` 时发生，因此 S5 这个「恒为 0」的硬目标在无人调用时**无法被证伪**——
  一条断链可以一直等到某次例会才被发现。失败与「没跑完」现在都会进日志与指标，
  两条既有告警（`Re0AuthAuditChainBroken` / `Re0AuthAuditVerifyError`）从「要人记得跑」变成「会自己响」。
  全表遍历较贵，所以间隔是小时级而非分钟级；日志大到 45s 扫不完时的处置仍是上增量校验点，见
  [docs/operations.md](docs/operations.md) 的「审计链锚点核对」。
- **`server.internal_addr` 绑到非 loopback 地址现在需要显式承认**：新增
  `server.expose_internal`（环境变量 `RE0AUTH_INTERNAL_EXPOSE`）。不设时，只有 loopback 地址
  被接受；`0.0.0.0:9090`、`[::]:9090` 或 `:9090` 一律拒绝启动。此前唯一的检查是「不等于
  `server.addr`」，于是把 `/metrics` 与 `/debug/pprof/`（堆、goroutine dump、CPU profile）
  交给网络只需要写错一个地址。**k8s 基线需要改**：`deploy/k8s/base/configmap.yaml` 已补上
  `expose_internal = true`，它的安全性来自同目录的 NetworkPolicy（只放行 monitoring 命名空间到 9090）。

## v0.0.0-rc.3

**目前唯一带产物的预发布**：release 里有六个平台的归档、`SHA256SUMS` 及其 cosign 签名、以及 SBOM。
它验证的仍是 **tag → CI → 产物** 这条链路，所以它和下面各条一样**不是可以部署的版本**——
rc.1 那节列出的适用条件全部成立。

## v0.0.0-rc.2

预发布 tag，用途与 rc.3 相同。**它没有产物**：那次 tag 运行死在 Trivy 扫镜像的一步
（OCI 引用的仓库名必须小写，而组织名是 `Re0Auth`，解析器不像 build/push 那样替我们规范化），
`gh release create` 因此从未执行。修法见 rc.3 那次运行，这也是「tag 一响就等于发布了」的反例。

## v0.0.0-rc.1

> **这个 tag 不存在。** 仓库里没有 `v0.0.0-rc.1`——`git ls-remote --tags` 只有 rc.2 与 rc.3，
> 也没有对应的 release。本节保留的是当时的**意图**记录。
>
> 代价值得记下来：`deploy/k8s/base/kustomization.yaml` 曾长期钉着这个名字，
> 而那是一份**拉不到的基线**，`internal/archtest` 当时只检查「非空且不是 `latest`」，
> 于是对一个从未构建过的 tag 报了绿。现在那条守卫会拿仓库里真实存在的 tag 比对。

预发布，用来把 **tag → CI → 产物** 这条链路端到端跑通一次（可下载产物的构成见 README
「发布产物」）。它不是可以部署的版本：

- 项目定位仍是迭代期，**未达生产可用**——见 README 顶部的警告与
  [SECURITY.md](SECURITY.md) 里逐条列出的已知限制。
- 三把密钥与 issuer 必填、缺一即拒绝启动；持久化部署还多一把审计链密钥。
