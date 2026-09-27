# 变更记录

> 这份文件记录**部署者与下游需要知道的变化**：破坏性变更、配置/密钥/迁移上的影响、协议面
> 行为的改变、以及操作性要求的变化。逐条提交级细节不在这里——那由提交历史（Conventional
> Commits，破坏性变更带 `!`）与每个 tag 的 release notes 承担；**为什么**这么改记录在
> `docs/*-decision.md` 的 ADR 里。升级步骤见 [docs/operations.md](docs/operations.md)
> 的「升级」一节，它的第一步就是先读这里与受影响的 ADR。

## Unreleased

- **源从配置移除后，名下绑定现在可以被用户断开**：`Unbind` 此前在读取绑定**之前**就对未知源返回
  `ErrUnknownSource`，于是 `DELETE /v1/bindings/{game}/{source}` 回 404，而 `GET /v1/bindings`
  仍带着 `configured:false` 列出这条绑定并声称「仍可断开」——那条上游令牌与其 vault 密文只能靠运维
  Kill Switch 或整账号抹除清除。现在注册表查找挪到读取绑定之后：绑定存在即执行本地那一半（撕密文、
  删行），上游记为 `nothing`（已无源可问）；只有「未知源且无绑定」才继续是 404。

- **协议面 `/.well-known/*` 的未知路径改为 OAuth JSON 404**：此前落在提供方 handler 的
  `http.NotFound` 分支，回的是标准库的 `text/plain` 404，而日志、指标与限流器都把该请求记为
  `plane=protocol`。未知路径与真实文档的尾斜杠拼写（如 `/.well-known/oauth-authorization-server/`）
  现在与 `/oauth/*` 的未知端点为同一形状。

- **每个端点声明自己的动词，未列出的动词一律 `405`**：协议面新增一张 `endpointMethods` 表
  （「已知端点」也由它派生），`authorize`/它的回调与 `userinfo` 收 `GET`/`POST`，`keys` 收
  `GET`/`HEAD`，其余收 `POST`；`PUT`/`DELETE`/`PATCH`/`OPTIONS` 等一律回 `405` 的 OAuth 错误体，
  不再落到库或某个没有方法策略的分支。`/oauth/keys` 此前对任意方法都回 200（响应只是公钥，未泄露
  任何东西，但它是唯一没有方法约束的端点）。业务面同样改为按方法分派：已注册路径上未声明的动词现在回
  `405` problem+json 并带 `Allow` 头，而不再被 `/v1/` 兜底吞成 `404`。两面的动词矩阵都从
  `specRoutes` / `endpointMethods` 自动派生，各有一条逐一断言的守卫测试。

- **撤销令牌的索引（迁移 `0018`）**：`oidc_refresh_tokens.id_hash` 此前没有索引，而 RFC 7009 撤销路径
  （`RevokeToken` 的查找与两条 DELETE）都按它查/删，每次撤销都退化成全表扫描。新迁移在启动时自动执行；
  影响面是撤销与应急响应端点，不是签发热路径。

- **公开库 `idp` 自带的 fallback HTTP client 改为 fail-closed**：调用方不注入
  `RegistryConfig.HTTPClient` 时，默认 client 现在也在拨号层拒绝 loopback / link-local / 私网地址，
  与生产装配根一致。身份提供方确实在私网的直接库使用者，需显式注入自己的 client。HTTP 面与配置不受影响。

- **`taptapoauth` 不再成段回显上游错误原文**：上游的 `error` / `error_description` / 原始 body
  现在按上限（200 rune）截断并压平换行后才进错误与日志，避免噪声与伪造日志行；错误分类不受影响。

- **新增 `perf` 工作流与 `make perf`（开发工具，无部署影响）**：每周/手动运行
  每基准 10 次采样的基准测试与 30s 容量画像，`cmd/perfreport` 把结果渲染成
  Markdown 报告（中位数、离散度、与上一次成功运行的基线对比），写入 job summary
  并随 run 存为 artifact。ci.yml 既有的 `bench`/`load` 门槛不变；本地 `make perf`
  无需数据库，审计链基准会照实跳过并在报告中注明。

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
