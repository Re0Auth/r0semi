# ADR-0007：可观测性——业务指标、SLO 与随仓库交付的告警

> 状态：**已接受**。
> 背景：`internal/observability` 一直只有 HTTP 黄金指标，没有任何**领域信号**——
> 登录失败、令牌签发/错误、撤销、上游刷新失败、vault 打不开、审计链校验失败，
> 在线上全都表现为一个 4xx 或一次重定向，与正常情况无法区分，也就没有东西可以告警。
> 相关：[operations-decision.md](./operations-decision.md)（ADR-0006）、[slo.md](./slo.md)。

## 决策

1. **业务/安全指标是一等公民，与黄金指标同住 `internal/observability`。**
   新增的信号（全部 `re0auth_` 前缀，标签取值全部有界）：

   | 指标 | 标签 | 它回答什么 |
   |---|---|---|
   | `auth_logins_total` | `provider`, `result` | 登录成功/失败，及失败原因 |
   | `tokens_issued_total` | `grant_type` | 令牌签发速率 |
   | `token_errors_total` | `grant_type`, `error` | 令牌端点的失败，按 OAuth 错误码 |
   | `device_decisions_total` | `decision` | 设备流批准/拒绝 |
   | `revocations_total` | `kind` | 撤销操作（grant/binding/cascade/kill_switch/erasure） |
   | `tokens_revoked_total` | `kind` | 被撤销的令牌条数 |
   | `admin_actions_total` | `action` | 运维面写操作 |
   | `audit_verify_total` | `result` | 审计链校验结果 |
   | `upstream_fetches_total` | `game`, `source`, `result` | 数据面读上游的结果（ok/degraded/not_bound/unavailable/circuit_open） |
   | `upstream_fetch_duration_seconds` | `game`, `source`, `result` | 数据面读上游的时延 |
   | `upstream_refreshes_total` | `result` | 上游刷新结果（ok/rejected/transient/lost_race/no_refresh_token） |
   | `upstream_circuit_transitions_total` | `state` | 上游熔断器进入的状态（open/half_open/closed）。补的是**不出网**的那一半：断路器打开后被拒的请求到不了网络，数据面自己的计数器因此安静 |
   | `vault_operations_total` | `operation`, `result` | vault 操作结果 |
   | `vault_operation_duration_seconds` | `operation` | vault 操作时延 |

2. **标签必须由构造保证有界。** 来自请求的值一律先归一：`grant_type` 与 OAuth 错误码走白名单、
   HTTP 方法走白名单、登录失败的 IdP `error` 值**不**透传（改用固定码）；唯一自由形式的一对
   `game`/`source` **只在源确实出自本部署的注册表时**才记录。无界标签等于把 `/metrics` 变成内存泄漏，
   而一个能被请求撑爆的指标端点，本身就是可用性缺口。

3. **告警规则随仓库交付**（`deploy/prometheus/re0auth.rules.yml`）。指标没有消费者等于没有指标；
   把规则留给部署方写，结果是公开实例上线时一条规则都没有。规则覆盖的 SLI 与目标在
   [slo.md](./slo.md)，每条告警都指向那里的一节。

4. **追踪维持 ADR-0006 的结论：只在进程内相关，不导出 span。** 本次不改这条——
   加告警不需要 OTel，而接入 exporter 是另一个面、另一条 ADR。

5. **基准数据的门禁只保证"跑出来了"，不设阈值。** `make bench` 与 CI 的 `bench` 作业执行容量基准；
   CI 断言"至少产出了若干条结果"，不断言快慢。会在慢机器上变红的门禁最后都会被人删掉，
   而为了不被删而调低阈值，等于把门禁变成装饰。数字对外报告（见本文件末），由人判断趋势。

## 为什么是现在

报警与排查此前完全依赖人工读日志：`operations.md` 的"常见现象"是一张要靠人主动去查的表。
这在"有人盯着"时可用，但授权层最关键的一类事件——**审计链不再自洽**、**vault 开始打不开**、
**上游集体拒绝刷新**——恰恰是没人会主动去查、却必须立刻知道的。它们没有 HTTP 状态码能表达，
所以必须先有信号，才谈得上告警。

## 被否决的替代方案

- **只加黄金指标、不加领域信号。** HTTP 5xx 速率看不见"审计链被改写后 `verify` 返回 `ok:false`"
  这类只在响应体内表达的事件；把安全事实塞进状态码也不对。
- **把领域信号做成日志、靠日志告警。** 日志是每请求一份的诊断流，按它告警要么噪声太大，
  要么依赖日志侧的聚合——而本服务刻意不持久化日志（ADR-0006）。指标是计数，天然适合告警。
- **把规则留给部署方。** 见决策 3。
- **为标签方便而透传请求里的原始值。** 见决策 2。

## 后果

- 新增 `deploy/` 下的 Prometheus 规则与 Grafana 面板；部署方把它们接到自己的 Prometheus/Grafana，
  或按同样语义翻译成自有的告警系统。
- 后端只要新增一条会发领域信号的处理路径，就要在同一次改动里给它接上 `Observe*`——
  这与"新增路由必须同时进 OpenAPI"是同一种纪律。
- `docs/operations.md` 的排障一节改为先指向 [slo.md](./slo.md)，再讲具体命令。

## 测试锚点

- `internal/observability`：领域信号进入 exposition、非正值不建序列、未知标签值被收敛、nil 接收者安全。
- `internal/httpapi`：`TestBusinessMetricsFireThroughTheServer` 走真实装配的服务器，
  断言令牌签发与错误信号确实被记录——证明的是**接线**，这是编译期检查不到的那一半。
- CI `bench` 作业：基准被编译并执行，且至少产出若干条结果。

## 本次实测（本机，Windows，20 逻辑核，`make bench`）

| 基准 | ns/op | B/op | allocs/op | 单核吞吐（约） |
|---|---|---|---|---|
| `BenchmarkBusinessPlaneBearerMe`（内省 + `/v1/me`） | 34489 | 25010 | 344 | 2.9 万 req/s |
| `BenchmarkProtocolIntrospect`（`POST /oauth/introspect`） | 44438 | 37646 | 436 | 2.3 万 req/s |
| `BenchmarkProtocolDiscovery`（discovery 文档） | 39371 | 30628 | 334 | 2.5 万 req/s |

这些是**单核、含完整中间件链与访问日志**的每请求成本，用来比较趋势，不是集群吞吐上限。
逐次运行有约一成抖动（同一份代码两次跑，`BearerMe` 分别是 37.0µs 与 34.5µs）。换机器要重新测，
不要在 CI 里设阈值。
