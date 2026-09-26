# 服务目标与告警（SLI / SLO）

> 决策见 [observability-decision.md](./observability-decision.md)（ADR-0007）。
> 规则文件：`deploy/prometheus/re0auth.rules.yml`。面板：`deploy/grafana/re0auth-dashboard.json`。
> 这里定义"什么算好"，规则表达"什么时候要人来看"，两者一一对应。

## 1. SLI 与目标

| # | SLI | 定义（PromQL 语义） | 目标（滚动 30 天） |
|---|---|---|---|
| S1 | 可用性 | 非 5xx 请求 / 全部请求，`re0auth_http_requests_total` | ≥ 99.9% |
| S2 | 令牌端点成功率 | 成功签发 /（签发 + 错误），`tokens_issued_total` + `token_errors_total` | ≥ 99.5% |
| S3 | 登录成功率 | `auth_logins_total{result="success"}` / 全部，按 provider | ≥ 95% |
| S4 | 业务面时延 | `http_request_duration_seconds{plane="business"}` p99 | < 1s |
| S5 | 审计链完整性 | `audit_verify_total{result="failed"}` | **恒为 0** |
| S6 | 凭据可用性 | `vault_operations_total{result!="ok"}` 的比例 | < 0.1% |
| S7 | 上游可用性 | `upstream_fetches_total{result="unavailable"}` 比例，按 source | < 5% |

S5 是**硬目标**：审计链自洽是本服务对"日志被动过吗"唯一的控制，任何一次 `failed` 都是事件，不是趋势。
`error`（校验本身没跑完）是 S5 的**盲区**：链可能完好，但没有人能证明——所以它单独告警
（`Re0AuthAuditVerifyError`），而不是并进 `failed`。

这个序列由**服务自己**推动：启动时与之后每 6 小时走一遍整条链（`cmd/re0auth` 的 `auditVerifyLoop`），
运维手工调 `GET /v1/admin/audit/verify` 走的是同一条路径、记的是同一个计数器。这一点是目标能否被
评估的前提——在循环存在之前，`failed` 恒为 0 只是因为没人调用过校验，而不是因为链是好的。
间隔的取舍与"扫不完怎么办"见 [operations.md](./operations.md) 的「审计链锚点核对」。

### 1.1 错误预算与燃尽率

S1 的 99.9% 目标等价于 30 天滚动窗口内 **0.1% 的错误预算**。规则文件的 `re0auth-slo` 组把各窗口的
错误比例物化成 `re0auth:errors:ratio_*` 记录规则，再由两条多窗口燃尽率告警消费：

| 告警 | 长窗 | 短窗 | 燃尽倍率 | 严重度 | 含义 |
|---|---|---|---|---|---|
| `Re0AuthErrorBudgetFastBurn` | 1h | 5m | 14.4× | critical | 按此速度几天烧完 30 天预算，立即处置 |
| `Re0AuthErrorBudgetSlowBurn` | 6h | 30m | 6× | warning | 稳定消耗，通常开单排查 |

燃尽倍率 × 0.1% 即允许的错误比例（14.4×0.1% = 1.44%）。§2 的阈值告警是短窗代理；这两条才是
真正跟踪 30 天预算的告警。预算耗尽的策略：**冻结非必要变更、优先恢复可用性**，随后按
[incident-response.md](./incident-response.md) 复盘。记录规则名用冒号（`re0auth:...`）而非下划线，
以免被 artifacts 测试的 `re0auth_` 指标扫描误当成导出序列。

## 2. 告警

规则见 `deploy/prometheus/re0auth.rules.yml`，每条告警的处置步骤见
[runbooks.md](./runbooks.md)。下表标出每条服务的 SLI。

| 告警 | 条件（摘要） | 严重度 | 服务 | 先做什么 |
|---|---|---|---|---|
| `Re0AuthHighErrorRate` | 5xx 比例 > 1%，持续 10m | critical | S1 | 看 `/readyz` 与数据库；见 runbooks |
| `Re0AuthErrorBudgetFastBurn` | 1h 与 5m 错误率同时 > 14.4×0.1% | critical | S1 | 按可用性事件处置并升级 |
| `Re0AuthErrorBudgetSlowBurn` | 6h 与 30m 错误率同时 > 6×0.1% | warning | S1 | 开单排查持续的小比例 5xx |
| `Re0AuthSlowRequests` | 业务面 p99 > 1s，持续 10m | warning | S4 | 查上游来源是否变慢、连接池是否打满 |
| `Re0AuthPoolSaturated` | 连接池占用 > 90% 且 10m 内空取 > 10 次，持续 10m | warning | S1/S4 | 先查长语句再谈加池；核对 `max_conns × 副本数` 预算 |
| `Re0AuthTokenEndpointErrorRate` | 令牌错误比例 > 5%，持续 10m | warning | S2 | 按 `error` 标签分组看是 `invalid_client` 还是 `invalid_grant` |
| `Re0AuthLoginFailureRate` | 登录失败比例 > 30%，持续 15m | warning | S3 | 按 `provider` 看是否某一个 IdP 的发现/换票挂了 |
| `Re0AuthAuditChainBroken` | `increase(audit_verify_total{result="failed"}[10m]) > 0` | critical | S5 | 按 `admin.md` §5 调查；`first_bad_id` 指向第一处不一致 |
| `Re0AuthAuditVerifyError` | `increase(audit_verify_total{result="error"}[10m]) > 0` | warning | S5 | 校验没跑完 ≠ 链坏了：先看数据库与语句超时，再手工跑一次 verify |
| `Re0AuthVaultOperationFailures` | 非 ok 比例 > 1%，持续 10m | critical | S6 | 看 `result`：`unconfigured_key` 意味着轮换没收尾，`decrypt_error` 意味着数据损坏 |
| `Re0AuthUpstreamSourceUnavailable` | 某 source `unavailable` 比例 > 30%，持续 10m | warning | S7 | 确认该数据源自身是否可达；`not_bound` 不是故障，不触发 |
| `Re0AuthUpstreamSlowSource` | 某 source `ok` 读取 p95 > 2s，持续 15m | warning | S7 | 区分网络还是源本身慢；长期慢可降级该源 |
| `Re0AuthRefreshRejections` | `rate(upstream_refreshes_total{result="rejected"}[15m]) > 0` | warning | S7 | 用户在被动重新绑定；查该源是否提前作废了 refresh token |
| `Re0AuthGoroutineLeak` | `go_goroutines` 持续高于阈值（默认 5000） | warning | — | 抓 `/debug/pprof/goroutine?debug=2` 查堆积 |
| `Re0AuthMemoryHigh` | `process_resident_memory_bytes` 持续高于阈值（默认 400MiB） | warning | — | 看 `/debug/pprof/heap`，先防 OOMKill 再查根因 |
| `Re0AuthFileDescriptorsHigh` | `process_open_fds / process_max_fds > 0.8`，持续 15m | warning | — | 查连接泄漏；提 ulimit 只买时间 |
| `Re0AuthKillSwitchFired` | `increase(revocations_total{kind="kill_switch"}[5m]) > 0` | info | — | 不是故障，是通知：有人拉了一键撤销，事故响应应该已经在进行 |

## 3. 刻意不告警的

- **`not_bound`。** 用户没连数据源是正常状态，不是上游故障。把它算进上游可用性会让每一次
  "还没绑定"都变成告警。
- **单条登录失败。** 打错 provider、Provider 拒绝授权都是用户行为；只在**比例**上告警。
- **基准快慢。** 见 ADR-0007 决策 5：CI 不按阈值卡基准。
- **`up`/抓取可达性。** 那是部署方 Prometheus 与 ServiceMonitor 的职责，不是本服务导出的指标。

## 4. 接入

部署方把内部监听器（`server.internal_addr`，默认 `:9090`）`/metrics` 接进 Prometheus，
再把 `deploy/prometheus/re0auth.rules.yml` 作为规则文件加载（或翻译成自有告警系统）。
`deploy/grafana/re0auth-dashboard.json` 可导入 Grafana，数据源指向同一个 Prometheus。

规则里的 `job`/`instance` 选择子故意留空——抓取配置由部署方决定；规则只依赖 `re0auth_*` 指标名，
因此不绑定任何一种 scrape 约定。
