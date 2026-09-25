# 告警 Runbook（运维处置手册）

> 每条告警的 `runbook_url` 指向本文对应小节。SLI/SLO 定义见 [slo.md](./slo.md)，
> 规则文件 `deploy/prometheus/re0auth.rules.yml`，面板 `deploy/grafana/re0auth-dashboard.json`。
> 事故响应的整体流程（严重度分级、升级、沟通、复盘）见 [incident-response.md](./incident-response.md)。

## 通用前提

- **操作面**：`/v1/admin/*` 只对 `[admin].allow` 允许列表里的 `usr_…` 开放，且变更类接口需要
  在 `[admin].reauth_window`（默认 15 分钟）内重新登录过。见 [admin.md](./admin.md)。
- **看指标**：内部监听器 `server.internal_addr`（默认 `:9090`）的 `/metrics`；`/debug/pprof` 也在这里。
- **看数据库/迁移**：`docs/operations.md` 的“排障”与“升级”两节。
- **先看面板**：`deploy/grafana/re0auth-dashboard.json` 的 overview；顶部的 “Telemetry volume (self-check)”
  面板若在流量正常时不动，说明领域埋点没被打到，不要据此判断“没发生”。

---

## Re0AuthHighErrorRate

**含义**：5xx 比例 > 1% 持续 10 分钟（SLI S1，可用性）。

**诊断**：
1. `GET /readyz` —— 503 说明连不上数据库，先看连接池与 Postgres 自身。
2. 看面板 “5xx error rate” 与 “Request rate by plane”，确认是哪个面（protocol / business）在涨。
3. 看日志里带 `request_id` 的错误行；`status=500` 的 handler 会记真实错误。

**处置**：数据库连接问题 → 检查 `RE0AUTH_DATABASE_URL`、Postgres `max_connections`、连接池
`max_conns × 副本数`（见 [capacity-planning.md](./capacity-planning.md)）。若是代码路径 panic，
`/debug/pprof/` 与访问日志的 `trace_id` 能定位。

**升级**：持续 15 分钟未缓解 → 按 [incident-response.md](./incident-response.md) 升级。

---

## Re0AuthSlowRequests

**含义**：业务面 p99 > 1s 持续 10 分钟（SLI S4）。

**诊断**：
1. 面板 “p99 latency by plane” 与新增的 “Upstream fetch latency p95 (by source)”，先分清是本服务慢还是上游慢。
2. “DB pool connections” 面板：`acquired_conns` 顶到 `max_conns` 且 `empty_acquire_count_total` 在涨，
   说明在等连接。
3. 单个源变慢会体现为该源 `result="ok"` 的 p95 上升；这是 `Re0AuthUpstreamSlowSource` 的前兆。

**处置**：连接池打满 → 见 [capacity-planning.md](./capacity-planning.md)；上游慢 → 联系该源，或临时降级
该源（`status = "degraded"`，见 [upstream-protocol.md](./upstream-protocol.md)）。

---

## Re0AuthTokenEndpointErrorRate

**含义**：令牌端点错误比例 > 5% 持续 10 分钟（SLI S2）。

**诊断**：按 `error` 标签分组：
- `invalid_client`：客户端凭据问题（secret 轮换后未更新、Basic 与表单 `client_id` 不一致）。
- `invalid_grant`：code/refresh 重放或过期。批量出现要查时钟偏移。
- `invalid_scope`：注册的 scope 与请求不符。

**处置**：对照 `oauth_clients` 表与注册时的返回；`invalid_grant` 批量出现且与
`Re0AuthRefreshRejections` 同时 → 见后者。

---

## Re0AuthLoginFailureRate

**含义**：登录失败比例 > 30% 持续 15 分钟（SLI S3）。

**诊断**：按 `provider` 分组。
- 单 provider 失败 → 该 IdP 的 discovery/换票挂了（`provider_unavailable`、`exchange_failed`）。
- 全部 provider 失败 → 本服务问题（会话存储、`redirect_uri` 配置、`issuer` 错）。

**处置**：确认对应 IdP 状态；检查本服务 `issuer` 与各 provider 回调地址是否与部署一致。

---

## Re0AuthAuditChainBroken

**含义**：审计链校验失败（SLI S5，**硬目标恒为 0**）。这是事件，不是趋势。

**诊断**：
1. `GET /v1/admin/audit/verify` —— 返回 `first_bad_id` 指向第一处不一致的行。
2. 确认是不是有人直接改了 `audit_events` 表，或 `RE0AUTH_AUDIT_KEY` 被换过。

**处置**：**按篡改处理，除非能证明是损坏**。保留现场（不要 `DELETE` 任何审计行），记录
`first_bad_id` 与时间窗；并比对日志里最新的链头锚点（步骤见
[operations.md](./operations.md#审计链锚点核对)），确认是不是尾部也被截断。见 [admin.md](./admin.md) §5。

**升级**：立即升级为安全事件，见 [incident-response.md](./incident-response.md)；考虑一键撤销。

---

## Re0AuthVaultOperationFailures

**含义**：凭据库非 ok 操作比例 > 1% 持续 10 分钟（SLI S6）。

**诊断**：按 `result` 分组：
- `unconfigured_key`：轮换没收尾——某个 retired KEK 被过早移除。看启动日志的 retired KEK 警告。
- `decrypt_error`：密文打不开——数据损坏或 KEK 不对。

**处置**：`unconfigured_key` → 把缺失的 retired KEK 加回配置，重跑 `-rotate-keys`，确认
`Rewrapped == 0` 后再移除。`decrypt_error` → 从数据库备份恢复，见 [operations.md](./operations.md)。

---

## Re0AuthUpstreamSourceUnavailable

**含义**：某数据源 `unavailable` 比例 > 30% 持续 10 分钟（SLI S7）。`not_bound` 不算。

**诊断**：面板 “Upstream fetch results (by source)”，确认该源自身是否可达。

**处置**：这是**该数据源的故障，不是 Re0Auth 的**；其它源与整体可用性不受影响。可联系源方；
需要时临时把该源标为 `degraded` 让流量走备用源。

---

## Re0AuthRefreshRejections

**含义**：`rate(upstream_refreshes_total{result="rejected"}[15m]) > 0`。

**诊断**：上游 refresh token 被提前作废，用户在被动重新绑定。

**处置**：查该源是否提前轮换/撤销了 token；查服务器时钟是否有偏移导致绑定过早到期。
必要时通知用户重新绑定。

---

## Re0AuthKillSwitchFired

**含义**：有人拉了一键撤销。**不是故障，是通知**。

**处置**：确认这是一次预期的事故响应；与审计里 `admin.kill_switch` 那行对照。若无人认领，
按安全事件处理。

---

## Re0AuthUpstreamSlowSource

**含义**：某源的成功读取 p95 > 2s 持续 15 分钟。补足 S7 的**延迟维度**——能答但很慢的源对
“unavailable 比例”告警是不可见的。

**诊断**：面板 “Upstream fetch latency p95 (by source)”；区分是网络还是源本身慢。

**处置**：同 `Re0AuthSlowRequests` 的上游分支。若长期慢，考虑降级该源。

---

## Re0AuthGoroutineLeak

**含义**：`go_goroutines` 长期高于阈值（默认 5000，按部署调整）。指标本身没有 `re0auth_` 前缀，
阈值应贴合本部署的并发规模。

**诊断**：`/debug/pprof/goroutine?debug=2` 抓当前栈，看是否有同一处堆积（常见于未取消的
context、未关闭的 response body）。

**处置**：定位并修复泄漏路径；紧急时可滚动重启释放。

---

## Re0AuthMemoryHigh

**含义**：`process_resident_memory_bytes` 长期高于阈值（默认 400MiB，应贴合 k8s 内存 limit，
默认 limit 512Mi）。

**诊断**：`/debug/pprof/heap` 看大头；结合 “DB pool connections” 判断是否连接积压。

**处置**：若接近 limit 会被 OOMKill → 先提高 limit 或扩容副本，再查根因（如无界 map、日志缓冲）。

---

## Re0AuthFileDescriptorsHigh

**含义**：`process_open_fds / process_max_fds > 0.8` 持续 15 分钟。

**诊断**：文件描述符多为 socket（上游连接、数据库连接、HTTP 连接）。看是否有连接泄漏
（未关闭的 body、未释放的连接）。

**处置**：确认上游/数据库连接在正常释放；必要时提高容器 `ulimit`，但先找泄漏。

---

## Re0AuthErrorBudgetFastBurn

**含义**：S1 错误预算以 **14.4×** 的速率消耗（1 小时长窗 + 5 分钟短窗同时越界），持续 2 分钟。
这是“照这个速度，30 天预算几天就烧完”的快速燃尽告警。

**处置**：等同一次**可用性事件**——立即按 `Re0AuthHighErrorRate` 的流程处置，并升级。
见 [incident-response.md](./incident-response.md)。

---

## Re0AuthErrorBudgetSlowBurn

**含义**：S1 错误预算以 **6×** 速率消耗（6 小时长窗 + 30 分钟短窗同时越界），持续 15 分钟。
比快燃尽温和，通常是工单而非叫醒。

**处置**：安排排查，确认不是持续的小比例 5xx（例如某个依赖间歇性失败）。
