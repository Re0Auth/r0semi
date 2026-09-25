# 事故响应手册

> 每条告警的逐条处置见 [runbooks.md](./runbooks.md)；SLI/SLO 见 [slo.md](./slo.md)；
> 操作员面契约见 [admin.md](./admin.md)；威胁模型见 [threat-model.md](./threat-model.md)。
> 本文只讲整体流程：分级、升级、拉闸、沟通、复盘、演练。

## 1. 严重度阶梯

严重度沿用告警自带的 `severity`（规则文件 `deploy/prometheus/re0auth.rules.yml`）：

| 级别 | 触发 | 含义 | 期望响应 |
|---|---|---|---|
| **critical** | `Re0AuthHighErrorRate`、`Re0AuthErrorBudgetFastBurn`、`Re0AuthAuditChainBroken`、`Re0AuthVaultOperationFailures` | 可用性受损，或审计完整性/凭据可用性出问题 | 立即叫人，按事故处理 |
| **warning** | `Re0AuthErrorBudgetSlowBurn`、`Re0AuthSlowRequests`、`Re0AuthUpstreamSlowSource`、`Re0AuthTokenEndpointErrorRate`、`Re0AuthLoginFailureRate`、`Re0AuthUpstreamSourceUnavailable`、`Re0AuthRefreshRejections`、`Re0AuthGoroutineLeak`、`Re0AuthMemoryHigh`、`Re0AuthFileDescriptorsHigh` | 趋势或单点劣化，尚未击穿目标 | 工作时间内开单排查 |
| **info** | `Re0AuthKillSwitchFired` | 有人拉了闸 | **不是故障**，是通知：确认这是一次预期的事故响应 |

判断口径：**打穿 SLO 目标或触及硬目标（S5 审计链恒为 0）= critical**，其余按级别走。

## 2. 升级路径

- 操作员面 `/v1/admin/*` 只对 `[admin].allow` 允许列表里的 `usr_…` 开放；变更类接口还要求
  在 `[admin].reauth_window`（默认 15 分钟）内重新登录过。**谁能操作是一个配置事实**——
  事故前先确认至少有两个人在允许列表里，且能登录。
- 升级顺序：值班 → 服务负责人 → 安全负责人（涉及凭据/审计时）。
- 跨团队（数据源方）的联系方式应写进部署方的运维手册；本仓库只提供“通知各数据源”这一步。

## 3. 拉闸：Kill Switch

语义与目标（`all` / `client` / `subject` / `bindings`）见 [admin.md](./admin.md) §4.2。要点：

- `POST /v1/admin/kill_switch`，body 指定**恰好一个** `target`。
- 响应返回**实际切断的数量**，不是一个空洞的 204——事故里要的正是这个数字。
- `all`/`subject` 只有在**持久会话存储**下才能清会话；内存模式清不了，启动时已大字警告。
- `bindings` 是窄形态：只断数据访问，大家的登录不受影响。
- 能力边界见 [threat-model.md](./threat-model.md) D5：**Re0Auth 自己够不到上游凭据**，
  它只能请数据源去作废；够不到的上游会在报告里计为 `unsupported`/`unavailable` 而不是算作成功。

## 4. 凭据泄露分支

[threat-model.md](./threat-model.md) §9 给出的顺序：

1. **拉闸**（Kill Switch）——先切断再调查，不要反过来。
2. **通知各数据源**——按 §3 的边界，能请人作废的就请。
3. **轮换受影响密钥**——KEK / OP 签名 / OP 令牌 / 审计 key 的步骤见
   [operations.md](./operations.md) §密钥轮换；审计 key 不可轮换而不归档旧链。
4. **复盘**（§6），并把“哪一步是这次没做好的”写进待办。

## 5. 沟通与合规

- 对用户的通报渠道与话术由部署方决定；本仓库只保证有可核对的**事实来源**：
  审计读 API（`GET /v1/admin/audit`、`GET /v1/admin/audit/verify`、`GET /v1/admin/audit/head`）。
- 合规义务见 [threat-model.md](./threat-model.md) §9（PIPL / GDPR 等的泄露通报时限）；
  触发条件与时限由部署方的法务确认，代码侧不代替判断。
- 对外只说已核实的事实；不确定的状态标为“调查中”，不要给未经验证的时间承诺。

## 6. 复盘与演练

**事后复盘（blameless）**，记录：

- 时间线：detect → 拉闸 → 缓解 → 恢复，各步骤的 UTC 时间与操作者。
- 影响面：受影响的 SLI、错误预算消耗（见 [slo.md](./slo.md) §1.1）、被切断的对象数量。
- 证据：相关 `request_id`/`trace_id`、审计条目、告警截图。
- 根因与**行动项**（谁、做什么、什么时候）。

**季度恢复演练记录模板**（[operations.md](./operations.md) §备份与恢复 承诺要记录）：

| 字段 | 值 |
|---|---|
| 日期 / 执行人 | |
| 备份文件与校验 | |
| 恢复到空库的耗时 | |
| `/readyz` 结果 | |
| 一次真实登录结果 | |
| 异常与改进 | |
