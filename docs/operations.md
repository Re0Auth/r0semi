# 运维手册

> 决策与理由见 [operations-decision.md](./operations-decision.md)（ADR-0006）。
> 事故整体流程见 [incident-response.md](./incident-response.md)，逐条告警处置见 [runbooks.md](./runbooks.md)，
> 容量与连接预算见 [capacity-planning.md](./capacity-planning.md)。这里只有可执行的步骤。

## 部署

`deploy/k8s/base` 是 kustomize 基线：Namespace、Deployment（2 副本、探针、资源上限、
非 root + 只读根文件系统）、Service（公网 80 / 内部 9090 分离）、PDB、NetworkPolicy、
Ingress、ConfigMap。先应用它，再按环境覆盖：

```sh
kustomize build deploy/k8s/base | kubectl apply -f -
kubectl -n re0auth create secret generic re0auth-secrets \
  --from-literal=database-url="$DATABASE_URL" \
  --from-literal=kek="$RE0AUTH_KEK" \
  --from-literal=oidc-token-key="$RE0AUTH_OIDC_TOKEN_KEY" \
  --from-literal=oidc-signing-key="$RE0AUTH_OIDC_SIGNING_KEY" \
  --from-literal=audit-key="$RE0AUTH_AUDIT_KEY"
# 把镜像钉到发布的 digest，而不是 latest：
kustomize edit set image ghcr.io/re0auth/r0semi=ghcr.io/re0auth/r0semi@sha256:...
```

镜像里没有配置和密钥；`issuer`、监听地址与密钥全部运行时注入。系统变更后：

```sh
kubectl -n re0auth rollout status deploy/re0auth
curl -fsS https://auth.example.com/healthz
curl -fsS https://auth.example.com/readyz
```

## 备份与恢复

数据库与密钥是**两份**备份，缺一不可：没有 KEK，转储里的每条 vault 记录都打不开。

```sh
# 1) 数据库
DATABASE_URL=... ./scripts/backup.sh /backups
# 2) 四把密钥（KEK / OIDC 签名 / OIDC 令牌 / 审计链）
RE0AUTH_KEK=... RE0AUTH_OIDC_TOKEN_KEY=... \
RE0AUTH_OIDC_SIGNING_KEY=... RE0AUTH_AUDIT_KEY=... \
BACKUP_AGE_RECIPIENT=age1... ./scripts/backup-keys.sh /backups
# 3) 恢复（数据库部分进空库）
DATABASE_URL=... BACKUP_AGE_IDENTITY=~/.age/keys.txt ./scripts/restore.sh /backups/re0auth-....dump.age
```

- 建议每 15 分钟一次逻辑备份或持续 WAL 归档；目标 RPO ≤ 15 分钟，RTO ≤ 1 小时。
- **恢复演练每季度一次**，并记录：恢复耗时、`/readyz` 结果、一次真实登录结果
  （模板见 [incident-response.md](./incident-response.md) §6）。
- 恢复只能进空库；`restore.sh` 会在目标已有表时拒绝执行。

### DR 密钥恢复（整站丢失）

四把密钥只在环境 / k8s Secret 里，**不在任何数据库备份里**——整站丢失时，光有数据库转储是不可恢复的。
`scripts/backup-keys.sh` 把 `RE0AUTH_KEK`、`RE0AUTH_OIDC_TOKEN_KEY`、`RE0AUTH_OIDC_SIGNING_KEY`、
`RE0AUTH_AUDIT_KEY`（以及轮换进行中的 retired 集合）写成 `0600` 的 `.env`，`BACKUP_AGE_RECIPIENT`
存在时用 age 加密，并附 sha256 校验。

- **密钥备份必须放在数据库备份够不到的地方**（另一个凭据域 / 账号），否则一次凭据泄露会同时拿走密文与钥匙。
- `vault.retired`（配置里的旧 KEK）不在环境变量里；轮换进行中要连同配置的 retired 段一起归档，
  否则仍被旧 key 包裹的记录会变得不可读。
- 丢失后果：KEK 丢失 → 上游凭据永久不可恢复；审计 key 丢失 → 链无法再校验；
  OP 两把 key 丢失 → 在途 `id_token` 全部失效、access token 不可读（等于全站登出）。

## 密钥轮换

- KEK：配置新 `kek_id`，把旧 key 放进 `vault.retired`，启动时 `-rotate-keys`，
  确认没有待重包记录后再移除旧 key。
- OP 签名密钥：新私钥签发，旧公钥留在 `RE0AUTH_OIDC_RETIRED_SIGNING_KEYS`，
  等最长 id_token 寿命过去后移除。
- OP 令牌加密密钥：新 key 加密，旧 key 留在 `RE0AUTH_OIDC_RETIRED_TOKEN_KEYS`，
  等最长 access token 寿命过去后移除。
- 审计 key：不可轮换而不重写历史；更换前先归档旧链与对应 key。

## 可观测与排障

- `/healthz` 存活、`/readyz` 依赖（Postgres ping）；两者纯文本、免限流，不属任何平面。
- `/metrics` 与 `/debug/pprof/` 在 `server.internal_addr` 的独立内部监听器上，绝不暴露公网。
- `/metrics` 导出**黄金指标**（按平面的请求/错误/时延/在途）与**业务与安全信号**（登录结果、
  令牌签发与错误、撤销、上游读取与刷新、vault 操作、审计链校验、设备流、运维动作）。
  **SLO 与告警规则**见 [slo.md](./slo.md) 与 `deploy/prometheus/re0auth.rules.yml`，
  面板见 `deploy/grafana/re0auth-dashboard.json`。接进 Prometheus 即可用，规则不绑定抓取约定。
- 访问日志含 `request_id`、`trace_id`、plane 与客户端地址；**不记录 query string**。
  请求携带的 `traceparent` 会被采纳，否则生成一个，便于跨日志关联。
- 限流：429 带 `Retry-After`，所有带限流的响应带 `RateLimit-Limit/Remaining/Reset`；
  并发打满时 503 带 `Retry-After: 1`。
- 常见现象：
  - `/readyz` 503 → Postgres 不可达或连接池耗尽；先看 `DATABASE_URL` 与数据库负载。
  - 大量 429 → 调整 `server.rate_limit` / `rate_limit_burst`，或检查是否有客户端刷接口。
  - 大量 503 → 调整 `server.max_in_flight`，或排查慢查询/上游拖慢。
  - 登录后无会话 → `cookie_secure` 与实际 scheme 不一致。

## 数据删除与保留

- 用户自助删除走 `DELETE /v1/account`（会话 + CSRF + 确认）：逐 store 清除绑定、vault、
  令牌、会话、OP 状态，审计行做主体假名化并销毁对应密钥。
- 审计记录默认无限期保留且不逐行删除；缩短保留期需要归档整段链并连带锚点删除。
- 运行日志与指标的保留周期由部署方的日志/指标系统决定，本服务不写第二份。

## 升级

1. 读 [CHANGELOG.md](../CHANGELOG.md)、release notes 与 `docs/*-decision.md` 中受影响的 ADR；
2. 在 staging 跑一次恢复演练到新版本；
3. 滚动更新（PDB 保证至少一个可用副本），观察 `/readyz`、错误率与 429/503；
4. 数据库迁移在启动时执行，多实例由 advisory lock 串行化；迁移前先做一次备份。
   迁移的兼容性规则与回滚策略见 [migration-decision.md](./migration-decision.md)（ADR-0008）：
   同一版本只做加法，破坏性变更延后一版；**回滚 = 从备份恢复**，`re0auth -migrate-down`
   只用于撤销最近一步。

## 容量

一个副本能扛多少、要开几个副本、Postgres 连接够不够，见 [capacity-planning.md](./capacity-planning.md)。
