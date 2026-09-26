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

镜像里没有配置和密钥；`issuer`、监听地址与密钥全部运行时注入。

base 里有两件 **cluster 侧的前置**，它不替你做，因为它们都是"应用基线之后才会暴露"的问题：

- **TLS**：Ingress 用 `re0auth-tls` 这个 secret 终止 TLS，而 base **不创建**它——否则等于把
  cert-manager 变成基线的硬依赖。装了 cert-manager 就用 `ingress.yaml` 里注释掉的那个
  `Certificate`；用别的签发方式，就自己签发并创建同名 secret。
- **镜像**：base 钉的是最近一个已发布 tag（目前只有 `v0.0.0-rc.1`）。生产按上面的
  `kustomize edit set image` 换成 digest。

系统变更后：

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

#### 集群内的定时备份（可选）

`deploy/k8s/backup/` 是一个**独立**的 kustomize 目录，故意不进 base：没有卷、没有数据库的部署
不该每 15 分钟失败一次。

```sh
# 基础部署起来、re0auth-secrets 里有 database-url 之后
kubectl apply -k deploy/k8s/backup
```

- 每 15 分钟一次 `pg_dump -Fc`（对应上面的 RPO 目标）；`concurrencyPolicy: Forbid` 保证一次慢
  转储不会与下一次重叠——重叠的两个 `pg_dump` 会去抢服务正在用的连接预算。保留 7 天
  （`BACKUP_RETAIN_DAYS`），过期删除在同一作业里做。
- **这个卷不是异地。** 它和数据库在同一个集群、同一个凭据域。要满足"密钥/备份放在数据库够不到的
  地方"，还需要把卷里的内容复制到对象存储或另一个账号，或用一个已经复制的 StorageClass——
  **复制目标是部署决策**，仓库不替你选。
- 转储**没有加密**（age 只在 `scripts/backup.sh` 的本地流程里）。落到共享存储时，用支持 SSE 的
  对象存储，或在复制那一步加密。
- 数据库大到一次转储超过 15 分钟时：放宽 `schedule`，不要把 `Forbid` 改成 `Allow`——那正是它
  拖垮服务的方式。要更小的 RPO 请走 WAL 归档 / PITR，逻辑转储不是那条路 (it is a full read of
  every table)。

### DR 密钥恢复（整站丢失）

四把密钥只在环境 / k8s Secret 里，**不在任何数据库备份里**——整站丢失时，光有数据库转储是不可恢复的。
`scripts/backup-keys.sh` 把 `RE0AUTH_KEK`、`RE0AUTH_OIDC_TOKEN_KEY`、`RE0AUTH_OIDC_SIGNING_KEY`、
`RE0AUTH_AUDIT_KEY`（以及轮换进行中的 retired 集合）写成 `0600` 的 `.env`，`BACKUP_AGE_RECIPIENT`
存在时用 age 加密，并附 sha256 校验。

除这四把之外，**配置里声明的机密变量也一并归档**，且它们是必须的：`vault.kek_env`（可以改名，
脚本通过 `re0auth -print-secret-env` 读出来，而不是假定叫 `RE0AUTH_KEK`）、
`vault.retired[].kek_env`、`idp.*.client_secret_env`、`sources[].client_secret_env`。
因此脚本需要两样东西：可读的配置文件（`RE0AUTH_CONFIG`，默认 `config/re0auth.toml`）与可执行的
二进制（`RE0AUTH_BIN`，默认 `./re0auth`）。

- **声明了就必须能归档**：任何一个声明的变量缺失、或拿不到二进制去枚举它们，脚本都会**中止并删掉
  半个文件**——宁可没有备份，也不要一个看起来完整的备份。没有配置文件时脚本按旧的四个名字工作。
- **密钥备份必须放在数据库备份够不到的地方**（另一个凭据域 / 账号），否则一次凭据泄露会同时拿走密文与钥匙。
- `vault.retired`（配置里的旧 KEK）现在由脚本自动覆盖（上面那条）；若你的配置把它声明在别处
  （非 `*_env` 形式），仍需手工归档。
- 丢失后果：KEK 丢失 → 上游凭据永久不可恢复；审计 key 丢失 → 链无法再校验；
  OP 两把 key 丢失 → 在途 `id_token` 全部失效、access token 不可读（等于全站登出）；
  IdP / 数据源 client secret 丢失 → 需在各提供方重新签发并更新配置。

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
  - 会话/授权码**提前**失效（不到 TTL 就没了）→ 查时钟偏移。过期判定用的是**写入方自己的时钟**
    （`internal/store/postgres` 的时钟策略：Go 写的时间戳由 Go 时钟判，数据库 `DEFAULT now()` 写的
    才由数据库判），所以这里剩下的偏移只可能来自**副本之间**——用 NTP 把副本与数据库拉齐。
    另外 `curl -i` 看 `Date` 响应头也能快速判断本机与副本的时差。

## 审计链锚点核对

链能自己挡住改行、中间删行与伪造签名，但**挡不住从尾部删行**：剩下的每一环仍然成立。
能看见它的唯一办法，是拿一个**记在库外**的链头去比对。所以服务每小时（以及每次启动）
把链头写进日志：

```
INFO audit chain head anchored head=3f9c…    # 链还没有写入过时是 head=genesis
```

例行或事故复盘时的核对：

```sh
# 1) 从日志里取最新的一条锚点，记下 head=<hex>（只看到 genesis 说明链还没写过）
# 2) 在库里找那一行——找不到，就是它之后的行被删过
psql "$DATABASE_URL" -c "SELECT count(*) FROM audit_events WHERE row_hash = '\x<hex>'"
```

- **为什么必须问库**：读 API（`GET /v1/admin/audit`）与 `verify` 都**不回**每行的 `row_hash`，
  所以「那一行还在不在」只能问表本身；而运维本来就拿得到库（备份/恢复、抹除都走这条路）。
- **反向的迹象同样要读**：当前链头**等于**某条更早的锚点、而更晚的锚点不存在，说明链被退回到了那一刻。
- 锚点行只在**持久化部署**里存在：内存模式的审计是环形缓冲，没有链，也没有 `Head()`。
- 日志系统要放在**够不到数据库的那个凭据域**，否则一次凭据泄露就能同时改表与改锚点——
  与 `scripts/backup-keys.sh` 对密钥备份的取舍相同。
- **校验本身有超时，而且是单独放宽的**：`GET /v1/admin/audit/verify` 是全表遍历，它在一个事务里把
  `statement_timeout` 临时抬到 45s（连接池默认是 30s，按请求量级设的），事务结束自动复原。
  它仍然有界，且必须小于 HTTP 的 60s 写超时——所以**校验失败先分清是"链有问题"还是"遍历没跑完"**：
  后者记的是 `result="error"`，由 `Re0AuthAuditVerifyError` 告警（见 [runbooks.md](./runbooks.md)）。
  真到了 45s 也扫不完的规模，那是要上增量校验点，而不是继续抬超时。

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
