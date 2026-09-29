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
- **镜像**：base 钉的是**最近一个真正发布过的 tag**（`v0.0.0-rc.3`，目前唯一带产物的预发布）。
  生产按上面的 `kustomize edit set image` 换成 digest。这个 pin 有守卫：`internal/archtest`
  会拿仓库里真实存在的 `v*` tag 比对，钉一个从未构建过的名字会直接失败——这条守卫存在的理由
  见 [CHANGELOG](../CHANGELOG.md) 的 rc.1 一节。

系统变更后：

```sh
kubectl -n re0auth rollout status deploy/re0auth
curl -fsS https://auth.example.com/healthz
curl -fsS https://auth.example.com/readyz
```

### 反向代理的要求（限流分桶键）

限流器按**客户端地址**分桶。那个地址来自对端，或来自一个**你的反代写下的**头——两者都不是
调用方能决定的事，而请求里没有任何东西能证明这一点。所以这两件必须由部署声明，缺一不可：

```toml
trusted_proxies    = ["10.0.0.0/8"]     # 谁有权替客户端说话
client_addr_header = "x-forwarded-for"  # 那个代理写的是哪个头
```

- 反代**必须覆盖或追加** XFF，二者都是正确的写法：

  ```nginx
  proxy_set_header X-Forwarded-For $remote_addr;                 # 覆盖
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;   # 追加
  ```

  **逐字转发调用方自带的 XFF（nginx 的默认行为）会让分桶键由调用方决定**，限流形同虚设。
  判据不是「追加还是覆盖」，而是「**追加的那一跳是否也在信任网内**」——第 3 条。
- `trusted_proxies` 只能写你自己的代理地址，**绝不能包含客户端可能位于的网络**。
  写 `0.0.0.0/0` / `::/0` 等于关闭这套判据（此时最右侧一跳必然落在信任网内，服务会退回对端地址，
  于是分桶键又回到调用方手里）——所以**这两个通配值现在被拒绝启动**，要使用必须显式承认
  `server.trusted_proxies_any = true`（`RE0AUTH_TRUSTED_PROXIES_ANY=true`），与 `expose_internal`
  同一形状。
- **`externalTrafficPolicy: Cluster` / 服务网格 / 内部 LB 会让「最右侧一跳」变成信任网内的地址**
  （节点 IP、网格边车），此时服务按上面的规则**退回对端地址**——也就是那一跳代理的地址。
  后果是**该代理后面的所有客户端共用一个桶**：这是安全方向的退化（可用性问题），不是越权。
  要恢复按客户端分桶，三选一：改用 `externalTrafficPolicy: Local`、上 PROXY protocol、
  或让最近一跳写入的地址不在 `trusted_proxies` 里。
- `client_addr_header` 只读**最右侧一条**，且要求 `trusted_proxies` 非空（否则拒绝启动）。
  两者都配好之后，「每客户端一个桶」才成立；只配 `trusted_proxies` 时，一个代理后面的所有
  客户端共用一个桶。

改动这两个值之前先做一次实测：从两个不同的外部地址各发一次请求，看访问日志里的 `client=`
是否分别是这两个地址。**如果两个地址写成同一个，说明声明与代理的实际行为不符**——
先修代理，再改配置。

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
- **转储 Pod 带自己的标签 `app.kubernetes.io/name: re0auth-backup`，并由同目录的
  `networkpolicy.yaml` 选中**（只放行到 Postgres 5432 与 DNS）。这条策略不是可选的：在一个
  default-deny 的集群上，没被任何策略选中的 Pod 根本到不了 Postgres，而**失败的 CronJob 不会
  惊动任何人**（不进服务指标、也没有"备份已停"的告警）——转储就这样静默停掉。若数据库不在
  `postgres` 命名空间（托管库按 IP 访问），改那条策略的选择器或补 `ipBlock`。
- 转储 Pod **不挂 ServiceAccount token**（`automountServiceAccountToken: false`）：它持有数据库
  DSN，一个没人读的 token 只是凭空多一把凭据。
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
  **重复到它报 `rewrapped=0 skipped=0` 且退出码为 0**，再移除旧 key。
  两条判据都不是「跑过一次」：
  - `skipped>0` 表示本轮有记录的行在读取期间被别的进程改了（新凭据入册 / 抹除），
    命令**非零退出**且审计记 `error`；重跑即可收敛。
  - `rewrapped=0` 还必须**在旧键进程全部下线之后**确认一次：游标走过之后写进来的凭据留在旧键上，
    轮换看不到它们，而 `replicas: 2` 的滚动更新让这件事成为常态。
  在这之前删键 ⇒ 落在旧键上的凭据**永久不可读**（不是报错，是解不开）。
- OP 签名密钥：新私钥签发，旧公钥留在 `RE0AUTH_OIDC_RETIRED_SIGNING_KEYS`，
  等最长 id_token 寿命过去后移除。
- OP 令牌加密密钥：新 key 加密，旧 key 留在 `RE0AUTH_OIDC_RETIRED_TOKEN_KEYS`，
  等最长 access token 寿命过去后移除。
- 审计 key：不可轮换而不重写历史；更换前先归档旧链与对应 key。

## 可观测与排障

- `/healthz` 存活、`/readyz` 依赖（Postgres ping）；两者纯文本、免限流，不属任何平面。
  **裁定（取舍写在这里）：探针永远不因为「忙」而失败，代价是它必须便宜。**
  两条一起才成立：
  - 免限流**也免并发上限**（`isProbe` 在两者之前判断）。理由是反的写法会自伤：把桶打满的那股流量
    会让**存活**探针被 429，于是编排系统重启一个本来没问题的进程；也会让**就绪**探针被 429，
    于是把一个还能服务的实例摘出轮转。
  - 因此免掉的那部分工作**必须廉价**：`/healthz` 什么都不查；`/readyz` 用
    **`httpapi.readinessTTL`（1s）内的一次检查结果**作答，同一时刻最多只跑一个检查，其余请求
    直接拿到上一次的结果——**不排队、不因为负载回 503**。没有这一条时，每个匿名请求就是一次
    占用连接池的数据库往返，「报告连接池状态的端点」反而成了打满它的手段。
    - 探针路径**跳过会话中间件**：`isProbe` 的豁免必须同样跳过 `sessions.LoadAndSave`，
      否则任意匿名 Cookie 就让每一次 `/healthz`、`/readyz` 都变成一次会话存储往返
      （有效 Cookie 还会因 `IdleTimeout` 触发写），而这条路径既无限流也无并发上限。
      准确口径是：**就绪检查每副本每秒最多一次数据库往返；探针请求本身不触碰会话存储。**
    - 就绪结论是**显式三态**（未知 / 就绪 / 不就绪）。未知（进程启动后首个检查尚未返回）一律
      **fail-closed**：503 `checking`，绝不回答未经验证的 200。检查跑在**不派生自调用方
      context** 的 `context.WithoutCancel` + `readinessTimeout` 上——缓存是全进程的，某个匿名
      连接挂断从来不是依赖的结论，取消类错误不写缓存、也不顶掉已有结论。首个检查仍在途中时，
      抢跑的请求最多等 `httpapi.readinessColdStartWait`（500ms）取那个结论，否则回 503；
      一旦已有结论，刷新期间一律回答上一次的结论，不排队。
  代价说清楚：就绪结论最多**旧 1 秒**（依赖掉了之后可能多报一秒 ready）。出厂 manifest 的
  `readinessProbe.periodSeconds` 是 5，`failureThreshold` 是 3，所以真实 kubelet 看到的每一次
  都仍是刚查过的；而它换来的是每个副本**每秒最多一次**数据库往返，而不是按请求数增长。
- `/metrics` 与 `/debug/pprof/` 在 `server.internal_addr` 的独立内部监听器上，绝不暴露公网。
  绑一个**非 loopback** 地址需要显式承认：`server.expose_internal = true`（或
  `RE0AUTH_INTERNAL_EXPOSE=true`），否则拒绝启动。这条不是形式——`/debug/pprof/` 会导出堆、
  goroutine dump 与 CPU profile，而原来的检查只有"不等于 `server.addr`"。k8s 基线里它是开着的
  （容器必须绑 `0.0.0.0` 才可能被 Service 选中），安全性来自同目录的 NetworkPolicy：
  只有 `monitoring` 命名空间能到 9090。**在别的编排系统上，请自己提供那个网络控制**，
  或者直接绑 loopback。
  - **前提（必须自己确认，仓库查不到）**：那条 NetworkPolicy **只有在 CNI 真的实现它时才生效**。
    有些 CNI（老版 flannel 等）会让 `kubectl apply` 成功而策略被静默忽略，此时任何集群内 Pod 都能
    读 9090（`/debug/pprof/heap` 含会话/在途凭据）。所以 `expose_internal = true` 的正当性押在
    「CNI 实现了 NetworkPolicy」这一条上，请自行验收：
    ```sh
    # 从一个不在 monitoring 命名空间的 Pod 里，这一步必须失败（超时/拒绝）
    kubectl -n default run probe --rm -it --image=curlimages/curl -- \
      curl -m2 -fsS http://re0auth-internal.re0auth.svc:9090/metrics
    ```
    若它能成功返回指标，说明策略没有被执行：请换一个支持 NetworkPolicy 的 CNI，或把
    `internal_addr` 绑回 loopback（用 sidecar / `kubectl port-forward` 抓取）。
- `/metrics` 导出**黄金指标**（按平面的请求/错误/时延/在途）与**业务与安全信号**（登录结果、
  令牌签发与错误、撤销、上游读取与刷新、vault 操作、审计链校验、设备流、运维动作）。
  **SLO 与告警规则**见 [slo.md](./slo.md) 与 `deploy/prometheus/re0auth.rules.yml`，
  面板见 `deploy/grafana/re0auth-dashboard.json`。接进 Prometheus 即可用，规则不绑定抓取约定。
- 访问日志含 `request_id`、`trace_id`、plane 与客户端地址；**不记录 query string**。
  请求携带的 `traceparent` 会被采纳，否则生成一个，便于跨日志关联。
- 限流：429 带 `Retry-After`，所有带限流的响应带 `RateLimit-Limit/Remaining/Reset`；
  并发打满时 503 带 `Retry-After: 1`。桶键是（平面, 客户端地址），**IPv6 地址归并到 /64**；
  `max_in_flight` 另按（平面, 客户端）分摊**份额**（上限的一半），单个地址占不满全部槽位。
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
- **链自己会被定期走一遍，不再等谁来点**：服务在启动时、以及之后每 6 小时，用**同一个**校验路径
  走一遍整条链，结果计入 `re0auth_audit_verify_total{result="ok|failed|error"}`。
  没有这一步时，S5（"`failed` 恒为 0"）只在有人手工调 `/v1/admin/audit/verify` 的那一刻才有意义——
  一个没人跑的控制不是控制。现在 `Re0AuthAuditChainBroken` 与 `Re0AuthAuditVerifyError` 会自己响，
  两条告警的处置步骤不变。
  间隔是小时级而不是分钟级，因为它是全表遍历：**把间隔调短不是"更安全"，只是更多次相同的读**；
  扫不完时的正解是增量校验点（上一条），不是更频繁的重扫。
  锚点循环（上面的链接头）仍然单独存在：它抓的是**尾部截断**，校验抓的是**剩下的链是否自洽**，
  两者互相补不上对方的盲区。

#### 手工触发一次

链有问题时，运维会想立刻再看一遍，而不是等下一个 6 小时：

```sh
# 走的是同一条校验路径，因此结果同样计入 audit_verify_total
curl -fsS -H "Cookie: ..." https://auth.example.com/v1/admin/audit/verify
```

它需要管理员会话（读日志等于读每个账号的活动），所以**不能**从 cron 调；这也正是把定期校验做进
服务内部而不是做成外部作业的原因。

## 数据删除与保留

- 用户自助删除走 `DELETE /v1/account`（会话 + CSRF + 确认）：逐 store 清除绑定、vault、
  令牌、会话、OP 状态，审计行做主体假名化并销毁对应密钥。
- 审计记录默认无限期保留且不逐行删除；缩短保留期需要归档整段链并连带锚点删除。
- 运行日志与指标的保留周期由部署方的日志/指标系统决定，本服务不写第二份。

## 升级

1. 读 [CHANGELOG.md](../CHANGELOG.md)、release notes 与 `docs/*-decision.md` 中受影响的 ADR；
2. 在 staging 跑一次恢复演练到新版本；
3. 滚动更新（PDB 保证至少一个可用副本），观察 `/readyz`、错误率与 429/503；
   **关停顺序**：收到 SIGTERM 后，进程先把 `/readyz` 翻成 503，等 **`endpointRemovalWait`（5s）**
   让编排系统把本实例摘出轮转，再开始 **`shutdownTimeout`（30s）** 的排空，最后才排空审计批次队列
   （**`auditDrainTimeout`（10s）**）。三段是**串行**的（审计排空在 HTTP 排空之后，不是并行），
   合计 5 + 30 + 10 = 45s，所以 `terminationGracePeriodSeconds` 必须 ≥ 45s（出厂 45s）——小于
   这个总数，审计排空的「过期拒绝」路径会在 SIGKILL 之前跑不完，在途审计行静默丢失。这四处的
   量级由 `TestGracefulShutdownWindowsAgree` 交叉校验。等待放在**进程内**而非 `preStop`：scratch
   镜像没有 `/bin/sleep` 可跑。
4. 数据库迁移在启动时执行，多实例由 advisory lock 串行化；迁移前先做一次备份。
   迁移的兼容性规则与回滚策略见 [migration-decision.md](./migration-decision.md)（ADR-0008）：
   同一版本只做加法，破坏性变更延后一版；**回滚 = 从备份恢复**，`re0auth -migrate-down`
   只用于撤销最近一步。

## 容量

一个副本能扛多少、要开几个副本、Postgres 连接够不够，见 [capacity-planning.md](./capacity-planning.md)。
