# 容量规划

> 备份/保留/KMS 的取舍见 [operations-decision.md](./operations-decision.md)（ADR-0006），
> 观测与告警见 [slo.md](./slo.md)。本文把散落在代码与部署清单里的数字接起来，回答
> “一个副本能扛多少、要开几个、Postgres 连接够不够”。

## 输入（都在仓库里）

| 量 | 出处 | 默认 |
|---|---|---|
| 单请求成本 | `internal/httpapi/bench_test.go`（`make bench`） | 需在目标机器上现测 |
| 连接池上限 | `postgres.PoolOptions.MaxConns` | `16` / 进程 |
| 连接池下限 | `PoolOptions.MinConns` | `2` |
| 语句超时 | `PoolOptions.StatementTimeout` | `30s` |
| 副本数 | `deploy/k8s/base/deployment.yaml` `replicas` | `2` |
| CPU / 内存 | 同上 `resources` | request `100m`/`128Mi`，limit `1`/`512Mi` |
| 滚动发布峰值 | `maxSurge: 1` / `maxUnavailable: 0` | 短暂 **3** 个实例 |
| 出站并发 | `cmd/re0auth` `federationMaxConcurrent` | `256` |
| 入站并发 | `server.max_in_flight` | `512` |

## 1. 单请求成本

```sh
make bench     # go test -run '^$' -bench . -benchmem ./...
```

三个基准对应三条热路径：`BenchmarkBusinessPlaneBearerMe`（不透明 bearer → introspection → `/v1/me`，
业务面）、`BenchmarkProtocolIntrospect`、`BenchmarkProtocolDiscovery`。

**注意基准跑在内存存储上**（`Makefile` 顶部已注明）：真实 Postgres 部署会在每次请求里多加
若干次数据库往返。所以把基准当作**单副本吞吐的上界**，真实值用面板里的 rate 与 CPU 利用率反推：
`每副本 QPS ≈ 观察到的 QPS / 副本数`，再与 limit 的 CPU 对照决定何时加副本。

## 2. Postgres 连接预算

`pgxpool` 的并发上限是**每进程**的（`postgres.go` 的 `PoolOptions` 注释与
`config/re0auth.example.toml` 都对此有说明），所以有效连接数是：

```
最大连接数 = max_conns × 副本数
滚动发布峰值 = max_conns × (副本数 + maxSurge)
```

默认 `16 × 2 = 32`，滚动期间短暂 `16 × 3 = 48`。这必须留在 Postgres 的
`max_connections` 之下，并留出余量给：迁移用的**那一条独立连接**（`Migrate`）、
以及一个拿着 `psql` 的人。经验规则：`max_connections ≥ 峰值 + 5`。

反过来说，调大 `max_conns` 不会让数据库更快——池太大不会响亮地失败，只会让数据库拒绝
**真正需要连接的东西**（包括它自己）。

## 3. 内存

k8s 默认 limit `512Mi`，`Re0AuthMemoryHigh` 告警阈值取 `400MiB`（比 limit 略低，先于 OOMKill 报警）。
Go 堆之外的主要占用来自连接缓冲与并发请求的响应体；数据面单个响应体有 `maxBody = 4 MiB` 的上限
（`internal/federation`），所以“在途请求数 × 平均响应体”是堆压力的主项。

## 4. 并发上限

两个上限作用在不同层，别混淆：

- `server.max_in_flight`（默认 512）：**入站准入**，超过即 503。它环在限流器之外，
  限的是“同时在处理的工作量”，不是到达速率。
- `federationMaxConcurrent`（默认 256）：**出站 bulkhead**，限制数据面对某个上游的在途请求数；
  一个请求可以在占用一个入站名额的同时等待一个出站名额。

一次数据面读的链路是：入站名额 → （可能需要一个连接池连接）→ 出站名额 → 上游。
因此 **`max_in_flight` 应 ≥ 连接池总量**，否则请求会先在池上排队而不是在准入上被挡住。

## 5. 算例（默认配置）

- 2 副本、`max_conns=16` → Postgres 侧 `32` 个连接，滚动峰值 `48`。
- 若 Postgres `max_connections=100`：`48 + 5 = 53 ≤ 100`，宽裕；可继续加副本到约 5 个（`16×6=96` + 余量已紧）。
- 若要把副本加到 5 个以上：要么调小 `max_conns`（如 8），要么上 PgBouncer 之类的连接池前置。

## 6. 何时扩容

按 `slo.md` 的信号判断，而不是凭感觉：

- CPU 长期贴着 limit（dashboard 看 Go/process 指标）→ 加副本。
- `re0auth_db_pool_empty_acquire_count_total` 上升 → 池在饱和，先看是不是慢查询，再考虑调池或加副本。
- `Re0AuthHighErrorRate` / `Re0AuthErrorBudgetSlowBurn` 且 `/readyz` 抖动 → 连接不够，按 §2 重算。

> 阈值（告警里的具体数字）是起点不是法律；换一套部署规格时，先按 §5 重算一遍再改。
