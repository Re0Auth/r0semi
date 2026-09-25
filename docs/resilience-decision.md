# ADR-0009：出站韧性——重试、熔断与 bulkhead 交给 failsafe-go

> 状态：**已接受**。
> 背景：`httpclient` 的重试循环、熔断三态机与出站信号量此前都是手写，`cenkalti/backoff/v4`
> 只承担退避曲线本身。[dependencies.md](./dependencies.md) §3 曾留下过一句
> "若将来重试逻辑变复杂，可换成 `go-retryablehttp`"。**那个条件后来满足了，但答案不是它**——
> 真正变复杂的是围绕重试的三件事，而 retryablehttp 只覆盖其中一件。本文记录这次选型、
> 被否的方案、以及三处有意接受的语义变化。落地的提交是 `refactor(httpclient)!`（`8c3672f`，
> 9 文件，+183/−191）。
> 相关：[dependencies.md](./dependencies.md) §1/§3、[architecture.md](./architecture.md)、
> [threat-model.md](./threat-model.md)。

## 决策

1. **出站韧性三件套统一由 `github.com/failsafe-go/failsafe-go` 承担**：重试（`retrypolicy`）、
   按上游 host 的熔断器（`circuitbreaker`）、出站并发上限（`bulkhead`）。
   `cenkalti/backoff/v4` 随之移除。

2. **策略留在本仓库，机制交给库。** 这条边界是本次决策的核心，不是实现细节：

   | | 内容 | 归谁 |
   |---|---|---|
   | 机制 | 重试的 attempt 循环、退避调度与等待、熔断的三态机 / 冷却 / 半开探测 / 成功失败计数、bulkhead 的许可计数 | 库 |
   | 策略 | 幂等方法白名单（POST 不隐式重放）、429/502/503/504 可重试而 **500 不可**、`Retry-After`（秒或 HTTP-date，上限 30s）、失败分类（4xx 与调用方取消都不算上游不健康） | `httpclient` |

   判据是"这条规则换一个部署还成立吗"。换成任何一家 HTTP 客户端，前两列的机制都不该重写；
   后两列是本服务对上游的承诺，换库时应该原样搬过去。

3. **bulkhead 用库的手动许可 API（`AcquirePermit` / `ReleasePermit`），不走策略。**
   策略的作用域是"被执行的函数"，而这里的临界区必须活过 `RoundTrip`、覆盖整段响应体传输：
   `RoundTrip` 在状态行到达时就返回，若许可在那时释放，读多兆字节 body 的调用方就跑在并发上限之外——
   而那种负载正是上限存在的理由。这条不变量由 `TestBulkheadHoldsSlotUntilBodyClosed` 钉住。

4. **`ErrCircuitOpen` 语义保持不变。** 库的 `circuitbreaker.ErrOpen` 在 `RoundTrip` 里被翻译成本包哨兵，
   于是 `internal/federation` 的两处 `errors.Is(err, httpclient.ErrCircuitOpen)` 无需改动。

5. **明确不做**：不引入 `failsafehttp.NewRoundTripper`，也不引入 hedge / timeout / cachepolicy /
   adaptivelimiter / ratelimiter。理由见下一节。

## 背景（实证）

手写版本不是"写得不好"，而是**状态空间只能被认为闭合，不能被证明闭合**：

- `httpclient/circuitbreaker.go`（改动前）用 `phase` + `failures` + `successes` + `openedAt` +
  `trialInUse` 五个字段表达状态，其中 `record()` 的 `breakerOpen` 分支上留着一句自供：
  `// Unreachable through admit; kept coherent anyway.`——一个需要靠注释说明"这里其实到不了"的分支，
  正是"分支数已经超过能靠读代码检验"的信号。
- `httpclient/retry.go`（改动前）自己维护 attempt 循环、`Retry-After` 解析、body 重放与连接 drain，
  其中"slot 何时归还"是手写的不变量，漏一条路径就是永久泄漏一个许可。
- `httpclient/outbound.go`（改动前）用带缓冲 channel 做计数信号量，两处（入站 `httpapi`、出站）
  各写了一遍。

同时，依赖图里已经躺着一个未用的同类库（`sethvargo/go-retry`，经 `zitadel/oidc` 传递进来），
说明"手写"在这里不是唯一选项，只是当时没被重新审视。

## 为什么是它，而不是别的

| 方案 | 结论 |
|---|---|
| **维持手写** | 不再可辩护。三件机制的维护成本已经体现在上面那三个文件里，而它们都不承载本项目的差异化逻辑（[dependencies.md](./dependencies.md) 开篇原则：协议与密码学不自己写，差异化逻辑自己写——韧性属于前者） |
| **`hashicorp/go-retryablehttp`** | **只覆盖重试。** 熔断与并发上限仍在外面，于是得到"一个库管一件事、彼此不知情"的拼装：重试不知道熔断已经打开（会白白重试到耗尽），熔断也不知道重试算一次还是三次。它在 `dependencies.md` §3 里原本就是作为"重试专用方案"被评估的；把它当成这次需求的答案，是把"重试变复杂"误读成了"三件事变复杂" |
| **`sony/gobreaker` + `backoff` + 自写信号量** | 两个库加一块自研，正是要消掉的形状；且三者之间同样互不知情 |
| **`failsafe-go`** | 一个 policy + executor 抽象覆盖三件；`bulkhead` 提供手动许可 API，正好满足第 3 条那条"许可必须活过 `RoundTrip`"的硬要求（本节的取舍里，这条是决定性的一条）；MIT；策略与机制可分离（见第 2 条），因此它不侵入领域规则 |

**为什么不直接用 `failsafehttp.NewRoundTripper`**（它确实是为 `http.RoundTripper` 准备的）：
它的 `doRequest` 用 `bodyReader` 在**每次尝试前**重新读取 `request.Body`，对未定型 body
（如 `http.NewRequest` 包出来的 `io.NopCloser`）走 `io.ReadAll` 全量缓冲，并且**完全不看 `req.GetBody`**。
这与本项目"body 不可重放就不重试、且不为重试缓冲请求体"的规则冲突（`retry.go` 的准入判断正是
`req.Body != nil && req.GetBody == nil` → 直通不重试）。于是改用它的 policy，不用它的 RoundTripper。

**为什么不做 hedge / timeout / cache / adaptive limiter**：本服务已有自己的超时语义
（`http.Client.Timeout` + `Transport.ResponseHeaderTimeout` + 每请求 deadline）与自己的限流
（`internal/ratelimit`，`x/time/rate`）。再引入库的 timeout 或 ratelimiter 会得到两套语义，
而"两套语义哪套生效"正是这类系统最难排查的故障。它们不是本次要解决的问题。

## 有意接受的语义变化

**这不是等价替换。** 三处变化是选择的结果，写在这里以免日后被当成 bug 重新发现：

1. **半开探测并发度从 1 变成至多 `failureThreshold`。** 旧实现是严格单发试探（`trialInUse` 布尔位），
   failsafe 在半开放行至多 `failureThreshold` 个并发许可。恢复瞬间对上游的压力从 1 变成至多 N。
   代价可接受（N 通常是个位数），收益是探测不再串行等待。**这是三处里最需要盯的一处**，
   若某个上游对恢复期的并发特别敏感，它会在触发条件里被重新评估。
2. **`Retry-After` 与退避的关系从"取较大者"变成"有 `Retry-After` 就用它"。**
   旧实现 `delay = max(backoff, retryAfter)`；现在是"上游给了就用上游的，否则用退避"。
   上游给的建议短于退避时，不再被本地的退避抬高。
3. **抖动也作用于 `Retry-After` 给出的延迟**（±50%）。旧实现只抖动退避曲线。
   抖动保留是为了不让一批调用方在同一个上游故障后同时回来；代价是延迟不再等于上游给的字面值。

**BREAKING：`BreakerOptions.Now` 被移除。** 熔断器使用库自己的时钟，无法注入假时钟。
对应的测试从"假时钟 + 时间跳跃"改为"真实短冷却窗口 + 显式等待"。这是本项目一贯的取舍
（[dependencies.md](./dependencies.md) §4 的"假时钟不能和真实时钟混用"）：宁可用真实短窗口，
也不要两套时钟。

## 后果

- **`httpclient` 的对外形状基本不变**：`Retry` / `Bulkhead` / `CircuitBreaker` / `NewOutboundClient`
  的签名与语义保持，调用方（`internal/federation`、`tapsign`、`taptapoauth`、`cmd/referencesource`、
  `cmd/re0auth`）零改动——这也是一次可验证的回归证据：那次提交只动了 9 个文件，且没有一个是调用方。
  唯一的例外是上面那条 BREAKING。
- **依赖代价**：`+failsafe-go v0.9.7`（MIT）与它的传递依赖 `bits-and-blooms/bitset`（BSD-3）。
  两者都在发布产物的构建图里（`go list -deps ./cmd/re0auth` 可验证），因此 `NOTICE` 的两节已同步。
- **退出路径是留着的**：正因为策略留在本仓库（第 2 条），换库只会触碰 `httpclient` 的三个文件；
  导出面除 `Now` 外没有变化。这不是"以后再换"的托词，而是这次选型的验收条件之一。
- **风险：failsafe-go 仍是 v0.x。** 这是本次决策**主要的、未消除的代价**：pre-1.0 意味着 API 可以在
  次要版本间破坏。缓解是 go.mod 的精确锁定，加上"升级按次要版本逐次评估、不批量跳版本"。
  对照 `zitadel/oidc/v3`（同为押注 pre-1.0 的稳定子集）的处理方式，见 [oidc-decision.md](./oidc-decision.md) §5.5。
- **熔断状态没有指标。** 库提供 `OnStateChanged` / `OnOpen` / `OnHalfOpen` / `OnClose` 监听器，
  但本次**不接线**：一个信号只有在"指标命名空间 → artifacts 一致性测试 → 告警规则 → 看板 → runbook"
  这条链走完才算完成（[observability-decision.md](./observability-decision.md)），那是独立的一次决策，
  不塞进这次重构。当前状态如实为"没有"。

## 重新评估的触发条件

出现以下任一条时，重开本决策：

1. **failsafe-go 发布 v1**——那时重新审视版本锁定与升级策略，而不是自动跟进。
2. **长期停在 v0.x 且出现安全修复**——需要评估"跟着走"与"换回自研"各自的成本。
3. **需要绕开库才能表达的策略**——若某条规则必须写进库的执行链之外（例如按 method 分别配置退避、
   或接入重试预算），说明抽象开始不匹配。
4. **半开并发度被证明有害**——某个上游在恢复期的 N 个并发探测下再次被打倒。
5. **需要把熔断状态变成可告警的信号**——按上面的完整链子做，而不是只加一个计数器。

## 测试锚点

`httpclient` 的 12 条韧性测试**一条未改地通过**（除 `TestCircuitBreakerOpensThenRecovers` 去掉假时钟），
它们钉住的正是本决策第 2 条列出的那些策略：

- 只重试幂等方法：`TestRetryDoesNotReplayPost`
- 失败时把上游自己的响应交给调用方（而非合成的"重试耗尽"）：`TestRetryGivesUpAndReturnsLastResponse`
- 调用方取消优先于上游错误：`TestRetryHonoursContextCancellation`
- 4xx 不计入熔断、5xx 计入：`TestCircuitBreakerCounts5xxNot4xx`
- 调用方取消不触发熔断：`TestCircuitBreakerIgnoresCallerCancellation`
- 熔断打开后不再打到下游、冷却后恢复：`TestCircuitBreakerOpensThenRecovers`
- 许可覆盖到 body 关闭、重复 Close 不会多还一次：`TestBulkheadHoldsSlotUntilBodyClosed`
- 取消的请求不占用许可：`TestBulkheadHonoursContext`
- 上限 ≤ 0 时返回原 transport（不套一层空壳）：`TestBulkheadDisabledWhenUnlimited`

## 参考

- [dependencies.md](./dependencies.md) §1（`failsafe-go` 一行）、§3（`go-retryablehttp` 的结论修订）、
  §4（"重试不能重放非幂等请求"、"假时钟不能和真实时钟混用"）
- [architecture.md](./architecture.md)：「出站韧性」一段（该段所在章节的编号目前在文档里被重复，故不引编号）
- [oidc-decision.md](./oidc-decision.md) §5.5（押注 pre-1.0 稳定子集的先例）
- [observability-decision.md](./observability-decision.md)（一个信号"算完成"的标准）
- [CONTRIBUTING.md](../CONTRIBUTING.md)（依赖方向由 `internal/archtest` 机器强制）
