# Z18 对抗性复核报告（VERIFIED）

- 被复核：`docs/audit-7/findings/Z18-go-hazard-sweep.md`
- 被复核探针（**未改动**）：`internal/zzprobe/audit7/z18gohazardsweep/`
- 本复核探针（新，全部 `//go:build audit7`）：
  `internal/zzprobe/audit7/z18verify/verify_test.go`
  运行：`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z18verify/...` → **4 红 2 绿**
- 复核口径：不改任何被跟踪文件；被复核者探针原样跑过并逐条核对 `file:line`；
  凡「同意」都由**另一入口/另一观测**独立复现，不引用被复核者探针的输出当证据。
- 终态：`go build ./...` 0；`go vet ./...` 0；`go vet -tags audit7 ./internal/zzprobe/audit7/z18verify/...` 0。

## 1. 逐条判定

### Z18-1 → **NOT-A-FINDING（重报）**，严重度 P2 → **P3**

- **机制描述正确**。`internal/httpapi/health.go:111-118` 确是
  `if fresh || c.running { return c.err }`，`c.checked` 不参与判据；在首次检查在途窗口
  `checked==false && err==nil`，返回零值 nil ⇒ `handleReady`（`:94-101`）写 200 "ok"。
  我独立复现（`TestZ18vReadyzColdStart…`，红），且换了观测点：不只断言 200，还断言该请求
  **没有再次调用探针**（`calls==1`），所以那个 200 不可能来自一次健康的实时检查；对照是
  「跑检查的那次 = 503、检查落地后 = 503」。
- **但这不是新发现，是被两次报过的同一缺陷**：
  - 第六轮 `docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md:118` **G-11**：
    「`/readyz` 在『已有一次检查在跑』时答 200：`check()` 在 `running` 分支直接返回**零值
    `nil`**（`:112-118`）… 定为 P3」。其探针
    `internal/zzprobe/audit6/z06httpedge/readiness_test.go:159-211` 在 HEAD **仍红**（从未被修）。
  - 第七轮 `docs/audit-7/findings/22-audit5-red-reconciliation.md:78-144` **22-1** 又报一次，
    探针 `internal/zzprobe/audit7/z22reconcile/readiness_test.go`。
  - 简报 §4.3 明令第六轮 `G-1…G-24` **一律不得作为新发现重报**。Z18-1 是 G-11 的第三次出现，
    应写成「对 G-11 的重申」而非新编号。
- **严重度虚高**：G-11 已按可达性下调为 **P3**（kubelet 每周期串行发一次，
  `deploy/k8s/base/deployment.yaml:96-100` `periodSeconds: 5 / failureThreshold: 3`；
  窗口 ≤ `readinessTimeout=2s` < 一个周期；摘除端点在连续 3 次失败之后）。
  Z18-1 未补可达性证据就给 P2，与被复核报告自己引用的 G-11 裁定冲突。
- **报告内部一处不实**：Z18-1 只写「对 Z11-1 的补充」，漏了真正的既有编号 G-11/22-1，
  这正是重复编号的来源。Z11-1（调用方 ctx 取消毒化、fail-closed 方向，见
  `internal/zzprobe/audit7/z11resiliencedos/readyz_poison_test.go`）确实是另一分支，该区分成立。
  另外 22-1 声称 grep 过 `scratchpad/audit6/**` 且「没有任何一处提到 running 分支」，
  该说法不成立（G-11 正是这一条）。汇总时以 G-11 为准，不叠加三份计数。

### Z18-2 → **CONFIRMED**，P3 维持（但影响面被夸大）

- **机制正确、`file:line` 正确**：`idp/idp.go:620-621` 取 `providerMu`，
  `:625` 在锁内调 `oidc.NewProvider`（真实 discovery HTTP 往返），`:634-635` 才释放（defer）。
  `oauthConfig`（`:466-481`）与 `idTokenVerifier`（`:640-646`）都经 `oidcProvider`，
  所以 `AuthCodeURL`/`Exchange`/`Identity` 三条登录/回调路径都排队。
- 我独立跑过被复核者的探针：**红**，且阳性对照成立（第二个登录在 400ms 内未完成；
  discovery 只被请求 1 次；释放后第一个登录成功）。
- **影响描述要降一格**：报告标题写「并发登录串行化」，正文写「登录吞吐变成 1/发现延迟」。
  实际频率是**每个缓存未命中窗口一次**：`idp.go:35 defaultProviderCacheTTL = 15 * time.Minute`，
  命中缓存时 `:622-624` 直接返回、不持锁做 I/O。稳态下 ~15 分钟才有一个锁内往返，真正被串行化
  的是「TTL 到期瞬间并发到达的登录」以及**issuer 抖动时**每次尝试（失败不缓存）的 10s
  （`idp.go:270-273`）。P3 仍正确；建议改写为「每次发现期间该 provider 的登录被串行化，
  最坏 10s/次，失败不缓存会重复」。
- **是否为重报**：grep `scratchpad/audit6/**` 与 `docs/audit-5/findings/**`，无
  `providerMu`/`oidcProvider` 命中；第五轮 fragment 只在「读了哪些函数」清单里列过它。
  **非重报，判定成立。**
- 探针质量注意（不构成新发现）：红色分支里有 `t.Fatalf` 从 **goroutine** 调用
  （`probes_test.go:247`、`:258`）——`FailNow` 必须从测试 goroutine 调用，从别的 goroutine 调用
  行为未定义（这里只是可能少一条失败记录，不影响本次判定）。

### Z18-3 → **CONFIRMED（机制）/ HYPOTHESIS（可利用性）**，严重度 P3 维持

- **机制正确**：`oauth/tokens.go:216-221 SaveAccess` / `:224-232 GetAccess` 按值存取结构体，
  `Scopes []Scope` 只复制 slice header；`oauth/as.go:280` 把 `at.Scopes` 原样作为
  `TokenInfo.Scopes` 交出去。我用自己的探针独立复现（红，两个方向都写穿：写
  `GetAccess` 的返回值、写调用方自己保留的原切片，都改到**存储**里的记录）。
- **可达性诚实说明正确**。我独立复核了本轮全部 `TokenInfo.Scopes` / `Grant.Scopes` 消费点：
  `internal/httpapi/middleware.go:592`（`slices.Contains`）、`v1_routes.go:18`（`scopeStrings`
  逐元素转换）、`federation_routes.go:116/260`、`oauth/grants.go:80`（`unionScopes` 建新切片）
  ——**无一处就地改写**。按简报 §3 反空转口径这**不是**可触发缺陷，报告已如实写明，P3 合理。
  最严口径下应记 `HYPOTHESIS`（结论依赖「将来的消费者会就地改」这一运行时前提）。
- **不是重报**：05-4 在 `internal/store/memory/oidc.go`（OP 内存后端的 `cloneAuthRequest`
  共享指针字段），本条在 `oauth` 包的内存令牌 store；同族不同站点。判定成立。
- **补强（Z18 未写的**）：同一条不变量的两个后端形态**不对称**——
  `internal/store/postgres/oauth.go:579-585 scopesFrom` 逐元素重建、`:55/:84/:121/:160/:410-414/:568`
  全部经它返回**新切片**；`oauth.MemoryStore` 不复制。这给了「该修」一个直接证据：
  同一契约另一个实现已经 clone。

## 2. 新发现（独立证据）

### Z18v-1 [P3 低] 同族的第二道门：`ListBySubject` 的 `GrantRecord.Scopes` 也指向存储数组
- 严重度：P3（与 Z18-3 同族、同可达性：无就地改写的消费者）
- 证据（红）：`…::TestZ18vGrantsViewSharesTheStoredScopeSlice` —— 把 `ListBySubject` 返回记录的
  `Scopes[0]` 收窄后，`ConsumeRefresh` 读回的存储值也变成收窄后的值（原 `account.id`）。
  源级：`oauth/tokens.go:158-180`（access/refresh 两个循环）把 `t.Scopes` 直接塞进 `GrantRecord`。
- 为什么要单独记：Z18-3 的修法只点了 `SaveAccess/SaveRefresh/SaveCode` 与
  `GetAccess/ConsumeRefresh/ConsumeCode`，**漏了 `ListBySubject`**；照建议修，这条门仍开。
- 影响：授予视图（`oauth/grants.go:57-80`、`internal/httpapi/grants_routes.go:37`、
  `export_routes.go:74`）拿到的数组就是活令牌的数组，任何就地排序/收窄都写进令牌。
- 修法：`ListBySubject` 返回时 clone（或统一到一个 `cloneToken` 出口）。

### Z18v-2 [P3 低] `idp` 的 provider TTL 在「发现失败」时不再成立：过期密钥被无限期信任
- 严重度：P3（正确性；不是绕过——缓存里的密钥本来就是这个 provider 的）
- 证据（红）：`…::TestZ18vDiscoveryFailureKeepsServingTheStaleProvider`
  输出：`ProviderCacheTTL=1ns`、issuer 的 discovery 改为 500 后，一次**必然要重新发现**的
  `AuthCodeURL` 仍然成功。
  阳性对照：同一个 broken issuer、冷缓存的新 client **必须失败**（探针已断言，成立）。
  源级：`idp/idp.go:626-633` 失败时 `return c.discovered, nil` 且**不更新 `discoveredAt`**，
  于是 `:622` 的 `time.Since(c.discoveredAt) < c.providerTTL` 永远为真。
- 影响：`:606-613` 的注释把缓存承诺写成「at most providerTTL」，这只在发现**成功**时成立。
  上游轮换/吊销签名密钥后，本进程继续用缓存 JWKS 验签（go-oidc 只在 kid 未命中缓存密钥时
  重取，见 `:610-613`），TTL 这条唯一的老化出口失效——上游明确告知密钥集已失效时反而最不
  可能更新。定 P3：不产生伪造令牌，但破坏注释承诺与密钥退役的可观测性。
- 修法：失败分支也推进 `discoveredAt`（或记录 `lastAttempt`），至少让注释与行为一致。

### Z18v-3 [P3 低] 被复核夹具使 `/readyz` 的「限流/在途豁免」断言在结构上不可证
- 严重度：P3（方法学 / 证据完整性；缺陷本身可能不存在）
- 证据（源级）：Z18-1 的夹具 `…/z18gohazardsweep/probes_test.go:63-70` 只设
  `Issuer/OIDC/TokenIntrospector/GrantStore/DeviceStore/Ready`；`Limiter` 为 nil、
  `MaxInFlight` 为 0，于是 `internal/httpapi/middleware.go:328-330`（`s.limiter == nil` 直接放行）
  与 `:394-396`（`maxInFlight <= 0` 直接放行）**都短路**。报告里「探针路径同时豁免限流与
  在途上限…不需要任何凭据或预算」这句话，该探针**证明不了**。
  这条豁免别处有真探针（`internal/zzprobe/audit7/z11resiliencedos/ratelimit_guard_test.go:116-131`、
  `inflight_test.go:84-91`），所以不是漏检，而是把别人的结论借到了自己的夹具上。
- 修法：把 `Limiter`/`MaxInFlight` 填上再断言 200，或删掉该句。

### Z18v-4 [P3 低] 「探过没破」第 2 条的绿探针是空守卫（不能为它作证）
- 严重度：P3（方法学：假绿）
- 证据（源级）：`…/probes_test.go:325-336 TestZ18NonPositiveBulkheadCapIsIgnored` 只断言
  `Bulkhead(next, 0/-1/-1<<20) == next` 与 `Bulkhead(next, 1) != next`。它**从不触发
  `uint(maxConcurrent)` 那次转换**，钉住的只是「非正值被忽略」这一返回值身份，证不了
  「负数经转换会变成天文容量」这一它要排除的失败形态。
- 守卫本身：`httpclient/outbound.go:203-205` 先判 `maxConcurrent <= 0 → return next`，再在
  `:209` 转换，**方向是对的**。所以这是「结论对、证据空」。建议补一条 `Bulkhead(next, 2)`
  下第 3 个并发 `RoundTrip` 被拒/阻塞的探针。

## 3. 探过没破（复核方）

1. **`oauth.MemoryStore` 的其余取值口**：`SaveCode/ConsumeCode`、`SaveRefresh/ConsumeRefresh`、
   `TokenOwner` 均与 Z18-3 同形（按值 + slice header）；refresh 路径已在
   `TestZ18vTokenStoreHandsOutTheStoredScopeSlice` 中写穿成立，确认为同族而非「已守住」。
2. **`oauth.MemoryClientRegistry.Get`（`oauth/client.go:358-366`）返回的
   `AllowedScopes`/`RedirectURIs` 同样别名**，`internal/store/memory/oidc.go:714-728` 也经它。
   消费面只读（`AllowsScope`/`AllowsRedirect` 不改写，`server.go:669` 的 `sort.Strings`
   作用在本地构造的 slice 上），故今天不可利用；与 Z18-3 同族，修时应一并 clone。
3. **`internal/store/postgres/oauth.go` 的 client 路径**：`scanClient`→
   `RestoreClientWithStatus`（`oauth/client.go:146-155`）显式 clone 三个切片，**守住**。
4. **`ratelimit` 的 0 速率语义**（Z18「判断」第 1 条）：独立跑出运行级证据——
   `TestZ18vZeroRateLimiterNeverRefills`（绿）证明 `New(0,1)` 首事件放行、之后**永不放行**、
   30ms 后也不放行，即 `rate.Limit(0)` 不是 `rate.Inf`，报告对注释的质疑成立；另一绿探针
   记录「不能按可回收性区分」这一观测极限。可达性亦复核：`cmd/re0auth/main.go:224-229
   buildLimiter` 对 `cfg.RateLimit <= 0` 返回 nil 限流器，发布组合根不可达。
5. **`/readyz` 的 fail-open 窗口是唯一的**：冷启动分支之外，`fresh` 与「运行中且有结果」
   两条路都返回真结果；无第三个失败/成功混合分支。
6. **溢出类**（`taptapoauth/client.go:96-103`、`httpclient/retry.go:176`）：读码级确认溢出后走
   `<=0` 默认回退或 clamp，未把溢出值送进信任判定。
7. **`internal/store/memory` 的 `Grants`（`oidc.go:1133-1192`）**：逐元素重建 `g.Scopes` 并在
   `:1187` 排序**新切片**，不别名存储——与 `oauth.MemoryStore.ListBySubject` 形成对照。

## 4. 未能到达 / 残余盲区（复核方）

1. **无 Docker / 无本地 Postgres**：Z18 的 PG 侧形状（单时钟政策、`clock_test.go` 的 CI 权威位）
   只能读到行；我**没有**执行任何 PG 用例，也未把源级推论升级为 CONFIRMED。
2. **未跑 `-race` 复核**：并行代理共享工作区；Z18「13 包 `-race` 全绿」我**未复核**。
3. **未起真进程**（端口 18802 未使用）：Z18-1 在 `httptest.Server` + 真实 `httpapi` 中间件链上
   已能判定；真进程内存模式的 `Ready` 为 nil（`cmd/re0auth/main.go:854-865`），**结构上无法**在
   内存真进程里构造依赖失败的 `/readyz`。这反而是 Z18 未说明的：失败分支只在 `DATABASE_URL`
   部署里可达。
4. **Z18 的零命中 grep 类**（`unsafe`/`reflect`/`os/exec`/`math/rand`/模板）：Z18 自己已声明
   「没有阳性对照，不当正面结论」，符合简报 §3，不记为证据不足。

## 5. 复核方判断（不构成 finding）

1. **Z18 的机器扫描面（golangci-lint / go vet）我没能复核**：本机无该 lint 配置与产物。
   这类「阴性套件结果」按简报 §3 需要阳性对照（先证明 linter 在注入缺陷时会报），报告未提供；
   故不列为新发现，但**不作为可依赖的结论**。
2. 被复核报告自称「3 红 1 绿」——原样复跑确为 3 红 1 绿，红的理由与报告声称一致
   （Z18-1 缓存零值、Z18-2 锁内 I/O、Z18-3 slice 别名），**无一条「红在别处」**。
   探针本身可信；问题只在编号、严重度与影响描述。

## 6. 汇总给主代理

| 编号 | 判定 | 严重度 |
|---|---|---|
| Z18-1 | NOT-A-FINDING（= 第六轮 G-11 + 第七轮 22-1，第三次报） | P2 → **P3** |
| Z18-2 | CONFIRMED（机制对；影响面夸大） | P3 维持 |
| Z18-3 | CONFIRMED 机制 / HYPOTHESIS 可利用性 | P3 维持 |
| Z18v-1 | NEW：`ListBySubject` 同族第二道门 | P3 |
| Z18v-2 | NEW：provider TTL 在发现失败时失效 | P3 |
| Z18v-3 | NEW：夹具使豁免断言不可证 | P3 |
| Z18v-4 | NEW：Bulkhead 绿探针是空守卫 | P3 |
