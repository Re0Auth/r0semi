# 区域 18：Go 级危险模式全仓扫描 — 第七轮审计报告

## 范围与方法

- 读码面：全仓非测试 `.go`（114 个文件中的生产面）——重点 `internal/httpapi`、`internal/store/{memory,postgres}`、
  `oauth/`、`internal/oidchttp`、`internal/federation`、`vault/`、`httpclient/`、`idp/`、`tapsign/`、
  `taptapoauth/`、`audit/`、`internal/{auth,account,admin,lifecycle,ratelimit,observability,core,oidcstore}`、
  `cmd/re0auth`。已避开本轮已审区（07/08/09/10/13/22）及其报告。
- 机械扫描：`golangci-lint run --no-config --default=none --enable=gocritic,bodyclose,rowserrcheck,nilerr,
  errorlint/unconvert/ineffassign/staticcheck/govet/…）全仓 → 仅 5 条**测试文件**问题，生产面 0；
  `go vet ./...` 干净；`math/rand|unsafe\.|reflect\.|exec\.Command|html/template|text/template` 在生产面无命中；
  所有熵来源均为 `crypto/rand`；`int()/uint()` 转型逐条核对（唯一可疑的 `uint(maxConcurrent)` 有守卫）。
- 并发：`go test -race -count=1` 跑 `internal/auth`、`internal/store/memory`、`oauth`、`internal/federation`、
  `httpclient`、`vault`、`audit`、`internal/observability`、`internal/ratelimit`、`idp`、`internal/lifecycle`、
  `internal/account`、`internal/admin` → 全绿（无数据竞争）。
- 探针目录：`internal/zzprobe/audit7/z18gohazardsweep/`（`doc.go` + `probes_test.go`，全部 `//go:build audit7`）。
  运行：`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z18gohazardsweep/...` → 3 红 1 绿。
- 本机无 Docker/Postgres，DB 侧结论只读码级。

## 发现

### Z18-1 `/readyz` 在「首次就绪检查仍在途中」时 fail-open（匿名可达）
- 严重度：P2 中
- 类别：可用性 / fail-closed
- 不变量：fail-closed
- 证据：`internal/httpapi/health.go:111-120`

  ```go
  c.mu.Lock()
  fresh := c.checked && time.Since(c.checkedAt) < readinessTTL
  if fresh || c.running { err := c.err; c.mu.Unlock(); return err }   // ← checked 未参与判据
  ```
  `c.running` 为真的窗口正是**第一次**依赖检查在途的窗口，此时 `checked==false`、`c.err==nil`，
  于是任何在该窗口到达的 `/readyz` 都拿到 nil → 200「ready」，无论依赖是否真的不可达。
  失败是静默的：与健康实例的 200 完全一致（理由只进 `slog.Debug`，health.go:98）。
  探针输出（红）：请求 1 停在依赖检查里（依赖返回错误），请求 2 在窗口内得到 **200**；
  对照：检查落地后的第一次与第三次 `/readyz` 都是 **503**，且探针只被调用 1 次。
- 状态：CONFIRMED（真 HTTP 面，红探针 + 阳性对照）
- 影响：滚动发布/冷启动时，依赖（数据库）不可达的实例在首个检查在途期间（≤ `readinessTimeout`=2s，冷启动
  时通常更长）对编排器报告 ready，于是流量被路由到一个不能服务的实例。探针路径同时豁免限流与在途上限
  （middleware.go:335/399），匿名即可触发，不需要任何凭据或预算。
- 探针：`internal/zzprobe/audit7/z18gohazardsweep/probes_test.go::TestZ18ReadinessIsFailOpenWhileTheFirstCheckRuns`（红）
- 修法建议：让「没有结果」不能读成「结果是好」——把短路条件改成 `fresh || (c.running && c.checked)`，
  未检查且正在跑时按「未就绪」回答（503），或 `checked ? c.err : errors.New("readiness unknown")`。
- 是否与既有编号相关：**对 Z11-1 的补充**（不是重报）。Z11-1 是同一缓存中调用方 ctx 被取消导致 **503 毒化**
  （fail-closed 方向）；本条是 `running` 分支在 `checked==false` 时返回零值 nil 导致 **fail-open**（相反方向、
  不同分支、不同前提），修 Z11-1 不会修掉本条。

### Z18-2 `idp` 把互斥锁跨网络 I/O 持有：同一 provider 的并发登录串行化
- 严重度：P3 低/提示
- 类别：可用性
- 不变量：性能/资源
- 证据：`idp/idp.go:619-637`

  ```go
  c.providerMu.Lock(); defer c.providerMu.Unlock()      // 620-621
  if c.discovered != nil && time.Since(c.discoveredAt) < c.providerTTL { return c.discovered, nil }
  provider, err := oidc.NewProvider(oidc.ClientContext(ctx, c.http), c.issuer)   // 625：锁内做网络请求
  ```
  `oidc.NewProvider` 是对 issuer discovery 文档的一次 HTTP 往返，锁一直持有到它返回。任何未命中缓存的
  `AuthCodeURL`/`Exchange`/`Identity`（`oauthConfig` → `oidcProvider`，idp.go:466-481）都要排队。
  失败不缓存（idp.go:626-633 注释与代码一致），所以 issuer 慢/挂时**每一次**尝试都重复一次最长 10s
  （`NewRegistry` 默认 client `Timeout: 10*time.Second`，idp.go:270-273）的锁内往返。
  探针输出（红）：假 issuer 只把**第一个** discovery 请求拖住，后续请求立即应答；第二个登录会话在 400ms 内
  没有完成，解放后被释放（第一个登录成功，正面控制成立）。
- 状态：CONFIRMED（真 `idp.Client` + 真 discovery 往返，红探针 + 阳性对照）
- 影响：某 provider 的登录吞吐变成 1/发现延迟；issuer 抖动时该 provider 的全部登录（含回调路径）排队，
  一次 10s 的挂起会挡住此前所有在途请求。触发者是任一发起登录/回调的匿名请求，但需要 issuer 侧变慢，
  攻击者不能直接制造该前提，故定 P3。
- 修法建议：把网络发现移到锁外（double-checked：锁内查缓存 → 解锁 → 发现 → 锁内写入且不覆盖更新的结果），
  或给发现单独设一个远小于 client timeout 的超时并缓存失败结果若干秒（单飞 singleflight）。
- 是否与既有编号相关：无（第六轮 findings 未涉及 `idp.oidcProvider`）

### Z18-3 `oauth.MemoryStore` 把存储的 scope 切片交出去：改返回值即改活令牌的授权
- 严重度：P3 低/提示
- 类别：安全
- 不变量：token/scope 签发
- 证据：`oauth/tokens.go:216-232`（`SaveAccess`/`GetAccess` 直接存取结构体，`Scopes []Scope` 只复制 slice header）、
  `oauth/tokens.go:158-180`（`ListBySubject` 同样把 `t.Scopes` 塞进 `GrantRecord`）、
  `oauth/as.go:280`（`Introspect` 把 `at.Scopes` 原样作为 `TokenInfo.Scopes` 交出去）。
  探针输出（红）：`SaveAccess` 写入 `account.id` 后，把 `GetAccess` 返回的 `Scopes[0]` 改成
  `phigros.score.read`，再次 `GetAccess` 读到的**存储值也变了**。
- 状态：CONFIRMED（读码到行 + 红探针）。**可达性诚实说明**：本仓当前没有任何消费者改写从 store 取回的
  `Scopes`（`internal/httpapi` 只做 `slices.Contains`、`v1_routes.go:18` 只读转换），所以这不是一条可
  利用路径，而是「store 必须 copy-on-return」这条本仓自己立下（05-4）的不变量在另一处缺失。
- 影响：任何第三方/后续调用方对 `TokenInfo.Scopes` 做一次就地的收窄、排序或写入，就会静默改变一个**仍在
  有效期内**的访问令牌的 scope（提权或降权），且改的是存储本身而不只是本地副本。
- 探针：`…::TestZ18IntrospectionDoesNotHandOutTheStoredScopeSlice`（红）
- 修法建议：`SaveAccess`/`SaveRefresh`/`SaveCode` 存 `slices.Clone(Scopes)`，`GetAccess`/`ConsumeRefresh`/
  `ConsumeCode`/`ListBySubject` 返回时再 clone（与 `internal/store/memory/oidc.go` 既有的
  `append([]string(nil), …)` 形态一致）。
- 是否与既有编号相关：与 **05-4**（`cloneAuthRequest` 共享指针字段）同类但**不同站点/不同 store**：
  05-4 在 OP 内存后端 `internal/store/memory/oidc.go`，本条在 `oauth` 包的内存令牌 store。

## 探过但没破的（也应变成守卫）

1. `oauth/device.go:461-476 newUserCode`：拒绝采样 `max := 256 - 256%len(alphabet)`，再 `buf[0] >= max` 重抽
   —— 用户码无模偏差（源级）。
2. `httpclient/outbound.go:203-210 Bulkhead`：`maxConcurrent <= 0` 在 `uint(...)` 之前返回 `next`，
   负值不会变成天文容量。绿探针：`TestZ18NonPositiveBulkheadCapIsIgnored`。
3. `taptapoauth/client.go:96-103`：`time.Duration(data.Interval)*time.Second` 溢出后的负/零值走默认回退；
   仅可能把本地期限算成垃圾值，不影响任何信任判定（源级）。
4. `internal/httpapi/federation_routes.go:307-337 rawDownloadName`：白名单替换 [A-Za-z0-9._-]+64 截断，
   `Content-Disposition` 无 CRLF/引号注入；`export_routes.go:115` 用 `%q` 且用户 id 为服务端生成（源级）。
5. `internal/federation/service.go:666-687 rejectEscapingPath`：四次解码逐层拒绝 `..` 前缀段与反斜杠，
   `%2e%2e` 被拦；`path.Clean` 只用于拼 URL 前缀（源级 + 包内既有 fuzz）。
6. `internal/store/postgres` 单时钟政策：bf81b2a 后设备三处 SQL 均改 `$n ← s.now()`；残留 `now()` 仅
   `COALESCE(auth_time, now())`（展示性）与 `sessions.go:151` 的 DB 自写列相对区间（源级；权威验证位是 CI）。
7. `internal/store/postgres/auditbatch.go`：`time.NewTimer` 有 `defer Stop`、`done` 带缓冲、`enqueue` 在 send
   后二次检查 `stop`、`Close` 等 `stopped` —— 未发现泄漏/永久阻塞路径（源级）。
8. 并发：13 个包 `-race` 全绿；`oauth`/`internal/store/memory`/`ratelimit` 的 map 均在锁内读写，
   `for range` 中 `delete` 是合法用法（源级 + race）。

## 未能到达（残余盲区）

1. 无 Docker、无本地 Postgres：所有 PG 侧形状（含 bf81b2a 的时钟修复）只有读码级证据，
   `clock_test.go` 的权威执行位在 CI 的 `postgres:16`。
2. 无 Playwright：前端侧运行时行为到不了（本轮由区 08 负责）。
3. 真实墙钟性能/吞吐不可测（多代理并行）；只能给复杂度与分配口径。
4. `unsafe`/`reflect`/`os/exec`/模板注入/`math/rand` 这些类在生产面**零命中**（grep 级），
   因此它们不是「守住了」而是「不存在该形状」——没有阳性对照，不当正面结论。
5. 未跑全仓 `go test ./...`（并行代理共用工作区），仅跑定向包与 `-race`。

## 判断（文档化决定可否质疑，不是 finding）

1. `internal/ratelimit/ratelimit.go:116-125`：`if l.limit <= 0 { return 0 // rate.Inf }` 的注释与语义不符——
   `rate.Limit(0)` 不是 `rate.Inf`（前者是「永不补充」）。由此 `refillWindow()==0` 让 `reclaimWindow()`
   回退到 TTL，一个**已耗尽**的不补充桶在 TTL 后变成可回收，其所有者白拿一次满 burst。
   当前从发布组合根**不可达**：`cmd/re0auth/main.go:225` 对 `cfg.RateLimit <= 0` 直接返回 nil 限流器，
   `config.go:513` 把负值当配置错误。故这是「注释写错 + 潜在分支」，不是缺陷；若将来有调用方传 0，
   这里应返回 `math.MaxInt64` 之类（表示永不可回收）。
2. `internal/httpapi/middleware.go:242-255` 用 `context.Background()` 写访问日志是**有意的**（客户端已断开时
   仍要留证据，注释写明），不作为 finding。
