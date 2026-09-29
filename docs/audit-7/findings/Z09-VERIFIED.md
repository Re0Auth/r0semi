# 区域 Z09：联邦数据面 — 第七轮**对抗性复核**报告（VERIFIED）

> 复核对象：`docs/audit-7/findings/Z09-federation-dataplane.md`
> 复核者立场：证伪优先。逐条读 `file:line`、复跑被复核者的探针、检查误报/重报/机制错/严重度虚高。
> 本报告**只新增文件**：本文件 + `internal/zzprobe/audit7/z09verify/`（全部带 `//go:build audit7`）。
> 未修改任何被跟踪文件（`git status --short` 只有 untracked）。

## 0. 复核方法与独立证据清单

**复跑的、被复核者的探针**（真 HTTP 面 / 真 OP / 真上游，逐条读过源码后复跑）：

```sh
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z09federationdataplane/...
# --- FAIL: TestZ09ARetiredSourceCanStillBeBound
# --- FAIL: TestZ09NormalizedReadServesAnOverCapBodyAsComplete
# --- FAIL: TestZ09SleeperReadsShedAFullCapReadForAnotherUser
# --- FAIL: TestZ09StatusSpellingDecidesWhetherARetiredSourceStillServes
# --- FAIL: TestZ09RegistryAcceptsAnyStatusSpelling
# --- FAIL: TestZ09AMisspelledRetirementStillDecidesAnotherSourcesGate
# --- PASS: TestZ09AnUpstreamTokenCannotInjectAHeader
# --- PASS: TestZ09RawResponseDoesNotLeakTheSourcesHeaders
# --- PASS: TestZ09RawPathCannotEscapeTheSourcesBase
# --- PASS: TestZ09ASourceNameCannotInjectAResponseHeader
# --- PASS: TestZ09ASourceThatAlwaysAnswers401TripsTheBreaker
```

**我自己写的探针**（独立实现、不复用被复核者的夹具）：

```sh
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z09verify/...
# --- FAIL: TestZ09VerifyOneAccountsDeadCredentialShedsAnothersRead     （新发现 V1）
# --- PASS: TestZ09VerifyTheVictimRecoversWhenTheBreakerHalfOpens        （V1 恢复对照）
# --- PASS: TestZ09VerifyAnInterleavedSuccessKeepsTheSharedBreakerClosed （V1 上界对照）
# --- FAIL: TestZ09VerifyAStoreReadFailureIsDestroyedAsIfTheGrantWereDead（新发现 V2，含对照子测试）
# --- PASS: TestZ09VerifyACleanTokenDoesReachTheUpstream                 （held #1 的阳性对照）
# --- FAIL: TestZ09VerifyASchemeRelativeIssuerWouldRedirectTheBindOffOrigin（附注 1 的实测）
```

**收尾门**：`go build ./...` exit 0、`go vet ./...` exit 0、`go vet -tags audit7 ./internal/zzprobe/audit7/z09verify/...` exit 0、
`gofmt -l internal/zzprobe/audit7/z09verify/` 空、`go test -count=1 ./internal/federation/... ./httpclient/...` 全绿。

**没有做的事**（与本区报告一致的盲区）：真实 Postgres / Docker / `-race`（只对 V1、V2 的确定性路径做了论证，没有并发检测器背书）。

---

## 1. 逐条裁定

### Z09-1 → **CONFIRMED**（P2 中，不升不降）

- **机制复核：报告写的机制是对的。** 逐行确认：`internal/federation/federation.go:53-62` 的 `statusRank` 只影响
  `service.go:533` 的**排序**，`default: return 2` 把词表外的值排在最后；真正「排除」退役源的是**三处精确字符串比较**
  `src.Status == StatusRetired`（`service.go:515`、`:526`、`:564`），另加 `missing.go:71` 与
  `internal/httpapi/binding_routes.go:95`。`NewRegistry`（`federation.go:162-164`）只把 `""` 归一成 `active`。
- **独立证据 1（配置路径确实可达，不只是库 API）**：`cmd/re0auth/config.go:225-226` 的 `Status string` 经
  `:897` `Status: federation.SourceStatus(section.Status)` **原样**塞进 `federation.Source`，随后
  `:925` 交给 `NewRegistry`；全文没有第二处 status 校验（grep 仅命中这两行）。`config/re0auth.example.toml:358-364`
  的 `token_class` 注释承诺「any other value is refused at startup」，`status` 只列词表、**没有任何拒绝承诺**——
  报告的引用逐字属实。
- **独立证据 2（复核新捡到的一条更硬的证据）：本轮报告漏了一份「书面安全断言」被证伪。**
  `docs/audit-5/findings/config-startup-disclosure.md:178-179`（CS-4）白纸黑字写着：
  「方向与 `status`（**未知值经 `federation.go:53-62` 的 `statusRank` 落到「retired」，fail-closed**）相反」。
  这是**错的**：`statusRank` 的 `default` 只是排序权重 2，落到「retired」的那一步根本不存在，未知值是可被选中的。
  也就是说，第五轮审计把「status 未知值 fail-closed」当成既有保证写进了文档，而它从来没有被验证过。
  这把 Z09-1 从「一个运维错字」提升为「一份审计文档记录了不存在的保证」——建议在修法同时更正该文档。
- **反空转**：报告自带 2 条阳性对照（精确 `retired` → 404/410；空值 → active 且被服务），复跑一致；
  `/v1/sources` 实测广播 `"Retired"`。**对照充分，不是「一切都 200」。**
- **严重度**：P2 恰当。前提是运维写出词表外的拼写（`前提较高`），后果是「被下线的源继续拿用户令牌读数据」（`影响确定`），
  且完全静默。不升 P1（无跨账号、无提权），不降 P3（后果是数据被一个运营者以为已下线的源继续读取，不是纯文档问题）。
- **是否重报**：否。它是对 CS-4（`token_class` 校验）与 FO-V2（闸门排除 retired）修复的补充，符合简报 §4.4。

### Z09-2 → **CONFIRMED**（P3 低/提示）

- **机制复核：报告写的机制是对的。** `service.go:760-775`：`reserveFor(resp, maxBody)` →
  `io.ReadAll(io.LimitReader(resp.Body, maxBody))`（`:765`）→ 只查 `StatusCode`（`:769`）与 `json.Valid`（`:772`），
  **从不比较 `len(body)` 与 `maxBody`**。对照 `rawFetch`（`:730-736`）：读 `maxBody+1` + `len(body) > maxBody → ErrResponseTooLarge`。
- **独立复跑（FAIL，原文见下）**：

  ```
  bodycap_test.go:57: normalized: upstream wrote 5242902 bytes, cap is 4194304, caller got 4194304: status=200 json.Valid=true
  bodycap_test.go:74: raw control: status=502 ... "the source's response is larger than this proxy will pass through"
  ```
  **上游写了 5 242 902 字节，调用方收到 4 194 304 字节并拿到 200**；同一 body 在 raw 路径得到 502。对照成立。
- **报告引用的「理由不成立」是对的**：`json.Valid` 接受尾随空白是 Go 的确定行为，`service.go:713-719` 的注释
  「its body has to parse as JSON, and a cut one does not」对「完整 JSON 值 + 填充」的形状不成立。
- **严重度**：P3 恰当（能过校验的截断形状数据本身通常在截断点前已完整；真实损害是契约与守卫的不对称 + 一行可修）。
  报告的自我克制是对的，不构成虚高。
- **是否重报**：否，是对第四轮 `18fed92` raw 一侧修复的补充。

### Z09-3 → **CONFIRMED**（P3 低/提示）

- **机制复核：报告写的机制是对的。** `bind.go:127-152`（`BeginBind`）在 `registry.Get`（`:128`）之后只检查
  `src.ClientID == "" || s.baseURL == ""`（`:132`）；`CompleteBind` 在 `:171` 取注册表条目后直接走到
  `:175` 的 code 兑换与 `:192-197` 的 `storeBindingSecret`（vault.Enroll），**两处都没有 `Status` 判据**。
- **独立复跑（FAIL）**：

  ```
  bind_test.go:73: MissingBindings offers [live] for "phigros.profile.read"   ← 展示层阳性对照
  bind_test.go:87: BeginBind started a binding flow for a RETIRED source:
      https://gone.example/oauth/authorize?client_id=cid&...
      &redirect_uri=...%2Fphigros%2Fgone%2Fcallback&scope=account.read+phigros.profile.read&state=bnd_281c...
  ```
- **四面一致性复核**：`candidates`（`service.go:526`）、`Raw`（`:564`）、`bindingView.Bindable`（`binding_routes.go:95`）、
  `MissingBindings`（`missing.go:71`）确实都用精确比较，四处都说退役源不可用；只有 `BeginBind`/`CompleteBind` 不是。
- **严重度**：P3 恰当，但**有一个可以上调 P2 的角度报告没写**：`CompleteBind` 会把用户的**授权码**送去
  `gone` 的 token 端点、并把它的上游令牌存进 vault。如果运营者退役该源的**原因**是它已不可信，
  那么「退役 = 不再有任何交互」在出站方向上被打破了一半。考虑到仍需一个手写/陈旧链接 + 用户确认，
  破坏面有界，**我维持 P3**，把这一点记为可上调的理由。
- **是否重报**：否（FO-V2/P1-5 一族，对象从 scope 闸门换成绑定资格）。

### Z09-4 → **CONFIRMED**（P2 中）

- **机制复核：报告写的机制是对的。** `service.go:24` `maxBody = 4<<20`；`:30` `defaultMaxBufferedBytes = 64<<20`；
  `reserveFor`（`:108-113`）在 `ContentLength` 未知时预留整个 cap；`rawFetch`（`:725-729`）与 `fetchResource`（`:760-764`）
  都是**读之前** `acquire`；`acquire`（`:71-82`）满了直接 shed、不排队、无 per-subject 配额。
  `cmd/re0auth/main.go:492-508` 全数据面共用**一个** outbound client，`:75` `federationMaxConcurrent = 256`。
- **独立复跑（FAIL）**：

  ```
  budget_test.go:134: with 16 sleepers holding reservations (handlers reached: 16 of 16), an unrelated user's read = 503
  budget_test.go:157: after releasing the sleepers, the unrelated user's read = 200
  ```
  基线（无 sleeper）200 → 16 个零字节 sleeper 在途时**另一个用户** 503 → 释放后 200。两条对照都成立，
  shed 确实归因于被占住的预留。算术复核：15 × (4 MiB+1) = 62 914 575，余 4 194 289 < 归一化预留 4 194 304 ⇒ 差 15 字节。
- **我的独立补充（方向是「报告低估了前提」，不是高估）**：报告把它写成「慢上游 / 会 stall 的源」，
  但 `rawFetch` 只要**响应体大到值得传**（≥4 MiB）就能占住预留——一个正常但 body 大的源 + 15 个并发读即可，
  不需要源配合 stall。也就是说它的触发前提**比报告写的更宽**。严重度维持 P2（跨用户可用性、无泄露、无绕过）。
- **是否重报**：否，是对 P0-3 / B-3「在途 × body 无联合上限」修复的补充（同一处代码的反方向后果：有界但无分摊）。

---

## 2. 新发现（报告漏掉的）

### Z09V-1 共享的 per-host 熔断器把「一个账号的凭据坏了」当成「源坏了」：5 次读就能让**其他账号**读不到该源

- 严重度：**P2 中**（一次登录即可；跨用户可用性；无泄露、无绕过；30s 冷却自限）
- 类别：可用性
- 不变量：fail-closed 且有界，**且一个调用方不能凭自己的失败决定别人的成败**（与 Z09-4 同族，但方向更便宜）
- 证据（执行过，FAIL；独立探针，未复用被复核者夹具）：

  ```
  baseline victim read ok (1 upstream calls);
  5 attacker reads produced 5 upstream calls; attacker errors = [401 ×5]
  after the attacker's reads: victim read = err=federation: source src: Get ".../resources/profile":
      httpclient: circuit breaker is open,   upstream calls added = 0
  ```
  对照 1（源对受害者是健康的）：基线读 200，且**释放后同一读恢复 200**（`TestZ09VerifyTheVictimRecoversWhenTheBreakerHalfOpens` PASS）。
  对照 2（上界，诚实标注）：`TestZ09VerifyAnInterleavedSuccessKeepsTheSharedBreakerClosed` PASS —— failsafe 的
  `countingStats` 是**最近 5 次执行的滚动窗口**，只有 5 次**全为失败**才开闸，所以任何一个成功的读都会压住它。
  这使本发现是「突发 / 安静源」型攻击，而不是必然成功。
- 机制（读码 + 库源码到行）：`httpclient/circuitbreaker.go:122` 以 `req.URL.Host` 为键；`:135-163` 每个 host 一个
  executor；`cmd/re0auth/main.go:492-508` 全数据面共用这一个 client ⇒ **熔断器是跨账号共享的**。
  `breakerFailure`（`circuitbreaker.go:196-204`）把 `401` 计为 host 不健康的失败（P1-3 于第五轮有意加入）。
  一次读得到的 401 是**调用方自己的上游凭据**状态（令牌被源撤销 / 过期且无 refresh / refresh 被拒），
  与 host 的健康无关。库侧语义已在 `.../failsafe-go@v0.9.7/internal/util/stats.go:42-100` 与
  `circuitstates.go:61-70` 核对（`FailureCount() >= 5` 且窗口容量 5）。
- 影响：任何一个已绑定该源的账号，只要它的上游凭据被源拒绝，连续 5 次读（突发即可）就把该 host 的熔断器打开，
  此后**所有账号**对该源的读在 30s 冷却内被 `ErrCircuitOpen` 直接拒绝（`Fetch` → `service.go:470` 分类），
  请求根本没出网。受害者拿到的是 `502 upstream_unavailable`，**无从知道这是别人造成的**。
  非恶意路径同样成立：一个用户的上游令牌自然过期（无 refresh）就是 5 次 401 的来源。
- 探针：`internal/zzprobe/audit7/z09verify/verify_test.go::TestZ09VerifyOneAccountsDeadCredentialShedsAnothersRead`（红）
  + `::TestZ09VerifyTheVictimRecoversWhenTheBreakerHalfOpens`（绿对照）
  + `::TestZ09VerifyAnInterleavedSuccessKeepsTheSharedBreakerClosed`（绿，上界）
- 修法建议（涉及裁定）：把 401 的「host 失败」语义按**调用方**分流——例如 401 不进入 host 熔断的失败计数，
  改成对**同一 binding** 的失败计数（`keyedMutex` 已经是按 binding 的，可以同构），或对 401 单独设
  「凭据失效」短路（把该 binding 标记为需重绑）而不动 host 熔断。P1-3 的目标（避免永久 401 源吃满超时）
  可以靠「同一 binding 连续 N 次 401 ⇒ 该 binding 冷却」达成，不必牵连整个 host。
- 是否与既有编号相关：**是对 P1-3（401 计入熔断）修复的补充**——第五轮只论证了「永久 401 的源应被跳过」，
  没有记录**per-host 熔断 + 401 会跨账号**这一后果。非重报（`docs/audit-6/findings/` 内 grep
  `circuit|breaker|熔断` 零命中；第七轮其他区报告零命中）。

### Z09V-2 `refreshRejected` 把「读不出来」当成「版本没动」——一次存储读失败就会撕掉一份可能仍有效的绑定

- 严重度：**P3 低/提示**（服务层行为 CONFIRMED；生产触发需要 Postgres 读故障，标 HYPOTHESIS）
- 类别：可用性 / 正确性 / 数据丢失
- 不变量：fail-closed；「破坏性分支必须在证据充分时才能走」
- 证据（执行过，FAIL；独立探针，真实 vault + 真 token 端点 + 注入的存储读故障）：

  ```
  A（读失败）：fetch err=federation: phigros/src is not bound;
      binding row after the failed re-read: err=federation: source is not bound;
      vault secret: err=vault: credential not found
  B（对照，同样的 400 invalid_grant，但重读成功且显示版本已推进）：
      fetch result={Source:src Data:{"served_by":"src"}} err=<nil>; binding row: <nil>
  ```
  两个子测试**只差重读的结果**，这正是被审的那条分支。
- 机制（读码到行）：`refresh.go:143`
  `if latest, err := s.bindings.Get(...); err == nil && latest.Version != spent.Version { return latest, nil }`
  ——只有「读成功且版本动了」才被放过；`err != nil`（并非 `ErrNotBound`）与「版本没动」一起落到
  `:151` `vault.Revoke` + `:159` `bindings.Delete`。存储故障不是「版本没动」的证据。
  生产可达性：`internal/store/postgres/federation.go:20-33` 只把 `noRows` 映射成 `ErrNotBound`，
  连接池/连接故障按原样返回（读码确认）；内存后端不会返回这种错误，所以本发现对内存模式不可达。
- 影响：一次（瞬时）存储读故障 + 上游一次 `invalid_grant` ⇒ 用户的绑定行被删、vault 密钥被 crypto-shred。
  若另一进程刚刚轮换过（本函数存在的全部理由），被删的就是一份**仍然有效**的绑定，用户必须重新绑定。
  破坏面有界（需要两个条件同时成立），且不会泄露凭据。
- 探针：`internal/zzprobe/audit7/z09verify/verify_test.go::TestZ09VerifyAStoreReadFailureIsDestroyedAsIfTheGrantWereDead`
  （子测试 A 红、B 绿对照）
- 修法建议（最小改法）：把重读的**非 `ErrNotBound` 错误**向上返回而不是落入破坏性分支，例如
  `latest, err := s.bindings.Get(...); if err != nil { if !errors.Is(err, ErrNotBound) { return Binding{}, err } } else if latest.Version != spent.Version { return latest, nil }`。
- 是否与既有编号相关：无直接编号。第五轮 `docs/audit/findings/federation.md:451`、`federation-VERIFIED.md:284`
  描述过 `refreshRejected`，但都默认「重读成功、发现版本没动」。非重报。

### Z09V-3 `/bind` 在 `Issuer = "//evil.example"` 时 302 到**另一个 origin**（报告已在未编号附注里发现）

- 严重度：**P3 低/提示**（前提是运维写出 scheme-relative 的 Issuer）
- 类别：安全（开放重定向 / 钓鱼面）
- 证据（执行过，FAIL；独立探针）：

  ```
  BeginBind authorize URL with Issuer=//evil.example:
      //evil.example/oauth/authorize?client_id=cid&...&state=bnd_1a90...
  Location: //evil.example/oauth/authorize?...   (url.Parse host="evil.example")
  ```
  `NewRegistry` 对 `Issuer` 只查非空（`federation.go:144-146`），`BeginBind`（`bind.go:150`）产出的
  `AuthCodeURL` 是协议相对形式，`handleBindStart`（`federation_routes.go:364`）
  直接 `http.Redirect(..., 302)`。浏览器会把 `//evil.example/...` 解析成 host=`evil.example`。
- **归属说明**：被复核报告在「复核附注 1」里**已经发现了这一条并明确选择不编号**（「留给该条的负责人，不计入本轮 findings」）。
  复核的独立判断是：它是与第六轮「令牌外流」**不同后果**的新面（不泄漏凭据，但把用户的绑定登录流程交给第三方 origin），
  且第六轮探针没有覆盖它。**建议作为独立编号收录**（编号权在主代理），所以我把它列在 new_findings 而不是当成重报。
- 探针：`internal/zzprobe/audit7/z09verify/verify_test.go::TestZ09VerifyASchemeRelativeIssuerWouldRedirectTheBindOffOrigin`（红）
- 修法建议：与 `validateRawBase`（`federation.go:207-220`）同形，在 `NewRegistry` 对 `Issuer` 要求
  `Scheme ∈ {http,https} && Host != ""`（顺带封住 `?`/`#` 吞掉资源路径的那一半）。

---

## 3. 对「探过没破」的复核（含假守卫排查）

| # | 报告结论 | 我的复核 | 裁定 |
|---|---|---|---|
| 1 | 上游令牌里的 CRLF 不能注入出站头（502，上游零请求） | **绿，但原探针缺阳性对照**：`len(up.requests())==0` 时它不做任何断言，所以「客户端拒发」与「数据面根本没发」在探针内不可区分。我补了同夹具的干净令牌对照：`TestZ09VerifyACleanTokenDoesReachTheUpstream` PASS（干净令牌到达上游 1 次）。**加上对照后守卫成立** | 守卫成立，证据补强 |
| 2 | raw 不透传 Set-Cookie/Location/CORS/内部头 | 原探针先 `if code != 200 { t.Fatalf }`，有成功路径对照；复跑 PASS | 守卫成立 |
| 3 | 源名 CRLF 不能注入响应头（值被压平成 `"src  X-Injected: 1"`） | 复跑 PASS，实测值确为压平而非拒绝；报告把它记为 FO-04 的附表是**正确的归类**，不虚报 | 守卫成立（FO-04 附表） |
| 4 | raw 路径不能离开 base（含对第五轮 `?`/`#` 结论的更正） | 复跑：`..%2f..%2fadmin`/`..%5c..%5cadmin`/`..;/admin`/`%252e...` → 400 + 上游零请求；`%2F%2Fevil.example%2Fx` → `/native/evil.example/x`；`x%3Fy=1` → **上游看到 `/native/x?y=1`**（我确认 `rawFetch` 无 `PathEscape`，`service.go:690-700` 是 `path.Clean` + 直接拼接）。**更正属实**，且不构成发现（host 与前缀未变、query 本由调用方控制） | 守卫成立，更正属实 |
| 5 | P1-3 的修复（401 计入熔断）生效：8 次读只拨号 5 次 | 复跑 PASS，`8 reads → 5 upstream requests`，精确匹配。**但这条正面结论的另一面就是我的 Z09V-1**：报告只验了「同一个用户对永久 401 源会被熔断」，没验「这会把别的用户也挡掉」 | 守卫成立，但不完整 |
| 6 | 归一化闸门与选源判据（P1-5/FO-01）在精确配置下同源 | 读码确认 `ResourceRequirements`（`service.go:384-410`）与 `Fetch` 用同一个 `candidates`；报告同时标注了 Z09-1 会让它在拼写变体下失效 | 成立 |

**假守卫结论**：没有发现「夹具用桩把被测对象换成永远答 200」这种整条假绿；唯一的一处证据不足是 held #1 的零命中
无阳性对照（已补）。报告的 4 条红探针都有阳性/恢复对照，非空转。

## 4. 未能到达（残余盲区，与报告一致）

1. **真实 Postgres**：Z09V-2 的生产触发（存储读故障）只有读码级证据（`postgres/federation.go:26-31`），标 HYPOTHESIS。
2. **地址闸门 / SSRF 解析层本轮仍未重测**：我的夹具也必须是 loopback 上游，`DenyPrivateAddresses` 取零值（与生产相反）。
   **说明**：`ProxyFromEnvironment` 绕过地址闸门这一条是第五轮 **FO-07**（`docs/audit-5/findings/federation.md:270-290`、
   `federation-VERIFIED.md:457-475`），**我没有重报**；本报告只指出报告把它放在「未能到达」是对的。
3. **`-race` 未跑**：V1/V2 都是确定性路径，但 `bufferBudget` / 熔断器 host map 仍无竞态检测器背书。
4. **真实 DNS rebinding / 重定向变体 / IP 字面量编码**：全部沿用第五轮结论，本轮未重做。

## 5. 我考虑过但不报的（避免重报）

1. **vault 身份命名空间歧义**（`Provider: game + "." + source` 无字符校验，两个 (game, source) 共享一行凭据）：
   我一度打算把它做成新发现并写好了探针，查证后确认它**已经是第六轮 03-1**
   （`docs/audit-6/findings/03-crypto-vault.md:32-63`，P3，含真实绑定流程复现）。**撤回，不报。**
2. **`ProxyFromEnvironment` 使地址闸门判定代理而非目标**：第五轮 FO-07，不报。
3. **`Issuer` 的 userinfo 形式（`https://x@127.0.0.1`）把用户令牌发到 authority**：第六轮已证，不报
   （Z09V-3 是它的**不同后果**，且第四轮未覆盖，故单独列出）。
4. **`NewService` 缺省 `HTTPClient` 是「有超时、无地址闸门」**：第五轮记为「判断」，报告正确未重报。
5. **kill switch 清扫不受 `TotalTimeout` 约束**：第六轮 `zz_audit_timeoutchain_test.go`，不报。

## 6. 判断（非 finding）

1. Z09V-1 的修法**涉及裁定**：把 401 从 host 熔断里挪出来，会削弱 P1-3 想要的「永久 401 源不烧超时」。
   我认为正确的语义是「凭据失败按 binding 计、host 失败按 host 计」，但这需要 ADR 级别的确认。
2. Z09-1 的修法「拒绝启动」vs「归一化」仍是裁定（我同意报告的倾向：与 `token_class` 同形 = 拒绝启动）。
3. 报告把 Z09-4 的触发前提写成「慢上游」偏保守；建议在收录时改成「大 body 并发读（≥4 MiB）即可」，更贴近实测。

## 7. 复核结论汇总

| 编号 | 原严重度 | 我的裁定 | 修正后 |
|---|---|---|---|
| Z09-1 | P2 | CONFIRMED（+ 发现 CS-4 文档断言为假） | P2 |
| Z09-2 | P3 | CONFIRMED | P3 |
| Z09-3 | P3 | CONFIRMED（记录了可上调 P2 的角度，维持 P3） | P3 |
| Z09-4 | P2 | CONFIRMED（前提比报告写的更宽） | P2 |
| Z09V-1 | — | 新发现 | P2 |
| Z09V-2 | — | 新发现 | P3 |
| Z09V-3 | — | 新发现（报告已披露但未编号，复核确认并建议编号） | P3 |

**四条被复核发现的机制全部复核为正确，未发现机制写错、未发现误报为文档化决定、未发现重报既有编号，
严重度无虚高。** 被复核报告的质量高于上一轮的区域报告；本轮真正的增量是 Z09V-1（P1-3 修复的跨账号后果）
与那条被证伪的 CS-4 书面断言。
