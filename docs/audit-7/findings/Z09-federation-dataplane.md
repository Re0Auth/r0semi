# 区域 Z09：联邦数据面 / 出站 / SSRF / 绑定生命周期 — 第七轮审计报告

## 范围与方法

**范围**：`internal/federation/*.go`（service/binding/bind/refresh/unbind/revocation/killswitch/missing/federation）、
`internal/httpapi/federation_routes.go`、`internal/httpapi/binding_routes.go`、`internal/safeurl/safeurl.go`、
`httpclient/*.go`、`cmd/re0auth/{config.go,main.go}` 的数据面装配、`docs/upstream-protocol.md`、
`docs/resilience-decision.md`、`config/re0auth.example.toml` 的 `[[sources]]` 段。

**方法**：数据面探针走**真实入口点**——`internal/httpapi.New` 起在 `httptest.Server` 上，背后是**真 OP**
（`internal/oidchttp` + `internal/store/memory` + 真 RSA signer），access token 经**真 authorize → callback →
token** 流程铸出；上游是**真 httptest 源**，经组合根同形的出站客户端
（`httpclient.NewOutboundClient{Breaker: &BreakerOptions{}}`，与 `cmd/re0auth/main.go:492-508` 一致）访问。
绑定生命周期中无法从 HTTP 面进入的两条（`BeginBind`/`CompleteBind` 的 retired 检查）走
`federation.Service` 的导出方法，并在报告里说明为什么这是等价入口（`handleBindStart` 是十行包装）。

**探针目录**：`internal/zzprobe/audit7/z09federationdataplane/`
（`doc.go` 带 `//go:build !audit7`，其余全部带 `//go:build audit7`）。

**跑过的命令**（全部在本机 Windows 11 / Go 1.27.1，**无 Docker、无本地 Postgres**）：

```sh
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z09federationdataplane/...
go build ./...      # exit 0
go vet ./...        # exit 0
go vet -tags audit7 ./internal/zzprobe/audit7/z09federationdataplane/...   # exit 0
gofmt -l internal/zzprobe/audit7/z09federationdataplane/                    # 空
git status --short  # 无任何被跟踪文件被修改
```

**没跑的**：全仓 `go test ./...`（并行代理共用工作区，按简报 §2 不跑）、任何需要真实 Postgres/容器的测试、
`-race`（本区除一条预算探针外都是单线程）。

**结果汇总**：4 条红探针（= 4 条 CONFIRMED 发现）、6 条绿探针（含 3 条阳性对照）。

---

## 发现

### Z09-1 `sources[].status` 从不校验：任何非字面 `retired` 的拼写都被静默当成「可服务源」，并且继续决定**另一个源**的 scope 闸门

- 严重度：**P2 中**（失败是静默的 ⇒ 按简报 §6 取本档上限；前提是操作者的一次拼写）
- 类别：安全 / 合规
- 不变量：fail-closed —— 「源的生命周期状态」这个操作者声明必须只接受文档化的词汇表
  （`docs/upstream-protocol.md` §10：`active → degraded → retired`），未知值必须被拒绝而不是被重新解释。
- 证据（执行过，FAIL）：
  - `internal/federation/federation.go:53-62` 的 `statusRank` 把 `""`/`active` 记 0、`degraded` 记 1、
    **`default` 记 2**；而「排除」只有一处判据：`service.go:515`/`:526`/`:564` 的
    `src.Status == StatusRetired`——**精确字符串比较**。`NewRegistry`（`federation.go:162-164`）只把空值
    归一成 `active`，对其它值**不做任何检查**。
  - 实测（真 HTTP 面，真令牌，真上游）：

    ```
    status="Retired": unpinned=200 Re0Auth-Source="src" | pinned=200 Re0Auth-Source="src" | /v1/sources says status="Retired"
    status="retired ": unpinned=200 | pinned=200 | /v1/sources says status="retired "
    status="disabled": unpinned=200 | pinned=200 | /v1/sources says status="disabled"
    对照 status="retired": unpinned=404 | pinned=410 | /v1/sources says status="retired"
    对照 status="":        unpinned=200（空值即 active，正确）
    ```
  - 第二个后果（同一根因，**拒绝方向**）：一个拼错的退役源**仍然参与闸门**，
    于是「退役一个源会静默改变另一个源的授权判据」（FO-V2 原形）：

    ```
    a-off status="retired"  → 200 Re0Auth-Source="b-live"（闸门不再要求 a-off 的 scope）
    a-off status="Retired"  → 403 scope_not_granted，body 明说 "...which source 'a-off' requires for this resource"
    ```
  - 反空转对照：`status="retired"` 的两种请求分别是 404/410、闸门不再含 a-off；
    `federation.SourceStatus("")` 被正确当成 active 且被服务 ⇒ 探针真的在区分这条判据，不是「一切都 200」。
  - 注册表侧（无服务器）实测：`"Retired"`、`"retired "`、`" RETIRED"`、`"disabled"`、`"off"`、`"Active"`、
    `"DEGRADED"`、`"degraded "` **全部被 `NewRegistry` 接受**。
  - 文档/配置的自相矛盾（这就是本条是「修不全」而不是「新需求」的原因）：
    `config/re0auth.example.toml:359-364` 紧挨着的两段注释——
    `token_class`（`:359-362`）写着「any other value is refused at startup（一个被读成 revocable 的拼写会把
    不可撤销的源报成『已撤销上游』）」，而 `status`（`:363-364`）只列 `active | degraded | retired`，
    **没有任何拒绝承诺**。
- 状态：**CONFIRMED**（真 HTTP 面 + 注册表层都执行过）
- 影响：
  - 运营者用 `status = "Retired"` / `"retired "`（尾随空格，复制粘贴最常见的形态）/ `"disabled"` 下线一个源
    （典型场景：源被入侵、停止合规、下游不再允许读取）时，**该源继续被选中、继续拿着用户的绑定令牌去读、
    响应照常 200**。`/v1/sources` 还会把 `"Retired"` 这种词表外的值**公开广播**给所有下游。
  - 反向：一个拼错的退役源继续进入 requirement 集合，使**另一个健康源**的读取被判 403——
    令牌明明持有实际服务方声明的 scope。这就是 FO-V2 说的「退役一个源会静默改变另一个源的授权判据」。
  - 同一件事的三个展示面（`candidates`、`Raw`、`bindingView.Bindable`（`httpapi/binding_routes.go:95`）、
    `MissingBindings`（`missing.go:71`））都用精确比较，所以它们**一致地**认为该源有效——问题不在某一处，
    而在「词汇表没有闸门」。
- 探针：`status_test.go::TestZ09StatusSpellingDecidesWhetherARetiredSourceStillServes`（红，含 2 条阳性对照）、
  `::TestZ09RegistryAcceptsAnyStatusSpelling`（红）、
  `::TestZ09AMisspelledRetirementStillDecidesAnotherSourcesGate`（红，含 1 条阳性对照）
- 修法建议（最小改法，与 token_class 完全同形，**不需要裁定**）：在 `NewRegistry` 里
  `switch s.Status { case "": s.Status = StatusActive; case StatusActive, StatusDegraded, StatusRetired:
  default: return nil, fmt.Errorf("federation: source %s: status %q must be one of ...") }`。
  这台机器上「拒绝启动」比「归一化」更符合本项目对 token_class 的既有选择（配置错误在启动时爆掉，
  而不是在请求路径上表现成别的东西）。**不要**只改 `statusRank` 去兜底：那会让拼写继续静默生效。
- 是否与既有编号相关：**是对 CS-4 / P2-x（`token_class` 既不校验也不默认）修复的补充**——
  同一次修复只覆盖了两个同类操作者声明中的一个；同时**是对 FO-V2 修复的补充**：
  「闸门排除 retired 源」只在精确拼写下成立。

---

### Z09-2 归一化读取没有「超过上限即拒绝」的判据：4 MiB 的上游响应体可以被静默截断后当成完整的 200 交回

- 严重度：**P3 低/提示**（对真实数据的损害有界：截断点落在 JSON 值的尾部空白里才可能通过 `json.Valid`；
  但它反驳了代码里写下的那条理由，且丢掉的是「完整/不完整」这个语义）
- 类别：安全 / 正确性
- 不变量：fail-closed —— 「超过上游响应上限的 body 一律报错，绝不作为完整响应交出」
  （这是第四轮 `18fed92` 在 raw 路径上立的规矩，它的提交信息原文：
  「a truncated body returned as a complete 200 claims a completeness it does not have」）。
- 证据（执行过，FAIL）：
  - `internal/federation/service.go:760-775`（`fetchResource`）：`reserve := reserveFor(resp, maxBody)` →
    `io.ReadAll(io.LimitReader(resp.Body, maxBody))` → 检查 `StatusCode` 与 `json.Valid`，
    **从不比较 `len(body)` 与 `maxBody`**。对照 `rawFetch`（`service.go:725-736`）：多读 1 字节 +
    `if len(body) > maxBody { return ErrResponseTooLarge }`。
  - 实测（真 HTTP 面，同一个上游、同一个 body）：

    ```
    normalized: upstream wrote 5242902 bytes, cap is 4194304, caller got 4194304: status=200 json.Valid=true
    raw control: status=502 detail="the source's response is larger than this proxy will pass through"
    ```
  - 该修复的注释（提交 `18fed92` 与 `service.go:713-719`）为归一化路径免除了这条判据，理由是
    「its body has to parse as JSON, and a cut one does not」。**这个理由不成立**：`json.Valid` 接受
    **尾随空白**，所以「一个完整 JSON 值 + 填充」这种 body 被从填充中间切断后仍然解析通过——
    探针构造的正是这个形状（`{"served_by":"padded"}` + 5 MiB 空格），下游拿到 200 + 4 MiB 截断体，无任何提示。
- 状态：**CONFIRMED**（真 HTTP 面）
- 影响：
  - 直接损害有界：能通过 `json.Valid` 的截断形状，数据本身通常已在截断点之前完整，被丢掉的是尾部空白。
    真正会丢数据的形状是「首 4 MiB 恰好构成一个合法 JSON 值、其后还有内容」（例如一个被上游拼接到一起的
    值序列，截断点落在某个 `}`/`]` 之后的换行上）——那种情况下下游会把第一段当成全部。
  - 更确定的是**契约与守卫的不对称**：同一个服务对同一种上游行为，一条读路径报 502、另一条答 200，
    而唯一的判据差别是「body 恰好能过 JSON 校验」。将来给 `maxBody` 加档、或给归一化路径加新的
    `Content-Type`（例如允许上游返回 JSON Lines 的扩展）时，这条缝隙会直接变成静默截断。
  - 修复成本极低（一行），所以留着它没有收益。
- 探针：`bodycap_test.go::TestZ09NormalizedReadServesAnOverCapBodyAsComplete`（红，含 raw 路径阳性对照）
- 修法建议（最小改法）：把 raw 的两行照搬过去——
  `body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))` 后
  `if len(body) > maxBody { return nil, ErrResponseTooLarge }`；`reserveFor` 已经是按 `readCap` 参数化的，
  传 `maxBody+1` 即可，预算语义不变。
- 是否与既有编号相关：**是对 `18fed92`（第四轮 raw 透传五处 fail-open）修复的补充**——
  同一类缺陷只修了 raw 一侧，且为该侧写的理由同样覆盖不了另一侧。

---

### Z09-3 已退役的源仍然可以被绑定：`BeginBind`/`CompleteBind` 不检查 `Status`，而展示层、选源层、raw 层都认为它不可用

- 严重度：**P3 低/提示**
- 类别：安全 / 正确性
- 不变量：**同一个对象上的资格判据必须只有一个**（FO-01 的判据，用在生命周期上）。
- 证据（执行过，FAIL；服务层导出入口 + 展示层阳性对照）：
  - `service.go:515/526/564`（`candidates`、`Raw`）拒绝精确 `retired`；
    `httpapi/binding_routes.go:95` 把 `bindable` 报成 false；
    `missing.go:71` 不把 retired 源列进绑定提示。四处一致。
  - `internal/federation/bind.go:127-152`（`BeginBind`）只检查 `registry.Get` 命中与 `ClientID`/`baseURL` 非空；
    `:171-178`（`CompleteBind`）只检查 flow 归属/期限/code 与注册表命中；**两条都没有状态检查**。
  - 实测：

    ```
    MissingBindings offers [live] for "phigros.profile.read"      ← 阳性对照：展示层确实不提供退役源
    BeginBind(live) = ok                                          ← 阳性对照：服务路径正常工作
    BeginBind(gone) → 成功，AuthorizeURL=https://gone.example/oauth/authorize?client_id=cid&...
        &redirect_uri=https%3A%2F%2Fre0auth.test%2Fauth%2Fupstream%2Fphigros%2Fgone%2Fcallback
        &scope=account.read+phigros.profile.read&state=bnd_47b1...
    ```
  - 手写的 `/bind?game=phigros&source=gone` 就是 `409 source_not_bound` 响应体里那种 `bind_url` 的形状
    （`internal/httpapi/federation_routes.go:200-206`），所以「进不去」不成立。
- 状态：**CONFIRMED**（服务层导出入口实测；`CompleteBind` 那一半是读码到行——同一次 `registry.Get`
  之后没有状态判据，`bind.go:192-197` 紧接着 `vault.Enroll` 上游令牌）
- 影响：用户在一条服务端明明认为「不可用」的源上完成授权后，Re0Auth 会把**该源的上游令牌存进 vault**
  （信封加密），而数据面永远不会用它（`candidates` 不选、`Raw` 拒绝）。结果是：
  一份永不使用的上游凭据长期留在 vault 里、账号页把它显示成 `configured=true, bindable=false` 的自相矛盾行；
  运营者对退役源的处置（「不再有任何交互」）被绕过一半。破坏面比 FO-01 小得多（没有跨源数据读取），
  所以定 P3。
- 探针：`bind_test.go::TestZ09ARetiredSourceCanStillBeBound`（红，含 2 条阳性对照）
- 修法建议（最小改法）：`BeginBind` 在 `registry.Get` 之后加
  `if src.Status == StatusRetired { return BindChallenge{}, ErrSourceRetired }`；
  `CompleteBind` 在 `bind.go:171-174` 之后再查一次（flow 可能有 10 分钟寿命，期间源可能被退役）。
  `handleBindStart` 已经把所有错误统一成 400，无需改 HTTP 层。
- 是否与既有编号相关：**是 FO-V2 / P1-5 一族（「闸门与选源判据必须同源」）的补充**，
  对象从「scope 闸门 vs 选源」换成「绑定资格 vs 选源」；无重报。

---

### Z09-4 上游响应预算没有按调用方分摊，且预留发生在收到第一个 body 字节之前：**15 个零字节的并发读**就能把**其他用户**的满额读全部 shed 成 503

- 严重度：**P2 中**（一次登录/任何一个持 token 的下游即可造成数据面全局可用性下降；无数据泄露、无鉴权绕过。
  按简报 §6「低门槛前提」的口径可上调 P1，我保守定 P2 并写明理由）
- 类别：可用性 / 性能·资源
- 不变量：fail-closed 且有界 —— 「在途 × body 上限」必须被约束（P0-3 立的就是这条），
  **且一个调用方不能凭自己的在途量决定别人的成败**。前半条满足，后半条不成立。
- 证据（执行过，FAIL；**使用出厂默认预算，未调 `MaxBufferedBytes`**）：
  - `service.go:30` `defaultMaxBufferedBytes = 64 << 20`（出厂 `config/re0auth.example.toml:69`
    也显式写了 `max_upstream_buffer_bytes = 67108864`）；`service.go:24` `maxBody = 4 << 20`。
  - `service.go:108-113` `reserveFor`：`ContentLength` 未知（chunked/被压缩）时预留**整个 cap**；
    `service.go:725-729`（raw）与 `:760-764`（normalized）在**读之前** `acquire`，
    `acquire`（`:71-82`）满了就 shed，**从不排队、也没有 per-subject 配额**。
  - 实测（真 HTTP 面，两个不同用户、两个不同源；攻击者的 16 个 raw 读各自在「上游发完响应头就挂住」的
    源上占住预留——**零字节 body 传输**）：

    ```
    基线（无并发）：被攻击者用户的归一化读 = 200
    16 个 sleeper 在途：unrelated user's read = 503（temporarily_unavailable，Retry-After: 1）
    释放 sleeper 之后：同一个读 = 200
    ```
  - 算术（可复核，确定性）：预算 67 108 864；raw 预留 = `maxBody+1` = 4 194 305；
    15 × 4 194 305 = 62 914 575，剩余 4 194 289；归一化读在 Content-Length 未知时预留 `maxBody` = 4 194 304，
    **比剩余多 15 字节** ⇒ 被 shed。第 16 个 sleeper 自己也拿不到预留，所以「15 个在途」就是上限。
  - 前提都是出厂值：`cmd/re0auth/main.go:71-75` `federationMaxConcurrent = 256`、
    示例配置 `max_in_flight = 512`，都远高于 15；限流按秒计，占住 15 个连接不需要额外速率。
- 状态：**CONFIRMED**（真 HTTP 面，出厂默认预算，含基线与释放后的两条对照）
- 影响：
  - 任何持有一个 access token 的调用方（下游 RP 的正常用户即可）打开 15 个「慢上游」raw 读，
    在最长 `TotalTimeout`（45s）内**持续让所有其他用户的、预留满额的数据面读取返回 503**；
    成本是 15 个 socket 和让上游推迟发送 body（真正需要的是「响应头已到、body 不来」，这是慢上游或
    攻击者自建的源都能给出的形状）。这是整条数据面的可用性，不是单个用户的；
  - 「shed 而不排队」的方向本身是 P0-3 记录过的有意取舍，账也算得对（不 shed 就 OOM）。
    **没有记录过的是分摊**：预算是全局先到先得，而 `bufferBudget` 的注释只讨论了「按字节而不是按请求数」。
  - 附带：被 shed 的调用方收到的是 `temporarily_unavailable`，它无从知道这是**别人**造成的。
- 探针：`budget_test.go::TestZ09SleeperReadsShedAFullCapReadForAnotherUser`（红，含基线/释放后两条对照）
- 修法建议（**涉及裁定**，三个方向语义不同）：
  ① 按调用方（subject 或 client）分摊预算配额，超配额者 shed —— 保住 fail-closed 且给出公平性；
  ② 预留改为「按声明的 Content-Length 预留、读到再补」，或把预留挂在**已读字节**而不是上限上
     （代价是上限不再等于内存不变量，需要重新推导 `MaxBufferedBytes` 的容量公式）；
  ③ 对「body 迟迟不来」单独设一个比 `TotalTimeout` 短得多的首字节期限（很多慢源问题都是这一条解决）。
  无论哪条，都要在 `Config.MaxBufferedBytes` 的注释里把「这是全局先到先得的预算」写明。
- 是否与既有编号相关：**是对 P0-3 / B-3（在途 × body 无联合上限）修复的补充**——
  同一处代码、相反方向的后果：修复把「无界」改成「有界且会 shed」，本条指出该界没有分摊，
  一个调用方可以决定别人的成败。不是重报。

---

## 探过但没破的（也应变成守卫）

1. **上游令牌里的 CRLF 不能注入出站请求头。**
   攻形：上游在 token 响应里发 `access_token = "tok\r\nX-Injected: 1"`，数据面把它拼进
   `Header.Set("Authorization", "Bearer "+token)`。实测：调用方拿到 **502**，上游**一个请求都没收到**
   （`upstream requests: []`）——Go 的 client 在写请求时校验 header value 并直接报错，请求根本没出网。
   探针：`held_test.go::TestZ09AnUpstreamTokenCannotInjectAHeader`（绿）。
   *建议保留为守卫*：这条正是「源的响应是攻击者可控内容」最直接的形状。

2. **raw 透传不泄漏上游的 Set-Cookie / Location / CORS / 自定义内部头。**
   实测：源返回 `Set-Cookie: sid=upstream-secret`、`Location`、`Access-Control-Allow-Origin: *`、
   `X-Upstream-Internal: 10.0.0.5`、`Content-Type: text/plain`、body `hello` 时，下游只拿到
   `Content-Type: text/plain` + `Cache-Control: no-store` + `Re0Auth-Source`；四个头一个都没出现。
   探针：`held_test.go::TestZ09RawResponseDoesNotLeakTheSourcesHeaders`（绿）。

3. **源名（未校验的操作者输入）不能注入响应头。**
   `NewRegistry` 接受 `Name: "src\r\nX-Injected: 1"`（FO-04 的已知缺口），而
   `w.Header().Set("Re0Auth-Source", ...)` 写出的值被 net/http 的换行替换成空格：
   实测 `Re0Auth-Source="src  X-Injected: 1"`、`X-Injected=""`。
   探针：`held_test.go::TestZ09ASourceNameCannotInjectAResponseHeader`（绿）。
   *注意*：值被「压平」而不是被拒绝，所以畸形源名会静默出现在下游响应头里——这是 FO-04 的附表，不是新发现。

4. **raw 路径无法离开配置的 base（host 与路径前缀都不变）。**
   实测（上游侧记录的真实 RequestURI）：
   `..%2f..%2fadmin` / `%252e%252e%252fadmin` / `..%5c..%5cadmin` / `..;/admin` → **400 + 上游零请求**；
   `%2F%2Fevil.example%2Fx` → `/native/evil.example/x`；`http:%2F%2Fevil.example%2Fx` →
   `/native/http:/evil.example/x`；`@evil.example%2Fx` → `/native/@evil.example/x`（全在 `/native/` 前缀内）。
   探针：`held_test.go::TestZ09RawPathCannotEscapeTheSourcesBase`（绿）。
   **更正第五轮报告的一处结论**：`internal/zzprobe/federation` 第五轮报告写「`?` / `#` 无法注入，
   因为 `url.PathEscape` 会编码它们」——`rawFetch` 里**没有** `PathEscape`（`service.go:690-700` 是
   `path.Clean` 之后直接拼接），实测 `x%3Fy=1` → 上游看到 **`/native/x?y=1`**，
   即解码后的 `?` 成了真正的查询分隔符。**这不构成发现**：host 与 base 前缀未变，而查询串本来就是
   调用方完全可控的（`RawRequest.Query` 就是 `r.URL.Query()`），把「路径里的一段」变成「查询」不多给任何权限。
   记在这里是因为它说明该处的「路径」分析单位并不是上游收到的 request-target。

5. **P1-3 的修复（401 计入熔断）确实生效。**
   攻形：对同一个源连续 8 次读，源永远回 401（绑定无 refresh token，所以 `callWithRefresh` 不会去轮换）。
   实测：上游只被拨打 **5** 次（`WithFailureThreshold(5)` 打开的正是第 5 次失败），第 6–8 次读在
   `RoundTrip` 之前就被 `ErrCircuitOpen` 拒绝。若 401 不计入失败，这里会是 8 次。
   探针：`held_test.go::TestZ09ASourceThatAlwaysAnswers401TripsTheBreaker`（绿）。
   *这也是本轮「前轮修复复核」的正面结论之一*。注意本探针用的是组合根同形的客户端
   （`Breaker: &httpclient.BreakerOptions{}`）；只传 `OutboundConfig{}` 时**根本没有熔断器**
   （`httpclient/outbound.go:312-315`），这是夹具必须显式接线的原因，也值得在 ADR 里再写一句。

6. **归一化路径的 scope 闸门与选源判据（P1-5 / FO-01）在本轮复核下仍然同源。**
   闸门要求**每个候选源**的 scope（`federation_routes.go:105-122` + `service.go:384-410`），
   候选集由 `candidates()` 给出（排除精确 retired、按状态排序），与 `Fetch` 用的是同一个函数。
   本区块的 Z09-1 说明这个「排除」在拼写变体下失效，但就 P1-5 本身（跨源 scope 混淆）而言，
   第五轮的修法在精确配置下是完整的：一条只持 A 源 scope 的令牌读不到 B 源的数据。

---

## 未能到达（残余盲区）

1. **真实 Postgres 侧**（本机无 Docker、无本地 Postgres）：`federation.Bindings.PutIfVersion` 的
   单条条件 UPDATE、`ListAllPage` 的 keyset 游标在「边扫边删」下的单调性、`federation_bind_flows`
   的到期清扫（`postgres/sweep.go:31` 确实列了这张表）、以及 PG 侧 `Get` 把 `pgx.ErrNoRows` 映射成
   `ErrNotBound`（`postgres/federation.go:26-28`，读码已确认）都只有读码级证据。
   **要证实需要** CI 的 `postgres:16`（`TEST_DATABASE_URL`）。
2. **`-race` 未跑**：本区探针除 Z09-4 的预算竞态外都是单线程。`keyedMutex` 的引用计数回收、
   `bufferBudget` 的加减、熔断器 host map 都没有竞态检测器背书（第六轮的 `zz_audit_race_test.go` 覆盖过，
   本轮未复跑）。
3. **拨号层的私网闸门本轮没有重测**：我的夹具必须连 `httptest` 的 loopback 源，所以
   `TransportConfig.DenyPrivateAddresses` 取的是零值（false）——与**生产组合根相反**
   （`cmd/re0auth/main.go:507` 传 `!cfg.AllowPrivateUpstreams`）。因此本报告里没有任何
   「地址闸门挡住了 X」的结论：十进制/八进制/十六进制 IPv4 字面量、IPv6 zone、IPv4-mapped、
   尾点、userinfo、23 个重定向变体全部是第五轮的结论，我没有重做。
   同一原因：无法构造真实 DNS rebinding（需要控制权威 DNS 或 hosts），
   只能引用 `outbound.go:93-102` 的「解析后、拨号前」控制钩子这一读码结论。
4. **`unix` socket 网络**：`denyPrivateAddress`（`outbound.go:157-161`）对 `unix` 直接放行，
   但 Go 的 `http.Transport` 不会用它，构造不出来。
5. **出厂 256 的出站 bulkhead 路径未跑**：Z09-4 的探针用的是无 bulkhead 的客户端
   （`MaxConcurrent` 为 0）。生产是 256（`main.go:75`），15 远低于它，所以结论不受影响，
   但我没有真的在 256 下跑一遍。
6. **发现驱动的源注册表不存在**（`docs/upstream-protocol.md` 开头自述），所以
   「一份恶意发现文档能否让 Re0Auth 调用配置外的端点」今天仍无从到达。
   记一句给将来的实现者：注册表一旦接管 `issuer` / `endpoint` 这些字段，本轮 Z09-1 与
   FO-04 里那些「配置畸形」就会从「操作者手误」升级成「远程可控值」——
   做发现驱动注册表之前，应先把 `federation.NewRegistry` 的字段校验补齐。

---

## 对既有编号 / 前轮探针的复核附注（**不作为本轮发现**）

1. **`Source.Issuer` 不做绝对 http(s) 校验——第六轮探针已覆盖，我不重报。**
   `internal/federation/zz_audit_issuer_userinfo_test.go`（`//go:build audit6`，工作区未跟踪）
   已经证明：`NewRegistry` 接受 `https://api.next-phi.example@127.0.0.1:PORT`，随后
   `fetchResource` 把用户的 bearer 令牌发到 `u.Host` 那个 authority；同时对照了
   `validateRawBase` 会拒带 query 的 base。我复核了这条代码路径，结论一致：
   `validateRawBase` 的校验（`federation.go:207-220`）**只挂在 `RawBase` 上**，
   `Issuer` 只要求非空（`federation.go:144-146`）。
   **它没有覆盖到的两个角度**（留给该条的负责人，不计入本轮 findings）：
   - `Issuer: "//evil.example"` 会被接受，而 `BeginBind` 的 `AuthCodeURL` 产出 scheme-relative 的
     authorize URL，`handleBindStart` 直接 `http.Redirect(..., 302)`（`federation_routes.go:364`）——
     浏览器会**跨 origin** 跳到 `evil.example`。这是**绑定流程**上的开放重定向/钓鱼面，
     与第六轮证明的「令牌外流」是不同的后果（不泄漏凭据，但把用户的登录流程交给第三方 origin）。
   - `Issuer` 自带 `?`/`#`（`https://api.example/v1?x=1`）时，`fetchResource` 的
     `Issuer + "/resources/<name>"` 会把资源路径吞进查询串（与 `validateRawBase` 注释描述的
     `raw_base` 失效模式逐字同形），上游请求变成一个带奇怪 query 的 `/v1`——静默读错 URL。
2. **FO-03（`IsPublicAddress` 漏 `0.0.0.0/8`）在 HEAD 上仍未修**：`httpclient/outbound.go:117-128`
   的 `nonPublicPrefixes` 里没有 `0.0.0.0/8`。我不重报。**同类的缺项还有**（同一函数、同一修法，
   一并交给该条的负责人）：`fec0::/10`（已废弃的 site-local）、`2001:10::/28` 与 `2001:20::/28`（ORCHID）、
   `3fff::/20`（RFC 9637 新分配的文档段）、`2001:2::/48`（基准测试）。
3. **`federation.NewService` 在 `HTTPClient` 缺省时给出的是**「有超时、无地址闸门」的客户端**
   （`service.go:288-298`）——第六轮 `zz_audit_fallbackclient_test.go` 已证，第五轮也把它记为「判断」而非发现。
   我不重报，只补一句可执行的收敛方向：把 `idp/idp.go:253-257` 的做法（硬编码
   `DenyPrivateAddresses: true`）搬过来，让「忘了传客户端」的调用方拿到 fail-closed 而不是 fail-open 的默认值。
4. **kill switch 的清扫不受 `TotalTimeout` 约束**——第六轮
   `zz_audit_timeoutchain_test.go` 已证（`RevokeAllBindings` 没有被 `withinTotalTimeout` 包装，
   而 `service.go:253-264` 的文档说它约束「ONE data-plane request」）。不重报。

---

## 判断（文档化决定可否质疑，不是 finding）

1. **数据面刻意不重试（FO-05）我认为是对的**，而且 `docs/source-onboarding.md:225` 至今仍对第三方源承诺
   「指数退避重试」——这是**文档**问题，不是代码问题：旋转型单次 refresh 不可重放，
   重试 `invalid_grant` 只会加剧轮换 churn。建议直接把那句话删掉，并在
   `docs/resilience-decision.md` 的「明确不做」一节写明理由（该 ADR 目前没提数据面不重试）。
2. **raw 透传的 scope 闸门是「源的任一资源 scope」**（`federation_routes.go:250-265` 自述
   「A dedicated `<game>.raw.read` scope is future work」，`threat-model.md` §9 登记了边界）。
   这是文档化决定，我不当发现。但要指出它没写清的那一半：闸门是**跨资源**的——
   持有 `phigros.profile.read` 就能走该源**整个**原生 API（包括该源用别的 scope 保护的写路径，
   只要源接受）。建议至少把「要 raw 一个源需要哪些 scope」写进 `openapi.yaml` 的端点说明。
3. **`Config.KillSwitchPageSize` 同时是运维配置和测试便利旋钮**（`service.go:226-229`）：
   一个部署把它设成 1 就是对源串行轰炸。建议降为内部 Option（同 FO round-5 的判断）。
4. **Z09-1 的修法是「拒绝」还是「归一化」是个裁定**：我建议与 `token_class` 同形（拒绝启动），
   因为本项目的既定选择就是「配置错误在启动时爆掉」；归一化（`strings.TrimSpace` + 大小写折叠）
   会把一个本来就不该存在的状态变成合法状态，但能让现存配置平滑过渡。二者只有一个能被选。
5. **Z09-4 的修法更是裁定**：它触到 P0-3 建立的容量不变量
   （`MaxBufferedBytes <= 容器上限 - 运行时开销`）。若选择「按已读字节预留」，
   那个公式必须重写；若选择「per-subject 配额」，要为配额之和留出余量。这不是顺手一改。
6. **`httpclient` 库级 `DenyPrivateAddresses` 默认 false**（`outbound.go:46-48`）与本仓库唯一的生产组合根
   （显式打开）之间的落差，已在第五轮记为判断。我同意那个结论，但要补充一个**可测量的**风险面：
   本仓库现在有两个 `NewOutboundClient(OutboundConfig{})` 调用点
   （`service.go:296` 与任何将来新增的），它们都是 fail-open 的。把安全放在调用方而不是默认值里，
   与 `idp/idp.go:243-257` 的注释（「a caller that forgets to pass one should not silently get the
   unhardened default client」）自相矛盾——建议把默认值改成 fail-closed，
   私网源改为显式 opt-in（`allow_private_addresses` 已经就是这个形状的开关）。
