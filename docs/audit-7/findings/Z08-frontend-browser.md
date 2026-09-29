# 区域 Z08：frontend-browser — 第七轮审计报告

> 审计对象：`C:\git\r0semi`，HEAD = `bf81b2a`（工作区对本轮**零个被跟踪文件被修改**：`git status --porcelain` 里唯一的新增都是审计产物）。
> 探针目录：`internal/zzprobe/audit7/z08frontendbrowser/`（除 `doc.go` 带 `!audit7` 外全部 `//go:build audit7`）。
> 验证命令：`go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z08frontendbrowser/...`
> 结果：**10 条红探针 / 8 条独立发现**，29 条绿探针（见「探过但没破的」）。
> `gofmt -l` 对本目录干净；`go build ./...`、`go vet ./...` 均 exit 0。

## 范围与方法

**读了什么**：`web/**`（全部 22 个 `.ts/.svelte/.html` 源文件、`vite.config.ts`、`app.html`、`playwright.config.ts`、`e2e/*.ts`）、
`internal/webui/`（`webui.go` + `dist/`）、`internal/httpapi/`（`server.go` 的 `/app/*` 挂载与三平面路由、`middleware.go`、
`authorization_routes.go`、`device_routes.go`、`binding_routes.go`、`federation_routes.go`、`grants_routes.go`、`identity_routes.go`、
`account_routes.go`、`admin_routes.go`、`session_routes.go`、`responses.go`）、`internal/compress/`、`internal/auth/auth.go`、
`internal/safeurl/`、`internal/oidchttp/oidchttp.go` 的 `DescribeAuthorization`/`ApproveAuthorization`、`oauth/scope.go`、
`internal/oidcstore/oidcstore.go` 的 `SplitProtocolScopes`、`cmd/re0auth/main.go` 的注册表装配、
`docs/browser-plane-decision.md`、`docs/cors-decision.md`、`.github/workflows/ci.yml`、`Makefile`、
以及依赖源码 `alexedwards/scs/v2@v2.9.0`。另读了第五轮 `docs/security-audit-5.md` / `AUDIT-ISSUES.md` 与第六轮汇总的编号，确保不重报。

**跑了什么**（三条独立路径）：

1. **`internal/webui.Handler` + 完整 httpapi 中间件链，喂合成构建树**（`testing/fstest.MapFS`，
   `newZ08Env(z08Options{Frontend: fsys})`）。这样探针在一台从没跑过 `pnpm build` 的机器上也确定，且看到的是生产中间件链
   （三平面路由、安全头、压缩）。用于：静态面调查、遍历矩阵、缓存/Range/缺失 asset、`Vary`。
2. **真实嵌入构建 + 真 OP 全接线**：`webui.FS()`（本机 `internal/webui/dist` 是 HEAD `bf81b2a` 的产物——dist 的 mtime 2026-09-29 18:44 晚于最后一次提交 16:23，
   也晚于全部 `web/src` 的 mtime，所以它不是陈旧产物）；OP 用 `internal/testoidc` + `memory.NewOIDCStore` + `oidchttp.New`，
   按 `cmd/re0auth` 的 `openOIDC` 形状装配，`Login` 钩子复刻了 `sessions.Bind(ctx,"authz",id)`。
   用于：CSP 头/meta 交集与内联脚本哈希、同意页「展示 vs 授予」的端到端流、设备页、CSRF 全量走查。
3. **真进程黑盒**：`go build ./cmd/re0auth` 后在内存模式（只给环境变量、无配置文件）起在 **127.0.0.1:17801**（区 08 分配端口），
   用真 `net/http` 客户端打。用于：所有静态面结论在「组合后的二进制」上复核。
4. **真浏览器**：本机 **Playwright 浏览器其实是装好的**（`%LOCALAPPDATA%\ms-playwright\chromium-1243`，与简报的假设不同）。
   我用一个仓库外的一次性脚本（同内容存于探针目录 `browser_probe.mjs`，供复核者重跑）对着上面的真进程跑 Chromium，
   得到 CSP 真实生效与 `?error=` 反射的两条浏览器级证据。

**没做什么**：**没有修改任何被 git 跟踪的文件**；**没有修任何 bug**；没有跑全仓 `go test ./...`（只在最后跑了 `go build ./...` 与 `go vet ./...`）；
没有跑 `pnpm e2e`（它会自建 18098/18099 上的服务器，与并行代理抢端口）。

---

## 发现

### Z08-1 静态资源命名空间里缺失的 hashed asset 回 **200 + SPA shell**，不是 404
- 严重度：**P3 低/提示**（但「失败是静默的」，见影响）
- 类别：可用性 / 可维护性
- 不变量：fail-closed（错误必须可观测）
- 证据（两条路径都跑过并失败）：
  - 合成树 + 全接线：`go test -tags audit7 -run TestZ08MissingImmutableAssetIsNotASilentShell -v`
    ```
    GET a hashed asset URL that names no file answered 200 "text/html; charset=utf-8" with 144 bytes of the shell
    --- FAIL: TestZ08MissingImmutableAssetIsNotASilentShell
    ```
    `TestZ08StaticServingSurvey` 的原始观测：`GET /app/_app/immutable/entry/start.MISSING.js -> 200 ct="text/html; charset=utf-8" cc="no-cache" len=144`
    （对照组：`start.abc.js` → 200 + `text/javascript` + `public, max-age=31536000, immutable`，说明探针确实在走文件服务，不是空跑）。
  - 组合后的真二进制（17801）：`TestZ08RealProcessAnswersAMissingAssetWithTheShell`
    ```
    GET a missing immutable asset -> 200 ct="text/html; charset=utf-8" cc="no-cache" vary="Cookie, Accept-Encoding" len=3304
    --- FAIL: TestZ08RealProcessAnswersAMissingAssetWithTheShell
    ```
    `len=3304` 就是 `internal/webui/dist/index.html` 的长度，即整个 shell。
  - 机制（`internal/webui/webui.go:119-127`）：`if name == "" || name == "." || !isFile(fsys, name) { name = "index.html" }`
    —— 回退**不区分**「客户端路由」与「hashed 资源命名空间」。
- **状态**：CONFIRMED
- **影响**：`/app/_app/immutable/*` 是内容哈希命名空间，正常部署下它里面的 URL 要么存在要么属于旧构建。
  现在它永远回 200：**任何只看状态码的监控/探活/合成监测都看不到「前端没发全」**；浏览器侧拿到的是 `text/html`，
  ES module 会因 MIME 校验失败而中止，页面白屏——用户看到的现象与 404 一样坏，但**运维端没有任何信号**，
  排障会从「前端 bug」开始查而不是「发布不完整」。这是简报 §6「失败是静默的 ⇒ 严重度升」的典型形状，
  所以我把它从「纯卫生问题」提到 P3 并单独列条（唯一让它不升到 P2 的是：用户可感知后果与 404 相同，损失有界）。
- **探针**：`frontend_handler_test.go::TestZ08MissingImmutableAssetIsNotASilentShell`（红）、
  `realproc_test.go::TestZ08RealProcessAnswersAMissingAssetWithTheShell`（红）；对照绿：
  `frontend_handler_test.go::TestZ08StaticServingSurvey`、`realproc_test.go::TestZ08RealProcessServesTheShellWithItsOwnPolicy`
- **修法建议**：在 `webui.Handler` 里把「回退到 shell」限制在**客户端路由**上，最小改法是给资源命名空间一条 404：
  ```go
  if !isFile(fsys, name) {
      // A hashed asset that is not there is a broken build, not a route.
      if strings.HasPrefix(name, "_app/") {
          http.NotFound(w, r)   // 浏览器面形状，与 handleNotFound 一致
          return
      }
      name = "index.html"
  }
  ```
  （`_app/` 是构建产物自己的命名空间，前端不会有名为 `_app` 的客户端路由；若担心，可再加一条「最后一段含 `.` 也回 404」。）
- **是否与既有编号相关**：无。这不是重报：`webui.go` 的注释只为「客户端路由」写了理由，本条的射程是 hashed 资源命名空间，
  以及它对运维可观测性的后果。

### Z08-2 shell 标了 `no-cache` 却没有任何校验器，因此永远不可能变成 304
- 严重度：**P3 低/提示**
- 类别：性能
- 不变量：性能/资源
- 证据（红）：
  ```
  $ go test -tags audit7 -run TestZ08ShellIsRevalidatableWithoutRefetching -v
  the shell answers "no-cache" with neither ETag nor Last-Modified, so `no-cache` can never become a 304:
  every navigation and every refresh re-sends the whole document (144 bytes here)
  --- FAIL
  ```
  真进程侧观测（`TestZ08RealProcessServesTheShellWithItsOwnPolicy` 的日志）：
  `GET /app/consent -> 200 ct="text/html; charset=utf-8" cc="no-cache" ... etag=""`。
  机制：`internal/webui/webui.go:147-148` 只设 `Cache-Control: no-cache`；文档由 `http.ServeFileFS` 送出，
  而 `embed.FS` 的 `FileInfo.ModTime()` 是零值，所以 stdlib **不会**发 `Last-Modified`，项目也没有自己算 `ETag`，
  于是 `no-cache`（=「每次必须重新验证」）退化成「每次必须重新下载」。
- **状态**：CONFIRMED
- **影响**：近 3.3KB（gzip 后约 1.4KB）的文档在**每一次页面加载/刷新/新标签**都要重传。对以「一个二进制、自带前端」为卖点的服务，
  这是纯浪费的往返与字节；对移动网络更明显。没有安全后果。
- **探针**：`frontend_handler_test.go::TestZ08ShellIsRevalidatableWithoutRefetching`（红）；
  旁证绿：`TestZ08ImmutableAssetIsConditionallyFetchable`（immutable 资源的缓存指令确实生效，所以问题只在校验器）
- **修法建议**：在 `setCacheHeaders` 里为 `index.html` 补一个内容校验器——嵌入文件没有 mtime，最省事的是
  `w.Header().Set("ETag", `"`+shellETag+`"`)`，其中 `shellETag` 由构建时或 `FS()` 初始化时对 `index.html` 求一次 sha256 得到（启动时算一次，之后零成本）。
- **是否与既有编号相关**：无。

### Z08-3 除 `_app/immutable/` 与 `index.html` 外，静态文件**没有任何 `Cache-Control`**
- 严重度：**P3 低/提示**
- 类别：性能 / 可用性
- 不变量：性能/资源
- 证据（红）：`TestZ08NonShellStaticFilesDeclareACachePolicy`
  ```
  /app/favicon.svg is served with no Cache-Control at all (ct="image/svg+xml")
  /app/_app/version.json is served with no Cache-Control at all (ct="application/json")
  --- FAIL
  ```
  真进程复核（`TestZ08RealProcessStaticSurfaceSurvey`）：
  ```
  GET /app/favicon.svg    -> 200 ct="image/svg+xml"               cc=""
  GET /app/robots.txt     -> 200 ct="text/plain; charset=utf-8"   cc=""          <- /app 下的副本
  GET /robots.txt         -> 200 ct="text/plain; charset=utf-8"   cc="public, max-age=3600"  <- 根上的副本有
  ```
  机制：`setCacheHeaders`（`webui.go:143-150`）只处理 `_app/immutable/` 前缀与 `index.html`；
  对照 `/robots.txt` 的处理器（`server.go:557-561`）**显式**写了 `public, max-age=3600`——同一批文件两种待遇，
  说明这是漏了而不是决定。
- **状态**：CONFIRMED
- **影响**：这几个响应没有声明新鲜度，缓存只能按各浏览器自己的启发式规则猜（Chrome 与 Safari 的策略不同），
  行为不可预测；`_app/version.json` 尤其敏感：SvelteKit 的部署探测就读它，**一个被中间缓存留住的旧 version.json 会让客户端永远发现不了新部署**
  （注：本机构建里客户端没有轮询它——grep 构建产物无 `version.json` 引用——所以今天只有潜在风险，一旦将来打开轮询就立刻成立）。
- **探针**：`frontend_handler_test.go::TestZ08NonShellStaticFilesDeclareACachePolicy`（红）
- **修法建议**：在 `setCacheHeaders` 里把默认值写成「除 `_app/immutable/` 外一律 `no-cache`」（`favicon.svg` 可给 `max-age=3600`，
  `_app/version.json` 必须 `no-store`），把「有缓存指令」变成规则而不是两个特例。
- **是否与既有编号相关**：无。（第五轮 `A5-4`/一轮的 `no-store` 覆盖讲的是 `/v1` 平面，不是 `/app` 静态面。）

### Z08-4 Range 请求可以把 **shell 的字节切片**当成缺失 asset 的 206 返回
- 严重度：**P3 低/提示**
- 类别：可用性 / 可维护性
- 不变量：fail-closed
- 证据（红，两条路径）：`TestZ08RangeOnTheShellCannotSpliceAssets` /
  `TestZ08RealProcessRangeOnAMissingAssetSplicesTheShell`
  ```
  range over a missing asset -> 206 ct="text/html; charset=utf-8" cr="bytes 0-9/144"  len=10      (合成树)
  range over a missing asset -> 206 ct="text/html; charset=utf-8" cr="bytes 0-15/3304" body="<!doctype html>\n"  (真二进制)
  --- FAIL 两条
  ```
  机制：`http.ServeFileFS` 支持 Range，而 Z08-1 已经把请求名换成了 `index.html`，于是 Content-Range 声明的是 shell 的长度、
  Content-Type 是 `text/html`，字节是 `<!doctype html>`。
- **状态**：CONFIRMED
- **影响**：任何按 Range 分片取资源的客户端（Service Worker 的缓存填充、分片下载器、某些构建期校验工具）
  看起来「脚本区间取回来了」，拿到的却是 HTML。它是 Z08-1 的一个次生形状：**同一个根因，两种观测**。
  单独列条是因为修法不同（Z08-1 的 404 顺带修掉它，但若只按扩展名判断而漏掉 Range 的判定顺序，这条会独立复现）。
- **探针**：`frontend_handler_test.go::TestZ08RangeOnTheShellCannotSpliceAssets`（红）、
  `realproc_test.go::TestZ08RealProcessRangeOnAMissingAssetSplicesTheShell`（红）
- **修法建议**：Z08-1 的 404 即可；额外可选：回退到 shell 的那条分支上 `w.Header().Set("Accept-Ranges", "none")`。
- **是否与既有编号相关**：无（与 Z08-1 同根因，显式标注为同一处的第二面）。

### Z08-5 `_app/immutable/*` 标了 `public, max-age=31536000, immutable`，却同时带 `Vary: Cookie`——共享缓存语义被静默取消
- 严重度：**P2 中**（**安全影响为零**；定 P2 的是「部署成本确定 + 失败静默」）
- 类别：性能
- 不变量：性能/资源
- 证据（红）：
  ```
  $ go test -tags audit7 -run TestZ08ImmutableAssetsDoNotVaryOnTheSessionCookie -v
  /app/_app/immutable/entry/start.abc.js is served with Cache-Control
  "public, max-age=31536000, immutable" and Vary "Cookie, Accept-Encoding":
  the session middleware adds Vary: Cookie to every response before any handler runs,
  so a shared cache keys a content-hashed, user-independent asset on the session cookie
  shell Cache-Control="no-cache" Vary="Cookie"; asset Cache-Control="public, max-age=31536000, immutable" Vary="Cookie, Accept-Encoding"
  --- FAIL
  ```
  组合后的真二进制同样命中（`TestZ08RealProcessServesTheShellWithItsOwnPolicy` 的断言）：
  `GET /app/_app/immutable/entry/start.DJJzSbG0.js -> 200 ... cc="public, max-age=31536000, immutable" vary="Cookie, Accept-Encoding"`。
  机制（依赖源码，逐行读到）：
  - `internal/httpapi/server.go:616-619`：`h = s.sessions.LoadAndSave(h)` 包住**整棵树**，`/app/*` 也在里面；
  - `internal/auth/auth.go:119-120`：`LoadAndSave` 直接委托给 `alexedwards/scs`；
  - `scs/v2@v2.9.0/session.go:139`：`w.Header().Add("Vary", "Cookie")`，**在任何处理器运行之前，对每个响应无条件执行**；
  - 因此 `internal/webui/webui.go:146` 精心设下的 `immutable` 与它并存，而 `Vary: Cookie` 的含义是「这个响应随 Cookie 头变化」——
    对一个内容哈希、与用户无关的资源来说这句话是假的。
  `grep -rn Vary internal/ oauth/ cmd/`（排除审计探针自身）在**非测试的项目代码里只在 `internal/compress/compress.go` 命中**；
  `internal/httpapi` 的命中全在 `*_test.go` 里，而且都是关于 `Accept-Encoding` 的。
  **没有任何项目代码或测试提到过 `Vary: Cookie`**，也没有任何测试断言过它不存在。
- **状态**：CONFIRMED
- **影响**：任何遵守 `Vary` 的共享缓存（nginx `proxy_cache`、CDN、Service Worker 之外的中层）都必须把
  `_app/immutable/*` 按**整个 Cookie 头**分键：N 个用户就是 N 份副本，很多 CDN 干脆拒绝缓存 `Vary: Cookie` 的响应。
  于是「hash 资源缓存一年」实际上只在**已经拿到它的那个浏览器**里成立，每个新访问者的首个请求都回源到 Go 进程。
  对一个把「一个二进制自带前端」当卖点的服务，这正好抵消了它自己写下的缓存设计；而运维看不到任何异常（响应头看起来「有缓存」）。
  安全上无影响（响应字节对所有 Cookie 都相同，不存在把别人的内容缓存给谁的问题）。
  「不可能被中间缓存放大」这一点也只有读码级证据（本机无 nginx/CDN 可复现，见「未能到达」）。
- **探针**：`frontend_handler_test.go::TestZ08ImmutableAssetsDoNotVaryOnTheSessionCookie`（红）、
  `realproc_test.go::TestZ08RealProcessServesTheShellWithItsOwnPolicy`（红，同一条断言）
- **修法建议**：两选一。
  (a) 最小改动：在 `webui.Handler` 里，当 `name` 落在 `_app/immutable/` 时 `w.Header().Del("Vary")`
      （压缩层随后会自己 `addVary("Accept-Encoding")`，所以不会丢 `Accept-Encoding`）；
  (b) 更干净：让 `/app/*` 不进会话中间件——把静态面挂到一条不经过 `sessions.LoadAndSave` 的子树上
      （`/app` 本来就不需要会话；今天需要会话的是 `/v1` 与 `/auth`）。这条同时省掉每个静态请求的一次会话加载尝试。
  无论选哪条，都应加一条守卫断言「`_app/immutable/*` 的响应头里没有 `Cookie` 这个 Vary token」。
- **是否与既有编号相关**：无。这是**依赖行为**，不是项目代码；而它抵消的是项目自己在 `webui.go` 里写下并有测试护航的缓存决定，
  所以按简报 §4.4 属于「既有设计的守卫不全」，不是重报。

### Z08-6 同意页 `scopeViews` 静默丢弃业务注册表不认识的 scope；两个注册表一旦不一致，就出现「展示少于授予」
- 严重度：**P3 低/提示**（行为 CONFIRMED；按今天的组合根不可达，见状态）
- 类别：安全 / 合规-隐私
- 不变量：token/scope 签发
- 证据（红，端到端走真 OP）：
  ```
  $ go test -tags audit7 -run TestZ08ConsentScreenCannotShowLessThanItGrantsWhenTheTwoRegistriesDiffer -v
  displayed: [account.id]
  granted:   [account.id z08.extra.read]
  the token carries "z08.extra.read" while the consent screen displayed [account.id]:
  a described scope the business plane's registry does not know is silently omitted from the screen
  (scopeViews() skips it) and then granted anyway when the scopes field is omitted
  --- FAIL
  ```
  装置：OP 的注册表用 `oauth.NewRegistry(DefaultDescriptors() + {Scope:"z08.extra.read", Risk:High})`，
  而 `httpapi.Config.Scopes` 保持默认（缺这个 scope），客户端被允许这两个 scope。
  流程是真实的：`GET /oauth/authorize` → 真 OP 发 pending 请求 → `GET /v1/authorization_requests/{id}` 取「屏幕会显示什么」→
  `POST .../decision {decision:"approve"}`（**省略 `scopes` 字段**，即 openapi 文档化的「授予整个请求」形式）→ 真 OP 回调拿 code →
  `POST /oauth/token` 换令牌 → 用 **OP 自己的 `Introspect`**（不是 `/v1` 的视图）读令牌实际带的 scope。
  机制（逐行）：
  - `internal/httpapi/authorization_routes.go:185-201` `scopeViews`：`d, ok := s.scopes.Get(sc); if !ok { continue }` —— **静默跳过，无日志、无错误**；
  - `internal/oidchttp/oidchttp.go:1546-1561` `ApproveAuthorization`：`scopes == nil` 时 `granted = requested`（完整请求），
    随后用 **OP 的** 注册表解析 descriptor；`scopeViews` 用的却是 `httpapi.Config.Scopes`。
  对照绿（同一装置，注册表一致时）：`TestZ08ConsentScreenDisplaysEveryDescribedScopeItGrantsOnce`
  ```
  displayed: [account.id phigros.profile.read]      requested: account.id phigros.profile.read openid
  granted:   [account.id phigros.profile.read openid]
  --- PASS
  ```
  —— 即**今天**同意页显示的就是它授予的（多出来的只有 O-3 明确不展示的协议 scope），这一条是**正面结论**。
- **状态**：CONFIRMED（行为已被红探针钉住）／**可达性受限**：`cmd/re0auth/main.go:1279-1362` 把同一个 `registry := oauth.DefaultRegistry()`
  同时交给 OP（`oidchttp.Config.Registry`）和存储，而 `httpapi.Config` **根本不设 `Scopes`**（`main.go:532-562`），
  于是两者退化成同内容的默认目录——**按今天的组合根不可达**。但（a）没有任何测试钉住「两者相等」；
  （b）`oauth.Registry.Register` 的文档明确写着「meant to be called by provider packages at composition time」，
  即未来在组合期加一个 scope 是预期用法，那时两处会静默分叉；（c）failure mode 正是这个页面存在的意义所在。
- **影响**：一旦分叉，用户在一个以「你是安全的」为卖点的页面上按下的同意，会授予一个它**从未显示过**的数据权限
  （本例 `z08.extra.read`，Risk=High）。反向（业务注册表更全）不会过度授予，只会让某个 scope 永远无法被授予且没有任何报错——
  同样是静默失败。影响面是可读的：这条路径只影响 `scopes` 被省略的调用方（SPA 自己总是回传展示集，所以 SPA 流程今天不会踩到）。
- **探针**：`consent_display_test.go::TestZ08ConsentScreenCannotShowLessThanItGrantsWhenTheTwoRegistriesDiffer`（红）；
  对照绿：`consent_display_test.go::TestZ08ConsentScreenDisplaysEveryDescribedScopeItGrantsOnce`、
  `::TestZ08ConsentDecisionCannotWidenTheRequest`、`device_browser_test.go::TestZ08DeviceScreenDisplaysEveryDescribedScopeItGrantsOnce`
- **修法建议**：两条一起做。
  1. **单一来源**：`openOIDC` 返回注册表（或在组合根里变量共享），`apiConfig.Scopes` 用同一个对象，消掉「两份目录」；
  2. **别静默**：`scopeViews` 遇到没有 descriptor 的 scope 时不能 `continue`——要么把整个同意请求判为不可批准（fail-closed，
     和 `Resolve` 的错误路径同形），要么至少 `slog.Warn` + 让该 scope 以「未描述」形态出现而不是消失。
  并加一条守卫测试断言「同意视图显示的 scope 集合 ⊇ `ApproveAuthorization` 会授予的 described scope 集合」。
- **是否与既有编号相关**：无。与 O-3/O-6（协议 scope 不展示）是**不同**的事，后者是有意的、我写进「判断」而不是这里。

### Z08-7 设备决策端点的未知 `decision` 值被静默当成「拒绝」并消耗掉设备码
- 严重度：**P3 低/提示**（fail-closed，但静默且与同意端点不一致）
- 类别：可用性 / 可维护性
- 不变量：fail-closed（「没听懂」必须与「用户说不」区分开）
- 证据（红）：
  ```
  $ go test -tags audit7 -run TestZ08DeviceUnknownDecisionVerbIsRefusedNotSilentlyDenied -v
  decision "" was answered 200 {"state":"denied"}
  --- FAIL
  ```
  机制：`internal/httpapi/device_routes.go:114-115,131-138` 把布尔直接写成 `body.Decision == "approve"`，
  没有任何白名单校验；`""`、`"APPROVE"`、`"approve "`、`"yes"` 全部走 `approve=false`。
  对照：同族的同意端点 `authorization_routes.go:149-170` 有 `switch body.Decision`，未知值 → `400 invalid_request`
  （`consent_display_test.go::TestZ08ConsentDecisionCannotWidenTheRequest` 的红字输出证明那条分支在工作）。
  历史旁证：第五轮 `device_routes_test.go:217-233` 明确论证过这个端点的 CSRF 例外，说明作者对「这个 GET/POST 对是怎么变成写的」想得很细——
  所以这个缺口更像是漏了校验而不是决定。
- **状态**：CONFIRMED
- **影响**：一个客户端拼错动词（或漏掉字段的 `{}`）得到 `200 {"state":"denied"}`：设备码被消耗、设备端显示用户拒绝，
  而**用户本人什么都没拒绝**；重试会拿到 `access_denied`（第五轮 `G-10` 同族的「码被烧掉」形状）。
  对 CI 之外的第三方设备客户端（RFC 8628 的轮询实现）这是难查的静默失败。没有越权后果。
- **探针**：`device_browser_test.go::TestZ08DeviceUnknownDecisionVerbIsRefusedNotSilentlyDenied`（红）；
  对照绿：`TestZ08DeviceVerificationRequiresASession`、`TestZ08DeviceScreenDisplaysEveryDescribedScopeItGrantsOnce`、
  `TestZ08DeviceCodeLoadedElsewhereCannotBeApprovedHere`
- **修法建议**：在读 `user_code` 之后、调用引擎之前加一段与同意端点同形的校验：
  ```go
  switch body.Decision {
  case "approve", "deny":
  default:
      s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", `decision must be "approve" or "deny"`)
      return
  }
  ```
- **是否与既有编号相关**：与 `G-10`（设备轮询被拒会烧掉 device_code）是**不同**的端点与不同的成因（那条是认证方法），
  但同属「设备流里一次不成功的调用会无可挽回地消耗设备码」，修 `G-10` 时建议一并收。

### Z08-8 账户页把 `?error=` 的原始值插进 DOM（**已转义、非 XSS**，残留 UI 欺骗面）
- 严重度：**P3 低/提示**
- 类别：安全
- 不变量：两平面分离（浏览器面的错误文本应是本服务自己的固定文案，不是 URL 的回声）
- 证据（**真 Chromium 1243**，脚本见探针目录 `browser_probe.mjs`，对着 17801 的组合二进制）：
  ```
  $ node browser_probe.mjs http://127.0.0.1:17801      # 载荷 ?error=<img src=x onerror=window.__z08xss=1>
  ERROR_PAGE_HAS_PAYLOAD_TEXT=true
  ERROR_PAGE_IMG_COUNT=0
  ERROR_PAGE_WINDOW_FLAG=null
  ERROR_PAGE_TEXT="... 登录没有完成（<img src=x onerror=window.__z08xss=1>）。 ..."
  ```
  机制：`web/src/routes/+page.svelte:63-84` 的 `authErrorMessage` 对未知 code 走 `default: return \`登录没有完成（${code}）。\``，
  由 Svelte 的文本插值渲染（因此被转义，实测 `img` 元素数 0、`onerror` 未执行）。
  对照（服务端侧是干净的）：`/nope` → `text/plain "not found"`；`POST /app/` → `text/plain "method not allowed"`；
  三个平面的 4xx 都不回显输入（见 `TestZ08TraversalMatrixSurvey`、`TestZ08RealProcessStaticSurfaceSurvey` 的 body 列）。
- **状态**：CONFIRMED（浏览器实测）。**XSS 已被证伪**：这不是脚本执行漏洞，`{code}` 落在文本节点里。
- **影响**：攻击者可以构造 `/app/?error=<任意短文本>`，让账户页在品牌页眉下显示
  「登录没有完成（<攻击者选的文本>）。」——一个受字数限制的**内容注入/钓鱼画布**（例如伪装成「账号已被冻结，请致电…」）。
  因为模板固定、长度受限、且页面同时显示本服务的真实品牌与登录按钮，危害有界。
- **探针**：`browser_probe.mjs`（手工，真浏览器，输出已记在文件头）；服务端侧的对照绿：
  `frontend_handler_test.go::TestZ08TraversalMatrixSurvey`、`realproc_test.go::TestZ08RealProcessStaticSurfaceSurvey`
- **修法建议**：`authErrorMessage` 的 `default` 分支不要回显 `code`，改成固定文案（如「登录没有完成，请重试。」），
  或者只对白名单内的前缀做映射、其余一律固定串。这条同时让浏览器面的错误文案拥有和 `/auth`、`/bind` 相同的性质：
  **由本服务决定，不由 URL 决定**（ADR-0003 §2 的精神）。
- **是否与既有编号相关**：无。

---

## 探过但没破的（也应变成守卫）

每条：攻击形状 + 探针名 + 为什么守住。全部绿。

1. **CSP 头/meta 交集把内联 bootstrap 挡掉（历史白屏回归）** —
   `shell_csp_test.go::TestZ08ServedShellMetaCSPAllowsItsOwnInlineScripts`、`::TestZ08ServedShellMetaCSPHasTheNonNegotiableDirectives`。
   从**服务端实际发出的字节**里正则取出 meta 策略，再对每个内联 `<script>` 的原文重算 `sha256`：1 个内联脚本，1 个命中 `script-src`。
   `script-src` 里没有 `'unsafe-inline'`/`'unsafe-eval'`/`*`/`data:`/任何 origin。策略原文：
   `default-src 'self'; connect-src 'self'; font-src 'self'; img-src 'self' data:; object-src 'none'; script-src 'self' 'sha256-qYHY…='; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'none'`。
2. **meta CSP 出现顺序** — `::TestZ08ShellMetaCSPPrecedesEveryScriptItMustGovern`：恰好 1 个 meta 策略，位于字节 [1061,1354)，
   第一个 `<script>` 在 2896，`</head>` 在 1969 ⇒ 它管住了它必须管的东西（meta 策略只管它之后的内容，这是它与头策略唯一的行为差别）。
3. **frame-ancestors 只在头里、meta 里没有**（浏览器忽略 meta 里的 frame-ancestors） —
   `::TestZ08FramingGuardComesFromTheHeaderNotTheMeta`：meta 里不含该指令，头里有 `frame-ancestors 'none'` + `X-Frame-Options: DENY`。
4. **每个浏览器面响应都有反框架/嗅探/引用者守卫** — `frontend_handler_test.go::TestZ08EveryBrowserPlaneResponseCarriesTheFramingGuard`、
   `::TestZ08StaticSurfaceCarriesNosniff`：`/app/`、`/app/consent`、缺失 asset、`POST /app/` 405、`/nope` 404、`/robots.txt`
   全部有 `X-Frame-Options: DENY` + `frame-ancestors 'none'` + `nosniff` + `no-referrer`。
5. **`img-src` 不允许任何外源**（IdP 的 `avatar_url` 因此渲染不出来，代码注释也说明了改用字母缩写） —
   `::TestZ08ServedShellImageSourcesExcludeThirdParties`。
6. **服务端发的就是构建产物本身（无注入、无模板化）** — `::TestZ08ServedShellIsTheBuildOutput`：与 `webui.FS()/index.html` 逐字节相同；
   这正是 webui 包承诺的「决定同意页说什么的那条路径上不放前端构建输出」。
7. **真实 Chromium 里 CSP 真的生效、应用真的渲染** — `browser_probe.mjs`：`CONSENT_H1="授权请求"`、`CSP_VIOLATIONS=[]`、`PAGEERRORS=[]`
   （console 里唯一一条是预期的匿名 401）。这是第 1 条的浏览器级阳性对照：**head+meta 的策略交集确实放行了 bootstrap**。
8. **全部写端点的 CSRF 三态走查（按已发布规范枚举，不按产品自己的路由表）** —
   `csrf_spec_test.go::TestZ08EverySpecifiedWriteNeedsTheSessionCSRFToken`：从 `docs/openapi.yaml` 解析出 **14 个**变更操作
   （简报里说的 13 个，实际是 14：`grants` DELETE、`bindings` DELETE、`cascade_revocation` POST、`sign_out` POST、
   `account` DELETE、`identities/{id}` DELETE、`authorization_requests/{id}/decision` POST、`device/decision` POST、
   `admin/clients` POST、`suspend`、`activate`、`rotate_secret`、`admin/clients/{id}` DELETE、`kill_switch` POST），
   每个都打三态。全部实测 `none=403 wrong=403 real=2xx/4xx-not-403`，逐条输出见探针日志。
   为让 admin 平面可达，装置复用了第一个环境的会话管理器与账户存储（`httpapi.Config.Admins` 是 `New` 时固定的，而账户 id 只能登录后才知道），
   并且**每个操作起一个独立服务器**——因为 `sign_out` 与 `account` DELETE 会真的结束它们跑在上面的那个会话（这是我第一版探针踩到的坑，值得记下来）。
9. **跨站表单 POST 打不到写端点** — `::TestZ08CrossSiteFormPostCannotReachAWrite`：`Content-Type: application/x-www-form-urlencoded`
   且无自定义头（这正是跨站 `<form>` 唯一能构造的形状）打 `/v1/sessions/sign_out` 与 `/v1/admin/kill_switch` → 两个 403。
10. **`/v1/device/verification` 是唯一需要 token 的 GET，且它确实返回 token** —
    `::TestZ08DeviceVerificationIsTheOneWriteThatNeedsNoToken`：该 GET 绑定并返回 `csrf_token`，例外是有目的、可闭合的。
11. **同意页展示 == 授予（注册表一致时）** — `consent_display_test.go::TestZ08ConsentScreenDisplaysEveryDescribedScopeItGrantsOnce`
    （见 Z08-6 的对照绿）。
12. **决策不能加宽授权请求** — `::TestZ08ConsentDecisionCannotWidenTheRequest`：`scopes` 里塞一个客户端没请求的 scope →
    `400 {"detail":"the decision cannot widen the requested scope","code":"invalid_request"}`。
13. **设备码绑定到「加载它的那个浏览器 + 那个账号」** — `device_browser_test.go::TestZ08DeviceCodeLoadedElsewhereCannotBeApprovedHere`：
    另一个浏览器（持**自己的**合法 CSRF token）批准 → `404 not_found "unknown user code"`；随后 owner 自己批准 → 200。
14. **匿名访客拿不到任何带会话数据的页面** — `::TestZ08DeviceVerificationRequiresASession`（401 + `unauthenticated`）、
    `realproc_test.go::TestZ08RealProcessSessionViewIsUncacheableAndCarriesNoCORS`（`/v1/sessions/current` 匿名 401 problem+json）。
15. **遍历/编码矩阵** — `frontend_handler_test.go::TestZ08TraversalMatrixSurvey`（12 个形状，含 `%2f`、`%2e%2e`、`\`、
    `/app%2Foauth/token`、`/app//oauth/token`、`/app/../../etc/passwd`）：没有一条读到文件系统内容，
    没有一条把非 `/app/` 的文件当 asset 送出；`/app/../oauth/token`、`/app/..%2Foauth/token` 由 `withCanonicalPath` 判成跨面 → 浏览器面 404 纯文本。
16. **`/app` 下不做目录枚举** — `::TestZ08DirectoryUnderTheMountIsNotListed`：`/app/_app/`、`/app/_app/immutable/`、
    `/app/_app/immutable/assets/` 都回 shell，body 里没有文件名也没有 `<a href`。
17. **动词闸门** — `::TestZ08WrongMethodUnderTheMountIsRefusedWithAllow`：`POST/PUT/OPTIONS /app/...` → 405 + `Allow: GET, HEAD` + `text/plain`
    （不是 problem+json，符合 ADR-0003 §2）。
18. **不发任何 CORS 头（含预检）** — `realproc_test.go::TestZ08RealProcessStaticSurfaceSurvey` 带 `Origin: https://evil.example`
    打 12 个请求（含 `OPTIONS /oauth/token`）→ 全部无 `Access-Control-Allow-*`。符合 ADR-0011。
19. **`/robots.txt` 在根上可服务** — `::TestZ08RealProcessStaticSurfaceSurvey`：根上的副本回 200 且带 `public, max-age=3600`，
    这正是 `Disallow: /app/` 生效的前提（`internal/webui/webui.go:69-82` 的理由）。
20. **开放重定向面** — `realproc_test.go::TestZ08RealProcessOpenRedirectSurface`：`return_to` = `//evil.example`、`https://evil.example/x`、
    `/\evil.example`、`/%09/evil.example`、`javascript:alert(1)`；打 `/auth/{p}/start` 与 `/bind` → 没有任何跨源 `Location`
    （内存模式没配 IdP，`/auth` 回 404 `unknown provider`；`/bind` 匿名回 401）。
21. **无客户端注入 sink / 无凭据进 web storage** — `bundle_sinks_test.go::TestZ08AppSourceHasNoClientSideSinkAndNeverStoresACredential`
    （22 个源文件，剔除注释后搜 `localStorage`/`sessionStorage`/`document.cookie`/`postMessage`/`innerHTML`/`outerHTML`/`insertAdjacentHTML`/`eval(`/`new Function`/`{@html`，
    含阳性对照 `api.ts` 里能找到 `fetch(`）、`::TestZ08BuiltBundleDoesNotPersistSecretsInWebStorage`
    （8 个 route chunk 同样干净；阳性对照：bundle 里能找到 `/v1/`、`fetch(`、`AbortController`）。
    **细节**：SvelteKit 运行时确实在 bundle 里带了 `sessionStorage` 辅助函数（2 处）与 trusted-types 的 `innerHTML` 模板构造器（2 处），
    但都在 runtime chunk 里、应用代码从不调用——所以结论是「应用不落任何东西进 web storage」，而不是「bundle 里没有这些字符串」。
    凭据设计（`api.ts` 顶部三条规则）与实现一致：只有 same-origin cookie。
22. **构建产物不加载任何第三方资源** — `::TestZ08BuiltBundleLoadsNoThirdPartyResource`：唯一的 CSS（1 个文件）里没有 `url(//…)`、
    没有 `@import http…`、没有 `@font-face`（CSS 里唯一的 `https:` 是 tailwind 的许可证注释）；shell 的 9 个引用全部以 `/app/` 开头。
23. **`postMessage` 面为零** — 同上两条：源码与 route chunk 里都没有 `postMessage`，所以没有跨窗口消息处理器需要审。
24. **静态响应带 nosniff + no-referrer** — `TestZ08StaticSurfaceCarriesNosniff`（5 条路径）。

---

## 未能到达（残余盲区）

1. **浏览器侧只有一次性手工探测，没有入库的 e2e 门禁。** Playwright 浏览器**是装好的**（与简报假设相反），我用一个
   仓库外脚本（内容存于探针目录 `browser_probe.mjs`）在 Chromium 1243 上跑了真进程；但**我没有把 spec 写进 `web/e2e/`**
   ——那超出「只能写报告与探针目录」的硬性约束。所以浏览器结论是**可复现的手工证据**，不是 CI 门禁；也没有跑完整 `pnpm e2e`
   （它会自建 18098/18099 上的服务器，与并行代理抢端口）。要把它变成门禁，应由主代理决定是否在 `web/e2e/` 加两条 spec。
2. **交互流程没在浏览器里跑通**：同意页的勾选→单独确认→批准→跳转、设备页的倒计时与批准、账户页的解绑确认焦点管理，
   都只有服务器侧端到端（Go 探针）与源码级结论。需要真正的点进流（或 `pnpm e2e`）才能覆盖。
3. **Z08-5 的规模后果只有机制级证据**：本机没有 nginx/CDN/Docker，「`Vary: Cookie` 会让共享缓存不缓存/按 Cookie 分键」
   是按 RFC 9111 §4.1 与 nginx `proxy_cache` 的既有行为推导的，**没有端到端复现**。机制（scs 源码那一行 + 实测响应头）是确定的。
4. **单一引擎**：只有 Chromium，没有 Firefox/WebKit。`frame-ancestors`、meta CSP 的哈希白名单、`Vary` 的引擎差异未测。
5. **真实发布链路未触达**：`internal/webui/dist` 的产物**不在 git 里**（`git ls-files internal/webui/dist` 只有 `.gitignore`/`.gitkeep`），
   CI 在 Go 步骤前 `pnpm install --frozen-lockfile && pnpm run build` 并断言 `index.html` 存在（`ci.yml` 步骤 "build frontend"）。
   我用的是本机 HEAD 的构建（dist mtime 晚于最后一次提交与全部 `web/src`），但**CI 构建环境的差异（Node/pnpm/依赖解析）不在我的验证范围内**；
   如果 CI 的构建与我的本地构建在 CSP 哈希或资源集合上不同，第 1/6/7 条的结论需要在 CI 产物上重跑一次。
6. **`?error=` 之外的其他反射面**未逐一在浏览器验证：SvelteKit 的错误边界（`+error.svelte`，`page.error?.message`）、
   `messageOf(err)` 把服务端 problem 的 `detail`/`title` 直接渲染（服务端已保证不回显调用方输入，但 `upstream_error` 字段
   （`UnbindResult.UpstreamError`，来自 data source）会经 `sources/+page.svelte` 进 DOM——源码里没有任何一页把它渲染出来
   （只用了 `upstreamCopy[outcome.upstream]` 的固定文案），值得作为下一步的浏览器级核查点。
7. **无 Postgres/Docker**：与前端无关，但 Z08-6 的「两个注册表相等」只在内存组合根上验证过；
   两个后端共用 `openOIDC` 的同一段装配代码，所以不影响结论。

---

## 判断（文档化决定可否质疑，不是 finding）

- **`/app/*` 未知路径回 shell 200 本身是有意的**（`internal/webui/webui.go:88-93`：客户端路由需要它，且这正是它必须钉死在自己前缀上的原因）。
  我没有把它当 finding；Z08-1/Z08-4 报的是**这个回退延伸到 `_app/immutable/*` 命名空间**所带来的可观测性问题，
  以及「hashed 资源命名空间」这个概念在 handler 里根本不存在。路线之争（「前端 SPA 就该这样」）我不参与。
- **同意页不展示 `openid`/`profile`/`email`/`phone`/`address`/`offline_access` 是有意的**（O-3：userinfo 只返回 `sub`；
  O-6 修订：always-on refresh）。我把它写在这里而不是 finding。但要指明它与「展示少于授予」的字面定义是相符的：
  授予集合确实大于展示集合（实测 `granted: [account.id phigros.profile.read openid]`），今天没有危害是因为 O-3 让这些 scope 是空操作。
  **一旦 O-3 变更（userinfo 真的返回 email/profile），必须先改这个页面**——那时它就从「无操作的协议标志」变成真实的数据授权。
- **`style-src 'self' 'unsafe-inline'`** 是 Svelte/Tailwind 的需要（内联 `style` 属性与转场）。在「没有内联事件处理器」
  （有 CSP 的 script-src 与 `{@html}` 缺席兜底）的前提下风险有限。可质疑，但不是缺陷。
- **HEAD 不带 `Vary: Accept-Encoding`**：`internal/compress/compress.go:139-145` 明确写下这是有意的（「the representation cannot vary for a HEAD」），
  第六轮的 `TestZ06VaryMatrix` 也把它钉成期望。与 RFC 9110 §9.3.2「HEAD 应与 GET 同头字段」有张力，但实际缓存实现不会因此出错。属可质疑项。
- **`Vary: Cookie` 是依赖库（scs v2）写的，不是项目写的**：全仓没有一处提到它，也没有测试断言过它。
  我把它报成 finding（Z08-5）而不是判断，理由是它**抵消了项目自己写下并有测试护航的缓存决定**——即「依赖的默认值悄悄改写了本项目的决定」，
  正是 `docs/cors-decision.md` 里 `rs/cors` 那个故事的同型（能力可以存在，行为必须是选择过的）。
- **`/app/index.html` 被 301 到 `/app/`**：`http.ServeFile` 对 `*/index.html` 的既有行为（`TestZ08StaticServingSurvey` 观测到 301，
  真进程里被客户端跟随成 200）。无安全影响，不建议改。
- **`avatar_url` 由外部 IdP 提供、未做校验，但前端不渲染它**（用首字母缩写，`+page.svelte:267-278` 写明了原因），
  且 `img-src 'self' data:` 会挡住外源图。保持现状即可；若将来要渲染，必须同时改 CSP 并想清楚「把用户 IP 交给第三方 IdP 的图床」这件事。
- **`internal/webui/dist` 不入库**：`go build` 得到一个「前端未构建」的 503 页面，这是 Makefile 与前提条件里写明的有意决定，
  不是 finding；CI 在测试前构建它，所以 CI 的 Go 测试跑在真 shell 上（这一条我读码确认过）。
