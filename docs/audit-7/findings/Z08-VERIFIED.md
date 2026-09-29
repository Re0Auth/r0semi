# 区域 Z08：frontend-browser — 第七轮**对抗性复核**（Z08-VERIFIED）

> 复核对象：`docs/audit-7/findings/Z08-frontend-browser.md`（下称"原报告"）、
> `internal/zzprobe/audit7/z08frontendbrowser/`（10 文件，**未改动**）。
> 我的探针：`internal/zzprobe/audit7/z08verify/`（`z08verify_test.go`、`browser_probe.mjs`、`doc.go`，全部 `//go:build audit7`）。
> 我的端口：真进程 **17802**；Chromium 1243 **已装**（与简报假设相反，我实跑过）。
> 我跑过：原报告全部探针（`go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z08frontendbrowser/... -v`
> → **10 红 / 27 绿**，逐条确认失败原因即所述机制，无夹具错位）；我的独立探针（绿，带回显）；
> 真 Chromium 独立脚本。读了 `webui.go`、`server.go`、`authorization_routes.go`、`device_routes.go`、
> `oidchttp.go`、`memory/oidc.go`、`compress.go`、`safeurl.go`、`+page.svelte`、`docs/openapi.yaml`、
> `docs/audit-5/findings/frontend{,-VERIFIED}.md`、`docs/security-audit-5.md`、第五/六轮编号表。

## 1. 判定表

| ID | 原判 | 我的裁定 | 修正严重度 | 一句话理由 |
|---|---|---|---|---|
| Z08-1 | P3 | **NOT-A-FINDING** | 提示（同第五轮） | **重报**：第五轮 A-FE-9 的复核发现 **V-2** 已把「缺失散列资产回 200 shell 而非 404」钉成性质，连**监控/告警假设**的后果都写了；原报告自称"与既有编号无关"不成立 |
| Z08-2 | P3 | **NOT-A-FINDING** | 低（同 A-FE-1） | **重报**：A-FE-1 已在第五轮判「低」（"shell 无 ETag/Last-Modified 属实"，仅残余在违规中介）；机制由我真进程独立复现 |
| Z08-3 | P3 | **DOWNGRADED** | P3（仅剩 favicon 卫生） | 核心（`_app/version.json` 无缓存指令）**重报 V-4**；且"构建产物无 `version.json` 引用"是**错的**（见 Z08V-2） |
| Z08-4 | P3 | **NOT-A-FINDING** | **提示** | **重报**：A-FE-2 已复现"206 半截 shell"并降为**提示**；本条是其与 V-2 的交叉点（同根因、同修法） |
| Z08-5 | **P2** | **DOWNGRADED** | **P3** | 机制 CONFIRMED（我独立复现），但**纯共享缓存效率、需要项目自身不拥有的 CDN/nginx 前提、安全影响为零** ⇒ P2 评高 |
| Z08-6 | P3 | **NOT-A-FINDING** | P3 | **重报**：A-FE-3 + 复核 V-1 已完整覆盖 `scopeViews`（`authorization_routes.go:188-190`）静默丢弃与设备流第二份实现；唯一新内容是一个原报告自己承认**不可达**的人造配置 |
| Z08-7 | P3 | **CONFIRMED** | P3 | 机制与"消耗设备码"后果我独立读码确认；但 `openapi.yaml:2300-2302` 的 `enum` 与之矛盾 ⇒ 正是简报 §6 的"docs vs 实现"P3 |
| Z08-8 | P3 | **CONFIRMED** | P3 | 我用**独立脚本 + 真 Chromium**复现：文本转义、`img`=0、`window` 标志为 null，且**探测器有阳性对照**（同一载荷在 `data:` 页里 flag=1） |
| Z08V-1 | — | **新发现** | P3 | 原报告 §探过没破 #20 的"开放重定向面"是**假守卫**：内存模式下该请求回 404/401，**永远到不了任何重定向 sink** |
| Z08V-2 | — | **新发现** | P3 | Z08-3 用来收窄影响的代码事实错误：构建产物**确实**带着 `version.json` 轮询代码（方向是**低估**） |

**总评**：8 条发现里 **4 条是已记录发现的重复**（且 4 条都自称"与既有编号无关"），
**1 条严重度评高**（Z08-5），**3 条成立**（Z08-7/Z08-8/Z08-3 的残余）。
没有一条是机制写错到"完全错误"的程度（这比第五轮的 3 条好）；但**唯一带 P2 的那条是虚高**，
而**这个区域的全部"新洞"其实在第五轮就已经存在**——这是本轮该记住的结论。

## 2. 逐条理由

### Z08-1 → NOT-A-FINDING（重报 A-FE-9/V-2）
原报告的每一项——`webui.go:119-127` 的回退、`200 text/html`、`len=3304`、
"状态码监控看不到发布不完整"——都在 `docs/audit-5/findings/frontend-VERIFIED.md:330-340`（V-2）里，
连修法（"对 `_app/immutable/**` 的未命中回真 404"）都逐字相同。唯一新增是把它叫"P3 + 失败静默"。
探针本身不假：`start.abc.js → 200 text/javascript + immutable` 是有效阳性对照（我复跑并在
`z08verify_test.go` 里用真进程再证一次：真实资产 `start.DJJzSbG0.js → 200 text/javascript`，
缺失名 → `200 text/html`，且 **len=3304 == shell len=3304**）。**问题在归类，不在证据。**

### Z08-2 → NOT-A-FINDING（重报 A-FE-1）
A-FE-1 及其复核结论（`frontend-VERIFIED.md:23,41-71`）：实测 `ETag=""`、`Last-Modified=""`、
条件请求永远 200 全量，判**低**。原报告换了措辞（"不可能变成 304"）但无新事实。
机制我也核到：`embed.FS` 的 `ModTime()` 为零 ⇒ `http.ServeFileFS` 不发 `Last-Modified`，
项目只设 `Cache-Control: no-cache`（`webui.go:147-148`）——与观测（真进程 `etag="" lm=""`）一致。

### Z08-3 → DOWNGRADED（核心重报 V-4，事实另有错误）
`/app/_app/version.json` 无任何 `Cache-Control` 由第五轮 **V-4** 记录（并已给出
"顺手给它 no-cache/no-store"的修法），原报告的核心射程与之一致。真正新的只有
`/app/favicon.svg` 与 `/app/robots.txt` 副本无缓存指令——纯卫生，且 **`/app` 下的 `robots.txt`
副本按 `webui.go:69-82` 本就不该被爬虫读到**，给它缓存策略没有意义。真进程复核：
根 `/robots.txt` 有 `public, max-age=3600`（`server.go:559`），`/app/robots.txt` 无——这是**有意**的
（同一个文件的两个路由，一个给爬虫、一个只是嵌入产物的副本）。

### Z08-4 → NOT-A-FINDING（重报 A-FE-2，且原判就偏高）
A-FE-2 = "对 HTML 文档发 Range 得 206 半截 shell"，第五轮复核已**降为提示**（无可达危害：
浏览器导航不发 Range、半截文档里仍是应用自己的脚本、响应带 `no-cache`）。原报告拿到的是
同一现象的一个特例（缺失名回退后也能 Range），机制、修法与后果都已在 V-2/A-FE-2 内。
它把已判"提示"的东西重新包装成 P3，属**严重度回升式重报**。

### Z08-5 → DOWNGRADED P2→P3（机制成立，严重度评高）
机制我**独立复现**（真进程 17802，自建二进制）：
`/app/consent → cc="no-cache" vary="Cookie, Accept-Encoding"`；
`/app/_app/immutable/entry/start.DJJzSbG0.js → cc="public, max-age=31536000, immutable" vary="Cookie, Accept-Encoding"`；
根因 `alexedwards/scs/v2@v2.9.0/session.go:139` 无条件 `w.Header().Add("Vary","Cookie")`，
而 `server.go:617-618` 把会话中间件包住**整棵树**。压缩层在外层（`server.go:625-627`），
`addVary` 在写头时发生 ⇒ 原报告修法 (a)（在 `webui.Handler` 里 `Del("Vary")`）**技术可行**，这条无需更正。
**但 P2 站不住**：(1) 安全影响为零（对任何 Cookie 字节相同，不会把别人的内容缓存给谁）；
(2) 触发前提是部署一个**项目本身不提供、也不在交付物里**的共享缓存（无 nginx/CDN 配置、无 Docker）；
(3) "失败是静默的"论证很弱——这里没有"报成功/退出 0"，只有"缓存没帮上忙"，
且第六/五轮把它当作**减少共享缓存命中的有利因素**（`frontend-VERIFIED.md:65`）。
它是**一处加固项**：与第六轮 A-FE-9 一族无关（主代理 V-13 已同意可压到 P3，我压）。

### Z08-6 → NOT-A-FINDING（重报 A-FE-3 + V-1）
`scopeViews` 静默 `continue`（`authorization_routes.go:188-190`）是 A-FE-3 的机制；
设备流第二/第三份实现是复核 V-1；"今天不可达（两个注册表都是 `oauth.DefaultRegistry()`）"
也已在 `docs/audit-5/findings/frontend.md:288` 写明。我核了组合根：`main.go:1279` 造一个 registry，
`openOIDC` **不把它交给 `httpapi.Config`**，于是 `server.go:260-262` 再造一个 `DefaultRegistry()`——
同内容、两个实例，原报告的可达性论述正确。但原报告的探针用的是**人为分叉的注册表**，
其"新"结论（一个 High 风险的**已描述** scope 被隐藏授予）在原报告自己写明不可达的前提下，
等于一个 HYPOTHESIS。**不构成新发现**；其修法（单一来源 + 别静默）与第五轮一致，值得照做。

### Z08-7 → CONFIRMED P3（并纠正"静默"的表述）
机制复到行：`device_routes.go:114-115` 与 `:131-138` 只比较 `body.Decision == "approve"`，
无白名单；未知值 ⇒ `approve=false` ⇒ `memory/oidc.go:1381-1382` 走 `DenyDevice`，该码被**终结**
（后续同一码会得到 `oauth.ErrDeviceNotFound`），即"消耗设备码"**成立**。原探针红（我复跑：
`decision "" was answered 200 {"state":"denied"}`）。两点更正：
① 它**不是全静默**——`device_routes.go:131-135` 会发 `observability.DeviceDenied` 指标，
只是与"用户真的点了拒绝"不可区分；② 它同时是**契约违背**：
`docs/openapi.yaml:2300-2302` 把 `decision` 声明为 `enum: [approve, deny]`，
而授权决策那侧（`:2228`）明写"其它值 = 400"，设备侧（`:797-801`）的 400 文案却只提"malformed body / scope"。
所以它是 **docs vs 实现不一致 + fail-closed 但会消耗码**，P3 准确。

### Z08-8 → CONFIRMED P3（独立浏览器证据 + 阳性对照）
源码：`web/src/routes/+page.svelte:63-84` 的 `default` 分支返回 ``登录没有完成（${code}）。``，
`code` 来自 `new URLSearchParams(location.search).get('error')`（`:40-41`）。我**没有**复用原报告的脚本，
自写 `z08verify/browser_probe.mjs`（真 Chromium 1243，对 17802 的真进程）：
`payload_escaped_in_html=true`、`img_count=0`、`window_flag=null`，
且**阳性对照**：同一载荷放进 `data:text/html` 页时 `window_flag=1`、`img_count=1`
（证明"没执行"不是探测器坏了）。同一跑还给出 `consent_h1="授权请求"`、`csp_violations=[]`，
即**独立复现了"探过没破"#7**。剩余问题（URL 决定页面文案）确如原报告所述，P3 合适。

## 3. 假守卫 / 反空转（我对 24 条"探过没破"逐条看了阳性对照）

**唯一一条结构性不可能失败：#20 开放重定向面**（= Z08V-1）。其余 23 条我都核过，
其中 #1/#6/#7/#15/#21/#22 的对照是真的（重算哈希、逐字节比对、`reached` 计数、
`fetch(`/`AbortController` 阳性串、CSS 文件数非零），#8/#9 的 CSRF 走查按 `docs/openapi.yaml`
枚举且断言 `gated == checked`（我复跑：全绿，14 个变更操作逐条 `none=403 wrong=403 real=非 403`）。

## 4. 新发现

### Z08V-1 [P3 · 报告质量] "开放重定向面"的绿是假守卫：该探针永远到不了任何重定向
- 证据（原探针自己的输出，我复跑并用自己的真进程再证）：
  ```
  /auth/z08idp/start?return_to=//evil.example   -> 404 loc="" body="unknown provider"
  /bind?game=g&source=s&return_to=//evil.example -> 401 loc="" body="sign in to bind a source"
  ```
  内存模式**没有配置 IdP**（`/auth` 路由在启动期按 registry 装配），所以那条 `start` 根本走不到
  "读 `return_to` → 302"；`/bind` 匿名在鉴权处就返回了。探针的"阳性对照"只是 `seen++`（计数 6 次请求），
  **不是**"真的到达了重定向分支"。⇒ 它对"开放重定向"零信息量。
- 真实守卫存在且另有测试：`safeurl.RelativePath`（`internal/safeurl/safeurl.go:34-53`，
  拒绝 `//`、`\`、控制字节）在 `internal/auth/auth.go:599` 与 `:636` 两处使用，
  `internal/auth/auth_test.go:254 TestReturnToIsSanitized` 钉住它。**产品没有洞，是报告的守卫是假的。**
- 我的探针：`z08verify_test.go::TestZ08VOpenRedirectGreenIsVacuous`（绿；若哪天出现带 `evil.example`
  的 302 它会红）。修法：把这条从"探过没破"删掉，或改用它已有的全接线夹具
  （`newZ08Env` 配了 provider）走完 start→callback 再断言 `Location`。

### Z08V-2 [P3 · 报告质量] Z08-3 的"构建产物无 `version.json` 引用"是错的（方向是低估）
- 原报告 Z08-3 写"本机构建里客户端没有轮询它——grep 构建产物无 `version.json` 引用——所以今天只有潜在风险"。
- 实测：`internal/webui/dist/_app/immutable/chunks/DqohD3-m.js` 里有
  ``fetch(`${de}/_app/version.json`,{headers:{pragma:`no-cache`,"cache-control":`no-cache`}})``
  与 `...version!==fe` 的比对逻辑（SvelteKit 的 `updated` 检查函数）。**引用存在。**
- 影响：不是新洞，但原报告用这个假事实把 V-4 的风险**往下限**了；实际是"部署新鲜度探测代码随产物发出"，
  更支持给 `version.json` 明确缓存指令。（是否被应用订阅/调用我没有证明，仍属未到达。）

## 5. 未能到达（残余盲区）
1. **共享缓存的端到端后果**：本机无 docker/nginx/CDN，Z08-5 的"按 Cookie 分键/拒绝缓存"
   仍是 RFC 9111 §4.1 与 nginx 既有行为的**推导**。机制（scs 一行 + 真进程响应头）是实测的。
2. **无 Postgres**：与前端平面无关；Z08-6 的两注册表关系只在内存组合根验证。
3. **浏览器只有 Chromium 1243**：无 Firefox/WebKit；`frame-ancestors`、meta CSP 哈希、
   `Vary` 的引擎差异未测（与原报告盲区 4 相同）。
4. **Z08-7 的"码被消耗"只有源码级 + 原探针的 200 红**：我没有自建完整设备流夹具
   （`memory/oidc.go:1378-1382` 的 `st.Denied → ErrDeviceNotFound` 链是确定的，但没跑第二次决策）。
5. **CI 构建产物**：我用的是本机 `internal/webui/dist`（未入库），CSP 哈希/资源集合在 CI 上是否一致仍需在 CI 产物上重跑。

## 6. 判断（不是 finding）
- 原报告的**负面结论我一条都没打破**：缺失资产 200、无校验器、Range 拼接、`Vary: Cookie`、
  未知 decision、`?error=` 反射全部独立复现；CSP/转义/CSRF/遍历/无 CORS 的绿也复现。
  这个区域确实没有未认证绕过、没有跨账号读、没有凭据泄露。
- 原报告的红探针计数是对的（我实测 **10 FAIL / 27 PASS / 0 SKIP**，合计 37 个测试函数），
  但"29 条绿探针"多算了 2 条（应为 27）。10 个红测试函数 = 8 条发现各自的否决断言，其中 Z08-1/Z08-4/Z08-5
  同时在合成树与真进程两条路径上各有一条（各 2），Z08-8 的红在浏览器脚本里、不在 Go 套件里。
- 最该改的是**编号纪律**：Z08-1/2/4/6 都应写成"对 A-FE-1/2/3/9 + V-1/V-2/V-4 的复述（无新增）"，
  而不是"与既有编号无关"。按简报 §4.3，它们不该占"新发现"的名额。
