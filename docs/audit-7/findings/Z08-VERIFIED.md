# 区域 Z08：frontend-browser �?第七�?*对抗性复�?*（Z08-VERIFIED�?
> 复核对象：`docs/audit-7/findings/Z08-frontend-browser.md`（下�?原报�?）�?> `internal/zzprobe/audit7/z08frontendbrowser/`�?0 文件�?*未改�?*）�?> 我的探针：`internal/zzprobe/audit7/z08verify/`（`z08verify_test.go`、`browser_probe.mjs`、`doc.go`，全�?`//go:build audit7`）�?> 我的端口：真进程 **17802**；Chromium 1243 **已装**（与简报假设相反，我实跑过）�?> 我跑过：原报告全部探针（`go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z08frontendbrowser/... -v`
> �?**10 �?/ 27 �?*，逐条确认失败原因即所述机制，无夹具错位）；我的独立探针（绿，带回显）�?> �?Chromium 独立脚本。读�?`webui.go`、`server.go`、`authorization_routes.go`、`device_routes.go`�?> `oidchttp.go`、`memory/oidc.go`、`compress.go`、`safeurl.go`、`+page.svelte`、`docs/openapi.yaml`�?> `docs/audit-5/findings/frontend{,-VERIFIED}.md`、`docs/security-audit-5.md`、第�?六轮编号表�?
## 1. 判定�?
| ID | 原判 | 我的裁定 | 修正严重�?| 一句话理由 |
|---|---|---|---|---|
| Z08-1 | P3 | **NOT-A-FINDING** | 提示（同第五轮） | **重报**：第五轮 A-FE-9 的复核发�?**V-2** 已把「缺失散列资产回 200 shell 而非 404」钉成性质，连**监控/告警假设**的后果都写了；原报告自称"与既有编号无�?不成�?|
| Z08-2 | P3 | **NOT-A-FINDING** | 低（�?A-FE-1�?| **重报**：A-FE-1 已在第五轮判「低」（"shell �?ETag/Last-Modified 属实"，仅残余在违规中介）；机制由我真进程独立复现 |
| Z08-3 | P3 | **DOWNGRADED** | P3（仅�?favicon 卫生�?| 核心（`_app/version.json` 无缓存指令）**重报 V-4**；且"构建产物�?`version.json` 引用"�?*错的**（见 Z08V-2�?|
| Z08-4 | P3 | **NOT-A-FINDING** | **提示** | **重报**：A-FE-2 已复�?206 半截 shell"并降�?*提示**；本条是其与 V-2 的交叉点（同根因、同修法�?|
| Z08-5 | **P2** | **DOWNGRADED** | **P3** | 机制 CONFIRMED（我独立复现），�?*纯共享缓存效率、需要项目自身不拥有�?CDN/nginx 前提、安全影响为�?* �?P2 评高 |
| Z08-6 | P3 | **NOT-A-FINDING** | P3 | **重报**：A-FE-3 + 复核 V-1 已完整覆�?`scopeViews`（`authorization_routes.go:188-190`）静默丢弃与设备流第二份实现；唯一新内容是一个原报告自己承认**不可�?*的人造配�?|
| Z08-7 | P3 | **CONFIRMED** | P3 | 机制�?消耗设备码"后果我独立读码确认；�?`openapi.yaml:2300-2302` �?`enum` 与之矛盾 �?正是简�?§6 �?docs vs 实现"P3 |
| Z08-8 | P3 | **CONFIRMED** | P3 | 我用**独立脚本 + �?Chromium**复现：文本转义、`img`=0、`window` 标志�?null，且**探测器有阳性对�?*（同一载荷�?`data:` 页里 flag=1�?|
| Z08V-1 | �?| **新发�?* | P3 | 原报�?§探过没破 #20 �?开放重定向�?�?*假守�?*：内存模式下该请求回 404/401�?*永远到不了任何重定向 sink** |
| Z08V-2 | �?| **新发�?* | P3 | Z08-3 用来收窄影响的代码事实错误：构建产物**确实**带着 `version.json` 轮询代码（方向是**低估**�?|

**总评**�? 条发现里 **4 条是已记录发现的重复**（且 4 条都自称"与既有编号无�?），
**1 条严重度评高**（Z08-5），**3 条成�?*（Z08-7/Z08-8/Z08-3 的残余）�?没有一条是机制写错�?完全错误"的程度（这比第五轮的 3 条好）；�?*唯一�?P2 的那条是虚高**�?�?*这个区域的全�?新洞"其实在第五轮就已经存�?*——这是本轮该记住的结论�?
## 2. 逐条理由

### Z08-1 �?NOT-A-FINDING（重�?A-FE-9/V-2�?原报告的每一项——`webui.go:119-127` 的回退、`200 text/html`、`len=3304`�?"状态码监控看不到发布不完整"——都�?`docs/audit-5/findings/frontend-VERIFIED.md:330-340`（V-2）里�?连修法（"�?`_app/immutable/**` 的未命中回真 404"）都逐字相同。唯一新增是把它叫"P3 + 失败静默"�?探针本身不假：`start.abc.js �?200 text/javascript + immutable` 是有效阳性对照（我复跑并�?`z08verify_test.go` 里用真进程再证一次：真实资产 `start.DJJzSbG0.js �?200 text/javascript`�?缺失�?�?`200 text/html`，且 **len=3304 == shell len=3304**）�?*问题在归类，不在证据�?*

### Z08-2 �?NOT-A-FINDING（重�?A-FE-1�?A-FE-1 及其复核结论（`frontend-VERIFIED.md:23,41-71`）：实测 `ETag=""`、`Last-Modified=""`�?条件请求永远 200 全量，判**�?*。原报告换了措辞�?不可能变�?304"）但无新事实�?机制我也核到：`embed.FS` �?`ModTime()` 为零 �?`http.ServeFileFS` 不发 `Last-Modified`�?项目只设 `Cache-Control: no-cache`（`webui.go:147-148`）——与观测（真进程 `etag="" lm=""`）一致�?
### Z08-3 �?DOWNGRADED（核心重�?V-4，事实另有错误）
`/app/_app/version.json` 无任�?`Cache-Control` 由第五轮 **V-4** 记录（并已给�?"顺手给它 no-cache/no-store"的修法），原报告的核心射程与之一致。真正新的只�?`/app/favicon.svg` �?`/app/robots.txt` 副本无缓存指令——纯卫生，且 **`/app` 下的 `robots.txt`
副本�?`webui.go:69-82` 本就不该被爬虫读�?*，给它缓存策略没有意义。真进程复核�?�?`/robots.txt` �?`public, max-age=3600`（`server.go:559`），`/app/robots.txt` 无——这�?*有意**�?（同一个文件的两个路由，一个给爬虫、一个只是嵌入产物的副本）�?
### Z08-4 �?NOT-A-FINDING（重�?A-FE-2，且原判就偏高）
A-FE-2 = "�?HTML 文档�?Range �?206 半截 shell"，第五轮复核�?*降为提示**（无可达危害�?浏览器导航不�?Range、半截文档里仍是应用自己的脚本、响应带 `no-cache`）。原报告拿到的是
同一现象的一个特例（缺失名回退后也�?Range），机制、修法与后果都已�?V-2/A-FE-2 内�?它把已判"提示"的东西重新包装成 P3，属**严重度回升式重报**�?
### Z08-5 �?DOWNGRADED P2→P3（机制成立，严重度评高）
机制�?*独立复现**（真进程 17802，自建二进制）：
`/app/consent �?cc="no-cache" vary="Cookie, Accept-Encoding"`�?`/app/_app/immutable/entry/start.DJJzSbG0.js �?cc="public, max-age=31536000, immutable" vary="Cookie, Accept-Encoding"`�?根因 `alexedwards/scs/v2@v2.9.0/session.go:139` 无条�?`w.Header().Add("Vary","Cookie")`�?�?`server.go:617-618` 把会话中间件包住**整棵�?*。压缩层在外层（`server.go:625-627`），
`addVary` 在写头时发生 �?原报告修�?(a)（在 `webui.Handler` �?`Del("Vary")`�?*技术可�?*，这条无需更正�?**�?P2 站不�?*�?1) 安全影响为零（对任何 Cookie 字节相同，不会把别人的内容缓存给谁）�?(2) 触发前提是部署一�?*项目本身不提供、也不在交付物里**的共享缓存（�?nginx/CDN 配置、无 Docker）；
(3) "失败是静默的"论证很弱——这里没�?报成�?退�?0"，只�?缓存没帮上忙"�?且第�?五轮把它当作**减少共享缓存命中的有利因�?*（`frontend-VERIFIED.md:65`）�?它是**一处加固项**：与第六�?A-FE-9 一族无关（主代�?V-13 已同意可压到 P3，我压）�?
### Z08-6 �?NOT-A-FINDING（重�?A-FE-3 + V-1�?`scopeViews` 静默 `continue`（`authorization_routes.go:188-190`）是 A-FE-3 的机制；
设备流第�?第三份实现是复核 V-1�?今天不可达（两个注册表都�?`oauth.DefaultRegistry()`�?
也已�?`docs/audit-5/findings/frontend.md:288` 写明。我核了组合根：`main.go:1279` 造一�?registry�?`openOIDC` **不把它交�?`httpapi.Config`**，于�?`server.go:260-262` 再造一�?`DefaultRegistry()`—�?同内容、两个实例，原报告的可达性论述正确。但原报告的探针用的�?*人为分叉的注册表**�?�?�?结论（一�?High 风险�?*已描�?* scope 被隐藏授予）在原报告自己写明不可达的前提下，
等于一�?HYPOTHESIS�?*不构成新发现**；其修法（单一来源 + 别静默）与第五轮一致，值得照做�?
### Z08-7 �?CONFIRMED P3（并纠正"静默"的表述）
机制复到行：`device_routes.go:114-115` �?`:131-138` 只比�?`body.Decision == "approve"`�?无白名单；未知�?�?`approve=false` �?`memory/oidc.go:1381-1382` �?`DenyDevice`，该码被**终结**
（后续同一码会得到 `oauth.ErrDeviceNotFound`），�?消耗设备码"**成立**。原探针红（我复跑：
`decision "" was answered 200 {"state":"denied"}`）。两点更正：
�?�?*不是全静�?*——`device_routes.go:131-135` 会发 `observability.DeviceDenied` 指标�?只是�?用户真的点了拒绝"不可区分；② 它同时是**契约违背**�?`docs/openapi.yaml:2300-2302` �?`decision` 声明�?`enum: [approve, deny]`�?而授权决策那侧（`:2228`）明�?其它�?= 400"，设备侧（`:797-801`）的 400 文案却只�?malformed body / scope"�?所以它�?**docs vs 实现不一�?+ fail-closed 但会消耗码**，P3 准确�?
### Z08-8 �?CONFIRMED P3（独立浏览器证据 + 阳性对照）
源码：`web/src/routes/+page.svelte:63-84` �?`default` 分支返回 ``登录没有完成�?{code}）。``�?`code` 来自 `new URLSearchParams(location.search).get('error')`（`:40-41`）。我**没有**复用原报告的脚本�?自写 `z08verify/browser_probe.mjs`（真 Chromium 1243，对 17802 的真进程）：
`payload_escaped_in_html=true`、`img_count=0`、`window_flag=null`�?�?*阳性对�?*：同一载荷放进 `data:text/html` 页时 `window_flag=1`、`img_count=1`
（证�?没执�?不是探测器坏了）。同一跑还给出 `consent_h1="授权请求"`、`csp_violations=[]`�?�?*独立复现�?探过没破"#7**。剩余问题（URL 决定页面文案）确如原报告所述，P3 合适�?
## 3. 假守�?/ 反空转（我对 24 �?探过没破"逐条看了阳性对照）

**唯一一条结构性不可能失败�?20 开放重定向�?*�? Z08V-1）。其�?23 条我都核过，
其中 #1/#6/#7/#15/#21/#22 的对照是真的（重算哈希、逐字节比对、`reached` 计数�?`fetch(`/`AbortController` 阳性串、CSS 文件数非零）�?8/#9 �?CSRF 走查�?`docs/openapi.yaml`
枚举且断言 `gated == checked`（我复跑：全绿，14 个变更操作逐条 `none=403 wrong=403 real=�?403`）�?
## 4. 新发�?
### Z08V-1 [P3 · 报告质量] "开放重定向�?的绿是假守卫：该探针永远到不了任何重定向
- 证据（原探针自己的输出，我复跑并用自己的真进程再证）�?  ```
  /auth/z08idp/start?return_to=//evil.example   -> 404 loc="" body="unknown provider"
  /bind?game=g&source=s&return_to=//evil.example -> 401 loc="" body="sign in to bind a source"
  ```
  内存模式**没有配置 IdP**（`/auth` 路由在启动期�?registry 装配），所以那�?`start` 根本走不�?  "�?`return_to` �?302"；`/bind` 匿名在鉴权处就返回了。探针的"阳性对�?只是 `seen++`（计�?6 次请求）�?  **不是**"真的到达了重定向分支"。⇒ 它对"开放重定向"零信息量�?- 真实守卫存在且另有测试：`safeurl.RelativePath`（`safeurl/safeurl.go:34-53`�?  拒绝 `//`、`\`、控制字节）�?`internal/auth/auth.go:599` �?`:636` 两处使用�?  `internal/auth/auth_test.go:254 TestReturnToIsSanitized` 钉住它�?*产品没有洞，是报告的守卫是假的�?*
- 我的探针：`z08verify_test.go::TestZ08VOpenRedirectGreenIsVacuous`（绿；若哪天出现�?`evil.example`
  �?302 它会红）。修法：把这条从"探过没破"删掉，或改用它已有的全接线夹�?  （`newZ08Env` 配了 provider）走�?start→callback 再断言 `Location`�?
### Z08V-2 [P3 · 报告质量] Z08-3 �?构建产物�?`version.json` 引用"是错的（方向是低估）
- 原报�?Z08-3 �?本机构建里客户端没有轮询它——grep 构建产物�?`version.json` 引用——所以今天只有潜在风�?�?- 实测：`internal/webui/dist/_app/immutable/chunks/DqohD3-m.js` 里有
  ``fetch(`${de}/_app/version.json`,{headers:{pragma:`no-cache`,"cache-control":`no-cache`}})``
  �?`...version!==fe` 的比对逻辑（SvelteKit �?`updated` 检查函数）�?*引用存在�?*
- 影响：不是新洞，但原报告用这个假事实�?V-4 的风�?*往下限**了；实际�?部署新鲜度探测代码随产物发出"�?  更支持给 `version.json` 明确缓存指令。（是否被应用订�?调用我没有证明，仍属未到达。）

## 5. 未能到达（残余盲区）
1. **共享缓存的端到端后果**：本机无 docker/nginx/CDN，Z08-5 �?�?Cookie 分键/拒绝缓存"
   仍是 RFC 9111 §4.1 �?nginx 既有行为�?*推导**。机制（scs 一�?+ 真进程响应头）是实测的�?2. **�?Postgres**：与前端平面无关；Z08-6 的两注册表关系只在内存组合根验证�?3. **浏览器只�?Chromium 1243**：无 Firefox/WebKit；`frame-ancestors`、meta CSP 哈希�?   `Vary` 的引擎差异未测（与原报告盲区 4 相同）�?4. **Z08-7 �?码被消�?只有源码�?+ 原探针的 200 �?*：我没有自建完整设备流夹�?   （`memory/oidc.go:1378-1382` �?`st.Denied �?ErrDeviceNotFound` 链是确定的，但没跑第二次决策）�?5. **CI 构建产物**：我用的是本�?`internal/webui/dist`（未入库），CSP 哈希/资源集合�?CI 上是否一致仍需�?CI 产物上重跑�?
## 6. 判断（不�?finding�?- 原报告的**负面结论我一条都没打�?*：缺失资�?200、无校验器、Range 拼接、`Vary: Cookie`�?  未知 decision、`?error=` 反射全部独立复现；CSP/转义/CSRF/遍历/�?CORS 的绿也复现�?  这个区域确实没有未认证绕过、没有跨账号读、没有凭据泄露�?- 原报告的红探针计数是对的（我实测 **10 FAIL / 27 PASS / 0 SKIP**，合�?37 个测试函数）�?  �?29 条绿探针"多算�?2 条（应为 27）�?0 个红测试函数 = 8 条发现各自的否决断言，其�?Z08-1/Z08-4/Z08-5
  同时在合成树与真进程两条路径上各有一条（�?2），Z08-8 的红在浏览器脚本里、不�?Go 套件里�?- 最该改的是**编号纪律**：Z08-1/2/4/6 都应写成"�?A-FE-1/2/3/9 + V-1/V-2/V-4 的复述（无新增）"�?  而不�?与既有编号无�?。按简�?§4.3，它们不该占"新发�?的名额�?