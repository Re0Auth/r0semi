# 前端报告复核（frontend.md → frontend-VERIFIED.md）

> 角色：证伪。目标报告 `docs/audit-5/findings/frontend.md`（A-FE-1 … A-FE-11）。
> 本文件按 `docs/audit-5/VERIFY-BRIEF.md` 的六段格式写。所有命令都在本机真的跑过；
> 读代码的地方标「读」。
>
> **一句话总结**：11 条发现里 **10 条的事实/机制部分我独立复现成功**
> （A-FE-1/2/3/4/5/6/8/9/10/11；A-FE-7 我只复现了它引用的渲染文本，因为它是设计判断），
> 但 **3 条严重度评高**（A-FE-1 中→低、A-FE-2 中→提示、A-FE-9 中→低），
> **2 条的可达性论述被推翻**（A-FE-1 的「CSP 哈希漂移导致白屏」在结构上不可能；A-FE-9 的
> 「不同字节拿到同一 URL」与「缺资产回 404」实测都不成立），
> 另有 **1 条「唯一入口」论断被推翻**（A-FE-3：设备流有第二份独立实现，我端到端跑出来了）。
> 报告里所有**负面结论**（无可绕过、无跨账号读、无凭据泄露、CSP/XSS 干净）我都独立复跑过，
> **没有一条被我打破**，而且我把「产物扫描」的 21 条正则做了**阳性对照**（21/21 在植入语料上命中），
> 所以「0 命中」不是正则写坏的假清白。

---

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|---|---|---|---|---|
| A-FE-1 | 中 | **低** | 部分成立 | 无验证器 + `no-cache` 实测如实（`etag/last-modified` 为空，任何条件请求都回 200 全量），但**「CSP 哈希与新构建不匹配 ⇒ 白屏」结构上不可能**：哈希与内联脚本在同一份文档里，漂移不了；浏览器路径 `no-cache` 已封住陈旧 shell，残余只落在**违反 RFC 9111 §5.2.2.4 的中介**上 |
| A-FE-2 | 中 | **提示** | 机制成立 / 严重度推翻 | 206 + 半截 shell 复现（含「range 起点越过 meta ⇒ 文档没有 meta 策略却带完整内联脚本」这一条），但**没有可达危害**：浏览器导航不发 Range，半截文档里的脚本仍是应用自己的启动脚本，且该响应同样带 `no-cache` |
| A-FE-3 | 低（任务书写「中」） | **低** | 部分成立 | 三集背离端到端复现（displayed=`account.id` / granted=`account.id openid profile email`），userinfo 只回 `sub`、id_token 无 `name/email` ⇒ 确认**无数据能力**；但「`authorization_routes.go:189` 是唯一入口」**被推翻**（见 V-1） |
| A-FE-4 | 低 | 低 | CONFIRMED | `web/` 下确无 `svelte.config.*`；配置内联在 `vite.config.ts:46-110`。纯可维护性，低站得住 |
| A-FE-5 | 低 | 低 | CONFIRMED | `--audit-level high` → `1 vulnerabilities found / Severity: 1 low` / **exit 0**；`--audit-level low` → exit 1；`cookie` 在生产包里**不可达**（三个特征串 0 命中）。「门永不响」属实，暴露面确实为零 |
| A-FE-6 | 低 | **提示** | 部分成立 | 「只对名为 index.html 的响应设策略」实测属实（MapFS 里的 `extra.html` 拿到空 CSP），但**不是可达缺口**：真实产物只有 1 个 HTML 文档，唯一的另一份 HTML（未构建 503 页）**不含任何 `<script>`**，且真实组合根对所有响应都发 `frame-ancestors 'none'`（我在活服务器上逐个响应验过） |
| A-FE-7 | 低 | **提示** | 事实成立 / 归类错误 | 同意页顶部确实渲染主导航（浏览器实测文本 `r0 Re0Auth 账号 应用 数据源 授权请求 …`），但报告自己写着「属于设计裁定」⇒ 按 BRIEF §5 应写进「判断」，不是 finding |
| A-FE-8 | 提示 | 提示 | CONFIRMED | `web/src/lib/assets/favicon.svg:1` 确是 `<title>svelte-logo</title>` + `#ff3e00`；`static/favicon.svg` 不含 svelte 字样，`app.html:20` 引的是 `%sveltekit.assets%` ⇒ 该副本未被引用 |
| A-FE-9 | 中 | **低** | 部分成立 | 机制与数字**逐项复现**（12/20 改名、13 个名称与字节都不变、`index.html`/`version.json` 同名变内容、13 位时间戳只在 1 个分块里），但两条危害论述**被实测推翻**：改内容的分块**从不保留旧名**（3 次构建 0 例）⇒ 不是缓存投毒；缺失资产**回 200 HTML 而不是 404**（V-2）。剩下的是「架构原则 §1.4 声称产物可复现」与实际不符 + 每次部署整图改名 |
| A-FE-10 | 提示 | 提示 | CONFIRMED（比原报告更强） | `console.warn`=6、`console.error`=1、`svelte.dev` 全在 vendor 分块；21 条扫描 + 阳性对照通过；**补充**：那 6 个 warn 函数在产物里有**未被 `DEV` 门保护**的调用点，所以「dev 块被编译掉所以不可达」这条理由不成立，只能靠「应用走不到」 |
| A-FE-11 | 提示 | 提示 | CONFIRMED | `%SC%` 递归 0 项、`git status`/`git ls-files`/`git check-ignore`（exit 1，即未被忽略）三者都确认；`scripts/web/deploy/config/.github/Makefile` 零命中。**但对上线报告的价值接近 0** |

**严重度被低估的：没有。** 我找不到任何一条应该往上调的——三条偏高，其余持平。

---

## 2. 降级或推翻的理由

### 2.1 A-FE-1（中 → 低）：危害的一半是结构上不可能的，另一半要靠违规中介

报告的不变量写作「**被部署的 HTML 与它所声明的 CSP 哈希必须是同一份构建**」，影响段写：
> 旧 shell + 新构建的资产名 = 白屏，或反过来**旧 shell + 新哈希 = 启动脚本被 CSP 拦下**、同样白屏。

第二半不可能成立：`script-src` 里的 `sha256-…` 与那段内联 bootstrap 脚本**在同一个字节流里**
（`internal/webui/dist/index.html`：meta 标签在 1079..1355，内联脚本在 2746..3126），
哈希由构建方对同一份脚本算出（`web/vite.config.ts` 的 `kit.csp`）。陈旧 shell 携带的**是它自己那份脚本的哈希**，
两者永远自洽——**陈旧 shell 不会因为哈希而白屏**，只会因为它引用的旧资产名在新部署里消失（见 V-2，那条的机制报告也写错了）。

真正的另一半风险是「陈旧 shell 被当作新 shell 用」。这一半被 `Cache-Control: no-cache` 封住。我实测：

```
=== shell  GET /app/consent -> 200
    cache-control: no-cache          etag/last-modified: 不存在
=== If-None-Match (bogus)  -> 200 (body 3153)
=== If-Modified-Since (old) -> 200 (body 3153)
```

以及 Go 侧探针（`internal/zzprobe/verifyfrontend`）：`Cache-Control="no-cache" ETag="" Last-Modified=""`，
`If-None-Match` / `If-Modified-Since` / `If-Range` 三种都回 **200 + 3303 字节全量**。
`no-cache` 的语义是「复用前必须成功校验」；没有验证器 ⇒ 校验不可能成功 ⇒ **任何合规缓存都必须回源**。
所以**浏览器永远拿不到陈旧 shell**，风险只落在「忽略 `no-cache` 的缓存」上：企业代理/杀毒 MITM 的启发式缓存、
或把 `Cache Everythin` / Edge Cache TTL 覆盖到 HTML 上的 CDN。项目自己没有任何 SW（产物里只有 SvelteKit
自己的 `navigator.serviceWorker.getRegistration` 检查，没有注册）。应用是 `Vary: Cookie` 的，也进一步减少共享缓存命中。

剩下的第二条后果（每次导航重新下载 3.1 KB / gzip 1.7 KB）我确认属实，但这是**带宽**，不是可用性：
`content-length: 1740`、`content-encoding: gzip`（活服务器实测）。

**结论**：机制 CONFIRMED，危害「部分成立」。加 ETag 是**正确的加固**（报告自己也写「不是裁定，是纵深防御」），
但按 BRIEF §7 的判据，前提是「运维部署了一个违反 RFC 的缓存」⇒ 应该降为**低**。

### 2.2 A-FE-2（中 → 提示）：机制真，危害不可达

机制我复现了，而且比报告更精确（`TestVRangeCanStripTheMetaPolicyButKeepTheScript`）：

```
Range bytes=1355-  -> 206 Content-Range="bytes 1355-3302/3303" len=1948  meta=false  script=true
header policy on the partial response: "frame-ancestors 'none'"
```

即：**只要客户端自己挑一个起点越过 meta 的区间**，拿到的文档就没有 `script-src`，而里面那段内联脚本是**完整的**。
报告这条子论断成立。但把它当「安全」问题站不住：

1. 谁会渲染它？浏览器导航**从不**对 HTML 发 Range（这是报告自己承认的）。要走到「没有策略的文档被执行」，
   必须是一个**主动挑了字节区间、又把结果当文档渲染**的客户端——不存在这种浏览器行为。
2. 即使存在，文档里的脚本**就是应用自己的 bootstrap**，攻击者无法往里注入任何东西，
   所以「策略缺失」不产生新的执行能力，只产生「应用自己的脚本在更弱的策略下运行」。
3. 那份 206 响应同样带 `Cache-Control: no-cache`，所以「截断实体被缓存下来分发给别人」需要一个
   **既把 206 当整份实体存、又忽略 no-cache** 的双重违规缓存——比 A-FE-1 的前提更刁钻。

按 BRIEF §7，这是**提示**。修法（对 shell 关掉 Range）仍然可以照做，成本一行。

### 2.3 A-FE-3（任务书写「中」，报告写「低」→ 我判 低）：机制确认，但「唯一入口」被推翻

三集背离我端到端重跑成功（两次独立方法：报告自己的 `scope-narrowing.mjs`，以及我写的
`verify-web/scope-grant-probe.mjs`）：

```
requested : openid profile email account.id
displayed : account.id
granted   : account.id openid profile email
userinfo  : 200 {"sub":"usr_7c53e8dd5c56d1d98df0e0c6a4070789"}
id_token claims : {"iss":…,"aud":["cli"],…,"at_hash":…,"c_hash":…}   ← 无 name / 无 email
```

浏览器侧同样成立（我的 `zzverify-frontend.spec.ts` 第 1 条，**故意写成「背离存在才通过」**）：
`displayed=["account.id"]`、`granted=["account.id","openid","profile","email"]`。

**「要确切说出用户被误导了什么」**：报告说同意页那句「该应用将获得以下权限」**严格来说是假的**。
我不接受这么强的表述，理由是项目自己的文档把 scope 分成两类且对 claim scope 明确定义为零操作——
`docs/oidc-decision.md:37`（O-3「userinfo 默认只返回 sub，email 永不返回」）、
`:40`（O-6「offline_access 是兼容性空操作」）、`internal/oidcstore/oidcstore.go:255-262`
（「profile/email 等 claim scope 作为 no-op 接受」）、`oauth/scope.go:124-131`（目录只描述数据权限）。
按这套定义，页面上那句话列的是**权限**，而 `profile/email` 按定义**不是权限**，所以那句话不是假的。
用户真正被误导的**范围是零**：页面上多了什么？没有。少显示了什么**他能观测到的能力**？没有。
唯一「书面事实」层面的不一致是令牌响应的 `scope` 字段（客户端可见）比页面列的多三项——
**被误导的是 RP，而 RP 本来就在请求里写了这三个 scope**。所以：**低**（甚至可归为提示），
而**任务书里的「中」是评高了**。报告自己写的低是对的。

**被推翻的部分**：报告在「判断」一节写
> `scopeViews` 静默丢弃目录外的 scope（`authorization_routes.go:189`）：…它是那类「显示少于授予」的**唯一入口**。

不成立。见 V-1。该修法只改 `authorization_routes.go:189` 会漏掉设备流。

### 2.4 A-FE-9（中 → 低）：数字全对，两条危害不成立

先把报告的数字逐项复现（我连跑两次 `cd web && pnpm run build`，每次对 `internal/webui/dist` 逐文件 sha256）：

```
run1 -> run2 : same-name/same-bytes=13   same-name/DIFFERENT-bytes=[index.html, _app\version.json]
               renamed=12                renames-that-are-byte-identical=[]
run0 -> run1 / run0 -> run2 : 完全同样的 13 / 2 / 12 / 0
```

- 「12 个分块内容与文件名一起改写」：**CONFIRMED**（12 个改名，全部在 `_app/immutable` 下）。
- 「另外 8 个名称与字节都不变」：**CONFIRMED**（8 个 js + css + favicon + robots = 13）。
- 根因定位：**CONFIRMED**。`_app/version.json` = `{"version":"1790525957345"}` → `2026-09-27T16:19:17.345Z`，
  正好是第二次构建的时刻；产物里**只有 1/20 个分块**含 13 位时间戳（`_app/immutable/chunks/-qnciKPy.js`），
  里面同时有 `fetch(`${de}/_app/version.json`,{headers:{pragma:`no-cache`,"cache-control":`no-cache`}})`
  和内联常量 `fe=`1790525957345`` —— 与报告描述逐字一致。

**危害一「两个不同的字节序列会拿到同一个 URL（`chunks/BGyvQZmW.js` 今天是这份内容，下次部署是另一份）」——推翻。**
这就是任务书要求「settle it with evidence」的那条，答案是**无害方向**：

- 内容变了的 `_app/immutable/*` 文件**从不保留旧名**：三次构建的两两对照里，「同名不同字节」只出现
  `index.html` 与 `_app/version.json` 两个（都不在 `immutable/` 前缀下，都不吃一年缓存）。
- 改名的文件**确实也改了字节**：`renames-that-are-byte-identical=[]`（若只是改名而内容不变，那才是「按时间戳命名」的病）。
- 也就是说 `immutable` 的承诺**没有被违反**：一个 `immutable` URL 从不会指向两个不同的字节序列。
  改名方向是「内容变 ⇒ 名字变」（预期行为，只是不必要地波及 12 个分块）。

**危害二「旧文档请求的资产在新部署里不存在（`http.ServeFileFS` 回 404，SPA 回落不会替脚本文件兜底）」——括号里的两个事实都推翻。**
实测（`verify-web/missing-asset-probe.mjs` + Go 探针 `TestVMissingAssetIsAnsweredWithTheShellNotA404`）：

```
/app/_app/immutable/entry/start.DELETEDBYDEPLOY.js -> 200 ct=text/html; charset=utf-8 cc="no-cache" body=<!doctype html>…
/app/_app/immutable/chunks/gone.js                 -> 200 ct=text/html; charset=utf-8 cc="no-cache" body=<!doctype html>…
/app/nothing-here.png                              -> 200 ct=text/html; charset=utf-8 cc="no-cache" body=<!doctype html>…
```

`internal/webui/webui.go:119-121` 在 `ServeFileFS` 之前就把任何「不是文件」的名字改写成 `index.html`，
所以 **ServeFileFS 根本不会为缺失资产发出 404**，SPA 回落**恰恰替脚本文件兜底了**。
白屏的结论仍然对（`nosniff` + 模块脚本的 MIME 检查会拒绝 `text/html` 的 JS），
但机制、以及报告用来支撑它的那行代码事实是错的。

**剩下什么**：`docs/architecture.md:12` 把「**构建产物可复现**、可签名」写成设计原则 §1.4，
而 `internal/webui/dist` 每次构建都变；`docs/dependencies.md:107-114,121-131` 的发布链
（SBOM、`SHA256SUMS`、cosign keyless 签名）让读者可以「按源码重建再对哈希」，而这条路走不通。
这是「文档与实现不一致 + 供应链证据的可核对性」，按 BRIEF §7 是**低**。报告写**中**，我降为低。

### 2.5 A-FE-5（低，CONFIRMED）与「cookie 的真实暴露」

门确实永不响，且我复现了三个 exit code：

```
pnpm audit --registry=https://registry.npmjs.org --audit-level high
  → 1 vulnerabilities found / Severity: 1 low      exit=0      （CI 用的就是这条，ci.yml:335-337）
pnpm audit --registry=https://registry.npmjs.org --audit-level low
  → cookie <0.7.0 low / GHSA-pxg6-pf52-xh8x        exit=1
pnpm audit --audit-level low      （本机默认 registry=npmmirror）
  → [ERR_PNPM_AUDIT_ENDPOINT_NOT_EXISTS] ...        exit=1
```

`web/.npmrc` 只有 `engine-strict=true`，`ci.yml` 的 supply-chain 作业不设 registry ⇒ CI 上是 npmjs，
所以 CI 上「能跑但永不响」。实装版本 `node_modules/.pnpm/cookie@0.6.0`，锁文件里 `cookie: 0.6.0` 单条。

**暴露面**：报告说是 HYPOTHESIS；我把它做成了可核对的负面结论——
产物里 `cookie` 的三个特征串（`argument str must be a string` / `fieldContentRegExp` /
`cookie is expected to have`）**0 命中**，`\bCookie\b` 0 次、`document.cookie` 0 次。
即：**发行产物里没有任何 `cookie` 代码**（它只被 `@sveltejs/kit` 的服务端/开发路径使用，
而本项目 `adapter-static` + `ssr=false`）。所以「一条不会响的门」是流程缺陷，**零运行时暴露**，低站得住。
（顺带：那条 `ERR_PNPM_AUDIT_ENDPOINT_NOT_EXISTS` 是**响的**——镜像没实现端点会让命令失败，
所以「镜像环境里门静默通过」这个担心不存在，报告把它写成盲区是过虑了。）

### 2.6 A-FE-6（低 → 提示）：模块边界上的缺口，真实组合里不存在

我独立钉住了三种响应的策略归属（`TestVWhichResponsesGetTheDocumentPolicy`）：

```
/app/                            -> ct=text/html  csp="frame-ancestors 'none'"
/app/consent                     -> ct=text/html  csp="frame-ancestors 'none'"
/app/extra.html                  -> ct=text/html  csp=""            ← 报告这条属实
/app/plain.txt                   -> ct=text/plain csp=""
/app/_app/immutable/chunks/a.js   -> ct=text/javascript csp=""
not-built（fsys 为空）            -> 503 ct=text/html csp=""  script=false
```

再补两个事实：① 真实产物里**只有 1 个 HTML 文档**（`TestVTheRealBuildContainsExactlyOneHTMLDocument`：
`html documents in the built tree: [index.html]`）；② 真实组合根把每个响应都盖上
`frame-ancestors 'none'`（活服务器逐条验过：shell / favicon / js / version.json / robots.txt / problem+json / oauth JSON 全带）。
③ 唯一的另一份 HTML（未构建 503 页）**不含 `<script>`**，且只有在「编进了一个没有前端构建的二进制」时才可能出现——
那种二进制**永远**走这条分支，不可能与已构建的 shell 并存。

所以报告说的「只有在有人把 `webui.Handler` 单独挂出去时才成立」是对的，而那不是任何**部署配置**下的情形
（BRIEF 的判据：前提是「运维做了一件没人会做的事」⇒ 降级）。降为**提示**；「把规则从文件名改成 `text/html`」
作为加固仍然值得做。

### 2.7 A-FE-7（低 → 提示，且归类错误）

事实成立（浏览器实测同意页可见文本以 `r0 Re0Auth 账号 应用 数据源 授权请求 …` 开头），
但报告自己在「影响」里写「这一条是**可用性/可信度**问题」、在「判断」里又写「属于设计裁定」。
BRIEF §5 明确要求「若你认为某个文档化决定本身是错的，单独写成判断，永远不要写成 finding」。
一个纯设计取舍（导航要不要在同意页收起）不是可失败的性质，**没有测试能让它失败** ⇒ 违反 BRIEF §3。
建议：把它从「发现」挪进「判断」。

### 2.8 A-FE-10（提示）：确认，并且比报告说得更硬

21 条正则 + **阳性对照**（我把每条正则自己的植入串拼成语料，21/21 全部命中）⇒ 「0 命中」不是正则坏了。
产物实况与报告完全一致：`console.warn`=6（全在 `_app/immutable/chunks/B-QHV2o-.js`）、
`console.error`=1（在 `entry/app.*.js`）、`console.log`/`debugger`/`sourceMappingURL`/`localhost`/`127.0.0.1`/
`@vite`/`@fs`/`import.meta.env.DEV`/`NODE_ENV!=='production'`/私钥/AKIA/ghp_/xox/JWT/Bearer/长 base64/`usr_`/`cli_` **全 0**。

**比报告更强的一点**：报告说「Svelte 5 生产构建会把 dev 块编译掉，所以未证实可达」。
我查了调用点，那 6 个 warn 函数**在产物里有未被 DEV 门保护的调用点**：

```
function Ce(){console.warn(`https://svelte.dev/e/derived_inert`)}
  … if(!lr&&r!==null&&e.v!==C&&r.f&24576)return Ce()      ← 真实运行时条件，不是 false&&
```

所以「不可达」不能靠「dev 块被删」来断言，只能靠「应用没有状态能走到」。
我在浏览器里走了一遍 sign-in → `/app/` → grants → sources → device → consent：
`console warnings during an app walk: []`（`zzverify-frontend.spec.ts` 第 3 条，**打印而非断言 0**）。
即：**在这些路径上不可达（观察），但函数不是死代码（读产物）**。严重度仍是提示，结论不变。

### 2.9 A-FE-11（提示）：确认，但请从上线报告里删掉

`Get-ChildItem -LiteralPath '%SC%' -Force -Recurse` → 0 项；`git status --porcelain -- '%SC%'` 空；
`git ls-files -- '%SC%'` 空；`git check-ignore -v -- '%SC%'` → exit 1（**未被忽略**，只是未跟踪）；
在 `scripts/ web/ deploy/ config/ .github/ vault/ cmd/ internal/ docs/ Makefile` 里搜 `%SC%` 零命中。
它在报告里占了一整条发现，但**不指向任何存在于仓库里的东西**（未跟踪、无引用、一次性 shell 调用的产物）。
对一份「上线前审计」来说这是噪音：建议降为附注或删掉。

---

## 3. 确认的（每条一行：我执行了什么 + 那一行有承载力的输出）

1. `go test ./internal/zzprobe/frontendaudit/ -v` → **7/7 PASS**，含 `validators: ETag="" Last-Modified=""`、`Range bytes=0-3 → 206 "<!do"`、`inline scripts covered by a declared hash: 1`，且穿越 10 条路径无一泄漏（对照组先证明能拿到 shell）。
2. `go test ./internal/zzprobe/verifyfrontend/ -v`（**新建**）→ **5/5 PASS**：策略归属 5 种响应、真实产物只有 1 个 HTML、条件请求永远 200、Range 越过 meta 后 `meta=false script=true`、缺失资产 `200 text/html`。
3. `cd web && pnpm install --frozen-lockfile` → `Already up to date`；`pnpm run build` ×2 → 每次 27 个文件；逐文件 sha256 对照：**改名 12 / 同名同字节 13 / 同名异字节 2（index.html、version.json）/ 改名且字节相同 0**。
4. `node docs/audit-5/probes/web/scope-narrowing.mjs` → `displayed: account.id` / `granted: account.id openid profile email` / **exit 0**（无数据 scope 被静默授予）。
5. `node docs/audit-5/probes/verify-web/scope-grant-probe.mjs`（**新建**）→ `userinfo: 200 {"sub":"…"}`；`id_token claims` 无 `name`/`email`；`/v1/me` 回 200 并回显 `scopes`。
6. `node docs/audit-5/probes/verify-web/device-scope-split.mjs`（**新建**）→ 设备页 `displayed: phigros.b30.read`、令牌 `granted: phigros.b30.read openid profile email`。
7. `node docs/audit-5/probes/verify-web/wire-probe.mjs`（**新建**）→ shell `cache-control: no-cache`、无 `etag`/`last-modified`；资产 `public, max-age=31536000, immutable`；`version.json` `content-type: application/json` 且**没有任何 Cache-Control**。
8. `node docs/audit-5/probes/verify-web/range-meta-probe.mjs`（**新建**）→ `Range bytes=1355- → 206 … meta=false script=true </html>=true`。
9. `node docs/audit-5/probes/verify-web/missing-asset-probe.mjs`（**新建**）→ 三条缺失路径全部 `200 text/html`。
10. `node docs/audit-5/probes/verify-web/bundle-verify.mjs`（**新建**）→ 真实产物 19/21 条扫描 0 命中（2 条命中＝console.warn 6 / console.error 1）；**阳性对照 21/21**；`cookie` 特征串 0 命中。
11. `node docs/audit-5/probes/verify-web/stamp-census.mjs`（**新建**）→ `chunks carrying a 13-digit epoch: 1/20`；`version.json → 2026-09-27T16:19:17.345Z`（＝第二次构建时刻）。
12. `pnpm audit`（high/low/默认 registry 三种）× → exit 0 / exit 1 / `ERR_PNPM_AUDIT_ENDPOINT_NOT_EXISTS`。
13. `pnpm exec playwright test --grep-invert @visual --reporter=list`（真实 Go 二进制 + 假 IdP，我起的 server）→ **67 passed**（含报告新写的 18 条对抗用例与 10 条 @visual）。
14. `pnpm exec playwright test zzverify-frontend --reporter=list`（**新建 spec**）→ **3 passed**：背离可观测、缺失分块回 200 HTML、应用走过路径 0 条 console 警告。
15. `git status --porcelain internal/webui/dist` → **空**；`git check-ignore -v internal/webui/dist/index.html` → `internal/webui/dist/.gitignore:1:*` ⇒ 构建不污染被跟踪树（我构建两次后复核）。
16. 负面结论（**未破**）：`{@html}`/`innerHTML`/`outerHTML`/`document.write`/`insertAdjacentHTML`/`eval(`/`new Function(`/`{@debug}`/`setTimeout('…')` 在 `web/src`+`static`+`scripts` **0 命中**；`fetch(` 只出现在 `lib/api.ts:336`；13 个写端点**全部**传 `csrf`（`api.ts:412,429,441,453,459,473,486,489,492,495,500,505,516`）；注入用的敌对 scope 在 `/oauth/authorize` 与 `/oauth/device_authorization` 两端都被 `invalid_scope` 拒绝（0 条进入目录/DOM）。

---

## 4. 我未能验证的

- **A-FE-1 的中介侧**：本机无 Docker、无 nginx/CDN，我没有在一个**真的忽略 `no-cache` 的缓存**上观察到陈旧 shell。
  我给出的「哪个客户端仍会受影响」是**推理**（企业代理/AV MITM 的启发式缓存、CDN 的 Cache Everything / Edge Cache TTL 覆盖、
  以及任何自己写 cache-first 逻辑的运维层），没有实测。要证实需要一个可编程代理（或者一个会无视 origin 头的 CDN 账号）。
- **跨引擎**：全部浏览器结论来自 Playwright 1.63 自带的 **Chromium 1243**（已装）。Firefox/Safari 对
  meta `form-action`、`frame-ancestors` 的实现差异我没有跑过任何一条。报告把它写进盲区是对的。
- **A-FE-9 在 Linux/容器里的复现**：我只在 Windows + 本机 pnpm 11.8/node 24.17 上连跑两次 + 一次原地对照，
  没有在 CI/`node:24-alpine` 里复现。但时间戳来自 `Date.now()`，与平台无关，所以「CI 也会这样」是**推断**而非实测。
- **A-FE-10 的完全可达性证明**：我证明了 warn 函数有非 DEV 门保护的调用点、且在一条较宽的应用路径上没触发。
  「不存在任何能触发 `derived_inert` 的应用状态」我没有证明（也不认为值得为一条提示去穷举）。
- **A-FE-7 的视觉/UX 判断**：没有截图基线背书（我没跑 `test:visual:update`），只有渲染文本与源码；
  而且它本来就该写成判断，不需要我实测。
- **报告「构建说明」里那一条我无法复现**（见 V-3）：报告说「第 1 次构建与审计开始时磁盘上的产物**逐字节一致**」，
  我三次构建三次都不一样。我无法回到那个时刻，所以只能指出它与报告自己记录的机制**互相矛盾**，不能证明当时发生了什么。

---

## 5. 新发现（复核时顺手看到的）

### V-1 [低] 「显示少于授予」有**第二份独立实现**：设备流（推翻 A-FE-3 的「唯一入口」）

- 严重度: 低（与 A-FE-3 同类，且同样**惰性**：被补授的全是 claim scope）
- 类别: 合规/隐私（知情同意的完整性）
- 证据（端到端实跑，`docs/audit-5/probes/verify-web/device-scope-split.mjs`）：

  ```
  requested: openid profile email phigros.b30.read
  device_authorization -> 200 {"device_code":"…","user_code":"JWDL-QJFW",…}
  describe -> 200 … "scopes":[{"scope":"phigros.b30.read",…}]      ← 设备页只显示 1 条
  decision -> 200 {"state":"approved"}
  token    -> 200 … "scope":"phigros.b30.read openid profile email"
  displayed (device page): phigros.b30.read
  granted  (token)       : phigros.b30.read openid profile email
  granted but never displayed: openid profile email
  ```

- 链路到行（读）：`internal/store/memory/oidc.go:1250`（`SplitProtocolScopes` 后只解析目录 scope ⇒ 页面只看得到数据权限）
  与 `:1283-1288`（批准时把 protocol scope 贴回 `granted`）。
  Postgres 侧**逐行同构**（读；无 DB 执行）：`internal/store/postgres/oidc.go:1060-1063`
  （注释原话「Only catalogue scopes are described; `openid`/`profile`/... are protocol flags」）
  与 `:1094-1102`（「Re-attach requested protocol scopes」，同一个 `SplitProtocolScopes` 循环）。
  所以这不是 `authorization_routes.go:189`，而是**同一类静默丢弃的第二、第三份实现**
  （内存一处、Postgres 一处，加上 `oidchttp.ApproveAuthorization` 的重贴）。
- 状态: **CONFIRMED**（端到端）。
- 影响: 与 A-FE-3 相同（令牌 `scope` 是页面的超集，且都是无数据能力的 claim scope），但**修法不同**：
  只按报告建议去改 `scopeViews` / `NarrowScopes` 不会覆盖这条路。而且这条路**已被既有测试钉住**
  （`internal/store/memory/oidc_test.go:99-138` 的 `TestDeviceFlowAcceptsStandardOIDCScopes`，Postgres 有镜像），
  即「设备页只列目录 scope」是有意为之的**已记录行为**——报告错的不是行为描述，而是**唯一性**论断。
- 修法建议: 若要落「显示 = 授予」这条不变量，必须同时覆盖 `oidchttp.ApproveAuthorization:1251-1262`
  与两处存储的 `DescribeDeviceAuthorization`/`DecideDeviceAuthorization`；否则不变量是假的。
- 复现: `node docs/audit-5/probes/verify-web/device-scope-split.mjs`（需 `node e2e/server.mjs`）。

### V-2 [提示] 缺失的散列资产回 **200 的 shell**，不是 404（推翻 A-FE-9 的故障链细节）

- 证据: 上面 §2.4 的三行输出；`TestVMissingAssetIsAnsweredWithTheShellNotA404` 把它钉成性质。
- 影响: 白屏仍会发生（`X-Content-Type-Options: nosniff` + 模块脚本要求 JS MIME ⇒ 浏览器拒收），
  但**报告用来支撑结论的代码事实是错的**，而且方向相反：SPA 回落**确实**替脚本文件兜底，
  一个陈旧 shell 请求已删除的分块拿到的是**200 + `text/html` + `no-cache`**。
  这一条之所以值得写出来，是因为「404 vs 200 HTML」会改变排查路径（浏览器报的是 MIME 错误，不是 404），
  也会改变任何基于「缺失资产应该 404」的监控/告警假设。
- 修法建议: 若要让陈旧客户端**可诊断**，对 `_app/immutable/**` 的未命中回真 404（而不是 shell），
  或至少不要在 `no-cache` 之外给这类回落任何缓存许可。属于裁定。
- 复现: `node docs/audit-5/probes/verify-web/missing-asset-probe.mjs`；`TestVMissingAssetIsAnsweredWithTheShellNotA404`。

### V-3 [提示] 报告的「构建说明」包含一条不可能成立的自证

- 报告 `frontend.md:27-29` 写：审计开始时磁盘上已有的产物与「第 1 次构建」**逐字节一致**（27 个文件 sha256 相同，
  `script-src` 哈希同为 `sha256-hmKSyb9MK624S0VCmGl2StNqMGwjfW+uQ2nREdu5Se8=`）。
- 这与报告自己（正确）记录的机制**互相矛盾**：`_app/version.json` 装的是构建时刻的 `Date.now()`，
  它被内联进分块、进而改写 `index.html` 引用的文件名与自身的 `script-src` 哈希。
  我三次构建三次不同（`index.html` 与 `version.json` 两两之间必然不同；CSP 哈希 `hmKSy…` → `YjHEf/…`）。
- 影响: 不影响 A-FE-9 的结论（结论由我独立复现），但这条「可复现性对照」是**它自己结论的反例**，
  建议在终稿里删掉或改成「同一时刻的产物与后续构建必然不同」。
- 状态: **CONFIRMED（矛盾）**；当时究竟比了什么，我无法回溯。

### V-4 [提示] `_app/version.json` 没有任何缓存指令——而它正是部署新鲜度探测文件

- 证据（活服务器实测）：`/app/_app/version.json -> 200 content-type: application/json accept-ranges: bytes`，
  **没有 `Cache-Control`**（既不是 `no-cache` 也不是 `no-store`），也没有 `ETag`/`Last-Modified`。
  对比：shell 是 `no-cache`、`_app/immutable/**` 是 `immutable`。
- 为什么今天不是缺陷（读）：客户端自己去取它时带 `{headers:{pragma:'no-cache',"cache-control":'no-cache'}}`
  （产物 `_app/immutable/chunks/-qnciKPy.js` 里的 `we()`），而请求头里的 `no-cache` 对合规缓存同样强制回源。
- 为什么仍值得写：这是全站**唯一一个「内容变化＝状态」的文件**，却唯一一个没有任何缓存指令，
  而 A-FE-9 的修法会去动它的内容语义。修 A-FE-9 时应顺手给它 `no-cache`（或 `no-store`），
  这样「部署检测」这件事就不再依赖客户端自觉。
- 复现: `node docs/audit-5/probes/verify-web/wire-probe.mjs`。

### V-5 [提示] 报告自己的浏览器守卫**看不见**它命名的那条背离

- `web/e2e/zzadversary-frontend.spec.ts:114` 的 *displayed scopes and granted scopes cannot diverge*
  用 `authorizeURL({ challenge, scopes: 'openid account.id' })` 发起请求，并在第 140 行把
  `openid`/`offline_access` 列为允许的例外。**这个夹具不可能产生 claim scope 的背离**——
  也就是说这条守卫测不到 A-FE-3 的形状（它的注释承认「今天把这个背离显式允许」，但名字与覆盖范围不符）。
- 我的对照（`web/e2e/zzverify-frontend.spec.ts` 第 1 条）：把请求改成 `openid profile email account.id` 后，
  同一条路径立刻给出 `displayed=["account.id"]` vs `granted=["account.id","openid","profile","email"]`。
- 影响: 与 A-FE-5 同类——**一条不会响的守卫**。若采纳 A-FE-3 的任何一种修法，应把这条守卫的夹具
  改成包含 claim scope，否则「修好了」与「没修」在 CI 上都一样绿。
- 状态: CONFIRMED（我的 spec 会因背离消失而失败，方向是「背离存在才通过」）。

---

## 6. 判断（复核意见，不是发现）

- **报告的负面结论可以直接被发布依赖**：我独立重跑了注入探针（含 `bypassCSP` 对照：同一载荷在
  `bypassCSP: true` 的上下文里**执行成功**，所以「被拦」不是「没跑」）、CSRF 全覆盖（13/13 写端点传头，
  且服务端 403 对照）、令牌不入 URL/存储/DOM、产物 0 密钥（带阳性对照）、越权 scope 两端被拒、
  `/app/*` 不吞 API 404。**一条都没被我打破。**
- **严重度整体偏保守偏高**：A-FE-1/A-FE-2/A-FE-9 三条的「中」都建立在**没有被验证的可达性**上，
  我把它们分别压到低/提示/低。这不是说它们不该报——A-FE-1 的 no-cache-without-validator 与
  A-FE-9 的架构原则 §1.4 冲突都值得修——而是说**危害描述比事实大**。
- **A-FE-7 / A-FE-11 属于「不该出现在发现列表里」的两类**：一个是设计裁定（应进判断），
  一个不指向仓库里任何存在物。
- **我没有发现被低估的严重度**：报告在这片区域没有漏掉值得升级的东西；前端确实没有未认证绕过、
  没有跨账号读、没有凭据泄露。

---

## 附：本次复核新增/使用的探针

| 路径 | 内容 |
|---|---|
| `internal/zzprobe/verifyfrontend/verify_frontend_test.go` | 5 条 Go 探针：策略归属（含 `extra.html` 与 503 页）、真实产物只有 1 个 HTML、条件请求永远 200、Range 越过 meta 后 `meta=false/script=true`、缺失资产回 200 shell |
| `web/e2e/zzverify-frontend.spec.ts` | 3 条浏览器用例：claim scope 背离可观测 + userinfo 只回 `sub`、缺失分块回 200 HTML、应用走过路径 0 条 console 警告 |
| `docs/audit-5/probes/verify-web/repro-build.ps1` | 连跑两次构建并逐文件 sha256 快照（`dist-run0/1/2.tsv`） |
| `docs/audit-5/probes/verify-web/scope-grant-probe.mjs` | 三集对比 + userinfo + introspect + id_token claims + `/v1` 越权探测 |
| `docs/audit-5/probes/verify-web/device-scope-split.mjs` | 设备流三集对比（V-1） |
| `docs/audit-5/probes/verify-web/wire-probe.mjs` | 活服务器头部/条件请求/Range/CSP meta/version.json 全量记录 |
| `docs/audit-5/probes/verify-web/range-meta-probe.mjs` | Range 越过 meta 后的文档形状 |
| `docs/audit-5/probes/verify-web/missing-asset-probe.mjs` | 缺失资产的实际响应（V-2） |
| `docs/audit-5/probes/verify-web/bundle-verify.mjs` | 21 条产物扫描 + **阳性对照** + `cookie` 可达性 |
| `docs/audit-5/probes/verify-web/stamp-census.mjs` | 13 位时间戳分布、version.json 与构建时刻、console.* 分布 |
| `docs/audit-5/probes/verify-web/scope-and-csp-probe.mjs` | 敌对 scope 在两端被拒 + 每种响应类型的 CSP/Cache-Control |
| `docs/audit-5/probes/verify-web/warn-reach.mjs` | Svelte warn 函数在产物里的调用点（是否被 DEV 门保护） |

> 未修改任何被跟踪文件；未使用 `git checkout/restore/stash/clean`；未删改 `docs/audit-5/**` 下任何既有文件。
> `internal/webui/dist` 在我构建两次后仍与 `git status` 干净（只有 `.gitignore`/`.gitkeep` 被跟踪），
> 但**磁盘上的产物已不是审计开始时那一份**（这是任务要求构建两次的必然结果，且 A-FE-9 证明它本来就不可能保持）。
