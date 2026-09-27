# HTTP 边缘审计报告 —— 对抗性复核（VERIFIED）

> 复核对象：`docs/audit-5/findings/http-edge.md`（HE-1 … HE-10）。
> 我的角色是**证伪**。凡我未能推翻的，下面会写清「我试过什么」。
> 我自己的探针：`internal/zzprobe/verifyhttpedge/`（**只含 `_test.go`**，只用 `httpapi` 的**导出面**
> 构造服务器，因此不继承被复核报告夹具的任何 bug）：
> `fixture_test.go`、`keycontrol_test.go`、`plane_headers_test.go`、`evict_test.go`、`spotcheck_test.go`。
> 共 10 个测试：**8 通过、2 按设计失败**，失败的两条就是 V-1 与 V-2 的证据（`--- FAIL` 即结论本身，
> 见 §3 与 §5）。

---

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|---|---|---|---|---|
| HE-1A 键可控 | 高 | 高（**须写前提**） | **部分成立 / CONFIRMED（条件）** | 判别式不是「代理追加还是覆盖」，而是「最近可信代理追加的那一跳**是否本身也在 `trusted_proxies` 里**」；`trusted_proxies = []`（默认，我的实测与你的实测一致）完全不受影响 |
| HE-1B 淘汰活桶 | 高（与 A 合并） | 低（**不独立**） | **成立但危害方向相反** | 实测活桶会被淘汰、下一个请求拿到满额桶——但拿到满额桶的是**受害者**（受益方），受损的是「已花费的额度」这件事本身；且它能做到的事 Half A 早就给了 |
| HE-2 302 无 no-store | 中 | **低** | **部分推翻** | 302 **不在** RFC 9110 §15.1 的 heuristically cacheable 列表里（200/203/204/206/300/301/308/404/405/410/414/501），报告「302 属于启发式缓存适用范围」这句是错的；缺失指令是加固/文档缺口 |
| HE-3 XFF 与主流反代不一致 | 中 | **低 + 应并入 HE-1** | **部分成立（重复计数）** | 与 HE-1A 是同一机制（报告自己就说「若成立，HE-1 的第一半……就成立」）；真正独立的那半是「只读 XFF ⇒ 用 `X-Real-IP` 的部署所有人共用一个桶」（可用性，低） |
| HE-4 编码路径绕过平面包装 | 低 | 低 | **成立（CONFIRMED，我独立复现）** | 指令缺失成立；但根因**不是**路由器边界（见 V-1：普通 429/413 也一样缺），panic 那半输入不可达 |
| HE-5 会话 cookie `Path=/` | 提示 | 提示 → **已知（非发现）** | **已知非发现** | `docs/account-model.md:124` 已把 `Secure; SameSite=Lax; Path=/` 记为会话 cookie 的既定形状；报告自己在「判断 #3」也不质疑现状 |
| HE-6 成功 JSON / 失败 problem+json | 提示 | **提示（内容大部推翻）** | **部分推翻** | 「失败是 problem+json」与实际相反（实测失败是协议面 OAuth JSON，这是**对的**）；「POST 得到 mux 自己写的 405 problem+json」**不存在**（实测 404 协议面 JSON）。仅剩「`assertOAuthPlane` 不看 2xx」这一条守卫缝隙 |
| HE-7 307 无 CT/无缓存指令 | 提示 | 提示 | **部分推翻** | 头部事实成立（GET 有 `text/html`、POST 无，与你的观察**不矛盾**）；但「跨平面不存在」**是错的**：`/v1/../oauth/token` → `307 /oauth/token`，真实 socket 复现 |
| HE-8 会话不绑定设备/方法 | 低（HYPOTHESIS） | **提示 / 判断** | **部分成立** | handle 确实绑定浏览器会话（`consentHandle` = `Bound` + `OwnerMatches`，`authorization_routes.go:72-81`），且 `threat-model.md:170` 已把 `auth_requests.id` 记为「**不是密钥**」；实际收益只剩「用户看到一个没请求过的同意页」 |
| HE-9 审计 `limit` 无上限 | 提示 | —— | **推翻** | `internal/store/postgres/auditread.go:29-35` 有 `maxAuditPage = 1000` 的钳制，`:83` 用的是钳制后的值，`:97` 还刻意用固定 `defaultAuditPage` 分配；报告说 Postgres 侧是「一条 `LIMIT n`」是**读错了代码** |
| HE-10 反空转守卫 | 提示 | 提示 | **部分成立** | 子测试 1/3 的对照是活的；子测试 2 的判据是「两条拼写**必须不同**」——**有洞才过**，作为回归守卫是反的（作者已自述）；子测试 1 的 `Cache-Control` 只 `t.Logf` 不断言；平面相等断言未覆盖 V-2 的输入 |

**合计（10 条 ID 全覆盖）**：维持「高」1 条（HE-1，须写前提）、维持「低」1 条（HE-4）、降级 2 条
（HE-2 中→低、HE-8 低→提示/判断）、内容部分推翻或需合并 4 条（HE-3 并入 HE-1、HE-6、HE-7、HE-10）、
**整体推翻** 1 条（HE-9）、**已知非发现** 1 条（HE-5）。

---

## 2. 降级或推翻的理由（这一节是重点）

### 2.1 HE-1 Half A：**判别式被我换成一条可执行的规则**（未推翻，但报告的理由是错的）

报告与它的探针给了两个**互相矛盾**的因果解释：

- 探针文件 `zzprobe_httpedge_test.go:420-422` 的注释说：调用方在**代理追加** XFF 时「被相信自己声明的地址」；
- 报告 HE-3 说：追加时「取到的是最右侧不可信地址 = 真实客户端（这没错）」。

**第二个才对，第一个错**。代码 `internal/httpapi/clientaddr.go:60-67`：

```go
// Walk from the nearest hop outward, skipping proxies we trust. The first
// address we do not trust is the client.
for i := len(hops) - 1; i >= 0; i-- {
    if trustedBy(hops[i], trusted) { continue }
    return hops[i].String()
}
```

从右往左取**第一个不在信任表里**的跳点。因此真正的判别式是：

> **键可控 ⟺ 收到的 XFF 链里，由可信代理写入的那些跳点全部落在 `trusted_proxies` 内（或可信代理根本没写）。**

我用自己的探针把四种形状各跑一遍（`keycontrol_test.go`，`ratelimit.New(0.001, 1)` =
「一个令牌、永不满血」，所以**放行次数 > 1 就一定是不同的桶键**；每个形状都自带
「同一链两次必须第二次 429」的对照）：

```
[命令] go test ./internal/zzprobe/verifyhttpedge/ -run TestV_XFFChainShapeDecidesTheKey -v -count=1
untrusted peer, rotating XFF:        admitted=0/20   controlSecondRequest429=true
trusted peer, client-supplied XFF:   admitted=20/20  controlSecondRequest429=true   ← 键可控
trusted peer, appended public client:admitted=0/20   controlSecondRequest429=true   ← 安全
trusted peer, appended trusted hop:  admitted=20/20  controlSecondRequest429=true   ← 键可控
```

- **你的实测（`trusted_proxies = []`，400 次轮换 XFF 与 400 次固定 XFF 都在第 101 次 429）与报告并不冲突**：
  空信任表下 `clientaddr.go:32-34` 直接用对端地址，头**根本不读**。报告自己的对照
  `TestZZProbeRateLimitIsFailClosedUnderAKeySpray` 给出的 `map[401:1 429:49]` 是同一件事，
  我的 `keycontrol_test.go` 第四个子测试也复现了（`admitted=0/20`）。**默认姿态是对的**，这一点报告与你一致。
- 但「需要错误配置」这个结论对 nginx 站不住：nginx 官方文档
  （`nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header`，我本次实际取回）明确写
  「By default, the header fields “Host” and “Connection” from the original request are **not** passed to
  the proxied server. …… these fields are redefined: `proxy_set_header Host $proxy_host; proxy_set_header
  Connection close;`」——**其余头一律原样转发**。也就是说，**只写 `proxy_pass` 的 nginx 默认配置就是
  「逐字转发 XFF」这一形状（键可控）**；`$proxy_add_x_forwarded_for`（追加真实客户端）反而**是安全的那一半**。
  报告把这两半说反了。
- 第二种不安全形状不需要任何特殊配置：**当最后一跳代理追加的地址本身就在信任网内**
  （k8s `externalTrafficPolicy=Cluster` 把客户端 SNAT 成节点 IP、服务网格/内部 LB 追加自己），
  链变成 `<调用方伪造>, <10.x 节点 IP>`，从右往左跳过 10.x 之后就取到**调用方写的那条**。
  这正是 `internal/httpapi/clientaddr_test.go:59-64`（`TestClientAddrSkipsTrustedHopsFromTheRight`）
  与 `:68-73`（注释写「the rightmost untrusted address is what that proxy actually saw」）所固化的假设：
  **它假设最近代理追加的地址一定不在信任表里**——在「客户端是公网地址」时成立，在「上一跳被 SNAT/是内网代理」时不成立。
- 该项目**自己的 k8s 基线**就落在被质疑的区间里：`deploy/k8s/base/configmap.yaml:25`
  `trusted_proxies = ["10.0.0.0/8"]`，`deploy/k8s/base/ingress.yaml` `ingressClassName: nginx`。
  我**没有**能确认 ingress-nginx 到底写哪一跳（见 §4：拉到的 `nginx.tmpl` 里主 location 的
  `proxy_set_header` 不在其中，`lua_ingress.lua` 也不含 XFF 逻辑），所以**不能**断言 shipped 栈一定可被打穿；
  能断言的是：**它是否可被打穿由一个控制器开关决定，而不是由「有没有配错」决定。**

**判定：HE-1 Half A = 部分成立、维持「高」，但报告必须改掉理由**——否则运维会去禁止「追加」，
而正确的要求是**覆盖**（`$remote_addr`），外加「别把客户端可能落在的网络写进信任表」。

### 2.2 HE-1 Half B：机制成立，**危害方向与「独立发现」的地位都不成立**

代码 + 我的实测（`evict_test.go`，把概率去掉）：

```
[命令] go test ./internal/zzprobe/verifyhttpedge/ -run 'TestV_Capacity|TestV_Eviction|TestV_WithNoIdle' -v -count=1
maxKeys=16 (1 per shard): 受害者已耗尽 → 插入无关键 → 受害者再次被放行 admitted=true
at capacity with one idle and one live bucket: 淘汰的是 idle 桶，已耗尽的活桶保持耗尽
no idle candidate: 2 个已耗尽桶里有 1 个被静默换成满额桶
```

即 `evictLocked`（`internal/ratelimit/ratelimit.go:213-234`）确实「偏好空闲桶，没有空闲就删一条活桶」，
报告对机制的描述**准确**。失效的是**严重度论证**：

1. **谁损失了什么**：被淘汰的桶下一次请求拿到**满额 burst** ⇒ 对那个客户端是**好处**，不是伤害。
   受害的只有「限流器承诺的『已花费的额度记得住』」这条性质本身。报告标题「会重置诚实客户端的配额」
   把它写成对诚实客户端的伤害，方向是反的（报告在「影响」末段自己也写了「把受害者刚用完的额度还给他」，
   所以这是标题与正文不一致）。
2. **能不能独立于 Half A**：报告把它们绑在一起（「需要一个能选地址的上游」）。**不准确**：不配任何 XFF 时
   `clientaddr.go:33` 直接把**对端地址**当键，所以一个能出示多个源地址的调用方（IPv6 /64、云 IP 段、
   代理池）本来就有「每地址一次满额 burst」，且因为分片是 `FNV-1a(key) % 16`（`ratelimit.go:57-68`），
   他**能自选要打哪个分片**，从而在没有 XFF 的情况下强制淘汰别人（我的 `TestV_PeerAddressAloneIsAKeySpaceOfItsOwn`：
   `no trust list, 50 distinct source addresses, one shared limiter: admitted=50/50`）。见 **V-3**。
3. **收益**：这样的攻击者已经不需要淘汰——换个地址就有新桶。所以 Half B **不增加任何攻击者能力**，
   它是 Half A 的一个子情形；量化（`maxKeys=10_000 / 16 = 625` per shard，`evictionScan = 64`）给出
   「每淘汰一个选定受害者约需 `625/64 ≈ 10` 次新键插入」，这个数字只对**想研究淘汰率**的人有意义
   （并发报告那边有独立复核，我不重复）。

**判定：Half B 单独 = 低；与 Half A 合并为**一个**高发现，前提写明。** 另：报告说限流是「这组昂贵端点上**唯一**的节流手段」是**错的**——
`server.max_in_flight` 存在且示例配置与 k8s 基线都设成 512（`config/re0auth.example.toml:46`、`middleware.go:393-419`），
绕过速率后仍要撞并发上限（503 + `Retry-After: 1`）。这不改变「暴力破解成本归零」的结论，但「无限次请求」要改成「并发上限内的高速率」。

### 2.3 HE-2：**影响论断被 RFC 文本推翻**，只剩加固/一致性

实测头部（我重跑作者探针的实际输出，与我读到的代码 `internal/oidchttp/oidchttp.go:521-527` 一致——
Cache 策略只覆盖 `introspection`/`userinfo`/`keys` 与 `isToken`，**不含 authorize**）：

```
login redirect:         302 Location="/login?authRequestID=95sKjY-…" Cache-Control="" Pragma=""
authorization response: 302 Location="https://app.example/cb?code=eyJhbGci…&iss=…&state=st" Cache-Control="" Pragma=""
```

但报告的影响段有两处错：

1. 「302 属于 RFC 9111 §3 heuristic freshness 的适用范围」——**错**。我本次实际取回 RFC 9110 §15.1：
   > Responses with status codes that are defined as heuristically cacheable (e.g., **200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501** in this specification) can be reused by a cache with heuristic
   > expiration …; **all other status codes are not heuristically cacheable.**

   302（以及 307）不在其中；RFC 9110 §15.4.3 的 302 正文也**没有**「heuristically cacheable」这句话。
   RFC 9111 §4.2.2 进一步限定启发式只能用在「被定义为 heuristically cacheable」的状态码上，且要靠
   `Last-Modified` 这类字段估值——两条 302 都没有。**没有真实缓存会在没有显式新鲜度时存这条响应。**
2. 「`Cache-Control` 是唯一能覆盖『浏览器把 Location 留在本地』的手段」——**不成立**。浏览器会**跟着** 302
   走到 `Location`（客户端 `redirect_uri?code=…`），那条 URL 无论 302 带不带 `no-store` 都会成为
   文档 URL / 历史记录项。给 302 加 `no-store` **并不能**阻止 code 留在本地，所以修法解决不了它声称解决的事。
3. 唯一站得住的文本依据是 RFC 6749 §5.1（我实际取回）：
   > The authorization server MUST include the HTTP "Cache-Control" response header field with a value of "no-store" in **any response containing tokens, credentials, or other sensitive information** …

   授权码是凭据 —— 但这句话位于 token 端点那一节，且**项目自己的契约没把它扩展到 3xx**：
   `docs/api-design.md:28` 只要求「`token` 响应必须 `no-store`」，`:49` 的「业务平面全部 `no-store`」
   也只管 `/v1`，`docs/protocol-hardening-decision.md:36`（ADR-0005 第 15 条）写的是「内省与 userinfo
   `no-store`；JWKS 与 discovery `public, max-age=300`」——**没有任何一处把授权 302 纳入**。
   报告自己第一段也承认「3xx 授权响应不在任何一张表里 …… 不是有人违反契约」。既然如此，
   **不变量「凡承载凭据必须 no-store」是报告新造的**，不是项目契约；把它当契约违反来定级会伤到报告可信度。
4. 另有一半被报告漏掉：`docs/threat-model.md:170` 明确把授权请求 handle 记为
   **「不是密钥：设计上就出现在浏览器 URL 与服务器日志里，且被绑定到创建它的会话」**。
   所以「`authRequestID` 出现在 Location 里」是**已文档化的决定**，不是新暴露面。

**判定：HE-2 = 提示/低**（「与 token/introspect/userinfo 的写法不一致，建议为 3xx 授权响应补
`no-store` 并写进 §3 的表」）。把它定成「中」会诱使别人以为存在一条真实的凭据缓存漏洞。

### 2.4 HE-4：成立（我独立复现），但**根因被写窄了**（→ V-1）

我的复现没有用作者的 raw-path 技巧（`httptest.NewRequest("/v1%2Fnope")` 本身就产生
`URL.Path=/v1/nope` + `EscapedPath=/v1%2Fnope`）：

```
control  /v1/nope   -> 404 "application/problem+json" Cache-Control="no-store"
escaped  /v1%2Fnope -> 404 "application/problem+json" Cache-Control=""       ← 成立
escaped 404 instance="/v1/nope" (the decoded, caller-supplied path)
```

顺带核对报告的**影响**段：body 里只有 `type/title/status/detail/instance/code/request_id`，
`instance` 是**调用方自己的**解码路径，缓存键也是那个 URL ⇒ **没有跨调用方泄漏**；
而且 404 恰好在 RFC 9110 §15.1 的可启发式缓存列表里（**与 HE-2 的 302 正好相反**），
所以这一条是「指令确实缺失、理论上可被共享缓存启发式存储」的真实缺口——只是回显内容无害，
「低」定得住。panic 那半：`handleNotFound`（`server.go:698-710`）里除 `planeOf` 与两个写出器外
没有能因输入而 panic 的代码，**输入不可达**；结构上成立（详见 V-4）。HE-4 的修法建议是对的。

### 2.5 HE-5：已知（非发现）

`docs/account-model.md:124`：「`Secure`、`SameSite=Lax`、`Path=/`。会话 id 不透明，服务端存储。」
——这就是报告的实测结果（我重跑探针也拿到同样的两条 `Set-Cookie`）。报告自己把它定为「提示 / 纵深防御」，
并在「判断 #3」写明不质疑现状，**处置恰当**；但按 BRIEF §5 的口径，这条应当标成
「**已知的、有意为之的同源设计**」，而不是一条发现。补充两点让结论更硬：
`__Host-` 前缀**要求** `Path=/`（报告说对了，这是真取舍）；`Path=/app` 会打断 SPA 自己的 `/v1` 调用
（`docs/browser-plane-decision.md` 的同源决定），所以「改 Path」不是随手可改。

### 2.6 HE-6：**「405 problem+json」不存在**，且报告标题与自己的证据相反

报告 HE-6 的证据行里，失败一行写的是 `404 application/json {"error":"invalid_request",…}`
——那正是**协议面正确的形状**，却在标题/不变量里被写成「失败是 problem+json」。
我重跑全部探针后逐行核对日志，`/.well-known/oauth-protected-resource` 的方法是：

```
POST/PUT/DELETE/PATCH/OPTIONS /.well-known/oauth-protected-resource -> 404 plane=protocol  bytes=73
GET  /.well-known/oauth-protected-resource                          -> 200 plane=protocol  bytes=240
```

73 字节就是 `{"error":"invalid_request","error_description":"unknown OAuth endpoint"}`。
原因在 `server.go:496` 与 `:505`：`GET /.well-known/oauth-protected-resource` 只管 GET，
而 `root.Handle("/.well-known/", s.oidc)` 是**方法无关**的，POST 落进 `s.oidc` ⇒ 协议面 404。
Go 的 mux 只有在「没有任何 pattern 匹配整个请求」时才自己写 405 problem+json，**这里不成立**。
（我把本次探针输出里**全部 52 条** 405 逐条归类：路径只出现在 `/oauth/*`、`/auth/github/start`、`/v1/me`
三处，`/oauth/*` 的是 `oidchttp` 的 OAuth JSON，`/v1/me` 的是业务 mux 自己的派发
（`server.go:653-655`），`/auth/github/start` 的是浏览器面纯文本 —— **没有一条是 Go mux
在协议面上替服务决定的**。）HE-6 里
「Go 标准库替我们决定的错误形状」这句因此**是凭印象写的、没实测**——而它却标了
「CONFIRMED（三种拼写/方法实测）」。

保留的那一半是真的且值钱：`internal/httpapi/plane_test.go:211`/`:259` 的 `if rec.Code >= 400 { assertOAuthPlane(t, rec) }`
—— **200 响应的 `Content-Type` 从未被断言**，所以 200 那半（`writeJSON` ⇒ `application/json + no-store`，
`responses.go:115-119`）没有守卫。要修就修这一处。**它不是 HE-4/HE-7 的同源实例**：
HE-4/HE-7 是「路由器与平面判定两个出口」，HE-6 是「守卫只覆盖 4xx」。合并会丢掉这一点。

### 2.7 HE-7：**「跨平面不存在」是错的**（→ V-2）

头部事实与你的观察**不矛盾**，两者都对：`GET` 的 307 带 `text/html; charset=utf-8`（`http.Redirect` 会为 GET
写 `<a href>` 体），`POST` 的 307 没有 `Content-Type`（无体）。我自己的走查：

```
inproc GET  /v1//me                          -> 307 Location="/v1/me"       Content-Type="text/html; charset=utf-8" Cache-Control=""
inproc POST /v1//me                          -> 307 Location="/v1/me"       Content-Type=""                         Cache-Control=""
inproc GET  /oauth//token                    -> 307 Location="/oauth/token" Content-Type="text/html; charset=utf-8" Cache-Control=""
inproc GET  /v1/../oauth/token               -> 307 Location="/oauth/token"   ← 业务面 → 协议面
inproc GET  /oauth/../v1/me                  -> 307 Location="/v1/me"         ← 协议面 → 业务面
live   /v1/../oauth/token                    -> 307 Location="/oauth/token" Content-Type="text/html; charset=utf-8"
live   /oauth/../v1/me                       -> 307 Location="/v1/me"       Content-Type="text/html; charset=utf-8"
```

后四条是**真实 socket**（`httptest.NewServer` + 不跟随跳转的 client）跑出来的。Go 的 mux 会清洗
`/v1/../oauth/token` 并 307 到 `/oauth/token`，`planeOf(raw)=business` 而 `planeOf(loc)=protocol`。
所以：①报告 HE-7 的「跨平面不存在：`/v1/../oauth/token` 这类**我逐一验证过**」是**未经执行的断言**；
②它自己的守卫（`zzprobe_httpedge_test.go:239` 断言 `planeOf(loc)==planeOf(raw)`）**没覆盖**这些输入，
把「没覆盖」写成了「不存在」。③这条 307 也不带任何平面指令，`Cache-Control=""`。
安全后果很小（307 由 mux 生成、目标端点自己还要再花一个令牌，甚至更贵），所以**保持提示**，
但审计本身的不一致必须纠正。另：报告说「6 个拼写 × 2 方法 = 12 次」与它自己打印的走查一致，没问题。

### 2.8 HE-8：绑定确实存在，跨站部分塌缩为「骚扰级」

`internal/httpapi/authorization_routes.go:72-81`：

```go
id := r.PathValue("id")
if !s.authInteract.ValidID(id) || !s.sessions.Bound(r.Context(), authzBindKind, id) { return "", false }
if !s.sessions.OwnerMatches(r.Context(), authzBindKind, id, user) { return "", false }
```

即 handle 绑到**创建它的会话**，且要求**同一个账号**——报告 373-389 行的阅读与我一致。
再叠加 `redirect_uri` 必须精确注册（报告自己也说了），跨站顶层 GET 的收益是：
`/oauth/authorize` 为受害者创建一个绑在**该浏览器**上的待决请求，并 302 到 `/login?authRequestID=…`
或同意页 —— **攻击者既拿不到 code，也拿不到 handle**（handle 换不了任何东西：`consentHandle` 会拒他）。
剩下的只有「用户看到一个没请求过的同意页」这一扰动，以及（用户点同意时）一次真实授权——
但那时攻击者必须**本来就是那个 client**（有 client_id 与 redirect_uri），他早就能发起同样的请求。
`docs/threat-model.md:170` 已经把 handle 写成「不是密钥」，`architecture.md:693` 已列
`TestAuthorizationHandleIsBoundToBrowser` ——**这条残余是被测量过的**。所以 HE-8 应当留在
「判断」里（建议把残余写进 `oidc-decision.md` O-9），**不要**留成一条「低」的发现。报告自己也写到了这一点，
只是标题仍以「低」的发现形式出现。

### 2.9 HE-9：**推翻**（这条如果留着会毁掉整份报告）

```go
// internal/store/postgres/auditread.go:29-35
limit := q.Limit
switch {
case limit <= 0:
    limit = defaultAuditPage          // 100
case limit > maxAuditPage:
    limit = maxAuditPage              // 1000
}
…
args = append(args, limit+1)                                   // :83，用的是钳制后的值
query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args)) // :84
page := audit.Page{Entries: make([]audit.Entry, 0, defaultAuditPage), Limit: limit}  // :97
```

- 钳制在**唯一**实现里：`cmd/re0auth/main.go:1397-1405` 的 `auditReadSide` 是对 `audit.Logger` 的
  类型断言（`*postgres.AuditLogger`）；`audit.NewMemoryLogger()` **不实现** `httpapi.AuditReader`
  （`cmd/re0auth/main_test.go:639` 断言它返回 nil）。所以不存在「另一条没有钳制的读路径」。
- `:97` 的注释还把这件事**明确**写成了设计意图：「sizing an allocation from a value that arrived in a request
  is a denial-of-service shape **even when a clamp upstream makes it safe**」。
- 既有测试就在测它：`internal/store/postgres/auditread_test.go:220-233`
  （`Query(audit.Query{Limit: maxAuditPage + 10_000})` ⇒ `page.Limit == maxAuditPage`，且空页返回 100）——
  需要 DB 才能跑，但第三轮审计 B3-2（`docs/security-audit-3.md:32,149-157`）已经把这个「服务端实际应用的 limit」
  当成既有契约记下来了。
- 报告说「不设上限，直接赋给 `audit.Query.Limit` → `auditReader.Query`（Postgres 侧即一条 `LIMIT n`）」：
  handler 确实不钳制（`audit_routes.go:54-61` 只查下界，这点读对了），**但下一跳把它钳住了**，
  而且钳制是**在构造 SQL 之前**。代价：一次 `?limit=2147483647` 只会拿到 ≤1000 行，
  不可能「让进程与数据库分配与 limit 成正比的内存/带宽」。

**判定：推翻。** 按 BRIEF 的证据标准，这条连 HYPOTHESIS 都不是——它是「读代码没读到被调用的那一层」。

### 2.10 HE-10：守卫的**方向**问题

- 子测试 1（双斜杠/点段是 307 + 对照）与子测试 3（指标标签 + 非空对照）是**真的会失败**的断言，成立。
- 子测试 2 的判据是 `escaped.Cache-Control != canonical.Cache-Control`（`zzprobe_httpedge_test.go:276-284`）：
  **有洞才过、修好就红**。作者自己写明了这一点，所以不算隐瞒；但它**不是** HE-4 的回归守卫，
  而是「当前状态探测器」。BRIEF 要求「发现 = 一条会失败的测试」，HE-4 的那条
  （`TestZZProbeEncodedBusinessPathSkipsThePlaneWrappers`）才是；子测试 2 应当改判据为
  「两条都必须 `no-store`」并在修复后启用。
- 子测试 1 里「307 不带缓存指令」只 `t.Logf`（`:245-247`，`if != "" { t.Logf }`），**没有断言**——
  所以 HE-7 的「无缓存指令」在套件里其实无人守卫。
- 平面相等断言漏掉了 V-2 的跨命名空间点段（我加了才红）。

---

## 3. 确认的（我执行了什么）

1. `go test ./internal/httpapi/ -run TestZZProbe -v -count=1 -timeout 600s`
   → **恰好 3 条失败**：`TestZZProbeRateLimitKeySpaceIsUncapped`、
   `TestZZProbeAuthorizationRedirectCarriesNoCacheDirective`、`TestZZProbeEncodedBusinessPathSkipsThePlaneWrappers`。
   与报告自述一致；其余 16 条（含 HE-10 三个子测试）通过。关键行：
   `one peer, 20000 distinct X-Forwarded-For values, rate=0.001/s: admitted=20000 refused=0`、
   `untrusted peer varying X-Forwarded-For: map[401:1 429:49]`、
   `5/20 trials: another client's key spray discarded the victim's exhausted bucket …`
   （**注意：报告写 6/20，我这次 5/20** —— 概率性证据，报告自己也这么定性，不影响结论）。
2. `go test ./internal/zzprobe/verifyhttpedge/ -v -count=1`（**我自己的探针**，只走导出面）：
   - `TestV_XFFChainShapeDecidesTheKey` → 四种链形状，每条都带「同链两次必须 429」的对照；
   - `TestV_PeerAddressAloneIsAKeySpaceOfItsOwn` → `admitted=50/50`（无信任表、50 个源地址）；
   - `TestV_CapacityEvictionDiscardsALiveBucket` → `admitted=true`（活桶被淘汰后满额复活）;
   - `TestV_EvictionPrefersAnIdleBucketToALiveOne` → 有 idle 时**不**动活桶（代码的偏好是真的）；
   - `TestV_WithNoIdleBucketALiveOneIsDeleted` → `1 of 2 exhausted buckets were silently replaced by full ones`；
   - `TestV_BusinessPlaneDirectiveIsNotAttachedToThePlane` → 复现 HE-4，并发现 429 也缺指令（V-1）；
   - `TestV_RouterRedirectsAndThePlaneBoundary` → **两条跨平面 307**（in-process 与真实 socket 各一次）；
   - `TestV_UncleanedPathDecidesTheLimiterPlane` → `2nd /oauth/../v1/me -> 429 "application/json"
     {"error":"temporarily_unavailable",…}`（协议面形状），而同一 peer 的 `/v1/me` 仍是 401
     ⇒ 限流键与指标标签用的是**未清洗**的路径；
   - `TestV_SpotCheckForwardingHeaders` → 9 个其他转发头**没有一个**能移动桶键（报告「探过没破」第 5 条，独立复核）；
   - `TestV_SpotCheckBodyLimitPerPlane` → 413 三个平面各自形状正确（报告第 9 条，独立复核）：
     `/oauth/token → application/json (no-store)`、`/v1/me → application/problem+json ("")`、`/nope → text/plain`。
3. 我**独立复核的三条「探过但没破」**：#5（只有 XFF 生效）、#6（无信任表下喷键无效，`admitted=0/20`）、
   #9（413 分平面）。三条都**站得住**——这是本次复核里最希望出错的三个地方，它们没出错。
4. 外部文本（本次实际取回）：RFC 9110 §15.1 可启发式缓存状态码列表、§15.4.3（302 无该表述）、
   RFC 9111 §4.2.2、RFC 6749 §5.1 的 `Cache-Control` 规范句、nginx `proxy_set_header` 的默认行为。

---

## 4. 我未能验证的

1. **ingress-nginx / 云 LB 到底把哪一跳写进 XFF。** 本机没有 nginx/Caddy/HAProxy，也没有集群。
   我拉到了 `kubernetes/ingress-nginx` 的 `nginx.tmpl`（61 KB）：里面只有错误页、auth 子请求与
   `$full_x_forwarded_for`（第 857/1062/1064 行）这几处 `proxy_set_header`，**主 location 的 XFF 赋值不在其中**；
   `lua_ingress.lua` 也不含 XFF 逻辑。所以「shipped k8s 栈是否可被打穿」我只能给**判别式**，不能给结论。
   要证实它需要一次真实的 ingress 往返（`kubectl port-forward` 或一个带 `compute-full-forwarded-for`
   的控制器实例）。
2. **浏览器层**：`SameSite=Lax` 在跨站顶层导航下是否真的带 cookie、`Referrer-Policy: no-referrer`
   是否真的抑制 Referer，我没有 Chromium，未跑 `pnpm test:e2e`（与分析 HE-2/HE-8 的残余一致）。
3. **Postgres 路径未执行**（本机无 DB）。HE-9 的推翻是**读代码到行**：`auditread.go:29-35/83/97`
   加上 `main.go:1397-1405` 的类型断言白名单。若第三条实现 `httpapi.AuditReader` 的存储适配器将来出现，
   该结论需要重查（今天的树里没有）。
4. **`-race` 未跑**：我的探针里唯一的并发面是 HTTP 处理器，且结论不依赖并发序；
   报告的 HE-1 Half B 是单线程确定性行为（我把它变成了确定性测试，见 §2.2）。
5. **HE-1 在真实反代下的前缀代价**：我没有测「追上 625 个键需要多少真实请求成本」
   （每键一次请求，插入成本 O(64) 采样，`maxKeys` 有界）——报告说「不是放大器」这一点我读了代码同意
   （`ratelimit.go:213-234`），但没有实测内存曲线（并发报告那边在做）。

---

## 5. 新发现（复核时顺手看到的）

### V-1 业务面 `no-store` 不是挂在平面上，而是挂在 `/v1` 的 mux 上 —— 429 与 413 同样缺指令

- 严重度: **低**   类别: 安全（纵深防御）/ 可维护性
- 不变量: `docs/api-design.md:49`「**业务平面全部 `no-store`**」
- 证据（我的探针，导出面构造的服务器）：
  ```
  admitted /v1/me -> 401 "application/problem+json" Cache-Control="no-store"   ← 走 mux 内，有
  refused  /v1/me -> 429 "application/problem+json" Cache-Control=""            ← 限流中间件在 mux 外，没有
  POST /v1/me (100 KiB) -> 413 "application/problem+json" Cache-Control=""      ← 体积上限中间件在 mux 外，没有
  POST /oauth/token (100 KiB) -> 413 "application/json" Cache-Control="no-store" ← 协议面写出器自带
  ```
  机制：`writeProblem`（`responses.go:61-77`）**自己不设**指令，指令来自 `withNoStore(mux)`
  （`server.go:661`），而 `withRateLimit`（`middleware.go:327-373`）、`withBodyLimit`（`:107-122`）
  都在 mux **外**（`server.go:591-592`）。HE-4 把它归因于「路由器边界」，实际是
  **「任何在平面包装之外调用 `writeProblem` 的地方」**——触发面比编码路径常见得多。
- 为什么今天没人看见：唯一的守卫 `internal/httpapi/responses_test.go:17` 只走 7 个**返回 200** 的端点
  （`/v1/sessions/current`、`/v1/account/export`、…）。
- 修法: 把 `no-store` 放进 `writeProblem` 自身（`writeJSON`/`writeOAuthError` 都已经这么做，只有它漏了），
  并把 `responses_test.go` 扩成「按平面走，含 4xx/5xx」。
- 守卫: `internal/zzprobe/verifyhttpedge/plane_headers_test.go` `TestV_BusinessPlaneDirectiveIsNotAttachedToThePlane`。

### V-2 mux 的路径清洗会**跨平面**307，且限流键/指标标签记的是未清洗路径

- 严重度: **提示**   类别: 可维护性 / 可观测
- 证据: 见 §2.7 的走查；`/v1/../oauth/token → 307 /oauth/token`、`/oauth/../v1/me → 307 /v1/me`，
  真实 socket 复现。同时 `planeOf(r.URL.Path)`（未清洗）在限流与指标里把前者的
  `plane` 记成 `business` —— 可复现：`TestV_UncleanedPathDecidesTheLimiterPlane` 里
  `2nd /oauth/../v1/me -> 429 "application/json" {"error":"temporarily_unavailable",…}`
  （协议面形状），而同一 peer 的 `/v1/me` 仍是 401（业务面桶没被动过）。
  安全后果小（目标端点照样要花自己的令牌），但它是 HE-7「跨平面不存在」的**反例**，
  且运维面板上会出现「协议面路径被记成 business」。
- 修法: 与 HE-4 同一处（把平面判定挪到清洗后的路径，或让 mux 的跳转也走平面写出器）。
- 守卫: `internal/zzprobe/verifyhttpedge/plane_headers_test.go` `TestV_RouterRedirectsAndThePlaneBoundary`。

### V-3 安全默认下限流键 = 对端地址，所以「多个源地址」本身就是绕过（Half B 不依赖 Half A）

- 严重度: **低**（可用性/公平性；不是放大器）   类别: 安全
- 证据: `clientaddr.go:32-34`（无信任表 ⇒ 对端地址）+ 我的
  `TestV_PeerAddressAloneIsAKeySpaceOfItsOwn`：`no trust list, 50 distinct source addresses, one shared limiter: admitted=50/50`。
  `shardFor` 是 `FNV-1a(key) % 16`（`ratelimit.go:57-68`）且键是 `plane|addr`，
  所以能选源地址的攻击者**能选分片**，从而在**不需要任何 XFF 配置**的前提下制造 Half B 的强制淘汰。
- 影响: ①IPv6（一个 /64 就是 2^64 个桶键）、云 IP 段、住宅代理池的调用方天然突破每地址配额；
  ②报告「Half B 需要一个能选地址的上游 ⇒ 依赖 Half A」的推论因此不成立（**但结论不变**：Half B 自身收益≈0）。
- 修法: 这条只能靠「按已认证主体计费/配额」（`api-design.md:141` 已经承认这个模型尚未定义，ADR-0006），
  或对 IPv6 前缀（/64）而不是单个地址分桶——**这是裁定，不是随手改**。

### V-4 `recoverBrowser` 与 `docs/api-design.md:393-394` 的表述互相矛盾（panic 形状）

- 严重度: **提示**   类别: 可维护性 / 合规
- 证据: 文档写「**panic 也必须落在自己的平面里**……业务面 → problem+json 500……（由最外层兜住，
  因此也覆盖共享中间件里的 panic）」；而 `middleware.go:537-555` 的 `recoverBrowser` 注释说
  「docs/api-design.md §6 **does not decide a format for them yet**」，实现是无条件 `http.Error(...)` 纯文本。
  两者对同一份文档的读法相反。结构后果：任何在**共享中间件**里 panic 的 `/v1` 请求都会得到 text/plain 500
  （平面包装在 mux 内，兜不住），违反文档的「业务面 → problem+json 500」。
- 可达性: 我**没有**找到能从输入触发共享中间件 panic 的路径，所以是结构性的、当前不可利用
  （与 HE-4 的 panic 半同源，报告的建议「让 `recoverBrowser` 按 `planeOf` 作答」正好覆盖它，
  但报告的定位（`handleNotFound`）说窄了）。
- 修法: 让 `recoverBrowser` 按 `planeOf(r.URL.Path)` 选择写出器，并把这句文档与代码注释对齐。

---

## 6. 我认为**被低估**的

1. **`client= 「访问日志里的客户端」可被伪造**（HE-1 的附带一句，报告放在「影响」里一句带过）：
   只要有信任表，`middleware.go:264` 的 `client=` 就是调用方写的值——我重跑探针时日志里
   逐行出现 `client=198.18.0.28`、`client=198.18.1.24` 这类**伪造地址**。
   审计归因、按 IP 的运维排查、`rate_limit` 的排障全部指向调用方选定的值。
   这一条独立于「限流被绕过」：**即使限流不被绕过，日志归因也已经不可信**。建议单独一条
   （低/中，取决于审计链是否被当作证据用）。
2. **`max_in_flight` 被报告写成不存在**（「限流是这个端点上唯一的节流手段」）。
   真实情况是它存在且默认按连接池推导（`config/re0auth.example.toml:35-46`、k8s 512）。
   这不降低 HE-1 的严重度，但「无限次请求」的措辞应改，否则一旦有人指出「并发上限还在」，
   整条高发现会被读成夸大。
3. **HE-2 与 HE-4 的严重度顺序应当对调**：真正落在 RFC 可启发式缓存列表里的是 **404**（HE-4），
   不是 302（HE-2）。报告把两者都定在合理区间，但理由写反了，修完 HE-4 之后 HE-2 才是可以不改的那条。
