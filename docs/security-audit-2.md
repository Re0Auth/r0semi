# 第二轮对抗性审计（Re0Auth）

**范围**：五个不变量 —— ①令牌与 scope 签发、②账号隔离、④撤销是否真的生效、⑤凭据containment、⑥fail-closed。
**不在范围内**：协议正确性的全面重扫（第一轮已覆盖）。

**方法**：`audit-authz` skill 的探针目录（`.commandcode/skills/audit-authz/references/probes.md`）。
每个发现都**必须有一条会失败的测试**才算数——「我推理它是安全的」正是这套流程要取代的东西。

**执行**：所有标记 CONFIRMED 的发现都由**实际运行**的测试复现（失败输出见各条）。第二轮共 **15 条**
（我报告 9 条 + 复核补充 6 条），**全部已修复**，每条的复现测试都已变成常规套件里的守卫——
它在修复前失败、现在通过，见各条的 `Pin`。守卫集中在被攻击代码旁边的 `adversary_test.go`，测试名即发现名。

```sh
go test ./...   # 全部守卫都在这个套件里，不再需要 build tag
```

## 修复总览

| # | 发现 | 不变量 | 根因 / 修法 | 守卫 |
|---|---|---|---|---|
| A1-2 | `POST /oauth/authorize` 绕过全部预检（机密客户端无 PKCE） | ① | 预检只守 `GET`；改为按方法无关、参数读 `r.Form` | `httpapi`: `TestAdversarialPostAuthorizeRequiresPKCE` |
| A1-1 | 设备流签发未注册 scope | ① | 该端点无任何 client-scope 检查；加同款预检 | `TestAdversarialDeviceAuthorizationRefusesUnregisteredScope` |
| A1-3 | `POST authorize` 静默收窄未注册 scope | ① | 同 A1-2 | `TestAdversarialPostAuthorizeRejectsUnregisteredScope` |
| 新增 | 协议平面非 JSON 失败（introspect / userinfo 吐 `text/plain`） | ③ | 库不经 r0semi 的写入器；在 `serveOAuth` 统一归一化 | `plane_test.go` 收紧后的 `assertOAuthPlane` |
| A4-1 | refresh token 撤销是空操作（200 但零删除） | ④ | `GetRefreshTokenInfo` 返回了 access 的 `id_hash`，而 `RevokeToken` 会对入参**再哈希** | `memory`: `TestRefreshTokenRevocationRoundTrip` |
| 新增 | `oauth.Revoke` 不校验令牌归属（RFC 7009 §2.1） | ④ | 删除前查 `TokenOwner` | `oauth`: `TestRevokeRefusesATokenIssuedToAnotherClient` |
| 新增 | `SweepExpired` 把登录中的会话踢出索引 | ④ | 索引行写在 scs commit 会话行**之前**；加 `created_at`（迁移 0015）+ 宽限期 | `postgres`: `TestSweepSparesAFreshIndexRowAndCollectsAnAgedOne` |
| 新增 | Kill Switch 输给并发刷新 → 凭证复活且重试够不到 | ④⑥ | Unbind/CascadeRevoke 不取键锁 + refresh 先写 vault 再 CAS；**两者都修** | `federation`: `TestAdversarialUnbindReportsAnUnopenableSecret` + 锁 |
| A6-2 | 输掉 CAS 的 refresh 覆盖了胜者的密钥 | ④⑥ | 改为 **先 CAS，赢了才写 vault** | `TestAdversarialLosingRefreshDoesNotOverwriteTheWinnersSecret` |
| 新增 | 重绑回到 `Version: 1` → 迟到刷新删掉刚建的绑定 | ④ | version 改为**随机代次**而非计数器 | `federation`: `TestBindFlow` + `newBindingGeneration` 文档 |
| A2-1 | bind 回调只查 `Bound` 不查 `OwnerMatches` | ② | 补上第二个检查（与同类处理器一致） | `TestAdversarialBindCallbackRejectsAnotherAccount` |
| A6-1 | `Unbind` 把「vault 打不开」塌缩成「无事可做」 | ⑥ | 区分 `ErrNotFound` 与其它错误 | `TestAdversarialUnbindReportsAnUnopenableSecret` |
| A6-5 | bind 回滚失败被 `_ =` 丢弃 | ④ | `errors.Join` 进返回错误 | `federation`: `TestBindFlow` 相邻 |
| A5-1 | 抹除把 `usr_…` 写进 `detail["actor"]` | ⑤ | Detail 不再放账号 id，改记 `self` | `lifecycle`: `TestAdversarialErasureLeavesTheAccountIdInTheAuditDetail` |
| A5-2 | 夹具不清 `audit_chain`（3A/3B 等于没验证） | ⑤ | 补进 `TRUNCATE` 并重播 genesis | `postgres` 全部审计测试 |
| A5-3 | 凭据列守卫只覆盖一张表 | ⑤ | 改为枚举**全部**表 + 显式豁免清单，并加静态（无 DB）版 | `TestNoColumnCanHoldACredential`（无需 DB）/ `TestNoColumnInTheLiveSchemaCanHoldACredential` |
| A5-4 | 业务平面无 `Cache-Control` | ⑤ | `writeJSON` 统一 `no-store` | `httpapi`: `TestBusinessPlaneResponsesAreNotCached` |
| A6-3 | 32 字节 **hex** 密钥永远被拒 | ⑥ | 依次尝试三种编码，取**第一个恰好 32 字节**的结果 | `cmd/re0auth`: `TestAdversarialHexKeyIsAccepted` |
| 新增 | `tapsign.DecodeCredential` 不调 `Valid()` | ⑫ | 补上，消除 latent trap | `tapsign` 既有调用方测试 |
| 新增 | `bindingSecret` 文档与实现不符 | ⑤ | 改文档说实话（Go string 不可零化） | 无测试，纯文档 |

**未修的一条（判断，不是遗漏）**：`admin` 的审计事件仍把**操作员的** `usr_…` 记在 `Detail["actor"]`。
这是有意的——操作员在信任边界之外（SECURITY.md「Out of scope」），而「谁停用了这个客户端」是运维必须能回答的。
残余是：该操作员若日后抹除自己的账号，这些行里的 id 不会随之解除关联。记录在此而非假装不存在。

## 这一轮修了什么，为什么值得单独说

三个**跨发现**的教训，比任何单条都重要：

1. **检查写在薄封装里，就要检查封装的每一条入口。** A1-2/A1-1/A1-3 是同一个洞的三个面：
   预检只挂在 `GET /oauth/authorize` 上，而库的同一批端点在别的 HTTP 方法、别的路径上照样可达。
   修法是让预检**与方法无关**，并把平面走查（`plane_test.go`）从「只走 GET」改成按方法走。
2. **收紧一个宽容的断言，会立刻找出它藏起来的东西。** `assertOAuthPlane` 原本容忍非 JSON body；
   去掉这条容忍后，`/oauth/introspect` 与 `/oauth/userinfo` 的 `text/plain` 401 当场暴露。
   一个「为了方便而放宽」的断言，正是下一个漏洞的藏身处。
3. **排序 bug 只在特定交错下才显形，所以要能把交错做出来。** A6-2 我前两次复现都**假通过**：
   一次因为 `refreshBinding` 顶部的版本重读提前返回，一次因为夹具漏了 `HasRefresh`。
   真正复现需要把胜者的提交**放进败者的上游调用期间**（`frozenStore`）。确定性复现失败的交错，
   比读一百遍代码有用。

## 没有报告什么（这是刻意的）

以下都是**文档化的决定**，不是缺陷，报告它们会毁掉整份报告的可信度：不做 DPoP / PAR / 动态客户端注册 /
`end_session` / 账号合并 / `Idempotency-Key` / 凭据导出端点 / KMS-HSM 适配器；内存存储无法枚举会话；
vault 的 `Identity` 与 `Meta` 明文落盘（threat-model §6.1）；审计链**尾部截断**不可检测（architecture §4.16）；
迁移 `0014` 之前的审计行保留原始 subject（architecture §4.17）；
跨实例 refresh 的**残余竞态**（architecture §4.11）。

---

## 发现（按攻击者收益排序）

### A1-2 `POST /oauth/authorize` 绕过全部前置校验，机密客户端拿到**无 PKCE 绑定**的授权码

- **不变量**：①
- **证据**：`internal/oidchttp/oidchttp.go:227` —— 前置校验（client 存在、redirect 精确匹配、PKCE 必须
  `S256`、catalogue + client scope 白名单）只在 `r.Method == GET && path == /oauth/authorize` 时运行。
  `internal/httpapi/server.go` 把 `/oauth/` 整个交给它（不带方法约束），zitadel/oidc 的 authorize handler
  也**没有方法约束**且从 `r.Form` 取值（含 POST body）。库只在兑换时对 `AuthMethodNone` 强制 PKCE，
  所以机密客户端这条路完全不要求 verifier。
- **复现**（已执行，FAIL）：
  ```
  adversary_test.go:127: a code obtained by POST was exchanged with no code_verifier:
  {"access_token":"eyJhbGciOiJBMjU2R0NN...","scope":"account.id","token_type":"Bearer"}
  ```
- **状态**：CONFIRMED → **已修复**
- **影响**：任何拿到授权码的第三方（重定向泄露、Referer、日志、恶意 App 注册的 redirect）只要同时拿到
  客户端密钥即可兑换，**没有 verifier 绑定**。现有测试 `TestAuthorizeRequiresPKCE` 只发 GET，因此
  它声称封住的那一类正是漏掉的这一类。
- **Pin**：`internal/oidchttp` —— POST 同一份 authorize 表单，断言与 GET 相同的
  `302 → error=invalid_request`；再加一条端到端：POST 得到的 code 不带 `code_verifier` 兑换必须失败。

### A4-1 `POST /oauth/revoke` 用 **refresh token** 请求时返回 `200` 却什么都没撤销

- **不变量**：④
- **证据**：`internal/store/postgres/oidc.go:386-397` 与 `internal/store/memory/oidc.go:414-422` 的
  `GetRefreshTokenInfo` 返回的是 **access token 的** `id_hash`。库（`pkg/op/server_legacy.go:419-439`）
  在 `token_type_hint != "access_token"` 时把这个值当作 tokenID 直接喂回 `RevokeToken`；
  `RevokeToken` 再哈希一次（`sha256(sha256(...))`），两个查找都落空，于是走 RFC 7009 的
  「本来就无效」分支 `return nil` → 200，**零行删除**。反证：故意送错的 hint（`access_token`）
  反而能让库跳过 `GetRefreshTokenInfo`、拿到原始值并**成功删除**——即唯一能用的撤销方式是客户端不会发的那个。
- **复现**（已执行，FAIL）：
  ```
  adversary_test.go:205: the revoked refresh token still mints tokens:
  {"access_token":"...","refresh_token":"T4OVnx87hIWRLXxyP86wXZW8gkL9nc59d6gNC-ZBhI4",...}
  ```
  注意它连**新的** refresh token 都发了。
- **状态**：CONFIRMED → **已修复**
- **影响**：被盗的 refresh token 在持有人撤销后**继续可用**，直到自然过期，而调用方收到 200。
  这正是 RFC 7009 承诺「不可抵赖」的地方给出的静默假保证。
- **Pin**：`internal/httpapi`（HTTP 层）+ 两个 store（无 HTTP 的等价断言：
  「`GetRefreshTokenInfo` 返回什么，`RevokeToken` 就必须能删掉什么」）。

### A1-1 设备流签发**客户端未注册**的 scope

- **不变量**：①
- **证据**：`POST /oauth/device_authorization` 完全不经过 `validateAuthorize`（后者只管 GET authorize）。
  库的 `createDeviceAuthorization`（`pkg/op/device.go:101`）把 `req.Scopes` **原样入库**，
  `ParseDeviceCodeRequest` 只校验 grant type。r0semi 自己的 scope 检查在
  `oidchttp.go:347-358`，只在 authorize 路由上跑。同意页用 `registry.Resolve` 渲染
  （`internal/httpapi/device_routes.go:31,46`；`oauth/scope.go:217-235`），它只看**目录**与
  `Descriptor.AllowedClients`，**从不看 `client.AllowsScope`**；决策侧 `oidcstore.NarrowScopes`
  只做「是 requested 的子集」检查。数据面 `internal/httpapi/federation_routes.go:92-95` 只看令牌里的 scope。
- **复现**（已执行，FAIL）：
  ```
  adversary_test.go:51: a client registered for account.id obtained a device code for an
  unregistered scope: 200 {"device_code":"f6P_95PgoMqMX0QiC97XEw","user_code":"VMLS-VRNS",...}
  ```
- **状态**：CONFIRMED → **已修复**
- **影响**：一个只注册到 `account.id` 的客户端可以拿到**任意目录内 scope**（只要受害者绑定了对应数据源），
  并读走受害者的游戏数据。
- **Pin**：`internal/oidchttp` —— `POST /oauth/device_authorization` 带未注册 scope 断言
  `400 invalid_scope`（对齐 `validateAuthorize`）；再加一条决策侧的守卫。
  现有 `TestDeviceAuthorizationEndToEnd` 抓不到，因为它的客户端**恰好**注册了它请求的 scope。

### A5-1 抹除账号时，审计行把 `usr_…` 写进了 `detail["actor"]`，假名密钥销毁够不到它

- **不变量**：⑤（明文落盘）兼 ④（抹除不彻底）
- **证据**：`internal/httpapi/account_routes.go:56` 自发抹除时 actor == subject；
  `internal/lifecycle/lifecycle.go:286` 把它写进 `Detail["actor"]`；
  `internal/store/postgres/audit.go:53` 只对 `e.Subject` 做假名化，`Detail` **原样入库**；
  `internal/store/postgres/auditpseudo.go:146-160` 的 `Destroy` 只删密钥行，不碰任何审计行；
  读端点 `internal/httpapi/audit_routes.go:96-107` 原样返回 `Detail`。
- **复现**（已执行，FAIL）：
  ```
  adversary_test.go:60: detail["actor"] carries the erased account id "usr_target",
  which the pseudonym key destruction cannot reach
  ```
- **状态**：CONFIRMED → **已修复**
- **影响**：抹除后，**唯一保证描述该账号的那一行**仍然带着账号 id——任何 dump、备份或运维读取都能把
  被抹除的人重新识别出来，并暴露抹除时间与其绑定/令牌数量。这与 `api-design.md` §4 与
  `threat-model.md` §9 声称的「再没人能把它们关联到你」直接矛盾；「机制落地前的行」那条豁免**覆盖不到它**，
  因为这行是机制自己写的。
- **Pin**：`internal/lifecycle` 扩展现有断言（`Detail` 的每个值都不得等于被抹除的 subject）；
  `internal/store/postgres` 再加一条：抹除后扫全表，断言原始 subject 不出现在任何列。

### A6-2 输掉 CAS 的 refresh 已经把**胜者的密钥覆盖掉了**

- **不变量**：⑥（半写）兼 ④
- **证据**：`internal/federation/refresh.go:90` 先 `storeBindingSecret`（写 vault），
  `:93` 才 `PutIfVersion`。`:97-101` 输掉时只返回胜者的**绑定行**，**没有任何一步把胜者的密钥写回去**。
  注意 `refreshBinding` 顶部 `:45` 的版本重读挡住的是「胜者已提交」这一种交错；
  真正的窗口是「重读之后、写密钥之前胜者提交」。
- **复现**（已执行，FAIL）：用 `frozenStore` 把胜者的提交放进败者的**上游调用期间**，
  否则版本重读会提前返回（我最初两次复现都因此**假通过**——这正是必须自己跑一遍的理由）：
  ```
  adversary_test.go:130: the vault now holds the LOSER's token "loser-token" while the
  winner's row describes "winner-token": the two stores disagree about which upstream token is live
  ```
- **状态**：CONFIRMED → **已修复**（代码路径 + 确定性复现）
- **影响**：vault 与绑定行就「哪个上游令牌还活着」产生分歧。最坏交错下 vault 留着一个源**已经轮换掉**的
  令牌，下一次调用读到 401 → 强刷 → `invalid_grant` → `refreshRejected`（`refresh.go:110-121`）
  于是**删掉一个本来健康的绑定并撕毁其密钥**，用户必须重新绑定。
- **Pin**：`internal/federation/refresh_cas_test.go` —— 断言输掉 CAS 后 vault 里仍是**胜者**的密钥。
  修法是先 CAS、只在赢的路径上写密钥，或输掉时把胜者的密钥读回重写。

### A2-1 bind 回调只校验「手柄属于这个浏览器」，不校验「属于这个账号」

- **不变量**：②
- **证据**：`internal/httpapi/federation_routes.go:266` 只调 `sessions.Bound`，**没有**
  `sessions.OwnerMatches`；两个同类处理器都查两者（`authorization_routes.go:74-77`、`device_routes.go:80-81`）。
  `auth.Manager.Bind`（`internal/auth/auth.go:213-218`）在登录状态下**会**记录 owner，
  `OwnerMatches`（`:225-236`）的文档写明这就是它的用途——标签在，只是没人查。
  接管路径：`Unbind`（`:270`）先删掉会话手柄，`CompleteBind`（`:277`）再消费 flow 行，
  之后才轮到它自己较弱的 `flow.User != user` 检查。
- **复现**（已执行，FAIL）：
  ```
  adversary_test.go:220: another account acted on A's bind handle: got 303, want 400
  adversary_test.go:230: the owner can no longer finish their own bind flow: got 400, want 303
  ```
- **状态**：CONFIRMED → **已修复**
- **影响**：同一浏览器里切换账号的第二个账号可以**摧毁**第一个账号的绑定流程（跨账号可用性/完整性）。
  绑定本身在下一层被正确拒绝，所以不是接管；但它是整棵树里**唯一**漏掉 owner 检查的调用点，
  而 `CompleteBind`/flow 存储的顺序一旦重构，它就会静默升级成完整的跨账号绑定。
- **Pin**：`internal/httpapi/bind_test.go` —— 双账号（`newFlowEnvWith` + `signInAs`）断言另一账号的
  回调得到 **400**（与未知手柄同形，不给存在性预言机），且原账号仍能完成。

### A6-1 `Unbind` 把「vault 打不开」塌缩成「没有东西要撤」

- **不变量**：⑥
- **证据**：`internal/federation/unbind.go:76-84` —— `useBindingSecret` 对**除「没有密钥」以外**的
  一切失败都返回 error（KEK 未配置、审计写入被拒、仓库读失败、AEAD 打开失败），而这里把它们**全部**
  变成 `RevocationNothingToDo`，**且不是 error**。`killswitch.go:88-95` 只统计
  `RevocationUnsupported`/`RevocationUnavailable`，于是该绑定计入 `Revoked++`、其它计数器不动。
  对照：`revocation.go:123-129`（`CascadeRevoke`）把同样的失败**当作 error**——两条路对「打不开的凭据」
  是否可报告这件事**互相矛盾**。
- **复现**（已执行，FAIL）：
  ```
  adversary_test.go:162: an unopenable credential was reported as "nothing": the caller — and
  the kill switch's counters — is told nothing needed doing, while the upstream token was never
  asked to be revoked
  ```
- **状态**：CONFIRMED → **已修复**
- **影响**：`DELETE /v1/bindings/...` 告诉用户「无事可做」；`POST /v1/admin/kill_switch` 回报
  `revoked: N, unavailable: 0, unsupported: 0`——**事故响应者会相信每个源都被通知了放弃令牌，而实际上
  一个撤销请求都没发出**，上游令牌继续有效。
- **Pin**：`internal/federation/unbind_test.go` —— 用一个「读永远失败」的 vault，
  断言 `Upstream == RevocationUnavailable`（今天是 `RevocationNothingToDo`）且
  `RevokeAllBindings(...).Unavailable >= 1`。需要为「打不开」与「本来就没有」给出两个不同的值。

### A1-3 `POST /oauth/authorize` 把未注册的 scope **静默收窄**，而 GET 会拒绝

- **不变量**：①
- **证据**：同 A1-2 的方法缺口。GET 走 `oidchttp.go:347-358` → `invalid_scope`；POST 落到库里
  `ValidateAuthReqScopes`（`pkg/op/auth_request.go:294-316`），它用 `slices.DeleteFunc` **删掉**越界 scope，
  请求照常创建并跳登录页。
- **复现**（已执行，FAIL）：
  ```
  adversary_test.go:159: POST silently accepted an unregistered scope:
  "/login?authRequestID=..." (GET refused it with "invalid_scope")
  ```
- **状态**：CONFIRMED → **已修复**
- **影响**：本身不提权，但决策记录 O-7（「未知/未授权 scope ⇒ `invalid_scope`，不是静默收窄」）
  在一条可达的线上路径上被违反；客户端永远不会被告知它要了不该要的东西。
- **Pin**：同 A1-2 的 POST 探针（`internal/oidchttp`）。

### A6-3 32 字节 **hex** 的 `RE0AUTH_KEK` / `RE0AUTH_AUDIT_KEY` 永远被拒绝

- **不变量**：⑥
- **证据**：`cmd/re0auth/config.go:524-534` 依次尝试 `base64.StdEncoding` → `RawStdEncoding` → `hex`。
  32 字节 hex 是 64 个字符，**全部落在 base64 字母表内且长度是 4 的倍数**，所以第一个分支成功并解出
  **48 字节**，长度检查随即拒绝，`hex` 分支成为死代码。
- **复现**（已执行，FAIL）：
  ```
  adversary_test.go:37: a 32-byte hex key was rejected: a vault KEK must be 32 bytes, got 48
  ```
- **状态**：CONFIRMED → **已修复**
- **影响**：**不是**绕过（进程仍然拒绝启动）。危险在信息：密钥格式错被报成**密钥长度错**，
  而最自然的补救——重新生成一把——会**静默让所有已存凭据不可读**，正是 `decodeKEK32` 存在的意义所在。
  审计 key 同理。
- **Pin**：`cmd/re0auth/main_test.go` —— `decodeKEK32(hex(32 随机字节))` 必须返回那 32 字节。

### A5-2 测试夹具不清 `audit_chain` / `audit_subject_keys`，审计链测试**从第二个起必失败**

- **不变量**：⑤（审计完整性守卫本身）
- **证据**：`internal/store/postgres/postgres_test.go:41-52` 是全仓库唯一的 `TRUNCATE`，
  它列了 `audit_events` 但**没有** `audit_chain`，也没有 `audit_subject_keys`。
  `appendChained` 读的是持久化的 `head_hash`，所以 `audit_events` 被清空后 head 仍然是**陈旧的**，
  下一行的 `prev_hash` 非空，`Verify`（`auditchain.go:120-128`）判定
  「first chained row does not point at the genesis hash」。
- **状态**：CONFIRMED → **已修复**——**这是本次审计中新代码自己的缺陷**，属第三项/3B 引入。
- **影响**：**3A/3B 在 CI 里等于没有验证过**：要么红，要么以错误的理由绿
  （`TestAuditChainCatchesDeletion` 等会「通过」，因为它们本就期待失败）。
  更糟的是，把这个红「修」成放宽 genesis 检查，会**删掉链首截断唯一的检测手段**。
- **处置**：**已在本次审计中修复**（夹具修复，非生产行为变更）：把两张表加进 `TRUNCATE`，
  并补回迁移 `0013` 的 genesis 行。这一条是唯一被顺手修掉的——它是**测试夹具**，
  留着会让第三项的全部验证失去意义；其余发现的修复留待决定。

---

## 探过但**没**破的（这些值得变成守卫）

- **① 刷新不能提权**：`grant_type=refresh_token` + 越界 `scope` → `400 invalid_scope`（库的
  `ValidateRefreshTokenScopes` 做子集检查）；重排、重复、省略都无法提权。
- **① 交互式同意不能提权**：`ApproveAuthorization` 拒绝不在 `requested` 里的 scope，
  且重新附上的协议 scope **来自 `requested`**，所以往返既不扩也不丢 `openid`。
- **① `offline_access` 不泄漏**：它在**入库前**就被剥离（两个 store），所以自省、
  `/v1/grants`、令牌响应里都看不到；`sanitizeTokenResponse` 覆盖了响应侧。
- **① 授权码单次使用**；**① 公开客户端的 POST 不能绕过 PKCE**（兑换要求 verifier）。
- **① 客户端不能在兑换时冒充另一个客户端**（库校验 `client.GetID() == authReq.GetClientID()`）。
- **② subject 来源**：每一个 `CompleteLogin` / 设备批准调用点都取自**会话**，没有任何路径从请求体取 subject。
  唯一进入系统的外部 subject 是 `id_token_hint`，而它到不了令牌（协议回调要求 `authReq.Done()`，
  只有会话绑定的 `CompleteLogin` 会置位）。
- **② 手柄所有权**：同意与设备决策两处都查 `Bound` **和** `OwnerMatches`，且答 **404**，无存在性预言机。
- **② I-3 / I-2 并发**：内存 store 的检查与写入在**同一把锁**内；Postgres 用 `UNIQUE(provider,subject)`
  与 `FOR UPDATE` 锁用户行，`23505` 被翻译成 `ErrIdentityTaken`（不是 500、更不是成功）。
- **④ 自省无缓存**：`withBearer` 每请求自省一次，删行即刻 `active:false`。
- **④ 授权按 client 聚合**，撤销一个 client 不影响同 subject 的另一个。
- **④ Kill Switch 四目标矩阵与 `admin.md` §4 一致，且偏向安全一侧**（`bindings` 完全不碰令牌与会话等）。
- **④ Unbind 与 CascadeRevoke 的失败规则**确实相反，且各自实现的是**自己**那条。
- **④ 刷新轮换单次使用**：内存与 Postgres 都拒绝重放。
- **⑤ `GET /v1/account/export` 结构性无凭据**：复用 `identityViews`/`bindingViews`/`grantViews`
  这三个列表端点同款构造函数，且反泄漏测试是**非空转**的（先塞已知明文再断言不出现）。
- **⑤ vault AAD 两层都把身份绑住**：KEK→DEK 与 DEK→payload 各自独立绑定，字段长度前缀避免了
  `("a","bc")` 与 `("ab","c")` 的歧义。
- **⑤ 无任何 `slog`/`log` 调用格式化凭据**；错误响应一律映射成固定码。
- **⑥ 审计写入失败仍然阻断跨边界调用**（新增的假名解析失败也照此传播）。
- **⑥ 上游响应形状**：非 200 视为错误，200 但没有 `access_token` 或 body 不是 JSON 一律失败。
- **⑥ 探针**：`isProbe` 在限流桶之前判断，桶满不影响 `/healthz` `/readyz`。

## 未能到达（残余盲区）

> 本节在后续改动落地后**逐条核对过一次**，与 [security-audit-3.md](./security-audit-3.md) 的同名小节同步。
> 每条现在都标着它是**已闭环**、**已由第三轮回答**还是**仍开放**——把已经修好的东西继续写成盲区，
> 和漏记一个洞一样有害。

**已闭环**

- **Postgres 相关的每一条现在都在 CI 里真的执行**：`test` 作业自带 `postgres:16` service，跑
  `./internal/store/postgres/` 全量、以 `-race -p 1` 跑全套件，并用 `E2E_DATABASE_URL` 再跑一遍
  Playwright（`.github/workflows/ci.yml`）。当年只有「读代码到行」的那几条，各自的落盘侧守卫是：
  - A4-1 的 Postgres 一半：`oidc_test.go` 的 `TestRevokeTokenCutsTheWholeGrant`——用 **refresh token 的值**
    请求撤销，断言配对的 access token 随即不可自省，正是本轮「`GetRefreshTokenInfo` 返回什么，
    `RevokeToken` 就必须能删掉什么」的判据。
  - A5-1 的落盘一半：`auditpseudo_test.go` 的 `TestAuditPseudonymisesSubjectAndUnlinksOnDestroy`
    （销毁后历史不复活、假名不重用）、`erasure_test.go` 的 `TestAccountDeletionLeavesNoOrphans`，
    以及静态解析迁移的 `erasure_schema_test.go` 的 `TestEverySubjectColumnIsHandledByErasure`
    （新增带 `subject`/`user_id` 的表却忘了抹除会在这里失败）。注意原文 Pin 里那句「抹除后扫全表，
    断言原始 subject 不出现在任何列」**没有**以整表扫描的形式落地；同一类担忧现在由上面那条
    迁移解析的静态守卫承担。
  - A5-2 的夹具：`postgres_test.go` 的 `openTestDB` 已把 `audit_chain`、`audit_subject_keys` 加进
    `TRUNCATE` 并重播 genesis，注释里写的正是本条发现——「链测试从第二个起必失败」不会再出现。
- **`-race` 未运行**：CI 现在以 `-race -p 1` 跑整套，并发论断由竞态检测器背书，不再只靠锁与事务结构。
  「本机无 cgo」这一事实没变，但它不再是盲区。
- **凭据列守卫只覆盖 `federation_bindings` 一张表**：已改为扫**整个 live schema**
  （`postgres_test.go` 的 `TestNoColumnInTheLiveSchemaCanHoldACredential`，带显式豁免清单），
  外加一条不需要数据库的静态版（`credential_columns_test.go` 的 `TestNoColumnCanHoldACredential`）。
  本轮点名的 `federation_bind_flows.pkce_verifier` 与 `audit_subject_keys.key` 都在覆盖内。
- **业务平面响应不带 `Cache-Control`**：`responses.go` 的 `writeJSON` 统一 `no-store`
  （`writeOAuthError` 同样），守卫是 `responses_test.go` 的 `TestBusinessPlaneResponsesAreNotCached`。
- **bind 回滚自身的失败被 `_ =` 丢弃**（原「未验证的假说」第 3 条）：**已修**，即「修复总览」里的 A6-5——
  `internal/federation/bind.go` 用 `errors.Join` 把回滚失败并进返回错误，不再吞掉。
  原文把同一件事同时挂在「已修复」与「未验证假说」两处，是本文件的自相矛盾，此处一并消除。

**已由第三轮回答**

- **设备批准是非原子「读—判—写」**（原「未验证的假说」第 1 条）：第三轮 C3-3 正面处理——机制确证、可利用性证伪，
  缺谓词仍在但构不出收益。守卫是 `internal/httpapi/device_adversary_test.go` 的
  `TestAdversarialDeviceTokenSubjectIsAlwaysAnApprover` 与 `TestAdversarialDeviceDenyWinsWhicheverWriteOrder`，
  见 [security-audit-3.md](./security-audit-3.md) C3-3。

**后来闭环的（本节原先列在「仍开放」）**

- **每 subject 的审计密钥若被写成零长度**（原「未验证的假说」第 2 条）：**已修**。长度被定义成常量，
  读路径的两处都过 `checkSubjectKey`（`internal/store/postgres/auditpseudo.go`）；守卫是纯函数层的
  `TestSubjectKeyLengthIsChecked` 与 Postgres 侧的 `TestAuditRefusesAKeyRowItDidNotMint`
  （后者顺带回答了当初「需要数据库才能确认 pgx 如何回读空 `bytea`」这个悬而未决的问题）。
  处置选择**失败**而不是「当作没有密钥」，理由写在 `checkSubjectKey` 的注释里：读路径把「没有行」
  当「还没有密钥」并铸一把新的，若把长度错的行也归入这一类，就会给一个已有密钥的 subject 再铸一把，
  把它的历史劈成两个假名。
- **第三方库未审计**：**第四轮已闭环**。它把这条缝当成靶子：枚举了 `zitadel/oidc v3.51.3` 在这些路径上
  写什么（`pkg/op/error.go` 的 `oidc_error` 带 `description` 与整条 `parent` 链；
  `pkg/oidc/authorization.go` 的 `LogValue` 记录 scopes/response_type/client_id/redirect_uri，
  **不**记录 `code_challenge` 与 `state`），并落成守卫
  `internal/oidchttp` 的 `TestAdversarialProtocolErrorsDoNotLogCredentials`（把进程默认 slog 换成捕获器，
  A1-1/A1-2 的根因就在**库与薄封装之间的缝**里，这正是那条缝的守卫）。随后又补上成功路径的一半：
  `TestAdversarialSuccessfulExchangesDoNotLogTokens`。
