# 第三轮对抗性审计（Re0Auth）

**性质**：定向轮。不重扫前两轮已覆盖的面，只打三处**未经对抗性检验**的地方——
①Zitadel 库与薄封装之间的接缝、②审计读取面、③设备流的并发与绑定正确性。

**方法**：`audit-authz` skill 的探针目录，三个**并行、严格只读**的对抗子代理各领一处
（`.commandcode/skills/audit-authz/references/probes.md`）。一条发现的成立标准不变：
**必须有一条会失败的测试**——「我推理它是安全的」正是这套流程要取代的东西。

**执行**：标 CONFIRMED 的发现，能在这台机器上跑的都用**实际运行**的测试复现了（输出见各条）。
Postgres 支撑的部分没有数据库，只有**读代码到行**的证据，已逐条注明。本轮共 **11 条**
（3 处各报若干），**CONFIRMED 的全部已修复**，每条的复现测试都改写成常规套件里的守卫。

```sh
go test ./...   # 全部守卫都在这个套件里，不再需要 build tag
```

## 修复总览

| # | 发现 | 不变量 | 根因 / 修法 | 守卫 |
|---|---|---|---|---|
| A3-1 | `GET /oauth/token` 绕过令牌响应契约：无 `openid` 也发 `id_token`，且无 `Cache-Control` | ①⑤ | `isToken` 判据带 `r.Method == POST`；库无方法约束。改为**只看路径** | `oidchttp`: `TestAdversarialTokenEndpointRejectsGET` |
| A3-2 | `GET /oauth/device_authorization` 绕过 client-scope 预检，签发未注册 scope | ① | 设备预检同样只在 POST 上跑。改为**与方法无关** | `oidchttp`: `TestAdversarialDeviceAuthorizationRejectsGET` |
| A3-3 | 协议面 401 不带 RFC 6750 Bearer challenge | ③ | 库不写 challenge，本包自己的 401 写的是 `Basic`（客户端认证用）。为 `userinfo` 补 Bearer challenge | `oidchttp`: `TestAdversarialUserinfoUnauthorizedCarriesABearerChallenge` |
| A3-5 | `Clients`/`Registry` 为 nil 时全部预检**静默失效**（fail-open） | ⑥ | `New` 不校验，`validate*` 里 `if h.clients == nil { return false }`。改为**必填**，去掉 fail-open 分支 | `oidchttp`: `TestAdversarialNewRequiresClientsAndRegistry` |
| 结构性 | 平面走查用 `protocolPostOnly` 按「预期方法」走，正是它看不见上面两条 | ③ | 改为对库无方法约束的端点**每种方法各走一遍** | `httpapi`: `plane_test.go` 收紧后的走查 |
| B3-1 | 整链元数据被 `UPDATE ... SET row_hash = NULL` 抹掉后 `verify` 仍 `ok:true` | ⑥ | `Verify` 不查 `audit_chain.head_hash`；全部行被判 legacy。加**链头见证** | `postgres`: `TestAdversarialAuditChainCatchesAWholeLogMetadataStrip` |
| B3-2 | 无假名密钥的空页 `pagination.limit=0`，成账号存在性预言机 | ② | 提前返回用了零值 `Limit`。带**服务端实际应用的 limit** 返回 | `postgres`: `TestAdversarialAuditNoKeyPageCarriesTheAppliedLimit` |
| B3-3 | `?until=0001-01-01T00:00:00Z` 被静默丢弃 → **扩大**结果集 | ⑥ | 零值被当「无界」。改为**拒绝**（400） | `httpapi`: `TestAdversarialAuditZeroTimeBoundIsRefused` |
| C3-1 | 撤销（含 Kill Switch `all`）到不了**已批准**的设备授权 → 下一次轮询复活 | ④ | 撤销只删令牌行，`oidc_devices` 没动。`RevokeTokens`/`RevokeGrant` 一并删匹配的设备授权 | `httpapi`: `TestAdversarialDeviceCodeIsRevokedByBulkRevocation` / `...ByTheRevokeButton` |
| C3-2 | `device_code` **不是单次使用**：批准后每次轮询都 mint 新令牌对 | ④ | 两个 store 的状态读取都是纯读，库没有消费步骤。**首次读到 Done 即消费**（内存删记录 / PG `DELETE ... RETURNING`） | `httpapi`: `TestAdversarialDeviceCodeIsSingleUse` |
| C3-3 | 第二轮假说：审批是**非原子读-判-写** | ①② | **机制确证、可利用性证伪**：库先判 `Denied` 再判 `Done`，subject 来自会话。缺谓词仍在，但构不出收益 | `httpapi`: `TestAdversarialDeviceTokenSubjectIsAlwaysAnApprover` + `...DenyWinsWhicheverWriteOrder` |

**未修、列为判断或假说的（不是遗漏）** 见文末「判断」与「未能到达」两节。

## 这一轮修了什么，为什么值得单独说

三条**跨发现**的教训，比任何单条都重要：

1. **与方法无关的检查，才叫检查。** A3-1/A3-2 与第二轮 A1-1/A1-2 是同一个洞的第一与第二个面：
   库把端点注册成**不带方法约束**、从 `r.Form` 取值，而封装的检查却在某个方法上。第二轮
   只把 `authorize` 改成了方法无关，**没有把这条教训推广到 token 与 device**——于是同一类洞
   又开了两扇。修法是把「方法无关」变成**平面走查的性质**（`protocolAnyMethod`），而不是每次都靠人记得。
2. **一个断言里的「预期方法」，正是下一个洞的藏身处。** `protocolPostOnly` 这个映射没有错，
   它只是**假设**了调用方会用的方法。走查按自己假设的方法走，就永远走不到洞所在的路径——
   这正是第二轮教训「收紧一个宽容的断言会立刻找出它藏起来的东西」在**结构**上的同构版本。
3. **「读接口」和「安全接口」是两回事。** B3 的两条都不是协议漏洞，而是**读侧的信息与语义**：
   空页的 `limit` 字段、被丢掉的零值时间界。它们不改变任何一行数据，却分别给出一个存在性预言机
   和一次静默的范围扩大。审计读取面越像「运维日志」，越容易被当成无害而跳过——这一轮证明它值得单独当靶子。

## 发现（按攻击者收益排序）

### A3-1 `GET /oauth/token` 绕过令牌响应契约：无 `openid` 也返回 `id_token`，且不带 `Cache-Control`

- **不变量**：①（未被批准的就签发）⑤（凭据流向缓存）
- **证据**：`internal/oidchttp/oidchttp.go` 的 `isToken := r.Method == http.MethodPost && r.URL.Path == tokenPath`
  同时挡住 `sanitizeTokenResponse`（O-2 / O-6）与 `Cache-Control: no-store`（RFC 6749 §5.1）。
  而库的 `op.Exchange` 从 `r.FormValue("grant_type")` 分派，GET 的查询串一样能填满它。实测：
  ```
  POST /oauth/token -> 200 {... 无 id_token ...} cache-control=no-store
  GET  /oauth/token -> 200 {"access_token":"eyJ…","id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHAtdGVzdCIsInR5cCI…",...} cache-control=
  ```
- **状态**：CONFIRMED（已执行）→ **已修复**
- **影响**：一个从未请求 `openid`、因此也从未走过 OpenID 同意路径的 RP，拿到了**签名身份断言**——
  正是 `oidc-decision` 说**永不返回**的东西；且携带 `access_token`+`id_token` 的响应没有任何缓存指令。
- **Pin**：`internal/oidchttp/adversary_test.go`，`TestAdversarialTokenEndpointRejectsGET`。

### A3-2 `GET /oauth/device_authorization` 绕过 client-scope 预检，签发客户端未注册的 scope

- **不变量**：①
- **证据**：`oidchttp.go` 的设备预检被 `r.Method == http.MethodPost` 挡住；库的
  `DeviceAuthorizationHandler` 不看方法、`createDeviceAuthorization` 把 `req.Scopes` **原样入库**。实测：
  ```
  POST /oauth/device_authorization -> 400 invalid_scope
  GET  /oauth/device_authorization -> 200 {"device_code":"eNWvIZoSMeJaeLPuVWGqwQ","user_code":"KHJF-HBNQ",…}
  ```
  并且该 scope 一路走到**活令牌**（`scope":"phigros.score.read"`）。
- **状态**：CONFIRMED（已执行）→ **已修复**
- **影响**：决定「哪个 RP 能要 `phigros.*`」的注册闸门，被换一个 HTTP 方法绕过。人类同意页会列出
  被批准的 scope（受害者看得见自己批准了什么），损失的是**运营商约束 RP 触达范围的能力**，不是盲目的受害者侧提权。
- **Pin**：同文件 `TestAdversarialDeviceAuthorizationRejectsGET`。

### C3-1 撤销（含 Kill Switch）到不了已批准的设备授权，下一次轮询就复活

- **不变量**：④（撤销没有真的生效）
- **证据**：所有撤销路径只删**令牌行**（`internal/store/memory/oidc.go` 的 `RevokeTokens`/`RevokeGrant`、
  `internal/store/postgres/oidc.go` 的 `revokeMatching`），`oidc_devices` 只在过期清扫与账号抹除时被碰。
  实测（内存后端）：批准 → 兑换一次（200，活令牌）→ `RevokeTokens(TokenFilter{})`（**就是 Kill Switch
  all-target 调的那个**）→ 旧令牌 `/v1/me` 已 401，但**同一个 `device_code` 再兑一次又是 200 的活令牌**。
  用户侧路径同理：`DELETE /v1/grants/cli` 返回 204，之后 `device_code` 仍能 mint。
- **状态**：CONFIRMED（已执行）→ **已修复**
- **影响**：Kill Switch 报出非零的 `tokens_revoked`，而持有 `device_code` 的客户端在**不与用户交互**的情况下
  重新拿到一整套 access+refresh，直到该 code 的 10 分钟 TTL 耗尽。对被攻陷客户端的围堵在「已切断」的报告之后
  被静默推翻。
- **Pin**：`internal/httpapi/device_adversary_test.go`，`TestAdversarialDeviceCodeIsRevokedByBulkRevocation`
  与 `...ByTheRevokeButton`。

### C3-2 `device_code` 不是单次使用：批准后每次轮询都 mint 一对新令牌

- **不变量**：④（可反复取用已消费的授权）
- **证据**：`op.CheckDeviceAuthorizationState` 纯读 `GetDeviceAuthorizatonState`，两个 store 的实现也都是纯读
  （内存 `return d.state()`；PG `SELECT …`），记录里**没有已消费字段**。实测：同一 `device_code` 连续兑换三次，
  得到三套**不同**的 `access_token`（且每次都带 refresh token）。项目自己在 `web/static/robots.txt` 里写着
  「device code is single use」——修好之前那句话是不成立的。
- **状态**：CONFIRMED（已执行）→ **已修复**
- **影响**：任何得知 `device_code` 的一方（日志、共享终端、缓存了它的客户端）在 TTL 内持续 mint 互相独立的令牌对，
  且每次重放都**凌驾于其间发生的撤销之上**（这就是 C3-1 的根因）。
- **Pin**：同文件 `TestAdversarialDeviceCodeIsSingleUse`。

### C3-3 第二轮遗留假说：审批是非原子「读—判—写」（**机制确证，可利用性证伪**）

- **不变量**：①②
- **证据**：写侧在两个 store 里都是无条件的（`ApproveDevice` 没有 `AND done = false`，也不嗅探过期），
  判定只在**读者**里、且与写分属两次加锁 / 两条语句之间。实测：两次 `ApproveDevice`（`usr_1` 再 `usr_2`）**都成功**，
  之后 mint 出的令牌属于后写者。**但没有收益**：要拿到受害者 subject 的令牌，必须有一次**携带受害者 subject 的写**，
  而那次写只存在于受害者自己点下批准之后（那是钓鱼步骤，不需要竞态）；与攻击者自己的批准竞争，得到的是攻击者自己的 subject。
  且库**先判 `Denied` 再判 `Done`**，所以「半状态」也不会漏出令牌。
- **状态**：CONFIRMED（机制）；**不可利用**（结论）
- **处置**：不引入可能出错的谓词去「修」一个构不出收益的东西；改为把**安全性质**钉住：
  令牌 subject 恒为**某个批准者**、且拒绝在任一写序下都赢。
- **Pin**：`TestAdversarialDeviceTokenSubjectIsAlwaysAnApprover`、`TestAdversarialDeviceDenyWinsWhicheverWriteOrder`。

### B3-1 整链元数据被抹除后 `verify` 仍报 `ok:true`

- **不变量**：⑥（控制报了它并不拥有的保证）
- **证据**（读代码到行；需 DB 执行）：`internal/store/postgres/auditchain.go` 里 `row_hash IS NULL` 的行
  计 `Legacy++` 并 `continue`，**不碰 `prev`/`started`**，且该分支只在链已开始后才判定违规；
  `Verify` 最后**无条件** `v.OK = true`，从不查 `audit_chain.head_hash`。于是
  `UPDATE audit_events SET row_hash=NULL, prev_hash=NULL, signature=NULL` 让整库读起来都像「迁移前的 legacy」，
  内容随便改都不再重算、不再验签，`verify` 返回 `200 {"ok":true,…}`。既有的编辑/中间删除/伪造签名/链后插入行守卫都覆盖不到它。
- **状态**：CONFIRMED（读；需 DB）→ **已修复**（加链头见证：链头已推进而没有任何 chained 行 ⇒ `ok:false`）
- **影响**：唯一以「日志被动过吗」为目的的控制，对「把整条链的元数据清零」的 attacker 报绿灯。
- **Pin**：`internal/store/postgres/auditchain_test.go`，`TestAdversarialAuditChainCatchesAWholeLogMetadataStrip`。
- **残余**：若攻击者**连链头也重置回 genesis**，就与「确实只有迁移前行」不可区分——这是**已记录的无外部锚点边界**，
  这一条不含它。

### B3-2 无假名密钥的空页 `pagination.limit = 0`，是账号存在性预言机

- **不变量**：②（一个关于他人账号的一比特预言机）
- **证据**（已执行，HTTP 边界）：`internal/store/postgres/auditread.go` 在「无假名密钥」的提前返回里
  用零值 `Page{Entries: …}`（`Limit=0`），而正常路径返回 `Limit: limit`；handler 把 `page.Limit` 原样写进 body。
  实测两页不同形：`noKey=…limit:0` vs `keyButEmpty=…limit:100`。
- **状态**：CONFIRMED（已执行）→ **已修复**（提前返回带上服务端实际应用的 limit）
- **影响**：被允许的运维可据此判断任意 `usr_…` **是否曾经出现过**（即账号是否存在），并确认某账号的假名密钥已被销毁。
  次生：`limit: 0` 不是 API 会用的大小（文档 `minimum: 1`），把 `pagination.limit` 回喂给 `?limit=` 的客户端会被拒。
- **Pin**：`internal/store/postgres/auditread_test.go`，`TestAdversarialAuditNoKeyPageCarriesTheAppliedLimit`。

### B3-3 `?until=<零值时间>` 被静默丢弃，**扩大**而非缩小结果

- **不变量**：⑥（不能被满足的约束被当作不存在）
- **证据**（已执行）：`time.Parse(RFC3339, "0001-01-01T00:00:00Z")` 返回**零值** `time.Time`，
  而读者的判据是零值测试而非**存在性**测试（`if !q.Until.IsZero()`）。于是该界被丢弃，返回整流日志（200，不是 400）。
  `?since=` 同向；`until` 是**泄露更多**的那个方向。
- **状态**：CONFIRMED（已执行）→ **已修复**（能解析成零值的界一律 400 拒绝）
- **影响**：一个「year 1 之后什么都不要」的请求（Go 的零值 `time.Time` 恰好格式化成这个串，现实产物）拿到整个日志；
  以为已经划定窗口的自动审查会过度采集。
- **Pin**：`internal/httpapi/audit_routes_test.go`，`TestAdversarialAuditZeroTimeBoundIsRefused`。

### A3-3 协议面 401 不带 Bearer challenge

- **不变量**：③（一个平面一套线格）
- **证据**（观察）：`GET /oauth/userinfo`（无令牌）→ `401 {"error":"invalid_token",…}`，`WWW-Authenticate` **为空**；
  而本包自己的 401 写的是 `Basic realm="oauth"`（给客户端认证用）。RFC 6750 §3 要求受保护资源的 401 带 Bearer challenge。
- **状态**：CONFIRMED（观察）→ **已修复**（`userinfo` 的 401 补 `Bearer error="invalid_token"`）
- **影响**：标准 RP 无法把「这个令牌不行，去刷新」与传输故障区分开。
- **Pin**：`internal/oidchttp/adversary_test.go`，`TestAdversarialUserinfoUnauthorizedCarriesABearerChallenge`。

### A3-5 `Clients`/`Registry` 为 nil 时全部预检静默失效（fail-open）

- **不变量**：⑥
- **证据**（读代码到行）：`New` 不校验它们，`validateAuthorize` / `validateDeviceAuthorization` 以
  `if h.clients == nil || h.registry == nil { return false }` 直接放行。此时 PKCE、scope 闸门、设备闸门**全部消失**，
  退化成库的默认（对机密客户端不强制 PKCE、未知 scope 静默丢弃）。
- **状态**：HYPOTHESIS（未观察到生产误配）→ **已加固**（`New` 将其改为必填，删掉 fail-open 分支）
- **影响**：一次接线错误就把 OP 降级成第二轮发现的那样，且没有错误、日志或测试会响。
- **Pin**：`TestAdversarialNewRequiresClientsAndRegistry`。

### A3-4 表单 `client_id` 与 HTTP Basic 不一致：按一个客户端校验、按另一个记账

- **不变量**：①（客户端代另一客户端行事）
- **证据**（读，未复现）：封装先读表单、再回退 Basic，且**从不校验 secret**
  （`oidchttp.go` 的 `validateDeviceAuthorization`）；库则相反，Basic 成功就**以 Basic 身份为准**。
  fixture 里缺一个「窄范围机密客户端」，这正是复现该方向所需，故未复现。
- **状态**：HYPOTHESIS
- **影响**：一个只注册到 `account.id` 的机密 RP，可在表单里写另一个（id 公开的）客户端、同时用 Basic 认证自己，
  过掉封装的检查，拿到未注册的 scope。
- **处置**：**未修**——修法涉及设备流的客户端认证语义（是否要求 secret），属于需要裁定的判断，
  留作独立决策而不是顺手改。已在本轮记录。
- **处置（第四轮，commit `5376ca3`）**：**已修并留守卫**。当时说"需要先裁定设备流的客户端认证语义"，
  第四轮把裁定落成了规则本身：**一个请求只能声明一个客户端身份**——表单 `client_id` 与 Basic 同时
  出现且不一致时直接拒绝，即使所求 scope 正是 Basic 那一方注册过的（偏好任何一方，正是这个洞能活过
  两轮的原因）。守卫是 `internal/oidchttp` 的
  `TestAdversarialDeviceAuthorizationRefusesTwoClientIdentities`，它同时钉住两条**诚实路径仍然可用**
  （机密客户端只用 Basic、公开客户端只在表单里写自己），避免"修"成一个更大的拒绝。fixture 也补上了
  当时缺的那个形状——窄范围机密客户端（`oidchttp_test.go` 的 `narrowID`，其注释即本条）。

## 探过但**没**破的（这些值得变成守卫）

- **① POST `/oauth/authorize` 的方法无关预检**（第二轮修复）在 GET/POST 下都成立：未注册 scope → 302
  `error=invalid_scope`；机密客户端缺 PKCE → 302 `error=invalid_request`。
- **① 重复 scope 参数不能提权**：库的 `ValidateAuthReqScopes` 会删掉不通过 `client.IsScopeAllowed` 的 scope，
  与封装的判据同源。
- **③ discovery**：两份文档内容一致，`code_challenge_methods_supported=["S256"]`，**不广告** `end_session`。
- **③ 错误归一化**：未认证的 `introspect`/`revoke` 都是 OAuth JSON，线路上看不到库内部文本（`ErrorType=`/`Parent=`）。
- **② B3-2 的读取本身无副作用**：`loadKey` 只 SELECT；唯一的 `INSERT … ON CONFLICT` 在写路径的 `subjectKey` 里。
- **② 过滤解析不可被导向**：`?subject=` 先 HMAC 成假名再作为绑定参数入库；`?action=` 同理；`OrderBy` 硬编码 `id DESC`。
- **② 分页完整**：`id < $before` 的排他上界，逐页无重无漏，末页**不带** `next_cursor`。
- **② 授权**：已登录非管理员 → **404**，与未知路径同形；无允许列表则整个平面不挂载。
- **④ 设备令牌的 subject** 恒来自会话（批准者的账号），令牌绑定发起流的客户端。
- **④ `user_code`** 两侧归一化一致（`upper(replace(code,'-',''))`），PG 唯一约束在同一表达式上，无碰撞/重绑。
- **④ 匿名预言机**：两个设备端点在无会话下 401（决策拒绝），无会话部署下**整体不挂载**。
- **⑥ 失败方向**：`verify` 把「链断了」当 `200 ok:false`；读侧故障是两个端点上的 500 problem+json。

## 未能到达（残余盲区）

> 与 [security-audit-2.md](./security-audit-2.md) 的同名小节同步核对过一次：每条按**当前代码与 CI**
> 标为**已闭环**或**仍开放**。已闭环的保留结论，但不再以盲区的身份留在清单里。

**已闭环**

- **Postgres 相关的重现现在都在 CI 里执行**：`test` 作业自带 `postgres:16` service，跑
  `./internal/store/postgres/` 全量、以 `-race -p 1` 跑全套件，并用 `E2E_DATABASE_URL` 再跑一遍
  Playwright（`.github/workflows/ci.yml`）。落盘侧的守卫是 `auditchain_test.go` 的
  `TestAdversarialAuditChainCatchesAWholeLogMetadataStrip`（B3-1）与 `auditread_test.go` 的
  `TestAdversarialAuditNoKeyPageCarriesTheAppliedLimit`（B3-2）。
- **`-race` 未运行**：CI 以 `-race -p 1` 跑整套。C3-3 的结论不依赖竞态检测这一点不变（它是确定性复现），
  但「并发论断没有检测器背书」不再是盲区。
- **`slow_down` / 轮询节流在活路径上不存在**：**已实现**，不再是文档与实现不一致。
  `internal/store/memory/oidc.go` 记录 `lastPoll`，在 `DefaultDevicePollInterval` 之内再次轮询即回
  `slow_down`；`internal/store/postgres/oidc.go` 用 `last_poll` 列做同一件事，由迁移
  `0016_oidc_device_last_poll.sql` 加入。守卫是 `memory/oidc_test.go` 的 `TestDevicePollingIsThrottled`
  与 `postgres/oidc_test.go` 的同名测试，`docs/architecture.md` §4.4 与实现现在一致。
  （库自己的 `CheckDeviceAuthorizationState` 仍不看 `PollInterval`——节流做在 store 层。）

**后来闭环的（本节原先列在「仍开放」）**

- **C3-1 / C3-2 的 Postgres 侧缺守卫**：**已补**。`internal/store/postgres/oidc_test.go` 现在有与内存侧
  同名的两条：`TestDeviceCodeIsSingleUse`（先断言第一次读**确实**交出已批准状态，再断言第二次不再交出）
  与 `TestRevokingAGrantDeletesItsDeviceAuthorization`（用不消费的 `deviceState` 做前置条件，
  撤销后断言该行消失）。两者本地是显式 SKIP，由 CI 的 `postgres:16` service 执行。
- **A3-4 未复现 / 未修**：**第四轮已修**，见上文该条的处置与守卫。
- **库自身的日志（probe 项 5）未审计**：**第四轮已闭环**。它把这条缝当靶子：枚举了
  `zitadel/oidc v3.51.3` 在这些路径上写什么（`pkg/op/error.go` 的 `oidc_error` 带 `description`
  与整条 `parent` 链；`pkg/oidc/authorization.go` 的 `LogValue` 记录 scopes/response_type/client_id/
  redirect_uri，**不**记录 `code_challenge` 与 `state`），并落成守卫
  `TestAdversarialProtocolErrorsDoNotLogCredentials`（把进程默认 slog 换成捕获器）。
  随后又补上成功路径的一半：`TestAdversarialSuccessfulExchangesDoNotLogTokens` 跑完整的
  authorize → 兑换 → userinfo → 刷新，断言**铸出来的** access/refresh/id token 与 `code_verifier`
  都不在日志里——失败路径的守卫看不到"真的发了令牌"这种情形。

**仍开放**

- **`oauth` 遗留引擎的设备决策是丢失更新**（`oauth/device.go` 读整条记录、判定、整条写回，无谓词）：
  读代码成立，但**从 re0auth 装配不可达**（`cmd/re0auth` 只装配 `oauth.TokenAdmins`、
  `oauth.NewMemoryClientRegistry` 与 `oauth.NewClient`；`upstreamkit` 不挂设备端点）。
  它是**公开库**，故对外部使用者是真缺陷——仍是假说，留作独立条目。
  （原文这里写作 `internal/oauth/device.go`，该包并不在 `internal/` 下。）

**两条常驻注意**

- 库日志守卫枚举的是**当前版本**（`zitadel/oidc v3.51.3`）的行为：升级该依赖时，那两个守卫就是检查点——
  若新版本开始把请求体或令牌写进日志，它们会失败。这正是把结论落成守卫而不是散文的用处。
- Postgres 侧的守卫在本地一律显式 SKIP（无 DSN），由 CI 执行；「我机器上能跑」不是证据，反之亦然。

## 判断（文档化决定，不是缺陷）

- **运维 `Detail["actor"]` 里的操作员 `usr_…`**：第二轮已定为有意保留（企业审计合规）。本轮**改变了它的暴露面**——
  `detail` 现在是文档化、可远程读取的契约字段，而 `docs/openapi.yaml` 把它描述成「按约定只装非秘密上下文
  （client id、request id、计数）」。**那句话对每一条 `admin.*` 事件都是假的。** 处置：改那句话，或把 actor
  换成 `lifecycle` 那样的形态（记 `self: true|false` 而非 id）。本轮先记，不顺手改契约。
- **未认证的 `/v1/admin/*` 返回 401 而非 404**：可让探测器得知本部署有运维面。`openapi.yaml` 已文档化该 401，
  且对每个 `/v1/admin/*` 都成立，非审计特有。保持现状。

## 文件与守卫

- 新增守卫：`internal/oidchttp/adversary_test.go`、`internal/httpapi/device_adversary_test.go`；
  扩充：`internal/httpapi/audit_routes_test.go`、`internal/httpapi/plane_test.go`、
  `internal/store/postgres/auditread_test.go`、`internal/store/postgres/auditchain_test.go`。
- 三个对抗子代理创建的临时探针文件（`internal/oidchttp/adversary_device_method_test.go`、
  `internal/httpapi/zz_device_adversary_test.go`）已**删除**，其断言迁移进上面的守卫。
- 改动的生产代码：`internal/oidchttp/oidchttp.go`、`internal/store/memory/oidc.go`、
  `internal/store/postgres/oidc.go`、`internal/store/postgres/auditread.go`、
  `internal/store/postgres/auditchain.go`、`internal/httpapi/audit_routes.go`。
