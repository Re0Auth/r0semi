# 区域 Z07：auth-session-lifecycle（会�?/ 账号 / 身份绑定 / 抹除生命周期）�?第七轮审计报�?
> 审计对象：`C:\git\r0semi`，HEAD = `bf81b2a`（与第六轮同一 commit：第六轮�?G-1…G-24 均未修复，本报告不重报）�?> 工作区：**零个被跟踪文件被修改**（`git diff --name-only` 为空）�?> 探针目录：`internal/zzprobe/audit7/z07authsessionlifecycle/`（全�?`//go:build audit7` + 一�?`//go:build !audit7` �?`doc.go`）�?> 报告文件：`docs/audit-7/findings/Z07-auth-session-lifecycle.md`�?
---

## 范围与方�?
### 读了什�?
- 重点路径：`internal/auth/auth.go`（会话管理器、Bind/OwnerMatches/CSRF/登录面）、`internal/account/account.go`（I-1/I-2/I-3）�?  `internal/lifecycle/lifecycle.go`（抹除链与顺序）、`internal/httpapi/{identity_routes,session_routes,account_routes,idp_routes,device_routes,authorization_routes,binding_routes,federation_routes,grants_routes,export_routes,responses,server,admin_routes}.go`�?  `internal/store/memory/oidc.go`、`internal/store/postgres/{oidc,account,sessions,sweep}.go`、`oauth/device.go`、`internal/oidchttp/oidchttp.go`�?  `cmd/re0auth/{config,main}.go`、`safeurl/safeurl.go`、`web/src/routes/{+page,+layout,consent,device,grants,sources,admin}`�?- 前轮约束：`docs/audit-7/BRIEF.md`、`docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md`、`AUDIT-ISSUES.md`�?  `docs/security-audit-5.md`、`docs/security-audit-2.md`、`docs/security-audit-3.md`�?  `docs/consent-binding-decision.md`（ADR-0004）、`docs/admin.md`、`docs/account-model.md`、`docs/api-design.md`�?- 第六轮遗留探�?`internal/zzprobe/audit6/z07authsession/` �?`internal/auth/zz_audit_session_test.go`（区 07 从未产出报告；下文逐条标注归属）�?
### 跑了什�?
```
go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z07authsessionlifecycle/...
# 28 个探针：9 红（= 本报告的 9 条发现） / 19 绿（右下「探过但没破的」）
gofmt -l internal/zzprobe/audit7/z07authsessionlifecycle/   # 干净
go build ./...                                              # exit 0
go vet ./...                                                # exit 0
```

### 夹具怎么搭的

`fixture_test.go` �?*全接线真实入口点**：`testoidc`（真 RSA 签名、真 discovery/JWKS/token 端点�? `idp.NewRegistry` +
`auth.NewManager/NewHandler` + �?`oidchttp` provider（`memory.OIDCStore`，带可注入时钟与 `RequestTTL`�?
`httpapi.New(Config{...})` + `federation.NewService` + �?`vault`，其登录钩子�?`cmd/re0auth` �?`openOIDC` 同形
（`sessions.Bind(ctx,"authz",id)` + `SetAuthTime`）。探针通过**�?cookie jar �?HTTP 客户�?*打真 `httptest.Server`�?消耗的�?`/auth/*`、`/oauth/*`、`/v1/*` 的产品路由，不调用任何包内未导出函数来取代协议级结论�?
---

## 发现

### Z07-1 pending 同意句柄�?TTL �?*两个后端的读/决策路径上都不裁�?*——只�?15 分钟一轮的 sweep 执行

- 严重度：P2 �?- 类别：安�?/ 正确�?- 不变量：撤销生效（期限裁决必须由被读取的那条记录自己作出，不能挂在后台循环上�?- 证据（红探针 ×2，走�?`httptest.Server`）：
  - `consent_ttl_test.go::TestZ07ExpiredPendingConsentHandleIsStillDescribable`（红�?    ```
    --- FAIL: TestZ07ExpiredPendingConsentHandleIsStillDescribable
        a consent handle 31m0s past its 30m0s deadline is still described as live:
        GET /v1/authorization_requests/{id} = 200 ({"client":{"id":"cli",...},"id":"NVO_�?,"scopes":[…]})
    ```
    同一条探针里�?*阳性对�?*：`opStore.SweepExpired()` 返回非零后同一请求�?404 �?记录确实早已过期，只是没人拦�?  - `consent_ttl_test.go::TestZ07ExpiredPendingConsentHandleIsStillApprovable`（红�?    ```
    --- FAIL: TestZ07ExpiredPendingConsentHandleIsStillApprovable
        a consent handle 1h30m0s past its 30m0s deadline was approved and handed the browser a next URL
        (/oauth/authorize/callback?id=�?
        the stale handle produced an authorization code eyJhbGci�?    ```
    即：过期 90 分钟的句�?�?决策 200 �?跟随后端返回�?`redirect_to` �?OP 铸出真实授权码�?- 机制（读码到行）�?  - 内存后端：`AuthRequestByID`（`internal/store/memory/oidc.go:402-410`�?*不读** `authRequestExpiry`；兄弟方�?    `AuthRequestByCode`（`:418-433`�?*�?*（`!s.now().Before(c.expiresAt)` 即拒）。`CompleteLogin` 也不看期限�?  - Postgres 后端同形：`AuthRequestByID`（`internal/store/postgres/oidc.go:207-213`）只�?`WHERE id = $1`�?    `AuthRequestByCode`（`:220-232`）用 `DELETE �?WHERE code_hash=$1 AND expires_at > $2`，且注释明说
    「It also checks expires_at here �?**the previous query ignored it**」⇒ 这是**只补�?code 路径、漏�?by-ID 路径**�?  - �?决策两条路都走它：`oidchttp.go:1519`（DescribeAuthorization）、`:1542`（ApproveAuthorization）�?  - 期限只由 sweep 执行：`cmd/re0auth/config.go:343`（`authorizationRequestTTL = 30 * time.Minute`）�?    `internal/store/memory/oidc.go:951-956`、`internal/store/postgres/sweep.go:32`、`cmd/re0auth/main.go:405`�?5 分钟一轮）�?    sweep 失败只打日志继续（`main.go:1111`）�?  - **同一份代码的注释已经断言了它没有的性质**：`cmd/re0auth/main.go:1325` 写「The memory store never expires a record on
    its own �?**a lookup refuses an expired one**」；�?auth request 而言这是假的�?- 状态：CONFIRMED（内存后端端到端；Postgres 侧为同构的读码级确证�?- 影响：`RequestTTL` 的承诺（「how long a pending consent handle stays valid」，memory/oidc.go:268）在
  `TTL` �?`TTL+15min` 之间不成立；sweep 停摆（库故障、loop 卡住）时**永不成立**。攻击面有界（要拿到别人�?*会话**才能读它�?  �?handle 同时�?`Bound`+`OwnerMatches` 钉住），但它把「期限」这一类裁决整体交给了后台循环——与 G-2/G-7 同一形状�?  且这次两个后�?*�?*漏了�?- 探针：`consent_ttl_test.go::TestZ07ExpiredPendingConsentHandleIsStillDescribable`（红）�?  `::TestZ07ExpiredPendingConsentHandleIsStillApprovable`（红�?- 修法建议：`AuthRequestByID` 的内存版�?`if expires, ok := s.authRequestExpiry[id]; ok && !s.now().Before(expires) { return nil, �?}`�?  Postgres 版加 `AND expires_at > $2`（`$2 �?s.now()`，遵守单时钟政策，见 P2-32 的处理方式）。`clock_test.go` 补一�?  「过�?auth request �?by-ID 读被拒」�?- 是否与既有编号相关：**�?G-2 / G-7 修复类的补充**（同一「期限裁决落�?sweep 上」家族，但这不是重报：G-2 �?refresh token�?  G-7 �?device_code，本条是 `oidc_auth_requests` �?by-ID 读；Postgres �?`AuthRequestByCode` 已被显式修过�?  说明 code 路径�?by-ID 路径被当成了一回事）�?
### Z07-2 抹除链最后一步失败时�?*审计日志里唯一那条记录谎报成功**，�?500 却承诺「审计记录了失败的那一步�?
- 严重度：P1 高（失败是静默的，且�?*主动写错**的记录，不是缺失�?- 类别：合�?隐私 / 可维护�?- 不变量：fail-closed（不可证明的抹除比失败的抹除更糟——这是本包自己写下的原则�?- 证据（红探针，走�?`DELETE /v1/account`）：
  ```
  --- FAIL: TestZ07ErasureAuditRecordClaimsSuccessWhileTheHistoryStaysLinkable
      the only record of this erasure reports outcome="ok" although the erasure returned an error and the
      account's audit history is still linkable (detail map[�?pseudonym_destroyed:true self:true …])
      the record reports pseudonym_destroyed="true" for a run where the destroy failed
      no record names the step that failed, and the 500 promised the audit log would
  ```
  阳性对�?`erasure_test.go::TestZ07ErasureWithAWorkingDestroyIsRecorded`（绿）：最后一步正常时同字段为
  `outcome=ok` + `pseudonym_destroyed=true` �?上面的红不是「日志什么都没写」造成的�?- 机制（读码到行）：`lifecycle.go:262` 先把 `res.PseudonymDestroyed = d.cfg.Pseudonyms != nil` 置真�?  `:269` �?`account.delete`（`outcome=ok`，detail �?`pseudonym_destroyed=true`）；`:277-283` 才调�?  `Pseudonyms.Destroy`，失败时**�?*返回 error�?*不再写第二条记录**（`d.fail` 没被调用 �?没有 `failed_at`、没�?error 记录）�?  �?HTTP 层的 600/500 文案�?`internal/httpapi/account_routes.go:62`�?  「…and the audit log records the step that failed」—�?*这句话是假的**�?- 状态：CONFIRMED
- 影响：`pseudonym_destroyed=true` 这条不可撤回的记录，恰好坐在「整账号唯一可被读到的那一行」上（该行的假名钥匙还存在，
  所以它仍然可归因到被抹除的账号）。运维读日志会得到「该账号的审计史已不可链接」的结论，而事实相反；GDPR/合规意义上的
  「抹除已证明完成」是错的。方向全部朝向「看起来成功」�?- 探针：`erasure_test.go::TestZ07ErasureAuditRecordClaimsSuccessWhileTheHistoryStaysLinkable`（红�?- 修法建议：`DeleteAccount` �?`:277-283` 的失败分支里补一�?`record(ctx, actor, subject, audit.OutcomeError, res, "pseudonym")`
  （把 `res.PseudonymDestroyed` 先置 false 再写），或把 `account.delete` 的成功记录挪�?`Destroy` 之后
  （代价：记录本身会重新铸钥匙，代码注释已解释为什么不能挪——所�?*应该补第二条**而不是挪第一条）�?- 是否与既有编号相关：第六轮区 07 探针 `internal/zzprobe/audit6/z07authsession/erasure_audit_test.go` 已发现同一形状�?  但区 07 从未产出报告、也未进�?G-1…G-24 / P-01…P-03；本条是**独立复现**（不同夹具、不同断言集合）后正式收录�?
### Z07-3 设备验证页把**调用方可控的 user_code 拼写**原样绑进浏览器会�?�?单会话可被灌�?~540KB，且上限�?32 �?
- 严重度：P2 �?- 类别：性能 / 可用性（资源耗尽�?- 不变量：性能/资源（会话大小必须由服务自己定价，不能由请求行定价）
- 证据（红探针，真 `httptest.Server` + 计数 store）：
  ```
  --- FAIL: TestZ07DeviceVerificationBindsCallerControlledUserCodeBytesIntoTheSession
      baseline session payload after sign-in: 409 bytes
      session payload after 3 crafted verification loads: 540747 bytes (baseline 409)
  ```
  3 个各 60000 字节填充的拼写，全部 `200 {"state":"pending"}`，全部被回显、全部被绑进会话�?- 机制（读码到行）�?  1. 查找时规范化：`oauth/device.go:481-483` `NormalizeUserCode = ToUpper(TrimSpace(s))` �?`-`
     �?**同一�?user code 有无穷多种被接受的拼�?*（`"B" + "-"*60000 + "CDFGHJK"` 归一化为 `BCDFGHJK`）�?  2. 回显的是**调用方输�?*：`internal/store/memory/oidc.go:1364` `UserCode:  userCode`（不�?`d.userCode`）�?  3. 绑定的也是回显值：`internal/httpapi/device_routes.go:69` `s.sessions.Bind(ctx, deviceBindKind, auth.UserCode)`�?  4. `auth.Manager.Bind`（`auth.go:304-330`）只拒绝�?ASCII US �?id，只�?*个数**封顶（`maxBoundHandlesPerKind = 32`），
     **从不限制字节**；每次请求整份会话被重写（`scs` `IdleTimeout>0` �?load �?Modified）�?- 状态：CONFIRMED（内存模式实测；Postgres 侧是同一份共享代�?+ `sessions.data` 落库，属同构�?- 影响：任�?*已登�?*用户访问一�?URL 即可让该会话永久携带 6 万字节级别的键；同一 user code �?32 种拼�?�?  单会�?~2MB（受限的�?Go 的请求行上限 ~1MB，不是产品）。user code 由攻击者匿名自�?  （`POST /oauth/device_authorization`，公开 client 即可），因此把链接递给**已登录的受害�?*点击（顶层导航，Lax cookie
  照发）即可让受害者会话膨胀；会话存储（PG `sessions` 表）与每次请求的整份重写同时被放大�?- 探针：`handle_binding_test.go::TestZ07DeviceVerificationBindsCallerControlledUserCodeBytesIntoTheSession`（红�?- 修法建议：绑定规范化后的值（`Bind(ctx, deviceBindKind, oauth.NormalizeUserCode(userCode))`），并让
  `DescribeDeviceAuthorization` 返回**存储的规范�?*而不是调用方输入；再�?`Bind` �?id 加一个字节上限（例如 64）�?- 是否与既有编号相关：第六轮遗留探�?`internal/auth/zz_audit_session_test.go::TestZZAuditBindAcceptsAnUnboundedID`
  已记录「per-kind cap 只限个数不限字节」（16KB 合成 id），但那条是直接�?`Bind` 的合成证明、且未进入任何已收录编号�?  本条给出的是**经真实入口点、调用方可控字节**的可达路径，以及�?*同一�?* user code 的倍数放大�?
### Z07-4 CSRF 令牌的创建是「后写者赢」的竞态：并发首读者会被发给服务端不认的令�?
- 严重度：P3 �?提示
- 类别：可用�?/ 正确�?- 不变量：fail-closed（写操作必须有可用且唯一�?CSRF 令牌；会话状态写入必须唯一�?- 证据（红探针，真 `httptest.Server` + 每操�?40ms �?store 模拟一次真实库往返）�?  ```
  --- FAIL: TestZ07ConcurrentCSRFTokenCreationHandsOutTokensTheServerWillReject
      4 concurrent first-readers received 4 distinct CSRF tokens
      3 of the 4 distinct tokens handed to the same browser were rejected by the server (only 1 validated)
  ```
  阳性对照内含：raced 之后仍有 1 个令牌被接受（`accepted == 1`），即端点本身正常工作、会话也真的推进了；
  如果 4 个令牌全被接受，探针�?`t.Fatalf` 报「store 没有串行化它们」。所以红只来自「并�?+ 4 个不同结果」�?  （窗口未开时探�?`t.Skipf` 而不是假绿。）
- 机制（读码到行）：`auth.go:238-245` �?`GetString` �?空则 `Put` 的读-�?写，无任何串行化；`scs` 的会话数据在请求结束�?  整份 `Commit`。两个并发请求都看到�?key、各自铸一个令牌、各自提�?�?只有一个进入存储�?- 状态：CONFIRMED
- 影响：窗口是一个存储往返。首发前端会�?*同一页面**并行取两个带 `csrf_token` 的端�?  （`/v1/sessions/current`、`/v1/authorization_requests/{id}`、`/v1/device/verification`），拿到不同令牌时后续写�?403�?  当前前端�?*顺序** `await`（`web/src/routes/+page.svelte:47-51`），consent/device 页各自只读一次，所以现实可达路径是
  同浏览器两个标签页并发首读；缺陷在服务端，属于「下一次前端并行化就会踩到」的地雷�?- 探针：`guards_test.go::TestZ07ConcurrentCSRFTokenCreationHandsOutTokensTheServerWillReject`（红�?- 修法建议：让令牌可由会话自身确定性导出（例如 `HMAC(serverKey, sessionToken)`）而不是随�?+ 存储�?  或在会话存储层对「首次创建」做一�?compare-and-set�?- 是否与既有编号相关：无。第六轮遗留探针 `TestZZAuditCSRFTokenSurvivesSessionRotation` 只记录了「不随会�?id 轮换」，
  没有记录创建竞态�?
### Z07-5 设备决策要求调用�?*原样拼写** user_code，而查找是规范化的 �?同一设备码有两个答案

- 严重度：P3 �?提示
- 类别：可维护�?/ 可用�?- 不变量：账号隔离 / handle 归属校验必须与查找用同一把尺�?- 证据（红探针）：
  ```
  --- FAIL: TestZ07UserCodeSpellingIsNormalisedForTheLookupButNotForTheHandle
      loaded with "rqlr-bfkp", the page echoed user_code="rqlr-bfkp" (the request's spelling, not the stored code "RQLR-BFKP")
      the same device grant answered to two spellings: the page loaded "rqlr-bfkp" as pending, but a decision
      carrying the canonical user_code "RQLR-BFKP" �?the value the device authorization endpoint returned and the
      one RFC 8628 prints �?is 404
  ```
- 机制：查�?`DeviceByUserCode` �?`normalizeUserCode`（`memory/oidc.go:850-852`）；判定�?  `device_routes.go:108-112` �?`Bound/OwnerMatches(kind, body.UserCode)`�?*原样比较**。附带一处文�?实现不一致：
  `oauth/device.go:479` 声称 user code 是「case- **and separator-**insensitive」，实测只有 `-` 被规范化�?  空格/下划线拼写一�?404（探针日�?`normalizeUserCode is hyphen-only …`）�?- 状态：CONFIRMED
- 影响：任何按 RFC 8628 形状实现、把 `POST /oauth/device_authorization` 返回�?`user_code` 回填进决策的客户端，
  会在一个刚刚显示为 pending 的码上得�?`404 unknown or expired user code`；失败方向是安全的（什么都没批准）�?  但「过期」与「拼写不同」被折叠成同一�?404。出�?SPA 恰好使用回显值（`web/src/routes/device/+page.svelte:128`），
  所以这不是线上故障而是一�?API 契约地雷�?- 探针：`handle_binding_test.go::TestZ07UserCodeSpellingIsNormalisedForTheLookupButNotForTheHandle`（红�?- 修法建议：`handleDeviceDecision` �?`body.UserCode` 先做 `oauth.NormalizeUserCode`（或绑定/判定都用规范值）�?  并把 `NormalizeUserCode` 的注释改成事实（只认 `-`）或真的把空白剥掉�?- 是否与既有编号相关：无�?
### Z07-6 `POST /v1/sessions/sign_out` 把「没有会话」答�?403（CSRF），是本平面唯一一�?
- 严重度：P3 �?提示
- 类别：可维护性（错误语义�?- 不变量：两平面分离（业务平面�?401/403 语义�?01 = 未认证，403 = 已认证但被拒�?- 证据（红探针，逐一对齐同一平面上的其它写端点）�?  ```
  --- FAIL: TestZ07SignOutAnswersForbiddenToARequestThatHasNoSession
      sign_out = 403 as expected
      delete_account = 401 / unlink_identity = 401 / revoke_grant = 401 /
      authorization_decision = 401 / device_decision = 401
      POST /v1/sessions/sign_out with no session at all = 403 (CSRF), while every other account write = 401
  ```
- 机制：`session_routes.go:66-70` �?`ValidCSRF` 后（根本不）看会话；其它处理器（`account_routes.go:32-41`�?  `identity_routes.go:42-51`、`grants_routes.go:72-81`、`device_routes.go:89-98`、`authorization_routes.go:127-136`�?  全部先看会话。由�?CSRF 令牌只可能存在于会话里，`want == ""` 必然导致 `false` �?对匿名调用者而言
  **401 分支永远不可�?*�?03 是唯一答案�?- 状态：CONFIRMED
- 影响：客户端的「会话过�?�?跳登录」逻辑（前端按 401 判定，见 `web/src/lib/api.ts` �?`needsSignIn`）在登出这一条上失灵�?  令牌已失效的用户得到的是一�?403，而不是「你未登录」�?- 探针：`session_test.go::TestZ07SignOutAnswersForbiddenToARequestThatHasNoSession`（红�?- 修法建议：与其它写端点同序——先 `sessions.User`�?01；再 `ValidCSRF`�?03�?- 是否与既有编号相关：无�?
### Z07-7 账号行已消失、会话仍在：`/v1/sessions/current` �?`/v1/account/export` �?500 而不是把会话丢掉�?01�?
- 严重度：P3 �?提示（生产组合根会按 subject 撤销会话，故实际只在内存形�?共享代码路径上可达）
- 类别：可用�?/ 正确�?- 不变量：fail-closed（服务自己失效的会话必须表现为「未认证」，不能表现为服务端故障�?- 证据（红探针）：
  ```
  --- FAIL: TestZ07ErasureFailureLeavesTheOtherSessionAnswering500
      the response does not report SessionScoped=false: �?SessionScoped":false,"PseudonymDestroyed":false�?      GET /v1/sessions/current from a session whose account row is gone = 500
      GET /v1/account/export     from a session whose account row is gone = 500
  ```
  阳性对照：同一探针里第一个浏览器（执行抹除的那个）的会话�?`EndSession` 正常销毁�?- 机制：内存形�?`lifecycle.Config.Sessions == nil`（`cmd/re0auth/main.go:875-899` �?`cfg.DatabaseURL == ""` 分支�?  `sessions: nil` 且不�?`sessionRevoker`；对�?`:924-938` 的持久分支设�?`sessionRevoker: sessions`），
  于是抹除只删账号行、不撤会话（`Result.SessionScoped=false` 如实报告了这一点，�?`lifecycle.go:220-227`）�?  之后 `handleCurrentSession`（`session_routes.go:27-31`）与 `handleExportAccount`（`export_routes.go:64-68`）把
  `account.ErrNotFound` 当作 `internal_error` 500�?- 状态：CONFIRMED（内存形态端到端；生产形态下不可达，因为 `RevokeSubjectSessions` 在账号行之前执行�?- 影响：抹除失�?内存部署后，受害者浏览器保持一个指向不存在账号的会话，UI 得到 500 而不是被登出�?  写端点会返回 404/403 而非 401，语义不一致�?- 探针：`erasure_test.go::TestZ07ErasureFailureLeavesTheOtherSessionAnswering500`（红�?- 修法建议：这两个处理器把 `account.ErrNotFound` 映射为「销毁会�?+ 401 unauthenticated」；
  或在会话中间件里做一次「账号存在性」校验（成本高，上面这条更小）�?- 是否与既有编号相关：无（`docs/api-design.md:310` 只解释了 `session_scoped` 布尔为何存在，未涉及本形状）�?
### Z07-8 link 流程�?`?error=identity_taken` 确认「这个外部身份是否已�?Re0Auth 账号�?
- 严重度：P3 �?提示
- 类别：安全（存在性枚举）
- 不变量：账号隔离 / 错误信息不得成为存在性预言�?- 证据（红探针）：
  ```
  --- FAIL: TestZ07LinkFlowConfirmsWhetherAnExternalIdentityAlreadyHasAnAccount
      link callback for an already-linked identity redirected to "/?error=identity_taken"
      linking a fresh identity succeeded (redirect "/")   �?阳性对�?  ```
- 机制：`auth.go:675-693` �?`mode=link` 时把 `account.ErrIdentityTaken`（I-3）折�?  `codeIdentityTaken` �?`?error=` 回跳。登录模式对同一事实**不泄�?*：未知身份就建号，两条分支都以同一�?303 结束�?- 状态：CONFIRMED
- 影响：任何持有某个已配置 provider 的一个外部身�?+ 任意一�?Re0Auth 账号的人，都能对所有外部身份做
  「是否已注册」的布尔查询。代价是一次登录，收益是账号存在性�?- 探针：`identity_test.go::TestZ07LinkFlowConfirmsWhetherAnExternalIdentityAlreadyHasAnAccount`（红�?- 修法建议：把「已被他人占用」与「链接失败」合并成同一个回跳码（前端文案本来就是同一句「请先登录那个账号解绑」，
  `web/src/routes/+page.svelte` �?`identity_taken` 只用于解释），或�?provider 侧限速�?  **这是一次裁�?*：`identity_taken` 是已文档化的 SPA 契约（`docs/account-model.md` 的登录失败码表）�?  若维持契约，则应把本条按「有意接受的存在性泄露」登记到决定文档里�?- 是否与既有编号相关：无�?
### Z07-9 不可逆的账号抹除**不要求近期重新认�?*，而同一份代码对可逆的管理面写操作要求

- 严重度：P3 �?提示
- 类别：安�?/ 合规/隐私（纵深防御）
- 不变量：fail-closed（不可撤销的动作应采用本服务已经实现的 step-up 机制�?- 证据（读码到�?+ 对照）：
  - `internal/httpapi/account_routes.go:32-41`：`DELETE /v1/account` 只检�?`sessions.User` + `ValidCSRF`�?    **没有任何 `AuthenticatedAt` 检�?*，尽管抹除是全局唯一一个「不可撤销、无回滚、且没有任何服务端恢复路径」的动作�?  - 同一份代�?*已经实现**了该机制：`internal/httpapi/admin_routes.go:77-97` `requireAdminWrite` �?CSRF 之后
    追加 `if s.adminReauth > 0 { at, ok := s.sessions.AuthenticatedAt(...); if !ok || time.Since(at) > s.adminReauth { 403 reauth_required } }`�?    注释写明「Step-up by re-login �?the strongest available bound on a stolen or long-idle operator session」�?  - 该策略文档化�?`docs/admin.md:22`（`[admin].reauth_window`，默�?15 分钟），**没有任何文档把自我抹除列为例�?*�?  - 缺失的检查本身无法被测试证伪（没有代码可失败），故本条为源级结论；反向对照是上面�?`requireAdminWrite`�?- 状态：CONFIRMED（源级）
- 影响：会话被盗（或被共享机器上的人取�?CSRF 令牌）后，攻击者可以永久摧毁该账号；而同一攻击�?*不能**在没有近期登录的
  情况下暂停一�?OAuth 客户端。危害次序被倒置�?- 探针：无红探针（源级）；`session_test.go::TestZ07SignOutAnswersForbiddenToARequestThatHasNoSession` 顺带固定�?  抹除端点�?401/403 形态�?- 修法建议：给 `handleDeleteAccount` 加与 `requireAdminWrite` 同形�?`AuthenticatedAt` 窗口检查，
  失败返回 `403 reauth_required`（problemTitles 已收录该码）；窗口取 `server.cookie_secure` 之外的新配置项或复用
  `[admin].reauth_window` 的取值�?*这是一次裁�?*：会改变自我抹除的交互（需重新登录一次）�?- 是否与既有编号相关：无（第五�?HE-8/AUDIT-ISSUES.md:262 讨论的是同意页展示，不是抹除�?step-up）�?
---

## 探过但没破的（也应变成守卫）

每条：攻击形�?+ 探针�?+ 为什么守住�?
1. **会话 cookie 属性（Secure/HttpOnly/SameSite/Path/Domain/名称�?* �?   `session_test.go::TestZ07SessionCookieShapeOverARealServer`（绿）。两种部署形态都实测：`__Host-r0semi_session`
   （Secure=true）与 `r0semi_session`（Secure=false）均�?`HttpOnly`、`SameSite=Lax`、`Path=/`�?*�?Domain**
   （Domain 会毁�?`__Host-`）。`server.issuer` �?https �?`cookie_secure=false` 会在启动时拒�?   （`cmd/re0auth/config.go:488-492`）。`CookieName` 可自定义�?*没有配置�?*（`cmd/re0auth` 从不设置它）�?   所以「运维自定义名字静默丢掉 `__Host-` 前缀」这条不成立�?2. **会话固定（登录前�?session id�?* �?`TestZ07SessionIdRotationOnSignIn`（绿）。登录前 id �?登录�?id�?   且旧值在另一�?jar 里重�?`/v1/sessions/current` = 401（`scs.RenewToken` 删旧行）�?3. **CSRF 令牌固定（fixation�?* �?`TestZ07NoCSRFTokenIsHandedOutBeforeSignIn`（绿）。逐个枚举 9 个端点，
   任何未认证响应都不含 `csrf_token`；令牌只在会话内生成。配合上面第 2 条，固定需要先拿到受害者的会话 cookie�?   而登录会把它换掉�?4. **CSRF 令牌不是账号属�?* �?`TestZ07CSRFTokenIsNotBoundToTheAccount`（绿）。A 登录时铸的令牌在 B 接手的同一浏览�?   会话里仍有效（`RenewToken` 保留会话值），但 A 持有�?cookie 已死，且 `X-CSRF-Token` 是自定义头、协议面不发任何
   CORS 头（ADR-0011），攻击者无法让 B 的浏览器替他发送。作为记录保留�?5. **登出后令牌重�?* �?`TestZ07CSRFTokenIsRebornWithANewSession`（绿）。登出→再登录后令牌不同，旧�?403�?6. **所有写端点在缺 CSRF 头时一�?fail-closed** �?`TestZ07UnsafeMethodsAreRefusedWithoutTheCSRFHeader`（绿）�?   8 个写端点（sign_out / delete_account / unlink_identity / revoke_grant / unbind / cascade_revocation /
   authorization decision / device decision）全�?403，且会话与账号状态未被改动�?7. **匿名流量不会为公用路由分配服务端会话�?* �?`TestZ07AnonymousTrafficDoesNotAllocateServerSideSessionRows`（绿）�?   `/v1/idp/providers`、`/.well-known/openid-configuration`、`/healthz` 三次匿名读提�?0 行；阳性对�?   `/auth/{p}/start` 确实提交（需要服务端 flow state）⇒ 这不是计�?store 没接上的假绿�?   `sessions.SweepExpired` 也顺带清�?`session_subjects` 孤儿行（`internal/store/postgres/sessions.go:143-160`）�?8. **登出是服务端删除，不只是过期 Set-Cookie** �?`TestZ07SignOutIsAServerSideDeleteNotJustAnExpiredCookie`（绿）�?9. **登出不撤销已签发的 OP 令牌（有意的边界�?* �?`TestZ07SignOutLeavesTheIssuedTokensAlive`（绿）�?   全流程铸�?access token �?`/v1/me` 200 �?登出 �?`/v1/grants` 401 �?`/v1/me` �?200�?   这与 `docs/account-model.md:107`（「登出＝�?Cookie、失效服务端会话」）一致，撤销是显式的
   `DELETE /v1/grants/{client_id}`�?10. **同意句柄不能被同一浏览器的另一个账号批准（ADR-0004�?* �?    `TestZ07ConsentHandleCannotBeApprovedByAnotherAccountInTheSameBrowser`（绿）。A 起授�?�?同浏览器 B 登录
    （不登出）→ B �?�?A 的句柄均 404；阳性对�?B 自己的句�?200。`OwnerMatches` 的空 owner 分支
    仍按 ADR §2 允许「谁先登录谁拥有」�?11. **设备句柄不能被同一浏览器的另一个账号批�?* �?    `TestZ07DeviceDecisionIsRefusedForAHandleBoundToAnotherAccount`（绿）。同上，�?B 自己的码可用�?12. **`/bind` 上游绑定句柄的归属校�?* �?`TestZ07BindHandleIsOwnedByTheAccountThatStartedIt`（绿）�?    B �?A �?state �?`/auth/upstream/phigros/fake/callback` �?400（该检查发生在任何网络调用之前�?    所以无需可达上游）。这正是 `docs/security-audit-2.md:180` 那条旧缺口（�?`OwnerMatches`）修好后的守卫�?13. **抹除是幂等且可并发的** �?`erasure_test.go::TestZ07ConcurrentErasuresOfOneAccountAreBothRecorded`（绿）�?    两个会话同时抹除：都拿到 200（每步幂等），审计里两条 `account.delete` 都带正确 subject，账号最终不存在�?14. **抹除成功后不残留可归因的假名** �?`TestZ07ErasureWithAWorkingDestroyIsRecorded`（绿，阳性对照）�?15. **同意句柄一次�?* �?`guards_test.go::TestZ07ConsentHandleIsSingleUse`（绿）。批准后 describe/approve/deny 全部
    �?200（`Unbind` + 存储侧认领即删除）�?16. **身份列表/授权视图/绑定视图�?bearer 令牌不可�?* �?`identity_test.go::TestZ07IdentityListIsSessionScoped`（绿）�?    **用无 cookie 的新 jar** 持真 access token：`/v1/me` 200（证明令牌本身可用）�?    `/v1/identities`、`/v1/grants`、`/v1/bindings`、`/v1/sessions/current` 全部�?200�?    （第一版探针带 cookie，全�?200 —�?那正是「零命中必须有阳性对照」要排除的夹具假象。）
17. **解绑他人身份�?404 而不�?403** �?`TestZ07UnlinkAnotherAccountsIdentityIsNotFound`（绿）�?    内存 `account.go:203-206`、PG `store/postgres/account.go:162-165` 都在存储内比�?owner�?    且事后受害者身份仍在�?18. **解绑最后一个身份被拒（I-2�?* �?`TestZ07UnlinkingTheLastIdentityIsRefused`（绿�?09）且身份未被删除�?    PG 侧用 `SELECT �?FOR UPDATE` 锁用户行后再 count（`store/postgres/account.go:153-176`），并发双删不会�?    账号变成零身份�?19. **导出不可缓存、不可被框、无凭据** �?`guards_test.go::TestZ07ExportIsPersonalAndUncacheable`（绿）�?    `Cache-Control: no-store`、`X-Frame-Options: DENY`、JSON、无 `access_token`/`refresh_token`/`client_secret`/`stoken`�?    无会�?�?401。（跨站顶层导航确实会带 Lax cookie，但响应无法跨源读取，且不可框。）
20. **`safeurl.RelativePath` 不接受跨源回�?* �?读码 + `safeurl/safeurl_test.go` 已有覆盖�?    `//host`、`\`、控制字节、空值全部折�?`/`；`%2F%2F` 不会被当�?authority�?    `/auth/{p}/start` �?`/bind` �?`return_to` 都过它（`auth.go:599`、`federation_routes.go:354`）�?21. **登录面的 state 一次性且单槽** �?第六轮遗留探针（`internal/auth/zz_audit_session_test.go`�?
    `docs/consent-binding-decision.md`：第二次 start 覆盖第一�?state；带 `?error=` 的回调也�?`clearFlow`
    （`auth.go:640`），重放�?400。本轮的�?绿探针在真实的「同浏览器换账号」流程里依赖同一性质
    （`TestZ07ConsentHandleCannotBeApprovedByAnotherAccountInTheSameBrowser` 的第二次登录必经 `clearFlow`）�?22. **设备 user_code 熵足�?* �?`oauth/device.go:28-31`�? �?× 20 字母表（去元音）= 20^8 �?2.56×10^10�?    �?`freeUserCode` 拒绝与现存码碰撞（`oauth/device.go:432-440`）。不存在可暴破的用户码空间�?23. **登录面无本地口令 �?无本地暴力破解面** �?认证完全委派给外�?IdP（`docs/account-model.md`），
    全仓没有口令校验路径；唯一的「猜」面�?device user_code（见上）与协议明文常量�?24. **上游绑定回调�?`state` 而非 CSRF 令牌是正确的形状** �?`federation_routes.go:369-392`�?    `state == "" || !Bound || !OwnerMatches` 三者任一失败都回同一�?400 文案�?    无法区分「不存在」与「不归你」，符合 ADR-0004 §2 �?404/400 的要求�?
---

## 未能到达（残余盲区）

1. **Postgres 运行时语�?*：本机无 Docker、无本地 Postgres，`TEST_DATABASE_URL` 不可能设置。因�?Z07-1 �?PG 侧�?   Z07-3 �?PG 侧（`sessions.data` 落库体积、`oidc_devices`）、Z07-7 的生产形态、以�?   `Sessions.SweepExpired` �?`session_subjects` 孤儿行的实际清扫，全部只�?*读码�?*证据�?   权威验证位是 CI �?`postgres:16`。需要什么：`TEST_DATABASE_URL` + 一�?add �?`internal/store/postgres` �?   `-tags audit7` 测试�?2. **真进程黑盒（`go build ./cmd/re0auth` + 内存模式 + 端口 17701/17751�?* 本轮**未使�?*�?   本区全部结论都能�?`httpapi` 全接�?`httptest.Server`（同一�?`Server.Handler()` 中间件链）在进程内给出，
   且进程外探测无法注入 `RequestTTL`/时钟，反而拿不到 Z07-1 的证据。这构成本轮的覆盖缺口：
   **HTTP 服务器自身的行为**（`MaxHeaderBytes` �?Z07-3 的真实上限、`Server` 连接层）只有库默认值推导�?3. **`scs` 在真 PG store 下的会话提交/读取并发**：Z07-4 用注入的 40ms store 模拟了一次库往返；
   真实 pgx 往返的窗口大小未测量（不引用墙钟，因为多代理并行）�?4. **前端浏览�?e2e**：Playwright 浏览器未安装。Z07-4 的「现实可达路径＝两个标签页并发首读」是**读前端源�?*的推�?   （`web/src/routes/+page.svelte:47-51` 顺序 await、consent/device 页各自只读一次），未在真浏览器里复现�?5. **`identity_taken` 的跨 provider 一致性与限�?*：`/auth/{p}/callback` 是否真被 limiter 分桶到同一 key�?   以及�?provider 下枚举是否需要多个外部身份，未做真进程测量�?6. **`AdminReauthWindow` 的运行时形�?*（Z07-9 假想的修法）：`cmd/re0auth` 默认�?15 分钟、以�?   `AuthenticatedAt` 在会话被 `RenewToken` 后是否被意外刷新，只做了读码（`auth.go:165` �?SignIn 里写 auth_time�?   `RenewToken` 在之后，�?auth_time 不被刷新——但未跑�?flag 组合）�?
---

## 判断（文档化决定可否质疑，不�?finding�?
1. **「登出不撤销令牌」是有意且已文档化的**（`docs/account-model.md:107`）：登出＝销毁浏览器会话�?   撤销�?`DELETE /v1/grants/{client_id}` / `DELETE /v1/account`。我复核过它确实如此（第 9 条守卫）�?   值得质疑的是**文案**：账号页的「退出登录」按钮与「撤销访问」是两个动作，但用户对「退出登录」的直觉�?   「哪都登出了」。建议在前端加一句提示，而不是改语义�?2. **「同一浏览器不登出就换账号 �?句柄跟着会话走」是 ADR-0004 明确接受的低危归属错�?*
   （`docs/consent-binding-decision.md:20-24` �?§3 逐条解释了为什么不选另外两条路）。本轮实测的�?*修好之后**的形态：
   只有 `owner == ""`（匿名创建的句柄）才允许「谁先登录谁拥有」。不得作�?finding�?3. **「抹除失败后无法从端点重试」是写在代码注释里的已知限制**（`lifecycle.go:186-193`、`account_routes.go:56-61`）：
   �?4 步撤销会话之后，会话作用域的端点再也无法重试。我认同这个折中（诚实的失败优于假装可重试）�?   但认为它应该写进 `docs/`（目前只在代码注释里），否则运维 runbook 无法预知「operator 必须手工收尾」�?4. **`account.delete` �?`self` 字段在所有可达路径上恒为 true**（`account_routes.go:54` �?`actor = user`），
   即它区分不了「本人抹除」与「替他人抹除」，而当�?*没有任何**替他人抹除的入口（`admin` 面只�?Kill Switch，不抹除）�?   这是一个「日志承诺了一件不可能发生的事」的形状：既然设计上�?actor 记成 shape 而不�?identity
   （`lifecycle.go:295-303` 明确说明），那么 `self` 恒真就是冗余而非缺陷。若将来加入 operator 抹除�?   必须同时想清�?actor 如何被记录�?5. **`recordUnlinkAudit` 的审计写失败降级为日志、响应仍�?204**（`identity_routes.go:76-91`）�?   �?`admin.record`、`auth.recordAudit`、抹除的 `audit` 一路是同一策略（「不可逆的事才 gate 在审计上」）�?   我认为对身份解绑是对的：身份已经没了，用 500 谎报失败更糟�?6. **`SameSite=Lax` 而非 `Strict`**：Lax 允许跨站顶层 GET �?cookie，这�?   `/auth/{p}/start`（启动一次登录）�?`/v1/account/export`（下载自己的数据）都成立�?   前者是登录 CSRF 的入口、后者是被框�?不可读的 JSON + `Content-Disposition: attachment`�?   在「自定义�?+ �?CORS」的体系�?Lax 足够；`Strict` 会破坏「从外部链接回到应用仍保持登录」。这是记录，不是异议�?7. **内存模式不撤销会话（`SessionScoped=false`�?*：`Result` 如实报告了缺口而不是折进一�?0�?   �?BRIEF 明确「内存模式不承担生产保证」。Z07-7 之所以仍然收录，是因为它暴露的是**共享代码**�?   「账号不存在 �?500」的错误映射，而不是内存模式的存储保证�?8. **`docs/security-audit-5.md:256` 的「匿�?`/oauth/authorize` 每次分配一�?pending 请求（TTL 30 分钟）�?   这条已被裁定为有�?*（峰�?= 到达�?× TTL）。我同意 TTL 给出上界，但 Z07-1 说明这个上界�?   by-ID 读路径上并不存在（sweep 停摆时无界），所以「有界」这一结论依赖 sweep 持续成功——建议把这条裁定
   补上一句依赖条件。这不算 finding，只是对既有裁定的限定�?