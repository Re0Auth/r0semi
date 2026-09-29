# 区域 Z07 对抗性复核报告（auth-session-lifecycle）— 第七轮

> 复核对象：`docs/audit-7/findings/Z07-auth-session-lifecycle.md`（下称「原报告」）
> 被复核探针：`internal/zzprobe/audit7/z07authsessionlifecycle/`（未改动一个字节）
> 复核探针（新增，独立夹具）：`internal/zzprobe/audit7/z07verify/authrequest_expiry_test.go`
> HEAD = `bf81b2a`。工作区：**被跟踪文件零修改**（`git status` 只有未跟踪的审计产物）。
> 端口未使用真进程：本区所有结论都能在进程内全接线服务器上给出，且 Z07-1 需要注入时钟，真进程拿不到。

---

## 1. 方法（我实际做了什么）

1. **跑了原报告的全部 28 个探针**（`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z07authsessionlifecycle/...`）：
   实测 **9 红 / 19 绿**，与原报告 §跑了什么 的计数完全一致，**红的测试名与条数逐一对上**。
2. **跑了第六轮遗留探针作为独立夹具/独立证据**（不是转述原报告）：
   - `go test -tags audit6 -run 'TestZZAuditDeviceVerification' -v ./internal/httpapi/` →
     `TestZZAuditDeviceVerificationStoresTheRawRequestString` **PASS**（证明入口点回显原始拼写）；
     `TestZZAuditDeviceVerificationInflatesTheSession` **FAIL**，日志：
     `one 61440-byte navigation -> session blob 184834 bytes`、`after 32 navigations … [1807500]`。
   - `go test -tags audit6 -run TestProbeErasure -v ./internal/zzprobe/audit6/z07authsession/` →
     独立夹具同样红：`the only record of this erasure reports outcome="ok"` /
     `pseudonym_destroyed="true" for a run where the destroy failed` / `no record names the step that failed`。
   - `go test -tags audit6 -run 'TestZZAuditBindAcceptsAnUnboundedID|TestZZAuditEveryRequestRewritesTheWholeSession' -v ./internal/auth/` →
     两条都 PASS：`largest committed session after 3 padded binds: 147950 bytes`、
     `commits: 1 after sign-in, 4 after 3 read-only requests`（每次只读也整份重写会话）。
3. **逐条读了原报告引用的每个 `file:line`**，并顺手核对了它没引的相邻代码（见下）。
4. **自己写了一条独立探针**（`internal/zzprobe/audit7/z07verify/`，自有时钟、自有 client registry、不含原报告夹具任何一行）：
   `TestZ07VerifyExpiredAuthRequestIsStillReadableByID` 实测**红**：
   ```
   AuthRequestByCode refuses the expired code: memory: authorization code is unknown or expired
   AuthRequestByID returned a pending consent handle 31m0s past its 30m0s deadline:
       the by-ID read carries no expiry predicate, so only the periodic sweep ends it
   ```
   同一函数内有阳性对照（TTL 内 by-ID 读成功；`SweepExpired()` 返回值非零才继续），
   所以这不是「store 什么都没干活」的假红。
5. **反空转/假守卫检查**：对原报告 24 条「探过没破的」逐条看了探针是否真的有阳性对照（见 §4）。
6. 复核期间**没有修改任何被跟踪文件**，也没有改被复核者的探针。

---

## 2. 逐条裁定

| 编号 | 裁定 | 修正后严重度 | 一句话 |
|---|---|---|---|
| Z07-1 | **CONFIRMED** | P2 | 机制、两个后端、阳性对照全部独立复现；PG 侧新增铁证（`expires_at` 在 PG 从不出现在任何 WHERE） |
| Z07-2 | **CONFIRMED** | P1 | 独立夹具（第六轮）复现同一红；补充「失败路径连一行 slog 都没有」 |
| Z07-3 | **CONFIRMED（机制有一处写错）** | P2 | 结果成立且被独立夹具量化（1 807 500 B），但「上限是 Go 的 ~1 MB」是错的：产品自设 **64 KiB** |
| Z07-4 | **CONFIRMED** | P3 | 竞态真实；探针阳性对照（`accepted==1`）成立；前端现实路径是读码推论，已如实标注 |
| Z07-5 | **CONFIRMED** | P3 | 查找规范化 / 句柄原样比较，实测两拼写两答案；缺的只是文档里那句注释 |
| Z07-6 | **CONFIRMED（影响机制写错）** | P3 | 403 是真；但前端不是「按 401 判定」而是按 problem code `unauthenticated`；「唯一一个」经全量校验成立 |
| Z07-7 | **CONFIRMED** | P3 | 内存形态端到端复现；生产分支确在删账号前按 subject 撤会话 |
| Z07-8 | **CONFIRMED（影响被夸大）** | P3 | 行为属实，但「对所有外部身份做布尔查询」不成立——必须先能以该身份登录 IdP |
| Z07-9 | **CONFIRMED（源级）** | P3 | `AuthenticatedAt` 全仓唯一执行点是 `admin_routes.go:90`；但「无法被测试证伪」的说法不精确 |

### Z07-1 我独立取得的证据

- 自写探针（store 级，独立于原报告夹具）：`AuthRequestByID` 返回已过期 31 分钟的记录，而
  `AuthRequestByCode` 对同一条记录派生的过期授权码拒绝；`SweepExpired()` 非零 ⇒ 记录**确实**过期。
- 读到原报告**没引**的两处同向证据，它们把这条从「漏了个谓词」升级为「代码自己写下的不变量是假的」：
  - `internal/store/postgres/sweep.go:11-13`：「an expired row is one a lookup already refuses … A lookup
    does refuse these -- the OP checks a token's deadline」；
  - `internal/store/memory/oidc.go:935`：「A lookup already refuses an expired record, but nothing removed it.」
- PG 侧我做了完整 grep（不是抽样）：`oidc_auth_requests` 在该包里只出现在 INSERT（`oidc.go:182`）、
  `WHERE id = $1`（`:212`）、按 id 的 DELETE（`:241`/`:303`）、`UPDATE … auth_time`（`:818`/`:833`）、
  按 subject 的删除/撤销（`:1029-1143`）与 `sweep.go:32`——**`expires_at` 从未进入任何 SELECT 的
  选择列或 WHERE**。原报告「只补了 code 路径、漏了 by-ID 路径」的判断成立。
- 原报告对 G-2/G-7 的归属判断成立：G-2 是 refresh、G-7 是 device_code，本条是 `oidc_auth_requests`
  的 by-ID 读，且它是第五轮 `postgres.md:220` 那句「所有读路径都以『未过期』为放行条件」的**反例**。
  不是重报。

### Z07-2 我独立取得的证据

- 第六轮**另一套夹具**（`internal/zzprobe/audit6/z07authsession/`，与原报告不同）同样红，
  三个断言字符串逐字对得上。
- 补充原报告没写的加重项：`internal/httpapi/account_routes.go:54-65` 的失败分支**没有任何 `slog`**，
  所以运维侧除了那条谎报 `outcome=ok` 的记录之外，**拿不到任何反向信号**——「失败是静默的」这半
  比原报告写得更硬。
- 代码自证：`cmd/re0auth/main.go:650-659` 已在启动期拦住「durable 但没接 Pseudonyms」的**配置**形态，
  说明作者清楚这条不变量的分量；漏的是**接了但 Destroy 运行时失败**的形态。不是有意设计。

### Z07-3 的机制纠错（同一严重度下的实质修正）

- 原报告：「受限的是 Go 的请求行上限 ~1MB，不是产品」。
  **错。** `cmd/re0auth/main.go:119-122` 自设 `maxHeaderBytes = 64 << 10`，`:779` 交给
  `http.Server.MaxHeaderBytes`。产品上限是 **64 KiB**，不是 1 MiB。
- 原报告「未能到达」第 2 条又说该上限「只有库默认值推导」——同样错，它是一个显式常量，且**已被**第六轮
  探针的注释（`zz_audit_device_bloat_test.go:96-98`）正确引用。
- 结论不变：实测 32 次导航把会话堆到 **1 807 500 B ≈ 1.72 MiB**（我亲自跑出的数），
  与「单会话 ~2MB」同量级；原报告探针用的 60 000 B 拼写也确实在 64 KiB 之内。
- **原报告漏引一条既存证据**：`internal/httpapi/zz_audit_device_bloat_test.go`（第六轮，`audit6` 标签）
  做的是**完全同一件事**——真 `httpapi` 入口点、调用方可控字节、32 次导航的体积放大。
  原报告只承认第六轮 `internal/auth/zz_audit_session_test.go::TestZZAuditBindAcceptsAnUnboundedID`
  是「合成证明」，却不知道自己这条其实是**第二次**经真实入口点证明。它仍不违反「不许重报」（该探针
  从未进入 G-1…G-24 / P-01…P-03），但「本条给出的是经真实入口点的可达路径」这句新颖性声明不准确。

### Z07-6 的影响机制纠错

- 行为属实且我复核了「唯一性」：全仓 `ValidCSRF` 的调用点逐个比对，**只有** `session_routes.go:67`
  之前没有 `sessions.User` 检查（`account_routes.go:33/38`、`identity_routes.go:43/48`、
  `grants_routes.go:73/78`、`device_routes.go:90/95`、`authorization_routes.go:128/133`、
  `binding_routes.go:134/139`、`:189/194` 全部是先会话后 CSRF）。所以「本平面唯一一个」成立。
- **但原报告的影响推理错了**：它写「前端按 401 判定，见 `web/src/lib/api.ts` 的 `needsSignIn`」。
  实际 `api.ts:85-87` 的 `needsSignIn` 判的是 **problem code === `unauthenticated`**，不是状态码。
  当前 403 分支的 code 是 `invalid_request`，所以 `needsSignIn=false`；改成会话优先后会返回
  `unauthenticated` ⇒ 结论方向仍成立，但理由不是「401 vs 403」。
- 另外：第五轮 `docs/audit-5/findings/http-edge.md:493` 的 `absent=403` 是**已登录但缺 CSRF 头**，
  不是匿名；所以匿名 403 这条**不是**第五轮「探过没破」的重报。我一开始怀疑是重报，核对了那一段的
  夹具描述（「每个路由一台全新的已登录服务」）后排除。

### Z07-8 影响被夸大（严重度维持 P3）

- 探针红是真的（独立可复现），`auth.go:675-693` 的分支也确实与 login 模式不对称。
- 但原报告的威胁模型站不住：link 流程要求攻击者**在 IdP 上以被探测的那个身份完成一次认证**。
  也就是说「这个外部身份是否已注册」只有**你已经能以它登录**时才能问——而那等于你本来就能进入那个账号。
  「任何持有某个 provider 的一个外部身份 + 任意一个 Re0Auth 账号的人，都能对**所有**外部身份做布尔查询」
  是错的；探针之所以能扮演 `victim`，是因为夹具的 `setIdentity` 能任意指定 subject，真实 IdP 不能。
- 行为本身（login 不说、link 说）仍是真实的实现/契约不一致，且 `identity_taken` 被
  `docs/architecture.md:715` 当作特性记录、并非「已接受的存在性泄露」的裁定。维持 P3，但影响一句必须改。

### Z07-9 的证据等级（源级成立，理由需更正）

- 机制我核过：全仓 `AuthenticatedAt` 的使用只有 `admin_routes.go:90` 一处 enforcement，
  另外两处是 OP 的 `auth_time` 写入（`main.go:1297`）与测试；`DELETE /v1/account`（`account_routes.go:32-41`）
  确实没有窗口检查。`docs/admin.md:22-25` 只把 `reauth_window` 绑在 `[admin]`，没有把自我抹除写成例外。
- 但原报告写「缺失的检查本身无法被测试证伪（没有代码可失败）」**不准确**：一条断言
  `403 reauth_required` 的探针今天就会红。它是**源级 CONFIRMED**（BRIEF §3 第 2 条允许），
  不是「不可测」。这不改变结论，只改变证据等级的表述。
- 与第五轮 RP-9（`docs/audit-5/findings/protocol.md:702`，link 不要求近期认证，HYPOTHESIS）是**同族不同动作**，
  不是重报。

### Z07-7

- 生产分支逐行核对成立：`main.go:924-938` 持久分支 `sessionRevoker: sessions` + `:660-665` 传进
  `lifecycle.Config.Sessions`；`lifecycle.go:220-227` 在 `:253` 删账号行**之前**撤会话。内存分支
  `main.go:875-899` 不设 `sessionRevoker`，原报告描述准确。
- 唯一可挑的措辞：它说生产形态「不可达」。严格说生产仍有窗口——**一个撤会话前已 load 的并发请求**
  仍会走到 `GetUser` → 500。窗口很小，但「不可达」应写成「需要与该账号会话擦除并发的极小窗口，或内存形态」。

---

## 3. 探过但没破的：我的对抗性抽查

我对原报告 24 条逐条读了探针源码，重点找「用桩写成假绿」的三类：

1. **完全用桩替换被测对象**（第六轮汇总 §5 那种 `http.HandlerFunc` 永远 200 的假象）：**没有**。
   Z07 夹具是全接线真 `httpapi.New` + 真 `oidchttp` + 真 `testoidc`，断言都落在产品路由上。
2. **零命中没有阳性对照**：
   - 第 3 条（未认证不发 `csrf_token`）：枚举 9 个端点但**没有**「已认证响应确实含该字段」的对照——
     不过同包 `b.csrf()` 在所有红探针里都依赖该字段存在，所以事实上被反复反证过；不必单列。
   - 第 7 条（匿名不分配会话行）：有对照（`/auth/{p}/start` 必须提交），**成立**。
   - 第 16 条（bearer 不能读身份列表）：有对照（同 jar 的 `/v1/me` 必须 200），且原报告自己记录了
     「第一版带 cookie 全是 200」这个夹具假象，**这是本轮质量最高的一条守卫**。
   - 第 12/24 条（`/bind` 归属）：**只有 B 被拒的 400，没有「A 完成自己的流程」的对照**。
     夹具的上游是永远 404 的桩（`fixture_test.go:195-196`），所以 A 自己走完应当是
     `303 bind_failed` 而不是 400——这条对照是可写的、却被漏了。见 new_findings。
3. **夹具把被测对象替换成永远成功的桩**：未发现。唯一一处「桩」是 federation 上游的 404 服务，
   它是为了证明「归属检查在任何网络调用之前」，用法正确。

**结论**：24 条「探过没破」整体可信，只有第 12/24 条缺一条正向对照。

---

## 4. 新发现（复核期间发现、原报告漏掉）

### NF-Z07-1 `/bind` 归属守卫是**单侧**的：探针只证明「B 被拒」，无法区分「B 被拒」与「所有人被拒」

- 严重度：P3 低/提示（证据质量 / 守卫覆盖）
- 类别：可维护性
- 证据（我读过被复核探针与夹具）：
  - `handle_binding_test.go::TestZ07BindHandleIsOwnedByTheAccountThatStartedIt`（= 原报告守卫第 12 条）
    只调用一次 callback，且**用的是 B 的账号**，断言 `400`。夹具的上游是
    `httptest.NewServer(http.NotFound)`（`fixture_test.go:195-196`），所以：
    - 归属检查**在**：B → 400（探针断言）；
    - 归属检查**被删**：B 会走到 `CompleteBind` → `Exchange` 失败 → `redirectWithError(...,"bind_failed")`
      → **303**（探针会红，说明它不是空探针）；
    - 归属检查**过强（对谁都拒）**：B → 400（探针**照样绿**），而 A 自己的流程也变 400，
      用户再也绑不了任何源——**这个回归探针看不见**。
  - 对照 `TestZ07ConsentHandleCannotBeApprovedByAnotherAccountInTheSameBrowser`（守卫第 10 条）
    就带了「B 自己的句柄 200」这个正向对照；设备流（第 11 条）同样带。
    `/bind` 这条是三个归属守卫里**唯一**没有正向对照的。
- 状态：CONFIRMED（源级 + 夹具级；不需要跑，读完探针与桩即可断定）
- 影响：不是产品漏洞，是**守卫的空洞**。一旦 `OwnerMatches` 或 `Bound` 的调用被改成恒 false
  （例如重构时把 `user` 传成零值），本轮这三条探针里会有一条继续绿，而绑定功能整体失效。
- 修法建议：在该探针里补一步「A 自己用同一 state 打 callback」的对照，断言它**不是 400**
  （夹具下应为 303 `bind_failed`）；`handle_bindings` 的 `OwnerMatches` 恒 false 时它会红。
- 探针：`internal/zzprobe/audit7/z07authsessionlifecycle/handle_binding_test.go::TestZ07BindHandleIsOwnedByTheAccountThatStartedIt`（绿，但单侧）

（我另外核过但没有立成 finding 的两条：`oauth/device.go:479` 那句悬空注释与实现不符——原报告已在 Z07-5
里作为附带项写出；授权码 TTL = `requestTTL`（30 分钟）——`AUDIT-ISSUES.md:379` 已把「授权码生命周期」
收进第五轮「探过但没破」，属不许重报，故不立。）

---

## 5. 判断（不是 finding）

1. **原报告的「未能到达」第 2 条应删掉一半**：`MaxHeaderBytes` 不是「只有库默认值推导」，
   而是 `cmd/re0auth/main.go:122` 的显式常量。这一条把「我查过」写成了「我猜的」，实际可查。
2. **原报告对第六轮遗留探针的清点不全**：它只提到 `internal/auth/zz_audit_session_test.go`，
   漏了 `internal/zzprobe/audit6/z07authsession/erasure_audit_test.go`（Z07-2 的前身）与
   `internal/httpapi/zz_audit_device_bloat_test.go`（Z07-3 的前身，且是真实入口点版本）。
   前两条它算作「独立复现」尚可，第三条被漏掉使「本条给出的是经真实入口点的可达路径」这句显得比实际更新。
   不影响 9 条结论本身（我已用这两套遗留探针做独立证据）。
3. **Z07-2 的 P1 我保留但认为它在边缘**：它需要「Pseudonyms 已接好但运行时 Destroy 失败」这一前提
   （配置没接好会在启动期被 `main.go:650-659` 拒绝）。之所以仍给 P1：不可逆抹除的**唯一**书面凭证被写成
   相反的结论，且失败路径连 slog 都没有，符合 BRIEF「失败是静默的 ⇒ 升」。

---

## 6. 收尾状态

- `go build ./...`：exit 0
- `go vet ./...`：exit 0
- 被跟踪文件零修改（`git diff --name-only` 为空；`git status --porcelain` 只有未跟踪的审计产物）
- 被复核探针零修改
