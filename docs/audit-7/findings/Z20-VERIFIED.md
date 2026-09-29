# 区域 20 对抗式复核：授权隔离矩阵 — 第七轮复核报告

> 复核对象：`docs/audit-7/findings/Z20-authz-isolation-matrix.md`（Z20-1…Z20-6）。
> 立场：**证伪优先**，逐条自己跑、自己读行。未改被审探针
> `internal/zzprobe/audit7/z20authzisolationmatrix/`，未改任何被跟踪文件。
> 新增探针：`internal/zzprobe/audit7/z20verify/z20adversarial_test.go`（`//go:build audit7`）。
> 注：同目录另有一次并发独立复核留下的夹具与探针（我**重跑**并引用其红/绿结论），我的新增探针与它同包、符号不冲突。

## 范围与方法

- 复跑被审探针 `go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z20authzisolationmatrix/...`
  → **4 红 / 6 绿**（红＝Z20-1/2/3/5），与报告一致；逐条读失败文本，机制与报告声称**逐字对上**，非 setup error。
- 逐行核 `file:line`：`memory/oidc.go:418-467,1055-1060,1086-1127,1381-1406`、
  `postgres/oidc.go:240-249,287-311,873-900,1187-1224`、`httpapi/federation_routes.go:105-122,212-265`、
  `httpapi/device_routes.go:108-115`、`oidchttp/oidchttp.go:655,1107-1122,1189-1194,1208-1234,1538-1622`、
  `federation/service.go:384-410,505-535`、库 `zitadel/oidc@v3.51.3/pkg/op/token.go:50`（GOMODCACHE 实读）。
- 独立探针 `go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z20verify/...` →
  `TestZ20AdvDeviceDenialAuditDropsTheSubject`（新，红）、`TestZ20AdvRawEscapeIsRefusedWith400AndNoUpstreamCall`（新，绿），
  加上并发复核的两条红（profile-only 任意原生路径、直呼 `ApproveDevice`）与一组绿（同一上游端点、双源闸门、转义内省阳性对照）。
- `go build ./...`、`go vet ./...`：见最终回复（exit 0）；`gofmt -l` 对新文件干净。

## 裁定

| ID | 裁定 | 修正后严重度 | 理由（我自己的证据） |
|---|---|---|---|
| Z20-1 | **CONFIRMED** | P2 | 逐步隔离：authorize/approve/callback 后 deny=0，**只有** `/oauth/token` 兑换后 +1 且 subject/client_id 全空；调用点唯一（库 `token.go:50`） |
| Z20-2 | **DOWNGRADED** | P2 → **P3** | 机制成立且影响比报告更宽，但闸门粗粒度是**已文档化的已知处**（`docs/architecture.md:468`），报告的「文档未声明」判断是错的 |
| Z20-3 | **CONFIRMED** | P3 | memory:1104 只有 client_id；postgres:898 连 client_id 都空；交互面 approve 带 scopes（阳性对照） |
| Z20-4 | **CONFIRMED** | P3 | 反驳成立：路由入口就是 `DecideDeviceAuthorization`，闸门 `87f4ad9`（2026-09-23）**早于第六轮**⇒ P-02 是真错 |
| Z20-5 | **REFUTED** | P3（属 G-8，非新条） | G-8 的**红探针本体**就是打在部署 OP 上，匿名公开 client 形态也已覆盖；「部署面从未被记」不成立 |
| Z20-6 | **CONFIRMED** | P3 | 反驳成立，并已补阳性对照：白名单机密客户端明文拿到 `active:true`，`co%6ef` 只拿到 `{"active":false}` |

### Z20-1（CONFIRMED, P2）
`git show 636a074` 确认 AUD-3 引入：`DeleteAuthRequest` 由 `_ context.Context` 改为读
`subject/clientID` 并无条件 `recordConsent(...deny)`（`memory:449-467`）；postgres 同形（`:287-311`）。
库铸完令牌才调它（`token.go:50`），而 `AuthRequestByCode` 已删行（`memory:418-433`；postgres
`DELETE…RETURNING :240-249`）⇒ 字段空。红文本
`a SUCCESSFUL code exchange recorded oidc.consent.deny: subject="" detail=map[client_id:]` 与报告一致，
且真拒绝对照绿、带 `client_id` ⇒ 探针非空转。
**重报检查**：`_audit/protocol.md` 只有 P-01…P-03；`docs/audit-6/findings/00-…CONSOLIDATED.md`
G-1…G-24 无此条。工作区那条 audit6 探针自标 `01-2`，但第六轮 HEAD 上该事件尚不存在 ⇒ 原报告
provenance 说明属实，**不重报**。P2 维持（审计「拒绝」流被 1:1 污染，无提权，处 P2/P1 边界）。

### Z20-2（CONFIRMED 机制 / **DOWNGRADED P3**）
机制复核：`sourceScopes`（取该源全部资源 scope，`federation_routes.go:223-236`）+ `hasAnyScope`（`:260`）
是源级粗闸门；归一路径逐资源要求（`:110-122`）。并发复核的独立观测更宽：profile-only 令牌打通
**任意原生路径** `/admin/wipe`（`z20verify_test.go::TestZ20VProfileOnlyTokenReachesAnyNativePath` 红，
上游真收到 `/admin/wipe`），且两入口在 `raw_base=issuer` 下确实同打 `/resources/scores`。
**但**：`docs/architecture.md:468` 白纸黑字——「已知粗粒度处：raw 的 scope 门禁用的是"该源任一资源 scope"，
专用 `<game>.raw.read` 为后续工作。」代码注释同义（`federation_routes.go:221-222`）。原报告称
"文档只说鉴权/转发/限流/provenance，未声明源级闸门"**与 architecture.md:468 冲突**。按简报 §5/§7，
这应写成「判断」+ 补文档，而非 P2 新洞 ⇒ 降 P3。
另一处证据偏差：报告的「同一 URL」依赖**夹具自选** `raw_base=issuer`（`fixture_test.go:159-164`），
出厂示例是 `raw_base=issuer+"/v1"`（`config/re0auth.example.toml:355,363`；报告引的 `:365` 是
`cascade_revocation` 注释，引错行）。机制不受影响（见任意路径证据）。

### Z20-3（CONFIRMED, P3）
`memory:1104` 仅 `record(..., d.clientID)`；交互面 `recordConsent` 记 `scopes`（`:1058-1060`）。
红文本 `detail=map[client_id:cli]`。复核补全：postgres `ApproveDevice:898` 记 `record(..., subject, "", ...)`，
连 `client_id` 都空（G-17）。与 G-17 不同字段，非重报。P3。

### Z20-4（CONFIRMED, P3）
两后端都在 Resolve 后调 `RequireExplicitConsent`（`memory:1397-1406`、`postgres:1217`），
路由 `device_routes.go:114` 走的正是 `DecideDeviceAuthorization`；绿探针有真目录（含 ExplicitConsent）
与带 tick/不带 tick 双对照。`git log -S` 显示闸门自 `87f4ad9`（2026-09-23）就在，**早于第六轮**
⇒ P-02 是读了错误的函数，反驳比报告说的更硬。残余见新发现 Z20V-2。P3。

### Z20-5（**REFUTED**；更正归属 G-8）
机制我核过且成立（`memory.RevokeToken:619-621,649-655` 对外来活令牌 `ErrInvalidClient`，未知串 200）。
但原报告的核心新意「此前只记在公开引擎，部署面从未被记」**为假**：G-8 的红探针
`internal/zzprobe/audit6/z02protocoltoken/revoke_test.go::TestZ02RevocationDistinguishesForeignLiveTokensFromUnknownOnes`
的夹具就是 `oidchttp.New`+`memory.NewOIDCStore`+`httptest`（`z02protocoltoken/fixture_test.go:186-202`），
即部署 OP 的 `/oauth/revoke`，且 `:62-80` 正是「公开 client id、纯 form、无 Basic」的匿名二值判定。
唯一有效成分是更正 G-8 的**散文**影响段（它把影响面写成 Kit 引擎，与自己的探针不符）——那应记在
G-8 名下，不是新 P3。按简报 §4.4 属更正，但按 §3「不算重报」只对**显式标注**的补充/反驳成立；
此处「补充」的事实前提被证伪 ⇒ **REFUTED**。

### Z20-6（CONFIRMED, P3）
守卫读原始 Basic 字节（`oidchttp.go:1107-1122`），`filterIntrospection` 的 caller 也来自
`callerClientID`（`:1189-1194`，调用点 `:655`），命中条件 `tokenClient==caller || clients[caller]`（`:1230`）
两处都按原始字节 ⇒ 转义拼写永远给 `{"active":false}`。并发复核的阳性对照（我重跑）：
白名单**机密**客户端明文 → `200 {"active":true,...,"client_id":"cli"}`；同身份 `co%6ef` → `{"active":false}`。
P-01 正文称 `:1230` 用的是已解码 caller，与源码不符——影响段建立在对自身的误读上。P3 维持。

## 新发现（复核代理独立提出）

### Z20V-1 设备**拒绝**审计丢掉 store 已拿到的账号（两后端）
- 严重度 P3 ｜ 类别 合规/隐私（审计完整性）｜ 不变量 审计忠实/fail-closed
- 证据（实跑，红）：`z20verify/z20adversarial_test.go::TestZ20AdvDeviceDenialAuditDropsTheSubject`
  ```
  device deny event: subject="" detail=map[client_id:cli] outcome=denied
  ```
  同探针阳性对照：同一 store、同一路径的**批准**分支记到 `subject="usr_v"` ⇒ sink 与路径都能带 subject，
  是拒绝分支丢的。机制：路由把 `string(user)` 交给 `DecideDeviceAuthorization`
  （`httpapi/device_routes.go:114-115`），但拒绝分支 `:1381-1382` 只把 `userCode` 转给 `DenyDevice`
  （`memory:1112-1127`，签名无 subject）；postgres 同形（`postgres:1195-1196 → 908-921`，client_id 也空，属 G-17）。
- 影响：`oidc.device.deny` 答不出「谁拒绝的」。交互面同病（`DenyAuthorization:1620` 走 `DeleteAuthRequest`
  读 `a.Subject`，而登录钩子 `cmd/re0auth/main.go:1292-1303` 只 `SetAuthTime`、不设 subject）——
  两条拒绝流共同的缺，但设备面尤其可惜：路由手里就有账号。
- 修法：`DenyDevice(ctx, userCode, subject)`；交互面把会话账号一并交给 store。
- 相关：Z20-3 同族、G-17 同族。探针红。

### Z20V-2 导出的 `ApproveDevice` 不过 ExplicitConsent 闸门（Z20-4 反驳的残余）
- 严重度 P3 ｜ 类别 可维护性/纵深防御 ｜ 不变量 token/scope 签发、fail-closed
- 证据：`memory:1086-1106`、`postgres:873-900` 都不碰 registry；闸门只在 `DecideDeviceAuthorization`。
  `httpapi.DeviceStore` 缝只暴露 `Describe/Decide`（`server.go:184-186`），故今天无路由可达；但它是导出方法。
  并发复核探针（我重跑，红）：`z20verify_test.go::TestZ20VDirectApproveDeviceSkipsExplicitConsent`
  ——控制段 `DecideDeviceAuthorization` 无 tick → `access_denied`，随后直呼 `ApproveDevice` 无 tick → `nil`。
- 修法：把 `RequireExplicitConsent` 收进 `ApproveDevice`，或降为非导出、由 `DecideDeviceAuthorization` 独占。
- 相关：Z20-4 补充；P-02 字面指向的正是这个方法（位置对、身份错）。

### Z20V-3 被审报告两条「探过没破」守卫偏弱（假绿风险，非产品缺陷）
- 严重度 P3 ｜ 类别 可维护性（测试质量）
- (a) `scopegate_test.go:92-96` 逃逸断言是 `if status==200 && len(calls)>0`：回归成「502 但已拨号」
  或「200 但计数没记」照样绿，且从不命名期望的 400。我加更强守卫
  `TestZ20AdvRawEscapeIsRefusedWith400AndNoUpstreamCall`（断言恰好 400、上游调用数不变、body 无 marker）**实跑绿**，
  证明产品当前正确，但原守卫证明不了。
- (b) `TestZ20NormalizedGateRequiresTheScopeOfEveryCandidateSource`（`scopegate_test.go:103-125`）建的是
  **单源**夹具（`fixture_test.go:165-173`）⇒「每个候选源」退化成「那一个源」，无法与「第一源优先」回归区分。
  双源探针 `z20verify_test.go::TestZ20VNormalizedGateRequiresEveryCandidateSourcesScope` 实跑绿，补上了这条。
- 修法：逃逸断言命名 400 + 零调用；归一化守卫至少两条候选源。

## 未能到达
- **Postgres 全部分支**只有读码级证据（无 PG/Docker）：Z20-1、Z20-3、Z20V-1、Z20V-2 的 postgres 侧；
  `TEST_DATABASE_URL` 是权威位。
- 未起 `cmd/re0auth` 真进程黑盒（**端口 19002 未使用**）：无浏览器、无第二个 IdP 会话，全部结论由进程内
  真栈取得；监听/中间件叠加与跨副本/多实例隔离未触。
- 真实 `/app/consent` 浏览器交互未跑（无 Playwright）。

## 判断（文档化决定，不是 finding）
1. **raw 源级粗闸门**（Z20-2 降级依据）：`docs/architecture.md:468` 已写成「已知粗粒度」，
   但未声明「用户同意页收窄掉的作用域可经 raw 绕过」。建议在 `docs/upstream-protocol.md §9` 明写这条后果
   并做决议；若裁定「源级即有意」，Z20-2 即改为判断条目。
2. **`introspection_clients` 必须是机密客户端**：今天由运行期守卫 + 出口改写（Z20-6）兜底，启动期校验仍值
   补（纵深防御），但不改变 Z20-6 结论。
3. G-8 的影响段文字应更正为「部署 OP + Kit 同形」——这是 Z20-5 唯一有效的成分，归属 G-8。
