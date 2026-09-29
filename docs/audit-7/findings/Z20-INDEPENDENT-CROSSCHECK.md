# 区域 20：授权隔离矩阵 — **独立交叉核对报告**（Z20-INDEPENDENT）

> **性质**：这不是第二份区域报告，而是对 `docs/audit-7/findings/Z20-authz-isolation-matrix.md`
> （下称「原报告」，作者为原 Z20 代理）的**独立复核**，外加原报告**没有命名探针**的那几个矩阵单元格。
> 独立性的保障是**不共用任何夹具**：本报告的全部探针建在
> `internal/zzprobe/audit7/z20independent/` 的自建真栈上（`httpapi.New`＋真 OP
> `oidchttp.New`＋`memory.NewOIDCStore`＋真 `federation.NewService`＋真上游 httptest＋真
> `/auth` 登录面＋真会话），没有一个 helper 与原报告的 `fixture_test.go` 共享。
>
> **方法学约束**：每条「某物不存在/被拒绝」的结论都带阳性对照（对照组先跑通，或故意注入必须失败）。
> 所有探针走真实入口点：真 `/oauth/*`、真 `/v1/*`、真 `/auth/*`、真同意决策 API、真设备决策 API。
>
> **注意**：我到达本区域时原报告的作者**仍在活动**（其探针 01:52→01:56 持续落盘、报告 01:57:48 新建），
> 故我的产物走独立路径，未触碰其任何文件。

## 范围与方法

- 读了：`oauth/{as,client,scope,grants,device,tokens,service,http}.go`、`internal/oidchttp/oidchttp.go`
  （含 zitadel/oidc v3.51.3 `pkg/op/{client,token_intospection,device}.go` 依赖源码）、
  `internal/oidcstore/oidcstore.go`、`internal/store/memory/oidc.go`、
  `internal/httpapi/{server,middleware,v1,grants,binding,federation,admin,authorization,device,account,identity,session,export,audit}_routes.go`、
  `internal/federation/{federation,service,binding,missing}.go`、`internal/auth/auth.go`、`internal/admin/admin.go`、
  `cmd/re0auth/{config,main}.go`、`config/re0auth.example.toml`、`docs/upstream-protocol.md` §9。
- 探针命令：`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z20independent/...`
  → **21 个探针：20 绿 / 1 红**（红的就是原报告 Z20-2 的独立复现，故意留红）。
- `gofmt -l` 对本目录干净；`go build ./...`、`go vet ./...`、`go vet -tags audit7 ./internal/zzprobe/audit7/z20independent/...`
  均 exit 0；未改任何被跟踪文件。

## 逐条裁定（原报告的 6 条）

### Z20I-X1 → Z20-1（成功的授权码兑换写一条假 `oidc.consent.deny`）：**AGREES**
- 我的证据（绿＝一致）：`TestZ20I001SpuriousConsentDenyOnSuccessfulExchange`
  ```
  deny events: before=0 after=1
    deny: subject="" outcome=denied detail=map[client_id:]
  ```
  路径与作者不同：我这里走的是**完整浏览器路径**（sign in → `/oauth/authorize` → 真
  `/v1/authorization_requests/{id}` → 真 `/v1/authorization_requests/{id}/decision` → callback →
  `/oauth/token`），不是直接调 `ConsentStore.CompleteLogin`。阳性对照：同一次流程里
  `oidc.consent.approve` 恰好 1 条且带 `client_id`，所以「没有 deny」不可能被解释成「流程没走到」。
- 严重度意见：**维持 P2**，但它处在 P2/P3 边界——它不参与任何安全裁决，只是让
  `oidc.consent.deny` 的数量在**每次成功登录**上 +1，且假行与真拒绝只能靠「字段是否为空」区分。
  修法必须保证真拒绝那条仍在（作者的对照探针 `TestZ20ARealRefusalStillRecordsTheEvent` 覆盖了这点）。

### Z20I-X2 → Z20-2（raw 透传闸门按源判、不按资源判）：**AGREES（机制），但严重度的前提要收紧**
- 我的证据（红＝一致）：`TestZ20I002RawPassthroughIgnoresWhichResourceTheScopeNames`
  ```
  normalized /v1/games/phigros/scores            (profile-only) -> 403
  raw        .../raw/resources/scores           (account.id)   -> 403   [对照]
  raw        .../raw/resources/scores           (score)        -> 200   [对照]
  raw        .../raw/resources/scores           (PROFILE-only) -> 200 {"marker":"Z20I-SCORES"}
  ```
  我的上游是**按路径应答**的（`/resources/scores`→SCORES、`/resources/profile`→PROFILE、
  其他→NATIVE），所以「profile-only 的令牌拿到了 scores 资源」不是桩的假象。
- **对原报告前提的更正（这是本节最重要的部分）**：原报告写「raw_base = 它的 issuer——自然配置，
  且 `config/re0auth.example.toml:365` 展示的形态」。实际：
  - `config/re0auth.example.toml:363` 配的是 `raw_base = "https://api.next-phi.example/v1"`，即
    **`{issuer}/v1`**；而源的归一化资源在 `{issuer}/resources/{name}`（`docs/upstream-protocol.md:227`
    的 `GET /resources/{name}`）。**两者不是同一个 URL。**
  - 我实测两种配置（`TestZ20I002cRawBaseSubPathDecidesWhetherTheWithheldResourceOverlaps`）：
    ```
    raw_base == issuer:     raw -> 200 {"marker":"Z20I-SCORES"}  upstream=/resources/scores   ← 重叠
    raw_base == issuer+/v1: raw -> 200 {"marker":"Z20I-NATIVE","path":"/v1/resources/scores"} ← 不重叠
                            （对照：归一化读仍打到 /resources/scores）
    ```
- 因此我的裁定是：**机制 CONFIRMED，但要按 `raw_base` 分档**——
  - 当 `raw_base` 是源的 issuer（或 `{issuer}/resources` 的祖先）时，raw 与归一化**指向同一上游端点**，
    用户未授予的那个 scope 被完全绕过 ⇒ **P2 成立**（且 `validateRawBase` 允许这种配法，只查
    http(s)+无 query/fragment）。
  - 按出厂样例的 `{issuer}/v1` 形态，raw 打的是源自己的**原生面**，拿不到归一化资源 ⇒ 这条降级为
    **P3**：闸门仍粗（任一资源 scope 打开整个原生 API），但代码注释
    （`federation_routes.go:221-222`「coarse gate … future work」）与 §9 都把 raw 当独立面，属已知取舍。
  - **给主代理的处置**：保留 P2，但报告必须写成**条件句**并把 `raw_base` 前提写进去，
    否则会被「出厂样例不重叠」一句推翻。

### Z20I-X3 → Z20-3（设备批准审计不带 scopes）：**AGREES**
- 我的证据（绿＝一致）：`TestZ20I003DeviceApprovalAuditOmitsTheGrantedScopes`——走真
  `/oauth/device_authorization` ＋ 真 `/v1/device/verification` ＋ 真 `/v1/device/decision`
  （scopes 只勾 profile，即发生 narrowing），结果 `detail=map[client_id:cli]`，无 `scopes`。
- 严重度：**维持 P3**（审计完整性问题，不是裁决缺口）。

### Z20I-X4 → Z20-4（设备批准入口**确实**执行 ExplicitConsent，反驳 P-02）：**AGREES（并独立复现反驳）**
- 我的证据（绿＝一致）：`TestZ20I004DeviceApprovalEnforcesExplicitConsent`——自建目录
  `DefaultDescriptors() + phigros.secret.read(ExplicitConsent)`，经真设备端点取码后走真
  `/v1/device/decision`：
  ```
  勾选 explicit -> 200
  不勾        -> 400 {"detail":"explicit consent is required for phigros.secret.read"}
  ```
  ⇒ `_audit/protocol.md` P-02 的「设备面缺闸门」不成立。**这是对 P-02 的反驳，独立确认。**

### Z20I-X5 → Z20-5（部署面 `/oauth/revoke` 也是存活性预言机）：**AGREES**
- 我的证据（绿＝一致）：`TestZ20I005RevocationOracleForForeignTokens`
  ```
  revoke unknown string        -> 200
  revoke another client's live -> 401 {"error":"invalid_client","description":"token was not issued for this client"}
  对照：该外来令牌随后仍能用（/v1/me 200）⇒ 401 是拒绝，不是删除
  ```
  与 `oauth/as.go:223-239` 自己写下的规则（「非本人」必须与「未知」同形）矛盾，且 G-8 只记在公开引擎上。
- 严重度：**维持 P3**（攻击者必须**已经持有**该字符串才有信息差，见「判断」）。

### Z20I-X6 → Z20-6（转义拼写绕过内省守卫后什么也拿不到）：**AGREES**
- 我的证据（绿＝一致）：`TestZ20I006EscapedPublicIntrospectionDisclosesNothing`
  ```
  plain public caller           -> 401 {"invalid_client":"introspection requires a confidential client"}
  percent-encoded public caller -> 200 {"active":false}          ← 守卫被绕过，但出口改写生效
  ```
  并且断言了 `sub` 等字段一个都没到调用方。⇒ P-01 的**影响段**不成立（机制段成立）。

## 我补的矩阵单元格（原报告未命名探针的部分）

| ID | 单元格 | 断言 | 结果 |
|---|---|---|---|
| Z20I-101 | 主体 × 资源 | 只有 `usr_victim` 有绑定；另一主体持**同一 scope** 读 → 409 `source_not_bound` 且上游零调用 | 守住 |
| Z20I-102 | 主体 × 路由 | 合法 bearer 打 `/v1/grants|bindings|identities|account/export|sessions/current` 全部 401（对照：同浏览器会话 200） | 守住 |
| Z20I-103 | 主体 × 会话 | 同一浏览器切换账号：export 的 `user_id` 随会话变、且不含前一主体的 identity id | 守住 |
| Z20I-104 | scope × 同意 | 决策 `scopes` 含**未请求**的已注册 scope，或**未注册**的 scope → 400「cannot widen the requested scope」 | 守住 |
| Z20I-105 | scope × 设备 | 设备批准含未请求的 scope → 400；对照组换取到的令牌 scope 恰为请求集 | 守住 |
| Z20I-106 | scope × 刷新 | `refresh_token` 携带 `scope=account.id phigros.score.read` → 400 `invalid_scope` | 守住 |
| Z20I-107 | 主体 × 管理面 | 精确 allowlist→200；**6 种近似拼写**（尾/首空格、全大写、去尾字符、追加字符、加 `%`）全部 404；未登录 401；另一账号 404 | 守住 |
| Z20I-108 | 客户端 × 公开读 | `/v1/sources`、`/v1/games/{g}/sources`（匿名）不含源的 `client_id`/`client_secret`/上游令牌 | 守住 |
| Z20I-109 | 资源 × 源 | 两源声明**同名资源** `scores` 但 scope 不同（`score` vs `b30`）：不 pin 时要求**两者都**持有 → 403；`?source=` pin 才收窄；两 scope 齐备 → 200 | 守住（FO-01 形状的正确性独立复现） |
| Z20I-110 | 主体 × 流程 | link 流程被后续登录**顶掉**：旧 state 的回调 400 `invalid state`，且未产生任何 identity | 守住（见「判断」注） |
| Z20I-111 | 客户端 × scope | `cli2`（只注册 account.id）在 authorize 得 `error=invalid_scope` 且无 handle、设备面 400；`cli` 兑换 `cli2` 的 code → 400 `invalid_grant` | 守住 |
| Z20I-112 | 主体 × 同 consent 句柄 | 句柄创建者 A 的会话换成 B 后，B 读/决策该句柄 → **404**（不是 403，无存在性预言机） | 守住 |
| Z20I-113 | 主体 × 设备句柄 | 同上，设备码由 B 决策 → 404，且该设备码仍不可兑换（`authorization_pending`） | 守住 |

**对原报告「探过没破」的两处更正/加强**：
1. 原报告把「会话面写操作与资源归属」与「句柄 `OwnerMatches`」列进「探过没破」但**没有命名探针**；
   Z20I-112 / Z20I-113 把它变成了**会失败的东西**（把 `OwnerMatches` 那一行删掉，这两条立刻转红）。
   另外原报告说「跨客户端的**刷新/兑换**身份互换被要求 `code.ClientID == client.ID`」——
   那份引用的 `memory/oidc.go:877` 是**公开引擎**的路径；部署面（zitadel OP）的这一条由 Z20I-111 实测
   （400 `invalid_grant`），两条路径都有证据。
2. Z20I-109 的日志显示：同优先级（都 `active`）时服务源是**按名字序**（`beta` < `fake`）而非配置序。
   原报告「`ResourceRequirements` 与 `Fetch` 用同一个 `candidates()`」的结论仍成立，
   但「哪一源实际服务」要写成「按 (statusRank, name)」。

## 探过但没破的（本报告的守卫，均应进 CI）

- **跨主体**：数据面 409 且上游零调用（Z20I-101）；bearer 打会话面全 401（Z20I-102）；
  一浏览器切账号不串数据（Z20I-103）。
- **scope 只收窄**：同意（Z20I-104）、设备（Z20I-105）、刷新（Z20I-106）三面均拒，且**换出的令牌
  实测 scope 等于授予集**（不是我读代码推断）。
- **管理面 allowlist 是精确相等**（Z20I-107，6 种近似拼写 + 未登录 + 非管理员）。
   注：`httpapi.New` 把 `cfg.Admins` 原样塞进 `map[account.UserID]bool`（`server.go:305-308`），
   大小写/前后缀/编码都不会命中 ⇒ 失败方向是 fail-closed（写错配置 = 没人能管，不是人人能管）。
- **公开读不泄凭据**（Z20I-108）：`sourceView` 只输出 game/source/display_name/token_class/status/raw/resources。
- **同名资源、异 scope 的闸门**（Z20I-109）：要求**每个**候选源的该资源 scope；`?source=` 是唯一收窄手段。
- **句柄归属**（Z20I-112/113）：`Bound` ＋ `OwnerMatches` 双条件、答 404、跨账号切换后失效。
- **link 流程**（Z20I-110）：后续登录会**覆写**会话里的 `flow_state`/`flow_mode`，旧回调直接
  `400 invalid state`，因此「A 起的 link 被 B 完成」这条形状不可达。
- **显式同意**在交互面与设备面都生效（Z20I-004 / Z20I-104）。

## 未能到达（残余盲区）

1. **Postgres 侧零运行时证据**：无本地 PG/Docker。Z20-1/Z20-3 的 PG 分支、`NarrowScopes` 的 PG 孪生
   只有读码级；权威位是 CI 的 `postgres:16`。
2. **真实浏览器**：Playwright 未装，同意页/设备页的**前端**未跑（我只驱动到 API 与句柄）。
3. **真进程黑盒（19001）未启用**：本报告的结论全部由进程内**全接线真栈**取得
   （真 `httpapi.Handler()`、真 OP、真中间件链、真会话）；我没有再起 `cmd/re0auth` 真进程复核，
   因此**监听器叠加/配置装载路径**（`sourceSection.raw_base` 的 TOML→`federation.Source` 映射）
   只有读码级（`config/re0auth.example.toml:363` 样例、`NewRegistry` 的 `validateRawBase`）。
4. **多副本**：跨实例的 refresh 家族/会话索引未触（单进程内存）。
5. **真实上游方言**：上游是 httptest 桩（但**按路径区分应答**，不是「永远答同一体」的桩）。

## 判断（不是 finding）

1. **Z20-2 的分档是裁定问题，不是代码问题**：`raw_base` 允许等于 issuer，也允许是子路径。
   若团队裁定「raw 永远是源级粗闸门」，就把这句话写进 `docs/upstream-protocol.md` §9
   （现在只在代码注释里）；否则应在归一化资源名可从 raw 路径推导时要求对应 scope。
   我倾向：**保留为 P2 但写清前提**——因为「同一份成绩数据，归一化 403 / raw 200」这个不对称
   本身就该在上线前对齐，与 `raw_base` 写法的选择无关。
2. **Z20-5 的收益被原报告略过**：预言机需要攻击者**已经持有**那个字符串。它的价值是
   「不用花用这枚令牌就能知道它是否还活着」（避免触发使用侧的检测），所以 P3 恰当，不应上调。
3. **Z20-6 说明 `filterIntrospection` 是真正的兜底**：即便修 P-01 的解码问题，
   也建议把「`introspection_clients` 必须是机密客户端」提到**启动期**（纵深防御）。
4. **link 流程守住是「副作用」而非设计**：它靠 `handleCallback` 先覆写 `flow_state` 而成立，
   不是靠 `OwnerMatches`。同族的 `flowNonce` 还漏在 `clearFlow` 之外（第五轮 RP-8，已知）。
   建议给 link 流程也加 `OwnerMatches` 语义，让守卫成为显式的。
