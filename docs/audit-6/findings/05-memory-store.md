# 区域 05 · 内存存储：语义漂移 / 竞态 / 增长边界（第六轮）

- 审计对象：HEAD `bf81b2a`。区域代码全部读过（`internal/store/memory/` 全部 8 个文件、
  `internal/store/postgres/oidc.go`/`sweep.go`/`oauth.go`、`internal/oidcstore/`、
  `cmd/re0auth/main.go` 组合根、`audit/audit.go`、scs/memstore 依赖源、
  zitadel/oidc v3.51.3 的 refresh/device/revocation/userinfo/introspection 路径）。
- 探针：`internal/zzprobe/audit6/z05memstore/`（9 个测试：3 红 = 发现，6 绿 = 守卫/对照）。
  跑法：`go test -tags audit6 -count=1 ./internal/zzprobe/audit6/z05memstore/...`。
- 真进程：内存模式 `re0auth` 于 127.0.0.1:16501（内部面 16551）起过两轮，已全部 Stop-Process。

## 执行摘要

**4 条发现，全部 P3，无 P0/P1/P2。** 一句话结论：f6af208 修对了它声明的部分且未引入新洞，
但 cloneAuthRequest 仍留两个共享指针字段（05-4，红探针）；两后端之间存在三处
「内存安全 / Postgres 不安全或较穷」的语义漂移——过期 refresh token 的裁决（05-1）、
设备决策审计的 client 归属（05-3）、（与 05-2 相关的）过期设备码兑换窗口——其中
05-1/05-3 的 Postgres 一半在本环境无数据库，只能读码定罪，标 HYPOTHESIS；
05-2 在内存后端有红探针 CONFIRMED。内存模式的声明面（README/启动告警）与实现
之间没有找到缝隙；sweep/growth 的已知 P3 类未发现新形态。

第五轮修复回归：**全部通过**（audit5 的 concurrency + verifycm 两包绿、内存 store 单测
-race 绿、假守卫 `worst` 已修、CM-1/2/3/4 探针维持绿、P0-1/P0-2 在内存后端的端到端
行为经本区新探针复验为绿）。

---

## 05-1 Postgres 的 refresh token 过期从不被读路径裁决，内存后端到点即拒——30 天 TTL 在生产后端只由 15 分钟一轮的 sweep 执行

- 严重度：P3
- 不变量：撤销生效（过期是签发时写下的撤销时刻）/ token 签发；两后端语义一致
- 证据（读码级）：
  - 内存后端**拒绝**过期 refresh token：`internal/store/memory/oidc.go:573`
    `if !ok || !s.now().Before(r.expiresAt) { return nil, errors.New("memory: invalid refresh token") }`。
  - Postgres 后端的同一方法**没有 expires_at 谓词**：`internal/store/postgres/oidc.go:430-435`
    `SELECT id_hash, client_id, subject, scopes, amr, audience, auth_time FROM oidc_refresh_tokens WHERE token_hash = $1`；
    轮换声明同样不看期限：`postgres/oidc.go:393-394`
    `DELETE FROM oidc_refresh_tokens WHERE token_hash = $1`（无 `AND expires_at > …`）。
  - 依赖库在 refresh 授予路径上不做任何期限检查（zitadel/oidc v3.51.3
    `pkg/op/token_refresh.go` 全文：client 匹配 + scope 子集，无 expiry；
    `CreateTokenResponse`/`createTokens` 亦无）。存储是唯一裁决点——而它没裁决。
  - 唯一执行者是 sweep：`postgres/sweep.go:29` 删除 `oidc_refresh_tokens` 的过期行，
    `cmd/re0auth/main.go:405` 每 **15 分钟**跑一次。
  - 已有守卫不覆盖此路径：`postgres/clock_test.go`（P2-32 的三段设备 + 会话/码/Grants）
    没有对 `TokenRequestByRefreshToken` 的过期断言。
- 状态：HYPOTHESIS（差什么：`TEST_DATABASE_URL`。Postgres 一半在本机不可运行；
  内存一半已由绿探针钉住——见下）
- 影响：生产后端上，一枚过了 30 天期限的 refresh token 在过期后最多 15 分钟内仍可兑换
  出**全新 30 天 TTL** 的 access+refresh 对（TTL 被整体重置，而不是被拒绝）；
  sweepLoop 若连续失败（错误只打日志，`main.go:1111`）窗口继续延长。
  内存模式到点即拒。攻击收益小（偷到的 token 多活 ≤15 分钟），但这是
  「一个后端安全另一个不安全」的教科书形状：所有测试（内存后端）全绿，生产行为不同。
- 探针：`drift_guards_test.go::TestMemoryRefusesAnExpiredRefreshToken`（**绿**，
  钉住内存的拒绝半边与对照控制；Postgres 半边即本发现）
- 修法建议：`TokenRequestByRefreshToken` 的 SELECT 加 `AND expires_at > $2`（用 `s.now()`
  传入，保持单时钟政策），或在 `CreateAccessAndRefreshTokens` 的 DELETE 里带上期限；
  并给 `clock_test.go` 补一段「过期 refresh token 被拒」。

## 05-2 已批准的 device_code 在广告的 expiry 过后仍能铸出整套 access/refresh——两后端同样缺谓词，内存后端红探针实证

- 严重度：P3
- 不变量：撤销生效（expires_in 是对客户端的广告契约，RFC 8628 §3.5 `expired_token`）
- 证据（红探针，内存后端，走真实 HTTP 入口）：
  ```
  --- FAIL: TestDeviceCodePastItsAdvertisedExpiryStillMintsTokens
      device_expired_test.go:81: a device_code redeemed 11m0s past its advertised
      expiry minted a full access/refresh pair (access_token len=295) and the
      access token answered userinfo with 200 — expected expired_token
  ```
  流程：`POST /oauth/device_authorization`（scope=openid account.id）→ 用户经
  `DecideDeviceAuthorization` 批准（未过期时）→ store 时钟推过 `expires_in`+60s →
  `POST /oauth/token`（device_code 授予）→ **200 + access/refresh + id_token**，
  且该 access token 在 `/oauth/userinfo` 拿到 200。
  机制：
  - 库只在 **pending** 分支查 `state.Expires`：zitadel/oidc
    `pkg/op/device.go:317-326`（`if state.Done { return state, nil }` 在
    `time.Now().After(state.Expires)` **之前**）——批准过的码由存储负责守期限。
  - 内存后端的消费分支没有期限谓词：`internal/store/memory/oidc.go:891-899`
    `if d.done && !d.denied { delete…; return st, nil }`。
  - Postgres 同形：`internal/store/postgres/oidc.go:750-752`
    `DELETE FROM oidc_devices WHERE device_code_hash = $1 AND client_id = $2
    AND done = true AND denied = false`——同样不看 `expires_at`。
  - 因此唯一移除者是 sweep：内存 janitor 每 5 分钟（`main.go:80`），
    Postgres 每 15 分钟（`main.go:405`）。窗口 ≈ [过期, 下一次清扫]。
  - 对照（绿）：同一流程不推时钟则 200 正常铸出（`TestDeviceCodeRedeemsWithinItsLifetime`），
  证明红探针不是「设备流在本夹具里本来就不通」。
- 状态：CONFIRMED（内存后端有红探针；Postgres 半边读码同形，属 05-1 同款盲区）
- 影响：持有 device_code 的一方可在其「已过期」后最多 ~5 分钟（内存）/ ~15 分钟（Postgres）
  兑换出一整套 30 天能力的 grant。用户确实在有效期内批准过，所以铸出的授权本身
  是用户同意过的集合——被违反的是广告出去的 `expires_in` 契约与「过期码必须回
  expired_token」。单次消费语义（c13effa）仍在：只能晚兑换一次，不能重复铸。
- 探针：`device_expired_test.go::TestDeviceCodePastItsAdvertisedExpiryStillMintsTokens`（红）
- 修法建议：两后端的消费谓词加期限——内存 `if d.done && !d.denied && s.now().Before(d.expiresAt)`；
  Postgres 的 DELETE 加 `AND expires_at > $3`（store 时钟）。

## 05-3 设备批准/拒绝的审计事件在 Postgres 后端不带 client_id，内存后端带——生产审计链回答不了「这个设备决策授权给了哪个客户端」

- 严重度：P3
- 不变量：审计可归因（撤销/问责面）
- 证据（读码级 + 内存半边绿探针）：
  - 内存后端记录归属：`internal/store/memory/oidc.go:1104`
    `s.record(ctx, "oidc.device.approve", subject, d.clientID, audit.OutcomeOK)`；
    `:1125` deny 同样带 `d.clientID`。
  - Postgres 后端传**空串**：`internal/store/postgres/oidc.go:898`
    `s.record(ctx, "oidc.device.approve", subject, "", audit.OutcomeOK)`；
    `:919` deny 同样为 `""`。git blame（1287d68 起）表明这是移植时的疏忽而非取舍
    ——内存后端一直记录，Postgres 版的 UPDATE 恰好没有 RETURNING client_id 可用。
  - 内存半边绿探针断言两事件的 `Detail["client_id"] == "cli"`：
    `TestDeviceDecisionsAreAuditedWithClientAttribution`。
- 状态：HYPOTHESIS（差什么：`TEST_DATABASE_URL`，Postgres 半边不可运行；
  机制本身两行代码即可读出）
- 影响：生产部署的审计事件 `oidc.device.approve/deny` 的 `client_id` 详情为空。
  运维回答「哪台设备/哪个用户把什么客户端批进来了」时，Postgres 审计链缺一半；
  内存模式反而齐全。属审计内容漂移，不涉权限边界。
- 探针：`drift_guards_test.go::TestDeviceDecisionsAreAuditedWithClientAttribution`（绿，
  钉内存半边）
- 修法建议：Postgres 的 `ApproveDevice/DenyDevice` UPDATE 改 `RETURNING client_id`
  （或在谓词里已知 client 时直接传入），使两后端事件一致。

## 05-4 f6af208 的 copy-on-return 没修全：cloneAuthRequest 仍共享 CodeChallenge 与 AuthTime 两个指针字段，写穿即改库

- 严重度：P3
- 不变量：token/scope 签发（PKCE 挑战值与 auth_time 都在签发路径上被读）；store 封装
- 证据（红探针，两个）：
  ```
  --- FAIL: TestAuthRequestCloneSharesItsAuthTimePointerWithTheStore
      alias_residual_test.go:86: a write through the AuthRequestByID clone's
      AuthTime pointer changed the stored record's auth_time to 2035-01-01…:
      the clone aliases store state
  --- FAIL: TestAuthRequestCloneSharesItsCodeChallengePointerWithTheStore
      alias_residual_test.go:117: a write through the AuthRequestByID clone's
      CodeChallenge pointer changed the stored record's PKCE challenge to
      "rewritten-by-the-caller" (method plain): the clone aliases store state
  ```
  机制：`internal/store/memory/oidc.go:435-439`
  ```go
  func cloneAuthRequest(a *oidcstore.AuthRequest) *oidcstore.AuthRequest {
      out := *a                       // 结构体浅拷贝
      out.Scopes = append(…)          // Scopes 深拷贝
      return &out                     // CodeChallenge / AuthTime 指针仍指向存量
  }
  ```
  `CreateAuthRequest`（:398）、`AuthRequestByID`（:409）、`AuthRequestByCode`（:432）
  都经它返回。对照（绿）：对 clone 的**字段**赋值（如 `.Subject=…`）不进库——
  结构体本身是拷贝；只有**写穿**共享指针才落库。
- 状态：CONFIRMED（机制有红探针；**可达性如实降格**：生产里没有任何写穿者——
  zitadel/oidc 只经 getter-only 的 `op.AuthRequest` 接口消费返回值
  （`pkg/op/auth_request.go` 对库自己的类型才会写字段，且发生在 CreateAuthRequest
  之前；`pkg/op/token_code.go:83-84` 只读 `GetCodeChallenge()`），
  `internal/oidchttp` 的三个调用点（oidchttp.go:1519/1542/1608）也只读。
  与第五轮 CM-3 的复核结论同构：机制成立、当条不可达，留作潜在缺陷——但 f6af208
  的提交信息声称「copy-on-return 补齐」，形状上没有补齐。）
- 影响：今天没有攻击者可达路径；风险是**未来任何持有返回值并写穿指针的调用方**
  （例如某天有人给 consent 流加「改写 auth_time」或复用 challenge 的优化）会绕过
  store 的锁直接改库——尤其 CodeChallenge 正是码兑换时 PKCE 校验用的那个值。
- 探针：`alias_residual_test.go::TestAuthRequestCloneSharesItsAuthTimePointerWithTheStore`（红）、
  `::TestAuthRequestCloneSharesItsCodeChallengePointerWithTheStore`（红）、
  `::TestF6af208AliasFixesHold`（绿——f6af208 修的部分没回归）
- 修法建议：cloneAuthRequest 补两个字段的深拷贝：
  `if a.AuthTime != nil { t := *a.AuthTime; out.AuthTime = &t }`、
  `if a.CodeChallenge != nil { c := *a.CodeChallenge; out.CodeChallenge = &c }`。

---

## 回归验证（第五轮以来本区域的修复）

| 修复 | 验证方式 | 结果 |
|---|---|---|
| f6af208 内存别名（CreateAuthRequest 返回 clone；TokenRequestByRefreshToken 深拷贝 AMR/Audience/AuthTime） | `TestF6af208AliasFixesHold`（新，绿）+ audit5 `concurrency`/`verifycm` 两包全绿 + 内存 store `-race` 绿 | **修对**；但形状没修全 → 05-4 |
| P0-1（id_token sub）两后端 | 端到端：设备授予（含 openid）→ id_token.sub == usr_probe（`TestDeviceGrantIDTokenCarriesSubjectAndTheBearerWorksAtUserinfo` 绿）；Postgres 半边读码一致（`postgres/oidc.go:630-633` 与内存同文） | 修对 |
| P0-2 存储半边（SetUserinfoFromToken 查活行） | `TestSetUserinfoFromTokenChecksTheStoredRow`（绿：空 tokenID/未知/subject 不匹配/过期全拒，只发布行内 subject）；HTTP 面 userinfo 200/401 正确 | 修对 |
| CM-1（Approve/Deny 在锁内写审计） | audit5 `concurrency::TestApproveDeviceHoldsTheStoreLockAcrossTheAuditWrite` 等照旧绿（行为被有意钉住）；内存模式 sink 是 MemoryLogger（CM-1 的复核结论：两 store 部署互斥，影响不成立） | 维持复核结论 |
| CM-2（三处丢 ctx） | audit5 `TestEveryAuditPathForwardsTheRequestContext` 绿 | 修对 |
| P2-32（设备路径单时钟） | `postgres/clock_test.go` 设备三段读码复核（本机无库不能跑）；内存后端自用 store 时钟，与探针一致 | 读码级一致 |
| 假守卫 `TestMemStoreSweepStallsConcurrentRequests` 的 `worst` 从不重置 | `internal/zzprobe/perf/memstore_test.go:192` 现有 `worst.Store(0)` 两段间重置 | **已修** |
| c13effa 撤销连带清理（码/设备） | 内存 store 单测（oidc_test.go 相应用例）绿；本区未发现绕过形态 | 修对 |

## 探过没破（含探针名）

1. **设备流在有效期内正常兑换**：`TestDeviceCodeRedeemsWithinItsLifetime`（绿，同
   响应顺带断言 P0-1 的 sub）。
2. **f6af208 的三处别名修复未回归**：`TestF6af208AliasFixesHold`（CreateAuthRequest
   返回值的字段/切片写不进库；RefreshRequest 的 Scopes/AMR/Audience/AuthTime 全不别名）。
3. **内存后端拒绝过期 refresh token**（05-1 的安全半边）：`TestMemoryRefusesAnExpiredRefreshToken`
   （对照控制：期限内可用）。
4. **内存后端设备决策审计带 client 归属**（05-3 的安全半边）：
   `TestDeviceDecisionsAreAuditedWithClientAttribution`。
5. **P0-2 存储半边在内存后端全拒**：`TestSetUserinfoFromTokenChecksTheStoredRow`
   （空 tokenID=JWT 回落面、未知 id、subject 不匹配、过期全拒；只发布行内 subject）。
6. **端到端 P0-1/P0-2 在内存后端成立**：`TestDeviceGrantIDTokenCarriesSubjectAndTheBearerWorksAtUserinfo`
   （id_token sub、userinfo 200、伪造 bearer 401）。
7. **读码级对照（无漂移）**：RevokeToken 三分支形状（含 idHash 残余对）、
   TerminateSession（两后端都只删 token；end_session 端点按 O-9 本就不挂载）、
   RevokeGrant/RevokeTokens/PurgeSubject 的谓词与连带清理（码随请求、设备随主体）、
   Approve/Deny 的状态谓词（deny 压 approve、二次拒绝、过期拒绝）、
   GetRefreshTokenInfo 的 client 过滤、Grants 的排序与 offline_access 剥离、
   SaveAuthCode、单时钟政策（写读同钟）——两后端逐方法一致。
8. **锁纪律**：TerminateSession/RevokeGrant/Grants 对索引 map 的 range 中只删当前键
   （Go 语义安全）；RevokeTokens/PurgeSubject 用拷贝出的键切片；`-race` 下内存 store
   与本区探针均无 DATA RACE（红探针的红是断言，不是竞态）。
9. **真进程黑盒**（内存模式，127.0.0.1:16501/16551，已杀净）：启动告警四条齐全且
   理由正确（`because="no DATABASE_URL is configured"`——P2-8 修复生效；
   审计环、抹除会话缺口各有专门告警）；`/oauth/authorize` 302 到 consent 且分配
   pending handle；`/oauth/device_authorization` 200 出码；**重启丢态 fail-closed**
   （重启前铸的 device_code 重启后兑换 → 400 `access_denied`）。
10. **第五轮本区探针回归**：`go test -tags audit5 ./internal/zzprobe/concurrency/...
    ./internal/zzprobe/verifycm/...` 全绿。
11. **增长边界复核**：pending 请求/设备码 = 到达率 × TTL（CM-4 复核结论维持）；
    审计环 10k 有界；scs memstore 自带每分钟清扫 goroutine；subjectIndex 三索引
    由随机游走不变量测试守护（oidc_index_test.go）。
12. **slow_down 语义**：内存后端在过早轮询时把 lastPoll 前移（比 Postgres 更严），
    方向无害，两后端都回 `context.DeadlineExceeded`→`slow_down`。

## 未能到达

1. **一切 Postgres 运行时语义**：05-1/05-2/05-3 的 Postgres 半边只有读码级证据
   （无 Docker/无本地库）；权威验证在 CI 的 `postgres:16`。
2. **真进程端到端设备批准**：内存模式进程未配 IdP（「nobody can sign in」），
   /app 同意页的浏览器会话路径无法黑盒走通；批准步用 httpapi 夹具的
   `DecideDeviceAuthorization`（与 /app 路由同一方法）替代。
3. **绝对墙钟数字**：本机多代理并行，延迟类不可引用；可引用的只有分配量与复杂度类
   （本区未发现新的性能形态，已知 P3 维持）。
4. **janitor 真实 5 分钟节律与长时段增长曲线**：结构上由单测/基准钉住，未跨真实时间观察。
