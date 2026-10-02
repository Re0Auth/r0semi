# P0 · 阻断上线（BLOCKERS）

> 不修就不能上线。G-1/G-2/G-3 由第七轮在 HEAD 上复跑确认；S02-1/S06-1/S08-2/S10-1/S13-1/S14-2 由第九轮独立审计命名（§7 第 1 步），并在 `992710b` 收口。
> **条目数：9** ｜ 由 `_fragments/_merge.mjs` 从各轮抽取结果生成（2026-10-02，HEAD `9ce8a4b`）。
> 严重度取**对抗性复核后的裁定**；同一机制多编号者已合并，别名写在 ID 列。

> **当前状态（HEAD `9ce8a4b`）：这 9 条全部 `FIXED`，没有未修 P0。**
> G-1/G-2/G-3 由第六轮认定、`79d7333` 收口；S02-1/S06-1/S08-2/S10-1/S13-1/S14-2 是第九轮
> 独立审计在 rc.4 之后重新发现的 8 条 High 中的 6 条，由 `992710b` 收口。保留在册只为溯源；
> 是否仍有残余，以每条的状态与 `docs/issues/README.md` 的统计为准。


### S02-1 prompt=login / max_age 不触发重新认证，OP 把同意时刻伪造成新的 auth_time
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **位置**：`internal/oidcstore/oidcstore.go:226; internal/oidchttp/oidchttp.go:1006; internal/store/memory/oidc.go:1274; internal/store/postgres/oidc.go:1269`
- **影响**：`RequiresReauthentication` 是唯一比较会话年龄与请求新鲜度的地方，但它的结果从不用于强制重登录：登录钩子只把 `sessions.AuthenticatedAt` 抄进 pending 请求并返回同意 URL，两个 store 在 `RequiresReauthentication==true` 时反而用"同意决策时刻"覆盖 `AuthTime`。结果是一条 24h 的旧会话可以满足 RP 的 step-up 要求，而 OP 用一个被签名的假 `auth_time` 为这次从未发生的认证背书。
- **修法**：让登录边界真正执行该要求：pending 请求 `RequiresReauthentication(now)` 时把浏览器送回 IdP 登录（`/auth/{provider}/start?mode=login`），只有新的 `SignIn` 盖过时间戳后才 `CompleteLogin`；否则绝不覆盖 `AuthTime`。`internal/oidcstore` 增加 `ErrReauthenticationRequired`，两后端 `CompleteLogin` 不再伪造。
- **状态**：FIXED（992710b）
- **证据**：`internal/oidcstore/zz_audit9_freshness_test.go`、`internal/store/memory/zz_audit9_reauth_test.go`、`internal/auth/zz_audit9_reauth_route_test.go`、`internal/zzprobe/protocol/audit9_basic_op_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）
- **首次记录**：第 9 轮


---

### S06-1 OIDC discovery / JWKS 用无上限 io.ReadAll 读取（自带 1 MiB 上限覆盖不到）
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **位置**：`idp/idp.go:298; idp/idp.go:711; idp/idp.go:836`
- **影响**：go-oidc 读 discovery 与 JWKS 时是裸 `io.ReadAll(resp.Body)`，唯一约束是 10s 超时（限时不限字节），且 net/http 透明解压 gzip，一个压缩炸弹可在一次正常登录中把进程 OOM。adapter 自己的 1 MiB 上限只作用于 userinfo/QQ。
- **修法**：把交给 `oidc.ClientContext` 的 client 包一层限流 RoundTripper（既查 ContentLength 也硬限 `resp.Body`），复用已有的 1 MiB 上限。
- **状态**：FIXED（992710b）
- **证据**：`idp/zz_audit9_discovery_body_test.go`、`idp.maxDiscoveryBytes`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）
- **首次记录**：第 9 轮


---

### S08-2 driver 由 dsn_env 推断时，storage.dsn_env 从不被解析 → 静默内存模式
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **位置**：`cmd/re0auth/config.go:680-710; cmd/re0auth/config.go:472; cmd/re0auth/config.go:722-724; cmd/re0auth/config.go:749-759; cmd/re0auth/main.go:892-917`
- **影响**：`databaseURL` 只从字面量 `DATABASE_URL` 预载。Driver 为空且 `dsn_env` 指向别的变量时，switch 把 driver 定为 postgres 却从不解析该变量，`openStorage` 按空 URL 走内存分支：不要求 `RE0AUTH_AUDIT_KEY`、审计链退化为内存 ring、重启丢全部状态、`max_in_flight` 按内存标定，且启动日志的 `because=""` 掩盖了原因。显式 driver 下环境里残留的 `DATABASE_URL` 还会盖过文件声明的变量。
- **修法**：推断分支用与显式分支相同的代码解析 DSN；声明了但未设置的变量按启动错误处理；文件的 `dsn_env` 优先于字面量 `DATABASE_URL`。
- **状态**：FIXED（992710b）
- **证据**：`cmd/re0auth/zz_audit9_dsnenv_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）
- **首次记录**：第 9 轮


---

### S10-1 并发上限的"单客户端半量"按 (平面,客户端) 计数，一个地址可吃满整个进程级信号量
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **位置**：`internal/httpapi/middleware.go:434; internal/httpapi/middleware.go:459; internal/httpapi/middleware.go:466; internal/httpapi/middleware.go:491`
- **影响**：信号量是进程级的，但每客户端计数按 `plane|client`：一个源地址在两个命名空间各拿 `maxInFlight/2`，合计等于整个上限（默认 512）。限流约束的是到达率而非占用槽位，探针又豁免两者，于是"一个地址打满全进程并发、其他客户端全 503，而 /healthz、/readyz 仍绿"这一正是该机制要防的 DoS 成立。
- **修法**：并发计数改按客户端身份（不含平面）累计；限流桶键保持 (平面,客户端)。
- **状态**：FIXED（992710b）
- **证据**：`internal/httpapi/zz_audit9_inflight_planes_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）
- **首次记录**：第 9 轮


---

### S13-1 压缩 406 拒绝在限流器与并发上限之前返回，完全绕过两道边界
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **位置**：`internal/httpapi/server.go:638; internal/httpapi/server.go:642; internal/httpapi/server.go:643; internal/compress/compress.go:147`
- **影响**：中间件链把 compressor 放在最外层，`negotiate` 不可接受时直接写 406 且不调用 `next`，于是限流令牌与并发槽位都不消耗，但 request-id、可信代理解析、访问日志与指标照付。任何匿名请求带 `Accept-Encoding: *;q=0` 即可无上限地驱动连接/goroutine 与日志洪泛。
- **修法**：把 compressor 移到限流与并发上限之内（`withRateLimit`/`withInFlightLimit` 包在外层）。
- **状态**：FIXED（992710b）
- **证据**：`internal/httpapi/zz_audit9_compress_bypass_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）
- **首次记录**：第 9 轮


---

### S14-2 CompleteBind 不取 per-binding 锁，在途绑定可复活刚被撤销的绑定与上游凭据
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **位置**：`internal/federation/bind.go:192; internal/federation/bind.go:198; internal/federation/unbind.go:50; internal/federation/revocation.go:132; internal/federation/killswitch.go:201; internal/federation/refresh.go:40`
- **影响**：per-binding keyedMutex 是"同一绑定只有一个写者"的机制，Unbind/CascadeRevoke/shredBinding/refreshBinding 都持它；只有 CompleteBind 既写 vault 又无条件 `bindings.Put`（忽略 Version）且不持锁。因此绑定回调与撤销并发时，可以在"已解绑/已 Kill Switch 扫过"之后重新造出可用的绑定行与上游令牌，而用户与运维被告知已断开。
- **修法**：CompleteBind 全程持同一把 per-binding 锁（必要时先重读行，确认未刚被解绑），或改成单个 CAS。
- **状态**：FIXED（992710b）
- **证据**：`internal/federation/zz_audit9_bind_unbind_race_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）
- **首次记录**：第 9 轮


---

### G-1 refresh token 重放被检测到之后，小偷那条链继续有效
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **上线阻断**：是
- **位置**：`internal/store/memory/oidc.go:211`（`ErrRefreshTokenSpent` 哨兵；返回处 `:556`，Postgres 对应 `internal/store/postgres/oidc.go:340` / `:399`）
- **影响**：refresh 是单次使用 + 轮换。小偷把偷到的第 2 代自己轮换成第 3 代后，合法客户端重放第 2 代（盗窃信号）只被拒，**第 3 代无人撤销**——攻击者保有静默访问直到 30 天 TTL 自然结束。「即时可撤销」卖点反面。
- **修法**：检测到已消费 refresh 重放时撤销该 (client, subject) 全部 refresh/access（RFC 9700 token family 撤销）。注意第 7 轮更正：检测点上被重放那行已被 delete，store 拿不到 subject/client，**必须先在轮换时留族/代号标识或墓碑**，否则修不出覆盖顺序重放的版本。
- **状态**：FIXED（79d7333）；探针已重推为回归守卫
- **证据**：`internal/zzprobe/audit6/z02protocoltoken/refresh_test.go::TestZ02RefreshReplayRevokesTheThiefsGeneration`（红）；`00-MAIN-VERIFICATION.md:249-267`（V-10 读码三点齐备）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:58`
- **首次记录**：第 6 轮


---

### G-2 生产后端（Postgres）的 refresh token 过期从不被裁决，30 天 TTL 只由 15 分钟一轮的 sweep 执行
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **上线阻断**：是
- **位置**：`internal/store/postgres/oidc.go:430`（SELECT 无 `expires_at` 谓词；轮换声明 `:392-401` 同）；对照内存 `internal/store/memory/oidc.go:573`
- **影响**：过期 refresh token 仍能换出**全新 30 天 TTL** 的 access+refresh（TTL 被重置而非拒绝）；sweep 连续失败时窗口继续延长（`cmd/re0auth/main.go:1111` 只打日志）。默认套件全跑内存后端，所以测试永远绿而生产行为不同。
- **修法**：`TokenRequestByRefreshToken` 的 SELECT 与轮换声明加 `expires_at > $n`（`$n` ← `s.now()`，保持单时钟政策）；两后端同形；`clock_test.go` 补「过期 refresh 被拒」。
- **状态**：FIXED（79d7333）；PG 侧端到端形状由 CI 的 postgres:16 定论
- **证据**：`00-MAIN-VERIFICATION.md:70-74`（V-01）；`05-memory-store.md:27-56`（HYPOTHESIS，差 `TEST_DATABASE_URL`）；`internal/zzprobe/audit6/z05memstore/drift_guards_test.go::TestMemoryRefusesAnExpiredRefreshToken`（绿，钉内存拒绝半边）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:75`
- **首次记录**：第 6 轮


---

### G-3 数据库故障时 RFC 7009 撤销回答 200，用户以为被盗令牌已撤销
- **严重度**：P0 · 阻断（原文记为「P1 · 阻断」；本寄存器按「是否阻断上线」归入 P0）
- **上线阻断**：是
- **位置**：`internal/store/postgres/oidc.go:474`
- **影响**：三个 owner 查找全部以 `err == nil` 为进入条件，任何错误（连接断开、故障切换、`statement_timeout`、ctx 取消）都落穿到 `:530` 的 `return nil` ⇒ 协议层按「未知令牌即成功」答 200 且**不写审计**。客户端按 RFC 7009 不再重试，令牌在库恢复后继续有效到自然过期（refresh 最长 30 天）。安全事件响应路径上的静默失效。
- **修法**：三个查找各接 `noRows(err)` 分类——只有 `pgx.ErrNoRows` 允许落穿；其余返回 `oidc.ErrServerError()`（映射 500，可重试）。照抄同文件 `TokenOwner`（`oauth.go:207`）的形状。
- **状态**：FIXED（79d7333）
- **证据**：`internal/zzprobe/audit6/z04pgstore/revocation_error_probe_test.go::TestRevokeTokenDoesNotReportSuccessWhenTheDatabaseCannotAnswer`（红）、`::TestRevokeTokenClassifiesOnlyNoRowsAsUnknownToken`（红）；`00-MAIN-VERIFICATION.md:76-80`（V-02）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:90`
- **首次记录**：第 6 轮

