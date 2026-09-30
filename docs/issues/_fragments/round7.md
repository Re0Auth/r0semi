# 第 7 轮 · 抽取结果

## P0/P1

### Z07-2 抹除链最后一步失败时审计日志唯一记录谎报成功，500 文案却承诺「审计记录了失败的那一步」
- **位置**：`internal/lifecycle/lifecycle.go:262`
- **影响**：受 `Destroy` 失败影响的账号，其审计里唯一一条记录写的是 `outcome=ok` + `pseudonym_destroyed=true`（假名钥匙仍在、仍可归因到被抹除账号），运维据此得到「审计史已不可链接」的错误结论——合规意义上的「抹除已证明完成」是假的；失败路径连一行 `slog` 都没有（`internal/httpapi/account_routes.go:54-65`），运维拿不到任何反向信号，而 500 文案「the audit log records the step that failed」对这一条是假的。
- **修法**：在 `lifecycle.go:277-283` 的失败分支补第二条记录：先把 `res.PseudonymDestroyed` 复位为 false，再 `d.record(ctx, actor, subject, audit.OutcomeError, res, "pseudonym")`（或调 `d.fail`）。**不要**把 `:269` 的成功记录挪到 `Destroy` 之后——记录本身会重新铸钥匙，代码注释已解释原因，所以应补而非挪。（此为修复建议，非裁定。）
- **状态**：FIXED（a3de9b9）
- **证据**：探针 `erasure_test.go::TestZ07ErasureAuditRecordClaimsSuccessWhileTheHistoryStaysLinkable`（红，真 `DELETE /v1/account`）；阳性对照 `::TestZ07ErasureWithAWorkingDestroyIsRecorded`（绿）；第六轮独立夹具 `internal/zzprobe/audit6/z07authsession/erasure_audit_test.go::TestProbeErasure` 同样红（三个断言字符串逐字对上）。
- **来源**：`docs/audit-7/findings/Z07-VERIFIED.md:46`（裁定表 P1）、`Z07-VERIFIED.md:71-79`（独立证据）；主代理确认 `docs/audit-7/findings/00-MAIN-VERIFICATION.md:228-238`

### Z11-1 / Z12-7 一次匿名 connect-then-hangup 把 `/readyz` 结果缓存成 503，健康实例被 kubelet 摘出流量
- **位置**：`internal/httpapi/health.go:122`（缓存 `:111-133`；探针豁免 `:151-166`；探针周期 `deploy/k8s/base/deployment.yaml:96-100`）
- **影响**：匿名者每一个 TTL 内赢一次「触发者」竞争（实测 1ms 依赖 8/8、瞬时依赖 5/8 命中）即可让健康副本持续答 503；kubelet `periodSeconds 5 / failureThreshold 3` ⇒ 15 秒内摘除端点，全副本可被匿名削减容量直至整体不可用；原因只进 `slog.Debug`，默认日志级别不可见。
- **修法**：就绪检查改用不派生自调用方生命周期的上下文（`context.WithoutCancel(r.Context())` 或 `context.Background()`）+ `readinessTimeout`，取消类错误不写缓存。**这是裁定**：共享缓存是全进程的，调用方取消从来不是它的语义。
- **状态**：FIXED（98b3c11）
- **证据**：`readyz_poison_test.go::TestZ11CallerCancellationDoesNotPoisonReadiness`（红）；`z11verify/readyz_race_test.go`（1ms 依赖 8/8）；`z12verify/verify_readyz_test.go::...SustainedHangUpsHoldReadyzDown`（红，持续挂断可持久化 503）；机制源码 `health.go:94/:122-133` 经主代理读码确认。
- **来源**：`docs/audit-7/findings/Z11-VERIFIED.md:12,58-68`；`docs/audit-7/findings/Z12-VERIFIED.md:87-108`；`docs/audit-7/findings/00-MAIN-VERIFICATION.md:496-511`（合并裁定见 Z11-VERIFIED.md:67-68）

### Z11-4 桶表被单个 IPv6 /64 填满后，所有新客户端共用一个兜底桶并被 429
- **位置**：`internal/ratelimit/ratelimit.go:199-215`（键构造 `internal/httpapi/middleware.go:349`；`reclaimLocked` `:226-240`）
- **影响**：任何**新**客户端（新 IP、重新拨号、NAT 出口变化）在三个平面上全部 429，登录/授权/数据面一起不可用；已被跟踪的客户端不受影响。进程不崩、探针照常 200，k8s 不重启也不摘除 ⇒ 故障静默。
- **修法**（裁定）：① overflow 桶按调用方分摊（每键一小桶 + LRU/计数上限）；② 或只拒绝重复进入 overflow 的客户端；③ 或 IPv6 地址按 /64 归并（与 P0-4 相反方向的取舍）。三条都需改 `operations-decision.md:49` 措辞。
- **状态**：FIXED（98b3c11）
- **证据**：`ratelimit_saturation_test.go::TestZ11OneIPv6Slash64CannotFillTheBucketTable`（红）；复核真中间件链 `ratelimit_http_test.go::TestZ11VOneIPv6Slash64CannotStarveUnrelatedClients`（空限流器 401 阳性对照 → 填满排空后 429）；绿对照 `TestZ11AtCapacityTheTableStaysBounded`。
- **来源**：`docs/audit-7/findings/Z11-VERIFIED.md:15,102-104`；`docs/audit-7/findings/00-MAIN-VERIFICATION.md:480-494`

### Z11-5 全进程一个 in-flight 信号量且不按调用方分摊：一个地址占满全部槽位，其他客户端全 503 而探针仍 200
- **位置**：`internal/httpapi/middleware.go:393-419`（外层顺序 `internal/httpapi/server.go:621-624`；ReadTimeout `cmd/re0auth/main.go:116`）
- **影响**：一个匿名地址（约 130 个慢 body socket、~5 req/s）即可持续占满 `max_in_flight`，让所有其他客户端在两个平面持续 503；`/healthz`、`/readyz` 全绿 ⇒ 编排器不摘除、不重启，故障对运维不可见地持续。
- **修法**（裁定）：① 槽位按 `(plane, client)` 分摊（每客户端上限 = `maxInFlight` 的一个分数 + 共享余量）；② 或把限流令牌绑在 in-flight 上而不是到达上；③ 至少给慢 body 一个远短于 `ReadTimeout` 的期限。
- **状态**：FIXED（98b3c11）
- **证据**：`inflight_test.go::TestZ11OneAddressCannotHoldEveryInFlightSlot`（红，`max_in_flight=2` 下另一源地址 503 而探针 200）；`server.go:621-624`、`main.go:116/775-779` 逐行核对；主代理读码 `middleware.go:393-405`。
- **来源**：`docs/audit-7/findings/Z11-VERIFIED.md:16,118-121`；`docs/audit-7/findings/00-MAIN-VERIFICATION.md:470-478`

### Z11-V1 探针豁免绕过两道上限，却绕过不了会话中间件：一个匿名 Cookie 让每次 `/healthz`、`/readyz` 都变成一次连接池往返
- **位置**：`internal/httpapi/server.go:616-624`（`isProbe` `internal/httpapi/health.go:164`、`internal/httpapi/middleware.go:335/399`；scs `postgres/sessions.go:75-82`）
- **影响**：匿名者用任意 Cookie 打 `/readyz`（免限流、免并发上限，不受 `max_in_flight` 约束）即可按请求数驱动池往返 ⇒ 池排队，正常登录/授权请求被饿。持有效 Cookie 时 scs 因 `IdleTimeout>0` 把每次探针标 `Modified` ⇒ 每请求一次写。违反 `docs/operations.md:171-183`「探针必须便宜、每副本每秒最多一次往返」。
- **修法**（裁定）：`isProbe` 的豁免也跳过 `sessions.LoadAndSave`（把探针挂在会话中间件之外），或对带 Cookie 的探针请求走限流。同步修 `docs/operations.md:177-183` 措辞。
- **状态**：FIXED（98b3c11）
- **证据**：`internal/zzprobe/audit7/z11verify/probe_session_store_test.go::TestZ11VProbePathSkipsTheSessionStore`（红）：`control cookie-less /readyz = 0 lookups`、`control /v1/me = 1 lookup`、`finding 20 cookie-bearing /readyz = 20 lookups`。
- **来源**：`docs/audit-7/findings/Z11-VERIFIED.md:72-94`

### Z12-3 首个 seed 之后 `[client]` 的任何改动都被静默忽略
- **位置**：`cmd/re0auth/main.go:1583-1591`
- **影响**：① 给 `client.secret_env` 加秘密以为变成机密客户端，实际仍是公开客户端（内省守卫会对它 401）——更重的是轮换 secret 时**旧 secret 仍然有效**；② 改 `redirect_uris` 后回调走旧地址，**删**生产回调地址不生效（本该撤销的回调留在白名单）；③ scopes 既不能加也不能收。日志只在第一次启动说 `registered`。
- **修法**：`Get` 命中后比对 type/redirects/scopes/secret-hash，不一致**拒绝启动**并点名字段。**这是一次裁定**（会改上线流程）。
- **状态**：FIXED（657d2f0）
- **证据**：`z12seedclient_test.go::TestZ12SeedClientNeverReconcilesTheConfiguredClient`（红）；复核端到端真二进制 + `admin_routes.go:100-189` 无任何改写既有 client 的入口；`config.go:780-794` 的 `[client]` 唯一读点在 `seedClient`。
- **来源**：`docs/audit-7/findings/Z12-VERIFIED.md:41-50`；`docs/audit-7/findings/00-MAIN-VERIFICATION.md:438-450`

### Z13V-2 `scripts/restore.sh` 在自身 `set -euo pipefail` 下无法执行：恢复路径 100% 死
- **位置**：`scripts/restore.sh:29`
- **影响**：`docs/operations.md:94` 与 `:281` 的恢复/演练命令在装有当前 bash 的主机上直接 `line 29: file: unbound variable` 退出 1，永远到不了边车校验；备份再正确也不能恢复。第五轮 P2-11 的修复**从未被执行过**。
- **修法**：拆成 `local file="$1"` 与 `local sidecar="$file.sha256" want got` 两条（同文件临时副本已证明可通）。
- **状态**：FIXED（a3de9b9）
- **证据**：`z13verify_test.go::TestZ13VRestoreScriptVerifierRunsAndVerifies`（红）；真 bash 5.3.9（含 `env -i`）实跑复现 `unbound variable`；修正副本跑通 `checksum verified … STUB pg_restore … restore complete` exit 0 且三条守卫按报告正确拒绝。
- **来源**：`docs/audit-7/findings/Z13-VERIFIED.md:64-80`

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| Z07-1 | P2 | pending 同意句柄的 TTL 在两个后端的 by-ID 读/决策路径上都不裁决，只靠 15 分钟一轮 sweep 执行（sweep 停摆则永不过期） | `internal/store/memory/oidc.go:402-410` | FIXED（b17c76f） | `AuthRequestByID` 内存版补过期判据、PG 版加 `AND expires_at > $2`，并补「过期 auth request 的 by-ID 读被拒」测试；依据 `Z07-VERIFIED.md:45`、`00-MAIN-VERIFICATION.md` 无对应节 |
| Z07-3 | P2 | 设备验证页把调用方可控的 user_code 原样绑进浏览器会话：实测 32 次导航把单会话堆到 1 807 500 B（≈1.72 MiB；产品自设上限为 64 KiB，非原报告的 1 MiB） | `internal/httpapi/device_routes.go:69` | FIXED（4dff4a3） | 绑定/回显都用 `oauth.NormalizeUserCode(userCode)` 的规范值，并给 `Bind` 的 id 加字节上限；依据 `Z07-VERIFIED.md:47`、`Z07-VERIFIED.md:81-94` |
| Z07-4 | P3 | CSRF 令牌创建是「后写者赢」竞态：并发首读者拿到服务端不认的令牌（4 个不同令牌中 3 个被拒） | `internal/auth/auth.go:238-245` | OPEN | 令牌由会话确定性导出（如 `HMAC(serverKey, sessionToken)`）或对「首次创建」做 compare-and-set；依据 `Z07-VERIFIED.md:48` |
| Z07-5 | P3 | 设备决策要求调用方原样拼写 user_code，而查找走规范化 ⇒ 同一设备码两个答案（规范拼写反而 404） | `internal/httpapi/device_routes.go:108-112` | OPEN | 决策前先 `oauth.NormalizeUserCode(body.UserCode)`，并修正 `oauth/device.go:479` 与实现不符的注释；依据 `Z07-VERIFIED.md:49` |
| Z07-6 | P3 | `POST /v1/sessions/sign_out` 对无会话请求答 403（CSRF），是本平面唯一一个（其余写端点均先会话后 CSRF） | `internal/httpapi/session_routes.go:66-70` | OPEN | 与其它写端点同序：先 `sessions.User`→401，再 `ValidCSRF`→403；注意前端 `needsSignIn` 判的是 problem code `unauthenticated` 而非状态码；依据 `Z07-VERIFIED.md:50`、`Z07-VERIFIED.md:96-108` |
| Z07-7 | P3 | 账号行已消失但会话仍在时，`/v1/sessions/current` 与 `/v1/account/export` 答 500 而非丢弃会话（401）；生产侧修复为「需与该账号会话擦除并发的极小窗口」 | `internal/httpapi/session_routes.go:27-31` | OPEN | 两个处理器把 `account.ErrNotFound` 映射为「销毁会话 + 401 unauthenticated」；依据 `Z07-VERIFIED.md:51`、`Z07-VERIFIED.md:131-137` |
| Z07-8 | P3 | link 流程用 `?error=identity_taken` 确认某个外部身份是否已有 Re0Auth 账号（login 模式对同一事实不泄露） | `internal/auth/auth.go:675-693` | OPEN | 把「已被他人占用」与「链接失败」合并为同一回跳码，或按 provider 限速；影响被复核收窄（须先能以该身份登录 IdP）；依据 `Z07-VERIFIED.md:52`、`Z07-VERIFIED.md:110-118` |
| Z07-9 | P3 | 不可逆的账号自我抹除不要求近期重新认证，而同代码已对可逆管理面写操作实现 `AuthenticatedAt` step-up | `internal/httpapi/account_routes.go:32-41` | OPEN | 给 `handleDeleteAccount` 加与 `requireAdminWrite`（`admin_routes.go:77-97`）同形的窗口检查，失败返回 `403 reauth_required`；属裁定项（会改变交互）；依据 `Z07-VERIFIED.md:53`、`Z07-VERIFIED.md:120-129` |
| NF-Z07-1 | P3 | `/bind` 归属守卫是单侧的：探针只证明「B 被拒」，无法区分「B 被拒」与「所有人被拒」（守卫空洞，非产品漏洞） | `internal/zzprobe/audit7/z07authsessionlifecycle/handle_binding_test.go` | OPEN | 在该探针补一步「A 自己用同一 state 打 callback」的对照，断言其不是 400（夹具下应为 303 `bind_failed`）；依据 `Z07-VERIFIED.md:165-186` |
| Z08-3 | P3 | 残余新增项：`/app/favicon.svg` 与 `/app/robots.txt` 副本无任何 `Cache-Control`（核心 `_app/version.json` 无缓存指令部分重报第五轮 V-4；`/app/robots.txt` 副本按 `webui.go:69-82` 本不该被爬虫读到） | `internal/webui/webui.go:143-150` | OPEN | 把 `setCacheHeaders` 默认值写成「除 `_app/immutable/` 外一律 `no-cache`」，`version.json` 用 `no-store`；依据 `Z08-VERIFIED.md:19`、`Z08-VERIFIED.md:49-55` |
| Z08-5 | P3 | `_app/immutable/*` 标 `public, max-age=31536000, immutable`，但会话中间件（scs `LoadAndSave`）给每个响应加 `Vary: Cookie` ⇒ 共享缓存按整个 Cookie 分键，`immutable` 名存实亡（安全影响为零，纯部署成本） | `internal/webui/webui.go:145-146` | OPEN | 在 `webui.Handler` 对 `_app/immutable/` 分支 `w.Header().Del("Vary")`（压缩层随后补 `Accept-Encoding`），或把 `/app/*` 移出 `sessions.LoadAndSave`；并加守卫断言无 `Cookie` Vary token；依据 `Z08-VERIFIED.md:21`、`Z08-VERIFIED.md:63-74`、`00-MAIN-VERIFICATION.md:295-303` |
| Z08-7 | P3 | 设备决策端点的未知 `decision` 值被静默当成「拒绝」并消耗掉设备码（与同意端点的 `switch` 校验不一致，且违背 openapi 的 `enum` 契约） | `internal/httpapi/device_routes.go:114-115` | OPEN | 读 `user_code` 后加与同意端点同形的白名单 `switch`，未知值回 `400 invalid_request`；依据 `Z08-VERIFIED.md:23`、`Z08-VERIFIED.md:85-94` |
| Z08-8 | P3 | 账户页把 `?error=` 原始值插进 DOM（已转义、非 XSS），构成受长度限制的 UI 欺骗/钓鱼画布 | `web/src/routes/+page.svelte:63-84` | OPEN | `authErrorMessage` 的 `default` 分支改为固定文案（不回显 `code`），或仅白名单前缀映射；依据 `Z08-VERIFIED.md:24`、`Z08-VERIFIED.md:96-103` |
| Z08V-1 | P3 | 「开放重定向面」的绿是假守卫：内存模式无 IdP，`/auth/{p}/start` 回 404、`/bind` 匿名回 401，探针永远到不了任何重定向 sink（产品无洞，是报告守卫无效） | `internal/zzprobe/audit7/z08frontendbrowser/realproc_test.go` | OPEN | 删掉该条「探过没破」，或用已配 provider 的全接线夹具走完 start→callback 再断言 `Location`；依据 `Z08-VERIFIED.md:25`、`Z08-VERIFIED.md:114-128` |
| Z08V-2 | P3 | Z08-3 的「构建产物无 `version.json` 引用」是错的：产物 `chunks/DqohD3-m.js` 确实带 `fetch(.../_app/version.json)` 与版本比对逻辑（方向是低估风险） | `docs/audit-7/findings/Z08-frontend-browser.md:133` | OPEN | 更正该事实，并据此给 `_app/version.json` 明确缓存指令；依据 `Z08-VERIFIED.md:26`、`Z08-VERIFIED.md:130-136` |
| Z09-1 | P2 | `sources[].status` 无词汇表闸门：任何拼写变体（`Retired`/`retired `/`disabled`）被静默当作可服务源继续读取，并继续决定**另一个源**的 scope 闸门 | `internal/federation/federation.go:53-62` | OPEN | 照 `token_class` 同形在 `NewRegistry` 加显式 switch、词表外值拒绝启动（拒绝 vs 归一化是裁定）；同时更正 CS-4 的假文档断言 | 
| Z09-4 | P2 | 缓冲预算全局先到先得、无 per-subject 分摊：15 个 raw 并发读（零字节或 ≥4 MiB body）即把其他用户的满额读 shed 成 503 | `internal/federation/service.go:108-113` | FIXED（6665193） | 三选一（裁定）：按调用方配额 / 按已读字节预留 / 首字节期限；并在 `MaxBufferedBytes` 注释写明"全局先到先得" | 
| Z09V-1 | P2 | 共享 per-host 熔断器把"一个账号凭据坏了"当"源坏了"：5 次 401 让**其他账号** 30s 内读不到该源 | `httpclient/circuitbreaker.go:196-204` | FIXED（b17c76f） | 401 按调用方/binding 计失败而非 host 熔断（裁定）；P1-3 目标用"同一 binding 连续 N 次 401 ⇒ 该 binding 冷却"达成 | 
| Z09-2 | P3 | 归一化读没有"超过上限即拒绝"：4 MiB 上游体被静默截断后作为完整的 200 交出（`json.Valid` 接受尾随空白） | `internal/federation/service.go:760-775` | OPEN | 照抄 raw 两行：`LimitReader(..., maxBody+1)` + `len(body)>maxBody → ErrResponseTooLarge` | 
| Z09-3 | P3 | 已退役的源仍可被绑定：`BeginBind`/`CompleteBind` 无 `Status` 判据，上游令牌被存进 vault 而数据面永不使用 | `internal/federation/bind.go:127-152` | OPEN | `registry.Get` 之后加 `Status == StatusRetired → ErrSourceRetired`（两处都要） | 
| Z09V-2 | P3 | `refreshRejected` 把存储读失败当成"版本没动"：一次读故障即删绑定行并 crypto-shred vault 密钥（可能撕掉仍有效的绑定） | `internal/federation/refresh.go:143-159` | OPEN-PG | 重读的非 `ErrNotBound` 错误向上返回，不落入破坏性分支 | 
| Z09V-3 | P3 | `Issuer = "//evil.example"` 时 `/bind` 302 到**另一个 origin**（开放重定向/钓鱼面） | `internal/federation/federation.go:144-146` | OPEN | 对 `Issuer` 照 `validateRawBase` 校验 `Scheme∈{http,https} && Host != ""` | 
| Z10-1 | P3 | 跨实例假名缓存使抹除失效：被抹除账号的审计历史在**另一副本**上继续可读、可续写（非窗口而是稳态） | `internal/store/postgres/auditpseudo.go:69-75` | OPEN-PG | 墓碑集合 / cache TTL；并把 `docs/architecture.md:661-662` 改成实话 | 
| Z10-2 | P3 | 链前伪造的未签名行被 `Verify` 判 `ok`：legacy（NULL 哈希）行没有上界，"迁移前行"与"伪造行"同形 | `internal/store/postgres/auditchain.go:270-282` | OPEN-PG | 给 `audit_chain` 加 `legacy_ceiling_id`，`id > ceiling && row_hash IS NULL` 即判失败 | 
| Z10-4 | P3 | 无会话端口时 Kill Switch 对 sessions 半边沉默：`sessions_revoked:0` 与"该账号没有会话"同形 | `internal/admin/admin.go:351-368` | OPEN | `Report` 加 `SessionsUnavailable` 并进 `killDetail`（与 `BindingsUnavailable` 同款） | 
| Z10-5 | P3 | 扫描失败时 HTTP 面丢弃已完成的摘要，只回 problem+json | `internal/httpapi/admin_routes.go:281-282` | OPEN | 失败路径也写一条 `outcome=error` 记录，Detail 带 tokens/sessions/bindings_error（响应体形状取舍是裁定） | 
| Z10-6 | P3 | P2-22 的修法只覆盖分页读：`/v1/admin/audit/verify`（全库扫描）与 `/head` 零记录 | `internal/httpapi/audit_routes.go:171-211` | OPEN | 两个 handler 各写 `admin.audit.verify` / `admin.audit.head` 记录 | 
| Z10-7 | P3 | 审计读接口可无写侧装配成功：`Config.Audit != nil, AuditLog == nil` 时 P2-22 的记录静默变空操作 | `internal/httpapi/server.go:297-304` | OPEN | `httpapi.New` 增加 `Config.Audit requires Config.AuditLog` 断言 | 
| Z10-8 | P3 | `admin.*` 行把 **client_id** 假名化且 `Detail` 无补偿字段：读接口答不出"哪个客户端" | `internal/admin/admin.go:439-447` | OPEN-PG | 给 `admin.*` 事件 Detail 补 `client_id`（`oidc.token` 已有先例） | 
| Z10-9 | P3 | `Verify` 不校验链头与最后一行一致：链头指向任何行都不拥有的哈希时仍答 `ok` | `internal/store/postgres/auditchain.go:318-328` | OPEN-PG | 遍历后 `bytes.Equal(prev, head)`，不一致即 `ok=false` + Reason | 
| Z10V-1 | P3 | Kill Switch **失败路径**审计行漏记 `sessions_revoked`（会话已被切掉，持久记录里没有这个数） | `internal/admin/admin.go:389-391` | OPEN | 三条失败路径 Detail 加 `sessions_revoked`，或统一让失败路径走 `killDetail` | 
| Z10V-2 | P3 | 内部监听器排空**没有自己的预算**：排在公网监听器之后共享同一个 30s `drainCtx`，第一个吃满时第二个得 0s | `cmd/re0auth/main.go:840-849` | OPEN | 每个 endpoint 各自 deadline / 内部监听器直接 `Close` / 改写 `shutdownTimeout` 语义并同步注释（裁定） | 
| Z11-2 | P2 | 上游字节预算在写响应体之前就释放：预算约束的是读，不是被持有的 body（P0-3 修复不全）。**复核更正**：探针「body 被持有」前提在本机不成立（48/48 handler 已返回），证据等级由「探针测到」降为「源级 CONFIRMED + Linux 平台推论」 | `internal/federation/service.go:725-729`（写 body `internal/httpapi/federation_routes.go:296-297`） | FIXED（b17c76f） | 预留生命周期挂到 body 持有者（`RawResult` 携带 `release`，`w.Write` 后释放），或按「已读+已写字节」计费 |
| Z11-3 | P2 | 调用方写的 `X-Request-Id` 无长度/字符集上限，被原样回显进响应头并写进访问日志（60 000 字节 ⇒ `echoed=60000 logged=60157`） | `internal/httpapi/middleware.go:138-142`（`:262` 入日志） | FIXED（6665193） | 仅 `len <= 128` 且字符集 `[A-Za-z0-9._-]` 时采信，否则生成新值；回显与日志都用清洗后的值 |
| Z12-1 | P2 | 缺 `id:` 前缀的 `RE0AUTH_OIDC_RETIRED_TOKEN_KEYS` 把密钥原文打进启动日志（退役密钥仍解密轮换前签发的 access token） | `cmd/re0auth/main.go:1410`（`:1414` 同形） | FIXED（17914d4） | 消息只报位置/形状；CS-8 守卫补 plant 该变量 |
| Z12-2 | P2 | `-rotate-keys` 扫到 0 条时退 0，恰好满足文档写下的放行闸门（「`rewrapped=0 skipped=0` 且退出 0」） | `cmd/re0auth/main.go:1209-1231`（文档闸门 `config/re0auth.example.toml:229-231`） | FIXED（b17c76f） | `Scanned == 0` 时非零退出 |
| Z12-4 | P2 | 文件里配的列表无法被环境清空（`RE0AUTH_ADMIN_SUBJECTS=""` ≠ 无人）：空串被当未设置，`/v1/admin` 仍挂着且无日志 | `cmd/re0auth/config.go:799`（`:564`、`:655`） | FIXED（b17c76f） | 与 `rate_limit` 同形用指针区分缺省与显式空，或启动日志公布三个列表生效长度 |
| Z12-6 | P2 | `rate_limit = NaN` 被接受并让限流器**放行一切**；复核补强：`+Inf` 语义同为永远允许，TOML 小写 `nan` 也成立（大写 `NaN` 被拒） | `cmd/re0auth/config.go:512-522`（`main.go:225-228`） | FIXED（b17c76f） | 解析后加 `math.IsNaN/IsInf` 即拒，判据改成非 NaN 安全形式 |
| Z12-9 | P2 | 文件里的池大小被截断到 int32（`4294967297` 读成 1、`4294967296` 读成 0），环境变量路径却拒绝越界值——两路径语义不一致 | `cmd/re0auth/config.go:1062-1067`（环境路径 `:1116-1126`） | OPEN-PG | 先做 `math.MinInt32/MaxInt32` 范围检查，或字段声明为 `*int32`；真 pgxpool 实际池大小只能在真 Postgres 上定论 |
| Z13-1 | P2 | 两个备份脚本默认输出目录 `./backups` 既不在 `.gitignore` 也不在 `.dockerignore`；一次 `git add -A` 送上 KEK 与全部长期密钥 | `scripts/backup.sh:12`、`scripts/backup-keys.sh:23` | FIXED（17914d4） | `.gitignore` 与 `.dockerignore` 各加 `/backups/`、`*.dump`、`*.env`（或默认落点改 `$TMPDIR`/必填） |
| Z13-3 | P2 | 运行镜像不带 npm 归属清单，而 Makefile 自己要求它随「每个二进制、归档和镜像」分发（SPA 经 `go:embed` 进同一二进制） | `Dockerfile:74`（`Makefile:205-221`） | FIXED（17914d4） | web 阶段落 `pnpm licenses list --json` 到 `/out/`，runtime `COPY`，并更新 `workflows_test.go:21-41` 与 `artifacts_test.go:606` 两处白名单 |
| Z13-4 | P2（age 半）/ P3（umask 半） | `backup-keys.sh` 的 umask 与 age 检查都在它们该保护的东西之后：age 缺失时明文密钥 env 残留（复核升 P2、与 P2-14 同形）；`mkdir` 早于 `umask 077`（umask 半维持 P3，权限位本机 noacl 无效、不采信） | `scripts/backup-keys.sh:24`（`:72`、`:73/:45`、`:100`） | FIXED（6665193） | `umask 077` 提到 `:24` 之前；age 存在性与 recipient 检查提到 `: > "$out"` 之前，或整段写入放 `mktemp -d` 并失败清理 |
| Z13V-1 | P2 | `.dockerignore` 只覆盖了 `.gitignore` 的一部分：审计工作区（`scratchpad/`，内含真 `keys.env` KEK + OIDC PEM 私钥）也进构建上下文与 backend 层 | `.dockerignore`（无行号；`.gitignore:70/:37/:46/:23/:29`） | FIXED（17914d4） | `.dockerignore` 加 `scratchpad`、`go.work`、`go.work.sum`、`*.local.toml`、`*.out`、`bench.txt`、`load.txt`、`report.md` |
| Z11-6 | P3 | `ResponseHeaderTimeout` 默认 30s 高于出站客户端默认 `Timeout` 20s，与自身注释相反。**复核更正影响句**：报告称「错误退化为 `context deadline exceeded`」是错的，Go 仍写成 `(Client.Timeout exceeded while awaiting headers)`、仍点名 headers 阶段 | `httpclient/outbound.go:36-39`（默认 `:53-63`、`:261`；`cmd/re0auth/main.go:492-507`） | OPEN | 把默认值改到低于整体 `Timeout`（如 15s）；无安全影响 |
| Z12-5 | P3 | `-migrate-down` 先跑整套 serving 期校验，缺审计链密钥就无法回滚（拒绝理由与回滚无关） | `cmd/re0auth/main.go:332`（`:369-371`、`:1158-1166`） | OPEN | 给 `loadConfig` 一个「只解析 DSN/池」的模式（仍拒它真用得到的坏值）。这是一次裁定 |
| Z12-8 | P3 | 位置参数从不检查：漏掉横线的 flag 被静默忽略（`-rotate-keys` 写成 `rotate-keys` 时进程照常起服务） | `cmd/re0auth/main.go:259` | OPEN | `if flag.NArg() > 0 { ...; os.Exit(2) }` |
| Z12V-1 | P3 | KEK 的解析**不**遵循文件声明的变量名：硬编码 `RE0AUTH_KEK` 先于 `vault.kek_env`，`KEKID` 亦脱钩 | `cmd/re0auth/config.go:721-731`（`:465`） | OPEN | `kek_env` 存在时**只**读它（或两者不一致时拒绝启动并点名），`KEKID` 同理从文件段取值 |
| Z12V-3 | P3 | `envInt32` 的越界报文自称「不是整数」（`4294967297` 实为整数、只是超出 int32） | `cmd/re0auth/config.go:1121-1123` | OPEN | 区分 `ErrRange` 与语法错误，报文写「out of range for a 32-bit pool size」 |
| Z13-2 | P3 | 版本 tag 先于 Trivy 进 GHCR（`push: true` 在 scan 之前）；`cosign sign` 晚于 `latest` 提升 | `.github/workflows/release.yml:64-71`（scan `:100-107`） | OPEN | `build-push-action` 改 `push: false, load: true` → 扫本地 → 再 push；把 `cosign sign` 挪到 `promote to latest` 之前。**复核：P3 不要升** |
| Z13-5 | P3 | `internal/archtest` 的写权限门只看 workflow 级 `permissions`，job 级越权不响（仓库已有真实 job 级 `security-events: write` 未被看见） | `internal/archtest/workflows_test.go:280-312` | OPEN | 下钻 `jobs.*.permissions`，断言写 scope 只出现在已知需要它的 job 名单里（名单写成测试常量） |
| Z13-6 | P3 | npm 归属清单是否被 `SHA256SUMS` 覆盖，没有守卫；**与 Z16-4 同守卫同根因，复核建议合并为一** | `Makefile:219`（`internal/archtest/workflows_test.go:16-20`） | OPEN | 门禁加「走向真实产出路径」的断言（解出 `checksums` glob 逐个匹配文件名），或改显式列表而非通配 |
| Z13-7 | P3 | README 对发布产物与镜像内容的描述与产物不符（未提 npm 清单；称镜像「只带二进制与 CA 证书」而 `Dockerfile:74` 已 COPY LICENSE/NOTICE） | `README.md:129-132`（`:160`） | OPEN | README 补 npm 清单文件名与用途；镜像那句改成含 LICENSE、NOTICE |
| Z14-1 | P2 | 级联撤销失败后 refresh token 已被源消费，Re0Auth 的「重试」永远解不出 subject，该绑定「登出全部设备」永久不可用 | `referencesource/cascade.go:52-55,80-86` | FIXED（b17c76f） | 先非破坏性解析 subject、上游成功后再消费，并把 `upstream-protocol.md:162` 与 `server.go:85-86` 改成「仅成功后 MAY consume」（来源：`Z14-VERIFIED.md:24-25`） |
| Z14-2 | P2 | 一致性套件对 `/oauth/revoke` 认证零断言，谁都能吊销的数据源被判 compliant（对 KIT-7 只修了 cascade 一半的补充） | `upstreamkit/conformance/conformance.go:253-265` | FIXED（4dff4a3） | `checkRevocationEndpoint` 对无凭据 POST 断言非 2xx，并给 `token.rejects_bad_grant` 加未知 client 判据（来源：`Z14-VERIFIED.md:39-40`） |
| Z14-3 | P2 | `jwks_uri` 不与 issuer 绑定，能左右 discovery 的一方用自控私钥伪造任意 sub（对 RP-3 修复的补充：钉了 2 个端点、漏第 3 个） | `idp/idp.go:486-509` | FIXED（17914d4） | `pinToIssuer` 纳入 `jwks_uri`（空值跳过）并接到 verifier 路径；该 scope-out 按裁定应本轮收回（来源：`Z14-VERIFIED.md:51-61`、`00-MAIN-VERIFICATION.md:411-424`） |
| Z14-4 | P2 | discovery 持续失败时 provider 缓存回退使退役密钥无限期验签成功（RP-2 的 TTL 被旁路，窗口从 15 分钟变成「故障持续多久」） | `idp/idp.go:619-637` | FIXED（4dff4a3） | 保留旧 provider 的同时保留其年龄，超过硬上界（如 `2×TTL`）即 fail-closed（来源：`Z14-VERIFIED.md:63-70`、`00-MAIN-VERIFICATION.md:426-436`） |
| Z14-5 | P3 | 只配 `auth_url`（未配 `token_url`）时显式端点被静默丢弃，登录静默走别的端点 | `idp/idp.go:466-481` | OPEN | 任一非空即进入显式模式，discovery 只填空字段（来源：`Z14-VERIFIED.md:72-79`） |
| Z14-6 | P3 | 参考数据源 TapTap 登录完成不绑定浏览器：加载 poll URL 即可以攻击者身份登录（会话固定/登录 CSRF） | `referencesource/taptap.go:219-226`、`referencesource/source.go:293-304` | OPEN | challenge 时把 attempt id 写入会话、poll 时比对，或校验 `Sec-Fetch-Site`/同源 `Origin`（来源：`Z14-VERIFIED.md:81-89`） |
| Z14-V1 | P3 | 套件用目标 origin 去判文档广告的端点：撤销端点被硬编码路径替代、级联端点丢弃 origin，合规源被误杀/「开放」端点假 PASS | `upstreamkit/conformance/conformance.go:255,288-296` | OPEN | `checkRevocationEndpoint` 改读 `disc.OAuth.RevocationEndpoint`（解析失败即 error），级联直接对绝对 URL 发请求（来源：`Z14-VERIFIED.md:95-134`） |
| Z15-1 | P2 | 过期清扫十条 DELETE 全无 `LIMIT` 且同一事务，撞 30 s 语句超时后每 tick 重试同一份越积越大的工作 | `internal/store/postgres/sweep.go:50-68` | FIXED（4dff4a3） | 每表改有界批（`ctid IN (… LIMIT $2)`）+ 有界推进预算 + 导出 sweep 计数；「每表一个事务」推翻文档化决定，须按裁定处理（来源：`Z15-VERIFIED.md:29-44`、`00-MAIN-VERIFICATION.md:392-409`） |
| Z15-2 | P3 | `BenchmarkTokenLifecycleWithJanitor` 的守卫在固定迭代数下不可达：`-benchtime=200x` 报 `peak_records=0` 且 exit 0，CI 正是 200x | `internal/store/memory/oidc_bench_test.go:79-91` | OPEN | 判据与 `b.N` 成比例（`\|\| i == b.N-1`），或 `b.N < sweepEvery` 直接 Fatalf（来源：`Z15-VERIFIED.md:46-56`） |
| Z15-3 | P3 | 内存 store 的 `DeleteAuthRequest` 在全局锁下遍历全部待兑换 code（Postgres 走 `oidc_codes(request_id)` 索引） | `internal/store/memory/oidc.go:449-468` | OPEN | 加 `codeByRequest`（requestID→TokenHash）并在同一临界区维护（来源：`Z15-VERIFIED.md:58-65`） |
| Z15-4 | P3 | `negotiate` 快速路径对每个已配置 coding 重新 `strings.Split` 一次头部，成本随服务端配置增长 | `internal/compress/compress.go:180-193` | OPEN | 快速路径先切一次成切片再 `EqualFold` 匹配（来源：`Z15-VERIFIED.md:67-77`） |
| Z15V-1 | P2 | 会话清扫与 Z15-1 跑在同一 15 分钟循环、同样无 `LIMIT`；单句撞超时第二句永不执行（孤儿行持续累积） | `internal/store/postgres/sessions.go:144-151` | FIXED（4dff4a3） | 同 Z15-1 的有界批 + 每句独立提交，anti-join 也分批（来源：`Z15-VERIFIED.md:83-96`） |
| Z16-1 | P2 | CI 的 `load` 门禁在「什么都没测」时仍然绿：job 内没有任何一步读 `make load` 的输出 | `.github/workflows/ci.yml:407-428` | OPEN | load job 加一行 `grep -q 'capacity profile:'`（照抄 perf.yml）（来源：`Z16-VERIFIED.md:29-36`） |
| Z16-2 | P2 | gosec 的 `includes` 是白名单：CI lint 门禁对有真实生产命中的规则（G112/G114/G115/G104/G107）永远不会红 | `.golangci.yml:55-61` | OPEN | 把 `includes` 换成 `excludes`，或把 G112/G114/G115 与 G104/G107 显式加回（来源：`Z16-VERIFIED.md:38-47`、`00-MAIN-VERIFICATION.md:533-547`） |
| Z16-3 | P2 | 101 个 `audit5` 标签探针在任何 CI 门禁之外，连编译/vet/lint 都看不到（对 N-04 的补充） | `.github/workflows/*.yml`（无 `-tags` 步骤） | OPEN | CI 加 `probe-compile` job：`go vet -tags audit5 ./...`（可再加 audit6/audit7）（来源：`Z16-VERIFIED.md:49-58`） |
| Z16-4 | P3 | `internal/archtest` 的 Makefile 守卫是整文件 `strings.Contains`，把目标行整行注释掉仍 PASS | `internal/archtest/workflows_test.go:31-40` | OPEN | 复用同包结构解析，断言 `release` 的前置真含 `npm-attribution`/`checksums`（来源：`Z16-VERIFIED.md:60-65`） |
| Z16-5 | P3 | `ci.yml` 的 fuzz 目标清单靠手维护，没有任何守卫保证它完整（删掉 5 条无人发现） | `.github/workflows/ci.yml:467-478` | OPEN | archtest 用 `go test -list '^Fuzz'` 枚举目标并断言全在清单（来源：`Z16-VERIFIED.md:67-72`） |
| Z16-6 | P3 | 又三条「算出结论只打印」的探针，其中一条可被 `-overlay` 注入的假期望骗过仍 PASS | `internal/zzprobe/pubaddr/addr_test.go:12-54`、`internal/zzprobe/federation/safeurl_test.go:425-443,181-186` | OPEN | 三条各补真断言（地址表逐例 `t.Errorf`、归一化断言 scheme/host 白名单、区域 ID 断言 err）（来源：`Z16-VERIFIED.md:74-80`） |
| Z16-7 | P3 | 覆盖率 floor 是全仓一个总数，其自述要防的「某包烂到 0」不在覆盖内（逐包表只进 summary 不设门禁） | `.github/workflows/ci.yml:170-179` | OPEN | 逐包设下限（报告标 HYPOTHESIS 偏保守，verifier 可升源级 CONFIRMED，P3 不变）（来源：`Z16-VERIFIED.md:82-88`） |
| VZ16-1 | P3 | 「可达性」守卫只读文件与 build 注释、从不编译：给它想要的 `-tags` 就能变成永久绿 | `internal/zzprobe/audit7/z16guardtestquality/gates_test.go:211-297` | OPEN | 守卫加真编译步骤（用真工具链取代 grep）（来源：`Z16-VERIFIED.md:92-100`） |
| VZ16-2 | P3 | 该守卫只认 `//go:build`，旧式 `// +build` 约束被它当成「默认套件」，两侧都兜不住 | `internal/zzprobe/audit7/z16guardtestquality/gates_test.go:260-271` | OPEN | 用 `go list -f '{{.TestGoFiles}}'`（真工具链）取代文本扫描，或同时解析 `// +build`（来源：`Z16-VERIFIED.md:102-110`） |
| Z17-1 | P3 | README 快速开始与随仓库交付的配置样例不兼容：照抄即拒绝启动（样例 IdP 段未注释、引用未设变量） | `config/re0auth.example.toml:316-322`、`README.md:17-27` | OPEN | 样例注释掉 `[idp.github]`/`[idp.google]`，或 README 片段补两个 secret（verifier 降级 P2→P3；与第五轮 CS-5 相邻，见「已裁定」）（来源：`Z17-VERIFIED.md:26-38`） |
| Z17-2 | P3 | README 的内存模式片段按原样无法启动（缺 `cookie_secure` 与两把 OP 密钥两处独立缺项） | `README.md:36-40` | OPEN | 片段补 `RE0AUTH_COOKIE_SECURE=true` 与两把 OP 密钥（或 issuer 换 http）（来源：`Z17-VERIFIED.md:40-48`） |
| Z17-3 | P3 | SECURITY.md 的「Our own audits」已过期：轮数与在盘文档都对不上（只列 -2/-3） | `SECURITY.md:121-130` | OPEN | 按实际轮数陈述并列出四份文档，或改成不绑定数字的措辞（来源：`Z17-VERIFIED.md:50-55`） |
| Z17-4 | P3 | openapi 的 `Binding.token_class`/`status` 封闭 enum 表示不了 `configured: false`（两字段无 `omitempty`，零值必上线） | `docs/openapi.yaml:1833-1842`、`internal/httpapi/binding_routes.go:23-24` | OPEN | 两字段加 `,omitempty`，或 enum 加 `""` 并写清语义（来源：`Z17-VERIFIED.md:57-64`） |
| Z17-5 | P3 | README 指认的「完整键位」样例漏 8 个已实现 env 覆盖；6/8 是第五轮 CS-10 的重报，仅 `RE0AUTH_LOG_LEVEL`/`LOG_FORMAT` 为新残留 | `config/re0auth.example.toml:13`、`README.md:42` | OPEN | 补 `# Environment override:` 行并文档化 `RE0AUTH_LOG_LEVEL`/`LOG_FORMAT` 及取值域（verifier 降级，作 CS-10 补充）（来源：`Z17-VERIFIED.md:66-79`） |
| Z17-6 | P3 | openapi 说 audit 的 `cursor` 是「不透明、非签发即拒」，实现是普通行号且接受任意正整数 | `docs/openapi.yaml:1452-1454`、`internal/httpapi/audit_routes.go:82-89` | OPEN | 把描述改成事实，或真做成不透明/签名游标（属裁定：建议只改文档）（来源：`Z17-VERIFIED.md:83-91`） |
| Z17V-1 | P3 | README 的参考数据源快速开始同样照抄即拒绝启动：样例 `[client] secret_env` 生效而样例头部自称「every field has a default」 | `config/referencesource.example.toml:17-18`、`README.md:73-78` | OPEN | 样例注释掉 `[client] secret_env`，README 片段补 `REFERENCE_SOURCE_CLIENT_SECRET`，并修正「或 GOOGLE_CLIENT_SECRET」的表述（来源：`Z17-VERIFIED.md:95-125`） |
| Z19-1 / Z19V-1 | P2 | `*_env`（含 `dsn_env`）「名字位塞值/DSN 原文」被启动错误原文回显进日志（同一洞，主代理 V-28 裁定合并） | `internal/config/config.go:57-66`；`internal/store/postgres/postgres.go:225-227`；`cmd/re0auth/config.go:1037` | FIXED（17914d4） | 不做形状正则判断（纯字母数字密钥可通过），直接**不回显文件里的字符串**，只报字段名＋「不是合法变量名」；同族站点 `kek_id` 一并对齐 |
| Z19-4 | P2 | `-rotate-keys` 用「同料不同 id」的 KEK 报出成功轮换，退役键仍能开每条记录且 exit 0 | `vault/service.go:112-130` | FIXED（4dff4a3） | `WithRetiredKeys` 在 id 检查外加材料同一性检查（`Fingerprint()`，不暴露 KEK），启动时两两比对拒绝启动 |
| Z20-1 | P2 | 每一次成功的授权码兑换都写一条字段全空的 `oidc.consent.deny`（两后端），真拒绝流被 1:1 污染 | `internal/store/memory/oidc.go:449-467`；`internal/store/postgres/oidc.go:287-311` | FIXED（b17c76f） | `DeleteAuthRequest` 先读 `done`/`subject`：行已不存在按「已兑换清理」记 `oidc.consent.exchange`（或不记），仅当行存在且 `!done` 才记 deny |
| Z18-2 | P3 | `idp` 把 `providerMu` 跨 discovery 网络 I/O 持有，发现期间该 provider 登录被串行化（最坏 10s/次，失败不缓存会重复） | `idp/idp.go:619-637` | OPEN | 网络发现移到锁外（double-checked）或给发现单独短超时＋singleflight |
| Z18-3 | P3 | `oauth.MemoryStore` 把存储的 `Scopes` 切片交出去（GetAccess/Introspect），改返回值即改活令牌授权 | `oauth/tokens.go:216-232`；`oauth/as.go:280` | OPEN | `Save*/Get*/Consume*` 出入口 `slices.Clone`（PG 后端已 clone，属同契约实现不对称） |
| Z18v-1 | P3 | 同族第二道门：`ListBySubject` 的 `GrantRecord.Scopes` 也指向存储数组，Z18-3 修法漏了它 | `oauth/tokens.go:158-180` | OPEN | `ListBySubject` 返回时 clone（或统一到一个 `cloneToken` 出口） |
| Z18v-3 | P3 | 被复核夹具 `Limiter=nil`、`MaxInFlight=0`，使 Z18-1 的「限流/在途豁免」断言在结构上不可证 | `internal/zzprobe/audit7/z18gohazardsweep/probes_test.go:63-70` | OPEN | 填上 `Limiter`/`MaxInFlight` 再断言 200，或删掉该句 |
| Z18v-4 | P3 | `Bulkhead` 绿探针是空守卫：从不触发 `uint(maxConcurrent)` 转换，证不了它要排除的形态 | `internal/zzprobe/audit7/z18gohazardsweep/probes_test.go:325-336` | OPEN | 补 `Bulkhead(next, 2)` 下第 3 个并发 `RoundTrip` 被拒/阻塞的探针 |
| Z19-2 | P3 | QQ 取用户信息把 access token 放进查询串，`url.Error` 把整条 URL 连 token 交给调用方（今天唯一调用方丢弃该错误） | `idp/idp.go:651,670-673` | OPEN | `getText` 包装错误时剥掉查询串，或源头用不回显 URL 的 Transport 错误 |
| Z19-3 | P3 | `vault.Use` 四条失败路径 `_ = s.record(…)` 丢审计，而同 sink 成功路径是 fail-closed（对 G-19「全部 fail-closed」的局部反驳） | `vault/service.go:247-252,269-271,278-280,288-290` | OPEN | 与成功路径同纪律：`errors.Join(err, aerr)`（不能只回审计错误，调用方依赖 `errors.Is(ErrNotFound)`） |
| Z19V-2 | P3 | `-print-secret-env` 把塞进名字位的值原样打到 stdout，是 Z19-1 的第二个出口且形状校验修法覆盖不到 | `cmd/re0auth/config.go:418-421` | OPEN | `configSecretEnvNames` 拒绝非变量名形状并给可操作错误，或明示接受该出口 |
| Z20-2 | P3 | raw 透传闸门按「源」判、不按「资源」判：用户不授予的 scope 仍经 raw 读同一资源（验证者复核后由 P2 降级） | `internal/httpapi/federation_routes.go:223-236,245-265` | OPEN | raw 闸门按资源名归一化后要求该资源 scope；或引入显式 `<game>.raw.read`，并在 `docs/upstream-protocol.md §9` 写明「同意页收窄可被 raw 绕过」 |
| Z20-3 | P3 | 设备面同意决策审计不带 scope（`ApproveDevice` 只记 `client_id`；PG 侧连 `client_id` 都空，属 G-17） | `internal/store/memory/oidc.go:1104` | OPEN | `ApproveDevice` 改走 `recordConsent(..., d.scopes, OK)` |
| Z20-4 | P3 | 【反驳 P-02】设备批准入口**确实**执行 `ExplicitConsent`（`87f4ad9` 起就在，早于第六轮）；真缺口只是缺测试 | `internal/store/memory/oidc.go:1397-1406`；`internal/store/postgres/oidc.go:1217` | OPEN | 把 P-02 改判为「已具备、缺守卫」，加一条带 ExplicitConsent 目录的设备面测试 |
| Z20-6 | P3 | 【反驳 P-01 影响段】转义拼写绕过内省守卫后出口改写生效，返回 `{"active":false}`，拿不到任何东西 | `internal/oidchttp/oidchttp.go:1208-1234` | OPEN | 仍做 P-01 修法（解码后再查库），并把「`introspection_clients` 必须是机密客户端」提到启动期校验 |
| Z20V-1 | P3 | 设备**拒绝**审计丢掉 store 已拿到的账号（两后端），`oidc.device.deny` 答不出「谁拒绝的」 | `internal/store/memory/oidc.go:1112-1127`；`internal/httpapi/device_routes.go:114-115` | OPEN | `DenyDevice(ctx, userCode, subject)`；交互面把会话账号一并交给 store |
| Z20V-2 | P3 | 导出的 `ApproveDevice` 不过 ExplicitConsent 闸门（今天无路由可达，但是导出方法） | `internal/store/memory/oidc.go:1086-1106`；`internal/store/postgres/oidc.go:873-900` | OPEN | 把 `RequireExplicitConsent` 收进 `ApproveDevice`，或降为非导出、由 `DecideDeviceAuthorization` 独占 |
| Z20V-3 | P3 | 被审报告两条「探过没破」守卫偏弱（逃逸断言不命名 400；归一化守卫是单源夹具），假绿风险 | `internal/zzprobe/audit7/z20authzisolationmatrix/scopegate_test.go:92-96,103-125` | OPEN | 逃逸断言命名 400＋零上游调用；归一化守卫至少两条候选源 |
| Z21-2 | P2 | `0013` 的 Down 丢掉 `audit_chain` 与逐列链元数据（`prev_hash`/`row_hash`/`signature`），Down→Up 一次往返就把历史每一行变成 NULL 哈希、链头回创世，`Verify` 全部计 `Legacy` 且 `OK=true`——审计链防篡改（S5）在无人察觉下被整体拆除（触发者是常规运维回退，且 `87f4ad9` 后新建库无版本 5，回退一路可达） | `internal/store/postgres/migrations/0013_audit_chain.sql:50-55` | FIXED（17914d4） | 把 0013/0014 的 Down 改成 no-op + 注释「不可回退，回滚=恢复备份」；`MigrateDown` 前加 `SELECT 1 FROM audit_events WHERE row_hash IS NOT NULL LIMIT 1` 拒退；ADR-0008 点名后果。源码级已定论，端到端真实 `MigrateDown`×N + 真实 `Verify` 返回值需真 Postgres（本机无），故运行时部分为 OPEN-PG。（来源：`Z21-VERIFIED.md:34`） |
| 22-1 / G-11 | P3 | `readinessCache` 在「首次检查仍在跑且从未产生过结论」（`checked==false && running==true`）时返回零值 `err=nil`，`/readyz` 回 `200 ok`（fail-open）：依赖不可达时实例仍报就绪，窗口 ≤ `readinessTimeout` 2s（Z18-1 是同一缺陷的第三次重报，已裁 NOT-A-FINDING）。区域 22 自评 P2；主复核按出厂清单（`startupProbe` 先于 `readinessProbe`、kubelet 串行）裁定 P3，此处从复核 | `internal/httpapi/health.go:111-118` | OPEN | `c.running && !c.checked` 时 fail-closed 回 503/`not ready`，绝不拿零值 `nil` 当结论（可加显式三态）；不改 TTL 取舍、不因负载 shed。（来源：`Z18-VERIFIED.md:14`、`22-audit5-red-reconciliation.md:78`） |
| Z21V-1 | P3 | `0014` 的 Down 丢弃全部每账号假名密钥（`audit_subject_keys` 是唯一副本）；回退后再 Up 时 `subjectKey` 重铸随机 key，同一账号的审计史被静默劈成两个假名，`?subject=` 此后只回一半，且无错误无标记、`Verify` 全绿 | `internal/store/postgres/migrations/0014_audit_pseudonyms.sql:41-42` | FIXED（17914d4） | 与 Z21-2 同批：0014 Down 改 no-op + 注释；`MigrateDown` 加 `SELECT 1 FROM audit_subject_keys LIMIT 1` 前置拒退。（来源：`Z21-VERIFIED.md:92`） |
| Z21V-2 | P3 | 被报告当作「去手写清单」的 `predicate_index_test` 看不见 04-3 那条语句：批量撤销 SQL 是 `db.Exec("DELETE FROM "+table+clause)` 运行时拼接，`revokeMatching` 的 5 张表在源码里无字面量；该守卫自称能自动抓住 04-3，实际结构上不可能（假绿，且是 04-3 唯一防复发机制） | `internal/zzprobe/audit7/z21migrationsschemaintegrity/predicate_index_test.go:123-129` | OPEN | 守卫改为从 `revokeMatching` 调用点反推 `[]string{…}` 表集合，或让该 SQL 文本可被静态提取。（来源：`Z21-VERIFIED.md:113`） |
| Z21-1 | P3 | `0010`/`0011` 的 Down 是 21 个文件里仅有的两条无 `IF EXISTS` 的 `DROP`；原称「重复 `-migrate-down` 第二步硬报错」的机制被复核推翻（goose Down 一次一版本且与版本行同事务），降为纯加固项（与其余 19 文件一致 + 抗版本表漂移） | `internal/store/postgres/migrations/0010_client_status.sql:15`（另 `internal/store/postgres/migrations/0011_session_subjects.sql:24`） | OPEN | 两处补 `IF EXISTS`；把该探针搬成 `internal/store/postgres` 的无 DB 守卫。（来源：`Z21-VERIFIED.md:32`） |
| Z21-4 | P3 | 设备码 user code 唯一性两表不对称：`oidc_devices` 有同名表达式 UNIQUE 索引，`oauth_device_authorizations` 只有非唯一索引；`SaveDevice` 是裸 INSERT、`freeUserCode` 查重与插入之间无约束，撞码时审批可能落到另一条流（同账号自己的设备申报，非跨账号泄露） | `internal/store/postgres/migrations/0001_init.sql:94-95` | OPEN | 新迁移给该表补表达式 UNIQUE 索引；`SaveDevice` 用 `isUniqueViolation` 走「重新生成 user code」路径；内存后端同步（其 `byUser` 是无条件覆盖，比 PG 更确定地丢前一条）。（来源：`Z21-VERIFIED.md:74`） |
| Z21-3 | P3 | 21 个迁移共 39 条 `CREATE INDEX`，0 个 `NO TRANSACTION`、0 条 `CONCURRENTLY`，goose 单事务 ⇒ 每条文件的索引总时长即写冻结窗口；多索引文件 8 个，最坏 `0012` 一次 9 条（跨 7 表），`0009` 还在同事务里 `ADD COLUMN … NOT NULL DEFAULT now()` 全表重写。第六轮 04-7 只点了 0022 的 4 条（时长部分 HYPOTHESIS，需真库 `pg_locks`） | `internal/store/postgres/migrations/0012_indexes.sql`（未记录行号） | OPEN | ADR-0008 §2 补记「索引迁移在役升级按表规模线性冻结写」并点名 0012/0008；后续索引迁移改 `NO TRANSACTION`+`CONCURRENTLY`；拆开 0009 这类「加列+建索引同文件」。（来源：`Z21-VERIFIED.md:63`） |
| 22-2 | P3 | round-5 给 FO-04 作证的 `TestProbeRegistryAcceptsPathEscapingNames` 循环里只有 `t.Logf`、无任何断言，结构上不可能失败而在 HEAD PASS；FO-04 的「畸形 game/name 被接受」这一半实际无守卫，回归不会被发现（证据链缺陷，非运行时攻击面） | `internal/zzprobe/federation/raw_test.go:284-317` | OPEN | 改成真断言（`..`、含 `/`、`?`、`#`、`\`、NUL、CR/LF、首尾空白、4096 字节等必须被 `NewRegistry` 拒绝）；或在 FO-04 结案前从证据清单移除、只留 `TestProbeScopeInjectionFromRegistry`。（来源：`22-audit5-red-reconciliation.md:146`） |
| N-01 | P2 | 两个后端的 sweep 注释都用一个**假的不变量**为自己开脱：refresh 读路径与设备消费路径实际上都不判期限 | `internal/store/postgres/sweep.go:10-13`、`internal/store/memory/oidc.go:935-944` | FIXED（6665193） | 给两处读路径补期限谓词（= G-2/G-7 的修法），改写注释，并加逐表守卫测试断言「过期行在 sweep 前已被读路径拒绝」 |
| N-02 | P2 | refresh 热路径的数据库故障被**无条件**折叠成 `400 invalid_grant`，且库层硬编码、改 store 也换不来 500 | `internal/store/postgres/oidc.go:434-436`、`internal/store/memory/oidc.go:574` | FIXED（6665193） | ①store 先分类（`pgx.ErrNoRows`→无效，其余 `%w` 保留）；②本项目边界补计数/告警（或依赖 readyz 摘实例）；③把库限制记入 `docs/dependencies.md` |
| N-03 | P3 | 公开引擎 `oauth/` 仍**完全静默**地吞掉审计失败——P2-1 的修复只覆盖了 OP store | `oauth/as.go:338-346` | OPEN | 照抄 OP store 形状（`slog.Error` + 计数指标），并把 P2-1 的守卫扩到 `oauth/` 包调用点 |
| N-04 | P2 | 全部安全探针（184 个文件）**不在 CI 里**：CI 全文 0 处 `-tags`，所有 P0/P1 修复没有回归防线 | `.github/workflows/ci.yml:158-162` | FIXED（4dff4a3） | CI 增作业按**已知绿集合**跑 `-tags audit5\|audit6\|audit7`；仍红的 19 条 audit5 探针要么修、要么 `t.Skip` 并写明编号/原因，不许靠标签藏起来 |

## 已修复（仅 ID + 一句话，供溯源）

- KIT-1 — 匿名 cascade 现在回 401（`TestE1_`/`TestE3_`/`TestF3_` 转绿）。
- KIT-3 — 暂停/删除客户端的令牌现在 `active=false` 且数据面 401（`TestA4_`/`TestA5_`/`TestE10_` 转绿）。
- CS-4 — `token_class` 现在在 `federation.go:173-180` 白名单校验。
- CS-1 / P1-4 — `/readyz` 现在有 `readinessTTL` 成本上限（提交 `0e6b701`）。
- 第五轮 P2-1 — OP store 两个后端的审计记录失败已改为打日志：`internal/store/postgres/oidc.go:129-140`、`internal/store/memory/oidc.go:323-334`。
- 第五轮 P2-24 — `prompt=none` 无会话回 `login_required`、矛盾组合回 `invalid_request`，由 `internal/oidchttp/oidchttp.go:950-972` 与 `oidchttp_test.go:236-294` 钉住。
- 第五轮 B-3 的一半 + DEP-V3 — 清单已设 `GOMEMLIMIT=384MiB`（`deploy/k8s/base/deployment.yaml:60-61`）且镜像不再用 `latest`（钉 `v0.0.0-rc.3`，`:44`）。
- 第二轮 A2-1 — `internal/httpapi/federation_routes.go:378-385` 曾漏 `OwnerMatches`，现已补上，守卫在 `internal/httpapi/adversary_test.go:161-172`。
- §0 基线修复（无编号）— 字节级修好未跟踪探针 `internal/store/postgres/zz_audit_keyrotation_test.go:9` 的非法 UTF-8（`E3 80 3F`→`E3 80 8D`），未删文件未改被跟踪文件，`go build`/`go vet` exit 0、默认套件 34 包全绿；归类为过程性缺陷。
- 区02 守住（G 面）— `TestZ02RefreshReplayAndExpiry`、`TestZ02IntrospectionRefusesPublicClients`、`TestZ02RefreshCannotEscalateScope`、`TestZ02UserinfoRequiresALiveAccessToken`、`TestZ02CodeExchangeGuardsHold`、`TestZ02GrantTypeDispatchRefusesUnadvertised` 全 PASS。
- 区04 守住（时钟面）— `TestEverySQLDatabaseClockUseIsReviewed`、`TestTheClockPolicyHasNoSecondUnjudgedDeadlineWriter` PASS，三条豁免清单守得住。
- 区06 守住（HTTP 面）— body limit、压缩、探针端点、不计 header 上限、Slowloris 真进程均 PASS。
- 区01 守住（第五轮回归）— 六个 `TestRegression*`（id_token sub、畸形参数、redirect_uri 变体、PKCE、码单次使用、request 参数）全 PASS。
- 守卫（正面结论）— `internal/webui/webui.go:8-12` 包注释声明「never injects data, never templates, never rewrites the shell」，与本轮前端面绿探针一致，应保留为守卫。
- KIT-4 — `ConsumeCode` 绑定校验后才原子消费，失败不再烧码并记 `oauth.exchange_failed` — `7cfbdb5`
- 第七轮 T1 批次（P2 分级里「不修上不了线」的一组，见 `docs/issues/P2-triage.md`）：
  - Z13-3 — 运行镜像带 npm 归属清单；`internal/archtest` 的发布门禁开始读 Dockerfile，audit5 运行阶段白名单同步 — `17914d4`
  - Z12-1 — 两个退役密钥解析器只报条目下标、不回显值；CS-8 补 plant 该变量 — `17914d4`
  - Z19-1 / Z19V-1 — `*_env` 名字位塞值与 DSN 原文不再回显（`config.Secret`、`trusted_proxies`、`kek_id`、Postgres 解析错误剥连接串） — `17914d4`
  - Z13-1 — 备份脚本默认落点与备份产物进 `.gitignore`/`.dockerignore` — `17914d4`
  - Z13V-1 — `.dockerignore` 补 `scratchpad` 与其余被 gitignore 的本地状态 — `17914d4`
  - Z21-2 / Z21V-1 — 0013/0014 的 Down 改空段、Up 幂等，`MigrateDown` 在链上有行时拒退；ADR-0008 §5 — `17914d4`
  - Z14-3 — `jwks_uri` 默认同源、显式配置精确匹配；`Credentials.JWKSURL` 与 `idp.*.jwks_uri` 提供跨源出口 — `17914d4`
- 第七轮 T2 批次（「首发窗口必修」；见 `docs/issues/P2-triage.md`，本轮先收 6 条）：
  - Z11-3 — `X-Request-Id` 仅在 `len<=128` 且 `[A-Za-z0-9._-]` 时采信；原本恒红的探针改写为回归守卫 — `6665193`
  - Z13-4 — `backup-keys.sh` 的 umask/age 守卫提前到它们保护的动作之前，age 失败清理半成品；黑盒探针翻转为断言不残留 — `6665193`
  - Z09-4 — 上游字节预算加 per-caller 分摊（镜像 `max_in_flight` 的既有裁定），注释与容量/决策文档同步 — `6665193`
  - N-01 — sweep 注释不再宣称假不变量；postgres 逐表守卫（显式豁免）+ memory 逐表守卫（G-7/Z07-1 带编号 `t.Skip`） — `6665193`
  - N-02 — 刷新热路径库故障与「未知令牌」分离（哨兵 + `%w`），`internal/oidchttp` 装饰器计入 `re0auth_store_unavailable_total`，库硬编码 `invalid_grant` 记入 `docs/dependencies.md` — `6665193`
- 第七轮 T2 收尾批次（其余 11 条，`4dff4a3`）：
  - Z07-3 — `user_code` 句柄只绑定规范化后的码（两 store 返回、页面回显、决策路径规范化），`auth.Manager.Bind` 加 128 字节上限 — `4dff4a3`
  - Z15-1 / Z15V-1 — 过期清扫改单事务内有界批次（`ctid IN (… LIMIT 1000)`，12 张表）；会话侧第二个 DELETE 不再被跳过；新增 sweep 计数指标 — `4dff4a3`
  - Z14-2 — conformance 断言匿名调用者不得从 `/oauth/revoke` 拿到 2xx — `4dff4a3`
  - Z14-4 — discovery 持续失败时 provider 缓存新增 2×TTL 硬上界，超过即 fail-closed — `4dff4a3`
  - Z19-4 — `vault.KeyFingerprint` 可选接口 + `LocalKeyWrapper` 指纹，`WithRetiredKeys` 拒绝同材料换 id 的「轮换」 — `4dff4a3`
  - N-04 — ci.yml 新增 `probes` 作业（三套 tag 的 vet 编译 + 显式绿名单），打 tag 时经 release.yml 自动继承 — `4dff4a3`
- 第七轮 T3 批次（「首个补丁（月内）」，本轮九项；Z16-2 另起，`b17c76f`）：
  - Z07-1 — 两个 store 的 `AuthRequestByID` 裁决 `expires_at`；N-01 的 Z07-1 豁免删除（postgres 守卫改为按方法体断言） — `b17c76f`
  - Z20-1 — 铸码后的 `DeleteAuthRequest` 清理不再写字段全空的 `oidc.consent.deny`；只在行还在且未完成时记真拒绝 — `b17c76f`
  - Z12-6 — 非有限 `rate_limit` 加载期拒绝，不再装「放行一切」的限流器 — `b17c76f`
  - Z12-4 — 显式空的三个列表变量真正清空文件列表（`config.List` 用 `os.LookupEnv`），并记 `access lists resolved` / `operator plane disabled` — `b17c76f`
  - Z12-2 — `-rotate-keys` 扫到 0 条时非零退出（`scanned=0` 不能认证轮换完成） — `b17c76f`
  - Z09V-1 — 401 不再算主机级熔断失败，改按 binding 的 401 冷却（阈值 5/30s，有界），跨账号不再互相 shed — `b17c76f`
  - Z11-2 — 先补平台无关的确定性复现（阻塞 writer），再把字节预算预留跟随响应体生命周期（`Release` + handler `defer`） — `b17c76f`
  - Z14-1 — `oauth.Store` 新增非破坏性 `GetRefresh`；级联失败不再消费 refresh，上游成功后才消费 — `b17c76f`

## 有意不做 / 已裁定

- Z08-1 / Z08-4 — 重报第五轮 A-FE-9/复核 V-2（缺失 hashed asset 回 200 + SPA shell）与 A-FE-2（Range 把 shell 字节切片当 206 返回，第五轮已判「提示」），机制、修法、后果均已记录 — 依据：`docs/audit-7/findings/Z08-VERIFIED.md:17`、`Z08-VERIFIED.md:20`
- Z08-2 — 重报第五轮 A-FE-1（shell 标 `no-cache` 却无 ETag/Last-Modified，条件请求永远 200 全量），无新事实 — 依据：`docs/audit-7/findings/Z08-VERIFIED.md:18`
- Z08-6 — 重报第五轮 A-FE-3 + 复核 V-1（`scopeViews` 静默丢弃业务注册表不认识的 scope，含设备流第二份实现）；唯一「新」内容是原报告自认不可达的人造分叉注册表配置，仅属 HYPOTHESIS — 依据：`docs/audit-7/findings/Z08-VERIFIED.md:22`
- Z10-3 — 关停栈 5+30+30=65s > grace 45s — 依据：`docs/audit-7/findings/Z10-VERIFIED.md:112`（NOT-A-FINDING，逐字重报第六轮 G-12；且不存在报告所称的"G-12 修复"）
- FO-03 — `IsPublicAddress` 漏 `0.0.0.0/8`（及 `fec0::/10` 等同类缺项）— 前轮已记录，本轮不重报 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:328`
- FO-07 — `ProxyFromEnvironment` 使地址闸门判定代理而非目标 — 第五轮已收录 — 依据：`docs/audit-7/findings/Z09-VERIFIED.md:243`
- 第六轮 03-1 — vault 身份命名空间歧义（`game + "." + source` 无校验）— 第六轮已收录，撤回不报 — 依据：`docs/audit-7/findings/Z09-VERIFIED.md:250`
- 第六轮 — `Issuer` 的 userinfo 形式把用户令牌发到 authority — 第六轮已证，不重报（Z09V-3 是不同后果）— 依据：`docs/audit-7/findings/Z09-VERIFIED.md:254`
- 第五轮判断 — `NewService` 缺省 `HTTPClient` 是"有超时、无地址闸门" — 已记为判断而非发现 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:332`
- 第六轮 — kill switch 清扫不受 `TotalTimeout` 约束 — 已证，不重报 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:336`
- FO-05 — 数据面刻意不重试（`docs/source-onboarding.md:225` 的"指数退避重试"承诺）— 文档化判断，仅建议改文档 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:344`
- raw 透传的 scope 闸门是"源的任一资源 scope" — 文档化决定，不作发现 — 依据：`docs/audit-7/findings/Z09-federation-dataplane.md:348`
- AUD-4 — 未声明动词 405 且泄露 `Allow`，`docs/admin.md:27`/openapi 与之漂移 — 第五轮已收录，不重报 — 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:382`
- 第六轮 z07 抹除记录探针（销毁前写 `account.delete` + `outcome=ok`）在 HEAD 上仍红 — 第六轮已有同形探针与论证，不列为本轮 finding — 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:389`
- AUD-10 — 内存模式清不掉会话（存活会话 = 存活运维权限）— 第五轮已收录，不重报 — 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:400`
- `admin.*` 的 `detail["actor"]` 记操作员原始 `usr_` — 已裁定（企业审计合规）— 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:404`
- `audit_subject_keys` 不在链上、内容不受签名保护 — 第六轮区 03 已证，不单列（仅在 Z10-2 影响里引用）— 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:407`
- 尾部截断不可检测（无外部锚点）— `migrations/0013` 与 `docs/architecture.md` §4.16 明写的边界 — 依据：`docs/audit-7/findings/Z10-admin-audit-privacy.md:412`
- Z12V-2 — 非新洞：仅补强 Z12-6（关闭 TOML `nan` 残余盲区，小写被接受、大写被拒），无独立缺陷 — 依据：`docs/audit-7/findings/Z12-VERIFIED.md:158-161`
- Z11-5 的子命题「并发上限没有按调用方分摊」 — 文档化裁定，OPEN 部分只保留「一个地址可据此饿死所有其他客户端，且探针全绿」这一新意 — 依据：`docs/audit-7/findings/Z11-VERIFIED.md:118-121`（`operations-decision.md:40`）
- 兜底桶本身存在（桶满不淘汰活桶、新键共用一个兜底桶） — 文档化的方向正确，不作为发现；Z11-4 只质疑其分摊粒度 — 依据：`docs/audit-7/findings/Z11-resilience-dos.md:94,153-154`（`operations-decision.md:49`）
- 探针豁免（`health.go:151-166`） — 必要裁定，非 finding；Z11-1 证明的是它的**输入**（调用方 ctx）不该进共享缓存 — 依据：`docs/audit-7/findings/Z11-resilience-dos.md:156`
- ADR-0009 半开并发度 N、`Retry-After` 抖动、`Bulkhead` 许可活到 body 关闭 — 按文档实现，无异议 — 依据：`docs/audit-7/findings/Z11-resilience-dos.md:155`
- `-rotate-keys` / `-migrate-down` 无二次确认 — 第五轮已记录，本轮不重报 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:163`
- SIGTERM/SIGINT 关闭路径与两监听器排空顺序未真跑 — G-12/Z10V-2 地盘，避免重报 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:152-153`
- SIGHUP 无任何 handler — 是否需要「重载配置」是裁定而非缺陷 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:154`
- `-print-secret-env` 打印变量**名**不是值 — 安全，非 finding；其行格式是 `scripts/backup-keys.sh` 依赖的接口 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:161`
- `-version` 在配置缺失时也工作 — 刻意行为 — 依据：`docs/audit-7/findings/Z12-config-startup-observability.md:162`
- 备份转储不加密 — 文档化取舍 — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:229`（`docs/operations.md:125-126`）
- 「备份已停」无告警 — 文档化取舍，第五轮 P2-16/DEP-06 已收录，属未闭合项而非新发现 — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:229-232`
- CI 的 image job 只 build 不 scan — 判断，不认为是漏洞（运行时 scratch + 每 PR 的 `govulncheck`） — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:233-235`
- `scratch` 而非 distroless — 判断，不是发现 — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:236-237`
- `-licenses` 未开 — 范围选择，第五轮 SUP-7 已裁定 — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:190`
- Trivy 按 digest 固定但不属 `uses:`，固定守卫看不到 — 已知范围选择（`docs/dependencies.md` §7） — 依据：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md:170`
- 原报告「探过但没破 #3」（`restore.sh` 三条 fail-closed 守卫绿） — 被 Z13V-2 推翻：绿来自逐行复核而非执行，不作为守卫计入 — 依据：`docs/audit-7/findings/Z13-VERIFIED.md:87`
- Z14-3 的 scope-out（`60de35d` 明写「JWKS 没有覆盖旋钮，所以只钉两个端点」）—— 该缺口是有意缩小范围，verifier 明确建议**本轮收回该决定**，在此之前必须当成已知缺口而不是已修，故 Z14-3 仍记 OPEN P2 —— 依据：`Z14-VERIFIED.md:57-61`、`Z14-VERIFIED.md:167-169`
- Z15-1 的「一个事务」—— `sweep.go:42-45` 是文档化决定（自述「a sweep is a single consistent step…retry is always safe」）；报告修法「每表一个事务」直接推翻该决定，按简报 §5/§7 该部分应写成「判断」而非混进 finding；核心增量「无每轮有界推进」仍成立 —— 依据：`Z15-VERIFIED.md:36-38`、`00-MAIN-VERIFICATION.md:396-399`
- Z15-3 只定 P3 —— 内存后端按 ADR-0006 决策 6 不提供生产保证（同第五轮 PERF-5/6 口径）—— 依据：`Z15-performance-capacity.md:79`、`Z15-performance-capacity.md:151`
- Z14-6 只定 P3 —— `referencesource` 不入发布产物（与 BRIEF §2/`SECURITY.md` 一致）；若当模板对外发布应升 P2 —— 依据：`Z14-kit-rp-taptap.md:136`、`Z14-VERIFIED.md:87-88`
- Z16-2 的 gosec 子集本身是文档化取舍（`.golangci.yml:43-51`），但其**形状与注释理由不匹配**（注释按「逐条排除」行文、实现是白名单）属裁定项；bench/load/perf「报数不设阈值」也是文档化决定、不质疑 —— 依据：`Z16-guard-test-quality.md:161-162`、`Z16-VERIFIED.md:44-47`、`Z16-VERIFIED.md:136-137`
- Z17 样例选择「把常见 IdP 段写成生效状态」是文档取向裁定、本身不是缺陷（缺陷是 README 与样例不兼容）—— 依据：`Z17-docs-contract-drift.md:191-193`
- Z17-5 与第五轮 CS-10 的重报关系 —— 8 个变量里 6 个（`COOKIE_SECURE`/`RATE_LIMIT(_BURST)`/`KEK_ID`/`CLIENT_ID`/`CLIENT_NAME`）已由 CS-10 逐名记录，只有 `RE0AUTH_LOG_LEVEL`/`LOG_FORMAT` 是新残留；该条整体作 CS-10 的补充，不另立新发现 —— 依据：`Z17-VERIFIED.md:66-79`
- Z18-1 — NOT-A-FINDING：与第六轮 `G-11` 及本轮区域 22 `22-1` 是**同一条代码路径**（`health.go:111-118`，`checked==false` 时拿零值 nil 当结论），第三次重报；严重度按出厂清单 P2→P3 — 依据：`docs/audit-7/findings/Z18-VERIFIED.md:14`、`Z18-VERIFIED.md:176`、`docs/audit-7/findings/00-MAIN-VERIFICATION.md:187`
- Z18v-2 — 重复：`idp` provider TTL 在 discovery 失败时不前进（`:626-633` 返回旧 provider 且不更新 `discoveredAt`）与区域 14 的 `Z14-4` 是同一机制、同一站点，不另开条目 — 依据：`docs/audit-7/findings/Z18-VERIFIED.md:93`、`docs/audit-7/findings/Z14-kit-rp-taptap.md:96`、`00-MAIN-VERIFICATION.md:426`
- Z20-5 — NOT-A-FINDING / REFUTED：生产 OP `/oauth/revoke` 存活性预言机的机制成立，但「部署面从未被记」为假——第六轮 `G-8` 的红探针本体就打在该部署 OP 上（匿名公开 client 形态已覆盖），唯一有效成分是更正 G-8 的散文影响段，归属 G-8 — 依据：`docs/audit-7/findings/Z20-VERIFIED.md:30`、`Z20-VERIFIED.md:68`
- （无编号）`internal/ratelimit/ratelimit.go:116-125` 的 `rate.Limit(0) != rate.Inf` 注释错误＋潜在可回收分支 — 从发布组合根不可达（`cmd/re0auth/main.go:225` 对 `RateLimit<=0` 返回 nil），是「注释写错＋潜在分支」而非缺陷 — 依据：`docs/audit-7/findings/Z18-go-hazard-sweep.md:126`、`Z18-VERIFIED.md:139`
- （无编号）`internal/httpapi/middleware.go:242-255` 用 `context.Background()` 写访问日志 — 有意为之（客户端断开仍要留证据），不作为 finding — 依据：`docs/audit-7/findings/Z18-go-hazard-sweep.md:132`
- （无编号）KEK/token key/audit key/per-subject key 的内存零化（`vault.Scrub` 只覆盖 DEK 与明文） — 文档化为 best effort，Go 无法用探针证明，维持「判断」 — 依据：`docs/audit-7/findings/Z19-secrets-lifecycle.md:162`、`Z19-VERIFIED.md:133`
- （无编号）raw 是「源级粗闸门」这一已文档化的已知取舍（`docs/architecture.md:468` 白纸黑字） — 按简报 §5/§7 应写成判断＋补文档，不构成新 P2 洞（此即 Z20-2 降级依据） — 依据：`docs/audit-7/findings/Z20-VERIFIED.md:27`、`Z20-VERIFIED.md:49`
- （无编号）`introspection_clients` 启动期「必须是机密客户端」校验 — 今天由运行期守卫＋出口改写兜底（Z20-6），补启动期校验只是纵深防御，不改变结论 — 依据：`docs/audit-7/findings/Z20-VERIFIED.md:134`、`Z20-authz-isolation-matrix.md:168`
- FO-02 — DECIDED-NONGOAL：探针在 CAS 输掉的分支触发、残留的是入册旧密钥，证据不成立；跨实例 refresh 残余竞态 `BRIEF §5` 已列为有意不做 — 依据：`22-audit5-red-reconciliation.md:202`
- FO-04 — 既有 KNOWN-OPEN（registry scope 原样收下空白 / 畸形 game·name 被接受）：红是真但已被 FO-04 覆盖，不重报 — 依据：`22-audit5-red-reconciliation.md:181`
- RP-7 — 既有 KNOWN-OPEN（同意重定向可重放 / 并发得三份码）：一次同意仍只产生一份可兑换 grant，只属死码残留级 — 依据：`22-audit5-red-reconciliation.md:193`
- RP-6 — 既有 KNOWN-OPEN（`clearFlow` 在 provider 比对之前执行，走错 provider 的回调烧掉待完成登录）：可用性级、需会话内 state，非安全 — 依据：`22-audit5-red-reconciliation.md:199`
- P1-4 的 audit5 探针（#18、#19）— DECIDED-NONGOAL：P1-4 已由 `0e6b701` 修复，探针断言的是修复前缺陷（#19 的红仅是文档化的 `readinessTTL` 1s 代价） — 依据：`22-audit5-red-reconciliation.md:63`
- k1/k6、FO-03、KIT-2、KIT-4（已修，见 P2-medium）、KIT-5、KIT-6、KIT-7、KIT-8、KIT-9、KIT-10、RP-5、RP-8 — 16 条 `KNOWN-OPEN` 的既有编号，本轮 19 探针归因确认为既有、不重报（含 `RP-7` 覆盖的两条探针） — 依据：`22-audit5-red-reconciliation.md:44`
- ADR-0008「Down 应分可回退 schema 步 / 不可回退完整性步（后者 no-op + 文档化）」与「审计只追加是部署形态而非控制」 — 报告自陈为文档化判断、不是 finding — 依据：`Z21-VERIFIED.md:162`
- §4-1 `postgres/oidc.go:834` 的 `auth_time = COALESCE(auth_time, now())` — 第六轮已按 P2-32 裁定为 display-only 回退、无期限裁决读它，不是新发现 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:659-661`
- §4-2 `TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent` 的红 — 夹具把 `Config.OIDC` 设成永远答 200 的桩，属夹具假象，不进清单 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:662`
- §4-3 根目录残留二进制（`re4auth.exe`/`perfreport.exe`/`httpapi.test.exe`）— 被 `*.exe` gitignore 覆盖、从未入库 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:663`
- §0 遗留探针本身 — 该文件未被 git 跟踪、不会进 CI，故不属于产品漏洞 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:17-18`
- G-1 修法与数据模型 — 检测点上被重放行已不存在（先删后判），无法就地撤销整条链，须先留族标识/已消费令牌墓碑 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:262-266`
- G-4 修法与存储边界 — `oidcstore.AuthRequest` 无 `MaxAge`/`Prompt` 字段，须先加字段再在钩子裁决 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:280-283`
- G-6 修法位置 — 必须落在 `internal/oidchttp`，不能靠改 `AuthorizeClientIDSecret` 修 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:91-92`
- Z20 编排更正 — 原「Z20 代理静默失败」判断是错的（只是慢），改走不冲突产物路径；隔离矩阵在覆盖族内成立，完整结论以 `Z20-authz-isolation-matrix.md` 与 `Z20-INDEPENDENT-CROSSCHECK.md` 为准 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:549-578`
- Z21 系列更正 — `0014` Down 不计入 Z21-2（其后果是独立新发现 Z21V-1）；「静默」表述过头，已改为「没有东西把 legacy>0 当回归」；可达性比原写更强；Z21-1 机制被复核推翻，降为纯加固项 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:580-597`
- 陈旧注释（无害提示）— `internal/httpapi/adversary_test.go:161-171` 的注释是「发现描述」旧文本，代码已修好，记为提示非缺陷 — 依据：`docs/audit-7/findings/00-MAIN-VERIFICATION.md:570-573`
- 04-7（第六轮 KNOWN-OPEN）— 建索引写冻结窗口，Z21-3 只补其时长部分（最坏 0012 一次 9 条）；时长须真 Postgres `pg_locks` 才能定论（OPEN-PG），本轮不重报 — 依据：`docs/audit-7/findings/Z21-VERIFIED.md:63`
