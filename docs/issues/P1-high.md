# P1 · 高（HIGH）

> 低门槛前提（一次登录、一个公开 client、一次匿名连接）即可扩大权限、读他人数据，或破坏生产稳定性。
> **条目数：13** ｜ 由 `_fragments/_merge.mjs` 从各轮抽取结果生成（2026-10-02，HEAD `71f56fa`）。
> 严重度取**对抗性复核后的裁定**；同一机制多编号者已合并，别名写在 ID 列。

> 其中 `Z11-1`/`Z11-4`/`Z11-5`/`Z11-V1` 是**匿名单机**可触发的跨用户可用性缺陷
> ——按本项目口径（「匿名可触发的 DoS」）它们处在 P1 的上沿；
> 若按上线门槛衡量，可与 P0 一起排期。
>
> **第九轮补充**：`S03-1`（return_to 无界）与 `S13-5`（内存存储无界）是第九轮 8 条 High 中
> 未被列为"上线阻断"的两条（部署形态相关），同样已在 `992710b` 收口。
> 当前 HEAD 上**没有未修的 P0/P1**；第 9 轮判为"上线前应先修"的 13 条 Medium 见
> [`P2-triage.md`](P2-triage.md) 的「T0 组」。


### S03-1 return_to 无长度上限且被整段写进服务端 session
- **严重度**：P1 · 高（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`internal/auth/auth.go:612; internal/auth/auth.go:616; internal/auth/auth.go:289; internal/safeurl/safeurl.go:34`
- **影响**：`safeurl.RelativePath` 只校验形状、无字节上限；scs 在响应结束时重写整个 session，于是任意匿名 `GET /auth/{provider}/start` 可为每条请求持久化约 60 KiB 的攻击者选定字节。内存模式进程 RAM 无界增长，Postgres 模式 `sessions.data` 无界增长（SweepExpired 每 15 分钟最多删 1000 行，追不上 50/s 的到达率）。这与同文件对 handle 设的 128 字节上限（"session 整体重写，其字节不能由调用方决定"）自相矛盾。
- **修法**：给 `return_to` 加 `maxReturnToBytes`（如 2048），超长即替换/拒绝，再写入 session。
- **状态**：FIXED（992710b）
- **证据**：`internal/safeurl.MaxRelativePathBytes`、`internal/auth/zz_audit9_returnto_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）
- **首次记录**：第 9 轮


---

### S13-5 内存 OP 存储所有 map 无上限；refresh tombstone 每次轮换留一条、存活 30 天，且 5 分钟清扫持全局锁全表扫描
- **严重度**：P1 · 高（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`internal/store/memory/oidc.go:34; internal/store/memory/oidc.go:44; internal/store/memory/oidc.go:52; internal/store/memory/oidc.go:639; internal/store/memory/oidc.go:1153; internal/store/memory/oidc.go:1174; internal/store/memory/oidc.go:1180; internal/store/memory/oidc.go:1488`
- **影响**：每次 refresh 轮换写一条以被消费令牌自身 30 天到期时间为期限的 tombstone，速率无 per-subject/进程上限。默认限流下可达 ~1.3e8 条、数 GB，OOM 或 GC 死亡；即便低速率，每 5 分钟的 `opJanitor` 也要持 `s.mu` 整表扫描，周期性冻结全部令牌操作。
- **修法**：给 store 加总量/tombstone 上限（默认 65536），超出丢弃最旧；清扫尽量移出全局锁或分片。
- **状态**：FIXED（992710b）
- **证据**：`internal/store/memory/zz_audit9_tombstones_test.go`、`MaxRefreshTombstones`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）
- **首次记录**：第 9 轮


---

### Z07-2 抹除链最后一步失败时审计日志唯一记录谎报成功，500 文案却承诺「审计记录了失败的那一步」
- **位置**：`internal/lifecycle/lifecycle.go:262`
- **影响**：受 `Destroy` 失败影响的账号，其审计里唯一一条记录写的是 `outcome=ok` + `pseudonym_destroyed=true`（假名钥匙仍在、仍可归因到被抹除账号），运维据此得到「审计史已不可链接」的错误结论——合规意义上的「抹除已证明完成」是假的；失败路径连一行 `slog` 都没有（`internal/httpapi/account_routes.go:54-65`），运维拿不到任何反向信号，而 500 文案「the audit log records the step that failed」对这一条是假的。
- **修法**：在 `lifecycle.go:277-283` 的失败分支补第二条记录：先把 `res.PseudonymDestroyed` 复位为 false，再 `d.record(ctx, actor, subject, audit.OutcomeError, res, "pseudonym")`（或调 `d.fail`）。**不要**把 `:269` 的成功记录挪到 `Destroy` 之后——记录本身会重新铸钥匙，代码注释已解释原因，所以应补而非挪。（此为修复建议，非裁定。）
- **状态**：FIXED（a3de9b9）
- **证据**：探针 `erasure_test.go::TestZ07ErasureAuditRecordClaimsSuccessWhileTheHistoryStaysLinkable`（红，真 `DELETE /v1/account`）；阳性对照 `::TestZ07ErasureWithAWorkingDestroyIsRecorded`（绿）；第六轮独立夹具 `internal/zzprobe/audit6/z07authsession/erasure_audit_test.go::TestProbeErasure` 同样红（三个断言字符串逐字对上）。
- **来源**：`docs/audit-7/findings/Z07-VERIFIED.md:46`（裁定表 P1）、`Z07-VERIFIED.md:71-79`（独立证据）；主代理确认 `docs/audit-7/findings/00-MAIN-VERIFICATION.md:228-238`
- **首次记录**：第 7 轮


---

### Z11-1 / Z12-7 一次匿名 connect-then-hangup 把 `/readyz` 结果缓存成 503，健康实例被 kubelet 摘出流量
- **位置**：`internal/httpapi/health.go:122`（缓存 `:111-133`；探针豁免 `:151-166`；探针周期 `deploy/k8s/base/deployment.yaml:96-100`）
- **影响**：匿名者每一个 TTL 内赢一次「触发者」竞争（实测 1ms 依赖 8/8、瞬时依赖 5/8 命中）即可让健康副本持续答 503；kubelet `periodSeconds 5 / failureThreshold 3` ⇒ 15 秒内摘除端点，全副本可被匿名削减容量直至整体不可用；原因只进 `slog.Debug`，默认日志级别不可见。
- **修法**：就绪检查改用不派生自调用方生命周期的上下文（`context.WithoutCancel(r.Context())` 或 `context.Background()`）+ `readinessTimeout`，取消类错误不写缓存。**这是裁定**：共享缓存是全进程的，调用方取消从来不是它的语义。
- **状态**：FIXED（98b3c11）
- **证据**：`readyz_poison_test.go::TestZ11CallerCancellationDoesNotPoisonReadiness`（红）；`z11verify/readyz_race_test.go`（1ms 依赖 8/8）；`z12verify/verify_readyz_test.go::...SustainedHangUpsHoldReadyzDown`（红，持续挂断可持久化 503）；机制源码 `health.go:94/:122-133` 经主代理读码确认。
- **来源**：`docs/audit-7/findings/Z11-VERIFIED.md:12,58-68`；`docs/audit-7/findings/Z12-VERIFIED.md:87-108`；`docs/audit-7/findings/00-MAIN-VERIFICATION.md:496-511`（合并裁定见 Z11-VERIFIED.md:67-68）
- **首次记录**：第 7 轮


---

### Z11-4 桶表被单个 IPv6 /64 填满后，所有新客户端共用一个兜底桶并被 429
- **位置**：`internal/ratelimit/ratelimit.go:199-215`（键构造 `internal/httpapi/middleware.go:349`；`reclaimLocked` `:226-240`）
- **影响**：任何**新**客户端（新 IP、重新拨号、NAT 出口变化）在三个平面上全部 429，登录/授权/数据面一起不可用；已被跟踪的客户端不受影响。进程不崩、探针照常 200，k8s 不重启也不摘除 ⇒ 故障静默。
- **修法**（裁定）：① overflow 桶按调用方分摊（每键一小桶 + LRU/计数上限）；② 或只拒绝重复进入 overflow 的客户端；③ 或 IPv6 地址按 /64 归并（与 P0-4 相反方向的取舍）。三条都需改 `operations-decision.md:49` 措辞。
- **状态**：FIXED（98b3c11）
- **证据**：`ratelimit_saturation_test.go::TestZ11OneIPv6Slash64CannotFillTheBucketTable`（红）；复核真中间件链 `ratelimit_http_test.go::TestZ11VOneIPv6Slash64CannotStarveUnrelatedClients`（空限流器 401 阳性对照 → 填满排空后 429）；绿对照 `TestZ11AtCapacityTheTableStaysBounded`。
- **来源**：`docs/audit-7/findings/Z11-VERIFIED.md:15,102-104`；`docs/audit-7/findings/00-MAIN-VERIFICATION.md:480-494`
- **首次记录**：第 7 轮


---

### Z11-5 全进程一个 in-flight 信号量且不按调用方分摊：一个地址占满全部槽位，其他客户端全 503 而探针仍 200
- **位置**：`internal/httpapi/middleware.go:393-419`（外层顺序 `internal/httpapi/server.go:621-624`；ReadTimeout `cmd/re0auth/main.go:116`）
- **影响**：一个匿名地址（约 130 个慢 body socket、~5 req/s）即可持续占满 `max_in_flight`，让所有其他客户端在两个平面持续 503；`/healthz`、`/readyz` 全绿 ⇒ 编排器不摘除、不重启，故障对运维不可见地持续。
- **修法**（裁定）：① 槽位按 `(plane, client)` 分摊（每客户端上限 = `maxInFlight` 的一个分数 + 共享余量）；② 或把限流令牌绑在 in-flight 上而不是到达上；③ 至少给慢 body 一个远短于 `ReadTimeout` 的期限。
- **状态**：FIXED（98b3c11）
- **证据**：`inflight_test.go::TestZ11OneAddressCannotHoldEveryInFlightSlot`（红，`max_in_flight=2` 下另一源地址 503 而探针 200）；`server.go:621-624`、`main.go:116/775-779` 逐行核对；主代理读码 `middleware.go:393-405`。
- **来源**：`docs/audit-7/findings/Z11-VERIFIED.md:16,118-121`；`docs/audit-7/findings/00-MAIN-VERIFICATION.md:470-478`
- **首次记录**：第 7 轮


---

### Z11-V1 探针豁免绕过两道上限，却绕过不了会话中间件：一个匿名 Cookie 让每次 `/healthz`、`/readyz` 都变成一次连接池往返
- **位置**：`internal/httpapi/server.go:616-624`（`isProbe` `internal/httpapi/health.go:164`、`internal/httpapi/middleware.go:335/399`；scs `postgres/sessions.go:75-82`）
- **影响**：匿名者用任意 Cookie 打 `/readyz`（免限流、免并发上限，不受 `max_in_flight` 约束）即可按请求数驱动池往返 ⇒ 池排队，正常登录/授权请求被饿。持有效 Cookie 时 scs 因 `IdleTimeout>0` 把每次探针标 `Modified` ⇒ 每请求一次写。违反 `docs/operations.md:171-183`「探针必须便宜、每副本每秒最多一次往返」。
- **修法**（裁定）：`isProbe` 的豁免也跳过 `sessions.LoadAndSave`（把探针挂在会话中间件之外），或对带 Cookie 的探针请求走限流。同步修 `docs/operations.md:177-183` 措辞。
- **状态**：FIXED（98b3c11）
- **证据**：`internal/zzprobe/audit7/z11verify/probe_session_store_test.go::TestZ11VProbePathSkipsTheSessionStore`（红）：`control cookie-less /readyz = 0 lookups`、`control /v1/me = 1 lookup`、`finding 20 cookie-bearing /readyz = 20 lookups`。
- **来源**：`docs/audit-7/findings/Z11-VERIFIED.md:72-94`
- **首次记录**：第 7 轮


---

### Z12-3 首个 seed 之后 `[client]` 的任何改动都被静默忽略
- **位置**：`cmd/re0auth/main.go:1583-1591`
- **影响**：① 给 `client.secret_env` 加秘密以为变成机密客户端，实际仍是公开客户端（内省守卫会对它 401）——更重的是轮换 secret 时**旧 secret 仍然有效**；② 改 `redirect_uris` 后回调走旧地址，**删**生产回调地址不生效（本该撤销的回调留在白名单）；③ scopes 既不能加也不能收。日志只在第一次启动说 `registered`。
- **修法**：`Get` 命中后比对 type/redirects/scopes/secret-hash，不一致**拒绝启动**并点名字段。**这是一次裁定**（会改上线流程）。
- **状态**：FIXED（657d2f0）
- **证据**：`z12seedclient_test.go::TestZ12SeedClientNeverReconcilesTheConfiguredClient`（红）；复核端到端真二进制 + `admin_routes.go:100-189` 无任何改写既有 client 的入口；`config.go:780-794` 的 `[client]` 唯一读点在 `seedClient`。
- **来源**：`docs/audit-7/findings/Z12-VERIFIED.md:41-50`；`docs/audit-7/findings/00-MAIN-VERIFICATION.md:438-450`
- **首次记录**：第 7 轮


---

### Z13V-2 `scripts/restore.sh` 在自身 `set -euo pipefail` 下无法执行：恢复路径 100% 死
- **位置**：`scripts/restore.sh:29`
- **影响**：`docs/operations.md:94` 与 `:281` 的恢复/演练命令在装有当前 bash 的主机上直接 `line 29: file: unbound variable` 退出 1，永远到不了边车校验；备份再正确也不能恢复。第五轮 P2-11 的修复**从未被执行过**。
- **修法**：拆成 `local file="$1"` 与 `local sidecar="$file.sha256" want got` 两条（同文件临时副本已证明可通）。
- **状态**：FIXED（a3de9b9）
- **证据**：`z13verify_test.go::TestZ13VRestoreScriptVerifierRunsAndVerifies`（红）；真 bash 5.3.9（含 `env -i`）实跑复现 `unbound variable`；修正副本跑通 `checksum verified … STUB pg_restore … restore complete` exit 0 且三条守卫按报告正确拒绝。
- **来源**：`docs/audit-7/findings/Z13-VERIFIED.md:64-80`
- **首次记录**：第 7 轮


---

### G-4 `prompt=login` 与 `max_age` 被完全忽略，id_token 带旧会话的 `auth_time`
- **严重度**：P1
- **位置**：`internal/oidchttp/oidchttp.go:950`（只有 `prompt=none` 分支；`MaxAge` 生产代码零命中）
- **影响**：RP 请求 step-up 重新认证时，OP 既不重新认证也不回 `login_required`，id_token 携带**旧会话的 `auth_time`**。`max_age` 完全不被读取。
- **修法**：`oidcstore.AuthRequest` 没有 `MaxAge`/`Prompt` 字段 ⇒ 需**先在存储边界加字段**再在会话/登录钩子裁决；无活会话时按 `login_required` fail-closed。不是「钩子里比较 auth_time」能解决的。
- **状态**：FIXED（4658066）
- **证据**：`internal/zzprobe/audit6/z01protocolauth/consent_face_test.go::TestProbePromptLoginAndMaxAgeDoNotForceReauthentication`（红）、`z02/idtoken_test.go::TestZ02MaxAgeAndPromptLoginAreIgnored`（红）；`00-MAIN-VERIFICATION.md:28,60,269-283`（V-11）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:111`
- **首次记录**：第 6 轮


---

### G-5 percent 编码的 client_id 绕过内省守卫
- **严重度**：P1
- **位置**：`internal/oidchttp/oidchttp.go:1107`（守卫；放行点 `:1115`）
- **影响**：`Basic z02-d%65vice-…` 使守卫用原始字节查库失败即 `return false`，而库 `url.QueryUnescape` 解码后认证通过 ⇒「内省必须机密客户端」（P0-6 / PROTO-4 的唯一修法）被一行绕过。未误配时攻击者只读到自己的令牌；名单一旦含公开客户端即等价 PROTO-4 复活。
- **修法**：守卫在查库前对 Basic 里的 client_id 做 `url.QueryUnescape`（与库对齐），或先解码再判定；并收紧 `return false` 的宽容语义（查不到/非机密直接 401，`client_assertion` 路径进守卫前显式拒绝）。
- **状态**：FIXED（4658066）
- **证据**：`internal/zzprobe/audit6/z02protocoltoken/introspect_test.go::TestZ02IntrospectionGuardBypassedByPercentEncodedClientID`（红）；`_audit/protocol.md:31-107`（P-01，红探针 `TestZZAudit_IntrospectionPublicClientGuardIsBypassedByPercentEncoding`）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:112`
- **首次记录**：第 6 轮


---

### G-6 匿名者可以机密客户端身份发起设备流
- **严重度**：P1
- **位置**：`internal/oidchttp/oidchttp.go:576`（项目边界；机制在库 `pkg/op/device.go:138` 丢弃 `ClientIDFromRequest` 的 `authenticated`）
- **影响**：`POST /oauth/device_authorization` 对任何（含机密）客户端都不要求认证，而验证页会把该客户端的**注册名**展示给任何跟着 user_code 走的人。第 7 轮更正：本项目 `AuthorizeClientIDSecret` 不在这条路径上，**不能靠改它来修**。
- **修法**：在 `internal/oidchttp` 把请求交给库**之前**对机密客户端强制认证（与 token 端点同形）。
- **状态**：FIXED（4658066）
- **证据**：`internal/zzprobe/audit6/z01protocolauth/device_flow_test.go::TestProbeConfidentialClientCanStartADeviceFlowUnauthenticated`（红）；`00-MAIN-VERIFICATION.md:82-92`（V-03 根因更正）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:113`
- **首次记录**：第 6 轮


---

### G-12 k8s 关闭预算与 grace 不自洽，在途审计批次整批丢失
- **严重度**：P1
- **位置**：`cmd/re0auth/main.go:137`（`endpointRemovalWait=5s`）、`:127`（`shutdownTimeout=30s`）、`internal/store/postgres/auditbatch.go:54`（`auditDrainTimeout=30s`）、`deploy/k8s/base/deployment.yaml:26`（`terminationGracePeriodSeconds: 45`）
- **影响**：三者串行，最坏 5+30+30=65s > 45s ⇒ SIGKILL 发生在审计排空预算到期**之前约 10s**；「过期拒绝」路径在 k8s 里从不运行，滚动更新/驱逐时在途审计行静默丢失，审计链在 k8s 上不可信。
- **修法**：`auditDrainTimeout` 改为 `grace - removal - http`（=10s），或把 grace 提到 ≥70s 并同步注释；至少把 `deployment.yaml:21-25` 的「35s total」注释改为全栈口径。
- **状态**：FIXED（657d2f0）
- **证据**：`internal/zzprobe/audit6/z04pgstore/drain_budget_probe_test.go::TestTheShutdownStackFitsThePodGrace`（红）、`::TestTheManifestCommentCountsTheWholeStack`（红）；`00-MAIN-VERIFICATION.md:174-185`（V-06，定级 P1）
- **来源**：`00-LAUNCH-READINESS-CONSOLIDATED.md:119`
- **首次记录**：第 6 轮

