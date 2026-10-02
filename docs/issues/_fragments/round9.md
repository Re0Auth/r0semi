# 第九轮独立审计抽取结果（157 条）

> 来源：[`docs/security-audit-9.md`](../../security-audit-9.md)（独立轮次，只读 HEAD 生产代码）。
> 由 `_extract_round9.mjs` 生成；**不要手改本文件**，改脚本或报告。
> 严重度沿用报告的高/中/低/信息，映射到寄存器为 P0/P1（High）、P2（Medium）、P3（Low + Info）。
> Low/Info 标题保留报告原文（英文），以免改写引入偏差；Medium 为人工中文摘要。
> `修复状态` 只认报告 §0 的修复台账：本轮的 8 条 High 与 S02-2 已在 `992710b` 收口。

## P0/P1

### S02-1 prompt=login / max_age 不触发重新认证，OP 把同意时刻伪造成新的 auth_time
- **严重度**：P0 · 阻断上线（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`internal/oidcstore/oidcstore.go:226; internal/oidchttp/oidchttp.go:1006; internal/store/memory/oidc.go:1274; internal/store/postgres/oidc.go:1269`
- **影响**：`RequiresReauthentication` 是唯一比较会话年龄与请求新鲜度的地方，但它的结果从不用于强制重登录：登录钩子只把 `sessions.AuthenticatedAt` 抄进 pending 请求并返回同意 URL，两个 store 在 `RequiresReauthentication==true` 时反而用"同意决策时刻"覆盖 `AuthTime`。结果是一条 24h 的旧会话可以满足 RP 的 step-up 要求，而 OP 用一个被签名的假 `auth_time` 为这次从未发生的认证背书。
- **修法**：让登录边界真正执行该要求：pending 请求 `RequiresReauthentication(now)` 时把浏览器送回 IdP 登录（`/auth/{provider}/start?mode=login`），只有新的 `SignIn` 盖过时间戳后才 `CompleteLogin`；否则绝不覆盖 `AuthTime`。`internal/oidcstore` 增加 `ErrReauthenticationRequired`，两后端 `CompleteLogin` 不再伪造。
- **状态**：FIXED（992710b）
- **证据**：`internal/oidcstore/zz_audit9_freshness_test.go`、`internal/store/memory/zz_audit9_reauth_test.go`、`internal/auth/zz_audit9_reauth_route_test.go`、`internal/zzprobe/protocol/audit9_basic_op_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）

### S06-1 OIDC discovery / JWKS 用无上限 io.ReadAll 读取（自带 1 MiB 上限覆盖不到）
- **严重度**：P0 · 阻断上线（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`idp/idp.go:298; idp/idp.go:711; idp/idp.go:836`
- **影响**：go-oidc 读 discovery 与 JWKS 时是裸 `io.ReadAll(resp.Body)`，唯一约束是 10s 超时（限时不限字节），且 net/http 透明解压 gzip，一个压缩炸弹可在一次正常登录中把进程 OOM。adapter 自己的 1 MiB 上限只作用于 userinfo/QQ。
- **修法**：把交给 `oidc.ClientContext` 的 client 包一层限流 RoundTripper（既查 ContentLength 也硬限 `resp.Body`），复用已有的 1 MiB 上限。
- **状态**：FIXED（992710b）
- **证据**：`idp/zz_audit9_discovery_body_test.go`、`idp.maxDiscoveryBytes`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）

### S08-2 driver 由 dsn_env 推断时，storage.dsn_env 从不被解析 → 静默内存模式
- **严重度**：P0 · 阻断上线（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`cmd/re0auth/config.go:680-710; cmd/re0auth/config.go:472; cmd/re0auth/config.go:722-724; cmd/re0auth/config.go:749-759; cmd/re0auth/main.go:892-917`
- **影响**：`databaseURL` 只从字面量 `DATABASE_URL` 预载。Driver 为空且 `dsn_env` 指向别的变量时，switch 把 driver 定为 postgres 却从不解析该变量，`openStorage` 按空 URL 走内存分支：不要求 `RE0AUTH_AUDIT_KEY`、审计链退化为内存 ring、重启丢全部状态、`max_in_flight` 按内存标定，且启动日志的 `because=""` 掩盖了原因。显式 driver 下环境里残留的 `DATABASE_URL` 还会盖过文件声明的变量。
- **修法**：推断分支用与显式分支相同的代码解析 DSN；声明了但未设置的变量按启动错误处理；文件的 `dsn_env` 优先于字面量 `DATABASE_URL`。
- **状态**：FIXED（992710b）
- **证据**：`cmd/re0auth/zz_audit9_dsnenv_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）

### S10-1 并发上限的"单客户端半量"按 (平面,客户端) 计数，一个地址可吃满整个进程级信号量
- **严重度**：P0 · 阻断上线（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`internal/httpapi/middleware.go:434; internal/httpapi/middleware.go:459; internal/httpapi/middleware.go:466; internal/httpapi/middleware.go:491`
- **影响**：信号量是进程级的，但每客户端计数按 `plane|client`：一个源地址在两个命名空间各拿 `maxInFlight/2`，合计等于整个上限（默认 512）。限流约束的是到达率而非占用槽位，探针又豁免两者，于是"一个地址打满全进程并发、其他客户端全 503，而 /healthz、/readyz 仍绿"这一正是该机制要防的 DoS 成立。
- **修法**：并发计数改按客户端身份（不含平面）累计；限流桶键保持 (平面,客户端)。
- **状态**：FIXED（992710b）
- **证据**：`internal/httpapi/zz_audit9_inflight_planes_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）

### S13-1 压缩 406 拒绝在限流器与并发上限之前返回，完全绕过两道边界
- **严重度**：P0 · 阻断上线（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`internal/httpapi/server.go:638; internal/httpapi/server.go:642; internal/httpapi/server.go:643; internal/compress/compress.go:147`
- **影响**：中间件链把 compressor 放在最外层，`negotiate` 不可接受时直接写 406 且不调用 `next`，于是限流令牌与并发槽位都不消耗，但 request-id、可信代理解析、访问日志与指标照付。任何匿名请求带 `Accept-Encoding: *;q=0` 即可无上限地驱动连接/goroutine 与日志洪泛。
- **修法**：把 compressor 移到限流与并发上限之内（`withRateLimit`/`withInFlightLimit` 包在外层）。
- **状态**：FIXED（992710b）
- **证据**：`internal/httpapi/zz_audit9_compress_bypass_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）

### S14-2 CompleteBind 不取 per-binding 锁，在途绑定可复活刚被撤销的绑定与上游凭据
- **严重度**：P0 · 阻断上线（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`internal/federation/bind.go:192; internal/federation/bind.go:198; internal/federation/unbind.go:50; internal/federation/revocation.go:132; internal/federation/killswitch.go:201; internal/federation/refresh.go:40`
- **影响**：per-binding keyedMutex 是"同一绑定只有一个写者"的机制，Unbind/CascadeRevoke/shredBinding/refreshBinding 都持它；只有 CompleteBind 既写 vault 又无条件 `bindings.Put`（忽略 Version）且不持锁。因此绑定回调与撤销并发时，可以在"已解绑/已 Kill Switch 扫过"之后重新造出可用的绑定行与上游令牌，而用户与运维被告知已断开。
- **修法**：CompleteBind 全程持同一把 per-binding 锁（必要时先重读行，确认未刚被解绑），或改成单个 CAS。
- **状态**：FIXED（992710b）
- **证据**：`internal/federation/zz_audit9_bind_unbind_race_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）

### S03-1 return_to 无长度上限且被整段写进服务端 session
- **严重度**：P1 · 高（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`internal/auth/auth.go:612; internal/auth/auth.go:616; internal/auth/auth.go:289; internal/safeurl/safeurl.go:34`
- **影响**：`safeurl.RelativePath` 只校验形状、无字节上限；scs 在响应结束时重写整个 session，于是任意匿名 `GET /auth/{provider}/start` 可为每条请求持久化约 60 KiB 的攻击者选定字节。内存模式进程 RAM 无界增长，Postgres 模式 `sessions.data` 无界增长（SweepExpired 每 15 分钟最多删 1000 行，追不上 50/s 的到达率）。这与同文件对 handle 设的 128 字节上限（"session 整体重写，其字节不能由调用方决定"）自相矛盾。
- **修法**：给 `return_to` 加 `maxReturnToBytes`（如 2048），超长即替换/拒绝，再写入 session。
- **状态**：FIXED（992710b）
- **证据**：`internal/safeurl.MaxRelativePathBytes`、`internal/auth/zz_audit9_returnto_test.go`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）

### S13-5 内存 OP 存储所有 map 无上限；refresh tombstone 每次轮换留一条、存活 30 天，且 5 分钟清扫持全局锁全表扫描
- **严重度**：P1 · 高（第九轮 High；原判 high，对抗性验证 confirmed）
- **位置**：`internal/store/memory/oidc.go:34; internal/store/memory/oidc.go:44; internal/store/memory/oidc.go:52; internal/store/memory/oidc.go:639; internal/store/memory/oidc.go:1153; internal/store/memory/oidc.go:1174; internal/store/memory/oidc.go:1180; internal/store/memory/oidc.go:1488`
- **影响**：每次 refresh 轮换写一条以被消费令牌自身 30 天到期时间为期限的 tombstone，速率无 per-subject/进程上限。默认限流下可达 ~1.3e8 条、数 GB，OOM 或 GC 死亡；即便低速率，每 5 分钟的 `opJanitor` 也要持 `s.mu` 整表扫描，周期性冻结全部令牌操作。
- **修法**：给 store 加总量/tombstone 上限（默认 65536），超出丢弃最旧；清扫尽量移出全局锁或分片。
- **状态**：FIXED（992710b）
- **证据**：`internal/store/memory/zz_audit9_tombstones_test.go`、`MaxRefreshTombstones`；完整机制与验证备注见 `docs/security-audit-9.md` §1
- **来源**：`docs/security-audit-9.md` §1（第九轮独立审计）

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| S01-1 | P2 | 已批准的 device_code 可无限次兑换：每次轮询都铸出全新令牌对，而非消费掉该授权（§5 合并：S04-1） | oauth/device.go:302-308; oauth/device.go:269-309 | OPEN | 轮询命中 DeviceApproved 后无条件 `s.issue`，从不标记消费或删除记录；撤销授权也会被静默撤销掉。属 `oauth` 包手写 AS（生产二进制未挂载该端点，嵌入/套件路径可达）。；让 approved 记录单次消费（置 spent/删除）后再签发；`DeviceStore` 增消费操作。 |
| S01-2 | P2 | MemoryDeviceStore 从不清理 pending/decided 记录，设备授权无界增长（§5 合并：S04-3、S14-8、S13-10） | oauth/device.go:139-163; oauth/device.go:224-247; oauth/as.go:57-59 | OPEN | `SaveDevice` 只插入 byDev/byUser，包内无删除、无过期清扫、无 `SweepExpired` 对应物；过期只在读时判。；加删除/清扫 API 并接入后台循环；给每用户与总量设上限。 |
| S01-3 | P2 | MemoryStore.ConsumeRefresh 忽略 tombstone 期限，过期已消费值仍触发家族撤销（PG 正确报未知） | oauth/tokens.go:440-450; oauth/tokens.go:248-261; oauth/as.go:264-283; internal/store/postgres/oauth.go:269-284 | OPEN | tombstone 带 `ExpiresAt` 且注释承诺按其自身期限到期，但 `ConsumeRefresh` 从不读该字段。；消费时比较 `tomb.ExpiresAt` 与 store 时钟，过期按未知令牌处理。 |
| S01-6 | P2 | AuthenticateClient 把公开客户端当"已认证"，cascade 撤销闸门对公开客户端形同虚设 | oauth/as.go:437-448; oauth/as.go:89-92; upstreamkit/server.go:330-357 | OPEN | `client(..., auth=true)` 只在 `ClientConfidential` 时校验 secret，公开客户端忽略 secret 无条件成功。；公开客户端一律认证失败（或要求机密）；套件补"无认证 must 被拒"断言。 |
| S02-2 | P2 | prompt=none 有活会话时被送进交互同意 UI，而不是回 consent_required | internal/oidchttp/oidchttp.go:991; internal/oidchttp/oidchttp.go:995; cmd/re0auth/main.go:1341 | FIXED（992710b） | 本 OP 不保存可复用同意，每次授权都是新 AuthRequest，只看 `Done` 不查历史授权。；有会话且无记忆同意时按 OIDC Core §3.1.2.1 回 `consent_required`。 |
| S02-3 | P2 | 设备授权端点拒绝合规的 Basic secret：client_id 做了 form-unescape，secret 没有 | internal/oidchttp/oidchttp.go:1114; internal/oidchttp/oidchttp.go:1152; internal/oidchttp/oidchttp.go:1175 | OPEN | `basicSecret` 原样比对存储的 SHA-256，而 RFC 6749 §2.3.1 要求 client 对两者都做 form-urlencode。；id 与 secret 成对解码后再认证。 |
| S02-4 | P2 | ValidateSigner 的 2048 位下限只作用于当前键，不覆盖 JWKS 里公布的 retired key | internal/oidcstore/oidcstore.go:62; internal/oidcstore/oidcstore.go:69; internal/oidcstore/oidcstore.go:73 | OPEN | retired key 的 Public 与当前键一起进 KeySet 并用于 id_token hint / access token 验证，弱键可继续验签。；对 KeySet 中全部签名键统一执行位数下限。 |
| S04-1 | P2 | 已启用的设备授权永不被消费：一个 device_code 铸无限令牌对并静默撤销掉一次 grant 撤销 | oauth/device.go:302-309; oauth/device.go:124-137; oauth/grants.go:128-137 | OPEN | （与 S01-1 同根、同位置，见 §5 合并表）；同 S01-1。 |
| S05-1 | P2 | 刷新拒绝把任何 400/401/403 都判为"授权已死"并加密销毁绑定 | internal/federation/refresh.go:170; internal/federation/refresh.go:179; internal/federation/refresh.go:142 | OPEN | 不看 OAuth error code 与响应体；`refreshRejected` 直接 `vault.Revoke` + `bindings.Delete`，连可重试的配置错误也一并 shred。；按 error code 分类（invalid_grant 才判死），可重试错误保留绑定并标冷却。 |
| S05-2 | P2 | （§5 合并入 S14-2）CompleteBind 绕过 per-binding 锁 | internal/federation/bind.go:157; internal/federation/bind.go:192; internal/federation/bind.go:198; internal/federation/unbind.go:50; internal/federation/killswitch.go:200 | OPEN |  |
| S06-2 | P2 | 配置了 HTTP(S)_PROXY 时，SSRF 私网拦截作用在代理地址而非目标地址 | httpclient/outbound.go:92; httpclient/outbound.go:95; httpclient/outbound.go:42 | OPEN | `http.ProxyFromEnvironment` 让 DialContext（以及 Control 钩子）拿到代理地址，目标主机从未被解析或检查。；在拨号前解析并校验目标地址，或对配置了代理的部署禁用私网直连。 |
| S06-3 | P2 | oidcProvider 持 providerMu 跨一次网络 discovery，失败又不缓存 ⇒ 一个死 issuer 串行化所有并发登录 | idp/idp.go:705; idp/idp.go:711; idp/idp.go:713 | OPEN | 锁覆盖整个 `oidc.NewProvider`（10s 超时），失败不推进 `discoveredAt`，每次请求重试。；发现移出锁（double-checked）或 singleflight + 短超时 + 负缓存。 |
| S06-4 | P2 | SocialLogin.states 无界 map，且每次未认证 start 都在锁下 O(n) 清扫 | referencesource/social.go:102; referencesource/social.go:104; referencesource/social.go:193 | OPEN | 无上限、无周期清扫，过期只靠每次新 start 的全表扫描执行。；给在途授权设上限 + 周期清扫（不随请求数线性）。 |
| S06-5 | P2 | TapTapLogin.attempts 同样无界、每 challenge 一次 O(n) 清扫，未认证可达 | referencesource/taptap.go:124; referencesource/taptap.go:126; referencesource/taptap.go:258 | OPEN | 每条 entry 还持有 DeviceAuth（含验证 URL/码），单条内存不小。；同 S06-4。 |
| S07-1 | P2 | 凭据型出站请求完全依赖注入 Doer 的跳转策略；net/http 会把自定义认证头复制到跨主机跳转目标 | tapsign/client.go:114; tapsign/client.go:115; tapsign/client.go:125; taptapoauth/client.go:195 | OPEN | X-LC-Session / X-LC-Key / 上游 MAC Authorization 在 CheckRedirect 为 nil（stdlib 默认）时会跟随跳转并携带。；客户端强制禁止跨主机跳转或在跳转时剥离认证头。 |
| S07-2 | P2 | vault.Enroll 先持久化凭据、后写审计事件 ⇒ 审计失败时对一次已发生的写入报错，留下未审计（federation 里还是孤儿）的秘密 | vault/service.go:245; vault/service.go:259 | OPEN | 与 `Use` 的 fail-closed（先审计后交明文）相反。；先审计后写入，或写入失败时回滚并在错误里 Join 审计错误。 |
| S08-1 | P2 | Vault KEK 解析硬编码 RE0AUTH_KEK 优先于 vault.kek_env，重命名的键被静默忽略 | cmd/re0auth/config.go:729-743; cmd/re0auth/config.go:471; scripts/backup-keys.sh:74-77 | OPEN | 其他设置都遵循 env > 文件约定或专用 RE0AUTH_ 覆盖，KEK 却先读死名字。；`kek_env` 存在时只读它；与 `RE0AUTH_KEK` 不一致时拒绝启动并点名。 |
| S08-4 | P2 | DeleteAccount 在本地移除 Failed>0 时仍报成功并写 outcome=ok | internal/lifecycle/lifecycle.go:200-206; internal/lifecycle/lifecycle.go:313-315; internal/federation/killswitch.go:140-146; internal/federation/killswitch.go:180-183 | OPEN | `RevokeUserBindings` 只在无法枚举时返错；单条绑定的本地移除失败被折叠进结果。；把 Failed>0 反映到 outcome 与错误，别写 ok。 |
| S09-1 | P2 | 迁移回退路径可把带密码的 DSN 写进日志：withMigrationLock 不过滤驱动的解析错误 | internal/store/postgres/postgres.go:378; internal/store/postgres/postgres.go:399; internal/store/postgres/postgres.go:402; internal/store/postgres/postgres.go:240; internal/store/postgres/postgres.go:452 | OPEN | `MigrateDown` 直接走 `withMigrationLock`，从不经过 `poolConfig` 的 `redactDSNParseError`。；对该路径的错误同样调用 `redactDSNParseError`。 |
| S09-2 | P2 | Tokens.RevokeTokens 并非事务，尽管 revokeMatching 注释声称在事务里 ⇒ 批量 Kill Switch/擦除可半执行 | internal/store/postgres/oauth.go:466; internal/store/postgres/oauth.go:471; internal/store/postgres/oauth.go:517; internal/store/postgres/oidc.go:1503 | OPEN | `revokeMatching` 跑在 `s.pool`（autocommit），之后另有两条 DELETE 也在池上。；把 revokeMatching 与其后的 DELETE 包进同一事务。 |
| S10-2 | P2 | readiness 探针 panic 会把 /readyz 永久钉在 "checking"(503)（§5 合并：S14-9） | internal/httpapi/health.go:183; internal/httpapi/health.go:194 | OPEN | `check` 在调用探针前置 `running=true`，只在正常返回路径复位；panic 后 `settled` 永不关闭。；`defer` 复位 `running`/关闭 `settled`，panic 也走异常路径复位。 |
| S11-6 | P2 | /v1/admin/audit/verify 同步全表走链、无并发约束，最长持有池连接 45s | internal/httpapi/audit_routes.go:171; internal/store/postgres/auditchain.go:220; internal/store/postgres/auditchain.go:264 | OPEN | 开事务、抬 statement_timeout 到 45s、整表扫描；无 per-endpoint 并发上限也无结果缓存。；加并发上限（或缓存结果），必要时改成可中断的分段校验。 |
| S12-1 | P2 | 每次尝试的请求超时在读取响应体之前就被解除 | web/src/lib/api.ts:334; web/src/lib/api.ts:354; web/src/lib/api.ts:369 | OPEN | `fetch` 在响应头到达即 resolve，唯一 deadline 在 `res.text()` 之前被 clear，body 卡住时 abort 永不触发。；把 clearTimeout 移到 body 读取完成之后（或到 finally）。 |
| S13-2 | P2 | StoreDeviceAuthorization 每次公开请求都持 store 全局锁 O(n) 扫描（§5 合并：S13-3、S14-1、S14-6、S14-7） | internal/store/memory/oidc.go:1050; internal/store/memory/oidc.go:1053; internal/store/memory/oidc.go:1124 | OPEN | 唯一 mutex 同时守所有令牌操作，设备授权端点公开可达。；为设备记录建索引/分桶，避免持全局锁扫描。 |
| S13-3 | P2 | DeleteAuthRequest 每次令牌兑换都在全局锁下扫描全部 pending code | internal/store/memory/oidc.go:508; internal/store/memory/oidc.go:516 | OPEN | 库在每次授权码铸令牌后调用它，按 requestID 线性查找。；加 requestID→code 索引并在同一临界区维护。 |
| S14-3 | P2 | 内存 store 分页器每页重排全表：vault Rotate 与 federation Kill Switch 变成 O(N²logN) | vault/repo.go:229; vault/repo.go:233; vault/rotate.go:45; internal/federation/binding.go:255; internal/federation/binding.go:262; internal/federation/killswitch.go:58 | OPEN | 每页都物化全部行、排序、再用游标过滤，游标不减少工作量。；让游标真正参与分页（持久有序索引或快照）。 |
| S14-5 | P2 | refresh 家族撤销与轮换非原子，并发重放可留下新世代 token | oauth/as.go:264; oauth/as.go:276; oauth/as.go:308; oauth/as.go:418; oauth/as.go:421; oauth/tokens.go:434 | OPEN | `ConsumeRefresh` 原子，但 `ConsumeRefresh → RevokeRefreshFamily` 与 `ConsumeRefresh → issue` 不是。；把"消费+撤销/签发"做成一个原子步骤（或家族级锁）。 |
| S14-6 | P2 | 内存 OIDCStore 的重放与撤销在单一把全局锁下扫描全部令牌与 tombstone | internal/store/memory/oidc.go:716; internal/store/memory/oidc.go:720; internal/store/memory/oidc.go:726; internal/store/memory/oidc.go:787; internal/store/memory/oidc.go:806 | OPEN | （与 S13-2 同根，见 §5 合并表）；同 S13-2。 |
| S15-1 | P2 | age 加密失败时 scripts/backup.sh 把明文转储留在磁盘 | scripts/backup.sh:44-48; scripts/backup.sh:10 | OPEN | 脚本 `set -euo pipefail`，`age` 非零即退出，后面的 shred/rm 永不执行。；trap 清理 + 先写临时目录，失败也删明文。 |
| S15-3 | P2 | 备份 CronJob 无 activeDeadlineSeconds：一次 pg_dump 挂死会静默停掉之后所有备份 | deploy/k8s/backup/cronjob.yaml:11-22; deploy/k8s/backup/cronjob.yaml:59-70 | OPEN | `concurrencyPolicy: Forbid` 会跳过新调度，jobTemplate 只有 backoffLimit。；加 activeDeadlineSeconds 与 pg_dump 侧 timeout。 |
| S01-10 | P3 | Client secrets are stored as an unsalted SHA-256 digest, so a weak config-file secret is off-line crackable if the store leaks | oauth/client.go:99-105; oauth/client.go:107-114; cmd/re0auth/main.go:1634-1643 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S01-11 | P3 | MemoryStore serialises all token operations on one Mutex and scans every record under the lock, so account-page reads and sweeps block token introspection | oauth/tokens.go:263-273; oauth/tokens.go:298-328; oauth/grants.go:157-221 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S01-12 | P3 | Store reads return struct copies whose Scopes slices alias the stored backing array, so a caller mutating a returned record corrupts stored authorization state | oauth/tokens.go:373-382; oauth/tokens.go:341-349; oauth/tokens.go:421-429; oauth/as.go:370-376 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S01-4 | P3 | Token issuance is not atomic: a failure after SaveAccess leaves a live, undeliverable access token in the store | oauth/as.go:405-432; oauth/as.go:388-423 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S01-5 | P3 | Client authentication tells an unknown client apart from a wrong secret, contradicting the kit's stated indistinguishability requirement | oauth/as.go:437-448; upstreamkit/server.go:339-345 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S01-7 | P3 | RotateSecret accepts a hash of any length while RestoreClient demands sha256.Size, so a bad rotation silently locks a confidential client out | oauth/client.go:415-432; oauth/client.go:124-145; oauth/client.go:107-114 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S01-8 | P3 | Revoke cannot reach a spent refresh token's tombstone: the documented DeleteRefresh tombstone-clear is unreachable and RFC 7009 revocation of a rotated token is a false success | oauth/as.go:311-345; oauth/tokens.go:393-405; oauth/tokens.go:453-464 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S01-9 | P3 | Audit failures are silently discarded, so reuse detection, revocation and failed exchanges can go unrecorded | oauth/as.go:451-459 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S02-10 | P3 | No length cap on state, nonce (or other authorize parameters) at the entrance, unlike PKCE, request-id and handle ids | internal/oidchttp/oidchttp.go:934; internal/oidchttp/oidchttp.go:1046; internal/oidchttp/oidchttp.go:1416 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S02-6 | P3 | Protocol-plane 405 responses omit the mandatory Allow header | internal/oidchttp/oidchttp.go:478; internal/oidchttp/oidchttp.go:256; internal/oidchttp/oidchttp.go:263 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S02-7 | P3 | Discovery rewrite mutates URL.Path but not RawPath, so a percent-encoded RFC 8414 alias 404s instead of serving the OIDC document | internal/oidchttp/oidchttp.go:255; internal/oidchttp/oidchttp.go:300; internal/oidchttp/oidchttp.go:46 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S02-8 | P3 | Handler.Introspect collapses a store outage into Active=false, reporting infrastructure failure to /v1 as an invalid token | internal/oidchttp/oidchttp.go:1677; internal/oidchttp/oidchttp.go:1664 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S02-9 | P3 | Every successful token response is fully JSON-decoded and re-encoded by sanitizeTokenResponse | internal/oidchttp/oidchttp.go:1538; internal/oidchttp/oidchttp.go:670; internal/oidchttp/oidchttp.go:761 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S03-10 | P3 | Kill Switch session revocation is unbounded and not atomic | internal/store/postgres/sessions.go:198; internal/store/postgres/sessions.go:202; internal/store/postgres/sessions.go:216 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S03-11 | P3 | core.App.Remove races with an in-flight load, allowing a removed fiber to be marked active without its scope | internal/core/app.go:99; internal/core/app.go:105; internal/core/app.go:334 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S03-2 | P3 | SignIn leaves an authenticated session outside the SessionIndex when RenewToken fails | internal/auth/auth.go:161; internal/auth/auth.go:166; internal/auth/auth.go:177 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S03-3 | P3 | EndSession forgets the session index before destroying the session, so a failed sign-out leaves an unrevocable live session | internal/auth/auth.go:210; internal/auth/auth.go:212; internal/auth/auth.go:216 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S03-4 | P3 | Concurrent first login of the same identity is reported as signup_failed instead of retrying the lookup | internal/auth/auth.go:713; internal/auth/auth.go:714; internal/auth/auth.go:716 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S03-5 | P3 | Session referencing a missing account answers 500 instead of tearing the session down | internal/httpapi/session_routes.go:27; internal/httpapi/session_routes.go:29; internal/httpapi/identity_routes.go:26; internal/httpapi/export_routes.go:64 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S03-6 | P3 | Admin authorization trusts the session claim without re-checking that the account still exists | internal/httpapi/admin_routes.go:62; internal/httpapi/admin_routes.go:67; internal/httpapi/server.go:305 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S03-7 | P3 | MemoryStore.Identities scans every identity in the process and holds the lock for the whole scan | internal/account/account.go:231; internal/account/account.go:281; internal/account/account.go:283 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S03-8 | P3 | Postgres Identities uses an EXISTS round trip before the real SELECT | internal/store/postgres/account.go:236; internal/store/postgres/account.go:244 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S03-9 | P3 | clearFlow does not remove the OIDC nonce from the session | internal/auth/auth.go:44; internal/auth/auth.go:737; internal/auth/auth.go:739 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S04-2 | P3 | BeginDeviceAuthorization does not authenticate confidential clients, allowing anonymous device requests that impersonate a trusted client on the consent screen | oauth/device.go:224-228; oauth/device.go:415-419; oauth/device.go:437-448 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S04-3 | P3 | MemoryDeviceStore never expires anything: device authorizations accumulate for the process lifetime | oauth/device.go:140-163; oauth/device.go:224-247 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S04-4 | P3 | Grants page scans every token in the process under the store's single mutex (no subject index in the in-memory store) | oauth/grants.go:158-180; internal/httpapi/grants_routes.go:31-43 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S04-5 | P3 | freeUserCode treats every store error as a collision and checks uniqueness non-atomically | oauth/device.go:432-443; oauth/device.go:155-163 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S04-6 | P3 | slow_down is returned before the terminal device status, and the advertised interval is truncated | oauth/device.go:289-307; oauth/device.go:252-255 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S04-7 | P3 | Consent decision conflates store failures with an expired authorization request | internal/httpapi/authorization_routes.go:97-101; internal/httpapi/authorization_routes.go:151-155; internal/httpapi/authorization_routes.go:159-166; internal/httpapi/authorization_routes.go:173-183 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S04-8 | P3 | Registry.Register mutates the scope map without synchronization while Get/Resolve read it concurrently（§5 合并：S14-10） | oauth/scope.go:183-197; oauth/scope.go:199-213; oauth/scope.go:217-235 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S04-9 | P3 | Device authorization accepts an empty scope set and issues a scope-less token pair | oauth/device.go:224-228; oauth/device.go:373-386; oauth/device.go:308 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S05-3 | P3 | MemoryBindingStore.List pre-allocates for the whole deployment and ListAllPage re-sorts the whole map on every page | internal/federation/binding.go:219; internal/federation/binding.go:262; internal/federation/binding.go:255 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S05-4 | P3 | MissingBindings is O((sources x resources)^2) with a copy+sort per candidate lookup | internal/federation/missing.go:65; internal/federation/missing.go:70; internal/federation/missing.go:74 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S05-5 | P3 | NewRegistry validates RawBase and token_class but not Status, so an unrecognized status is fail-open | internal/federation/federation.go:162; internal/federation/federation.go:173; internal/federation/federation.go:637 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S05-6 | P3 | Source.Issuer and endpoint overrides are not validated as absolute http(s), unlike RawBase | internal/federation/federation.go:144; internal/federation/federation.go:151; internal/federation/bind.go:150; internal/federation/bind.go:235 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S05-7 | P3 | BeginBind and CompleteBind accept a retired source that the rest of the plane refuses | internal/federation/bind.go:127; internal/federation/bind.go:171; internal/federation/service.go:637 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S05-8 | P3 | revokeUpstream logs a vault error that can embed the raw subject identity | internal/federation/unbind.go:124; vault/service.go:309 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S06-10 | P3 | SocialLogin stores and echoes return_to without safeurl.RelativePath validation | referencesource/social.go:108; referencesource/social.go:189 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S06-6 | P3 | Conformance runner leaks the response body of a non-200 metadata document (never closed) | upstreamkit/conformance/conformance.go:211; upstreamkit/conformance/conformance.go:212; upstreamkit/conformance/conformance.go:216 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S06-7 | P3 | A partial AuthURL/TokenURL override on a discovered OIDC provider is silently discarded | idp/idp.go:505; idp/idp.go:507; idp/idp.go:520 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S06-8 | P3 | Injected RegistryConfig.HTTPClient may have no timeout, and go-oidc's JWKS fetch is context.WithoutCancel'd, so a hung IdP can pin a login goroutine | idp/idp.go:287; idp/idp.go:751; idp/idp.go:648 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S06-9 | P3 | federation.NewService's Doer-only fallback builds an outbound client with the SSRF guard off | internal/federation/service.go:376; httpclient/outbound.go:304 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S07-10 | P3 | tapsign.Rotate returns the replacement token together with an audit error, inviting callers to discard a token that is now the only live credential | tapsign/client.go:60; tapsign/client.go:197 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S07-3 | P3 | MemoryRepo.ListPage reloads clones and re-sorts the entire store on every page, making a rotation O(N^2 log N) with N clones per page | vault/repo.go:229; vault/repo.go:233 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S07-5 | P3 | taptapoauth accepts upstream-controlled interval and expires_in without an upper bound or overflow guard | taptapoauth/client.go:96; taptapoauth/client.go:100 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S07-6 | P3 | tapsign.Verify performs a credential-bearing upstream call with no audit record | tapsign/client.go:44; tapsign/client.go:40 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S08-3 | P3 | DeleteAccount writes an outcome=ok record claiming the pseudonym key was destroyed before Destroy runs, and the correcting record is best-effort | internal/lifecycle/lifecycle.go:262-271; internal/lifecycle/lifecycle.go:277-291; internal/lifecycle/lifecycle.go:299-302 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S08-5 | P3 | Universal trusted-proxy list check only matches a single /0 prefix, so two /1 entries bypass the acknowledgement | cmd/re0auth/config.go:1016-1023; cmd/re0auth/config.go:589-601 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S08-6 | P3 | -print-secret-env echoes whatever is in an *_env name slot verbatim, disclosing a value pasted into the wrong field | cmd/re0auth/config.go:424-431; cmd/re0auth/config.go:441-445; cmd/re0auth/main.go:276-290 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S08-7 | P3 | Graceful-shutdown drain budget (30s) is shorter than dataPlaneTimeout (45s), so shutdown cuts the request the design says must get a readable refusal | cmd/re0auth/main.go:128; cmd/re0auth/main.go:116-150; cmd/re0auth/main.go:854-866 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S08-8 | P3 | An explicitly configured max_upstream_buffer_bytes = 0 is silently replaced by the 64 MiB default | cmd/re0auth/config.go:553-571; cmd/re0auth/main.go:523; internal/federation/service.go:382-383 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S08-9 | P3 | A custom OIDC provider's issuer is not required to be https, so the token exchange can run in cleartext | cmd/re0auth/config.go:855-890; idp/idp.go:530-548 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S09-3 | P3 | UnlinkIdentity masks any database error as ErrNotFound because ownership is checked before err | internal/store/postgres/account.go:199 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S09-5 | P3 | Rolling back migrations 0024/0025 silently drops refresh-family tombstones and replay detection; the MigrateDown guard only covers 13/14 | internal/store/postgres/postgres.go:469; internal/store/postgres/postgres.go:496; internal/store/postgres/migrations/0024_refresh_token_family.sql:50; internal/store/postgres/migrations/0025_oauth_refresh_family.sql:59 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S09-6 | P3 | Verify reads audit_chain.head_hash as a witness but never compares it to the walked chain, so tail truncation is not detected even though the anchor is in hand | internal/store/postgres/auditchain.go:259; internal/store/postgres/auditchain.go:346 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S09-7 | P3 | Database outages are collapsed into protocol 'not found' on the authorization-code and device-poll paths, unlike every refresh/revocation path | internal/store/postgres/oidc.go:327; internal/store/postgres/oidc.go:1210; internal/store/postgres/oidc.go:660 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S09-8 | P3 | Several multi-statement deletes run without a transaction, leaving orphaned session index rows and post-revocation replay tombstones | internal/store/postgres/sessions.go:197; internal/store/postgres/sessions.go:211; internal/store/postgres/oauth.go:290; internal/store/postgres/oauth.go:495 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S09-9 | P3 | Audit pseudonym cache is dropped wholesale at 4096 entries, so bursts over distinct subjects put 1-3 extra queries on the vault fail-closed path | internal/store/postgres/auditpseudo.go:144; internal/store/postgres/auditpseudo.go:115; internal/store/postgres/auditpseudo.go:69 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S10-3 | P3 | Compression writer is never closed or pooled when a handler panics after compression starts | internal/compress/compress.go:160; internal/compress/compress.go:162 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S11-1 | P3 | Admin audit detail stores the raw operator account id in Detail["actor"], defeating pseudonym-key destruction | internal/admin/admin.go:485; internal/admin/admin.go:490; audit/audit.go:73; audit/audit.go:84 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S11-2 | P3 | Kill Switch silently reports sessions_revoked=0 when the deployment has no session revoker, with no unavailability marker | internal/admin/admin.go:351; internal/admin/admin.go:167; internal/admin/admin.go:169; cmd/re0auth/main.go:618; cmd/re0auth/main.go:903 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S11-3 | P3 | Kill Switch `all` cannot purge in-flight bind flows and does not say so, allowing access to be re-created after the sweep（§5 合并：S11-5） | internal/admin/admin.go:399; internal/admin/admin.go:404; internal/federation/bind.go:47 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S11-4 | P3 | Kill Switch returns a bare 500 on a partial failure, discarding the counts of what was already revoked | internal/admin/admin.go:361; internal/admin/admin.go:388; internal/httpapi/admin_routes.go:281 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S11-5 | P3 | Kill Switch `client` target aborts before token revocation when the client row is gone, so its live tokens survive | internal/admin/admin.go:324; internal/admin/admin.go:326; internal/httpapi/admin_routes.go:277 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S11-7 | P3 | Audit subject filter performs an uncached negative DB lookup per distinct subject and leaks 'has pseudonym key' timing | internal/store/postgres/auditpseudo.go:69; internal/store/postgres/auditread.go:67; internal/store/postgres/auditpseudo.go:144 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S11-8 | P3 | Account export claims to be everything held about the account but omits sessions, issued tokens and audit history, while the notice only disclaims credentials | internal/httpapi/export_routes.go:10; internal/httpapi/export_routes.go:30; internal/httpapi/export_routes.go:39 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S11-9 | P3 | GET /v1/admin/clients returns every client with no pagination or cap | internal/httpapi/admin_routes.go:100; internal/store/postgres/oauth.go:732 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S12-10 | P3 | Response shape validation is applied to only two endpoints; the rest throw inside render and expose the JS error via +error.svelte | web/src/lib/api.ts:468; web/src/lib/api.ts:480; web/src/routes/admin/+page.svelte:72; web/src/routes/+error.svelte:9 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S12-3 | P3 | Stale ?error= is carried through SignIn return_to, so a later successful sign-in still reports failure | web/src/routes/+page.svelte:40; web/src/routes/+page.svelte:241 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S12-4 | P3 | Attacker-controlled ?error= is rendered verbatim inside the branded failure alert | web/src/routes/+page.svelte:41; web/src/routes/+page.svelte:82 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S12-5 | P3 | Account export revokes the object URL synchronously and trusts an unvalidated profile field | web/src/routes/+page.svelte:162; web/src/routes/+page.svelte:164 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S12-6 | P3 | Focus restoration builds a CSS selector by string interpolation from server/config ids | web/src/lib/a11y.ts:33; web/src/lib/a11y.ts:35; web/src/routes/sources/+page.svelte:186; web/src/routes/grants/+page.svelte:73 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S12-8 | P3 | SPA shell is sent with no cache validator, so Cache-Control: no-cache forces a full body transfer each load | internal/webui/webui.go:151; internal/webui/webui.go:152 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S13-10 | P3 | oauth.MemoryStore / MemoryDeviceStore / MemoryClientRegistry have no cap and no in-process janitor | oauth/tokens.go:263; oauth/tokens.go:285; oauth/device.go:139; oauth/client.go:334 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S13-11 | P3 | perfreport divides by the baseline median without a zero check, producing NaN/Inf deltas and a NaN geomean | cmd/perfreport/main.go:355; cmd/perfreport/main.go:373 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S13-4 | P3 | Device approve/deny call the synchronous audit sink while holding the OIDC store's global mutex | internal/store/memory/oidc.go:1308; internal/store/memory/oidc.go:1326; internal/store/memory/oidc.go:1334; internal/store/memory/oidc.go:1347; audit/audit.go:35; internal/store/postgres/audit.go:54 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S13-6 | P3 | compress responseWriter swallows the final status after a 1xx header | internal/compress/compress.go:318; internal/compress/compress.go:327 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S13-7 | P3 | HTTP status metric label is not normalized and can be set from an upstream-controlled status | internal/observability/observability.go:310; internal/observability/observability.go:629; internal/httpapi/federation_routes.go:320 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S13-8 | P3 | pprof profile/trace endpoints accept unbounded seconds and have no concurrency or size cap | internal/observability/observability.go:611; internal/observability/observability.go:616; internal/observability/observability.go:618 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S13-9 | P3 | Oversized chunked JSON bodies surface as 400 'malformed JSON body' instead of the middleware's plane-shaped 413 | internal/httpapi/admin_routes.go:133; internal/httpapi/authorization_routes.go:144; internal/httpapi/device_routes.go:105; internal/httpapi/binding_routes.go:202; internal/httpapi/account_routes.go:44; internal/httpapi/middleware.go:113; oauth/bodylimit.go:33 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S14-1 | P3 | memory.OIDCStore device decision holds the store-wide mutex across a durable audit write | internal/store/memory/oidc.go:1308; internal/store/memory/oidc.go:1326; internal/store/memory/oidc.go:1334; internal/store/memory/oidc.go:1347 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S14-10 | P3 | oauth.Registry.Register mutates a map that Resolve/Get/Descriptors read without any lock | oauth/scope.go:185; oauth/scope.go:195; oauth/scope.go:200; oauth/scope.go:208; oauth/scope.go:226 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S14-4 | P3 | federation.MemoryBindingStore.List has no per-user index: every account page scans all bindings under the read lock | internal/federation/binding.go:215; internal/federation/binding.go:219; internal/federation/binding.go:220 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S14-7 | P3 | memory.OIDCStore.StoreDeviceAuthorization purges expired devices with a full scan under the lock on every call | internal/store/memory/oidc.go:1051; internal/store/memory/oidc.go:1053; internal/store/memory/oidc.go:1124 | OPEN | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S14-8 | P3 | oauth.MemoryDeviceStore has no deletion path and no sweep, so device records grow without bound | oauth/device.go:140; oauth/device.go:206; oauth/as.go:57; oauth/as.go:58 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S14-9 | P3 | readinessCache is not panic-safe: a panicking readiness probe latches /readyz to 503 'checking' forever | internal/httpapi/health.go:183; internal/httpapi/health.go:190; internal/httpapi/health.go:192; internal/httpapi/health.go:195 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S15-10 | P3 | scripts/backup-keys.sh is committed mode 100644 while the documented invocation runs it directly | scripts/backup-keys.sh:1; docs/operations.md:90-92 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S15-11 | P3 | Release archives embed the built SPA but do not carry the npm attribution the image deliberately includes | Makefile:160-182; Makefile:215-221; Dockerfile:86-90 | OPEN | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S15-2 | P3 | CI/release-gate Postgres service image is a floating tag while every other image in the project is digest-pinned | .github/workflows/ci.yml:34; .github/workflows/ci.yml:278; .github/workflows/perf.yml:45; .github/workflows/release.yml:20 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S15-4 | P3 | .dockerignore excludes scratchpad but not the live audit workspace or generic key shapes, so they enter the `COPY . .` build layer | .dockerignore:42-43; .gitignore:62; Dockerfile:53; .gitleaks.toml:13-20 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S15-5 | P3 | Base ConfigMap hardcodes trusted_proxies to 10.0.0.0/8; on a non-10/8 pod CIDR every client silently shares one rate-limit bucket | deploy/k8s/base/configmap.yaml:43-44; internal/httpapi/clientaddr.go:104-110; internal/httpapi/clientaddr.go:78-81 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S15-6 | P3 | Release image is pushed under its release tag before the Trivy gate runs; only `latest` is withheld | .github/workflows/release.yml:64-80; .github/workflows/release.yml:100-107; .github/workflows/release.yml:109-119; deploy/k8s/base/deployment.yaml:46 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S15-7 | P3 | Trivy scan runs with the host Docker socket mounted inside a job holding packages:write and id-token:write | .github/workflows/release.yml:100-107; .github/workflows/release.yml:36-39 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S15-8 | P3 | Three alert rules keyed on generic go_*/process_* metrics carry no job selector and can fire on unrelated targets | deploy/prometheus/re0auth.rules.yml:304-348; deploy/prometheus/re0auth.rules.yml:4-7 | OPEN | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S15-9 | P3 | Namespace has no Pod Security Admission labels, so the hardened pod spec is not enforced as a precondition | deploy/k8s/base/namespace.yaml:1-4; deploy/k8s/base/deployment.yaml:29-33; deploy/k8s/base/deployment.yaml:108-111 | OPEN | 见 `docs/security-audit-9.md` §3（类别：security） |
| S01-13 | P3 · 信息 | [info] The declared-length pre-check is the only path to 413; a chunked body over the cap surfaces as a 400 malformed-form instead | oauth/bodylimit.go:27-34; upstreamkit/server.go:162-169; upstreamkit/server.go:242-246 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S02-11 | P3 · 信息 | [info] DenyAuthorization uses the static issuer only, so a dynamic-issuer deployment emits a denial without the RFC 9207 iss parameter | internal/oidchttp/oidchttp.go:1794; internal/oidchttp/oidchttp.go:1444 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S02-5 | P3 · 信息 | [info] Discovery documents are cached for the process lifetime while the issuer is derived per request from Host | internal/oidchttp/oidchttp.go:294; internal/oidchttp/oidchttp.go:300; internal/oidchttp/oidchttp.go:193 | OPEN | 见 `docs/security-audit-9.md` §4（类别：security） |
| S05-10 | P3 · 信息 | [info] CompleteBind consumes the flow before the owner check (cross-account DoS), mitigated by the HTTP handler | internal/federation/bind.go:158; internal/federation/bind.go:163; internal/httpapi/federation_routes.go:410 | OPEN | 见 `docs/security-audit-9.md` §4（类别：security） |
| S05-9 | P3 · 信息 | [info] MemoryBindFlowStore.SweepExpired uses time.Now instead of the service clock | internal/federation/bind.go:112; internal/federation/bind.go:144; internal/federation/bind.go:165 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S06-11 | P3 · 信息 | [info] safeurl.RelativePath resists scheme-relative, backslash and control-byte escapes; percent-encoded and dot-segment forms cannot change origin | internal/safeurl/safeurl.go:34 | OPEN | 见 `docs/security-audit-9.md` §4（类别：security） |
| S07-11 | P3 · 信息 | [info] bindingAAD truncates identity lengths to uint32 before length-prefixing | vault/envelope.go:148; vault/envelope.go:150 | OPEN | 见 `docs/security-audit-9.md` §4（类别：security） |
| S07-4 | P3 · 信息 | [info] Use builds the AEAD AAD from the requested identity while Rotate builds it from the stored record identity | vault/service.go:300; vault/rotate.go:104 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S07-7 | P3 · 信息 | [info] taptapoauth bounds upstream error text for logs but only strips CR/LF, leaving other control characters | taptapoauth/client.go:337; taptapoauth/client.go:338 | OPEN | 见 `docs/security-audit-9.md` §4（类别：security） |
| S07-8 | P3 · 信息 | [info] tapsign.drain and the response handling dereference resp and resp.Body without a nil check | tapsign/client.go:224; tapsign/client.go:48 | OPEN | 见 `docs/security-audit-9.md` §4（类别：reliability） |
| S07-9 | P3 · 信息 | [info] Re-enrolling a credential overwrites CreatedAt, discarding the original creation time | vault/service.go:244; vault/service.go:253 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S09-10 | P3 · 信息 | [info] OP token issued_at is written by the database's now(), not the store clock the rest of OIDCStore uses | internal/store/postgres/oidc.go:429; internal/store/postgres/oidc.go:573; internal/store/postgres/migrations/0009_oidc_token_issued_at.sql:5; internal/store/postgres/oidc.go:41 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S09-4 | P3 · 信息 | [info] ConsumeRefresh claims expired values (no expires_at predicate) although the Store contract says "live", unlike the OP store's rotation claim | internal/store/postgres/oauth.go:242; internal/store/postgres/oidc.go:514; oauth/as.go:289; oauth/tokens.go:168 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S10-4 | P3 · 信息 | [info] Business-plane responses carrying the session CSRF token are compressed (BREACH-style compression oracle) | internal/httpapi/server.go:353; internal/compress/compress.go:336; internal/httpapi/session_routes.go:42; internal/httpapi/device_routes.go:75; internal/auth/auth.go:240 | OPEN | 见 `docs/security-audit-9.md` §4（类别：security） |
| S10-5 | P3 · 信息 | [info] Limiter.Check heap-allocates a *rate.Reservation on every request | internal/ratelimit/ratelimit.go:289; internal/ratelimit/ratelimit.go:295 | OPEN | 见 `docs/security-audit-9.md` §4（类别：performance） |
| S12-11 | P3 · 信息 | [info] Every asset request performs three embedded-FS stats | internal/webui/webui.go:106; internal/webui/webui.go:119; internal/webui/webui.go:133 | OPEN | 见 `docs/security-audit-9.md` §4（类别：performance） |
| S12-12 | P3 · 信息 | [info] SignIn appends return_to after a URL fragment, unlike the equivalent link() path | web/src/lib/components/SignIn.svelte:50; web/src/lib/components/SignIn.svelte:52 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S12-2 | P3 · 信息 | [info] Dev root redirect does not match a request that carries a query string | web/vite.config.ts:27; web/vite.config.ts:28 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S12-7 | P3 · 信息 | [info] Sources page re-runs O(available x bindings) scans on every reactive invalidation | web/src/routes/sources/+page.svelte:82; web/src/routes/sources/+page.svelte:89; web/src/routes/sources/+page.svelte:288 | OPEN | 见 `docs/security-audit-9.md` §4（类别：performance） |
| S12-9 | P3 · 信息 | [info] Retried responses are discarded without draining or cancelling the body | web/src/lib/api.ts:358; web/src/lib/api.ts:361 | OPEN | 见 `docs/security-audit-9.md` §4（类别：reliability） |
| S14-11 | P3 · 信息 | [info] oidchttp.serveOAuth can leak a pooled bufferedWriter on panic because release is not deferred | internal/oidchttp/oidchttp.go:636; internal/oidchttp/oidchttp.go:637; internal/oidchttp/oidchttp.go:716; internal/oidchttp/oidchttp.go:717 | OPEN | 见 `docs/security-audit-9.md` §4（类别：reliability） |
| S14-12 | P3 · 信息 | [info] federation.refreshBinding's row-then-secret write order is deliberately protected by the per-binding lock (suspicious but mitigated) | internal/federation/refresh.go:40; internal/federation/refresh.go:111; internal/federation/refresh.go:121 | OPEN | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S15-12 | P3 · 信息 | [info] Backup CronJob writes plaintext database dumps; no age encryption path is wired, unlike scripts/backup.sh | deploy/k8s/backup/cronjob.yaml:59-70; docs/operations.md:125-126 | OPEN | 见 `docs/security-audit-9.md` §4（类别：security） |
| S15-13 | P3 · 信息 | [info] .gitleaks path allowlist exempts any file matching docs/security-audit-<n>.md from every rule | .gitleaks.toml:17-20; .gitleaks.toml:1-6 | OPEN | 见 `docs/security-audit-9.md` §4（类别：security） |

## 已修复

- 第九轮 8 条 High + S02-2 — `992710b`（逐条修法与复现测试见 `docs/security-audit-9.md`「修复状态」）
  - S02-1 `prompt=login`/`max_age` 重认证、S02-2 `prompt=none` 有会话回 `consent_required`、S03-1 `return_to` 2048 字节上限、
    S06-1 discovery/JWKS 1 MiB 上限、S08-2 `dsn_env` 总是解析、S10-1 并发计数改按客户端、
    S13-1 压缩移入限流/并发上限之内、S13-5 refresh tombstone 上限、S14-2 `CompleteBind` 全程持 per-binding 锁
