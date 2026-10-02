# 第 11 轮：本会话修复的状态合并

> 由提交标题反查：某条寄存器 ID 在本会话（`6be9bb2..HEAD`）的提交标题里被点名，即记 `FIXED`。
> 未点名的保持原状态，避免把没有证据的条目误标。优先级最高（prio -4），用于覆盖前几轮的 OPEN 行。

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| S01-1 | P2 | 已批准的 device_code 可无限次兑换：每次轮询都铸出全新令牌对，而非消费掉该授权（§5 合并：S04-1） | oauth/device.go:302-308; oauth/device.go:269-309 | FIXED（153d910） | 轮询命中 DeviceApproved 后无条件 `s.issue`，从不标记消费或删除记录；撤销授权也会被静默撤销掉。属 `oauth` 包手写 AS（生产二进制未挂载该端点，嵌入/套件路径可达）。；让 approved 记录单次消费（置 spent/删除）后再签发；`DeviceStore` 增消费操作。 |
| S01-2 | P2 | MemoryDeviceStore 从不清理 pending/decided 记录，设备授权无界增长（§5 合并：S04-3、S14-8、S13-10） | oauth/device.go:139-163; oauth/device.go:224-247; oauth/as.go:57-59 | FIXED（79a767c） | `SaveDevice` 只插入 byDev/byUser，包内无删除、无过期清扫、无 `SweepExpired` 对应物；过期只在读时判。；加删除/清扫 API 并接入后台循环；给每用户与总量设上限。 |
| S01-3 | P2 | MemoryStore.ConsumeRefresh 忽略 tombstone 期限，过期已消费值仍触发家族撤销（PG 正确报未知） | oauth/tokens.go:440-450; oauth/tokens.go:248-261; oauth/as.go:264-283; internal/store/postgres/oauth.go:269-284 | FIXED（7c5f515） | tombstone 带 `ExpiresAt` 且注释承诺按其自身期限到期，但 `ConsumeRefresh` 从不读该字段。；消费时比较 `tomb.ExpiresAt` 与 store 时钟，过期按未知令牌处理。 |
| S01-6 | P2 | AuthenticateClient 把公开客户端当"已认证"，cascade 撤销闸门对公开客户端形同虚设 | oauth/as.go:437-448; oauth/as.go:89-92; upstreamkit/server.go:330-357 | FIXED（d8de48a） | `client(..., auth=true)` 只在 `ClientConfidential` 时校验 secret，公开客户端忽略 secret 无条件成功。；公开客户端一律认证失败（或要求机密）；套件补"无认证 must 被拒"断言。 |
| S02-3 | P2 | 设备授权端点拒绝合规的 Basic secret：client_id 做了 form-unescape，secret 没有 | internal/oidchttp/oidchttp.go:1114; internal/oidchttp/oidchttp.go:1152; internal/oidchttp/oidchttp.go:1175 | FIXED（284c5be） | `basicSecret` 原样比对存储的 SHA-256，而 RFC 6749 §2.3.1 要求 client 对两者都做 form-urlencode。；id 与 secret 成对解码后再认证。 |
| S02-4 | P2 | ValidateSigner 的 2048 位下限只作用于当前键，不覆盖 JWKS 里公布的 retired key | internal/oidcstore/oidcstore.go:62; internal/oidcstore/oidcstore.go:69; internal/oidcstore/oidcstore.go:73 | FIXED（3617ac2） | retired key 的 Public 与当前键一起进 KeySet 并用于 id_token hint / access token 验证，弱键可继续验签。；对 KeySet 中全部签名键统一执行位数下限。 |
| S05-1 | P2 | 刷新拒绝把任何 400/401/403 都判为"授权已死"并加密销毁绑定 | internal/federation/refresh.go:170; internal/federation/refresh.go:179; internal/federation/refresh.go:142 | FIXED（1c3f249） | 不看 OAuth error code 与响应体；`refreshRejected` 直接 `vault.Revoke` + `bindings.Delete`，连可重试的配置错误也一并 shred。；按 error code 分类（invalid_grant 才判死），可重试错误保留绑定并标冷却。 |
| S06-3 | P2 | oidcProvider 持 providerMu 跨一次网络 discovery，失败又不缓存 ⇒ 一个死 issuer 串行化所有并发登录 | idp/idp.go:705; idp/idp.go:711; idp/idp.go:713 | FIXED（d4a60f2） | 锁覆盖整个 `oidc.NewProvider`（10s 超时），失败不推进 `discoveredAt`，每次请求重试。；发现移出锁（double-checked）或 singleflight + 短超时 + 负缓存。 |
| S06-4 | P2 | SocialLogin.states 无界 map，且每次未认证 start 都在锁下 O(n) 清扫 | referencesource/social.go:102; referencesource/social.go:104; referencesource/social.go:193 | FIXED（03c1ae1） | 无上限、无周期清扫，过期只靠每次新 start 的全表扫描执行。；给在途授权设上限 + 周期清扫（不随请求数线性）。 |
| S06-5 | P2 | TapTapLogin.attempts 同样无界、每 challenge 一次 O(n) 清扫，未认证可达 | referencesource/taptap.go:124; referencesource/taptap.go:126; referencesource/taptap.go:258 | FIXED（03c1ae1） | 每条 entry 还持有 DeviceAuth（含验证 URL/码），单条内存不小。；同 S06-4。 |
| S07-2 | P2 | vault.Enroll 先持久化凭据、后写审计事件 ⇒ 审计失败时对一次已发生的写入报错，留下未审计（federation 里还是孤儿）的秘密 | vault/service.go:245; vault/service.go:259 | FIXED（13e753e） | 与 `Use` 的 fail-closed（先审计后交明文）相反。；先审计后写入，或写入失败时回滚并在错误里 Join 审计错误。 |
| S08-1 | P2 | Vault KEK 解析硬编码 RE0AUTH_KEK 优先于 vault.kek_env，重命名的键被静默忽略 | cmd/re0auth/config.go:729-743; cmd/re0auth/config.go:471; scripts/backup-keys.sh:74-77 | FIXED（dc7400a） | 其他设置都遵循 env > 文件约定或专用 RE0AUTH_ 覆盖，KEK 却先读死名字。；`kek_env` 存在时只读它；与 `RE0AUTH_KEK` 不一致时拒绝启动并点名。 |
| S08-4 | P2 | DeleteAccount 在本地移除 Failed>0 时仍报成功并写 outcome=ok | internal/lifecycle/lifecycle.go:200-206; internal/lifecycle/lifecycle.go:313-315; internal/federation/killswitch.go:140-146; internal/federation/killswitch.go:180-183 | FIXED（fceaccd） | `RevokeUserBindings` 只在无法枚举时返错；单条绑定的本地移除失败被折叠进结果。；把 Failed>0 反映到 outcome 与错误，别写 ok。 |
| S09-1 | P2 | 迁移回退路径可把带密码的 DSN 写进日志：withMigrationLock 不过滤驱动的解析错误 | internal/store/postgres/postgres.go:378; internal/store/postgres/postgres.go:399; internal/store/postgres/postgres.go:402; internal/store/postgres/postgres.go:240; internal/store/postgres/postgres.go:452 | FIXED（232d162） | `MigrateDown` 直接走 `withMigrationLock`，从不经过 `poolConfig` 的 `redactDSNParseError`。；对该路径的错误同样调用 `redactDSNParseError`。 |
| S09-2 | P2 | Tokens.RevokeTokens 并非事务，尽管 revokeMatching 注释声称在事务里 ⇒ 批量 Kill Switch/擦除可半执行 | internal/store/postgres/oauth.go:466; internal/store/postgres/oauth.go:471; internal/store/postgres/oauth.go:517; internal/store/postgres/oidc.go:1503 | FIXED（fac6ad7） | `revokeMatching` 跑在 `s.pool`（autocommit），之后另有两条 DELETE 也在池上。；把 revokeMatching 与其后的 DELETE 包进同一事务。 |
| S10-2 | P2 | readiness 探针 panic 会把 /readyz 永久钉在 "checking"(503)（§5 合并：S14-9） | internal/httpapi/health.go:183; internal/httpapi/health.go:194 | FIXED（ee3d20b） | `check` 在调用探针前置 `running=true`，只在正常返回路径复位；panic 后 `settled` 永不关闭。；`defer` 复位 `running`/关闭 `settled`，panic 也走异常路径复位。 |
| S11-6 | P2 | /v1/admin/audit/verify 同步全表走链、无并发约束，最长持有池连接 45s | internal/httpapi/audit_routes.go:171; internal/store/postgres/auditchain.go:220; internal/store/postgres/auditchain.go:264 | FIXED（0220f24） | 开事务、抬 statement_timeout 到 45s、整表扫描；无 per-endpoint 并发上限也无结果缓存。；加并发上限（或缓存结果），必要时改成可中断的分段校验。 |
| S12-1 | P2 | 每次尝试的请求超时在读取响应体之前就被解除 | web/src/lib/api.ts:334; web/src/lib/api.ts:354; web/src/lib/api.ts:369 | FIXED（a8a5122） | `fetch` 在响应头到达即 resolve，唯一 deadline 在 `res.text()` 之前被 clear，body 卡住时 abort 永不触发。；把 clearTimeout 移到 body 读取完成之后（或到 finally）。 |
| S13-2 | P2 | StoreDeviceAuthorization 每次公开请求都持 store 全局锁 O(n) 扫描（§5 合并：S13-3、S14-1、S14-6、S14-7） | internal/store/memory/oidc.go:1050; internal/store/memory/oidc.go:1053; internal/store/memory/oidc.go:1124 | FIXED（a0487e1） | 唯一 mutex 同时守所有令牌操作，设备授权端点公开可达。；为设备记录建索引/分桶，避免持全局锁扫描。 |
| S14-3 | P2 | 内存 store 分页器每页重排全表：vault Rotate 与 federation Kill Switch 变成 O(N²logN) | vault/repo.go:229; vault/repo.go:233; vault/rotate.go:45; internal/federation/binding.go:255; internal/federation/binding.go:262; internal/federation/killswitch.go:58 | FIXED（c3401b5） | 每页都物化全部行、排序、再用游标过滤，游标不减少工作量。；让游标真正参与分页（持久有序索引或快照）。 |
| S14-5 | P2 | refresh 家族撤销与轮换非原子，并发重放可留下新世代 token | oauth/as.go:264; oauth/as.go:276; oauth/as.go:308; oauth/as.go:418; oauth/as.go:421; oauth/tokens.go:434 | FIXED（042d7d0） | `ConsumeRefresh` 原子，但 `ConsumeRefresh → RevokeRefreshFamily` 与 `ConsumeRefresh → issue` 不是。；把"消费+撤销/签发"做成一个原子步骤（或家族级锁）。 |
| S01-10 | P3 | Client secrets are stored as an unsalted SHA-256 digest, so a weak config-file secret is off-line crackable if the store leaks | oauth/client.go:99-105; oauth/client.go:107-114; cmd/re0auth/main.go:1634-1643 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S01-11 | P3 | MemoryStore serialises all token operations on one Mutex and scans every record under the lock, so account-page reads and sweeps block token introspection | oauth/tokens.go:263-273; oauth/tokens.go:298-328; oauth/grants.go:157-221 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S01-12 | P3 | Store reads return struct copies whose Scopes slices alias the stored backing array, so a caller mutating a returned record corrupts stored authorization state | oauth/tokens.go:373-382; oauth/tokens.go:341-349; oauth/tokens.go:421-429; oauth/as.go:370-376 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S01-4 | P3 | Token issuance is not atomic: a failure after SaveAccess leaves a live, undeliverable access token in the store | oauth/as.go:405-432; oauth/as.go:388-423 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S01-5 | P3 | Client authentication tells an unknown client apart from a wrong secret, contradicting the kit's stated indistinguishability requirement | oauth/as.go:437-448; upstreamkit/server.go:339-345 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S01-7 | P3 | RotateSecret accepts a hash of any length while RestoreClient demands sha256.Size, so a bad rotation silently locks a confidential client out | oauth/client.go:415-432; oauth/client.go:124-145; oauth/client.go:107-114 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S01-8 | P3 | Revoke cannot reach a spent refresh token's tombstone: the documented DeleteRefresh tombstone-clear is unreachable and RFC 7009 revocation of a rotated token is a false success | oauth/as.go:311-345; oauth/tokens.go:393-405; oauth/tokens.go:453-464 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S01-9 | P3 | Audit failures are silently discarded, so reuse detection, revocation and failed exchanges can go unrecorded | oauth/as.go:451-459 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S02-10 | P3 | No length cap on state, nonce (or other authorize parameters) at the entrance, unlike PKCE, request-id and handle ids | internal/oidchttp/oidchttp.go:934; internal/oidchttp/oidchttp.go:1046; internal/oidchttp/oidchttp.go:1416 | FIXED（b6407e1） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S02-6 | P3 | Protocol-plane 405 responses omit the mandatory Allow header | internal/oidchttp/oidchttp.go:478; internal/oidchttp/oidchttp.go:256; internal/oidchttp/oidchttp.go:263 | FIXED（b6407e1） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S02-7 | P3 | Discovery rewrite mutates URL.Path but not RawPath, so a percent-encoded RFC 8414 alias 404s instead of serving the OIDC document | internal/oidchttp/oidchttp.go:255; internal/oidchttp/oidchttp.go:300; internal/oidchttp/oidchttp.go:46 | FIXED（b6407e1） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S02-8 | P3 | Handler.Introspect collapses a store outage into Active=false, reporting infrastructure failure to /v1 as an invalid token | internal/oidchttp/oidchttp.go:1677; internal/oidchttp/oidchttp.go:1664 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S02-9 | P3 | Every successful token response is fully JSON-decoded and re-encoded by sanitizeTokenResponse | internal/oidchttp/oidchttp.go:1538; internal/oidchttp/oidchttp.go:670; internal/oidchttp/oidchttp.go:761 | FIXED（b6407e1） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S03-10 | P3 | Kill Switch session revocation is unbounded and not atomic | internal/store/postgres/sessions.go:198; internal/store/postgres/sessions.go:202; internal/store/postgres/sessions.go:216 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S03-2 | P3 | SignIn leaves an authenticated session outside the SessionIndex when RenewToken fails | internal/auth/auth.go:161; internal/auth/auth.go:166; internal/auth/auth.go:177 | FIXED（56acd6b） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S03-3 | P3 | EndSession forgets the session index before destroying the session, so a failed sign-out leaves an unrevocable live session | internal/auth/auth.go:210; internal/auth/auth.go:212; internal/auth/auth.go:216 | FIXED（511cced） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S03-4 | P3 | Concurrent first login of the same identity is reported as signup_failed instead of retrying the lookup | internal/auth/auth.go:713; internal/auth/auth.go:714; internal/auth/auth.go:716 | FIXED（511cced） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S03-5 | P3 | Session referencing a missing account answers 500 instead of tearing the session down | internal/httpapi/session_routes.go:27; internal/httpapi/session_routes.go:29; internal/httpapi/identity_routes.go:26; internal/httpapi/export_routes.go:64 | FIXED（b0004c0） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S03-6 | P3 | Admin authorization trusts the session claim without re-checking that the account still exists | internal/httpapi/admin_routes.go:62; internal/httpapi/admin_routes.go:67; internal/httpapi/server.go:305 | FIXED（b0004c0） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S03-8 | P3 | Postgres Identities uses an EXISTS round trip before the real SELECT | internal/store/postgres/account.go:236; internal/store/postgres/account.go:244 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S03-9 | P3 | clearFlow does not remove the OIDC nonce from the session | internal/auth/auth.go:44; internal/auth/auth.go:737; internal/auth/auth.go:739 | FIXED（511cced） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S04-2 | P3 | BeginDeviceAuthorization does not authenticate confidential clients, allowing anonymous device requests that impersonate a trusted client on the consent screen | oauth/device.go:224-228; oauth/device.go:415-419; oauth/device.go:437-448 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S04-4 | P3 | Grants page scans every token in the process under the store's single mutex (no subject index in the in-memory store) | oauth/grants.go:158-180; internal/httpapi/grants_routes.go:31-43 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S04-5 | P3 | freeUserCode treats every store error as a collision and checks uniqueness non-atomically | oauth/device.go:432-443; oauth/device.go:155-163 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S04-6 | P3 | slow_down is returned before the terminal device status, and the advertised interval is truncated | oauth/device.go:289-307; oauth/device.go:252-255 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S04-7 | P3 | Consent decision conflates store failures with an expired authorization request | internal/httpapi/authorization_routes.go:97-101; internal/httpapi/authorization_routes.go:151-155; internal/httpapi/authorization_routes.go:159-166; internal/httpapi/authorization_routes.go:173-183 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S04-8 | P3 | Registry.Register mutates the scope map without synchronization while Get/Resolve read it concurrently（§5 合并：S14-10） | oauth/scope.go:183-197; oauth/scope.go:199-213; oauth/scope.go:217-235 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S04-9 | P3 | Device authorization accepts an empty scope set and issues a scope-less token pair | oauth/device.go:224-228; oauth/device.go:373-386; oauth/device.go:308 | FIXED（c17ce23） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S05-3 | P3 | MemoryBindingStore.List pre-allocates for the whole deployment and ListAllPage re-sorts the whole map on every page | internal/federation/binding.go:219; internal/federation/binding.go:262; internal/federation/binding.go:255 | FIXED（2ab00ee） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S05-4 | P3 | MissingBindings is O((sources x resources)^2) with a copy+sort per candidate lookup | internal/federation/missing.go:65; internal/federation/missing.go:70; internal/federation/missing.go:74 | FIXED（2ab00ee） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S05-5 | P3 | NewRegistry validates RawBase and token_class but not Status, so an unrecognized status is fail-open | internal/federation/federation.go:162; internal/federation/federation.go:173; internal/federation/federation.go:637 | FIXED（2ab00ee） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S05-6 | P3 | Source.Issuer and endpoint overrides are not validated as absolute http(s), unlike RawBase | internal/federation/federation.go:144; internal/federation/federation.go:151; internal/federation/bind.go:150; internal/federation/bind.go:235 | FIXED（93009b0） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S05-7 | P3 | BeginBind and CompleteBind accept a retired source that the rest of the plane refuses | internal/federation/bind.go:127; internal/federation/bind.go:171; internal/federation/service.go:637 | FIXED（2ab00ee） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S05-8 | P3 | revokeUpstream logs a vault error that can embed the raw subject identity | internal/federation/unbind.go:124; vault/service.go:309 | FIXED（2ab00ee） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S06-10 | P3 | SocialLogin stores and echoes return_to without safeurl.RelativePath validation | referencesource/social.go:108; referencesource/social.go:189 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S06-6 | P3 | Conformance runner leaks the response body of a non-200 metadata document (never closed) | upstreamkit/conformance/conformance.go:211; upstreamkit/conformance/conformance.go:212; upstreamkit/conformance/conformance.go:216 | FIXED（f0f9256） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S06-7 | P3 | A partial AuthURL/TokenURL override on a discovered OIDC provider is silently discarded | idp/idp.go:505; idp/idp.go:507; idp/idp.go:520 | FIXED（a8bca1f） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S06-8 | P3 | Injected RegistryConfig.HTTPClient may have no timeout, and go-oidc's JWKS fetch is context.WithoutCancel'd, so a hung IdP can pin a login goroutine | idp/idp.go:287; idp/idp.go:751; idp/idp.go:648 | FIXED（a8bca1f） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S06-9 | P3 | federation.NewService's Doer-only fallback builds an outbound client with the SSRF guard off | internal/federation/service.go:376; httpclient/outbound.go:304 | FIXED（2ab00ee） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S07-10 | P3 | tapsign.Rotate returns the replacement token together with an audit error, inviting callers to discard a token that is now the only live credential | tapsign/client.go:60; tapsign/client.go:197 | FIXED（53bbe24） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S07-3 | P3 | MemoryRepo.ListPage reloads clones and re-sorts the entire store on every page, making a rotation O(N^2 log N) with N clones per page | vault/repo.go:229; vault/repo.go:233 | FIXED（c3401b5） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S07-5 | P3 | taptapoauth accepts upstream-controlled interval and expires_in without an upper bound or overflow guard | taptapoauth/client.go:96; taptapoauth/client.go:100 | FIXED（53bbe24） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S07-6 | P3 | tapsign.Verify performs a credential-bearing upstream call with no audit record | tapsign/client.go:44; tapsign/client.go:40 | FIXED（53bbe24） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S08-5 | P3 | Universal trusted-proxy list check only matches a single /0 prefix, so two /1 entries bypass the acknowledgement | cmd/re0auth/config.go:1016-1023; cmd/re0auth/config.go:589-601 | FIXED（7a35ac6） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S08-6 | P3 | -print-secret-env echoes whatever is in an *_env name slot verbatim, disclosing a value pasted into the wrong field | cmd/re0auth/config.go:424-431; cmd/re0auth/config.go:441-445; cmd/re0auth/main.go:276-290 | FIXED（7a35ac6） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S08-7 | P3 | Graceful-shutdown drain budget (30s) is shorter than dataPlaneTimeout (45s), so shutdown cuts the request the design says must get a readable refusal | cmd/re0auth/main.go:128; cmd/re0auth/main.go:116-150; cmd/re0auth/main.go:854-866 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S08-8 | P3 | An explicitly configured max_upstream_buffer_bytes = 0 is silently replaced by the 64 MiB default | cmd/re0auth/config.go:553-571; cmd/re0auth/main.go:523; internal/federation/service.go:382-383 | FIXED（7a35ac6） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S08-9 | P3 | A custom OIDC provider's issuer is not required to be https, so the token exchange can run in cleartext | cmd/re0auth/config.go:855-890; idp/idp.go:530-548 | FIXED（7a35ac6） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S09-3 | P3 | UnlinkIdentity masks any database error as ErrNotFound because ownership is checked before err | internal/store/postgres/account.go:199 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S09-5 | P3 | Rolling back migrations 0024/0025 silently drops refresh-family tombstones and replay detection; the MigrateDown guard only covers 13/14 | internal/store/postgres/postgres.go:469; internal/store/postgres/postgres.go:496; internal/store/postgres/migrations/0024_refresh_token_family.sql:50; internal/store/postgres/migrations/0025_oauth_refresh_family.sql:59 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S09-6 | P3 | Verify reads audit_chain.head_hash as a witness but never compares it to the walked chain, so tail truncation is not detected even though the anchor is in hand | internal/store/postgres/auditchain.go:259; internal/store/postgres/auditchain.go:346 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S09-7 | P3 | Database outages are collapsed into protocol 'not found' on the authorization-code and device-poll paths, unlike every refresh/revocation path | internal/store/postgres/oidc.go:327; internal/store/postgres/oidc.go:1210; internal/store/postgres/oidc.go:660 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S09-8 | P3 | Several multi-statement deletes run without a transaction, leaving orphaned session index rows and post-revocation replay tombstones | internal/store/postgres/sessions.go:197; internal/store/postgres/sessions.go:211; internal/store/postgres/oauth.go:290; internal/store/postgres/oauth.go:495 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S09-9 | P3 | Audit pseudonym cache is dropped wholesale at 4096 entries, so bursts over distinct subjects put 1-3 extra queries on the vault fail-closed path | internal/store/postgres/auditpseudo.go:144; internal/store/postgres/auditpseudo.go:115; internal/store/postgres/auditpseudo.go:69 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S10-3 | P3 | Compression writer is never closed or pooled when a handler panics after compression starts | internal/compress/compress.go:160; internal/compress/compress.go:162 | FIXED（4fd7603） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S11-2 | P3 | Kill Switch silently reports sessions_revoked=0 when the deployment has no session revoker, with no unavailability marker | internal/admin/admin.go:351; internal/admin/admin.go:167; internal/admin/admin.go:169; cmd/re0auth/main.go:618; cmd/re0auth/main.go:903 | FIXED（be67775） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S11-3 | P3 | Kill Switch `all` cannot purge in-flight bind flows and does not say so, allowing access to be re-created after the sweep（§5 合并：S11-5） | internal/admin/admin.go:399; internal/admin/admin.go:404; internal/federation/bind.go:47 | FIXED（be67775） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S11-4 | P3 | Kill Switch returns a bare 500 on a partial failure, discarding the counts of what was already revoked | internal/admin/admin.go:361; internal/admin/admin.go:388; internal/httpapi/admin_routes.go:281 | FIXED（be67775） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S11-7 | P3 | Audit subject filter performs an uncached negative DB lookup per distinct subject and leaks 'has pseudonym key' timing | internal/store/postgres/auditpseudo.go:69; internal/store/postgres/auditread.go:67; internal/store/postgres/auditpseudo.go:144 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S11-8 | P3 | Account export claims to be everything held about the account but omits sessions, issued tokens and audit history, while the notice only disclaims credentials | internal/httpapi/export_routes.go:10; internal/httpapi/export_routes.go:30; internal/httpapi/export_routes.go:39 | FIXED（b0004c0） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S11-9 | P3 | GET /v1/admin/clients returns every client with no pagination or cap | internal/httpapi/admin_routes.go:100; internal/store/postgres/oauth.go:732 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S12-10 | P3 | Response shape validation is applied to only two endpoints; the rest throw inside render and expose the JS error via +error.svelte | web/src/lib/api.ts:468; web/src/lib/api.ts:480; web/src/routes/admin/+page.svelte:72; web/src/routes/+error.svelte:9 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S12-3 | P3 | Stale ?error= is carried through SignIn return_to, so a later successful sign-in still reports failure | web/src/routes/+page.svelte:40; web/src/routes/+page.svelte:241 | FIXED（6598fc5） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S12-4 | P3 | Attacker-controlled ?error= is rendered verbatim inside the branded failure alert | web/src/routes/+page.svelte:41; web/src/routes/+page.svelte:82 | FIXED（6598fc5） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S12-5 | P3 | Account export revokes the object URL synchronously and trusts an unvalidated profile field | web/src/routes/+page.svelte:162; web/src/routes/+page.svelte:164 | FIXED（6598fc5） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S12-6 | P3 | Focus restoration builds a CSS selector by string interpolation from server/config ids | web/src/lib/a11y.ts:33; web/src/lib/a11y.ts:35; web/src/routes/sources/+page.svelte:186; web/src/routes/grants/+page.svelte:73 | FIXED（6598fc5） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S12-8 | P3 | SPA shell is sent with no cache validator, so Cache-Control: no-cache forces a full body transfer each load | internal/webui/webui.go:151; internal/webui/webui.go:152 | FIXED（93009b0） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S13-4 | P3 | Device approve/deny call the synchronous audit sink while holding the OIDC store's global mutex | internal/store/memory/oidc.go:1308; internal/store/memory/oidc.go:1326; internal/store/memory/oidc.go:1334; internal/store/memory/oidc.go:1347; audit/audit.go:35; internal/store/postgres/audit.go:54 | FIXED（93009b0） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S13-6 | P3 | compress responseWriter swallows the final status after a 1xx header | internal/compress/compress.go:318; internal/compress/compress.go:327 | FIXED（4fd7603） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S13-7 | P3 | HTTP status metric label is not normalized and can be set from an upstream-controlled status | internal/observability/observability.go:310; internal/observability/observability.go:629; internal/httpapi/federation_routes.go:320 | FIXED（b640434） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S13-8 | P3 | pprof profile/trace endpoints accept unbounded seconds and have no concurrency or size cap | internal/observability/observability.go:611; internal/observability/observability.go:616; internal/observability/observability.go:618 | FIXED（b640434） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S13-9 | P3 | Oversized chunked JSON bodies surface as 400 'malformed JSON body' instead of the middleware's plane-shaped 413 | internal/httpapi/admin_routes.go:133; internal/httpapi/authorization_routes.go:144; internal/httpapi/device_routes.go:105; internal/httpapi/binding_routes.go:202; internal/httpapi/account_routes.go:44; internal/httpapi/middleware.go:113; oauth/bodylimit.go:33 | FIXED（b0004c0） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S14-4 | P3 | federation.MemoryBindingStore.List has no per-user index: every account page scans all bindings under the read lock | internal/federation/binding.go:215; internal/federation/binding.go:219; internal/federation/binding.go:220 | FIXED（2ab00ee） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S15-11 | P3 | Release archives embed the built SPA but do not carry the npm attribution the image deliberately includes | Makefile:160-182; Makefile:215-221; Dockerfile:86-90 | FIXED（95f13f0） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S15-2 | P3 | CI/release-gate Postgres service image is a floating tag while every other image in the project is digest-pinned | .github/workflows/ci.yml:34; .github/workflows/ci.yml:278; .github/workflows/perf.yml:45; .github/workflows/release.yml:20 | FIXED（07f7105） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S15-4 | P3 | .dockerignore excludes scratchpad but not the live audit workspace or generic key shapes, so they enter the `COPY . .` build layer | .dockerignore:42-43; .gitignore:62; Dockerfile:53; .gitleaks.toml:13-20 | FIXED（95f13f0） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S15-5 | P3 | Base ConfigMap hardcodes trusted_proxies to 10.0.0.0/8; on a non-10/8 pod CIDR every client silently shares one rate-limit bucket | deploy/k8s/base/configmap.yaml:43-44; internal/httpapi/clientaddr.go:104-110; internal/httpapi/clientaddr.go:78-81 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §3（类别：reliability） |
| S15-6 | P3 | Release image is pushed under its release tag before the Trivy gate runs; only `latest` is withheld | .github/workflows/release.yml:64-80; .github/workflows/release.yml:100-107; .github/workflows/release.yml:109-119; deploy/k8s/base/deployment.yaml:46 | FIXED（07f7105） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S15-7 | P3 | Trivy scan runs with the host Docker socket mounted inside a job holding packages:write and id-token:write | .github/workflows/release.yml:100-107; .github/workflows/release.yml:36-39 | FIXED（07f7105） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S15-9 | P3 | Namespace has no Pod Security Admission labels, so the hardened pod spec is not enforced as a precondition | deploy/k8s/base/namespace.yaml:1-4; deploy/k8s/base/deployment.yaml:29-33; deploy/k8s/base/deployment.yaml:108-111 | FIXED（07f7105） | 见 `docs/security-audit-9.md` §3（类别：security） |
| S01-13 | P3 · 信息 | [info] The declared-length pre-check is the only path to 413; a chunked body over the cap surfaces as a 400 malformed-form instead | oauth/bodylimit.go:27-34; upstreamkit/server.go:162-169; upstreamkit/server.go:242-246 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S02-5 | P3 · 信息 | [info] Discovery documents are cached for the process lifetime while the issuer is derived per request from Host | internal/oidchttp/oidchttp.go:294; internal/oidchttp/oidchttp.go:300; internal/oidchttp/oidchttp.go:193 | FIXED（b6407e1） | 见 `docs/security-audit-9.md` §4（类别：security） |
| S05-10 | P3 · 信息 | [info] CompleteBind consumes the flow before the owner check (cross-account DoS), mitigated by the HTTP handler | internal/federation/bind.go:158; internal/federation/bind.go:163; internal/httpapi/federation_routes.go:410 | FIXED（da9f33a） | 见 `docs/security-audit-9.md` §4（类别：security） |
| S05-9 | P3 · 信息 | [info] MemoryBindFlowStore.SweepExpired uses time.Now instead of the service clock | internal/federation/bind.go:112; internal/federation/bind.go:144; internal/federation/bind.go:165 | FIXED（da9f33a） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S06-11 | P3 · 信息 | [info] safeurl.RelativePath resists scheme-relative, backslash and control-byte escapes; percent-encoded and dot-segment forms cannot change origin | internal/safeurl/safeurl.go:34 | DECIDED-NONGOAL（docs/issues/not-doing.md） | 见 `docs/security-audit-9.md` §4（类别：security） |
| S07-11 | P3 · 信息 | [info] bindingAAD truncates identity lengths to uint32 before length-prefixing | vault/envelope.go:148; vault/envelope.go:150 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §4（类别：security） |
| S07-4 | P3 · 信息 | [info] Use builds the AEAD AAD from the requested identity while Rotate builds it from the stored record identity | vault/service.go:300; vault/rotate.go:104 | FIXED（6527fbe） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S07-7 | P3 · 信息 | [info] taptapoauth bounds upstream error text for logs but only strips CR/LF, leaving other control characters | taptapoauth/client.go:337; taptapoauth/client.go:338 | FIXED（53bbe24） | 见 `docs/security-audit-9.md` §4（类别：security） |
| S07-8 | P3 · 信息 | [info] tapsign.drain and the response handling dereference resp and resp.Body without a nil check | tapsign/client.go:224; tapsign/client.go:48 | FIXED（53bbe24） | 见 `docs/security-audit-9.md` §4（类别：reliability） |
| S07-9 | P3 · 信息 | [info] Re-enrolling a credential overwrites CreatedAt, discarding the original creation time | vault/service.go:244; vault/service.go:253 | FIXED（6527fbe） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S09-10 | P3 · 信息 | [info] OP token issued_at is written by the database's now(), not the store clock the rest of OIDCStore uses | internal/store/postgres/oidc.go:429; internal/store/postgres/oidc.go:573; internal/store/postgres/migrations/0009_oidc_token_issued_at.sql:5; internal/store/postgres/oidc.go:41 | FIXED（6cc3cc2） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S09-4 | P3 · 信息 | [info] ConsumeRefresh claims expired values (no expires_at predicate) although the Store contract says "live", unlike the OP store's rotation claim | internal/store/postgres/oauth.go:242; internal/store/postgres/oidc.go:514; oauth/as.go:289; oauth/tokens.go:168 | FIXED（fddbde4） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S10-4 | P3 · 信息 | [info] Business-plane responses carrying the session CSRF token are compressed (BREACH-style compression oracle) | internal/httpapi/server.go:353; internal/compress/compress.go:336; internal/httpapi/session_routes.go:42; internal/httpapi/device_routes.go:75; internal/auth/auth.go:240 | FIXED（b0004c0） | 见 `docs/security-audit-9.md` §4（类别：security） |
| S12-11 | P3 · 信息 | [info] Every asset request performs three embedded-FS stats | internal/webui/webui.go:106; internal/webui/webui.go:119; internal/webui/webui.go:133 | FIXED（e3184bf） | 见 `docs/security-audit-9.md` §4（类别：performance） |
| S12-9 | P3 · 信息 | [info] Retried responses are discarded without draining or cancelling the body | web/src/lib/api.ts:358; web/src/lib/api.ts:361 | FIXED（6598fc5） | 见 `docs/security-audit-9.md` §4（类别：reliability） |
| S14-11 | P3 · 信息 | [info] oidchttp.serveOAuth can leak a pooled bufferedWriter on panic because release is not deferred | internal/oidchttp/oidchttp.go:636; internal/oidchttp/oidchttp.go:637; internal/oidchttp/oidchttp.go:716; internal/oidchttp/oidchttp.go:717 | FIXED（b6407e1） | 见 `docs/security-audit-9.md` §4（类别：reliability） |
| S14-12 | P3 · 信息 | [info] federation.refreshBinding's row-then-secret write order is deliberately protected by the per-binding lock (suspicious but mitigated) | internal/federation/refresh.go:40; internal/federation/refresh.go:111; internal/federation/refresh.go:121 | FIXED（da9f33a） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S15-13 | P3 · 信息 | [info] .gitleaks path allowlist exempts any file matching docs/security-audit-<n>.md from every rule | .gitleaks.toml:17-20; .gitleaks.toml:1-6 | FIXED（95f13f0） | 见 `docs/security-audit-9.md` §4（类别：security） |
| CONF-1 | P3 | conformance spike 的四个镜像都是浮动 tag（`caddy:2`、`curlimages/curl:latest`、`conformance-suite:latest`、`mongo:6.0.13`），与本项目"基础镜像按 digest 固定"的纪律不一致 | `docs/conformance.md:218-223` | FIXED（fddbde4） | 转门禁时按 digest 固定；与 `S15-2` 一起收 |
| CONF-2 | P3 | 计划 **allowlist 未钉死**：必须命名本 OP 支持的计划（授权码+PKCE+refresh+设备），并显式记录有意不支持（DCR/PAR）的计划，而不是静默跳过 | `docs/conformance.md:174-177` | FIXED（fddbde4） | 在 plan 配置/dispatch 里写死 allowlist，未知计划报错 |
| CONF-3 | P3 | JVM trust store 的派生镜像（`keytool` 导入 Caddy 本地 CA）**从未在 runner 上观察到**；基础镜像 JDK 路径不符即静默回退上游镜像 | `docs/conformance.md:162-170` | FIXED（fddbde4） | 首次绿后固化；或改用公开可信证书消除该步骤 |
| CONF-4 | P3 | 该 job 仍是 spike：`continue-on-error`、非阻断，且 `release.yml` **没有调用它** ⇒ 打 tag 发布不经过一致性门禁 | `docs/conformance.md:225-229` | FIXED（fddbde4） | 计划全绿后去掉 `continue-on-error`、按 digest 固定镜像，并从 `release.yml` 前置调用 |
| Z07-4 | P3 | CSRF 令牌创建是「后写者赢」竞态：并发首读者拿到服务端不认的令牌（4 个不同令牌中 3 个被拒） | `internal/auth/auth.go:238-245` | FIXED（511cced） | 令牌由会话确定性导出（如 `HMAC(serverKey, sessionToken)`）或对「首次创建」做 compare-and-set；依据 `Z07-VERIFIED.md:48` |
| Z07-5 | P3 | 设备决策要求调用方原样拼写 user_code，而查找走规范化 ⇒ 同一设备码两个答案（规范拼写反而 404） | `internal/httpapi/device_routes.go:108-112` | FIXED（b0004c0） | 决策前先 `oauth.NormalizeUserCode(body.UserCode)`，并修正 `oauth/device.go:479` 与实现不符的注释；依据 `Z07-VERIFIED.md:49` |
| Z07-6 | P3 | `POST /v1/sessions/sign_out` 对无会话请求答 403（CSRF），是本平面唯一一个（其余写端点均先会话后 CSRF） | `internal/httpapi/session_routes.go:66-70` | FIXED（b0004c0） | 与其它写端点同序：先 `sessions.User`→401，再 `ValidCSRF`→403；注意前端 `needsSignIn` 判的是 problem code `unauthenticated` 而非状态码；依据 `Z07-VERIFIED.md:50`、`Z07-VERIFIED.md:96-108` |
| Z07-7 | P3 | 账号行已消失但会话仍在时，`/v1/sessions/current` 与 `/v1/account/export` 答 500 而非丢弃会话（401）；生产侧修复为「需与该账号会话擦除并发的极小窗口」 | `internal/httpapi/session_routes.go:27-31` | FIXED（b0004c0） | 两个处理器把 `account.ErrNotFound` 映射为「销毁会话 + 401 unauthenticated」；依据 `Z07-VERIFIED.md:51`、`Z07-VERIFIED.md:131-137` |
| Z07-8 | P3 | link 流程用 `?error=identity_taken` 确认某个外部身份是否已有 Re0Auth 账号（login 模式对同一事实不泄露） | `internal/auth/auth.go:675-693` | FIXED（fddbde4） | 把「已被他人占用」与「链接失败」合并为同一回跳码，或按 provider 限速；影响被复核收窄（须先能以该身份登录 IdP）；依据 `Z07-VERIFIED.md:52`、`Z07-VERIFIED.md:110-118` |
| Z07-9 | P3 | 不可逆的账号自我抹除不要求近期重新认证，而同代码已对可逆管理面写操作实现 `AuthenticatedAt` step-up | `internal/httpapi/account_routes.go:32-41` | FIXED（fddbde4） | 给 `handleDeleteAccount` 加与 `requireAdminWrite`（`admin_routes.go:77-97`）同形的窗口检查，失败返回 `403 reauth_required`；属裁定项（会改变交互）；依据 `Z07-VERIFIED.md:53`、`Z07-VERIFIED.md:120-129` |
| Z08-3 | P3 | 残余新增项：`/app/favicon.svg` 与 `/app/robots.txt` 副本无任何 `Cache-Control`（核心 `_app/version.json` 无缓存指令部分重报第五轮 V-4；`/app/robots.txt` 副本按 `webui.go:69-82` 本不该被爬虫读到） | `internal/webui/webui.go:143-150` | FIXED（e3184bf） | 把 `setCacheHeaders` 默认值写成「除 `_app/immutable/` 外一律 `no-cache`」，`version.json` 用 `no-store`；依据 `Z08-VERIFIED.md:19`、`Z08-VERIFIED.md:49-55` |
| Z08-5 | P3 | `_app/immutable/*` 标 `public, max-age=31536000, immutable`，但会话中间件（scs `LoadAndSave`）给每个响应加 `Vary: Cookie` ⇒ 共享缓存按整个 Cookie 分键，`immutable` 名存实亡（安全影响为零，纯部署成本） | `internal/webui/webui.go:145-146` | FIXED（93009b0） | 在 `webui.Handler` 对 `_app/immutable/` 分支 `w.Header().Del("Vary")`（压缩层随后补 `Accept-Encoding`），或把 `/app/*` 移出 `sessions.LoadAndSave`；并加守卫断言无 `Cookie` Vary token；依据 `Z08-VERIFIED.md:21`、`Z08-VERIFIED.md:63-74`、`00-MAIN-VERIFICATION.md:295-303` |
| Z08-7 | P3 | 设备决策端点的未知 `decision` 值被静默当成「拒绝」并消耗掉设备码（与同意端点的 `switch` 校验不一致，且违背 openapi 的 `enum` 契约） | `internal/httpapi/device_routes.go:114-115` | FIXED（b0004c0） | 读 `user_code` 后加与同意端点同形的白名单 `switch`，未知值回 `400 invalid_request`；依据 `Z08-VERIFIED.md:23`、`Z08-VERIFIED.md:85-94` |
| Z08-8 | P3 | 账户页把 `?error=` 原始值插进 DOM（已转义、非 XSS），构成受长度限制的 UI 欺骗/钓鱼画布 | `web/src/routes/+page.svelte:63-84` | FIXED（6598fc5） | `authErrorMessage` 的 `default` 分支改为固定文案（不回显 `code`），或仅白名单前缀映射；依据 `Z08-VERIFIED.md:24`、`Z08-VERIFIED.md:96-103` |
| Z09-2 | P3 | 归一化读没有"超过上限即拒绝"：4 MiB 上游体被静默截断后作为完整的 200 交出（`json.Valid` 接受尾随空白） | `internal/federation/service.go:760-775` | FIXED（da9f33a） | 照抄 raw 两行：`LimitReader(..., maxBody+1)` + `len(body)>maxBody → ErrResponseTooLarge` |
| Z09-3 | P3 | 已退役的源仍可被绑定：`BeginBind`/`CompleteBind` 无 `Status` 判据，上游令牌被存进 vault 而数据面永不使用 | `internal/federation/bind.go:127-152` | FIXED（da9f33a） | `registry.Get` 之后加 `Status == StatusRetired → ErrSourceRetired`（两处都要） |
| Z09V-2 | P3 | `refreshRejected` 把存储读失败当成"版本没动"：一次读故障即删绑定行并 crypto-shred vault 密钥（可能撕掉仍有效的绑定） | `internal/federation/refresh.go:143-159` | FIXED（da9f33a） | 重读的非 `ErrNotBound` 错误向上返回，不落入破坏性分支 |
| Z09V-3 | P3 | `Issuer = "//evil.example"` 时 `/bind` 302 到**另一个 origin**（开放重定向/钓鱼面） | `internal/federation/federation.go:144-146` | FIXED（da9f33a） | 对 `Issuer` 照 `validateRawBase` 校验 `Scheme∈{http,https} && Host != ""` |
| Z10-1 | P3 | 跨实例假名缓存使抹除失效：被抹除账号的审计历史在**另一副本**上继续可读、可续写（非窗口而是稳态） | `internal/store/postgres/auditpseudo.go:69-75` | FIXED（fddbde4） | 墓碑集合 / cache TTL；并把 `docs/architecture.md:661-662` 改成实话 |
| Z10-2 | P3 | 链前伪造的未签名行被 `Verify` 判 `ok`：legacy（NULL 哈希）行没有上界，"迁移前行"与"伪造行"同形 | `internal/store/postgres/auditchain.go:270-282` | FIXED（6cc3cc2） | 给 `audit_chain` 加 `legacy_ceiling_id`，`id > ceiling && row_hash IS NULL` 即判失败 |
| Z10-4 | P3 | 无会话端口时 Kill Switch 对 sessions 半边沉默：`sessions_revoked:0` 与"该账号没有会话"同形 | `internal/admin/admin.go:351-368` | FIXED（cb8b49d） | `Report` 加 `SessionsUnavailable` 并进 `killDetail`（与 `BindingsUnavailable` 同款） |
| Z10-5 | P3 | 扫描失败时 HTTP 面丢弃已完成的摘要，只回 problem+json | `internal/httpapi/admin_routes.go:281-282` | FIXED（fddbde4） | 失败路径也写一条 `outcome=error` 记录，Detail 带 tokens/sessions/bindings_error（响应体形状取舍是裁定） |
| Z10-6 | P3 | P2-22 的修法只覆盖分页读：`/v1/admin/audit/verify`（全库扫描）与 `/head` 零记录 | `internal/httpapi/audit_routes.go:171-211` | FIXED（93009b0） | 两个 handler 各写 `admin.audit.verify` / `admin.audit.head` 记录 |
| Z10-7 | P3 | 审计读接口可无写侧装配成功：`Config.Audit != nil, AuditLog == nil` 时 P2-22 的记录静默变空操作 | `internal/httpapi/server.go:297-304` | FIXED（93009b0） | `httpapi.New` 增加 `Config.Audit requires Config.AuditLog` 断言 |
| Z10-8 | P3 | `admin.*` 行把 **client_id** 假名化且 `Detail` 无补偿字段：读接口答不出"哪个客户端" | `internal/admin/admin.go:439-447` | FIXED（cb8b49d） | 给 `admin.*` 事件 Detail 补 `client_id`（`oidc.token` 已有先例） |
| Z10-9 | P3 | `Verify` 不校验链头与最后一行一致：链头指向任何行都不拥有的哈希时仍答 `ok` | `internal/store/postgres/auditchain.go:318-328` | FIXED（93009b0） | 遍历后 `bytes.Equal(prev, head)`，不一致即 `ok=false` + Reason |
| Z10V-1 | P3 | Kill Switch **失败路径**审计行漏记 `sessions_revoked`（会话已被切掉，持久记录里没有这个数） | `internal/admin/admin.go:389-391` | FIXED（be67775） | 三条失败路径 Detail 加 `sessions_revoked`，或统一让失败路径走 `killDetail` |
| Z10V-2 | P3 | 内部监听器排空**没有自己的预算**：排在公网监听器之后共享同一个 30s `drainCtx`，第一个吃满时第二个得 0s | `cmd/re0auth/main.go:840-849` | FIXED（7a35ac6） | 每个 endpoint 各自 deadline / 内部监听器直接 `Close` / 改写 `shutdownTimeout` 语义并同步注释（裁定） |
| Z11-6 | P3 | `ResponseHeaderTimeout` 默认 30s 高于出站客户端默认 `Timeout` 20s，与自身注释相反。**复核更正影响句**：报告称「错误退化为 `context deadline exceeded`」是错的，Go 仍写成 `(Client.Timeout exceeded while awaiting headers)`、仍点名 headers 阶段 | `httpclient/outbound.go:36-39`（默认 `:53-63`、`:261`；`cmd/re0auth/main.go:492-507`） | FIXED（15878e2） | 把默认值改到低于整体 `Timeout`（如 15s）；无安全影响 |
| Z12-5 | P3 | `-migrate-down` 先跑整套 serving 期校验，缺审计链密钥就无法回滚（拒绝理由与回滚无关） | `cmd/re0auth/main.go:332`（`:369-371`、`:1158-1166`） | FIXED（7a35ac6） | 给 `loadConfig` 一个「只解析 DSN/池」的模式（仍拒它真用得到的坏值）。这是一次裁定 |
| Z12-8 | P3 | 位置参数从不检查：漏掉横线的 flag 被静默忽略（`-rotate-keys` 写成 `rotate-keys` 时进程照常起服务） | `cmd/re0auth/main.go:259` | FIXED（7a35ac6） | `if flag.NArg() > 0 { ...; os.Exit(2) }` |
| Z12V-1 | P3 | KEK 的解析**不**遵循文件声明的变量名：硬编码 `RE0AUTH_KEK` 先于 `vault.kek_env`，`KEKID` 亦脱钩 | `cmd/re0auth/config.go:721-731`（`:465`） | FIXED（7a35ac6） | `kek_env` 存在时**只**读它（或两者不一致时拒绝启动并点名），`KEKID` 同理从文件段取值 |
| Z12V-3 | P3 | `envInt32` 的越界报文自称「不是整数」（`4294967297` 实为整数、只是超出 int32） | `cmd/re0auth/config.go:1121-1123` | FIXED（7a35ac6） | 区分 `ErrRange` 与语法错误，报文写「out of range for a 32-bit pool size」 |
| Z13-2 | P3 | 版本 tag 先于 Trivy 进 GHCR（`push: true` 在 scan 之前）；`cosign sign` 晚于 `latest` 提升 | `.github/workflows/release.yml:64-71`（scan `:100-107`） | FIXED（cb8b49d） | `build-push-action` 改 `push: false, load: true` → 扫本地 → 再 push；把 `cosign sign` 挪到 `promote to latest` 之前。**复核：P3 不要升** |
| Z13-5 | P3 | `internal/archtest` 的写权限门只看 workflow 级 `permissions`，job 级越权不响（仓库已有真实 job 级 `security-events: write` 未被看见） | `internal/archtest/workflows_test.go:280-312` | FIXED（f0f9256） | 下钻 `jobs.*.permissions`，断言写 scope 只出现在已知需要它的 job 名单里（名单写成测试常量） |
| Z13-6 | P3 | npm 归属清单是否被 `SHA256SUMS` 覆盖，没有守卫；**与 Z16-4 同守卫同根因，复核建议合并为一** | `Makefile:219`（`internal/archtest/workflows_test.go:16-20`） | FIXED（461e1d3） | 门禁加「走向真实产出路径」的断言（解出 `checksums` glob 逐个匹配文件名），或改显式列表而非通配 |
| Z13-7 | P3 | README 对发布产物与镜像内容的描述与产物不符（未提 npm 清单；称镜像「只带二进制与 CA 证书」而 `Dockerfile:74` 已 COPY LICENSE/NOTICE） | `README.md:129-132`（`:160`） | FIXED（95f13f0） | README 补 npm 清单文件名与用途；镜像那句改成含 LICENSE、NOTICE |
| Z14-5 | P3 | 只配 `auth_url`（未配 `token_url`）时显式端点被静默丢弃，登录静默走别的端点 | `idp/idp.go:466-481` | FIXED（a8bca1f） | 任一非空即进入显式模式，discovery 只填空字段（来源：`Z14-VERIFIED.md:72-79`） |
| Z14-6 | P3 | 参考数据源 TapTap 登录完成不绑定浏览器：加载 poll URL 即可以攻击者身份登录（会话固定/登录 CSRF） | `referencesource/taptap.go:219-226`、`referencesource/source.go:293-304` | FIXED（aee682f） | challenge 时把 attempt id 写入会话、poll 时比对，或校验 `Sec-Fetch-Site`/同源 `Origin`（来源：`Z14-VERIFIED.md:81-89`） |
| Z14-V1 | P3 | 套件用目标 origin 去判文档广告的端点：撤销端点被硬编码路径替代、级联端点丢弃 origin，合规源被误杀/「开放」端点假 PASS | `upstreamkit/conformance/conformance.go:255,288-296` | FIXED（f0f9256） | `checkRevocationEndpoint` 改读 `disc.OAuth.RevocationEndpoint`（解析失败即 error），级联直接对绝对 URL 发请求（来源：`Z14-VERIFIED.md:95-134`） |
| Z15-2 | P3 | `BenchmarkTokenLifecycleWithJanitor` 的守卫在固定迭代数下不可达：`-benchtime=200x` 报 `peak_records=0` 且 exit 0，CI 正是 200x | `internal/store/memory/oidc_bench_test.go:79-91` | FIXED（1eda335） | 判据与 `b.N` 成比例（`\\ | \\ | i == b.N-1`），或 `b.N < sweepEvery` 直接 Fatalf（来源：`Z15-VERIFIED.md:46-56`） |
| Z15-3 | P3 | 内存 store 的 `DeleteAuthRequest` 在全局锁下遍历全部待兑换 code（Postgres 走 `oidc_codes(request_id)` 索引） | `internal/store/memory/oidc.go:449-468` | FIXED（64be6b1） | 加 `codeByRequest`（requestID→TokenHash）并在同一临界区维护（来源：`Z15-VERIFIED.md:58-65`） |
| Z15-4 | P3 | `negotiate` 快速路径对每个已配置 coding 重新 `strings.Split` 一次头部，成本随服务端配置增长 | `internal/compress/compress.go:180-193` | FIXED（4fd7603） | 快速路径先切一次成切片再 `EqualFold` 匹配（来源：`Z15-VERIFIED.md:67-77`） |
| Z16-4 | P3 | `internal/archtest` 的 Makefile 守卫是整文件 `strings.Contains`，把目标行整行注释掉仍 PASS | `internal/archtest/workflows_test.go:31-40` | FIXED（f0f9256） | 复用同包结构解析，断言 `release` 的前置真含 `npm-attribution`/`checksums`（来源：`Z16-VERIFIED.md:60-65`） |
| Z16-5 | P3 | `ci.yml` 的 fuzz 目标清单靠手维护，没有任何守卫保证它完整（删掉 5 条无人发现） | `.github/workflows/ci.yml:467-478` | FIXED（b37864e） | archtest 用 `go test -list '^Fuzz'` 枚举目标并断言全在清单（来源：`Z16-VERIFIED.md:67-72`） |
| Z16-6 | P3 | 又三条「算出结论只打印」的探针，其中一条可被 `-overlay` 注入的假期望骗过仍 PASS | `internal/zzprobe/pubaddr/addr_test.go:12-54`、`internal/zzprobe/federation/safeurl_test.go:425-443,181-186` | FIXED（893c6a3） | 三条各补真断言（地址表逐例 `t.Errorf`、归一化断言 scheme/host 白名单、区域 ID 断言 err）（来源：`Z16-VERIFIED.md:74-80`） |
| Z16-7 | P3 | 覆盖率 floor 是全仓一个总数，其自述要防的「某包烂到 0」不在覆盖内（逐包表只进 summary 不设门禁） | `.github/workflows/ci.yml:170-179` | FIXED（07f7105） | 逐包设下限（报告标 HYPOTHESIS 偏保守，verifier 可升源级 CONFIRMED，P3 不变）（来源：`Z16-VERIFIED.md:82-88`） |
| Z17-1 | P3 | README 快速开始与随仓库交付的配置样例不兼容：照抄即拒绝启动（样例 IdP 段未注释、引用未设变量） | `config/re0auth.example.toml:316-322`、`README.md:17-27` | FIXED（07f7105） | 样例注释掉 `[idp.github]`/`[idp.google]`，或 README 片段补两个 secret（verifier 降级 P2→P3；与第五轮 CS-5 相邻，见「已裁定」）（来源：`Z17-VERIFIED.md:26-38`） |
| Z17-2 | P3 | README 的内存模式片段按原样无法启动（缺 `cookie_secure` 与两把 OP 密钥两处独立缺项） | `README.md:36-40` | FIXED（95f13f0） | 片段补 `RE0AUTH_COOKIE_SECURE=true` 与两把 OP 密钥（或 issuer 换 http）（来源：`Z17-VERIFIED.md:40-48`） |
| Z17-3 | P3 | SECURITY.md 的「Our own audits」已过期：轮数与在盘文档都对不上（只列 -2/-3） | `SECURITY.md:121-130` | FIXED（95f13f0） | 按实际轮数陈述并列出四份文档，或改成不绑定数字的措辞（来源：`Z17-VERIFIED.md:50-55`） |
| Z17-4 | P3 | openapi 的 `Binding.token_class`/`status` 封闭 enum 表示不了 `configured: false`（两字段无 `omitempty`，零值必上线） | `docs/openapi.yaml:1833-1842`、`internal/httpapi/binding_routes.go:23-24` | FIXED（fddbde4） | 两字段加 `,omitempty`，或 enum 加 `""` 并写清语义（来源：`Z17-VERIFIED.md:57-64`） |
| Z17-5 | P3 | README 指认的「完整键位」样例漏 8 个已实现 env 覆盖；6/8 是第五轮 CS-10 的重报，仅 `RE0AUTH_LOG_LEVEL`/`LOG_FORMAT` 为新残留 | `config/re0auth.example.toml:13`、`README.md:42` | FIXED（07f7105） | 补 `# Environment override:` 行并文档化 `RE0AUTH_LOG_LEVEL`/`LOG_FORMAT` 及取值域（verifier 降级，作 CS-10 补充）（来源：`Z17-VERIFIED.md:66-79`） |
| Z17V-1 | P3 | README 的参考数据源快速开始同样照抄即拒绝启动：样例 `[client] secret_env` 生效而样例头部自称「every field has a default」 | `config/referencesource.example.toml:17-18`、`README.md:73-78` | FIXED（07f7105） | 样例注释掉 `[client] secret_env`，README 片段补 `REFERENCE_SOURCE_CLIENT_SECRET`，并修正「或 GOOGLE_CLIENT_SECRET」的表述（来源：`Z17-VERIFIED.md:95-125`） |
| Z18-2 | P3 | `idp` 把 `providerMu` 跨 discovery 网络 I/O 持有，发现期间该 provider 登录被串行化（最坏 10s/次，失败不缓存会重复） | `idp/idp.go:619-637` | FIXED（a8bca1f） | 网络发现移到锁外（double-checked）或给发现单独短超时＋singleflight |
| Z18-3 | P3 | `oauth.MemoryStore` 把存储的 `Scopes` 切片交出去（GetAccess/Introspect），改返回值即改活令牌授权 | `oauth/tokens.go:216-232`；`oauth/as.go:280` | FIXED（c17ce23） | `Save*/Get*/Consume*` 出入口 `slices.Clone`（PG 后端已 clone，属同契约实现不对称） |
| Z18v-1 | P3 | 同族第二道门：`ListBySubject` 的 `GrantRecord.Scopes` 也指向存储数组，Z18-3 修法漏了它 | `oauth/tokens.go:158-180` | FIXED（c17ce23） | `ListBySubject` 返回时 clone（或统一到一个 `cloneToken` 出口） |
| Z19-2 | P3 | QQ 取用户信息把 access token 放进查询串，`url.Error` 把整条 URL 连 token 交给调用方（今天唯一调用方丢弃该错误） | `idp/idp.go:651,670-673` | FIXED（a8bca1f） | `getText` 包装错误时剥掉查询串，或源头用不回显 URL 的 Transport 错误 |
| Z19-3 | P3 | `vault.Use` 四条失败路径 `_ = s.record(…)` 丢审计，而同 sink 成功路径是 fail-closed（对 G-19「全部 fail-closed」的局部反驳） | `vault/service.go:247-252,269-271,278-280,288-290` | FIXED（6527fbe） | 与成功路径同纪律：`errors.Join(err, aerr)`（不能只回审计错误，调用方依赖 `errors.Is(ErrNotFound)`） |
| Z19V-2 | P3 | `-print-secret-env` 把塞进名字位的值原样打到 stdout，是 Z19-1 的第二个出口且形状校验修法覆盖不到 | `cmd/re0auth/config.go:418-421` | FIXED（7a35ac6） | `configSecretEnvNames` 拒绝非变量名形状并给可操作错误，或明示接受该出口 |
| Z20-2 | P3 | raw 透传闸门按「源」判、不按「资源」判：用户不授予的 scope 仍经 raw 读同一资源（验证者复核后由 P2 降级） | `internal/httpapi/federation_routes.go:223-236,245-265` | FIXED（fddbde4） | raw 闸门按资源名归一化后要求该资源 scope；或引入显式 `<game>.raw.read`，并在 `docs/upstream-protocol.md §9` 写明「同意页收窄可被 raw 绕过」 |
| Z20-3 | P3 | 设备面同意决策审计不带 scope（`ApproveDevice` 只记 `client_id`；PG 侧连 `client_id` 都空，属 G-17） | `internal/store/memory/oidc.go:1104` | FIXED（64be6b1） | `ApproveDevice` 改走 `recordConsent(..., d.scopes, OK)` |
| Z20-4 | P3 | 【反驳 P-02】设备批准入口**确实**执行 `ExplicitConsent`（`87f4ad9` 起就在，早于第六轮）；真缺口只是缺测试 | `internal/store/memory/oidc.go:1397-1406`；`internal/store/postgres/oidc.go:1217` | FIXED（64be6b1） | 把 P-02 改判为「已具备、缺守卫」，加一条带 ExplicitConsent 目录的设备面测试 |
| Z20-6 | P3 | 【反驳 P-01 影响段】转义拼写绕过内省守卫后出口改写生效，返回 `{"active":false}`，拿不到任何东西 | `internal/oidchttp/oidchttp.go:1208-1234` | FIXED（b6407e1） | 仍做 P-01 修法（解码后再查库），并把「`introspection_clients` 必须是机密客户端」提到启动期校验 |
| Z20V-1 | P3 | 设备**拒绝**审计丢掉 store 已拿到的账号（两后端），`oidc.device.deny` 答不出「谁拒绝的」 | `internal/store/memory/oidc.go:1112-1127`；`internal/httpapi/device_routes.go:114-115` | FIXED（fddbde4） | `DenyDevice(ctx, userCode, subject)`；交互面把会话账号一并交给 store |
| Z20V-2 | P3 | 导出的 `ApproveDevice` 不过 ExplicitConsent 闸门（今天无路由可达，但是导出方法） | `internal/store/memory/oidc.go:1086-1106`；`internal/store/postgres/oidc.go:873-900` | FIXED（fddbde4） | 把 `RequireExplicitConsent` 收进 `ApproveDevice`，或降为非导出、由 `DecideDeviceAuthorization` 独占 |
| 22-1 / G-11 | P3 | `readinessCache` 在「首次检查仍在跑且从未产生过结论」（`checked==false && running==true`）时返回零值 `err=nil`，`/readyz` 回 `200 ok`（fail-open）：依赖不可达时实例仍报就绪，窗口 ≤ `readinessTimeout` 2s（Z18-1 是同一缺陷的第三次重报，已裁 NOT-A-FINDING）。区域 22 自评 P2；主复核按出厂清单（`startupProbe` 先于 `readinessProbe`、kubelet 串行）裁定 P3，此处从复核 | `internal/httpapi/health.go:111-118` | FIXED（b0004c0） | `c.running && !c.checked` 时 fail-closed 回 503/`not ready`，绝不拿零值 `nil` 当结论（可加显式三态）；不改 TTL 取舍、不因负载 shed。（来源：`Z18-VERIFIED.md:14`、`22-audit5-red-reconciliation.md:78`） |
| Z21V-2 | P3 | 被报告当作「去手写清单」的 `predicate_index_test` 看不见 04-3 那条语句：批量撤销 SQL 是 `db.Exec("DELETE FROM "+table+clause)` 运行时拼接，`revokeMatching` 的 5 张表在源码里无字面量；该守卫自称能自动抓住 04-3，实际结构上不可能（假绿，且是 04-3 唯一防复发机制） | `internal/zzprobe/audit7/z21migrationsschemaintegrity/predicate_index_test.go:123-129` | FIXED（7feca3f） | 守卫改为从 `revokeMatching` 调用点反推 `[]string{…}` 表集合，或让该 SQL 文本可被静态提取。（来源：`Z21-VERIFIED.md:113`） |
| Z21-1 | P3 | `0010`/`0011` 的 Down 是 21 个文件里仅有的两条无 `IF EXISTS` 的 `DROP`；原称「重复 `-migrate-down` 第二步硬报错」的机制被复核推翻（goose Down 一次一版本且与版本行同事务），降为纯加固项（与其余 19 文件一致 + 抗版本表漂移） | `internal/store/postgres/migrations/0010_client_status.sql:15`（另 `internal/store/postgres/migrations/0011_session_subjects.sql:24`） | FIXED（7feca3f） | 两处补 `IF EXISTS`；把该探针搬成 `internal/store/postgres` 的无 DB 守卫。（来源：`Z21-VERIFIED.md:32`） |
| Z21-4 | P3 | 设备码 user code 唯一性两表不对称：`oidc_devices` 有同名表达式 UNIQUE 索引，`oauth_device_authorizations` 只有非唯一索引；`SaveDevice` 是裸 INSERT、`freeUserCode` 查重与插入之间无约束，撞码时审批可能落到另一条流（同账号自己的设备申报，非跨账号泄露） | `internal/store/postgres/migrations/0001_init.sql:94-95` | FIXED（7feca3f） | 新迁移给该表补表达式 UNIQUE 索引；`SaveDevice` 用 `isUniqueViolation` 走「重新生成 user code」路径；内存后端同步（其 `byUser` 是无条件覆盖，比 PG 更确定地丢前一条）。（来源：`Z21-VERIFIED.md:74`） |
| Z21-3 | P3 | 21 个迁移共 39 条 `CREATE INDEX`，0 个 `NO TRANSACTION`、0 条 `CONCURRENTLY`，goose 单事务 ⇒ 每条文件的索引总时长即写冻结窗口；多索引文件 8 个，最坏 `0012` 一次 9 条（跨 7 表），`0009` 还在同事务里 `ADD COLUMN … NOT NULL DEFAULT now()` 全表重写。第六轮 04-7 只点了 0022 的 4 条（时长部分 HYPOTHESIS，需真库 `pg_locks`） | `internal/store/postgres/migrations/0012_indexes.sql`（未记录行号） | FIXED（7feca3f） | ADR-0008 §2 补记「索引迁移在役升级按表规模线性冻结写」并点名 0012/0008；后续索引迁移改 `NO TRANSACTION`+`CONCURRENTLY`；拆开 0009 这类「加列+建索引同文件」。（来源：`Z21-VERIFIED.md:63`） |
| 22-2 | P3 | round-5 给 FO-04 作证的 `TestProbeRegistryAcceptsPathEscapingNames` 循环里只有 `t.Logf`、无任何断言，结构上不可能失败而在 HEAD PASS；FO-04 的「畸形 game/name 被接受」这一半实际无守卫，回归不会被发现（证据链缺陷，非运行时攻击面） | `internal/zzprobe/federation/raw_test.go:284-317` | FIXED（cb8b49d） | 改成真断言（`..`、含 `/`、`?`、`#`、`\`、NUL、CR/LF、首尾空白、4096 字节等必须被 `NewRegistry` 拒绝）；或在 FO-04 结案前从证据清单移除、只留 `TestProbeScopeInjectionFromRegistry`。（来源：`22-audit5-red-reconciliation.md:146`） |
| N-03 | P3 | 公开引擎 `oauth/` 仍**完全静默**地吞掉审计失败——P2-1 的修复只覆盖了 OP store | `oauth/as.go:338-346` | FIXED（c17ce23） | 照抄 OP store 形状（`slog.Error` + 计数指标），并把 P2-1 的守卫扩到 `oauth/` 包调用点 |
| G-11 | P3 | `/readyz` 在「已有一次检查在跑」且**从未产生结论**时答 200（`running` 分支返回零值 `nil`） | `internal/httpapi/health.go:111` | FIXED（b0004c0） | `c.running && !c.checked` 时 fail-closed 回 503；已下调 P3（出厂清单下 kubelet 撞不到） |
| G-14 | P3 | `oidc_devices` 是第七张没有 `client_id` 前导索引的 client-only 批量撤销表，守卫手写清单也漏了它 | `internal/store/postgres/oidc.go:1075`、`internal/store/postgres/migrations/0022_bulk_revoke_client_indexes.sql` | FIXED（6cc3cc2） | 迁移 0023 补 `oidc_devices(client_id)`；守卫改为从 `revokeMatching` 调用点反推表集合 |
| G-15 | P3 | 设备路径 `slow_down` 节流锚点分叉：内存锚「上一次尝试」、PG 锚「上一次放行」 | `internal/store/memory/oidc.go:884` vs `internal/store/postgres/oidc.go:773` | FIXED（d4ad025） | 裁定一个语义（建议锚「上一次尝试」），PG 改为无条件写 `last_poll`；无安全后果 |
| G-16 | P3 | 内存 `cloneAuthRequest` 仍共享 `CodeChallenge`/`AuthTime` 两个指针字段，写穿即改库 | `internal/store/memory/oidc.go:435` | FIXED（64be6b1） | 两字段深拷贝；机制成立但今天无写穿调用方（可达性已降格，留作潜在缺陷） |
| G-17 | P3 | Postgres 的设备批准/拒绝审计事件不带 `client_id`（内存带） | `internal/store/postgres/oidc.go:898`（deny `:919`） | FIXED（6cc3cc2） | 两处 UPDATE 改 `RETURNING client_id`；生产审计链回答不了「哪个客户端被批进来」 |
| G-18 | P3 | vault 身份命名空间 `game + "." + source` 无字符校验，两个 (game, source) 映射同一凭据行 | `internal/federation/binding.go:76` | FIXED（da9f33a） | `NewRegistry` 校验 `Game`/`Name` 字符集 fail-closed；**不能**改拼接符（AAD 绑存量密文） |
| G-19 | P3 | `vault.Rotate` 把自己的审计写入失败用 `_ =` 丢弃，而 Enroll/Use/Revoke 全 fail-closed | `vault/rotate.go:82` | FIXED（6527fbe） | 与 Enroll/Use/Revoke 同纪律（返回错误，让 `rotateAndReport` 非零退出）；轮换幂等，重跑无害 |
| G-20 | P3 | `Enroll` 先落库后写审计：审计失败时凭据已存、调用方被告知失败，绑定路径不回滚不记日志 | `vault/service.go:209`、`internal/federation/bind.go:191` | FIXED（fddbde4） | 与兄弟分支 `bind.go:198-213` 对齐：失败尝试 `vault.Revoke` 回滚，失败则 slog + `errors.Join` |
| G-21 | P3 | vault 错误文本内嵌原始 `usr_…`，经 `-rotate-keys` die 路径与 unbind/cascade warn 路径进进程日志 | `vault/repo.go:29`、`vault/service.go:273`、`vault/rotate.go:113` | FIXED（6527fbe） | 错误里用形状代替身份（只报 provider + kek_id）；attr 守卫结构上看不见这个通道 |
| G-22 | P3 | 三把 32 字节密钥可共用同一值被无提示接受（KEK == token key，乃至 audit key） | `cmd/re0auth/config.go:719`、`cmd/re0auth/main.go:1385` | FIXED（7a35ac6） | `loadConfig` 解析完三把密钥后两两比较，相同即拒绝启动（或至少 Warn） |
| 04-7 | P3 | 0022 一类索引迁移在单个 goose 事务里非并发建索引：在役升级窗口对相关表是写冻结 | `internal/store/postgres/migrations/0022_bulk_revoke_client_indexes.sql` | FIXED（fddbde4） | 记录在 migration-decision；表会大时改 `CREATE INDEX CONCURRENTLY` + `-- +goose NO TRANSACTION`（0017-0022 同形） |
| P-02 | P3 | 设备流批准不检查 `ExplicitConsent`，与同意面不对称（机制在、闸门缺） | `internal/httpapi/device_routes.go:114`、`internal/store/memory/oidc.go:1086` | DECIDED-NONGOAL（docs/issues/not-doing.md） | `ApproveDevice`（含 Postgres）在 `Resolve` 后调 `RequireExplicitConsent` 并把 `explicit` 一路传下去；今天目录无此类 scope 故不可达 |
| P-03 | P3 | discovery 缓存无 Host 维度：动态 issuer 下一次伪造 Host 永久固定两份文档 | `internal/oidchttp/oidchttp.go:346`（缓存键）；`serveDiscovery` `:293` | FIXED（b6407e1） | 缓存键改 `IssuerFromRequest(r) + path`，或 `Config.Issuer == ""` 时禁用缓存；生产强制 issuer 必填故限动态形态 |
| k6 | P3 | 同类身份进日志共 7 处（除 k1 都在错误路径），不受假名销毁影响；`admin.go:442` 由合法运维请求触发、面最大 | `internal/admin/admin.go:442`、`internal/auth/auth.go:218`、`internal/federation/bind.go:208`、`internal/federation/refresh.go:155`、`:160`、`internal/httpapi/account_routes.go:73`、`internal/httpapi/binding_routes.go:57` | FIXED（511cced） | 统一改记 `action`/`self` 等形状而非 id；把该静态守卫并入常规套件｜来源：`docs/audit-5/findings/crypto-keys.md:175` |
| FO-03 | P3 | `nonPublicPrefixes` 漏 `0.0.0.0/8`（含 `::ffff:0.x`），`DenyPrivateAddresses=true` 时仍被拨号层放行；Linux 上若内核把 `0/8` 路由到回环即等价 SSRF（本机 Windows 未能证实可利用性） | `httpclient/outbound.go:117-128`（`IsPublicAddress` 在 `:130-153`） | FIXED（93009b0） | 把 `netip.MustParsePrefix("0.0.0.0/8")` 加进 `nonPublicPrefixes`｜来源：`docs/audit-5/findings/federation.md:123` |
| FO-04 | P3 | `NewRegistry` 不校验 `game`/`name`/`Resources[].Scope`：带空格的 scope 让上游收到从未声明的额外 scope，`?`/`#`/`..` 让回调 URL 与注册到源的 `redirect_uri` 不一致（操作者 TOML 输入，无远程路径） | `internal/federation/federation.go:112-122`（`bindScopes`）、`:141-175`（`NewRegistry`） | FIXED（cb8b49d） | 按 `idp.validateProviderName` 同款规则校验 `game`/`name`，`Resource.Scope` 严格文法或拒绝含空白｜来源：`docs/audit-5/findings/federation.md:164` |
| KIT-8 | P3 | 无 `Content-Length`（chunked/gzip）的超限体经 `MaxBytesError`→`ParseForm` 错误塌成 `400 malformed form body`，而非文档承诺的 413（**无绕过**，是误分类/不可观测） | `oauth/bodylimit.go:27-35`、`upstreamkit/server.go:240-243`（另 `:296-299`、`:319-322`） | FIXED（fddbde4） | `ParseForm` 错误里 `errors.As(err, new(*http.MaxBytesError))` → 413；三个调用点共用一个 helper｜来源：`docs/audit-5/findings/_fragment_kit.md:310` |
| KIT-9 | P3 | 两份 well-known 都不设 `Cache-Control`/`Vary` ⇒ 中间层可长期钉住过期发现文档（含已移除的 `cascade_revocation_endpoint`） | `upstreamkit/server.go:169-185` | FIXED（893c6a3） | `handleDiscovery`/`handleOAuthMetadata` 各加 `Cache-Control: no-store`（与 Re0Auth 平面一致）｜来源：`docs/audit-5/findings/_fragment_kit.md:354` |
| KIT-10 | P3 | `ClientAdmin.Delete` 只删 client 行、不删令牌：令牌行留下且仍 active，授权列表出现无名字记录（与 KIT-3 同根的另一出口） | `oauth/client.go:423-428`、`internal/store/postgres/oauth.go:515-518` | FIXED（fddbde4） | 让 `Delete` 契约包含令牌清理（调 `TokenAdmin.RevokeTokens`），或文档明写「不撤销」并把责任交调用方｜来源：`docs/audit-5/findings/_fragment_kit.md:387` |
| RP-5 | P3 | discovery 缺 `authorization_endpoint` 时 `provider.Endpoint()` 回空串，被 `http.Redirect` 交给浏览器 ⇒ 相对登录 URL、原地打转/404（同源，仅可用性） | `idp/idp.go:427-435`、`internal/auth/auth.go:602` | FIXED（a8bca1f） | 发现后校验 auth/token 端点非空且为带 scheme+host 的绝对 URL，否则 `provider_unavailable`｜来源：`docs/audit-5/findings/_fragment_rp.md:181` |
| RP-6 | P3 | `clearFlow` 在 provider 比对之前执行 ⇒ 一次「走错 provider」的被拒回调烧掉待完成登录，`provider_mismatch` 诊断码被抹掉（需会话内 state，攻击者不能主动触发） | `internal/auth/auth.go:627`（比对在 `:629-633`） | FIXED（511cced） | 把 provider 比对与 error/code 存在性检查移到 `clearFlow` 之前｜来源：`docs/audit-5/findings/_fragment_rp.md:203` |
| RP-7 | P3 | 同一 auth request 的批准 redirect 可重放，每次访问都新签一份码；第一份兑换成功后其余成死码，URL 预取/刷新可能抢走唯一兑换机会，死码残留至 TTL（一次同意仍只一份可兑换 grant） | `internal/store/memory/oidc.go`（`SaveAuthCode`/`AuthRequestByCode`；**行号未记录**） | DECIDED-NONGOAL（docs/issues/not-doing.md） | 让 `/oauth/authorize/callback` 对同一 auth request 幂等：已 `Done` 且有码则重定向同一码，或先 `DeleteAuthCodeByRequest`｜来源：`docs/audit-5/findings/_fragment_rp.md:227` |
| RP-8 | P3 | 登录完成后会话里仍留着 `flow_nonce`：`flowKeys` 漏了 `keyFlowNonce`，写入列表与清理列表不一致（目前无利用性） | `internal/auth/auth.go:41`、`:44`（`flowKeys`）、`:708-712`（`clearFlow`） | FIXED（511cced） | 把 `keyFlowNonce` 加进 `flowKeys`，或让写入与清理共用同一列表｜来源：`docs/audit-5/findings/_fragment_rp.md:263` |
| FO-05 | P3 | 数据面没有重试层，而 `docs/source-onboarding.md` §4 对源的承诺多了一项 | `docs/source-onboarding.md:225`、`cmd/re0auth/main.go:459-475`、`httpclient/outbound.go:304-321` | FIXED（fddbde4） | **改文档比加代码正确**（不装重试是裁定，见「有意不做」）；或改 `source-onboarding.md:225`，并在 `resilience-decision.md` 补一句理由 — 来源：`docs/audit-5/findings/federation.md:214（第 5 轮）` |
| A-FE-1 | P3 | SPA shell 没有缓存验证器，只剩 `Cache-Control: no-cache` 一层 | `internal/webui/webui.go:129,143-150` | FIXED（93009b0） | 首次调用时对 `index.html` 算一次强 `ETag` 并缓存，让 `http.ServeFileFS` 回 304 — 来源：`docs/audit-5/findings/frontend.md:50（第 5 轮）` |
| A-FE-2 | P3 | 对 HTML 文档响应 `Range`，源站回 206 与半截 shell | `internal/webui/webui.go:129` | FIXED（93009b0） | 对 `index.html` 删掉 `Range`/`If-Range` 使其 200-only；`_app/immutable/*` 保留可 Range — 来源：`docs/audit-5/findings/frontend.md:68（第 5 轮）` |
| A-FE-3 | P3 | 同意页显示的 scope 集合 ≠ 服务器授予的 scope 集合（OIDC claim scope 静默补授） | `internal/httpapi/authorization_routes.go:185-201`、`internal/oidchttp/oidchttp.go:1251-1262` | FIXED（fddbde4） | 三选一裁定：同意页加一行常驻说明 / `scopeViews` 回显式「未描述」占位 / 给 `NarrowScopes` 加「批准集必须覆盖 displayed」的不变量 — 来源：`docs/audit-5/findings/frontend.md:87（第 5 轮）` |
| A-FE-V1 | P3 | 「显示少于授予」有第二/第三份独立实现（设备流）⇒ 只改一处覆盖不到 | `internal/store/memory/oidc.go:1250,1283-1288`、`internal/store/postgres/oidc.go:1060,1094-1102` | FIXED（fddbde4） | 与 A-FE-3 共用同一判据；修 A-FE-3 时必须一并覆盖设备流两后端 — 来源：`docs/audit-5/findings/frontend-VERIFIED.md:297（第 5 轮）` |
| A-FE-6 | P3 | `internal/webui` 只对 shell 设文档策略，非 HTML 资源不带 CSP | `internal/webui/webui.go:123-127` | FIXED（93009b0） | 把 `shellCSP` 扩成「任何 `text/html` 响应」，并断言 shell 上存在 `frame-ancestors`（真实组合根已由 `withSecurityHeaders` 兜住，属纵深防御） — 来源：`docs/audit-5/findings/frontend.md:140（第 5 轮）` |

## 已修复

- S01-1 — FIXED（153d910）
- S01-2 — FIXED（79a767c）
- S01-3 — FIXED（7c5f515）
- S01-6 — FIXED（d8de48a）
- S02-3 — FIXED（284c5be）
- S02-4 — FIXED（3617ac2）
- S05-1 — FIXED（1c3f249）
- S06-3 — FIXED（d4a60f2）
- S06-4 — FIXED（03c1ae1）
- S06-5 — FIXED（03c1ae1）
- S07-2 — FIXED（13e753e）
- S08-1 — FIXED（dc7400a）
- S08-4 — FIXED（fceaccd）
- S09-1 — FIXED（232d162）
- S09-2 — FIXED（fac6ad7）
- S10-2 — FIXED（ee3d20b）
- S11-6 — FIXED（0220f24）
- S12-1 — FIXED（a8a5122）
- S13-2 — FIXED（a0487e1）
- S14-3 — FIXED（c3401b5）
- S14-5 — FIXED（042d7d0）
- S01-10 — FIXED（fddbde4）
- S01-11 — FIXED（c17ce23）
- S01-12 — FIXED（c17ce23）
- S01-4 — FIXED（c17ce23）
- S01-5 — FIXED（c17ce23）
- S01-7 — FIXED（c17ce23）
- S01-8 — FIXED（c17ce23）
- S01-9 — FIXED（c17ce23）
- S02-10 — FIXED（b6407e1）
- S02-6 — FIXED（b6407e1）
- S02-7 — FIXED（b6407e1）
- S02-8 — FIXED（fddbde4）
- S02-9 — FIXED（b6407e1）
- S03-10 — FIXED（6cc3cc2）
- S03-2 — FIXED（56acd6b）
- S03-3 — FIXED（511cced）
- S03-4 — FIXED（511cced）
- S03-5 — FIXED（b0004c0）
- S03-6 — FIXED（b0004c0）
- S03-8 — FIXED（6cc3cc2）
- S03-9 — FIXED（511cced）
- S04-2 — FIXED（c17ce23）
- S04-4 — FIXED（c17ce23）
- S04-5 — FIXED（fddbde4）
- S04-6 — FIXED（c17ce23）
- S04-7 — FIXED（fddbde4）
- S04-8 — FIXED（c17ce23）
- S04-9 — FIXED（c17ce23）
- S05-3 — FIXED（2ab00ee）
- S05-4 — FIXED（2ab00ee）
- S05-5 — FIXED（2ab00ee）
- S05-6 — FIXED（93009b0）
- S05-7 — FIXED（2ab00ee）
- S05-8 — FIXED（2ab00ee）
- S06-10 — FIXED（fddbde4）
- S06-6 — FIXED（f0f9256）
- S06-7 — FIXED（a8bca1f）
- S06-8 — FIXED（a8bca1f）
- S06-9 — FIXED（2ab00ee）
- S07-10 — FIXED（53bbe24）
- S07-3 — FIXED（c3401b5）
- S07-5 — FIXED（53bbe24）
- S07-6 — FIXED（53bbe24）
- S08-5 — FIXED（7a35ac6）
- S08-6 — FIXED（7a35ac6）
- S08-7 — FIXED（fddbde4）
- S08-8 — FIXED（7a35ac6）
- S08-9 — FIXED（7a35ac6）
- S09-3 — FIXED（6cc3cc2）
- S09-5 — FIXED（6cc3cc2）
- S09-6 — FIXED（6cc3cc2）
- S09-7 — FIXED（6cc3cc2）
- S09-8 — FIXED（6cc3cc2）
- S09-9 — FIXED（6cc3cc2）
- S10-3 — FIXED（4fd7603）
- S11-2 — FIXED（be67775）
- S11-3 — FIXED（be67775）
- S11-4 — FIXED（be67775）
- S11-7 — FIXED（6cc3cc2）
- S11-8 — FIXED（b0004c0）
- S11-9 — FIXED（fddbde4）
- S12-10 — FIXED（fddbde4）
- S12-3 — FIXED（6598fc5）
- S12-4 — FIXED（6598fc5）
- S12-5 — FIXED（6598fc5）
- S12-6 — FIXED（6598fc5）
- S12-8 — FIXED（93009b0）
- S13-4 — FIXED（93009b0）
- S13-6 — FIXED（4fd7603）
- S13-7 — FIXED（b640434）
- S13-8 — FIXED（b640434）
- S13-9 — FIXED（b0004c0）
- S14-4 — FIXED（2ab00ee）
- S15-11 — FIXED（95f13f0）
- S15-2 — FIXED（07f7105）
- S15-4 — FIXED（95f13f0）
- S15-5 — FIXED（fddbde4）
- S15-6 — FIXED（07f7105）
- S15-7 — FIXED（07f7105）
- S15-9 — FIXED（07f7105）
- S01-13 — FIXED（fddbde4）
- S02-5 — FIXED（b6407e1）
- S05-10 — FIXED（da9f33a）
- S05-9 — FIXED（da9f33a）
- S07-11 — FIXED（fddbde4）
- S07-4 — FIXED（6527fbe）
- S07-7 — FIXED（53bbe24）
- S07-8 — FIXED（53bbe24）
- S07-9 — FIXED（6527fbe）
- S09-10 — FIXED（6cc3cc2）
- S09-4 — FIXED（fddbde4）
- S10-4 — FIXED（b0004c0）
- S12-11 — FIXED（e3184bf）
- S12-9 — FIXED（6598fc5）
- S14-11 — FIXED（b6407e1）
- S14-12 — FIXED（da9f33a）
- S15-13 — FIXED（95f13f0）
- CONF-1 — FIXED（fddbde4）
- CONF-2 — FIXED（fddbde4）
- CONF-3 — FIXED（fddbde4）
- CONF-4 — FIXED（fddbde4）
- Z07-4 — FIXED（511cced）
- Z07-5 — FIXED（b0004c0）
- Z07-6 — FIXED（b0004c0）
- Z07-7 — FIXED（b0004c0）
- Z07-8 — FIXED（fddbde4）
- Z07-9 — FIXED（fddbde4）
- Z08-3 — FIXED（e3184bf）
- Z08-5 — FIXED（93009b0）
- Z08-7 — FIXED（b0004c0）
- Z08-8 — FIXED（6598fc5）
- Z09-2 — FIXED（da9f33a）
- Z09-3 — FIXED（da9f33a）
- Z09V-2 — FIXED（da9f33a）
- Z09V-3 — FIXED（da9f33a）
- Z10-1 — FIXED（fddbde4）
- Z10-2 — FIXED（6cc3cc2）
- Z10-4 — FIXED（cb8b49d）
- Z10-5 — FIXED（fddbde4）
- Z10-6 — FIXED（93009b0）
- Z10-7 — FIXED（93009b0）
- Z10-8 — FIXED（cb8b49d）
- Z10-9 — FIXED（93009b0）
- Z10V-1 — FIXED（be67775）
- Z10V-2 — FIXED（7a35ac6）
- Z11-6 — FIXED（15878e2）
- Z12-5 — FIXED（7a35ac6）
- Z12-8 — FIXED（7a35ac6）
- Z12V-1 — FIXED（7a35ac6）
- Z12V-3 — FIXED（7a35ac6）
- Z13-2 — FIXED（cb8b49d）
- Z13-5 — FIXED（f0f9256）
- Z13-6 — FIXED（461e1d3）
- Z13-7 — FIXED（95f13f0）
- Z14-5 — FIXED（a8bca1f）
- Z14-6 — FIXED（aee682f）
- Z14-V1 — FIXED（f0f9256）
- Z15-2 — FIXED（1eda335）
- Z15-3 — FIXED（64be6b1）
- Z15-4 — FIXED（4fd7603）
- Z16-4 — FIXED（f0f9256）
- Z16-5 — FIXED（b37864e）
- Z16-6 — FIXED（893c6a3）
- Z16-7 — FIXED（07f7105）
- Z17-1 — FIXED（07f7105）
- Z17-2 — FIXED（95f13f0）
- Z17-3 — FIXED（95f13f0）
- Z17-4 — FIXED（fddbde4）
- Z17-5 — FIXED（07f7105）
- Z17V-1 — FIXED（07f7105）
- Z18-2 — FIXED（a8bca1f）
- Z18-3 — FIXED（c17ce23）
- Z18v-1 — FIXED（c17ce23）
- Z19-2 — FIXED（a8bca1f）
- Z19-3 — FIXED（6527fbe）
- Z19V-2 — FIXED（7a35ac6）
- Z20-2 — FIXED（fddbde4）
- Z20-3 — FIXED（64be6b1）
- Z20-4 — FIXED（64be6b1）
- Z20-6 — FIXED（b6407e1）
- Z20V-1 — FIXED（fddbde4）
- Z20V-2 — FIXED（fddbde4）
- 22-1 / G-11 — FIXED（b0004c0）
- Z21V-2 — FIXED（7feca3f）
- Z21-1 — FIXED（7feca3f）
- Z21-4 — FIXED（7feca3f）
- Z21-3 — FIXED（7feca3f）
- 22-2 — FIXED（cb8b49d）
- N-03 — FIXED（c17ce23）
- G-11 — FIXED（b0004c0）
- G-14 — FIXED（6cc3cc2）
- G-15 — FIXED（d4ad025）
- G-16 — FIXED（64be6b1）
- G-17 — FIXED（6cc3cc2）
- G-18 — FIXED（da9f33a）
- G-19 — FIXED（6527fbe）
- G-20 — FIXED（fddbde4）
- G-21 — FIXED（6527fbe）
- G-22 — FIXED（7a35ac6）
- 04-7 — FIXED（fddbde4）
- P-03 — FIXED（b6407e1）
- k6 — FIXED（511cced）
- FO-03 — FIXED（93009b0）
- FO-04 — FIXED（cb8b49d）
- KIT-8 — FIXED（fddbde4）
- KIT-9 — FIXED（893c6a3）
- KIT-10 — FIXED（fddbde4）
- RP-5 — FIXED（a8bca1f）
- RP-6 — FIXED（511cced）
- RP-8 — FIXED（511cced）
- FO-05 — FIXED（fddbde4）
- A-FE-1 — FIXED（93009b0）
- A-FE-2 — FIXED（93009b0）
- A-FE-3 — FIXED（fddbde4）
- A-FE-V1 — FIXED（fddbde4）
- A-FE-6 — FIXED（93009b0）
