# 已修复（仅供溯源）

> **这里不是待办。** 保留它只为了回答"这条当初为什么存在、后来被哪个 commit 收掉"。
> 由 `_fragments/_merge.mjs` 从各轮抽取结果生成（2026-09-30）。

### 第 7 轮

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

### 第 6 轮

- （无）第 7 轮在 HEAD=`bf81b2a` 复跑第 6 轮全部红探针仍红，**第 6 轮无发现被修复**（`00-MAIN-VERIFICATION.md:20-66`）。
- B-1 — 第五轮阻断项 id_token 缺必需 `sub`；第 6 轮实测已修（`_audit/protocol.md:206`）。
- B-2 — id_token 可在 `/oauth/userinfo` 当 access token 用；第 6 轮实测已修（`_audit/protocol.md:207`）。
- PROTO-1 — 不可解析 body 吞 `ParseForm` 错误绕过设备 scope 闸门；已修（`_audit/protocol.md:208`）。
- PROTO-4 — 内省白名单含公开客户端 ⇒ 无凭据读任意 token；**主体已修**（守卫被转义绕过另记 G-5）（`_audit/protocol.md:209`）。
- PROTO-5/6/7/9/10 — discovery 不撒谎、`prompt=none` 落地、`form_post` 拒绝带 `iss`、POST+query 拆分拒绝、userinfo 判据；均已修（`_audit/protocol.md:210-214`）。
- P1-1/P1-2 — vault 轮换窄写/CAS（lost-update）；第 6 轮新探针验证「修对、修全」（`03-crypto-vault.md:173-193`）。
- P2-32 — 设备路径单时钟（bf81b2a）；三处 SQL 参数化，未引入新洞（`03-crypto-vault.md:195-201`）。
- G-9 — 刷新签发的 id_token 保留原 nonce（OIDC Core §12.2）：`RefreshRequest`/`NonceOf`、两个 store 在 refresh 行上持久化并随轮换继承、`SetUserinfoFromRequest`、迁移 `0026`；audit6 里原本断言「刷新后没有 nonce」的探针翻转为断言保留 — `17914d4`
- G-23 — 6 处原始 `usr_…` 不再进 slog（admin/auth/federation bind+refresh/httpapi binding_routes；第 7 处 account_routes 由 k1 收掉）；audit5 静态守卫由红翻绿 — `6665193`
- G-13 — `GetRefreshTokenInfo` 现在把 `noRows` 报成哨兵、其余报 `oidc.ErrServerError`（库的 500 分支恢复可达）；经查在 `79d7333` 随 G-3 一并修掉，注册表此前陈旧 — `79d7333`
- G-7 — 已批准但过期的 `device_code` 不再换到令牌：库先判 `Done` 再判 `Expires`，两个 store 同时收紧消费谓词并修掉「`Done=true` 的 fall-through」（memory 删除后 `Done=false`，postgres 过期时补删再清 `Done`） — `4dff4a3`
- G-8 — `/oauth/revoke` 不再当存活性预言机：他人的活令牌与未知字符串同样 200、都不删；公共引擎与两个 store 的 `RevokeToken` 同步 — `4dff4a3`
- G-10 — 设备码轮询接受自己广告的 `client_secret_post`，且认证失败不再烧码：`internal/oidchttp` 在库的消费谓词之前先认证机密客户端 — `4dff4a3`

### 第 5 轮

- P0-1 — `id_token` 两条签发路径补上 `sub` — `02dd448`
- P0-2 — userinfo 拒绝三段式 JWS 形状 bearer、`SetUserinfoFromToken` 校验 tokenID — 同批 `02dd448`
- P0-3 — 数据面内存按字节约束、重标 `max_in_flight` 并加 `GOMEMLIMIT` — `fb3cff3`
- P0-4 — 分桶键不再含调用方写的值，桶表满时 fail-closed 不丢活桶 — `ce1915c`
- P0-5 — 参数集只解析一次、scope 闸门读全部值 — `6dec6e1`
- P0-6 — 内省白名单只接受机密客户端 — `b0df14b`
- P1-1 — 轮转只按 CAS 重写信封，未完成轮转不再报成功 — `1076cbf`
- P1-2 — `rotate.go` 不再整条覆盖并发入册的 stale 记录 — 同批 `1076cbf`
- P1-3 — 数据面设总期限，401 计入熔断失败判据 — `96d76cc`
- P1-4 — 豁免探针路径设成本上限且永不 shed（**其成本上限实现引入 22-1**） — `0e6b701`
- P1-5 — 按真正服务这次读取的源判定资源 scope（顺带修掉 P2-18） — `5793274`
- P2-1 — OP store 不再 `_ =` 吞审计失败，改 `slog.Error` — `5cd1690`
- P2-2 — 改承诺：抹除失败的 500 文案不再假装可重试 — `5cd1690`
- P2-3 — 抹除路径改用 `EndSession`，不再在假名销毁后写原始 `usr_` — `5cd1690`
- P2-4 — 四条批量撤销谓词补前导索引（0022 迁移） — `b35f893`
- P2-5 — `oidc_auth_requests.client_id` 补前导索引 — `b35f893`
- P2-6 — `trusted_proxies` 的 `0.0.0.0/0`/`::/0` 需显式承认 — `e9dc23d`
- P2-7 — `sources[].token_class` 校验枚举并给安全默认（=CS-4 转绿） — `e9dc23d`
- KIT-7 — conformance 套件新增客户端认证断言：未知客户端+无凭据在 token/revoke 必须 401，可选 `ClientID/ClientSecret` 校验「正确密钥不被 invalid_client 拒、错密钥必须被拒」，并对照 `token_endpoint_auth_methods_supported` — `4dff4a3`
- P2-8 — `DATABASE_URL` 单独即选 postgres、新增 `RE0AUTH_STORAGE_DRIVER`、修正警告文案 — `e9dc23d`
- P2-9 — `restore.sh` 校验绑定到实际入参 — `7f19637`
- P2-10 — `.age` 加密备份路径同样执行校验 — `7f19637`
- P2-11 — `.sha256` 缺失即拒绝（不再 fail-open） — `7f19637`
- P2-12 — Trivy 门禁前移到 push 之前、manifest 去掉 `latest` — `7f19637`
- P2-13 — 发布镜像补 `VERSION` build-arg — `7f19637`
- P2-14 — 备份脚本 `umask 077`、临时目录清理、DSN 走 env — `7f19637`
- P2-15 — runbook `[admin].allow`→`subjects`、内部监听器默认值等文档漂移 — `7f19637`
- P2-16 — 备份 Pod 加独立标签并被 NetworkPolicy 选中 — `e9dc23d`
- P2-17 — 同意面「已满足」判据与数据面同源（按资源名） — `f6af208`
- P2-18 — 闸门与选源用同一状态过滤（retired 源不能再设闸门） — `5793274`
- P2-20 — `pnpm audit` 门槛降到 low 并忽略不可达告警 — `c3c40a7`
- P2-21 — `make npm-attribution` 生成清单并接进 checksums/release — `e9dc23d`/`7f19637`
- P2-22 — `account.export` 与 `admin.audit.read` 各留一条审计 — `5cd1690`
- P2-23 — 内省只广告 `client_secret_basic` — `513471d`
- P2-24 — 实现 `prompt=none` — `f6af208`
- P2-25 — RP 侧 JWKS 缓存加 TTL — `60de35d`
- P2-26 — RP 侧 discovery 端点钉在 issuer 上 — `60de35d`
- P2-27 — Kit 级联撤销端点必须先认证（=KIT-1 转绿） — `b5f01da`
- P2-28 — `Introspect` 查 client 状态（=KIT-3 转绿） — `b5f01da`
- P2-29 — `writeProblem` 自身设 `no-store`，覆盖编码路径 404 — `b35f893`
- P2-30 — 业务面 429/413 补 `no-store` — `b35f893`
- P2-31 — auditbatch 排空加 30s 总预算 — `5cd1690`
- P2-32 — 设备路径期限改由 store 时钟裁决 — `bf81b2a`
- k1 — 抹除后的会话清理告警不再带原始 `usr_`，改带 `request_id`；新增默认套件守卫（旧代码上为红） — `17914d4`

### 第 2 轮

- **第二轮全族（A1-* / A2-* / A4-* / A5-* / A6-*）** — 报告自陈 15 条全部已修，每条复现测试都改写成常规套件里的守卫：`docs/security-audit-2.md:9-11`。
- A1-1 / A1-2 / A1-3 — 预检改为方法无关；POST authorize 与设备流都不再签发未注册 scope（守卫 `TestAdversarialPostAuthorizeRejectsUnregisteredScope`、`TestAdversarialDeviceAuthorizationRefusesUnregisteredScope`）。
- A2-1 及其邻项 — bind 回调补上 `sessions.OwnerMatches`（与 `Bound` 一起查、失败同形 400）；同批 A1-2/A1-3/A6-1/A6-2/A6-5 均已修（`docs/security-audit-2.md:17-38`）。
- A4-1（及同批撤销缺口） — refresh token 撤销真的删行；`oauth.Revoke` 校验归属；`SweepExpired` 不再踢登录中的会话。
- A5-1 — 抹除的审计 `Detail` 不再装 `usr_…`（改记 `self`）。
- A5-2 — 夹具把 `audit_chain`/`audit_subject_keys` 加进 `TRUNCATE` 并重播 genesis。
- A5-3 — 凭据列守卫改为扫整个 live schema + 一条无 DB 的静态版。
- A5-4 — 业务平面 `writeJSON` 统一 `no-store`。
- A6-1 — `Unbind` 区分「vault 打不开」（`RevocationUnavailable`）与「无事可做」。
- A6-2 — refresh 改为先 CAS、赢了才写 vault。
- A6-3 — 32 字节 hex 的 KEK/审计密钥现在被正确接受。
- A6-5 — bind 回滚失败用 `errors.Join` 并入返回错误。
- **第三轮全族（A3-* / B3-* / C3-*）** — CONFIRMED 的全部已修：`docs/security-audit-3.md:16`。
- A3-1 / A3-2 — `isToken` 与设备预检改为只看路径；GET 不再绕过令牌响应契约与 scope 闸门。
- A3-3 — `userinfo` 的 401 补 RFC 6750 Bearer challenge。
- A3-5 — `oidchttp.New` 要求 `Clients`/`Registry` 必填，删掉 fail-open 分支。
- A3-4 — 设备流「一个请求只能声明一个客户端身份」；**第四轮 commit `5376ca3` 修复**并留守卫（`docs/security-audit-3.md:201-207`）。
- B3-1 / B3-2 / B3-3 — 审计链加链头见证、空页带上服务端实际应用的 limit、零值时间界一律 400。
- C3-1 / C3-2 / C3-3 — 撤销触达已批准设备授权、`device_code` 单次使用、设备审批写路径带谓词（`done = false AND denied = false AND expires_at > now()`）。
- 结构性（第三轮） — 平面走查改为对库无方法约束的端点逐方法各走一遍（`protocolAnyMethod`）。
- 第三方库日志面（第四轮） — 枚举 `zitadel/oidc v3.51.3` 在这些路径上写什么，落成 `TestAdversarialProtocolErrorsDoNotLogCredentials` 与成功路径的一半（`docs/security-audit-2.md:351-358`）。
- `oauth` 遗留引擎的设备决策丢失更新（第三轮「仍开放」） — 拆成 `RecordPoll`/`RecordDecision`，第一决定即最终（破坏性变更，见 CHANGELOG；`docs/security-audit-3.md:263-276`）。
- KIT-1 / KIT-3 — 已由后续修复转绿（匿名 cascade 现在 401；暂停/删除客户端的令牌现在 `active=false` 且数据面 401）：`docs/audit-7/findings/22-audit5-red-reconciliation.md:70`。
- A-FE-9 — 残余（`architecture.md:12` 声称「构建产物可复现」与实际不符）已消除：该行现在明确写「**注意"可复现"不是当前成立的性质**」并说明所需前置条件（`docs/architecture.md:12-14`）。
