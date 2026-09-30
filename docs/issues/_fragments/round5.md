# 第 5 轮 · 抽取结果

> 口径：**只收 `HEAD = bf81b2a` 上仍未修的条目**。红/绿以 `//go:build audit5` 探针在 HEAD 的
> 实际运行为准（权威：`docs/audit-7/findings/22-audit5-red-reconciliation.md`）。
> 19 条红探针 = KNOWN-OPEN 16 / DECIDED-NONGOAL 3 / REGRESSION 0 / UNCLASSIFIED 0；
> round-5 之后约 35 个修复提交（`51d0e99..bf81b2a`）已收掉 P0-1…P0-6、P1-1…P1-5 与 P2 表 30 条。

## P0/P1

（本区块**无 OPEN 项**：round-5 的 P0-1…P0-6、P1-1…P1-5 在 HEAD 上全部已修，逐条见「已修复」。
唯一与 P1-4 修复相关的新缺陷是回归 22-1，属 P2，见下表。）

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| k1 | P2 | 账号抹除后原始 `usr_…` 仍随 `slog.Warn("...erasure", "user", string(user))` 进**进程日志**，假名密钥销毁够不到 | `internal/httpapi/account_routes.go:54-74`（日志在 `:73`） | FIXED（17914d4） | 删掉该行的 `"user"` 属性（`request_id` 已够定位）或改记形状｜来源：`docs/audit-5/findings/crypto-keys.md:51` |
| k6 | P3 | 同类身份进日志共 7 处（除 k1 都在错误路径），不受假名销毁影响；`admin.go:442` 由合法运维请求触发、面最大 | `internal/admin/admin.go:442`、`internal/auth/auth.go:218`、`internal/federation/bind.go:208`、`internal/federation/refresh.go:155`、`:160`、`internal/httpapi/account_routes.go:73`、`internal/httpapi/binding_routes.go:57` | OPEN | 统一改记 `action`/`self` 等形状而非 id；把该静态守卫并入常规套件｜来源：`docs/audit-5/findings/crypto-keys.md:175` |
| FO-03 | P3 | `nonPublicPrefixes` 漏 `0.0.0.0/8`（含 `::ffff:0.x`），`DenyPrivateAddresses=true` 时仍被拨号层放行；Linux 上若内核把 `0/8` 路由到回环即等价 SSRF（本机 Windows 未能证实可利用性） | `httpclient/outbound.go:117-128`（`IsPublicAddress` 在 `:130-153`） | OPEN | 把 `netip.MustParsePrefix("0.0.0.0/8")` 加进 `nonPublicPrefixes`｜来源：`docs/audit-5/findings/federation.md:123` |
| FO-04 | P3 | `NewRegistry` 不校验 `game`/`name`/`Resources[].Scope`：带空格的 scope 让上游收到从未声明的额外 scope，`?`/`#`/`..` 让回调 URL 与注册到源的 `redirect_uri` 不一致（操作者 TOML 输入，无远程路径） | `internal/federation/federation.go:112-122`（`bindScopes`）、`:141-175`（`NewRegistry`） | OPEN | 按 `idp.validateProviderName` 同款规则校验 `game`/`name`，`Resource.Scope` 严格文法或拒绝含空白｜来源：`docs/audit-5/findings/federation.md:164` |
| KIT-2 | P2 | 一次请求可声明两个客户端身份：`ClientCredentials` Basic 赢者通吃，表单里的第二个身份完全不比对（未观察到提权，风险是下游按表单判身份时与 kit 不一致） | `oauth/http.go:33-38` | OPEN | 把 `internal/oidchttp` 已裁定的「一请求一身份」搬进 `oauth.ClientCredentials`：两身份同时出现且不一致 → `invalid_client`｜来源：`docs/audit-5/findings/_fragment_kit.md:82` |
| KIT-4 | P2 | `ConsumeCode` 在任何绑定校验之前执行 ⇒ 知道 code 就足以无凭据烧掉它（低成本定向 DoS），且失败不写审计、不可观测 | `oauth/as.go:165`（校验在 `:175`/`:178`/`:181`） | FIXED（7cfbdb5） | 已按建议的最小形状落地：非破坏性 `GetCode` → 全绑定校验 → `ConsumeCode` 原子门（单次使用/并发窗口不变），失败记 `oauth.exchange_failed`。守卫：`oauth/as_test.go`、`oauth/tokens_test.go`、kit `TestC1_`/`TestC2_`、postgres 无 DB 源码守卫。注：OP 面（`oidchttp`+`OIDCStore.AuthRequestByCode`）仍是 consume-on-read 的同形兄弟项，本条不含。｜来源：`docs/audit-5/findings/_fragment_kit.md:154` |
| KIT-5 | P2 | `describe()` 只查非空 + S256，1 字符/padded/大写 `code_challenge` 也发码，该码永远换不出令牌；KIT-4 已修后该码不再被烧，但仍是死码，用户白授权且需重走全流程 | `oauth/as.go:104-106` | OPEN | 在 `describe()` 加与兑换侧同源的形状校验（S256 必为 43 字符 base64url），或抽公共函数防两处漂移｜来源：`docs/audit-5/findings/_fragment_kit.md:189` |
| KIT-6 | P2 | `RestoreClient` 故意不重校验重定向 URI，而 authorize 路径没有第二道检查 ⇒ registry 里的 `javascript:`/`data:` 历史行照单全收（现代浏览器 `Location` 不执行，风险在渲染成链接的源实现） | `oauth/client.go:180-192`、`:159-166`（`AllowsRedirect` 纯字符串） | OPEN | 在 `AllowsRedirect` 里补 `validRedirectURI`。**涉及裁定**：`docs/admin.md:69` 把 registry 写入方视为可信运维，not-doing §四.2 主张正式降为提示｜来源：`docs/audit-5/findings/_fragment_kit.md:226` |
| KIT-7 | P2 | 一致性套件对客户端认证零断言：声明 `client_secret_basic` 却谁都不认证的源零 error 通过（含无认证 cascade 判 PASS）⇒ 假「合规」保证 | `upstreamkit/conformance/conformance.go:183-205` | OPEN | 加「未知 client 打已宣告端点必须 4xx」与「正确凭据 200 / 错误凭据 401」两组断言，并把 `token_endpoint_auth_methods_supported` 与实收方式比对｜来源：`docs/audit-5/findings/_fragment_kit.md:263` |
| KIT-8 | P3 | 无 `Content-Length`（chunked/gzip）的超限体经 `MaxBytesError`→`ParseForm` 错误塌成 `400 malformed form body`，而非文档承诺的 413（**无绕过**，是误分类/不可观测） | `oauth/bodylimit.go:27-35`、`upstreamkit/server.go:240-243`（另 `:296-299`、`:319-322`） | OPEN | `ParseForm` 错误里 `errors.As(err, new(*http.MaxBytesError))` → 413；三个调用点共用一个 helper｜来源：`docs/audit-5/findings/_fragment_kit.md:310` |
| KIT-9 | P3 | 两份 well-known 都不设 `Cache-Control`/`Vary` ⇒ 中间层可长期钉住过期发现文档（含已移除的 `cascade_revocation_endpoint`） | `upstreamkit/server.go:169-185` | OPEN | `handleDiscovery`/`handleOAuthMetadata` 各加 `Cache-Control: no-store`（与 Re0Auth 平面一致）｜来源：`docs/audit-5/findings/_fragment_kit.md:354` |
| KIT-10 | P3 | `ClientAdmin.Delete` 只删 client 行、不删令牌：令牌行留下且仍 active，授权列表出现无名字记录（与 KIT-3 同根的另一出口） | `oauth/client.go:423-428`、`internal/store/postgres/oauth.go:515-518` | OPEN | 让 `Delete` 契约包含令牌清理（调 `TokenAdmin.RevokeTokens`），或文档明写「不撤销」并把责任交调用方｜来源：`docs/audit-5/findings/_fragment_kit.md:387` |
| RP-5 | P3 | discovery 缺 `authorization_endpoint` 时 `provider.Endpoint()` 回空串，被 `http.Redirect` 交给浏览器 ⇒ 相对登录 URL、原地打转/404（同源，仅可用性） | `idp/idp.go:427-435`、`internal/auth/auth.go:602` | OPEN | 发现后校验 auth/token 端点非空且为带 scheme+host 的绝对 URL，否则 `provider_unavailable`｜来源：`docs/audit-5/findings/_fragment_rp.md:181` |
| RP-6 | P3 | `clearFlow` 在 provider 比对之前执行 ⇒ 一次「走错 provider」的被拒回调烧掉待完成登录，`provider_mismatch` 诊断码被抹掉（需会话内 state，攻击者不能主动触发） | `internal/auth/auth.go:627`（比对在 `:629-633`） | OPEN | 把 provider 比对与 error/code 存在性检查移到 `clearFlow` 之前｜来源：`docs/audit-5/findings/_fragment_rp.md:203` |
| RP-7 | P3 | 同一 auth request 的批准 redirect 可重放，每次访问都新签一份码；第一份兑换成功后其余成死码，URL 预取/刷新可能抢走唯一兑换机会，死码残留至 TTL（一次同意仍只一份可兑换 grant） | `internal/store/memory/oidc.go`（`SaveAuthCode`/`AuthRequestByCode`；**行号未记录**） | OPEN | 让 `/oauth/authorize/callback` 对同一 auth request 幂等：已 `Done` 且有码则重定向同一码，或先 `DeleteAuthCodeByRequest`｜来源：`docs/audit-5/findings/_fragment_rp.md:227` |
| RP-8 | P3 | 登录完成后会话里仍留着 `flow_nonce`：`flowKeys` 漏了 `keyFlowNonce`，写入列表与清理列表不一致（目前无利用性） | `internal/auth/auth.go:41`、`:44`（`flowKeys`）、`:708-712`（`clearFlow`） | OPEN | 把 `keyFlowNonce` 加进 `flowKeys`，或让写入与清理共用同一列表｜来源：`docs/audit-5/findings/_fragment_rp.md:263` |
| 22-1 | P2 | **回归**（对 P1-4 修复的实现补充）：`readinessCache` 在「首次检查仍在进行、从未产生结论」时返回零值 `err=nil` ⇒ 依赖不可达时 `/readyz` 回 `200 ok`，窗口 ≤ `readinessTimeout`（2s），fail-open 且静默 | `internal/httpapi/health.go:111-118`（`handleReady` 在 `:94-101`） | OPEN | `if c.running { if c.checked { return c.err }; return errNoResultYet }`，由 `handleReady` 按普通失败回 503；不取消豁免、仍不因忙 shed｜来源：`docs/audit-7/findings/22-audit5-red-reconciliation.md:78` |
| 22-2 | P3 | FO-04 证据链里 `TestProbeRegistryAcceptsPathEscapingNames` 只做 `t.Logf`、无任何断言 ⇒ 结构上不可能失败；「畸形 game/name 被接受」在 HEAD 无守卫（方法学/证据缺陷，非运行时面） | `internal/zzprobe/federation/raw_test.go:284-317` | OPEN | 改成真守卫（断言 `NewRegistry` 拒绝 `..`、`/`、`?`、`#`、`\`、NUL、CR/LF、前后空白、超长），或在 FO-04 结案前从证据清单移除｜来源：`docs/audit-7/findings/22-audit5-red-reconciliation.md:146` |

## 已修复（仅 ID + 一句话，供溯源）

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

## 有意不做 / 已裁定

- FO-02 — refresh 赢 CAS 后行被删的 vault 残留：探针在 CAS **输掉**的分支触发（删行在 `PutIfVersion` 之前），残留是入册时那条旧密钥；「跨实例 refresh 残余竞态」已列有意不做 — 依据：`docs/issues/not-doing.md:53`、`docs/audit-7/findings/22-audit5-red-reconciliation.md:47`、`docs/security-audit-5.md:313`
- FO-05 — 数据面刻意不装重试层（绑定刷新是旋转型单次凭据）；`source-onboarding.md:225` 的「指数退避重试」是文档写错，不是实现缺陷 — 依据：`docs/issues/not-doing.md:35`、`docs/audit-5/findings/federation.md:214`、`docs/audit-7/findings/22-audit5-red-reconciliation.md:247`
- P2-19 — 不透明 bearer 的 JWE 解析约 12 KB/请求，仍在延迟预算余量内：裁定维持 go-jose 标准库、不自造轮子，仅业务到量级再立项 — 依据：`AUDIT-ISSUES.md:233`、commit `9db3a99`
- （无独立编号；startup 探针 #18/#19）— round-5 P1-4 已由 `0e6b701` 修复；两条探针断言的是修复前的缺陷与 `readinessTTL`（1s）的文档化代价，故判 DECIDED-NONGOAL，不重报 — 依据：`docs/audit-7/findings/22-audit5-red-reconciliation.md:63-64`、`docs/operations.md:171-183`
