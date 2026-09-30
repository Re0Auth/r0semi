# 第 2–4 轮 · 抽取结果

> **口径**：`HEAD = bf81b2a`。只收「在 HEAD 上仍未修」的条目；第 2/3 轮报告已显式标记为
> `已修复` 的成员只在「已修复」一节压缩保留。
>
> **轮次归属提示**：本片按用户口径收录第 2–4 轮台账；其中 `FO-*` / `KIT-*` / `RP-*` / `k1`/`k6` /
> `A-FE-*` 的**原始落盘位置**是 `docs/audit-5/findings/`（项目自身把那一轮编号为**第五轮**），
> 故各条的 `来源` 行按原始报告标注为「第 5 轮」。
>
> **仍然开放的 16 条**（`k1`/`k6`、`FO-03/04/05`、`KIT-2/4/5/6/7/8/9/10`、`RP-5/6/7/8`）由
> `docs/security-audit-7.md:83` 与 `docs/audit-7/findings/22-audit5-red-reconciliation.md:44-68`
> 共同确证：19 条 `audit5` 红探针中 **KNOWN-OPEN 16 / DECIDED-NONGOAL 3 / REGRESSION 0 / UNCLASSIFIED 0**。

## P0/P1

（本片抽取范围内**无 P0/P1 项**。历史未关闭的 16 条按各原始报告的自评为「中/低/提示」，全部落在下方
P2/P3 表；A-FE 家族经对抗性复核后最高为「中」——见 `docs/audit-5/findings/frontend-VERIFIED.md:23-33`、
`docs/security-audit-7.md:83`。）

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| k1 | P2 | 账号抹除后 `usr_…` 仍被写进进程日志，假名密钥销毁够不到它 | `internal/httpapi/account_routes.go:54-74` | OPEN | 删掉 `slog` 里的 `"user"` 属性（同一条行已有 `request_id`），或像 `lifecycle` 那样只记形状 — 来源：`docs/audit-5/findings/crypto-keys.md:51（第 5 轮）` |
| k6 | P3 | 同一类「身份进 slog」共 7 处，静态守卫持续抓到 | `internal/admin/admin.go:442`、`internal/auth/auth.go:218`、`internal/federation/bind.go:208`、`internal/federation/refresh.go:155,160`、`internal/httpapi/account_routes.go:73`、`internal/httpapi/binding_routes.go:57` | OPEN | 统一改成「形状而非 id」（`action` 已足够定位），并把该 AST 守卫并进常规套件 — 来源：`docs/audit-5/findings/crypto-keys.md:175（第 5 轮）` |
| KIT-2 | P2 | 一次请求可声明两个客户端身份：Basic 与表单互不校验，谁被采用只看哪个非空 | `oauth/http.go:33-38` | OPEN | 把 `internal/oidchttp` 已落地的「一个请求只能声明一个客户端身份」搬进 `oauth.ClientCredentials`；两边一致才放行 — 来源：`docs/audit-5/findings/_fragment_kit.md:82（第 5 轮）` |
| KIT-4 | P2 | 失败的兑换会把授权码烧掉：知道 code 就足以让合法客户端拿不到令牌 | `oauth/as.go:165`（校验在 `:175`、`:178`、`:181`） | FIXED（7cfbdb5） | 已落地：非破坏性 `GetCode` → 全绑定校验 → `ConsumeCode` 原子门，失败记 `oauth.exchange_failed`；见 round5 同条。 — 来源：`docs/audit-5/findings/_fragment_kit.md:154（第 5 轮）` |
| KIT-5 | P2 | authorize 不校验 `code_challenge` 形状：1 个字符的挑战也发码，而该码永远换不出令牌 | `oauth/as.go:104-106` | OPEN | 在 `describe()` 加 43 字符 + base64url 字母表校验（与兑换侧同源抽成一个共用函数） — 来源：`docs/audit-5/findings/_fragment_kit.md:189（第 5 轮）` |
| KIT-6 | P2 | `RestoreClient` 跳过重定向 URI 校验，authorize 会照单全收 `javascript:` 重定向 | `oauth/client.go:159-166,180-192`、`oauth/as.go:101-103` | OPEN | 在 `Client.AllowsRedirect` 里先跑 `validRedirectURI`（一处收口覆盖 authorize 与 kit），并加启动自检标记历史坏行 — 来源：`docs/audit-5/findings/_fragment_kit.md:226（第 5 轮）` |
| KIT-7 | P2 | conformance 不对客户端认证做任何断言：声明 `client_secret_basic` 却谁都不认证的源零 error 通过 | `upstreamkit/conformance/conformance.go:183-205,295-297` | OPEN | 补两组带状态检查：未知 client_id 打 revoke/cascade 必须 4xx；用正确/错误凭据各跑一次兑换并比对 `token_endpoint_auth_methods_supported` — 来源：`docs/audit-5/findings/_fragment_kit.md:263（第 5 轮）` |
| KIT-8 | P3 | 无 `Content-Length`（chunked/gzip）的超限体回 `400 malformed form body` 而不是承诺的 `413` | `oauth/bodylimit.go:27-35`、`upstreamkit/server.go:240-243,296-299,319-322` | OPEN | `ParseForm` 错误先 `errors.As(*http.MaxBytesError)` 归成 413，三个调用点共用一个小 helper — 来源：`docs/audit-5/findings/_fragment_kit.md:310（第 5 轮）` |
| KIT-9 | P3 | 两份 well-known 文档都没有 `Cache-Control`/`Vary`：过期的发现文档可被中间层长期钉住 | `upstreamkit/server.go:169-185` | OPEN | 两处 handler 加 `Cache-Control: no-store`（与 Re0Auth 平面一致），或显式 `public, max-age=<短>` + `Vary: Host` — 来源：`docs/audit-5/findings/_fragment_kit.md:354（第 5 轮）` |
| KIT-10 | P3 | `ClientAdmin.Delete` 只删客户端行不删令牌 ⇒「客户端已删除」与「它的授权还在」同时成立（孤儿令牌行） | `oauth/client.go:423-428`、`internal/store/postgres/oauth.go:515-518` | OPEN | 让 `Delete` 契约包含 `RevokeTokens(TokenFilter{ClientID: id})`，或在文档里明确写「Delete 不撤销令牌」 — 来源：`docs/audit-5/findings/_fragment_kit.md:387（第 5 轮）` |
| RP-5 | P3 | discovery 缺 `authorization_endpoint` 时，RP 把「相对登录 URL」交给浏览器 | `idp/idp.go:427-435`、`internal/auth/auth.go:602` | OPEN | 发现端点后校验 `authorization_endpoint`/`token_endpoint` 非空且为绝对 URL，否则判 `provider_unavailable`，不交给浏览器 — 来源：`docs/audit-5/findings/_fragment_rp.md:181（第 5 轮）` |
| RP-6 | P3 | 指向错误 provider 的 callback 先 `clearFlow` 再比对 provider：一次被拒的回调烧掉待完成登录 | `internal/auth/auth.go:627-633` | OPEN | 把 provider 比对（及 error/code 存在性检查）移到 `clearFlow` 之前，只在确认是本流程回调后消费会话状态 — 来源：`docs/audit-5/findings/_fragment_rp.md:203（第 5 轮）` |
| RP-7 | P3 | 同意批准返回的 redirect 可重放：每次访问都新签一个授权码，只有先被兑换的那份算 grant | `internal/store/memory/oidc.go`（`SaveAuthCode`/`AuthRequestByCode`；行号未记录） | OPEN | 让 `/oauth/authorize/callback` 对同一 auth request 幂等：已 `Done` 且有码就重定向到同一个码，或生成前先 `DeleteAuthCodeByRequest` — 来源：`docs/audit-5/findings/_fragment_rp.md:227（第 5 轮）` |
| RP-8 | P3 | 登录完成后会话里仍留着 `flow_nonce`（`flowKeys` 漏了 `keyFlowNonce`） | `internal/auth/auth.go:41,44,708-712` | OPEN | 把 `keyFlowNonce` 加进 `flowKeys`；更好的是让写入与清理共用同一个列表 — 来源：`docs/audit-5/findings/_fragment_rp.md:263（第 5 轮）` |
| FO-03 | P3 | 私网地址闸门漏掉 `0.0.0.0/8`（含 IPv4-mapped 形式）；可利用性未在 Linux 上验证 | `httpclient/outbound.go:117-153` | OPEN | 把 `netip.MustParsePrefix("0.0.0.0/8")` 加进 `nonPublicPrefixes`（`Unmap()` 已覆盖 `::ffff:0.x`） — 来源：`docs/audit-5/findings/federation.md:123（第 5 轮）` |
| FO-04 | P3 | 源注册表不校验 `game`/`name`/`Resources[].Scope`，它们直接进重定向 URL 与 OAuth scope 参数 | `internal/federation/federation.go:112-122,141-175,250` | OPEN | 按 `idp.validateProviderName` 同款规则校验 `Game`/`Name`，`Resource.Scope` 用严格文法校验或在 `bindScopes` 拒绝含空白者 — 来源：`docs/audit-5/findings/federation.md:164（第 5 轮）` |
| FO-05 | P3 | 数据面没有重试层，而 `docs/source-onboarding.md` §4 对源的承诺多了一项 | `docs/source-onboarding.md:225`、`cmd/re0auth/main.go:459-475`、`httpclient/outbound.go:304-321` | OPEN | **改文档比加代码正确**（不装重试是裁定，见「有意不做」）；或改 `source-onboarding.md:225`，并在 `resilience-decision.md` 补一句理由 — 来源：`docs/audit-5/findings/federation.md:214（第 5 轮）` |
| A-FE-5（别名 P2-20） | P2 | CI 前端依赖审计门是 `pnpm audit --audit-level high`，树里唯一告警 `cookie@0.6.0` 恰在门槛下 ⇒ 这道门永远不会响 | `.github/workflows/ci.yml:335-337` | OPEN | 降到 `--audit-level low` 并把结果条数落进 job summary，或在 `docs/dependencies.md` 显式写下「low 以下不阻断」的理由 — 来源：`docs/audit-5/findings/frontend.md:119（第 5 轮）` |
| A-FE-1 | P3 | SPA shell 没有缓存验证器，只剩 `Cache-Control: no-cache` 一层 | `internal/webui/webui.go:129,143-150` | OPEN | 首次调用时对 `index.html` 算一次强 `ETag` 并缓存，让 `http.ServeFileFS` 回 304 — 来源：`docs/audit-5/findings/frontend.md:50（第 5 轮）` |
| A-FE-2 | P3 | 对 HTML 文档响应 `Range`，源站回 206 与半截 shell | `internal/webui/webui.go:129` | OPEN | 对 `index.html` 删掉 `Range`/`If-Range` 使其 200-only；`_app/immutable/*` 保留可 Range — 来源：`docs/audit-5/findings/frontend.md:68（第 5 轮）` |
| A-FE-3 | P3 | 同意页显示的 scope 集合 ≠ 服务器授予的 scope 集合（OIDC claim scope 静默补授） | `internal/httpapi/authorization_routes.go:185-201`、`internal/oidchttp/oidchttp.go:1251-1262` | OPEN | 三选一裁定：同意页加一行常驻说明 / `scopeViews` 回显式「未描述」占位 / 给 `NarrowScopes` 加「批准集必须覆盖 displayed」的不变量 — 来源：`docs/audit-5/findings/frontend.md:87（第 5 轮）` |
| A-FE-V1 | P3 | 「显示少于授予」有第二/第三份独立实现（设备流）⇒ 只改一处覆盖不到 | `internal/store/memory/oidc.go:1250,1283-1288`、`internal/store/postgres/oidc.go:1060,1094-1102` | OPEN | 与 A-FE-3 共用同一判据；修 A-FE-3 时必须一并覆盖设备流两后端 — 来源：`docs/audit-5/findings/frontend-VERIFIED.md:297（第 5 轮）` |
| A-FE-4 | P3 | `web/svelte.config.js` 不存在——kit 配置只活在 `vite.config.ts` 里 | `web/vite.config.ts:46-110`（`web/svelte.config.*` 不存在） | OPEN | 在 `web/README.md` 写明「刻意不用 `svelte.config.js`」，或把配置搬回标准位置并让 `webui_test.go` 改读它；加一条「两份 kit 配置即失败」的守卫 — 来源：`docs/audit-5/findings/frontend.md:109（第 5 轮）` |
| A-FE-6 | P3 | `internal/webui` 只对 shell 设文档策略，非 HTML 资源不带 CSP | `internal/webui/webui.go:123-127` | OPEN | 把 `shellCSP` 扩成「任何 `text/html` 响应」，并断言 shell 上存在 `frame-ancestors`（真实组合根已由 `withSecurityHeaders` 兜住，属纵深防御） — 来源：`docs/audit-5/findings/frontend.md:140（第 5 轮）` |
| A-FE-8 | P3 | 未使用的 `web/src/lib/assets/favicon.svg` 仍是 Svelte 官方 logo | `web/src/lib/assets/favicon.svg:1` | OPEN | 删掉该文件或换成真正的品牌标记 — 来源：`docs/audit-5/findings/frontend.md:160（第 5 轮）` |
| A-FE-10 | P3 | 发布产物里有 6 处 `console.warn`，带 `svelte.dev/e/…` 文档链接 | `internal/webui/dist/_app/immutable/chunks/`（构建产物；具体分块名随构建变化） | OPEN | 在 `web/scripts/` 加一条产物 grep 守卫（与 `check-bundle-size.mjs` 同风格）；确认不可达则在守卫里显式豁免并写理由 — 来源：`docs/audit-5/findings/frontend.md:200（第 5 轮）` |
| A-FE-11 | P3 | 仓库根有一个名为 `%SC%` 的空目录（未被展开的 Windows 变量） | `%SC%/`（仓库根，空目录，未被 git 跟踪） | OPEN | 直接删掉；真实风险是同类笔误落在有内容的路径上 — 来源：`docs/audit-5/findings/frontend.md:224（第 5 轮）` |

## 已修复（仅 ID + 一句话，供溯源）

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

## 有意不做 / 已裁定

- FO-02 — 刷新赢得 CAS 后行被删留下的 vault 残留 / 跨实例 refresh 残余竞态：探针在 CAS **输掉**的分支触发，属「已知（非发现）+ 证据不成立」 — 依据：`docs/issues/not-doing.md:53`、`docs/security-audit-5.md:313`、`docs/audit-7/BRIEF.md:108`。
- FO-05 的后半（**数据面刻意不装重试层**）— 绑定刷新是旋转型单次凭据，重试无意义且加剧 churn ⇒ 改文档比加代码正确（待改的只是 `docs/source-onboarding.md:225`）— 依据：`docs/issues/not-doing.md:35`。
- A-FE-7 — 同意页/设备页共用带导航的布局：属**设计裁定**，应按 BRIEF §5 写进「判断」而非 finding — 依据：`docs/audit-5/findings/frontend-VERIFIED.md:29`。
- A-FE-V2 — 缺失的散列资产回 **200 shell** 而非 404：已被钉成性质（连监控/告警假设的后果都写了），不要再作为缺陷上报 — 依据：`docs/security-audit-7.md:302`、`docs/issues/not-doing.md:48`。
- （AUD/第二轮遗留）操作员 `usr_…` 仍进 `admin.*` 审计的 `Detail["actor"]` — 企业审计合规，**有意保留**；残余是该操作员日后抹除自己账号不会解除这些行的关联 — 依据：`docs/security-audit-2.md:42-44`、`docs/security-audit-3.md:286-294`。
- （第三轮判断）未认证的 `/v1/admin/*` 返回 **401 而非 404** — 有意的信息形态，`openapi.yaml` 已文档化 — 依据：`docs/security-audit-3.md:295-296`、`docs/issues/not-doing.md:28`。
- O-9 — 不做 `end_session` / `id_token_hint` / PAR / 动态客户端注册 / OIDC Session Management — 依据：`docs/oidc-decision.md:45`。
- D-3 — v1 不做 DPoP（RFC 9449），只签发普通 Bearer — 依据：`docs/api-design.md:13`、`docs/api-design.md:25`。
- （CORS）协议面不发任何 CORS 头；跨源 SPA 属明确不做 — 依据：`docs/cors-decision.md:32`。
- （密钥）不接 KMS/HSM，KEK 来自环境变量：KMS 买的是可恢复性与可归因，不是预防 — 依据：`docs/threat-model.md:121`、`docs/threat-model.md:136-138`。
- （落盘）vault 的 `Identity`/`Meta` 明文落盘（PII 定性，只写不读）— 依据：`docs/threat-model.md:161-177`。
- （审计）链尾部截断**就地验证挡不住**；改用服务每小时把链头写进日志的锚点，日志不落库外的部署维持较弱保证 — 依据：`docs/architecture.md:634`。
- （审计）迁移 `0014` 之前的审计行**保留原始 `usr_`**，不回填 — 依据：`docs/threat-model.md:255-256`。
- （审计）`auth_time = COALESCE(auth_time, now())` 用数据库时钟 — 第六轮按 P2-32（`bf81b2a`）裁定为 display-only 回退 — 依据：`docs/issues/not-doing.md:34`。
- （运行时）内存模式重启即丢、不承担生产保证 — 依据：`docs/threat-model.md:237-239`、`docs/issues/not-doing.md:22`。
- （数据面）raw 透传逐字转发、不解析 body；源自己返回凭据是源的缺陷 — 依据：`docs/threat-model.md:246-248`。
- （密码学）`server.rate_limit = 0` 会同时撤掉 `user_code`（20⁸ = 34.575 bit）的在线猜测界 — 配置项本身是文档化的，只需把副作用写进文档 — 依据：`docs/audit-5/findings/crypto-keys.md:460-462`。
- （密码学）两层 AAD 缺 `kek`/`payload` 层标签：当前靠密钥隔离，加标签会作废全部存量密文 ⇒ 只能随下一次 KEK 轮换做 — 依据：`docs/audit-5/findings/crypto-keys.md:457-459`。
- （协议）`user_code` 保持 20⁸（8 字符 / 20 符号）：RFC 8628 §6.1 在限流且短寿命下足够 — 依据：`docs/audit-5/findings/crypto-keys.md:463-465`。
