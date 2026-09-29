# 区域 14 复核：Upstream Kit / RP 侧 / TapTap 适配 — 对抗性复核报告

复核对象：`docs/audit-7/findings/Z14-kit-rp-taptap.md`（6 条发现）。
方法：逐条读 `file:line`、亲自重跑被复核者探针（`internal/zzprobe/audit7/z14kitrptaptap/`），
比照第四/五/六轮台账（`docs/audit-5/findings/_fragment_rp.md`、`_fragment_kit.md`、
`protocol-VERIFIED.md`、`docs/security-audit-5.md`、`scratchpad/audit6/`）排除重报，
并新增独立探针 `internal/zzprobe/audit7/z14verify/`（`//go:build audit7`，端口未占用 18402）。

```
go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z14kitrptaptap/...   # 6 FAIL / 6 PASS
go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z14verify/...        # 3 FAIL / 3 PASS
go build ./...   # exit 0
go vet ./...     # exit 0   （另跑 go vet -tags audit7 两个目录，exit 0）
gofmt -l internal/zzprobe/audit7/z14verify/   # 空
```

被复核者探针的**红与理由逐条复现一致**；只有一处元数据错误：报告写「6 红 / 7 绿」，
实测 `-v` 为 **6 红 / 6 绿**（`fakeop_test.go` 是夹具不是 test）。

---

## 逐条裁定

### Z14-1 级联撤销失败烧掉 refresh token ⇒ 重试打不到上游
- **CONFIRMED，P2（维持）**。真进程复现：`cascade #1: 500 (RevokeUpstream calls=1)`、
  `cascade #2: 500 (calls=1)`、`credential still in vault: true`。
- 机制逐行核对无误：`referencesource/cascade.go:52-55` 先 `tokenSubject`，`:80-86`
  用破坏性的 `s.tokens.ConsumeRefresh`，`:59-65` 才调 `RevokeUpstream`；
  `internal/federation/revocation.go:148-155` 失败即 `return`（绑定与凭据保留），
  第二次仍送同一个 refresh token（`preferredToken:67-75`）。
- 文档矛盾属实：`docs/upstream-protocol.md:162` 允许无条件消费，`:165-166` 又承诺可重试；
  `upstreamkit/server.go:85-86` "the binding is removed either way" 在失败路径不成立。
- 「永久不可用」措辞我独立收紧后仍成立：该 refresh token 在**源自己的存储**里已被删除，
  之后 Re0Auth 的 `refreshBinding`（`internal/federation/refresh.go:68-92`）只会拿到
  invalid_grant → `refreshRejected`，不存在「先刷新再级联」的自愈。
- 非重报：全仓 grep `ConsumeRefresh`/`tokenSubject` 在四~六轮台账中无对应条目；
  KIT-1 只覆盖「端点不认证」，机制不同。

### Z14-2 一致性套件对 `/oauth/revoke` 认证零断言（对 KIT-7 的补充）
- **CONFIRMED，P2（维持）**。复现：`unauthenticated /oauth/revoke hits=1; suite findings:`
  仅两条 skipped，零 error；阳性对照 `TestZ14ControlConformanceDetectsAnObviousNonConformance` PASS。
- 机制属实：`conformance.go:253-265` 唯一判据 `StatusCode == 404`；相邻
  `checkCascadeEndpoint:294-313` 送同样的「无凭据 + 未知 client」却要求非 2xx；
  `checkTokenRejectsBadGrant:233-251` 亦然（报告已在正文点出，未重复计一条，恰当）。
- 非重报、且不是误报文档化决定：`docs/audit-5/findings/_fragment_kit.md:299-301`（KIT-7）
  的修法第 1 条**同时点名** `checkRevocationEndpoint` 与 `checkCascadeEndpoint`；
  `b5f01da` 只落了 cascade 一半。这属于 BRIEF §4.4 允许的「修复不全」，报告已显式标注。
- 唯一措辞瑕疵：「相关」行写「KIT-7（round-5，**未修**）」与它自己「修复把这一条只加到了
  cascade」相抵，应为「修了一半」。不影响裁定。

### Z14-3 `jwks_uri` 不与 issuer 绑定（对 RP-3 的补充）
- **CONFIRMED，P2（维持）**。复现：`issuer=...59540 jwks_uri=...59541 discovery=1
  issuer-jwks-hits=0`，伪造 `sub` 被接受；两条对照（同源 keyset 接受、异源密钥在
  `jwks_uri` 未改时被拒）均 PASS ⇒ 接受只来自 `jwks_uri` 被改指向。
- 机制属实：`idp/idp.go:486-509` `pinToIssuer` 只列 authorization/token 两端点；
  `oauthConfig:466-481` 只 pin 这两条；`jwks_uri` 由 go-oidc 原样取用。
- **需要主代理知晓的一点**：修复提交 `60de35d` 的 message 明写「JWKS 没有覆盖旋钮，
  所以只钉这两个端点」——即该缺口**是有意缩小范围**，只是不在 BRIEF §5 的「有意不做」清单里，
  且 RP-5 轮 `_fragment_rp.md:139-141` 的修法建议本来就点名 `jwks_uri`。
  因此我维持 CONFIRMED（这是一条修复不全，不是重报），但把它归为「判断：这个 scope-out 应当收回」，
  严重度按与 RP-3 相同的前提取 P2，不升 P1（前提不是「一次登录 / 公开 client」）。

### Z14-4 provider TTL 被失败的 rediscovery 击穿（对 RP-2 的反驳/补充）
- **CONFIRMED，P2（维持）**。复现：`attempt 1/2/3: ACCEPTED sub="attacker-with-the-retired-key"`，
  恢复 discovery 后同令牌被拒；对照 `TestZ14ControlTheProviderTTLCacheRetiresARotatedKey` PASS。
- 机制属实：`idp/idp.go:622` TTL 判定在前，`:626-631` 失败时返回旧 provider 且
  `discoveredAt` 不前进；go-oidc 的 `RemoteKeySet` 命中即返回、无 TTL。
  「无限期」=「discovery 持续失败期间」，恢复即失效，报告在「未能到达 #2」如实标注了这是逻辑推导。
- 非重报：RP-2 讲的是「无 TTL」，本条讲的是「TTL 有上界以外的旁路」；`60de35d` 只把
  保留旧 provider 当成「抖一下」的可用性理由，未处理持续故障 ⇒ 属修复不全。

### Z14-5 只配 `auth_url` 时显式端点被静默丢弃
- **CONFIRMED，P3（维持）**。复现：`auth_url=.../real-authorize was configured; the browser got
  "/authorize"; discovery calls=1`；对照两设全配 → `/real-authorize`、discovery 0 次。
- 机制与可达性都独立核过：`idp/idp.go:468` 要求两者皆非空，否则 `:479` 整体覆盖；
  `oauthConfig` 对**内置** provider 因 `def.endpoint` 已静态填好而永远走早返回，所以
  半配置只对自定义 OIDC provider 有意义——而 `cmd/re0auth/config.go:854-876` 只强制
  「自定义 provider 必须有 issuer」，**不强制 auth_url/token_url 成对**，故经真实配置可达。
  无跨源后果（`pinToIssuer:502-506` 的报错本身自相矛盾只是提示问题）⇒ P3 恰当。

### Z14-6 参考源 TapTap 登录完成不绑定浏览器（登录 CSRF）
- **CONFIRMED，P3（维持）**。复现：受害浏览器仅 GET poll 即 `confirmed/openid_attacker_z14`；
  同测试内未知 id 对照保持 `anonymous/`；发起者对照 PASS。
- 机制属实：`referencesource/taptap.go:129-136` 把 attempt id 交给发起方（即攻击者）前端，
  `:219-226` 的 poll 无归属校验，`referencesource/source.go:293-304` 的 `establish`
  无条件覆盖调用者会话；`source.go:374` `SameSite=Lax` 经核对无误。
- 跨站那半步未验证（无 Playwright），报告已标「跨站那半步未用浏览器验证」；P3 因
  `referencesource` 不入发布产物，BRIEF §2/`SECURITY.md` 一致，未虚高。
- 非重报：四~六轮台账无 `/login/taptap`、poll、会话固定的条目。

---

## 新发现（独立证据）

### Z14-V1 一致性套件用**目标 origin** 去判**文档广告的端点**：撤销端点被整体忽略，级联端点丢弃 origin
- 严重度：**P3**（可执行规范给出错误裁定；最稳的后果是误杀合规源，另有假 PASS 方向）
- 类别：可维护性 / 合规（生态）
- 不变量：套件必须按 `docs/upstream-protocol.md` §4 所广告的绝对 URL 去验收；§13 又规定
  「通过套件才能登记为兼容源」。
- 证据（探针，3 红 3 绿）：
  ```
  # 红 1：撤销端点被硬编码路径替代，广告的 URL 从未被访问
  advertised revocation endpoint http://127.0.0.1:55444/oauth/revoke-v2 hits=0; /oauth/revoke hits=1
  findings: revoke.present error "revocation endpoint is missing"     # 合规源被误判
  # 红 2：广告的级联端点从不被访问，"开放"端点被判 PASS
  advertised (open) endpoint hits=0; target's decoy path hits=1; findings: 无 error
  # 红 3：广告值不是 URL 也通过
  revocation_endpoint="not-a-url" ⇒ 套件零 error
  # 绿：同 origin 不同路径的级联端点确实被使用（RequestURI 保留 path）⇒ 只有 origin 被丢
  ```
- 机制：
  - `conformance.go:255` `checkRevocationEndpoint` POST 到字面量 `"/oauth/revoke"`，
    `r.request` 再做 `r.base + path`（`:116-129`）；**从不读 `disc.OAuth.RevocationEndpoint`**。
  - `conformance.go:288-296` `checkCascadeEndpoint` 先断言广告端点 `IsAbs()`（允许跨 origin），
    随后只取 `parsed.RequestURI()`（path+query）再拼 `r.base` ⇒ 广告的 **origin 被丢弃**。
  - `checkDiscovery:171` 只要求该字段非空（cascade 有绝对性断言，revoke 连 URL 都不校验），
    因此 `"not-a-url"` 入档；而 `internal/federation/revocation.go:153` 会把原字符串交给
    `http.NewRequestWithContext`（"unsupported protocol scheme"）。
  - 套件文档自己说它要抓「不用 kit、照规范手写」的源（`:278-281`），而 kit 恒广告
    `{issuer}/oauth/cascade_revocation`（`upstreamkit/server.go:120-124`）⇒ 只有手写源会撞上，
    恰好是它承诺覆盖的那一类。
- 影响：合规的多主机数据源被 `cascade.present`/`revoke.present` 误判为不合规；
  反向可让「广告在别处、实际谁都能结束全会话」的级联端点零 error 通过——Re0Auth 恰恰只打
  广告的那个 URL（`federation/revocation.go:153`）。
- 探针：`internal/zzprobe/audit7/z14verify/endpoint_test.go::
  TestZ14VRevocationEndpointOnAnotherPathIsReportedMissing`（红）、
  `::TestZ14VTheAdvertisedCascadeEndpointIsNeverContacted`（红）、
  `::TestZ14VGarbageAdvertisedRevocationEndpointIsAccepted`（红）；
  对照 `::TestZ14VControlTheSuiteProbesTheAdvertisedTargetPath`、
  `::TestZ14VControlTheAdvertisedCascadePathIsHonoured`（绿）。
- 修法：`checkRevocationEndpoint` 改收 `disc` 并使用 `disc.OAuth.RevocationEndpoint`（解析失败即
  `revoke.absolute` error），`checkCascadeEndpoint` 直接对绝对 URL 发请求（或显式要求
  endpoint 与 target 同 origin 并在文档里写明——那是另一条裁定）。
- 相关：与 Z14-2 同属「套件假裁定」，但根因不同（Z14-2 是缺断言，本条是打错 URL），不重复计。

---

## 「探过没破」的夹具/桩审查

| 守卫 | 证据等级 | 复核结论 |
|---|---|---|
| 1 RP nonce/azp（`idp/idp.go:579-594`） | 读码 | 行号与逻辑一致；无本次探针，未翻案 |
| 2 `safeurl.RelativePath` | 读码 | 未复跑，未翻案 |
| 3 kit 的 `/oauth/cascade_revocation` 先认证 | **本次实测** | 独立探针确认：匿名 POST→401 且 hook 调用 **0** 次；注册客户端→200 且 hook **1** 次。真 kit + 真 `oauth.Service`，无桩 |
| 4 kit authorize PKCE/redirect/Exchange | 读码 | 与 `oauth/as.go:101-116,160-183` 一致（`Exchange` 先认证客户端再消费 code，未见 code 燃烧 DoS） |
| 5 `taptapoauth` MAC 与 `boundDetail` | 读码 | `client.go:252-277`、`:337-343` 与报告一致；MAC 是否与真实 TapTap 相符**无法离线证伪**，属残余盲区 |
| 6 `tapsign` 不泄露凭据 | 读码 | `client.go:124-126`、`:197-211` 属实；另 `httpclient.NoCrossHostRedirects` 已挂在该客户端上（`cmd/referencesource/main.go:145,174`），跨站重定向泄露形状已封 |
| 7 「套件是活的，无假 PASS 面」 | **被本次探针部分推翻** | `checkDiscovery/checkOAuthMetadata` 自洽，但 `checkRevocationEndpoint/checkCascadeEndpoint` 存在 Z14-V1 的假 PASS/误杀面；该守卫表述过强 |

桩检查：被复核者的红探针没有用「永远返回固定值」的假 OP 掩盖真路径——`fakeop_test.go` 是
**可控** OP（文档/JWKS/状态都要翻转），且每条红都配了会变的对照；`cascade_test.go` 用真
`upstreamkit.Server` + 真 `referencesource.Source` + 真 HTTP，非桩。未发现夹具造成的假绿。

---

## 未能到达（残余盲区）

1. 真实 Postgres/容器：本区无依赖，未受影响（Z14 全部形态均在内存/httptest 可达）。
2. Z14-4 的「跨越 15 分钟默认 TTL」未用真实时钟跑；探针用 `time.Nanosecond` + 状态翻转，
   等价性成立但不等于真实时钟。
3. Z14-6 的跨站顶层导航（Lax cookie 真实携带）未构造，无 Playwright。
4. 真实 TapTap/Microsoft 端点未联网打；`taptapoauth` MAC 拼装正确性无法离线证实。
5. 一致性套件 data 面（`Options.AccessToken`）未单列；本轮新发现不涉及该面。

## 判断（不是 finding）

1. Z14-3 的 scope-out（`60de35d`：没有 jwks_uri 覆盖旋钮所以不 pin）我认同**动机**，
   但「加一个与 auth_url/token_url 同语义的显式开关」成本很低，建议本轮收回该决定；
   在此之前它必须被当成已知缺口，而不是已修。
2. Z14-4 的「保留旧 provider」动机正确，缺的只是硬上界（如 `2×TTL` 后 fail-closed）；
   这是「保留」与「无限期信任」的区分问题，不是要不要保留的问题。
3. Z14-2/Z14-V1 表明套件当前的验收面比 `docs/upstream-protocol.md` §13 承诺的窄且位置不准；
   在「通过套件才能登记」的流程下，这两条应在登记前修，而不是当提示。
