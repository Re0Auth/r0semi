# Re0Auth 第 5 轮对抗审计（上线前）——汇总

**性质**：report-only（未改任何生产代码）。**环境**：Windows 11、Go 1.27.1、无 Docker/无本地 Postgres。
`gofmt`/`go vet`/`go test ./...` 全绿；`internal/store/postgres` 测试全部 SKIP。被审计对象是**含未提交改动的工作树**。
**方法**：不变量清单（①令牌/scope ②账号隔离 ③平面/⑥fail-closed ④撤销 ⑤凭据）+ 性能/资源 + 配置/供应链 + 前端；
「先有一条会失败的测试」收口。**每条都注明 CONFIRMED（实跑/行级）还是 HYPOTHESIS（假说）**。

---

## A. 最高优先级（建议上线前处理）

### R5-1【高】参数名**大小写变体键**绕过 `device_authorization` 的客户端 scope 闸门
- 性质 ①。客户端 `cli` 只注册 `account.id`：
  - 控制 `scope=phigros.score.read` → **400 invalid_scope**（正确）
  - 攻击 `client_id=cli&scope=account.id&Scope=phigros.score.read` → **200 + device_code**；60/60 接受，**52/60** 存下未注册 scope（经 `/v1/device/verification` 读出）
- 根因：包装层预检用大小写**精确**的 `Values.Get`（`internal/oidchttp/oidchttp.go:849,872`）；zitadel 解码器**大小写不敏感**
  （`zitadel/schema@v1.3.2/cache.go:217`）且**取最后一个同名键**（`decoder.go:427-431`，`SpaceDelimitedArray.UnmarshalText` 整体替换）；
  `duplicatedParam`（`oidchttp.go:1003`）只按完全相同键计数。同样适用于 `client_id`/Basic 一致性检查。
- 状态 CONFIRMED。修法：预检读「解码后视图」，`duplicatedParam` 把折叠同名键视为重复。

### R5-13【高】**body 不可解析**时，重复参数拒绝被关掉 → 设备流/授权码流拿到未注册 scope
- 性质 ①③。`requestParams`（`oidchttp.go:723`）`ParseForm` 出错即返回**空表**，而 `net/http` 的 `ParseForm`
  **先**填 `r.Form`（含 query）、**再**返回 body 错误且幂等：**第一次**调用（`duplicatedParam`，`:440`）看空集→通过，
  后续调用不再报错→看到真实参数。实测（**FAIL**）：
  `POST /oauth/device_authorization?...&scope=account.id&scope=phigros.score.read` + `x=%zz` body → `200`，
  **存下并铸出携带 `phigros.score.read` 的活令牌**；body 良好 → `400`（对照）。authorize 同形。
- 状态 CONFIRMED。→「预检所见」与「库所用」是两个视图（与 R5-1 同源）。

### R5-14【高】**每个 `id_token` 都缺 `sub`**（OIDC 必需 claim）
- 性质 ①。库 `CreateIDToken`（`zitadel/oidc@v3.51.3/pkg/op/token.go:241-253`）先 `SetUserinfoFromScopes` 再
  `claims.SetUserInfo(userInfo)`，而 `SetUserInfo`（`pkg/oidc/token.go:159`）`t.Subject = i.Subject`（**赋值**）；
  两个 store 的 `SetUserinfoFromScopes` 都是**空实现**（`internal/store/memory/oidc.go:685`、`.../postgres/oidc.go:577`）
  → `sub` 被覆盖成空串。`SetUserinfoFromToken`（走 userinfo）却正确——两路实现互相矛盾。实测（**FAIL**）：
  userinfo `sub=usr_probe`，`id_token` 无 `sub`（code 与 refresh 皆然）。
- 状态 CONFIRMED。修法（两行）：`SetUserinfoFromScopes` 里 `userinfo.Subject = subject`。

### R5-6【高｜性能】`max_in_flight=512` × 单请求 4 MiB 上游缓冲 ≫ 512Mi 上限 → 可 **OOMKill**
- 证据：`internal/federation/service.go:23` `maxBody=4<<20`、`:517/:545` `io.ReadAll` 整段入堆；
  `deploy/k8s/base/configmap.yaml` `max_in_flight=512`；`deployment.yaml` `limits.memory=512Mi`；
  出站 bulkhead `cmd/re0auth/main.go:75 =256`；内存模式默认 `config.go:305 =512`。
  最坏 `min(512,256)×4MiB≈1GiB`。状态 CONFIRMED（算术；真机压测=HYPOTHESIS）。
- 修法：调低 `max_in_flight`，或对数据面大响应**流式转发**，并在 `docs/capacity-planning.md` 写明最坏界。

---

## B. 中危（契约/纵深，建议排期）

- **R5-2 协议面 405 不带 `Allow`**（与同提交里业务面的「对等」声明矛盾；RFC 9110 §15.5.6）。实测 `GET /oauth/token` → 405 `Allow=""`。CONFIRMED。
- **R5-3 `recoverBrowser` 在平面内路径上回 `text/plain` 500**（`middleware.go:545-555` 不看 `planeOf`），实测 `/v1/me`、`/oauth/token`、`/auth/*` 均纯文本 500。CONFIRMED（形状）。
- **R5-4 非规范路径的 307 是 `text/html`**，而 `planeOf` 判其为业务/协议平面（`//v1/me`、`/v1//me`、`//oauth/token`）。CONFIRMED（会污染指标/日志/限流桶）。
- **R5-5 `/.well-known/*` 两份文档不受动词矩阵约束**：任意方法（POST/PUT/…）回 `200 application/json`，与未提交 `CHANGELOG.md` 的承诺冲突。CONFIRMED。
- **R5-7 限流器在容量处驱逐**存活**桶 → 键喷洒可重置预算**：`ratelimit.go:213-235` fallback 删第一个扫描到的桶（可活）；实测受害者 429 后，同 shard 700 键喷洒 → 受害者 401。CONFIRMED。k8s 基线信任 `10.0.0.0/8`（可自选 XFF）时尤甚。
- **R5-9 `oauth`（公开库）设备码非单次使用、撤销后可再铸**（`oauth/device.go:269-309` 无消费位；实测同码两次得不同令牌对，`RevokeTokens` 后仍活）。CONFIRMED。
- **R5-15 `introspection_clients` 含 public client ⇒ 匿名读任意令牌**（`SetUserinfoFromScopes` 无关；此处是 `AuthorizeClientIDSecret` 对 public 恒成功 + 库以 nil=已认证）：`Basic base64(<public id>:garbage)` → `active=true` 含 scope/sub。CONFIRMED（无 allowlist 时 `active=false` 对照成立）。
- **R5-16 发现文档宣称 introspection 支持 `client_secret_post`，实测 401**。CONFIRMED。
- **R5-17 `id_token` 可当访问令牌用于 `/oauth/userinfo`**（令牌类型混淆，且不可撤销）。CONFIRMED（今天仅因 R5-14 抹掉 `sub` 才回 `{}`）。

---

## C. 低危 / 提示

- **R5-8** `httpclient.IsPublicAddress` 接受 `0.1.2.3`（`0/8`）、`192.88.99.1`（6to4 relay）。CONFIRMED（谓词枚举）。
- **R5-10** 公开库 `oauth.Refresh` 在校验归属前就消费 refresh（`oauth/as.go:192` 先于 `:202`）；实测**他方客户端可把持有者的 refresh 一次性烧掉**。CONFIRMED。
- **R5-11** BREACH 守卫缺口：`/v1/device/verification` 同体返回 `csrf_token` 与调用者回显的 `user_code`，而 `breach_test.go` 只注入 `breach_canary`；`POST /v1/admin/clients`（一次性 secret + 调用者文本）也不在扫描范围。CONFIRMED（读码）。
- **R5-12** `handleDeviceDecision` 的 `OwnerMatches` **无测试钉住**（实现正确；删掉不变红）。CONFIRMED（缺口）。
- **R5-18** `response_mode=form_post` 的授权响应不带 `iss`，发现文档却宣称支持（RFC 9207）；另 `response_modes_supported` 完全未广告。CONFIRMED。
- **R5-19**（HYPOTHESIS）`prompt=none` 被静默忽略。

---

## D. HYPOTHESIS / 判断（非 defect）

- **H-1** 数据源孤岛绑定：用户侧记 `nothing`，运维侧记 `orphaned`；`docs/openapi.yaml:297` 对 `nothing` 的释义「没有凭据可撤销」在孤岛路径上是假陈述（密文刚被撕）。已在未提交 `CHANGELOG` 记为**有意决定**。
- **H-2/H-3** 全部 Postgres 路径（撤销/绑定 CAS/审计假名化/哈希链/`auditread.go` 的 `id DESC` 与 `occurred_at DESC` 索引不匹配）**读到行**，需 Linux+PG CI 用集成测试/`EXPLAIN` 收口。
- **H-4** 若前端 device 页「加载即自动提交 decision」，R5-3 的 `GET /v1/device/verification`（无 CSRF、可写会话）将升级为同意绕过；需读 `web/src/routes/device`。
- **判断**（文档化决定，非缺陷）：不做 DPoP/PAR/`end_session`/动态注册/Session Management/CORS、无 KMS、内存重启即丢、`/v1/admin/*` 未认证 401、raw 逐字转发。

---

## E. 性能实测（内存存储上界）

`internal/httpapi` 业务面 `BenchmarkBusinessPlaneBearerMe` 19.8k ns / 180 allocs；协议 introspect 35.3k ns / 269 allocs；
`internal/ratelimit` 热键 120 ns / 0 allocs，满容量新键 ~1.1–1.3 µs；`internal/store/memory` introspect 157 ns；
`TestLoadProfile` 8 worker ≈ **17.4k req/s**（Windows 单调钟 ~1 ms，p50/p95 被量化）。
Postgres 模式每请求 ≥1 往返（introspect）+ 会话读 + 数据面绑定/vault/审计链写，需真库压测。

---

## F. 探过但没破（值得变成守卫）

- 三平面 405/404/429/413/503 形状；`planeOf` 单一判定；压缩器复用该判定；`isProbe` 精确匹配。
- `specRoutes` ↔ `openapi.yaml` 双向相等；方法派发只在已注册路径收窄动词。
- 中间件顺序：安全头在压缩之外、体限在处理器之外、in-flight 在限流之外；业务面 `withNoStore` 平面级 `no-store`。
- 三个 kind 句柄消费点均双检 `Bound`+`OwnerMatches`，404 无存在性预言机；`sub` 恒来自会话。
- 授权码单次使用/绑定 client+redirect+verifier+subject；refresh 不提权（含 json-ish/comma/`scope[]` 等拼写，wrapper 拒重复参数）；client 认证（无/错 secret → 401）。
- 上传响应有界（`tapsign`/`taptapoauth`/`conformance` 1 MiB；`federation` 4 MiB 且超限报错）；出站 `NoCrossHostRedirects` + 拨号层 `DenyPrivateAddresses` + bulkhead 覆盖整段 body + 只重试幂等。
- **raw 路径不能改 host**（26 种遍历/绝对 URL/`//`/`\`/`%2f` 拼法实测，rig 只收到 `GET /v1...`；见 `zzprobe/federation/raw_test.go`）。
- 后台循环都启动并被 join；内存存储有界（限流器/LRU 审计环/假名缓存/句柄上限 32/kind）；无入站解压。
- 前端无 `{@html}`/`innerHTML`；`script-src` 无 `unsafe-inline`；`frame-ancestors` 在头；CSRF 头-only 常数时间；`return_to` 经 `safeurl`。
- 配置：issuer/三把 OP 密钥/KEK（32B 含 hex）/审计 key fail-closed；未知 TOML 键直接拒；`-rotate-keys` 不触碰载荷。
- 供应链：`govulncheck` → 无洞；`gitleaks` 全历史零命中；actions 按 SHA、镜像按 digest、Trivy 阻断、cosign；k8s 有 NetworkPolicy/非 root/read-only/PDB。

## G. 残余盲区

全部 Postgres 路径（无 DSN）；`-race`（Windows 无 cgo）；容器/registry（无 Docker）；真实浏览器渲染；`web/` 前端与 device 页。

## H. 复核

本轮由主代理亲自复核 R5-13/14/15/16/17/18 与 R5-1/6/7：读过 `pkg/op/token.go`、`pkg/oidc/token.go`、
`zitadel/schema` 的 `decoder.go`/`cache.go`、两个 store 的 `AuthorizeClientIDSecret`/`SetUserinfoFromScopes`
并**实跑**了对应探针，结论非转述。
