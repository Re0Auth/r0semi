# Re0Auth 上线前问题清单

> **来源**：第五轮审计（12 个区域审计 + 12 个对抗性复核）。
> 汇总报告见 [`docs/security-audit-5.md`](docs/security-audit-5.md)，
> 逐条证据与原始探针见 `docs/audit-5/findings/`。
>
> **状态口径**：本项目规矩是「一条发现必须有一条会失败的测试才算数」。
> 表中 **V=已复核** 表示已由独立复核代理复核（复核者被要求**证伪**）；
> **D=复核降级**、**R=复核推翻** 表示原区域报告的严重度**不成立**，以本表为准。
> **位置** 里的行号是审计当时的快照。
>
> **怎么跑证据**：
> ```sh
> go build ./... && go vet ./... && go test ./...        # 33 个包全绿（探针已被标签排除）
> go test -race -p 1 ./...                               # 全绿，无 DATA RACE
> go test -tags audit5 -count=1 ./internal/zzprobe/...   # 红 —— 这就是证据
> ```

**统计**：P0 阻断 6 · P1 高 5 · P2 中 33 · P3 低/提示 30+ · 复核更正 12 · 探过没破 200+。
**125 条待办中，只有 6 条真正挡住上线。**

---

## 目录

- [P0 阻断上线（6 条）](#p0-阻断上线6-条)
- [P1 高（5 条）](#p1-高5-条)
- [P2 中（33 条）](#p2-中33-条)
- [P3 低 / 提示](#p3-低--提示)
- [复核更正：不要按原始报告读的 12 条](#复核更正不要按原始报告读的-12-条)
- [探过但没破（安全姿态）](#探过但没破安全姿态)
- [未能到达（残余盲区）](#未能到达残余盲区)
- [判断：值得重新裁定的文档化决定](#判断值得重新裁定的文档化决定)
- [执行顺序建议](#执行顺序建议)
- [附录：探针文件与流程说明](#附录探针文件与流程说明)

---

## P0 阻断上线（6 条）

### P0-1 `id_token` 缺少必需的 `sub` 声明

- **问题**：授权码兑换与刷新**两条**签发路径的 `id_token` 都没有 `sub`；而 `userinfo` 有。
  OIDC Core §2 要求 `sub` 必需 ⇒ 严格的 RP 拒收，宽松的 RP 若拿 `id_token.sub` 当用户主键
  会把**所有用户归并到同一个空身份**。
- **根因**：库的 `claims.SetUserInfo(userInfo)` 用空 subject 覆盖了刚设好的值，
  因为两个 store 的 `SetUserinfoFromScopes` 是空实现，注释还写着「deprecated upstream; no-op」——
  **那条注释是错的**，该回调在 `zitadel/oidc v3.51.3` 的签发路径上正被调用。
- **位置**：`internal/store/memory/oidc.go:685-687`、`internal/store/postgres/oidc.go:577-581`
- **修法**：两处各加 `userinfo.Subject = subject; return nil`（只写 `sub`，与 O-3 一致）。
- **守卫**：断言 `id_token.sub` **等于**已登录的 `usr_…`（不是「key 存在」，那会空转）。
- **附带**：`discovery` 的 `claims_supported: ["sub"]` 只广告这一个声明，而它就是唯一没发出的那个。
- **状态**：V（我与复核各自独立复现并逐行核对机制）
- **证据**：`internal/zzprobe/protocol/idtokens_test.go::TestProbeIDTokenIsMissingTheSubjectClaim`

### P0-2 `id_token` 可在 `/oauth/userinfo` 当访问令牌用；且该端点不检查令牌是否活着

- **问题**：① 库在解密失败后**回退**到 JWT 验签，而 `pkg/oidc/verifier.go:110-112` 的
  `DecryptToken` 是 `return tokenString, nil // TODO: impl` ⇒ **本 OP 签的 `id_token` 被当作 bearer 接受**。
  ② `/oauth/userinfo` 对**已撤销/已过期**的 access token 照样返回 `sub`（业务面已 401）。
- **⚠️ 排序约束**：**①今天只回 `200 {}`，纯粹因为 P0-1 把 `sub` 抹空了。P0-1 一修好，
  这个洞当场显形为一个可用的身份 bearer。两条必须同批落地，否则修 P0-1 等于开新洞。**
- **位置**：`internal/store/memory/oidc.go:691-694`（`SetUserinfoFromToken` 不看 tokenID）
- **修法**：在 `internal/oidchttp` 的 userinfo 前置检查里拒绝三段式 JWT 形状的 bearer；
  `SetUserinfoFromToken` 校验 `tokenID` 非空且命中存储（一次查表，同时挡住 JWT 回落）。
  **不要等上游修 `DecryptToken`。**
- **状态**：V（读码确证 + 与 P0-1 的交互已证）
- **归因**：根在依赖库；本项目能在边界上以极小代价关掉。应作为**判断**记入 `docs/dependencies.md`。

### P0-3 数据面「在途请求数 × 响应体」没有联合上限 → OOMKill

- **问题**：raw 透传把整个上游响应体读进内存（`io.ReadAll`，`internal/federation/service.go:517`），
  实测 **5.80 MB/请求**且呈**线性**（n=1…32 边际 5.79–5.81 MB，无固定项；
  `FreeOSMemory` 只差 32 B/req ⇒ 不是未清扫垃圾）。
  出厂 `max_in_flight = 512` ⇒ **512 × 5.80 MiB = 2834 MiB ≈ 5.5 × 512Mi 的 limit**。
  且全仓**没有 `GOMEMLIMIT`** ⇒ 没有软着陆，直接 OOMKill。
- **位置**：`deploy/k8s/base/configmap.yaml:24`、`config/re0auth.example.toml:46`
- **前提**：需要配置 `[[sources]]` 才有数据面 ⇒ **裸基线不触发**，但任何真正在用的部署都会配。
- **修法**：给「在途 × body 上限」一个联合预算（bulkhead 按**字节**而不是按请求数），
  或对 raw 设响应体上限；重标 `max_in_flight` 使其与内存 limit 挂钩；设 `GOMEMLIMIT`。
- **状态**：V（复核证明归因成立，并把数字从原报告的 708 MiB 修正为 **2834 MiB**——**比原报告更严重**）

### P0-4 限流分桶键归调用方，且桶满时淘汰活桶 → 限流可被完全绕过

- **问题**：`trusted_proxies` 已配置时，分桶键取自 `X-Forwarded-For` 的解析结果，而该值可被调用方决定。
  **判据是「追加的那一跳是否也在信任网内」**（不是「追加 vs 覆盖」）：
  - `trusted_proxies = []`（默认）→ **安全**（实测伪造 XFF 不可换桶）
  - 逐字转发客户端 XFF → **不安全**（**nginx 默认只重定义 `Host`/`Connection`，其余头逐字转发**）
  - 追加真实客户端地址 → 安全
  - 追加的那一跳本身在信任网内（k8s SNAT / 服务网格）→ **不安全**
  叠加第二半：桶上限处 `evictLocked` 淘汰**活跃**桶、新桶以满 burst 创建
  ⇒ 一个可控键空间 = 每次请求都是免费的全新配额。
- **影响**：限流是这些昂贵端点上**唯一**的节流手段（`/oauth/token`、`/oauth/device_authorization`、
  `/oauth/introspect`、`/oauth/authorize`、raw 上游代理、`/v1/account/export`、`/v1/admin/*`）；
  同时**访问日志的 `client=` 与审计归因可被伪造**。
  实测：`rate=0.001/s`（一千秒一个令牌）下 **20000 个不同 XFF → 20000 次放行、0 次拒绝**。
- **位置**：`internal/httpapi/middleware.go:349`（键）、`internal/httpapi/clientaddr.go:23-36`、
  `internal/ratelimit/ratelimit.go:213-234`（淘汰）
- **修法**：① 分桶键不含调用方写的值——不可信时退回对端地址；② 只取**最右侧**由最近代理写入的一条
  （或引入 `server.client_addr_header`，默认 `none`）；③ 桶满时 **fail-closed**（新键共用一个兜底桶），
  **绝不删活桶**；④ 文档写明「反代必须**覆盖**而不是转发 XFF」。
- **状态**：V（复核维持「高」，但改写前提；默认姿态由我与复核各自实测确认为安全）

### P0-5 不可解析的 body 关掉「重复参数」检查 → 设备流 scope 闸门被绕过

- **问题**：只注册 `account.id` 的**公开**客户端发一条 body 不可解析的请求
  （`Content-Type: x-www-form-urlencoded` + body `x=%zz`），参数走查询串
  `?client_id=…&scope=account.id&scope=phigros.score.read`，即可：
  1. `requestParams` 第一次调用吞掉整个参数集（`ParseForm` 返回错误 ⇒ 返回空表）
     ⇒ 重复参数检查静默通过（而第二次调用 `ParseForm` 返回 nil，读到真实参数）；
  2. 闸门用 `form.Get("scope")` 只看**第一个**值（`account.id`，已注册），
     而库的解码器取**最后一个**（`phigros.score.read`）并原样入库。
- **结果**：**拿到 `scope=phigros.score.read` 的活 access token**，可直读该受害者的游戏数据。
  这是第二轮 A1-1 的收益，而它的修复被绕过了。
- **位置**：`internal/oidchttp/oidchttp.go:723-731`（`requestParams`）、`:872`（`form.Get`）、`:810`
- **修法**：① `requestParams` 解析失败即整个请求 400（根因，且消除「同一函数在不同调用点看到不同参数」）；
  ② 闸门/白名单类检查必须针对**全部**值，或拒绝任何多值。
- **状态**：V（**我亲自执行复现**：`the minted token's scope is "phigros.score.read"`）
- **证据**：`internal/zzprobe/protocol/dupbypass_test.go`

### P0-6 内省白名单里只要有一个公开客户端，任何人无需凭据就能读任意 token

- **问题**：`POST /oauth/introspect` + `Authorization: Basic base64("<公开client_id>:")`
  （**空 secret 也行**）即可读到**任意** token 的 `active/scope/sub/client_id/exp`。
  机制：三个 store 对非机密客户端直接 `return nil`，而库把 nil 当作「已认证」⇒
  「认证」退化为「这个 id 存在且是公开客户端」；白名单命中后 `filterIntrospection` 放行跨客户端结果。
- **影响**：公开客户端的 id 本来就印在客户端二进制与授权请求 URL 里；
  配置里一旦出现一个公开客户端 id，**任何能访问内省端点的匿名者**即可读走
  「谁在用哪些 scope、属于哪个 `usr_`」——跨客户端信息泄露。
- **位置**：`internal/store/memory/oidc.go:670-682`、`internal/store/postgres/oidc.go:562-574`、
  `internal/oidchttp/oidchttp.go:900-905,919-945`
- **修法**：白名单只接受**机密**客户端（配置层过滤或 `filterIntrospection` 要求已认证的机密客户端），
  并把这条要求写进 `Config.IntrospectionClients` 注释、配置样例与 `docs/api-design.md`。
- **状态**：V（**我亲自执行复现**：`active=true scope=… sub=usr_probe`）
- **证据**：`internal/zzprobe/protocol/seam_test.go`

---

## P1 高（5 条）

### P1-1 轮转之后落地的写入停在退役 KEK 上，删掉 `retired` 即永久不可读而命令报成功

- **问题**：文档的三步是「先轮换 → 删 `vault.retired` → 重启」。若旋转**之后**
  （或旋转游标已越过该 identity 之后）仍有按旧键配置服务的进程写入一条凭据，
  那条就留在 `kek-1` 上；紧接着删掉退役键 ⇒ **永久不可读**，
  而 `-rotate-keys` 打印 `{Scanned:1 Rewrapped:1}` 并 **exit 0**，全程无错。
  `replicas: 2` + 滚动更新让「还有旧键进程在服务」成为**常态**；**不需要窄窗口、不需要同一行**。
- **位置**：`vault/rotate.go:91-137`、`README.md:55`、`config/re0auth.example.toml:167-168`
- **修法**：① 重封装改**窄写 + CAS**；② `-rotate-keys` 结束时**无条件**告警
  （`already_current + rewrapped != scanned` 时）；③ README/配置样例的三步补上运维文档里已有、
  却不在三步里的那道闸门：**「确认 `Rewrapped == 0`」**与「不要在仍有旧键进程服务时执行」。
- **状态**：V（**复核新发现**，比原报告的 k2 更严重、触发面更大；机制与「重跑收敛」都已实测）
- **证据**：`internal/zzprobe/verifycrypto/verify_crypto_test.go::TestVerifyWriteAfterRotationLeavesARowOnTheRetiredKey`

### P1-2 `-rotate-keys` 用整条 stale 记录覆盖，静默回滚并发入册的凭据

- **问题**：`rotate.go` 把**整条读到的记录**（含 `Nonce`/`Ciphertext`/`Meta`/`CreatedAt`）写回，
  而 Postgres 适配器的 `ON CONFLICT DO UPDATE` **无条件覆盖全部列**。
  窗口是「读完一页到写完该页」（Postgres 路径 `rotatePageSize = 200`）。
  命中后**静默回滚**成旧值：用户刚写入的新凭据消失，而命令报成功、审计写 `ok`、退出码 0。
  对 federation 来说，丢的是赢家刚写进 vault 的上游 refresh token ⇒ 需要重新绑定。
- **位置**：`vault/rotate.go:91-137`、`internal/store/postgres/vault.go:80-94`
- **修法**：同 P1-1 ①（窄写或 CAS）。**注意**：`Repo.Put` 的契约确实是「整条替换」，
  所以这是 `rotate.go` 的 lost update，不是 repo 违约。
- **状态**：V（**复核推翻了原报告的机制**：那行**仍然可读**（读到旧值），
  不是原报告写的「AES-GCM 拒绝/永久不可读」；但**静默**比报错更糟，故仅小幅降级）
- **证据**：`internal/zzprobe/crypto/rotate_lifecycle_test.go`

### P1-3 数据面单请求最坏 80 s，而 `WriteTimeout` 只有 60 s；熔断不兜底

- **问题**：候选源循环 × 20 s 出站 + 刷新 20 s + 401 后强制刷新重取 ⇒ 最坏远超 60 s 写超时
  ⇒ 客户端拿到**断连/半截 body，且没有错误体**。
  复核**实测**：一个 raw 请求真的 4 次**串行**出站（token→resource→token→resource，484 ms ≈ 4×121 ms）。
  且 **401 是 4xx，`circuitbreaker.go:76-78` 明文不计入失败 ⇒ 熔断器不会兜住它**
  （比原报告说的更严重）。`max_in_flight` 限的是**数量**，不是**时长**。
- **位置**：`internal/federation/service.go`（候选循环）、`internal/httpclient/circuitbreaker.go:76-78`
- **修法**：让总超时大于「候选源数 × 出站期限」的最坏值，或给数据面单独的写超时；
  把 401 纳入熔断的失败判据。
- **状态**：V（复核实测 + 行级算术）

### P1-4 `/readyz` 同时免限流与免并发上限，且每请求一次数据库往返

- **问题**：实测桶空时 8 连击全部 200；`max_in_flight = 1` 被占满时 32 并发 `/readyz`
  **全部进入探测**（`isProbe` 在限流器与并发上限**之前**判断）。
  每请求取一条池连接（`pgxpool.Ping`）⇒ 匿名可把连接池打满。
- **位置**：`internal/httpapi/middleware.go` 的 `isProbe` 两处调用点、`internal/httpapi/health.go`
- **修法**：给探针单独的小配额（或在池满时返回上一次的结果而不是发起新往返）。
  **⚠️ 直接「满了回 503」会重新引入 `health.go:69-77` 明确要避免的失败形态** ⇒ 这是**裁定**，
  需要把取舍写进 `docs/operations.md`。
- **状态**：V（复核降为**中高**并收窄：「几百并发占满池」只在 DB 往返 ≳1 ms 时成立，
  同机健康库要 ~10⁴ req/s）

### P1-5 归一化资源的 scope 闸门与数据来源不一致

- **问题**：`ResourceScope(game, resource)` 按**名字顺序**返回「第一个声明该资源的源」的 scope，
  而真正被读的源由**绑定 + 状态排序**决定（`candidates()`）——两者毫无关系。
  实测：持 `phigros.profile.read`（官方源声明的 scope，也是该 client **唯一**注册的 scope），
  用户只绑定社区源，`GET /v1/games/phigros/profile` 返回社区源的数据；
  `?source=` 钉源**也不改判据**。
- **真正的修复理由**：同一道闸门**两个方向都判错**——放行他源数据，
  同时**拒绝该源自己声明的 scope**。
- **位置**：`internal/httpapi/federation_routes.go:89` vs `internal/federation/service.go:206-213,305-335`
- **修法**：让判据与 `Fetch` 实际选中的源一致（`result.Source` 参与判定），
  或要求令牌持有全部候选源的 scope。这是**独立裁定**。
- **状态**：V（复核降为**中**：读的是受害者**自己绑定**的源上**自己**的数据，
  且 `Re0Auth-Source` 是上游协议 MUST）
- **证据**：`internal/zzprobe/federationhttp/scopegate_test.go`（**我亲自执行复现**）

---

## P2 中（33 条）

| ID | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|
| **P2-1** | OP 存储层 `_ = s.audit.Record(...)` **静默吞掉审计失败**：令牌签发/设备批准照做，记录丢失，无错误无日志（vault 是 fail-closed、admin/auth 会打日志，OP 两个方向都没选） | 两个 store 的 OP 路径 | V | 至少记日志 + 计数指标；按 `audit/audit.go:35-39` 的契约决定方向 |
| **P2-2** | 抹除**最后一步**（销毁假名密钥）失败后**不可重试**：账号行与会话都已清，而 500 仍说「可以再试一次」；复核补充范围应扩到**倒数第二步** `record`（其注释自称可重试也是错的） | `internal/lifecycle/lifecycle.go:246-263`、`internal/httpapi/account_routes.go` | V | 把可重试性做成真的（幂等重建会话/保留最小重试凭据），或改承诺 |
| **P2-3** | **`SignOut` 在假名密钥销毁之后**写一条带原始 `usr_…` 的 `auth.logout` 审计行，同一 sink 会**重新铸一把假名密钥** ⇒ `docs/admin.md:130` 的「销毁后过滤返回空页」承诺不成立，**每次成功的持久化抹除都发生** | `internal/httpapi/account_routes.go:68`、`internal/auth/auth.go:202` | V（**两个复核独立命中**，确定性非竞态） | 该事件不要携带原始 subject（用 `lifecycle` 的形状化做法），或抹除后不再写这条 |
| **P2-4** | **四条仍在生产调用的批量撤销谓词没有前导索引**（`oauth_codes.client_id` + 三张 legacy token 表的 `client_id`）；复核**推翻**了 `architecture.md:757`「无生产调用者」 | migrations、`internal/admin/admin.go:242/260/309`、`internal/lifecycle/lifecycle.go:235` | V（原报告有一处计数错误） | 新迁移补索引 |
| **P2-5** | **`oidc_auth_requests.client_id` 无前导索引**——**当前引擎**的表，全新部署也会长起来 | migrations 0008/0012 | V（**复核新发现**，原报告漏了） | 0022 迁移一并补上 |
| **P2-6** | `trusted_proxies` 接受 `0.0.0.0/0` / `::/0`（唯一让它失效的值恰是没被拦的那个）⇒ 限流桶与日志 `client=` 由调用方自选 | `cmd/re0auth/config.go` | V（真进程实测伪造 XFF 进了访问日志） | 危险值需要显式 acknowledgement，与 `expose_internal` 同一形状 |
| **P2-7** | `sources[].token_class` **既不校验也不默认**：`long_live`/`Revocable`/省略/`session` 全部被接受，而 `unbind.go:74` 一律按 revocable 处理 ⇒ 不可撤销的源被报成「已撤销上游」 | `internal/federation/federation.go`、`unbind.go:74` | V（真进程三种写法都启动成功；同一枚举在 `upstreamkit/conformance` 却是被校验的） | 校验枚举 + 缺失即拒绝或给安全默认 |
| **P2-8** | 设了 `DATABASE_URL` 但无 `[storage]` 段 ⇒ **静默内存模式**（审计链/锚点/自检全无），而警告写的是 `because="no DATABASE_URL"`；且不存在 `RE0AUTH_STORAGE_DRIVER` ⇒ **纯环境部署无法持久化** | `cmd/re0auth/config.go`/`main.go` | V（真进程复现了**错误原因的警告**；与 `SECURITY.md:10`、`README.md:20,30` 相反） | 修文案；补一个环境变量或让 `DATABASE_URL` 自动选 driver |
| **P2-9** | `scripts/restore.sh` 的 sha256 守卫校验的是 `.sha256` 里记录的**路径**而不是命令行给的文件：异地恢复被自己挡死，而**截断的转储能「校验通过」**进入 `pg_restore` | `scripts/restore.sh:23-25` | V（真脚本 + 桩工具跑出两向） | 校验绑定到实际入参；`pg_restore` 加 `--single-transaction` |
| **P2-10** | **`.age` 加密备份路径下校验守卫一行都不执行** | `scripts/restore.sh` | V（复核新发现，实测 `exit=0`） | 解密后同样校验，或在解密前校验密文 |
| **P2-11** | `.sha256` 缺失时校验**静默跳过**（fail-open，而其余前提全是 fail-closed） | `scripts/restore.sh` | V（复核新发现） | 缺失即拒绝 |
| **P2-12** | `release.yml` 推 `latest` → Trivy `--exit-code 1` 在其**之后** → 而 `deployment.yaml:37` 正引用 `latest` ⇒ **未过门禁的镜像成为默认被引用的那一个** | `.github/workflows/release.yml:53,86-93` | V | Trivy 挪到 push 之前；manifest 不引用 `latest` |
| **P2-13** | 发布镜像不传 `VERSION` build-arg ⇒ 二进制与启动日志报 `version=dev`（`ci.yml` 反而传了），与 Dockerfile/README 承诺相反 | `release.yml:55-66`、`Dockerfile:48` | V | 传 build-arg |
| **P2-14** | 备份脚本默认 umask 写出**世界可读**的明文转储（真跑 `-rw-r--r--`，而 `backup-keys.sh` 有 0600）；`restore.sh` 把明文解密在备份目录且不清理；DSN 走 argv 可被 `ps` 读到 | `scripts/backup.sh`、`restore.sh:16-21` | V | `umask 077`；临时目录 + trap 清理；DSN 走 env |
| **P2-15** | runbook 写的 `[admin].allow` 不是真键（真名 `subjects`，未知键会**拒绝启动**）；`runbooks.md`/`slo.md` 称内部监听器「默认 :9090」（实际默认不监听） | `docs/runbooks.md:9,11`、`docs/incident-response.md:21`、`docs/slo.md:79` | V | 改文档 |
| **P2-16** | 备份 Pod **无任何标签** ⇒ 不被任何 NetworkPolicy 选中（default-deny 集群上每次转储静默失败）；叠加 P2-21（备份停了无告警） | `deploy/k8s/backup/*` | V | 加标签让策略选中；加「备份未运行」告警 |
| **P2-17** | 同意面按 **scope** 判「已满足」而数据面按**资源名** ⇒ 同意页可能叫用户连 a、而读取由 b 服务（`missing.go:84` 的注释自称镜像数据面选源规则，实际不是） | `internal/federation/missing.go:54-62,84-95` | V（复核新发现） | 让两面共用同一判据 |
| **P2-18** | 闸门可被**已 retired 的源**决定（`ResourceScope` 不看 `Status`，`candidates` 看）⇒ 退役一个源会静默改变另一个源的授权判据、把在用的令牌打成 403 | `internal/federation/service.go:206-213` | V（复核新发现） | 闸门与选源用同一状态过滤 |
| **P2-19** | 不透明 bearer 是 compact JWE，解析走 go-jose 通用路径：**97% 的成本与内存都在 JWE**（12 208 B/op vs store 查询 192 B/op）；端到端 `/v1/me` = 180 allocs/14.9 KB | `internal/oidcstore`、`internal/oidchttp` | V | `op.WithCrypto` + `NewCompositeCrypto` 是现成替换缝（该接缝还覆盖 auth request ID） |
| **P2-20** | CI 前端依赖审计门是 `pnpm audit --audit-level high`，而树里唯一告警 `cookie@0.6.0 <0.7.0` 恰在门槛下 ⇒ **这道门永远不会响** | `.github/workflows/ci.yml` | V（high=exit 0、low=exit 1；该包在产物中不可达） | 降到 `low` 或显式忽略该告警 |
| **P2-21** | 内嵌进二进制的 npm 前端代码**无版权/许可声明**（`__svelte`×7、`__sveltekit`×5，而 `Copyright`/`@license`/SPDX 全为 0），而随归档的 `NOTICE` 只覆盖 42 条 Go 模块 ⇒ **已随 rc.3 公开发出、不可回溯** | 构建链、`NOTICE` | V（复核用**已发布的 rc.3 二进制**钉死） | 生成 npm 许可清单并随归档分发（**"开 legal-comments 保留" 那一步是空转**——539 个 JS 文件零 legal comment） |
| **P2-22** | `GET /v1/account/export` 与 `GET /v1/admin/audit` **都不留审计记录**（导出一次拿走全部个人数据、读日志一次读遍所有账号）；复核认为此条**被低估** | `internal/httpapi/export_routes.go`、`audit_routes.go` | V | 补审计事件 |
| **P2-23** | discovery 为内省端点广告 `client_secret_post`，而该端点**只认 HTTP Basic** ⇒ 按 discovery 协商的 RP 拿到 401；**方向搞反**（把库的正确值改成了错的），违反 ADR-0005 第 5 条 | `internal/oidchttp/oidchttp.go:385-387` | V | 改回 `["client_secret_basic"]` |
| **P2-24** | `prompt=none` **全仓未实现**：静默认证被 302 到登录页而不是 `error=login_required`。复核确认它**不在** O-9 的「不做」清单里 ⇒ 是**漏实现**，不是已文档化决定 | `internal/oidchttp` | V | 实现，或明确列入不做清单并修 discovery |
| **P2-25** | RP 侧 JWKS 缓存**无 TTL** ⇒ 上游 IdP 吊销的签名密钥仍继续验签 | `idp/idp.go` | V | 加 TTL；失败不缓存（这一半已成立） |
| **P2-26** | RP 侧 discovery 端点**未钉在 issuer 上** ⇒ 配置里的 `client_secret` 可能被投递给文档给出的任意 origin | `idp/idp.go` | V（维持中；可达性取决于谁能改 issuer 配置） | 校验文档中的端点与配置 issuer 同源 |
| **P2-27** | Upstream Kit 生成的 `/oauth/cascade_revocation` **自身不认证**，而一致性套件把它判 **PASS** ⇒ 第三方数据源可能照抄出一个「任何人可结束用户全部上游会话」的端点 | `upstreamkit/server.go:318-339`、`upstreamkit/conformance` | V（复核降为**中**：唯一在仓实现在钩子里做了机密客户端认证） | kit 代认证 + 套件断言「无认证的 cascade 必须被拒」 |
| **P2-28** | Kit 的 `Introspect` **不问 client 状态**（违反库自己的文档）⇒ 被暂停/删除的客户端令牌仍 active 且能读数据面 | `oauth/as.go:253-271` | V（复核降为**中**：仓内唯一调用者 `internal/admin` 暂停时连带 `RevokeTokens`） | 让 `Introspect` 查 client 状态 |
| **P2-29** | 编码路径下的业务面 404 **绕过 `/v1` 层的 `no-store` 与 panic 恢复器**；复核指出根因不是「路由器边界」而是 `writeProblem` 自身不设 `no-store` | `internal/httpapi/server.go`、`responses.go` | V（独立复现；panic 半输入不可达） | 把 `no-store` 放进 `writeProblem` 本身 |
| **P2-30** | 业务面的 **429/413 同样缺 `no-store`**，而唯一守卫只走 7 个 200 端点 | `internal/httpapi/middleware.go` | V（复核新发现） | 同上 |
| **P2-31** | `drain` 时审计批次排空**无总时间上界**（k8s manifest 的 45 s 只算了 HTTP 的 30 s） | `cmd/re0auth/main.go`、`internal/store/postgres/auditbatch.go` | V（读；无 DB） | 给排空阶段单独预算 |
| **P2-32** | 设备路径用**数据库的 `now()`** 判 `expires_at`/`last_poll`，而内存后端与 Go 读路径用 store 时钟 ⇒ 同一个 `expires_at` 被两个时钟裁决（UI 说有效、审批被拒且文案说码不存在） | `internal/store/postgres/oidc.go:771` vs `:1083` | V（复核降为**低**：同机部署共享内核墙钟，方向在安全一侧） | 统一时钟来源 |
| **P2-33** | `Dockerfile:60` 从构建阶段 `COPY` Alpine 的 CA bundle；**若是符号链接**则 scratch 里成悬空链接 ⇒ 全部出站 TLS 失败（失败点是**首次登录**） | `Dockerfile:60` | **HYPOTHESIS**（无 Docker 既不能证实也不能证伪） | `docker run` 一行确认；修法：构建阶段先 `cp` 解引用 |

---

## P3 低 / 提示

**协议面**：`response_mode=form_post` 的授权响应不带 RFC 9207 `iss`（而 discovery 广告支持）；
令牌端点只挡 GET、不挡「POST + **查询串**」⇒ 凭据仍可进 URL（**更正**：Re0Auth 自己的访问日志
**刻意不记 query**，风险落在中间层日志）；`userinfo` 对没有 `openid` 的令牌也返回 `sub`；
匿名 `/oauth/authorize` 每次分配一条 pending 请求（TTL 30 分钟，与内存模式增长同源）。
**RP 侧**：`azp` 完全不校验（复核**实测推翻**「账号接管」：callback 只读 `state`+`code`，
id_token 只来自本服务自己那次带 secret+PKCE 的交换 ⇒ **纵深防御缺口**）；
内置 `microsoft` issuer 必然 discovery 失败（文档其实给了 `<tenant>` 写法）。

**HTTP 边界**：会话 Cookie 受众是整个源（`Path=/`，`account-model.md:124` **已记录**）；
会话不绑定设备/方法，只剩「用户看到没请求过的同意页」（handle 确实 `Bound`+`OwnerMatches` 绑会话）；
mux 路径清洗制造的 307 会**跨平面**（`/v1/../oauth/token → 307 /oauth/token`），
且限流与指标按**未清洗**路径归 plane。

**并发/内存**：三处丢 `ctx`（无观测影响）；**copy-on-return 别名**——复核用 `-race`
**造出过真 DATA RACE**（`oidcstore.go:222` vs `memory/oidc.go:940`），
但生产唯一持有者只取 `GetID()` 就丢指针 ⇒ 可达性被推翻，留作潜在缺陷；
`auditbatch.enqueue` 在「读 closed」与「入队」之间确有窗口（复核 ≈32 万次调用命中 7 次
「已接受永不回答」；装运路径全是请求 ctx ⇒ 提示级）；
**`TestMemStoreSweepStallsConcurrentRequests` 的 `worst` 从不重置 ⇒ 该探针结构上不可能失败**
（假守卫，应修）。

**Postgres**：三个 `Sessions` 多写方法无事务（失败并非静默，返回非零 err）；
抹除静态守卫看不见 `ALTER TABLE ADD COLUMN` 与 `subject`/`user_id` 以外的命名
（但 CI 的动态守卫走 `information_schema` 能覆盖，**CI 才是权威**）；
`-migrate-down` 从版本 6 出发的**那一次**就整体失败（`Down(ctx)` 传 version=0），
且 ADR-0008 已把回滚故事定义为**恢复备份** ⇒ 低-中。

**性能**：审计批的 1 ms 收集窗口与 `64/commit` 天花板（机制与拐点判据**已写在**
`capacity-planning.md:131-139`，`slo.md:59` 的告警本就点名了）；`/v1/admin/audit/verify`
全表同步扫描（实测 **1.34–1.47 µs/行**，阈值约 3×10⁷ 行；`operations.md:171-182`
**已经写了**同一个修法）；内存模式的 sweep 与 device 清理是 O(live) 且持全局锁
（ADR-0006 决策 6 明确内存模式不承担生产保证）；
`capacity-planning.md` 的 `max_in_flight` 与内存模型两处文档失真。

**前端**：shell 无 `ETag`/`Last-Modified`（但 **`no-cache` 已封住浏览器路径**，
「CSP 哈希与新构建不匹配 ⇒ 白屏」**结构上不可能**——哈希与内联脚本在同一份文档里）；
HTML 文档对 `Range` 回 206 半截 shell（浏览器导航不发 Range ⇒ 无可达危害）；
同意页/设备页「显示少于授予」（端到端复现，但**无数据能力**：userinfo 只回 `{"sub":…}`、
id_token 无 name/email）；构建不可复现（`_app/version.json` 装构建时刻毫秒时间戳；
**但两条危害被实测推翻**：改内容的分块从不保留旧名 ⇒ 不是缓存投毒；
缺失资产回 **200 shell** 而不是 404）⇒ 剩下只是「`architecture.md:12` 写『构建产物可复现』与实际不符」；
产物里有 6 处 `console.warn` + 25 个 `svelte.dev/e/…` 串。

**依赖/供应链**：`uses:` 47 处（46 远程全 SHA）但**没有测试守 `uses:` 与工具版本这两半**
（base image 那一半**有**守卫，实跑 PASS，而 `dependencies.md:121-125` 声称 archtest 守着）；
`make dist` 的 `cp` 不带 `|| exit 1`、归档无内容断言（**但「给 NOTICE 改名」被推翻**：
`archtest/notice_test.go:55` 会让 tag 门禁先红 ⇒ 真正会**静默**的是 `LICENSE`/`README.md`/`SECURITY.md`）；
归档与镜像各自构建一次前端（**是观察不是缺陷**，仓库里没有任何「归档 = 镜像」的断言）；
发布只由 tag 触发、不校验它是否指向 main 上已评审的 commit；
SBOM 未开 `-licenses`（**属范围选择**，无人声称它承担许可合规）；
运行镜像不带 `LICENSE`/`NOTICE`（与 P2-12 同一缺口）。

**配置/启动**：启动日志**不公布任何一个安全开关**（真进程完整日志里 `cookie_secure`/
`trusted_proxies`/`rate_limit`/`max_in_flight`/`expose_internal`/`allow_private`/
`introspection_clients`/`reauth` 八项全缺席）；内部监听器无任何访问日志；
`docs/runbooks.md:27` 让运维检查 `RE0AUTH_DATABASE_URL`，该变量在 `*.go` 里 **0 处**；
示例配置的 `Environment override` 只覆盖 7 条而代码有 18 个 `RE0AUTH_*`；
`internal_addr != addr` 只是字符串比较（但运维面**始终只在 loopback**，
原报告「`curl localhost` 落到运维面」的**方向是反的**）；
`0.0.0.0:P` 在 Go/Windows 实际绑成 `[::]:P`（按 IPv4 CIDR 写的控制不覆盖 IPv6 通配）。

**部署**：空白名单 ⇒ Kill Switch 与审计读取/校验都不挂载，而 runbook 与 S5 都依赖它们，
但没有「加第一个管理员」的步骤（复核降为**低**：空白名单是明写的**有意安全默认**，
S5 另有服务内 6h 自校验循环 ⇒ 是 onboarding 文档缺口）；
备份保留策略（`*/15` × 7 天 × 20Gi）与「备份停无告警」（**但「必然写满」被推翻**：
`pvc.yaml:9-11` 自己写了 sizing 公式）；Makefile 把 `$(VERSION)` 插进 shell 配方
（`make -n` 复现注入，但能推 tag 者本就能构建任意树 ⇒ 真正的问题是工作流里那条
「已经防住」的注释是**假的**）；无 `preStop` + SIGTERM 立刻关监听器 ⇒ 滚动更新有
connection-refused 窗口（scratch 无 `/bin/sleep`，修法要先解决这一点）；
迁移 >120 s 撞 `startupProbe` 预算；改 ConfigMap 需显式 rollout restart；
CodeQL 不解析 `.svelte`（15/21 文件）；`expose_internal=true` 的正当性完全押在
CNI 真实现 NetworkPolicy 上；PDB + `ScheduleAnyway` 措辞夸大；namespace 无 PSA 标签。

**协议面动词矩阵的两个缺口**（我本人实测确认，均为「守卫与被守卫对象共用同一假设」）：
- `/.well-known/openid-configuration` 与 `/.well-known/oauth-authorization-server`
  **任意 HTTP 动词都回 200 + 完整文档**（`endpointMethods` 只列 `/oauth/*`，
  两份发现文档在 `ServeHTTP` 里**直接**交给 `serveDiscovery`，不查那张表）。
  与工作区未提交的 CHANGELOG 声明「未列出的动词一律 405」直接冲突。
- `/v1//me` → **307 `text/html`**，而指标把它记成 `plane="business"`
  （`ServeMux` 的路径清理发生在任何 handler 之前，不经过三个平面写出器的任何一个）。
  守卫从 `specRoutes()` 的规范路径派生，走查在结构上到不了非规范路径。

---

## 复核更正：不要按原始报告读的 12 条

> 12 个复核代理里 11 个真的动了手。**只跑区域审计不跑复核，报告里会多出至少 30 条错误的严重度
> 判定和 3 条完全错误的技术机制。**

| 原判定 | 更正 | 关键依据 |
|---|---|---|
| k2 覆盖后「永久不可读」 | **机制推翻**（仍可读，是**静默回滚**） | 原报告自己的 FAIL 输出里那行**读出了**旧值 |
| k3 半途失败 = 永久丢失 | **降为低** | 保留两把 KEK **重跑收敛**（实测 `{Scanned:3 Rewrapped:2 AlreadyCurrent:1}`） |
| PG-002「先退 6、下次退 5 才失败」 | **机制写错** | `Down(ctx)` 传 version=**0** ⇒ 那一次就整体失败 |
| PG-003 两个时钟裁决 | **降为低** | `WithClock` 自述只是「让单时钟政策可断言」的注入点 |
| PG-005 拼接 where 有风险 | **不是发现** | 未导出 + 3 个调用点全是常量 |
| RP-1「azp 不校验 ⇒ 账号接管」 | **降为低，部分推翻** | 实测 callback 只读 `state`+`code`；带真 nonce 的伪造令牌 → `303 /?error=identity_failed` |
| KIT-1「任何人可摧毁上游会话」 | **降为中** | 唯一在仓实现 `referencesource/cascade.go:48` 在钩子里做了机密客户端认证 |
| KIT-3「暂停后令牌仍能读数据面」 | **降为中** | 仓内唯一调用者 `internal/admin` 暂停时连带 `RevokeTokens` |
| CM-1「持久化部署里内存锁横跨 DB 往返」 | **影响叙说推翻** | 两种 store 在同一部署**互斥**（`main.go:1170-1198` 单一分支）——**类别错误** |
| CM-4「无界增长」 | **降为低** | 峰值 = 到达率 × 30 min TTL，**有界**（实测 TTL 后 5000/5000 被清空） |
| HE-2「302 会被启发式缓存」 | **降为低，部分推翻** | 302 **不在** RFC 9110 §15.1 的可缓存状态列表里（复核取回了原文） |
| HE-9「审计 limit 无服务端上限」 | **推翻** | `postgres/auditread.go:29-35` 钳到 **1000**——原报告读错了被调用层 |
| A-FE-1「陈旧 shell 白屏」 | **降为低** | 「CSP 哈希与新构建不匹配」**结构上不可能**：哈希与内联脚本在同一份文档里 |
| A-FE-9「缓存投毒」 | **降为低，两条危害推翻** | 改内容的分块从不保留旧名；缺失资产回 **200 shell** 而非 404 |
| SUP-1「完全没有许可文本」 | **实质成立，表述错** | CSS 与二进制各含 1 处 tailwindcss MIT banner |
| SUP-3「43 处 uses，无守卫」 | **两处错** | 真值 **47**；base-image 那一半**有**守卫且实跑 PASS |
| SUP-4「给 NOTICE 改名会静默发出去」 | **部分推翻** | `notice_test.go:55` 会让 tag 门禁先红 |
| DEP-01「高」 | **降为中** | 「半库后锁死」已被 `operations.md:63` 文档化，补救是一条 DROP |
| DEP-05/06/11「中」 | **降为低** | 有意安全默认 / `pvc.yaml` 自己写了 sizing 公式 / 注入不构成越权 |
| FO-02「中」 | **已知（非发现）+ 证据不成立** | 「跨实例 refresh 残余」是简报明列非目标；其探针在 CAS **输掉**的分支上触发 |
| CS-1「高」 | **降为中高** | 「几百并发占满池」只在 DB 往返 ≳1 ms 时成立 |
| CS-2「中」 | **降为低，方向推翻** | 运维面**始终只在 loopback** |
| 「无 cgo、`-race` 跑不了」 | **推翻** | CGO_ENABLED=1 + gcc；复核整包 `-race` 通过并用**故意注入的竞态**证明检测器活着 |

**已知有缺陷的探针（不要当成发现）**：`internal/zzprobe/federationhttp` 的
`TestZZProbeKillSwitchRequiresAnOperator` 断言 401 而实际是 404 —— 复核已指出它与报告正文
及 `docs/admin.md` 都矛盾。收作守卫前必须先修它。

---

## 探过但没破（安全姿态）

**200+ 条负面结论**，摘最要紧的：

- **协议面**：`redirect_uri` 精确匹配（复核另用 13 个新变体：`cb/../cb`、`client.example./cb`、
  `CB?`、`CB#`、`cb;x=1`、`%00`、制表符……全部 400 且不重定向）；授权码生命周期与单次使用；
  刷新**不能**提权（10 个变体）；PKCE 常数时间；JWKS 无私钥材料且 `kid` 一致；
  令牌 JWE 抗篡改与轮换契约。
- **限流**：**默认姿态完全正确**——我独立实测伪造 `X-Forwarded-For` **不能**换桶，
  固定与轮换 XFF 两轮突发都在**第 101 个请求**开始 429（`rate_limit_burst = 100`）；
  并发 1920 请求 shed 1523；429 的形状两面都对，都带 `Retry-After: 1`。
- **无 CORS 暴露**：带 `Origin: https://evil.example` 的 GET 与 `OPTIONS` 预检
  **没有任何 `Access-Control-Allow-*` 头**，与 ADR-0011 一致。
- **启动期配置校验全部 fail-closed**（我真进程实测，退出码 1、消息精确）：四个必需密钥各自缺失即拒绝；
  KEK 与 token key 非 32 字节拒绝；**1024 位 RSA 拒绝**；非 PKCS#8 的签名密钥拒绝；
  `internal_addr == addr` 拒绝；`internal_addr` 绑非 loopback 而未 `expose_internal=true` 拒绝；
  `trusted_proxies` 非法条目拒绝；非法 TOML 给出精确行列；
  **没有配置文件时进入 environment-only 模式**（README 第二种快速开始形式成立）。
- **运维面在公网面完全不可达**（实测：`/metrics`、`/debug/pprof/` 在公网端口 404）。
- **安全响应头**逐响应齐全；前端 CSP 两层（头只发 `frame-ancestors`，meta 发 hash 版
  `script-src`，无 `unsafe-inline`/`unsafe-eval`），复核用**真 Chromium**（含 `bypassCSP` 对照）
  验证注入被拦、应用 0 违规、**67 个 e2e 通过**。
- **前端**：全 `web/**` 只有 1 处 `{@html}` 类命中且是注释；产物里 `console.log`/`debugger`/
  `sourceMappingURL`/`localhost`/`@vite`/密钥形状 **全部 0 命中**（21 条正则 + **阳性对照 21/21**）；
  13/13 写端点都带 CSRF；20 个 JS 分块从 shell 出发全部可达。
- **并发**：授权码/refresh 轮换/`device_code` 消费在**真实 goroutine 竞态**下仍是单次使用；
  并发设备批准至多一人胜出；并发 Kill Switch 幂等；四个后台循环都随 ctx 返回且 ticker 全部 `Stop`；
  生产代码无「循环里的 `time.After`」；未发现锁序倒置；`vault.Use` 不跨锁回调。整套 `-race -p 1` **无 DATA RACE**。
- **密码学**：AAD **双向**绑定身份（交换两行必失败）；`recordVersion` 只进 AAD 且**没有**按版本分支
  ⇒ 不存在降级面；两层 nonce 各 512 次无重复；`kek_id` 只在启动构造的 map 里选
  ⇒ 能写库者无法指向自控密钥；`CompositeCrypto` **不按 kid 查表** ⇒ 无解密预言机；
  审计 canonical 无歧义、三个域分离 label 不可跨用途互换；
  `user_code` = 20⁸ = **34.575 bit**（出厂限流下单地址 60 s P=1.2e-07）；全部 `crypto/rand`。
- **Postgres**：17 处 SQL 拼接逐处复核**全是编译期常量**；四处单次使用都是 **DELETE-first 认领**；
  **29 处 `RowsAffected()` 无 fail-open 形状**；advisory lock 在 panic/ctx 取消下仍释放。
- **依赖**：`govulncheck@v1.8.0 ./...` 报 **`No vulnerabilities found.`**，模块图 5 条通告全不可达，
  且复核**自建带洞对照模块**（`x/text@v0.3.7` → `GO-2022-1059` 可达、exit 3）证明工具非空转；
  SBOM 与发布二进制的模块集**精确相等 42 = 42**；`NOTICE` 与 Linux 构建图 **42 = 42**；
  `go mod verify` 通过；全仓无 `GOFLAGS`/`GONOSUMDB`/`GOINSECURE`。
- **部署**：CI 里本地可查的一半**全绿**（10/10 fuzz 目标、`cmd/covertable`、`TestLoadProfile`、
  `go vet` exit 0、`gofmt` 干净）；`from:scratch` 非 root；基础镜像按 digest 固定。

---

## 未能到达（残余盲区）

1. **一切 Postgres 运行时语义**：本机无 Docker/无本地库 ⇒ 索引是否真被使用、事务隔离、
   `statement_timeout` 实际效果、`-migrate-down` 的报错文本，全部只有读码级证据。
   **权威验证在 Linux CI**（`ci.yml` 自带 `postgres:16`）。
   特别地：**`TestMigrateDownRollsBackOneStep` 在 CI 里现在是红还是绿没有闭合**，
   它决定 `-migrate-down` 那条的最终严重度。
2. **容器/镜像层**：CA bundle 是否符号链接（P2-33）、镜像 digest 内的工具版本、cosign 行为、
   Trivy 实际结果、kustomize 的 API 校验、CNI 是否真实现 NetworkPolicy。
3. **真实发布链路**：没有真 tag、没有 cosign、网络受限 ⇒ `SHA256SUMS` 的覆盖面只在脚本层确证。
4. **真实上游**：数据面探针全部用 stub Doer；真实 TapTap/LeanCloud 方言、真实跨实例 refresh
   交错、真实双进程时序未跑。
5. **Linux 特定行为**：`0.0.0.0/8` 是否路由到本机回环（Windows 上实测不可路由）、
   同端口两次 bind 的内核语义、IPv6 通配的实际覆盖。
6. **浏览器/中介层**：只有 Chromium 一个引擎；「违反 RFC 9111 的中介缓存陈旧 shell」只能在真代理上测。
7. **绝对性能数字不可引用**：本机同时有 10+ 个审计代理在跑。可引用的是**每操作分配量**
   （与负载无关）与复杂度类。

---

## 判断：值得重新裁定的文档化决定

> 这些**不是缺陷**（项目已明确记录为决定），但上线前值得重新看一眼。

1. **`max_in_flight` 的标定**：文档里 512 与 128 两个数并存，出厂配置是 512。
   应给它一个与内存 limit 挂钩的推导，而不是两个互相矛盾的常数。
2. **`/readyz` 的豁免**：代码注释解释了「探针不能被限流拖死」，而那正是让它可被打满池的原因。
   这是**取舍**，需要写进 `docs/operations.md` 并给出「探针该多贵」的裁定。
3. **跨引擎的同意面一致性**：`authorization_routes.go`、`memory/oidc.go`、`postgres/oidc.go`
   各有一份「显示少于授予」的实现。要么定义「协议 scope 不算权限」并让**所有**展示层一致，
   要么把 `openid`/`profile`/`email` 从展示集明确排除。
4. **`azp` 与 JWKS 缓存**：RP 侧这两条是**依赖库/上游 IdP 的属性**，项目能做的只是加固，
   建议记入 `docs/dependencies.md`。
5. **`-migrate-down` 的前置条件**：ADR-0008 的 expand/contract 只约束正向；
   建议明确写「`-migrate-down` 的前置是已摘除流量」。
6. **`architecture.md:12`「构建产物可复现」**与实测不符。要么实现可复现构建
   （把 SvelteKit 的 `version.name` 钉成 git rev / BUILD_ID），要么改这句话——
   它正被 SBOM/checksums 的论证引用。
7. **未实现的 OIDC 面**：`prompt=none` 不在 O-9 的「不做」清单里，但也没实现 ⇒ 要么实现，
   要么补进清单并让 discovery 一致。

---

## 执行顺序建议

**第 1 批（阻断，同一次提交）**
1. P0-1 + **P0-2 必须同批**（否则修 P0-1 会当场开出一个新洞）
2. P0-5（`requestParams` 吞错 + scope 闸门查全部值）
3. P0-6（内省白名单只接受机密客户端）
4. P0-3（在途 × body 联合预算 + 重标 `max_in_flight` + `GOMEMLIMIT`）
5. P0-4（分桶键不含调用方写的值；桶满 fail-closed）

**第 2 批（高）**
6. P1-1 + P1-2（轮转窄写/CAS + `-rotate-keys` 退出告警 + 文档三步补闸门）
7. P1-3（数据面总超时 + 401 纳入熔断）
8. P1-4（`/readyz` 配额，附裁定文档）
9. P1-5（闸门与选源同源）

**第 3 批（中，按「静默失败优先」排序）**
10. 所有**静默失败**类：P2-1（吞审计）、P2-2、P2-3、P2-9/P2-10/P2-11（restore 校验）、
    P2-12（未过门禁的镜像被引用）、P2-8（错误的启动警告）
11. 索引补齐：P2-4 + P2-5（一条迁移）
12. 配置校验：P2-6、P2-7、P2-23
13. 文档一致性：P2-15、P2-22、以及 P3 里的 docs 漂移（`[admin].allow`、
    `RE0AUTH_DATABASE_URL`、内部监听器默认、`upstream-protocol.md:188` 的映射表、
    `dependencies.md:121-125` 的 action pin、`architecture.md:12`）

**第 4 批**：P3 与判断清单，随迭代处理。

**两个守卫缺口优先补**（它们属于「守卫与被守卫对象共用同一假设」，会继续漏）：
`/.well-known/*` 不受动词矩阵约束（守卫应从 `http.ServeMux` 实际注册表反推），
以及 `ServeMux` 路径清理制造的非规范路径 307（守卫不能只走 `specRoutes()` 的规范路径）。

---

## 附录：探针文件与流程说明

**92 个探针文件**（22 个新包）全部放在 `//go:build audit5` 之后：

```sh
go build ./... && go vet ./... && go test ./...       # 33 个包全绿（已实跑）
go test -race -p 1 ./...                              # 全绿，无 DATA RACE（已实跑）
go test -tags audit5 -count=1 ./internal/zzprobe/...  # 红 —— 这就是证据
```

**为什么加标签**：这些探针就是发现的证据（本项目规矩：一条发现必须有一条会失败的测试），
但留在默认套件里会让 `go test ./...` 与 CI 立刻变红，挡住所有其它改动。
加标签后默认套件**恢复全绿**，一条证据都没删，一个标志就能跑全部对抗用例。

**当前为红的探针（即缺陷仍在）**：PROTO 区 8 条、admin 区 4 条、concurrency 区 3 条、
crypto 区 2 条、dependencies 区 3 条、federation 区 4+3 条、pgstore 区 2 条。修好一处就绿一条。

**回退方式**：探针全部是**未跟踪**的新文件（`git status` 里以 `??` 出现）。
要彻底移除，删掉 `internal/zzprobe/`、各包内的 `zzprobe_*_test.go` / `zz_probe_test.go`
与 `internal/zzprobe/*/doc.go`（后者是空包占位，让排除标签后包仍然存在）。

**未修改任何被跟踪文件**：`git diff --stat` 只有**审计开始之前就已存在**的 8 个改动
（`CHANGELOG.md`、`internal/federation/unbind.go`(+test)、
`internal/httpapi/{server.go,bind_test.go,plane_test.go}`、
`internal/oidchttp/{oidchttp.go,adversary_test.go}`）。`gofmt -l .` 干净，`go vet ./...` 干净。

**流程说明（如实记录）**：审计期间共享简报被某个代理误删过一次（由主代理重建）；
有一个代理的探针曾短暂引入非法 UTF-8 使 `internal/httpapi` 整包约 10 分钟不可编译；
另有一个代理向 `internal/store/postgres/postgres.go` 加过一行仅供探针的导出，已回滚
（该文件现与 `HEAD` 逐字节一致）。**下次这类审计应给每个代理一份独立的 `git worktree`。**
