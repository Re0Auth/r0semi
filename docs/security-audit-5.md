# 第五轮：上线前全面安全与性能审计（Re0Auth）

> **性质**：这一轮不是「再来一遍前四轮」，而是**上线前的全面覆盖 + 对抗性复核**。
> 范围从安全扩到**性能、部署产物、前端、依赖供应链、配置/启动路径**；
> 方法是**区域审计之后每份报告都交给一个被要求「证伪」的复核者**。
>
> **一句话结论**：协议与授权核心的工程纪律**很高**（前四轮留下的守卫大量仍在生效，
> 本轮 200+ 条「探过但没破」的正面结论就是证据），但**上线前有 3 条必须修**，
> 其中一条（`id_token` 无 `sub`）会让「下游一次 OIDC 接入就拿到『这是谁』」这个核心卖点失效。

---

## 0. 方法与边界（先说清楚，否则下面的每条都要打折看）

**做法**：12 个区域并行审计（协议面、HTTP 边界、密码学/密钥、Postgres、并发/内存存储、
联邦/出站、管理面/审计/隐私、前端、部署/CI、依赖供应链、性能容量、配置/启动/可观测性），
每个区域交一份报告；随后**每个区域再派一个复核子代理，其任务书里写的是「你的工作是证伪，不是同意」**。
主代理另在**真进程**上独立核实了几条最重的结论，并独立跑过基线、`-race`、限流、启动校验、CORS。

**证据标准**（沿用项目自己的规矩）：**a finding is not a finding until a test can fail on it**。
每条发现要么带一条实际跑过并失败的测试，要么是 `file:line` 的读码确证并明确标注
「读；未执行」。**本轮所有 CONFIRMED 条目都有可执行的复现**，探针清单见 §11。

**本机边界（必须如实说）**：
- **没有 Docker、没有本地 Postgres** ⇒ 所有落盘/事务/索引/镜像/集群结论都是**读码级**，
  复核者也逐条标注了这一点。
- `-race` **可用**（CGO_ENABLED=1 + gcc），整套在 `-race -p 1` 下跑过，**未发现 DATA RACE**。
  注意：本轮有一个区域报告声称「无 cgo，`-race` 跑不了」，**该说法被复核推翻**。
- Windows 11 / PowerShell 5.1 ⇒ 涉及 Linux 内核路由、CNI、容器层语义的结论只能是假说。

**统计**：12 份区域报告 + 12 份复核报告；原始发现 130+ 条；
**复核推翻或降级 30 余条，复核过程中又新发现 20 余条**。两类数字都重要——
只有把「复核掉了什么」写清楚，剩下的才可信。

---

## 1. 上线前必修（阻断级，3 条 + 1 条排序约束）

### B-1 【阻断】`id_token` 里**没有 `sub`** —— OIDC Core §2 的必需声明被静默抹掉

- **来源**：PROTO-2 / M-RT-3。**复核结论：CONFIRMED，且机制逐行核对无误。**
- **证据（实际执行）**：
  ```
  $ go test ./internal/zzprobe/protocol/ -run TestProbeIDTokenIsMissingTheSubjectClaim -v
      authorization_code: the id_token has no `sub` claim at all
        (claims: [iss exp nonce client_id at_hash c_hash aud iat auth_time azp])
      refresh_token:      the id_token has no `sub` claim at all
      userinfo carries sub=usr_probe while the id_token does not
  ```
  两条签发路径（授权码兑换、刷新）都缺；而 `userinfo` 正确返回 `sub`，
  所以「先换 token 再调 `/v1/me`」这种测试链**看不出**它——这正是它活到今天的原因。
- **根因**：`zitadel/oidc v3.51.3` 的 `pkg/op/token.go:241-254` 在 `len(scopes) > 0` 时调
  `storage.SetUserinfoFromScopes(...)` 然后 `claims.SetUserInfo(userInfo)`，
  而 `pkg/oidc/token.go:158-159` 的 `SetUserInfo` 第一句就是 `t.Subject = i.Subject`。
  本项目两个 store 的 `SetUserinfoFromScopes` 都是**空实现并注释「deprecated upstream; no-op」**：
  `internal/store/memory/oidc.go:685-687`、`internal/store/postgres/oidc.go:577-581`。
  于是空 `UserInfo.Subject` **覆盖**了刚刚正确设好的 subject，
  `json:"sub,omitempty"` 再把它从 token 里抹去。**那条注释是错的**——
  该回调在 v3.51.3 的签发路径上正被调用。
- **影响**：严格的 RP 直接拒收（登录失败）；宽松的 RP 若拿 `id_token.sub` 当用户主键，
  会把**所有用户归并到同一个空身份**（在 RP 侧构成账号混淆）。
  同时 `discovery` 里 `claims_supported: ["sub"]`（`internal/oidchttp/oidchttp.go:159,381`）
  只广告这一个声明，而它就是唯一没被发出的那个；`docs/threat-model.md` A8、
  `docs/architecture.md` §4.4、`docs/oidc-decision.md` O-4 的全部描述也因此不成立。
- **修法**（两行）：两个 store 的空实现改成与 `SetUserinfoFromToken` 一致——
  `userinfo.Subject = subject; return nil`。只写 `sub`，不写 `profile`/`email`（与 O-3 一致）。
- **守卫**：断言 `id_token.sub` **等于已登录的 `usr_…`**（不是「key 存在」，那会空转）。

### B-2 【排序约束，必须与 B-1 同批落地】`id_token` 可以在 `/oauth/userinfo` 当访问令牌用

- **来源**：PROTO-3 / M-RT-4。**复核结论：CONFIRMED（读码级 + 与 B-1 的交互已证）。**
- **机制**：库的 `pkg/op/userinfo.go:91-108` 在 `Crypto().Decrypt(accessToken)` 失败后
  **回退**到 `VerifyAccessToken`（当 JWT 验签），而 `pkg/oidc/verifier.go:110-112` 的
  `DecryptToken` 是 `return tokenString, nil // TODO: impl`。
  id_token 正是本 OP 签的 JWS ⇒ 验签通过 ⇒ 被当作 bearer 接受。
  **今天它只回 `200 {}`，因为 B-1 把 `sub` 抹空了。**
- **为什么必须同批修**：**B-1 一修好，同一个请求立刻返回 `200 {"sub":"usr_…"}`**——
  一个**发给 RP 的** id_token 变成可用凭据。同时 PROTO-3b 指出 `/oauth/userinfo`
  **完全不检查令牌是否活着**（已撤销/过期的 access token 照样回 `sub`，业务面已 401）。
  这三条同根，必须一起改、一起加守卫。
- **修法建议**：在 `internal/oidchttp` 的 userinfo 前置检查里拒绝三段式 JWT 形状的 bearer
  （不透明令牌不是 JWT），或让 `SetUserinfoFromToken` 校验 `tokenID` 非空且命中存储。
  **不要指望 `pkg/oidc.DecryptToken`**——上游是 TODO。
- **归因**：根在依赖库；但本项目可以用极小的代价在边界上关掉它。应作为**判断**记入
  `docs/dependencies.md`。

### B-3 【阻断】数据面「在途请求数 × 响应体」没有联合上限 → 出厂配置下 5.5 倍超限 OOMKill

- **来源**：PERF-1。**复核结论：部分成立——归因成立，但原报告的数字配错了对，真实情况更糟。**
- **证据（复核实测）**：每请求 live heap 呈**线性**（n=1…32 边际 5.79–5.81 MB，无固定项；
  `debug.FreeOSMemory` 只差 32 B/req ⇒ 不是未清扫垃圾；精确 profile 归因到
  `io.ReadAll → rawFetch`，`internal/federation/service.go:517`）。
  出厂 `max_in_flight` **是 512**（`deploy/k8s/base/configmap.yaml:24`、
  `config/re0auth.example.toml:46` 都显式写了 512），
  所以对 512Mi 的 limit 是 **512 × 5.80 MiB = 2834 MiB ≈ 5.5×**，不是原报告写的 708 MiB。
  且全仓库**没有 `GOMEMLIMIT`** ⇒ 没有软着陆。
- **前提（必须写明）**：需要在配置里注册 `[[sources]]` 才有数据面；
  出厂的 k8s 基线 configmap **没有** source，所以**裸基线不会触发**——
  但任何真正在用这个服务的部署都会配。
- **修法**：给「在途 × body 上限」一个联合预算（bulkhead 按字节而不是按请求数），
  或对 raw 透传设响应体上限并把 `max_in_flight` 与内存 limit 一起标定；同时设 `GOMEMLIMIT`。

### B-4 【阻断】限流的分桶键在「配了 trusted_proxies」的部署里归调用方 → 限流可被完全绕过

- **来源**：HE-1（+HE-3）。**复核结论：部分成立，维持「高」，但前提必须改写。**
  原报告（及其探针注释）把判据说成「追加 vs 覆盖」；**复核实测四种形状后纠正为**：

  | 代理行为 | 键可控？ | 实测 |
  |---|---|---|
  | `trusted_proxies = []`（默认） | 否 | 0/20 绕过（**默认安全**，与主代理独立实测一致：固定/轮换 XFF 都在第 101 个请求开始 429） |
  | 逐字转发客户端 XFF | **是** | 20/20 |
  | 追加真实客户端地址（`$proxy_add_x_forwarded_for`） | 否 | 0/20 |
  | 追加的那一跳**本身在信任网内**（k8s SNAT / 服务网格） | **是** | 20/20 |

  判别式是「可信代理追加的那一跳是否本身也在 trust list 内」。
  而 **nginx 默认只重定义 `Host`/`Connection`，其余头逐字转发** ⇒ 「键可控」不是运维配错，
  是**主流代理的默认行为之一**。
- **放大器**：桶上限处 `evictLocked` 会淘汰**活跃**桶
  （`internal/ratelimit/ratelimit.go:213-234`，64 条随机样本，找不到空闲就删第一个），
  新桶以满 burst 创建 ⇒ 一个可控键空间 = 每次请求都是免费的全新配额。
  实测：`rate=0.001/s`（一千秒一个令牌）下 **20000 个不同 XFF → 20000 次放行、0 次拒绝**。
  （复核把「淘汰活桶」这半边降为低并指出危害方向相反：被淘汰者拿到满额桶是**受益**；
  真正的损害是「已耗额度记不住」这条性质。两者合并为一条高发现。）
- **影响**：限流是这些昂贵端点上**唯一**的节流手段（`/oauth/token`、`/oauth/device_authorization`、
  `/oauth/introspect`、`/v1/games/.../raw/...` 的上游代理、`/v1/account/export`、`/v1/admin/*`），
  于是暴力破解成本归零、上游/数据库成本被放大、且**访问日志的 `client=` 字段可被伪造**
  （审计归因同时失效）。
- **修法**：① 分桶键不要包含任何调用方写的值——`clientaddr` 在「可信链解析出的值不可信」时
  退回对端地址；② 更彻底：只取**最右侧**由最近代理写入的那一条，忽略左侧全部内容
  （或引入 `server.client_addr_header`，默认 `none`）；③ 淘汰**绝不能删活桶**：达到上限应
  fail-closed（新键共用一个兜底桶）。④ 文档要写明「代理必须覆盖而不是转发 XFF」。

---

## 2. 高

| ID | 发现 | 证据/状态 | 修法 |
|---|---|---|---|
| **PROTO-1** | **不可解析的 body 关掉「重复参数」检查 → 设备流 scope 闸门被绕过**：只注册 `account.id` 的公开客户端用 `x=%zz` 当 body，就能拿到 `phigros.score.read` 的**活 access token** | **主代理亲自执行**：`... the minted token's scope is "phigros.score.read"` / `live token introspects as active=true` | `internal/oidchttp/oidchttp.go:723-731` 的 `requestParams` 不得吞掉 `ParseForm` 错误（解析失败即 400）；闸门必须检查**全部** scope 值而不是 `form.Get`（后者只看第一个，而库取最后一个） |
| **PROTO-4** | **内省白名单里只要有一个公开客户端，任何人无需凭据就能读任意 token 的 scope/subject** | **主代理亲自执行**：`Basic <public-id>:`（空 secret）→ `active=true scope=openid account.id phigros.score.read sub=usr_probe` | 三个 store 对非机密客户端直接 `return nil`（`memory/oidc.go:670-682`）而库把 nil 当「已认证」；修法：白名单只接受机密客户端，或在 `Introspect` 里自行判定调用方身份。同时把这条要求写进配置注释与文档 |
| **k-V1**（复核新发现） | **轮转之后落地的写入停在退役 KEK 上**：按 `README.md:55` / 配置样例的三步（先轮换 → 删 `vault.retired` → 重启）执行，那些凭据**永久不可读**，而 `-rotate-keys` 报 `{Scanned:1 Rewrapped:1}` 并 **exit 0**。`replicas: 2` + 滚动更新让「还有旧键进程在服务」成为常态 | 复核探针：`after removing the retired key usr_b is permanently unreadable ... although -rotate-keys reported {Scanned:1 Rewrapped:1 AlreadyCurrent:0} and exited 0` | ① 重封装改窄写 + CAS；② `-rotate-keys` 结束时**无条件**告警（`already_current + rewrapped != scanned`）；③ README/配置样例的三步补上运维文档里已有、却不在三步里的那道闸门「确认 `Rewrapped == 0`」与「不要在仍有旧键进程服务时执行」 |
| **k2** | **`-rotate-keys` 用整条 stale 记录 `Put` 写回**：窗口「读完一页到写完该页」内新入册的凭据被**静默回滚**成旧值（`vault/rotate.go:91-137` + `postgres/vault.go:80-94` 无条件覆盖全部列） | 复核**纠正了机制**：那行**仍然可读**（读到旧值），不是原报告写的「AES-GCM 拒绝/永久不可读」；但**静默**比报错更糟，故不降到中低 | 同 k-V1 ①：给 `Repo` 加窄方法（只更 `wrapped_dek`/`kek_id`/`updated_at`）或按 `wrapped_dek` 做 CAS |
| **PERF-2** | 数据面单请求**最坏 80 s**（候选源循环 × 20 s + 刷新 + 401 强制刷新重取），而 `WriteTimeout` 只有 **60 s** ⇒ 客户端拿到断连/半截 body，没有错误体 | 复核**实测**：一个 raw 请求真的 4 次**串行**出站（token→resource→token→resource，484 ms ≈ 4×121 ms）。且 **401 是 4xx，`circuitbreaker.go:76-78` 明文不计入失败 ⇒ 熔断器不兜底**（比原报告说的更严重） | 让总超时大于「候选源数 × 出站期限」的最坏值，或给数据面单独的写超时；把 401 纳入熔断的失败判据 |
| **CS-1** | `/readyz` **同时免限流与免并发上限**，且每请求取一条池连接 ⇒ 匿名可把连接池打满 | 复核降为**中高**并收窄：真进程实测豁免成立、`pgxpool.Ping` 源码确认每请求一次池往返；但「几百并发占满池」只在 DB 往返 ≳1 ms 时成立（同机健康库要 ~10⁴ req/s）。**且修法要当心**：直接「满了回 503」会重新引入 `health.go:69-77` 明确要避免的失败形态 ⇒ 属**裁定** | 给探针单独一个小配额（或在池满时返回上一次的结果而不是发起新往返），并把这份取舍写进 `docs/operations.md` |
| **FO-01** | **归一化资源的 scope 闸门取自「第一个声明该资源的源」，数据却由另一个源提供** | 复核**降为中**并给出理由：读的是受害者**自己绑定**的源上**自己**的数据、`Re0Auth-Source` 是上游协议 MUST。真正该修的是**同一道闸门两个方向都判错**：放行他源数据，同时**拒绝该源自己声明的 scope** | 让判据与 `Fetch` 实际选中的源一致（`result.Source` 参与判定），或要求令牌持有全部候选源的 scope |

---

## 3. 中

| ID | 发现 | 状态 |
|---|---|---|
| **AUD-1** | OP 存储层用 `_ = s.audit.Record(...)` 静默吞掉审计失败：令牌签发/设备批准照做、记录丢失、无错误无日志（vault 是 fail-closed、admin/auth 会打日志，OP 两个方向都没选） | 复核 CONFIRMED（中维持），但把支点从「违反 I3」换成 `audit/audit.go:35-39` 的契约 + 三处已选方向的先例 |
| **AUD-2** | 抹除的最后一步（销毁假名密钥）失败后**不可重试**：账号行与会话都已清，而 500 仍说「可以再试一次」；复核补充**范围应扩到倒数第二步**（`record` 的注释自称可重试也是错的） | 复核：部分成立，限持久化部署 |
| **AUD-V1 / k-V2**（两个复核独立发现同一条） | **`SignOut` 在假名密钥销毁之后写一条带原始 `usr_…` 的 `auth.logout` 审计行**，同一个 sink 会**重新铸一把假名密钥** ⇒ `docs/admin.md:130` 的「销毁后按 subject 过滤返回空页」这条成文承诺不成立，**每次成功的持久化抹除都发生** | 确定性、非竞态；建议单独立条、低-中 |
| **PG-001** | **四条仍在生产调用的**批量撤销谓词没有前导索引（`oauth_codes.client_id`、三张 legacy token 表的 `client_id`）；复核**推翻**了 `docs/architecture.md:757`「无生产调用者」——`main.go:849 legacy: db.Tokens()` + admin/lifecycle 都在用 | 复核：部分成立，**不降级**（并指出原报告有一处计数错误） |
| **PG-V1**（复核新发现） | 真正被执行且无前导索引的活谓词是 **`oidc_auth_requests.client_id`**——**当前引擎**的表，全新部署也会长起来，原报告完全漏了 | 建议 0022 迁移补上 |
| **CS-3** | `trusted_proxies` 接受 `0.0.0.0/0` / `::/0`（唯一让它失效的值恰是没被拦的那个）⇒ 限流桶与日志 `client=` 由调用方自选 | 复核 CONFIRMED（真进程实测伪造 XFF 进了访问日志） |
| **CS-4** | `sources[].token_class` **既不校验也不默认**：`long_live`/`Revocable`/省略/`session` 全部被接受，而 `unbind.go:74` 一律按 revocable 处理 ⇒ 不可撤销的源被报成「已撤销上游」 | 复核 CONFIRMED（真进程三种写法都正常启动；同一枚举在 `upstreamkit/conformance` 却是被校验的） |
| **CS-5** | 设了 `DATABASE_URL` 但无 `[storage]` 段 ⇒ **静默内存模式**（审计链/锚点/自检全无），而警告写的是 `because="no DATABASE_URL"`；且不存在 `RE0AUTH_STORAGE_DRIVER` ⇒ 纯环境部署无法持久化 | 复核 CONFIRMED（真进程复现了那条**错误原因的警告**） |
| **DEP-01** | `scripts/restore.sh` 的 sha256 守卫校验的是 `.sha256` 里记录的**路径**而不是命令行给的文件：异地恢复被自己挡死，而**截断的转储能「校验通过」**进入 `pg_restore` | 复核降为**中**（用真脚本 + 桩工具跑出两向），并追加两条更狠的：**DEP-V1** `.age` 加密路径下校验**一行都不执行**；**DEP-V2** `.sha256` 缺失时校验**静默跳过**（fail-open，其余前提都是 fail-closed） |
| **DEP-V3**（复核） | `release.yml` 推 `latest` → Trivy `--exit-code 1` 在其**之后** → 而 `deployment.yaml:37` 正引用 `latest` ⇒ **未过门禁的镜像成为默认被引用的那一个** | 复核 CONFIRMED |
| **DEP-03 / 04 / 07 / 08 / 09 / 10** | 发布镜像不传 `VERSION` build-arg（报 `version=dev`）；Trivy 阻断发生在 push 之后；备份脚本写出**世界可读**的明文转储（keys 脚本反而有 0600）；`restore.sh` 把明文解密在备份目录不清理；runbook 写的 `[admin].allow` 不是真键（真名 `subjects`，未知键**拒绝启动**）；`runbooks.md`/`slo.md` 称内部监听器「默认 :9090」（实际默认不监听） | 复核逐条 CONFIRMED |
| **DEP-12** | 备份 Pod **无任何标签** ⇒ 不被任何 NetworkPolicy 选中（default-deny 集群上每次转储静默失败）；而 DEP-06 已证「备份停了没有告警」 | 两处静默叠加 |
| **FO-V1 / FO-V2**（复核新发现） | ① 同意面按 **scope** 判「已满足」而数据面按**资源名** ⇒ 同意页可能叫用户连 a、而读取由 b 服务；② 闸门可被**已 retired 的源**决定 ⇒ 退役一个源会静默改变另一个源的授权判据、把在用的令牌打成 403 | 复核 CONFIRMED |
| **PERF-7** | 不透明 bearer 是 compact JWE，解析走 go-jose 通用路径：**97% 的成本与内存都在 JWE**（12 208 B/op vs store 查询 192 B/op）；`op.WithCrypto` 是现成替换缝 | 复核 CONFIRMED（并指出 97% 跨进程基准不可用，应以 B/op 表述） |
| **A-FE-5** | CI 前端依赖审计门是 `pnpm audit --audit-level high`，而树里唯一告警 `cookie@0.6.0` 恰在门槛下 ⇒ **这道门永远不会响** | 复核 CONFIRMED（high=exit 0、low=exit 1；且该包在产物中不可达） |
| **SUP-1** | 内嵌进二进制的 npm 前端代码在 27 个交付文件里**零版权/许可文本**，而 `NOTICE` 只覆盖 Go 模块图 | 复核见 §5 |

---

## 4. 低 / 提示（合并）

- **协议面**：PROTO-5（discovery 为内省广告 `client_secret_post` 而该端点只认 Basic——事实成立，**违反 ADR-0005 第 5 条「只声明真实能力」**，而且方向搞反了：把库的正确值改成了错的）；
  PROTO-6（`prompt=none` 全仓未实现，静默认证被 302 到登录页而非 `error=login_required`；
  复核确认它**不在** O-9 的不做清单里，故是漏实现而非已文档化决定）；
  PROTO-7（`response_mode=form_post` 的授权响应不带 RFC 9207 `iss`，而 discovery 广告支持）；
  PROTO-9（令牌端点只挡 GET、不挡「POST + 查询串」⇒ 凭据仍可进 URL；**更正**：Re0Auth 自己的访问日志**刻意不记 query**，风险落在中间层日志）；
  PROTO-10（userinfo 对没有 `openid` 的令牌也返回 `sub`）；
  PROTO-11（匿名 `/oauth/authorize` 每次分配一条 pending 请求，TTL 30 分钟）。
- **RP 侧**（re0auth 作为 OAuth 客户端）：**RP-1 [高→低，部分推翻]**——`azp` 确实完全不校验，
  但复核用**实际执行**证明「喂给 `/auth/*/callback`」不成立：callback 只读 `state`+`code`，
  id_token 只来自本服务自己那次带 secret+PKCE 的交换 ⇒ 是纵深防御缺口，**不是账号接管**；
  RP-2（JWKS 缓存无 TTL，吊销的签名密钥仍验签）与 RP-3（discovery 端点未钉在 issuer 上）
  维持**中**；RP-4 [中→部分成立]（内置 `microsoft` issuer 必然 discovery 失败，
  但「文档没提」被推翻——`config/re0auth.example.toml:250-254` 给了 `<tenant>` 写法）。
- **Upstream Kit（第三方数据源要运行的公开库）**：**KIT-1 [高→中]**（生成的
  `/oauth/cascade_revocation` 自身不认证；但唯一在仓实现 `referencesource` 在钩子里做了
  机密客户端认证 ⇒ 真问题是「kit 不代认证 + 一致性套件把无认证 cascade 判 PASS」两处）；
  **KIT-3 [高→中]**（`oauth/as.go:253-271` 的 `Introspect` 确实不问 client 状态，
  违反库自己的文档；但仓内唯一调用者 `internal/admin` 暂停时会连带 `RevokeTokens` ⇒ 影响被抵消，
  只剩第三方源 ≤1 TTL 的窗口）。
- **HTTP 边界**：**HE-4**（编码路径下的业务面 404 绕过 `/v1` 层的 `no-store` 与 panic 恢复器；
  复核**独立复现**，并指出根因不是「路由器边界」而是 `writeProblem` 自身不设 `no-store`
  ⇒ **V-1：业务面的 429/413 同样缺 `no-store`**，唯一守卫只走 7 个 200 端点）；
  **HE-9 [推翻]**（审计 `limit` 的钳制**存在**：`postgres/auditread.go:29-35` 钳到 1000，
  原报告读错了被调用层）；**HE-2 [中→低，部分推翻]**（302 **不在** RFC 9110 §15.1 的启发式
  可缓存列表，原报告的缓存影响论断错误；只剩「契约从未覆盖 3xx」这一条）；
  **HE-5 [→已知非发现]**（`account-model.md:124` 已记录 `Path=/`）；
  **HE-8 [低→提示/判断]**（handle 确实 `Bound`+`OwnerMatches` 绑会话，只剩「用户看到没请求过的同意页」）；
  **V-2**（mux 路径清洗制造的 307 会**跨平面**：`/v1/../oauth/token → 307 /oauth/token`，
  且限流/指标按**未清洗**路径算 plane ⇒ 得到协议面的 429 而业务面的桶没动）。
- **并发/内存**：CM-2（三处丢 `ctx`，无观测影响）；**CM-3 [中→低]**（复核用 `-race`
  **造出过真 DATA RACE**（`oidcstore.go:222` vs `memory/oidc.go:940`），但生产唯一持有者
  只取 `GetID()` 就丢指针 ⇒ 可达性被推翻，留作潜在缺陷）；**CM-6 [提示→CONFIRMED]**
  （`auditbatch.enqueue` 在「读 closed」与「入队」之间确有窗口：复核 6 次运行 ≈32 万次调用
  竞速 `Close` 命中 7 次「已接受永不回答」；但装运路径全是请求 ctx ⇒ 严重度维持提示）。
- **Postgres**：PG-003（设备路径用 DB 的 `now()` 判 `expires_at`，而内存后端与 Go 读路径用
  store 时钟；复核降为**低**：`WithClock` 自述只是「让单时钟政策可断言」的注入点，
  同机部署共享内核墙钟，方向在安全一侧 ⇒ 可用性问题）；PG-004（三个 `Sessions` 多写方法无事务；
  复核指出失败并非静默——返回非零 err）；PG-006（抹除静态守卫看不见 `ALTER TABLE ADD COLUMN`
  与 `subject`/`user_id` 以外的命名；但 CI 的动态守卫走 `information_schema` 能覆盖，
  **CI 才是权威**）；PG-007/PG-010 移入「探过没破」。**PG-002 部分成立、机制写错**：
  `Down(ctx)` 传的 version 是 **0**，且 `down()` 在 `runMigrations` **之前**建完整条 apply 列表
  ⇒ 从 6 出发的**那一次**就整体失败、一个版本都没退（原报告说「先退 6，下次退 5 才失败」），
  且 ADR-0008 已把回滚故事定义为备份恢复 ⇒ 降至低-中。
- **性能**：**PERF-3 [→低]**（1 ms 收集窗口与 `64/commit` 天花板复现，但机制与拐点判据
  已写在 `capacity-planning.md:131-139`，`slo.md:59` 的告警本就点名它是串行上限；
  且「每个请求至少等 1 ms」被它自己的饱和数据推翻）；**PERF-4 [→已知非发现，低]**
  （`operations.md:171-182` 已经写了「45 s 也扫不完的规模 → 增量校验点」，
  原报告的修法建议与文档逐字重合；残留价值是实测 **1.34–1.47 µs/行**，阈值约 3×10⁷ 行）；
  **PERF-5 / PERF-6 [→低]**（内存模式专用，而 ADR-0006 决策 6 明确内存模式不承担生产保证；
  PERF-5 的 30 天外推高估 2 倍，且 `Re0AuthMemoryHigh` 告警存在）；
  **PERF-9 [部分成立→低]**（四处文档失真里只有一处成立）；PERF-10/PERF-12 CONFIRMED。
- **前端**：**A-FE-1 [中→低，部分成立]**（shell 无 `ETag`/`Last-Modified` 属实，
  但「CSP 哈希与新构建不匹配 ⇒ 白屏」**结构上不可能**——哈希与内联脚本在同一份文档里；
  `no-cache` 也封住了浏览器路径，残余只在违反 RFC 9111 的中介）；
  **A-FE-2 [中→提示]**（206 半截 shell 复现，但浏览器导航不发 Range、脚本仍是应用自己的、
  响应也带 `no-cache`）；**A-FE-3 [低]**（同意页「显示少于授予」端到端复现，
  但**无数据能力**：userinfo 只回 `{"sub":…}`、id_token 无 name/email；
  **V-1：设备流有独立的第二/第三份同类实现**（`memory/oidc.go:1250,1283-1288`、
  `postgres/oidc.go:1060,1094-1102`）⇒ 只改 `authorization_routes.go:189` 覆盖不到）；
  **A-FE-9 [中→低]**（构建不可复现的数字全对：12 改名 / 13 同名同字节 / 13 位时间戳只在 1/20 分块，
  但两条危害**被实测推翻**：改内容的分块从不保留旧名 ⇒ **不是缓存投毒**；
  缺失资产回 **200 text/html** 而不是 404 ⇒ 剩下的只是「`docs/architecture.md:12`
  写「构建产物可复现」与实际不符」）。
- **依赖/供应链**：**SUP-8 是头条好消息**——`govulncheck@v1.8.0 ./...` 报
  **`No vulnerabilities found.`**，模块图里 5 条通告（x/crypto 3、x/mod 2）**全部不可达**；
  复核**自建对照模块**（`x/text@v0.3.7` + `ParseAcceptLanguage`）拿到 `GO-2022-1059` **可达、exit 3**
  ⇒ 证明工具非空转，并用 OSV API 独立查得同样 5 条。
  **SUP-1 [中，复核钉死且收窄]**：复核用**已发布的 `v0.0.0-rc.3` 归档与二进制**验证——
  二进制里 `__svelte`×7、`__sveltekit`×5、`svelte.dev/e/`×25，而
  `Copyright (c) 2016-2025`、`Permission is hereby granted`、`@license`、SPDX **全为 0**；
  随归档发出的 `NOTICE`（4242 B、42 条 Go 模块）里 `svelte|devalue|npm` 零命中。
  **但两处要更正**：① 「完全没有许可文本」是错的——CSS 与二进制各含 1 处
  `/*! tailwindcss v4.3.3 | MIT License | …`（正对照已证扫描有效）；
  ② 它推荐的修法第 2 步（开 legal-comments 保留）**是空转**——svelte/@sveltejs/kit/devalue
  的 **539 个 JS 文件零 legal comment**，故第 1 步（生成 npm 清单随归档分发）必要且充分。
  该缺陷**已随 rc.3 公开发出、不可回溯** ⇒ 严重度维持中，但性质是「下一个 release 前必修」。
  **SUP-3 [低→提示]**：`uses:` 真值是 **47（46 远程 + 1 本地）而不是 43**，46 个远程全为 40 位 SHA；
  「守卫不存在」过头——base image 那一半**有**守卫（`TestDockerfileBaseImagesArePinned`，实跑 PASS），
  缺守卫的只有 `uses:` 与工具版本两半。
  **SUP-4 [提示] 部分成立**：机制经**执行级**复现（`cp` 全失败仍 exit 0、tar 产出缺 5 文件的合法归档；
  全仓无归档内容断言），但它点名的「给 `NOTICE` 改名」**被推翻**（`archtest/notice_test.go:55`
  会在 tag 门禁先红）——真正会**静默**的是 `LICENSE` / `README.md` / `SECURITY.md`。
  SUP-2（镜像不带 LICENSE/NOTICE，与 deploy-ops DEP-21 同一缺口，应合并）、
  SUP-5（归档与镜像各自构建一次前端 ⇒ 内嵌 SPA 必定不同字节；**是观察不是缺陷**——
  仓库里没有任何「归档 = 镜像」的断言）、SUP-6（发布只由 tag 触发，不校验它是否指向 main 上
  已评审的 commit）、SUP-7（SBOM 未开 `-licenses`，属范围选择，无人声称它承担许可合规）均成立。
- **配置/启动**：CS-6（启动日志**不公布任何一个安全开关**——真进程完整日志里
  `cookie_secure`/`trusted_proxies`/`rate_limit`/`max_in_flight`/`expose_internal`/
  `allow_private`/`introspection_clients`/`reauth` 八项全缺席）；
  CS-7 [中→低]（内部监听器无任何访问日志）；CS-8（drain 时审计批次排空无总时间上界）；
  CS-9（`docs/runbooks.md:27` 让运维检查 `RE0AUTH_DATABASE_URL`，该变量在 `*.go` 里 **0 处**）；
  CS-10（示例配置的 `Environment override` 只覆盖 7 条而代码有 18 个 `RE0AUTH_*`）；
  **CS-2 [中→低，部分推翻]**（「`internal_addr != addr` 只是字符串比较」属实，
  但运维面**始终只在 loopback**；原报告「`curl localhost` 落到运维面」的**方向是反的**）。
- **部署**：DEP-02 [高/HYPOTHESIS，**既不能证实也不能证伪**：`Dockerfile:60` 从构建阶段
  `COPY` Alpine 的 CA bundle，若是符号链接则 scratch 里成悬空链接 ⇒ 全部出站 TLS 失败；
  失败点是**首次登录**。需要一条 `docker run` 才能定论，本机无 Docker]；
  DEP-05 [中→低：空白名单是明写的**有意安全默认**，S5 另有服务内 6h 自校验循环
  ⇒ 是 onboarding 文档缺口，不是缺陷]；DEP-06 [中→低，部分推翻：`pvc.yaml:9-11` 自己写了
  sizing 公式，「必然写满」不成立；「备份停无告警」成立]；DEP-11 [中→低：Makefile 把
  `$(VERSION)` 插进 shell 配方（`make -n` 复现注入），但能推 tag 者本就能构建任意树
  ⇒ 真正的问题是工作流里那条「已经防住」的注释是**假的**]；DEP-13/14/15/16–28：
  低严重度九条经抽查**没有一条是错的**。

---

## 5. 复核推翻了什么（这一节决定上一节有多可信）

**这是本轮最该被记住的一节。** 12 个复核代理里有 11 个都在「证伪」这件事上真的动了手：

| 原判定 | 复核后的判定 | 关键依据 |
|---|---|---|
| PROTO-1/PROTO-4 「高」 | **维持** | 复核者把机制逐行核对无误，并确认两者**都不是已记录边界** |
| RP-1 「高：azp 不校验 ⇒ 账号接管」 | **低，部分推翻** | 实测：callback 只读 `state`+`code`，id_token 只来自本服务自己那次带 secret+PKCE 的交换；带真 nonce 的伪造令牌 → `303 /?error=identity_failed` |
| KIT-1 「高：任何人可摧毁上游会话」 | **中，部分推翻** | 唯一在仓实现 `referencesource/cascade.go:48` 在钩子里做了机密客户端认证 |
| KIT-3 「高：暂停/删除后令牌仍能读数据面」 | **中，部分成立** | 仓内唯一调用者 `internal/admin` 暂停时连带 `RevokeTokens`（已有测试断言） |
| CM-1 「高：持久化部署里内存锁横跨 DB 往返」 | **低，影响叙说被推翻** | memory store 与 `postgres.AuditLogger` 在同一部署里**互斥**（`main.go:1170-1198` 单一分支）——那是一种**类别错误** |
| CM-4 「高：无界增长」 | **低** | 峰值 = 到达率 × 30 min TTL，**有界**（实测 TTL 后 5000/5000 被 janitor 清空）；内存模式是文档写明的开发形态 |
| CM-5 「注释写反了 / 淘汰是漏洞」 | **低** | 注释没错；删桶只会**放宽**、永不误拦；换 key 绕过限流根本不需要淘汰 |
| k2 「覆盖后永久不可读」 | **中高，机制被推翻** | 那行**仍然可读**（读到旧值）——是**静默回滚**，不是不可读。静默更糟，故不降太多，但论证必须删掉 |
| k3 「半途失败 = 永久丢失」 | **低** | 保留两把 KEK **重跑收敛**（实测 `{Scanned:3 Rewrapped:2 AlreadyCurrent:1}`），且 `runbooks.md:164` 已写处置 |
| PG-003 「两个时钟裁决」 | **低** | `WithClock` 自述只为「让单时钟政策可断言」；同机部署共享内核墙钟；方向在安全一侧 |
| PG-005 「拼接 where 有风险」 | **不是发现** | 未导出 + 3 个调用点全是常量 |
| PG-002 「先退 6、下次退 5 才失败」 | **机制写错** | `Down(ctx)` 传 version=**0** ⇒ 那一次就整体失败、一个版本都没退 |
| PERF-1 「128 → 708 MiB」 | **数字配错，真实更糟** | 出厂是 **512** ⇒ **2834 MiB ≈ 5.5×**；且无 `GOMEMLIMIT` |
| PERF-3 「每个请求至少等 1 ms」 | **低** | 机制与拐点判据**已写在文档里**；标题被它自己的饱和数据推翻 |
| PERF-4 「1e7 行起不可能完成」 | **已知非发现** | `operations.md:171-182` 已给出同一个修法；标题与自己的表冲突 |
| HE-2 「302 会被启发式缓存」 | **低，部分推翻** | 302 **不在** RFC 9110 §15.1 的可缓存状态列表里（复核取回了原文） |
| HE-9 「审计 limit 无上限」 | **推翻** | `postgres/auditread.go:29-35` 钳到 **1000**，`:83` 用钳制值——原报告读错了层 |
| HE-6 「POST 到 mux 得 405 problem+json」 | **部分推翻** | 实测是 404 协议面 OAuth JSON；52 条 405 逐条归类无一是 mux 写的 |
| A-FE-1 「陈旧 shell 白屏」 | **低** | 「CSP 哈希与新构建不匹配」**结构上不可能**：哈希与内联脚本在同一份文档里 |
| A-FE-9 「缓存投毒」 | **低，两条危害被推翻** | 改内容的分块从不保留旧名（3 次构建 0 例）；缺失资产回 **200 shell** 而非 404 |
| AUD-5 「销毁与并发写入竞态」 | **低，部分推翻** | `Destroy` **确实驱逐缓存**（`auditpseudo.go:183-185`） |
| AUD-3 「谁同意了不知道」 | **低-中，部分成立** | approver 恒等于 subject（`authorization_routes.go:160`）；真缺口是 scope 集与拒绝无痕 |
| CS-1 「高」 | **中高，收窄** | 「几百并发占满池」只在 DB 往返 ≳1 ms 时成立；且修法要当心重新引入已被避免的失败形态 |
| CS-2 「中」 | **低，方向被推翻** | 运维面**始终只在 loopback**；「`curl localhost` 落到运维面」实测方向相反 |
| CS-7 「中」 | **低** | 纯取证缺口，前提是先能到 9090 |
| DEP-01 「高」 | **中** | 用真脚本 + 桩工具跑出两向；但「半库后锁死」已被 `operations.md:63` 文档化，补救是一条 DROP |
| DEP-05/06/11 「中」 | **低** | 见 §4；`pvc.yaml` 自己写了 sizing 公式；`$(VERSION)` 注入不构成越权 |
| FO-02 「中」 | **提示｜已知（非发现）+ 证据不成立** | 「跨实例 refresh 残余」是简报明列非目标；其探针在 CAS **输掉**的分支上触发（实测 `won=false`、密钥未变） |
| FO-03/04 「低」 | **部分成立→更弱** | 本机实测 `0/8` 不可路由；键碰撞在启动即被拒 |
| SUP-1 「完全没有许可文本」 | **实质成立，表述错** | 用**已发布的 rc.3 二进制**钉死「无版权/许可声明」，但 CSS 与二进制各含 1 处 tailwindcss MIT banner ⇒「完全没有」不成立；且它推荐的修法第 2 步是空转 |
| SUP-3 「43 处 uses，无守卫」 | **提示，两处错** | 真值 47（46 远程全 SHA）；base-image 那一半**有**守卫且实跑 PASS |
| SUP-4 「给 NOTICE 改名会静默发出去」 | **部分推翻** | `notice_test.go:55` 会让 tag 门禁先红；真正静默的是 LICENSE/README/SECURITY |
| 「无 cgo、`-race` 跑不了」 | **推翻** | CGO_ENABLED=1 + gcc；复核者整包 `-race` 通过，并用**故意注入的竞态**证明检测器活着 |

**方法学结论**：如果这一轮只跑区域审计、不做复核，报告里会多出至少 **30 条错误的严重度判定**
和 **3 条完全错误的技术机制**（k2 的不可读性、PG-002 的退化路径、HE-9 的缺失钳制）。
复核不是礼节，是**产出的质量要件**。

---

## 6. 复核过程中新发现的（20+ 条里最要紧的）

1. **k-V1 [高]**：轮转之后落地的写入停在退役 KEK 上，而**文档的三步顺序**恰好会导致「先轮换、
   紧接着删掉退役键」⇒ 永久不可读，同时报成功 exit 0。**不需要窄窗口、不需要同一行**。
2. **PG-V1 [中]**：`oidc_auth_requests.client_id` 是被执行的活谓词且无前导索引——
   **当前引擎**的表，全新部署也会长起来（原报告漏了）。
3. **AUD-V1 / k-V2（两个复核独立命中同一条）**：`SignOut` 在假名密钥销毁**之后**写带原始
   `usr_…` 的审计事件，同一 sink **重新铸一把假名密钥** ⇒ 文档承诺的「销毁后过滤返回空页」不成立。
4. **HE-V1 [低]**：业务面的 **429/413 同样缺 `no-store`**（`writeProblem` 自身不设），
   根因不是「路由器边界」，唯一守卫只覆盖 7 个 200 端点。
5. **HE-V2 [提示]**：mux 路径清洗制造的 307 会**跨平面**（`/v1/../oauth/token → 307 /oauth/token`），
   且限流与指标按**未清洗**路径归 plane。
6. **CM-V1 [被低估]**：限流按 `/128` 分桶（`clientaddr.go:23-36` 用 `addr.String()`）⇒
   **单个 IPv6 /64 主机即等价于「N 个地址」**，键空间放大从「需要僵尸网络」变成单机可触发。
   （与 HE-V3 同源。）
7. **DEP-V1 / DEP-V2 [中]**：`.age` 备份路径下校验守卫**一行都不执行**；
   `.sha256` 缺失时校验**静默跳过**（fail-open，而其余前提全是 fail-closed）。
8. **DEP-V3**：`latest` tag + Trivy 失败在其之后 + `deployment.yaml` 引用 `latest`
   ⇒ **未过门禁的镜像成为默认被引用的那一个**。
9. **FO-V1 [中]**：同意面按 scope 判「已满足」、数据面按资源名 ⇒ 同意页可能与实际服务源不一致。
10. **FO-V2 [中]**：闸门可被**已 retired 的源**决定 ⇒ 退役一个源会静默改另一个源的授权判据。
11. **A-FE-V1 [低]**：设备流有**独立的第二/第三份**「显示少于授予」实现 ⇒ 只改一处覆盖不到。
12. **PERF-V4**：401 是 4xx、熔断器明文不计数 ⇒ **80 s 最坏值不会被熔断兜住**（PERF-2 加强）。
13. **PERF-V7**：`Verify` 的实际阈值约 **3×10⁷ 行**，不是原报告写的 10⁷。
14. **PERF-V1**：出厂 `max_in_flight = 512` ⇒ **2834 MiB**（同时修正 PERF-1 与 PERF-9a）。
15. **PERF-V6**：`TestMemStoreSweepStallsConcurrentRequests` 的 `worst` 从不重置
    ⇒ 该探针**结构上不可能失败**（一个假守卫，应当修）。
16. **CS-V1 [提示]**：`0.0.0.0:P` 在 Go/Windows 实际绑成 `[::]:P` ⇒ 按 IPv4 CIDR 写的控制
    不覆盖 IPv6 通配。
17. **V-5（联邦复核）**：`docs/upstream-protocol.md:188-189` 宣称存在「下游 scope ↔ canonical
    scope 映射表」，实现里没有。

---

## 7. 探过但**没**破的（安全姿态的正面结论，共 200+ 条，摘最要紧的）

- **协议面**：redirect_uri 精确匹配（复核另用 13 个新变体：`cb/../cb`、`client.example./cb`、
  `CB?`、`CB#`、`cb;x=1`、`%00`、制表符……全部 400 且不重定向）；授权码生命周期与单次使用；
  刷新**不能**提权（10 个变体）；PKCE 常数时间比较；`code_challenge_methods_supported=["S256"]`；
  JWKS 无私钥材料且 `kid` 一致；令牌 JWE 抗篡改与轮换契约；`userinfo` 的反空转对照。
- **限流**：**默认姿态完全正确**——主代理独立实测：伪造 `X-Forwarded-For` **不能**换桶，
  固定与轮换 XFF 两轮突发都在**第 101 个请求**开始 429（`rate_limit_burst = 100`）；
  并发 1920 请求 shed 1523；429 的形状两面都对（业务面 `application/problem+json` +
  `code=rate_limited`，协议面 `{"error":"temporarily_unavailable"}`，都带 `Retry-After: 1`）。
  探针路径与拉满的 `max_in_flight` 都不影响探针（`isProbe` 在桶之前判断）。
- **协议面无 CORS**：带 `Origin: https://evil.example` 的 GET 与 `OPTIONS` 预检**没有任何
  `Access-Control-Allow-*` 头**，与 ADR-0011 一致（`Vary: Origin` 是库留下的痕迹，没有 ACAO 就无授权）。
- **启动期配置校验全部 fail-closed**（主代理真进程实测，退出码 1、消息精确）：
  四个必需密钥各自缺失即拒绝；KEK 与 token key 非 32 字节拒绝；
  **1024 位 RSA 拒绝**（`signing key must be at least 2048 bits, got 1024`）；
  非 PKCS#8 的签名密钥拒绝；`internal_addr == addr` 拒绝；`internal_addr` 绑非 loopback
  而未 `expose_internal=true` 拒绝；`trusted_proxies` 非法条目拒绝；非法 TOML 拒绝并给出精确行列；
  **没有配置文件时进入 environment-only 模式**（README 第二种快速开始形式成立）；
  `-version` 打印 `re0auth dev`；`-print-secret-env` 在无配置时明确报错而不是猜。
- **运维面在公网面完全不可达**（主代理实测：`/metrics`、`/debug/pprof/` 在公网端口 404，
  在内部端口正常；`/healthz` 反之）。
- **安全响应头**：每个响应都带 `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、
  `X-Frame-Options: DENY`、`Content-Security-Policy: frame-ancestors 'none'`；
  前端 CSP 是两层（头只发 `frame-ancestors`，meta 发 hash 版 `script-src`，无 `unsafe-inline`/
  `unsafe-eval`，`base-uri`/`form-action`/`object-src` 全 `'none'`），
  且复核用**真 Chromium**（含 `bypassCSP` 对照）验证注入被拦、应用 0 违规、67 个 e2e 通过。
- **业务面每一个响应都 `no-store`**（`withNoStore` 挂在平面上而不是逐个 writer 上）。
- **前端**：全 `web/**` 只有 1 处 `{@html}` 类命中且是注释；注入探针在真浏览器里不成标记、不执行；
  产物里 `console.log`/`debugger`/`sourceMappingURL`/`localhost`/`@vite`/密钥形状 **全部 0 命中**
  （21 条正则 + **阳性对照 21/21**）；13/13 写端点都带 CSRF；20 个 JS 分块从 shell 出发全部可达。
- **并发**：授权码/refresh 轮换/`device_code` 消费在**真实 goroutine 竞态**下仍是单次使用；
  并发设备批准至多一人胜出；并发 Kill Switch 幂等；四个后台循环都随 ctx 返回且 ticker 全部 `Stop`；
  生产代码无「循环里的 `time.After`」；未发现锁序倒置；`vault.Use` 不跨锁回调；
  指标标签基数有界；出站响应体全部关闭。整套 `-race -p 1` **无 DATA RACE**。
- **密码学**：AAD **双向**绑定身份（交换两行必失败）；`recordVersion` 只进 AAD 且**没有**任何
  按版本分支 ⇒ 不存在降级面；两层 nonce 各 512 次无重复；`kek_id` 只在启动构造的 map 里选
  ⇒ 能写库者无法指向自控密钥；OP 双密钥重叠轮换与 §6.0.1 逐条一致；`CompositeCrypto` **不按 kid 查表**
  ⇒ 无解密预言机；`kid` 冲突与 1024 位签名密钥全被 `ValidateSigner` 拒；
  审计 canonical 长度前缀无歧义、`detail` 键排序与项数被承诺、时间戳微秒一致、
  三个域分离 label 互不为前缀且不可跨用途互换、HMAC key 无第二用途；
  `user_code` = 20⁸ = **34.575 bit**（出厂限流下单地址 60 s P=1.2e-07、全 TTL 1.2e-06，
  要 1% 需 ≈8505 个地址，而限流 map 上限 10000）；会话/CSRF/state/授权码/设备码/用户名 id
  全部 `crypto/rand` 且传播错误；常量时间比较该用的一处不缺。
- **Postgres**：17 处 SQL 拼接逐处复核**全是编译期常量**（无请求值入 SQL）；
  refresh/bind-flow/device/授权码四处单次使用都是 **DELETE-first 认领**（未发现读后写）；
  `FOR UPDATE`、`UNIQUE`+`23505` 映射、审计链头串行化均成立；**29 处 `RowsAffected()` 无 fail-open 形状**；
  Down 段表/索引自洽；advisory lock 在 panic/ctx 取消下仍释放；池参数全部到达驱动。
- **依赖**：`govulncheck` 报**无可达漏洞**（模块图 5 条通告全不可达）；
  SBOM 与发布二进制的模块集**精确相等 42 = 42**；`NOTICE` 与 Linux 构建图 **42 = 42**
  且 `TestNoticeCoversTheBuildGraph` 实跑 PASS；`go mod verify` 通过；
  全仓无 `GOFLAGS`/`GONOSUMDB`/`GONOSUMCHECK`/`GOPRIVATE`/`GOINSECURE`；工具链 1.27.1 与 CI/镜像一致。
- **部署**：CI 里本地可查的一半**全绿**（10/10 fuzz 目标存在、`cmd/covertable`、
  `TestLoadProfile`、`go vet` exit 0、被跟踪文件 `gofmt` 干净、`rc.3` tag 在）；
  43 处 `uses:` 今天都钉了 SHA；`from:scratch` 非 root；基础镜像按 digest 固定。

---

## 8. 未能到达（残余盲区，必须如实写）

1. **一切 Postgres 运行时语义**：无 Docker / 无本地库 ⇒ 索引是否真被使用、事务隔离、
   `FOR UPDATE` 行为、`statement_timeout` 的实际效果、`-migrate-down` 的报错文本，
   全部只有读码级证据。**权威验证在 Linux CI**（`ci.yml` 自带 `postgres:16`）。
   特别地，**`TestMigrateDownRollsBackOneStep` 在 CI 里现在是红还是绿没有闭合**，
   而它决定 PG-002 是否还要再降一级。
2. **容器/镜像层语义**：DEP-02（Alpine CA bundle 是否符号链接）既不能证实也不能证伪；
   镜像 digest 内的 Go/Node/Trivy 版本、cosign 行为、Trivy 实际扫描结果、kustomize 的 API 校验、
   CNI 是否真实现 NetworkPolicy —— 全部需要 Docker 与集群。
3. **真实发布链路**：没有真 tag、没有 `cosign`、没有网络 ⇒ `SHA256SUMS` 的覆盖面只在脚本层确证。
4. **真实上游**：联邦数据面的探针全部用 stub Doer；真实 TapTap/LeanCloud 方言、真实
   跨实例 refresh 交错、真实双进程时序未跑。
5. **Linux 特定行为**：`0.0.0.0/8` 是否路由到本机回环（Windows 上实测不可路由）、
   同一端口两次 bind 的内核语义、IPv6 通配的实际覆盖。
6. **浏览器/中介层**：只有 Chromium 1243 一个引擎；「违反 RFC 9111 的中介缓存陈旧 shell」
   只能在真代理（nginx/企业代理）上测。
7. **绝对性能数字**：本机同时有 10+ 个审计代理在跑 ⇒ 报告里的**吞吐/延迟绝对值不可引用**；
   可引用的是**每操作分配量**（与负载无关）与复杂度类。

---

## 9. 判断（文档化决定，值得重新裁定——不是缺陷）

1. **`max_in_flight` 的标定方式**：文档里 512 与 128 两个数并存（`capacity-planning.md` §0 表 vs §4），
   而出厂配置是 512。上线前应给它一个**与内存 limit 挂钩**的推导，而不是两个互相矛盾的常数。
2. **`/readyz` 的豁免**：代码注释解释了「探针不能被限流拖死」的理由，
   而那正是让它可以被匿名打满池的原因。这是一个**取舍**，需要写进 `docs/operations.md`
   并给出「探针该多贵」的裁定。
3. **跨引擎的同意面一致性**：`authorization_routes.go`、`memory/oidc.go`、`postgres/oidc.go`
   各有一份「显示少于授予」的实现（A-FE-3 + A-FE-V1）。要么定义「协议 scope 不算权限」
   并让**所有**展示层一致，要么把 `openid`/`profile`/`email` 从展示集里明确排除。
4. **KIT-1 的正确表述**：应写成「kit 不代认证 + 一致性套件把无认证的 cascade 判 PASS」两处，
   而不是「kit 生成了一个任何人都能打的毁灭性端点」——后者对唯一在仓实现不成立。
5. **`azp` 与 JWKS 缓存**：RP 侧的这两条是**依赖库/上游 IdP 的属性**，
   项目能做的只是加固。建议记入 `docs/dependencies.md`。
6. **`-migrate-down` 的前置条件**：ADR-0008 的 expand/contract 只约束正向；
   建议明确写「`-migrate-down` 的前置是已摘除流量」。
7. **`docs/architecture.md:12`「构建产物可复现」**：与实测不符（A-FE-9）。
   要么实现可复现构建（把 SvelteKit 的 `version.name` 钉成 git rev / BUILD_ID），
   要么改这句话——它正被 SBOM/checksums 的论证引用。

---

## 10. 上线前检查清单（可执行，按顺序）

**必须做（阻断级）**
1. 修 `SetUserinfoFromScopes`（两个 store，各一行），**同一提交**里关掉 `/oauth/userinfo`
   对 JWS 形状 bearer 的接受，并让 userinfo 检查令牌是否活着（PROTO-2 / 3 / 3b，B-1/B-2）。
2. 给「在途请求数 × 响应体上限」一个联合预算，重标 `max_in_flight`，设 `GOMEMLIMIT`（B-3）。
3. 分桶键不再包含调用方写的值；桶满时 fail-closed 而不是淘汰活桶；
   并在 `docs/operations.md` 写明「反代必须覆盖 XFF」（B-4）。
4. 修 `requestParams` 吞错 + scope 闸门改查全部值（PROTO-1）。
5. 内省白名单只接受机密客户端（PROTO-4），并把这条要求写进配置注释与文档。
6. KEK 轮换文档补上「确认 `Rewrapped == 0`」与「不要在旧键进程仍在服务时执行」，
   并给 `-rotate-keys` 加退出时的混合状态告警（k-V1 / k2）。

**强烈建议（高/中，越早越好）**
7. 修 `scripts/restore.sh` 的校验绑定与 `.age` 路径、`.sha256` 缺失时的 fail-open（DEP-01/V1/V2）。
8. Trivy 阻断挪到 `push` 之前；`deployment.yaml` 不要引用 `latest`（DEP-V3/DEP-04）。
9. 补 0022 迁移：`oidc_auth_requests.client_id` 与四条 legacy 撤销谓词的前导索引（PG-V1/PG-001）。
10. OP 存储层不再吞审计失败（AUD-1）；`SignOut` 在抹除后不要写原始 subject（AUD-V1）。
11. 让数据面的总超时大于最坏串行出站之和，并把 401 纳入熔断（PERF-2）。
12. 让 scope 闸门与 `Fetch` 实际选中的源一致（FO-01），并让同意面的「已满足」判据与数据面同源（FO-V1）。
13. 给 `sources[].token_class` 加校验与默认值（CS-4）；拒绝 `0.0.0.0/0` / `::/0` 的
    `trusted_proxies`（CS-3）；修正 `DATABASE_URL` 存在时的启动警告文案（CS-5）。
14. 启动日志公布八项安全开关的**生效值**（CS-6）。
15. 修 runbook 里的 `[admin].allow` → `subjects`、`RE0AUTH_DATABASE_URL` → `DATABASE_URL`、
    内部监听器「默认 :9090」→「默认不监听」（DEP-09/10、CS-9）。

**文档一致性（一次改完）**
16. `claims_supported: ["sub"]` 与 id_token 的实际内容对齐（B-1 修好后自然成立）。
17. `capacity-planning.md` 的 `max_in_flight` 与内存模型两处失真；
    discovery 的 `client_secret_post`（PROTO-5）；`upstream-protocol.md:188` 的映射表（V-5）；
    `dependencies.md:121-125` 的「archtest 守着 action pin」；`architecture.md:12` 的「可复现」；
    `admin.md`/`api-design.md` 缺 `rotate_secret` 与 `/v1/admin/audit/head` 两条路由。

---

## 11. 文件与守卫

**报告**（每份都含「探过没破」与「未能到达」两节）：
`docs/audit-5/findings/` 下的
`protocol.md`、`http-edge.md`、`crypto-keys.md`、`postgres.md`、`concurrency-memory.md`、
`federation.md`、`admin-audit-privacy.md`、`frontend.md`、`deploy-ops.md`、`dependencies.md`、
`performance.md`、`config-startup-disclosure.md`、`_main-runtime-findings.md`，
以及对应的 12 份 `*-VERIFIED.md`（对抗性复核）。

### 探针放在 `audit5` 构建标签之后（重要）

本轮新增了 **92 个探针文件**（`internal/zzprobe/**` 22 个包、`internal/httpapi/zzprobe_*.go`、
`internal/store/postgres/zzprobe_*.go`、`internal/ratelimit/zzprobe_*.go`、
`cmd/re0auth/zzprobe_*.go`、`vault/zzprobe_*.go`、`oauth/zz_probe_test.go`）。
**它们全部带 `//go:build audit5`**，因此：

```sh
go build ./... && go vet ./... && go test ./...      # 33 个包全绿（探针被排除）
go test -race -p 1 ./...                             # 同样全绿，无 DATA RACE（已实跑）
go test -tags audit5 -count=1 ./internal/zzprobe/... # 红 —— 这就是证据
```

**为什么这么做**：这些探针就是发现的证据（本项目规矩：一条发现必须有一条会失败的测试），
但把它们留在默认套件里会让 `go test ./...` 与 CI 立刻变红，挡住所有其它改动。
加标签后：默认套件**恢复全绿**，一条证据都没删，一个标志就能跑全部对抗用例。
**回退方式**：探针文件全部是**未跟踪**的新文件，`git status` 里以 `??` 出现；
若要彻底移除，删掉 `internal/zzprobe/`、各包内的 `zzprobe_*_test.go` / `zz_probe_test.go`
与 `internal/zzprobe/*/doc.go` 即可（`doc.go` 是空包占位，用于让排除标签后包仍然存在）。

**当前为红（即其钉住的缺陷仍在）的探针**：PROTO 区 8 条、admin 区 4 条、concurrency 区 3 条、
crypto 区 2 条、dependencies 区 3 条、federation 区 4+3 条、pgstore 区 2 条。修好一处就绿一条。

**已知有缺陷的探针（不要当成发现）**：`internal/zzprobe/federationhttp` 的
`TestZZProbeKillSwitchRequiresAnOperator` 断言 401 而实际是 404 —— 复核已指出它与报告正文
及 `docs/admin.md` 都矛盾（未带会话访问未挂载的 admin 面就是 404）。收作守卫前必须先修它。

### 未修改任何被跟踪文件

复核前后 `git diff --stat` 逐字一致，只有**审计开始之前就已存在**的 8 个改动：
`CHANGELOG.md`、`internal/federation/unbind.go`（+test）、`internal/httpapi/{server.go,bind_test.go,plane_test.go}`、
`internal/oidchttp/{oidchttp.go,adversary_test.go}`。
`gofmt -l .` 干净，`go vet ./...` 干净。
`internal/webui/dist` 与 `config/*.local.toml` 都被 gitignore，构建与本地配置没有污染树。

**流程说明（如实记录）**：审计期间共享简报 `docs/audit-5/BRIEF.md`
被某个代理误删过一次（由主代理重建，此后 3 个复核者报告它缺失）；
有一个代理的探针曾短暂引入非法 UTF-8 使 `internal/httpapi` 整包不可编译（约 10 分钟内被本人修好），
这直接导致两次 `-race` 运行报 `build failed`；另有一个代理向
`internal/store/postgres/postgres.go` 加过一行仅供探针使用的导出 `MigrationsFS()`，
经指出后已改为直读磁盘上的迁移 SQL，该文件现与 `HEAD` 逐字节一致。
这些都不影响结论，但它们是「12 个代理共用一棵工作树」的真实代价——
下一次应当给每个代理一份独立的 worktree 或 `git worktree` 副本。

