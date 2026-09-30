# 变更记录

> 这份文件记录**部署者与下游需要知道的变化**：破坏性变更、配置/密钥/迁移上的影响、协议面
> 行为的改变、以及操作性要求的变化。逐条提交级细节不在这里——那由提交历史（Conventional
> Commits，破坏性变更带 `!`）与每个 tag 的 release notes 承担；**为什么**这么改记录在
> `docs/*-decision.md` 的 ADR 里。升级步骤见 [docs/operations.md](docs/operations.md)
> 的「升级」一节，它的第一步就是先读这里与受影响的 ADR。

## v0.0.0-rc.4

**本轮把 P0/P1 全部收掉，并把 P2 分级里 T1（「不修上不了线」）的 9 条一并收掉**
（逐条与守卫见 [docs/issues/P0-blockers.md](docs/issues/P0-blockers.md)、
[docs/issues/P1-high.md](docs/issues/P1-high.md)、[docs/issues/P2-triage.md](docs/issues/P2-triage.md)）。
下面先列部署者/下游必须知道的变化，其后是自 rc.3 以来累积的条目。

> 与 rc.3 一样，rc.4 验证的仍是 **tag → CI → 产物** 这条链路，**不是可以部署的版本**：
> rc.1 一节列出的适用条件全部成立。另需记录在 release notes 里的一条：rc.3 已公开的归档中
> Svelte/SvelteKit 代码缺少版权/许可声明（第五轮 SUP-1），**已发出的产物无法回溯**；自 rc.4 起
> 归档随附 `re0auth_<ver>_npm-attribution.json` 许可清单（`make npm-attribution`，
> 与 `SHA256SUMS` 一同发布，见本节 P2-21 条）。
>
> **发布动作（两步，顺序不能反）**：① 在 `main` 上打 `v0.0.0-rc.4` 并推送——`release.yml` 以
> `ci.yml` 为门禁，门禁过了才发布产物；② 随后用**单独一次提交**把 `deploy/k8s/base` 的 pin 与
> [docs/operations.md](docs/operations.md) 的「最近一个真正发布过的 tag」换到 rc.4。pin 有守卫：
> `internal/archtest` 要求它指向仓库里**真实存在**的 `v*` tag，所以第二步必须等 tag 推上去之后
> ——rc.3 就是这么换的（提交 `632e00b`），rc.1 一节的教训也在这里。

### T1 · P2 分级里「不修上不了线」的 9 条（`17914d4`）

- **刷新签发的 id_token 现在保留原 `nonce`（OIDC Core §12.2，G-9）**：此前刷新请求不是
  `op.AuthRequest`，库读不到 nonce，任何校验 nonce 的 RP 每次刷新都失败。现在 refresh 行
  持久化原 nonce 并随轮换继承，`SetUserinfoFromRequest` 把它写回 id_token。**升级影响**：
  新迁移 `0026` 给 `oidc_refresh_tokens` 加 `nonce`（存量行与设备流为空串，行为不变），
  启动时自动执行。**行为变化**：刷新返回的 id_token 带上认证时的 nonce——这是 RP 期待的
  形状；不检查 nonce 的 RP 无感。
- **`jwks_uri` 绑定 issuer（Z14-3）**：验证 id_token 用的密钥集此前完全取自 discovery 文档，
  能左右 discovery 的一方可用自控私钥伪造任意 `sub`。现在 discovery 里的 `jwks_uri`
  默认必须与 issuer 同源；确实把密钥集放在别的源的提供方要么用内置（Google 已内置
  `www.googleapis.com` 的真值），要么显式配置新增的 `[idp.*] jwks_uri`，此时要求与文档
  完全一致。**行为变化**：跨源密钥集而**未**配置 `jwks_uri` 的自定义 IdP 会 fail-closed
  拒绝登录并给出可操作的错误，而不是静默沿用文档里的值。
- **审计链的 0013/0014 不可再被回退（Z21-2 / Z21V-1）**：这两步的 `Down` 现在不执行任何
  DDL——旧 Down 会让历史行哈希变 NULL、链头回创世，而 `Verify` 仍报 `OK=true`（0014 则是
  丢掉唯一的每账号假名密钥）。`postgres.MigrateDown` 在链上已有 `row_hash IS NOT NULL` 的
  行时直接拒退并提示恢复备份；为兼容 goose 对空 Down 也会删版本行的行为，两者的 `Up`
  已幂等化（`IF NOT EXISTS` + 链头 `ON CONFLICT DO NOTHING`，保留真实链头）。ADR-0008 增 §5。
  **升级影响**：无新迁移；`-migrate-down` 在正常库上会在这两步之前被拦住，这是预期。
- **运行镜像随附 npm 归属清单（Z13-3）**：`/npm-attribution.json` 进镜像，和归档里的
  `re0auth_<ver>_npm-attribution.json` 是同一次 `pnpm licenses list --json` 的产物；
  发布门禁开始读 `Dockerfile`。
- **仓库与构建上下文不再包含备份产物与审计工作区（Z13-1 / Z13V-1）**：`.gitignore` 与
  `.dockerignore` 补 `/backups/`、`*.dump`、`*.env`、`scratchpad`、`go.work*`、`*.local.toml`
  等。**行为变化**：默认落点 `./backups` 下的文件不再被 `git add -A` 暂存；审计工作区
  不再进 `docker build` 的上下文。
- **密钥/凭据不再进日志（Z12-1 / Z19-1 / Z19V-1 / k1）**：退役 token/signing key 解析失败、
  `*_env` 名字位被塞入值、`dsn_env` 的 DSN 解析失败、`trusted_proxies` 的自由文本、`kek_id`
  冲突、以及抹除后会话清理失败——这些错误现在只报**字段与位置**（条目下标 / `request_id`），
  不再回显配置或密钥原文。**行为变化**：启动日志里这些错误的文案不再带变量名或值，
  排障时以字段名 + 手上的配置文件定位。

- **refresh 重放即撤销整条令牌族（RFC 9700 §4.14.2，P0 G-1）**：此前重放一个已轮换的 refresh token
  只被拒，小偷已换出的那一代继续有效到 TTL 结束。现在轮换在被消费的行上留墓碑（族标识 + 配对
  access 的 id），读路径命中墓碑即在一个事务里撤销该族全部 refresh 与 access，然后仍按
  `400 invalid_grant` 拒绝。检测必须落在读路径，是库的调用顺序决定的
  （`TokenRequestByRefreshToken` 先于轮换被调用）。
  **升级影响**：新迁移 `0024` 给 `oidc_refresh_tokens` 加 `family_id`（存量行回填为自身
  `token_hash`，即「各自成族」，与既有行为一致）并建墓碑表，启动时自动执行。**行为变化**：
  检测到重放后，该族里先前仍可用的 access token 也会立即失效——这正是本条的目的。

- **Postgres 后端开始裁决 refresh 的过期（P0 G-2）**：refresh 读路径与轮换声明此前都没有
  `expires_at` 谓词，30 天 TTL 只由 15 分钟一轮的 sweep 执行（sweep 连续失败则窗口继续延长）；
  两处现在都按 store 时钟 `$n` 判定，与内存后端同形。**行为变化**：过期 refresh 不再能换出新的
  30 天令牌对，不再依赖 sweep。

- **RFC 7009 撤销在数据库故障时不再回答 200（P0 G-3 / G-13）**：`RevokeToken` 的三个属主查找
  此前以 `err == nil` 为进入条件，任何库错误（断连、故障切换、`statement_timeout`、ctx 取消）
  都落穿成「未知令牌即成功」且不写审计；`GetRefreshTokenInfo` 把同样的错误折叠成
  `invalid_grant`，使库的 5xx 分支不可达。现在只有 `pgx.ErrNoRows` 算「未知」，其余如实返回
  `server_error`。**行为变化**：库故障时撤销端点会失败（客户端应按 RFC 7009 重试），而不是
  谎报成功。

- **公开库 `oauth` 的破坏性变更（仅影响直接实现 `oauth.Store` 的代码）**：新增族谱与墓碑——
  `AccessToken`/`RefreshToken` 增加 `FamilyID`；新增 `ErrRefreshTokenReused` 与
  `*RefreshReuseError`；`ConsumeRefresh` 现在必须把「已被本店消费过」的值报成
  `*RefreshReuseError`（而不是 `ErrTokenNotFound`），并保留被消费值的族归属（墓碑）；新增
  `RevokeRefreshFamily(ctx, familyID)` 与只读 `GetCode(ctx, value)`。服务侧同时收掉两条同形缺陷：
  刷新的归属在消费**之前**判定（此前他方客户端可把持有者的 refresh 一次性烧掉），授权码先读、
  校验全部绑定、通过后才原子消费（失败的兑换不再烧码，并新增 `oauth.exchange_failed` 审计）。
  **升级影响**：第三方 `oauth.Store` 实现需补 `RevokeRefreshFamily`/`GetCode` 并承担
  `ConsumeRefresh` 的新义务，否则编译不过；Postgres 形态随迁移 `0025`（两张 legacy token 表加
  `family_id` + 墓碑表）自动执行。背景见 ADR-0005 §8 与
  [docs/authorization-engines-decision.md](docs/authorization-engines-decision.md)。

- **`prompt=login` 与 `max_age` 现在会强制重新认证（G-4）**：此前两者被完全忽略，id_token 携带
  旧会话的 `auth_time`，step-up 请求既不重新认证也不回 `login_required`。现在按 OIDC Core
  §3.1.2.1：无活会话或 `max_age` 超龄时经 `redirect_uri` 返回 `error=login_required`（带 `iss`）。

- **设备流端点对机密客户端强制认证（G-6）**：`POST /oauth/device_authorization` 此前对任何客户端
  （含机密）都不要求认证，而验证页会把该客户端的注册名展示给任何跟着 `user_code` 走的人；现在与
  token 端点同形，机密客户端未认证即 401。**行为变化**：匿名发起设备流的机密客户端会开始收到 401。

- **`[client]` 首次 seed 之后的漂移拒绝启动（Z12-3）**：此前改 `secret_env` / `redirect_uris` /
  scopes 被静默忽略——轮换 secret 时旧 secret 仍有效，删掉的生产回调仍留在白名单。现在
  `seedClient` 命中后逐字段比对，不一致**拒绝启动**并点名字段。**行为变化**：与既有注册行不一致的
  配置会启动失败（这是一次有意的裁定）。

- **抗 DoS：探针、限流桶与 in-flight 槽位不再被单个匿名调用方独占（Z11-1/4/5/V1）**：`/readyz`
  的就绪检查改用不随调用方取消的上下文（取消不再把结果缓存成 503，健康副本不再被摘流）；限流的
  overflow 桶按调用方分摊并保持有界；in-flight 槽位按（平面, 客户端）分摊；探针豁免现在也跳过
  会话中间件（带 Cookie 的匿名探针不再每请求一次连接池往返）。**升级影响**：无配置变化；
  容量口径见 [docs/operations.md](docs/operations.md)。

- **抹除链失败的那一步现在入审计（Z07-2）**：`Destroy` 失败时，审计里唯一一条记录此前写的是
  `outcome=ok` + `pseudonym_destroyed=true`（假名钥匙仍在、仍可归因），运维据此得到
  「历史已不可链接」的错误结论。现在失败分支补记一条 `outcome=error`，与
  [docs/operations.md](docs/operations.md)「数据删除与保留」一节的口径一致。

- **设备路径的期限改由 store 时钟裁决（P2-32）**：postgres 适配器的三条设备 SQL
  （poll 节流的 `last_poll`、`ApproveDevice` 的 `expires_at` 谓词与 `auth_time` 戳）
  此前用数据库 `now()` 裁决/写入进程写的期限——两个后端对「这个设备码还有效吗」给出不同答案
  （UI 说有效、审批被拒且报「码不存在」）。现在三处全改为 `$n` 参数 ← `s.now()`，
  与内存后端及 `sweep.go` 的既定形态一致。**升级影响**：无 schema/配置变化；
  `COALESCE(auth_time, now())` 展示性回退与 `sessions.go` 的相对区间比较（两钟相消）按原裁定保留。

- **Kill Switch 的绑定维度不再沉默、`subject` 清在途绑定流程（AUD-9 + AUD-8）**：无数据源的部署上，
  `all` / `subject` 此前整段跳过绑定半边（`bindings` 字段省略）——响应者无法区分「本部署没有绑定」
  与「本部署清不了绑定」。现在目标带绑定维度而端口缺失时报 `bindings_unavailable: true`（审计
  `Detail` 同名）；`bindings` 目标仍 fail-loud。`subject` 目标新增清掉该账号**在途绑定流程**
  （`flows_purged`，与抹除同一份能力）：一个 pending flow 能在事后造出新绑定 + 新上游令牌，
  此前 Kill Switch 断了绑定却留着流程，与 erasure 对同一中间状态给出两个答案。
  **升级影响**：响应体新增 `flows_purged` / `bindings_unavailable` 字段（新增，无破坏）。

- **抹除的假名步骤如实上报 + 组合根对 durable 断言（AUD-6）**：假名 store 缺失时，抹除结果与
  `account.delete` 审计此前都**不说**这一步被跳过——「历史已不可关联」与「这步没做」在成功里长得
  一样。现在 `Result.PseudonymDestroyed` 与审计 `Detail[pseudonym_destroyed]` 如实记录；组合根对
  durable 部署断言审计 sink 暴露销毁能力，缺失则拒绝启动（内存模式不受影响，其日志本就不存密钥）。
  **升级影响**：自定义审计 sink 若不实现销毁能力，durable 部署将拒绝启动。

- **同意决策（approve/deny）写入审计（AUD-3）**：「用户把账号数据授权给哪个 client、哪些 scope」是
  这套服务最核心的授权事件，此前批准（`CompleteLogin`）与拒绝（`DeleteAuthRequest`）两个出口都不写
  审计——被拒绝的请求完全无痕。现在两个 store（memory + postgres）各记
  `oidc.consent.approve`（含 `client_id` 与批准的 `scopes`）/ `oidc.consent.deny`。

- **配置校验：`trusted_proxies` 通配需显式承认、`sources[].token_class` 校验并默认（P2-6 + P2-7）**：
  `trusted_proxies` 里的 `0.0.0.0/0` / `::/0` 不扩大信任面而是**清空**它（每跳都算「信任网内」，
  分桶键又回到调用方手里），现在被拒绝启动，要用必须显式承认 `server.trusted_proxies_any = true`
  （`RE0AUTH_TRUSTED_PROXIES_ANY=true`），与 `expose_internal` 同形。`token_class` 此前在任何 store
  都不被校验，`unbind.go` 只认 `long_lived`、其余一律读成可撤销 ⇒ 拼错/大写/省略都会把「不可撤销」
  的源报成「已撤销上游」；现在在 `federation.NewRegistry` 校验：空 → `revocable`，两个真值保留，
  其余拒绝启动。**升级影响**：写了通配 `trusted_proxies` 或错拼 `token_class` 的部署会拒绝启动。

- **存储选择：`DATABASE_URL` 单独即可选 durable、`RE0AUTH_STORAGE_DRIVER` 新增、内存警告修因（P2-8）**：
  此前 driver 只由配置文件的 `[storage]` 决定，「设了 `DATABASE_URL`、没写 `[storage]`」会静默退回内存
  模式（审计链/锚点/自检全无），而警告还硬编码 `because="no DATABASE_URL"` —— 变量明明设了。现在：①
  环境里给了 `DATABASE_URL` 即选 postgres（README 快速开始形态）；②新增 `RE0AUTH_STORAGE_DRIVER`（环境
  > 文件 > 推断）；③警告按**实际原因**取值，并公布 `driver`。**升级影响**：只设 `DATABASE_URL` 的纯环境
  部署现在会尝试连库（而不是静默内存）；要强制内存请设 `RE0AUTH_STORAGE_DRIVER=memory`。

- **备份 Pod 被自己的 NetworkPolicy 选中、不再挂 SA token（P2-16）**：`deploy/k8s/backup` 的转储 Pod
  此前**没有任何标签**，于是不被任何 NetworkPolicy 选中——default-deny 集群上每次转储都失败，而失败的
  CronJob 无声（不进指标、无告警），备份就这么静默停掉。现在它有独立标签
  `app.kubernetes.io/name: re0auth-backup`，由新增的 `deploy/k8s/backup/networkpolicy.yaml` 选中
  （放行到 Postgres 5432 与 DNS），并 `automountServiceAccountToken: false`。

- **SPA 的 npm 归属清单：把守卫改成断言真实机制（P2-21）**：`make npm-attribution` 早已生成
  `dist/re0auth_<ver>_npm-attribution.json` 并接进 `checksums`/`release`，但探针断言的是「构建产物里
  内嵌版权文本」——Svelte/SvelteKit 并不往产物里塞 MIT banner，所以那条断言永远红、且测错了对象。现在
  探针（`internal/zzprobe/dependencies`）与 archtest 断言的是 Makefile 接线与「非空」守卫。

- **备份/恢复脚本收紧（`scripts/`）**：`restore.sh` 现在 ①校验**命令行给的那个文件**（此前
  `sha256sum --check` 读的是 `.sha256` 里记录的路径——异地恢复被自己挡死，而截断件却能「校验通过」
  进入 `pg_restore`）；②`.age` 路径**先校验密文再解密**（此前该分支一行校验都不跑）；③**缺失
  `.sha256` 即拒绝**（此前静默跳过）；④解密到 0700 临时目录并在退出时清理（此前明文留在备份目录）；
  ⑤`pg_restore` 加 `--single-transaction`（此前半途失败会留下半填充的库，而空库守卫又挡住重试）。
  `backup.sh` 以 `umask 077` 写转储（此前世界可读），并在落盘**之前**检查 `age` 是否存在；
  `deploy/k8s/backup` 的内联脚本同样加了 `umask 077`。

- **发布镜像的门禁顺序、版本标记与许可**：`release.yml` 不再在扫描前推 `latest`——镜像先按 tag 推送，
  Trivy（`--exit-code 1`）扫过之后才用 `buildx imagetools` 把 `latest` 指到那个 digest，预发布 tag
  不产生 `latest`；同一 job **补传 `VERSION` build-arg**，镜像里的 `-version` 与启动日志不再报 `dev`。
  `deploy/k8s/base/deployment.yaml` 的基线镜像由 `:latest` 改为钉住的 tag。运行镜像（scratch）
  现在 `COPY LICENSE NOTICE`；发布增加 npm 许可清单（`make npm-attribution` 产出，随 `SHA256SUMS`
  一起发布），补上 NOTICE 只覆盖 Go 模块的那一半。Dockerfile 的 CA bundle 改为在构建阶段 `cp -L`
  解引用后再 COPY，避免符号链接在 scratch 里悬空导致出站 TLS 全挂。

- **前端依赖审计门现在会响**：CI 的 `pnpm audit` 从 `--audit-level high` 降为 `low`（树里唯一的
  告警是 low，此前这道门永远不会红），并把已知不可达的那条（`cookie@0.6.0`，SvelteKit 的
  dev-only 传递依赖）列进 `web/package.json` 的 `pnpm.audit.ignore`。

- **`make dist` 不再静默漏文件**：`cp` 加 `|| exit 1`，并对每个归档逐个断言 `re0auth` 与五个随附
  文件都在（此前 `LICENSE`/`README.md`/`SECURITY.md` 缺失会静默发出去）。`VERSION` 改为经环境变量
  进配方（`$${VERSION}`），不再在 make 期插值进脚本文本。

- **文档与实现对齐**：runbook/incident-response 的 `[admin].allow` 更正为真键 `[admin].subjects`；
  内部监听器「默认 `:9090`」更正为**默认不监听**；`RE0AUTH_DATABASE_URL` 更正为 `DATABASE_URL`
  （或 `[storage].dsn_env` 指向的变量）；`architecture.md` 的「构建产物可复现」更正为「可签名」
  （前端 `_app/version.json` 带构建时刻）；`dependencies.md` §7 说明 action SHA 与基础镜像 digest
  两半已有 archtest 守卫、工具版本那半没有；`upstream-protocol.md` 的「名称映射表」更正为
  「不存在映射表，用的是同一个 scope 字符串，唯一例外是硬编码的 `account.read`」。

- **撤销索引补齐（迁移 `0022`）**：迁移 `0021` 只给 OIDC 引擎的 `oidc_access_tokens` / `oidc_refresh_tokens`
  补了 `client_id` 前导索引，而按 `client_id` 单独过滤的批量撤销还有四处：`revokeMatching` 触及的三张
  legacy `oauth_access_tokens` / `oauth_refresh_tokens` / `oauth_codes`，以及 `revokePendingAuthorizations`
  触及的当前引擎表 `oidc_auth_requests`。新迁移在启动时自动执行；影响面是撤销与应急响应端点，
  不是签发热路径。

- **`/.well-known/*` 的两份发现文档纳入动词矩阵**：它们在提供方的 `ServeHTTP` 里走单独一条分支，
  此前不查 `endpointMethods`，因此任意动词都回 `200` 与完整文档。现在与其它协议端点一致：只收
  `GET`/`HEAD`，其余动词回 `405` 的 OAuth 错误体。

- **关停顺序：先翻 `/readyz` 503，等窗口，再排空（滚动更新不再有 connection-refused 窗口）**：
  此前收到 SIGTERM 立即 `Shutdown`（先关监听器），而 K8s 摘 Endpoint 与发信号是并发的，于是每次滚动
  更新都有一小段把新连接路由到已关监听器的窗口（502/503，消耗 S1 可用性预算）。现在进程先让
  `/readyz` 返 503，等 **`endpointRemovalWait`（5s，进程内，因为 scratch 没有 `/bin/sleep` 跑
  `preStop`）** 让编排摘完端点，再走 **`shutdownTimeout`（30s）** 的排空，最后才排空审计批次队列
  （**`auditDrainTimeout`（10s）**，由 `grace - removal - http` 反推——它串行发生在 HTTP 排空之后，
  而不是并行）。三段相加 **5 + 30 + 10 = 45s**，所以部署方需要确保
  `terminationGracePeriodSeconds ≥ 45s`（出厂基线 45s）；给得比三段总和小，审计排空的「过期拒绝」
  路径就会先被 SIGKILL 打断，在途审计行静默丢失。

- **协议面 `prompt=none` 实现（OIDC Core §3.1.2.1）**：此前不读 `prompt`，静默授权请求被当作普通
  交互请求，把 iframe 客户端送到登录页并留下一条 30 分钟的孤儿 pending 请求。现在无活会话时经
  `redirect_uri` 返回 `error=login_required`（带 `iss`），`prompt=none` 与其它值组合返回
  `invalid_request`。实现方式（记入 [oidc-decision.md](docs/oidc-decision.md) O-8a）：给
  `oidchttp.Config` 注入会话查询钩子；未注入即 fail-closed。

- **业务面的失败响应补齐 `Cache-Control: no-store`**：此前该指令只在 `/v1` 子 mux 的包装器与确认
  `200` 的写路径上；限流 `429`、体限 `413`、在途上限 `503` 由子 mux 之外的中件写出，从未带上它。
  现在由 `writeProblem` 自身设置，与协议面一致，也覆盖编码路径上的 `404`。

- **跨平面的非规范拼写改为 `404`，而不是 `307`**：`/v1/../oauth/token` 这类路径会被 `ServeMux`
  清洗后重定向进另一个平面（`/oauth/token`），而该重定向由路由器写出、不带任何平面的形状，限流与
  指标却按原路径归类。现在这类拼写在其**原**平面的形状里被拒（`404`），不再发生跨平面跳转；同平面的
  清洗（如 `/v1//me`）与尾斜杠行为不变。

- **源从配置移除后，名下绑定现在可以被用户断开**：`Unbind` 此前在读取绑定**之前**就对未知源返回
  `ErrUnknownSource`，于是 `DELETE /v1/bindings/{game}/{source}` 回 404，而 `GET /v1/bindings`
  仍带着 `configured:false` 列出这条绑定并声称「仍可断开」——那条上游令牌与其 vault 密文只能靠运维
  Kill Switch 或整账号抹除清除。现在注册表查找挪到读取绑定之后：绑定存在即执行本地那一半（撕密文、
  删行），上游记为 `nothing`（已无源可问）；只有「未知源且无绑定」才继续是 404。

- **协议面 `/.well-known/*` 的未知路径改为 OAuth JSON 404**：此前落在提供方 handler 的
  `http.NotFound` 分支，回的是标准库的 `text/plain` 404，而日志、指标与限流器都把该请求记为
  `plane=protocol`。未知路径与真实文档的尾斜杠拼写（如 `/.well-known/oauth-authorization-server/`）
  现在与 `/oauth/*` 的未知端点为同一形状。

- **每个端点声明自己的动词，未列出的动词一律 `405`**：协议面新增一张 `endpointMethods` 表
  （「已知端点」也由它派生），`authorize`/它的回调与 `userinfo` 收 `GET`/`POST`，`keys` 收
  `GET`/`HEAD`，其余收 `POST`；`PUT`/`DELETE`/`PATCH`/`OPTIONS` 等一律回 `405` 的 OAuth 错误体，
  不再落到库或某个没有方法策略的分支。`/oauth/keys` 此前对任意方法都回 200（响应只是公钥，未泄露
  任何东西，但它是唯一没有方法约束的端点）。业务面同样改为按方法分派：已注册路径上未声明的动词现在回
  `405` problem+json 并带 `Allow` 头，而不再被 `/v1/` 兜底吞成 `404`。两面的动词矩阵都从
  `specRoutes` / `endpointMethods` 自动派生，各有一条逐一断言的守卫测试。

- **撤销令牌的索引（迁移 `0018`）**：`oidc_refresh_tokens.id_hash` 此前没有索引，而 RFC 7009 撤销路径
  （`RevokeToken` 的查找与两条 DELETE）都按它查/删，每次撤销都退化成全表扫描。新迁移在启动时自动执行；
  影响面是撤销与应急响应端点，不是签发热路径。

- **公开库 `idp` 自带的 fallback HTTP client 改为 fail-closed**：调用方不注入
  `RegistryConfig.HTTPClient` 时，默认 client 现在也在拨号层拒绝 loopback / link-local / 私网地址，
  与生产装配根一致。身份提供方确实在私网的直接库使用者，需显式注入自己的 client。HTTP 面与配置不受影响。

- **`taptapoauth` 不再成段回显上游错误原文**：上游的 `error` / `error_description` / 原始 body
  现在按上限（200 rune）截断并压平换行后才进错误与日志，避免噪声与伪造日志行；错误分类不受影响。

- **新增 `perf` 工作流与 `make perf`（开发工具，无部署影响）**：每周/手动运行
  每基准 10 次采样的基准测试与 30s 容量画像，`cmd/perfreport` 把结果渲染成
  Markdown 报告（中位数、离散度、与上一次成功运行的基线对比），写入 job summary
  并随 run 存为 artifact。ci.yml 既有的 `bench`/`load` 门槛不变；本地 `make perf`
  无需数据库，审计链基准会照实跳过并在报告中注明。

- **破坏性（仅影响直接使用公开库 `oauth` 的代码）**：`oauth.DeviceStore` 的
  `UpdateDevice(ctx, DeviceAuthorizationRecord)` 拆成两个字段级方法——
  `RecordPoll(ctx, deviceCodeHash, at)` 与
  `RecordDecision(ctx, deviceCodeHash, DeviceDecision) (bool, error)`。
  原因：整条写回让一次轮询可以把落在读之后的**决定**抹回 pending，且两次并发决定会互相覆盖。
  实现者需改这两个方法（`MemoryDeviceStore` 与 Postgres 侧已改）；HTTP 面与配置不受影响。
  背景见 [docs/security-audit-3.md](docs/security-audit-3.md) 与本条对应的提交。
- **过期判定改为单时钟**：Go 写的时间戳（会话、授权码、OP 令牌）一律由进程时钟判定，
  数据库 `DEFAULT now()` 写的仍由数据库判定。副本与数据库之间无需再对齐到亚秒——但仍建议 NTP；
  排障见 [docs/operations.md](docs/operations.md) 的「可观测与排障」。

- **协议面不再返回 CORS 头**（discovery 与 `/oauth/*`）：库此前按请求 `Origin` 回
  `Access-Control-Allow-Origin` 与 `Access-Control-Allow-Credentials: true`，与服务同源的部署无关，
  但对任何来源都生效。现在这些头被去掉，同源客户端不受影响；跨源前端请看
  [docs/cors-decision.md](docs/cors-decision.md)（ADR-0011，含重新评估的触发条件）。

- **审计链改为持续校验**：新增一个后台循环，启动时与之后每 6 小时走一遍整条记录链，
  结果计入 `re0auth_audit_verify_total{result=…}`。此前校验只在运维手工调用
  `GET /v1/admin/audit/verify` 时发生，因此 S5 这个「恒为 0」的硬目标在无人调用时**无法被证伪**——
  一条断链可以一直等到某次例会才被发现。失败与「没跑完」现在都会进日志与指标，
  两条既有告警（`Re0AuthAuditChainBroken` / `Re0AuthAuditVerifyError`）从「要人记得跑」变成「会自己响」。
  全表遍历较贵，所以间隔是小时级而非分钟级；日志大到 45s 扫不完时的处置仍是上增量校验点，见
  [docs/operations.md](docs/operations.md) 的「审计链锚点核对」。
- **`server.internal_addr` 绑到非 loopback 地址现在需要显式承认**：新增
  `server.expose_internal`（环境变量 `RE0AUTH_INTERNAL_EXPOSE`）。不设时，只有 loopback 地址
  被接受；`0.0.0.0:9090`、`[::]:9090` 或 `:9090` 一律拒绝启动。此前唯一的检查是「不等于
  `server.addr`」，于是把 `/metrics` 与 `/debug/pprof/`（堆、goroutine dump、CPU profile）
  交给网络只需要写错一个地址。**k8s 基线需要改**：`deploy/k8s/base/configmap.yaml` 已补上
  `expose_internal = true`，它的安全性来自同目录的 NetworkPolicy（只放行 monitoring 命名空间到 9090）。

## v0.0.0-rc.3

**首个带产物的预发布**（rc.4 之前唯一一个）：release 里有六个平台的归档、`SHA256SUMS` 及其 cosign 签名、以及 SBOM。
它验证的仍是 **tag → CI → 产物** 这条链路，所以它和下面各条一样**不是可以部署的版本**——
rc.1 那节列出的适用条件全部成立。

## v0.0.0-rc.2

预发布 tag，用途与 rc.3 相同。**它没有产物**：那次 tag 运行死在 Trivy 扫镜像的一步
（OCI 引用的仓库名必须小写，而组织名是 `Re0Auth`，解析器不像 build/push 那样替我们规范化），
`gh release create` 因此从未执行。修法见 rc.3 那次运行，这也是「tag 一响就等于发布了」的反例。

## v0.0.0-rc.1

> **这个 tag 不存在。** 仓库里没有 `v0.0.0-rc.1`——`git ls-remote --tags` 只有 rc.2 与 rc.3，
> 也没有对应的 release。本节保留的是当时的**意图**记录。
>
> 代价值得记下来：`deploy/k8s/base/kustomization.yaml` 曾长期钉着这个名字，
> 而那是一份**拉不到的基线**，`internal/archtest` 当时只检查「非空且不是 `latest`」，
> 于是对一个从未构建过的 tag 报了绿。现在那条守卫会拿仓库里真实存在的 tag 比对。

预发布，用来把 **tag → CI → 产物** 这条链路端到端跑通一次（可下载产物的构成见 README
「发布产物」）。它不是可以部署的版本：

- 项目定位仍是迭代期，**未达生产可用**——见 README 顶部的警告与
  [SECURITY.md](SECURITY.md) 里逐条列出的已知限制。
- 三把密钥与 issuer 必填、缺一即拒绝启动；持久化部署还多一把审计链密钥。
