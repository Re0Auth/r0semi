# 区域 Z19：密钥与敏感数据全生命周期 — 第七轮**对抗性复核**

> 复核人立场：证伪。原报告 `docs/audit-7/findings/Z19-secrets-lifecycle.md`（HEAD `bf81b2a` 工作区）。
> 复核探针：`internal/zzprobe/audit7/z19verify/`（`//go:build audit7` + `doc.go` 带 `!audit7`）。
> 被跟踪文件零修改（`git status --porcelain` 过滤 `??` 后为空）。

## 复核方法与实跑

```
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z19secretslifecycle/...   # 被复核者：5 FAIL / 1 PASS
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z19verify/...             # 本复核：3 FAIL（3 条探针）
go test -count=1 -run TestAdversarialProtocolErrorsDoNotLogCredentials ./internal/oidchttp/   # ok（原报告称 GREEN，属实）
go vet -tags audit7 ./internal/zzprobe/audit7/{z19secretslifecycle,z19verify}/...     # exit 0
go build ./... ; go vet ./...                                                          # exit 0
```

我逐条读了原报告的每个 `file:line`，并复跑了它的全部探针。**结论：4 条发现机制全部核实、探针红的理由与报告声称一致；无重度误报、无重报、严重度无虚高。** 但发现两处它没开的新通道，且它的两条「探过没破」正面结论经复验是**假绿**。

## 逐条裁定

### Z19-1 `*_env` 名字位塞值被原文回显 → **CONFIRMED，P2 维持**
- 源码逐点核实：`internal/config/config.go:57-66`（名字未设时 `%q` 回显 `envName`）、
  `cmd/re0auth/main.go:303-304`（`slog.Error("cannot start", …, "err", …)`）、
  `cmd/re0auth/config.go:1037`（`trusted_proxies entry %q`）。全仓无任何 env 名形状校验
  （grep `A-Za-z_`/`validEnv` 零命中于生产代码）。
- 实跑确认 4 个子测试全红，且日志行与报告贴的逐字一致（`vault.kek_env names "Z19-KEK-VALUE-…"` 等）。
  对照组（合法名字未设）只回显名字，也复现。
- **更正 1（关系标注不准确）**：报告写「是否与既有编号相关：无直接对应」。第五轮
  `docs/audit-5/findings/crypto-keys.md:396-398` 把**相反面**写成了正面结论（「`Secret()` 在错误里只放变量名，
  不放值」）。本条不是重报，但它是**对那份「探过没破」的证伪**，应显式写成「对 crypto-keys #15 的反驳」，
  否则主代理会以为这是全新面。另：报告提到的「CS-8 守卫」在本仓有两个不同含义
  （`docs/security-audit-5.md:263` 的 CS-8 = 审计排空；探针注释里的 CS-8 =
  `cmd/re0auth/zzprobe_startup_test.go:396` 的启动回显）。建议点名探针文件而不是编号。
- **更正 2（修法不完整，会给出虚假安全感）**：建议的 `^[A-Za-z_][A-Za-z0-9_]*$` 形状闸门**挡不住**
  纯字母数字的密钥（`client_secret_env = "S3cr3tV4lue"` 通过该正则，仍按原文回显）。正确的最小修法是
  **不做形状判断、直接不回显文件里的那个字符串**（只报 `field` + 「the value is not a valid variable name」），
  或对回显内容做脱敏。这一点在合并前必须改，否则修了等于没修。
- 第二子项（`trusted_proxies` 回显）单独看只有 P3 力度（该字段不是文档化的秘密位），
  是主断言的一个「同族例证」，不额外升级也不降级。

### Z19-2 QQ token 进 URL 再进 `url.Error` → **CONFIRMED，P3 维持**
- `idp/idp.go:651`、`:670-673`（token 作为查询参数）、`:710-722`（`%w` 包装 `hc.Do`）逐行核实。
- 实跑：红，控制组 GitHub（Authorization 头）**不**含 token，QQ 的错误值含 token。断言成立。
- 生产调用方核实：全仓 grep `Identity(ctx` 的生产代码只有 `internal/auth/auth.go:669-673`，
  它丢弃 `err` 且只回有界 `code`（`codeIdentityFailed`）。**「今天尚未落日志」属实**，P3 不高。
- 唯一可挑之处：报告说「本项目在失败路径上正是这么做的（`bind.go:208-211`、`unbind.go:124`）」——
  那两处是 federation 的绑定错误，不是 idp 的错误；类比略远，但不影响机制与严重度。

### Z19-3 `vault.Use` 四条失败路径 `_ = s.record` → **CONFIRMED，P3 维持**
- `vault/service.go:247-252`（Get 失败/未找到）、`:269-271`（KEK 未配置）、`:278-280`（unwrap 失败）、
  `:288-290`（解密失败）逐行核实为 `_ = s.record(...)`；成功路径 `:296-303` 确为 fail-closed
  （`:298` 在 `fn(plain)` **之前**返回审计错误）。实跑红，控制组（同 sink 成功路径）也确实不放行。
- **更正 3（探针强度）**：`vaultaudit_test.go` 只对 `:269` 一个站点 `t.Errorf`，其余三站是 `t.Logf`。
  「四条站点」的结论是**源级**成立的（四处写法完全同形），但探针的红色只由一个站点背书。报告措辞
  「进程内复现（已执行，FAIL）」容易让人以为是四站各有断言，应写明。
- **修正 4（对 G-19 的更强关系）**：第六轮 G-19 的原话是「同一 sink 让 `Enroll/Use/Revoke` **全部** fail-closed」
  （`docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md:133`）。本条的准确性质是
  **对 G-19 描述的局部反驳**：`Use` 只有成功路径 fail-closed。比「补充」更有价值，建议这样写。

### Z19-4 「同料不同 id」的轮换静默无效 → **CONFIRMED，P2 维持**
- `vault/service.go:112-130` 只比 `id`（`:119-122`），从不比材料；`cmd/re0auth/config.go:756-765`
  同样只拒「retired.kek_id == 当前 kek_id」。全包 grep `Fingerprint|ConstantTime|Equal` 在 `vault/`
  生产代码零命中（只有测试）。实跑红：`{Scanned:1 Rewrapped:1 AlreadyCurrent:0 Skipped:0}`，
  退役键仍能解开重包后的 DEK；异料对照则打不开。
- 命令面源级确定：`cmd/re0auth/main.go:1216-1230` 在 `Skipped==0` 时 `incomplete=false`，
  `rotateAndReport:1189-1192` 因此返回 nil ⇒ `run()` 返回 nil ⇒ exit 0；
  `:1226-1229` 仍打印「rewrapped=0 skipped=0 再删退役键」。属实，且**失败是静默的**，P2 不虚高。
- **加强证据（报告没写）**：同一函数在**相反方向**上是有意设防的——`vault/rotate.go:106-121`
  对「id 相同、材料已换」显式做了 `Unwrap` 验证并报错，注释写着「否则看起来完全轮换而每条凭据都不可读」。
  说明作者确实思考过 id/材料的同一性，只覆盖了一半。这是「机制成立而非苛求」的最强背书，建议补进报告。
- 与 G-22 的关系标注正确（同料不同角色 vs 轮换语义内复用），前提是运维把同一个值配进两个 `kek_env`
  （报告已如实写明），属「影响有界但确定」，P2 可接受；若主代理要与 G-22 合并也不损失信息。

## 新发现（本复核，独立证据）

### Z19V-1 `storage.dsn_env`/`DATABASE_URL` 的「缺 `@` 主机」形态把口令原文打进启动日志 → P2
- 严重度：P2 中（凭据进日志，确定性、静默从运维视角看是「配置错了」而非「泄漏了」）
- 类别：安全 / 合规-隐私；不变量：凭据封存 | fail-closed（错误路径不得成为泄漏路径）
- 机制：`internal/store/postgres/postgres.go:225-227` 把 `pgxpool.ParseConfig` 的错误 `%w` 包装，
  `main.go:375` 在 `stage=storage` 打印。pgx v5.11.0 的 `redactPW`
  （`…/pgconn/errors.go:236-246`）只脱敏它**认得出的位置**；userinfo 没有 `@` 时它整串原样带出。
  库自己的注释就写着这是「necessarily best effort」、畸形输入下无法保证。
- 离线证据（走的是**生产那一个调用**，不触网）：
  `z19verify/dsnredact_test.go::TestZ19VDsnParseErrorRedactionBattery`（红，21 个形态，3 红）：
  ```
  postgres://z19vuser:Z19V-DSN-PASSWORD-5f3a
    -> cannot parse `postgres://z19vuser:Z19V-DSN-PASSWORD-5f3a`: invalid port
  z19vuser:Z19V-DSN-PASSWORD-5f3a   -> 整串回显
  host=h password Z19V-DSN-PASSWORD-5f3a   -> 整串回显（漏写 `=` 的形态）
  ```
- 真进程黑盒证据：`z19verify/dsnbinary_test.go::TestZ19VHostlessDsnPasswordReachesTheStartupLog`（红）：
  ```
  control: …stage=storage err="postgres: parse dsn: cannot parse `postgres://z19vuser:xxxxx@127.0.0.1:notaport/db`: invalid port"
  DISCLOSURE: …stage=storage err="postgres: parse dsn: cannot parse `postgres://z19vuser:Z19V-HOSTLESS-DSN-PASSWORD-a71c`: invalid port"
  ```
- 影响：一个手写 DSN 时漏掉 `@host`（或漏 `=`）的错误，把 Postgres 口令写进日志管道（SIEM、工单、CI 日志）。
- **它证伪了原报告的两处正面结论**：①「探过没破 #5：区 12 的 DSN 条目在本版本上泄漏面比想象的窄」；
  ② 区域 12 自己的绿探针 `z12dsn_test.go`（5 个形态）**样本不足**，未覆盖「无 `@`」与「漏 `=`」。
- 修法建议：在把驱动错误交给 `die`/slog 之前兜一层——只保留 `postgres: parse dsn: invalid port` 这类结构信息，
  或在 `poolConfig` 里把 `pgconn.ParseConfigError.ConnString` 换成脱敏形态。**这是一次裁定**（会改变
  排障信息量），但「口令不进日志」优先。关联：对区域 12 `z12dsn_test.go` 的补充；第五轮 DSN 条目
  （`deploy-ops.md:213-217`）讲的是 argv 暴露，机制不同，不重报。

### Z19V-2 `-print-secret-env` 会把塞进名字位的值原样打到 stdout → P3
- 严重度：P3 低/提示（需要显式调用该子命令；但 runbook/CI 会捕获 stdout）
- 证据：`z19verify/printenv_test.go::TestZ19VPrintSecretEnvEchoesAPastedValueNullifiesThePositiveClaim`（红）：
  ```
  control: vault.kek_env=Z19V_CONTROL_KEK
  DISCLOSURE: vault.kek_env=Z19V-PRINT-SECRET-ENV-PASTED-a0b4   (exit=0)
  ```
  `configSecretEnvNames`（`cmd/re0auth/config.go:418-421`）就是 `role+"="+name`，零校验。
- 为什么单列：这正是原报告「探过没破 #4：`-print-secret-env` 只打印角色+变量名，不解析、不回显值」的反例，
  而且它是 Z19-1 的**第二个出口**——Z19-1 建议的「回显前判形状」修法**覆盖不到它**（这个子命令的职责就是打印名字），
  所以两处必须一起裁定：要么在 `configSecretEnvNames` 里拒绝非变量名形状并给出可操作错误，要么接受这条出口。
- 影响：同一次粘贴错误在 CI/runbook 的 stdout 里第二次落地；`scripts/backup-keys.sh:57-87`
  正是消费这行输出的一方（它会把该字符串当变量名去 `printenv`，然后以「is not set」拒绝——至少 fail-closed）。

## 探过没破的复验（哪些真绿、哪些假绿）

| 原报告正面结论 | 复验 | 结论 |
|---|---|---|
| #1 真进程 7 类请求 ×9 个 planted 值零命中（GREEN） | 复跑绿。逐条看响应：400 invalid_grant / 401 invalid_client / 200 / 400 access_denied / 401 invalid_token / 401 unknown client，都是**处理器形状**而非 404 ⇒ 凭据确实走到了真实代码路径 | **真绿**（唯一弱点是 introspect 因公共客户端认证失败 401，那条 planted token 未必进入令牌解析；该站另有 tracked 守卫覆盖） |
| #2 tracked 的 `TestAdversarialProtocolErrorsDoNotLogCredentials` | 复跑 ok | **真绿** |
| #3 metrics label 有界 | 抽查 `federation/service.go:416`、`observability.go:502-536` 一致 | **成立**（未做新探针） |
| #4 `-print-secret-env` 只打印名字、不回显值 | **被 Z19V-2 证伪** | **假绿** |
| #5 pgx `ParseConfigError.Error()` 已 `redactPW` ⇒ 泄漏面窄 | **被 Z19V-1 证伪（3 个形态）** | **假绿** |

## 未能到达 / 残余盲区（沿用原报告，我未能突破）

1. 无 Docker / 无本地 Postgres：Z19-3 的生产形态（审计链写失败而队列写仍成功）与 Z19-4 的真库退出码
   仍只有进程内 + 源级证据。Z19V-1 不需要数据库，已是真进程黑盒。
2. 多实例交错、k8s Secret 两个 key 同值：不可达，Z19-4 的前提只在进程内建模。
3. 密钥材料的内存驻留与零化：无法用探针证明，维持「判断」。

## 判断（不是 finding）

1. **Z19-1 的正确修法是不回显、不是判形状**（见更正 2）。这是本轮我最想请主代理改的一处措辞。
2. `kek_id` 也是文件自由文本，`cmd/re0auth/config.go:762-764` 与 `vault/service.go:120-121` 同样 `%q` 回显；
   把密钥粘进 `kek_id` 会走同一条路。它属 Z19-1 家族的第三个站点，我未单列（避免灌水），
   收口时与 Z19-1/Z19V-2 一起处理即可。
3. Z19-4 与 G-22 合并与否都不损失信息；我倾向保留为独立条目，因为它落在**轮换语义**内，
   后果（安全补救静默无效）与 G-22（一次泄露=三角色）不同。
4. 区域 12 的 `z12dsn_test.go` 应把 Z19V-1 的三个形态并入，否则那条绿探针会继续给后续轮次虚假信心。
