# 区域 Z17 对抗性复核（第七轮）—— 文档 / 契约 / 配置样例漂移

复核对象：`docs/audit-7/findings/Z17-docs-contract-drift.md`
探针（被复核，未改）：`internal/zzprobe/audit7/z17docscontractdrift/`
我的新探针：`internal/zzprobe/audit7/z17verify/verify_referencesource_test.go`（`//go:build audit7`，端口 18702）
立场：**证伪**。凡我确认的给出我自己的命令与承重输出；凡降级/推翻的给出 `file:line`。

## 0. 我实际执行了什么

```
go test -tags audit7 -count=1 ./internal/zzprobe/audit7/z17docscontractdrift/...
  → 5 个探针全红，失败行与报告声称逐条对得上（见下）
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z17verify/...
  → 1 个探针红（新发现；阳性对照通过）
go build ./...   → exit 0
go vet -tags audit7 ./internal/zzprobe/audit7/z17verify/...  → exit 0
```

被复核探针的红与报告声称一致（我逐条贴过）：Z17-1 `err="idp.github.client_secret_env names
\"GITHUB_CLIENT_SECRET\", which is not set"`；Z17-2 先 `server.cookie_secure must be true when
server.issuer is https`；Z17-3 `SECURITY.md says 4 rounds ... docs/security-audit-5.md is on disk`；
Z17-4 两字段 enum 越界；Z17-5 8 个变量。**报告没有夸大探针结果**。

## 1. 逐条裁定

### Z17-1 README 快速开始与样例不兼容 —— 机制 CONFIRMED，**严重度降为 P3**
- 机制我独立复核到行：`config/re0auth.example.toml:316-322` 确为**未注释**的 `[idp.github]`/
  `[idp.google]`；`internal/config/config.go:57-66` 未设即错；`cmd/re0auth/config.go:832` → `loadIdP`
  在监听之前。真进程红行与报告完全一致。
- **降级理由**：这是「文档与实现不一致」（简报 §6 把该形态明确列为 P3），无安全影响、fail-closed
  生效，代价是一次排障。同一份报告把**同一类**缺陷（Z17-2 的 README 片段）定为 P3，Z17-1 定 P2 属
  内部标准不一致。
- **报告说错的关联字段**：Z17-1 的「是否与既有编号相关：无」不准确。第五轮 **CS-5** 已就「照 README
  快速开始 `cp` 示例文件会拒绝启动」给出 CONFIRMED 结论（`docs/security-audit-5.md:160`、
  `docs/audit-5/findings/config-startup-disclosure-VERIFIED.md:250-259`：那份示例文件 + 无
  `DATABASE_URL` → `stage=config err="storage.dsn_env names \"DATABASE_URL\""`）。Z17-1 是**同一
  快速开始路径上的第二个独立拦路点**（IdP secret），机制是新的、不构成重报，但必须写明与 CS-5 相邻。
- 状态：CONFIRMED（运行时），严重度 **P3**。

### Z17-2 README 内存模式片段按原样不可启动 —— CONFIRMED，P3
- 我复核到行：`cmd/re0auth/config.go:453`（无文件时 `CookieSecure=false`）、`:488-492`（https ⇒
  必须 Secure）与 `cmd/re0auth/main.go:1385-1397`（`RE0AUTH_OIDC_TOKEN_KEY is required (32 bytes,
  base64)`）。探针第一次红的确为 cookie 错，第二次红后 3 行被 `firstLines(3)` 截断（只显示两行 WARN
  memory/audit），报告写的 `RE0AUTH_OIDC_TOKEN_KEY is required` 需读源码才看得到——我读到了，一致。
- 一点保留（不改变裁定）：第二颗子弹（缺两把 OP 密钥）较软，因为 `README.md:31-32` 在片段**紧上方**
  就写明「无论哪种模式，两把 OP 密钥都必填」，片段省略 OP 密钥可读作叙述性简写；真正无歧义的是
  `cookie_secure` —— 它在**整份文档里一个字都没有**（见 Z17-5）。仍为 P3。
- 状态：CONFIRMED，P3。

### Z17-3 SECURITY.md 的审计轮数陈旧 —— CONFIRMED，P3
- `SECURITY.md:121-130` 逐字与报告一致：写 "Four rounds have been run / Two of them were written up
  as documents"，只列 `-2`/`-3`，而 `docs/security-audit-5.md` 是**已跟踪**文件（`git ls-files` 命中）。
  因此即便完全无视本轮产物 `docs/security-audit-7.md`（`git status` 显示未跟踪），这条也**单独成立**。
- 报告把 `-7` 也算进去属可接受的顺带；载重的是 `-5`。P3（对外证据陈述陈旧），合理。
- 状态：CONFIRMED，P3。

### Z17-4 openapi 的 Binding enum 表示不了 `configured:false` —— CONFIRMED，P3（最扎实的一条）
- 独立复核：`docs/openapi.yaml:1833-1838` `token_class enum [revocable, long_lived]`、`:1839-1842`
  `status enum [active, degraded, retired]`；`internal/httpapi/binding_routes.go:23-24` 两字段
  **无 `omitempty`**，`:82-98` 仅在 `sources[...]` 命中时赋值，未命中留 `""`。`configured` 是 required
  且描述明说 "False when the binding outlived the source's entry..."（`:1860-1862`），
  `CHANGELOG.md:126-130` 要求该状态仍可列出并断开。零值必上线，判定成立。
- 报告引用的行号 `:1828-1834`/`:1835-1837` 略有偏移（实际 1833-1838/1839-1842），内容与机制无误。
- 状态：CONFIRMED（源级，必要条件即可判定），P3。

### Z17-5 「README 指认的完整键位样例漏掉 8 个覆盖」—— **大部分是第五轮 CS-10 的重报**
- **重报**：第五轮 **CS-10** 就是这个断言，且已复核 CONFIRMED、并入汇总
  （`docs/security-audit-5.md:265`：「CS-10（示例配置的 `Environment override` 只覆盖 7 条而代码有
  18 个 `RE0AUTH_*`）」；`docs/audit-5/findings/config-startup-disclosure.md:354-382` 逐名列出的正是
  `RE0AUTH_COOKIE_SECURE`、`RE0AUTH_RATE_LIMIT(_BURST)`、`RE0AUTH_KEK_ID`、
  `RE0AUTH_CLIENT_ID`/`RE0AUTH_CLIENT_NAME`——8 个里的 6 个，连给的守卫建议都相同）。
  简报 §4.3 明令第五轮发现不得作为新发现重报，而报告的「是否与既有编号相关」写「无」，**这两处是错的**。
- **机制写错**：报告称这 8 个名字「在**整个仓库的任何文档里**都没有出现」。我的全仓递归扫描
  （含 `docs/` 子目录、`deploy/`、`scripts/`、`.github/`）显示：探针只 `ReadDir(docs)` **非递归**，
  因此漏掉 `docs/audit-5/findings/*.md`——上面那份文档**逐字**写着这 6 个名字（我的命令：
  对 `docs/` 递归 grep `RE0AUTH_CLIENT_ID` 等命中 `docs/audit-5/findings/config-startup-disclosure.md:365-366`）。
  所以「no document」对 6/8 不成立（剩下的 `RE0AUTH_LOG_LEVEL`/`RE0AUTH_LOG_FORMAT` 确为全仓仅见于
  `internal/config/logging.go:26-27` 的代码注释与测试，无产品文档）。
- 结论：8 个里只有日志这一对是**新**残留；整体应作 CS-10 的补充。状态：**DOWNGRADED**，P3。
- 附：`RE0AUTH_LOG_LEVEL`/`LOG_FORMAT` 在 `logging.go:26-30` 有相当完整的代码注释（取值域、fail-closed
  语义），报告「运维无法发现」对**读代码者**偏强，对 README/运维文档读者成立。

### Z17-6 openapi 的 `cursor` 说明与实现不符 —— CONFIRMED，P3
- 独立复核：`docs/openapi.yaml:1452-1454` 「Opaque; the server rejects anything it did not issue.」；
  `internal/httpapi/audit_routes.go:82-89` 是 `strconv.ParseInt(raw,10,64)` 且只拒 `<1`，
  `:163` 产出 `strconv.FormatInt(page.NextBefore,10)` = 十进制行 id。`?cursor=1` 被接受，判定成立。
- **报告的探针说法是错的**：它写「无专用探针（上一条**同一文件同一函数**的静态对照已足够）」——
  Z17-4 的探针在 `binding_routes.go`，与本条的 `audit_routes.go` 既非同一文件也非同一函数，等于
  **本条没有任何探针**。裁定仍为 CONFIRMED（源级 `file:line` 即可判定，简报 §3 允许），但探针
  字段应清除该误导表述。
- 状态：CONFIRMED（源级），P3。

## 2. 新发现（我的独立证据）

### Z17V-1 README 的**参考数据源**快速开始同样照抄即拒绝启动（Z17 完全没开这个入口）
- 严重度：P3 低/提示（与 Z17-1 同类：文档与实现不一致；无安全影响，fail-closed 生效）
- 类别：可维护性
- 证据（真进程，含阳性对照）：
  - `README.md:73-78`：`cp config/referencesource.example.toml config/referencesource.toml` →
    `export TAPTAP_LEANCLOUD_APP_KEY=...   # 或 GOOGLE_CLIENT_SECRET=...` → 构建运行。
  - 样例 `config/referencesource.example.toml:17-18` 是**生效**的
    `[client] secret_env = "REFERENCE_SOURCE_CLIENT_SECRET"`；同文件头部（`:7`）却声明
    「every field has a default」——`secret_env` 没有默认值。
  - `cmd/referencesource/config.go:133-138` 对 `SecretEnv` 调用 `config.Secret`（未设即错），
    紧接着 `:143-145` 硬要求 `ClientSecret != ""`。
  - 结构上同型的第二点：`[taptap]`（`:48-58`）生效，`config.go:196-206` 无条件要求
    `TAPTAP_LEANCLOUD_APP_KEY`，而 `[social.google]`/`[social.github]`（`:69-77`）是注释掉的——
    所以 README:75 的「**或** `GOOGLE_CLIENT_SECRET`」不是替代项。
- 承重输出（我跑的探针，红）：
  ```
  ERROR msg="cannot start" stage=config
    err="client.secret_env names \"REFERENCE_SOURCE_CLIENT_SECRET\", which is not set"
  ```
  两次（只给 TapTap key；只给 Google secret）都是同一处 `stage=config`。
- 阳性对照（同一次调用 + 补上它自己声明的两把 secret）到达 `msg="listening"`，证明失败点就是这条声明、
  且探针确实驱动了真实二进制与真实配置路径。
- 影响：README 唯一演示 Upstream Kit 的第二个快速开始不可用；想验证上游协议的人第一步即失败，
  错误指向一个样例从未提过的变量名。
- 探针：`internal/zzprobe/audit7/z17verify/verify_referencesource_test.go::TestZ17VerifyReferenceSourceQuickstartCannotStart`（红）
- 修法建议：把样例 `[client] secret_env` 注释掉（与 `[taptap]` 之外的可选项一致）并在 README 片段补
  `export REFERENCE_SOURCE_CLIENT_SECRET=...`；同时把 README:75 的「或 `GOOGLE_CLIENT_SECRET`」改成
  需先取消 `[social.*]` 注释，或直接去掉 TapTap 段。
- 是否与既有编号相关：无（第五至六轮无此条，全仓检索 `REFERENCE_SOURCE_CLIENT_SECRET` 在
  `docs/security-audit-*.md`、`AUDIT-ISSUES.md`、`docs/audit-5/findings/*`、`scratchpad/audit6/*` 中 0 命中）。
- 状态：CONFIRMED（运行时）。

## 3. 我复核过的「探过没破」（无假绿）

- **数字类全部对得上**，我抽查了最容易漂的几条：`capacity-planning.md:13-21` 的池 16/2/5s/30s、
  入站 128/内存 512、出站 256、64 MiB 预算 = `internal/store/postgres/postgres.go:123-133`、
  `cmd/re0auth/config.go:347-396`、`internal/federation/service.go:24`；`operations.md:223` 的「每小时」
  = `main.go:91` `auditAnchorInterval = time.Hour`；`slo.md:23` 的「每 6 小时走一遍整条链」
  = `main.go:100` `auditVerifyInterval = 6*time.Hour`；`operations.md:178` = `health.go:33`；
  `audit_routes.go` 的 verify 45s = `internal/store/postgres/auditchain.go:199/230`。**没有一条是错的**。
- **探针的阳性对照是真的、不是夹具桩**：Z17-1/2 用 `go build` 出的**真二进制** + `-config`，对照分支
  分别到达 `stage=storage` 与 `http://127.0.0.1:18701/healthz` 200；Z17-4/5 的对照是「结构缺失即
  `t.Fatal`（vacuous）」加两个确在文档里的变量名（`RE0AUTH_KEK`、`RE0AUTH_MAX_IN_FLIGHT`）。
  我未发现桩造成的假绿（探针全红，且红点与源码逐行吻合）。
- **非重报核对**：Z17-1/Z17-2/Z17-4/Z17-6 在第二至六轮编号里 0 命中（我按 `token_class`、
  `configured:false`、`next_cursor`、`cookie_secure`、`GITHUB_CLIENT_SECRET` 在各轮汇总与
  `docs/audit-5/findings/*` 检索）。**Z17-5 例外，见上。**

## 4. 报告的小瑕疵（不影响裁定的证据强度）

- `openapi_test.go` 实为 **5** 条守卫（`:215/229/254/314/345`），报告写「三条」。
- Z17-5 的文档扫描非递归，漏 `docs/**` 子目录（见上）。
- Z17-6 的探针说明张冠李戴（见上）。
- Z17-1 的「相关：无」应写 CS-5。

## 5. 未能到达（残余盲区）

- 真 Postgres / 集群相关一律未跑（本机无库、无 Docker），本轮未新增运行时结论。
- `docs/audit-5/BRIEF.md` 在 `config-startup-disclosure-VERIFIED.md` 中被记为「不存在」；我以
  `docs/security-audit-5.md` 的汇总表（`:159-265`）作为第五轮「不许重报」的权威清单。
- `deploy/prometheus` 面板 title 与 `runbooks.md` 锚点的逐条比对仍未展开（属区 13）。
