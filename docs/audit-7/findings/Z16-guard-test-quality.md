# 区域 16：守卫与测试质量（假守卫、永不失败的门禁）— 第七轮审计报告

## 范围与方法

读了：`internal/archtest/**`、`.github/workflows/*`、`Makefile`、`.golangci.yml`、全仓 `*_test.go`（266 个被跟踪）、
`internal/zzprobe/**`（第五/六/七轮探针）。跑了：`go vet -tags audit5 ./...` 与 `-tags audit6 ./...`（均 exit 0）；
`golangci-lint v2.14.0`（= CI 固定版本）宽集与仓内配置各一遍；`go build ./...`/`go vet ./...`（exit 0）；
`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z16guardtestquality/...`（9 条探针全红）；
另把 `internal/archtest` 用 `go test -c` 编成真 test 二进制、在只含被读产物的临时模块根里跑同一个守卫（带双向对照），
并用 `go test -overlay` 注入变异源码。

**说明**：本目录已有两轮 Z16 遗留文件（`assertless_test.go`、`gates_test.go`，untracked）。我逐条**重跑并复核**，
采纳其元守卫（全仓"无法失败"扫描）与标签普查为 Z16-3/Z16-6 的探针；它们报的 3 条 default-suite 命中经复核是**误报**
（见"探过但没破"6），未作为发现。我另写 3 个文件，每条都带阳性对照。目录：`internal/zzprobe/audit7/z16guardtestquality/`。

## 发现

### Z16-1 CI 的 `load` 门禁在"什么都没测"时仍然绿：没有任何一步读它的输出
- 严重度：P2 中
- 类别：可维护性 / 可用性（门禁覆盖）
- 不变量：fail-closed（产能门禁的绿必须意味着真的测到了东西）
- 证据：`ci.yml` 的 `load` job（`:407-428`）只有一步 `run: make load`；`Makefile:62-63` 是
  `RE0AUTH_LOAD_PROFILE=1 go test -count=1 -v -run TestLoadProfile ./internal/httpapi/`。实测
  `go test -count=1 -run 'TestLoadProfileRenamedAway' ./internal/httpapi/` → `ok … [no tests to run]`，**exit 0**；
  唯一的 floor（`total < 100` → `t.Fatalf`）在 `load_test.go:161`，即被 `-run` 找到的那个测试自己。对照：
  `perf.yml:96-97` 同一门禁多一行 `grep -q 'capacity profile:' load.txt`，`ci.yml:222-224` 也为
  `TestOIDCWiringEndToEnd` 写了 `grep -q -- '--- PASS:'`——**只有 load job 没有**。
- 状态：CONFIRMED（真跑；`jobBlock` 已剥离注释，确认 job 内无 `grep -q`/`::error::`/`exit 1`）
- 影响：把 `TestLoadProfile` 改名/搬包/加 build tag（本仓惯例就是给它加 tag），产能门禁**继续绿**且零测量。
  Makefile:56-57 自述"green 不可能意味着什么都没测"——该自述只靠测试名成立。
- 探针：`z16_ci_gates_test.go::TestZ16LoadJobIsGreenWithZeroMeasurement`（红）
- 修法建议：load job 加一行 `grep -q 'capacity profile:'`（照抄 perf.yml），或 `go test -list '^TestLoadProfile$'` 先断言命中。
- 是否与既有编号相关：无（第五轮 `AUDIT-ISSUES.md:413` 只把它列进"CI 里本地可查的一半全绿"，不是发现）。

### Z16-2 gosec 的 `includes` 是白名单：CI lint 门禁对**有真实生产命中的规则**永远不会红
- 严重度：P2 中
- 类别：安全 / 可维护性（门禁覆盖）
- 不变量：fail-closed（启用的扫描器必须在它的规则有命中时变红）
- 证据：用 CI 固定的 `golangci-lint v2.14.0` 实跑同一个包集：
  - 宽集（`--no-config --default none --enable gosec ./cmd/re0auth/ ./cmd/referencesource/ ./cmd/perfreport/`）报
    `G306`、`G101`、`G115 ×2`、`G112 ×3`、`G114 ×1`，其中**生产代码**两条：`cmd/re0auth/config.go:1063,1066`
    （`out.MaxConns = int32(*section.MaxConns)`，G115）与 `cmd/referencesource/main.go:135`（G114）；
  - 仓内配置（`golangci-lint run …`）报 **`0 issues.` exit 0**。
  `.golangci.yml:55-61` 的 `includes` 只列 G304/G401/G402/G404/G501；gosec 的 `includes` 是**过滤器**，未列出的规则
  即便启用也不运行。该文件注释逐条解释了被排除的 G101/G401 等，却没说 G112/G114/G115 也在被排除之列。
  机制（源级）：`config.go:1098-1102` 的校验发生在 `int32(...)` **之后**（`out.MaxConns < 1`），因此
  `max_conns = 5000000000` 会先被截断成 `705032704` 再通过"合法"，与该文件 1049-1053 行"validate rather than clamp"
  的自述相反。
- 状态：CONFIRMED（真跑两个配置；截断算术语义确定。**生产爆炸半径与 max_conns 取值的现实性**留给区 12 裁定，
  本条只主张"门禁看不见"）
- 影响：配置里任何一处 `int→int32` 截断、监听器少超时、`WriteFile 0644`，lint job 都是绿的；"golangci-lint 通过"
  比实际覆盖面宽。
- 探针：`gates_test.go::TestNarrowedGosecRuleSetHidesNoLiveFinding`（红；含"宽集必须非空"的阳性对照与我复核的
  narrow=0 issues 对照）
- 修法建议：把 `includes` 换成 `excludes`（默认全开、只排除已裁定项），或把 G112/G114/G115 显式加回，或对
  `config.go:1098` 前补 `MaxConns` 上界校验并 `//nolint` 说明。
- 是否与既有编号相关：无（Z13 只读了 `.golangci.yml` 注释，未报规则集被过滤）。

### Z16-3 101（含第六轮共 162）个探针文件在任何 CI 门禁之外：连编译/vet/lint 都看不到（N-04 补充）
- 严重度：P2 中
- 类别：可维护性 / 安全（证据链）
- 不变量：fail-closed（被审计文档当作证据的守卫，必须至少被某个门禁真正执行）
- 证据：`git ls-files '*_test.go'` 中 101 个带 `//go:build audit5`（另有 61 个第六轮 `audit6` 未跟踪文件）。
  实跑 `TestEveryTaggedTestFileIsReachableFromCI` 报 "101 of 266 tracked test files are behind a tag no workflow sets"
  并枚举全表；我的普查（root 行走）报 `audit5:101 audit6:61 audit7:67`、591 个 `func Test`。
  阳性对照：`go list -f '{{len .TestGoFiles}}' ./internal/zzprobe/federation/` 无 tag 报 **0**、`-tags audit5` 报 **>0**；
  workflow 与 `Makefile` 里 `-tags audit` 命中 0 次。因此 `go test ./...`、`go vet ./...`、`golangci-lint run ./...`
  （build tag 生效）**既不运行也不编译**它们。
- 状态：CONFIRMED（两条探针红 + `go list` 双向对照）
- 影响：第五/六轮报告里作为"守卫/证据"引用的上百条探针，其编译性、vet/lint 干净度、断言有效性都没有门禁；任一条因
  生产 API 改名而失效，仓库侧零信号。（实测两轮语料今天仍 exit 0——是运气而非门禁。）
- 探针：`z16_ci_gates_test.go::TestZ16AdversarialProbeCorpusIsInvisibleToCI`（红）、
  `gates_test.go::TestEveryTaggedTestFileIsReachableFromCI`（红）
- 修法建议：CI 加 `probe-compile` job：`go vet -tags audit5 ./...`（可再加 audit6/audit7），把"语料仍在编译"变成门禁。
- 是否与既有编号相关：**对 N-04 的补充**——N-04 记录"探针不在 CI 里跑"，新证据是它们也**不被编译/vet/lint**，附可核查对照。

### Z16-4 `internal/archtest` 的 Makefile 守卫是整文件 `strings.Contains`：注释即可满足
- 严重度：P3 低/提示
- 类别：可维护性（门禁覆盖）
- 不变量：fail-closed（守卫断言的应是 Makefile 的依赖边，而不是文件里出现过某些词）
- 证据：把真 `internal/archtest` 编成 test 二进制，在临时模块根里跑：
  - 对照 1（未变异）→ `TestReleaseShipsNpmAttribution` **PASS**；
  - 对照 2（把 `npm-attribution:` 改成 `npm-licences:`）→ **FAIL**（变异确实到达守卫）；
  - 变异：把 `Makefile:229` 的 `release: dist sbom npm-attribution checksums` 整行加 `# ` 注释掉，四个 needle
    （`workflows_test.go:31-40`）仍以文本形式存在 → 守卫**仍 PASS**，而 `make release` 已无规则。
- 状态：CONFIRMED（真门禁 + 双向对照）
- 影响：该守卫自称"The file must be built by `release` and covered by `checksums`"，实际只检查四个字符串是否出现在
  Makefile 任意位置；同类 `Contains` 形状还用于 k8s 备份脚本 needle（`k8s_test.go:406-414`），注释里留词即可保持绿。
- 探针：`z16_archtest_guards_test.go::TestZ16ArchtestGuardsAreSatisfiedByComments`（红）
- 修法建议：复用同包已有的 `makeTargetInstallsPnpm` 式结构解析，断言 `release` 的**前置**含 `npm-attribution`、
  `checksums` 的 recipe 真读到那个文件（Z13-6 的修法可合并到这里）。
- 是否与既有编号相关：对 **Z13-6**（同一测试的 checksums glob 断言）的**补充**，机制不同（文本 vs 结构）。

### Z16-5 `ci.yml` 的 fuzz 目标清单靠手维护，没有任何守卫保证它完整
- 严重度：P3 低/提示
- 类别：可维护性（门禁覆盖）
- 不变量：fail-closed（声明"覆盖每个 fuzz 目标"的门禁必须能发现新目标未入列）
- 证据：全仓 10 个 `func Fuzz*`，`ci.yml:467-478` 手列 10 条——**今天精确相等**（探针实时算集合差为 0）。把 5 条
  `./internal/oidchttp:Fuzz*` 从清单删掉后，重跑 archtest 里全部读 workflow 的守卫（3 条）**仍全绿**；且
  `internal/archtest/*.go` 里 `Fuzz` 命中 0（探针断言）。`git grep` 证实这些目标名**只**出现在 ci.yml。
  （反方向由 `set -e` 兜住：删目标会让 `go test -fuzz=<不存在>` 报错。）
- 状态：CONFIRMED（真门禁 + 变异；含"清单解析非空"下限）
- 影响：新增 `func Fuzz*` 而忘记改 ci.yml 就被静默漏掉；这正是 `ci.yml:439-441` 注释自述要防的回归。
- 探针：`z16_archtest_guards_test.go::TestZ16NoGuardKeepsTheFuzzTargetListComplete`（红）
- 修法建议：archtest 加一检查：`go test -list '^Fuzz' ./...`（或 go/ast）枚举目标，断言它们全在 `TARGETS` 清单里。
- 是否与既有编号相关：无。

### Z16-6 又三条"算出结论只打印"的探针（同族新实例，含一条可被假期望骗过）
- 严重度：P3 低/提示
- 类别：可维护性（证据完整性）
- 不变量：一条只 `t.Logf` 的探针不能成为任何结论的证据
- 证据（全部真跑，PASS 且只打印）：
  1. `internal/zzprobe/pubaddr/addr_test.go:12-54::TestPubAddrRanges`：构造 `status := "MISMATCH"` 后**只 log**。
     用 `go test -overlay` 注入变异（`{"8.8.8.8","public"}` → `"nonpublic"`）后**仍然 PASS** 并打出
     `8.8.8.8 public want=nonpublic MISMATCH`；反对照：同一 overlay 机制注入 `t.Fatal("overlay applied")` 时该测试**FAIL**。
  2. `internal/zzprobe/federation/safeurl_test.go:425-443::TestProbeURLHostNormalisation`：只 log 归一化结果。
  3. `internal/zzprobe/federation/safeurl_test.go:181-186::TestProbeZonedIPv6DialAddressIsJudgedNotCrashed`：两次
     `netip.ParseAddr` + 两次 `t.Logf`，`err` 丢弃 —— 名字宣告一个判定，代码不判定。
- 状态：CONFIRMED（AST 级"函数体内无任何失败调用" + 执行级 PASS/对照。旧扫描器另报 8 个 tier1，其中已记录的两个先例
  （`raw_test.go::TestProbeRegistryAcceptsPathEscapingNames`、`httpclient_test.go::TestProbeRetryIsNotInstalledOnTheDataPlane`）
  **不计入本条**）
- 影响：SSRF 宿主归一化/区域 ID 与公网地址表这三块的"结论"只存在于日志文本里，回归无人拦。
- 探针：`z16_fake_probe_guards_test.go::TestZ16PubAddrProbeAcceptsAWrongExpectation`、
  `::TestZ16LogOnlyProbesInSafeURLFile`（均红）
- 修法建议：三条各补断言（地址表逐例 `t.Errorf`；归一化断言 scheme/host 白名单；区域 ID 断言 `ParseAddr("fe80::1%eth0")`
  的 err 与 `IsPublicAddress` 的拒绝面）。
- 是否与既有编号相关：同族**新实例**（先例见 `AUDIT-ISSUES.md:271`、`docs/audit-7/findings/22-audit5-red-reconciliation.md:146`）。

### Z16-7 覆盖率 floor 是全仓一个总数，其自述要防的"某包烂到 0"不在覆盖内
- P3 低/提示，HYPOTHESIS，可维护性。`ci.yml:166-167` 自称防 "a package can rot to zero … while every other gate
  stays green"，但 `:170-179` 只把 `go tool cover -func | tail -1` 的全局总数与 62 比（`:49-55` 自述跳过 Postgres
  仍有 66.0%，余量约 4 点），`:186-194` 的逐包表只进 job summary、不设门禁 ⇒ 占全仓语句数 <4% 的包烂到 0 仍绿。
  缺实测（本轮禁跑全仓带覆盖率 `go test`）。修法：逐包设下限。探针：无（源级）。与既有编号相关：无。

## 探过但没破的（也应变成守卫）

1. **10/10 fuzz 目标在列、有种子、fuzz body 有真断言**：`FuzzCleanRawPath` 断言"过 `cleanRawPath` 的段不以 `..` 开头"，
   其余 `_ =` 型断言即"不 panic"（合法的崩溃安全目标）；改名/删除会让 `go test -fuzz` 报错并被 `set -e` 接住。
2. **`-race` 是真并发**：全仓无 `t.Parallel()`，但 30 个 test 文件跑真 `httptest.NewServer`、10 个文件显式 `go func`
   （`cmd/re0auth/main_test.go` 9 处、postgres 审计批 7 处），`ci.yml:160` 的 `-race -p 1` 有真实交错面可测。
3. **Postgres 测试不会静默跳过**：`openTestDBWith` 在 `$CI` 非空且 `TEST_DATABASE_URL` 缺失时 `t.Fatal`；
   `ci.yml:220-224` 另用 `grep -q -- '--- PASS: TestOIDCWiringEndToEnd'` 钉住包外那一条。
4. **两轮探针语料今天仍能编译**：`go vet -tags audit5 ./...`、`go vet -tags audit6 ./...` 均 exit 0。
5. **archtest 的反空转下限都在且非空**：`pinned≥30`、`cached≥3`、`checked>0`、`modules≥20`/`declared≥20`、`FROM≥3`、
   bench `results<3→红`、sbom `components>10`；`readYAMLDocs` 的解析失败会由 kind 断言暴露。
6. **旧扫描器报的 3 条 default-suite "无法失败"是误报**：`TestNilMetricsIsSafe`、`TestScrubToleratesNilAndEmpty`
   的失败方式是**隐式 panic**，`TestConcurrentUseIsSafe` 是 `-race` 数据竞争（CI 开着 `-race`）；三者都能失败，故不作为发现。
7. **Makefile 依赖链 / digest 固定 / Notice/SBOM**：本轮 `go build`/`go vet` exit 0，Z13 已给绿方；我只补 Z16-4 的机制缺口。

## 未能到达（残余盲区）

1. **无 Docker / 无本地 Postgres**：`openTestDBWith` 在真 Linux CI 上是否如期 `t.Fatal`、`-race -p 1` 的真覆盖数字未复现
   （Z16-7 因此只能 HYPOTHESIS）。
2. **本轮禁跑全仓 `go test ./...`**：拿不到逐包语句占比，无法点名"哪些包能烂到 0 而不触发 62"。
3. **Playwright 未装**：`pnpm run test:e2e`/`check:bundle` 未复跑（属区 08）。
4. **宽集 gosec 只扫了三个 `cmd/*` 包**：Z16-2 的隐藏规则清单是**下界**，`internal/**`、`vault/` 未宽扫。
5. **`windows-smoke` 的 pwsh 包集**只在读码层确证。 6. **真 tag / 真发布链路**未跑（与 Z13 同盲区）。

## 判断（文档化决定可否质疑，不是 finding）

- **gosec 子集本身是文档化取舍**（`.golangci.yml:43-51`）：其**形状**与注释理由不匹配（注释按"逐条排除"行文，实现是白名单）。属裁定项。
- **bench/load/perf 的"报数不设阈值"**是文档化决定，不质疑；Z16-1 要的是与 perf.yml 同款的反空转检查，不是阈值。
