# 区域 Z16 复核（对抗性验证）— Z16-VERIFIED

## 方法

复核对象：`docs/audit-7/findings/Z16-guard-test-quality.md`、其探针目录
`internal/zzprobe/audit7/z16guardtestquality/`。**未改动任何被跟踪文件**，未改被复核者的探针。
独立探针：`internal/zzprobe/audit7/z16verify/`（两个文件 + doc.go，全部 `//go:build audit7`，
全部**绿**，即对照组成立；绿在这里的含义是「被复核的机制被本地复现」，不是「没发现」）。

复核跑过的东西（全部亲跑）：

- `go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z16guardtestquality/...` → 9 条红，
  逐条与报告声称的失败理由对照（见下）。
- `golangci-lint v2.14.0`（与 CI 同版本）：宽集
  `--no-config --default none --enable gosec ./cmd/re0auth/ ./cmd/referencesource/ ./cmd/perfreport/`
  → 8 issues / exit 1；仓内配置同一包集 → `0 issues.` exit 0。
- `RE0AUTH_LOAD_PROFILE=1 go test -count=1 -v -run TestLoadProfile ./internal/httpapi/`
  （6s/4workers）→ `capacity profile: 4 workers, 6s, 109416 requests, 18236.0 req/s`，exit 0；
  `-run TestLoadProfileRenamedAway` → `[no tests to run]`，exit 0，输出中**无**该标记。
- 逐行读 `ci.yml`（全部 13 个 job）、`Makefile:50-75`、`internal/httpapi/load_test.go:26-75,150-165`、
  `.golangci.yml`、`internal/archtest/workflows_test.go:16-41`、`k8s_test.go:396-414`、
  `internal/zzprobe/{pubaddr/addr_test.go,federation/safeurl_test.go}`。
- 新建三个一次性 Go 模块，实测「tag 后面的类型/语法错误能不能被默认门禁看见」。
- 用真 test 二进制：`internal/zzprobe/audit7/z16verify` 把整个仓复制到临时根，变异一个 audit6 探针后
  跑**被复核者自己的** `TestEveryTaggedTestFileIsReachableFromCI`。

## 逐条裁定

### Z16-1 load 门禁零测量仍绿 — CONFIRMED，P2 成立
报告的机制被本地正向复现：真 load 跑出 `capacity profile:`（exit 0），零命中 `-run` 同样 exit 0
且**没有**该标记 —— 也就是 perf.yml 那一行 `grep -q` 恰好是有效判据，而 `ci.yml:407-428` 的 load job
只有一步 `run: make load`（我按 job 边界逐行确认 job 内无 `grep -q`/`::error::`/`exit 1`）。
`load_test.go:161` 的 `total < 100` 确实在 `TestLoadProfile` 内部（`:39-41` 还有 env 早退），
所以唯一的 floor 依赖 `-run` 命中测试名。**不构成重报**：`AUDIT-ISSUES.md` 只把它当背景。
附带发现（独立证据）：`make load` 作为门禁在 CI 里是**哑的**而 `perf.yml:96-97` 是响的 —— 同一个
PR 可以让 ci.yml 的 load job 绿、perf 红；perf.yml 不在 PR 门禁里 ⇒ 零测量只会在事后被人肉发现。

### Z16-2 gosec `includes` 是白名单 — CONFIRMED，P2 成立
独立复现：宽集 8 条（`G306`/`G101`/`G115×2`/`G112×3`/`G114×1`，其中
`cmd/re0auth/config.go:1063,1066` 与 `cmd/referencesource/main.go:135` 是**生产文件**），
仓内配置同一包集 `0 issues.`。报告把 G306（`cmd/perfreport/main.go:655`，生产文件的 0644 写）
也只当作宽集成员而不单独主张，措辞克制，无夸大。源级补充确认：`config.go:1098-1102` 的校验
发生在 `int32(...)`（`:1063,1066`）之后，与 `:1049-1053` 的 "validates rather than clamps" 自述相反。
**不构成误报文档化决定**：`.golangci.yml:43-51` 只解释了不做全量 gosec，逐条注释里只提到
G101 与两个 pattern，没有一处说 `includes` 是过滤器、也没说 G112/G114/G115/G306 被静默排除；
`docs/dependencies.md:121` 也只写"标准分析器 + 少数检查"。报告把它写成"形状与注释理由不匹配"的
裁定项，处理恰当。

### Z16-3 被标记探针不在任何门禁（连编译/vet/lint 都没有）— CONFIRMED，P2 成立（标注为 N-04 补充）
计数复核：`git ls-files '*_test.go'` = 266；`audit5` = 101；CI 与 Makefile 中 `-tags` 命中 0
（唯二命中是 `bench-ab.yml` 的 `--no-new-privileges` 类假阳与 `Makefile:145` 的 `git describe --tags`）。
我自己另建最小模块实测报告最核心的加强项：带 `auditX` 标签的测试文件里放
`real("string")`（类型不符）与 `noSuchFunctionAnywhere()`（未定义函数）后，
`go build ./...` 与 `go vet ./...` **都 exit 0**，只有 `go vet -tags auditX ./...` 才红。
报告正文（以及 `docs/security-audit-7.md:367` 的转述）有一处**过宽**：它说"语法/编码错误仍会暴露，
因为 Go 为了取 import 会词法扫描整个文件"。实测**不成立**：我把 `func oops( {` 和未终止字符串放进
被 tag 排除的文件，`go build ./...`、`go vet ./...`、`go test -c` **全部 exit 0**。这不是把
Z16-3 降级（它加强而非削弱该结论），但它是一处需要更正的机制描述。

### Z16-4 archtest 的 Makefile 守卫是整文件 `strings.Contains` — CONFIRMED，P3 成立
`workflows_test.go:31-40` 四个 needle 的确是整文件包含判断；报告的变异（把
`release: dist sbom npm-attribution checksums` 整行注释掉）语义上确实让 `make release` 无规则，
且四个 needle 仍以文本存在。我核了它给出的变异载荷字符串与 Makefile 里的目标行一致。
夹具非桩：它编译**真的** archtest 二进制并在临时根里跑，含"未变异必须 PASS""改名必须 FAIL"
双向对照，不是自造替身。

### Z16-5 ci.yml 手维护 fuzz 目标清单无守卫 — CONFIRMED，P3 成立
我独立枚举：全仓 `^func Fuzz` = 10（idp 1、oauth 1、internal/federation 3、internal/oidchttp 5），
与 `ci.yml:467-478` 的 10 条**逐条相等**；`git grep` 级核对：`Fuzz\w+` 在整个
`.github/workflows/*.yml` + `Makefile` 里只出现在 ci.yml（另 2 处命中是同一 job 的注释文本），
目标名不在别处。`internal/archtest/*.go` 中 `Fuzz` 命中 0。报告说"反方向由 `set -e` 兜住"
（删目标/改名会被 `go test -fuzz=<不存在>` 抓住），这一限定是对的，所以它只主张"新增目标会静默漏掉"。

### Z16-6 三条"算出结论只打印"的探针 — CONFIRMED，P3 成立
我逐行核对：`pubaddr/addr_test.go:12-54` 构造 `status := "MISMATCH"`（`:48-51`）后只有 `t.Logf`（`:52`），
无任何失败调用；`federation/safeurl_test.go:425-443` 只 `t.Logf`；`:181-186` 两次 `netip.ParseAddr`
后只 `t.Logf`，`err` 被丢弃。三者我都在 `-tags audit5` 下实跑并 PASS（另在
`z16verify::TestRecordedPrecedentsAreStillGreen` 里把两条"已记录先例"也跑绿，确认报告划分的
"先例 vs 新实例"边界是真的）。报告明确写了这两条先例**不计入**本条并给了出处，属同族新实例，
不是重报既有编号。

### Z16-7 覆盖率 floor 是全仓总数 — 裁定：报告标 HYPOTHESIS 偏保守，可升 CONFIRMED（源级），P3 不变
我读了 `ci.yml:47-55`（`COVERAGE_FLOOR: '62'`，注释自述跳过 Postgres 仍有 66.0%）、
`:170-179`（唯一的判据是 `tail -1` 的全局数）、`:186-194`（逐包表只 `>> $GITHUB_STEP_SUMMARY`，
无读回）。断言"某包烂到 0 而其它门禁全绿"不需要运行时：62 < 66.0 且 66.0-62 = 4.0 点；
只要没有任何**单包**占全仓语句 ≥4 点，该包归零不会把全局拉破 62。缺的只是"哪个包"的点名。
因此我认为它是**源级 CONFIRMED**（依赖的前提是确定性算式），报告更保守的 HYPOTHESIS 不影响其成立。
它自述"探针：无（源级）"——这是弱点，但按简报 §3 第 2 项，读码到行足以 CONFIRMED。

## 新发现（本次复核新增，均带独立证据）

### VZ16-1 [P3] 「可达性」守卫只读文件与 build 注释，从不编译：给它想要的 `-tags` 就能变成永久绿
- 证据：`gates_test.go:211-297` 的语义是「标签必须被某个 workflow 设置」。用真 test 二进制把整仓
  复制到临时根，把一条 audit6 探针改成调用不存在的函数（`go vet -tags audit6` 该包 exit 1），
  再跑被复核者的守卫：它**照常把该文件列进清单**（"…tracked test files are behind a tag no workflow
  sets"，文件按名出现），全程只读文本。探针：
  `z16verify::TestTaggedCorpusGuardIsBlindToWhetherItsFilesCompile`（绿）。
  **后续（已修复）**：编译步已在 `gates_test.go` 的 "real compile" 段落地；该证伪探针据此改名并翻转为
  回归对照 `z16verify::TestTaggedCorpusGuardCompilesWhatItAccepts`（同一株植入现在让守卫以
  `COMPILE FAILURE` 变红，孤儿形态仍被点名）。
- 影响：任何人为了消掉 Z16-3/N-04 的红，把 `-tags audit5,audit6,audit7` 加进一个 job，这条守卫
  会变成永久绿，而被 tag 排除的文件里的类型/未定义错误（VZ16-1 的实测面）仍然一个都看不见 ——
  "别靠标签藏起来"这条规则需要一个编译步骤，现在只有一次 grep。

### VZ16-2 [P3] 该守卫只认 `//go:build`，旧式 `// +build` 约束被它当成「默认套件」
- 证据：`gates_test.go:260-271` 只在 `//go:build` 前缀上取标签。把一条 audit6 探针换成只有
  `// +build audit6` 的形式后：`go vet ./internal/zzprobe/audit6/z05memstore/...`（默认）exit 0，
  `go vet -tags audit6 …` exit 1（**工具链仍认它是受约束文件**），而守卫的报告里
  `rev1_test.go` 从不出现。探针：
  `z16verify::TestTaggedCorpusGuardParsesOnlyGoBuildNotTheLegacyTag`（绿）。
  **后续（已修复）**：`buildConstraintOf` 已同时解析 `//go:build` 与 `// +build`；该证伪探针据此改名并翻转为
  回归对照 `z16verify::TestTaggedCorpusGuardReadsTheLegacyBuildTag`（workflow 命中该旧式标签时编译步失败，
  旧式孤儿标签被点名为 orphan）。
- 影响：一条 `// +build` 形式的探针既是"默认套件看不见的"又是"守卫认为在默认套件里"的，
  它和它引用的修复都不会被任何一侧兜住。修法：`go list -f '{{.TestGoFiles}}'`（真工具链）取代
  文本扫描，或同时解析 `// +build`。

## 探过但没破（复核侧）

1. **探针夹具不是桩**：Z16-4/Z16-5 的 archtest 变异确实编译真 `internal/archtest` 二进制并在临时根
   里跑；我逐行读了 `buildArchtest`/`runArchtest`/`archtestRoot`，没有发现"夹具替换掉了真守卫"的假绿。
2. **Z16-6 的 overlay 机制有效**：`writeOverlay` 用绝对路径 + `go test -overlay`，报告声明的
   `t.Fatal("overlay applied")` 反对照是有效阳性对照；我另外用 `-tags audit5` 复跑了三条被点名探针
   与被排除的两条先例，全部 PASS。
3. **无重报**：Z16-1/2/4/5 在 `AUDIT-ISSUES.md`、第五/六轮编号与 `docs/security-audit-7.md` 中
   无对应条目；Z16-3 显式写了"对 N-04 的补充"并给出新证据（不被编译），Z16-4 显式写了
   "对 Z13-6 的补充，机制不同"，Z16-6 显式给了两条先例出处。均符合简报 §4.4。
4. **严重度无虚高**：9 条中最高 P2，全部是门禁覆盖/证据链，无运行时可利用面；P3×4 里没有
   把"文档化决定"当缺陷的条目（`gosec` 子集与 bench/load 不设阈值都被报告放进"判断"）。
5. **九条红探针的失败理由与报告声称一致**：逐条对照运行输出，无一条是"因别的原因红"
   （唯一的机制性偏差是 Z16-3 正文里"语法/编码错误仍会暴露"这句，已在上文更正）。

## 未能到达

- 无 Docker / 无本地 Postgres：`-race -p 1` 的真覆盖率数字、逐包语句占比拿不到；Z16-7 的
  "哪个包能烂到 0"只能按算式判定，不能点名。
- 未跑全仓带覆盖率的 `go test ./...`（并行代理共用工作区），因此没有实测 62 的余量。
- `windows-smoke` 与 release 链路只在读码层确证（与 Z13 同盲区）。

## 判断（不是 finding）

- Z16-1 的修法（加 `grep -q 'capacity profile:'`）与 perf.yml 同款，属最小改动，不涉及裁定；
  "load 不设阈值"本身是文档化决定，报告没有质疑它，正确。
- Z16-3 若按报告修法（CI 加 `go vet -tags audit5 ./...`）落地，建议同时把 VZ16-1/VZ16-2 一起收：
  否则"标签可达性"守卫会给出一种虚假的安心。
