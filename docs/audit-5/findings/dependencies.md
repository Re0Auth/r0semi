# 依赖图与构建/发布供应链 审计报告

> 审计对象：`.`（Re0Auth，模块 `github.com/Re0Auth/r0semi`）
> 区域：Go/npm 依赖图、已知漏洞与**可达性**、锁文件与可复现性、许可合规、发布产物链完整性
> 环境：Windows 11 + Go 1.27.1 + Node 24.17 + pnpm 11.8.0；**无 Docker、无本地 Postgres**
> **ID 前缀说明**：本报告用 `SUP-`，因为 `deploy-ops.md` 已占用 `DEP-`（DEP-01…DEP-28）。
> 与其他报告的**重叠**在本报告里逐条点明（`A-FE-*` = `frontend.md`，`DEP-*` = `deploy-ops.md`），
> 重复的部分**不当作新发现**重报。

---

## 范围与方法

### 读了什么

`docs/audit-5/BRIEF.md`、`docs/dependencies.md`（§3 非目标、§5 前端、§6 CI 工具、§7 供应链边界）、
`NOTICE`、`go.mod`、`go.sum`、`web/package.json`、`web/pnpm-lock.yaml`、`web/.npmrc`、
`docs/security-audit-2.md`、`docs/security-audit-3.md`（确认前两轮没覆盖本区域）、
`README.md`（发布/验证/镜像三节）、`.github/workflows/{ci,release,codeql,perf,visual-baselines}.yml`、
`.github/dependabot.yml`、`Makefile`、`Dockerfile`、`LICENSE`、
`internal/archtest/{notice,dockerfile,workflows}_test.go`、`internal/webui/webui.go`（`//go:embed all:dist`）、
以及同行报告 `docs/audit-5/findings/{frontend,deploy-ops}.md`（用于去重）。

### 跑了什么（关键命令与结果）

| 命令 | 结果 |
|---|---|
| `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0`（CI 钉的版本，`ci.yml:349`） | 装成；`govulncheck -version` → `Go: go1.27.1 / Scanner: govulncheck@v1.8.0 / DB: https://vuln.go.dev`，DB 更新于 `2026-09-24T20:07:49Z`（与 `https://vuln.go.dev/index/db.json` 的 `modified` 一致） |
| `govulncheck ./...` | **`No vulnerabilities found.`**（exit 0） |
| `govulncheck -show verbose ./...` | 打印「scanned the following 42 modules and the go1.27.1 standard library」→ 结论非空转 |
| **对照实验**（`%TEMP%\r0semi-govuln-control`：一个 import `golang.org/x/text/language@v0.3.7` 并调用 `ParseAcceptLanguage` 的模块） | `Vulnerability #1: GO-2022-1059 … main.go:10:44: control.main calls language.ParseAcceptLanguage` / `Your code is affected by 1 vulnerability from 1 module.`（exit 3）→ **证明工具与 DB 在这个网络上真的能报出可达漏洞**，所以上面那句"没有漏洞"是有信息的 |
| `go list -deps` 六个 `GOOS/GOARCH` | linux 42 / 其余各 41 个第三方模块；差集只有 `github.com/prometheus/procfs`；六平台并集 = 42 |
| 自建"发布形状"二进制：`CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=audit-probe" ./cmd/re0auth` + `go version -m` | 内嵌 **42** 个 `dep` 模块，与 SBOM 的 42 个组件**集合相等** |
| `cyclonedx-gomod mod -json`（v1.12.0，与 `ci.yml:361-362`/`Makefile:193` 完全同参） | 42 个 `library` 组件、specVersion 1.6、**`licenses` 字段 0/42**、`hashes` 42/42、含 `prometheus/procfs` |
| OSV API：对 `go list -m all` 的 **137** 个模块**按钉住的版本**批量查 | 只有 5 条命中，全在 `x/crypto@v0.55.0`、`x/mod@v0.38.0`（详见 SUP-8） |
| `go mod why -m golang.org/x/{crypto,mod}` | 两条都是 `(main module does not need module …)` |
| `go mod verify` | `all modules verified` |
| `go env GOPROXY GOSUMDB GONOSUMDB GOPRIVATE GOFLAGS GONOSUMCHECK GOINSECURE GOVCS GOTOOLCHAIN` | `https://proxy.golang.org,direct` / `sum.golang.org` / **其余全空** / `auto` |
| 四个 workflow 的 `uses:` / `image:` 全量扫描 | 43 处 `uses:` 全部 40 位 SHA（唯一例外 `release.yml:23` 本地复用 workflow）；`image:` 只有 `postgres:16`（×2）非 digest |
| `pnpm audit --prod --registry=https://registry.npmjs.org/` | `No known vulnerabilities found`，但 JSON 里 `totalDependencies: 0` |
| `pnpm audit --registry=https://registry.npmjs.org/` | 1 条：`cookie@0.6.0`（`GHSA-pxg6-pf52-xh8x`/CVE-2024-47764，**low**） |
| `pnpm audit` 的**对照实验**（临时目录里 `lodash@4.17.20`） | 报出 6 条（含 high `GHSA-35jh-r3h4-6jhm`）→ 端点有效，上面的结果不是"端点没通" |
| 遍历 `web/node_modules/.pnpm/**/package.json`（123 实例 / 52 唯一包） | 许可 MIT 90 / Apache-2.0 15 / MPL-2.0 10 / ISC 5 / BSD-3 3；**无包缺 license 字段、无包缺许可文件**；**无包声明 `preinstall`/`install`/`postinstall`**（27 处全是 `prepare`/`prepublishOnly`） |
| 构建图 42 个 Go 模块**逐个读 `$(go env GOMODCACHE)` 里的 LICENSE/COPYING/NOTICE 原文**并分类 | 无 `NO-LICENSE-FILE`、无 `UNKNOWN`、无 GPL/AGPL/SSPL/BSL/Commons-Clause |
| `go test ./internal/archtest/ -run TestNoticeCoversTheBuildGraph -v` | `--- PASS` |
| `go test ./internal/archtest/ -run 'TestDockerfileBaseImagesArePinned\|TestWorkflowsCacheOnlyWhatTheyCreate' -v` | 两条 PASS（并由此确证它们**不覆盖** `uses:` / service 镜像 / 工具 pin） |
| 上游 `docker-library/golang` 的 `1.27/alpine3.23/Dockerfile` 原文 | `ENV GOLANG_VERSION 1.27.1` + **`ENV GOTOOLCHAIN=local`** |
| 剥符号对照（临时模块，`-s -w` vs 不剥，各跑一次除零 panic） | `go tool nm`：**0** vs **2490** 条符号；**panic 栈两边完全一致且都有函数名** |
| 前端包最新版本（`registry.npmmirror.com/<pkg>/latest`）+ OSV 逐版本查 | 见「探过但没破的」第 12 条 |
| `internal/webui/dist/**` 全量 grep `copyright\|@license\|SPDX\|Licensed under` | **0 命中**（27 个交付文件，181 KB） |
| `go test ./internal/zzprobe/dependencies/ -v`（**本次审计新建的探针**） | 4 条：1 条 PASS（`TestProbeWorkflowActionsArePinnedToASHA`，即"固定今天是对的"这条被落成了守卫）、3 条 **FAIL** —— 逐条复现 SUP-1 / SUP-2 / SUP-4，见各自的「复现/守卫」 |

### 什么跑不了

- **没有 Docker**：`docker build`/`buildx`、Trivy 镜像扫描、以及"看 pinned digest 里真实的 Go/Node 版本"全都做不了。
- **没有已发布的 release 产物**：`SHA256SUMS` 的覆盖面是"读 `Makefile` 到行"的结论，不是在 release 页上跑 `sha256sum -c`。
- **没有 cosign**：无法端到端验证 `README.md:126-132` 的 `verify-blob`（只能核对 identity 字符串与 workflow 路径一致）。
- **npm audit 必须显式指定官方 registry**：本机 user-level `~/.npmrc` 指向 `registry.npmmirror.com`，该镜像没有 audit 端点
  （`ERR_NPM_AUDIT_ENDPOINT_NOT_EXISTS`）。我自己踩到了这一点，并且核对确认 `frontend.md`（A-FE-5 一节）已经记过同一件事，
  所以本报告不把它当新发现（见「探过但没破的」第 17 条）。
- **本机网络不稳**：对 `proxy.golang.org` 的 IPv6 连接多次超时（`dial tcp [2404:…]:443`），
  `go install cyclonedx-gomod` / `govulncheck` 是靠换镜像与重试装上的。不影响结论，但说明这里的"能装成"带运气成分。

### 本次新建的探针（只新建文件，未修改任何被跟踪文件）

- **`.internal\zzprobe\dependencies\dependencies_probe_test.go`**（新包 `internal/zzprobe/dependencies`）
- 测试函数：`TestProbeWorkflowActionsArePinnedToASHA`、`TestProbeDockerfileRuntimeCarriesLicenceAndNotice`、
  `TestProbeDistRecipeCopiesAreFatal`、`TestProbeShippedFrontendCarriesThirdPartyAttribution`
- 跑法：`go test ./internal/zzprobe/dependencies/ -v`
- 该包只读文件（workflow / Makefile / Dockerfile / `internal/webui/dist`），不需要 DB、Docker 或任何安装；
  按 BRIEF §4，包留在这里由主代理统一清理。
- 其余证据是**命令输出**（govulncheck、OSV、pnpm audit、cyclonedx-gomod、`go version -m`），
  原始产物放在 `%TEMP%\r0semi-dep-evidence\`，不进仓库。

### 环境异常（先说，否则别人找不到我的证据）

审计进行中 `docs/audit-5/` 曾被另一个进程整体删除过一次（连只读的 `BRIEF.md` 都不见了），
之后又被恢复。我把全部中间证据放在 **`%TEMP%\r0semi-dep-evidence\`**
（`sbom_mod.cdx.json`、`mods_*.txt`、`re0auth-linux-amd64`、`npm_currency.txt`），
避免共享目录被清理时丢掉可复核的原始输出。

---

## 发现

### SUP-1 交付给用户的前端代码没有任何版权/许可文本，而 NOTICE 声称覆盖"发布产物的构建图"

- 严重度: **中**
- 类别: 合规/隐私（兼 可维护性）
- 不变量/性质: NOTICE 是发布产物的许可与归属清单（`NOTICE:5-8`：*"The list below covers every module in the
  build graph of the released binaries and libraries"*）
- 证据:
  1. `internal/webui/dist/**` 的**全部 27 个交付文件（181 KB）**里：
     ```
     Get-ChildItem internal\webui\dist -Recurse -Include *.js,*.css |
       Select-String -Pattern 'copyright|@license|SPDX|Licensed under'    →  无输出（0 命中）
     ```
  2. 这些文件里确实有第三方运行时：`_app/immutable/chunks/xihTtKlq.js` **全文只有 65 字节**，内容就是
     ``typeof window<`u`&&((window.__svelte??={}).v??=new Set).add(`5`)``（Svelte 5 运行时注入）；
     `sEbpUoe5.js`（26.6 KB）是 SvelteKit 客户端运行时；`B-QHV2o-.js`（56.8 KB）含 `hydrat`/`devalue` 标记。
  3. `internal/webui/webui.go:47` 是 `//go:embed all:dist`，`:52` 对它 `fs.Sub` —— 所以上面这批字节
     **就是**二进制里、六平台归档里、GHCR 镜像里的那一批；`Makefile:156` 与 `ci.yml:96-99` 都断言
     `index.html` 存在，即"嵌进去的是真应用而不是占位文件"。
  4. `NOTICE` 的 42 条条目**全部是 Go 模块路径**，一条 npm 包都没有；
     `internal/archtest/notice_test.go:45` 的守卫用 `go list -deps ./...`（Go 模块图）比对 NOTICE —— 前端结构上不在任何守卫里。
  5. `NOTICE:113-116` 与 `Makefile:167` 只覆盖 Go 侧：归档里放的是 `LICENSE`/`NOTICE`/`README.md`/`SECURITY.md`/示例配置。
- 状态: **CONFIRMED**（对磁盘上 embed 输入逐文件 grep + 读 `webui.go` 到行；嵌的就是它，不需要执行就能断定）
- 影响: MIT/ISC 的条款要求"在软件的所有副本中保留版权声明与许可文本"。当前**每一个**发布产物
  （六个归档、两个平台的镜像、以及二进制本身）都在再分发 Svelte/SvelteKit 等 npm 代码，而这些代码在产物里
  **没有任何归属或授权说明**；同时 `NOTICE` 的抬头使人相信这件事已经覆盖。这类缺陷**不可回溯修复**：已发出的归档补不了。
- 修法建议（最小改法，两步且缺一不可）:
  1. 生成 npm 侧清单（`pnpm licenses list` 一类）并入 `NOTICE` 的独立小节（或 `NOTICE-frontend`），
     并把它加进 `Makefile:167` 的 `cp` —— 覆盖"归档"这一侧。
  2. 让构建产出自带归属：给 rolldown 开 legal-comments 保留，并加**反空转断言**（产物里必须出现 N 处许可文本），
     否则这条配置会静默失效。只做 1 不做 2，**嵌进二进制的** JS 里仍然没有归属。
- 复现/守卫: **探针**：`internal/zzprobe/dependencies/dependencies_probe_test.go` 的
  `TestProbeShippedFrontendCarriesThirdPartyAttribution`。实际运行（FAIL，含反空转地板）：
  ```
  go test ./internal/zzprobe/dependencies/ -run TestProbeShippedFrontendCarriesThirdPartyAttribution -v
  --- FAIL: TestProbeShippedFrontendCarriesThirdPartyAttribution
      dependencies_probe_test.go:237: 21 built assets ship inside the binary but none carries a copyright
      or licence notice: the Svelte/SvelteKit runtime (3 files mention it) is redistributed without
      attribution, and NOTICE lists Go modules only
  ```
  它自带两层非空转：至少要读到 5 个产物，且**必须**有一个产物提到 Svelte 运行时的标记
  （否则说明读的不是真构建，licencing 结论作废）。修好 SUP-1 的修法 2 后这条会转绿。
- **与其他报告的关系**: `frontend.md` A-FE-8 报的是**未使用**的 `web/src/lib/assets/favicon.svg` 仍是 Svelte 官方 logo
  （信标/品牌问题，且那个文件**不被服务**），与"交付物没有许可文本"不是同一件事，两者互补。

### SUP-2 容器镜像不携带 `LICENSE` / `NOTICE`（归档携带）

- 严重度: **低**
- 类别: 合规/隐私
- 不变量/性质: 同一版本的所有交付形态携带同一份许可与归属材料
- 证据: `Dockerfile:59-64` 的运行时阶段只有三条有效指令（`FROM scratch`、一条 `COPY` CA bundle、
  一条 `COPY /out/re0auth`、`USER 65532:65532`），**没有** `COPY LICENSE` / `COPY NOTICE`；
  `release.yml:49-53` 的 labels 全部来自 `docker/metadata-action` 的标准字段，没有 `org.opencontainers.image.licenses`。
  对照 `Makefile:167`：归档**有**这两个文件。
- 状态: **CONFIRMED**（读 `Dockerfile` 到行：镜像内容是可穷举的）
- 影响: 拉镜像的人拿不到 MPL-2.0 全文，也拿不到 Apache-2.0 §4(d) 要求的 NOTICE 归属
  （`coreos/go-oidc`、`zitadel/oidc`、`prometheus/*` 的 NOTICE 文本都在 `NOTICE` 里）。
- 修法建议: `COPY LICENSE NOTICE /`（约 10 KB，scratch 的代价可忽略）+ 在 labels 里写 `MPL-2.0`。
  同时把它写进 `docs/dependencies.md` §7 的"做了的"，否则下次会有人当多余文件删掉。
- 复现/守卫: **探针**：同文件的 `TestProbeDockerfileRuntimeCarriesLicenceAndNotice`。实际运行（FAIL）：
  ```
  --- FAIL: TestProbeDockerfileRuntimeCarriesLicenceAndNotice
      dependencies_probe_test.go:113: the runtime image stage never copies LICENSE; the archive does
      (Makefile:167), so the two artifacts of the same tag are not equally redistributable
      dependencies_probe_test.go:113: the runtime image stage never copies NOTICE; ...
  ```
  它先断言 `FROM scratch` 仍在（否则"最后一个 FROM 之后"这个解析前提就变了），再查两条 `COPY`。
- **与其他报告的关系（重要）**: `deploy-ops.md` **DEP-21** 已经报了同一条根因的另一面 ——
  "镜像里没有'未达生产可用'的警告文本，归档里有"，并给出了同样的修法方向。
  本条**不重复那一维**，只补"许可与归属"这一维：两者是同一个 `Dockerfile` 缺口的两份材料。
  如果只取一条，应取**能覆盖两者的合并项**（把 `LICENSE`、`NOTICE`、`SECURITY.md` 一起 `COPY` 进镜像并加 label）。

### SUP-3 `uses:` 的 SHA 固定没有任何守卫，而文档把它写成"已被测试守住"

- 严重度: **低**
- 类别: 可维护性（兼 供应链）
- 不变量/性质: 文档所描述的守卫确实存在
- 证据:
  - `docs/dependencies.md:121-125`: "CI action 按 commit SHA 固定、基础镜像按 digest 固定、扫描器与工具按精确版本固定…
    **固定本身由 `internal/archtest` 与 `internal/observability` 的产物一致性测试守住，不靠约定**。"
  - 现状是对的：我把四个 workflow 的 **43 处** `uses:` 全部抽出来比对，
    唯一不是 40 位 SHA 的是 `release.yml:23` 的 `./.github/workflows/ci.yml`（本地复用，本就没有 SHA 可言）；
    `release.yml:91` 的 Trivy 按 digest；`Dockerfile:13,38` 的基础镜像按 digest。
  - 但守卫不存在：
    `internal/archtest/workflows_test.go` 唯一的 workflow 检查是 `TestWorkflowsCacheOnlyWhatTheyCreate`
    （缓存 pnpm 的作业必须真的安装过 pnpm）；
    `internal/archtest/dockerfile_test.go:27` 只读 `Dockerfile`（`os.ReadFile(filepath.Join(root, "Dockerfile"))`），**不看 workflow**；
    把 `*_test.go` 全量 grep `govulncheck|v1\.8\.0|v2\.14\.0|v8\.30\.1|v1\.12\.0|golangci-lint|gitleaks|cyclonedx`
    → **0 命中**；没有任何测试检查 `uses:` 的形状。
  - `internal/observability/artifacts_test.go` 是"声明与产出的指标一致"，与固定无关。
- 状态: **CONFIRMED**（全量抽取比对 + grep 零命中；两条 pin 守卫我都实际跑过，PASS，且由此确证它们不覆盖这一项）
- 影响: 今天没有洞，但这条属性只靠"人记得"。下一个 `uses: actions/checkout@v7` 能通过**全部**门禁，
  而文档会让评审者相信它不可能发生。这正是 `docs/dependencies.md:106` 自己为固定版本辩护时用的论证的反面：
  **一条不存在的门禁会让人以为不需要检查**。
- 修法建议: 把已经写在注释里的规则变成测试：解析 `.github/workflows/*.yml` 的 `uses:`，
  断言 `@` 后是 40 位 hex（白名单 `./` 开头的本地复用）；`go install …@` 的版本不得是 `latest`。
  反空转地板 = "至少解析到 N 处 `uses:`"（当前 43）。
- 复现/守卫: **探针**：同文件的 `TestProbeWorkflowActionsArePinnedToASHA`。实际运行：
  ```
  --- PASS: TestProbeWorkflowActionsArePinnedToASHA (0.00s)
  ```
  它**就是**这条缺失的守卫（本次审计新建）：解析全部 workflow 的 `uses:`，远程 ref 必须匹配 `@[0-9a-f]{40}$`，
  并豁免 `uses: ./…`；自带两层反空转地板（远程 ref 数 ≥ 10、本地复用数 ≥ 1），
  这样"重命名/搬走 workflow"会让它失败而不是空转通过。
  建议把这条和 `go install …@latest` 的禁令一起移进 `internal/archtest/workflows_test.go`（那边已经在读 workflow 了）。
- **与其他报告的关系**: `deploy-ops.md` **DEP-22** 已报"工具版本 pin 没有更新通道/没有过期检查"（含
  `Makefile:110,152,191` 与 workflow 里同一版本号无人比对、dependabot 覆盖不到 `go install`）；
  **DEP-19** 已报"CI 用浮动 `postgres:16`"。
  本条**只保留增量**：action `uses:` 的 SHA 形状没有守卫，以及那句"由 archtest 守住"对 workflow 其实是空的。
  三者合起来同一个修法：**给 `internal/archtest/workflows_test.go` 加"workflow 固定性"一族检查**。

### SUP-4 `make dist` 的 `cp` 不是致命的，归档内容也没有断言：缺一个 `NOTICE` 也能发出去

- 严重度: **提示**
- 类别: 可用性 / 合规（发布完整性）
- 不变量/性质: 「这个归档里确实有 README 承诺的那些文件」（`README.md:117-118`）
- 证据: `Makefile:158-174` 的循环里，**`go build` 与 `tar`/`zip` 都带 `|| exit 1`，唯独 `cp` 没有**：
  ```make
  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
      -ldflags "-s -w -X main.version=$(VERSION)" \
      -o "dist/$$name/re0auth$$ext" ./cmd/re0auth || exit 1;
  cp config/re0auth.example.toml LICENSE NOTICE README.md SECURITY.md "dist/$$name/";   # ← 无守卫
  if [ "$$os" = windows ]; then ... zip ... || exit 1; else tar ... || exit 1; fi;
  ```
  这是 `sh -c` 里的一行循环体，**没有 `set -e`**：`cp` 失败只打印一行错误，循环继续，
  后面的 `tar`/`zip` 照样成功 → 产出一个**缺文件的合法归档**，而 `checksums` 会照常为它生成摘要。
  已有一个**文本级**守卫：`internal/zzprobe/deploy/artifacts_test.go:475 TestReleasedArchivesCarryThePreReleaseWarning`
  检查 `dist` 配方里是否提到 `README.md` 与 `SECURITY.md`（5 个文件里的 2 个）。
  它**挡不住**这一类：它读的是 Makefile 配方文本，所以源文件在磁盘上被改名/搬走时它仍然通过，
  而运行时 `cp` 静默失败。另外三个文件（`LICENSE`、`NOTICE`、示例配置）也不在它覆盖内。
- 状态: **CONFIRMED**（读 Makefile 到行 + `sh` 语义 + 读了那个探针确认它断言的是配方文本）
- 影响: 今天五个文件都在，属潜伏缺陷。触发条件是"有人搬动 `config/re0auth.example.toml` 或给 `NOTICE` 改名"，
  之后每个归档各少一个文件而发布仍然成功 —— 这正好会把 SUP-1/SUP-2 的合规问题一起掩盖掉。
- 修法建议: `cp ... || exit 1`（或循环前 `for f in …; do test -f "$$f" || exit 1; done`），
  并在打包后加内容断言（对每个归档 `tar -tzf` 必须列出可执行文件与 `NOTICE`）。
  后者可以做成不需要发版的测试：解析 `dist` 配方，断言每条 `cp` 都带 `|| exit 1` 或前置 `test -f`。
- 复现/守卫: **探针**：同文件的 `TestProbeDistRecipeCopiesAreFatal`。实际运行（FAIL）：
  ```
  --- FAIL: TestProbeDistRecipeCopiesAreFatal
      dependencies_probe_test.go:149: this copy in the dist recipe cannot fail the recipe, so a missing
      source file ships an archive without it:
        cp config/re0auth.example.toml LICENSE NOTICE README.md SECURITY.md "dist/$$name/"; \
  ```
  它先断言 `dist` 配方里**至少有一条** `cp`（否则"有守卫"与"什么都没复制"不可区分），
  再要求每条 `cp` 带 `|| exit 1` 一类后缀。`deploy-ops` 的文本级探针（`internal/zzprobe/deploy/artifacts_test.go:475`）
  覆盖 5 个名字里的 2 个、且不看致命性，所以两条不重叠。

### SUP-5 同一 tag 的两个交付物（归档 vs GHCR 镜像）内嵌的前端不可能相同

- 严重度: **提示**
- 类别: 可维护性（可复现性）/ 供应链证据
- 不变量/性质: 「验证了归档就等于验证了镜像」（README 把两者描述为对等的发布产物）
- 证据:
  - `frontend.md` **A-FE-9**（严重度**中**，CONFIRMED，两次连续构建逐文件 sha256 对照）已证明
    **同一份源码构建两次产出不同字节**：`_app/version.json` 里的毫秒时间戳进入客户端分块，
    导致 12/20 个 JS 分块的内容与**文件名**一起改写，`index.html` 与 CSP 里的 `script-src` 哈希随之改变。
  - 我这一侧的增量是**发布链的构成**：`release.yml` 在**两个不同的作业**里各构建了一次前端 ——
    `image` 作业在 `Dockerfile:31-35`（`node:24-alpine@sha256:…` 内）里 `pnpm run build`，
    `release` 作业在宿主 runner 上走 `make web`（`release.yml:127`）。两次构建的环境不同（Node 版本见下条），
    结果按 A-FE-9 必然不同。
- 状态: **CONFIRMED**（A-FE-9 的实测 + 我对两个作业构建路径的逐行阅读；我不重复跑那两次构建）
- 影响: 任何"源相同 ⇒ 产物相同"的核对都会在这里失败。各自仍有 `SHA256SUMS`/Trivy/cosign，
  所以不是不可检测；但**归档里的 SPA 与镜像里的 SPA 不是同一批字节**，这句话目前没有任何文档说出来。
  对"用一个 digest 去复算另一个产物"的取证做法是直接障碍。
- 修法建议: 根因修法在 A-FE-9（把版本号改成由源码/`RE0AUTH_BUILD` 决定，时间戳退出产物）。
  链条侧的最小改法是**只构建一次**再把产物喂给镜像（`docker build` 用 `--build-context` 或把
  `internal/webui/dist` 作为构建上下文的一部分传进去），或者干脆在文档里承认两者各自可验证。
- 复现/守卫: A-FE-9 已给出"连续构建两次并逐文件比对 sha256"的守卫建议；本条建议再加一条
  "release 作业与 image 作业不得各自独立构建前端"的文本级检查。

### SUP-6 发布只由 tag 触发，没有任何检查确认该 tag 指向 main 上的、已评审的 commit

- 严重度: **提示**
- 类别: 安全（供应链）
- 不变量/性质: 「发布的是被评审过的代码」
- 证据: `release.yml:6-8` 只有 `on: push: tags: ['v*']`；`release.yml:22-23` 复用 `ci.yml` 作为 tag 门禁，
  它保证的是"这个 commit 通过 CI"，**不是**"这个 commit 在 main 上"。发布作业里没有
  `git merge-base --is-ancestor`、没有分支断言、也没有 `environment:` 人工审批。
  `actions/checkout` 不带 `ref` → 用 `github.sha`（tag 指向的 commit），所以**构建确实来自 tag**（这一点是对的）。
- 状态: **CONFIRMED**（读 workflow 到行）
- 影响: 任何能 push tag 的协作者（含被临时授予写权限的自动化身份）可以指向任意一个他能 push 的 commit
  并触发一次完整发布（含推 GHCR），分支保护对 tag 不生效。"CI 通过才发布"这句话容易被读成更强的保证。
- 修法建议（裁定点）: 在 `release`/`image` 作业第一步加
  `git merge-base --is-ancestor "$GITHUB_SHA" origin/main`，或挂 `environment:` 做审批。
- 复现/守卫: 无。
- **与其他报告的关系**: `deploy-ops.md` **DEP-24** 报的是 `release` 作业权限过大与缺 `concurrency`（同文件、不同性质），本条不重复。

### SUP-7 SBOM 不含任何许可信息，因此不能承担许可合规；它的"完整性"只由"组件数 > 10"守着

- 严重度: **提示**
- 类别: 合规/隐私 / 可维护性
- 不变量/性质: 「SBOM 是发布产物的清单」——清单应当能回答"这些模块以什么许可进来"
- 证据:
  - 我用与 CI/发布**完全相同**的参数生成 SBOM：42 个组件、`specVersion 1.6`、`hashes` 42/42、
    **`licenses` 0/42**。
  - 工具自述（`cyclonedx-gomod mod --help`）：`-licenses=false`（默认关闭），且
    *"Licenses detected via -licenses flag will, per default, be reported as evidence. This is because it can not be
    guaranteed that the detected licenses are in fact correct."* —— 打开后给的也是"证据"而非"断言"。
  - CI 的守卫是 `ci.yml:363-365`：`grep -c '"type": "library"'` 后 `test "$components" -gt 10`。
    我把这条等价地跑了一遍：**42**，所以地板今天不空转；但它的粒度是"有没有解析到东西"。
- 状态: **CONFIRMED**（自己生成的 SBOM 字段统计 + `--help` 原文 + 等价执行 CI 的计数）
- 影响: SBOM 能回答"由哪些模块构成"（这一点它做得很准，见「探过但没破的」第 2 条），但**不能**回答许可合规；
  而本项目的许可合规靠手写的 `NOTICE`。两份东西覆盖范围不同，前端那一块两份都没覆盖（SUP-1）。
  风险是下游把空 `licenses` 读成"没有许可信息需要关心"。
- 修法建议（裁定点）: 若要许可进 SBOM，需要 `-licenses -assert-licenses`，那等于用启发式替换人工审核；
  更稳的最小改法是在 SBOM 元数据里加一句"许可归属见 NOTICE"。
- 复现/守卫: 无（建议在 `docs/dependencies.md` 里写明 SBOM 不含许可）。

### SUP-8 信息性：模块图里有 5 条通告，全部**不可达**；其中两条打在"供应链本体"上

- 严重度: **提示**（这是"present-in-module but not-reachable"清单，不是缺陷）
- 类别: 安全（信息性）
- 不变量/性质: —
- 证据: 对 `go list -m all` 的 **137** 个模块按**钉住的版本**批量查 OSV，命中如下 5 条；
  同时 `govulncheck` 明说我这份代码只涉及 **42** 个模块 + go1.27.1 标准库，
  `go mod why -m golang.org/x/crypto` 与 `…/x/mod` 都回答 `(main module does not need module …)`，
  这两个模块也**不在任何平台**的构建图里（六平台 `go list -deps` 的并集里没有它们）。

  | 通告 | 模块@版本 | 摘要 | 修复版本 | 在我们图里的位置 |
  |---|---|---|---|---|
  | `GO-2026-5932` | `golang.org/x/crypto@v0.55.0` | `openpgp` 包不再维护、设计上不安全 | 无（包被移除） | 仅模块图 |
  | `GO-2026-6354` (CVE-2026-78662) | 同上 | ssh：已建立通道死锁时的 DoS | `x/crypto 0.56.0` | 仅模块图 |
  | `GO-2026-6355` (CVE-2026-56855) | 同上 | ssh：同上（另一分支） | `x/crypto 0.56.0` | 仅模块图 |
  | `GO-2026-6179` (CVE-2026-56865) | `golang.org/x/mod@v0.38.0` | **恶意 GOPROXY 可伪造最多两个 sumdb tile，绕过 GOSUMDB 校验，把攻击者内容写进本地模块缓存** | `x/mod 0.40.0`；toolchain `1.27.0-rc.3`/`1.26.6`/`1.25.13` | 仅模块图 |
  | `GO-2026-6180` (CVE-2026-56864) | 同上 | **恶意 GOSUMDB 可提供不在透明日志里的任意模块内容** | 同上 | 仅模块图 |

  说明：Go 漏洞库（`vuln.go.dev` / OSV 的 Go 生态）**不提供 severity 字段**（我逐条取过 `database_specific`，为空），
  所以这里只标"可达/不可达"、不给分级 —— 这个生态本来就是按可达性而不是 CVSS 组织的。
  npm 侧那条（`cookie`）我从 GitHub advisory 拿到了 `low`。
- 状态: **CONFIRMED**（OSV 按版本批量查询 + `go mod why` + govulncheck 的模块清单，三方一致）
- 影响: 今天没有可利用性。两条值得留下：
  1. **GO-2026-6179/6180 打的是"我们用来保证依赖没被掉包"的那个机制**（GOSUMDB/透明日志）。
     我们自己的二进制不含 `x/mod`，工具链 go1.27.1 也已在修复侧，所以本仓库不受影响；
     但通告给出的排查动作值得抄进来：`rm -r go.sum go.work.sum vendor/ && go mod tidy`（在怀疑期内构建过的话）。
  2. 「降级就会重新中招」的清单，见下面「探过但没破的」第 2 条的 fixed-in 表。
- 修法建议: 无需改动。建议把这张表放在 `docs/dependencies.md` §7「不做的」旁边，作为**已知-不可达**记录，
  免得下一轮审计重新发现一遍。
- 复现/守卫: 无（`govulncheck ./...` 本身就是守卫，且它就是可达性的权威）。

---

## 探过但没破的（这些也应变成守卫）

1. **Go 侧可达漏洞：0 条（含标准库）。** `govulncheck ./...`（v1.8.0，DB 2026-09-24）→ `No vulnerabilities found.`；
   `-show verbose` 显示它扫了 42 个模块 + go1.27.1 标准库。
   **非空转已证**：一个 import `golang.org/x/text/language@v0.3.7` 的对照模块被报 `GO-2022-1059` 可达（exit 3）。
   CI 已在跑这条门禁（`ci.yml:347-350`，版本钉 v1.8.0）。
   补一句"降级就会重新中招"的坐标（我逐条取过 fixed 版本）：
   `go-jose/v4` 的 `GO-2026-4945`（JWE 解密 panic）**fixed 恰好是 4.1.4 = 我们的 pin**，
   `GO-2025-3485` fixed 4.0.5、`GO-2024-2631`（解压炸弹）fixed 4.0.1；
   `x/text` `GO-2026-5970` fixed 0.39.0（我们 0.41.0）；`klauspost/compress` `GO-2026-5841`（`s2` 越界读）fixed 1.18.7（我们 1.19.2）；
   `pgx` `GO-2026-5004` fixed 5.9.2、`GO-2026-4771/4772` fixed 5.9.0（我们 5.11.0）；
   `chi` `GO-2026-5774/5775/5777` fixed 5.3.0（我们 5.3.2，且我们不使用 chi 的 `RealIP`——
   `internal/httpapi/clientaddr.go:40` 是自己实现的、带可信代理校验的 `X-Forwarded-For` 解析）；
   `otel` `GO-2026-5506` fixed 1.41.0、`GO-2026-5158` 的两段范围都止于 1.44.0（我们 1.46.0，
   且 `go.opentelemetry.io/*` **完全不被我们自己的代码 import**，它来自 `zitadel/oidc`）；
   `x/sys` `GO-2026-5024`（Windows `NewNTUnicodeString` 整数溢出）fixed 0.44.0（我们 0.47.0）；
   `x/oauth2` `GO-2025-3488`（token 解析内存消耗）fixed 0.27.0（我们 0.37.0，而 `x/oauth2` **是**直接用在
   `idp`/`federation` 的，所以这条 fixed 值得记住）；`protobuf` `GO-2024-2611` fixed 1.33.0、`GO-2023-1631` fixed 1.29.1；
   `rs/cors` `GO-2024-2883` fixed 1.11.0（我们 1.11.1；且 CORS 是不做的文档化决定）；
   `prometheus/client_golang` `GO-2022-0322` fixed 1.11.1；`yaml.v3` `GO-2022-0603` fixed
   `3.0.0-20220521103104-8f96da9f5d5e`（我们 v3.0.1，即**不含**它）。
   唯一"卡在修复版本上"的是 `go-jose/v4 v4.1.4` —— 任何 downgrade 立刻重新受影响，值得写成注释。

2. **SBOM 与二进制里的模块集合逐一相等（42 = 42）。** 我按发布参数构建了 `linux/amd64` 二进制，
   用 `go version -m` 读出内嵌的 42 个 `dep`，与同参 `cyclonedx-gomod mod` 的 42 个组件做集合比较 →
   `SBOM and binary agree exactly`；SBOM 与"六平台构建图并集"也相等，且**包含** Linux 独有的 `prometheus/procfs`
   （Windows 的 `go list -deps` 不含它，所以这一条不是巧合）。
   → **任务书里"SBOM 从模块图生成、可能和二进制不一致"这个担心，在 v1.12.0 上不成立**：
   该子命令读的是构建图（`-test=false` 是默认，`-test` 才会带上测试依赖）。
   **但要写成守卫**：这一致性来自工具实现，流水线里**没有任何一步在比较两者**（只有"组件数 > 10"）。
   建议加一条 CI 步骤：`go version -m` 与 SBOM 组件集合做 diff。

3. **`NOTICE` 与 Linux 构建图精确相等（42 = 42，无漏无多），并且这条有守卫。**
   `internal/archtest/notice_test.go:32 TestNoticeCoversTheBuildGraph` 拿 `go list -deps ./...` 比对 NOTICE，
   我实际跑了它 → `--- PASS`。我也验了它守护的图与**发布二进制**的图一致（Windows 两边都 41；Linux 都 42）。
   它是单向的（"图 ⊆ NOTICE"），文档解释了为什么（多列一条无害）。头部的 `len(modules) < 20` / `len(declared) < 20`
   是反空转地板。缺口只有一个且已被 SUP-1 单独报出：**npm 树不在这个守卫的定义域里**。

4. **`klauspost/compress` 在 NOTICE 里归到 BSD 3-Clause 是准确的。**
   我读了模块里的 LICENSE 原文（248 行、5 个 `Files:` 作用域）：默认 BSD-3、`gzhttp/*` 是 Apache-2.0、
   `s2/cmd/internal/readahead/*` 与 `s2/cmd/internal/filepathx/*` 是 MIT、`snappy/*`+`internal/snapref/*` 是 BSD-3。
   实际链接进二进制的是 `compress`、`fse`、`huff0`、`internal/{cpuinfo,le,snapref}`、`zstd`、`zstd/internal/xxhash`：
   **Apache-2.0 的 `gzhttp` 与 MIT 的 `s2/cmd/*` 都不在构建图里**，`internal/snapref` 属 BSD-3 作用域 → 归类正确。
   （顺带：`GO-2026-5841` 的越界读在 `s2`，`s2` 也不在构建图里。）

5. **许可兼容性：Go 侧无 copyleft 冲突，npm 侧无"无许可"包。**
   42 个 Go 模块逐个读磁盘上的许可原文分类：MIT / Apache-2.0 / BSD-3 / ISC / Unlicense；
   **没有 GPL/AGPL/SSPL/BSL/Commons-Clause，没有缺许可文件的模块**
   （唯一匹配到 "GNU General Public License" 的是本项目自己的 `LICENSE` —— MPL-2.0 §3.3 的正文提到 GPL，属分类器假阳性）。
   npm 装机树 52 个唯一包（123 实例）：MIT 90 / Apache-2.0 15 / **MPL-2.0 10** / ISC 5 / BSD-3 3，
   **零个包缺 license 字段、零个缺许可文件**。MPL-2.0 的 10 个是 `lightningcss`（及其平台包），
   与项目自身许可同源、无冲突，且作为构建期工具不作为代码再分发。
   → 「无许可的 npm 包不可再分发」这类最常见的发现**在这里不存在**（这是执行过的结论，不是"看着像 MIT"）。

6. **锁文件固定：所有会安装依赖的入口都用 `--frozen-lockfile`。**
   `ci.yml:91`、`Makefile:17`（`release.yml:127` 经 `make web` 走这里）、`visual-baselines.yml:46`、`Dockerfile:22`；
   `codeql.yml` 与 `perf.yml` 不装 pnpm。`Makefile:20` 与 `ci.yml:96-99` 都断言
   `internal/webui/dist/index.html` 存在 —— "没构建成"不会静默降级成占位页。
   `web/pnpm-lock.yaml` 是 tracked（`git ls-files --error-unmatch` 成功）、`lockfileVersion: '9.0'`、
   122 行 `integrity:`（即 tarball 哈希被锁住，不只是版本号）。
   **但没有任何测试守这条**（`*_test.go` 里 grep `frozen-lockfile` → 0 命中）→ 归入 SUP-3 的修法。
   （`deploy-ops.md` 第 12 条也注意到 `integrity:` 这一点并标为"论证而非实测"。）

7. **pnpm 版本被固定，且 Dockerfile 与 CI 一致。** `web/package.json:6` `"packageManager": "pnpm@11.8.0"`；
   `ci.yml:75-77`、`release.yml:113-115` 显式 `version: 11.8.0`；`Dockerfile:18` 用 `corepack enable`
   从 `packageManager` 解析同一版本（所以镜像里的 pnpm 不漂在 `latest` 上）。

8. **没有"安装时执行任意代码"的依赖。** 遍历 123 个已安装包实例：**没有任何包声明
   `preinstall`/`install`/`postinstall`**（27 处命中全是 `prepare`/`prepublishOnly`，对 registry 依赖不执行）；
   `node_modules/.modules.yaml` 的 `pendingBuilds: []`。
   仓库**没有** `pnpm.onlyBuiltDependencies` 允许列表，所以这一层安全靠 pnpm 10+ 的默认行为，
   不是靠仓库显式声明 —— 如果将来引入需要编译的原生依赖，它会**不被构建**（失败是响的，不是静默的）。
   （`deploy-ops.md` DEP-24 与 `frontend.md` 第 265 行都提到这一层；本条的增量是"遍历全部已安装包确认零命中"。）

9. **构建期没有"执行外部代码"的形状。** 四个 workflow + Makefile + Dockerfile 里
   `@latest` / `curl ` / `wget ` / `| sh` / `| bash` **零命中**（唯二命中是注释文字）。
   所有 `go install` 都钉确切版本。全部 Go 源码里没有 `import "C"` / `#cgo` —— `CGO_ENABLED=0` 与
   `scratch` 运行时的前提成立（`Dockerfile:49`、`Makefile:164`）。

10. **`-ldflags "-s -w"` 的代价被实测澄清：Go 的崩溃报告**不**丢符号。**
    同一个除零 panic，`-s -w` 与不剥符号两份二进制输出**完全一致**，都有
    `main.inner(...)` + `stripprobe/main.go:5`（Go 的 `pclntab` 不受 `-s -w` 影响）。
    真正丢的是外部符号表与 DWARF：`go tool nm` 从 **2490** 条（不剥）变成 **0** 条（`-s -w`），
    即 gdb/delve 这类外部调试器与部分采样工具会退化。
    仓库里**没有任何文档提到这个取舍**（`-s -w` 只出现在 `Makefile:165` 与 `Dockerfile:50` 的命令里）。
    建议在 `docs/dependencies.md` §6 或 `docs/architecture.md` 补一句，防止未来有人为"崩溃可诊断性"把它删掉、
    或在排查时误以为符号已被剥掉。**注意**：任务书里"会剥掉崩溃报告的符号"这一前提对 Go 是**不成立**的。

11. **校验和链路没有被削弱。** 被跟踪配置里 `GOFLAGS`、`GONOSUMDB`、`GONOSUMCHECK`、`GOPRIVATE`、`GOINSECURE`、
    `GOSUMDB`、`GOTOOLCHAIN`、`-mod=mod` **一个都没有出现**（全量 grep，0 命中）；本机 `go env` 是默认值；
    `go mod verify` → `all modules verified`；`go.sum` 145 行。

12. **工具链一致性与 stdlib 版本。** `go.mod:3` `go 1.27.1`；CI 全部用 `actions/setup-go` +
    `go-version-file: go.mod` → 装的就是 1.27.1；本机 `go version` 也是 `go1.27.1`。
    官方镜像侧我取了上游原文：`docker-library/golang` 的 `1.27/alpine3.23/Dockerfile` 是
    `ENV GOLANG_VERSION 1.27.1` + **`ENV GOTOOLCHAIN=local`** —— 后者意味着镜像里的 Go 若旧于 go.mod 的要求，
    构建会**硬失败**，而不是静默换一个 stdlib。
    stdlib 侧：govulncheck 在 go1.27.1 上报 0 条；唯一涉及工具链的 GO-2026-6179/6180 的
    `toolchain fixed=1.27.0-rc.3`，1.27.1 在修复侧。

13. **`SHA256SUMS` 的覆盖面与"空 tar"风险。** `Makefile:200-201`：
    `cd dist && $(SHA256) re0auth_$(VERSION)_* > SHA256SUMS` —— 发布集里**每个**构建产物都落在这个 glob 里
    （6 个归档 + `re0auth_<v>_sbom.cdx.json`，SBOM 的文件名是**刻意**取成能被匹配的）；
    glob 匹配为空时 `sha256sum` 返回非零 → `&&` 链失败 → make 失败，所以不会产出"看起来完整但什么都没覆盖"的清单。
    归档的来源是**显式目录名**（`re0auth_$(VERSION)_$${os}_$${arch}`），不是 glob，因此不存在"匹配不到却生成合法空 tar"的路径。
    发布集里另外三个文件（`SHA256SUMS.sig`/`.pem` 与 `SHA256SUMS` 自己）不被自己覆盖 —— 这是签名方案的固有形状，不是遗漏。
    **注意**：`deploy-ops.md` DEP-11 报的是同一配方里 `$(VERSION)` 被插进 shell 的风险，与本条的 glob 语义无关，两条不冲突。

14. **cosign 身份约束与 workflow 路径一致。** `README.md:129` 的
    `--certificate-identity-regexp '^https://github.com/Re0Auth/r0semi/\.github/workflows/release\.yml@'`
    指向的文件与"真正执行 `cosign sign-blob` 的作业所在文件"是同一个 `.github/workflows/release.yml`
    （`release.yml:160-165` 在 `release` 作业内），因此 GitHub OIDC 的 `job_workflow_ref` 会匹配；
    `--certificate-oidc-issuer https://token.actions.githubusercontent.com`（`README.md:130`）也给了。
    可收紧两处（提示级）：正则止于 `@`、不约束后缀（同 workflow 的任何 ref 都能通过），加 `@refs/tags/` 更紧；
    没有额外的 repository 断言。**我无法端到端验证**（本机无 cosign、无已发布资产）。

15. **`release.yml` 从 tag 构建，不是从分支。** `actions/checkout` 不带 `ref` → 用 `github.sha`，
    对 tag push 就是该 tag 指向的 commit；版本号取自 `github.ref_name`（`release.yml:147`，注释解释了
    为什么不用 `git describe`：浅克隆下也能与 release 一致）。两个作业 checkout 同一个 commit。
    残留只有 SUP-6（tag 是否在 main 上）。

16. **前端版本基本都在最新，钉住的版本上没有已知通告（唯一的例外已由同行报出）。**
    与本机 `registry.npmmirror.com/<pkg>/latest` 对比：`svelte` 5.57.1 = latest、
    `@sveltejs/kit` 2.70.3 = latest、`@sveltejs/adapter-static` 3.0.10 = latest、
    `@sveltejs/vite-plugin-svelte` 7.3.0 = latest、`tailwindcss`/`@tailwindcss/vite` 4.3.3 = latest、
    `@playwright/test` 1.63.0 = latest、`@axe-core/playwright` 4.13.0 = latest、
    `lightningcss` 1.33.0 = latest、`postcss` 8.5.28 = latest；
    `vite` 8.3.0（latest 8.3.1）、`rolldown` 1.2.9（latest 1.2.11）各落后一个 patch；
    `svelte-check` 4.6.0（latest 4.7.6）、`typescript` 6.0.3（latest 7.0.2）落后，但只在 dev/CI 用。
    逐版本 OSV 查询：`vite@8.3.0`、`svelte@5.57.1`、`@sveltejs/kit@2.70.3`、`tailwindcss@4.3.3`、
    `rolldown@1.2.9`、`lightningcss@1.33.0`、`@playwright/test@1.63.0`、`typescript@6.0.3`
    → 全部 "no advisory affects this exact version"。
    **`esbuild` 根本不在依赖树里**：vite 8 用 rolldown/oxc；锁文件里 `esbuild` 只出现两次，
    都是 `vite@8.3.0` 的 **optional peer**（`peerDependenciesMeta.esbuild.optional: true`），
    `node_modules/.pnpm` 下**没有任何** `esbuild@*` 目录。
    → 任务书里"Vite/Svelte/esbuild 的 dev-server 通告"这一类**不适用**于本仓库。

17. **npm 侧唯一通告与 CI 的审计门（已被同行报出，这里只补两个事实）。**
    `frontend.md` **A-FE-5** 已完整报了：`cookie@0.6.0`（`GHSA-pxg6-pf52-xh8x`/CVE-2024-47764，low）是图中唯一通告，
    而 CI 的门是 `pnpm audit --audit-level high`（`ci.yml:337`），所以它**永远不会**让 CI 变红。
    两个补充事实（A-FE-5 没有的）：
    (a) **这条通告无法靠更新锁文件解决** —— `@sveltejs/kit@2.70.3` 的依赖是 `"cookie": "^0.6.0"`，
    而修复版本是 `0.7.0`，`0.x` 的 caret 不含它，且 kit 2.70.3 已是最新；
    (b) 交付产物里**没有** `cookie` 的序列化路径：`internal/webui/dist/**/*.js` 里 `max-age|Max-Age|set-cookie|samesite`
    零命中，且 `web/package.json` 把所有包都放在 `devDependencies`（所以 `pnpm audit --prod --json` 的
    `totalDependencies` 是 **0**，"生产树干净"这句话在语义上是空集）。
    另外 npm 镜像没有 audit 端点这件事，`frontend.md`（第 278 行附近）与 `deploy-ops.md` 都已记录，
    本条不重报；我只确认：CI 不覆盖 registry，所以 CI 走 npmjs.org 不受影响，而失败是**响的**（非零退出），不是静默通过。

---

## 未能到达（残余盲区）—— 必须写，并说清为什么

- **没有 Docker，镜像这条链有一半是读的**：无法 `docker build`、无法跑 Trivy、无法用
  `docker buildx imagetools inspect` 看 pinned digest 里真实的 `GOLANG_VERSION`/Node 版本。
  **HYPOTHESIS**：`golang:1.27-alpine@sha256:8a5910…` 里是 1.27.1（上游同 tag 的 Dockerfile 今天是）；
  若实际更旧，`GOTOOLCHAIN=local` 会让构建**失败** —— 也就是"不会静默换 stdlib"成立，
  但"这个 digest 就是 1.27.1"没被验证。要证实：有 Docker 后跑 `docker run --rm <digest> go version`。
- **没有已发布的 release 资产**：`SHA256SUMS` 对六个归档的覆盖是"读 `Makefile:200-201` 的 glob 语义"得出的
  （在构建脚本层面 CONFIRMED），**不是**在 release 页上下载后跑 `sha256sum -c`。
  要证实：对任一 `v*` tag 下载 `SHA256SUMS` 与全部资产，跑 `sha256sum -c`，并断言资产数 = 10。
- **没有 cosign**：README 的验证命令无法端到端执行（回显的 identity 是字符串比对，不是证书比对）。
- **发布产物的字节级"归档 = 镜像"从未被验证**：SUP-5 的结论是"A-FE-9 的实测 + 两次构建均在流水线里"的合成，
  我没有真的构建镜像、也没有在两种 Node 下各构建一次。要证实：在 CI/容器里连跑两次 `pnpm run build` 并对六平台归档与镜像
  分别逐文件比对（`frontend.md` 已给出这条守卫的写法）。
- **govulncheck 的结论依赖漏洞库的符号清单**：我做的是"工具说没有可达漏洞 + 用对照模块证明工具有效"，
  没有、也不可能逐函数复核 DB 对 `go-jose`/`zitadel/oidc` 中每个符号的覆盖。
  若某通告的影响函数**不在 DB 的符号清单**里，它会表现为"报为不可达"而不是"漏报" —— 这一点本机无法排除，
  只能靠定期重跑（CI 已在做）。
- **SBOM 与二进制的一致性只在当前工具版本下被验证**：v1.12.0 今天产出的是构建图。
  升级该工具（或它改变 `mod` 的语义）之后，"SBOM 列出链接进二进制的全部模块"这句话就可能变成假的，
  而流水线里没有任何一步会比较两者。要闭环：把「探过但没破的」第 2 条的 diff 检查做成 CI 步骤。
- **前端许可文本的检查是在本机构建产物上做的**：`internal/webui/dist` 是本地用锁文件钉住的
  vite 8.3.0/rolldown 1.2.9 构建的，CI 用同一套版本（`--frozen-lockfile`），但我没有比对 CI 产物的字节。
  按 `frontend.md` A-FE-9，两次构建的**分块文件名**都会变，所以"每个分块里都没有许可文本"这个结论
  需要以"所有分块都被扫过"为前提 —— 我扫的是当时磁盘上的 27 个文件；**没有**对第二份构建产物重复扫描。
  要闭环：把 SUP-1 的守卫写成测试（它会在每次构建后重跑），而不是只留一次扫描结论。
- **未做来源证明（provenance）验证**：`docs/dependencies.md` §7 明确不做 sigstore 验证，属文档化边界；
  这是边界，不是盲区。
- **npm 侧只有一条通告是 audit 的结论**：我额外用 OSV 核对了 9 个关键包的钉住版本，
  **没有**对全部 52 个包逐个跑 OSV（`pnpm audit` 已覆盖整棵树，且做了对照实验）。

---

## 判断（文档化决定可否质疑，不是 finding）

1. **`docs/dependencies.md` §7 的"不做的"清单**（不声明 SLSA 等级、不校验依赖自身的来源证明、
   不为不在构建图里的模块伪造记录）—— 我这一轮的实测**支持**这个边界：`go.sum` + GOSUMDB 被完好使用
   （`go mod verify` 通过，无任何削弱校验和的环境变量），SBOM 确实只覆盖构建图。
   唯一要提醒的是 GO-2026-6179/6180 恰好打在"GOSUMDB 那一半"上，而我们的工具链已在修复侧 ——
   这句话值得写进 §7，因为它就是"边界在哪"的具体答案。
2. **SBOM 是否要带许可（`-licenses -assert-licenses`）**：工具自己声明检测的许可"不保证正确"。
   把许可归属继续放在手写 `NOTICE`（并有 `TestNoticeCoversTheBuildGraph` 守着"不漏"）比换成启发式更可辩护；
   若要走自动检测，应同时保留人工清单。**这是裁定，不是缺陷。**
3. **发布是否要求 tag 指向 main 的祖先**（SUP-6）：会引入一次人工动作或一条额外检查。
   现状"CI 通过即发布"可辩护，但文档表述容易让人以为更多。
4. **`-s -w` 是否保留**：实测显示代价比通常以为的小（Go 崩溃报告仍有符号），收益是体积。
   保留合理；需要的是把它写下来。
5. **镜像该带哪些文件**：SUP-2 与 `deploy-ops.md` DEP-21 是同一缺口的两份材料（许可/归属 与 预发布警告）。
   若只改一处，应合并成"把 `LICENSE`、`NOTICE`、`SECURITY.md` 一起 `COPY` 进镜像 + 加 OCI label"，
   并写进 §7 的"做了的"，否则下次会被当成多余文件删掉。
