# 依赖与发布供应链审计报告 —— 复核（VERIFIED）

> 复核对象：`docs/audit-5/findings/dependencies.md`（SUP-1 … SUP-8）
> 复核者角色：**证伪**。规范见 `docs/audit-5/VERIFY-BRIEF.md`、`docs/audit-5/BRIEF.md`。
> 环境：Windows 11 + Go 1.27.1 + Node 24.17。**无 Docker**（故镜像内容只能读 `Dockerfile` 到行）；
> 但**本机对 GitHub API 与 release 资产的网络是通的**，所以我把复核做到了**已发布的真实产物**上
> （见 §3 第 6/7 条）—— 这是原报告明确列为「未能到达」的那一格。
> 我的探针（只新建文件，未改动任何被跟踪文件）：
> `internal/zzprobe/verifydependencies/verify_dependencies_test.go`
> （`TestVerifyLicenceScanHasAPositiveControl`、`TestVerifyNoUpstreamLegalCommentToPreserve`、
> `TestVerifyUsesSitesArePinnedButUnguarded`、`TestVerifyWhichRenamesShipSilently`、
> `TestVerifySBOMFlagIsAbsentAndItsGuardIsCoarse`）。

---

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|---|---|---|---|---|
| SUP-1 | 中 | 中（**维持**，但标题与修法必须改） | **部分成立（实质成立、表述不成立）** | 交付物确实在无归属地再分发 Svelte/SvelteKit —— 我用**已发布的 rc.3 二进制**证实（`__svelte`×7、`__sveltekit`×5、`svelte.dev/e/`×25，而 copyright/@license/SPDX 命中 **0**）；但「**完全没有任何**版权/许可文本」是错的（CSS 与二进制里各有 1 处 `/*! tailwindcss v4.3.3 \| MIT License \| …`），且它推荐的修法第 2 步「开 legal-comments 保留」是**空转**：上游 539 个 JS 文件里**一个** legal comment 都没有 |
| SUP-2 | 低 | 低（维持） | **成立** | `Dockerfile:59-64` 运行阶段确实只有 `FROM scratch` + 两条 `COPY` + `USER`；与 `deploy-ops.md` DEP-21 **同一缺口的两份材料**，合并是对的。但「MPL-2.0 §3.2 未满足」这一半比报告说的弱：镜像很可能带 `org.opencontainers.image.source` 默认标签（源码可得性告知），我**无法在离线/flaky 网络下核实默认标签集**，故只对 MIT/Apache §4(d) 那一半给 CONFIRMED |
| SUP-3 | 低 | **提示**（降一级） | **部分成立** | 缺守卫属实（`workflows_test.go` 只查 pnpm 缓存），但报告的「守卫不存在」**过头了**：`internal/archtest/dockerfile_test.go:27 TestDockerfileBaseImagesArePinned` **就是**那句文档话里「基础镜像按 digest 固定」那一半的守卫（我跑了，PASS）。另外计数错了：真值是 **47 个 `uses:`（46 远程 + 1 本地复用）**，不是 43 |
| SUP-4 | 提示 | 提示（维持） | **部分成立（机制成立、后果举错了例子）** | 我用 `sh` 复跑了该循环的**真实形状**（`go build` 换成 `true`）：`cp` 全失败、脚本仍 **exit 0**、`tar` 产出一个**不含那 5 个文件的合法归档** —— 机制 CONFIRMED；但报告点名的触发条件「给 `NOTICE` 改名」被**推翻**：`internal/archtest/notice_test.go:55` 和 `cmd/re0auth/secret_env_test.go:118` 是**被跟踪**测试，改名会让 tag 门禁（`release.yml:22-23` 复用 `ci.yml`）先红。真正会静默的是 **`LICENSE` / `README.md` / `SECURITY.md`** |
| SUP-5 | 提示 | 提示（维持，实为观察） | **部分成立** | 「两个作业各构一次前端」是**读出来的事实**（镜像侧在 `Dockerfile:13-35`，归档侧 `release.yml:127 make web`），前端不可复现由 A-FE-9 背书；但**仓库里没有任何一处声称「归档与镜像字节相同」**（`README:147-149`、`Makefile:205-209` 都只说「同一份源码」），所以这是**证据边界的观察**，不是被破坏的不变量 —— 且它基本是 A-FE-9 后果的复述 |
| SUP-6 | 提示 | 提示（维持） | **成立** | `release.yml:6-8` 只有 tag 触发；`git grep -i` 全仓库对 branch/tag protection、`environment:`、`merge-base`/`is-ancestor`、rulesets **零命中** → 属「仓库外（GitHub 设置）的不可验证控制」。工作流**可以**廉价断言（一行 `git merge-base --is-ancestor`），报告的建议成立 |
| SUP-7 | 提示 | 提示（维持，属范围选择） | **成立** | 我自己生成的 SBOM：42 组件、`licenses` **0/42**、`hashes` 42/42、specVersion 1.6；`-licenses` 在全仓库**零命中**；守卫确为 `components > 10`（`ci.yml:365`）。但**SBOM 本就不必带许可**，且 `README`/`SECURITY`/`docs/dependencies.md` **没有任何地方**声称它带 —— 是范围选择，不是缺陷 |
| SUP-8 | 提示 | 提示（维持） | **成立** | 我不复用它的对照：自建 `x/text@v0.3.7` 对照模块 → `GO-2022-1059` 可达、**exit 3**（工具非空转）；`govulncheck -show verbose ./...` → 「scanned the following **42** modules and the go1.27.1 standard library」+ `No vulnerabilities found.`（exit 0）；OSV API 独立查得**同样 5 条**（`x/crypto@v0.55.0`→5932/6354/6355，`x/mod@v0.38.0`→6179/6180），且两模块 `go mod why` = 「main module does not need module」、不在任何平台的二进制里 → 「仅在模块图、不可达」成立 |

---

## 2. 降级 / 推翻的理由（逐条）

### SUP-1 —— 实质成立，但标题是错的，推荐的修法有一半是空转

**(a) 我重做了那个「零命中」，并带正对照。** 我把 `internal/webui/dist` 拷到 `%TEMP%` 并植入
`/*! Copyright (c) 2024 Positive Control @license MIT SPDX-License-Identifier: MIT */`，
同一条扫描命令在对照树上命中、在真树上得到 **1 处命中**：

```
=== CONTROL TREE (planted in -GD-CDAB.js) ===
HIT 0.GGQYCh1V.css:1
HIT -GD-CDAB.js:1
=== REAL TREE ===
matches=1
```

那 1 处是 `_app/immutable/assets/0.GGQYCh1V.css:1` 的
`/*! tailwindcss v4.3.3 | MIT License | https://tailwindcss.com */`。
所以报告标题里的「**carries no copyright/licence text at all**」**不成立**（逐图案计数：
`copyright`→0、`@license`→0、`SPDX`→0、`Licensed under`→0、`/\*!`→**1**、`MIT License`→**1**）。

**这不是吹毛求疵，因为它同时暴露了报告那条第 2 步修法的失效路径**：报告的探针用
`(?i)copyright|@license|SPDX-License-Identifier|Licensed under` —— 这 4 个图案**都不匹配** tailwind 那条
banner，所以它的 `hits == 0` 是**标记集的人为产物**；更要紧的是它的通过条件是
「**任意一个产物里出现任意一次** `copyright`」，即只要将来有人往任意一个 CSS 里塞一句
`/* Copyright */`（比如再引入一个 tailwind 式的编译器 banner），这条守卫就转绿，
**完全不需要给 Svelte 补归属**。它测的是「词是否出现过」，不是「被再分发的那几个包是否被归属」。

**(b) 修法第 2 步（「给 rolldown 开 legal-comments 保留」）是空转。** 逐文件读上游**实际进入 bundle 的**
三个包的 JS 源码（含 pnpm 的 symlink，`filepath.Walk` 会漏掉 symlink 根，必须自己解析）：

```
TestVerifyNoUpstreamLegalCommentToPreserve:
  539 JS files read from svelte, @sveltejs/kit and devalue;
  0 carry a licence comment, so no bundler option can put attribution into the bundle:
  it has to be shipped alongside it
```

539 个文件里**零个** `@license` / `@preserve` / `Copyright` / `/*!`。
`legal-comments` 保留一个**不存在**的注释，逐字节不改变产物；而报告一边把这一步写成「**缺一不可**」，
一边自己警告「否则这条配置会静默失效」——**它开的正是那个会静默失效的配置**。
结论：修法第 1 步（生成 npm 侧清单并随归档分发）**必要且充分**；第 2 步要么删掉，要么改成
「往 `NOTICE`/`NOTICE-frontend` 里写归属 + 断言该文件的**条目数下限**」，断言的是**归属**而不是**词**。

**(c) 文档侧的范围我想再加强一点（报告只引了 `NOTICE:5-8`）。** 另外两处同样会让人相信「已经覆盖」：
`README.md:167` 「本项目采用 **MPL-2.0**，全文见 LICENSE，**第三方依赖见 NOTICE**」，
以及 `docs/dependencies.md:71` 「前端只在**构建期**存在。运行时没有 Node，没有 `node_modules`…
产物是静态文件，`go:embed` 进同一个二进制」——后者字面为真（`node_modules` 确实不进产物），
但它与前者拼起来的效果是「第三方依赖都在 NOTICE 里、前端只是构建期的事」，
而事实是 **Svelte/SvelteKit/devalue 的代码就在产物字节里**（下面 (d) 的实测）。

**(d) 我把结论做到了已发布的真实产物上（原报告把这一格列为「未能到达」）。**
`CHANGELOG.md:79` 写着「目前唯一带产物的预发布：release 里有六个平台的归档、`SHA256SUMS` 及其 cosign 签名、
以及 SBOM」；GitHub API 证实 **`v0.0.0-rc.3`（prerelease=True，10 个资产）确实存在并已公开**。
我下载了 `re0auth_v0.0.0-rc.3_linux_amd64.tar.gz`：

```
=== shipped archive contents (published v0.0.0-rc.3, linux/amd64) ===
-rw-r--r--  4242  re0auth_v0.0.0-rc.3_linux_amd64/NOTICE
-rw-r--r-- 12083  re0auth_v0.0.0-rc.3_linux_amd64/re0auth.example.toml
-rw-r--r-- 16726  re0auth_v0.0.0-rc.3_linux_amd64/LICENSE
-rw-r--r--  5648  re0auth_v0.0.0-rc.3_linux_amd64/SECURITY.md
-rw-r--r--  7365  re0auth_v0.0.0-rc.3_linux_amd64/README.md
-rwxr-xr-x 21999776 re0auth_v0.0.0-rc.3_linux_amd64/re0auth

shipped NOTICE: svelte -> 0, Svelte -> 0, devalue -> 0, tailwind -> 0, npm -> 0, node_modules -> 0
shipped NOTICE module entries = 42        (与仓库 NOTICE 同为 4242 字节)
```

再把归档里那个**真实发布过的二进制**当字节流扫一遍：

```
scanned 21999776 bytes of .../re0auth_v0.0.0-rc.3_linux_amd64/re0auth
  "Copyright (c) 2016-2025"            occurrences=0     ← svelte 的 MIT 版权行
  "Copyright (c) 2020 [these people]"  occurrences=0     ← kit 的 MIT 版权行
  "Permission is hereby granted"       occurrences=0     ← MIT 许可正文
  "SPDX-License-Identifier"            occurrences=0
  "@license"                           occurrences=0
  "/*!"                                occurrences=1     ← tailwind 那条 banner
  "__svelte"                           occurrences=7
  "__sveltekit"                        occurrences=5
  "svelte.dev/e/"                      occurrences=25
```

**这就是 SUP-1 的 CONFIRMED，而且比报告更强**：不是「磁盘上的 dist 没有许可文本」，
而是「**已发布给全世界的 rc.3 归档与二进制里，Svelte/SvelteKit 代码被无归属地再分发，
MIT 的『版权声明与许可声明须随所有副本』那一条没有被满足**」。
报告写的「已发出的归档补不了」不再是假设 —— rc.3 已经发出去了。

**严重度：维持「中」，但「要不要在发公开版本前修」的答案要改成现在时。**
- 不升级到「高」：它不产生可利用面，三个包都是 MIT，没有 copyleft 冲突（这一点报告的实测我认同）。
- 不降到「提示」：它是**发布产物本身**的许可条件未满足，且**已经对外发布**，不可能回溯；同时
  `NOTICE:5-8` 那句「covers every module in the build graph of the released binaries」在字面意义上
  对「released binary 里确实含有的 npm 代码」是**不成立的**，这属于本项目自己最在意的「元数据不能撒谎」
  （`docs/dependencies.md:62`）那一类。
- 建议表述：**「下一个 release（rc.4 或首个正式版）之前必须修；rc.3 已无法回溯，应在 release notes 里注明」**。
  修法是机械的：`pnpm licenses list`（或 `license-checker`）产出 `THIRD-PARTY-NOTICES.txt`
  → 进 `Makefile:167` 的 `cp` 列表、进 `Dockerfile` 的 `COPY`、并在 `NOTICE` 里加一段指针；
  守卫断言**该文件的条目数 ≥ 实测的运行时包数**，而不是「产物里出现过 copyright」。

### SUP-2 —— 成立，但「MPL-2.0 §3.2」这一半我说不准，且应与 DEP-21 合并

`Dockerfile:59-64` 逐行读：`FROM scratch` / `COPY … ca-certificates.crt` / `COPY … /re0auth` / `USER 65532:65532`，
运行阶段**没有** `COPY LICENSE`/`COPY NOTICE` —— 与报告一致，CONFIRMED（读；无 Docker 执行）。
`deploy-ops.md` DEP-21（第 447-461 行）报的是同一个 `Dockerfile` 缺口的另一份材料
（镜像里没有「未达生产可用」的警告文本，而归档里有）。**两份材料应当合并成一条**：
把 `LICENSE`、`NOTICE`、`SECURITY.md` 一起 `COPY` 进镜像 + 加一条 OCI 标签。报告自己也这么建议，我同意。

要修正的是法条归属：**MIT/Apache-2.0 §4(d) 那一半是硬的**（镜像就是 MIT 代码的「副本」，
而镜像里没有任何许可/归属文本）；**MPL-2.0 §3.2 那一半是软的**：§3.2 要求对以 Executable Form 分发的人
「inform … how they can obtain a copy of such Source Code Form by reasonable means」，
而 `release.yml:48-53` 用 `docker/metadata-action` 的 `steps.meta.outputs.labels`，
该 action 的默认标签集在文档中包含 `org.opencontainers.image.source`（指向源码仓库）——
若确实存在，则「如何取得源码」这条**很可能已被满足**。我**无法证实**默认标签集：
`raw.githubusercontent.com` 在本机多次超时（`action.yml` 取到了 2057 字节、里面只声明 inputs/outputs，
不含默认标签），`web_search` 工具返回 `Authentication Fails`（与报告遇到的是同一个网络/凭据问题）。
所以这一半我标 **HYPOTHESIS**，请勿按 CONFIRMED 引用。严重度 低维持。

### SUP-3 —— 缺守卫是真的，但「守卫不存在」过头，且计数错了

三个部分逐一核：
1. **文档**：`docs/dependencies.md:121-125` 原文确为
   「**做了的**：CI action 按 commit SHA 固定、基础镜像按 digest 固定、扫描器与工具按精确版本固定…
   **固定本身由 `internal/archtest` 与 `internal/observability` 的产物一致性测试守住，不靠约定。**」
   （`README.md:149` 同一断言：「基础镜像按 digest 固定，`internal/archtest` 会检查这一点」）
2. **现状**：我全量重数 —— **47 个 `uses:` 键（46 远程 + 1 本地 `release.yml:23`），远程 46 个全部是 40 位 hex**，
   `image:` 只有 `postgres:16`×2 非 digest（这一条是 `deploy-ops` DEP-19 的，不重报）。
   **报告说 43，实测 47** —— 它自己提醒过「不要信它的计数」，确实不该信（多半漏了 `- uses:` 之外的形态）。
3. **守卫**：`internal/archtest/workflows_test.go` 里唯一 workflow 检查是
   `TestWorkflowsCacheOnlyWhatTheyCreate`（缓存 pnpm 的作业必须真的装过 pnpm），
   **确实没有任何测试解析 `uses:` 的形状** → 我写的
   `TestVerifyUsesSitesArePinnedButUnguarded` 用正则在整个 `internal/archtest` 里找
   `uses:\s*\(|shaPin|pinnedToASHA|usesRef` → 零命中，同时确认 `dockerfile_test.go` 里
   `digestPinnedFROM` 仍在。

**所以准确的表述是**：那句文档话里「基础镜像按 digest 固定」**有守卫**（`TestDockerfileBaseImagesArePinned`，
我跑了 PASS）；「CI action 按 commit SHA 固定」与「扫描器与工具按精确版本固定」**没有守卫**
（工具版本那一半 `deploy-ops` DEP-22 已报）。报告的绝对化措辞会把一条**部分准确**的文档话
说成全错，这在「文档与实现不一致」这一类里是方向性错误 —— 评审者按报告去查
`TestDockerfileBaseImagesArePinned` 会以为报告错了。**严重度 低 → 提示**：现状是对的、
`ci.yml:15-21` 在**使用点**写了 pin 策略与理由，缺的只是一条把约定机器化的测试。

### SUP-4 —— 机制我复现了；但它举的触发条件恰好是被守卫挡住的那一个

**机制（执行过）**：我把 `Makefile:158-174` 的循环形状原样搬到 `sh` 里（唯一替换：`go build` → `true`，
让执行真的走到 `cp`），源码文件全部不存在：

```
  re0auth_v0_linux_amd64
recipe body finished
SCRIPT EXIT CODE = 0
--- archive contents (should lack the 5 files) ---
re0auth_v0_linux_amd64/
（stderr: cp: cannot stat 'config/re0auth.example.toml' … 'LICENSE' … 'NOTICE' … 'README.md' … 'SECURITY.md'）
```

即：`cp` 全部失败、循环**照常走完、退出码 0**、`tar` 产出**合法归档**（只含空目录），错误只到 stderr。
再加上 `git grep` 确认**全仓库没有任何归档内容断言**（`tar -t`/`unzip -l`/`zipinfo` 零命中），
`sbom` 的 `-s` 只守 SBOM、`SHA256SUMS` 的 glob 只覆盖「已存在的文件」——
**「缺文件也能发出去」这一半 CONFIRMED**。

**但「给 `NOTICE` 改名」这个例子是错的（部分推翻）**。我的
`TestVerifyWhichRenamesShipSilently` 逐文件问「有哪个**被跟踪**的测试读它」（引号内的字面量，避免把散文里的
`LICENSE` 当成守卫）：

```
LICENSE                read by tracked code: []
NOTICE                 read by tracked code: [internal\archtest\notice_test.go]
README.md              read by tracked code: []
SECURITY.md            read by tracked code: []
re0auth.example.toml   read by tracked code: [cmd\re0auth\secret_env_test.go]
renaming these ships an incomplete archive with a green pipeline: [LICENSE README.md SECURITY.md]
```

- `NOTICE` 被 `internal/archtest/notice_test.go:55` 读（`os.ReadFile` → `t.Fatal`），
- `config/re0auth.example.toml` 被 `cmd/re0auth/secret_env_test.go:118` 读（`TestShippedExampleConfigDecodes`），
- 两者都是**被跟踪**测试；`ci.yml:141`（`go test ./internal/archtest/`）与 `ci.yml:160-162`（`go test ./...`）
  会在每次提交上跑，而 `release.yml:22-23` 把 `ci.yml` 当 tag 门禁、`release: needs: [ci, image]`
  → **改名会在归档诞生之前就把 tag 门禁变红**。`internal/zzprobe/deploy/artifacts_test.go:475` 那个
  「文本级守卫」报告说得对（它读配方文本、只覆盖 5 个名字里的 2 个、且是审计探针不是仓库守卫）。

**结论**：缺口成立、严重度 提示 维持；但「触发条件」必须换成 **`LICENSE` / `README.md` / `SECURITY.md`**
这三个（其中 `LICENSE` 最要紧：改名后归档里就没有 MPL-2.0 全文了，而这正是报告担心的「掩盖 SUP-1/SUP-2」）。
报告说 `deploy-ops` 的探针「挡不住这一类」也对，但真正挡住它点名的那个例子的是 **`notice_test.go`**。

### SUP-5 —— 结构成立，但没有任何被破坏的断言 ⇒ 属观察

`release.yml` 逐行读确认了两次独立构建：`image` 作业只调 `docker/build-push-action`（`release.yml:55-66`），
前端在 `Dockerfile:13-35` 的 `node:24-alpine@sha256:…` 阶段里 `pnpm run build`；
`release` 作业在宿主 runner 上 `make web`（`release.yml:126-127`）。加上 A-FE-9（前端报告，CONFIRMED：
连续两次构建 12/20 个分块名与内容都变）→ **两次构建的 `dist` 字节必然不同**，这一推理我认同。

**但「不变量/性质」那一栏填的是「验证了归档就等于验证了镜像（README 把两者描述为对等的发布产物）」** ——
`README.md:147-149` 的实际措辞是「`make docker` 用仓库根的多阶段 `Dockerfile` 构建镜像：前端（pnpm 构建，
锁文件固定版本）→ 静态 Go 二进制（前端 `go:embed` 进**同一个文件**）→ `scratch` 非 root 运行时」，
`Makefile:205-209` 是「this builds the image from the same source the release archives come from」。
**「同一个文件」（指同一份 Dockerfile 内的 embed 关系）与「同一份源码」都不是「同一批字节」**，
`SHA256SUMS` 也只覆盖归档+SBOM，**没有任何一句声称镜像与归档可互相复算**。
所以这是**证据边界的观察**（我尝试找那条断言，没找到），不是缺陷；严重度 提示 合适，
但应归入 A-FE-9 的后果，而不是单列一条（它的独立增量只有「两个作业各自构建」这个结构事实）。

### SUP-6 —— 成立（作「仓库外控制」）

`release.yml:6-8` = `on: push: tags: ['v*']`，无 `environment:`、无 `merge-base`/`is-ancestor`；
全仓库 `git grep -i` 对 `branch protection|tag protection|protected branch|environment:|merge-base|is-ancestor|rulesets`
**零命中**（只有 `docs/openapi.yaml` 里无关的「approval」）。仓库里有 `.github/CODEOWNERS`
（`internal/archtest/owners_test.go` 还守着它的形状），但它只管 PR 评审路由、**管不到 tag 指向哪里**。
判定：这是**不可从仓库验证的 GitHub 侧控制**，不是代码缺陷 —— 报告的分级（提示）与建议
（工作流里加一行 `git merge-base --is-ancestor "$GITHUB_SHA" origin/main`）都成立，我维持。

### SUP-7 —— 成立，但它自己的「判断」才是正解

`-licenses`/`-assert-licenses` 在 `Makefile`、`ci.yml`、`release.yml`、`docs/dependencies.md` **零命中**；
`ci.yml:361-365` 是 `cyclonedx-gomod mod -json -output sbom.cdx.json` + `grep -c '"type": "library"'` +
`test "$components" -gt 10`；我自己生成的 SBOM：`components=42 specVersion=1.6 libraries=42`、
**`components carrying a licenses field=0`**、`components carrying hashes=42`。
判定：**SBOM 不必带许可**（CycloneDX 里 `licenses` 是可选字段），而 `README.md`、`SECURITY.md`、
`docs/dependencies.md` **没有一处**声称它带 —— 所以是**范围选择**，提示级正确。
要补一句的是**交付物层面**的合成结论（不是新缺陷）：唯一回答许可问题的产物是手写的 `NOTICE`，
而它不含 npm 树，因此「SBOM 不做许可」在这里意味着**没有任何产物**回答得出
「这 3 个 MIT 包以什么身份在里面」。这条应与 SUP-1 写在同一个修法里。

### SUP-8 —— 成立，且我独立证明了工具不空转

- 本机 `govulncheck -version` → `Scanner: govulncheck@v1.8.0`、`DB: https://vuln.go.dev`、
  `DB updated: 2026-09-24 20:07:49 +0000 UTC`（与报告同期）。
- `govulncheck -show verbose ./...` → 「Govulncheck scanned the following **42** modules and the
  go1.27.1 standard library」（逐个列出了 `github.com/Re0Auth/r0semi` + 41 个第三方）+
  「**No vulnerabilities found.**」、**exit 0** → 「结论非空转」这一句成立。
- **我自建的对照**（`%TEMP%\r0semi-verify-govuln\control`，`golang.org/x/text v0.3.7` +
  `language.ParseAcceptLanguage`）：
  ```
  Vulnerability #1: GO-2022-1059 … Found in: golang.org/x/text@v0.3.7  Fixed in: v0.3.8
        #1: main.go:13:46: control.main calls language.ParseAcceptLanguage
  Your code is affected by 1 vulnerability from 1 module.     EXIT=3
  ```
  → **工具与 DB 在这台机器的这个网络上真的会报可达漏洞**，所以「没有漏洞」是有信息的。
- **5 条通告我独立查了 OSV API**（不是复用它的输出）：
  ```
  x/crypto@v0.55.0 -> GO-2026-5932, GO-2026-6354, GO-2026-6355
  x/mod@v0.38.0    -> GO-2026-6179, GO-2026-6180
  ```
  与报告表格逐条一致。可达性方面我用的论据比「trace」更硬：这两个模块**不在构建图里**——
  `go mod why -m golang.org/x/crypto|golang.org/x/mod` 都是
  `(main module does not need module …)`，且它们**不出现在 release 形状二进制（42 个 dep）里**、
  也不在 `NOTICE` 的 42 条里（`go list -m all` 共 138 行，含主模块 → 137 个外部模块，与报告一致）。
- 报告的诚实边界（「结论依赖 DB 的符号清单」）是对的，我保留它：
  我的对照只证明**管线能报**，不能证明**没有漏报**。

---

## 3. 确认的（每条 = 我执行的命令 + 有承载力的那一行输出）

| # | 我执行了什么 | 承载力的输出 |
|---|---|---|
| 1 | `go test ./internal/zzprobe/dependencies/ -v`（原报告探针） | `--- PASS: TestProbeWorkflowActionsArePinnedToASHA` + 3 条 `--- FAIL`（`TestProbeDockerfileRuntimeCarriesLicenceAndNotice`、`TestProbeDistRecipeCopiesAreFatal`、`TestProbeShippedFrontendCarriesThirdPartyAttribution`）—— 报告声称的「1 PASS = 缺守卫 / 3 FAIL = SUP-1/2/4 复现」**逐条对上** |
| 2 | 许可标记扫描 + **正对照**（拷到 `%TEMP%` 植入 `/*! Copyright … @license MIT …`） | 对照树命中、真树 **matches=1**（tailwind banner）→ SUP-1 的「0 命中」是标记集产物 |
| 3 | `go test ./internal/zzprobe/verifydependencies/ -v`（我的探针） | 5 条全 PASS：正对照命中；`dist: 25 text files scanned; files carrying any licence marker: 1`；`539 JS files … 0 carry a licence comment`；`real uses: keys: 46 remote + 1 local = 47`；`renaming these ships … : [LICENSE README.md SECURITY.md]`；SBOM 守卫 `-gt 10` |
| 4 | **已发布产物**：GitHub API → 下载 `re0auth_v0.0.0-rc.3_linux_amd64.tar.gz` → `tar -tzvf` + `tar -x` + `go version -m` + 字节扫描 | 归档 6 项（NOTICE 4242B / LICENSE / SECURITY.md / README.md / example.toml / re0auth 21,999,776B）；`shipped NOTICE entries = 42` 且 `svelte/devalue/tailwind/npm = 0`；shipped binary **42 deps ≡ NOTICE 42 条**（SETS EQUAL）；二进制内 `__svelte`×7、`__sveltekit`×5、`Copyright (c) 2016-2025`×**0**、`Permission is hereby granted`×**0** |
| 5 | `go list -deps -f '{{with .Module}}{{.Path}}{{end}}' ./...`（linux/amd64）× NOTICE × 发布形状二进制（`go version -m`） | `NOTICE=42 BINARY=42`、`SETS EQUAL`（两方向均无差集，含 `prometheus/procfs`）；`./...` 图 = `./cmd/re0auth` 图（无差集） |
| 6 | `cyclonedx-gomod mod -json`（与 `Makefile:193`/`ci.yml:362` 同参） | `components=42 specVersion=1.6 libraries=42`、`licenses 0/42`、`hashes 42/42`，且 **SBOM 组件集 ≡ 二进制模块集**（`SETS EQUAL n=42`） |
| 7 | `go mod verify` / `git grep -E 'GOFLAGS\|GONOSUMDB\|GONOSUMCHECK\|GOINSECURE\|GOPRIVATE\|GOSUMDB\|GOTOOLCHAIN\|mod=mod'` | `all modules verified`；grep **零命中**（exit 1）→ 校验和链路未被削弱 |
| 8 | `-s -w` 对照（临时模块，除零 panic，剥与不剥各一份） | `go tool nm`: `plain=1986  stripped=0`；两份 panic 输出**都**有 `main.inner(...)` + `main.go:3` → 报告的这条否定成立（我测到 1986/0，它写 2490/0，数字因模块而异，性质一致） |
| 9 | `sh` 复跑 `dist` 循环形状 | `SCRIPT EXIT CODE = 0` + 归档只含空目录 → 「`cp` 不致命」执行级确认 |
| 10 | 归档内容断言的 `git grep` | `tar -t\|unzip -l\|tar -tz\|zipinfo` 在 `Makefile`/`.github`/`docs` **零命中** → 没有任何后续步骤会发现缺文件 |
| 11 | OSV API（`api.osv.dev/v1/query`）× 2 | 与报告表格**逐条同 ID** 的 5 条通告 |

---

## 4. 我未能验证的

- **镜像侧的一切执行**：无 Docker。`Dockerfile` 内容可穷举（所以 SUP-2 的运行阶段结论是「读；无 Docker 执行」，
  与报告同级）；`docker build`/Trivy/`imagetools inspect` 都没跑。
- **`metadata-action` 的默认标签集**（决定 MPL-2.0 §3.2 那一半是否已被满足）：
  `raw.githubusercontent.com` 多次超时；`web_search` 工具返回 `Authentication Fails, Your api key … is invalid`。
  我只取到了 `action.yml`（2057 B，只有 inputs/outputs，无默认标签）→ SUP-2 的 MPL 维度标 **HYPOTHESIS**。
- **`SHA256SUMS` 与 SBOM 资产的字节级核对**：归档下载成功（7,997,296 B），
  但随后对 `SHA256SUMS`（730 B）与 SBOM（38 KB）的下载连续失败（`无法连接到远程服务器`，6 次重试），
  所以「`sha256sum -c` 通过」我**没有**做到；报告同样把它列为盲区。
  （顺带：我从 API 拿到 `SHA256SUMS` 的名称/大小与它「覆盖归档 + SBOM」的说法形状一致，但那是形状，不是校验。）
- **cosign 端到端**：无 cosign，只读到了 `release.yml:160-165` 与 `README.md:126-132` 的字符串一致性。
- **govulncheck 的漏报面**：我的对照只能证明「能报」，不能证明 DB 符号清单完备（报告已自认，我保留）。
- **`v0.0.0-rc.2`/`rc.1` 的产物**：rc.1 的 tag 不存在（`CHANGELOG.md:89-92`），rc.2 没有 release 资产。

---

## 5. 新发现（复核时顺手看到的）

### V-1 [中] SUP-1 的守卫是「词出现过」而不是「归属存在」，且它的标记集漏掉了已经存在的那处许可文本
`TestProbeShippedFrontendCarriesThirdPartyAttribution` 的失败条件是
`hits == 0`，而 `hits` 的图案是 `(?i)copyright|@license|SPDX-License-Identifier|Licensed under`。
后果有两层：
1. **它今天就在漏报**：CSS 里已有 `/*! tailwindcss v4.3.3 | MIT License | … */`，
   这四个图案**都不匹配**，所以「0 命中」不是「没有任何许可文本」，而是「没有任何**这四种**文本」；
2. **它可以被一句无关的话满足**：任何人往任意一个产物写一次 `Copyright`（例如再引入一个带 banner 的
   编译器，或给某个 chunk 加一行注释），守卫立刻转绿，**Svelte 的归属仍然缺失**。
3. 这三件事合起来意味着：报告把「修好后这条会转绿」当作验收条件，而**转绿并不等于修好**。
   建议守卫改成断言 `THIRD-PARTY-NOTICES`（或 `NOTICE` 的 npm 小节）存在且**条目数 ≥ N**（N = 打包器里
   实际出现的运行时包数，今天至少 3：svelte / @sveltejs/kit / devalue），并断言**归档里含该文件**
   （后者顺带补上 SUP-4）。

### V-2 [提示] 「前端只在构建期存在」这句文档话需要一句限定
`docs/dependencies.md:71` 与 `README.md:167` 合起来会让人相信「第三方依赖 = NOTICE 里的 42 个 Go 模块」。
它不是假话（`node_modules` 确实不进产物），但**编译后的框架运行时代码进了**（V-1 与 §2 SUP-1(d) 的字节证据）。
最小改法：在 §5 开头加一句「**构建期依赖不等于不进产物**：编译后的 svelte/@sveltejs/kit 运行时代码
随 `go:embed` 进入二进制，其归属见 `NOTICE` 的 npm 小节」。这不是新缺陷，是 SUP-1 的文档侧半边。

### V-3 [提示] `SHA256SUMS` 与 cosign 覆盖的是「`dist/*` 里当时有什么」，而归档**内容**无人断言
`release.yml:183` 是 `gh release create "${GITHUB_REF_NAME}" dist/*`，`Makefile:201` 是
`cd dist && sha256sum re0auth_$(VERSION)_* > SHA256SUMS`。两者都只保证「存在的文件被签名/被摘要」，
**不保证归档里有哪几个文件** —— 这与 SUP-4 是同一道缝，但作用域不同（发布级 vs 配方级）。
廉价闭包：在 `release.yml` 里对每个归档跑一次
`tar -tzf "$a" | grep -q 'NOTICE'`（windows 用 `unzip -l`），或断言资产数 = 10。
顺带：我已用 GitHub API 证实 rc.3 的 10 个资产与 `Makefile:200-201` 的 glob 形状吻合
（6 归档 + SBOM + `SHA256SUMS` + `.sig` + `.pem`），即「checksum 覆盖全部产物」这句话**在形状上**成立。

### V-4 [提示] 报告的 evidence 表里有两条与本机现状不符的细节（不影响结论）
1. 报告写「`internal/webui/dist/**` 的**全部 27 个交付文件（181 KB）**」上的 grep 是 0 命中，
   但它给的命令是 `-Include *.js,*.css` —— 那是 **21 个文件 / 180,581 B**；
   「27 个 / 181 KB（185,680 B）」是**整棵树**的数字（我数过：27 文件，185,680 B）。两者被混在一句里。
2. 报告举例 `_app/immutable/chunks/sEbpUoe5.js`（26.6 KB 的 SvelteKit 运行时）——
   **该文件名现在不存在**；当前 26,649 B 的那个分块叫 `-qnciKPy.js`。
   这与 A-FE-9（每次构建 12/20 个分块改名）一致：报告的证据是在**另一次构建**的产物上取的。
   我因此**在今天的树上重做了整个扫描**（结论不变），并且额外在**已发布的 rc.3 二进制**上复核了一遍。

---

## 6. 我认为严重度被低估的

**没有一条需要升级到「高」或「阻断上线」**，但有一个方向要记下来：
**SUP-1 的影响不是「将要发生」，而是「已经发生」**。报告的盲区清单写着
「**没有已发布的 release 产物**」，而 `CHANGELOG.md:79` 与 GitHub API 都表明
`v0.0.0-rc.3` 已经带 10 个资产公开发布（2026-09-26），我下载并核对了其中的 `linux/amd64` 归档。
所以「这类缺陷不可回溯修复：已发出的归档补不了」这句从假设变成了事实陈述，
**建议在报告里把它从「影响」的一行改成「已确认发生」的一行**，并给出上面的可证据化路径
（GitHub API + `tar -tzvf` + 二进制字节扫描）—— 这比任何推理都硬。
严重度仍维持「中」（无安全可利用面、三个包均为 MIT），但**修的时候点在「下一个 release 之前」，
而不是「将来某次发版之前」**。

---

## 7. 小结（给主代理的一句话级判断）

原报告在这一区域**方向是对的、数字与修法有硬伤**：SUP-2/6/7/8 我逐条确认；
SUP-1 **实质成立且我已用已发布产物把它钉死**，但标题（「完全没有许可文本」）与修法第 2 步
（legal-comments 保留 = 空转）必须改；SUP-3 缺守卫成立但「守卫不存在」过头（base-image 那一半有守卫）、
计数 43 应为 47；SUP-4 机制我执行级复现，但它举的 `NOTICE` 例子恰好**被 `notice_test.go` 挡住**，
真正的静默面是 `LICENSE`/`README.md`/`SECURITY.md`；SUP-5 是观察而非缺陷（没有任何「归档=镜像」的断言）。
报告的 6 条否定结论我抽查了 5 条（NOTICE 集合、SBOM 集合、`go mod verify`、无校验和削弱、`-s -w` 与 panic 符号），
**全部成立**，其中「NOTICE 42 ≡ 构建图 42」与「SBOM 42 ≡ 二进制 42」我还在**已发布产物**上确认了一遍。
