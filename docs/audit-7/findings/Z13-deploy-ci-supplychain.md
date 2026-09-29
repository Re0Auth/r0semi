# 区域 13：部署 / CI / 供应链 / 发布产物 — 第七轮审计报告

## 范围与方法

读了：`Dockerfile`、`.dockerignore`、`.gitignore`、`.gitleaks.toml`、`Makefile`、
`deploy/k8s/{base,backup}/*`、`deploy/prometheus/re0auth.rules.yml`、`scripts/{backup,restore,backup-keys}.sh`、
`.github/workflows/*`（ci/release/codeql/perf/bench-ab/visual-baselines）、`internal/archtest/*`、
`NOTICE`、`SECURITY.md`、`CHANGELOG.md`、`README.md`、`docs/operations.md`、`cmd/re0auth` 的 flag 与迁移 `0013/0014`。

跑了：`go test ./internal/archtest/`（green，2.1s）、`go test -tags audit5 ./internal/zzprobe/deploy/...`
（green，第五轮那些门禁现在都过）、`go build ./cmd/re0auth` + 真二进制 `-h` / `-print-secret-env -config config/re0auth.example.toml`
（用真实 flag 与真实输出核对 runbook）、`git check-ignore -v`（含正对照）、
以及 `internal/zzprobe/audit7/z13deploycisupplychain/` 里的 7 条探针——**全部红**（同一条测试里带正对照）。
其中两条探针把 `internal/archtest` **编译成真 test 二进制**，在一个只含被读产物的临时模块根里跑，
先证明「未变异时绿、workflow 级变异时红」，再证明「job 级 / 文件名的同形变异不红」。

本机无 Docker、无本地 Postgres、**无 bash**（PowerShell-only）：容器层、真镜像、真 age/pg_dump 行为一律
读码级；`scripts/*.sh` 无法实跑，已在「未能到达」写明。

探针目录：`internal/zzprobe/audit7/z13deploycisupplychain/`
验证命令：`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z13deploycisupplychain/...`

## 发现

### Z13-1 两个备份脚本的默认输出目录 `./backups` 既不在 `.gitignore` 也不在 `.dockerignore`
- 严重度：P2 中
- 类别：安全 / 合规
- 不变量：凭据封存（备份产物不得进入版本库或镜像层）
- 证据：`scripts/backup.sh:12`、`scripts/backup-keys.sh:23` 都是 `dir="${1:-./backups}"`；
  `backup-keys.sh` 在该目录写出**明文** `re0auth-keys-<stamp>.env`（`RE0AUTH_KEK` + OIDC 签名私钥 +
  OIDC 令牌密钥 + 审计链密钥 + 配置声明的所有 `client_secret_env` + retired 集合），`backup.sh`
  写出明文 SQL 转储。探针（红）：
  - `git check-ignore -v backups/re0auth-keys-<stamp>.env{,.age}` → exit 1（未被忽略）；
  - 正对照：`.env`、`config/re0auth.toml`、`config/x.secret.toml` → exit 0（真被忽略，读取规则有效）；
  - `.dockerignore` 含 `.env` 与 `config/*.secret.*`，但**没有**任何 `backup` 规则（其自身注释：
    「deployment-local secrets and the tool's own state stay out」）。
  `.gitignore` 为 `.env`(:41)、`config/*.secret.*`(:45)、`config/re0auth.toml`(:50) 各写了规则，
  唯独仓库自己的备份脚本默认落点没写。`git add -A` 会暂存它们；`docker build .` 会把整个目录带进
  构建上下文与 `COPY . .` 的 backend 阶段层（最终 scratch 阶段只 COPY 二进制/证书/LICENSE/NOTICE，
  所以不进发布镜像，但中间层与本地 context 都在）。
- 状态：CONFIRMED（真跑 `git check-ignore` + 正对照；dockerignore 为源级）
- 影响：一次 `git add -A` 就把 KEK 与全部长期密钥送上远端；gitleaks 的唯一补充规则是默认
  generic-api-key 的熵规则（`.gitleaks.toml` 只额外豁免审计报告路径，未给这些形状加规则），
  不能当作兜底。这是「脚本自己写出的机密落在无保护路径」这一类，与 P2-14 同形。
- 探针：`z13_test.go::TestZ13BackupDefaultDirIsNotIgnored`（红）
- 修法建议：`.gitignore` 与 `.dockerignore` 各加 `/backups/`、`*.dump`、`*.env`（或把默认输出改成
  `$TMPDIR`/必填参数，**拒绝**在仓库内写机密）。最小改法是加两行。
- 是否与既有编号相关：对 P2-14（备份脚本明文权限）修复的**补充**——同一次修复里改了 umask，
  没有改落点。

### Z13-2 版本 tag 先于 Trivy 进 GHCR；`cosign sign` 晚于 `latest` 提升
- 严重度：P3 低/提示
- 类别：安全 / 合规
- 不变量：fail-closed（未过扫描的镜像不得以发布名可拉取）
- 证据：`release.yml` image job 的步骤序号（探针实测，红）：`docker/build-push-action`（step 5，
  `push: true` + `tags: ${{ steps.meta.outputs.tags }}`，metadata-action 只产 `type=ref,event=tag`）
  在第 7 步 `scan the image`（`--exit-code 1 --severity HIGH,CRITICAL`）**之前**。
  第 8 步才 `promote to latest`、第 9 步才 `cosign sign`。
- 状态：CONFIRMED（探针按行序断言；`--exit-code 1`、`push: true`、无 `latest` 都作了正对照）
- 影响：扫描失败时 `ghcr.io/re0auth/r0semi:<tag>` 已存在且与扫过的镜像无法区分；被挡住的只有
  `latest` 与 `gh release create`。P2-12/DEP-V3 的原始形状（`latest` + manifest 引用 `latest`）已修对，
  剩下这一半：**基线文档让运维「钉发布的 tag」**（`docs/operations.md:21-22,32-34`），而失败的
  tag 在注册表里长得一样。另外 `latest` 在签名之前就被提升，`cosign sign` 失败会留下未签名的浮动 tag。
- 探针：`z13_test.go::TestZ13ReleasePushesTheReleaseTagBeforeTheScan`（红）
- 修法建议：`build-push-action` 改 `push: false, load: true` → 扫本地 → 再单独 push（或
  `--push` 前加一步 `docker buildx build --output=type=registry`）；把 `cosign sign` 挪到
  `promote to latest` 之前。属于顺序调整，不是设计裁定。
- 是否与既有编号相关：对 **P2-12 / DEP-V3** 修复的**补充/部分反驳**——`latest` 那一半修对了，
  「Trivy 阻断发生在 push 之后」那一半仍在。

### Z13-3 运行镜像不带 npm 归属清单，而 Makefile 自己要求它随「每个二进制、归档和镜像」分发
- 严重度：P2 中
- 类别：合规/隐私
- 不变量：许可随产物分发（发布的每个形态都带三方的版权/许可文本）
- 证据：`Dockerfile:74` 只 `COPY LICENSE NOTICE /`；runtime 阶段全部 COPY 行实测为
  `ca-certificates.crt` / `re0auth` / `LICENSE NOTICE`（探针打印，红）。`Makefile:205-221` 的注释：
  「The SPA is third-party code too (Svelte, SvelteKit, Tailwind), and it ships inside every binary,
  archive **and image**, so it needs the same attribution」——而 `npm-attribution` 只挂在
  `release`/`checksums` 上，Dockerfile 不引用它。SPA 由 `//go:embed` 进同一个二进制，所以镜像里的
  SPA 与归档里的完全一样。
- 状态：CONFIRMED（源级 + 红探针；正对照：LICENSE/NOTICE 确实在、`npm-attribution:` 确实是真目标）
- 影响：`ghcr.io/re0auth/r0semi:<tag>` 分发出去的二进制里含 Svelte/SvelteKit/Tailwind 却没有任何
  npm 侧归属（P2-21 已证这些 bundle 里 legal comment 为 0）。用镜像部署的沿用者拿不到那份清单。
  同一条不变量在两处守卫里被**放行**：`internal/archtest/workflows_test.go:21-41` 只 grep Makefile 接线；
  第五轮探针 `internal/zzprobe/deploy` 的 `TestRuntimeStageShipsTheBinaryAndTheCABundleOnly:606`
  的白名单是 `{ca-certificates.crt, /out/re0auth, LICENSE, NOTICE}`——它把「镜像只该带这四个」写成了断言，
  于是 SPA 的清单即使被加进去也会被判红。
- 探针：`z13_test.go::TestZ13RuntimeImageShipsTheNpmAttribution`（红）
- 修法建议：web 阶段把 `pnpm licenses list --json` 的输出落到 `/out/`，runtime 阶段
  `COPY --from=web /out/npm-attribution.json /`（文件名带版本或不带都行），并把两处白名单加上它。
- 是否与既有编号相关：对 **P2-21 / DEP-21**（镜像补 LICENSE/NOTICE）修复的**补充**——归档那一半修了，
  镜像这一半没修，且第五轮的守卫把缺口固化了。

### Z13-4 `backup-keys.sh` 的 umask 与 age 检查都在它们该保护的东西之后
- 严重度：P3 低/提示
- 类别：安全
- 不变量：fail-closed（密钥备份不得在降级路径上留明文；目录不得比文件更宽）
- 证据（源级，行序由探针断言，红）：
  - `scripts/backup-keys.sh:24` `mkdir -p "$dir"` 在 `:72` `umask 077` **之前**——新建的密钥备份目录
    取环境 umask（常见 022 ⇒ 0755），本地任意用户可遍历。`scripts/backup.sh:19` 反过来，其注释写明
    「Setting it before mkdir also makes a freshly created backup directory 0700」；
  - `:73` `: > "$out"` 与 `:45` 的 `printf … >> "$out"` 在 `:100` 的 `command -v age` **之前**——
    `BACKUP_AGE_RECIPIENT` 已设而 `age` 未装时，脚本 exit 1，但四把密钥（加配置声明的 client secret）
    已经明文写在 `backups/re0auth-keys-<stamp>.env` 里，看到非零退出码的运维没有理由去找它。
    `backup.sh:28` 的同类检查在 `pg_dump` 之前，注释解释了原因。
- 状态：CONFIRMED（源级：bash 的 umask/mkdir 与 set -e 语义是确定的；两种形状的行序由探针钉住。
  目录的**具体权限位**取决于环境 umask，属运行时前提——本机无 bash 不能实跑，见「未能到达」）
- 影响：P2-14 的同一类降级路径在 keys 脚本里没修；也是最容易踩的一次「装了 age 才安全」。
- 探针：`z13_test.go::TestZ13KeyBackupScriptOrdersItsGuards`（红；正对照：`backup.sh` 的两处顺序都对）
- 修法建议：`umask 077` 提到 `:24` 之前；把 age 存在性检查（及 `BACKUP_AGE_RECIPIENT` 的取值检查）
  提到 `: > "$out"` 之前，或把整段写入放进 `mktemp -d` 并在失败时清理。
- 是否与既有编号相关：对 **P2-14** 修复的**补充**（`backup.sh` 修了，`backup-keys.sh` 没有）。

### Z13-5 `internal/archtest` 的写权限门只看 workflow 级 `permissions`，job 级越权不响
- 严重度：P3 低/提示
- 类别：可维护性 / 安全（门禁覆盖）
- 不变量：fail-closed（CI 门禁在越权形状上真的会红）
- 证据：探针把真 `internal/archtest` 编译成 test 二进制，在临时模块根里跑同一道门：
  1. 未变异 → PASS；
  2. 在 `ci.yml` **workflow 级** `permissions:` 里加 `packages: write` → **FAIL**（门真的能红）；
  3. 把同样的 `packages: write` 加到 **`test` job** 上 → **PASS**（第 559 行报红）。
  机制：`workflows_test.go:280-312` 只把 `permissions` 解到顶层 `any`，从不下钻 `jobs.*.permissions`。
- 状态：CONFIRMED（真门禁 + 双向阳性对照）
- 影响：`release.yml:10-14` 的承诺是「每个 job 自己声明它真正用的 scope」，把 workflow 级块去掉正是
  为了缩小爆炸半径；但这条守卫在「只给某一个 job 加回写权限」时沉默——而那恰恰是它要防的形状
  （一次性便利、代价直到某个不该持 token 的步骤花掉它才可见）。
- 探针：`z13_test.go::TestZ13PermissionsGateIgnoresJobLevelGrants`（红；含 2 个正对照）
- 修法建议：把每个 job 的 `permissions`（及其 `uses:` 是否用到 `secrets.`）一并解出并断言
  「写 scope 只出现在已知需要它的 job 名单里」；名单本身写成测试里的常量。
- 是否与既有编号相关：对 P2-12 修复时引入的这道门（githubactions:S8233）的**补充**。

### Z13-6 npm 归属清单是否被 `SHA256SUMS` 覆盖，没有守卫
- 严重度：P3 低/提示
- 类别：合规/隐私（供应链）
- 不变量：校验和覆盖发布的每个文件（「checksum 文件比没有更糟」的自己那句）
- 证据：探针在临时模块根内把 `Makefile:219` 的输出名从
  `../dist/re0auth_${VERSION}_npm-attribution.json` 改成 `../dist/npm-attribution.json`：
  `TestReleaseShipsNpmAttribution` **仍然 PASS**（第 589 行报红）。正对照：同一探针断言
  `^re0auth_[^_]+_` 不匹配 `npm-attribution.json`、匹配真名；门禁变异的失败方向也已证明可红（见 Z13-5）。
  实际后果链：`checksums: cd dist && sha256sum re0auth_${VERSION}_*` 漏掉该文件（不报错），
  `gh release create <tag> dist/*` 把 `dist/` 里**全部**文件发出去 ⇒ 一个不在 `SHA256SUMS` 里的
  许可文件随发布走，而 `SHA256SUMS` 看上去仍然完整。
- 状态：CONFIRMED（真门禁 + 文件名变异）
- 影响：`workflows_test.go:16-20` 的注释正是「The file must be built by `release` and **covered by
  `checksums`**, or it is generated and then dropped」——断言只做到前半句。
- 探针：`z13_test.go::TestZ13NpmAttributionGateIgnoresTheChecksumsGlob`（红）
- 修法建议：门禁加一条「走向真实的产出路径」的断言：把 Makefile 的 `dist` 目标产出清单（或 `checksums`
  的 glob）解出来，逐个断言文件名匹配 glob；或改成显式列表 `SHA256 ?= dist/... ` 而非通配。
- 是否与既有编号相关：与 P2-21 修复同期加入的门禁；无既有编号。

### Z13-7 README 对发布产物与镜像内容的描述与产物不符
- 严重度：P3 低/提示
- 类别：可维护性
- 不变量：文档与实现一致（运维按文档判断产物里有什么）
- 证据：`README.md:129-132` 列了归档内容、SBOM、`SHA256SUMS` 与 cosign 签名，**从未提**
  `re0auth_<version>_npm-attribution.json`（只有 `CHANGELOG.md:58-61,75` 提到）；
  `README.md:160` 说运行镜像「只带二进制与 CA 证书」，而 `Dockerfile:74` 已 `COPY LICENSE NOTICE`。
- 状态：CONFIRMED（源级 + 红探针，正对照：两个小节标题与 SBOM/SHA256SUMS 字样仍在）
- 影响：合规产物的存在与镜像内容两个判断，读者只能从 CHANGELOG 与 Dockerfile 反推。
- 探针：`z13_test.go::TestZ13ReleaseDocsDescribeTheShippedArtifacts`（红）
- 修法建议：README 补 npm 清单文件名与用途（它也在 `SHA256SUMS` 覆盖内，顺带与 Z13-6 的修法对齐）；
  镜像那句改成「二进制、CA 证书、LICENSE、NOTICE（SPA 的 npm 清单见 Z13-3）」。
- 是否与既有编号相关：对 P2-21 修复的文档补充。

## 探过但没破的（也应变成守卫）

1. **基础镜像与 `uses:` 固定**：`TestDockerfileBaseImagesArePinned`、`TestWorkflowActionsArePinnedToFullSHAs`
   实跑 green（`go test ./internal/archtest/` → ok）。三个 `FROM` 全 digest、30+ 个远端 `uses:` 全 40-hex，
   反空转下限（≥3 FROM、≥30 uses）都在。Trivy 也按 digest 固定（`release.yml:105`），只是那不属于 `uses:`，
   守卫看不到——属已知的范围选择（`docs/dependencies.md` §7）。
2. **NetworkPolicy 选择器 / 备份 Pod 标签 / 资源与探针 / grace 自洽 / Ingress 注解**：第五轮探针
   `go test -tags audit5 ./internal/zzprobe/deploy/...` 全 green。含：base 四选择器互相对齐、
   `expose_internal=true` 有策略背书、`terminationGracePeriodSeconds 45 ≥ endpointRemovalWait 5 + shutdownTimeout 30 (+5)`
   且 nginx `proxy-read-timeout: 60` 足够、危险注解黑名单、备份 Pod 由自己的策略选中且不挂 SA token。
3. **备份/恢复校验绑定**：`restore.sh:28-42` 现在把摘要与**命令行给的文件**比较（不用 `--check` 读边车路径）、
   缺 `.sha256` 直接 `exit 1`（原 P2-11 的 fail-open 已关）、`.age` 路径**先校验密文再解密**（P2-10 已关）、
   解密进 `mktemp -d` + EXIT trap、`pg_restore --single-transaction --exit-on-error`、空库守卫。
   我把每条与 `security-audit-5.md` 的 DEP-01/V1/V2 逐条对照过，没有找到残余 fail-open。
4. **CronJob 侧转储权限**：内联脚本 `umask 077` 在 `pg_dump` 之前、`sha256sum` 边车与 `.dump` 同步按
   `-mtime +${BACKUP_RETAIN_DAYS}` 清理、`concurrencyPolicy: Forbid`、`startingDeadlineSeconds: 300`、
   `automountServiceAccountToken: false`、`readOnlyRootFilesystem` + `capabilities.drop: [ALL]`、
   镜像 digest 固定、`/backups` 真挂载。转储不加密是**文档化的决定**（`docs/operations.md:125-126`），不作为发现。
5. **secrets 进镜像/层/日志**：`.dockerignore` 排除 `.git`、`.github`、**本机私有工具目录**、`.env`、
   `config/*.local.*`、`config/*.secret.*`、`config/re0auth.toml`；runtime 阶段 `scratch` + `USER 65532:65532` + 无 HEALTHCHECK
   （故无 shell 依赖），`CGO_ENABLED=0`。`release.yml` 里 tag 经 `VERSION=…` 环境变量而非插值（`make` 侧
   `export VERSION` + `$${VERSION}`），`gh release create` 读 `GITHUB_REF_NAME` 并 `case` 判 prerelease；
   这两个防「tag 里的 shell 元字符变成代码」的点都在，我复核了 `make` 不会在展开期把 `$(VERSION)` 插进脚本文本。
6. **SBOM 与模块集**：`make sbom` 用 `cyclonedx-gomod mod -json` 并 `test -s` 非空；`ci.yml` 里 SBOM 组件数
   `test "$components" -gt 10` 是反空转下限；`TestNoticeCoversTheBuildGraph` 实跑 green（NOTICE = 生产图）。
   `-licenses` 未开是范围选择（第五轮 SUP-7 已裁定）。
7. **runbook 命令与真实 flag/键名**：真二进制核对通过——`-config`、`-migrate-down`、`-print-secret-env`、
   `-rotate-keys`、`-version` 全部存在；`-print-secret-env -config config/re0auth.example.toml` 输出
   `idp.github.client_secret_env=…` / `vault.kek_env=RE0AUTH_KEK`，与 `backup-keys.sh:58,85` 的 `sed`
   解析、`docs/operations.md:138-142` 的描述一致；`docs/operations.md:15-20` 的 secret 五个键与
   `deployment.yaml:62-76` 的 `secretKeyRef` 逐一对齐；`SELECT count(*) FROM audit_events WHERE row_hash='\x<hex>'`
   的列名真实存在（迁移 `0013_audit_chain.sql:28`，`audit_events.row_hash bytea`），日志侧确实写
   `slog.Info("audit chain head anchored", "head", hex…)`（`cmd/re0auth/main.go:1036-1038`）。
   `prometheus` 的 20 条 `runbook_url` 锚点与 `docs/runbooks.md` 的 20 个 `## Re0Auth…` 标题逐个对上。
8. **无 `pull_request_target`、无 fork 拿写 token**：全部 workflow 里 `on: pull_request` 的两份
   （ci/codeql）都只有读权限（`release.yml` 不响应 PR）；`bench-ab`/`perf`/`visual-baselines` 只
   `workflow_dispatch`/`schedule` 且无写权限（`visual-baselines` 明说不 commit、只发 artifact）。
   `.github/dependabot.yml` 覆盖 gomod/npm/github-actions/docker 四个生态。
9. **`.dockerignore` 的 `*.exe`**：仓库根三个残留二进制（`re0auth.exe`/`perfreport.exe`/`httpapi.test.exe`）
   被覆盖，`git ls-files` 零命中（第六轮已核，我这里只复核 `.dockerignore:13` 仍在）。

## 未能到达（残余盲区）

1. **无 Docker**：镜像层、CA bundle 是否悬空（P2-33）、`cp -L` 是否真的解引用、Trivy 实际扫描结果
   （含多平台 index 的 `--platform` 行为）、`sbom: true`/`provenance: true` 附在 manifest 上的形状、
   `buildx imagetools create` 提升 `latest` 的行为、cosign keyless 与 Fulcio/Rekor 的交互，全部只能读码。
   Z13-2 的结论因此只到「步骤顺序」这一层，不到「注册表里真实存在什么」。
2. **无 bash**（PowerShell-only，`Get-Command bash` 未找到）：`scripts/*.sh` 一次都没实跑。
   Z13-4 因此只能给行序级证据（umask/mkdir 与 set -e 的语义确定），**目录的实际权限位**与
   「缺 age 时磁盘上留下的文件」是推断——要实跑一次 `./scripts/backup-keys.sh <tmp>` 才能把权限位钉死。
   同理 `restore.sh` 的三条修复我只做到逐行复核，没有第五轮那样的桩工具实跑。
3. **无本地 Postgres / 无集群**：`pg_dump -Fc` 的真实产物、`pg_restore -l` 校验、备份 CronJob 在
   default-deny 集群上是否真的通（NetworkPolicy 是否被 CNI 实现，`docs/operations.md:191-201` 自己
   把它列为部署方验收项）、PVC/fsGroup 的可写性，全部没跑。
4. **无网络/无真 tag 运行**：`release.yml` 从未真跑（本地只有 `v0.0.0-rc.2/rc.3` 两个 tag），
   `make release` 未执行（Windows 无 make/zip/sha256sum），所以「`dist/*` 实际含哪些文件」「`SHA256SUMS`
   实际覆盖哪些」只在脚本层确证（Z13-6 的探针也是脚本层）。
5. **`.gitleaks.toml` 的实际检出能力**：gitleaks 未安装、无网络，无法验证明文 `RE0AUTH_KEK=<base64>`
   会不会被默认 generic-api-key 规则命中。Z13-1 的「gitleaks 不是兜底」是按配置读出来的，不是跑出来的。
6. **`rc.3` 镜像里到底有什么**：无法 pull，所以 Z13-3 的「已发出、不可回溯」只对**归档**成立；
   镜像是否已发出（GHCR 是否有 rc.3）未能确认，我因此没把它写成「已公开发出」。

## 判断（文档化决定可否质疑，不是 finding）

- **备份转储不加密**（`docs/operations.md:125-126`）与 **「备份已停」无告警**（`docs/operations.md:117-118`、
  第五轮 P2-16/DEP-06 已收录）都是文档化的取舍，按简报不作为发现。但第二条值得记一笔：现在文档把它
  写成了已知后果而不是「有意不做」，`Re0AuthBackupStale` 之类的规则至今不在
  `deploy/prometheus/re0auth.rules.yml`（该文件 20 条规则里没有备份维度）。**这是第五轮的未闭合项，不是新发现**。
- **CI 的 `image` job 只 build 不 scan**（`ci.yml:533-552`）：README 说「CI 每次改动都会构建一次」，
  而 Trivy 只在 tag 时跑。因为运行时是 scratch、依赖面由 `govulncheck`（按可达性）在每次 PR 覆盖，
  我不认为这是漏洞；记在此处供裁定者决定要不要在 CI 里也扫一遍。
- **`scratch` 而非 distroless**：Dockerfile 的注释把理由写全了（静态二进制 + 无会漂移的基础 digest），
  我同意；这是判断，不是发现。
