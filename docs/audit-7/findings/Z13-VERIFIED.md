# 区域 13 对抗式复核：部署 / CI / 供应链 / 发布产物 — Z13-VERIFIED

## 复核范围与方法

复核对象：`docs/audit-7/findings/Z13-deploy-ci-supplychain.md`（Z13-1…Z13-7）与其探针
`internal/zzprobe/audit7/z13deploycisupplychain/`（2 文件，7 条探针，我实跑：**7 条全红**，失败原因与报告所述一致）。

我自己读了：`Dockerfile`、`.dockerignore`、`.gitignore`、`.gitleaks.toml`、`Makefile`、
`.github/workflows/{release,codeql}.yml`、`internal/archtest/{workflows,dockerfile}_test.go`、
`internal/zzprobe/deploy/artifacts_test.go:591-624`、`scripts/{backup,backup-keys,restore}.sh`、
`deploy/k8s/{base/deployment.yaml,backup/cronjob.yaml}`、`README.md:118-172`、`docs/operations.md:82-146`、
第六轮汇总 `docs/audit-6/findings/00-LAUNCH-READINESS-CONSOLIDATED.md:158-159`、`Z16-guard-test-quality.md:77-92`、
`Z16-VERIFIED.md:60,114-121`、`Z17-docs-contract-drift.md:45`。

我实跑了：`go test ./internal/archtest/`（ok）、`go test -tags audit5 ./internal/zzprobe/deploy/...`（ok）、
被复核探针（红/绿如述）、`git check-ignore` 正负对照，以及**真实 bash**（见下）驱动的
`scripts/{backup,backup-keys,restore}.sh`（桩 `pg_dump`/`psql`/`pg_restore`）。

我的探针：`internal/zzprobe/audit7/z13verify/`（5 条：4 红 + 1 正对照绿）。
命令：`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z13verify/...`。

**关键环境修正（原报告前提错误）**：原报告「未能到达 #2」称本机**无 bash**（依据是 `Get-Command bash` 找不到）。
实际 `C:\Program Files\Git\bin\bash.exe` 存在，`bash 5.3.9(1)-release`，且能跑仓库脚本。因此 Z13-4 的下半段
与 restore.sh 都能、也应该被实跑——这直接改变了第三条结论。

## 逐条裁定

| ID | 裁定 | 修正严重度 | 一句话理由 |
|---|---|---|---|
| Z13-1 | CONFIRMED | P2（维持） | 复跑 `git check-ignore`：`backups/*.dump`、`*.env`、`*.age` 全 exit 1，`.env`/`config/*.secret.*` exit 0；两脚本默认值确在 `:12`/`:23`；非 P2-14、非文档化决定。注意文档化调用都显式传 `/backups`，触发面是「裸跑脚本」 |
| Z13-2 | CONFIRMED | P3（维持，不要升） | 逐行读 release.yml：push（`:64-71`，`push: true`）在 scan（`:100-107`，`--exit-code 1`）之前，promote/sign 在其后。`deployment.yaml:44` 已钉 `v0.0.0-rc.3`、metadata 不再产 `latest`，P2-12 的放大项确已消失，残余仅是「可拉取的 tag」，失败也不静默 |
| Z13-3 | CONFIRMED | P2（维持） | `Dockerfile:69-74` 运行阶段确无 npm 清单；`Makefile:207-208` 自述「ships inside every binary, archive **and image**」。第五轮守卫 `artifacts_test.go:606` 的四项白名单确会把新增 COPY 判红（`Contains`，我读码确认）。P2-21 的归档半边已修、镜像半边未修 → 补充成立 |
| Z13-4 | CONFIRMED | P3（umask 半）/ **P2（age 半）** | 行序属实（`backup-keys.sh:24` < `:72`；`:73`/`:45` < `:100`）。我实跑：`BACKUP_AGE_RECIPIENT` 已设而 `age` 缺失时 exit 1，**`re0auth-keys-*.env` 明文残留**（含 KEK/TOKEN/SIGNING），而 `backup.sh` 同样条件下不留 `.dump` → age 半与 P2-14 同形，应升 P2。**权限位我拒绝采信**：本机 Git Bash 挂载是 `noacl`，我实测同一 umask 下两脚本产物都是 644/755，任何权限位读数在本机都无效——报告没把它们当证据是对的 |
| Z13-5 | CONFIRMED | P3（维持） | 独立复现：未变异 PASS、workflow 级 `packages: write` FAIL、job 级 `packages: write` **PASS**。更强证据：仓库里已有一个**真实的** job 级写权限 `codeql.yml:19-22 security-events: write`，门禁从未看见它——它区分不了合法与越权 |
| Z13-6 | CONFIRMED，与 Z16-4 重叠 | P3（建议合并） | 我补上了原探针缺失的阳性对照：把 `npm-attribution: dist` 改名 → 门禁 **FAIL**（证明它读的就是这棵树），再把输出名改成 `../dist/npm-attribution.json` → 仍 **PASS**。同守卫、同根因（整文件 grep），Z16-VERIFIED 已判 Z16-4 CONFIRMED P3 并承认交叉；宜合并为一 |
| Z13-7 | CONFIRMED | P3（维持） | `README.md:126-132` 未提 npm 清单、`:160` 仍写「只带二进制与 CA 证书」而 `Dockerfile:74` 已 COPY LICENSE/NOTICE。非 Z17 重报（`Z17:45` 已划界） |

补充裁定细节：Z13-2 的 P2-12「部分反驳」定性准确；Z13-3 对第五轮守卫缺口「把缺口固化」的描述准确；
Z13-5/6 都不是 P2-12 或 SUP-7 的重报；Z13-1 与 `00-MAIN-VERIFICATION.md:286`（主代理独立复核）独立同源，不重复。

## 新发现

### Z13V-1 `.dockerignore` 只覆盖了 `.gitignore` 的一部分：审计工作区（内含真 KEK 文件）也进构建上下文
- 严重度：P2 中
- 类别：安全 / 合规
- 不变量：凭据封存（本地状态与机密不得进入构建上下文/镜像层）
- 证据：`.gitignore` 有 `/scratchpad/`(:70)、`go.work`(:37)、`*.local.toml`(:46)、`*.out`(:23)、`/bench.txt`(:29)；
  `.dockerignore` 对**这些路径一个 pattern 都没有**（唯一相关的是根级 `.env`，而工作区里的文件叫 `keys.env`）。
  我按 Docker 文档的两种读法各实现一个匹配器（无斜杠 pattern 既按「仅根目录」也按「任意深度 basename」判），
  两者对这些路径都判「不排除」；正对照：`.env`/`config/*.secret.*`/`web/node_modules/**`/`dist/**` 两种读法都排除，
  `config/re0auth.example.toml`/`README.md` 都不排除。当前工作区实况：`scratchpad/` = 112 文件 / 68.34 MB，
  其中 `scratchpad/audit7/z08v/keys.env`（UTF-16LE，**该文件已在事后工作区清理中删除**）含 `RE0AUTH_KEK=<32B base64>` 与
  `RE0AUTH_OIDC_SIGNING_KEY=MII…`（PEM 私钥）。`make docker`/README 的 `docker build .` → 构建上下文，
  Dockerfile:42 `COPY . .` → backend 阶段层；远程/云 builder 会整体上传 context。
- 状态：CONFIRMED（源级 pattern 分析 + 工作区实况；层内容需 Docker，未能实看）
- 影响：`.gitignore` 让人在 `git status` 里看不见这些文件，而构建照旧带上它们；`Z13-1` 只报了 `./backups`，
  实际漏掉的是整个被忽略的本地状态面。probe 产生的密钥不是生产密钥，但机制对任何 `*.local.toml`/`go.work` 同样成立。
- 探针：`z13verify_test.go::TestZ13VDockerignoreLeavesGitIgnoredSecretsInTheBuildContext`（红）+
  `TestZ13VDockerignoreMatchersHavePositiveControls`（绿，匹配器双向对照）
- 修法建议：`.dockerignore` 加 `scratchpad`、`go.work`、`go.work.sum`、`*.local.toml`、`*.out`、`bench.txt`、`load.txt`、`report.md`。
- 是否与既有编号相关：第六轮 `00-LAUNCH-READINESS-CONSOLIDATED.md:158-159` 已把「`.dockerignore` 没有 `*.test`」
  记为**信息级**；本条是同一机制下的新实例且指认了具体机密文件（非重报）。Z13-1 是其子集。

### Z13V-2 `scripts/restore.sh` 在自身 `set -euo pipefail` 下无法执行：恢复路径 100% 死
- 严重度：P1 高
- 类别：可用性 / 正确性（灾难恢复）
- 不变量：fail-closed 且可执行（文档化的唯一恢复路径必须真的能跑）
- 证据：`scripts/restore.sh:29` `local file="$1" sidecar="$file.sha256" want got`。bash 在**执行 `local` 之前**
  展开其全部右值：`set -u` 下 → `line 29: file: unbound variable`，exit 1，永远到不了 `:30` 的边车检查；
  去掉 `set -u` → `sidecar` 变成 `.sha256`（错的路径）。我用真实 bash（5.3.9，含 `env -i` 干净环境）实测，
  与 Go 探针两条路径一致。对照：把该行拆成两条 `local` 的**同文件临时副本**跑通
  （`checksum verified: …` + `STUB pg_restore …` + `restore complete`，exit 0），且三条守卫在修正副本上
  全部按报告所述正确拒绝（无 `.sha256`→`is missing`；边车指向别的文件→`checksum mismatch`；目标非空→`refusing to restore`）。
- 状态：CONFIRMED（实跑；唯一保留项：本机只有 5.3.9 一个 bash，见「未能到达」）
- 影响：`docs/operations.md:94` 与 `:281` 的恢复/演练命令在装有当前 bash 的主机上直接报 `unbound variable` 退出。
  第五轮 P2-11 的修复**从未被执行过**（`docs/audit-5/findings/deploy-ops-VERIFIED.md:242-246` 跑的是修复**前**的
  `sha256sum --check` 版本）。备份再正确也不能恢复。
- 探针：`z13verify_test.go::TestZ13VRestoreScriptVerifierAbortsBeforeItVerifies`（红，含修正副本对照 + 三条守卫绿对照）
- 修法建议：拆成 `local file="$1"` 与 `local sidecar="$file.sha256" want got` 两条（已用临时副本证明可通）。
- 是否与既有编号相关：**对 P2-11 修复的反驳/补充**（修复引入了新缺陷），并**反驳原报告「探过但没破 #3」**。

## 「探过但没破」的假守卫检查（逐条）

1. 基础镜像 / `uses:` 固定——**真守卫**：我实跑 archtest 绿；`dockerfile_test.go:44` 有 `FROM ≥ 3` 下限、
   `workflows_test.go:104` 有 `pinned ≥ 30` 下限，不是「找不到也算过」。
2. 第五轮 `internal/zzprobe/deploy`——我实跑绿（`-tags audit5`），确认报告没有拿空跑冒充。
3. 备份/恢复三条 fail-closed——**被 Z13V-2 推翻**：报告的绿来自逐行复核而非执行；修正那一行后三条守卫才是真的。
4. CronJob——读码逐项属实（`:66` umask 在 `:69` pg_dump 前、`:71` 边车、`:75-76` 按 mtime 清理、
   `:15/:17/:35/:42/:85` 自洽、`:49` digest 固定、`:78-79` volume 真挂）。绿。（唯一瑕疵：注释把 `-Fc` 称作
   「plain SQL」，纯文字，不单列 finding。）
5. 「secrets 不进镜像/层/日志」——**部分推翻**：`.dockerignore` 覆盖面不完整（Z13V-1）。
   其中「tag 不插值」那一半我核过：`Makefile:146-150` `export VERSION` + 配方用 `$${VERSION}`，
   `release.yml:179-180` 经 `env:` 传递、`:211-215` 读 `GITHUB_REF_NAME` → 成立。
6. SBOM/NOTICE——archtest 全绿（含 `TestNoticeCoversTheBuildGraph`）、`ci.yml` 组件数下限在。
7. runbook 命令与 flag——`cmd/re0auth/main.go:55-61` 五个 flag 全在。
8. 无 `pull_request_target`——全 workflows grep 0 命中。
9. `.dockerignore:13 *.exe` 在，仓库根三个残留二进制 `git ls-files` 零命中；但 `scratchpad/` 下的 `.exe`
   是否被覆盖取决于 dockerignore 的无斜杠语义，归入 Z13V-1 的注记，不计入本条。

## 未能到达（残余盲区）

1. **无 Docker**：构建上下文的真实内容、层、Trivy/多平台 index 行为仍只能读码（与报告一致）。
2. **只有一个 bash**：本机唯一的 bash 是 Git for Windows 的 5.3.9。我无法判定 `local` 的展开顺序是
   5.3 的行为变化还是历来如此；若仅 5.3+，Z13V-2 的严重度应降为 P2（兼容性），但修法不变。
   `pg_dump`/`psql`/`pg_restore`/`age` 全用桩，真实产物与真实 `--single-transaction` 行为未验。
3. 无本地 Postgres / 无集群：CronJob 在 default-deny 集群上是否真通、PVC/fsGroup 可写性未验。
4. `release.yml` 从未真跑（无网络、无 tag 运行），Z13-2/Z13-6 的结论止于脚本层。
5. Git Bash 的挂载是 `noacl`：**任何 umask/权限位结论在本机都无法成立**（我实测 644/755），
   这同时提醒：第五轮复核里以 mode=644 为据的段落也可能是同一环境假象。

## 判断（不是 finding）

- 同意原报告的三条判断：`scratch` 优于 distroless；转储不加密是文档化取舍；CI 的 image job 不扫可接受。
- 追加一条判断：**Z13-2 的 P3 不要升**。它是「Trivy 门禁在 push 之后」的残余，而 P2-12 之所以是 P2 靠的是
  `deployment.yaml` 引用 `latest` 这个放大项，该放大项今天已不存在，且失败是响亮的。
