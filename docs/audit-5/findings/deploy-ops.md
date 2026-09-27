# 部署与运维（deploy/ops）审计报告

> 审计员：对抗式供应链 / 部署 / 运维审计子代理。
> 本报告只覆盖"跑起来与发出去"的东西：镜像、清单、脚本、CI、发布链、配置面。
> 不覆盖 `internal/config` 的解析逻辑、httpapi 的路由/鉴权逻辑本身（别人的区域），
> 但**因为部署要满足它们**，所以引用了它们的 `file:line`。

## 范围与方法

### 读过（全文）
`Dockerfile`、`.dockerignore`、`.github/workflows/{ci,codeql,perf,release,visual-baselines}.yml`、
`.github/{dependabot.yml,CODEOWNERS}`、`deploy/k8s/**`（base 全部 9 个清单 + backup 3 个）、
`deploy/prometheus/re0auth.rules.yml`、`deploy/grafana/re0auth-dashboard.json`（结构 + 面板表达式）、
`scripts/{backup,restore,backup-keys}.sh`、`Makefile`、`.gitleaks.toml`、`.golangci.yml`、
`config/{re0auth.example.toml,referencesource.example.toml}`、`cmd/re0auth/{main.go,config.go}`（启动/关闭/密钥/迁移相关段）、
`internal/archtest/{k8s_test,workflows_test,notice_test,dockerfile_test,tooling_test}.go`、
`internal/observability/artifacts_test.go`、`web/package.json`、`web/scripts/restore-dist-placeholder.mjs`、
README/CHANGELOG/SECURITY 与 `docs/{operations,runbooks,incident-response,slo,capacity-planning,operations-decision,migration-decision}.md`、
`docs/architecture.md` §4.13/§5/§6/§7、`docs/security-audit-2.md`/`security-audit-3.md` 的目录与"未破/盲区"两节。

### 跑过（真执行）
| 命令 | 结果 |
|---|---|
| `go test ./internal/archtest/` | ok（含 k8s/workflows/dockerfile/notice 断言） |
| `go test ./internal/observability/ -run 'TestAlertRules|TestDashboard|TestEveryRunbookLinkResolves'` | ok |
| `go test -race -count=1 ./internal/observability/` | ok（**本机 `-race` 可用**，4.1s） |
| `go test ./internal/zzprobe/deploy/ -v` | ok（本报告新增的探针，见下） |
| `bash -n scripts/*.sh` | 三个脚本语法均 OK（shellcheck 未安装，未使用） |
| `bash /tmp/zz-probe-sha2.sh`（复刻 `backup.sh`+`restore.sh` 的校验和流程） | **复现 DEP-01** |
| `git check-ref-format 'refs/tags/v1";id;#'` 等 7 个用例 | 含 `"`、`;`、`#`、`$()`、反引号、`|` 的 tag 名**全部合法** |
| `mingw32-make -n dist 'VERSION=v1";id;#'` | **复现 DEP-11**：`name="re0auth_v1;id;#_${os}_${arch}";` |
| `bash -lc 'name="re0auth_v1";echo INJECTED_COMMAND_RAN;#...'` | 注入命令真的被执行，行内其余部分被 `#` 吃掉 |
| `git check-ref-format`/`git tag --list v*`/`git describe` | 仓库只有 `v0.0.0-rc.2`、`v0.0.0-rc.3`；基线 pin 的 `v0.0.0-rc.3` 存在 |
| 全文 grep（`os.TempDir`/`CreateTemp`/`MkdirTemp`/`os/user`/`LoadLocation`/`ParseMultipartForm`/`hostNetwork`/`hostPath`/`pull_request_target`/`uses:`/`permissions:`） | 逐条见正文 |
| 规则/面板里 16 个 `re0auth_*` 指标名 vs 代码 | 全部在 `internal/observability/observability.go` 声明（3 个经前缀拼接，已核对） |

### 新增探针
`internal/zzprobe/deploy/artifacts_test.go`（10 个测试，**当前全部 PASS**）。
其中 3 个是"把当前缺陷写成断言"的形式（`t.Log` 记 GAP），修好之后把断言反过来就是守卫；
每个测试的注释都写了它守卫哪条不变量。函数名：`TestBaseNetworkPolicySelectsTheDeploymentItProtects`、
`TestExposeInternalAcknowledgementIsBackedByAPolicy`、`TestGracefulShutdownWindowsAgree`、
`TestIngressHasNoAnnotationThatWouldWeakenTLSOrTrustHeaders`、`TestBackupWorkloadIsUnselectedAndKeepsItsServiceAccountToken`、
`TestReleasedArchivesCarryThePreReleaseWarning`、`TestImageVersionStampingIsPresentInCIAndAbsentAtRelease`、
`TestRuntimeStageShipsTheBinaryAndTheCABundleOnly`、`TestNoWorkflowRunsUntrustedCodeWithWritePermissions`。

### 跑不了（本机事实）
Windows 11，**无 Docker、无 kubectl/kustomize、无 shellcheck、外网检索不可用**（web_search 返回鉴权失败）。
因此：镜像层内容、镜像 digest 是否存在、K8s API 校验（OpenAPI schema / admission）、
CNI 是否真的实现 NetworkPolicy、GitHub Actions 运行时的实际权限（fork PR 的 `security-events`、cache 作用域）、
Trivy/CodeQL/gitleaks 的真实行为，**一律只能是"读到行"或假说**，逐条标注。

---

## 发现

### DEP-01 `restore.sh` 的校验和守卫校验的不是它要恢复的那个文件；恢复本身又不是原子的
- 严重度: 高
- 类别: 可用性 / 数据丢失
- 不变量/性质: 「一个备份文件在被恢复之前，其完整性已被验证」；「一次失败的恢复不会把目标库留在半状态而堵死下一次恢复」
- 证据:
  - `scripts/backup.sh:32` 与 `deploy/k8s/backup/cronjob.yaml:57` 都写 `sha256sum "$out" > "$out.sha256"`，
    于是校验文件里记的是**生成时的路径**（探针输出：`ab7b82… */tmp/zz-probe-sha/backupdir/re0auth-20250101T000000Z.dump`）。
  - `scripts/restore.sh:23-25` 只是 `sha256sum --check "$dump.sha256"`，`$dump`（命令行给的路径）**从未进入校验**。
  - 真跑（`/tmp/zz-probe-sha2.sh`，两次）：
    (a) 把 `.dump` + `.dump.sha256` 拷到另一台/另一目录（备份主机上的 `/backups` 不存在）：
        `sha256sum: …/backups/re0auth-….dump: No such file or directory` / `FAILED open or read` / `check_exit=1`
        —— 在 `set -euo pipefail` 下 `restore.sh` 于 `psql` 之前退出，**异地恢复被自己的校验步骤挡死**；
    (b) 把一份**截断**的 dump（8192→1024 字节）放在 `restore.sh` 参数里，`.sha256` 仍是好的那份：
        `…/backups/re0auth-….dump: OK` / `check_exit=0`，而 `cmp` 证明"被校验的文件"与"将被 `pg_restore` 的文件"**不同**
        —— 守卫报绿，`pg_restore` 拿到的是截断件。
  - `scripts/restore.sh:35` `pg_restore --exit-on-error` **没有** `--single-transaction`：截断件会让 `pg_restore`
    在中途 exit-on-error，目标库留在半填充状态；而 `restore.sh:28-33` 的空库守卫此时会因为"已经有表"而**拒绝重试**。
    组合起来的失败形态是：恢复→部分失败→再也跑不了第二次（除非人工 DROP SCHEMA）。
- 状态: CONFIRMED（(a)(b) 为真跑复现；`--exit-on-error` 与空库守卫的相互作用是读代码到行）
- 影响: 运维在 DR 当天要么被自己的校验步骤挡住（异地恢复），要么拿着一份"校验通过"的截断转储恢复出一个不完整的库，
  随后被空库守卫锁死。这与 `docs/operations.md:60` 承诺的 RTO ≤ 1 小时直接冲突，而且失败信号是绿的。
- 修法建议: (1) 让校验绑定参数：`cd "$(dirname "$dump")" && sha256sum -c "$(basename "$dump").sha256"` 之前先用
  `grep -F "$(basename "$dump")"` 核对校验文件记的确实是这个 basename，或干脆改成
  `expected=$(awk '{print $1}' "$dump.sha256"); echo "$expected  $dump" | sha256sum -c -`；
  (2) `pg_restore --single-transaction --exit-on-error`（`-1` 同时蕴含 `--exit-on-error`），让失败回滚而不是留半库；
  (3) 在恢复前 `pg_restore --list "$dump" | grep -q audit_events` —— 顺手把"这份 dump 里真的有审计链与假名表"变成检查。
- 复现/守卫: `internal/zzprobe/deploy/artifacts_test.go` 不含此项（它是脚本行为，不适合用 Go 断言），
  复现脚本命令已写在证据里（可在有 bash 的机器上重跑）；建议把上面三条写进 `scripts/restore.sh` 后加一条
  `bash -n` + 一个"把 dump 移到别的目录仍能通过校验"的 shell 冒烟测试。

### DEP-02 `scratch` 阶段的 CA bundle 可能是悬空符号链接，那会让全部出站 TLS 失败
- 严重度: 高（若成立即为阻断上线）
- 类别: 安全 / 可用性
- 不变量/性质: 「运行镜像里 `/etc/ssl/certs/ca-certificates.crt` 是一个可读的证书包」
- 证据: `Dockerfile:60` `COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt`。
  `COPY --from=<stage>` 复制的是**符号链接本身**，不跟随；`FROM scratch` 里若落成 `ca-certificates.crt -> /etc/ssl/cert.pem`
  这样的绝对链接，目标文件不在镜像里，于是：Go 的 `crypto/x509` 依次尝试
  `/etc/ssl/certs/ca-certificates.crt`（读到 dangling symlink 失败）→ `/etc/ssl/certs` 目录（镜像里只有那个链接，无证书）→
  `/etc/ssl/cert.pem` 等，全部落空，**系统根证书为空**，所有上游调用（IdP discovery/JWKS、联邦数据源）
  报 `x509: certificate signed by unknown authority`。
- 状态: HYPOTHESIS（**无法在本机证实**：无 Docker、无外网检索）
- 影响: 若成立，镜像只能建连到明文/自签上游；容器化部署等于完全不能用（本机二进制不受影响）。
- 我为什么还是报它: 这条路径没有任何检查覆盖（`internal/archtest/dockerfile_test.go` 只查 `FROM scratch` 与 `USER 65532`），
  而修复成本是一行，且**确认成本也是一行**。倾向性说明：Alpine 打包里更常见的是 `cert.pem` 指向 `ca-certificates.crt`（反向），
  那样这份 Dockerfile 是对的；但我无法验证，按证据标准只能算假说。
- 需什么才能证实（各一行，任选）:
  `docker build -t re0auth:probe . && docker export $(docker create re0auth:probe) | tar -tv | grep ssl`
  —— 看该条目是 `-`（普通文件，安全）还是 `l`（符号链接，危险）；
  或 `docker run --rm <build-stage> ls -l /etc/ssl/certs/ca-certificates.crt` 看源；或直接跑一次出站 HTTPS。
- 修法建议: 在 build 阶段先把包解引用成普通文件：`RUN cp /etc/ssl/certs/ca-certificates.crt /out/ca-bundle.crt`
  （`cp` 会跟随链接），然后 `COPY --from=build /out/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt`。
  这是零风险的一行加固；同时建议在 `dockerfile_test.go` 里加一条"运行阶段只从 `/out/…` 复制"的形状断言。

### DEP-03 发布到 GHCR 的镜像里，二进制报告 `version=dev`
- 严重度: 中
- 类别: 合规/可维护性
- 不变量/性质: 「一个发布产物能说出自己是什么版本」（README.md:139 的承诺："`re0auth -version` 打印构建版本（由 tag 注入）"）
- 证据: `Dockerfile:48` `ARG VERSION=dev`；`Dockerfile:49-51` `-ldflags "… -X main.version=${VERSION}"`；
  `cmd/re0auth/main.go:68` `var version = "dev"`、`main.go:661` 启动日志 `version=version`。
  `ci.yml:544-545` 传了 `VERSION=ci`，**而 `.github/workflows/release.yml:55-66` 的 `docker/build-push-action`
  没有任何 `build-args`**（它只传 context/platforms/push/tags/labels/provenance/sbom）。`docker/metadata-action` 只产出
  tags/labels，不会填 `ARG VERSION`。
- 状态: CONFIRMED（读代码到行；探针 `TestImageVersionStampingIsPresentInCIAndAbsentAtRelease` 把这条差异写成断言并 PASS）
- 影响: 部署方 `kubectl exec` 不可用（scratch 无 shell），唯一能问"这个 pod 跑的是哪个 release"的地方是启动日志——
  而它会回答 `version=dev`。`deploy/k8s/base/kustomization.yaml:27` 钉的 `v0.0.0-rc.3` 镜像，
  与 tag/CHANGELOG/archtest 的一致性说法对不上；provenance 里 `VERSION` 也是空的。
  Dockerfile:46-47 的注释（"`re0auth -version` 和启动日志在镜像里也能回答'这是哪个构建'"）与事实相反。
- 修法建议: 在 release.yml 的 image job 加 `build-args: VERSION=${{ github.ref_name }}`（经 env 传亦可），
  并把探针里那条 `t.Log` 改成 `t.Error`。

### DEP-04 Trivy 的"失败即阻断"发生在 push 之后，GHCR 上已经躺着那个 tag
- 严重度: 中
- 类别: 供应链
- 不变量/性质: 「被 HIGH/CRITICAL 挡住的东西不会出现在 registry 上」（README.md:150-151 的说法）
- 证据: `release.yml:55-66` 先 `push: true`（多平台 manifest 已推到 `ghcr.io/re0auth/r0semi:v0.0.0-rc.x`），
  之后 `release.yml:86-93` 才用 Trivy `--exit-code 1 --severity HIGH,CRITICAL` 扫同一个 digest。
  `release.yml:99-100` 的 `release` job `needs: [ci, image]`，所以扫描失败只是**不发 GitHub Release**；
  GHCR 上的 tag 与镜像仍然存在且可拉（只是没有 cosign 签名）。
- 状态: CONFIRMED（行级：push 步骤在 scan 步骤之前，且两者之间没有任何 digest 提升/删除逻辑）
- 影响: `deploy/k8s` 的镜像 pin（`kustomization.yaml:27`）认的是 **tag 存在**（`internal/archtest` 只用仓库 tag 比对），
  所以一个"扫描没过、没有签名"的镜像完全可能被钉进基线并被部署。这正是 CHANGELOG 里 rc.2/rc.3 记的那类"tag 一响就等于发布了"。
- 修法建议: 改成"先 build 到本地/临时 tag，扫描通过后才 push"；或用 digest-promotion
  （push 到一个 `staging` tag → 扫描 → `docker buildx imagetools create` 提升）；至少让扫描失败时
  `ghcr.io/...` 的 tag 被显式删除（`gh api -X DELETE`），或把扫描移到 push 之前（buildx `load` + 本地扫）。
- 复现/守卫: 静态断言即可——"release.yml 中 scan 步骤的行号必须小于 push 步骤"，
  或"image job 必须存在一个 `pull: true` 的预扫步骤"。

### DEP-05 基线 ConfigMap 的 `[admin].subjects = []` 让 runbook 依赖的三个控制全部不存在
- 严重度: 中
- 类别: 可用性 / 合规
- 不变量/性质: 「事故处置手册里写的每一步，在基线部署上是可执行的」
- 证据: `deploy/k8s/base/configmap.yaml:36` `subjects = []`；
  `cmd/re0auth/main.go:557-575` 只有 `len(cfg.adminSubjects) > 0` 才挂载 operator 面；
  `main.go:587-590` 审计读取 API 也随 operator 面一起被门控。
  而 `docs/incident-response.md:29-36`（Kill Switch）、`docs/runbooks.md:101,121,192`（审计校验/锚点/抹除）、
  `docs/operations.md:190-193`（手工触发校验）都要求这三样存在。
  `docs/incident-response.md:21-23` 只说"事故前先确认至少有两个人在允许列表里"，**没有任何地方写"怎么把第一个人加进去"**，
  也没有写改完 ConfigMap 需要重启 Pod（见 DEP-17）。
- 状态: CONFIRMED（行级：清单给空、代码给门、文档给依赖，三者对不上）
- 影响: 按 `docs/operations.md:15-23` 装完基线后，`POST /v1/admin/kill_switch`（凭据泄露时的第一杠杆）、
  `GET /v1/admin/audit/verify`（S5 硬目标的读侧）都不存在；事故里现场才发现，且没有写好的补救步骤。
- 修法建议: 在 `docs/operations.md` 的部署步骤里加一步"把运维账号的 `usr_…` 填进 `[admin].subjects`（或
  `RE0AUTH_ADMIN_SUBJECTS`）并 `kubectl rollout restart`"，并在基线 ConfigMap 里留一条注释指向它；
  最好在 `docs/operations.md` 的部署段落里加一条"部署验收：`/v1/admin/audit/head` 返回 200（或 401）而不是 404"。

### DEP-06 备份默认组合在数学上必然写满卷，而"备份停了"没有任何告警
- 严重度: 中
- 类别: 可用性 / 数据丢失
- 不变量/性质: 「仓库自带的 RPO ≤ 15 分钟的备份作业能在默认规格下持续运行，且停了会有人知道」
- 证据: `deploy/k8s/backup/cronjob.yaml:11` `schedule: "*/15 * * * *"`、`:47-48` `BACKUP_RETAIN_DAYS="7"`、
  `deploy/k8s/backup/pvc.yaml:11` `storage: 20Gi`。
  7 天 × 96 次/天 = **672 份转储**，20 GiB ÷ 672 ≈ **30 MiB/份**（压缩后）。
  超过这个体量，卷会先被写满，`find … -mtime +7 -delete`（`cronjob.yaml:61-62`）永远等不到可以删的东西。
  `cronjob.yaml:58-60` 的注释自己说"失败的备份没人看就等于没有"，但：
  - 备份作业不导出任何指标（`internal/observability` 只有 `re0auth_*` 业务/HTTP/池指标）；
  - `deploy/prometheus/re0auth.rules.yml` 里没有任何 `kube_cronjob_*` / "最后一次成功备份距今多久" 的规则
    （整个文件只读 `re0auth_*`、`go_*`、`process_*`）；
  - `docs/operations.md:65-85` 也没有给"备份是否还在跑"任何检查步骤。
- 状态: CONFIRMED（算术 + 行级；"卷写满后 pg_dump 失败"是读 `cronjob.yaml:55-56` 的直接推论）
- 影响: 生产里最典型的结果是"RPO 在某个时刻悄悄失效"：卷满 → 每 15 分钟一次失败 Job →
  `failedJobsHistoryLimit: 3` 把证据也冲掉 → 直到真的需要恢复时才发现最后一份备份是几周前的。
  这正是审计链那种"没人看的控制等于没有控制"的同一种失败形态。
- 修法建议: (1) 保留策略改成按**容量/份数**而不是按天（或者 `BACKUP_RETAIN_DAYS` 默认调小 + PVC 按实际体积算并在
  `docs/operations.md` 写清"默认 20Gi 只够 ≤30 MiB/份"）；(2) 加一条告警：
  `time() - kube_cronjob_status_last_successful_time{namespace="re0auth",cronjob="re0auth-backup"} > 45*60`，
  以及 `kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes > 0.85`；
  (3) 更彻底：让备份作业在成功后把"最后一次成功时间"写成一个 Pushgateway/textfile 指标。

### DEP-07 备份脚本用默认 umask 写**明文**转储，`restore.sh` 还会把明文解密到备份目录并留着
- 严重度: 中
- 类别: 安全 / 合规/隐私
- 不变量/性质: 「数据库转储（含全部 vault 密文、审计史、假名键）不得被本机其他用户读取」；
  「开启 age 加密的备份目录里不得同时躺着明文」
- 证据:
  - `scripts/backup.sh:10-20` 没有 `umask`：真跑复现（`/tmp/zz-probe-sha.sh`）在默认 `umask 0022` 下产出
    `-rw-r--r-- 1 … re0auth-…dump`（**世界可读**）；同一脚本在 `:22-30` 才谈加密。
  - 对比 `scripts/backup-keys.sh:72` 明确 `umask 077`，并在注释里说"明文不应在任何时刻以更宽的权限存在"——
    两把脚本对**同一类秘密**的权限纪律不一致，而密钥备份是四把 key、数据库转储是整个库。
  - `scripts/restore.sh:16-21`：`.age` 输入被解密到 `plain="${dump%.age}"`，也就是**同一个备份目录**，
    之后 `:35` 才用它恢复；脚本结束不清理，也不改权限（继承默认 umask）。
    `docs/operations.md:81-82` 与 ADR-0006 明确说"转储默认不加密、加密是部署决策"，
    但**没有一处说"恢复会把明文·留在备份目录"**——这等于在 DR 当天把 age 加密的收益当场抹掉。
  - `scripts/backup.sh:22-26`：`command -v age` 的检查在 `pg_dump`（`:20`）**之后**。若 `BACKUP_AGE_RECIPIENT`
    已设置但 age 不在 PATH，脚本以 1 退出，而那份**未加密**的转储已经落在备份目录里，且不会被后续成功运行清掉。
- 状态: CONFIRMED（权限为真跑输出；其余为行级）
- 影响: 共享运维主机/共享备份卷上的任何本地用户或备份代理都能读到全库转储；"备份桶里不会有明文"的说法在实际操作路径上不成立。
- 修法建议: `backup.sh` 开头 `umask 077`（并让 `$dir` 也 0700）；`restore.sh` 解密到
  `mktemp`（`umask 077`）并在退出时 `trap` 删除，或直接 `age --decrypt … | pg_restore`（管道，不落盘）；
  把 `command -v age` 前置到 `pg_dump` 之前。

### DEP-08 连接串（含密码）经命令行参数传给 `pg_dump`/`psql`，本机任何用户可读
- 严重度: 中
- 类别: 安全 / 凭据泄露
- 不变量/性质: 「数据库口令不出现在进程表里」
- 证据: `scripts/backup.sh:20` `pg_dump … --dbname "$DATABASE_URL" …`；`scripts/restore.sh:28` `psql --dbname "$DATABASE_URL"`；
  `scripts/restore.sh:35` `pg_restore --dbname "$DATABASE_URL"`。
  同形问题在 `deploy/k8s/backup/cronjob.yaml:55-56`（`--dbname="$DATABASE_URL"`）——容器里 `ps`（postgres 镜像有 shell）
  能看到展开后的 DSN，任何能 `kubectl exec` 进这个 Pod 的人也能看到。
- 状态: CONFIRMED（行级；`/proc/<pid>/cmdline` 的可见性是一般 POSIX 事实，本机未复现 pg_dump）
- 影响: 备份主机通常是共享的运维跳板机；一次转储跑几分钟，`ps -ef` 就能拿到 DSN（含口令），
  而 DSN 同时是**数据库的管理凭据**（`operations.md` 的所有步骤都用它）。
- 修法建议: 用 `PGPASSWORD`/`PGPASSFILE`（`~/.pgpass` 0600）或 `PGSERVICE`，把 DSN 里的口令去掉；
  在 k8s 里把 Secret 拆成 `PGHOST/PGUSER/PGPASSWORD/PGDATABASE` 之类的分量 env（`postgres` 客户端原生读取），
  这样 `ps` 只看到不含口令的散件。

### DEP-09 事故手册把允许列表键写成 `[admin].allow`，真实键是 `[admin].subjects`，而未知键会让服务拒绝启动
- 严重度: 中
- 类别: 合规/可维护性 / 可用性
- 不变量/性质: 「文档里的配置键名就是程序接受的键名」
- 证据:
  - 错的地方：`docs/runbooks.md:9`、`docs/incident-response.md:21` 都写 `[admin].allow`。
  - 对的地方：`config/re0auth.example.toml:196` `subjects = []`、`docs/api-design.md:310`、`docs/architecture.md:583`
    都写 `[admin].subjects` / `RE0AUTH_ADMIN_SUBJECTS`。代码侧 `cmd/re0auth/config.go` 的 schema 里没有 `allow`。
  - 放大后果：`cmd/re0auth/config.go:43-49` 对未识别键**直接报错**：
    `unknown keys (a typo here is a setting that never takes effect)`；`cmd/re0auth/secret_env_test.go:109-121`
    的注释也确认"unknown keys are now refused"。
- 状态: CONFIRMED（行级）
- 影响: 事故中（正是需要把自己加进管理员名单、好用 Kill Switch 的时候）照抄 runbook 会得到一个**起不来的服务**。
  有错误信息可读，但代价是几分钟的停机窗口——对"先拉闸再调查"的流程尤其糟。
- 修法建议: 改两处文档；并加一条守卫：让 `internal/archtest`（或 `observability` 那套 artifacts 测试的做法）
  扫描 `docs/*.md` 里形如 `[section].key` 的配置引用，逐条比对 `config/re0auth.example.toml` 的键集。
  这条守卫同样能抓 DEP-10。

### DEP-10 `runbooks.md`/`slo.md` 说内部监听器"默认 :9090"，实际默认是**不监听**
- 严重度: 中
- 类别: 可维护性 / 可用性
- 不变量/性质: 「文档里的默认值等于代码里的默认值」
- 证据: `docs/runbooks.md:11` "内部监听器 `server.internal_addr`（默认 `:9090`）的 `/metrics`"；
  `docs/slo.md:79` "内部监听器（`server.internal_addr`，默认 `:9090`）"。
  实际：`config/re0auth.example.toml:81` `internal_addr = ""`（注释明写"Empty — the default — serves neither"）、
  `cmd/re0auth/main.go:647` `if cfg.InternalAddr != ""` 才起第二个监听器、
  `cmd/re0auth/config.go` 全文没有一个 `9090` 默认值（只出现在注释里）。
- 状态: CONFIRMED（行级）
- 影响: 运维按 runbook 上 `:9090` 抓指标会发现**什么都没有在听**（不是 404，是连接被拒），
  然后很可能去怀疑网络/NetworkPolicy/Service，而不是"这个部署根本没开内部监听器"。
  slo.md 的 S1–S7 全部建立在"能抓到这些指标"之上。
- 修法建议: 两处改成"默认关闭；k8s 基线显式设为 `0.0.0.0:9090`"；并加 DEP-09 建议的键/默认值守卫。

### DEP-11 Makefile 把 `$(VERSION)` 直接插进 Shell 配方，而合法的 git tag 可以含 Shell 元字符
- 严重度: 中
- 类别: 安全（供应链 / 发布链）
- 不变量/性质: 「tag 名是数据，不是代码」（`release.yml:141-144` 自己声明的性质）
- 证据:
  - tag 合法性（真跑）：`git check-ref-format 'refs/tags/v1";id;#'` → 退出码 0；
    `'refs/tags/v1";curl${IFS}-s${IFS}x|sh;#'` → 0；`'refs/tags/v1$(id)'` → 0；`'refs/tags/v1`id`'` → 0。
    （只有空格被拒；`${IFS}` 可以替代空格。）
  - 插值点（真跑）：`mingw32-make -n dist 'VERSION=v1";id;#'` 输出
    `name="re0auth_v1;id;#_${os}_${arch}";`，另外 `-ldflags "-s -w -X main.version=v1;id;#"`（`Makefile:165`）同样破出引号。
  - 该行为可执行（真跑）：`bash -lc $'name="re0auth_v1";echo INJECTED_COMMAND_RAN;#_${os}_${arch}"; echo done'`
    打印了 `INJECTED_COMMAND_RAN`，行内其余部分被 `#` 注释掉（`\` 续行也被吃掉）。
  - 到达路径：`release.yml:145-148` `run: make release VERSION="$VERSION"`，`VERSION=${{ github.ref_name }}`。
  - 被违反的承诺：`release.yml:141-144` 的注释说"The tag travels through the environment rather than being
    interpolated into the script: git allows shell metacharacters in a ref name"——这句对 `publish` 步骤成立
    （那里用 `GITHUB_REF_NAME`，是对的），但**make 会把它重新插回配方文本**，所以整条链并没有被保护。
  - 同一文件 `Makefile:212` 的 `docker:` 目标更糟（`-t $(IMAGE):$(VERSION)` 连引号都没有）。
- 状态: CONFIRMED（三条真跑证据）
- **严重度校准（重要，必须和结论一起读）**: 这条**并没有扩大攻击面**——能推 tag 的人本来就能把 tag 指向任意 commit，
  而 `release.yml` 会 checkout 那棵树并执行它（`make web` 跑 `pnpm` 生命周期脚本、`make release` 跑 Makefile、
  `image` job 跑 Dockerfile 的 `RUN`），`image` job 还持有 `packages: write` + `id-token: write`。
  所以真正的信任边界是"谁能推 `v*` tag"，而不是这条注入。它的价值在于：(1) 工作流里那条"已经防住了"的注释会误导评审；
  (2) 一个被误建的 tag（例如带反引号的版本名）会在发布作业里执行陌生命令；(3) 修它几乎免费。
- 修法建议: 在 Makefile 顶部加 `VERSION ?= …` 之后统一用引号包裹：
  `name="re0auth_$(VERSION)_$${os}_$${arch}"` 改成把版本经环境变量传入配方（`VERSION="$$VERSION"` 由 make 的
  `export VERSION` 提供，配方里写 `$$VERSION`），即"值不进文本"；或对 `VERSION` 做白名单校验
  （`release:` 目标里 `case "$(VERSION)" in *[!A-Za-z0-9._-]*) echo refuse; exit 1;; esac`）。
  同时把 `docker:` 目标补上引号。

### DEP-12 备份 CronJob 的 Pod 不被任何 NetworkPolicy 选中：默认拒绝的集群上每次转储都静默失败
- 严重度: 中
- 类别: 可用性 / 数据丢失
- 不变量/性质: 「自带的定时备份作业在自带的安全策略下能真的连上数据库」
- 证据:
  - `deploy/k8s/backup/cronjob.yaml` 的 `jobTemplate.spec.template` **没有 `metadata.labels`**（只有 `spec:`），
    因此 `deploy/k8s/base/networkpolicy.yaml:7-8` 的 `podSelector: app.kubernetes.io/name: re0auth` 不选中它。
  - 反过来看：基线的 egress 规则（`:24-43`）**只对"被自己选中的 Pod"生效**，所以仓库没有任何一条策略为备份 Pod
    放行到 Postgres 的流量。探针 `TestBackupWorkloadIsUnselectedAndKeepsItsServiceAccountToken` 断言并记录了这一点。
  - 后果链条：集群若启用默认拒绝 egress（基线的 NetworkPolicy 正是那种"默认拒绝"思路的产物），
    `pg_dump` 连不上 `kubernetes.io/metadata.name: postgres` 的 5432，每 15 分钟失败一次；
    而 DEP-06 已经说明"备份失败"没有任何告警。
  - 另外 `networkpolicy.yaml:33-34` 把数据库位置硬编码成 `namespaceSelector: postgres`：
    托管数据库（RDS 等）或别的命名空间都不在这条规则里——仓库没有把这三个命名空间前提写进 `docs/`（全文只有
    `operations.md:10,126` 两处提到 NetworkPolicy，都没提命名空间前提）。
- 状态: CONFIRMED（探针断言 + 行级）；"默认拒绝集群上失败"是该前提下的推论（HYPOTHESIS 部分：CNI 行为未实测）
- 影响: 一个"装上了但从来没成功过"的备份作业，且没有任何信号。
- 修法建议: 给备份 Pod 打上自己的标签（例如 `app.kubernetes.io/name: re0auth-backup`）并在 `deploy/k8s/backup/`
  里加一条只放行 DNS + Postgres 的目的地策略；把 `ingress-nginx`/`monitoring`/`postgres` 三个命名空间前提
  写进 `docs/operations.md` 的部署段落（"若你的数据库在别的命名空间/是托管服务，这条 egress 必须改"）。

### DEP-13 `expose_internal = true` 的安全性完全押在"这个集群真的实现 NetworkPolicy"上，而这一点没有被检查或说明
- 严重度: 中
- 类别: 安全
- 不变量/性质: 「`/metrics` 与 `/debug/pprof/` 只对受信来源可达」——这是 `config.go:515-529` 让
  `0.0.0.0:9090` 通过的唯一理由
- 证据: `deploy/k8s/base/configmap.yaml:11-20`（`internal_addr = "0.0.0.0:9090"` + `expose_internal = true`，
  注释明写"What makes it safe is the NetworkPolicy beside this file"）；`deploy/k8s/base/networkpolicy.yaml` 就是那条策略；
  `cmd/re0auth/config.go:522-528` 的报错文案也把 NetworkPolicy 列为承认的前提。
  但：仓库没有任何地方说明"必须使用实现 NetworkPolicy 的 CNI"，也没有任何探针/文档步骤去验证它。
  `docs/` 全文提到 NetworkPolicy 只有两处（`operations.md:10,126`）。
- 状态: HYPOTHESIS（"某些 CNI 不实现 NetworkPolicy"是集群侧事实，本机无集群无法实测；"仓库没有前提说明/检查"是行级 CONFIRMED）
- 影响: 在不实现策略的 CNI 上（例如 flannel 默认形态），`kubectl apply` 一切成功、网络策略被无声忽略，
  于是集群内**任何** Pod 都能抓 `/debug/pprof/heap`、`/debug/pprof/goroutine?debug=2`、`/metrics`——
  堆里有会话与在途凭据材料，goroutine dump 里有请求路径。同时 8080 也变成任何 10.x Pod 可达，
  配合 `trusted_proxies = ["10.0.0.0/8"]`（`configmap.yaml:25`）就能**伪造客户端地址**（限流桶、审计里的客户端地址）。
- 需什么才能证实: 一个真实集群 + `kubectl run` 一个 `monitoring` 命名空间之外的 Pod 去抓 9090；
  或读部署方 CNI 文档。
- 修法建议: 在 `docs/operations.md` 的部署前置里加"集群必须实现 NetworkPolicy（基线的安全论证依赖它）"，
  并给出一条可执行的验收命令（从另一个命名空间的 Pod `curl -m2 re0auth-internal.re0auth:9090/metrics` 必须失败）；
  更稳的做法是把 `internal_addr` 留在 loopback、让 Prometheus 用 sidecar/`kubectl port-forward` 抓取。

### DEP-14 没有 `preStop`/端点摘除等待：每次滚动更新都有一个 connection-refused 窗口
- 严重度: 中
- 类别: 可用性
- 不变量/性质: 「滚动更新不产生面向用户的 5xx」（`deployment.yaml:21-23` 的注释宣称的意图）
- 证据: `cmd/re0auth/main.go:745-759`：收到 SIGTERM 后立刻 `ep.server.Shutdown(drainCtx)`，
  而 `Shutdown` 的语义是**先关监听器**、再等在途请求。
  `deploy/k8s/base/deployment.yaml:16-94` 里**没有 `lifecycle.preStop`**，
  容器级 `securityContext` 也只有 allowPrivilegeEscalation/readOnlyRootFilesystem/capabilities。
  Kubernetes 删除 Pod 与从 Service/EndpointSlice 摘除是**并发**的：在 kube-proxy/ingress 完成转发规则更新之前，
  新连接仍可能被送到已经没有监听器的 Pod → `connection refused`（nginx 会回 502/503）。
  同时 `/readyz`（`internal/httpapi/health.go:37-53`）在关闭开始时也不会先转 503，无从提供"先摘流量再关"的窗口。
- 状态: HYPOTHESIS（需要集群才能测出真实窗口长度；代码与清单的行级事实是确定的）
- 影响: `maxUnavailable: 0` 保证了容量，但没保证**连接**：小流量下表现为偶发 5xx，大流量下更明显。
  与 `docs/slo.md` 的 S1（≥99.9%）直接相关。
- 修法建议: 在容器上加
  `lifecycle: {preStop: {exec: {command: ["/bin/sleep", "5"]}}}`——注意 scratch **没有 `/bin/sleep`**，
  所以要么改成 `exec: {command: ["/re0auth", "-drain-only"]}` 之类的新入口，要么用
  `preStop: {httpGet: {path: /readyz, ...}}`（不阻塞）不够；`sleep` 方案在 scratch 上不可用是本条修复时必须一起解决的约束。
  更轻的做法：让 `/readyz` 在收到 SIGTERM 后立刻返回 503（改代码），再由 `preStop` 触发一次请求。

### DEP-15 迁移慢于 120s 会撞上 startupProbe 预算：容器被杀、迁移重来、发布卡住
- 严重度: 低
- 类别: 可用性
- 不变量/性质: 「慢迁移不会把一次升级变成无限重试」
- 证据: `deploy/k8s/base/deployment.yaml:61-72`（注释明确承认"a slow migration is a legitimate reason for
  /healthz to be unreachable"，预算 24×5s = **120s**）；`cmd/re0auth/main.go:340,815` 启动即 `postgres.Open`→`Migrate`，
  且**监听器在迁移之后才 bind**（`main.go:637`）；`docs/migration-decision.md:12-16` 说明迁移在 advisory lock 下、
  第二个实例等待锁而不是并行迁移——也就是说**等待时间可能叠加在迁移时间上**。
  migration 0018（`CHANGELOG.md:30-32`）与索引类迁移在 `audit_events` 上建索引，正是"小库秒级、大库分钟级"的形态。
- 状态: HYPOTHESIS（迁移时长无法在本机（无 DB、无集群）测量；预算数字与调用顺序是行级 CONFIRMED）
- 影响: 迁移 >120s → kubelet 杀容器（迁移事务回滚）→ 重试 → 同样超时 → `maxUnavailable: 0` 让旧副本继续服务，
  但**这个发布永远完不成**（Rollout 卡在 CrashLoopBackOff/ProgressDeadlineExceeded）。
  好消息是服务不停；坏消息是运维看到的是"升级没生效"而不是"迁移太慢"。
- 修法建议: 把长迁移从启动路径里拿出来（独立的 pre-deploy Job + `-migrate-only` 之类的入口），
  或至少把 startupProbe 预算改成与迁移 SLA 对齐并可调（例如 `failureThreshold: 240`，并在 `docs/operations.md`
  写"预计超过 X 分钟的迁移请先用 Job 跑"）。

### DEP-16 文档化的 KEK 轮换在自带 k8s 路径上没有可执行形式，且步骤顺序容易先毁掉旧 key
- 严重度: 低
- 类别: 可维护性 / 可用性
- 不变量/性质: 「文档里的每一步，在自带部署上有对应操作」
- 证据:
  - 步骤本身（`README.md:45-57`、`config/re0auth.example.toml:164-178`、`docs/operations.md:111-112`）与代码一致：
    `vault.retired` + `-rotate-keys`（`cmd/re0auth/main.go:56-57,402-410`，`main.go:1044-1056` 只用于 unwrap）。
  - 但 `deploy/k8s/base/configmap.yaml` **没有** `[[vault.retired]]` 的位置，
    `deploy/k8s/base/deployment.yaml:43-58` 的 Secret 只有 `kek`（没有 `RE0AUTH_KEK_OLD`），
    `deploy/k8s/` 下**没有任何 Job**；文档写"启动时 `-rotate-keys`"，但没写"在 k8s 上怎么启动一个带同样
    ConfigMap+Secret 的一次性 Pod"。scratch 镜像没有 shell，`kubectl exec` 也做不了。
  - 顺序陷阱：第 1 步是"生成新 KEK 放进 `RE0AUTH_KEK`"，第 2 步才"声明旧 KEK"。旧 key 只存在于
    `RE0AUTH_KEK` 这一个地方，**没有任何一句写"先把旧值拷到 `RE0AUTH_KEK_OLD` 再覆盖"**。
    一旦照字面执行，旧 key 材料就没了；此后 `vault.retired` 指向的是一份错材料，
    所有旧记录 `decrypt_error`（`docs/runbooks.md:160-165`）——即"全部上游凭据需要重新绑定"。
    （代码在这一点上是 fail-closed：`main.go:1049-1052` 会让轮换直接报错而不是静默成功，因此严重度不更高。）
- 状态: CONFIRMED（行级：缺清单/缺配置位/缺 Secret 键是事实；"照字面执行会丢旧 key"是对文档文本的直读）
- 修法建议: 在 `deploy/k8s/` 加一个参数化的 `rotate-keys-job.yaml`（同一 ConfigMap/Secret，`args: ["-rotate-keys", "-config=…"]`，
  `restartPolicy: Never`），在 `docs/operations.md` 里改成可复制的 `kubectl create job --from=…` 形式；
  并把第 1 步改成"**先把当前 `RE0AUTH_KEK` 的值另存为 `RE0AUTH_KEK_OLD`**，再生成新 key 覆盖 `RE0AUTH_KEK`"。

### DEP-17 改 ConfigMap/Secret 不会影响正在运行的 Pod，而文档没说需要 `rollout restart`
- 严重度: 低
- 类别: 可用性 / 可维护性
- 不变量/性质: 「按文档改了配置，行为就会变」
- 证据: `deploy/k8s/base/deployment.yaml:39` `args: ["-config=/etc/re0auth/re0auth.toml"]`，
  配置以 `volumeMounts`（`:59-60`）注入；`cmd/re0auth/main.go:289-302`、`config.go` 只在启动时读一次配置；
  Deployment 没有 `annotations: checksum/config` 之类触发滚动的机制，也没有热加载（`architecture.md:728` 明确"不引入 HMR"）。
  `secretKeyRef` 注入的 env（`:44-58`）更是**永不**对运行中的 Pod 更新。
  `docs/operations.md` 的部署/升级/轮换三段都没有"改完要重启"这一步。
- 状态: CONFIRMED（行级）
- 影响: 运维改完 ConfigMap（例如按 DEP-05 加管理员、按 DEP-16 加 retired KEK）看到 `kubectl apply` 成功、
  ConfigMap 内容也变了，但行为不变；在事故里这会白白烧掉几分钟，并且很容易被误判成"配置没生效/代码有 bug"。
- 修法建议: 在 Deployment 的 pod template 上加一条由配置内容派生的注解（kustomize 做不到，需 Helm/`kustomize` 的
  `configMapGenerator` + `annotations`），或在文档的每一步"改配置"后面显式补 `kubectl -n re0auth rollout restart deploy/re0auth`。

### DEP-18 基线与示例配置把 `max_in_flight` 写死成 512，与 `capacity-planning.md` §4 自己的推导相反
- 严重度: 低
- 类别: 性能 / 可用性
- 不变量/性质: 「入站准入上限应贴合连接池容量，而不是远高于它」
- 证据: `deploy/k8s/base/configmap.yaml:24` `max_in_flight = 512`；`config/re0auth.example.toml:46` 同样是 512，
  而其**紧邻的注释**（`:39-43`）说"Leave this out and a durable deployment gets max(64, max_conns × 8)"（池 16 → 128）。
  `docs/capacity-planning.md:113-121` 把这条推导讲得很清楚，并点名"这就是缺省值按池推导而不是写死 512 的原因"。
  基线 `kek…`/`max_conns` 用默认 16（`configmap.yaml` 未设），缩放系数 2 副本 → 池总量 32，而准入上限是 1024。
- 状态: CONFIRMED（行级；512 被显式设置，故推导值不会生效）
- 影响: 洪水下最多 1024 个请求进入处理，其中绝大多数在 16 条/进程的连接池上排队，最长等到 statement/read timeout——
  正是 `capacity-planning.md` 说的"把快速 503 换成在 pgx 上慢慢等"。前端限流（`rate_limit=50`/地址/平面/副本）
  是第一道闸，但在多副本 + NAT 共用出口地址的形态下它并不足以兜住。
- 修法建议: 从基线 ConfigMap 与示例配置里删掉这一行（让推导生效），或在注释里说明为什么这个部署需要 512。

### DEP-19 镜像引用纪律不一致：Deployment 自己写 `:latest` + `IfNotPresent`，CI 用浮动 `postgres:16`
- 严重度: 低
- 类别: 供应链
- 不变量/性质: 「部署引用的镜像是一个不可变、可追溯的东西」
- 证据:
  - `deploy/k8s/base/deployment.yaml:37` `image: ghcr.io/re0auth/r0semi:latest` +
    `:38 imagePullPolicy: IfNotPresent`；pin 只存在于 `deploy/k8s/base/kustomization.yaml:25-27`。
    任何不经 kustomize 的路径（`kubectl apply -f deploy/k8s/base/deployment.yaml`、把它复制进别处的 chart、
    评审时只看 Deployment）拿到的都是**浮动 tag**，而 `IfNotPresent` 会让已经缓存过 `latest` 的节点**永不更新**。
    `internal/archtest/k8s_test.go:118-166` 只检查 kustomization 的 tag，不检查 Deployment 里的引用。
  - `.github/workflows/ci.yml:34` 与 `perf.yml:45` 的服务容器是 `image: postgres:16`（浮动 tag），
    而 `deploy/k8s/backup/cronjob.yaml:39` 是 `postgres:16@sha256:…`（digest）。
    也就是说"被测试过的 Postgres"与"被备份的 Postgres"靠 tag 对齐，而 tag 会动。
  - `internal/archtest/k8s_test.go:335-338` 只断言备份镜像含 `@sha256:`，不管 CI 的服务镜像。
- 状态: CONFIRMED（行级）
- 影响: 一次"看起来什么都没改"的重部署可能拉到不同的镜像；CI 里的 Postgres 也可能在无提交的情况下换掉小版本。
- 修法建议: Deployment 里直接写 digest（kustomize 的 `images:` 覆盖仍可保留作为升级入口），
  或把 `imagePullPolicy` 改成 `Always`（浪费但安全）；CI 的两个服务容器也钉 digest
  （`dependabot` 的 `docker` 生态会替 Dockerfile 更新 digest，但**不会**更新 workflow 里的 `image:` 字符串，见 DEP-23）。

### DEP-20 备份 Pod 保留 ServiceAccount token；基线的 SA 已经关掉，`archtest` 不检查这一项
- 严重度: 低
- 类别: 安全（纵深防御）
- 不变量/性质: 「不需要 Kubernetes API 的容器不持有 API 凭据」
- 证据: `deploy/k8s/base/serviceaccount.yaml:7` `automountServiceAccountToken: false`（并把理由写在注释里）；
  `deploy/k8s/backup/cronjob.yaml:26-33` 的 Pod securityContext 里**没有** `automountServiceAccountToken`，
  也没写 `serviceAccountName`，于是用命名空间的 `default` SA，kubelet 会挂一个 projected token
  （`default` SA 自 1.24 起不再有长期 Secret，但 bound token 仍然会被投影挂载）。
  `internal/archtest/k8s_test.go:327-355` 检查了备份 Pod 的 runAsNonRoot/securityContext，**没有**检查这一项。
- 状态: CONFIRMED（行级；"token 会被挂载"是 K8s 默认行为，本机无集群未实测）
- 影响: 一个持有数据库 DSN 的容器里多了一把（默认只有 discovery/selfsubjectaccessreview 权限的）API 凭据。
  收益有限但为零风险可除，且与基线自身的纪律不一致——不一致本身就是"下一个改动会不会照抄"的问题。
- 修法建议: 在 `cronjob.yaml` 的 pod spec 加 `automountServiceAccountToken: false`，
  并在 `k8s_test.go` 的备份断言里补一条。

### DEP-21 镜像不携带"未达生产可用"警告（归档携带）
- 严重度: 低
- 类别: 合规
- 不变量/性质: `README.md:118` 的承诺「'未达生产可用'那条警告要跟着产物走」
- 证据: `Makefile:167` `cp config/re0auth.example.toml LICENSE NOTICE README.md SECURITY.md "dist/$$name/"` ——
  归档里有 `README.md`（`:9-10` 的 `[!WARNING]`）与 `SECURITY.md`（`:5` "**Re0auth is not production-ready.**"），
  探针 `TestReleasedArchivesCarryThePreReleaseWarning` 断言并确认了这一点（含 `dist` 配方不再复制它们时会失败）。
  但运行镜像（`Dockerfile:59-76`）只有二进制与 CA 包，**没有**任何警告文本，也没有 OCI 标签承载它；
  `release.yml:49-53` 的 annotations/labels 全部来自 `docker/metadata-action` 的标准字段。
  而镜像恰恰是 `deploy/k8s` 真正部署的东西。
- 状态: CONFIRMED（行级 + 探针）
- 影响: 从 GHCR 拉镜像的人（也就是部署的人）看不到任何"未达生产可用"的信号；警告只覆盖到"下载归档"的人。
- 修法建议: 在 `release.yml` 的 `labels` 里加一条自述标签（如
  `org.opencontainers.image.description=Pre-release: not production-ready`）或 `io.re0auth.pre-release=true`，
  必要时把 `SECURITY.md` 复制进镜像根（一行 `COPY`，注意别把 `config/` 一起带进去）。

### DEP-22 工具链 pin 没有更新通道，也没有过期检查
- 严重度: 低
- 类别: 可维护性 / 供应链
- 不变量/性质: 「被 pin 的工具要么有人负责升级，要么有检查提醒它已经落后」
- 证据: `.github/dependabot.yml` 覆盖 `gomod` / `npm`(/web) / `github-actions` / `docker`(/Dockerfile)。
  但被 pin 的工具是**工作流里的 `go install`**与**扫描器镜像 digest**：
  `ci.yml:349` `govulncheck@v1.8.0`、`ci.yml:494` `golangci-lint@v2.14.0`、`ci.yml:523` `gitleaks/v8@v8.30.1`、
  `ci.yml:361` 与 `release.yml:133` `cyclonedx-gomod@v1.12.0`、`release.yml:91` `aquasec/trivy@sha256:ab70a0…`，
  以及 `Makefile:110,152,191` 里重复的同一版本号（注释自称"pinned here and in the release workflow"，但没有测试比对它们）。
  dependabot 的 docker 生态读的是 `Dockerfile`，看不到 workflow 里的 `image:` 或 `go install`。
- 状态: CONFIRMED（行级）
- 影响: 一个停在两年前的漏洞库前端（govulncheck 的**数据库**是新的，工具是旧的）、或一个过期很久的 golangci-lint，
  都是"绿色的假信号"；而且 `Makefile` 与 workflow 里的版本号靠注释维持一致，没有守卫。
- 修法建议: 加一条测试：把 `Makefile` 里的 pin 与 workflow 里的 pin 逐一比对（现在就可以写，`workflows_test.go` 已有
  读 Makefile 配方的先例）；给"工具 pin 表"加一条注释说明复查节奏，或用 dependabot 的 `docker` 生态 +
  定期人工复查（前者不覆盖 `go install`）。

### DEP-23 CodeQL 的 `javascript-typescript` 不解析 `.svelte`，前端的绝大部分代码不在分析面内
- 严重度: 低
- 类别: 安全（门禁覆盖）
- 不变量/性质: 「声称覆盖前端安全分析的作业，实际分析了前端代码」
- 证据: `.github/workflows/codeql.yml:26` `language: [go, javascript-typescript]`（注释说"CodeQL's security queries
  cover data flow across the request path"，这是对 Go 侧成立的说法）。
  但 `web/src` 里 `.svelte` 15 个、`.ts` 6 个、`.css`/`.html`/`.svg` 各 1 个（实测统计）：
  CodeQL 没有 Svelte 前端解析器，组件里的脚本块（首页/同意页/设备码页的主要逻辑）不在提取范围内。
- 状态: CONFIRMED（文件计数与 workflow 语言列表为实测/行级；"CodeQL 不支持 .svelte"来自其公开文档，本机无网无法引用链接）
- 影响: 一个只覆盖 6 个 `.ts` 文件的前端分析作业，会被读成"前端也被扫了"。
- 修法建议: 在 `codeql.yml` 或 `docs/dependencies.md` 里写清"javascript-typescript 覆盖 `web/src/**/*.ts`，
  `.svelte` 不在 CodeQL 的提取范围内；前端的静态门禁是 `pnpm run check`（svelte-check）+ `check:bundle`"，
  避免把覆盖缺口误读成覆盖。

### DEP-24 `release` 作业继承了它不需要的 `packages: write`，且整个工作流没有 concurrency 组
- 严重度: 低
- 类别: 安全（最小权限）/ 供应链
- 不变量/性质: 「每个作业只持有它需要的最小权限」
- 证据: `release.yml:13-16` 在工作流级声明 `contents: write, packages: write, id-token: write`；
  `image` job（`:31-34`）自己收窄成 `contents: read, packages: write, id-token: write`；
  `release` job（`:99-102`）**没有** permissions 块，于是继承三者。而 `release` job 里跑的是
  `make release`（即 `pnpm install` + `go build` + 打包）与 `gh release create` + `cosign sign-blob`：
  它需要 `contents: write` 与 `id-token: write`，**不需要** `packages: write`。
  另外 `perf.yml:26-30` 有 `concurrency: group: perf`，而 release.yml 没有——两个 tag 同时推送时
  `gh release create` / GHCR 的 `latest` tag 会互相竞争。
- 状态: CONFIRMED（行级）
- 影响: 发布作业里执行 npm 依赖生命周期脚本（pnpm 默认阻止依赖脚本，但显式放行的包会跑）时，
  多一个 `packages: write` 就多一条"把镜像 push 到 GHCR"的路。
- 修法建议: 给 `release` job 加 `permissions: {contents: write, id-token: write}`；
  给 release.yml 加 `concurrency: {group: release-${{ github.ref }}, cancel-in-progress: false}`。

### DEP-25 扫描步骤把 docker.sock 与 GHCR 凭据挂进一个第三方容器
- 严重度: 低
- 类别: 供应链
- 不变量/性质: 「扫描器只需要读镜像，不需要控制宿主 Docker，也不需要 registry 凭据」
- 证据: `release.yml:86-93`：`docker run --rm -v /var/run/docker.sock:/var/run/docker.sock
  -v "$HOME/.docker/config.json":/root/.docker/config.json:ro aquasec/trivy@sha256:…`。
  该步骤所在 job 持有 `packages: write` 与 `id-token: write`（`:31-34`），而 Docker 配置里是 `GITHUB_TOKEN`
  的登录凭据（`:41-45`）。
- 状态: CONFIRMED（行级）
- 影响: digest 被 pin 使这条风险有限（上游必须在该 digest 上就是恶意的），但一旦成立，该容器既能覆盖 GHCR 上的 tag，
  也能借 docker.sock 影响 runner。这是"扫描器按设计需要凭据"的典型形态，值得用更强的隔离替代。
- 修法建议: 用 `docker buildx build --output type=oci,dest=/tmp/img.tar`（或 `docker save`）把镜像落成 tar，
  再让 Trivy 用 `trivy image --input /tmp/img.tar` 扫——不需要 socket，也不需要 registry 凭据。

### DEP-26 基线 kustomization 的 `resources` 列表没有任何守卫（archtest 读目录，kustomize 读列表）
- 严重度: 低
- 类别: 可维护性
- 不变量/性质: 「被断言的东西就是被应用的东西」
- 证据: `internal/archtest/k8s_test.go:219-246` 的 `readYAMLDocs` **遍历目录**读取全部 `*.yaml`；
  而 `deploy/k8s/base/kustomization.yaml:4-12` 的 `resources:` 才是 `kubectl apply -k` 真正应用的东西。
  两者没有比对：往 `deploy/k8s/base/` 里放一个新清单却忘了登记，archtest 会断言它、kustomize 会忽略它。
  对照：备份 overlay 就有这条守卫（`k8s_test.go:273-296` 明确断言 `resources` 里必须列出 `pvc.yaml` 与 `cronjob.yaml`）。
- 状态: CONFIRMED（行级）
- 修法建议: 把 `TestBackupWorkloadIsSafeToLeaveRunning` 里那段"kustomization 必须列出每个清单"的断言
  提成两处共用的检查（base 与 backup 各一份）。

### DEP-27 PDB + `ScheduleAnyway` 在单节点/节点故障下不提供保护；`operations.md` 的措辞把 PDB 说大了
- 严重度: 低
- 类别: 可用性
- 不变量/性质: 「2 副本 + PDB 意味着任何时刻至少一个副本可用」
- 证据: `deploy/k8s/base/pdb.yaml:7` `minAvailable: 1`；`deployment.yaml:8` `replicas: 2`；
  `deployment.yaml:29-34` `topologySpreadConstraints … whenUnsatisfiable: ScheduleAnyway`。
  `docs/operations.md:209` 写"滚动更新（PDB 保证至少一个可用副本）"。
  事实：(a) 滚动更新由 `maxUnavailable: 0` 保证，PDB 管的是**自愿驱逐**（drain/node drain），两者不是一回事；
  (b) `ScheduleAnyway` 允许两个副本落在同一节点，节点故障会把两个一起带走，PDB 对此无能为力。
- 状态: CONFIRMED（行级；语义部分是一般 K8s 事实）
- 修法建议: 文档改成"滚动更新由 `maxUnavailable: 0` 保证；PDB 限制自愿驱逐"，
  并在 `docs/operations.md` 写清"本基线的可用性假设是 ≥2 个节点"（若接受单节点，就把 PDB 的意义说清，
  这属于裁定而非改代码）。

### DEP-28 namespace 没有 Pod Security admission 标签（两处工作负载其实都满足 `restricted`）
- 严重度: 低
- 类别: 安全（纵深防御）
- 不变量/性质: 「基线声明的加固由集群强制，而不是由清单自觉」
- 证据: `deploy/k8s/base/namespace.yaml`（4 行，只有名字）没有
  `pod-security.kubernetes.io/enforce`；而两个工作负载的 securityContext 已经满足 `restricted` 的硬性要求
  （`deployment.yaml:24-28,88-91`：runAsNonRoot/runAsUser 非 0/seccompProfile RuntimeDefault/
  allowPrivilegeEscalation false/capabilities drop ALL；`cronjob.yaml:26-33,69-72` 同形）。
- 状态: CONFIRMED（行级；"满足 restricted"是逐字段比对 PSA 规则，未在集群上验证）
- 影响: 将来有人误加 `privileged: true` 或去掉 `runAsNonRoot` 时，只有 review 会拦；加上标签后 apiserver 会直接拒绝。
- 修法建议: 在 namespace 上加 `pod-security.kubernetes.io/enforce: restricted`（先 `audit`/`warn` 一版再 enforce），
  并加一条 archtest 断言标签存在——这样"声明"就变成了"集群强制"。

---

## 探过但没破的（这些也应变成守卫）

1. **NetworkPolicy 真的选中了 Deployment；端口与来源都正确。** 探针
   `TestBaseNetworkPolicySelectsTheDeploymentItProtects` 交叉比对了 Deployment/Service/PDB/NetworkPolicy 四处 selector
   与 `policyTypes`，断言 8080 只来自 `ingress-nginx`、9090 只来自 `monitoring`、没有"到处都放行"的规则。
   这条正是 `archtest` 的缺口（它只断言 NetworkPolicy 文档存在）。
2. **Ingress 没有任何削弱 TLS/伪造来源的注解。** 探针 `TestIngressHasNoAnnotationThatWouldWeakenTLSOrTrustHeaders`
   逐键检查了 `ssl-verify/use-forwarded-headers/*-snippet/auth-url/backend-protocol` 等，并断言
   `proxy-body-size` 是显式 MiB 且 ≤8m；基线只有 `proxy-body-size: 1m` 与 `proxy-read-timeout: "60"`（`ingress.yaml:9-11`）。
   注意：`trusted_proxies = ["10.0.0.0/8"]`（`configmap.yaml:25`）确实**依赖** ingress-nginx 转发 XFF
   （默认行为成立），但 CIDR 与实际集群网段的匹配是未文档化的前提 → 见 DEP-13 的影响段。
3. **三个关停窗口的量级是一致的。** 探针 `TestGracefulShutdownWindowsAgree`：
   `cmd/re0auth/main.go:119` 30s drain < `deployment.yaml:23` 45s grace（余量 15s）< `ingress.yaml:11` 60s proxy-read-timeout。
   `archtest` 只断言 grace 字段**存在**（`k8s_test.go:97-99`），不检查它是否大于 drain。
4. **运行阶段只带二进制与 CA 包、数字非 root、静态链接、两处断言了前端真的构建过。**
   探针 `TestRuntimeStageShipsTheBinaryAndTheCABundleOnly` 断言 `FROM scratch` 之后除
   `/etc/ssl/certs/ca-certificates.crt` 与 `/out/re0auth` 外没有任何 `COPY/ADD`、`USER 65532`、
   `CGO_ENABLED=0 go build`，以及 `test -f internal/webui/dist/index.html` 至少出现两次（`Dockerfile:35,45`）；
   `web/scripts/restore-dist-placeholder.mjs` 解释了为什么 `.gitkeep/.gitignore` 需要在构建后被恢复
   （`adapter-static` 清目录、`//go:embed all:dist` 需要非空）——这条"placeholder 里没有 index.html，所以它是前端真构建过的证据"
   的设计是可靠的。
5. **运行时不写任何磁盘、不需要 `/etc/passwd`、不需要 zoneinfo。** 全仓 grep：
   `os.TempDir`/`CreateTemp`/`MkdirTemp`/`os.UserHomeDir`/`user.Current`/`user.Lookup`/`time.LoadLocation`/
   `ParseMultipartForm`/`FormFile` **零命中**（生产与测试代码都没有）。
   所以 `readOnlyRootFilesystem: true` + scratch 无 `/tmp` 的组合是自洽的（例外见 DEP-14：修 preStop 时想用 `/bin/sleep` 会发现没有）。
6. **探针/存活语义正确。** `internal/httpapi/health.go:25-27` `/healthz` 不查任何依赖（避免"数据库挂了→重启循环"），
   `:37-53` `/readyz` 在 2s 超时内只查池，`:75-77` 两个端点免限流（避免桶满把健康进程摘掉），
   `:62-66` 带 `no-store`（避免代理缓存"ready"）。这些是编排层最容易写错的地方，这里是写对的，值得保留断言。
7. **审计锚点 runbook 与实际 schema 对得上。** `cmd/re0auth/main.go:918-947` 启动即写一次并每小时写一次，
   格式 `audit chain head anchored head=<hex>`；`internal/store/postgres/auditchain.go:337-343` 的 `Head()`
   取的是 `audit_chain.head_hash`，而 `auditchain.go:162-181` 证明它恒等于最后一行 `audit_events.row_hash`（bytea，
   `migrations/0013_audit_chain.sql:31`）。所以 `docs/operations.md:162` 的
   `SELECT count(*) FROM audit_events WHERE row_hash = '\x<hex>'` 是对的；genesis 的空串也在 runbook 里说明了。
8. **规则/面板与代码的指标名一致（有守卫）。** 16 个 `re0auth_*` 名字全部在
   `internal/observability/observability.go` 声明（其中 `audit_append_duration_seconds`、
   `upstream_fetch_duration_seconds`、`upstream_circuit_transitions_total` 经 `:125,129,133` 的前缀拼接，
   我的 grep 一开始没命中，逐条核对过）；`internal/observability/artifacts_test.go:93-292` 已经断言了
   规则/面板的指标名与 `runbook_url` 锚点，我跑了它（ok）。
9. **部署清单里没有 `hostNetwork`/`hostPath`/`hostPort`/`privileged`/`runAsUser: 0`/`nodeName`。** 全目录 grep 零命中。
10. **`deploy/`、`.github/`、`scripts/`、`Dockerfile`、`Makefile` 里没有字面量秘密。**
    唯一命中是 CI 服务容器的 `POSTGRES_PASSWORD: postgres`（`ci.yml:37`、`perf.yml:48`），是本地临时值；
    `deploy/k8s` 里没有 `kind: Secret`（`operations.md:15-20` 让运维创建），`.dockerignore:28-31` 排除了
    `config/re0auth.toml`、`config/*.local.*`、`config/*.secret.*`、`.env`。
11. **所有 `uses:` 都按 commit SHA pin，且没有 `pull_request_target`。**
    逐行提取：46 条 `uses:` 全部是 40 位 SHA（ci 24、codeql 3、perf 3、release 12、visual-baselines 4），
    另有 1 条复用本地工作流 `release.yml:23 ./.github/workflows/ci.yml`；
    全部 5 个工作流里 `pull_request_target` 零命中（探针
    `TestNoWorkflowRunsUntrustedCodeWithWritePermissions` 也断言"回答 `pull_request` 的工作流里不出现
    `contents: write`/`packages: write`/`id-token: write`"）。
    回答 `pull_request` 的只有 ci.yml 与 codeql.yml，两者都只有 `contents: read`
    （codeql 另有 `security-events: write`，是上传 SARIF 所必需，且只影响扫描结果），
    没有任何 `secrets.*` 被交给跑 PR 代码的步骤；整个 ci.yml 全文只出现 `secrets.` 的**注释**一次（`ci.yml:19`）。
12. **pnpm 缓存投毒被 lockfile 的完整性摘要限制。** `web/pnpm-lock.yaml` 是 `lockfileVersion: '9.0'`，
    含 122 处 `integrity:`；`pnpm install --frozen-lockfile` 会校验。`actions/cache` 的作用域按 ref，
    PR 的缓存不会进默认分支的键空间。这两条合起来使"缓存投毒"在不动 lockfile 的前提下不可行——
    值得写成一条注释级守卫（这条结论依赖 pnpm 的校验行为，未见其源码，标为论证而非实测）。
13. **发布链的"警告跟着产物走"这一半是成立的。** 见 DEP-21 的探针：归档里有 README/SECURITY，
    `VERSION` 来自 `github.ref_name`（不是 `git describe`），`SHA256SUMS` 覆盖归档与 SBOM，
    签名的是 `SHA256SUMS` 本身；`Makefile:200-203` 的依赖链保证 checksums 在 dist/sbom 之后生成。
14. **`.golangci.yml` 的 `default: standard` 含 `errcheck`**（配置注释与 golangci-lint v2 的 standard 集合），
    `gosec` 是按 includes 收窄的 5 条规则（`:56-61`），G101 被有意排除——这些都在文件里写明了理由。
    本机未安装 golangci-lint（不安装），所以"它当前是绿的"这一条我没有验证。

---

## 未能到达（残余盲区）——必须写，并说清为什么

1. **镜像层的一切**：无 Docker。因此 DEP-02（CA 符号链接）只是假说；
   我也无法确认 `node:24-alpine@sha256:ebfe2f…`、`golang:1.27-alpine@sha256:8a5910…`、
   `postgres:16@sha256:1a6ab3…`、`aquasec/trivy@sha256:ab70a0…` 这些 digest 是否存在、是否对应它们注释里的版本。
   `internal/archtest/dockerfile_test.go` 只保证"格式是 digest"。
2. **K8s API 层校验**：无 kubectl/kustomize。所以所有清单只经过 yaml.v3 解析 + 我自己的断言（探针），
   没有经过 OpenAPI schema 校验、没有 `--dry-run=server`、没有 admission。字段名写错（例如把
   `readOnlyRootFilesystem` 写到 pod 级）在本机不会被任何东西发现。
3. **集群行为**：CNI 是否实现 NetworkPolicy（DEP-13）、连接残留窗口的实际长度（DEP-14）、
   迁移的真实时长（DEP-15）、ServiceAccount token 是否真的被投影挂载（DEP-20）、
   `restricted` PSA 是否真的接受这些清单（DEP-28）——全部需要集群。
4. **GitHub Actions 运行时**：fork PR 在 codeql 上是否会因 `security-events: write` 被降级而上传失败、
   `actions/cache` 的实际作用域、`docker/metadata-action` 的标签产出、以及**CI 当前是否全绿**（无网络，看不到运行记录）。
   我对 release.yml 的结论都是行级阅读，不含运行记录。
5. **扫描器与工具的真实行为**：Trivy/CodeQL/gitleaks/govulncheck/golangci-lint 本机都没装、也没网；
   DEP-23 里"CodeQL 不解析 .svelte"来自我对该工具的既有认识，未能用文档或实测复核。
6. **shellcheck**：未安装（按 brief 不安装），所以 `scripts/*.sh` 只有 `bash -n` 做语法检查；
   DEP-07/08 的结论来自行级阅读与我自己复刻的流程，不是 shellcheck 的输出。
7. **`docs/security-audit-2.md` / `-3.md` 的逐条内容**：我读了它们的发现标题与"未破/盲区"两节，
   确认部署面（镜像/清单/脚本/CI/发布链）不是这两轮的目标，因此本报告的条目没有重复它们；
   但我没有逐段通读这两份长文，个别条目仍可能有重叠（例如 audit-2 的 A5-* 涉及审计读 API 的门控，与 DEP-05 相邻）。

---

## 判断（文档化决定可否质疑，不是 finding）

1. **"谁能推 `v*` tag，谁就能让这条流水线构建并签名任意代码"**，这是 release.yml 的设计（tag-only 触发、
   `gh release create`、cosign keyless），CHANGELOG 的 rc.1/rc.2 两节甚至把它当成"tag 一响就等于发布了"的教训来讲。
   但仓库内**没有任何东西能表达或检查 tag 保护规则**（GitHub 侧的规则不在 git 里），
   `SECURITY.md`/`threat-model` 也没写"一个签名产物只等于'某个能推 tag 的账号认可它'"。
   我认为这是应该写进 SECURITY.md 的一句话（尤其是 README 教用户用 `cosign verify-blob` 时），
   但它是权衡（要不要引入人工审批/环境保护），不是缺陷。
2. **`maxSurge: 1` + 启动即迁移**：ADR-0008 选择"迁移跟着进程走 + 只做加法 + 回滚=恢复备份"，
   代价是"迁移时长被启动探针的预算约束"（DEP-15）。我认为这个取舍本身是合理的（少一个需要运维记得跑的步骤），
   但它的**代价没有被写下来**——建议在 ADR-0008 里补一句"最坏情况下升级会被 startupProbe 预算卡住，长迁移请走 Job"。
3. **`perf` 工作流的"门"不是性能门**（`perf.yml:85-88` 的 `< 100` 与 `ci.yml:395` 的 `< 3` 都是反空转下限），
   这是 ADR-0007 决策 5 明确写的（"CI 不按阈值卡基准"）。我不把它当 finding；但 `docs/capacity-planning.md:68`
   的"什么都没测到会失败"应当被读成"夹具还在跑"，而不是"性能没退化"。
4. **视觉基线测试当前不是门禁**（`ci.yml:246-251` 的注释明确说明：等 `visual-baselines` 工作流的产物被提交后再加
   `pnpm run test:visual` 一步）。这是一个**有明确后继动作的未完成项**，我只提醒它不能被读成"视觉测试在跑"。
5. **Ingress 上没有速率限制注解**（`ingress.yaml:6-11` 只有 body-size 与 read-timeout）：
   平台唯一的限流是进程内、按（平面, 地址）、每副本的桶（ADR-0006 决策 5 记录了"N 副本 = N 倍限额"）。
   `nginx.ingress.kubernetes.io/limit-rps` 也只能做到"每 ingress 副本"，收益有限，所以我把它留作判断而非 finding。
6. **CrashLoopBackOff 下的 Pod 仍会被 StartupProbe 反复杀**、`restartPolicy: Always` 没有指数退避上限之外的护栏——
   这是 K8s 的默认语义，不是本项目的选择；DEP-15 的处理建议已经覆盖了实际后果。
