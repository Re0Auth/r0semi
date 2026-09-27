# 部署与运维（deploy/ops）审计报告 —— 对抗式复核

> 复核员：对抗式复核子代理。目标报告：`docs/audit-5/findings/deploy-ops.md`（DEP-01 … DEP-28）。
> 本机：Windows 11，**无 Docker / 无 kubectl / 无本地 Postgres**；Git for Windows 2.54 自带
> `bash.exe`（`C:\Program Files\Git\bin\bash.exe`）与 `sha256sum`（`usr\bin`），**因此原报告
> 声称的脚本执行是可以重跑的，我也重跑了**（见 §3）。
> **过程说明（必须记录）**：任务要求先读 `docs/audit-5/BRIEF.md`，**该文件不存在**
> （`docs/audit-5/` 下只有 `VERIFY-BRIEF.md`、`findings/`、`probes/`、`runtime/`）。
> 我按 `VERIFY-BRIEF.md` 的规则执行。
> **编号说明**：任务提示里的 `DEP-16`（`max_in_flight=512`）与 `DEP-21`（`:latest`）对应
> **本报告中的 DEP-18 与 DEP-19**；提示里的编号比报告整体前移 2 位。下文一律用**报告编号**。

## 1. 判定表

| ID | 原严重度 | 我的判定 | 结论 | 一句话理由 |
|---|---|---|---|---|
| DEP-01 | 高 | **中** | 部分成立（核心 CONFIRMED，影响链降级） | 真跑 `restore.sh` 复现了两向；但「锁定不可恢复」不成立（`operations.md:63` 明写只进空库），且加密路径上守卫根本不执行（V-1） |
| DEP-02 | 高(HYP) | 高(HYP) | 维持假说（**未能证实也未能证伪**） | 无 Docker、`web_search` 鉴权失败（我也失败）；补：失败点不在启动而在首次登录 |
| DEP-03 | 中 | 中 | CONFIRMED | `release.yml:55-66` 确无 `build-args`，`ci.yml:544-545` 确有 `VERSION=ci` |
| DEP-04 | 中 | 中（**倾向被低估**） | CONFIRMED | 步骤顺序确如此；另见 V-3：稳定 tag 时 `latest` 同样指向未扫描镜像 |
| DEP-05 | 中 | **低** | 部分成立（是 onboarding 文档缺口，非安全缺陷） | 空白名单是**写进代码注释的有意安全默认**；且 S5 仍有服务内自校验循环，不只是读 API |
| DEP-06 | 中 | 低 | 部分推翻 | 「数学上必然写满」不成立；`pvc.yaml:9-11` **自己就写了 sizing 方法**。「备份失败无告警」成立 |
| DEP-07 | 中 | 中 | CONFIRMED | 真跑：解密后的明文以 **644** 留在备份目录；`backup-keys.sh:70-72` 确有 `umask 077` |
| DEP-08 | 中 | 中 | CONFIRMED | 行级成立；argv 机制真跑可见（本机等价物） |
| DEP-09 | 中 | 中 | CONFIRMED | `runbooks.md:9`、`incident-response.md:21` 确写 `[admin].allow`，代码只有 `subjects` |
| DEP-10 | 中 | 中 | CONFIRMED | `runbooks.md:11`、`slo.md:79` 确写「默认 `:9090`」；`example.toml:81` 是 `""` |
| DEP-11 | 中 | **低** | CONFIRMED（严重度我判更低） | 插值真跑确认；但它是「注释里的虚假安全感」，不是提权路径——报告自己也这么校准，那严重度就该跟着降 |
| DEP-12 | 中 | 中（条件性） | CONFIRMED | 备份 Pod 确无 labels，策略确不选中它；「每次必失败」以默认拒绝为前提 |
| DEP-13 | 中(HYP) | 低–中 | 部分成立 | 缺的是「k8s + CNI 必须实现策略」这一句；`operations.md:127` 已对**别的编排系统**给了同类指引 |
| DEP-14 | 中(HYP) | 中 | CONFIRMED（行级）/HYP（窗口长度） | 确无 `preStop`；`Shutdown` 确实先关监听器；修正方案必须绕开 scratch 无 `/bin/sleep` |
| DEP-15 | 低 | 低 | 成立（HYPOTHESIS） | 顺序与 120s 预算行级确认，时长不可测 |
| DEP-16 | 低 | 低 | CONFIRMED | 无 `rotate-keys` Job、无 `RE0AUTH_KEK_OLD`、无 `[[vault.retired]]` 位；README:50-54 确有顺序陷阱 |
| DEP-17 | 低 | 低 | CONFIRMED | 无 checksum 注解、无热加载；三段文档都没有 `rollout restart` |
| DEP-18 | 低 | 低 | CONFIRMED | 基线确显式 512，与 `capacity-planning.md:113-121` 的推导（128）冲突 |
| DEP-19 | 低 | 低 | CONFIRMED | `deployment.yaml:37-38` 确是 `:latest` + `IfNotPresent`；`k8s_test.go:125` 只读 kustomization |
| DEP-20 | 低 | 低 | CONFIRMED | CronJob 确无 `automountServiceAccountToken`，也无 `serviceAccountName` |
| DEP-21 | 低 | 低 | CONFIRMED | 镜像里确无任何警告文本；labels 全部来自 metadata-action |
| DEP-22 | 低 | 低 | CONFIRMED | dependabot 四个生态确不含 `go install` pin 与扫描器 digest |
| DEP-23 | 低 | 低 | CONFIRMED（文件计数实测） | `.svelte 15 / .ts 6` 实测吻合；「CodeQL 不解析 .svelte」本机无法复核 |
| DEP-24 | 低 | 低 | CONFIRMED | `release` job 确无 permissions 块；全网只有 `perf.yml:26` 有 concurrency |
| DEP-25 | 低 | 低 | CONFIRMED | `release.yml:88-93` 确挂 docker.sock + docker config，所在 job 确有 `packages: write` |
| DEP-26 | 低 | 低 | CONFIRMED | base 的 `resources` 无守卫；backup 有守卫（`k8s_test.go:275-295`） |
| DEP-27 | 低 | 低 | CONFIRMED | `minAvailable: 1` + `ScheduleAnyway` + `operations.md:209` 的措辞，三者均确认 |
| DEP-28 | 低 | 低 | CONFIRMED | `namespace.yaml` 4 行、无 PSA 标签 |

探针本身质量：**合格**。`dig()` 在缺键时 `t.Fatal`、`yamlDocs()` 在解析为空时 `t.Fatal`、
`TestNoWorkflowRunsUntrustedCodeWithWritePermissions` 有 `checked < 1` 反空转计数——不存在
「因为夹具坏了而通过」的形态。唯一缺陷是形状问题：`TestBackupWorkloadIsUnselected…` 在缺陷
**被修好**（给 Pod 加 labels）时会 `t.Errorf` 失败，它是快照不是守卫（报告自己在注释里承认了）。

---

## 2. 降级、推翻与维持的理由

### DEP-01（高 → 中）：核心为真，影响链被夸大
`scripts/restore.sh:23-25` 就是 `if [ -f "$dump.sha256" ]; then sha256sum --check "$dump.sha256"; fi`
——`$dump` 没有进入校验，报告说得对。我用**真脚本 + 桩 psql/pg_restore** 跑出了两向（输出见 §3），
比原报告的「复刻流程」证据更强：原报告跑的是 `/tmp/zz-probe-sha2.sh`，那是**只抽出校验那一行**的
模拟（文件我读了，`set -u` 而非 `-euo pipefail`，从不调用 `psql`/`pg_restore`）；我跑的是脚本本身。

降级的理由有三条，都在控制流里：

1. **`operations.md:63` 明写**「恢复只能进空库；`restore.sh` 会在目标已有表时拒绝执行」，`restore.sh:2-4`
   的头注释同样如此。所以「半库后拒绝重试」不是缺陷被撞见，而是**被文档化的有意行为**
   （"recovery must be deliberate"）。运维拿到的是一个**响亮**的 `exit 1`（我实测 `refusing to restore:
   the target already has 7 tables`），补救是 `DROP DATABASE`/换一个空库——报告写的「除非人工 DROP SCHEMA」
   其实是**一行命令**，不是「不可恢复状态」。这一句严重度被写高了。
2. **`--exit-on-error` 失败本身是响亮的**（非零退出 + 报错），所以「被校验过的文件 ≠ 被恢复的文件」
   导致的不是「静默恢复出一个坏库」，而是「恢复中途失败且归因可能被误导」。静默的只有**校验报告本身**。
3. **(a) 方向在推荐的加密路径上不成立**：`operations.md:57` 给 DR 的示例用的是 `…dump.age` +
   `BACKUP_AGE_IDENTITY`，而该路径下守卫**完全不执行**（V-1，实测）。也就是说报告说的
   「运维要么被自己的校验步骤挡死（异地恢复）」**对加密备份不适用**（对未加密备份才成立）。

**仍然成立且值得修**：守卫与参数不绑定是真实缺陷（守卫在撒谎），修法是 3 行。`--single-transaction`
也确实缺失，值得加。

### DEP-02（维持高/HYPOTHESIS）：无法证实，也无法证伪——这次不是「偷懒」
- 行级：`Dockerfile:60` 与报告引用**逐字一致**；`internal/archtest/dockerfile_test.go` 全文只断言
  「每个 FROM 有 digest」「有 `FROM scratch`」「有 `USER 65532:65532`」，**没有任何 CA 包断言**——报告对
  「这条路径无检查覆盖」的判断成立。
- 外部事实：`web_search` 在**本会话同样是鉴权失败**（`Your api key: ****fa0d is invalid`，试了两次）。
  所以「Alpine 里 `ca-certificates.crt` 是普通文件还是符号链接」我**既不能引用证实，也不能引用证伪**。
  我的既有认知是 Alpine 的 `ca-certificates-bundle` 把 `ca-certificates.crt` 作为**普通文件**提供，
  反向的 `cert.pem -> ca-certificates.crt` 才是符号链接（若如此则本 Dockerfile 正确）；但这是我的
  **知识而非证据**，不足以推翻原报告的 HYPOTHESIS 标注。**双方都停在假说，这是本机条件下的正确结论。**
- 我另外补了两点报告没写的：
  1. **失败不是启动期的，而是首次登录时的**：`idp.NewRegistry`（`idp/idp.go:238-264`）只做构造，
     不发网络请求；`federation.NewRegistry` 同理；`openStorage`/`seedClient` 只碰数据库。所以悬空 CA
     的后果是：Pod `Running`、`/readyz` 200，**第一个用户登录时才炸**（`x509: certificate signed by
     unknown authority`）。这比「启动即崩」更难发现——但也不是静默：日志与登录失败率会立刻反映。
  2. 机制细节我做了实证：Go 1.27 的 `crypto/x509/root_linux.go` 里 `certFiles` 顺序确实是
     `ca-certificates.crt` → … → `/etc/ssl/cert.pem`，并有 `certDirectories = ["/etc/ssl/certs", …]`
     的目录扫描；`root.go:156-173` 是「找到即停 + 再扫目录」。所以报告描述的失败链**方向正确**。
     但 `COPY --from=<stage>` 到底复制链接还是解引用，本机**无法验证**——报告把它写成事实，这一点
     应降为「已知的常见失效形态（copied symlink in scratch）」。
- 一行验证（报告给的两条我保留，并补一条最省的）：`docker run --rm <build-stage> ls -l
  /etc/ssl/certs/ca-certificates.crt` → 看有没有 `->`。

### DEP-03（CONFIRMED）：干净的文档/行为不一致
`Dockerfile:48 ARG VERSION=dev`、`:49-51 -X main.version=${VERSION}`、`cmd/re0auth/main.go:68
var version = "dev"`；`ci.yml:544-545` 是 `build-args: |` + `VERSION=ci`；`release.yml:55-66` 只有
context/platforms/push/tags/labels/provenance/sbom，**没有 build-args**。README:139-140 的承诺
（「`re0auth -version` 打印构建版本（由 tag 注入），启动日志里也带同一个值」）与事实相反。
一句提醒：报告把「kustomization.yaml:27 钉 rc.3 与 CHANGELOG/archtest 的一致性对不上」也算进本条，
那部分我没有找到依据（pin 是 tag，archtest 的 tag 比对是过的），建议从本条证据里删掉。
`scratch` 无 shell 使 `-version`/启动日志成为**唯一**可问版本的地方，这一点成立，是本条的真正分量。

### DEP-04（CONFIRMED，且我认为被低估）
步骤顺序确认：`push: true` 在 `:60`，Trivy `--exit-code 1` 在 `:86-93`，`cosign sign` 在 `:97`
（所以扫描失败连签名都没有），`release` job `needs: [ci, image]`（`:100`）⇒ **GitHub Release 被门住**，
GHCR 上的 tag 不会消失。所以后果**不是**「release 已发布」，报告写对了。

但有一条报告没串起来的、更重的路径（见 V-3）：`release.yml:53` 在**稳定 tag**（不含 `-`）时会额外推
`latest`，而 `deploy/k8s/base/deployment.yaml:37` 引用的正是 `ghcr.io/re0auth/r0semi:latest`。两个事实叠加 ⇒ 一次「扫描没过」的稳定发布会把 **`latest` 指向一个未扫描、未签名的镜像**，
而基线 Deployment 的镜像引用恰好是 `latest`。当前仓库只有 `-rc` tag（`v0.0.0-rc.2/.3`），所以这条路径
**尚未被触发**，但它是设计好的路径。

### DEP-05（中 → 低）：这是 onboarding 缺口，不是安全缺陷
- 空白名单**是有意的**：`cmd/re0auth/main.go:549-551`（「skips it entirely rather than mounting a door
  with no lock」）、`main.go:584-586`（「A durable deployment with no admins is legitimate — it simply has
  no read API — and it must still start」）、`cmd/re0auth/config.go:264-266`（「Empty means the operator
  plane is not mounted at all」），并且 `cmd/re0auth/main_test.go:163-166` **把这条写成了测试**
  （「the read API was offered without an admin allowlist」会失败）。按 VERIFY-BRIEF §2，这是
  「有意决定」，不能当安全缺陷报。
- 报告的**影响段有一处不准**：`main.go:384-386` 的 `auditVerifyLoop` **不**受白名单门控
  （注释：\"a chain nobody is allowed to *read* is still a chain that must be *sound*\"），所以 S5 的
  「failed 恒为 0」仍然被服务自己每 6 小时走一遍并计入 `re0auth_audit_verify_total`
  （`operations.md:176-184`）。缺的是 `GET /v1/admin/audit/verify` 这条**手工**读侧与 Kill Switch。
- 真正站得住的部分：`incident-response.md:21-23` 说「事故前先确认至少有两个人在允许列表里」，却
  **全仓没有一句写「怎么把第一个人加进去」**，也没有「改完要重启」（DEP-17）。加上 DEP-09 的错键名，
  事故当天照抄 runbook 会得到一个起不来的服务。⇒ **低**（文档/onboarding 缺口）；把它与 DEP-09、
  DEP-17 合成一条「上线首日清单」比拆成三条更有用。

### DEP-06（中 → 低，部分推翻）：「必然写满」不成立
算术本身对：`*/15` ⇒ 96 次/天 × 7 天 = 672 份，`20GiB/672 ≈ 30 MiB/份`。
但「**数学上必然**写满」是错的：这只在「压缩后单份转储 > ~30 MiB」时成立，而这是一个**部署数据相关**的
未知量。更关键的是，`deploy/k8s/backup/pvc.yaml:9-11` 的注释**自己就写了 sizing 公式**：
「A starting point, not a recommendation: size it from the dump size (pg_dump -Fc compresses) times the
retention in the CronJob.」——报告把「必须按体积估算」当成自己的发现，而清单里已经写了。
（`operations.md:78-80` 也把「复制到对象存储」列为部署决策。）
**成立的部分**：`deploy/prometheus/re0auth.rules.yml` 全文 grep `kube_|cronjob|backup` **零命中**
（实测），所以「备份停了没人知道」是真的，且 `failedJobsHistoryLimit: 3` 会把证据冲掉、
`cronjob.yaml:58-60` 的注释自己承认「a failed backup that nobody reads is the same as none」。
⇒ 保留「缺告警」，降为低；把「必然写满」删掉。

### DEP-07（CONFIRMED，我用执行而非阅读）
- `scripts/backup.sh` 全文 grep `umask` **无命中**；`scripts/backup-keys.sh:70-72` 有
  `# 0600 from the start…` + `umask 077`（原文一致）。
- 我实跑了 `restore.sh` 的加密分支（桩 `age`）：**解密后的明文落在备份目录、mode=644、脚本结束仍在**，
  输出原文见 §3。这一条报告说是「行级」，我把它升级为**执行证据**。
  （`backup.sh:20` 的 pg_dump 产物权限是同一机制——`>` 与 `--file` 都是 `0666 & ~umask`；我在默认
  `umask 022` 下复现了 644。）
- `backup.sh:22-26` 的 `command -v age` 在 `pg_dump`（`:20`）之后，这一条行级确认。

### DEP-08（CONFIRMED）：措辞要收窄到「有进程可见性的本机攻击者」
行级完全成立（`backup.sh:20`、`restore.sh:28,35`、`cronjob.yaml:56` 都是 `--dbname "$DATABASE_URL"`）。
我在本机用桩 `pg_restore` 拿到了展开后的 `--dbname postgres://u:p@h:5432/db` 作为 argv——机制成立。
要精确的是：**这需要攻击者能在同一台机器上读进程表**（Linux `/proc/<pid>/cmdline` 默认 444；
`hidepid` 下不成立），并且 `restore.sh` 的运行者就是运维自己。所以严重度取决于「备份主机是否多人共享」，
报告自己也这么写了（「备份主机通常是共享的运维跳板机」——这是**假设**，仓库没有说备份机是跳板机）。
⇒ 保留中，但把前提写进证据，而不是放进影响段。

### DEP-09 / DEP-10（CONFIRMED）：两处都是「上线首日必踩」
- DEP-09：`runbooks.md:9`、`incident-response.md:21` 写 `[admin].allow`；正确键是
  `config/re0auth.example.toml:196`/`api-design.md:310`/`architecture.md:583` 的 `[admin].subjects`；
  `cmd/re0auth/config.go:65-67` 只有 `Subjects []string \`toml:\"subjects\"\``。启动期后果我确认了
  机制（`config.go` 的未知键拒绝 + `secret_env_test.go` 的注释），但**我没有实跑**「带 `allow` 的配置
  会拒绝启动」——`internal/config` 是别人的区域，我不越界，只标注为「读；未执行」。
- DEP-10：`runbooks.md:11` 与 `slo.md:79` 写「默认 `:9090`」；实际
  `config/re0auth.example.toml:81 internal_addr = ""`（注释「Empty — the default — serves neither」）、
  `cmd/re0auth/main.go:647 if cfg.InternalAddr != ""`。**基线 k8s 里反而是开着的**
  （`configmap.yaml:13` `0.0.0.0:9090`）——所以「基线上抓不到指标」不成立，**照文档在别处部署**才抓不到。
  报告的影响段写的是「运维按 runbook 上 `:9090` 抓指标会发现什么都没在听」，需要补这句限定。

### DEP-11（CONFIRMED，但严重度我判低）
我重跑了 dry run（`mingw32-make -n dist 'VERSION=v1";id;#'`），配方文本确实变成
`name="re0auth_v1;id;#_${os}_${arch}"; \`，`-ldflags` 那行同样破出引号（§3）。`Makefile:212` 的
`docker:` 目标更是连引号都没有。`release.yml:141-144` 的注释确实与事实不符。
但**「这条注释给了虚假的安全感」是一个评审假设，不是一个可利用的缺陷**：能推 `v*` tag 的人本来就能
让工作流 checkout 任意树并执行它。报告自己做了这个校准，那么严重度就该落到**低**（报告的 中 与它的
校准自相矛盾）。另外回答提问：**除了 tag，没有别的输入到达那个配方**——`Makefile:145` 的
`VERSION ?= $(shell git describe …)` 是本地默认，工作流显式覆盖；`release.yml:147` 的来源是
`github.ref_name`，没有其它调用方（全仓 grep `make release` 只有这一处）。

### DEP-12（CONFIRMED，条件性）
`deploy/k8s/backup/cronjob.yaml:23-24` 的 `template:` 下直接是 `spec:`，**没有 `metadata.labels`**；
`deploy/k8s/base/networkpolicy.yaml:7-8` 的 selector 是 `app.kubernetes.io/name: re0auth`；
`deploy/k8s/backup/` 下也没有第二条策略（只有 pvc/cronjob/kustomization）。所以「没有策略为备份 Pod
放行」是事实。**两个静默叠加是我认同的实质**：把 `re0auth.rules.yml` 全文 grep 一遍
（`kube_|cronjob|backup` 零命中）+ `failedJobsHistoryLimit: 3` ⇒ 失败会在几小时内自我湮灭。
限定词要说清：这**只在集群有默认拒绝 egress 时**才让每次转储失败（裸集群上备份能跑）。⇒ 中，条件性。

### DEP-13（中 → 低–中，部分成立）
行级部分我全部确认，包括报告那句「`docs/` 全文提到 NetworkPolicy 只有两处」——实测正是
`operations.md:10` 与 `:126`。但**报告漏读了一句**：`operations.md:127-128` 已经写
「**在别的编排系统上，请自己提供那个网络控制**，或者直接绑 loopback」。缺的因此不是「没有前提说明」，
而是**更窄的一条**：「在 k8s 上，这条策略只有在 CNI 真的实现 NetworkPolicy 时才生效」。按
VERIFY-BRIEF §3，前提是「集群的 CNI 不实现策略」——多数托管集群（Calico/Cilium/GKE/AKS/EKS）实现，
flannel 默认形态不实现。⇒ 降为**低–中**，修法是一句话加一条验收命令。

### DEP-14（CONFIRMED 行级 / HYPOTHESIS 窗口长度）
`deployment.yaml:16-94` 全文确无 `lifecycle`；`cmd/re0auth/main.go:745-759` 在 `ctx.Done()` 里对每个
endpoint 调 `ep.server.Shutdown(drainCtx)`——`http.Server.Shutdown` 的语义就是**先关监听器、再等在途**，
注释里也写着「the listeners stop accepting new ones first」。`/readyz` 由 `readinessProbe`
（`main.go:770-775`）提供，只做池 ping，**不感知关停**。K8s 的「摘端点与 SIGTERM 并发」是一般事实。
⇒ 机制成立，窗口长度需要集群。**修复约束（提问要求点名）**：`preStop` 的 `exec` 在 scratch 里
**无法用 `/bin/sleep`**（镜像只有 `/re0auth`），所以正确修法是二选一：(a) 让进程在收到 SIGTERM 后
**先让 `/readyz` 返 503、等 N 秒、再 `Shutdown`**（不需要任何外部二进制，最干净）；(b) 给 `preStop`
一个镜像里**确实存在**的 exec（例如 `/re0auth -drain-only`，需要新 flag）。`httpGet` 型 `preStop`
**不能**用来当 sleep（它不提供「等待直到完成再让 kubelet 发 SIGTERM」的阻塞语义），报告自己标了
「不够」，正确。

### DEP-15（低，HYPOTHESIS 成立）
`deployment.yaml:61-72` 的 24×5s=120s 与注释都在；`cmd/re0auth/main.go:340`（`openStorage`）→
`:815`（`postgres.Open`，注释「Open migrates up」）确实发生在 `:637 net.Listen` **之前**；顺序确认。
真实时长不可测（无 DB/集群）。⇒ 低，且它与 ADR-0008 的取舍绑定，报告在「判断」一节里的处理是对的。

### DEP-16 … DEP-28（低）：抽查 8 条，**没有一条是错的**
抽查并逐行确认：DEP-16（`configmap.yaml` 无 `[[vault.retired]]`；`deployment.yaml:43-58` 只有 `kek`，
无 `RE0AUTH_KEK_OLD`；`deploy/k8s/` 无任何 Job；README:50-54 的顺序陷阱逐字确认）、DEP-17、
DEP-18（提示里的 DEP-16）、DEP-19（提示里的 DEP-21）、DEP-20、DEP-21、DEP-22、DEP-24、DEP-25、
DEP-26、DEP-27、DEP-28。其中值得点名的两条：

- **DEP-18（`max_in_flight`）**：交叉核对了 performance 报告的指控。`capacity-planning.md:113` 确写
  「缺省值 = max(64, max_conns × 8)（默认池 16 → **128**）」，`:121` 写「这就是缺省值按池推导而不是
  写死 512 的原因」；`cmd/re0auth/config.go:329-338` 的实现站在 §4 这边（durable 派生，内存 512）。
  `deploy/k8s/base/configmap.yaml:24` 与 `config/re0auth.example.toml:46` 都**显式**写了 512 ⇒ 推导不生效。
  performance 报告说的「文档 §1 表格与 §4 自相矛盾」是**另一条**（`capacity-planning.md:20` 的表），
  与 DEP-18 不冲突：一条是文档内部矛盾，一条是基线覆盖了推导值。两条都对，不重复。
- **DEP-19（`:latest`）**：`deployment.yaml:37-38` 确认；`internal/archtest/k8s_test.go:125-165` 确认只读
  `deploy/k8s/base/kustomization.yaml` 并与仓库真实 `v*` tag 比对（`:146-165`），**完全不读
  deployment.yaml** ⇒ 报告「archtest 只检查 kustomization 的 tag」成立。

---

## 3. 我执行了什么（每条一行证据）

| 命令 | 有承载力的输出 |
|---|---|
| `go test ./internal/zzprobe/deploy/ -v` | `ok … 0.230s`，10 个测试全 PASS，3 条 `GAP` 以 `t.Log` 记录（与报告一致） |
| `go test ./internal/archtest/ -v` | `ok … 1.617s`，12 个测试全 PASS |
| `bash scripts/restore.sh <异地 dump>`（桩 psql/pg_restore，真实脚本） | `…dump: FAILED open or read` / `restore.sh exit=1`，**没有** `STUB pg_restore` 行 ⇒ 在 psql 之前退出：DEP-01(a) 复现 |
| `bash scripts/restore.sh <截断副本>` | `…backups/…dump: OK`（绿），随后 `STUB pg_restore RECEIVED: …/restorehost/…dump (1024 bytes)`、`restore complete`、`exit=0` ⇒ DEP-01(b) 复现，且**被校验的是 8192 字节那份** |
| 同上，无 `.sha256` | 无校验、无警告、`restore complete`、`exit=0` ⇒ **V-2** |
| 同上，`ZZV_PSQL_COUNT=7` | `refusing to restore: the target already has 7 tables`、`exit=1` ⇒ 空库守卫确实拒绝重试（但这是 `operations.md:63` 写明的行为） |
| `bash scripts/restore.sh <…dump.age>`（桩 age/psql/pg_restore） | 守卫**未执行**（找的是 `…dump.sha256`，`exists? NO`），`exit=0`，`restore complete` ⇒ **V-1**；残留 `-rw-r--r-- … re0auth-….dump`（**mode=644**）⇒ DEP-07 的下半段升级为执行证据 |
| `dash -c 'set -euo pipefail; echo REACHED-NEXT-LINE'`（本机 MSYS dash） | `REACHED-NEXT-LINE`、`exit=0` ⇒ **我的一个怀疑被自己的实验推翻**（见 §4） |
| `mingw32-make -n dist 'VERSION=v1";id;#'` | `name="re0auth_v1;id;#_${os}_${arch}"; \` 与 `-ldflags … main.version=v1;id;#` ⇒ DEP-11 复现（dry run，未执行任何东西） |
| `go vet ./...` | `exit 0`（含全部探针文件）⇒ CI 的 `go vet` 门在这棵树上不会因类型错误而红 |
| `gofmt -l .` + `git ls-files` 比对 | 21 个未格式化文件**全部未被 git 跟踪**（都是别的审计代理的探针）⇒ CI 的 `gofmt -l .` 门不受影响 |
| ci.yml 里 10 个 fuzz 目标逐个 `Select-String` | 10/10 `FOUND`（`idp`、`oauth`、`federation`、`oidchttp`）⇒ fuzz 作业不会因「目标改名/删除」而失败（正是该作业注释担心的失败模式） |
| `Test-Path cmd\covertable`、`TestLoadProfile`、`web/package.json` scripts | 全部存在（`cover`/`load` 作业与 `check`/`check:bundle`/`test:e2e` 步骤的依赖都在） |
| `git tag --list` | `v0.0.0-rc.2`、`v0.0.0-rc.3` ⇒ 基线 pin 的 rc.3 存在，`k8s_test` 的 tag 比对能过（CI 里 `fetch-depth: 0` 已给） |
| `web/src` 文件计数 | `.svelte 15 / .ts 6 / .css 1 / .svg 1 / .html 1` ⇒ DEP-23 的计数逐字吻合 |
| `re0auth.rules.yml` grep `kube_\|cronjob\|backup` | 零命中 ⇒ DEP-06/DEP-12 的「备份失败无告警」成立 |

**仓库卫生**：我**没有**改动任何被跟踪文件。全部实验产物写在 `%TEMP%`（`zzv-dep01.sh`、
`zzv-dep01-age.sh`、`zzv-dash.sh`），`git status` 的前后对比只有别的代理新增的探针文件（8 M / 19→20 ??）。
`make -n` 是 dry run，未生成 `dist/`。

### CI 是否能绿（报告列为「未能到达」，我做了本地可做的那一半）
报告说「看不到运行记录」，这我改变不了。但「**是否有步骤在新的一次运行上注定失败**」是可以本地查的，
我全查了，**没有发现注定失败的步骤**：10 个 fuzz 目标都在、`cmd/covertable` 在、`TestLoadProfile` 在、
`web/package.json` 的 4 个脚本都在、`go vet` 通过、被跟踪文件全部 gofmt 干净、archtest 的 tag 前提满足。
剩下的只能靠运行记录：`go install …@v1.8.0 / v2.14.0 / v8.30.1 / v1.12.0` 与
`aquasec/trivy@sha256:ab70a0…` 是否可安装/存在、**`pnpm audit --audit-level high` 今天是否命中上游公告**
（这是最可能让 CI 变红的门，因为它随上游漂移）、playwright e2e、以及 GitHub 侧权限。
另外注意：**当前工作树有 8 个被跟踪文件被改动**（`internal/federation/unbind.go`、`internal/httpapi/server.go`、
`internal/oidchttp/oidchttp.go` 等，共 +509/−87），所以「这棵树绿」与「main 绿」是两个问题；
本报告的全体部署类结论都落在**未被改动**的文件上（Dockerfile/scripts/workflows/manifests/Makefile），不受影响。

---

## 4. 我未能验证的

1. **Alpine 的 `ca-certificates.crt` 是不是符号链接**（DEP-02 的全部）：无 Docker；`web_search` 鉴权失败
   （`****fa0d is invalid`，两次）。也**无法**用本地构建产物替代。⇒ DEP-02 停在 HYPOTHESIS，正确。
2. Docker 的 `COPY --from` 对符号链接是复制链接还是解引用：同因。报告把它写成事实，应降为「常见失效形态」。
3. 镜像层内容、base image digest 是否存在、Trivy/CodeQL/gitleaks 的真实行为、action SHA 有效性、
   `go install` 的 pin 版本是否存在：全部需要网络或 Docker。
4. CNI 是否实现 NetworkPolicy（DEP-13）、连接残留窗口长度（DEP-14）、迁移时长（DEP-15）、
   SA token 是否真被投影（DEP-20）、PSA `restricted` 是否接受这些清单（DEP-28）：需要集群。
5. `pg_restore`/`psql`/`age` 的真实行为：本机没有，我用**桩**验证了**脚本自身的控制流**（argv、
   执行顺序、退出码、残留文件权限），但**没有**验证「截断的自定义格式转储在真 pg_restore 下会走到哪一步」；
   `--exit-on-error` 与 `--single-transaction` 的语义是读文档 + 阅读 `restore.sh:35`，未实测。
6. **一个我自己提出、又被自己的实验推翻的怀疑（记录在案，不作为发现）**：
   `deploy/k8s/backup/cronjob.yaml:49-52` 用 `command: ["/bin/sh","-c"]` 跑 `set -euo pipefail`，
   而 `postgres:16` 是 Debian（`/bin/sh` → dash）。我怀疑 dash 会在第一行报
   「Illegal option -o pipefail」而让**整个备份作业每次失败**。本机 Git 自带的 `/usr/bin/dash`
   **接受了它**（`REACHED-NEXT-LINE`、`exit=0`），因此我**无法证实**这条；Debian 侧 dash 的行为我
   也不能在本机测定。一行验证（需要 Docker）：
   `docker run --rm postgres:16 /bin/sh -c 'set -euo pipefail; echo survived'`。
   若它报错，这就是一条高于 DEP-06/DEP-12 的发现；若它成功，报告没有漏掉任何东西。
7. `docs/security-audit-2.md`/`-3.md` 的逐段内容：我只做了针对性 grep（`admin|allowlist|restore|backup|
   NetworkPolicy|pre-release`），audit-3 零命中、audit-2 只有 3 处相邻但不同的问题
   （`:42` actor 记名、`:214` kill_switch 回报、`:289` 四目标矩阵），**没有与本报告条目重复**。
8. `.github/workflows/*.yml` 的运行时权限语义（reusable workflow 的权限继承、fork PR 的
   `security-events`）：行级阅读之外的结论我没有下。

---

## 5. 新发现（复核时顺手找到的）

### V-1 `.age` 备份（也就是文档推荐的 DR 路径）上，`restore.sh` 的校验守卫**一行都不执行**
`restore.sh:16-21` 把 `dump` 重新赋值成 `plain`（去掉 `.age`），`:23` 于是去找
`<plain>.sha256`；而 `backup.sh:27-32` 在加密后 `shred -u "$out"` 并在 `out="$out.age"` **之后**
才写校验文件 ⇒ 磁盘上只有 `<dump>.age` 与 `<dump>.age.sha256`，**没有** `<dump>.sha256`。
实测（桩 age/psql/pg_restore，真脚本）：

```
  -> looks for : /tmp/zzv-dep01-age/backups/re0auth-20250101T000000Z.dump.sha256   exists? NO
  STUB pg_restore RECEIVED: …dump (30 bytes) mode=644
restore complete: …dump
  restore.sh exit=0
```

⇒ 对 `operations.md:57` 那条命令（`BACKUP_AGE_IDENTITY=… restore.sh …dump.age`），**校验从来没有发生过**。
两面性必须写清：(a) 这是守卫失效（assurance 缺失）；(b) 它同时**抵消**了 DEP-01(a) —— 加密备份异地恢复
**不会**被自己的校验挡死。age 是 AEAD，密文完整性由解密本身保证，所以危害主要是「守卫形同虚设」而不是
「静默恢复坏数据」⇒ **中**（原报告完全没有这条路径）。

### V-2 `.sha256` 文件缺失时，校验被**静默跳过**（无警告、退出 0、打印 `restore complete`）
`restore.sh:23` 是 `if [ -f "$dump.sha256" ]` 且**没有 else**。实测：没有 `.sha256` 的转储被直接
`pg_restore`，`exit=0`。这其实是最可能的 DR 现场（`.sha256` 没跟着转储一起被复制/恢复时，没人会注意到）。
对比：脚本对其它前提都用了 `: "${DATABASE_URL:?…}"`（`:14`）这种 fail-closed 写法，唯独完整性检查是
fail-open。⇒ **中**；修法一行（`[ -f … ] || { echo …; exit 1; }`，或提供显式 `--no-checksum` 逃生门）。

### V-3 `latest` × Trivy 失败 × `deployment.yaml` 的镜像引用：一条报告没有串起来的路径
`release.yml:53` 在**非预发布** tag 上会额外推 `latest`；`:60` 的 push 在 `:86-93` 的扫描之前；
`deploy/k8s/base/deployment.yaml:37` 引用的正是 `ghcr.io/re0auth/r0semi:latest`。三者叠加 ⇒
一次「HIGH/CRITICAL 扫描没过」的稳定发布会把 **`latest` 指向未扫描、未签名的镜像**，而既有基线
Deployment 的引用恰好就是 `latest`（kustomize 覆盖只在走 kustomize 的路径上生效）。
当前仓库只有 `v0.0.0-rc.2/.3`（不含 `-` 的 tag 尚未出现），所以这条路径**还没被触发**。
⇒ 这是把 DEP-04 从「一个多余的 tag 存在」抬到「拉 `latest` 的人会拿到没过门禁的镜像」的那一步。

---

## 6. 我认为被**低估**的

1. **DEP-04 的严重度（中）应当跟着 V-3 一起看**：单独看「push 在 scan 前」只是「registry 上多了一个
   未签名 tag」；串上 `latest`（`release.yml:53`）与基线 Deployment 的 `:latest`
   （`deployment.yaml:37`）+ `imagePullPolicy: IfNotPresent`（`:38`，会让缓存过 `latest` 的节点**永不更新**）
   之后，后果变成「**未通过漏洞门禁的镜像被部署方的默认引用指到**」。修法很便宜：把 scan 移到 push
   之前（buildx `load` + 本地扫），或至少在扫描失败时删掉 `latest`。
2. **DEP-12 + DEP-06 的「两个静默复合」值得单独成一格严重度**：报告把两者分开写在两条「中」里，
   但真正的形态是「备份 100% 失败 × 没有任何告警 × `failedJobsHistoryLimit: 3` 把证据冲掉 ×
   文档承诺 RPO ≤ 15 分钟」，直到真的需要恢复那天才发现。按 VERIFY-BRIEF §3 的「静默 ⇒ 升」，
   这条复合应该比单看任一条更重；报告已经在文字里说了，但严重度格子里没有体现。
3. **报告 DEP-01 的修法建议 1 会引入新 bug（顺手指出）**：建议的
   `cd "$(dirname "$dump")" && sha256sum -c "$(basename "$dump").sha256"` **不能**解决绑定问题
   ——`.sha256` 里记的是**绝对路径**，`-c` 依然去读那一行里的路径。真正可行的是一次性绑定：
   `expected=$(awk '{print $1}' "$dump.sha256"); printf '%s  %s\n' "$expected" "$dump" | sha256sum -c -`。
   报告在同一段里给了这个正确写法，但把前一个也列成了并列选项，落地时容易选错。
