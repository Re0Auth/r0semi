# 区域 Z12 复核报告（第七轮 · 对抗性复核）

> 被复核：`docs/audit-7/findings/Z12-config-startup-observability.md`
> `HEAD = bf81b2a`。复核探针：`internal/zzprobe/audit7/z12verify/`（全部 `//go:build audit7`）。
> 结论：**9 条中 7 条 CONFIRMED（严重度维持）、1 条 UPGRADED（跨区重复于 Z11-1）、0 条 REFUTED**；
> 另有 **2 条新发现（均 P3）+ 1 条对 Z12-6 的补强**（关闭其残余盲区）。被跟踪文件零修改。

## 1 复核方法

- 逐条读被复核报告给出的 `file:line`，并在源码中重新定位（不采信行号转述）。
- 亲自跑被复核者的探针：`go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z12configstartupobservability/...`
  → **11 个探针函数，9 红 / 2 绿**，与报告声称一致；红的理由与断言文本一致（见 §2 逐条）。
- 独立重证：不复用被复核者夹具，另开 `z12verify` 包重写探针（`TestMain` 自建二进制 + httptest）。
- 反空转：逐条检查阳性对照是否真走到目标路径，以及「探过没破」是否有夹具用桩造成的假绿。
- 未改被复核者探针；未改被跟踪文件（`git status --porcelain` 非 `??` 行为空）。

## 2 逐条裁决

### Z12-1 密钥原文进启动日志 — CONFIRMED，P2 维持

`cmd/re0auth/main.go:1410` 逐字确认：只有 `!ok || id == ""` 分支会走到 `%q` + `part`（整段原文），
且该分支正是「只粘贴密钥」的形状。真二进制复现（复核基线输出）：

```
stage=oidc err="... entry \"WjEyLVJFVElSRUQtVE9LRU4tS0VZLU1BTEVSVElBQQAA...\" must be id:base64"
```

阳性对照（`z12-old:<base64>` → `stage=listen` 且日志不含密钥）通过。CS-8 经我逐行确认：
`cmd/re0auth/zzprobe_startup_test.go:463-476` 的 planted 集合**不含** `RE0AUTH_OIDC_RETIRED_TOKEN_KEYS`
⇒「CS-8 覆盖不到」成立。另核：`main.go:1414` 同类消息回显 `id`（退化形态下同为密钥原文）。

### Z12-2 `-rotate-keys` 扫 0 条退 0 — CONFIRMED，P2 维持

`main.go:1189-1191`：只有 `incomplete && Skipped > 0` 才 `die`；`main.go:1213-1215` 对 `Scanned == 0`
只追加一句疑问句，`complete` 仍为 false ⇒ 返回 nil ⇒ exit 0。文档闸门核对：
`config/re0auth.example.toml:229-231` 原文是「repeat it until it prints `rewrapped=0 skipped=0`
**AND exits 0**」——报告写 `:232-233`（轻微行号偏差，结论不受影响）。空运行确实同时满足两者。
红探针同时断言 `scanned=0` 与 `nothing to rotate` 两条输出 ⇒ 非空转。**不重报**：第五轮
`docs/audit-5/findings/config-startup-disclosure.md:243-244` 只把这条输出当日志观察，未提闸门/退出码。

### Z12-3 seed 后 `[client]` 改动被静默忽略 — CONFIRMED，P1 维持

`main.go:1583-1591` 逐字确认：`clients.Get` 成功即 `return nil`；只有 `ErrClientNotFound` 才继续。
我另外查了**是否已有替代协调路径**：`internal/httpapi/admin_routes.go:100-189` 只有
list / register（`internal/admin/admin.go:222-244` 生成**新** client id）/ rotate-secret，
**没有任何改写既有 client 的 type/redirect_uris/scopes 的入口**，且公开路由只有 `POST /oauth/...`；
`cmd/re0auth/config.go:780-794` 的 `[client]` 只在 `seedClient` 处被消费（`grep` 确认唯一读点）。
⇒「配置改了但没有任何生效路径」成立，P1 不过高。报告的读码级补充（Postgres 同接口、无 reconcile）正确。
我的端到端探针（真二进制连续启动）确认了真进程的客户端行为与日志形态；内存模式下 `Get` 命中分支
无法由真进程触发（每次启动空库），该分支由源码与被复核者的注册表探针共同证明——报告已注明。

### Z12-4 文件列表无法被环境清空 — CONFIRMED，P2 维持

`cmd/re0auth/config.go:799 / :564 / :655` 三处 `TrimSpace(os.Getenv(...)) != ""` 逐字确认；
相邻 `rate_limit`（`:500-522`）确实用指针区分缺省与显式 0，对照成立。**不构成文档化决定**：
`docs/admin.md:19` 写「环境变量…**优先于文件**」，且随仓库的 `deploy/k8s/base/configmap.yaml:54-55`
就是 `subjects = []`，所以「用环境把文件里的名单收窄到空」是文档鼓励的形状。
我的独立探针补充了一条缓解事实（见 §4 判断）：**文件里的 `subjects = []` 确实能清空**（探针实测
`operator plane enabled` 消失），所以操作员有出路，只是环境这条不能表达「空」——P2 维持合适。

### Z12-5 `-migrate-down` 先跑 serving 期校验 — CONFIRMED，P3 维持

`main.go:332` 无条件 `loadConfig`；`:369-371` 才分发 `migrateDownAndReport`；`main.go:1158-1166`
只把 `DatabaseURL` + `ConnectTimeout` 交给 `MigrateDown`——审计链密钥不在路径上。红探针的
阳性对照（补上 audit key 后走到 `stage=migrate-down` 真连库）通过 ⇒ 非空转。
**不重报**：第五轮 `config-startup-disclosure.md:484-486` 只标「`-migrate-down` 退出码未验证」，
本条是「拒绝的理由与回滚无关」。P3 维持：rollback 被 ADR-0008 定位为备份恢复的补充，
且该键可临时提供任意合法 32 字节值绕过（探针即如此）。

### Z12-6 `rate_limit = NaN` 放行一切 — CONFIRMED，P2 维持（附新证据）

源码链逐条确认：`internal/config/config.go:103` `strconv.ParseFloat` 收 NaN；
`cmd/re0auth/config.go:512-522` 的 `NaN < 0`/`NaN == 0`/`burst < 1` 全部为 false；
`main.go:225` `NaN <= 0` 为 false ⇒ 装限流器。
我的独立探针把结论抬到**HTTP 层**（被复核者只在 `ratelimit.Allow` 循环里测）：

```
control: finite(50,100) shed 398 of 500      # 同一 handler，限流真的在拒
control: no limiter admitted 500 of 500
subject: NaN(100) admitted=500 shed=0        # 经真实中间件链，0 个 429
```

**全新证据（补上报告自己列的残余盲区 5）**：TOML 路径也成立，但只在**小写**拼写时——
`rate_limit = nan`（真二进制）走到 `stage=listen`；`rate_limit = NaN` 在 `stage=config`
被 BurntSushi 拒绝。报告「未实跑」的那条现在可以改为「小写 nan 成立，大写 NaN 安全」。

### Z12-7 `/readyz` 缓存被挂断污染 — **UPGRADED（跨区重复，且被低报）**

机制本身 CONFIRMED，且我把它证到了更强的一档。被复核者宣称「可保持 503 只要它一直问」，
但那是断言不是测量；我的两个独立探针给出：

```
codes after ONE hang-up, polled every 400ms: [503 503 503 200 200 200]  (healed after 1 TTL)
sustained hang-up loop (~4/s): kubelet-shaped probes (5s apart) = [503 503 503], cancellations=14
```

即：单次挂断只污染**一个 TTL 窗口**（自愈）；但「每 TTL 内赢一次触发者竞争」的**持续**挂断
可让健康依赖下的每次 kubelet 探测都拿到 503，而 `deploy/k8s/base/deployment.yaml:96-100`
的 `periodSeconds: 5 / failureThreshold: 3` ⇒ 15 秒摘除端点。**一个匿名单机连接循环
即可把健康副本摘出流量** —— 这是简报 §6 明列的 P0 形态「匿名可触发的 DoS」，至少 P1。

**但它不是新发现**：本轮**同一轮**的区 11 已报告 **Z11-1**
（`docs/audit-7/findings/Z11-resilience-dos.md`，评级 **P1**，探针
`internal/zzprobe/audit7/z11resiliencedos/readyz_poison_test.go:41 TestZ11CallerCancellationPoisonsTheSharedReadinessResult`，
其证据文本与 Z12-7 是同一机制同一行 `health.go:122`）。被复核者的「关联」一节只对照了
G-11 / P1-4 / CS-1，**完全没有意识到区 11 已经报了同一条**，并因此把它写成 P2。
按简报「不许重报」⇒ Z12-7 应作废为 Z11-1 的重复；若保留，严重度必须按 Z11-1 的 P1。
被复核者对 G-11 的区分（`running` 分支 fail-open vs `fresh` 分支缓存取消）本身正确，不据此加分。

### Z12-8 位置参数被静默忽略 — CONFIRMED，P3 维持

`main.go:259` 只 `flag.Parse()`；`grep` 确认 `cmd/re0auth` 无 `flag.Args()`/`flag.NArg()`。
红探针真二进制输出与断言一致（3 种位置参数均 exit 0），阳性对照（`-version` 单独 exit 0）通过。
**措辞问题（不影响结论）**：`z12limiterargs_test.go:127` 把 `{"-version","rotate-keys"}` 说成
「missing its dashes turns the requested one-shot mode into whatever the remaining flags select」——
该组参数里**选中了** `-version`，这句话对该用例是错的（真实现场是 `re0auth -config … rotate-keys`，
那时确实会起服务，报告正文举的例子正确）。

### Z12-9 池大小截断到 int32 — CONFIRMED，P2 维持

`cmd/re0auth/config.go:1062-1067` 的 `int32(*section.MaxConns)` 逐字确认；相邻环境路径
`:1116-1126` 用 `strconv.ParseInt(raw, 10, 32)`。我独立复证了「两条路径语义不一致」这半边：

```
RE0AUTH_STORAGE_MAX_CONNS = 4294967297 -> stage=config err="... is not an integer"
file max_conns = 4294967297           -> stage=storage（被读成 1）
```

阳性对照（文件 `max_conns = 0` 在 `stage=config` 被点名；`16` 走到 `stage=storage`）由被复核者
探针给出且我重跑通过 ⇒ 非空转。P2 维持；残余（真 pgxpool 实际池大小）报告已标 HYPOTHESIS。

## 3 新发现（独立证据）

### Z12V-1 KEK 的解析**不**遵循文件声明的变量名：硬编码 `RE0AUTH_KEK` 先于 `vault.kek_env`

- 严重度：**P3**（可维护性 / 安全姿态；失败在运行时才出现，不是攻击者可达的绕过）
- 证据（源码 + 探针，路径 `internal/zzprobe/audit7/z12verify/verify_kekenv_test.go`）：
  `cmd/re0auth/config.go:721-731` 是
  `kekValue := os.Getenv("RE0AUTH_KEK"); if kekValue == "" { ... config.Secret(f.Vault.KEKEnv, ...) }`
  ——与全文件用了几十次的 `FirstNonEmpty(env, file)` **顺序相反**：文件声明的 `vault.kek_env`
  只在硬编码名**为空**时才被读取。探针实测：
  ```
  vault.kek_env = Z12V_OTHER_KEK（已设为合法 32 字节）且 RE0AUTH_KEK 也设 -> 走到 stage=listen（文件被忽略）
  对照：删掉 RE0AUTH_KEK -> 文件声明的变量被使用（改名本身可行）
  对照：RE0AUTH_KEK 设为非法值 + 文件指向合法变量 -> stage=config 失败（硬编码名真的在裁决）
  ```
  而 `KEKID` 取自 `:465` 的 `RE0AUTH_KEK_ID`（裸读 `os.Getenv`），与 `vault.kek_env` 完全脱钩。
- 为什么是缺陷：`docs/operations.md:138-139` **明写**「`vault.kek_env`（可以改名，脚本通过
  `re0auth -print-secret-env` 读出来，**而不是假定叫 `RE0AUTH_KEK`**）」，
  `internal/config/config.go:4-6` 也把「文件命名变量、环境持有值」写成包的契约。
  `-print-secret-env` / `scripts/backup-keys.sh` 按文件读名，进程按硬编码名取值 ⇒ 两者不一致。
- 事故形状：按文档把 KEK 改名轮换（`kek_env = "RE0AUTH_KEK_2"` + 新 `kek_id`），而编排器仍在注入
  旧名 ⇒ 进程用**旧密钥 + 新 kek_id** 启动，日志无提示；首次写入看似成功，之后每次解封都
  `authentication failed`（全账号绑定不可读，只能从备份恢复）。
- 状态：CONFIRMED（源级 + 上述对照已跑）- 修法：`kek_env` 存在时**只**读它（或至少两者不一致时拒绝启动并点名），`KEKID` 同理从文件段取值。
- 关联：与 Z12-4 同族（空/缺省被当成未设置），但是不同的键与后果，不构成重报。

### Z12V-2 被复核者列在「未能到达 5」的 TOML `nan` 已可结论（补强 Z12-6，非新洞）

见 §2 Z12-6：`nan` 小写被接受、`NaN` 被拒。仅关闭该残余盲区，并把修法收紧为「同时拒绝两种
字面量的接受面差异」。

### Z12V-3 `envInt32` 的越界报文自称「不是整数」

- 严重度：**P3**（可维护性；报错文本误导排查方向）
- 证据：`cmd/re0auth/config.go:1121-1123` 对 `strconv.ParseInt` 的任何错误都返回
  `"%s %q is not an integer"`；`RE0AUTH_STORAGE_MAX_CONNS=4294967297` 因此报「is not an integer」，
  而它**是**整数、只是超出 int32（实测输出见 §2 Z12-9）。
- 影响：运维按报文去找「哪里写了个非数字」，真问题在量级/字段类型——与同文件 `resolvePool` 的
  「validate rather than clamp」注释正好相悖：这里是 clamp。
- 修法：区分 `ErrRange` 与语法错误，报文写「out of range for a 32-bit pool size」。
- 关联：Z12-9 的补充（同一路径的另一半）。

## 4 判断（不是 finding）

1. **Z12-4 的严重度可讨论**：文件 `subjects = []` 能清空（我实测），随仓库 ConfigMap 本来就是
   `subjects = []`，所以「运维被静默困住」只发生在 overlay 用环境清空时。P2 是保守上限；若要压缩
   清单规模，它是本区最可降的一条（P3）。我未据此改判，因为文档确实写了「环境优先」。2. `-rotate-keys` 的 `scanned=0` 文案（`main.go:1214`）已问了「is the configured storage the one
   holding credentials?」——信息在场，缺的是**退出码**。Z12-2 的修法（非零退出）与
   `rotationReport` 注释「counts only speak for the records this run read」的立场冲突，属裁定。
3. 「探过没破」第 4 条（`trusted_proxies = ["0.0.0.0/0"]` 安全无操作）我未复跑，但
   `cmd/re0auth/config.go:101-108` 与 `clientaddr.go:104-110`「最右跳仍在列表内则回落 peer」一致。
4. 「未能到达 3」（SIGTERM/排空顺序真跑）我同样未做：我的真进程探针也都在监听器之前返回。

## 5 复核探针清单

| 文件 | 探针 | 判红/绿 | 作用 |
|---|---|---|---|
| `verify_limiter_rate_test.go` | `...NaNInstallsAnAdmittingLimiterThroughTheRealChain` | **绿**（NaN 0 个 429） | 把 Z12-6 抬到 HTTP 层，带 2 个阳性对照 |
| `verify_readyz_test.go` | `...ReadyzStaysDownWhileKubeletKeepsProbing` | 绿（自愈） | 反证「单次挂断 = 一个 TTL」 |
| `verify_readyz_test.go` | `...SustainedHangUpsHoldReadyzDown` | **红** | Z12-7 可持久化（P1，重复 Z11-1） |
| `verify_binary_test.go` | `...TOMLNaNIsAlsoAccepted` | **红**（小写 nan 被接受） | 关闭 Z12-6 残余盲区 |
| `verify_binary_test.go` | `...EnvPoolSizeIsRefusedWhereTheFileIsTruncated` | 绿 | Z12-9 两路径不一致 |
| `verify_binary_test.go` | `...FileListCanBeEmptiedButNotTheEnv` | 绿 | Z12-4 缓解事实 |
| `verify_kekenv_test.go` | `...KekReadsRE0AUTHKEKRegardlessOfKekEnv` | 绿（机制确证） | Z12V-1 |
| `verify_kekenv_test.go` | `...EnvEmptyFallsBackToTheFileDriver` | 绿 | 环境空值族 |
| `verify_seedclient_test.go` | `...SecondBoot...KeepsTheFirstShape` | 绿 | Z12-3 进程级观察 |

工具：`go build ./...` / `go vet ./...` / `go vet -tags audit7 ./internal/zzprobe/audit7/z12verify/...`
全部 exit 0；`gofmt -l` 干净；`git status --porcelain` 无被跟踪文件改动。
