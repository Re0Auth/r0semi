# 密码学/密钥生命周期审计报告 —— 对抗性复核（crypto-VERIFIED）

复核对象：`docs/audit-5/findings/crypto-keys.md`（k1–k8）
复核者立场：**证伪**。凡我确认的，都在本文件里给出我自己重跑的命令与承重输出行；凡我降级或推翻的，都在第 2 节给出代码/文档引证。

## 0. 复核环境与一处方法论修正

- Go 1.27.1 windows/amd64。全部命令**实际执行**，未跑 `go test ./...`，未改任何已跟踪文件，未碰他人的探针文件。
- 我的探针：`internal/zzprobe/verifycrypto/verify_crypto_test.go`（新包，只做测试）。它专门用来**打掉**报告的结论；
  它 **FAIL 的地方才是报告活下来的部分**，PASS 的地方是报告被推翻的部分。
- **修正一处探针调用约定**：任务里给的 `go test ./vault/ -run ZZprobe -v` 与
  `go test ./internal/zzprobe/crypto/` 的名字约定不一致 —— 探针函数名是 `TestProbe*`，不含 "ZZprobe"。
  用 `-run ZZprobe` 会得到 `testing: warning: no tests to run` / `ok ... [no tests to run]`（我实测过），
  这会**假通过**。正确的过滤是 `-run TestProbe`。
- **`.scratchpad\audit\BRIEF.md` 不存在**（全仓库搜 `*BRIEF*` 零命中，`docs/audit-5/` 下只有
  `findings/`、`probes/`、`runtime/`、`_urlprobe/`）。所以「不得报告的文档化非目标」清单我无法照它核对，
  只能用 `docs/positioning.md` §5「明确不做」与 `docs/security-audit-2.md:61-67`「没有报告什么（这是刻意的）」代替。
  这影响的是「已知（非发现）」这一列的判定强度，我在各条里明说了我用了哪份替代清单。
- **报告的残余盲区 #4 已过期**：报告称 `internal/httpapi` 整个包因他人留下的非法 UTF-8 探针无法编译、
  所以 k1 的动态复现做不了。我实测 `go build ./internal/httpapi/` 与 `go vet ./internal/httpapi/` **EXIT=0**
  （那个 `zzprobe_adminpriv_test.go` 现在不在树里）。所以 k1 的**动态**复现是可做的，我做了（见 k1 节）。

---

## 1. 判定表

| ID | 原判定严重度 | 我的判定 | 结论 | 一句话理由 |
|----|----|----|----|----|
| k1 | 中 | 中（可达性收窄） | **部分成立** | 原始 `usr_…` 进进程日志、假名密钥销毁够不到，这一点成立且默认配置下真的会输出；但它**只在会话存储故障时**才可达（不是常规路径），「前提②被本服务日志推翻」的表述不严谨，报告自陈「动态复现做不了」也已过期。 |
| k2 | 高 | 中高 | **部分成立** | 缺陷、交错与静默性成立，且比报告说的更严重（见 V-1）；但报告的机制描述被推翻 —— 覆盖后那一行**仍然可读**（读到旧值），不是「AES-GCM 拒绝、永久不可读」。 |
| k3 | 中 | 低（信号质量） | **部分成立（降级）** | 无原子性/无检查点、失败不进审计，这些成立；但「永久数据丢失」不成立：保留两把 KEK 重跑**收敛**（我实测），且 `runbooks.md:164` 已写明处置。剩余问题是运维信号质量。 |
| k4 | 低 | 低（更轻） | **部分成立** | 配置层确实不去重（读），但「运维不知道是哪两行」被夸大：库侧报错文本里带着那个 `kek_id`。 |
| k5 | 提示 | 提示 | **CONFIRMED** | 计数 wrapper 实测 `wrap=0 unwrap=1`，且既有守卫逐字节断言 `Ciphertext`/`Nonce` 不变。 |
| k6 | 低 | 低 | **CONFIRMED** | 我用**独立方法**（自己 grep 全仓库生产的 slog 调用）复核，7 处完全一致，无遗漏、无多报；但守卫自称的「完整覆盖」不成立（见 V-3）。 |
| k7 | 提示 | 提示 | **CONFIRMED** | 两条探针 PASS，且 `oidcRetiredTokenKeys` 确实只校验非空 id 与 32 字节、不做 id 冲突检查（读）。 |
| k8 | 提示 | 提示 | **CONFIRMED** | `vault` 的 5 条零化探针全部 PASS；残余的边界声明与 `vault/scrub.go` 文档一致。 |

---

## 2. 我降级或推翻的条目（本文件最重要的一节）

### 2.1 推翻 k2 的**机制**：那行覆盖后仍然可读，不是「AES-GCM 拒绝 / 永久不可读」

报告 k2「影响」写：
> 用户/数据源在窗口内刚写入的 `Ciphertext` 被旧密文覆盖，`WrappedDEK`/`KEKID` 却是**新的**，
> AES-GCM 会拒绝（AAD 匹配、DEK 换了 ⇒ tag 不匹配），于是这个绑定**永久不可读**

这是把两个不同的 DEK 搞混了。`vault/rotate.go:95` 的 `aad` 与 `:120` 的
`old.Unwrap(ctx, rec.WrappedDEK, aad)` 都取自**同一条读到的记录** `rec`；`:130-131` 改的只是
`WrappedDEK`/`KEKID`，`Nonce`/`Ciphertext` 用的还是**同一条 `rec`** 的值。
所以旋转写回去的是「**被重封装的那个 DEK** + **用同一个 DEK 加出来的那个密文**」——
**配对是匹配的**。并发 enroll 的新密文被丢掉，留下的旧密文与旧 DEK 依然成对。

我自己跑（`internal/zzprobe/verifycrypto/verify_crypto_test.go::TestVerifyRotateOverwriteLeavesARecordThatStillDecrypts`，
**PASS** = 报告被推翻）：

```
REFUTED: the stale record is still readable and self-consistent under the NEW key
  (read back "first-secret", no unwrap or GCM failure). rotation reported
  {Scanned:1 Rewrapped:1 AlreadyCurrent:0}. So the harm is a SILENT ROLLBACK to the
  previous payload, not an unreadable row.
the surviving row is on kek_id="kek-2" (new envelope) with the payload it was read with,
  i.e. a MATCHED pair
```

**决定性反证不需要新测试**：报告自己那条 FAIL 的输出里，
`rotate_lifecycle_test.go:132` 的 `readSecret(t, newWriter, id)` **成功返回了** `"first-secret"`，
测试是因为 `got != "second-secret"` 才 FAIL 的。一个「永久不可读」的行是**读不出任何东西**的，
而它读出来了。所以报告这条 FAIL 证明的是「静默回滚到旧值」，**不是**它写的那个机制。

**这件事改变判决吗？** 改的是**性质**，不是**有无**：
- 丢的确实是用户刚写的新数据（对 federation 来说，是赢家刚写进 vault 的上游 refresh token；
  上游 refresh token 通常会轮换，所以留下的旧 token 很可能已在上游失效 ⇒ 变成「需要重新绑定」，不是「可读的旧值就没事」）；
- 但「AES-GCM 拒绝」意味着可用性事故（每个读该行的用户都报错），而实际是**无错误、无告警、静默回退**。
  静默比报错更糟，所以严重度我不下调到「中低」；但报告用它来论证的**不可读性**必须删掉。

### 2.2 k2 的其余两问（按任务要求逐条给结论）

**(a) `hookRepo` 是不是真实 Postgres 路径的忠实模型？—— 是。**
`internal/store/postgres/vault.go:80-96`（「读；无 DB 执行」）的 `Put` 是
`INSERT ... ON CONFLICT (subject, provider) DO UPDATE SET version, wrapped_dek, kek_id, nonce, ciphertext,
meta, created_at, updated_at = EXCLUDED.*` —— **每个载荷列都无条件被覆盖**，没有版本谓词、没有 `WHERE`、
没有「只更信封」的变体。所以 `hookRepo` 用 MemoryRepo 模拟的「整条记录盖回去」与真实 Postgres 语义一致；
交错本身也是真实的：Postgres 里等价于「旋转的 SELECT 完成 → 另一事务提交了该行的 UPDATE →
旋转的 `INSERT ... ON CONFLICT` 阻塞在行锁上、然后照样把 `EXCLUDED` 盖上去」（last-writer-wins）。
并发写方也是**整条写**：`internal/federation/binding.go:87` 走的是 `s.vault.Enroll(...)`（不是窄更新），
所以「模拟的并发写」与「真实的并发写」形状相同。
（`hookRepo` 唯一的不忠实之处是把 hook 放在 `inner.Put` **之前**，但那只影响窗口边界的定义，
不影响 ON CONFLICT 覆盖整行这个承重事实。）

**(b) `Repo.Put` 的契约是否就是「替换整条记录」？—— 是，所以旋转的整行写是符合契约的。**
`vault/repo.go:120`：`// Put implements Repo. Existing records are replaced.`
`internal/store/postgres/vault.go:71-72`：`// Put implements vault.Repo. An existing record is replaced
wholesale, so the repository never invents timestamps or merges metadata on its own.`
结论要说清：**这不是 repo 违约，是 `rotate.go` 的读-改-写没有 CAS 的 lost update**（调方责任）。
报告「修法建议①」要求给 `Repo` 加窄方法，等于**改契约**——报告也承认了，但没指出它正在改契约。
这会让「按契约写整行」看起来像 bug，实际上契约明文允许；缺陷在**并发语义**上。

**(c) 带着服务跑 `-rotate-keys` 在出厂部署里可达吗？—— 可达，而且文档的做法让它更可达。**
逐处引证：

- `README.md:55-56` 三步是：`# 3. 轮换，然后删掉这段声明并重启` / `re0auth -rotate-keys -config ...`。
  **先轮换、后重启** —— 也就是说旋转**恰恰是**在「还在按旧配置（`kek-1` 为 current）服务的进程」还活着的时候跑的。
- `config/re0auth.example.toml:167-168`：`# 3. run: re0auth -rotate-keys ...` / `# then remove the block below and
  restart. The old key is no longer needed.` 同样没有停机步骤，也没有「确认 `Rewrapped == 0`」这道闸门。
- `cmd/re0auth/main.go:1078-1082` 的注释只是**理由**：「It is a startup action rather than a running one …
  so it **should not** race a server that is already serving」——`should not` 不是 `must not`，
  而且**没有任何机制执行它**：对比迁移路径，`internal/store/postgres/postgres.go:348` 明确取
  `pg_advisory_lock($1)` 把多实例串行化；`Rotate` 路径**没有**任何锁（我 grep 全仓库确认）。
- 出厂部署形状本身就是多实例并发：`docs/capacity-planning.md:16-18` = `replicas: 2`、
  `maxSurge: 1 / maxUnavailable: 0`；`docs/operations.md:209` 是滚动更新。
  「另一个实例正在服务」是**常态**，不是特例。

**判定**：文档**没有禁止**这个用法，也**没有使安全用法可达**（它既不说「必须在无人服务的窗口内」，
也不给任何可检查的完成闸门 —— 见 V-4）。失败是**静默的**：`-rotate-keys` 打印
`key rotation complete scanned=N rewrapped=M already_current=K` 并**退出 0**（`main.go:1088-1091`）。
所以「静默的数据丢失」**改变**我对严重度的判断：它把「运维做错了」变成「照文档做也会中招」。
我给的严重度是**中高**（不是报告的「高」，因为触发仍需并发写落在窗口内；也不是「中」，
因为按 README 的顺序跑，窗口必然覆盖仍在服务的旧进程）。

### 2.3 推翻 k3 的「永久数据丢失」：保留两把 KEK 重跑**收敛**，且项目已文档化处置

报告 k3 的影响段是「真实危害是**永久凭据丢失**」。任务里问的那条推理链我实测走了一遍
（`verify_crypto_test.go::TestVerifyPartialRotationConvergesOnRerun`，**PASS** = 报告被推翻）：

```
partial run: {Scanned:2 Rewrapped:1 AlreadyCurrent:0}, err=vault: rotate: persist taptap:usr_b: context deadline exceeded
re-run:      {Scanned:3 Rewrapped:2 AlreadyCurrent:1}
REFUTES k3's 'permanent data loss': after a partial run, keeping both keys and re-running
  converged, and removing the retired key then lost NOTHING (all 3 credentials readable
  under the new key alone).
```

机理是结构性的，不是巧合：`vault/rotate.go:97-112` 把已经在新 key 上的记录走
`AlreadyCurrent`（并验证能 unwrap），`:114-136` 只处理剩下的旧 key 记录。所以
「旧 key 仍在配置里」时重跑**恰好处理剩下的那一部分**，是幂等且可续的。
文档层面也早就这么写：
- `config/re0auth.example.toml:171`：`It does not decrypt or rewrite payloads, so it is cheap and
  **safe to run again**.`
- `docs/runbooks.md:164-165`：`**处置**：unconfigured_key → 把缺失的 retired KEK 加回配置，重跑
  -rotate-keys，确认 Rewrapped == 0 后再移除。` —— 项目**已经**给这个症状写了 runbook（含恢复与闸门）。
- `docs/operations.md:111-112`：`…启动时 -rotate-keys，确认没有待重包记录后再移除旧 key。`

所以 k3 正确的部分是：**失败时一次审计都不写**（我重跑确认，见第 3 节）、
`-rotate-keys` 失败时**丢弃 partial 计数**（`main.go:1085-1087` 只把 `err` 交给 `die`，
`rotation` 结构体被扔掉，运维看不到「已经改了几条」）。
这是**运维信号质量**问题，不是数据丢失。**降级为低**。报告 k3 的「次生」结论
（单行 `kek_id` 污染让整次轮转停摆）成立且我重跑确认，但它与「永久丢失」无关。

### 2.4 k4：配置层确实不去重，但代价被夸大

读（无 DB 执行）：`cmd/re0auth/config.go:619-638` 的循环只拒绝两类 —— `retired.KEKID == ""`
（`:622-623`）与 `retired.KEKID == cfg.KEKID`（`:624-627`），**没有 `seen` map，不去重**，
两条同 id 的 `[[vault.retired]]` 会双双进入 `cfg.RetiredKEKs`；库侧
`vault/service.go:123-125` 用 `vault: retired key %q is declared twice` 拦住。
「没有更早的检查」这一点我确认（我在 `cmd/re0auth` 里 grep `seen[`/`declared twice`/`duplicate`
零命中）。**但报告的代价描述不成立**：该报错**把重复的那个 `kek_id` 印出来了**，
运维在刚编辑过的配置文件里 grep 这个 id 就能看到两行；`低` 这个级别我认为仍然偏高，
实际是**锦上添花**级。结论：部分成立、程度更轻。

### 2.5 k1 的措辞与可达性（核心成立，但三处要收窄）

1. **可达性是「存储故障」，不是常规路径。** `internal/httpapi/account_routes.go:68` 的
   `slog.Warn` 只在 `s.SignOut(...)` 返回错误时触发，而 `SignOut` 的错误**只**来自
   `internal/auth/auth.go:197` 的 `m.sessions.Destroy(ctx)`（`:202` 的 `recordAudit` 不再返回错误）。
   抹除已经把会话行删了，`scs` 对「删 0 行」不报错，所以正常路径**到不了**这一行。
   我构造了确定性失败（`failingDeleteStore`，`TestVerifySignOutFailsDeterministicallyWhenTheStoreFails`，**PASS**）：
   ```
   SignOut saw user="usr_verify" and returned err=session store unreachable
   （对照组：健康 store → SignOut saw user="usr_verify" and returned err=<nil>）
   ```
   所以它**可达但潜伏**：需要一个与「刚刚成功的抹除」几乎同时发生的会话存储故障。
   报告把它当成「同一行日志里躺着明文 `usr_…`」的常规后果，可达性上略微夸大；
   但方向是对的（fail 面的日志里确实有原始 id）。
2. **「威胁模型前提②被本服务自己的日志推翻」这句不严谨。** `docs/threat-model.md:249` 的原文是
   「「不可关联」的前提是**除本服务外**无人持久化 `usr_` 与自然人身份的对应」——
   字面上「除本服务外」并没有被本服务自己的日志推翻。**真正被破坏的是主句**
   （`:248`「抹除后那些行仍在、仍能校验，但无法再关联到人」）：原始 `usr_` 落进了一个
   **销毁假名密钥够不到、且保留期由部署方决定**的 sink。这一点项目自己也认了 ——
   `docs/operations.md:203`：「运行日志与指标的保留周期由**部署方的日志/指标系统**决定，本服务不写第二份。」
   这行字恰好是 k1 最有力的引证：**项目明知进程日志是服务控制不到的持久 sink，却往里写原始 id。**
3. **修法理由里有个事实错误**：报告说「它唯一的用途是相关性，而同一条行已有 `request_id`」。
   `account_routes.go:73` 那一行**没有** `request_id` 属性（对比 `binding_routes.go:57` 有）。
   所以「删掉 `user` 属性即可」的论证需要补上「这行本来就没有 request_id」这一句，
   否则运维会以为关联能力已被保留。
4. **k1 不是「已知非发现」，但它也不是全新的不变量。** `docs/security-audit-2.md:34,136-155` 的
   **A5-1** 就是同一个不变量、同一条推理（原文：「这与 api-design.md §4 与 threat-model.md §9 声称的
   『再没人能把它们关联到你』直接矛盾；『机制落地前的行』那条豁免**覆盖不到它**，因为这行是机制自己写的」），
   第二轮已修（`Detail` 不再放账号 id，改记 `self`）。k1 是**同一个不变量的另一个 sink**（进程日志 vs 审计 `Detail`），
   不是重复发现，也不是文档化残余 —— 但它的修复范式在仓库里**已经存在**（`internal/lifecycle/lifecycle.go:276-294`
   的做法），所以它更接近「最后一处遗漏」而不是「新一类漏洞」。这一点会实质影响它的处置优先级。

### 2.6 k6：计数与逐条可达性我独立复核通过；但「守卫完整」这个前提不成立

7 处我用**与报告不同的方法**核了一遍（不跑它的 AST 守卫，而是自己 grep 全部生产的
`slog.*` 调用点），**完全一致，既无多报也无遗漏**，且每一处的值确实是原始 `usr_…`：
`internal/admin/admin.go:442`（`"subject", subject`，`record(ctx, actor, action, subject, …)` 的 `:428` 签名说明
这是 kill switch 的**目标**账号，不是操作员）、`internal/auth/auth.go:218`（`"subject", e.Subject`）、
`internal/federation/bind.go:208`、`refresh.go:155`、`refresh.go:160`（`"user", string(x.User)`）、
`internal/httpapi/account_routes.go:73`、`binding_routes.go:57`。

两处必须补正：
1. **`admin.go:442` 的那条不受「操作员在信任边界之外」的既有裁定保护。**
   `docs/security-audit-2.md:42-44` 记录的**未修判断**是：`admin` 的审计事件把**操作员的**
   `usr_…` 记在 `Detail["actor"]`，因为有意的（操作员在 SECURITY.md「Out of scope」）。
   但 `admin.go:442` 印的是 `subject`（**被 kill 的目标**）而不是 `actor`。
   所以报告说这条「范围最大」是站得住的，且它**不属于**那条已记录的判断。
2. **守卫的完整性主张不成立（报告在「未能到达 #6」里说它是「完整的（AST 级，覆盖全部 .go 文件）」）**：
   `source_log_guard_test.go:76` 要求接收者必须**字面**叫 `slog` 或 `log`，`:56` 跳过 `_test.go`，
   `:51` 跳过 `web/vendor/testdata/scratchpad`。一个存在结构体字段里、或名字不叫 `slog` 的
   logger 调用**完全不会被扫到**。我用 grep 复核后确认**目前没有这样的漏网命中**，
   所以结论不变；但「穷举式否定」的**强度**被高估了，应当改成「在本仓库当前写法下是完整的」。

---

## 3. 我确认的条目：我实际跑了什么

| ID | 我执行的命令 | 承重输出行 |
|----|----|----|
| k5 | `go test ./internal/zzprobe/crypto/ -count=1 -v` | `--- PASS: TestProbeRotationDoesNotDecryptPayloads`（另：`vault/rotate_test.go:77-85` 我读到了，逐字节断言 `Ciphertext` 与 `Nonce` 不变、`WrappedDEK` 必须变） |
| k3(部分) | 同上 | `--- PASS: TestProbeRotationIsNotAtomicAcrossRecords`，输出 `CONFIRMED: a rotation that fails on its first write produces no audit event at all…`（该探针在 `rotate_lifecycle_test.go:365-367` 先 `t.Fatal` 断言失败确实发生，**反空转对照存在**） |
| k3(部分) | 同上 | `--- PASS: TestProbeRotateRefusesAKEKIDItCannotUnwrap`：`rotation aborted at {Scanned:1 Rewrapped:0 AlreadyCurrent:0}` |
| k6 | `go test ./internal/zzprobe/crypto/ -count=1 -v` + **我自己的** `grep` 复核 | `--- FAIL: TestProbeNoSlogCallCarriesAnAccountIdentifier` 打出 7 行（`admin.go:442` / `auth.go:218` / `bind.go:208` / `refresh.go:155` / `refresh.go:160` / `account_routes.go:73` / `binding_routes.go:57`）；我的 grep 独立得到同样 7 处 |
| k7 | `go test ./internal/zzprobe/crypto/ -count=1 -v` | `--- PASS: TestProbeRetiredTokenKeyIDsAreNotValidatedLocally`、`::TestProbeTokenDecryptionIsKeyOrderIndependent`、`::TestProbeCompositeCryptoOverlap`；另读 `cmd/re0auth/main.go:1253-1273` 确认只校验非空 id 与 32 字节 |
| k8 | `go test ./vault/ -run TestProbe -count=1 -v` | `--- PASS: TestProbeScrubZeroesTheBackingArrayItWasGiven` / `::TestProbeUseZeroizesThePlaintextItHandedOut` / `::TestProbeUseZeroizesEvenWhenTheCallbackFails` / `::TestProbeEnrollDoesNotRetainTheCallersSecretBytes` / `::TestProbeUseDoesNotZeroizeTheCallersCopy` |
| k2(k2 的**存在性**，非其机制) | `go test ./internal/zzprobe/crypto/ -count=1 -v` | `--- FAIL: TestProbeRotationOverwritesARecordEnrolledDuringTheRun`，`CONFIRMED: rotation overwrote a concurrently enrolled secret with the stale payload; rotation reported {Scanned:1 Rewrapped:1 AlreadyCurrent:0} (success).` |
| k1(可达性) | `go test ./internal/zzprobe/verifycrypto/ -run TestVerifySignOutFails -v` | `SignOut saw user="usr_verify" and returned err=session store unreachable`（对照组 `err=<nil>`） |
| k1(默认 sink) | `… -run TestVerifyWarnIsEnabled -v` | `CONFIRMED: default level is info, so Warn and Error are ENABLED and the handler writes to os.Stderr`；Debug 未启用（先断言了这一点，防止「哨兵恒真」） |

---

## 4. 我未能验证的

1. **任何需要真实 Postgres 的观察。** 本机无 Docker、无 Postgres，所以下列论断仍只有行级证据，我逐条标「读；无 DB 执行」：
   - `internal/store/postgres/vault.go:83-91` 的 `ON CONFLICT DO UPDATE` 真的覆盖全部载荷列（k2 的核心前提）；
   - `auditpseudo.go:115-142` 在 `Destroy` 之后确实会**铸一把新 key** —— 这一条有**既有 DB 测试**
     背书（`internal/store/postgres/auditpseudo_test.go:232-244`，断言 "A new key, so it lands under a
     different pseudonym"），但它**需要 DB 才能跑**，我没有跑；
   - V-2 的最后一跳（`audit_subject_keys` 的行数在抹除请求结束后回到 1）需要真实 DB 观察。
2. **`-race` 未运行**（需要 cgo，报告也没跑）。我所有结论都是**确定性交错**，不依赖检测器；
   但「`vault.Service` 在多 goroutine 下除 repo 外无共享可变状态」这一点仍然没有检测器背书。
3. **`internal/httpapi` 包内的端到端复现**：我可以编译这个包（实测 EXIT=0），但我没有把
   `DELETE /v1/account` 整条 HTTP 路径跑起来（该包的测试装配 `newFlowEnvWithOptions` 是**包内未导出**
   的，我从 `internal/zzprobe/verifycrypto/` 复用它需要把探针放进 `internal/httpapi/`，
   而任务要求我的探针放在 `internal/zzprobe/verifycrypto/`）。所以我用「真实 `auth.Manager` + 真实 `scs` +
   真实 `lifecycle.Deleter` + httptest」把**除 httpapi 那一层以外的全部承重环节**跑通了，
   `account_routes.go:68-73` 这 6 行仍是**行级**证据。
4. **`BRIEF.md` 缺失**（见第 0 节），所以「已记录的非目标」我只能用 `docs/positioning.md` §5 与
   `security-audit-2.md:61-67` 代替核对；若真正的简报里还钉了别的不报项，我可能漏判一条「已知」。
5. **报告的「未能到达」清单里我逐条复算过的部分**：`#1`（Postgres 落盘）同 1；`#2`（-race）同 2；
   `#4`（httpapi 不可编译）**已过期**，见第 0 节；`#3`（假说）**我找到了路径**，见 V-2。
   `#5`/`#6`/`#7`/`#8` 我**没有**重新穷举（`upstreamkit`、`taptapoauth` 头、`recover*` 的 panic 值、
   `X-Request-Id` 未边界化），它们的可信度仍取决于报告自己那次扫描。

---

## 5. 我在复核中发现的新问题

### V-1 轮转**之后**落地的写入会停在退役 KEK 上；按文档第 3 步删掉 retired 即永久不可读，而 `-rotate-keys` 报成功

这比报告 k2 描述的那个交错**更严重、触发面更大**，而且**是文档的顺序造成的**：

- `internal/zzprobe/verifycrypto/verify_crypto_test.go::TestVerifyWriteAfterRotationLeavesARowOnTheRetiredKey`（**PASS** = 报告漏了这个）实测：
  ```
  rotation reported {Scanned:1 Rewrapped:1 AlreadyCurrent:0} over 2 records; 2 records now exist.
    It cannot mention the write it never saw.
  CONFIRMED-BEYOND-THE-REPORT: after removing the retired key usr_b is permanently unreadable
    (vault: taptap:usr_b was wrapped by key "kek-1", which is not configured; declare it as a
     retired key if this deployment rotated away from it), although -rotate-keys reported
    {Scanned:1 Rewrapped:1 AlreadyCurrent:0} and exited 0. No error was raised at any point.
  ```
- 与 k2 的区别：**不需要**写命中同一行、也不需要落在「读一页到写该页」那个窄窗口里。
  只要有一个还在按旧配置（`kek-1` 为 current）服务的进程在旋转**之后**（或旋转游标**已经越过**该 identity 之后）
  写了一条凭据，那条就留在 `kek-1` 上。`replicas: 2` + 滚动更新（`docs/capacity-planning.md:16-18`）
  让「还有旧键进程在服务」成为**常态**。
- 而 `README.md:55` 与 `config/re0auth.example.toml:167-168` 的**第 3 步就是「先轮换、再删声明、再重启」**：
  旋转被安排在「旧进程还活着」的时刻执行，然后紧接着把 `vault.retired` 删掉。
  改法收敛（我先验证了这一点）：保留两把 KEK 重跑一次就修好，我实测
  `a second run with both keys configured converged ({Scanned:2 Rewrapped:1 AlreadyCurrent:1}): usr_b is readable again`。
- **为什么这不是「运维自己作死」**：`-rotate-keys` 的成功输出
  （`main.go:1088-1091` 的 `scanned/rewrapped/already_current` + 退出 0）对「被越过的那条」**不可能**有任何提及，
  而唯一的完成闸门（`operations.md:112` / `runbooks.md:165` 的「确认 `Rewrapped == 0`」）
  **不在 README 与配置样例的三步里**（见 V-4），本身就要求在一个**没有写入的静止窗口**内才可能为真，
  而文档从没说需要静止。
- **建议**：① 让重封装成为窄写 + CAS（已由报告 k2 提出）；② 更便宜的补救是
  `-rotate-keys` 结束时**无条件**打印混合状态（`already_current + rewrapped != scanned` 时告警），
  并在 README/配置样例的三步里补上「确认 `Rewrapped == 0`」与「不要在仍有旧键进程服务时执行」；
  ③ 长期：给 `Rotate` 加一把 advisory lock（迁移已有先例：`internal/store/postgres/postgres.go:348`），
  或者让 `-rotate-keys` 拒绝在检测到「仍在服务」时运行。
- 严重度：**高**（静默 + 永久不可读 + 由文档顺序诱发）。

### V-2 抹除请求的最后一步被下一行撤销：`SignOut` 在假名密钥销毁**之后**写入一条带着原始 subject 的审计事件

这正是报告「未能到达 #3」的**假说**（报告原文：`Destroy` 只删一行、`subjectKey` 在**没有行时会铸一把新的**，
「我**没有找到**这样一条路径」）。路径是：

- `internal/httpapi/account_routes.go:54` 先跑完 `DeleteAccount`，其中
  `internal/lifecycle/lifecycle.go:258-263` 的 `Pseudonyms.Destroy` 是**最后一步**（`:254-257` 特意解释顺序）；
- 紧接着 `account_routes.go:68` 调 `s.SignOut(...)`；
- `internal/auth/auth.go:187-203`：`SignOut` 在 `:188-191` **先把原始 subject 取出来**，
  `:197` 销毁会话，**:202 无条件** `recordAudit(..., audit.Event{Action: "auth.logout", Subject: subject, …})`；
- `cmd/re0auth/main.go:437-440` 把同一个 `logger` 交给 `auth.Options.Audit`，
  `:614-615` 把同一个 sink 交给 `lifecycle` 的 `Pseudonyms`（`pseudonymStore`，`:1371-1379`）——
  所以**同一个 sink**先被要求销毁、随后又被喂进这个 subject；
- `internal/store/postgres/audit.go:73` 对该 subject 调 `pseudonymize`，`auditpseudo.go:156-165` → `subjectKey`
  → `:116-119` `loadKey` 因无行返回 `nil` → **`:121-142` 铸一把新 key 并 INSERT**。

实测（`verify_crypto_test.go::TestVerifyErasureUnlinksThenImmediatelyRelinks`，**FAIL 即确认**）：
```
0: record account.delete subject=usr_erased (RAW account id)
1: DESTROY pseudonym key for usr_erased
2: record auth.logout subject=usr_erased (RAW account id)
CONFIRMED: … is written to the audit sink AFTER the pseudonym key for that subject was
  destroyed (line 2).
```
（该测试用真实的 `lifecycle.Deleter`、真实的 `auth.Manager`、真实的 `scs` 会话，只把审计 sink 换成
一个同时实现 `Record` 与 `Destroy` 的捕获器，以记录顺序 —— 与 `main.go` 的接线同构。
`Record` 之后「铸新 key」这一跳由既有 DB 测试 `internal/store/postgres/auditpseudo_test.go:232-244`
背书，我无 DB 未能亲自观察，见第 4 节。）

**诚实的边界（避免我自己夸大）**：被销毁的那把 key 回不来，**旧审计行仍然解不开**，
所以这不是「历史重新可关联」。实际影响是两条：
① 抹除请求结束后 `audit_subject_keys` 里**又有了**这个已抹除账号的一行（既有测试
`auditpseudo_test.go:225-230` 断言的 `keys == 0 after destroy` 在真实请求序列下**不成立**）；
② 该账号在抹除**之后**的活动（这里就是那一条 `auth.logout`）对持有审计 key 的一方**重新可关联**
到候选 subject。而且它发生在**每一次成功的抹除**上，不限于错误路径。
严重度：**低-中**。修法很小：`SignOut` 的 `recordAudit` 在「主体已被抹除」的场景下不应携带
原始 subject（用 `internal/lifecycle/lifecycle.go:276-294` 的形状化做法，或让 erasure 之后不再写这条事件）。

### V-3 `source_log_guard_test.go` 的两处自身缺陷（不影响结论，影响它的说服力）

- `internal/zzprobe/crypto/source_log_guard_test.go:24` 的注释写
  `It found four sites; three of them are in production paths.` —— **实测是 7 处，且全部在生产路径上**。
  k6 报告用了真实的 7，所以**报告没错，探针注释过时**；但这条注释会让人低估发现。
- 该守卫只认字面接收者 `slog`/`log`（`:76`），并跳过 `_test.go`（`:56`）与 `web/vendor/testdata/scratchpad`（`:51`）。
  所以「覆盖全部 .go 文件」不成立；报告在「未能到达 #6」里把它当作穷举式否定的基础，是被高估的。
  建议把它并入常规套件时同时把接收者判定放宽到「任何 `.Info/.Warn/.Error/.Debug` 选择器调用」。

### V-4 README/配置样例的轮换三步缺少运维文档里那道闸门（文档不一致）

- `README.md:49-57` 与 `config/re0auth.example.toml:164-178` 的三步**没有**「确认 `Rewrapped == 0`」
  也没有「必须在无人服务时执行」；
- 但 `docs/operations.md:111-112` 与 `docs/runbooks.md:164-165` **有**这道闸门（「确认没有待重包记录后再移除旧 key」
  /「确认 `Rewrapped == 0` 后再移除」）。
- 结果是：**最短路径的读者**（README）拿不到闸门，而闸门正是唯一能挡住 V-1 / k3 的东西。
  建议把 operations.md 那一句抄进 README 与配置样例的第 3 步。

### V-5 审计简报 `docs/audit-5/BRIEF.md` 不存在

任务的第一条强制步骤要求读它（证据标准、输出格式、探针约定、不得报告的非目标清单），但全仓库零命中。
我用 `docs/positioning.md` §5 与 `docs/security-audit-2.md:61-67` 代替。
若它本该存在，那是一个**流程缺陷**：后续复核者都会缺同一块上下文。
