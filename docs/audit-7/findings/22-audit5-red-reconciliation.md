# 区域 22：round-5 `audit5` 红探针逐条归因（第七轮审计报告）

> 任务：把 HEAD 上仍然红的 19 个 `//go:build audit5` 探针，逐条判定为
> `KNOWN-OPEN` / `DECIDED-NONGOAL` / `REGRESSION` / `UNCLASSIFIED`，并只对后两类出完整发现。
>
> 本报告**只新增两个位置的文件**：本文件与 `internal/zzprobe/audit7/z22reconcile/`
> （`readiness_test.go`、`doc.go`，均带 build tag）。未改任何被 git 跟踪的文件，未修任何 bug。

## 范围与方法

**读到的**

- 19 个红探针的源码（逐个函数读，定位断言行）：
  `internal/zzprobe/crypto/source_log_guard_test.go:27`、
  `internal/zzprobe/federation/lifecycle_test.go:222`、`raw_test.go:321`、`safeurl_test.go:33`、
  `internal/zzprobe/protocol/kit/kit_probe_test.go:203/331/418/448/553/967/1078/1423`、
  `internal/zzprobe/protocol/rp/builtin_test.go:90`、`consent_test.go:219/286`、`e2e_test.go:319/504`、
  `internal/zzprobe/startup/startup_probe_test.go:151`、`surface_probe_test.go:133`。
- 为了对照「红 = 真缺陷」还是「红 = 已裁定」，读了机制所在的**生产代码**：
  `internal/httpapi/health.go`、`internal/federation/{federation.go,refresh.go,bind.go}`、
  `httpclient/outbound.go`、`oauth/client.go`、`idp/idp.go`、`internal/auth/auth.go`、
  `upstreamkit/conformance/conformance.go`（只到判据层）。
- 前 2-6 轮的全部文档：`AUDIT-ISSUES.md`（P0/P1/P2/P3 与「复核更正」）、`docs/security-audit-5.md`、
  `docs/audit-5/findings/{federation.md,crypto-keys.md,config-startup-disclosure.md,_fragment_rp.md,_fragment_kit.md}`、
  `docs/audit-7/BRIEF.md`。
- 修复史：`git log`/`git show 0e6b701`（P1-4 的 `/readyz` 成本上限修复），用来判定
  startup 两条探针是不是「修复之后变陈旧」。

**跑到的（全部实际执行，本机 Windows 11 / Go 1.27.1）**

```sh
go test -tags audit5 -count=1 -v -run '<每条探针>' ./internal/zzprobe/<pkg>/
go test -tags audit7 -count=1 -v ./internal/zzprobe/audit7/z22reconcile/
go build ./...      # exit 0
go vet ./...        # exit 0
gofmt -l internal/zzprobe/audit7/z22reconcile/   # 空
```

**跑不了的**：无 Docker / 无本地 Postgres ⇒ 凡是落盘/跨进程语义（FO-02 的真实交错、KIT-4 的 PG
`DELETE ... RETURNING`）只有读码级证据，已逐条标注。按简报要求**没有**跑 `go test ./...`。

**归因结果（19 条）**

| # | 探针（包） | 类别 | 既有编号 / 新编号 | 红的机制（读码确认） |
|---|---|---|---|---|
| 1 | `TestProbeNoSlogCallCarriesAnAccountIdentifier`（crypto） | KNOWN-OPEN | **k1/k6**（`crypto-keys.md:51,175`） | AST 扫出 7 处 slog 身份 attrs，与 k6 清单逐个相同 |
| 2 | `TestProbeRefreshVaultResidueAfterRowDisappears`（federation） | DECIDED-NONGOAL | **FO-02**，复核已判「已知（非发现）+ 证据不成立」（`AUDIT-ISSUES.md:363`、`security-audit-5.md:313`、`BRIEF §5`） | 探针在 **CAS 输掉**的分支触发（删行发生在 `PutIfVersion` **之前**）；残留的是入册时那条密钥，不是刷新写的 |
| 3 | `TestProbeScopeInjectionFromRegistry`（federation） | KNOWN-OPEN | **FO-04**（`federation.md:164`） | `bindScopes` 原样收下带空格的 `Resource.Scope`；`oauth2` 用空格 join 成多个 scope 发出 |
| 4 | `TestProbeIsPublicAddressCoversEverySpecialRange`（federation） | KNOWN-OPEN | **FO-03**（`federation.md:123`） | `0.0.0.0/8`（含 `::ffff:0.x`）不在 `nonPublicPrefixes`，`IsGlobalUnicast()` 判真 |
| 5 | `TestA2_FormAndBasicMayDisagree`（kit） | KNOWN-OPEN | **KIT-2**（`_fragment_kit.md:82`） | `ClientCredentials` Basic 赢者通吃，表单里的第二个身份不比对 |
| 6 | `TestA6_DeleteClientLeavesTokenRows`（kit） | KNOWN-OPEN | **KIT-10**（`_fragment_kit.md:387`） | `ClientAdmin.Delete` 只删 client 行 |
| 7 | `TestB3_RestoreClientSkipsRedirectValidation`（kit） | KNOWN-OPEN | **KIT-6**（`_fragment_kit.md:226`） | `RestoreClient` 故意不校验，而 authorize 路径没有第二道检查 |
| 8 | `TestC1_FailedExchangeConsumesTheCode`（kit） | KNOWN-OPEN | **KIT-4**（`_fragment_kit.md:154`） | `ConsumeCode` 在任何绑定校验之前 |
| 9 | `TestC4_PKCEChallengeShapeIsNotValidated`（kit） | KNOWN-OPEN | **KIT-5**（`_fragment_kit.md:189`） | `describe()` 只查非空 + S256 |
| 10 | `TestE6_BodyLimitVariants`（kit） | KNOWN-OPEN | **KIT-8**（`_fragment_kit.md:310`） | 无 `Content-Length` 的超限体经 `MaxBytesError`→`ParseForm` 错误塌成 400 |
| 11 | `TestE7_DiscoveryCacheHeaders`（kit） | KNOWN-OPEN | **KIT-9**（`_fragment_kit.md:354`） | 两份 well-known 都不设 `Cache-Control` |
| 12 | `TestF2_ConformanceIgnoresClientAuthentication`（kit） | KNOWN-OPEN | **KIT-7**（`_fragment_kit.md:263`） | 套件从不做「正确凭据成功、错误凭据失败」的断言 |
| 13 | `TestRPDiscoveryWithoutAuthorizationEndpointYieldsARelativeLoginURL`（rp） | KNOWN-OPEN | **RP-5**（`_fragment_rp.md:181`） | discovery 缺 `authorization_endpoint` 时 `provider.Endpoint()` 回空串，被 `http.Redirect` |
| 14 | `TestRPConsentApprovalRedirectIsReplayable`（rp） | KNOWN-OPEN | **RP-7**（`_fragment_rp.md:227`） | 同一个 auth request 每次访问都新签一份码 |
| 15 | `TestRPConsentDecisionConcurrency`（rp） | KNOWN-OPEN | **RP-7**（同上） | 并发决策成功后跟随 redirect 三次得三份码 |
| 16 | `TestRPLoginStateIsBoundToItsProvider`（rp） | KNOWN-OPEN | **RP-6**（`_fragment_rp.md:203`） | `clearFlow` 在 provider 比对之前 |
| 17 | `TestRPLoginLeavesNoFlowValuesInTheSession`（rp） | KNOWN-OPEN | **RP-8**（`_fragment_rp.md:263`） | `flowKeys` 漏了 `keyFlowNonce` |
| 18 | `TestProbeReadyzBypassesTheLimiterAndTheInFlightCap`（startup） | DECIDED-NONGOAL | **P1-4 已由 `0e6b701` 修复**；探针断言的是修复前的缺陷 | 新增 `readinessCache` 让同一时刻只跑一个检查，`ready.inside==32` 永远不成立 |
| 19 | `TestProbeHealthEndpointsAreNoStoreAndLeakNothing`（startup） | DECIDED-NONGOAL | 同上；代价见 `docs/operations.md:171-183` | 翻转依赖后立刻再打，`readinessTTL`（1s）内的旧结果仍是 200（见 **22-1** 的对照探针） |

**计数**：`KNOWN-OPEN` **16**、`DECIDED-NONGOAL` **3**、`REGRESSION` **0**、`UNCLASSIFIED` **0**（就这 19 条而言）。
**相邻发现 2 条**：**22-1（REGRESSION, P2）** —— probe #19 那片代码里由 `0e6b701` 引入的 fail-open；
**22-2（UNCLASSIFIED, P3）** —— round-5 证据链里一条结构上不可能失败的探针。

**顺带复核「已修」的四条（红转绿，不应重报）**：KIT-1（匿名 cascade → 现在 401，`TestE1_`/`TestE3_`/`TestF3_` 转绿）、
KIT-3（暂停/删除客户端的令牌现在 `active=false` 且数据面 401，`TestA4_`/`TestA5_`/`TestE10_` 转绿）、
CS-4（`token_class` 现在在 `federation.go:173-180` 白名单校验）、CS-1/P1-4（`/readyz` 现在有 `readinessTTL` 成本上限）。

---

## 发现

### 22-1 [REGRESSION，P2 中] `readinessCache` 在「首次检查仍在进行」时把 `/readyz` 回答成 ready（fail-open）：1 秒 TTL 之外，还有一条从未产生过结论的 200

- 严重度：**P2 中**（正确性 / fail-open；不因负载 shed，但会在依赖不可达时给出「就绪」）
- 类别：可用性 / 正确性
- 不变量：`docs/api-design.md:407` 与 `internal/httpapi/health.go:66-69` 的承诺——「`/readyz` 只有在
  每个依赖都可用时才回 200」；以及 `docs/operations.md:177-180` 的实现承诺——「其余请求直接拿到
  **上一次的结果**」。当**根本没有**上一次结果时，实现返回了零值 `err=nil`，即「就绪」。
- 证据（我自己的新探针，实际失败）：
  ```
  > go test -tags audit7 -count=1 -v -run TestZ22ReadinessAnswersReadyWhileTheFirstCheckIsRunning ./internal/zzprobe/audit7/z22reconcile/
  === RUN   TestZ22ReadinessAnswersReadyWhileTheFirstCheckIsRunning
      readiness_test.go:134: the request that ran the check = 503; a request that arrived while it was
                              still running (nothing cached yet) = 200 "ok\n"
      readiness_test.go:141: a /readyz that arrived while the first dependency check was still running
                              was answered 200 (ready) although the dependency is unreachable and no
                              result had ever been produced; the readiness cache returned its
                              zero-valued error (internal/httpapi/health.go:111-118)
  --- FAIL: TestZ22ReadinessAnswersReadyWhileTheFirstCheckIsRunning (0.05s)
  ```
  探针的**受控对照**：真正跑检查的那次请求拿到 **503**（依赖确实不可达），所以那个 200 不是「依赖恰好健康」。
- 机制（`file:line`，不需要再执行即可断定）：
  - `internal/httpapi/health.go:111-118`：
    ```go
    fresh := c.checked && time.Since(c.checkedAt) < readinessTTL
    if fresh || c.running {
        err := c.err      // <- 零值就是 nil
        c.mu.Unlock()
        return err
    }
    ```
    `c.checked` 为 false（首次检查从未完成）时，`c.err` 是**零值 nil**；`c.running` 为 true 时
    这条分支被走到，于是 `handleReady`（`health.go:94-101`）走 `err == nil` 分支写 `200 ok`。
  - 这不是 TTL 的代价：TTL 分支要求 `c.checked == true`，而失败分支没有这个要求。
- **这是回归，不是新增设计**：
  - 修复前（`git show 0e6b701 -- internal/httpapi/health.go` 删掉的行）`handleReady` 对**每个**请求
    自己 `context.WithTimeout(r.Context(), readinessTimeout)` 后调 `s.ready(ctx)`，
    因此并发/第二个探测者一定拿到同一个 503。
  - 修复提交 `0e6b701`（P1-4）的意图是「同一时刻最多只跑一个检查；**刷新期间到达的请求直接拿到
    上一次结果**」。「上一次结果」在从未有过结果时不存在，代码却用零值兜了底——提交信息与
    `docs/operations.md:177-180` 都没有写这条兜底，所以它是实现副作用而非裁定。
  - 我 grep 了 `docs/**`、`scratchpad/audit6/**`、`_audit/protocol.md` 的 `readiness|readyz|readinessTTL|readinessCache`
    全部命中：没有任何一处提到「无缓存结果时的 running 分支」。故不是已记录项。
- 状态：**CONFIRMED**（确定性探针，无并发时序假设：探针用「后台请求阻塞在检查里 → 主线程再发一次」构造）
- 影响：
  - 依赖不可达时 `/readyz` 仍会回 `200 ok`，窗口 = 一次检查的时长（≤ `readinessTimeout` 2s）。
    触发条件有两个，都在真实部署形态里：
    1. **进程刚起来、结果还没产生**（`checked=false`）：持久化部署启动时 Postgres 不可达，
       两个探测重叠 → 一个 503、另一个 200；
    2. **结果过期后有检查在跑**（`checked=true` 但 `fresh=false`，`running=true`）：这时返回的是
       **过期结果**（文档化代价，最多旧 1s）。注意第 2 条返回的是真结果，只有第 1 条是凭空造的。
  - 第 1 条的收益：一个匿名调用者在实例启动瞬间（或任何检查刚被触发时）并发打 `/readyz`，
    可以在 2s 窗口内拿到「就绪」，而实例其实连不上库。如果这个状态被 LB/编排器（该端点的唯一消费者）
    读到，就会把不能服务的实例留在轮转里。它是**失败被静默**（回 200 且 body 是 `ok`，不写任何日志）。
- 最小修法建议：
  ```go
  if fresh { return c.err }
  if c.running {
      if c.checked { return c.err }   // 有结果才复用
      return errNoResultYet           // 无结果：fail-closed，绝不回 nil
  }
  ```
  `handleReady` 把 `errNoResultYet` 按普通失败写 503（`not ready`），但不写 `slog.Debug(...err...)`
  以免伪装成依赖错误。这**不取消豁免**，也仍然「不因忙而 shed」（它不是因为负载才 503，而是没有结论时
  fail-closed）；若团队要求「第二个请求也不许等、也不许 503」，则替代方案是让首个调用者完成前把
  `handleReady` 直接 `503`，或者维护一个「检查进行中」的显式三态而不是把 `nil` 复用。
- 探针：`internal/zzprobe/audit7/z22reconcile/readiness_test.go::TestZ22ReadinessAnswersReadyWhileTheFirstCheckIsRunning`（红）
- 是否与既有编号相关：**对 P1-4 修复（`0e6b701`）的反驳/补充**，不是重报 P1-4。

### 22-2 [UNCLASSIFIED，P3 低] round-5 用来给 FO-04 作证的两条探针里，有一条结构上不可能失败（假守卫）

- 严重度：**P3 低**（方法学 / 证据完整性；本身不是运行时缺陷）
- 类别：可维护性
- 不变量：「红 = 证据」的反面——一条只做 `t.Logf` 的探针**不能**成为任何结论的证据。
- 证据（读码到行 + HEAD 运行结果）：
  - `internal/zzprobe/federation/raw_test.go:284-317`（`TestProbeRegistryAcceptsPathEscapingNames`）在循环里
    只有 `t.Logf`，**没有任何 `t.Error`/`t.Fatal`/断言**；它唯一的失败方式是 `NewRegistry` panic。
  - HEAD 运行它 **PASS**，同时打出：
    ```
    raw_test.go:312: game="phigros" name="../evil" => ACCEPTED; ...
    raw_test.go:312: game="phigros" name="src with space" => ACCEPTED; ...
    raw_test.go:312: game="phigros" name="src\x00null" => ACCEPTED; ...
    raw_test.go:312: game="phigros" name="src\nnewline" => ACCEPTED; ...
    --- PASS: TestProbeRegistryAcceptsPathEscapingNames
    ```
  - 而 `docs/audit-5/findings/federation.md:209-210`（FO-04 的「复现/守卫」）把这条与
    `TestProbeScopeInjectionFromRegistry` **并列**写成证据。后者会失败（见分类表 #3），前者不会——
    也就是说 FO-04 的「畸形 game/name 被接受」这一半，在 HEAD 处于**无守卫**状态：将来若有人
    让 `NewRegistry` 重新接受/继续接受畸形名，套件仍然全绿。
- 状态：**CONFIRMED（源级 + 执行级）**
- 影响：运维/后继审计者按 round-5 台账核对时，会得到「path-escaping 半边有探针守着」的假保证。
  危害限于证据链（会掩盖 FO-04 的回归），不是运行时攻击面。
- 修法建议：把它改成真正的守卫（`..`、含 `/`、`?`、`#`、`\`、NUL、CR/LF、前导/尾随空白、4096 字节
  等一律断言 `NewRegistry` **拒绝**；只有当前合法集合 `[a-z0-9][a-z0-9._-]*` 通过），
  或在 FO-04 结案前把它从证据清单里去掉、只留 `TestProbeScopeInjectionFromRegistry`。
- 是否与既有编号相关：FO-04 的**证据缺陷**，不是 FO-04 本身（FO-04 仍是 KNOWN-OPEN）。
  同类「假守卫」已有先例被记录（`AUDIT-ISSUES.md` P3：`TestMemStoreSweepStallsConcurrentRequests`
  的 `worst` 从不重置；FO-05 文档自述 `TestProbeRetryIsNotInstalledOnTheDataPlane` 只会打印），
  但**这一条**未被任何既有文档点名。

---

## 被点名但确认属既有的四条（不重报）

1. **`raw_test.go:336/339/312` 的 scope 注入与畸形名**：属 **FO-04**（`docs/audit-5/findings/federation.md:164-210`，
   复核见 `security-audit-5.md:314`「部分成立→更弱」）。机制我方复核成立：
   `bind.go:224` 把 `src.bindScopes()` 交给 `oauth2.Config.Scopes`，而
   `golang.org/x/oauth2@v0.36.0/oauth2.go:170,204` 是 `v.Set("scope", strings.Join(c.Scopes, " "))`
   ⇒ 声明的 `"phigros.profile.read account.id"` 在往上游的 token/授权请求里变成**两个** scope。
   `federation.go:112-122` 的 `bindScopes` 确实不切分、不校验空白；`NewRegistry`（`:141-189`）只校验
   非空/重复/`token_class`/`RawBase`，不校验 `Game`/`Name`/`Resource.Scope`。
   即：**红是真，但已被 FO-04 覆盖**；严重度仍受 FO-04 的定性约束（操作者配置，非远程面）。
2. **`httpclient_test.go:324-328` 的「数据面无重试层 vs 文档承诺指数退避」**：属 **FO-05**
   （`federation.md:214-235`，提示级）。该探针在 HEAD **PASS**（它只 `t.Logf`），FO-05 文档自己已说明
   它「现在只是一个会打印结论的探针」，并建议改成静态守卫。机制我方复核成立：
   `httpclient.Retry` 唯一构造点是 `cmd/referencesource/main.go`。**不重报**。
3. **`TestRPConsentApprovalRedirectIsReplayable` 与 `TestRPConsentDecisionConcurrency`**：属 **RP-7**
   （`_fragment_rp.md:227-261`）。不是未分类，也不严重：一次同意仍只产生一份**可兑换**的 grant
   （`internal/zzprobe/concurrency/single_use_test.go` 另有守卫），实际危害是「先被取走的码抢掉唯一
   兑奖机会」+ 死码残留。HEAD 复核：单线程两次访问得两份码、第一份 200 第二份 400；
   并发 8 次里 2 次返回 200、同一 redirect 跟随后产生 **3** 份不同码——与 RP-7 描述一致（数字有漂移，
   性质不变）。
4. **`TestRPLoginStateIsBoundToItsProvider`**：属 **RP-6**（`_fragment_rp.md:203-225`）。
   机制我方复核成立：`internal/auth/auth.go` 的 `clearFlow` 在 `flowProvider` 比对之前执行，
   于是一次「走错 provider」的回调烧掉待完成登录（第二次变 `invalid state`）。可用性级别，非安全。
5. **`lifecycle_test.go:290` 的 vault 残留**：属 **FO-02**，且复核已判「已知（非发现）+ 证据不成立」。
   我方复核补一条**探针机制错误**：`lifecycle_test.go:266-273` 的 `frozenStore.onPut` 在
   **调用底层 `PutIfVersion` 之前**就删了行，因此 CAS 一定**输**（`refresh.go:111-120` 的 `!won`
   分支直接 `return s.bindings.Get(...)` → `ErrNotBound`），残留的 vault 密钥是 `:259` 那次
   `v.Enroll` 写入的**旧密钥**，不是刷新写的。真正的 FO-02 窗口（CAS 赢、`storeBindingSecret`
   之前行被删）探针并没有构造到。而 `BRIEF.md §5` 已把「跨实例 refresh 的残余竞态」列为**有意不做**，
   故归 `DECIDED-NONGOAL`。

---

## 探过但没破的（应留成守卫）

- **`/readyz` 的依赖失败确实会被报告**：`TestZ22ReadinessTTLIsTheStaleAudit5Probe`（PASS）——
  健康结果入缓存 → 翻转依赖 → TTL 内仍 200（旧的、文档化的代价）→ 1.1s 后再打是
  `503 not ready`。这证明红探针 #19 的红**只是 TTL**，没有把依赖失败藏过一个 TTL 以上。
  建议：把 `audit5` 的 `TestProbeHealthEndpointsAreNoStoreAndLeakNothing` 改成「翻转后 `sleep(TTL+ε)`
  再断言 503」，否则它会一直红而掩盖 22-1 那种真问题。
- **探针豁免本身没有被破坏**：`isProbe`（`health.go:164-166`）仍在限流器与在途上限之前判断；
  `0e6b701` 的 `TestReadyzAnswersUnderLoadRatherThanShedding`（仓内）已钉住「32 并发探针全部 200」。
  所以 #18 的红是「探针在数并发检查数」，不是「豁免丢了」。
- 分类表 #1/#3/#4/#5-#17 对应的既有 finding 在 HEAD 逐条复现成功（命令与输出见上表与
  `docs/audit-7/audit5-red.log`），可作为「这些洞没有在 35 个修复提交里被顺手修掉」的守卫基线。

---

## 未能到达（残余盲区）

1. **FO-02 的真实交错（跨进程，CAS 赢后行被删）** 没有构造：需要两个进程/两个 store 实例，
   本机同进程的 `frozenStore` 只能在 CAS 前删行。要证实需要「`PutIfVersion` 返回 true 之后、
   `storeBindingSecret` 之前删行」的注入点（改探针即可，但会变成对生产代码的钩子依赖）。
   本条不影响归因（BRIEF §5 已列为有意不做）。
2. **KIT-4 的 Postgres 形态**（`DELETE ... RETURNING` 无谓词）只有读码级证据，无 DB 可跑。
3. **`readinessCache` 的 wall-clock 依赖**：TTL 用 `time.Since`，探针只能实时 sleep（1.1s）验证；
   没有可注入时钟。

---

## 判断（文档化决定可否质疑，不是 finding）

1. **`clearFlow` 的消费顺序（RP-6）是可用性问题，不是安全问题**：它需要会话内的 state 才能触发，
   攻击者不能主动触发。我同意 round-5 的低定级，不建议为此单开一轮。
2. **`RestoreClient` 不重校验（KIT-6）确实有文档支撑**（`docs/admin.md:69`、`oauth/client.go:180-192`），
   但「决定不校验」被实现成「authorize 路径上没有任何替代检查」这一点没有文档化。若维护者
   把 registry 写入方视为可信运维，KIT-6 应正式降为「提示」并在 `client.go` 注释里补一句
   「因此 authorize 路径不再做第二道检查」——目前注释只说了前半句。
3. **数据面不重试（FO-05）我认同「改文档比加代码正确」**：绑定刷新是旋转型单次凭据，重试无意义且加剧 churn。
4. **`readinessTTL` 的取舍本身合理**（`docs/operations.md:171-183` 论证完整、`periodSeconds=5` 与
   `failureThreshold=3` 也把代价框住）。22-1 不是在质疑 TTL，而是在质疑「无结果时用零值兜底」——
   这是实现没跟上裁定，而不是裁定错了。
