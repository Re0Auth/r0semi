# 联邦数据面与出站 HTTP 审计 —— 对抗性复核（federation-VERIFIED）

复核对象：`docs/audit-5/findings/federation.md`（FO-01 … FO-07）。
复核立场：**证伪**。凡我确认的，在本文件里给出我自己跑过的命令与承重输出行；凡我降级或推翻的，在第 3 节给出代码/文档引证。
我的探针：`internal/zzprobe/verifyfederation/`（新包，只含 `_test.go`：`addr_test.go`、`helpers_test.go`、
`killswitch_test.go`、`refresh_test.go`、`scopegate_test.go`）。

---

## 0. 复核环境、方法，与三处必须更正的元信息

**实际执行过的命令**（绝不 `go test ./...`，绝不改被跟踪文件）：

```
go test ./internal/zzprobe/federation/ -run TestProbe -v -count=1          # 报告的探针（原样复跑）
go test ./internal/zzprobe/federationhttp/ -run TestZZProbe -v -count=1    # 报告的探针（原样复跑）
go test -race ./internal/zzprobe/verifyfederation/ -count=1 -timeout 180s  # 我的探针 → ok 2.012s
go env CGO_ENABLED ; gcc --version ; go version
git status --porcelain                                                     # 复核前后逐字一致
```

**（修正 1）`docs/audit-5/BRIEF.md` 在我开始复核时不存在。** 我第一次读它是 `not found`，
`docs/audit-5/` 下只有 `findings/`、`probes/`、`runtime/`、`_urlprobe/`；主代理在 0:17:23 重建了它
（文件头自己写着「本文件曾被某个代理误删过一次，由主代理重建」），`VERIFY-BRIEF.md` 也在 0:15:42 才出现。
我读到的是**重建版**，本文件里所有「已知（非发现）」的判定都基于重建版 §5 的清单，请主代理按此折算强度。
（另一位复核者 `crypto-VERIFIED.md:15-18` 遇到的是同一个缺口，可交叉印证。）

**（修正 2）报告称「无 cgo，`-race` 跑不了」（第 30 行、残余盲区 #2）不成立。**
`go env CGO_ENABLED` = `1`，`gcc (MinGW-W64) 16.1.0` 在场，BRIEF §2 也明写「`go test -race` **可用**」。
我在 `-race` 下跑完我的整包（`ok ... 2.012s`），并用一个**故意竞态**的控制用例证明检测器活着
（`WARNING: DATA RACE` + `FAIL`），随后删掉该控制文件。
后果：报告里「`keyedMutex` 的 refcount 回收」「Kill Switch 的 8 个 worker」这类**并发论断**没有被检测器背书的
理由只成立到「作者没跑」，不成立到「环境不允许」——这是可以补的，不是边界。

**（修正 3）报告 FO-02 引用了仓库里不存在的类型 `SessionRevocationSummary`**（第 109 行）。
全仓库只有 `federation.BindingRevocationSummary`（`internal/federation/killswitch.go:14`）；
`grep -rn "SessionRevocationSummary"` 零命中。这句话想说的是「不进 Kill Switch 的计数」，
但索引到一个不存在的符号，属于**未核对就落笔**的证据。

**纪律**：未修改任何被跟踪文件（复核前后的 `git status` 非 `??` 行完全一致，仍是审计开始前那 8 个改动）；
未碰邻居的 `internal/zzprobe/federation/{helpers,crypto_shim}_test.go` 与 `federationhttp/` 同名副本；
未动被复核的报告与探针；未删 `docs/audit-5/**` 下任何东西。

---

## 1. 判定表

| ID | 原判定严重度 | 我的判定 | 结论 | 一句话理由 |
|----|----|----|----|----|
| FO-01 | 高 | **中** | **CONFIRMED（降级）** | 闸门与选源确实是两次互不相干的查找（我独立复现：闸门给 `phigros.profile.read`，数据来自 `b`），`?source=` 也不改判据；但收益有界——读的是**受害者自己绑定**的源上**自己**的数据、响应头是 MUST 级披露、载荷 schema 由协议 §8 固定——且前提是运维给同名资源在不同源上声明不同 scope，而协议的 canonical 文法本要求同名资源同 scope。 |
| FO-02 | 中 | **提示** | **已知（非发现）＋证据不成立** | 「跨实例 refresh 的残余竞态」是 BRIEF §5 明列的文档化非目标，现象原文写在 `refresh.go:106-110`（"only an account erasure clears"）与 `lifecycle.go:163-165`；其探针在 **CAS 未赢**的分支上触发、看到的密钥是夹具自己 `Enroll` 的那条（我实测 `won=false` 且密钥未变），而 `refresh.go:121-127` 讲的是 vault 写失败那条路径——我实测那条路径**确实**自愈。 |
| FO-03 | 低 | 低（谓词）／提示（可利用性） | **部分成立** | 谓词缺口 CONFIRMED：我实测 `0.0.0.1`／`0.1.2.3`／`0.255.255.255`／`::ffff:0.1.2.3` 均判 PUBLIC；但**本机（Windows）实测 0/8 不可路由**（`connectex: ... unreachable network`），唯一能打到回环的 `0.0.0.0` 恰好被 `IsUnspecified` 拦下，Linux 仍未知——即可利用性方向**更弱**，不是更强。 |
| FO-04 | 低 | **提示** | **部分成立** | 事实成立（我执行到 wire：注入空格让源收到 4 个 scope；`?`/`#` 让 `redirect_uri` 被解析成别的东西），但全是运维 TOML 输入、无远程路径；两个子论据被推翻（键空间碰撞会在启动被 `duplicate source` 拒绝、且请求路径先过 game 查找；`NewRegistry` 只校验非空已由同轮 CS-4 记录）；报告用「威胁模型把操作者列在信任边界之外」降级是**引证反了**（`threat-model.md:57` 的 B6 写的是运营者**不受信任**）。 |
| FO-05 | 提示 | 提示 | **CONFIRMED（但与 performance.md 重复）** | `httpclient.Retry` 全仓库只有 `cmd/referencesource/main.go:143` 一个构造点，组合根的数据面客户端只装 pool+bulkhead+breaker（`main.go:459-475`）；`source-onboarding.md:225` 那一行确实是 re0auth 自己的出站承诺。但同轮的 `performance.md:112-113` 已经记过「re0auth 的出站客户端没有包重试」，新增信息只剩文档那一处。 |
| FO-06 | 低 | 低 | **CONFIRMED（比报告更彻底）** | 我端到端执行：第 3 页失败时 `RevokeAllBindings` 返回 `{Total:4 Revoked:4}` + err，已断的 4 条不再可枚举，admin 层 `report.Bindings=nil`；**补充**：审计行 detail 只有 `{actor, tokens_revoked:0}`，连审计链也没有那 4 个计数。另：报告称「无 DB 无法构造探针」不成立，我用一个实现 `BindingStore`+`BindingPager` 的测试 store 就构造出来了。 |
| FO-07 | 提示 | 提示 | **CONFIRMED（边界比报告更窄）** | 我执行了它没跑的那一步：闸门开 + 回环代理 → 拒绝文本里出现的是**代理**地址（fail-closed）；闸门关 → 代理收到绝对 URI `http://10.0.0.5/secret`，目标地址无人检查。全仓库（Dockerfile、`deploy/k8s`、CI、config）**没有任何地方设置 `HTTP(S)_PROXY`**，所以前提就是「有人能改进程环境」，与报告自己的限定一致。报告里「`HTTPS_PROXY=http://10.0.0.5:3128` 通过闸门」一句与它下一行的自我更正矛盾，应以更正为准。 |

---

## 2. FO-01 专节 —— 那个「最重要的」宣言，一半成立

### 2.1 是不是真的？（是，我独立复现；不是夹具artifact）

**先手推路径，两处判定确实是独立的两次查找：**

- **闸门（授权判定）**：`internal/httpapi/federation_routes.go:89`

  ```go
  scope, ok := s.federate.ResourceScope(game, resource)
  ```
  `:94-97` 用它比对令牌 scope；注意 `:103` **同一个 handler 才**读 `?source=`：
  `Source: r.URL.Query().Get("source")`。也就是说**判据产生在知道要服务哪个源之前**。

- **`ResourceScope` 的实现**：`internal/federation/service.go:206-213`

  ```go
  for _, src := range s.registry.Sources(game) {
      if res, ok := src.Resource(resource); ok {
          return res.Scope, true
      }
  }
  ```
  `Registry.Sources`（`federation.go:234-238`）**按 name 排序**，所以这里返回的是「名字最小的、声明了该资源的源」的 scope。
  接口签名本身就是证据——`service.go:73`：`ResourceScope(game, resource string) (string, bool)`，**没有 source 参数**，
  所以这道闸门在类型层面就不可能按源判定。

- **选源（数据来自哪）**：`service.go:216` → `candidates`（`:305-335`）→ `trySource`（`:278-300`）。
  `candidates` 只做「跳过 retired + 声明了该资源」，然后 `sort.SliceStable` 按 `statusRank`；`trySource` 用
  `bindings.Get(ctx, req.User, req.Game, src.Name)`（`:279`）挑第一个**已绑定**的候选。
  真正被读的 URL 由 `fetchResource` 用**被选中的那个源**拼：`:532`
  `endpoint := strings.TrimRight(src.Issuer, "/") + "/resources/" + url.PathEscape(resource)`。

- `?source=` 不改变任何东西：`candidates` 分支（`:310-321`）只校验「源存在 + 非 retired + 声明了该资源」，
  闸门已在 `:94` 之前跑完。

**我自己的执行证据**（`internal/zzprobe/verifyfederation/scopegate_test.go`，
`TestVerifyGateAndServingSourceAreIndependent`，PASS = 报告这一半成立）：

```
gate names "phigros.profile.read" (source a's declaration); the read came from "b" with {"served_by":"b"}
source a was asked for []; source b was asked for [/resources/profile]
```

我也原样复跑了报告的探针，两条都按它说的 FAIL：

```
--- FAIL: TestZZProbeScopeGateAndServingSourceDisagree
    GET /v1/games/phigros/profile => 200, Re0Auth-Source="zz-community" ...
--- FAIL: TestZZProbePinnedSourceAdmitsAnotherSourcesScope
    GET .../profile?source=zz-community => 200 ...
```

**所以：机制是真的，不是夹具artifact。** 反空转也成立：不带令牌 → 401（`TestZZProbeGateIsActuallyConsulted` PASS），
而如果闸门改成按源判定，上面两条测试就会变绿——它**能失败**。

### 2.2 是不是被文档化的决定？（不是。而且报告的引证少了一处更关键的反证）

搜遍 `docs/`：**没有任何地方**说「同名资源在不同源上等价」。唯一写着「已知粗粒度」的是
`docs/architecture.md:466`，而且它只管 **raw**：

> 已知粗粒度处：raw 的 scope 门禁用的是「该源任一资源 scope」，专用 `<game>.raw.read` 为后续工作。

归一化资源这条路**没有**任何对应记载。`architecture.md:423` 只笼统地说「把下游对某个游戏资源的请求，
映射到一个已绑定的上游数据源」，`:434` 只说 `Fetch(...) → 选源`，`:456-457` 只讲 active/degraded/retired 仲裁。
`docs/threat-model.md` §9 的「raw 透传的边界」也只管 raw。

**但有一处文档是朝相反方向写的，报告没提**：`docs/upstream-protocol.md:188-190`

> **名称映射**：Re0Auth 的下游 scope 与数据源 canonical scope 不必同名，**映射表由 Re0Auth 的源注册表维护**。
> 已知特例：下游 `account.id` ↔ 上游 `account.read`。
> 这样下游的 scope 稳定，不受数据源差异影响。

「映射表由源注册表维护」= 每个源各自声明自己的 `{resource → scope}`，这正是**按源**的语义；
而 `Source.Resources[].Scope` 的字段注释（`federation.go:68-69`「Scope is the canonical scope that grants access to it」）
与 `bindScopes`（`:110-122`）用的都是它。所以：

- **代码只是「假设」运维会让同名资源在各源上映射到同一个 scope，并不「强制」。**
  `NewRegistry`（`federation.go:141-175`）对 `Resources[].Scope` 一个字节都不检查（见 FO-04），
  也没有任何跨源一致性检查。假设没有被写下、也没有被守护。
- 反方向也有一处反证：`docs/api-design.md:213-215` 把下游 scope 表钉成**游戏级**的
  （`GET /v1/games/phigros/me` → `phigros.profile.read`、`scores` → `phigros.score.read`），
  以及 §7 的 canonical 文法 `<game>.<resource>.<action>`（`upstream-protocol.md:173`）。
  按这套写法，**同一个资源名在两个源上本来就该是同一个 scope 串**，那时闸门的「取第一个」是无害的。

**结论（区分两种东西）**：

- (a) **运维误配置**：给同名资源声明了不同 scope。设计**容忍**它（无校验），并且在这一支上会把判据变成「随便一个源的说法」——这是本条的实质。
- (b) **用户拿到了他从未被授权访问的源的数据**：是的，但**不是别人的数据、也不是他从未连接的源的数据**（见 2.3）。
  这是「授权语义被混淆」，不是「保密性被突破」。

### 2.3 攻击者是谁、得到什么？（这一条决定严重度，我把它作为降级的主要依据）

**我尝试构造跨账号读取，构造不出来。** `Fetch` 的主体来自令牌
（`federation_routes.go:100` `account.UserID(info.Subject)`），绑定键含 user（`binding.go:231-233`
`user|game|source`），Kill Switch/解绑都按 user 或全量。跨源读取**始终限定在令牌主体的绑定集合内**。

所以攻击者是「持有某个 scope 的下游 RP」，收益是：**在它没有被注册、用户也没有为它同意过的那个 scope 上，
读到了该用户在那个源上的数据。** 关键在于这个源必须是**用户自己绑定过的**：

- 绑定的唯一入口是 `GET /bind?game=&source=`，需要登录（`federation_routes.go:302-321`），
  再把浏览器跳到**源自己的** authorize 端点（PKCE），用户在**源侧**登录并同意（`upstream-protocol.md:111-113`
  「数据源负责其终端用户的认证与同意」）。没有用户自己去源侧走一遍，就没有绑定行、也就没有可读的数据。
- 协议把这件事写成了设计本身：`upstream-protocol.md:28`「**授权粒度 = 每个 `(usr_, source)` 一次。
  同一游戏的不同源各自独立授权**」。
- 因此「跨源」的那份数据是**用户自己连接、自己在上游同意过**的数据；它不是别人的数据，
  也不是 re0auth 单方面能从别处抓来的数据。

**用户对「哪个源」有没有同意？** 这是他侧的弱点，也是我确认报告这一半的地方（细节见 **V-1**）：

- 同意页列的 descriptor 是**游戏级**的（`oauth/scope.go:144`：「通过 Re0Auth 代理读取你的 Phigros 档案（rks 等）」），
  **不点名源**。
- 同意页确实会点名源，但**只在缺绑定时**：`httpapi/authorization_routes.go:30-51` 用 `MissingBindings` 渲染
  `{game, source, display_name, bind_url}`。而 `MissingBindings`（`missing.go:54-62`）是按 **scope**
  建立的索引、按 **scope** 判断「已满足」（`:84-95`），数据面是按**资源名**判断——两套模型不一致。
  我执行出来的效果（`TestVerifyConsentPlaneNamesASourceTheReadDoesNotNeed`，PASS）：

  ```
  MissingBindings(for "phigros.profile.read") = [{Game:phigros Source:a ...}]
    consent screen says: connect "a" (A) to serve [phigros.profile.read]
  the same read, with source a unbound, is served by "b": {"served_by":"b"}
  MissingBindings(for "phigros.community.read") = [] (the source that will serve it is already bound)
  ```

  即：用户的同意页在叫他去连 a，而实际把数据交出去的是 **b**；而当被问及 b 自己的 scope 时，页面说「什么都不缺」。
  这对用户是错的模型，也正是报告「用户看不到」那半句的**唯一**成立形式（但不是经由 scope 本身，
  而是经由「scope→源」的提示）。

**所以我的严重度裁定：高 → 中。** 理由三条，都可引证：

1. **没有跨主体影响**：数据属于令牌主体、源由主体自己绑定（上面已引证）。
2. **披露是 MUST 级且已实现**：`federation_routes.go:110` 每次都写 `Re0Auth-Source`，
   `upstream-protocol.md:237-242` §10「**来源永远可见、绝不静默换源**」把 `Re0Auth-Source` 写成 MUST，
   钉源不可用时必须 `503` 不得替换。调用方**总能**知道是谁答的（这一条**减轻**但**不能消除**问题：
  它让替换可被下游察觉与拒绝，但不会让 RP 在读到数据前获得拒绝的机会——数据已经交出去了）。
3. **可读性由 schema 契约收紧**：`upstream-protocol.md:194-198` 钉了规范化 schema
   （`re0auth.<game>.<resource>/<major>`），`api-design.md:201-204` 说实现层只校验 JSON、
   schema 由契约保证。所以报告影响 #2 里「两个源对同名 `profile` / `scores` 的**语义、schema** 可以完全不同」
   **被削弱**：同名资源在不同 schema 上声明本身就是违约；真正不同的是**数据集与处理者**（谁的副本、谁的合规级别）。

**同时，报告漏掉了一条对我上述降级不利的事实，我把账补上**：同一处闸门在反方向是**功能缺陷**。
持有**后一个源**所声明 scope 的令牌会被拒绝——即使那个源正是会服务它的源。
我把报告自己那半截探针（`TestProbeScopeGateRefusesTheBoundSourcesOwnScope`，它只 `t.Logf`、从不断言）补成断言，
并把我实测到的另一面写进 V-2。一个「两个方向都判错」的闸门，不是简单的「粗粒度」。

### 2.4 `Re0Auth-Source` / `Re0Auth-Degraded` 是否让替换可见？（是，且这是规范要求）

- `federation_routes.go:110-113`：成功路径无条件写 `Re0Auth-Source`；被跳过的首选源写 `Re0Auth-Degraded: true`
  （`service.go:232-241` 的 `result.Degraded = i > 0`）。
- `upstream-protocol.md:237-242` 把这条写成 MUST，并把「下游指定了源 → 该源不可用 → `503` **不得替换**」
  也写成 MUST，实现一致（`service.go:310-321` 永不替换钉源）。
- 判定：**它把「静默换源」变成「可见换源」，从而降低但不消除严重度**。降低是因为下游可审计 / 可拒绝继续；
  不消除是因为数据在被判定之前已经交给调用方，而 RP 没有在读取前拒绝的机会。

### 2.5 探针反空转？（FO-01 的两条探针通过这一检查；但另有一条探针自带错误断言）

- `TestZZProbeGateIsActuallyConsulted`（无令牌 → 401）成立，说明带令牌的 200 不是「闸门从来没跑」。
- 两条 FAIL 的断言会在**正确实现**下变绿（判据真的改成按源），所以不是「断言了个恒真的事」。
- 但必须记下：**同一个探针包并不是全绿的**——`TestZZProbeKillSwitchRequiresAnOperator` 报
  `an unauthenticated kill switch was answered 404, want the documented 401` 而 FAIL。
  代码给的是 404（我复跑确认），报告正文也说 404 是正确形态，`docs/admin.md:27,125` 只把 404 写成文档行为，
  BRIEF §5 也把这条列为文档化决定。所以这是**探针里一条与正文自相矛盾的过期断言**（见 V-3）。

---

## 3. 逐条：我降级或推翻的理由

### 3.1 FO-02：现象是**已记录的残余**，而它的探针根本没测到那件事，注释批评也打偏了

**(a) 现象已被文档化，按 BRIEF §5 不是发现。** BRIEF §5 的「不得报告（文档化决定）」清单里明列
**「跨实例 refresh 的残余竞态」**。代码侧同样写着，而且写的**正是**「vault 留下密钥」这一侧——
`internal/federation/refresh.go:106-110`：

> And a refresh racing an Unbind resurrected the secret of a binding that had just been removed: the row was
> gone so the swap failed, but the vault write had already happened, leaving a decryptable token that **ListAll
> cannot see, the Kill Switch cannot reach again, and only an account erasure clears**.

`internal/lifecycle/lifecycle.go:163-165` 又把这个后果写成抹除路径的存在理由：

> Vault. Any credential left after the binding sweep — **a leftover from an already-unbound source**, or a
> provider that is not a federation binding — goes here.

报告自己在第 113-114 行也承认「与 BRIEF §5 已记录的残余是同一竞态的另一侧后果」，然后用「那条记的是绑定被误删、
这条记的是密钥被留下」来分家——但 §5 的措辞是泛指的「残余竞态」，而 `refresh.go:106-110` 记的恰好就是「密钥被留下」。
所以这不是新后果，**是同一残余的另一半，而且那一半在代码里写着**。

**(b) 它的探针没有测到它说的那件事。** 报告的机制是「赢下 CAS *之后*、写 vault *之前* 行被删」。
但 `frozenStore.PutIfVersion`（`internal/zzprobe/federation/lifecycle_test.go:200-208`）的执行顺序是
**先跑 hook（删行）再调用真实 `PutIfVersion`**，于是内存实现的 CAS 看到「行不存在」
（`binding.go:188-198`：`if !ok || existing.Version != expectedVersion { return false, nil }`）
→ `won=false` → `refresh.go:115-120` 走「别人赢了、**不许碰 vault**」那一支 → `storeBindingSecret` **根本不会被调用**。

我自己加了仪表重跑这个交错（`TestVerifyReportedFO02ProbeIsNonDiscriminating`，PASS）：

```
CAS won=false (false means the refresh never reached its vault write)
row present=true vault secret present=true content=map[access_token:old-access refresh_token:old-refresh]
the audit's predicate `gerr != nil && exists` is TRUE with no service call at all: its FAIL is produced by the fixture, not by the refresh
```

即：探针看到的那条「vault 里还有密钥」是**夹具自己在 `:251` Enroll 的那条**（内容仍是 `old-access`，refresh 一个字都没写），
而它命中的谓词 `gerr != nil && exists` 在**完全不调用服务**的夹具上也为真。**这正是 VERIFY-BRIEF §1 说的
「夹具制造了失败」+「断言在正确实现上也会失败」**。报告把它写成「实测（执行过，FAIL）」并据以宣布 CONFIRMED，
证据不成立。

**(c) 「`refresh.go:122-127` 的注释对它的自评是错的」——打偏了。** 那段注释的语境是
`storeBindingSecret` **返回错误**（vault 写失败），不是「行被删」：

```go
if err := s.storeBindingSecret(ctx, updated, rotated); err != nil {
    // The row now describes a rotation whose secret was not stored. That is a
    // broken binding rather than a silent divergence: the next call presents
    // the old token, is rejected, and the rejection path cleans up. ...
```

在这个语境里「行还在」，所以「下一次调用会被拒、并清理」是**真的**。我用一个「第一次 Enroll 必败」的 vault
包装器把这条路径跑通（`TestVerifyCommentCaseSelfHeals`，PASS）：

```
after the failed vault write: err=verify: simulated vault write failure row present=true version=12
after the next call: err=federation: phigros/src is not bound row present=false vault present=false refreshes=3
```

即：写失败后行还在（version 已被 CAS 推到 12）→ 下一次调用拿旧令牌 → 401 → 强制刷新 → `invalid_grant`
→ `refreshRejected`（`refresh.go:142-163`）重读发现版本没动 → `vault.Revoke` + `bindings.Delete`
→ `NotBoundError`，**密钥与行都清掉了**，用户回到「引导绑定」。注释的自评在这一支上是**准确**的。

**(d) 现象本身我确实复现了——用一条**正确**的探针，它把结论钉在正确的窗口上。**
`TestVerifyOrphanSecretIsReachableOnlyByErasure`（PASS）把 hook 放在 **CAS 返回 true 之后**，
并按生产路径的顺序删（先 `vault.Revoke` 再 `store.Delete`，即 `unbind.go:91` → `:94`）：

```
CAS won=true fetch err=<nil> row present=false vault present=true content=map[access_token:rotated-access refresh_token:rotated-refresh]
REPRODUCED: the refresh wrote a secret after its row was deleted, and the secret is the ROTATED one
Unbind on the orphan: {Upstream:nothing UpstreamError:}
after Unbind the orphan secret is STILL in the vault: no endpoint reaches it
Kill Switch summary on an orphan-only deployment: {Total:0 Revoked:0 Cascade:0 Unsupported:0 Unavailable:0 Orphaned:0 Failed:0}
vault.DeleteSubject removed 1 record(s); orphan still present: false
```

**所以：机制成立**（跨实例窗口下 CAS 先赢、vault 后写，确实会留下可解密的孤儿密钥），
**报告的「只有账号抹除能清」也成立**——`Unbind`（`unbind.go:53-61`：`bindings.Get` 得 `ErrNotBound` 就
`return RevocationNothingToDo`，**不碰 vault**）、`shredBinding`（`killswitch.go:204` 也在 Revoke 之前先要行）、
`CascadeRevoke`（`revocation.go:124`）、`ListAll`/`ListAllPage`（`binding.go:237-275`、`postgres/federation.go:95-126`：只从 store 枚举）
四条路都到不了；而 `lifecycle.go:197` 的 `Vault.DeleteSubject`（按 subject 删整行）到得了。
按 VERIFY-BRIEF 的说法：这是**「抹除前的孤儿」**，不是「永久残留」。

**(e) 严重度：中 → 提示。** 判据来自 VERIFY-BRIEF §3 的三问：
前提是「**两个实例共享一个库**、且另一个实例的解绑恰好落在赢家 CAS 与 vault 写之间的**微秒级窗口**里」——
`refresh.go:111` 与 `:121` 之间只有一个 `if` 语句，中间没有 I/O；进程内的解绑/抹除路径全部持同一把
per-binding 锁（`refresh.go:40-41`、`unbind.go:50`、`killswitch.go:201`、`revocation.go:121`），
所以**进程内根本不可达**，只有跨实例（或多实例 + 库层直接删）才可达。
后果是一个 API 完全触不到的密文，且抹除路径能清；**没有静默失败**（`storeBindingSecret` 的错误被返回、
metrics 记 `RefreshTransient`），因此不适用「静默 ⇒ 升」。报告的 `中` 与这份账不匹配，我给**提示**。

### 3.2 FO-03：谓词缺口成立，但**可利用性被本机实测削弱**，且引证有两处不准

- **谓词侧 CONFIRMED（我执行）**：`httpclient/outbound.go:117-128` 的 `nonPublicPrefixes` 列了
  `100.64.0.0/10`、`192.0.0.0/24`、`192.0.2.0/24`、`198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、
  `240.0.0.0/4`、`64:ff9b::/96`、`2001:db8::/32`、`2002::/16`，**没有 `0.0.0.0/8`**；
  `IsPublicAddress`（`:138-153`）先 `Unmap()` 再 `IsGlobalUnicast()`，于是：

  ```
  IsPublicAddress(0.0.0.0) = false   IsPublicAddress(0.0.0.1) = true   IsPublicAddress(0.1.2.3) = true
  IsPublicAddress(0.255.255.255) = true   IsPublicAddress(::ffff:0.1.2.3) = true
  IsPublicAddress(127.0.0.1) = false   IsPublicAddress(169.254.169.254) = false   IsPublicAddress(8.8.8.8) = true
  ```

- **可利用性：报告标 HYPOTHESIS 是对的，但它假设的方向比现实更糟。** 我在本机（Windows 11）用真实客户端跑了：

  ```
  raw dial 127.0.0.1  -> CONNECTED to the loopback listener
  raw dial 0.0.0.0    -> CONNECTED to the loopback listener
  raw dial 0.0.0.1    -> refused/failed: connectex: A socket operation was attempted to an unreachable network.
  raw dial 0.1.2.3    -> refused/failed: connectex: ... unreachable network.
  raw dial 0.255.255.255 -> refused/failed: connectex: ... unreachable network.
  guarded GET http://0.1.2.3:PORT/probe -> refused: dial tcp 0.1.2.3:... unreachable network   ← 是内核拒绝，不是闸门
  guarded GET http://127.0.0.1:PORT/probe -> refused: httpclient: refusing to connect to 127.0.0.1 (闸门拒绝)
  ```

  读数很清楚：**闸门确实放行了 `0/8` 地址**（错误来自网络层而不是 `httpclient` 的拒绝文本），
  但**本机内核不给路由**。而唯一能打到本机回环的字面量 `0.0.0.0` 已经被 `IsUnspecified` 挡下
  （`IsGlobalUnicast()` 对 unspecified 为 false）——也就是说「0/8 里真正危险的入口恰好不在缺口里」。
  所以这一条在 Windows 上是**不可利用**；在 Linux 上（`ip_route_output` 对 0/8 的 loopback 分支）我无法执行，
  仍是不确定。**要证实它需要什么**与报告一致：一台 Linux 主机 + 一个本机监听 + `dial 0.1.2.3:port`。
- **两处引证不准**：(i) 报告说 `docs/architecture.md:310-312` 把它说成一条完整性质——原文是
  「**私网 / 环回 / 链路本地地址**在拨号层拒绝」，只列三类（`0/8` 三类都不属），
  「完整性」的说法实际出自 `outbound.go:42-48`（"refuses a connection whose resolved address is not public"）；
  (ii) 「同类块都列了、所以这是遗漏」成立（`192.0.0.0/24`/`240.0.0.0/4`/`100.64.0.0/10` 确实在表里），
  这一条我不推翻。
- **重复**：同轮的 `round5-report.md:62` R5-8 已经收了同一条（「`IsPublicAddress` 接受 `0.1.2.3`（0/8）、
  `192.88.99.1`」）。所以 FO-03 对主代理不再是新信息；`192.88.99.1` 报告自己排除，我同意（RFC 7526 已弃用且与本服务威胁模型无关）。
- **严重度**：谓词 低；可利用性 提示（不可利用于本机实测的平台，Linux 未知）。不升。

### 3.3 FO-04：事实成立，但两个子论据被推翻，且**降级理由引证反了**

**成立的部分**（我执行到 wire，不再只是复读夹具）：

- `TestVerifyDeclaredScopeReachesTheWireWithInjectedSpaces`（PASS）——通过**生产代码**（`BeginBind` →
  `oauthConfig` → `oauth2.AuthCodeURL`）取到真 URL：

  ```
  authorize URL scope parameter = "account.read phigros.profile.read account.id phigros.score.read"
  the source is asked for 4 scope(s): [account.read phigros.profile.read account.id phigros.score.read]
  ```
  即 `resources[].scope = "phigros.profile.read account.id"` 让**一个元素带空格**，`oauth2` 把它 join 成
  **4 个 upstream scope**，源收到一个它从未声明的 `account.id`。`Source.bindScopes`（`federation.go:110-122`）
  只按整串去重、不切分，确实没拦。
- `TestVerifySourceNameShapesReachTheRedirectURI`（PASS）——`?`/`#` 让 `redirect_uri` 参数被 URL 解析成别的路径：

  ```
  name="src?x=1" -> redirect_uri=".../phigros/src?x=1/callback" ; 解析结果 ".../phigros/src"
  name="src#f"   -> redirect_uri=".../phigros/src#f/callback"   ; 解析结果 ".../phigros/src"
  ```
- `NewRegistry`（`federation.go:141-175`）只校验 `Game/Name/Issuer` 非空 + 重复键，这是**读代码到行**，
  且 `cmd/re0auth/config.go:782-786` 明说「registry 是唯一权威」，我确认无第二道校验。

**被推翻的子论据**：

1. **「键空间可碰撞（`("../..","src")` 与 `("..","../src")` 都是 `../../src`），所以重复源拒绝对畸形输入不构成保证」**
   —— 反了。两个都配进去时 `NewRegistry` 直接拒绝（我实测：`registering both colliding pairs ->
   federation: duplicate source ../../src`）；而**请求路径根本走不到别名**，因为闸门先做 game 查找：
   `Fetch(game="..", source="../src")` → `federation: unknown game`（`ResourceScope` 用 `Sources(game)`，
   而该源注册在 game `"../.."` 下）。我用 `TestVerifyCollidingSourceKeyHasNoRequestPath` 把两步都做了。
   `sourceKey` 只是「game + "/" + name」的拼接，它不是安全边界，也不需要是。
2. **「用户看不到被索取的上游 scope」** —— 被 `upstream-protocol.md:111-113` 削弱：数据源**负责它终端用户的
   认证与同意**，请求里的 scope 集合就出现在**源自己的**同意页上。所以这不是「静默扩权」，
   而是「re0auth 侧的配置错误被推迟到源的同意页暴露」——仍然是配置校验缺口，但不是静默的。
3. **降级理由引证反了**：报告（第 197-198 行）说「威胁模型把操作者列在信任边界之外（B6）」。
   `docs/threat-model.md:57` 的 B6 原文是 `| B6 | 运营者 / 内部人员 | 公共实例的最高权限 | **不受信任**，最小权限 + 全程审计 |`
   ——运营者是**在**模型里、被当作**不可信**的一方；§9 还给了治理手段（透明度报告、第三方审计、密钥多人控制，`:235`）。
   所以「运维配置」这条路既不是自动豁免，也不是自动高危；正确的说法是：
   运营者**本来就可以重配整个源注册表**，所以「畸形 name/scope」的边际收益小——这才是不升级的理由，
   而不是「他不在威胁模型里」。

**报告未提、但同类更该报的一条**：`NewRegistry` 连 `Issuer` 的 scheme/host 都不校验
（`federation.go:151` 只做 `TrimRight(s.Issuer, "/")`），只有 `RawBase` 有 `validateRawBase`（`:191-204`）。
报告在残余盲区 #5 里把这点写成「不校验 `Issuer` 的 scheme/host **之外**」，读起来像校验过 scheme/host，**表述错误**。

**严重度**：提示（配置校验/加固，无远程路径），与报告一致；`NewRegistry` 只校验非空这一事实同轮的
`config-startup-disclosure.md:158-160`（CS-4）已记录，FO-04 的新增部分是 `game`/`name`/`scope` 三个实例。

### 3.4 FO-05：成立，但**已经有人报过同一件事**

- 事实面我逐条核过：`grep -rn "Retry("` 只有 `cmd/referencesource/main.go:143`（+测试）；
  `cmd/re0auth/main.go:459-475` 的 `federationClient` 是
  `NewOutboundClient(OutboundConfig{Timeout, MaxConcurrent, Breaker, Transport})`——
  `OutboundConfig`（`httpclient/outbound.go:247-259`）**根本没有 Retry 字段**，装饰链是
  `Transport → Bulkhead → CircuitBreaker`（`:304-321`）。所以 `Retry` 具体没装，而 `httpclient` **装了**
  （pool + bulkhead + breaker + 地址闸门），任务里问的那个区分我确认了。
- **那句话讲的是谁**：`docs/source-onboarding.md:220-230` 的表头是「## 4. Re0Auth **会给源什么** / What Re0Auth gives back」，
  同一行的其它条目（稳定域名、每用户归因、凭据不外泄、一处撤销）全是「re0auth 提供给源的行为」，
  且这一行还自带一句自我修正「**当前没有响应缓存或 singleflight，旧文档的这项承诺并未实现**」——
  作者已经在这张表里纠正过过期承诺。所以「出站连接池 + 并发上限（bulkhead）+ **指数退避重试**」
  确实是**re0auth 自己的出站承诺**，实现里缺了第三项。是文档与实现不一致，不是误读。
- **但**：同轮的 `performance.md:112-113` 已经写了「附带澄清：…`httpclient.Retry` 只有
  `cmd/referencesource` 用（`grep -rn "httpclient.Retry("`），re0auth 的出站客户端没有包重试」。
  FO-05 的新增信息只有「文档那一行」这一半。另外 `docs/resilience-decision.md:37` 的「明确不做」一节
  确实没有「数据面不重试」的说明，报告建议补一句是合理的。
- 我**不同意**报告「不加重试是对的」里的一条推断细节，但它不影响结论：数据面并非全不可重放
  （`fetchResource` 是 GET，`httpclient.Retry` 本来就只重试幂等方法），真正不可重放的只有
  token 交换与撤销；所以「因为不可重放所以不加重试」这句话过宽，正确理由是「读取路径已有熔断 + 上层单次重试语义就够」。
  严重度 提示，维持。

### 3.5 FO-06：成立，且比报告写的更彻底；但它的「无探针」论断是错的

- 三处控制流我读到的就是报告说的：`killswitch.go:56-74` 的 `return summary, err`（注释在 `:59-63` 明说
  「a partial sweep is never presented as a complete one」）；`admin.go:345-362` 的
  `if err != nil { s.record(... OutcomeError ...); return rep, err }`（**`rep.Bindings` 保持 nil**）；
  `admin_routes.go:281-282` 的 `default` → 500 `internal_error`，body 无计数。
- **我把它执行了**（报告说这条「无探针，需要 DB」，所以没跑）：
  `internal/zzprobe/verifyfederation/killswitch_test.go::TestVerifyPartialKillSwitchSummaryIsDiscardedByTheOperatorPlane`
  （PASS）。探针只用一个实现 `BindingStore`+`BindingPager` 的测试 store（`failAt: 3`、`KillSwitchPageSize: 2`、5 条绑定，
  每条都有 vault 秘密、源有 revocation 端点），**不需要数据库**：

  ```
  federation.RevokeAllBindings after page 3 failed: summary={Total:4 Revoked:4 ...} err=verify: page fetch failed
  bindings already cut and no longer listed: 4 of 5; still present: 1
  admin.KillSwitch: err=verify: page fetch failed report.Bindings=<nil>
  audit row: outcome=error detail=map[actor:usr_admin tokens_revoked:0]
  the audit chain does NOT carry the partial counts: only map[actor:usr_admin tokens_revoked:0]
  ```

  所以：(i) 报告的三条控制流断言全部成立；(ii) **补充**：那 4 个计数**也不在审计链里**
  （`admin.go:356-358` 只写 `tokens_revoked`），即「连事后补都对不出来」，比报告说的更彻底；
  (iii) 报告「建议守卫但需要 DB」不成立——`BindingPager` 是从 `Bindings` 做类型断言拿的
  （`killswitch.go:44`），一个同时实现两个接口的测试 store 就够了，这条**可测性缺口不存在**。
- **一处引证要改**：报告说这条是 `threat-model.md` §5 D5「如实报告」失效之处。D5（`threat-model.md:86-93`）
  说的是「源不支持/不可达**会如实报告**，不会假装成功」，部分扫描返回错误**并没有假装成功**。
  真正被破坏的性质写在代码自己那里：`killswitch.go:59-63`「部分不能当成全部」以及报告引的
  「也不能被当成什么都没做」。不要把它挂到 D5 上。
- **严重度 低，维持**：失败不是静默的（500 + 审计行 `OutcomeError`），重跑幂等且是预期恢复方式
  （`docs/api-design.md:266`「每一步都幂等」）。同轮 `crypto-VERIFIED.md:31,145` 对同形状的
  「partial 计数被丢弃」也是降级到「低（信号质量）」，判据一致。

### 3.6 FO-07：成立，但我把它**执行**了，并且它的边界比报告写的更窄

- 结构面（`outbound.go:92` 的 `Proxy: http.ProxyFromEnvironment` 硬编码；`DenyPrivateAddresses` 只挂在
  `DialContext` 的 `net.Dialer.Control`，`:93-102`）我确认，并用 `TestVerifyProxyGuardJudgesTheProxyNotTheTarget`
  （PASS，`HTTP_PROXY` 在 `TestMain` 里装好——`ProxyFromEnvironment` 每进程只解析一次环境）把它跑成事实：

  ```
  guard ON,  target http://10.0.0.5/secret, proxy 127.0.0.1:PORT
    -> Get "http://10.0.0.5/secret": proxyconnect tcp: dial tcp 127.0.0.1:PORT:
       httpclient: refusing to connect to 127.0.0.1:PORT: 127.0.0.1 is not a public address
  guard OFF, target http://10.0.0.5/secret -> 200 proxy-saw-target
  the proxy received: [http://10.0.0.5/secret]
  ```

  即：**闸门判的是代理的地址**（拒绝文本里是 `127.0.0.1`，而请求 URL 是 `10.0.0.5`），
  而在闸门关闭时目标地址**完全不经过任何检查**。报告的结构论断成立，且它的
  「代理在私网 ⇒ 其实是 fail-closed」这句自我更正才是对的（报告第 280-281 行的
  「`HTTPS_PROXY=http://10.0.0.5:3128` 通过闸门」与紧接着的括号互相矛盾，**应以更正为准**）。
- **前提有多现实**：`grep -rn "(?i)http_proxy|https_proxy|no_proxy"` 在**整个仓库**只命中被复核的报告本身——
  `Dockerfile`、`deploy/k8s/**`、`.github/workflows/**`、`config/*.toml` 都没有设置代理变量。
  所以「部署会设 `HTTP_PROXY`」不是任何本仓库产物造成的现状，前提就是「有人能改进程环境」。
  报告自己也把收益限定在这一点（B6），我只是把 B6 的引证换成了正确的那一句（见 3.3 第 3 点）。
- 报告提到「`web/e2e/server.mjs:330` 与 CI 里 `allow_private_addresses = true`」：`web/e2e/server.mjs:330` 确有此行，
  CI（`.github/workflows/ci.yml:243-254`）确实跑该 e2e 套件，所以「CI 里」的说法成立；但那是**全部源都在本机回环的
  e2e 夹具**，不是生产姿态，不能当作「有人会打开这个开关」的证据。
- **严重度 提示，维持**（加固项；报告自己也这么定）。修法建议（把 `Proxy` 变成 `TransportConfig` 字段、
  在 `DenyPrivateAddresses` 打开时要求显式配置）我认同。

---

## 4. 我确认的（执行过的，逐条附承重输出行）

| 条目 | 我执行了什么 | 承重输出 |
|---|---|---|
| FO-01 机制 | 自己写的服务层双源 rig：`go test ./internal/zzprobe/verifyfederation/ -run TestVerifyGateAndServingSourceAreIndependent -v` | `gate names "phigros.profile.read" (source a's declaration); the read came from "b"` / `Service.ResourceScope(game, resource) has no source parameter` |
| FO-01 HTTP 面 | 原样复跑报告探针：`go test ./internal/zzprobe/federationhttp/ -run TestZZProbe -v -count=1` | `--- FAIL: TestZZProbeScopeGateAndServingSourceDisagree ... Re0Auth-Source="zz-community"`；`--- FAIL: TestZZProbePinnedSourceAdmitsAnotherSourcesScope` |
| FO-01 反空转 | 同上 | `--- PASS: TestZZProbeGateIsActuallyConsulted`（无令牌 401） |
| V-1 同意面 | `-run TestVerifyConsentPlaneNamesASourceTheReadDoesNotNeed -v` | `consent screen says: connect "a"` 而 `the same read ... is served by "b"` |
| V-2 retired | `-run TestVerifyRetiredSourceCanSetTheGate -v` | `source a is RETIRED and declares "phigros.profile.read"; the gate still requires it, and the read is served by "b"` |
| FO-02 探针空转 | `-run TestVerifyReportedFO02ProbeIsNonDiscriminating -v` | `CAS won=false` + `content=map[access_token:old-access ...]` + 无服务调用时谓词亦真 |
| FO-02 真窗口 + 可达性 | `-run TestVerifyOrphanSecretIsReachableOnlyByErasure -v` | `CAS won=true ... content=map[access_token:rotated-access ...]`；`Unbind ... {Upstream:nothing}`；Kill Switch `{Total:0 ...}`；`vault.DeleteSubject removed 1 record(s)` |
| FO-02 注释那一支 | `-run TestVerifyCommentCaseSelfHeals -v` | `row present=true version=12` → 下一次 `row present=false vault present=false` |
| FO-03 谓词 | `-run TestVerifyZeroEightPredicateGap -v` | `0.0.0.0=false, 0.0.0.1=true, 0.1.2.3=true, 0.255.255.255=true, ::ffff:0.1.2.3=true`（对照 127/10/169.254/100.64/192.0.0/240/255.255.255.255 全 false，8.8.8.8 true） |
| FO-03 可达性 | `-run TestVerifyZeroEightRoutesToLoopbackOnThisPlatform -v` | `raw dial 0.1.2.3 -> connectex: ... unreachable network`（`0.0.0.0` 连通但被 `IsUnspecified` 拦下） |
| FO-04 scope | `-run TestVerifyDeclaredScopeReachesTheWireWithInjectedSpaces -v` | `authorize URL scope parameter = "account.read phigros.profile.read account.id phigros.score.read"` |
| FO-04 redirect | `-run TestVerifySourceNameShapesReachTheRedirectURI -v` | `name="src?x=1" -> ...?x=1/callback ; 解析 ".../phigros/src"` |
| FO-04 键碰撞（推翻） | `-run TestVerifyCollidingSourceKeyHasNoRequestPath -v` | `Fetch(game="..", source="../src") -> federation: unknown game`；两对同配 → `duplicate source ../../src` |
| FO-06 端到端 | `-run TestVerifyPartialKillSwitchSummaryIsDiscardedByTheOperatorPlane -v` | `summary={Total:4 Revoked:4} err=...` / `admin.KillSwitch: report.Bindings=<nil>` / 审计 detail 只有 `tokens_revoked:0` |
| FO-07 | `-run TestVerifyProxyGuardJudgesTheProxyNotTheTarget -v` | `refusing to connect to 127.0.0.1:PORT`（闸门开）；`the proxy received: [http://10.0.0.5/secret]`（闸门关） |
| 环境（-race） | `go env CGO_ENABLED`；故意竞态控制跑 `go test -race`；随后 `go test -race ./internal/zzprobe/verifyfederation/` | `1`；`WARNING: DATA RACE`（控制，已删）；`ok ... 2.012s`（我的整包全绿） |

未改任何被跟踪文件：复核前后 `git status --porcelain` 的非 `??` 行完全一致。

---

## 5. 我未能验证的

1. **Linux 上 `0.0.0.0/8` 是否被路由到本机回环**（FO-03 可利用性的最终判定）。本机是 Windows，
   实测不可达；没有 Linux 主机、没有 Docker、没有 WSL 可用。**要证实需要**：一台 Linux + 一个本机监听，
   `dial 0.1.2.3:port` 看是否落到本机。这一条不改谓词侧的 CONFIRMED。
2. **真 Postgres 上 FO-02 的跨实例窗口是否同样可达**：`Bindings.PutIfVersion` 是单条条件 UPDATE
   （`internal/store/postgres/federation.go:55-69`，读；无 DSN），所以窗口同样存在，但「另一个实例的解绑」在真实
   事务/连接池下的时序我没有执行过。内存实现与 SQL 文本都已读到行；按 BRIEF §2 标「读；无 DB 执行」。
3. **真起两个进程**交错复现 FO-02：我用 store 钩子做确定性构造（与报告同法），因为无共享库可用。
4. **前端实际渲染**：V-1 里「用户在同意页看到什么」我只读到了 `missingBindingViews` 的响应形状
   （`authorization_routes.go:30-51`）与 descriptor 文本（`oauth/scope.go:144`），没有跑 `web/` 前端或 e2e 套件，
   所以「用户是否真的会把 a/b 混淆」这一层是读 + 推断，不是执行。
5. **报告「探过但没破的」那一大段我只抽验了两点**（重试的构造点、`IsPublicAddress` 的枚举），
   熔断/bulkhead/重定向 23 变体/raw 27 payload/令牌处理那些结论我**没有**重跑，因此本文件对它们不作背书也不作否定。
6. **`go test ./internal/httpapi/` 全绿这个前提**我没有验证（该目录仍有别的代理在飞的探针文件），
   我也没验证 `internal/zzprobe/federationhttp/` 之外是否还有别的探针包被拖红。
7. 报告 FO-01 的 HTTP 面我复跑的是**它的**探针；我自己的独立探针只到服务层
   （HTTP transport 与令牌铸造在服务层之上，我判断不改变那两条判定的位置）。若要一条完全独立的 HTTP 面复核，
   需要重写一份真 OP 装配（约 200 行），我判断边际价值低而未做。

---

## 6. 复核时顺手看到的新问题

### V-1【中】同意面与数据面对「可服务」的模型不一致：同意页会为一个不需要的源提示，却从不告诉用户实际会服务的是谁

- 证据（执行）：`TestVerifyConsentPlaneNamesASourceTheReadDoesNotNeed`（PASS）——

  ```
  MissingBindings(for "phigros.profile.read") = [{Game:phigros Source:a DisplayName:A Scopes:[phigros.profile.read]}]
  the same read, with source a unbound, is served by "b": {"served_by":"b"}
  MissingBindings(for "phigros.community.read") = []
  ```
- 机制：`missing.go:54-62` 建立的是 **scope → 声明该 scope 的源** 的索引，`:84-95` 的「已满足」判据是
  「有任意一个声明**该 scope** 的已连接源」；数据面的判据是「有任意一个声明**该资源名**的已连接源」
  （`candidates`，`service.go:325-332`）。两者在「同名资源、不同 scope」的部署里必然分叉。
- 而 `missing.go:84-85` 的注释自称这套逻辑「mirroring the data plane's **skip retired** rule」——
  它镜像的其实不是数据面的选源规则，只是一条 retired 过滤。**注释与实现说的不是同一件事**。
- 影响：用户按提示去连 a（a 从来不会服务这次读取），而真正把他的数据交出去的是 b；反向地，
  当被问及 b 的 scope 时页面说「什么都不缺」。这是**用户可见的误导**，也是 FO-01 里「用户没有同意到那个源」
  唯一站得住的形式。它不依赖跨源混淆是否成立——即使闸门改成按源判定，这套提示逻辑仍然是错的。
- 修法建议（涉及裁定）：让 `MissingBindings` 与 `candidates` 用同一个「资源名 → 源」的判据，
  或在同意页明确写出「本次读取可能由 A、B 中任一已连接源提供」。

### V-2【中】闸门可以被**已 retired 的源**决定；退役一个源会静默改变另一个源的授权判据

- 证据（执行）：`TestVerifyRetiredSourceCanSetTheGate`（PASS）——
  `source a is RETIRED and declares "phigros.profile.read"; the gate still requires it, and the read is served by "b"`。
- 机制：`ResourceScope`（`service.go:206-213`）遍历 `registry.Sources(game)` 时**不看 `Status`**，
  而 `candidates`（`:326-328`）跳过 retired。所以「判据来自一个永远不可能被选中的源」是可达的。
- 影响：把一个源标记为 `retired`（运营者以为这是「下线」）会**改变别名的授权判据**：
  如果退役的正好是名字最小的那个声明者，下一个源声明的 scope 就变成了新的必需 scope，
  于是**已经签发的、针对旧 scope 的令牌全部变成 403**（`federation_routes.go:94-97`），
  而那个正在服务请求的源本身没有任何变化。反之，任何一次「谁排在前」的变化都会静默移动这道闸门的判据。
- 与 FO-01 的关系：FO-01 说的是「闸门与选源可以指向不同的**源**」，V-2 说的是「闸门甚至可以指向一个
  **不可服务的**源」——同一个根因（判据取自一个与选源无关的遍历），但触发方式不同、且不需要运维配两个不同 scope。
- 修法建议：`ResourceScope` 至少要与 `candidates` 用同一条「非 retired」过滤；彻底的做法是 2.1 里的判定 A。

### V-3【方法】报告的探针包**不是全绿的**，其中一条失败断言与报告正文自相矛盾

- `go test ./internal/zzprobe/federationhttp/ -run TestZZProbe -v -count=1` 的输出里有第三条 FAIL：
  `TestZZProbeKillSwitchRequiresAnOperator` →
  `an unauthenticated kill switch was answered 404, want the documented 401`。
- 但代码给 404（我复跑确认），报告正文（第 474-476 行）把 404 说成正确形态，`docs/admin.md:27,125` 只写了 404，
  BRIEF §5 也把这条列为文档化决定。所以失败的是**断言**，不是代码。
- 影响：报告用「实测」支撑的若干结论里，至少这一处是未清理的中间态；主代理若把这些探针留作守卫，
  必须先修掉它，否则守卫生来就是红的（红守卫 = 无守卫）。

### V-4【方法】「无 cgo / `-race` 跑不了」不成立（已见 §0 修正 2）

- 证据：`CGO_ENABLED=1`、`gcc 16.1.0`；`go test -race ./internal/zzprobe/verifyfederation/` → `ok 2.012s`；
  故意竞态控制 → `WARNING: DATA RACE` 后删除。
- 影响（对报告成立的强度）：报告残余盲区 #2 把「`keyedMutex` 的 refcount 回收没有丢锁」「Kill Switch 8 个 worker
  的计数合并」这类**并发论断**的责任推给了环境。环境是允许的，所以这些论断目前只是**没人验**，
  不能算「受环境限制而只能读到行」。`round5-report.md:105` 也把 `-race` 写进残余盲区（同为误判），
  主代理应把这两处一起改掉。

### V-5【提示】`upstream-protocol.md` §7 宣称存在「下游 scope ↔ 数据源 canonical scope 的映射表」，实现里没有

- 文档（`upstream-protocol.md:188-189`）：「Re0Auth 的下游 scope 与数据源 canonical scope **不必同名**，
  **映射表由 Re0Auth 的源注册表维护**。已知特例：下游 `account.id` ↔ 上游 `account.read`。」
- 实现：`bindScopes`（`federation.go:110-122`）把资源 scope **原样**发给源，
  我执行 `BeginBind` 取到的 authorize URL 里 `scope=account.read phigros.profile.read account.id phigros.score.read`
  （`TestVerifyDeclaredScopeReachesTheWireWithInjectedSpaces` 的 `%q` 输出）——**下游用的是同一个串**。
  唯一实现出来的映射就是那个**硬编码**的特例（`:113` 的 `"account.read"`）。
- 影响：文档让源运营者以为可以给自己的资源起与下游不同的 canonical 名字，实际不能；而
  `docs/upstream-protocol.md:173-177` 又说 re0auth 自己的 catalogue 只要求两段，于是**同一串**既当下游 scope
  又当上游请求的 scope，两侧的文法约束却不同（FO-04 的空白注入正是从这里漏出去的）。
- 与 FO-01 的关系：这条是 FO-01「按源声明 scope 到底意味着什么」在文档层面的另一半——
  文档说有映射表（听起来像按源），代码里没有映射（一串两用）。建议要么实现映射，要么把这两句改掉。

---

## 7. 我对严重度的最终意见（一句话汇总）

FO-01 仍然值得在上线前处理（它是本轮**唯一**同时满足「新、可执行复现、破坏授权判据」的条目），
但它是**中**不是**高**：数据是主体自己的、源是主体自己绑的、来源是 MUST 级披露的，前提是运维为同名资源
声明了不同 scope（而 canonical 文法本该让这种事不发生）。真正让它是「必须修」而不是「加固」的理由，
不是保密性，而是 2.3 末尾那条：**同一道闸门在两个方向上都判错**——它放行另一个源的数据，
同时拒绝那个源自己的 scope。修法建议里我倾向报告列的**判定 A（按源判定）**：
它同时消灭 V-2，且与 `federation_routes.go:110` 已经在响应头里公布的那个「实际服务的源」一致。
