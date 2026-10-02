# 联邦数据面与全部出站 HTTP 审计报告

## 范围与方�?
**范围**：`internal/federation/`（全部文件，含工作树未提交的 `unbind.go`）、`safeurl/`�?`httpclient/`、`upstreamkit/`（含 `conformance/`）、`referencesource/`、`cmd/referencesource/`�?`internal/httpapi/{federation_routes.go,binding_routes.go}`、`cmd/re0auth/` 的客户端装配�?`idp/`（re0auth 作为 RP �?IdP 调用�?JWKS 拉取）�?
**方法**：全部以真实入口驱动。探针分两个包：

- `internal/zzprobe/federation/` —�?纯服务层、`httpclient`、`vault`、`netip` 层探针，无外部依赖�?- `internal/zzprobe/federationhttp/` —�?�?`httpapi.New` + �?OP handler 起真�?HTTP 面，
  令牌�?*真的** authorize �?callback �?token 流程铸出�?
> **为什么拆成两个包**：`internal/httpapi` 目录下同时有另外两个审计代理�?`zzprobe_*_test.go`（在飞的写入），
> 期间该包一度因 `zzprobe_adminpriv_test.go:3: illegal UTF-8 encoding` 无法编译，把所有依赖它的探针一起拖红�?> 拆包�?HTTP 层探针可以独立跑，其余探针不受影响�?
**跑过的命�?*�?
```sh
go test ./internal/zzprobe/federation/ -run TestProbe -v -count=1
go test ./internal/zzprobe/federationhttp/ -run TestZZProbe -v -count=1
```

**跑不了的**�?
- **�?Postgres**：`PutIfVersion` / `ListAllPage` 的落盘侧语义（行�?CAS、`FOR UPDATE`�?*只读代码到行**，标注为「读；无 DB 执行」�?- **�?`-race`**：本机未�?cgo，并发论断没有竞态检测器背书。本轮所有并发结论都来自**确定性交�?*（`frozenStore` 钩子），不是靠跑得多�?- **�?Linux**：`0.0.0.0/8` 能否路由到本机回环是**内核行为**，本机（Windows 11）无法执行验证，FO-03 因此明确标注 HYPOTHESIS�?
---

## 发现

### FO-01 归一化资源的 scope 闸门取自「第一个声明该资源的源」，数据却来自另一个源

- 严重�? **�?*
- 类别: 安全
- 不变�?性质: **授权判据与被授权的对象必须是同一�?*（scope �?�?�?数据）。此处是 scope �?�?A，数�?�?�?B�?- 证据:
  - `internal/httpapi/federation_routes.go:89` —�?闸门问的�?`s.federate.ResourceScope(game, resource)`�?    `internal/federation/service.go:206-213` 的实现是**按名字顺序遍历该 game 的源，返回第一个声明该资源的源�?`Scope`**�?  - `internal/federation/service.go:305-335`（`candidates`）—�?真正被读的源�?*绑定**�?*状态排�?*决定�?    与上面那个「第一个声明的源」没有任何关系。闸门只�?`resource` 这个名字，不看源的身份�?  - 实测（执行过，FAIL）：
    ```
    GET /v1/games/phigros/profile => 200, Re0Auth-Source="zz-community",
      body={"served_by":"zz-community","note":"community data"}
    source aa-official was asked for: []
    source zz-community was asked for: [/resources/profile]
    ```
    令牌是用 `scope=phigros.profile.read` 铸出的——那�?`aa-official`（官方源）声明的 scope�?    也是�?client **唯一**注册到的 scope；调用者只绑定�?`zz-community`（社区源），
    �?`zz-community` 为同一个资源名声明的是 `phigros.community.read`�?  - �?`?source=zz-community` 明示要社区源，结果同样是 200（第二条探针 `TestZZProbePinnedSourceAdmitsAnotherSourcesScope`）�?  - 反空转对照：同配置下不带令牌 �?401（`TestZZProbeGateIsActuallyConsulted` PASS），
    �?`ResourceScope()` 在服务层确实返回 `"phigros.profile.read"`（`lifecycle_test.go:124` 日志）�?- 状�? **CONFIRMED**
- 影响: 具体到「能做什么」—�?  1. **运营者的 scope→资源约束失�?*：运营者注册一�?RP �?`phigros.profile.read`，本意是「它只能读官方源的档案」�?     实际上只�?*受害者（�?RP 的用户）额外绑定了任意第二个声明同名资源的源**，这�?RP 就能读走第二个源的数据�?     攻击者不需要新的权限，只需要受害者多连了一个源（`GET /v1/sources` 是公开的，攻击者能列出所有源并挑一个名字排序靠前的）�?  2. **跨源数据混淆**：两个源对同�?`profile` / `scores` 的语义、schema、合规级别可以完全不�?     （官方源 vs 社区源；或同一运营方的生产�?vs 测试源）。下游拿到的是它没有被授权的那一份�?  3. **可预测且可武器化**：选哪个源�?`name` 字典�?+ `Status` 决定，攻击者可以据公开�?`/v1/sources` 反推�?     并用 `?source=` 把它钉死（第二名探针证明钉源不改判据）�?- 修法建议�?*涉及裁定，因为两种修法语义不�?*�?
  - 判定 A�?*闸门改成按源判定** —�?`handleGameResource` 先解析出「将要服务的源」（未钉源时�?`candidates` 顺序取第一�?    已绑定的），再用该源自己�?`Resource.Scope` 去查令牌。语义：令牌授权「某个源的这个资源」�?  - 判定 B�?*闸门保留按资源判定，但要求令牌持有所有候选源�?scope**（未钉源时的并集）�?    语义：令牌授权「这�?game 的这个资源概念」，代价是加源会抬高对下游的 scope 要求�?  - 无论哪种，`Fetch` 返回�?`result.Source` 都应参与判据，而不是只出现在响应头里�?  - 这是一�?*独立的裁�?*，本轮只记录不顺手改�?- 复现/守卫: `internal/zzprobe/federationhttp/scopegate_test.go`
  `TestZZProbeScopeGateAndServingSourceDisagree`、`TestZZProbePinnedSourceAdmitsAnotherSourcesScope`�?  服务层等价断言�?`internal/zzprobe/federation/lifecycle_test.go`
  `TestProbeResourceScopeComesFromOneSourceButDataFromAnother`�?
---

### FO-02 刷新赢得 CAS 之后行被删掉，vault 里留下的密钥**任何端点都到不了**，且代码注释对它的自评是错的

- 严重�? **�?*
- 类别: 安全 / 合规/隐私
- 不变�?性质: 「vault 里不该存在没有绑定行指向的、可解密的凭据」——这�?`bind.go:199-213`
  （回滚失败要 `slog.Error` + `errors.Join`）、`refresh.go:106-110`、`unbind.go`、`killswitch.go`
  （`shredBinding`）四处都在守的同一条�?- 证据:
  - `internal/federation/refresh.go:111` �?`PutIfVersion`（赢），`:121` �?`storeBindingSecret`�?    两者之间若绑定行被另一个进程删掉，vault 里就留下一个孤儿密钥�?  - `refresh.go:122-127` 的注释把这件事定性为：「That is a broken binding rather than a silent divergence:
    **the next call presents the old token, is rejected, and the rejection path cleans up**.�?    **这句话是错的**：行已经不存在了，下一次调用在 `trySource` �?`bindings.Get`
    （`service.go:279-285`）就撞上 `ErrNotBound`，走的是 `NotBoundError`�?*永远不会**�?`refreshRejected`�?  - 实测（执行过，FAIL）：
    ```
    fetch err after the row vanished mid-refresh: federation: source is not bound
    row present: false; vault secret present: true
    ```
    （探针用 `frozenStore` �?`PutIfVersion` 之前删行，确定性构造「CAS �?+ 行消失」这个交错。）
  - 残留的可达性，逐条读过：`ListAll`/`ListAllPage`（`binding.go:237-275`）只�?**store** 枚举，看不到 vault 行；
    `revokeBinding`（`killswitch.go:160-169`）先 `registry.Get`，源还在，于是走 `CascadeRevoke`/`Unbind`�?    两者都�?`bindings.Get` 开�?�?`ErrNotBound` �?`failed:1`�?*不会**碰那条密钥；
    `Unbind` 同理�?`:53` 就因�?`ErrNotBound` 返回 `nothing`；用户侧无任何端点。只有账号抹除能清�?- 状�? **CONFIRMED**（本进程可构造的等价交错已复现；**跨进�?*版本读代码到行—�?  `BindingStore.PutIfVersion` 的内存实现与 Postgres 实现的「行不存在即返回 false」都已核对）
- 影响: 一�?*可解密的源令�?*无限期留�?vault 里，既不�?`SessionRevocationSummary`、也不进
  `ListAll` 的扫描面，运营者的 Kill Switch 事后**无法证明**它不存在。这�?  `threat-model.md` §6「任一侧数据库单独泄露 �?无法解密」不冲突（KEK 仍需要）�?  但破坏了本项目自己反复声明的那条「没有行指向的密钥不是可接受的残留」�?  �?BRIEF §5 已记录的残余（两个进程在赢家落库前都判凭据已死）**是同一竞态的另一侧后�?*�?  那条记的是「绑定被误删」，这条记的是「密钥被留下」，而代码对后者的自评是错的�?- 修法建议: 最小改法是�?`refresh.go:121` �?`storeBindingSecret` **之前或之�?*加一次行存在性检查：
  写成 vault 之后�?`PutIfVersion`/`Get` 复核，若行已不在�?`vault.Revoke` 掉刚写的密钥并返�?`ErrNotBound`�?  或者把 `storeBindingSecret` 做成「CAS 与写入同一临界区」的 store 级操作（Postgres 侧可以放进同一事务）�?- 复现/守卫: `internal/zzprobe/federation/lifecycle_test.go`
  `TestProbeRefreshVaultResidueAfterRowDisappears`�?
---

### FO-03 私网地址闸门漏掉 `0.0.0.0/8`（含 IPv4-mapped 形式�?
- 严重�? **�?*
- 类别: 安全
- 不变�?性质: 「非公网地址在拨号层一律拒绝」——`docs/architecture.md:310-312` �?  `httpclient.TransportConfig.DenyPrivateAddresses` 的注释都把它说成一条完整性质�?  且刻意选了 allow-list 形式（`outbound.go:130-137` 的注释原文：「a deny-list would have to keep up with them」）�?- 证据:
  - `httpclient/outbound.go:130-153`（`IsPublicAddress`）：�?`Unmap()`，然�?    `IsGlobalUnicast()` + `IsPrivate/IsLoopback/IsLinkLocal*/IsMulticast` + 一�?`nonPublicPrefixes` 表�?    **`0.0.0.0/8` 不在表里，且 `0.1.2.3` �?`IsGlobalUnicast()` 判为 true**�?  - 实测（执行过，FAIL）：
    ```
    4 non-public addresses pass the guard:
      ::ffff:8.8.8.8 (...) �?这条是误报，见下
      0.1.2.3 (0.0.0.0/8) was judged PUBLIC
      0.255.255.255 (0.0.0.0/8 upper edge) was judged PUBLIC
      ::ffff:0.1.2.3 (IPv4-mapped 0/8) was judged PUBLIC
    ```
    （`192.88.99.1` 也在输出里，�?6to4 中继任播已由 RFC 7526 弃用、且与本服务的威胁模型无关，**不作为发�?*�?    `::ffff:8.8.8.8` 是我探针里写错的一条——它**应该**是公网，`Unmap()` 后判 PUBLIC �?*正确**行为。）
  - 那张 `nonPublicPrefixes` 表（`:117-128`）列�?`192.0.0.0/24`、`240.0.0.0/4`、`100.64.0.0/10`
    这些**同类**的「不是公网但 `netip` 不认为是特殊地址」的块，却漏�?`0.0.0.0/8`——所以这是遗漏，不是有意取舍�?- 状�? **HYPOTHESIS**（谓词侧�?CONFIRMED 的执行结果；**可利用性未验证**�?- 影响（精确到我能证明与不能证明的�?
  - 能证明：`DenyPrivateAddresses=true` 时，`http://0.1.2.3/` 这种 URL 会被放行到拨号层�?  - 不能证明（本机是 Windows，无 Linux 可执行）：在 Linux �?*目标地址落在 `0.0.0.0/8` 时内核把它路由到本机回环**
    （Linux �?`ip_route_output` �?`0/8` �?`ip_route_output_slow` �?loopback 分支），
    于是这等价于�?`127.0.0.1`�?*要证实它需要什�?*：一�?Linux 主机 + `ssh -L`/本地服务�?    然后 `curl --interface` 或直�?`dial 0.1.2.3:port` 看是否落本机；或�?    `net.Dial("tcp","0.1.2.3:22")` 观察是否得到本机 sshd �?banner�?  - 若证实，收益是：一�?*源注册里�?DNS 记录**（或将来发现驱动的注册表里的一份发现文档）可以指向
    `0.0.0.0` 段地址，绕过「私�?回环在拨号层被拒」这条唯一防线，打到本进程旁边的内部监听�?    raw 透传会把响应原样交回调用者，因此那是一个可读的 SSRF，不只是盲打�?- 修法建议: �?`netip.MustParsePrefix("0.0.0.0/8")` 加进 `nonPublicPrefixes`
  （`Unmap()` 已经覆盖�?`::ffff:0.x` 形式，无需额外处理）�?- 复现/守卫: `internal/zzprobe/federation/safeurl_test.go`
  `TestProbeIsPublicAddressCoversEverySpecialRange`�?
---

### FO-04 源注册表不校�?`game` / `name` / `Resources[].Scope`，它们直接进入重定向 URL �?OAuth scope 参数

- 严重�? **�?*
- 类别: 安全 / 可维护�?- 不变�?性质: 凡是会被拼进 URL 路径、或会被当作 OAuth scope 发出的操作者输入都要校验—�?  这个项目�?`idp.validateProviderName`（`idp/idp.go:332-347`）里对同类的操作者输入正是这么做的，
  而且注释写明理由：「The name is operator input, but it ends up in the callback URL and in every stored identity,
  so it is checked rather than trusted.」`federation.NewRegistry` 没有对应的检查�?- 证据（执行过�?
  - `internal/federation/federation.go:141-175`：只检�?`Game == "" || Name == "" || Issuer == ""` 与重复键�?    实测以下�?*全部被接�?*�?    ```
    game="../.."  name="src"        => ACCEPTED; scope="../....profile.read"
    game="phigros" name="../evil"   => ACCEPTED; redirect=".../auth/upstream/phigros/../evil/callback"
    game="phigros" name="src?x=1"   => ACCEPTED; redirect=".../auth/upstream/phigros/src?x=1/callback"
    game="phigros" name="src#f"     => ACCEPTED
    game="phigros" name="src\nnewline" => ACCEPTED
    ```
  - scope 侧的实测（执行过，FAIL）：
    ```
    declared resource scope ["phigros.profile.read account.id"] is used verbatim in: bindScopes, the scope gate, and the wire
    ```
    `Source.bindScopes()`（`federation.go:112-122`）只按整串去重、不做切分，
    于是 `oauthConfig(src).Scopes` 里一个元素带空格，`golang.org/x/oauth2` �?join �?    `scope=account.read+phigros.profile.read+account.id`—�?*上游源收到一个它从未声明�?scope**�?    �?`Source.bindScopes` 的文档承诺是「the account scope plus every resource scope」�?    注意 `docs/upstream-protocol.md:174-177` 自己说明 re0auth �?scope 文法�?Kit 侧宽松（只要求两段）�?    所�?`Source.bindScopes` �?*唯一**能拦住这类配置的地方，而它没拦�?  - `sourceKey(game, name) = game + "/" + name`（`federation.go:250`）：键空间是可碰撞的
    （`("../..","src")` �?`("..","../src")` 都得�?`"../../src"`），因此「重复源拒绝」这条检�?    对畸形输入不构成保证�?- 状�? **CONFIRMED**（补丁接受行为是执行过的；`Service.BeginBind` �?`registry.Get` 用的是同一�?  `sourceKey`，所以畸�?name 不会从那条路漏掉——这一半也读到了行�?- 影响: 这是一�?*配置校验缺口**，不是远程攻击面：所有值都来自操作者的 TOML，而威胁模型把操作者列�?  信任边界之外（B6，`SECURITY.md`「Out of scope」）。真实收益有三条，都不大但都是确定的�?  1. `bindScopes` 的静默扩权：一个手误（`scope = "a.b.read c.d.read"`）让 re0auth 在绑定上游时
     索取一个额�?scope，用户看不到（同意页列出的是 re0auth �?*下游** scope，不是发给源�?scope）�?  2. �?`?` / `#` 的源名让 `redirectURL()`（`bind.go:232-234`）产出的回调 URL 不是操作者以为的那个�?     错误会以「源�?redirect_uri 不匹配」的形式出现在很远的地方�?  3. `..` 段让注册时的回调 URL 与实际注册到源的 `redirect_uri` 可能不一致——取决于�?代理是否归一化，
     属于「行为依赖另一个组件的属性」，正是 `cleanRawPath` 注释（`service.go:410-421`）反对的那种依赖�?- 修法建议: �?`NewRegistry` 里按 `idp.validateProviderName` 的同款规则校�?`Game` �?`Name`
  （`[a-z0-9][a-z0-9._-]*`，且不得�?`/`、`?`、`#`、`\`、控制字节）�?  `Resource.Name` 同样校验；`Resource.Scope` 用严格三段式文法校验（`upstreamkit.ValidCanonicalScope` 已有），
  或在 `bindScopes` 里拒绝含空白�?scope�?- 复现/守卫: `internal/zzprobe/federation/raw_test.go`
  `TestProbeRegistryAcceptsPathEscapingNames`、`TestProbeScopeInjectionFromRegistry`�?
---

### FO-05 数据面没有重试层，`docs/source-onboarding.md` §4 对源的承诺多了一�?
- 严重�? **提示**
- 类别: 可维护�?- 不变�?性质: 文档与实现一致——该文档是给**第三方数据源运营�?*看的对外承诺�?- 证据（静态搜�?+ 执行过的记录探针�?
  - `httpclient.Retry` 在全仓库**只有一个构造点**：`cmd/referencesource/main.go:143`（TapTap 客户端）�?  - `cmd/re0auth/main.go:459-475` �?`federationClient` 只走 `httpclient.NewOutboundClient`�?    其装饰链�?`Transport �?Bulkhead �?CircuitBreaker`（`httpclient/outbound.go:304-321`），**没有 Retry**�?  - �?`docs/source-onboarding.md:225` 对源承诺的是「出站连接池 + 并发上限（bulkhead�? **指数退避重�?*�?    同一绑定的刷新串行化」�?  - `idp` 侧（`idp/idp.go:253-256`）同样没�?Retry�?- 状�? **CONFIRMED**（读代码到行 + 执行过的静态断言探针�?- 影响: 源运营者按文档准备承受重试流量，实际只承受单次请求。反向看�?*这对源更友好**，所以不是安全问题；
  但它使运营者无法据文档判断突发形态。另�?*不加重试�?refresh 的正确选择**：重试一�?`invalid_grant`
  的通知是没有意义的，重试一个旋转型 refresh 反而会加剧轮换 churn——所以修法应该是**改文�?*�?  并把「为什么数据面刻意不重试」写�?`resilience-decision.md`（该 ADR 目前的「明确不做」一节没有提到这一点）�?- 修法建议: �?`docs/source-onboarding.md:225`，或�?`resilience-decision.md` 补一�?  「`Retry` 只挂�?`cmd/referencesource` �?TapTap 客户端上；数据面刻意不重试，因为绑定刷新不可重放」�?- 复现/守卫: `internal/zzprobe/federation/httpclient_test.go` `TestProbeRetryIsNotInstalledOnTheDataPlane`
  （它现在只是一个会打印结论的探针，建议改成一条真正的静态守卫：
  `go list`/AST 断言 `Retry(` 只出现在允许的位置，或断言 `federationClient` �?Doer 类型里没�?retry 包装）�?
---

### FO-06 Kill Switch 的分页扫描一旦中途出错，**已经切断的部分消失在响应�?*

- 严重�? **�?*
- 类别: 可用�?- 不变�?性质: 「部分完成不能被当成完整完成，也不能被当成什么都没做」—�?  `killswitch.go:59-64` 的注释把这条写得很清楚�?- 证据（读代码到行�?
  - `federation.RevokeAllBindings`（`killswitch.go:56-74`）在分页出错�?    `return summary, err` —�?**注释明说这是为了「偏从不被当成全部�?*�?  - `internal/admin/admin.go:345-360`：`outcome, err = s.bindings.RevokeAllBindings(ctx)`�?    只要 `err != nil` 就立�?`s.record(... OutcomeError ...)` �?`return rep, err`�?    **不把 `outcome` 放进 `rep`**（`rep.Bindings` 保持 `nil`）�?  - `internal/httpapi/admin_routes.go:281-282`：`default` 分支把任何非 `ErrInvalidTarget` /
    `ErrBindingsUnavailable` 的错误映射成 **500 `internal_error`「the kill switch could not complete�?*�?    body 不含任何计数�?  - 于是：一�?300 页的扫描在第 250 页因 Postgres 抖动失败 �?�?249 页（可能上万条绑定）**已经被删并已向源发了撤销**�?    而运营者看到的是「the kill switch could not complete」，没有任何数字，重跑是唯一选择�?- 状�? **CONFIRMED**（纯读代码到行：三处的控制流都是无条件形态，不需要执行就能断定；
  需要的是「分页中途出错」这个前提，而它�?store 层决定，�?DB 无法构造）
- 影响: 事故响应者无法判断「是不是每个源都被通知了」——�?FO-01 之外的这一条正�?  `threat-model.md` §5 D5 承诺的「如实报告」失效的地方。次生：重跑会把已经切断的绑定再扫一遍，
  对源产生第二轮无意义�?revocation 请求�?- 修法建议: `internal/admin/admin.go:355-360` 改成�?`outcome` 写进 `rep.Bindings` 再返�?error�?  `handleAdminKillSwitch` 增加一个分支：`errors.Is(err, ...)` �?`report.Bindings != nil` �?  返回 **207/200 �?`partial: true` + 计数 + 错误�?*，或至少 500 �?body 里带上计数�?- 复现/守卫: **无探�?*（需�?DB 才能�?`ListAllPage` 在第 N 页失败）�?  建议守卫：给 `federation.Config` 加一个可注入�?pager（现�?`BindingPager` 是从 `Bindings` 类型断言的，
  测试无法从一个「第 2 页起失败」的 store 得到它）——这本身就是一条可测性缺口�?
---

### FO-07 `httpclient.NewTransport` 硬编�?`Proxy: http.ProxyFromEnvironment`，而地址闸门只看代理的地址

- 严重�? **提示**
- 类别: 安全
- 不变�?性质: 「一个源注册或一份发现文档不能把本进程指向内部服务」——这�?`cmd/re0auth/main.go:469-474`
  注释�?`TransportConfig.DenyPrivateAddresses` 的完整承诺�?- 证据（读代码到行�?
  - `httpclient/outbound.go:92`：`Proxy: http.ProxyFromEnvironment`（不可配置）�?  - `DenyPrivateAddresses` 只作用于 `DialContext` 里那�?`net.Dialer`（`:93-102`），
    因此它判的是**实际被拨号的那个地址**——用代理时就�?*代理自己的地址**�?  - 结果：`HTTPS_PROXY=http://10.0.0.5:3128` 通过闸门（如果代理在私网，实际上**�?*通过—�?    这一条反而是 fail-closed 的）；但 `HTTPS_PROXY=http://proxy.example:3128` 会通过�?    �?`POST http://proxy.example:3128/` 里的**目标地址**完全是调用者给�?URL，不受任何检查�?- 状�? **HYPOTHESIS**（代码结构是读到的；未执行，因为要构造一个受控代�?+ 私网目标�?  而本�?`DenyPrivateAddresses` �?httptest �?loopback 源都拒——这正是该闸门的作用�?- 影响: 前提是攻击者能设置 `HTTPS_PROXY`（进程环境）。那已经在信任边界之外（B6），
  所以收益有限：它让「设一个环境变量」从「什么都改不了」变成「把全部出站流量改道」，
  �?*已经能改环境变量的人**是免费的提权，不是新的入口�?  值得注意的是 `web/e2e/server.mjs:330` �?CI �?`allow_private_addresses = true` 的用法：
  若某个部署为了自托管的私网源打开它，闸门就整体关闭了，�?`Proxy` 环境变量此时是唯一剩下的重定向面�?- 修法建议: �?`Proxy` 变成 `TransportConfig` 的一个字段，默认 `http.ProxyFromEnvironment`（保持现状）�?  �?*�?`DenyPrivateAddresses` 打开�?*要求显式配置代理，并在文档里写明
  「开了代理，地址闸门只保证代理是公网地址」。这属于加固，不是修 bug�?- 复现/守卫: 无独立探针；结论来自 `httpclient/outbound.go:92` �?`:93-102` 的对照�?
---

## 探过但没破的（这些也应变成守卫）

**SSRF / 地址闸门**

- **地址闸门确实在拨号层，不是装�?*：`DenyPrivateAddresses=true` 的真�?  `httpclient.NewOutboundClient` �?httptest �?loopback 源都拒，错误文本�?`allow_private_addresses`�?  关掉开关后同一个客户端可达（负对照通过）→ `TestProbeDenyPrivateAddressesBlocksTheDial`�?- **IPv6 覆盖完整**：`::1`、`fe80::/10`、`fc00::/7`（含 `fdff:...:ffff` 上沿）�?  IPv4-mapped �?loopback / RFC1918 / link-local / CGNAT / IETF / 保留 / 基准 / 文档段�?  `64:ff9b::/96` �?`2002::/16` 的内嵌形式、`2001:db8::/32`、多播、`::`、`255.255.255.255`
  **全部被拒**；`8.8.8.8` / `1.1.1.1` / `2606:4700:4700::1111` 仍被允许（非空转对照）�?- **`allow_private_addresses` 没有扩大超出文档的范�?*：它只关�?`denyPrivateAddress` 这一�?  `net.Dialer.Control` 钩子（`outbound.go:95-100`），不碰重定向策略、不�?bulkhead、不碰熔断�?  `config/re0auth.example.toml:220` �?`architecture.md:312` 都写明了它是什么�?- **IPv6 zone id 不会让判定崩�?*：`netip.ParseAddr("fe80::1%eth0")` 成功�?  `IsLinkLocalUnicast()` 仍为�?�?拒绝，不是「解析失败的另一种拒绝」�?- **`Proxy` 字段之外，没有第二个客户端漏掉闸�?*：仓库里全部 `http.Client` 构造点已逐一枚举�?  `cmd/re0auth/main.go:424,459`（两个都�?`DenyPrivateAddresses: !cfg.AllowPrivateUpstreams`）�?  `idp/idp.go:253`（库内默认，**硬编�?`DenyPrivateAddresses: true`**，注释写明是 fail-closed）�?  `federation/service.go:160`（`HTTPClient` 缺省时也�?`NewOutboundClient`，不�?`http.DefaultClient`）�?  **两个例外**（`cmd/referencesource/main.go:143` �?`:174`）在 `cmd/referencesource/` 里—�?  它们**确实没有地址闸门**，见下「未能到达」�?
**重定向策略（对着 Go �?`net/http` 真行为逐个变体打过�?*

- 全部 **23 �?* 变体符合预期。被拒：�?host、子域、父域�?*scheme 降级**、大�?host（`SOURCE.EXAMPLE`）�?  尾点（`source.example.`）、`%73ource.example`（`url.Parse` 直接�?invalid URL escape）�?  `https://source.example@evil.example/`（`u.Host` �?`evil.example`）、异 port、`source.example.evil.example`�?  `evil-source.example`、`//evil.example`、IPv4 字面量、十六进�?十进�?IPv4 字面量、尾部空格�?  host �?TAB、Location 里的 CRLF。被允许�?*只有**�?host（含 `fragment` 与路径穿越，它们不是 authority）�?- **判据用的�?`req.URL.Host` 而不是字符串前缀**：探针确�?`https://evil.example@source.example/next`
  �?*允许**的，因为 `u.Host == "source.example"`——即请求确实还是发给 source.example�?  这条值得留成守卫，因为它证明「URL 看起来像谁」不是被检查的东西�?- **Go 不会归一�?host 的大小写**（`url.Parse("HTTPS://Source.Example/Path")` �?scheme 小写、host 原样�?  �?所以策�?*偏向拒绝**（`SOURCE.EXAMPLE` 会被当成�?host 拒掉）�?  反向的「攻击者用大小写变体绕过」因此不成立；代价是同一台服务器的另一种写法会被拒，属保守�?- **凭据到不了被拒的那一�?*：三跳链 `source.example �?source.example �?evil.example` 里，
  只有前两跳见�?`Authorization`，第三跳�?`RoundTrip` 之前就被�?  （错误文�?`refused a redirect from https://source.example to https://evil.example`，只�?scheme+host，不含路�?查询）�?- **307/308 的表单体不会被送到�?host**：`grant_type=refresh_token&refresh_token=�?client_secret=…`
  �?`source.example/token �?evil.example/token` �?307 链上，第二跳没有被发出�?  注意这里**不是** stdlib �?body-strip 在起作用�?07/308 对任�?host 都不 strip body），
  是本包自己的 `CheckRedirect` 在请求构造之后、发送之前拒掉——这正是它必须存在的理由�?- **`CheckRedirect` �?`Authorization` 复制决策之后运行**，所以策略本身不能依赖「头被剥掉了」；
  它必须独立判定并拒绝。实测符合（第三跳没见过任何头）。这一条是**设计结论**，建议写�?  `NoCrossHostRedirects` 的注释：现在的注释说「the standard library only strips Authorization when the
  destination is outside the same domain」，读起来像是在依赖 stdlib，实际不是�?
**raw 透传的路径处理（27 �?payload，全部打真源�?*

- **路径无法改变 host**：`..`、`../secret`、`a/../../secret`、`..%2fsecret`、`%2e%2e/secret`�?  `%2e%2e%2fsecret`、`%252e%252e%252fsecret`、`.../`、`..;/`、`.%2e/`、`..%5c`、`..\`�?  `//evil.example/x`、`///evil.example/x`、`/\evil.example/x`、`http://evil.example/x`�?  `https://evil.example/x`、`@evil.example/x`、`%2F%2Fevil.example`
  —�?全部要么�?`ErrRawPathEscapes` 拒（源一个请求都没收到），要么在源的 `RawBase` 前缀**之内**落地�?  后者具体形态（实测记录�?RequestURI）：
  ```
  "//evil.example/x"     => GET /v1/evil.example/x?keep=1
  "http://evil.example/x"=> GET /v1/http:/evil.example/x?keep=1
  "%2F%2Fevil.example"   => GET /v1/%2F%2Fevil.example?keep=1
  ```
  �?`path.Clean("/"+p)` 消掉多余斜杠后仍是相对路径——这�?*安全的方�?*，也是它不能�?SSRF 用的原因�?- **`?` / `#` 无法注入**：`url.PathEscape` 会编码它们，
  `"?a=b"` �?`GET /v1/?a=b?keep=1`（注意出现两�?`?`，是源的解析问题，不�?re0auth 的：re0auth 发的�?  `.../v1/%3Fa%3Db`... 实测里源看到的是未编码形式，因为 **`path.Clean` 不编�?*�?  �?`r.URL.RequestURI()` 回显的是源自己解析后的形式。这一点值得单独读一�?`cleanRawPath` 的注释确认：
  它明确说「`?` �?`#` 不能改变 join 的含义」，理由�?`RawBase` 已被 `validateRawBase` 保证不带 query/fragment�?  而实测支持这个结论。）
- **CRLF 不能注入�?*：`a%0d%0aX-Injected:%201` �?`GET /v1/a%0d%0aX-Injected:%201?...`�?  单行、无新头。`%00` 同样只是路径里的字节�?- **双重编码被逐层拦住**：`%2e%2e/x`、`%252e%252e/x`、`%25252e%25252e/x` 以及
  命中 `maxRawPathDecodeRounds` 的四重编�?*全部** `ErrRawPathEscapes`；上游一个请求都没发�?  `%c0%ae%c0%ae`（overlong UTF-8）与全角句点原样透传，但 `url.PathEscape` 之后就是字面文本�?  Go 的源不会把它解成 `..` —�?建议把这两条留成守卫（它们是「守住了但没人验证过」的形状）�?- **响应大小与流**：`Content-Length: 1e18` 只让源收到一�?short body 后报
  `unexpected EOF`�?08µs 返回）；**永不结束�?body** �?`maxBody+1` 字节处被
  `io.LimitReader` 切断并返�?`ErrResponseTooLarge`�?*4.9ms**，不是靠 20s �?client timeout）�?  �?`service.go:510-523` 的注释（「one byte past the cap, so "exactly at the limit" and
  "past the limit" are distinguishable」）与实测一致�?- **归一化资源的 body 也是 capped**（`service.go:545` �?`io.LimitReader(resp.Body, maxBody)`）�?
**raw 响应头（真实 HTTP 面）**

- 成功路径：`Content-Type: text/html` 原样透传、`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox`�?  `Content-Disposition: attachment; filename="phigros-src-page"`、`X-Content-Type-Options: nosniff`�?  `Cache-Control: no-store`、`Referrer-Policy: no-referrer`、`Re0Auth-Source: src`
  —�?一个源返回�?`<script>alert(1)</script>` 在这�?origin �?*不能执行**（sandbox + attachment + nosniff）�?- 错误路径�?*源返�?401 / `text/html`** 时，调用者拿到的�?  `503 application/problem+json` + 通用 `detail`�?*源的 body 一个字都没�?*，且 `Content-Type` �?problem+json
  而不是源�?`text/html`。逃逸路径是 `400 invalid_request` + 同一形状�?  即任务里问的「错误响应上是否也设�?CSP/Content-Disposition」答案是**不设，但也不需�?*—�?  错误响应从不携带源的 body 或源�?media type，它�?`writeProblem`，只吃全局�?  `frame-ancestors 'none'` + `nosniff`。这条建议留成守卫（这正是「media type 被原样回�?�?存储�?XSS」的唯一入口�?  而它在错误分支上关着）�?- **`rawDownloadName` 的字符白名单**（`federation_routes.go:263-293`）能挡住
  `"` �?CRLF：源名与路径�?`[A-Za-z0-9._-]` 之外的一切都被替换成 `_`，上�?64 字节�?
**出站韧�?*

- **熔断器真的是 per-host**：两�?host 走同一�?client，一个连�?5xx 被打开�?  **不再被拨�?*（transport 尝试�?3 �?3 不变，错误是 `circuit breaker is open`），
  同时健康 host �?3 次请�?*全部通过**（尝试数 3）→ `TestProbeCircuitBreakerIsPerHost`�?  这验证了 `doc` 里「one breaker per upstream rather than one per process」的承诺
  （键�?`req.URL.Host`，`circuitbreaker.go:119`；map 有锁）�?- **`Retry-After` 真的有上�?*：源�?`Retry-After: 86400`，调用在 **2.0s** 返回
  （命�?`MaxElapsedTime=2s`），�?2 次尝试——没有被拖住一天�?  源码侧的上限�?`maxRetryAfter = 30s`（`retry.go:42-43`�? `WithMaxDuration`，两级都在�?- **`Retry-After` 的抖动符�?ADR-0009 的声�?*：源�?`Retry-After: 1`，实测两次间�?  1.4887s / 1.3239s / 1.1493s / 0.6388s，全�?0.5�?.5s 带内（�?0%）�?  这条确认�?ADR 里那�?*有意接受的语义变�?*（「抖动也作用�?`Retry-After` 给出的延迟」）是真的�?- **调用方取消优先于上游错误**：`Retry-After: 30` + 500ms �?ctx�?  500ms 返回 `context deadline exceeded`，只�?1 次——`AbortOnErrors` + `HandleIf` 生效�?- **重试不会重放不可重放�?body**：`GetBody == nil` �?GET 只发 1 次；POST 只发 1 次；
  `GetBody != nil` �?GET 三次都带完整 body�?*不是�?body**）—�?  `retry.go:113` 的准入判断与 `:122-128` �?`req.GetBody()` 换体都是对的�?- **bulkhead 的许可确实活�?`RoundTrip`**：调用方不关�?body 时，第二个请�?  **拿不�?*许可（在 3s 内超时），说明许可确实被那个未关闭的 body 占着—�?  这正是设计意图，也说�?ADR §3「许可必须活�?`RoundTrip`」成立�?  同一测试的反面：正常 `Close()` 三次连续请求全部成功 �?许可会归还�?  残余（已�?ADR 里记录）：忘�?Close 的调用方会占住一个许�?*直到 `http.Client.Timeout`**�?0s），
  不是永久——因�?client 超时会取消请求并关闭 body�?- **`Retry` 只重试幂等方�?*，因此源侧的 `POST /oauth/revoke` �?`/cascade_revocation`
  永远不会被重试放大。加�?`MaxRetries=3` + `MaxElapsedTime=15s` + `Retry-After �?0s` 三重上限�?  「重试把源打�?DoS」不成立�?
**绑定生命周期（工作树改动�?*

- **工作树对 `Unbind` 的改动是完整的，没有留下「列表说能断、某条路却拒绝」的缺口**�?  逐条追过：`bindingView.Configured=false` 的分支在
  `web/src/routes/sources/+page.svelte:294-298`（提示「连接仍可断开」）�?`:378-383`
  �?*无条�?*渲染「断开连接」按钮，�?`Configured`/`Bindable` 无关）；
  服务�?`Unbind`（工作树版）现在先读绑定行、再查注册表，源不存在时�?  `result.Upstream = RevocationNothingToDo` 并照�?`vault.Revoke` + `bindings.Delete`�?  实测：孤儿绑�?`res={Upstream:nothing} err=<nil>`，行与密钥都被清�?  （`TestProbeOrphanedBindingIsListedAndRemovable`、`TestProbeUnbindOrderingAgainstTheHTTPContract` PASS）�?  `CascadeRevoke` 对无源绑定返�?`ErrCascadeUnsupported`/`ErrUnknownSource` �?*正确**的：
  级联撤销的语义就是「让源去结束会话」，没有源就没有这个动作，前端也不给按钮
  （`bindingView.CascadeRevocation` 只在 `Configured=true` 时可能为真）�?- **`Unbind` 的存在性预言机不泄露新信�?*：`known source, nothing bound => err=<nil>`�?  `unknown source, nothing bound => ErrUnknownSource`（HTTP 404）。这条差异在 `GET /v1/sources`
  **公开列出全部已配置源**的前提下是零信息量的（探针里记了这句）�?- **`Unbind` 的本地半边确实无条件执行**：源不可达（DNS 失败）时仍是
  `res={Upstream:unavailable UpstreamError:upstream_revocation_failed} err=<nil>`�?  即「上游叫不动」与「本地切掉」被分开如实报告——`unbind.go:72-97` 的注释与实现一致，
  �?`revokeUpstream` 现在区分 `vault.ErrNotFound`（→ `nothing`）与其它失败（→ `unavailable`），
  第二�?A6-1 的塌缩确实修掉了�?- **`BeginBind` 把流程绑到会�?+ 账号所有�?*：`handleBindStart` �?  `sessions.Bind(ctx,"bind",challenge.ID)`（`federation_routes.go:319`），
  `handleBindCallback` 同时�?`sessions.Bound` **�?* `sessions.OwnerMatches`
  （`:342-347`），两者缺一�?400 且与「未�?handle」同形。这是第二轮 A2-1 的修复点�?  本轮复核**没有发现回退**，也没有发现第二个调用点漏掉 owner 检查�?  同一浏览器里换账号后，第一个账号的 flow 不会被第二个账号消费掉（`CompleteBind` 里还�?`flow.User != user` 兜底）�?- **`shredBinding` / `Unbind` / `CascadeRevoke` / `refreshBinding` 用的是同一�?per-binding �?*
  （`keyedMutex`，键 `bindingKey(user,game,source)`）：四条路径我都读了锁的获取点，
  没有发现「删行但不持锁」的路径。`refreshRejected` 是唯一在持锁状态下不能再取锁的地方�?  而它的注释（`refresh.go:149-150`）明确说明了这一点，并且它自己做�?`vault.Revoke` + `Delete` 而不是调 `shredBinding`—�?*正确**�?- **重绑不会回到 `Version: 1`**：`newBindingGeneration()` �?8 字节随机数（`binding.go:55-64`），
  非零。第二轮那个「迟到刷新删掉刚建的绑定」被这条挡住；`refreshRejected` �?  `latest.Version != spent.Version` 判据因此把「重绑」正确读成「有人赢过」�?
**令牌处理**

- **上游令牌只在 vault 的明文窗口内被解�?*，`useBindingSecret`（`binding.go:104-112`）的注释**已经说了实话**
  （「strings are immutable�?those copies live until the GC reclaims them」）�?  不再有「窗口关掉就消失」的错误声明——本轮复核确认代码与注释一致�?- **明文副本不会越过调用**：`revokeUpstream` �?`secret = *sec`（`unbind.go:105-108`�?  �?`CascadeRevoke` 的同款（`revocation.go:129-135`）都�?`bindingSecret` 结构体拷到窗口外�?  但拷的仍是那两个 `string` 头，不产生新副本；没有任何地方把它写进日志、响应或 store�?- **令牌不会从错误信息里漏出**：`postRevocation`/`rawFetch`/`fetchResource` 的错误只带源名与状态码�?  `NoCrossHostRedirects` 的错�?*刻意**只带 scheme+host 且注释说明了理由�?  `writeFederationError` 全部映射成固�?code；access log �?`r.URL.Path` **不记 query**
  （`middleware.go:245-267`），所�?`?token=` 形态永远不进日志�?- **重试不保留明�?*：`callWithRefresh` 的第二次 `withAccessToken` 重新开一�?vault 窗口
  （`refresh.go:209`），不复用上一次的 `token` 变量�?
**Kill Switch**

- **非管理员拿不到它**：未配置 allowlist 时整�?`/v1/admin/*` **不挂�?*，实�?  `POST /v1/admin/kill_switch`（只�?bearer）→ **404** problem+json�?  已登录非管理�?�?404（`requireAdmin`，`admin_routes.go:67-70`，与未知路径同形，无存在性预言机）�?  写操作另需 CSRF + `reauth_required` 窗口（`:77-98`）�?- **`client` 目标确实不碰绑定**�?*`bindings` 目标确实不碰令牌与会�?*：`admin.go:306-362` 的三�?  `if` 条件互相独立，`Target.setCount() != 1` 强制只有一个目标，
  实测 `{"target":"subject"}` �?`subject` 为空�?`setCount()==0` �?`ErrInvalidTarget` �?400（不会误扫全员）�?- **本地半边总是发生**：`revokeBinding`（`killswitch.go:160-192`）在源不可达时仍 `revoked:1, unavailable:1`�?  `failed:1` 只在 `Unbind`/`shredBinding` **报了 error** 时才出现，�?`Unbind` 在源失败时不返回 error—�?  即「本地的切掉不会因为源的态度而被吞掉」�?- **响应不泄露别人东西的数量给非管理�?*：报告体只出现在管理员请求的 200 里�?  `BindingRevocationSummary` 是纯计数（`Total/Revoked/Cascade/Unsupported/Unavailable/Orphaned/Failed`），
  不含 `usr_`、源名或绑定键�?- **四目标矩阵与 `docs/admin.md` §4.2 一�?*，且 `bindings.unsupported` / `bindings.unavailable`
  确实是真值而不是伪造的成功（`TestProbeUnbindOrderingAgainstTheHTTPContract` 打出 `unavailable` +
  `upstream_revocation_failed` 而非 `done`）�?
---

## 未能到达（残余盲区）

1. **Postgres 侧的 `PutIfVersion` / `ListAllPage` 语义**。`internal/store/postgres` 的实现我没有
   DSN 可跑，只能读代码。具体未验证的两点：①CAS 是否真的在一�?`UPDATE ... WHERE version = $n` 里完�?   （若是「先 SELECT �?UPDATE」，�?FO-02 的窗口会比内存实现大得多）；②`ListAllPage` 的游�?   �?*同一个事务里删除行之�?*是否仍然单调（Kill Switch 边扫边删）�?   **要证实需�?*：`E2E_DATABASE_URL` + 一个「第 N 页之后开始失败」的注入点�?2. **`-race` 未跑**（无 cgo）。FO-02 的复现是确定性的（`frozenStore` 钩子�?`PutIfVersion` 之前删行），
   不依赖竞态检测器；但「`keyedMutex` �?refcount 回收没有丢锁」这类论�?*没有检测器背书**�?   只是读代码�?3. **`0.0.0.0/8` �?Linux 上路由到回环**（FO-03 的可利用性）。本机是 Windows 11�?   我无法执�?`/proc/net/route` 之外的事。这�?FO-03 停在 HYPOTHESIS 的唯一原因—�?   谓词侧是执行过的，可利用性不是�?4. **`cmd/referencesource` 的两个客户端没有地址闸门**（`main.go:143`、`:174`）�?   我确认了它们**没有** `TransportConfig{DenyPrivateAddresses:...}`，但**没有把它报成 finding**�?   该二进制的读者就是数据源自己，它要连�?`taptap` / `leancloud` / IdP 端点都是它自己配的，
   �?`SECURITY.md` �?`referencesource` 排除在发布产物之外�?*这是一条「类型上成立、收益上构不出」的观察**�?   留在这里而不是发现里，因为它正是那份 `httpclient.TransportConfig` 注释所说的
   「自托管数据源在私网是受支持形态」——re0auth �?referencesource 的角色不同�?   若将�?`upstreamkit` �?`conformance` 或某个默认客户端**发到第三方手�?*作为「数据源应当使用的出站客户端」，
   这条就该升级�?finding。`upstreamkit/conformance/conformance.go:60` �?`&http.Client{Timeout: 10s}`
   是同类：它是给数据源运维者跑的扫描器，目�?URL 由运维者给�?5. **发现驱动的源注册表不存在**（`docs/upstream-protocol.md` 开头自己写明「现为静态配置」）�?   因此「恶意发现文档能否让 re0auth 调用一个不是配置里的端点」这个问�?*今天无从到达**�?   `Source.CascadeRevocationEndpoint` / `RevocationEndpoint` / `TokenEndpoint` 全部只来�?TOML
   （`cmd/re0auth/config.go:752-788`），�?`loadSources` �?`NewRegistry` 当唯一权威做校验�?   值得记的�?*这一条将来会变成 FO-04 的放大器**：`NewRegistry` 现在不校�?`Issuer` �?scheme/host 之外�?   一旦发现文档接管这些字段，FO-04 里那些「配置畸形」就直接变成「远程可控值」�?   建议在做发现驱动注册表时**先把 FO-04 的校验补�?*�?6. **`internal/httpapi` 的完整测试包在本轮部分时段不可编�?*（同名目录下另外两个审计代理�?   `zzprobe_*.go` 在飞）。我�?`internal/zzprobe/federationhttp/` 绕过，并在两个包都跑出了结果�?   但「`go test ./internal/httpapi/` 全绿」这个前提我**没有**验证过，也就没有把它当成任何结论的依据�?7. **`safeurl` 只有 `RelativePath` 一个函�?*，没有任务描述里说的「private-address denial」—�?   地址闸门实际�?`httpclient`。`return_to` 的处置我已按 `RelativePath` 的文档复核：
   `""`→`/`、`//evil`→`/`、含 `\`→`/`、`url.Parse` 失败→`/`，且注释明确说明
   **刻意不拒** `..`、空格与百分号编码的控制字节（「a path is not an authority」）——这个取舍成立�?   没有发现绕过�?
---

## 判断（文档化决定可否质疑，不�?finding�?
1. **raw 透传�?scope 闸门是「源的任一资源 scope」，这是文档化决�?*
   （`federation_routes.go:177-179`：「A dedicated `<game>.raw.read` scope is future work」；
   `threat-model.md` §9 也登记了 raw 的边界）�?*但我要指出一条它没覆盖的东西**�?   闸门�?*跨资�?*的（�?`profile` �?scope 就能�?complete 原生 API，包括写路径，只要源有）�?   �?FO-01 说明它连「跨源」都不是保证。前者是有意的（文档写了），后者不是（FO-01）�?   若接受「粗闸门」，建议至少�?`?source=` �?scope 的对应关系写�?`openapi.yaml` 的端点说明—�?   现在客户端读不出「我该要哪个 scope 才能 raw 这个源」�?2. **数据面没有重�?*（FO-05�?*我认为不加重试是对的**：绑定刷新是旋转型单次凭据，
   重试 `invalid_grant` 无意义、重试旋转会加剧 churn。所以这不是「缺了功能」，
   而是「文档说了一个不存在的功能」——改文档比加代码正确�?3. **`Config.KillSwitchPageSize` 暴露成了 public 配置**（`service.go:121-124`），
   注释说「a test sets it small to exercise the paging loop」。用公开配置服务测试便利性是可以的，
   但它同时也是 `RevokeAllBindings` 的分页大小——一个部署把它设�?1 就是对源的串行轰炸�?   这属于「用一个旋钮做两件事」，建议改成 `Option` 或直接只给测试用内部字段�?4. **`httpclient.TransportConfig.DenyPrivateAddresses` 的默认值是 false**
   （`outbound.go:46-48`：「Off by default because self-hosted data sources on a private network are
   a supported shape」）。组合根**确实**把它设成�?`!cfg.AllowPrivateUpstreams`，所以生产是 fail-closed�?   我保留这条判断：**库级默认 false + 组合根负责打开**，意味着任何一个新�?   `NewOutboundClient(OutboundConfig{})` 调用点（本仓库已经有 `federation/service.go:160` 这一处）
   默认是不设防的。`federation/service.go:160` 目前是安全的（它只是 `HTTPClient` 的缺省值）�?   但把「安全」放在调用方而不是默认值里，正�?`idp/idp.go:243-257` 的注释所反对的做�?   （「a caller that forgets to pass one should not silently get the unhardened default client」）�?   两处对同一个问题给了相反的答案，建议统一�?`idp` 那一种�?