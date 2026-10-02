# 第九轮安全与性能审计报告（上线前 · 独立轮次�?
> 本报告是�?9 轮上线前独立审计�?*刻意不依赖前几轮的审计结�?*：审计员只读当前生产代码�?> 禁止引用 `AUDIT-ISSUES.md`、`docs/security-audit-*.md`、`internal/zzprobe/**`、`_audit/**`、`audit/**`�?> 完整原始数据�?`_audit/round9/`（`raw/` 发现、`verify/` 对抗性验证、`matrix9.csv` 汇总）�?
## 0. 执行摘要

| 指标 | �?|
|---|---|
| 目标 | `C:\git\r0semi` �?Re0Auth，Go 1.27 OIDC/OAuth2 身份与授权层 |
| 代码规模 | 655 �?Go 文件 / �?138,113 行（另有 SvelteKit 前端�?|
| 审计环境 | Windows 11 + Windows PowerShell 5.1（本机无 pwsh 7）；**�?Docker、无本地 PostgreSQL** |
| 方法 | 15 个分域发现子代理 �?15 个对抗性验证子代理（共 30 个）；每条发现必须给�?`file:line` 证据 |
| 原始发现 | 157 �?|
| 验证�?| **0 critical · 8 high · 30 medium · 95 low · 24 info/零严重度** |
| 基线门禁 | `go build` / `go vet` / `go test ./...` / `go test -race` / `gofmt -l` / `govulncheck` / `gitleaks` **全部通过** |

**一句话结论�?*这份代码的工程化程度和纵深防御明显高于同类项目（中间件顺序、平面隔离�?密钥处理、审计链、限流与预算设计都经过反复打磨），但仍有 **8 �?High** 足以在上线前阻断�?其中 5 条集中在“降级路�?边界路径没有走主路径的约束”这一共同模式上�?
### 上线阻断（建议先修）

| 编号 | 严重�?| 一句话 |
|---|---|---|
| S02-1 | High | `prompt=login` / `max_age` 不会真正重新认证，OP 把“同意点击时刻”伪造成新的 `auth_time` 并签�?|
| S08-2 | High | `storage.dsn_env` 指向�?`DATABASE_URL` 时，driver 推断�?postgres 但不解析 DSN，静默退回内存存储（跳过审计密钥、持久化、防篡改链） |
| S10-1 | High | 并发上限的“单客户端半量”按 `(平面,客户�?` 计数，一个地址可用两个平面吃满整个进程级信号量 |
| S13-1 | High | 压缩协商�?406 分支在限流器与并发上�?*之前**返回，完全绕过两道反滥用边界 |
| S13-5 | High | 内存 OP 存储的所�?map 无上限；refresh 轮换每次留下一个存�?30 天的 tombstone�? 分钟清扫全表且持全局�?|
| S03-1 | High | `return_to` 无长度上限且被整段写进服务端 session；匿名请求即可把内存/`sessions.data` 撑爆 |
| S06-1 | High | OIDC discovery / JWKS �?go-oidc 用无上限 `io.ReadAll` 读取（自�?1 MiB 上限不覆盖此路径），可被配置�?IdP �?gzip 炸弹打爆 |
| S14-2 | High | `federation.CompleteBind` 未取 per-binding 锁，可在一�?Kill Switch / Unbind / 账号擦除之后复活绑定与上游凭�?|

### 修复状态（�?1 步：8 �?High 已全部修复，S02-2 一并修复）

| 编号 | 修复位置 | 复现测试（现状全绿） |
|---|---|---|
| S02-1 | `internal/oidcstore`（新鲜度判定 + `ErrReauthenticationRequired`）、两�?store �?`CompleteLogin` 不再伪造、`cmd/re0auth` 登录钩子�?`/auth/reauth` 强制重认证、`oidchttp.ApproveAuthorization` 回写真实 `auth_time` | `internal/oidcstore/zz_audit9_freshness_test.go`、`internal/store/memory/zz_audit9_reauth_test.go`、端到端 `internal/zzprobe/protocol/audit9_basic_op_test.go`（authorize→完成→callback→token，断言 id_token �?`auth_time`）、`internal/auth/zz_audit9_reauth_route_test.go` |
| S02-2 | `internal/oidchttp.validateAuthorize`：`prompt=none` 有会话时�?`consent_required`（无记忆同意�?| `TestPromptNoneRequiresASession`（已按新语义更新�?|
| S03-1 | `safeurl.RelativePath` 增加 `MaxRelativePathBytes=2048` | `internal/auth/zz_audit9_returnto_test.go`、`safeurl_test.go` |
| S06-1 | `idp.discoveryClient` �?1 MiB 上限�?RoundTripper 包住 discovery/JWKS | `idp/zz_audit9_discovery_body_test.go` |
| S08-2 | `cmd/re0auth/config.go`：`dsn_env` 在推断分支也解析；文件的 `dsn_env` 名字优先于字面量 `DATABASE_URL` | `cmd/re0auth/zz_audit9_dsnenv_test.go` |
| S10-1 | `internal/httpapi`：并发计数改为仅按客户端（限流仍按平面） | `internal/httpapi/zz_audit9_inflight_planes_test.go` |
| S13-1 | `internal/httpapi/server.go`：压缩移入限流与并发上限之内 | `internal/httpapi/zz_audit9_compress_bypass_test.go` |
| S13-5 | `internal/store/memory`：tombstone 上限 `MaxRefreshTombstones`（默�?65536�?| `internal/store/memory/zz_audit9_tombstones_test.go` |
| S14-2 | `internal/federation/bind.go`：`CompleteBind` 全程持有 per-binding �?| `internal/federation/zz_audit9_bind_unbind_race_test.go` |

修复�?`go build` / `go vet` / `gofmt -l` / `go test ./...` / `go test -race`（受影响包）全部通过�?
### 静态扫描：Semgrep 首跑（本地实�?1.178.0�?
`semgrep scan --config p/golang --config p/jwt` 一次跑通（48 条规�?/ 216 个目标，两个 pack 名有效）�?报出 6 条，逐条复核**全部为模式误�?*，已在源码就地用 `// nosemgrep: <rule>` 标注理由�?
| 位置 | 规则 | 复核结论 |
|---|---|---|
| `internal/auth/auth.go`（`/auth/reauth` 跳转�?| open-redirect | 同源路径：provider 来自注册表、`return_to` �?`safeurl.RelativePath` |
| `internal/httpapi/server.go`（`/{$}` 跳转�?| open-redirect | 目标�?`webui.BasePath` 常量开头，查询串无法改�?origin |
| `internal/httpapi/server.go`（`withCanonicalPath`�?| filepath-clean-misuse | `path.Clean` 只用于比较平面，不清洗被读取的路�?|
| `internal/httpapi/federation_routes.go:388` | open-redirect | `challenge.AuthorizeURL` 由注册源客户端按自身 issuer 构�?|
| `internal/httpapi/federation_routes.go:429` | open-redirect | `return_to` �?`safeurl.RelativePath` |
| `upstreamkit/server.go` | open-redirect | `redirect_uri` 已在 `DescribeAuthorization` 按注�?URI 校验（`oauth/as.go:101`�?|

加标注后复跑：控制台 **0 findings**（SARIF �?6 条带 `suppressions: inSource`，是被抑制而非删除）�?工作流的汇总步已改�?*只统计未被抑制的结果**，否则会把已复核站点每次报成新发现�?
### 其它值得注意�?Medium（部分）

- **S06-2**：设置了 `HTTP(S)_PROXY` 时，SSRF 的私网拦截作用在代理地址而非目标地址上——守卫失效�?- **S05-1**：刷新时把上游任�?400/401/403 都判定为“授权已死”并**加密销�?*绑定（含可能只是可重试的配置错误）�?- **S09-1**：`-migrate-down` 路径�?DSN 解析错误可能把带密码的连接串写进日志�?- **S09-2**：`Tokens.RevokeTokens` 文档声称在事务里，实际不在，批量 Kill Switch / 擦除可能半执行�?- **S14-5**：refresh family 撤销与轮换非原子，重放竞争可能留下新世代 token�?- **S07-1**：凭据型出站请求依赖注入�?`Doer` 的跳转策略；`net/http` 会把自定义认证头复制到跨主机跳转目标�?- **S08-4 / S11-6 / S12-1 / S15-1 / S15-3**：擦除成功口径不实、审计校验持有连�?45s 无并发约束、前�?`fetch` 超时在读�?body 前被解除、备份加密失败会留下明文 dump、备�?CronJob �?`activeDeadlineSeconds`�?
### 基线自动化门禁（本轮实跑�?
| 门禁 | 命令 | 结果 |
|---|---|---|
| 构建 | `go build ./...` | 通过 |
| 静态检�?| `go vet ./...` | 通过 |
| 单元/集成测试 | `go test ./...`（无 Postgres，跳�?DB 集成�?| 全部 ok |
| 数据竞争 | `go test -race`（oauth、vault、ratelimit、memory、compress、federation、oidchttp、oidcstore、httpapi、auth、observability、admin、lifecycle、account、webui�?| 全部 ok |
| 格式 | `gofmt -l .` | 无输�?|
| 依赖漏洞 | `govulncheck ./...` | `No vulnerabilities found` |
| 密钥泄露 | `gitleaks detect`�?10 commits / 14.33 MB�?| `no leaks found` |

**未能执行的部分：**�?Docker、无本地 PostgreSQL，因此容器镜像构�?Trivy 扫描、K8s 清单实际
apply、以及所�?`TEST_DATABASE_URL` 集成测试无法在本机运行；相关结论均为代码级静态分析与
既有单元测试推断（报告中已逐条标注）�?
## 1. 高危发现（High，共 8 条）

### H1. S02-1 �?prompt=login / max_age never re-authenticate: the OP fabricates a fresh auth_time instead

- **严重�?/ 类别�?* high / security；原�?high，验证结�?**confirmed**
- **位置�?* `internal/oidcstore/oidcstore.go:226; internal/oidchttp/oidchttp.go:1006; internal/store/memory/oidc.go:1274; internal/store/postgres/oidc.go:1269`
- **证据�?*

```go
func (a *AuthRequest) RequiresReauthentication(now time.Time) bool {
	if slices.Contains(a.Prompt, oidc.PromptLogin) {
		return true
	}
	if a.MaxAge == nil {
		return false
	}
	at := a.GetAuthTime()
	if at.IsZero() {
		return true
	}
	const maxDurationSeconds = uint64(math.MaxInt64) / uint64(time.Second)
	if uint64(*a.MaxAge) > maxDurationSeconds {
		return false
	}
	return now.Sub(at) > time.Duration(*a.MaxAge)*time.Second
}

-- call site, internal/store/memory/oidc.go:1274 (identical logic in postgres:1269) --
	if now := s.now(); a.RequiresReauthentication(now) || a.AuthTime == nil {
		a.AuthTime = &now
	}

-- oidchttp.go:1006-1014 leaves max_age enforcement entirely to the store --
	// OIDC Core §3.1.2.1: `max_age=N` asks the OP to re-authenticate when the
	// browser's last authentication is more than N seconds old. The judgement
	// itself is made where the session's auth_time and the request meet �?the
	// login boundary (CompleteLogin) �?because the store is what holds both.
	if raw := strings.TrimSpace(q.Get("max_age")); raw != "" {
		if _, err := strconv.ParseUint(raw, 10, 64); err != nil {
```

- **成因与影响：** RequiresReauthentication is the only place the recorded session age is compared with the request's freshness bound, and its result is never used to force a re-login. cmd/re0auth/main.go's login hook only copies sessions.AuthenticatedAt into the pending request (SetAuthTime) and returns the consent URL; nothing sends the browser to /auth/{provider}/start when a fresh authentication is required, and the consent payload returned by handleGetAuthorizationRequest carries no prompt/max_age/auth_time field so the SPA cannot trigger it either. Both stores react to RequiresReauthentication==true by OVERWRITING AuthTime with the consent-decision timestamp, so the id_token advertises auth_time=now for an authentication that never happened. OIDC Core §2 defines auth_time as the time the End-User authentication occurred; a client that used max_age/prompt=login to force a fresh credential check is told it got one.

- **触发/利用�?* An RP protecting a sensitive operation sends /oauth/authorize?...&max_age=300 (or prompt=login) for a user whose browser session is already hours old. The user is taken straight to the consent screen (no credential prompt), clicks approve, and the id_token carries auth_time = the click time. The RP accepts the token as freshly authenticated. An attacker holding a stolen-but-still-valid session cookie (Lifetime 24h / IdleTimeout 2h) can therefore satisfy an RP's step-up requirement without any credential, and the false auth_time claim is signed by the OP so a verifier cannot detect it. The same path satisfies prompt=login, which is documented as 'always requires a fresh authentication'.

- **修复建议�?* Make the login boundary enforce the requirement instead of relabelling it: when the pending request RequiresReauthentication(now), the authorize/login redirect must send the browser through the IdP sign-in flow again (e.g. /auth/{provider}/start?mode=login&return_to=<resume URL>) and only CompleteLogin after a new SignIn has stamped a fresh auth_time; otherwise never overwrite AuthTime with the decision time. Keep SetAuthTime's value as the authoritative auth_time, and add a regression test that a max_age=0 / prompt=login request with a 2h-old session results in a new authentication (new AuthenticatedAt), not just a new auth_time.

- **验证备注�?* Mechanism independently confirmed end to end. (1) The library's Authorize always calls RedirectToLogin for a request that is not Done, with no session branch (pkg/op/auth_request.go:145-150,442), so a live session still goes to the login hook. (2) cmd/re0auth/main.go:1331-1342's login hook only binds the request and copies sessions.AuthenticatedAt via SetAuthTime; it never reads prompt/max_age and never forces a credential prompt. (3) The consent API response (internal/httpapi/authorization_routes.go:109-115) carries only id/client/scopes/missing_bindings/csrf_token, so the SPA cannot learn the freshness requirement either. (4) CompleteLogin reacts to RequiresReauthentication==true by overwriting AuthTime with the store clock (memory/oidc.go:1274, postgres/oidc.go:1269); the id_token's auth_time is then taken from request.GetAuthTime() (pkg/op/token.go:211). So prompt=login / max_age never trigger a re-authentication, and the signed auth_time reports the consent-click time for an authentication that did not occur. I ran the in-tree probe TestZ02MaxAgeAndPromptLoginAreIgnored (audit6 tag) and it passed: with a 2h-old session, prompt=login, max_age=0 and max_age=1 all complete and the id_token's auth_time is the decision time (the control asserts a plain request keeps the stale sign-in). OIDC Core §3.1.2.1 requires an attempt to re-authenticate for max_age; prompt=login is at minimum a SHOULD, and a fail-closed login_required is the permitted alternative. A borrowed/stolen 24h session (IdleTimeout 2h) can satisfy an RP's step-up bound that the OP falsely attests. High retained.

### H2. S03-1 �?Unbounded caller-controlled return_to persisted in the server-side session

- **严重�?/ 类别�?* high / performance；原�?high，验证结�?**confirmed**
- **位置�?* `internal/auth/auth.go:612; internal/auth/auth.go:616; internal/auth/auth.go:289; safeurl/safeurl.go:34`
- **证据�?*

```go
returnTo := safeurl.RelativePath(r.URL.Query().Get("return_to"))
	h.manager.sessions.Put(ctx, keyFlowState, state)
	h.manager.sessions.Put(ctx, keyFlowProvider, string(provider))
	h.manager.sessions.Put(ctx, keyFlowMode, mode)
	h.manager.sessions.Put(ctx, keyFlowReturnTo, returnTo)
```

- **成因与影响：** safeurl.RelativePath only enforces form (leading single slash, no backslash, url.Parse-able); it has no length bound, so return_to is stored verbatim in the session. Scs re-encodes the whole session value map and commits it at response end, so each anonymous GET /auth/{provider}/start can persist up to ~64 KiB (server maxHeaderBytes) of attacker-chosen bytes, for the session's full 24h lifetime. There is no cap on the number of sessions either: a request without a cookie creates a new one (scs Lifetime default 24h, Persist=true, and the in-memory memstore used when no database is configured sweeps only by expiry). This directly contradicts the discipline already applied to handles in the same file, where maxBoundHandleBytes=128 exists precisely because 'a session is rewritten whole, so its bytes must not be caller-chosen (Z07-3)'.

- **触发/利用�?* Unauthenticated loop, no cookie, registered provider: GET /auth/github/start?return_to=/AAAA...(60 KiB). Each request allocates a fresh session whose payload is dominated by return_to; in memory mode (cmd/re0auth/main.go:892-903 wires auth.NewManager with a nil Store -> scs memstore) this is unbounded process RAM, and in Postgres mode it is unbounded growth of sessions.data bytea. The default limiter is 50/s per (plane,/64) with burst 100, i.e. ~3 MB/s and ~180k sessions/hour from one address, none collected for 24h.

- **修复建议�?* Bound return_to the same way handles are bounded: add a maxReturnToBytes constant (e.g. 2048) and drop/refuse anything longer before Put. Optionally also cap total session bytes and the number of live sessions in the memory store.

- **验证备注�?* The mechanism is real. handleStart stores safeurl.RelativePath(q.Get("return_to")) into the scs session with no byte bound (auth.go:612,616); safeurl.RelativePath only enforces form (safeurl.go:34-52), while the same file refuses bound handles over 128 bytes (auth.go:289,316) precisely because the session is rewritten whole. A cookie-less GET gets a fresh sessionData; Put sets Modified, so scs mints a token and commits a row + Set-Cookie (scs data.go:99-104,155-162; session.go:169-183). MaxHeaderBytes=64 KiB (main.go:118-123) bounds one return_to at ~60 KiB, so each request buys ~60 KiB of persisted state. Two discovery details are overstated and are corrected here: (a) the committed expiry is min(24h lifetime, now+2h IdleTimeout) because scs Commit uses the idle expiry (data.go:111-117; auth.go:93-97), so retention is ~2h, not 24h; (b) memstore has a 1-minute cleanup goroutine (memstore.go:22-23,102-140), so memory mode is bounded (~50/s x 2h = ~360k sessions, ~21GB) rather than literally unbounded. Neither correction removes the impact: the Postgres path is effectively unbounded because SweepExpired deletes at most 1000 rows per 15-minute tick (sessions.go:152-184; main.go:406) = ~1.1 rows/s against 50/s arrivals, so a sustained unauthenticated loop outruns the sweep and grows sessions.data/disk without bound; memory mode still reaches ~21GB. The default limiter is 50/s burst 100 per (plane,/64) (main.go:225-229; config.go:354-355; middleware.go:488-504), so the cited ~3MB/s is right. Availability-only DoS, unauthenticated, requires only one registered IdP. High stands.

### H3. S06-1 �?OIDC discovery and JWKS fetches read an unbounded upstream body (go-oidc io.ReadAll) while the adapter's own 1 MiB cap does not apply

- **严重�?/ 类别�?* high / security；原�?high，验证结�?**confirmed**
- **位置�?* `idp/idp.go:298; idp/idp.go:711; idp/idp.go:836`
- **证据�?*

```go
		hc = httpclient.NewOutboundClient(httpclient.OutboundConfig{
			Timeout:   10 * time.Second,
			Transport: httpclient.TransportConfig{DenyPrivateAddresses: true},
		})
...
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, c.http), c.issuer)
...
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
```

- **成因与影响：** idp caps its own userinfo/QQ reads at 1 MiB (idp/idp.go:836) but the OIDC discovery document and the JWKS key set are fetched by go-oidc, which does `body, err := io.ReadAll(resp.Body)` (go-oidc v3.21.0 oidc/oidc.go:312 for discovery and oidc/jwks.go:315 for keys) with no size limit. The only bound is the client's Timeout, which limits time, not bytes; net/http auto-decompresses gzip, so a gzip bomb amplifies the allocation. One login can therefore allocate gigabytes and kill the process.

- **触发/利用�?* A configured OIDC provider (self-hosted Keycloak/Authentik, or a compromised/hijacked public IdP such as the issuer named in Credentials.Issuer) serves /.well-known/openid-configuration or its jwks_uri as an endless/deflated body. Discovery is fetched at every providerTTL boundary (default 15 min), and the JWKS whenever the id_token's kid misses the cache; the process OOMs during a normal sign-in.

- **修复建议�?* Wrap the http.Client handed to oidc.ClientContext in a RoundTripper that caps the response body (both ContentLength check and a hard LimitReader on resp.Body), or build the oidc.Provider/key set from a bounded fetch. The 1 MiB cap already used by getText is the right bound to apply here too.

- **验证备注�?* Independently confirmed against go-oidc v3.21.0 in the module cache. oidc.NewProvider does `body, err := io.ReadAll(resp.Body)` (oidc/oidc.go:312) with no LimitReader/ContentLength check, and RemoteKeySet.updateKeys does the same (oidc/jwks.go:315). The client the adapter hands over (idp/idp.go:298-301, or an injected one) is a plain *http.Client over httpclient.NewTransport; NewTransport sets no DisableCompression and wraps no byte limit (httpclient/outbound.go:91-110, 304-321), so net/http's transparent gzip is on and io.ReadAll is bounded only by http.Client.Timeout (10s), not by bytes. The adapter's own 1 MiB cap at idp/idp.go:836 applies only to getText/userinfo. A 10 MB gzip bomb at 1000:1 inflates to ~10 GB, and a fast/stalled issuer can deliver that inside the 10s budget; the process OOMs. Discovery is reachable from the unauthenticated GET /auth/{provider}/start -> AuthCodeURL -> oauthConfig -> oidcProvider whenever the 15-min providerTTL has elapsed; the JWKS read (idp/idp.go:648 -> verifier.Verify) re-fires on any kid cache miss. Impact follows; high stands.

### H4. S08-2 �?storage.dsn_env is never resolved when driver is inferred in the config loading logic

- **严重�?/ 类别�?* high / correctness；原�?high，验证结�?**confirmed**
- **位置�?* `cmd/re0auth/config.go:680-710; cmd/re0auth/config.go:472; cmd/re0auth/config.go:722-724; cmd/re0auth/config.go:749-759; cmd/re0auth/main.go:892-917`
- **证据�?*

```go
driver := config.FirstNonEmpty(strings.TrimSpace(os.Getenv("RE0AUTH_STORAGE_DRIVER")), f.Storage.Driver)
switch driver {
case "":
	if f.Storage.DSNEnv != "" || cfg.DatabaseURL != "" {
		driver = "postgres"
	} else {
		driver = "memory"
		cfg.StorageReason = "no DATABASE_URL is configured"
	}
case "memory":
	driver = "memory"
	cfg.StorageReason = "storage.driver is memory"
case "postgres":
	if cfg.DatabaseURL == "" {
		dsnEnv := f.Storage.DSNEnv
		if dsnEnv == "" {
			dsnEnv = "DATABASE_URL"
		}
		dsn, err := config.Secret(dsnEnv, "storage.dsn_env")
		if err != nil {
			return settings{}, err
		}
		cfg.DatabaseURL = dsn
	}
default:
	return settings{}, fmt.Errorf("storage.driver %q must be \"memory\" or \"postgres\"", driver)
}
```

- **成因与影响：** cfg.DatabaseURL is pre-loaded only from the literal DATABASE_URL (config.go:472). When Driver is empty and dsn_env names some other variable, the switch sets driver = "postgres" but never calls config.Secret on that name, so DatabaseURL stays empty. openStorage then takes the memory branch (main.go:892) even though StorageDriver says postgres. The consequences of that silent downgrade are broad: RE0AUTH_AUDIT_KEY is not required (config.go:749 gates on cfg.DatabaseURL), the audit sink is the non-tamper-evident in-memory ring buffer, sessions/bindings/OP state disappear on restart, max_in_flight is sized for memory rather than the pool (config.go:723), and reportDurability prints because="" (StorageReason was never set). The declared-but-unset variable that should be a hard "names an environment variable that is not set" error instead becomes ephemeral storage. A secondary manifestation of the same hardcoded-name preference: with an explicit driver = "postgres", a stale DATABASE_URL in the environment wins over the file's dsn_env and the process connects to the wrong database.

- **触发/利用�?* config/re0auth.toml contains [storage] dsn_env = "RE0AUTH_DSN" with no driver, and RE0AUTH_DSN is set; DATABASE_URL is not. The server starts with an in-memory store, silently, and a restart after a deploy loses every session, binding, pending request and audits record. If DATABASE_URL is also leaked in from a base image, it instead overrides the operator's declared variable and points at whatever database that URL names.

- **修复建议�?* Resolve the DSN in the inferred branch with the same code the explicit branch uses (dsnEnv := f.Storage.DSNEnv; if empty, use DATABASE_URL; config.Secret it), so DatabaseURL is non-empty whenever driver resolves to postgres. Treat the declared-but-unset variable as a startup error, and stop reading the literal DATABASE_URL ahead of the file's dsn_env.

- **验证备注�?* CONFIRMED and reproduced with a temporary in-package probe. Config [storage] dsn_env="RE0AUTH_DSN" with RE0AUTH_DSN set, DATABASE_URL unset, driver omitted returned driver="postgres", DatabaseURL="", StorageReason="" and no error. The inferred branch at config.go:682-688 sets driver="postgres" but never calls config.Secret on f.Storage.DSNEnv (only the explicit "postgres" branch at :692-703 does). openStorage (main.go:892) then takes the memory branch purely on cfg.DatabaseURL=="", so StorageDriver says postgres while the process runs in memory. Downstream consequences verified: the durable-audit gate at config.go:749 is skipped (RE0AUTH_AUDIT_KEY not required), the audit sink is the non-tamper-evident memory ring, sessions/bindings/OP state do not survive restart, maxInFlight is sized via defaultMaxInFlightFor(cfg.DatabaseURL != "", ...) at :722-723 as memory (512), and reportDurability logs because="" (main.go:995-999). This is precisely the 'setting that looks applied and is not' class the surrounding validation exists to prevent; the file explicitly documents that dsn_env alone selects postgres (config.go:147-150). Secondary observation also true: with an explicit driver, a stale DATABASE_URL pre-loaded at :472 shadows the file's dsn_env at :693 (this is the env>file convention, so I treat it as a lesser note, not the finding's core).

### H5. S10-1 �?In-flight per-client cap is keyed per (plane, client), so one address can occupy the entire process-wide concurrency cap

- **严重�?/ 类别�?* high / reliability；原�?high，验证结�?**confirmed**
- **位置�?* `internal/httpapi/middleware.go:434; internal/httpapi/middleware.go:459; internal/httpapi/middleware.go:466; internal/httpapi/middleware.go:491`
- **证据�?*

```go
sem := make(chan struct{}, s.maxInFlight)
	perClient := s.maxInFlight / 2
...
		key := s.bucketKey(r)
		mu.Lock()
		if active[key] >= perClient {
			mu.Unlock()
			refuse(w, r)
			return
		}
		active[key]++
...
func (s *Server) bucketKey(r *http.Request) string {
	return planeOf(r.URL.Path).String() + "|" + aggregateClientKey(s.clientKeyOf(r))
}
```

- **成因与影响：** The comment above withInFlightLimit states the guarantee: "one (plane, client) may hold at most half of it, and the other half is headroom every other client draws from". That guarantee holds only per key, and the key includes the plane (planeOf(...).String()). The shared semaphore is process-wide but the per-client counter is per (plane, client): a single source address that touches two namespaces gets two independent maxInFlight/2 allowances whose sum is the whole cap. With the shipped defaults (defaultMaxInFlightMemory = 512, cmd/re0auth/config.go:359) and maxInFlight/2 = 256, 256 concurrent requests under /oauth plus 256 under a non-protocol path (browser or /v1) fill all 512 slots. The rate limiter does not prevent this: it bounds arrivals over time, not slots held; probes are exempt from both, so /healthz and /readyz stay green while the whole service answers 503 "server busy" to every other client. This is exactly the single-address denial of service the per-client split was added to prevent.

- **触发/利用�?* One source IP opens 256 connections to /oauth/token and trickles each form body (approximately 2 KiB/s) so each handler blocks reading for the 30 s ReadTimeout (cmd/re0auth/main.go:117), and 256 connections to a large SPA asset under /app/_app/immutable/ that are never read, so the handlers block on Write for up to the 60 s WriteTimeout. Every slot in the global semaphore is then held by that one address; all non-probe traffic from every other client receives 503 problem+json/OAuth temporarily_unavailable until the attacker stops. (An authenticated account can substitute slow JSON bodies on /v1 endpoints for the asset half.)

- **修复建议�?* Enforce the half-cap on the client identity alone rather than on the (plane, client) key: keep a second map keyed by aggregateClientKey(s.clientKeyOf(r)) for the concurrency counter (or reserve a global emergency pool that per-plane keys cannot consume), so the sum of one address's slots across planes cannot exceed maxInFlight/2. Add a test that saturates two planes from one peer and asserts other peers are still admitted.

- **验证备注�?* Confirmed by source and by an independent runtime probe. withInFlightLimit keys its per-client counter on s.bucketKey(r) = plane + client (middleware.go:459,491-493) while the semaphore is process-wide (middleware.go:434), and perClient = maxInFlight/2 (middleware.go:435). A single client address therefore gets one maxInFlight/2 allowance per plane, and its total across the three planes can equal the whole cap. I wrote a temporary test in package httpapi: Server{maxInFlight:4} (perClient=2), one RemoteAddr issued 2 requests to /oauth/token (planeProtocol) and 2 to /v1/me (planeBusiness); all four slots were held by that one address and a second client address received 503. The rate limiter does not prevent this: it bounds arrivals over time (default 50/s burst 100, config.go:354-355) but not slots held, and per-plane buckets are independent, so ~100 burst + 50/s for ~3s is enough to push in 256 slow requests whose slots are held for the 30s ReadTimeout / 60s WriteTimeout (main.go:117-118). Probes are exempt (middleware.go:455), so /healthz and /readyz stay 200. This defeats the stated guarantee in the comment at middleware.go:423-425 ('at most half of it, and the other half is headroom every other client draws from'). Existing TestInFlightCapIsSharedPerClient only exercises a single plane (/v1/me) and does not cover this. Severity kept at high.

### H6. S13-1 �?Compression 406 refusal runs before the rate limiter and the in-flight cap, fully bypassing both

- **严重�?/ 类别�?* high / security；原�?high，验证结�?**confirmed**
- **位置�?* `internal/httpapi/server.go:638; internal/httpapi/server.go:642; internal/httpapi/server.go:643; internal/compress/compress.go:147`
- **证据�?*

```go
server.go:638-645
	h = s.withBodyLimit(h)
	h = s.withRateLimit(h)
	// In-flight wraps the limiter: concurrency is the harder bound, so it answers
	// before a rate-limited request spends a token.
	h = s.withInFlightLimit(h)
	if s.compressor != nil {
		h = s.compressor.Handler(h)
	}

compress.go:147-152
		coding, acceptable := negotiate(r.Header.Get("Accept-Encoding"), c.names)
		if !acceptable {
			addVary(w.Header(), "Accept-Encoding")
			c.notAccept(w, r)
			return
		}
```

- **成因与影响：** The middleware chain is built so the compressor wraps withInFlightLimit, which wraps withRateLimit. When negotiation finds no acceptable representation, compress.Handler writes its own 406 and returns WITHOUT calling next, so neither the rate limiter (ratelimit.Limiter.Check) nor the global concurrency semaphore in withInFlightLimit ever runs. Every such request still costs a request-id (crypto/rand), a trusted-proxy client-key derivation, the full middleware/log path and an access-log write, but consumes no rate-limit token and holds no in-flight slot. The 406 body is cheap, so the primary impact is that the two anti-abuse bounds are disabled on a path any unauthenticated caller can drive without limit: unbounded concurrent connections/goroutines and an unbounded access-log flood. The in-flight cap is documented as the bound that 'protects memory and database connections when many slow requests arrive together'.

- **触发/利用�?* Send any request to a non-protocol path (any /v1/*, /auth/*, / or the SPA) with `Accept-Encoding: *;q=0` (or `identity;q=0`). negotiate() returns acceptable=false (wildcard q=0 zeroes identity too), the compressor writes 406 and never calls the limiter. Repeat with as many parallel connections as desired; RateLimit-* headers are absent and the Retry-After/in-flight 503 never appear, while each request is still logged at info. A variant with a large Accept-Encoding containing ';' also forces the allocating general parse path before any limiter runs.

- **修复建议�?* Move the compressor inside the limiter and in-flight cap (place withRateLimit/withInFlightLimit outside s.compressor.Handler), or have the compressor call next after writing its negotiation failure so accounting still runs (e.g. let the negotiation decision be made by a middleware that has already passed check-in). Add a regression test asserting a 406 consumes a limiter token / an in-flight slot.

- **验证备注�?* Chain order proven at internal/httpapi/server.go:619-647: withCanonicalPath/sessions/withBodyLimit/withRateLimit/withInFlightLimit are layered inside compressor.Handler (h = s.compressor.Handler(h) at 644). compress.Handler (internal/compress/compress.go:147-152) calls c.notAccept(w,r) and returns without next.ServeHTTP when negotiate reports acceptable=false. negotiate returns ('', false) for `*;q=0` / `identity;q=0` via compress.go:229-238 (identityQ = star = 0). withRequestContext, withAccessLog and metrics.Middleware are outside compression (server.go:647-654), so each refused request still pays request-id generation, trusted-proxy client-key derivation, the access log line and the request counter, while consuming no limiter token and holding no in-flight slot. The design is deliberate for security headers (server.go:610-618) and the project's own test comment says so ('it refuses without ever calling next', internal/httpapi/security_headers_test.go:124-141; test at internal/zzprobe/audit6/z06httpedge/compress_test.go:300 drives `identity;q=0, *;q=0`). Reachable unauthenticated on every non-protocol path (eligible = planeOf != planeProtocol, server.go:353-355). Impact: both anti-abuse bounds are disabled on a caller-driven path -> connection/goroutine burst and access-log flood past the configured per-address rate. High stands.

### H7. S13-5 �?OIDC memory store maps are uncapped; refresh tombstones grow one per rotation for the full 30-day refresh TTL and the 5-minute sweep scans them all under the global lock

- **严重�?/ 类别�?* high / performance；原�?high，验证结�?**confirmed**
- **位置�?* `internal/store/memory/oidc.go:34; internal/store/memory/oidc.go:44; internal/store/memory/oidc.go:52; internal/store/memory/oidc.go:639; internal/store/memory/oidc.go:1153; internal/store/memory/oidc.go:1174; internal/store/memory/oidc.go:1180; internal/store/memory/oidc.go:1488`
- **证据�?*

```go
oidc.go:33-54 (single mutex, uncapped maps)
type OIDCStore struct {
	mu       sync.Mutex
	...
	refreshTokens     map[string]refreshToken
	refreshTombstones map[string]refreshTombstone
	...

oidc.go:639-646 (tombstone per rotation, lifetime = spent token's 30d expiry)
		s.refreshTombstones[spent] = refreshTombstone{
			familyID:  familyID,
			idHash:    held.idHash,
			clientID:  held.clientID,
			subject:   held.subject,
			expiresAt: held.expiresAt,
		}
		s.deleteRefreshLocked(spent)

oidc.go:1174-1185 (full scans under the lock, every sweep)
	for k, t := range s.accessTokens {
		if !now.Before(t.expiresAt) {
			s.deleteAccessLocked(k)
			removed++
		}
	}
	for k, t := range s.refreshTokens {
		if !now.Before(t.expiresAt) {
			s.deleteRefreshLocked(k)
			removed++
		}
	}
```

- **成因与影响：** Every map in the in-memory OP store (authRequests, codes, accessTokens, refreshTokens, refreshTombstones, devices, userCodes) has no count cap. The worst is refreshTombstones: refresh-token rotation is the normal token-endpoint path and it writes one tombstone per rotation, retained until the spent token's own expiry - 30 days by default. Nothing bounds rotation rate per subject or per process; the only backstop is the per-address rate limiter (default 50/s, bypassable per S13-1). At even 1 rotation/s one client accumulates ~2.6M tombstones in 30 days; at the default limit, ~130M entries, each with a 64-hex key plus a struct and map overhead. The 5-minute opJanitor (cmd/re0auth/main.go:81, opJanitorInterval=5m) then ranges over all of them while holding s.mu, so the sweep perf window grows without bound and the sweep's critical section periodically freezes every auth/token operation. The Kill Switch 'all' path also materializes every key into a new slice under the lock (accessKeysLocked/refreshKeysLocked/requestKeysLocked, oidc.go:161-207), so a large table makes an operator's revocation allocate hundreds of MB while blocking the store. In-memory mode is a supported deployment (ADR-0001 P4b: a deployment without DATABASE_URL gets this store), so this is an availability issue, not just a test artifact.

- **触发/利用�?* A registered confidential/public client with one live refresh token calls POST /oauth/token grant_type=refresh_token in a loop. Each call rotates and leaves a tombstone that survives 30 days. A single source at the default 50 req/s yields on the order of 10^8 tombstones (multiple GB) before any expires, ending in OOM or GC death; even far lower rates make each 5-minute sweep a multi-second global stall. Distributed sources scale the rate past the per-address cap, and the documented limiter bypass in S13-1 removes even that bound.

- **修复建议�?* Bound the store: cap total records/tombstones (or tombstones per family/subject) and shed/reject past the cap; consider storing only the most recent spent value per family when the replay window can be expressed that way. Run SweepExpired without holding the single mutex (swap-in a fresh map under the lock, scan/delete outside), or shard the store as the limiter does. Document/guard memory mode with an explicit maximum-record config.

- **验证备注�?* Core claim verified. Every map in memory/oidc.go:33-54 has no count cap; each refresh rotation writes exactly one tombstone keyed by the spent value hash with expiresAt = held.expiresAt, i.e. the spent token's own 30-day expiry (639-646; refreshTTL = 30*24h at 334), then deletes the live row. SweepExpired ranges the whole refreshTombstones map (and every other map) while holding s.mu (1153-1197) and is driven every 5 minutes (cmd/re0auth/main.go:81,573). In-memory mode is a supported deployment (same no-DATABASE_URL branch, main.go:892-916). An authenticated client holding one offline_access refresh token can rotate at up to the per-address budget and leave one 30-day tombstone per call: at the default 50 req/s that is ~1.3e8 entries, multi-GB, ending in OOM or GC death; even 1 req/s leaves ~2.6M. Two corrections to the evidence, neither changing the verdict: (a) /oauth/token is protocol plane (internal/oidchttp/oidchttp.go:38,200) and the compressor's Eligible predicate excludes the protocol plane (server.go:353-355), so the S13-1 limiter bypass does NOT apply to the refresh endpoint -- the per-address rate limiter still runs there; distributed sources are what scale it. (b) The Kill Switch allocation addendum concerns the live access/refresh/auth-request maps (accessKeysLocked/refreshKeysLocked/requestKeysLocked, oidc.go:161-207); tombstones are ranged in place at 1512-1518 and are not materialized into a slice, so 'hundreds of MB' from tombstones during revocation is wrong, though RevokeTokens does range them under the lock. High stands on the unbounded-growth/OOM and periodic multi-second lock hold.

### H8. S14-2 �?federation.CompleteBind writes the vault secret and the binding row without the per-binding keyed mutex, so an in-flight bind can resurrect a just-revoked binding

- **严重�?/ 类别�?* high / security；原�?high，验证结�?**confirmed**
- **位置�?* `internal/federation/bind.go:192; internal/federation/bind.go:198; internal/federation/unbind.go:50; internal/federation/revocation.go:132; internal/federation/killswitch.go:201; internal/federation/refresh.go:40`
- **证据�?*

```go
// bind.go CompleteBind - no s.locks.lock anywhere in the method
	if err := s.storeBindingSecret(ctx, binding, bindingSecret{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}); err != nil {
		return Binding{}, flow, err
	}
	if err := s.bindings.Put(ctx, binding); err != nil {

// unbind.go - every other writer takes the key
	unlock := s.locks.lock(bindingKey(user, game, source))
	defer unlock()
// revocation.go CascadeRevoke:
	unlock := s.locks.lock(bindingKey(user, game, source))
// killswitch.go shredBinding:
	unlock := s.locks.lock(bindingKey(b.User, b.Game, b.Source))
// refresh.go refreshBinding:
	unlock := s.locks.lock(bindingKey(current.User, current.Game, current.Source))
```

- **成因与影响：** The per-binding keyedMutex (refresh.go:214-248) is documented as the mechanism that orders every writer of one binding's credential: Unbind takes it 'for the whole call' (unbind.go:41-51) so a refresh cannot write a secret back after an unbind shredded it; shredBinding takes it for the same reason (killswitch.go:195-202); CascadeRevoke takes it (revocation.go:128-133). CompleteBind is the one writer that stores a fresh secret (vault write) and then an unconditional Bindings.Put (the store's Put overwrites any Version), and it takes no lock. Therefore a bind callback that lands concurrently with Unbind / CascadeRevoke / RevokeUserBindings / RevokeAllBindings can re-create the binding row and a live upstream token AFTER the removal reported success. It also defeats the CAS ordering refreshBinding relies on: refreshBinding claims the row with PutIfVersion and only then writes the vault, all under the lock; CompleteBind's unconditional Put ignores Version and can replace or reintroduce the row underneath it.

- **触发/利用�?* A user or an operator revokes a binding while an upstream bind callback is still in flight (two tabs, or a Kill Switch sweep running while a bind completes). Unbind/Cascade/shred finishes (row deleted, secret shredded), then CompleteBind's storeBindingSecret + bindings.Put re-creates the binding and a valid upstream credential. The user was told the source was disconnected and the operator was told the Kill Switch swept every binding, yet the source remains connected and usable. A compromised session can deliberately stage a bind and complete it after the victim runs the Kill Switch.

- **修复建议�?* Take the same per-binding keyedMutex in CompleteBind for the whole store-and-put sequence (and re-read the row first, refusing to bind if the account has just unbound), or make the row+secret write a single compare-and-swap that a concurrent Delete invalidates. At minimum, write the row first with the store's versioned primitive and roll the secret back on failure, under the lock.

- **验证备注�?* Confirmed and no guard was missed. CompleteBind performs storeBindingSecret (vault Enroll under BindingIdentity = user\|game.source, version-independent) and then an unconditional bindings.Put with no s.locks.lock anywhere (bind.go:180-217); MemoryBindingStore.Put overwrites by key regardless of Version (binding.go:181-187). Every other credential writer takes the per-binding keyedMutex for its whole critical section: Unbind (unbind.go:41-51), CascadeRevoke (revocation.go:128-133), shredBinding (killswitch.go:196-202), refreshBinding (refresh.go:40-41, 111-128). Because CompleteBind does not, the interleaving Unbind(vault.Revoke; bindings.Delete) -> CompleteBind(storeBindingSecret; bindings.Put) re-creates both a live vault secret and a binding row after the removal already returned success, and the row/key use the same identity so the resurrected credential is usable. This is reachable: the bind callback (federation_routes.go:410-423) and federation Unbind (binding_routes.go:135-153) are independent HTTP paths with no per-user serialization, and the flow single-use check only prevents replaying one CompleteBind, not overlapping it with an Unbind. Kill Switch reaches the same removal via CascadeRevoke/Unbind/shredBinding (killswitch.go:160-192). Severity kept at high because this bypasses an explicit, user- or operator-requested revocation control; the concurrency preconditions (two overlapping authorized operations for one binding) are the only reason it is not higher, but they are not privileged and the window is real.

## 2. 中危发现（Medium，共 30 条）

| ID | 类别 | 标题 | 位置 | 简�?|
|---|---|---|---|---|
| S01-1 | security | An approved device_code is redeemable repeatedly: every poll mints a fresh token pair instead of consuming the device authorization | `oauth/device.go:302-308; oauth/device.go:269-309` | PollDeviceAuthorization never invalidates or consumes the approved device record. Once a record reaches DeviceApproved, every later poll falls through the switch and calls s.issue again, minting a brand-new access+refresh pair (each in a brand-new family, beca�?|
| S01-2 | reliability | MemoryDeviceStore never prunes pending/decided device records and exposes no sweep API, so device authorizations grow unbounded | `oauth/device.go:139-163; oauth/device.go:224-247; oauth/as.go:57-59` | SaveDevice inserts into byDev and byUser and nothing in the package ever deletes from either map: MemoryDeviceStore has no delete, no expiry sweep and no SweepExpired counterpart to MemoryStore.SweepExpired. Expiry is enforced only on read. Every BeginDeviceAu�?|
| S01-3 | correctness | MemoryStore.ConsumeRefresh ignores the tombstone deadline, so expired spent refresh values still trigger family revocation while the Postgres store correctly reports them unknown | `oauth/tokens.go:440-450; oauth/tokens.go:248-261; oauth/as.go:264-283; internal/store/postgres/oauth.go:269-284` | The tombstone carries ExpiresAt and the struct comment promises it 'expires on the spent token's own deadline', but ConsumeRefresh never reads tomb.ExpiresAt; any tombstone still resident in the map is reported as *RefreshReuseError regardless of age. The only�?|
| S01-6 | security | AuthenticateClient treats public clients as always authenticated, so the cascade-revocation gate does not actually gate public clients | `oauth/as.go:437-448; oauth/as.go:89-92; upstreamkit/server.go:330-357` | client(..., auth=true) only verifies a secret when c.Type == ClientConfidential. For a public client the supplied secret is ignored and the call succeeds unconditionally. upstreamkit handles POST /oauth/cascade_revocation by first calling AuthenticateClient an�?|
| S02-2 | correctness | prompt=none with a live session redirects into the interactive consent UI instead of returning consent_required | `internal/oidchttp/oidchttp.go:991; internal/oidchttp/oidchttp.go:995; cmd/re0auth/main.go:1341` | Only the no-session half of OIDC Core §3.1.2.1 is implemented. Re0Auth has no remembered/pre-configured consent: every authorization creates a fresh AuthRequest that only CompleteLogin marks Done, and CreateAuthRequest never consults existing grants. So with a�?|
| S02-3 | correctness | Device authorization endpoint refuses spec-compliant Basic secrets: id is form-unescaped, secret is not | `internal/oidchttp/oidchttp.go:1114; internal/oidchttp/oidchttp.go:1152; internal/oidchttp/oidchttp.go:1175` | basicID is decoded with url.QueryUnescape two lines before use, but the paired basicSecret is passed raw to client.Authenticate, which hashes it and compares with the stored SHA-256 of the plaintext secret. RFC 6749 §2.3.1 requires a client to form-urlencode b�?|
| S02-4 | security | ValidateSigner enforces the 2048-bit floor on the current key only, not on retired keys published in the JWKS | `internal/oidcstore/oidcstore.go:62; internal/oidcstore/oidcstore.go:69; internal/oidcstore/oidcstore.go:73` | RetiredSigningKey.Public is published by Signer.KeySet() alongside the current key and is used by object ID token hint / access-token verification (op.OpenIDKeySet over the whole KeySet). The guard reason ('a small RSA key is not a defensible signature at this�?|
| S04-1 | security | Enabled device authorization is never consumed: one device_code mints unlimited token pairs and silently undoes a grant revocation | `oauth/device.go:302-309; oauth/device.go:124-137; oauth/grants.go:128-137` | PollDeviceAuthorization treats a DeviceApproved record as reusable forever: the read at line 274 is followed by an unconditional s.issue(...) and nothing marks the record spent or deletes it. DeviceStore (lines 124-137) exposes no consume/claim operation, so t�?|
| S05-1 | reliability | Refresh rejection classifies every 400/401/403 as a dead grant and crypto-shreds the binding | `internal/federation/refresh.go:170; internal/federation/refresh.go:179; internal/federation/refresh.go:142` | A 400/401/403 is treated as a definitively dead grant regardless of the OAuth error code or the response body. refreshRejected then does vault.Revoke (crypto-shreds the upstream token) plus bindings.Delete (refresh.go:151-165). RFC 6749 defines retryable/confi�?|
| S05-2 | security | CompleteBind bypasses the per-binding keyed lock, so a completing bind can resurrect a row and secret after Unbind or account erasure | `internal/federation/bind.go:157; internal/federation/bind.go:192; internal/federation/bind.go:198; internal/federation/unbind.go:50; internal/federation/killswitch.go:200` | Every removal/mutation path (refreshBinding refresh.go:40, Unbind unbind.go:50, CascadeRevoke revocation.go:132, shredBinding killswitch.go:201) takes s.locks.lock(bindingKey(user,game,source)) so that a refresh cannot write a secret back after a removal. Begi�?|
| S06-2 | security | DenyPrivateAddresses is applied to the proxy address, not the target, whenever an HTTP(S) proxy is configured in the environment | `httpclient/outbound.go:92; httpclient/outbound.go:95; httpclient/outbound.go:42` | http.ProxyFromEnvironment makes net/http dial the proxy; DialContext (and therefore the Control hook, and therefore IsPublicAddress) is handed the proxy's address. The target host is never resolved or checked by this process. The field's own doc-comment claims�?|
| S06-3 | performance | oidcProvider holds providerMu across a network discovery round trip, and a failed discovery is not cached, so a dead issuer serializes every concurrent login | `idp/idp.go:705; idp/idp.go:711; idp/idp.go:713` | The mutex is held for the whole oidc.NewProvider call, which is a network fetch with a 10s client timeout. A failed discovery does not advance discoveredAt and is not negatively cached ('A failed discovery is not cached, so it can be retried on the next reques�?|
| S06-4 | performance | SocialLogin.states is an unbounded map swept in O(n) on every unauthenticated start request | `referencesource/social.go:102; referencesource/social.go:104; referencesource/social.go:193` | There is no cap on the number of in-flight authorizations and no periodic sweeper; expiry is enforced only by a full map scan performed under the mutex on each new start. An unauthenticated flood of GET /login/{provider}/start grows the map (bounded only by th�?|
| S06-5 | performance | TapTapLogin.attempts is an unbounded map with an O(n) sweep per challenge, reachable unauthenticated | `referencesource/taptap.go:124; referencesource/taptap.go:126; referencesource/taptap.go:258` | Same shape as the social login: one entry per POST /login/taptap/challenge, no cap, and the only expiry is a full O(n) scan run under the mutex on each begin. Each entry holds a DeviceAuth including the verification URL/codes, so the memory per entry is non-tr�?|
| S07-1 | security | Credential-bearing outbound requests rely entirely on the injected Doer for redirect policy; custom auth headers are copied to cross-host redirect targets by net/http | `tapsign/client.go:114; tapsign/client.go:115; tapsign/client.go:125; taptapoauth/client.go:195` | The long-lived TapTap session token is sent as X-LC-Session and the app key as X-LC-Key, and taptapoauth sends the MAC Authorization header. When the Doer is an *http.Client whose CheckRedirect is nil (the stdlib default), the client follows redirects. net/htt�?|
| S07-2 | reliability | vault.Enroll persists the credential before writing its audit event, so an audit failure returns an error for a write that already happened and leaves an un-audited (and in federation, orphaned) secret | `vault/service.go:245; vault/service.go:259` | Unlike Use (which fails closed before handing over the plaintext, service.go:334-339), Enroll writes the encrypted credential first and audits second. If the audit sink fails the caller is told the enrollment failed while the credential is stored and unaudited�?|
| S08-1 | security | Vault KEK resolution hardcodes RE0AUTH_KEK ahead of vault.kek_env, silently ignoring a renamed key | `cmd/re0auth/config.go:729-743; cmd/re0auth/config.go:471; scripts/backup-keys.sh:74-77` | The file convention the package documents is that a config NEVER holds a secret and instead names the environment variable holding it; every other setting resolves as FirstNonEmpty(env, file) or through a dedicated RE0AUTH_ override, and -print-secret-env / sc�?|
| S08-4 | correctness | DeleteAccount reports success and writes outcome=ok when the binding sweep has Failed>0 local removals | `internal/lifecycle/lifecycle.go:200-206; internal/lifecycle/lifecycle.go:313-315; internal/federation/killswitch.go:140-146; internal/federation/killswitch.go:180-183` | federation.RevokeUserBindings returns an error only when it cannot enumerate bindings; a binding whose LOCAL removal failed (vault.Revoke or bindings.Delete returned an error - Unbind only returns err for those two paths, upstream failures are folded into resu�?|
| S09-1 | security | DSN (with password) can reach logs on the migration-down path: withMigrationLock never redacts the driver's parse error | `internal/store/postgres/postgres.go:378; internal/store/postgres/postgres.go:399; internal/store/postgres/postgres.go:402; internal/store/postgres/postgres.go:240; internal/store/postgres/postgres.go:452` | poolConfig redacts the driver's parse error, but withMigrationLock �?used by Migrate and, crucially, by MigrateDown (which calls it directly, without ever going through poolConfig) �?wraps the raw pgx.ParseConfig error. sql.Open only records the DSN; the parse�?|
| S09-2 | correctness | Tokens.RevokeTokens is not transactional although revokeMatching documents that it is, so a bulk Kill Switch/erasure can half-apply | `internal/store/postgres/oauth.go:466; internal/store/postgres/oauth.go:471; internal/store/postgres/oauth.go:517; internal/store/postgres/oidc.go:1503` | revokeMatching is called on s.pool (autocommit, one transaction per statement) and two further DELETEs run on the pool. The doc comment on revokeMatching explicitly claims RevokeTokens wraps it in one transaction; the OIDCStore.RevokeTokens does, so this is a �?|
| S10-2 | reliability | A panic in the readiness probe wedges /readyz at "checking" (503) forever | `internal/httpapi/health.go:183; internal/httpapi/health.go:194` | readinessCache.check sets c.running = true before invoking the probe and clears it only on the normal return path, after probe(probeCtx). If the probe panics, control leaves check with c.running still true, c.settled never closed, and c.state still readinessUn�?|
| S11-6 | performance | /v1/admin/audit/verify runs a full-table chain walk synchronously with no concurrency bound, holding a pooled DB connection up to 45s | `internal/httpapi/audit_routes.go:171; internal/store/postgres/auditchain.go:220; internal/store/postgres/auditchain.go:264` | Verify opens a transaction, raises statement_timeout to 45s and scans the entire audit_events table, holding one pooled connection for the whole walk. There is no per-endpoint concurrency limit and no cache of the result, so an operator (or anyone who steals a�?|
| S12-1 | reliability | Per-attempt request timeout is disarmed before the response body is read | `web/src/lib/api.ts:334; web/src/lib/api.ts:354; web/src/lib/api.ts:369` | fetch() resolves as soon as the response *headers* arrive, but the only deadline in the client is cleared at line 354 before the body is consumed at line 369. The AbortController therefore never fires for a response whose body stalls, so res.text() can remain �?|
| S13-2 | performance | StoreDeviceAuthorization is O(n) in the number of live device authorizations, under the store-wide mutex, on every public device-authorization request | `internal/store/memory/oidc.go:1050; internal/store/memory/oidc.go:1053; internal/store/memory/oidc.go:1124` | The device-authorization endpoint (/oauth/device_authorization, public to registered clients per RFC 8628) calls StoreDeviceAuthorization for every request. Each call ranges over the ENTIRE devices map under s.mu, the single mutex that also guards every token �?|
| S13-3 | performance | DeleteAuthRequest scans every pending authorization code under the store mutex on each token exchange | `internal/store/memory/oidc.go:508; internal/store/memory/oidc.go:516` | The OIDC library calls DeleteAuthRequest after every authorization-code token mint. The memory store answers it by ranging over the whole codes map to find rows whose requestID matches. AuthRequestByCode has already deleted the code for this request (oidc.go:4�?|
| S14-3 | performance | Memory store pagers re-sort the whole table on every page: vault Rotate and the federation Kill Switch are O(N^2 log N) | `vault/repo.go:229; vault/repo.go:233; vault/rotate.go:45; internal/federation/binding.go:255; internal/federation/binding.go:262; internal/federation/killswitch.go:58` | Each page call materialises ALL rows, sorts them, and only then applies the cursor as a filter. The cursor does not reduce the work. Rotation pages 200 records at a time (vault/rotate.go:96) and the Kill Switch pages 500 at a time (internal/federation/killswit�?|
| S14-5 | security | oauth.Service.Refresh: refresh-family revocation is not atomic with rotation, so a concurrent replay can leave the new generation alive | `oauth/as.go:264; oauth/as.go:276; oauth/as.go:308; oauth/as.go:418; oauth/as.go:421; oauth/tokens.go:434` | ConsumeRefresh is atomic, but the sequence ConsumeRefresh -> RevokeRefreshFamily (on the reuse branch) and ConsumeRefresh -> issue (SaveAccess then SaveRefresh) is not. A replayed/stolen token (or a legitimate duplicate request, e.g. a client retry) racing the�?|
| S14-6 | performance | memory.OIDCStore replays and revocations scan every token and tombstone while holding the single global mutex | `internal/store/memory/oidc.go:716; internal/store/memory/oidc.go:720; internal/store/memory/oidc.go:726; internal/store/memory/oidc.go:787; internal/store/memory/oidc.go:806` | All of these loops are full-map scans executed under s.mu, the one mutex every OP operation needs. revokeFamilyLocked is reached from TokenRequestByRefreshToken (:677-679) on a replay of a spent refresh token - i.e. from attacker-supplied input - and from Crea�?|
| S15-1 | security | scripts/backup.sh leaves the plaintext database dump behind when age encryption fails | `scripts/backup.sh:44-48; scripts/backup.sh:10` | The script runs under `set -euo pipefail` (scripts/backup.sh:10). If the `age` invocation on line 45 exits non-zero (unreachable recipient, short write, full disk, interrupted process), the shell aborts before line 46 shreds/removes the plaintext dump, so `re0�?|
| S15-3 | reliability | Backup CronJob has no activeDeadlineSeconds: a hung pg_dump stops all future backups, silently | `deploy/k8s/backup/cronjob.yaml:11-22; deploy/k8s/backup/cronjob.yaml:59-70` | `concurrencyPolicy: Forbid` skips every new schedule while a run is still active, and the jobTemplate sets only `backoffLimit: 2` �?no `activeDeadlineSeconds`, and the inline `pg_dump` (lines 69-70) has no `timeout`/`statement_timeout`. A pg_dump that blocks (�?|

## 3. 低危发现（Low，共 95 条）

| ID | 类别 | 标题 | 位置 |
|---|---|---|---|
| S01-10 | security | Client secrets are stored as an unsalted SHA-256 digest, so a weak config-file secret is off-line crackable if the store leaks | `oauth/client.go:99-105; oauth/client.go:107-114; cmd/re0auth/main.go:1634-1643` |
| S01-11 | performance | MemoryStore serialises all token operations on one Mutex and scans every record under the lock, so account-page reads and sweeps block token introspection | `oauth/tokens.go:263-273; oauth/tokens.go:298-328; oauth/grants.go:157-221` |
| S01-12 | correctness | Store reads return struct copies whose Scopes slices alias the stored backing array, so a caller mutating a returned record corrupts stored authorization state | `oauth/tokens.go:373-382; oauth/tokens.go:341-349; oauth/tokens.go:421-429; oauth/as.go:370-376` |
| S01-4 | reliability | Token issuance is not atomic: a failure after SaveAccess leaves a live, undeliverable access token in the store | `oauth/as.go:405-432; oauth/as.go:388-423` |
| S01-5 | security | Client authentication tells an unknown client apart from a wrong secret, contradicting the kit's stated indistinguishability requirement | `oauth/as.go:437-448; upstreamkit/server.go:339-345` |
| S01-7 | correctness | RotateSecret accepts a hash of any length while RestoreClient demands sha256.Size, so a bad rotation silently locks a confidential client out | `oauth/client.go:415-432; oauth/client.go:124-145; oauth/client.go:107-114` |
| S01-8 | correctness | Revoke cannot reach a spent refresh token's tombstone: the documented DeleteRefresh tombstone-clear is unreachable and RFC 7009 revocation of a rotated token is a false success | `oauth/as.go:311-345; oauth/tokens.go:393-405; oauth/tokens.go:453-464` |
| S01-9 | reliability | Audit failures are silently discarded, so reuse detection, revocation and failed exchanges can go unrecorded | `oauth/as.go:451-459` |
| S02-10 | reliability | No length cap on state, nonce (or other authorize parameters) at the entrance, unlike PKCE, request-id and handle ids | `internal/oidchttp/oidchttp.go:934; internal/oidchttp/oidchttp.go:1046; internal/oidchttp/oidchttp.go:1416` |
| S02-6 | correctness | Protocol-plane 405 responses omit the mandatory Allow header | `internal/oidchttp/oidchttp.go:478; internal/oidchttp/oidchttp.go:256; internal/oidchttp/oidchttp.go:263` |
| S02-7 | correctness | Discovery rewrite mutates URL.Path but not RawPath, so a percent-encoded RFC 8414 alias 404s instead of serving the OIDC document | `internal/oidchttp/oidchttp.go:255; internal/oidchttp/oidchttp.go:300; internal/oidchttp/oidchttp.go:46` |
| S02-8 | reliability | Handler.Introspect collapses a store outage into Active=false, reporting infrastructure failure to /v1 as an invalid token | `internal/oidchttp/oidchttp.go:1677; internal/oidchttp/oidchttp.go:1664` |
| S02-9 | performance | Every successful token response is fully JSON-decoded and re-encoded by sanitizeTokenResponse | `internal/oidchttp/oidchttp.go:1538; internal/oidchttp/oidchttp.go:670; internal/oidchttp/oidchttp.go:761` |
| S03-10 | reliability | Kill Switch session revocation is unbounded and not atomic | `internal/store/postgres/sessions.go:198; internal/store/postgres/sessions.go:202; internal/store/postgres/sessions.go:216` |
| S03-11 | correctness | core.App.Remove races with an in-flight load, allowing a removed fiber to be marked active without its scope | `internal/core/app.go:99; internal/core/app.go:105; internal/core/app.go:334` |
| S03-2 | security | SignIn leaves an authenticated session outside the SessionIndex when RenewToken fails | `internal/auth/auth.go:161; internal/auth/auth.go:166; internal/auth/auth.go:177` |
| S03-3 | security | EndSession forgets the session index before destroying the session, so a failed sign-out leaves an unrevocable live session | `internal/auth/auth.go:210; internal/auth/auth.go:212; internal/auth/auth.go:216` |
| S03-4 | correctness | Concurrent first login of the same identity is reported as signup_failed instead of retrying the lookup | `internal/auth/auth.go:713; internal/auth/auth.go:714; internal/auth/auth.go:716` |
| S03-5 | reliability | Session referencing a missing account answers 500 instead of tearing the session down | `internal/httpapi/session_routes.go:27; internal/httpapi/session_routes.go:29; internal/httpapi/identity_routes.go:26; internal/httpapi/export_routes.go:64` |
| S03-6 | security | Admin authorization trusts the session claim without re-checking that the account still exists | `internal/httpapi/admin_routes.go:62; internal/httpapi/admin_routes.go:67; internal/httpapi/server.go:305` |
| S03-7 | performance | MemoryStore.Identities scans every identity in the process and holds the lock for the whole scan | `internal/account/account.go:231; internal/account/account.go:281; internal/account/account.go:283` |
| S03-8 | performance | Postgres Identities uses an EXISTS round trip before the real SELECT | `internal/store/postgres/account.go:236; internal/store/postgres/account.go:244` |
| S03-9 | correctness | clearFlow does not remove the OIDC nonce from the session | `internal/auth/auth.go:44; internal/auth/auth.go:737; internal/auth/auth.go:739` |
| S04-2 | security | BeginDeviceAuthorization does not authenticate confidential clients, allowing anonymous device requests that impersonate a trusted client on the consent screen | `oauth/device.go:224-228; oauth/device.go:415-419; oauth/device.go:437-448` |
| S04-3 | performance | MemoryDeviceStore never expires anything: device authorizations accumulate for the process lifetime | `oauth/device.go:140-163; oauth/device.go:224-247` |
| S04-4 | performance | Grants page scans every token in the process under the store's single mutex (no subject index in the in-memory store) | `oauth/grants.go:158-180; internal/httpapi/grants_routes.go:31-43` |
| S04-5 | correctness | freeUserCode treats every store error as a collision and checks uniqueness non-atomically | `oauth/device.go:432-443; oauth/device.go:155-163` |
| S04-6 | correctness | slow_down is returned before the terminal device status, and the advertised interval is truncated | `oauth/device.go:289-307; oauth/device.go:252-255` |
| S04-7 | reliability | Consent decision conflates store failures with an expired authorization request | `internal/httpapi/authorization_routes.go:97-101; internal/httpapi/authorization_routes.go:151-155; internal/httpapi/authorization_routes.go:159-166; internal/httpapi/authorization_routes.go:173-183` |
| S04-8 | correctness | Registry.Register mutates the scope map without synchronization while Get/Resolve read it concurrently | `oauth/scope.go:183-197; oauth/scope.go:199-213; oauth/scope.go:217-235` |
| S04-9 | correctness | Device authorization accepts an empty scope set and issues a scope-less token pair | `oauth/device.go:224-228; oauth/device.go:373-386; oauth/device.go:308` |
| S05-3 | performance | MemoryBindingStore.List pre-allocates for the whole deployment and ListAllPage re-sorts the whole map on every page | `internal/federation/binding.go:219; internal/federation/binding.go:262; internal/federation/binding.go:255` |
| S05-4 | performance | MissingBindings is O((sources x resources)^2) with a copy+sort per candidate lookup | `internal/federation/missing.go:65; internal/federation/missing.go:70; internal/federation/missing.go:74` |
| S05-5 | correctness | NewRegistry validates RawBase and token_class but not Status, so an unrecognized status is fail-open | `internal/federation/federation.go:162; internal/federation/federation.go:173; internal/federation/federation.go:637` |
| S05-6 | security | Source.Issuer and endpoint overrides are not validated as absolute http(s), unlike RawBase | `internal/federation/federation.go:144; internal/federation/federation.go:151; internal/federation/bind.go:150; internal/federation/bind.go:235` |
| S05-7 | correctness | BeginBind and CompleteBind accept a retired source that the rest of the plane refuses | `internal/federation/bind.go:127; internal/federation/bind.go:171; internal/federation/service.go:637` |
| S05-8 | security | revokeUpstream logs a vault error that can embed the raw subject identity | `internal/federation/unbind.go:124; vault/service.go:309` |
| S06-10 | security | SocialLogin stores and echoes return_to without safeurl.RelativePath validation | `referencesource/social.go:108; referencesource/social.go:189` |
| S06-6 | reliability | Conformance runner leaks the response body of a non-200 metadata document (never closed) | `upstreamkit/conformance/conformance.go:211; upstreamkit/conformance/conformance.go:212; upstreamkit/conformance/conformance.go:216` |
| S06-7 | correctness | A partial AuthURL/TokenURL override on a discovered OIDC provider is silently discarded | `idp/idp.go:505; idp/idp.go:507; idp/idp.go:520` |
| S06-8 | reliability | Injected RegistryConfig.HTTPClient may have no timeout, and go-oidc's JWKS fetch is context.WithoutCancel'd, so a hung IdP can pin a login goroutine | `idp/idp.go:287; idp/idp.go:751; idp/idp.go:648` |
| S06-9 | security | federation.NewService's Doer-only fallback builds an outbound client with the SSRF guard off | `internal/federation/service.go:376; httpclient/outbound.go:304` |
| S07-10 | reliability | tapsign.Rotate returns the replacement token together with an audit error, inviting callers to discard a token that is now the only live credential | `tapsign/client.go:60; tapsign/client.go:197` |
| S07-3 | performance | MemoryRepo.ListPage reloads clones and re-sorts the entire store on every page, making a rotation O(N^2 log N) with N clones per page | `vault/repo.go:229; vault/repo.go:233` |
| S07-5 | reliability | taptapoauth accepts upstream-controlled interval and expires_in without an upper bound or overflow guard | `taptapoauth/client.go:96; taptapoauth/client.go:100` |
| S07-6 | security | tapsign.Verify performs a credential-bearing upstream call with no audit record | `tapsign/client.go:44; tapsign/client.go:40` |
| S08-3 | correctness | DeleteAccount writes an outcome=ok record claiming the pseudonym key was destroyed before Destroy runs, and the correcting record is best-effort | `internal/lifecycle/lifecycle.go:262-271; internal/lifecycle/lifecycle.go:277-291; internal/lifecycle/lifecycle.go:299-302` |
| S08-5 | security | Universal trusted-proxy list check only matches a single /0 prefix, so two /1 entries bypass the acknowledgement | `cmd/re0auth/config.go:1016-1023; cmd/re0auth/config.go:589-601` |
| S08-6 | security | -print-secret-env echoes whatever is in an *_env name slot verbatim, disclosing a value pasted into the wrong field | `cmd/re0auth/config.go:424-431; cmd/re0auth/config.go:441-445; cmd/re0auth/main.go:276-290` |
| S08-7 | reliability | Graceful-shutdown drain budget (30s) is shorter than dataPlaneTimeout (45s), so shutdown cuts the request the design says must get a readable refusal | `cmd/re0auth/main.go:128; cmd/re0auth/main.go:116-150; cmd/re0auth/main.go:854-866` |
| S08-8 | correctness | An explicitly configured max_upstream_buffer_bytes = 0 is silently replaced by the 64 MiB default | `cmd/re0auth/config.go:553-571; cmd/re0auth/main.go:523; internal/federation/service.go:382-383` |
| S08-9 | security | A custom OIDC provider's issuer is not required to be https, so the token exchange can run in cleartext | `cmd/re0auth/config.go:855-890; idp/idp.go:530-548` |
| S09-3 | correctness | UnlinkIdentity masks any database error as ErrNotFound because ownership is checked before err | `internal/store/postgres/account.go:199` |
| S09-5 | security | Rolling back migrations 0024/0025 silently drops refresh-family tombstones and replay detection; the MigrateDown guard only covers 13/14 | `internal/store/postgres/postgres.go:469; internal/store/postgres/postgres.go:496; internal/store/postgres/migrations/0024_refresh_token_family.sql:50; internal/store/postgres/migrations/0025_oauth_refresh_family.sql:59` |
| S09-6 | security | Verify reads audit_chain.head_hash as a witness but never compares it to the walked chain, so tail truncation is not detected even though the anchor is in hand | `internal/store/postgres/auditchain.go:259; internal/store/postgres/auditchain.go:346` |
| S09-7 | reliability | Database outages are collapsed into protocol 'not found' on the authorization-code and device-poll paths, unlike every refresh/revocation path | `internal/store/postgres/oidc.go:327; internal/store/postgres/oidc.go:1210; internal/store/postgres/oidc.go:660` |
| S09-8 | reliability | Several multi-statement deletes run without a transaction, leaving orphaned session index rows and post-revocation replay tombstones | `internal/store/postgres/sessions.go:197; internal/store/postgres/sessions.go:211; internal/store/postgres/oauth.go:290; internal/store/postgres/oauth.go:495` |
| S09-9 | performance | Audit pseudonym cache is dropped wholesale at 4096 entries, so bursts over distinct subjects put 1-3 extra queries on the vault fail-closed path | `internal/store/postgres/auditpseudo.go:144; internal/store/postgres/auditpseudo.go:115; internal/store/postgres/auditpseudo.go:69` |
| S10-3 | reliability | Compression writer is never closed or pooled when a handler panics after compression starts | `internal/compress/compress.go:160; internal/compress/compress.go:162` |
| S11-1 | security | Admin audit detail stores the raw operator account id in Detail["actor"], defeating pseudonym-key destruction | `internal/admin/admin.go:485; internal/admin/admin.go:490; audit/audit.go:73; audit/audit.go:84` |
| S11-2 | security | Kill Switch silently reports sessions_revoked=0 when the deployment has no session revoker, with no unavailability marker | `internal/admin/admin.go:351; internal/admin/admin.go:167; internal/admin/admin.go:169; cmd/re0auth/main.go:618; cmd/re0auth/main.go:903` |
| S11-3 | security | Kill Switch `all` cannot purge in-flight bind flows and does not say so, allowing access to be re-created after the sweep | `internal/admin/admin.go:399; internal/admin/admin.go:404; internal/federation/bind.go:47` |
| S11-4 | reliability | Kill Switch returns a bare 500 on a partial failure, discarding the counts of what was already revoked | `internal/admin/admin.go:361; internal/admin/admin.go:388; internal/httpapi/admin_routes.go:281` |
| S11-5 | correctness | Kill Switch `client` target aborts before token revocation when the client row is gone, so its live tokens survive | `internal/admin/admin.go:324; internal/admin/admin.go:326; internal/httpapi/admin_routes.go:277` |
| S11-7 | security | Audit subject filter performs an uncached negative DB lookup per distinct subject and leaks 'has pseudonym key' timing | `internal/store/postgres/auditpseudo.go:69; internal/store/postgres/auditread.go:67; internal/store/postgres/auditpseudo.go:144` |
| S11-8 | correctness | Account export claims to be everything held about the account but omits sessions, issued tokens and audit history, while the notice only disclaims credentials | `internal/httpapi/export_routes.go:10; internal/httpapi/export_routes.go:30; internal/httpapi/export_routes.go:39` |
| S11-9 | performance | GET /v1/admin/clients returns every client with no pagination or cap | `internal/httpapi/admin_routes.go:100; internal/store/postgres/oauth.go:732` |
| S12-10 | correctness | Response shape validation is applied to only two endpoints; the rest throw inside render and expose the JS error via +error.svelte | `web/src/lib/api.ts:468; web/src/lib/api.ts:480; web/src/routes/admin/+page.svelte:72; web/src/routes/+error.svelte:9` |
| S12-3 | correctness | Stale ?error= is carried through SignIn return_to, so a later successful sign-in still reports failure | `web/src/routes/+page.svelte:40; web/src/routes/+page.svelte:241` |
| S12-4 | security | Attacker-controlled ?error= is rendered verbatim inside the branded failure alert | `web/src/routes/+page.svelte:41; web/src/routes/+page.svelte:82` |
| S12-5 | reliability | Account export revokes the object URL synchronously and trusts an unvalidated profile field | `web/src/routes/+page.svelte:162; web/src/routes/+page.svelte:164` |
| S12-6 | correctness | Focus restoration builds a CSS selector by string interpolation from server/config ids | `web/src/lib/a11y.ts:33; web/src/lib/a11y.ts:35; web/src/routes/sources/+page.svelte:186; web/src/routes/grants/+page.svelte:73` |
| S12-8 | performance | SPA shell is sent with no cache validator, so Cache-Control: no-cache forces a full body transfer each load | `internal/webui/webui.go:151; internal/webui/webui.go:152` |
| S13-10 | performance | oauth.MemoryStore / MemoryDeviceStore / MemoryClientRegistry have no cap and no in-process janitor | `oauth/tokens.go:263; oauth/tokens.go:285; oauth/device.go:139; oauth/client.go:334` |
| S13-11 | correctness | perfreport divides by the baseline median without a zero check, producing NaN/Inf deltas and a NaN geomean | `cmd/perfreport/main.go:355; cmd/perfreport/main.go:373` |
| S13-4 | reliability | Device approve/deny call the synchronous audit sink while holding the OIDC store's global mutex | `internal/store/memory/oidc.go:1308; internal/store/memory/oidc.go:1326; internal/store/memory/oidc.go:1334; internal/store/memory/oidc.go:1347; audit/audit.go:35; internal/store/postgres/audit.go:54` |
| S13-6 | correctness | compress responseWriter swallows the final status after a 1xx header | `internal/compress/compress.go:318; internal/compress/compress.go:327` |
| S13-7 | performance | HTTP status metric label is not normalized and can be set from an upstream-controlled status | `internal/observability/observability.go:310; internal/observability/observability.go:629; internal/httpapi/federation_routes.go:320` |
| S13-8 | security | pprof profile/trace endpoints accept unbounded seconds and have no concurrency or size cap | `internal/observability/observability.go:611; internal/observability/observability.go:616; internal/observability/observability.go:618` |
| S13-9 | correctness | Oversized chunked JSON bodies surface as 400 'malformed JSON body' instead of the middleware's plane-shaped 413 | `internal/httpapi/admin_routes.go:133; internal/httpapi/authorization_routes.go:144; internal/httpapi/device_routes.go:105; internal/httpapi/binding_routes.go:202; internal/httpapi/account_routes.go:44; internal/httpapi/middleware.go:113; oauth/bodylimit.go:33` |
| S14-1 | reliability | memory.OIDCStore device decision holds the store-wide mutex across a durable audit write | `internal/store/memory/oidc.go:1308; internal/store/memory/oidc.go:1326; internal/store/memory/oidc.go:1334; internal/store/memory/oidc.go:1347` |
| S14-10 | correctness | oauth.Registry.Register mutates a map that Resolve/Get/Descriptors read without any lock | `oauth/scope.go:185; oauth/scope.go:195; oauth/scope.go:200; oauth/scope.go:208; oauth/scope.go:226` |
| S14-4 | performance | federation.MemoryBindingStore.List has no per-user index: every account page scans all bindings under the read lock | `internal/federation/binding.go:215; internal/federation/binding.go:219; internal/federation/binding.go:220` |
| S14-7 | performance | memory.OIDCStore.StoreDeviceAuthorization purges expired devices with a full scan under the lock on every call | `internal/store/memory/oidc.go:1051; internal/store/memory/oidc.go:1053; internal/store/memory/oidc.go:1124` |
| S14-8 | reliability | oauth.MemoryDeviceStore has no deletion path and no sweep, so device records grow without bound | `oauth/device.go:140; oauth/device.go:206; oauth/as.go:57; oauth/as.go:58` |
| S14-9 | reliability | readinessCache is not panic-safe: a panicking readiness probe latches /readyz to 503 'checking' forever | `internal/httpapi/health.go:183; internal/httpapi/health.go:190; internal/httpapi/health.go:192; internal/httpapi/health.go:195` |
| S15-10 | correctness | scripts/backup-keys.sh is committed mode 100644 while the documented invocation runs it directly | `scripts/backup-keys.sh:1; docs/operations.md:90-92` |
| S15-11 | correctness | Release archives embed the built SPA but do not carry the npm attribution the image deliberately includes | `Makefile:160-182; Makefile:215-221; Dockerfile:86-90` |
| S15-2 | security | CI/release-gate Postgres service image is a floating tag while every other image in the project is digest-pinned | `.github/workflows/ci.yml:34; .github/workflows/ci.yml:278; .github/workflows/perf.yml:45; .github/workflows/release.yml:20` |
| S15-4 | security | .dockerignore excludes scratchpad but not the live audit workspace or generic key shapes, so they enter the `COPY . .` build layer | `.dockerignore:42-43; .gitignore:62; Dockerfile:53; .gitleaks.toml:13-20` |
| S15-5 | reliability | Base ConfigMap hardcodes trusted_proxies to 10.0.0.0/8; on a non-10/8 pod CIDR every client silently shares one rate-limit bucket | `deploy/k8s/base/configmap.yaml:43-44; internal/httpapi/clientaddr.go:104-110; internal/httpapi/clientaddr.go:78-81` |
| S15-6 | security | Release image is pushed under its release tag before the Trivy gate runs; only `latest` is withheld | `.github/workflows/release.yml:64-80; .github/workflows/release.yml:100-107; .github/workflows/release.yml:109-119; deploy/k8s/base/deployment.yaml:46` |
| S15-7 | security | Trivy scan runs with the host Docker socket mounted inside a job holding packages:write and id-token:write | `.github/workflows/release.yml:100-107; .github/workflows/release.yml:36-39` |
| S15-8 | reliability | Three alert rules keyed on generic go_*/process_* metrics carry no job selector and can fire on unrelated targets | `deploy/prometheus/re0auth.rules.yml:304-348; deploy/prometheus/re0auth.rules.yml:4-7` |
| S15-9 | security | Namespace has no Pod Security Admission labels, so the hardened pod spec is not enforced as a precondition | `deploy/k8s/base/namespace.yaml:1-4; deploy/k8s/base/deployment.yaml:29-33; deploy/k8s/base/deployment.yaml:108-111` |

## 4. 信息级（Info，共 24 条）

| ID | 类别 | 标题 | 位置 |
|---|---|---|---|
| S01-13 | correctness | The declared-length pre-check is the only path to 413; a chunked body over the cap surfaces as a 400 malformed-form instead | `oauth/bodylimit.go:27-34; upstreamkit/server.go:162-169; upstreamkit/server.go:242-246` |
| S02-11 | correctness | DenyAuthorization uses the static issuer only, so a dynamic-issuer deployment emits a denial without the RFC 9207 iss parameter | `internal/oidchttp/oidchttp.go:1794; internal/oidchttp/oidchttp.go:1444` |
| S02-5 | security | Discovery documents are cached for the process lifetime while the issuer is derived per request from Host | `internal/oidchttp/oidchttp.go:294; internal/oidchttp/oidchttp.go:300; internal/oidchttp/oidchttp.go:193` |
| S05-10 | security | CompleteBind consumes the flow before the owner check (cross-account DoS), mitigated by the HTTP handler | `internal/federation/bind.go:158; internal/federation/bind.go:163; internal/httpapi/federation_routes.go:410` |
| S05-9 | correctness | MemoryBindFlowStore.SweepExpired uses time.Now instead of the service clock | `internal/federation/bind.go:112; internal/federation/bind.go:144; internal/federation/bind.go:165` |
| S06-11 | security | safeurl.RelativePath resists scheme-relative, backslash and control-byte escapes; percent-encoded and dot-segment forms cannot change origin | `safeurl/safeurl.go:34` |
| S07-11 | security | bindingAAD truncates identity lengths to uint32 before length-prefixing | `vault/envelope.go:148; vault/envelope.go:150` |
| S07-4 | correctness | Use builds the AEAD AAD from the requested identity while Rotate builds it from the stored record identity | `vault/service.go:300; vault/rotate.go:104` |
| S07-7 | security | taptapoauth bounds upstream error text for logs but only strips CR/LF, leaving other control characters | `taptapoauth/client.go:337; taptapoauth/client.go:338` |
| S07-8 | reliability | tapsign.drain and the response handling dereference resp and resp.Body without a nil check | `tapsign/client.go:224; tapsign/client.go:48` |
| S07-9 | correctness | Re-enrolling a credential overwrites CreatedAt, discarding the original creation time | `vault/service.go:244; vault/service.go:253` |
| S09-10 | correctness | OP token issued_at is written by the database's now(), not the store clock the rest of OIDCStore uses | `internal/store/postgres/oidc.go:429; internal/store/postgres/oidc.go:573; internal/store/postgres/migrations/0009_oidc_token_issued_at.sql:5; internal/store/postgres/oidc.go:41` |
| S09-4 | correctness | ConsumeRefresh claims expired values (no expires_at predicate) although the Store contract says "live", unlike the OP store's rotation claim | `internal/store/postgres/oauth.go:242; internal/store/postgres/oidc.go:514; oauth/as.go:289; oauth/tokens.go:168` |
| S10-4 | security | Business-plane responses carrying the session CSRF token are compressed (BREACH-style compression oracle) | `internal/httpapi/server.go:353; internal/compress/compress.go:336; internal/httpapi/session_routes.go:42; internal/httpapi/device_routes.go:75; internal/auth/auth.go:240` |
| S10-5 | performance | Limiter.Check heap-allocates a *rate.Reservation on every request | `internal/ratelimit/ratelimit.go:289; internal/ratelimit/ratelimit.go:295` |
| S12-11 | performance | Every asset request performs three embedded-FS stats | `internal/webui/webui.go:106; internal/webui/webui.go:119; internal/webui/webui.go:133` |
| S12-12 | correctness | SignIn appends return_to after a URL fragment, unlike the equivalent link() path | `web/src/lib/components/SignIn.svelte:50; web/src/lib/components/SignIn.svelte:52` |
| S12-2 | correctness | Dev root redirect does not match a request that carries a query string | `web/vite.config.ts:27; web/vite.config.ts:28` |
| S12-7 | performance | Sources page re-runs O(available x bindings) scans on every reactive invalidation | `web/src/routes/sources/+page.svelte:82; web/src/routes/sources/+page.svelte:89; web/src/routes/sources/+page.svelte:288` |
| S12-9 | reliability | Retried responses are discarded without draining or cancelling the body | `web/src/lib/api.ts:358; web/src/lib/api.ts:361` |
| S14-11 | reliability | oidchttp.serveOAuth can leak a pooled bufferedWriter on panic because release is not deferred | `internal/oidchttp/oidchttp.go:636; internal/oidchttp/oidchttp.go:637; internal/oidchttp/oidchttp.go:716; internal/oidchttp/oidchttp.go:717` |
| S14-12 | correctness | federation.refreshBinding's row-then-secret write order is deliberately protected by the per-binding lock (suspicious but mitigated) | `internal/federation/refresh.go:40; internal/federation/refresh.go:111; internal/federation/refresh.go:121` |
| S15-12 | security | Backup CronJob writes plaintext database dumps; no age encryption path is wired, unlike scripts/backup.sh | `deploy/k8s/backup/cronjob.yaml:59-70; docs/operations.md:125-126` |
| S15-13 | security | .gitleaks path allowlist exempts any file matching docs/security-audit-<n>.md from every rule | `.gitleaks.toml:17-20; .gitleaks.toml:1-6` |

## 5. 去重与关联（同一根因的多条编号）

对抗性验证按“根本原因”去重后，以下编号指向同一处代码：

| 根因 | 相关编号 | 建议合并后的严重�?|
|---|---|---|
| `federation.CompleteBind` 未取 per-binding �?| S14-2（high）、S05-2（medium�?| High |
| 设备授权被批准后可无限次兑换 | S01-1（medium）、S04-1（medium�?| Medium（仅在自定义嵌入 / 上游套件路径可达；随�?OP 不受影响�?|
| 内存 `MemoryDeviceStore` 无删�?无清�?| S01-2、S04-3、S14-8 | Medium |
| 内存 OIDC 存储在全局锁下全表扫描 | S13-2、S13-3、S14-6、S14-7、S14-1 | Medium/High |
| readiness 探针 panic 后卡�?503 | S10-2（medium）、S14-9（low�?| Medium |
| `Registry.Register` 无同步写 map | S04-8、S14-10 | Low |
| Kill Switch 无法清掉在�?bind flow / 客户端行缺失时提前返�?| S11-3、S11-5 | Low |
| `oauth.MemoryStore` 无上限无清扫 | S01-2、S13-10 | Low（仅内存模式/自定义嵌入） |

## 6. 方法论与可达性说明（重要�?
- **严重度是“可达性加权”后的结果�?* 发现阶段给出�?14 �?high 中，�?6 条在验证阶段被降级，
  因为它们的利用面在生产二进制中并不挂载或需要非默认配置�?  - `oauth` 包那套手�?AS �?device / token 端点**没有�?`cmd/re0auth` 挂载**�?    生产的设备流�?zitadel OP + `internal/oidchttp` 的组合（S01-1 / S04-1 因此降为 medium）�?  - `internal/store/memory` 只在没有 `DATABASE_URL` 的部署形态下使用；这类部署本身即
    “重启即失”的定位，但仍是 ADR-0001 认可的部署模式，故内存增长类问题保留 medium/high 分级�?  - 涉及 `referencesource`（演示数据源，明确不发布）的性能/DoS 条目（S06-4、S06-5）按
    “第三方复制该套件时才会命中”计�?medium�?- **�?Docker / �?Postgres 的边界：** 所�?SQL、迁移、审计链、备份脚本、K8s 清单�?  Dockerfile、CI 相关结论均为静态审读；凡依赖数据库运行时行为的结论，验证代理已明确标注
  “read, not executed”。若要补齐，建议在一台带 Postgres 的机器上�?  `TEST_DATABASE_URL=... go test ./internal/store/postgres/` 并实际构建镜像过 Trivy�?
## 7. 上线前建议处置顺�?
1. **P0（阻断）**：S02-1、S08-2、S10-1、S13-1、S14-2、S06-1�?2. **P0/P1（取决于部署形态）**：S03-1、S13-5 —�?若上线用内存模式，这两条同样是阻断级�?   若用 Postgres，S13-5 转移到数据库行增长与清扫成本，S03-1 转移�?`sessions.data` 增长�?3. **P1**：S05-1、S06-2、S08-1、S09-1、S09-2、S14-5、S07-1、S07-2、S10-2、S11-6、S12-1、S15-1、S15-3�?4. **P2**：其�?medium（尤其是“口径不诚实/可观测性缺失”类：S08-4、S11-4、S09-7）�?5. **P3（上线后清理�?*�?5 �?low，多数是边界正确性、指标基数、内存布局与文档契约漂移�?
## 9. 测试用例验证覆盖（第二轮复核�?
�?157 条发现逐条核对了全�?479 �?`*_test.go` / 1,847 个测试函数后�?
| 判定 | 含义 | 数量 |
|---|---|---|
| direct | 有测试锁定该缺陷（现状通过、修复即红） | 29 |
| partial | 只走到相关路径，未断言本缺�?| 105 |
| none | 完全没有测试到达 | 23 |

**8 �?High 现已全部有直接复现测试；Medium 7/30、Low 2/95 的缺口也已补�?*（均可直�?`go test` 运行）：
S02-1（新�?freshness/reauth 测试）、S03-1、S06-1、S08-2、S10-1、S13-1、S13-5、S14-2�? �?High），
以及 S01-2、S10-2（Medium）与 S08-8、S13-6（Low）�?新增测试文件：`internal/auth/zz_audit9_returnto_test.go`、`idp/zz_audit9_discovery_body_test.go`�?`cmd/re0auth/zz_audit9_dsnenv_test.go`、`internal/httpapi/zz_audit9_inflight_planes_test.go`�?`internal/httpapi/zz_audit9_compress_bypass_test.go`、`internal/httpapi/zz_audit9_readyz_panic_test.go`�?`internal/store/memory/zz_audit9_tombstones_test.go`、`internal/federation/zz_audit9_bind_unbind_race_test.go`�?`internal/federation/zz_audit9_buffer_budget_zero_test.go`、`internal/compress/zz_audit9_1xx_status_test.go`�?`oauth/zz_audit9_device_store_growth_test.go`、`internal/oidcstore/zz_audit9_freshness_test.go`�?`internal/store/memory/zz_audit9_reauth_test.go`、`internal/auth/zz_audit9_reauth_route_test.go`�?`internal/zzprobe/protocol/audit9_basic_op_test.go`（audit5 e2e，随 CI �?audit5 作业实跑）�?
逐条明细�?23 条缺口的补齐方案�?[`_audit/round9/COVERAGE-REPORT.md`](../_audit/round9/COVERAGE-REPORT.md)
�?[`_audit/round9/coverage-matrix.csv`](../_audit/round9/coverage-matrix.csv)�?复核�?`go vet ./...`、`gofmt -l .`、`go test ./...` 仍然全绿�?
## 10. 原始数据索引

| 路径 | 内容 |
|---|---|
| `_audit/round9/raw/S01..S15.json` | 15 个分域的原始发现（含证据、利用、修复建议） |
| `_audit/round9/verify/S01..S15.json` | 逐条对抗性验证结论（confirmed / downgraded / rejected + 理由�?|
| `_audit/round9/coverage/S01..S15.json` | 逐条测试覆盖二次核验结论 |
| `_audit/round9/coverage-matrix.csv` | 157 �?× 严重�?× 覆盖判定 |
| `_audit/round9/COVERAGE-REPORT.md` | 测试用例验证覆盖报告 |
| `_audit/round9/matrix9.csv` | 157 条的最终严重度矩阵 |
| `_audit/round9/summary9.txt` | 纯文本摘�?|
| `_audit/round9/README.md` | 本轮范围与独立性约�?|

*报告�?Lead 汇总：8 �?High 均由 Lead 亲自到源码逐条复核并确认；覆盖判定�?30 个子代理二次核验�?
