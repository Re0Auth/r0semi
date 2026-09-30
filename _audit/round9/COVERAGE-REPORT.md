# 第九轮发现 · 测试用例验证覆盖报告

> 本报告回答一个问题：**第九轮审计的 157 条发现，是否都有测试用例验证？**
> 逐条核对现有全部 `*_test.go`（479 个文件 / 1,847 个测试函数），并为缺失的高危与部分中危发现
> 补齐了可运行的复现测试。完整逐条数据见 `_audit/round9/coverage-matrix.csv`，
> 二次核验原始结论见 `_audit/round9/coverage/S01..S15.json`。

## 一、结论（先给答案）

**不是全部都有。** 逐条核对后：

| 判定 | 含义 | 数量 |
|---|---|---|
| **direct** | 有测试**锁定该缺陷**：现状下通过，一旦按报告建议修复就会失败（或当前为红灯的「修复期望」探针） | 29 |
| **partial** | 只有**相关路径**的测试：走到了这段代码，但没有断言本报告描述的缺陷 | 105 |
| **none** | **完全没有测试**到达该行为 | 23 |
| 合计 | | 157 |

- **8 条 High 全部已有直接复现测试**（其中 7 条为本轮新写或补齐）。
- **30 条 Medium：7 条 direct、19 条 partial、4 条 none。**
- 缺口集中在 Low（13 条 none）与 Info（6 条 none），以及大量只测「正常路径」的 partial。

> 约定说明：判定口径是「该测试能否把本报告的缺陷钉死」。只测相邻功能、或只在正确实现下才通过
> 的「红灯修复期望探针」，都记 partial；后者仍是有价值的验证（它证明缺陷存在），只是不是缺陷回归护栏。

## 二、High 逐条（8/8 已覆盖）

| ID | 复现测试 |
|---|---|
| S02-1 | `internal/zzprobe/audit6/z02protocoltoken/idtoken_test.go :: TestZ02MaxAgeAndPromptLoginAreIgnored` |
| S03-1 | `internal/auth/zz_audit9_returnto_test.go :: TestAudit9ReturnToLengthIsUnboundedInTheSession` |
| S06-1 | `idp/zz_audit9_discovery_body_test.go :: TestAudit9DiscoveryBodyHasNoSizeCap` |
| S08-2 | `cmd/re0auth/zz_audit9_dsnenv_test.go :: TestAudit9DSNEnvIsIgnoredWhenDriverIsInferred` |
| S10-1 | `internal/httpapi/zz_audit9_inflight_planes_test.go :: TestAudit9OneAddressHoldsTheWholeInFlightCapAcrossPlanes` |
| S13-1 | `internal/httpapi/zz_audit9_compress_bypass_test.go :: TestAudit9Compression406BypassesTheRateLimiter` |
| S13-5 | `internal/store/memory/oidc_family_test.go :: TestRefreshTombstonesAreSweptOnTheSpentTokensDeadline` |
| S14-2 | `internal/federation/zz_audit9_bind_unbind_race_test.go :: TestAudit9CompleteBindResurrectsAnUnboundRow` |

## 三、本轮新增/补齐的复现测试（12 个测试函数）

| 覆盖发现 | 文件 | 测试函数 | 验证内容 |
|---|---|---|---|
| S01-2 | `oauth/zz_audit9_device_store_growth_test.go` | `TestAudit9MemoryDeviceStoreNeverReclaimsExpiredRecords` | 过期设备记录永不回收（无删除、无清扫） |
| S03-1 | `internal/auth/zz_audit9_returnto_test.go` | `TestAudit9ReturnToLengthIsUnboundedInTheSession` | 8 KiB return_to 被原样写进服务端 session |
| S06-1 | `idp/zz_audit9_discovery_body_test.go` | `TestAudit9DiscoveryBodyHasNoSizeCap` | 2 MiB discovery 文档被接受（1 MiB 上限不覆盖此路径） |
| S08-2 | `cmd/re0auth/zz_audit9_dsnenv_test.go` | `TestAudit9DSNEnvIsIgnoredWhenDriverIsInferred` | dsn_env 推断为 postgres 但 DatabaseURL 为空、审计密钥未校验 |
| S10-1 | `internal/httpapi/zz_audit9_inflight_planes_test.go` | `TestAudit9OneAddressHoldsTheWholeInFlightCapAcrossPlanes` | 单个地址跨两平面占满全部并发槽位 |
| S10-2 | `internal/httpapi/zz_audit9_readyz_panic_test.go` | `TestAudit9PanickingReadinessProbeWedgesReadinessAtChecking` | 探针 panic 后 /readyz 永久卡在 503 checking |
| S13-1 | `internal/httpapi/zz_audit9_compress_bypass_test.go` | `TestAudit9Compression406BypassesTheRateLimiter` | 406 分支不消耗限流令牌 |
| S13-1 | `internal/httpapi/zz_audit9_compress_bypass_test.go` | `TestAudit9Compression406BypassesTheInFlightCap` | 406 分支不占用并发槽位 |
| S13-5 | `internal/store/memory/zz_audit9_tombstones_test.go` | `TestAudit9RefreshTombstonesAreUnbounded` | 2000 次轮换留下 2000 个 tombstone 且清扫不回收 |
| S14-2 | `internal/federation/zz_audit9_bind_unbind_race_test.go` | `TestAudit9CompleteBindResurrectsAnUnboundRow` | Unbind 成功后，在途 CompleteBind 把行写回来 |
| S08-8 | `internal/federation/zz_audit9_buffer_budget_zero_test.go` | `TestAudit9ZeroBufferBudgetIsCoercedToTheDefault` | 显式配置的上游字节预算 0 被静默换成 64 MiB 默认 |
| S13-6 | `internal/compress/zz_audit9_1xx_status_test.go` | `TestAudit9InformationalStatusSwallowsTheFinalStatus` | 1xx 状态锁定 wroteHeader，后续最终状态被吞掉 |

## 四、Medium 逐条（30 条）

| ID | 判定 | 测试 / 缺口 |
|---|---|---|
| S01-1 | partial | `oauth/device_test.go :: TestDeviceAuthorizationHappyPath` No test asserts single-use redemption of an approved device_code. Needed: a default-suite test that (a) redeems an approved device_code, then polls the same code again after the poll interval and asserts invalid_grant and that no second access/refresh pair exis… |
| S01-2 | direct | `oauth/zz_audit9_device_store_growth_test.go :: TestAudit9MemoryDeviceStoreNeverReclaimsExpiredRecords` |
| S01-3 | direct | `oauth/tokens_reuse_test.go :: TestMemoryStoreSweepReclaimsExpiredTombstones` |
| S01-6 | partial | `upstreamkit/cascade_test.go :: TestCascadeIsAdvertisedOnlyWhenImplemented` Need a cascade test whose registry contains a ClientPublic client and which POSTs /oauth/cascade_revocation with that public client_id, a bogus client_secret and an arbitrary token, asserting the request is refused (401) before the hook. Curren… |
| S02-2 | direct | `internal/oidchttp/oidchttp_test.go :: TestPromptNoneRequiresASession` |
| S02-3 | partial | `internal/oidchttp/device_clientauth_test.go :: TestDeviceGrantPollAcceptsAdvertisedClientSecretPost` No test registers a confidential client whose secret contains '+', ' ', '%', '/' or '=' and sends the correctly percent-encoded Basic pair (rawBasicHeader(url.QueryEscape(id), url.QueryEscape(secret))) to POST /oauth/d… |
| S02-4 | partial | `internal/oidcstore/oidcstore_test.go :: TestValidateSigner` Missing: NewSigner(good2048).WithRetired(RetiredSigningKey{ID:"old", Public:&small1024.PublicKey}) must be rejected by ValidateSigner (it is currently accepted and the key is published by KeySet/JWKS). Harness is trivial: reuse the existing 1024-bit `small` v… |
| S04-1 | partial | `oauth/zz_probe_test.go :: TestZZProbeDeviceCodeRepeatMint` Needs an assertion on the oauth.Service path: after one successful token exchange, a second PollDeviceAuthorization with the same approved device_code must return invalid_grant, and a poll issued after RevokeGrant must not mint a new access+refresh pair. A con… |
| S05-1 | partial | `internal/federation/refresh_test.go :: TestFetchRebindsWhenRefreshRejected` No test reaches the defective status-code switch at refresh.go:178-183 with an error code that is NOT invalid_grant. The 400 case used by the existing tests is decided by re.ErrorCode, so a fix that restricts isRefreshRejected to invalid_grant… |
| S05-2 | partial | `internal/federation/zz_audit_race_test.go :: TestZZAuditRaceProbeAllPathsAtOnce` No test drives the specific CompleteBind window (token exchange in flight while Unbind, RevokeAllBindings, or lifecycle.DeleteAccount deletes the row and shreds the secret) and then asserts the resurrected row/secret do or do not exist. T… |
| S06-2 | direct | `internal/zzprobe/verifyfederation/addr_test.go :: TestVerifyProxyGuardJudgesTheProxyNotTheTarget` |
| S06-3 | partial | `internal/zzprobe/audit7/z18gohazardsweep/probes_test.go :: TestZ18ConcurrentLoginIsBlockedByAnotherLoginsDiscovery` CORRECTED from direct to partial. It is a pure fixture probe rather than a defect pin: it t.Errorf's while the defect exists and would PASS only once the lock is released without single-flight, so it doe… |
| S06-4 | none | _无测试_ No test floods /login/{provider}/start, and no test observes the size of SocialLogin.states or the O(n) sweepLocked cost. referencesource/social_test.go exercises start+callback once (TestSocialLoginEndToEnd, TestSocialLoginStateIsSingleUse) but never inserts more than a state or two and never asserts a bound; th… |
| S06-5 | none | _无测试_ No test floods POST /login/taptap/challenge or inspects TapTapLogin.attempts / sweepLocked. referencesource/taptap_test.go exercises one challenge+poll end to end (TestTapTapLoginEndToEnd, with a fake clock) and internal/zzprobe/audit7/z14kitrptaptap/refsrc_test.go adds cross-browser poll probes, but neither inse… |
| S07-1 | none | _无测试_ No test exercises redirect handling in tapsign or taptapoauth. Every test builds an httptest server that answers in place and passes srv.Client() (CheckRedirect nil is never a variable under test); no test returns a 302 to a second host. httpclient/outbound_test.go TestNoCrossHostRedirectsRefusesASchemeChange onl… |
| S07-2 | partial | `internal/zzprobe/audit6/z03crypto/binding_namespace_test.go :: TestProbeBindAuditFailureStrandsTheUpstreamToken` No default-suite regression guard for the store-then-audit order. Harness needed: an untagged vault/federation test with a failing audit.Logger asserting Enroll leaves no record (repo has no identity) / no … |
| S08-1 | direct | `cmd/re0auth/zz_audit_keysource_test.go :: TestAuditRenamedKekEnvLosesToTheFixedName` |
| S08-4 | partial | `internal/federation/killswitch_test.go :: TestRevokeUserBindingsLeavesOthersAlone` Harness needed: bind a user in internal/federation over a vault whose Revoke returns an error (the existing revokeBrokenVault in refresh_rejected_test.go is the right shape), assert RevokeUserBindings returns Failed>=1 with a nil error;… |
| S09-1 | partial | `internal/store/postgres/migrate_down_test.go :: TestMigrateDownRollsBackOneStep` No test reaches the withMigrationLock/MigrateDown DSN-parse-error path the finding is about. Harness needed: call MigrateDown(ctx, malformedDSN, DefaultPoolOptions()) (or Migrate) with a DSN whose password pgconn cannot redact (e.g. "post… |
| S09-2 | direct | `internal/zzprobe/pgstore/atomicity_probe_test.go :: TestMultiStatementMutationsRunInATransaction` |
| S10-2 | direct | `internal/httpapi/zz_audit9_readyz_panic_test.go :: TestAudit9PanickingReadinessProbeWedgesReadinessAtChecking` |
| S11-6 | partial | `internal/store/postgres/auditchain_test.go :: TestVerifyTimeoutOutlivesThePoolBoundButStaysUnderTheHTTPCeiling` Nothing asserts a per-endpoint concurrency bound, a single-flight/last-result cache, or that repeated /v1/admin/audit/verify calls cannot pin pooled connections. Harness needed: a DB-backed test (TEST_DATABA… |
| S12-1 | none | _无测试_ Nothing proves the AbortController deadline survives `await res.text()` (clearTimeout at api.ts:354 happens before the body read at :369). Harness needed: a Playwright test that page.route-fulfils a response whose headers arrive but whose body never completes (or is delayed past 15s), then asserts the page leaves… |
| S13-2 | partial | `internal/zzprobe/perf/memstore_test.go :: TestMemStoreDevicePurgeIsPerInsert` No test pins purgeExpiredDevicesLocked's semantics or cost. Needed: plant N expired and M live device authorizations and assert one StoreDeviceAuthorization removes exactly the expired ones (Counts().Devices before/after), or a deterministic… |
| S13-3 | partial | `internal/zzprobe/audit7/z15performancecapacity/performance_probe_test.go :: TestZ15MemoryDeleteAuthRequestScalesWithEveryPendingCode` No defect-pinning test exists for the O(pending codes) scan. Needed: a test that asserts the defective behaviour directly (e.g. an instrumented codes map proving DeleteAuthRequest visit… |
| S14-3 | partial | `vault/rotate_page_test.go :: TestRotateWalksPagesAndCoversEveryRecord; TestMemoryRepoPagesMatchList` Needs a scaling/complexity probe (the z15 perCall pattern) that fixes the page size and grows N, asserting the per-page cost does not track N, or a pager wrapper that fails if ListPage internally calls List()/sorts all… |
| S14-5 | partial | `oauth/refresh_family_test.go :: TestRefreshReplayRevokesTheFamilyWithoutOverRevoking; TestRefreshReuseWithAFailingRevocationFailsClosed` Needs a concurrent-interleaving harness: a Store wrapper that parks SaveAccess/SaveRefresh (or RevokeRefreshFamily) so a second Refresh can run between the winner's ConsumeRefresh an… |
| S14-6 | partial | `internal/store/memory/oidc_family_test.go :: TestRefreshReplayRevokesTheWholeFamily` Needs a scaling probe over the replay path (perCall at N and kN tombstones/live refresh tokens, with a flatness control) or an invariant/import probe asserting a familyID index and an idHash index are maintained by putRefreshLocked/de… |
| S15-1 | partial | `internal/zzprobe/audit7/z13verify/z13verify_test.go :: TestZ13VKeyBackupLeavesPlaintextWhereTheSiblingLeavesNothing` No test exercises the defect: an `age` that exists but exits non-zero on line 45. Missing harness: put a stub `age` (exit 1) early on PATH, run the real scripts/backup.sh with BACKUP_AGE_RECIPIENT set i… |
| S15-3 | partial | `internal/archtest/k8s_test.go :: TestBackupWorkloadIsSafeToLeaveRunning` It never asserts jobTemplate.spec.activeDeadlineSeconds, a `timeout`/PGOPTIONS statement_timeout around pg_dump, or a backup-staleness metric/alert in deploy/prometheus/re0auth.rules.yml — exactly the defect S15-3 describes. Harness needed: exten… |

## 五、完全无测试到达的 23 条（缺口清单）

| ID | 严重度 | 缺口 |
|---|---|---|
| S06-4 | medium | No test floods /login/{provider}/start, and no test observes the size of SocialLogin.states or the O(n) sweepLocked cost. referencesource/social_test.go exercises start+callback once (TestSocialLoginEndToEnd, TestSocialL… |
| S06-5 | medium | No test floods POST /login/taptap/challenge or inspects TapTapLogin.attempts / sweepLocked. referencesource/taptap_test.go exercises one challenge+poll end to end (TestTapTapLoginEndToEnd, with a fake clock) and internal… |
| S07-1 | medium | No test exercises redirect handling in tapsign or taptapoauth. Every test builds an httptest server that answers in place and passes srv.Client() (CheckRedirect nil is never a variable under test); no test returns a 302 … |
| S12-1 | medium | Nothing proves the AbortController deadline survives `await res.text()` (clearTimeout at api.ts:354 happens before the body read at :369). Harness needed: a Playwright test that page.route-fulfils a response whose header… |
| S02-10 | low | Confirmed none. Independent greps for state/nonce length coverage found nothing: no test matches "(state\|nonce)": {strings.Repeat, no maxState/maxNonce/StateBytes/NonceBytes/stateLength/nonceLength identifiers, and len(… |
| S04-7 | low | No test reaches writeDecisionError's default branch or the DescribeAuthorization/DenyAuthorization error branches in internal/httpapi/authorization_routes.go. authz_flow_test.go's flowEnvOptions only allows substituting … |
| S04-8 | low | oauth/scope_test.go exercises Registry.Register (duplicate/malformed rejection), Get and Resolve only sequentially, as does oauth/as_test.go:43; no test performs a concurrent Register against concurrent Get/Resolve, so t… |
| S04-9 | low | Every default-build call to BeginDeviceAuthorization in the oauth tests passes a non-empty scope slice (device_test.go, device_verify_path_test.go); the empty-scope input is never exercised, so the Registry.Resolve(nil) … |
| S06-6 | low | Every existing conformance.Run test serves a 200 /.well-known/oauth-authorization-server (upstreamkit/conformance/conformance_test.go default and its metadata() helper, internal/zzprobe/audit7/z14kitrptaptap/conformance_… |
| S06-8 | low | No test asserts that an injected RegistryConfig.HTTPClient must have a Timeout, and none exercises a hung jwks_uri during verifier.Verify to show that client cancellation/deadline cannot release the goroutine. TestExchan… |
| S10-3 | low | The panic-after-commit path (finish/release skipped, zstd encoder Close never called, writer never returned to sync.Pool) has no test. Harness needed: compress.Compressor.Handler wrapping a handler that writes >DefaultMi… |
| S11-5 | low | Confirmed none. Harness needed: an admin.Service whose Clients.SetStatus returns oauth.ErrClientNotFound (e.g. oauth.MemoryClientRegistry after Delete, or a stub) while Tokens is non-nil with live tokens, then assert Rev… |
| S12-10 | low | Needed: a Playwright test that page.route-fulfils a 200 with a shape missing `data` (e.g. {} for /v1/admin/clients or /v1/grants) and asserts the user sees a fixed recoverable message rather than +error.svelte rendering … |
| S14-9 | low | Harness needed: an httptest server whose httpapi.Config.Ready panics; issue one GET /readyz (recovered by the outer recoverer), then issue subsequent /readyz requests and assert they do not latch at 503 'checking' but re… |
| S15-10 | low | No test inspects git file modes. The only script-related probes (internal/zzprobe/audit7/z13verify and z13deploycisupplychain) shell out to `git check-ignore`, run the scripts via `bash scripts/...` (never `./scripts/...… |
| S15-2 | low | No test reaches the CI service-image tags. internal/archtest/workflows_test.go only validates remote `uses:` SHA pinning (and pnpm caching / permissions), and internal/archtest/dockerfile_test.go only validates Dockerfil… |
| S15-9 | low | No test reads deploy/k8s/base/namespace.yaml. internal/archtest/k8s_test.go parses the base and backup YAML but asserts only Deployment/Service/PDB/NetworkPolicy/ServiceAccount kinds, probes, resources, the pod/container… |
| S07-4 | info | No test constructs a Repo whose Get returns a Record with rec.Identity != the requested id. vault/service_test.go TestCiphertextBindsIdentity tampers with rec.Identity but re-Puts and re-Gets through MemoryRepo, so the r… |
| S07-9 | info | No test asserts CreatedAt semantics on re-enroll. vault/service_test.go TestEnrollReplacesExisting only asserts the replaced plaintext is readable; no vault test reads Record.CreatedAt at all (repo-wide grep for CreatedA… |
| S12-2 | info | The dev root redirect (vite.config.ts:27-28) has no coverage at all. Harness needed: extract the plugin's configureServer middleware (or refactor it into an exported function) and call it with mock req/res/next for targe… |
| S12-9 | info | Needed: a Playwright test that page.route-fulfils a GET endpoint with 503 (optionally Retry-After), lets the client retry to success, and proves the first response body was released - e.g. by forcing a fresh connection (… |
| S14-11 | info | Harness needed: an injectable provider/panic seam in oidchttp (or a test-only ServeHTTP wrapper) that panics inside serveOAuth after bw is acquired, plus a pool-observation hook (count of outstanding writers / re-acquire… |
| S15-13 | info | No _test.go reads .gitleaks.toml (repo-wide grep: the only references are the CI action in ci.yml's secrets job, docs prose, and the audit reports). The only gitleaks usage in the project is the CI action (ci.yml secrets… |

## 六、分严重度统计

| 严重度 | direct | partial | none | 合计 |
|---|---|---|---|---|
| high | 8 | 0 | 0 | 8 |
| medium | 7 | 19 | 4 | 30 |
| low | 10 | 72 | 13 | 95 |
| info | 4 | 14 | 6 | 24 |
| **合计** | **29** | **105** | **23** | **157** |

## 七、如何补齐（可执行清单）

1. **Medium 缺口（4 条 none）**：S06-4、S06-5、S07-1、S12-1 —— 需要构造畸形输入或故障注入（referencesource 的 states/attempts 洪泛、跨主机 302、前端 body 停滞等）。
2. **Low 缺口（13 条 none）**：S02-10、S04-7、S04-8、S04-9、S06-6、S06-8、S10-3、S11-5、S12-10、S14-9、S15-10、S15-2、S15-9。
3. **Info 缺口（6 条 none）**：S07-4、S07-9、S12-2、S12-9、S14-11、S15-13。
4. **Partial 的最大类**：性能类发现（N+1、全表扫描、O(N²)）几乎都只有正确性测试，没有基准/分配断言；要「有测试验证」应加 `Benchmark` 或 `AllocsPerRun`/查询计数断言。
5. 所有新增测试都遵循仓库既有的「缺陷护栏」风格：现状通过、修复即红，并在注释里写明如何更新。
