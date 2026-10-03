# 第 14 轮：最后 5 条收口

> 前 4 条按 A/A/B+A/A 方案修复（提交 94bbd4b），S02-11 判非缺陷并加组合根守卫。
> 优先级 -7，覆盖 round11/12/13。

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| S03-11 | P3 | core.App.Remove races with an in-flight load, allowing a removed fiber to be marked active without its scope | internal/core/app.go:99; internal/core/app.go:105; internal/core/app.go:334 | FIXED（94bbd4b） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S03-7 | P3 | MemoryStore.Identities scans every identity in the process and holds the lock for the whole scan | internal/account/account.go:231; internal/account/account.go:281; internal/account/account.go:283 | FIXED（94bbd4b） | 见 `docs/security-audit-9.md` §3（类别：performance） |
| S08-3 | P3 | DeleteAccount writes an outcome=ok record claiming the pseudonym key was destroyed before Destroy runs, and the correcting record is best-effort | internal/lifecycle/lifecycle.go:262-271; internal/lifecycle/lifecycle.go:277-291; internal/lifecycle/lifecycle.go:299-302 | FIXED（94bbd4b） | 见 `docs/security-audit-9.md` §3（类别：correctness） |
| S02-11 | P3 · 信息 | [info] DenyAuthorization uses the static issuer only, so a dynamic-issuer deployment emits a denial without the RFC 9207 iss parameter | internal/oidchttp/oidchttp.go:1794; internal/oidchttp/oidchttp.go:1444 | NOT-A-DEFECT（生产两个组合根 cmd/re0auth 与 httpapi.New 都拒绝空 issuer，动态 issuer 形态在 shipped 部署不可达；守卫 internal/archtest/issuer_test.go::TestS02_11CompositionRootsRequireAStaticIssuer 会在有人放开任一组合根时变红） | 见 `docs/security-audit-9.md` §4（类别：correctness） |
| S12-7 | P3 · 信息 | [info] Sources page re-runs O(available x bindings) scans on every reactive invalidation | web/src/routes/sources/+page.svelte:82; web/src/routes/sources/+page.svelte:89; web/src/routes/sources/+page.svelte:288 | FIXED（94bbd4b） | 见 `docs/security-audit-9.md` §4（类别：performance） |

## 已修复

- S03-11 — FIXED（94bbd4b）
- S03-7 — FIXED（94bbd4b）
- S08-3 — FIXED（94bbd4b）
- S12-7 — FIXED（94bbd4b）
