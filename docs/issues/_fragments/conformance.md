# OIDF 一致性套件（conformance spike）的已知缺口

> 来源：`docs/conformance.md` §「Known gaps (the reason this is still a spike)」与 §「Turning it into a gate」。
> 这些不是 OIDF 模块报出的产品缺陷，而是**这道门禁自身还不完整**的已知项；
> 写进寄存器的理由是：转成门禁之前必须逐条收口，且它们与 `S15-2`（CI 镜像浮动 tag）同族。
> 手工维护的文件（不随第九轮报告重生成）。

## P2/P3

| ID | 严重度 | 问题 | 位置 | 状态 | 修法要点 |
|---|---|---|---|---|---|
| CONF-1 | P3 | conformance spike 的四个镜像都是浮动 tag（`caddy:2`、`curlimages/curl:latest`、`conformance-suite:latest`、`mongo:6.0.13`），与本项目"基础镜像按 digest 固定"的纪律不一致 | `docs/conformance.md:218-223` | OPEN | 转门禁时按 digest 固定；与 `S15-2` 一起收 |
| CONF-2 | P3 | 计划 **allowlist 未钉死**：必须命名本 OP 支持的计划（授权码+PKCE+refresh+设备），并显式记录有意不支持（DCR/PAR）的计划，而不是静默跳过 | `docs/conformance.md:174-177` | OPEN | 在 plan 配置/dispatch 里写死 allowlist，未知计划报错 |
| CONF-3 | P3 | JVM trust store 的派生镜像（`keytool` 导入 Caddy 本地 CA）**从未在 runner 上观察到**；基础镜像 JDK 路径不符即静默回退上游镜像 | `docs/conformance.md:162-170` | OPEN | 首次绿后固化；或改用公开可信证书消除该步骤 |
| CONF-4 | P3 | 该 job 仍是 spike：`continue-on-error`、非阻断，且 `release.yml` **没有调用它** ⇒ 打 tag 发布不经过一致性门禁 | `docs/conformance.md:225-229` | OPEN | 计划全绿后去掉 `continue-on-error`、按 digest 固定镜像，并从 `release.yml` 前置调用 |

## 有意不做 / 已裁定

- `oidcc-server` 的 `client_id` WARNING —— 已知且接受的行为差异，见 `docs/oidc-decision.md` O-10 与 `not-doing.md`。
