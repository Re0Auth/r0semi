# 数据源接入清单 / Source Onboarding Checklist

> 面向：愿意被 Re0Auth 接入的游戏后端 / 社区数据源负责人。
> Audience: operators of a game backend or community data source that wants to be
> reachable through Re0Auth.
>
> 关键词 / Keywords: **MUST（必需）**、**SHOULD（强烈建议）**、**MAY（可选，高杠杆）**。
> 一条原则贯穿全文 / One rule runs through this document:
> **声明即承诺。广告一个能力，就等于承诺它存在；做不到的就不写。**
> **Advertising a capability IS promising it. If you cannot do it, do not list it.**

## 0. 一句话 / In one line

Re0Auth 替下游保管「你的源签发的、可吊销的派生令牌」，并按你规定的方式注入；你的主凭据永远不出你的服务器。
Re0Auth holds the *derived, revocable* token **your source issues**, injects it the
way you specify, and never asks for your master credential.

我们需要你配合的最小集合只有四条 / The minimum ask is exactly four items:

| # | 事项 / Item | 验收一句话 / Acceptance in one line |
|---|---|---|
| A1 | 每用户派生令牌 / Per-user derived token | 用户扫码一次即可拿到；不能反向换出主凭据；可单方面吊销 |
| A2 | 注入方式 / Injection | 设一个头（首选 `Authorization: Bearer`）即可通过鉴权，无需改 body |
| A3 | 吊销接口 / Revocation | 调一次即作废；被吊销的令牌在所有受保护路径上返回 401 |
| A4 | 自描述文档 / Self-describing doc | 一个稳定 URL 的 JSON，能凭它自动配置一个源 |

其余是稳定性与可选增强，见 §2、§3。
Everything else is stability or optional leverage (§2, §3).

---

## 1. MUST — 接入必需 / Required

### A1. 每用户派生令牌的签发 / Per-user derived token issuance

**要求 / Requirement**

- 以玩家的 TapTap（或等价）登录为输入，产出一个**不透明令牌**。
  Take the player's TapTap (or equivalent) login as input and return an **opaque token**.
- 流程必须能被第三方程序驱动（轮询二维码状态 / 一次性 code / OAuth），**不要让用户手抄 token**。
  The flow must be drivable by a program (QR polling / one-time code / OAuth);
  **never require a human to copy a token by hand**.
- 令牌**不可反推你的主凭据**，且带 **scope + 有效期**。
  The token must **not** be reducible to your master credential, and it must carry
  a **scope and an expiry**.
- 你能**单方面吊销**它，不影响用户其它客户端。
  You can **revoke it unilaterally**, without disturbing the user's other clients.

**为什么 / Why**

主凭据是万能钥匙，一旦被复制就无法挽回。派生令牌让 Re0Auth 只持有「可以随时作废的那一把」，这也是玩家愿意把账号连过来的前提。
A master credential is irreversible once copied. A derived token is the one thing
Re0Auth can hold and you can kill at any time — which is what makes players willing
to connect.

**验收 / Acceptance**

1. 在与生产隔离的测试环境里，从零完成一次签发（脚本化，无人工复制）。
2. 该令牌通过 §A2 的方式可访问受保护路径。
3. 该令牌**不能**用于换出主凭据 / 访问带 `strict=2` 或 admin 级别的路径。
4. 吊销后，**所有**受保护路径对它返回 401。
5. 同一用户可同时持有多个令牌，吊销其中一个不影响另一个。

---

### A2. 令牌注入方式 / Token injection

**要求 / Requirement**

- 首选：在所有需要用户身份的路径上接受 `Authorization: Bearer <token>`。
  Preferred: accept `Authorization: Bearer <token>` on every path that needs a user.
- 若用自定义头（如 `X-Auth-User-Token`），请在文档中写明：**头名大小写、值格式、是否还需要额外头**（客户端 id、版本号、时间戳/nonce/签名等）。
  If you use a custom header (e.g. `X-Auth-User-Token`), document the **exact name,
  value format, and any additional headers** (client id, version, timestamp/nonce/signature).
- **不要把凭据要求放进 JSON body**。如果现状如此，请同时接受等效的头（详见下）。
  **Do not require a credential inside the JSON body.** If that is the status quo,
  please also accept the equivalent header.
- 若必须签名（HMAC），提供**签名规范**：待签串的精确拼接、算法、时钟偏移容忍、重放窗口。
  If signing (HMAC) is required, provide the **signing spec**: the exact signing
  string, algorithm, clock-skew tolerance and replay window.

**为什么 / Why**

「凭据在 body 里」会强迫 Re0Auth 解析并改写下游的 JSON，这既是实现负担，也容易在字段升级时悄悄写坏请求。一个头是最稳的接口。
A body credential forces Re0Auth to parse and rewrite the caller's JSON — a
maintenance burden and a quiet way to corrupt requests when fields evolve. A header
is the stable interface.

**验收 / Acceptance**

1. 仅设置一个头（或按签名规范计算出的几个头）就能通过鉴权。
2. 请求 body 可以原样透传，Re0Auth 不需要理解其内容。
3. 缺少该头时返回明确的 `401`，且错误体带稳定机器码（见 §B3）。

---

### A3. 吊销接口 / Revocation endpoint

**要求 / Requirement**

- 一个文档化的端点，用**你自己的凭据**（而非被吊销的令牌）调用，作废一张派生令牌。
  A documented endpoint that invalidates one derived token, called with **your own
  authority** (not the token being revoked).
- **幂等**：重复吊销、吊销不存在的令牌都应成功返回。
  **Idempotent**: revoking twice, or revoking an unknown token, must succeed.
- 可选（高价值）：一个「级联吊销」端点，结束该用户的**整段上游会话**（含其它设备）。
  Optional but valuable: a **cascade revocation** endpoint that ends the subject's
  whole upstream session, including other devices.

**为什么 / Why**

玩家点「断开连接」或触发 Kill Switch 时，Re0Auth 必须能真的让这张令牌失效；否则「已断开」就是一句谎话。
When a player disconnects or the kill switch fires, Re0Auth must be able to
actually kill the token — otherwise "disconnected" is a lie.

**验收 / Acceptance**

1. 调用吊销接口后，该令牌在 §A2 的所有受保护路径上立即 401。
2. 连续调用两次返回成功。
3. 若实现了级联吊销，在文档中通过 `cascade_revocation_endpoint` 声明，并验收「另一台设备也被登出」。

---

### A4. 自描述文档 / Self-describing discovery document

**要求 / Requirement**

在一个**稳定 URL** 提供一份 JSON。首选 `/.well-known/re0auth-upstream`（[`docs/upstream-protocol.md`](./upstream-protocol.md) 定义的发现文档，`upstreamkit` 会自动生成它）；暂时做不到的话，一份固定链接的静态 JSON 也可以。
Publish a JSON at a **stable URL**. Preferred: `/.well-known/re0auth-upstream`, the
discovery document defined in [`docs/upstream-protocol.md`](./upstream-protocol.md)
and generated for you by `upstreamkit`. A static JSON at a fixed link is an
acceptable interim.

字段 / Fields（`upstreamkit` 已覆盖前几项；标 ★ 的是我们建议补充的，现在先用静态 JSON 写也行）:

| 字段 / Field | 含义 / Meaning |
|---|---|
| `source`, `display_name` | 源标识与展示名 / id and display name |
| `base` | 业务 API 基址（含前缀）/ business API base including prefix |
| `token_class` | `revocable` 或 `long_lived` / honest classification |
| `revoke`, `cascade_revocation_endpoint` | 吊销端点 / revocation endpoints |
| `resources` | 资源名 + canonical schema + scope / resource name, schema, scope |
| ★ `auth` | 注入方式：`bearer` / `header`（含名字）/ `hmac`（含规范链接） |
| ★ `public_paths` | 免鉴权路径 / paths needing no credential |
| ★ `user_paths` | 需每用户令牌的路径 / paths needing a per-user token |
| ★ `write_paths` | 写操作路径（与读分开）/ write paths, separated from reads |
| `openapi` | OpenAPI 文档链接（若有）/ link to your OpenAPI, if any |
| ★ `api_version` | API 版本，并在响应头回带 / API version, echoed in a response header |
| ★ `rate_limits` | 限额维度与数值 / rate-limit dimensions and values |
| `contact` | 出问题时联系谁 / who to contact |

**为什么 / Why**

有了它，接入是「读文档→配置」而不是「读代码→试错」；能力也就能被如实展示（做不到的字段就省略）。
With it, onboarding is "read the doc → configure", not "read the code → guess";
and capabilities can be shown honestly (omit what you cannot do).

**验收 / Acceptance**

1. `curl` 该 URL 得到可解析 JSON，无鉴权依赖。
2. 其中每个端点都能被实际调用并符合声明。
3. 路径分类（公共 / 用户 / 写）与实际行为一致。

---

## 2. SHOULD — 稳定性 / Stability

### B1. TLS 证书有效 / Valid TLS certificate

证书须由公共 CA 签发、在有效期内、链完整。**过期证书会让标准客户端直接拒连**，Re0Auth 不会为任何源关闭证书校验。
The certificate must chain to a public CA, be within its validity window, and be
complete. **An expired certificate makes standard clients refuse to connect**, and
Re0Auth will not disable verification for any source.

*验收：`openssl s_client -connect <host>:<port> -servername <host>` 无报错，`notAfter` 在将来。*

### B2. 限流透明、按用户归因 / Transparent, per-user-attributed rate limits

- 公布限额维度（per-key / per-IP / per-user）与数值、突发、以及 `Retry-After` 语义。
  Publish the dimensions, values, burst and `Retry-After` semantics.
- **尽量按「请求携带的每用户令牌」归因，而不是按 Re0Auth 的出口 IP。** Re0Auth 是所有下游的共享出口，按 IP 会把所有人算进一个桶。
  **Attribute by the per-user token in the request, not by Re0Auth's egress IP.**
- 如果可能，给 Re0Auth 一个更高配额的 key。
  If possible, issue Re0Auth a higher-quota key.

*验收：给出一个可预期的限额说明；Re0Auth 的请求在你的统计里能按用户区分。*

### B3. 稳定的错误与版本 / Stable errors and versioning

- HTTP 状态码语义正确（401 / 403 / 404 / 429 / 5xx 不要混用）。
  Correct status semantics.
- 错误体带**稳定的机器码**（首选 RFC 9457 `application/problem+json`）。
  Error body with a **stable machine code** (RFC 9457 preferred).
- 响应头回带 API 版本；破坏性变更**提前通知**。
  Echo the API version in a response header; announce breaking changes in advance.

*验收：一个 401 的错误体里有可据以分支的字段，而不是一句散文。*

---

## 3. MAY — 高杠杆 / High leverage

### C1. 在源侧跑一个薄适配层 / Run a thin adapter on your side

如果你愿意，`upstreamkit` 可以在你的服务前放一个进程：它对外暴露 OAuth + `/resources` +
一个「原生透传」口，把原生方言（header 名、HMAC、body 凭据）挡在源侧。
Then Re0Auth needs no source-specific code, and the adapter evolves with your API.

*收益：Re0Auth 侧零适配；你的主凭据与方言完全不出你的边界。*

### C2. 如实声明能力 / Declare capabilities honestly

只在**真正实现**时才声明：`cascade_revocation_endpoint`、`raw`（允许逐字透传的原生 API）、
`jwks_uri`、`token_class`。声明了就要能通过验收——广告了却不实现，比不广告更糟。
Declare `cascade_revocation_endpoint`, `raw`, `jwks_uri`, `token_class` **only if
real**. An advertised capability that does not exist is worse than a missing one.

---

## 4. Re0Auth 会给源什么 / What Re0Auth gives back

| 给源 / To the source | 说明 / Detail |
|---|---|
| 一个稳定域名 | 下游只接一次，就消费了你的数据 |
| **更少的负载** | 出站连接池 + 并发上限（bulkhead）+ 指数退避重试；同一绑定的刷新串行化。**当前没有响应缓存或 singleflight**，旧文档的这项承诺并未实现 |
| 每用户归因 | 请求带你的每用户令牌，谁在用一目了然 |
| 凭据不外泄 | 下游永远拿不到你的令牌 |
| 一处撤销 | 解绑 / Kill Switch 调用你的吊销接口，且只在你声明支持时显示「全部退出」 |
| 统一 scope | 你的资源以 canonical scope 暴露，跨下游可移植 |

---

## 5. 如何回复 / How to respond

请按 §A1–A4 逐条给出：**端点 / 头名 / 示例请求 / 示例响应 / 吊销方式 / 测试环境**。
未实现的条目直接写「暂不支持」即可——我们会如实降低展示能力，而不是假装可用。

For each of §A1–A4 please provide: **endpoint, header names, example request,
example response, how to revoke, and a test environment.** Write "not supported"
for anything you cannot do; we will honestly downgrade the capability rather than
pretend it works.

---

## 附录：最小验收示例 / Appendix: minimal acceptance sketch

```sh
# A1+A2: 用派生令牌访问一条受保护路径
curl -sS -D - \
  -H "Authorization: Bearer $DERIVED_TOKEN" \
  "https://<source>/<base>/<user-path>"

# A3: 吊销后应变为 401
curl -sS -X POST -H "X-Your-Authority: ..." \
  "https://<source>/<base>/revoke" -d '{"token":"'"$DERIVED_TOKEN"'"}'
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $DERIVED_TOKEN" \
  "https://<source>/<base>/<user-path>"   # 期望 401

# A4: 发现文档
curl -sS "https://<source>/.well-known/re0auth-upstream" | jq .
```

> 相关文档 / See also: [`docs/upstream-protocol.md`](./upstream-protocol.md)、
> [`docs/threat-model.md`](./threat-model.md)、[`docs/architecture.md`](./architecture.md) §4.9。
