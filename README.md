# r0semi / Re0Auth

音游数据的**身份与授权层**：一套 OIDC/OAuth 协议 + 一个参考实现。

玩家用外部 IdP 登录一次；下游一次 OIDC 接入，同时拿到“这是谁”（`id_token` / `userinfo`）与“能读什么”
（带 scope 的 access token），即可跨游戏、跨数据源读取数据；游戏后端通过实现
[上游协议](docs/upstream-protocol.md) 接入生态。

> [!WARNING]
> **本项目位于迭代期，未达到生产可用，请勿用真实凭据部署。**

## 快速开始

需要 Go 1.27+（见 `go.mod`）。

```sh
cp config/re0auth.example.toml config/re0auth.toml

export RE0AUTH_KEK=$(head -c 32 /dev/urandom | base64)
export DATABASE_URL='postgres://user:pass@localhost:5432/re0auth?sslmode=disable'
export RE0AUTH_AUDIT_KEY=$(head -c 32 /dev/urandom | base64)
export RE0AUTH_OIDC_TOKEN_KEY=$(head -c 32 /dev/urandom | base64)
export RE0AUTH_OIDC_SIGNING_KEY=$(openssl genpkey -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 -outform DER 2>/dev/null | base64 -w0)

go build ./cmd/re0auth
./re0auth -config config/re0auth.toml
```

不设 `DATABASE_URL` 也能跑：状态全部在内存，重启即丢；**但授权引擎仍然是 OpenID Provider**
（ADR-0001 P4b），只是存储从 Postgres 换成内存。无论哪种模式，两把 OP 密钥都必填
（`RE0AUTH_OIDC_TOKEN_KEY`、`RE0AUTH_OIDC_SIGNING_KEY`），缺一即拒绝启动。
**有数据库时 `RE0AUTH_AUDIT_KEY` 也必填**：审计日志逐行链接并用它签名，没有密钥的链只是看起来像防篡改；
内存模式不需要它（内存日志是环形缓冲，本身就不是防篡改结构）。

```sh
RE0AUTH_ISSUER=https://re0auth.example \
RE0AUTH_KEK=$(head -c 32 /dev/urandom | base64) \
./re0auth
```

完整键位、默认值与每段说明见 [`config/re0auth.example.toml`](config/re0auth.example.toml)；
配置优先级为 **环境变量 > 文件 > 默认值**。

### KEK 轮换

三步（`config/re0auth.example.toml` 的 `[vault]` 段里有同样的说明）：

```sh
# 1. 生成新 KEK 放进 RE0AUTH_KEK，并把 vault.kek_id 改成新的（例如 "kek-2"）
# 2. 在 [vault] 下声明旧 KEK，用它在当时用过的那个 id：
#      [[vault.retired]]
#      kek_id  = "kek-1"
#      kek_env = "RE0AUTH_KEK_OLD"
# 3. 轮换，然后删掉这段声明并重启
re0auth -rotate-keys -config config/re0auth.toml
```

参考数据源（独立进程，用来验证 Upstream Kit）：

```sh
cp config/referencesource.example.toml config/referencesource.toml
export TAPTAP_LEANCLOUD_APP_KEY=...   # 或 GOOGLE_CLIENT_SECRET=...

go build ./cmd/referencesource
./referencesource -config config/referencesource.toml
```

## 前端

前端为 SvelteKit 构建出的静态 SPA，`go:embed` 进同一个二进制，挂在 `/app/*`。

```sh
make web     # pnpm install + vite build，产物直接写进 internal/webui/dist
make build
```

## 验证

```sh
gofmt -l .
go vet ./...
go test ./...
make bench    # capacity benchmarks; CI runs these on every change
```

前端：

```sh
cd web && pnpm install --frozen-lockfile && pnpm run check
```

```sh
make e2e      # 或 cd web && npx playwright install chromium && npx playwright test
```

```sh
docker run -d --rm -e POSTGRES_PASSWORD=x -p 5432:5432 postgres:16
TEST_DATABASE_URL='postgres://postgres:x@localhost:5432/postgres?sslmode=disable' \
  go test ./internal/store/postgres/
```

CI 另有一条 `supply-chain` 作业：`govulncheck ./...`（只报**从本代码可达**的依赖漏洞，而非"依赖树里有这个版本"）
与 SBOM 生成，见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)。本地复现：

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
govulncheck ./...
```

## 发布产物

打 `v*` tag 时 CI 会构建并发布预编译二进制（`linux` / `darwin` / `windows` × `amd64` / `arm64`），
每个平台一个归档，内含可执行文件、`config/re0auth.example.toml`、`LICENSE`、`NOTICE`，以及
`README.md` 与 `SECURITY.md`——**「未达生产可用」那条警告要跟着产物走**，而不是留在仓库里。
另有 `SHA256SUMS`、一份 CycloneDX **SBOM**（`re0auth_<version>_sbom.cdx.json`，列出链接进二进制的全部模块），
以及 `SHA256SUMS` 的 **cosign keyless 签名**（`SHA256SUMS.sig` + `SHA256SUMS.pem`）。最后一步是 `gh release create`。

**验证签名。** keyless 意味着签名身份就是发布这个 tag 的 workflow，由 GitHub 的 OIDC 签发、并记录在透明日志里——
没有需要维护的签名密钥，也没有会悄悄过期的密钥：

```sh
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/Re0Auth/r0semi/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS    # macOS: shasum -a 256 -c SHA256SUMS
```

签名覆盖 `SHA256SUMS`，而 `SHA256SUMS` 覆盖每个归档**与** SBOM——一次验证锁住全部产物。

产物**不是开箱即用**：三把密钥与 issuer 必填（`RE0AUTH_KEK`、`RE0AUTH_OIDC_TOKEN_KEY`、
`RE0AUTH_OIDC_SIGNING_KEY`），缺一即拒绝启动；**持久化部署还多一把 `RE0AUTH_AUDIT_KEY`**。
没有默认值是有意的，见上面的「快速开始」。`re0auth -version` 打印构建版本（由 tag 注入），
启动日志里也带同一个值。

`cmd/referencesource` **不在产物里**：它是验证 Upstream Kit 的演示数据源，vault 与会话都在内存、
登录是桩实现，发布它等于暗示可以拿它去部署。

## 容器镜像

`make docker` 用仓库根的多阶段 `Dockerfile` 构建镜像：前端（`pnpm` 构建，锁文件固定版本）→ 静态 Go
二进制（前端 `go:embed` 进同一个文件）→ `scratch` 非 root 运行时（只带二进制与 CA 证书）。基础镜像按
digest 固定，`internal/archtest` 会检查这一点。CI 每次改动都会构建一次；**tag 发布会把
`linux/amd64` 与 `linux/arm64` 镜像推到 GHCR**，附带 SBOM 与 provenance 证明、Trivy 扫描（HIGH/CRITICAL
失败即阻断）与 cosign 签名。

镜像里**没有配置、也没有密钥**：issuer 与各把密钥都在运行时经环境变量注入（见上面的「快速开始」）。
`RE0AUTH_ADDR` 在镜像里预设为 `0.0.0.0:8080`，否则进程默认的 `127.0.0.1` 从容器外不可达。

## 运维面

`/healthz`（存活）与 `/readyz`（就绪）在公网监听器上，纯文本、免限流，供编排器读状态码。

Prometheus 指标（黄金指标 + Go 运行时/进程采集器）与 `pprof` **不在公网端口**：设
`server.internal_addr`（例如 `127.0.0.1:9090`）会另起一个内部监听器提供 `/metrics` 与 `/debug/pprof/`，
不设置即两者都不提供。它**必须与 `addr` 不同**——pprof 会导出进程内部状态，单独一个监听器是「只限内部」
的**结构性**保证，而不是一句约定。

## 许可与合规

本项目采用 **MPL-2.0**，全文见 [LICENSE](LICENSE)，第三方依赖见 [NOTICE](NOTICE)。

贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，安全漏洞请走 [SECURITY.md](SECURITY.md)

## 特别鸣谢

- **Yifan Shi, Wei Zhang, Tianyi Cui.** *A Programming Paradigm for Spatiotemporal Composability.*
  arXiv:2608.25512 
