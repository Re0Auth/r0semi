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
export RE0AUTH_OIDC_TOKEN_KEY=$(head -c 32 /dev/urandom | base64)
export RE0AUTH_OIDC_SIGNING_KEY=$(openssl genpkey -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 -outform DER 2>/dev/null | base64 -w0)

go build ./cmd/re0auth
./re0auth -config config/re0auth.toml
```

不设 `DATABASE_URL` 也能跑：状态全部在内存，重启即丢；**但授权引擎仍然是 OpenID Provider**
（ADR-0001 P4b），只是存储从 Postgres 换成内存。无论哪种模式，两把 OP 密钥都必填
（`RE0AUTH_OIDC_TOKEN_KEY`、`RE0AUTH_OIDC_SIGNING_KEY`），缺一即拒绝启动。

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

## 发布产物

打 `v*` tag 时 CI 会构建并发布预编译二进制（`linux` / `darwin` / `windows` × `amd64` / `arm64`），
每个平台一个归档，内含可执行文件、`config/re0auth.example.toml`、`LICENSE`、`NOTICE`，以及
`README.md` 与 `SECURITY.md`——**「未达生产可用」那条警告要跟着产物走**，而不是留在仓库里。
另有 `SHA256SUMS`，最后一步是 `gh release create`。

产物**不是开箱即用**：三把密钥与 issuer 必填（`RE0AUTH_KEK`、`RE0AUTH_OIDC_TOKEN_KEY`、
`RE0AUTH_OIDC_SIGNING_KEY`），缺一即拒绝启动——没有默认值是有意的，见上面的「快速开始」。
`re0auth -version` 打印构建版本（由 tag 注入），启动日志里也带同一个值。

`cmd/referencesource` **不在产物里**：它是验证 Upstream Kit 的演示数据源，vault 与会话都在内存、
登录是桩实现，发布它等于暗示可以拿它去部署。

## 许可与合规

本项目采用 **MPL-2.0**，全文见 [LICENSE](LICENSE)，第三方依赖见 [NOTICE](NOTICE)。

贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，安全漏洞请走 [SECURITY.md](SECURITY.md)

## 特别鸣谢

- **Yifan Shi, Wei Zhang, Tianyi Cui.** *A Programming Paradigm for Spatiotemporal Composability.*
  arXiv:2608.25512 
