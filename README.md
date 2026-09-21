# r0semi / Re0Auth

音游数据的**授权与互通层**：一套协议 + 一个参考实现。

玩家一次授权、下游一次接入，即可跨游戏、跨数据源读取数据；游戏后端通过实现 [上游协议](docs/upstream-protocol.md) 接入生态。

> [!WARNING]
> **本项目位于迭代期，部分组件（凭据、会话）仍为内存态，未达到生产可用，请勿用真实凭据部署。**

## 快速开始

需要 Go 1.27+（见 `go.mod`）。

```sh
go build ./cmd/re0auth

RE0AUTH_ISSUER=https://re0auth.example \
RE0AUTH_KEK=$(head -c 32 /dev/urandom | base64) \
DATABASE_URL='postgres://user:pass@localhost:5432/re0auth?sslmode=disable' \
./re0auth
```

参考数据源（独立进程，用来验证 Upstream Kit）：

```sh
go build ./cmd/referencesource
GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... ./referencesource   # 或 TAPTAP_CLIENT_ID=...
```

## 验证

```sh
gofmt -l .
go vet ./...
go test ./...
```

```sh
docker run -d --rm -e POSTGRES_PASSWORD=x -p 5432:5432 postgres:16
TEST_DATABASE_URL='postgres://postgres:x@localhost:5432/postgres?sslmode=disable' \
  go test ./internal/store/postgres/
```

## 许可与合规

本项目采用 **MPL-2.0**，全文见 [LICENSE](LICENSE)，第三方依赖见 [NOTICE](NOTICE)。

贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，安全漏洞请走 [SECURITY.md](SECURITY.md)

## 特别鸣谢

- **Yifan Shi, Wei Zhang, Tianyi Cui.** *A Programming Paradigm for Spatiotemporal Composability.*
  arXiv:2608.25512 
