# r0semi / Re0Auth

音游数据的**授权与互通层**：一套协议 + 一个参考实现。

玩家一次授权、下游一次接入，即可跨游戏、跨数据源读取数据；游戏后端通过实现 [上游协议](docs/upstream-protocol.md) 接入生态。

> [!WARNING]
> **本项目位于迭代期，未达到生产可用，请勿用真实凭据部署。**
> 后端持久化已收尾：**9 个存储端口全部可落 Postgres，审计日志也落 Postgres**（不设 `DATABASE_URL` 则退回内存，启动时会逐条警告）。
> 前端已可用：**同意页**、**设备流验证页**、**授权管理页**与**数据源连接页**（连接 / 断开 / 请求登出全部设备）。
> 三条用户旅程都有界面，威胁模型里的三层撤销都有实现。

## 快速开始

需要 Go 1.27+（见 `go.mod`）。

```sh
cp config/re0auth.example.toml config/re0auth.toml   # 按需修改

# 密钥不写进配置文件：文件里只写变量名（*_env）
export RE0AUTH_KEK=$(head -c 32 /dev/urandom | base64)
export DATABASE_URL='postgres://user:pass@localhost:5432/re0auth?sslmode=disable'

go build ./cmd/re0auth
./re0auth -config config/re0auth.toml
```

不写配置文件、只靠环境变量也能起（会打警告），最小可用：

```sh
RE0AUTH_ISSUER=https://re0auth.example \
RE0AUTH_KEK=$(head -c 32 /dev/urandom | base64) \
./re0auth
```

完整键位、默认值与每段说明见 [`config/re0auth.example.toml`](config/re0auth.example.toml)；
配置优先级为 **环境变量 > 文件 > 默认值**，校验 fail-closed（缺密钥 / 缺 issuer / KEK 长度不对都拒绝启动）。

日志走标准库 `log/slog`，两个旋钮都在环境里（它们描述的是进程**跑在哪**，不是它**是什么**）：

```sh
RE0AUTH_LOG_LEVEL=debug    # debug | info | warn | error，默认 info
RE0AUTH_LOG_FORMAT=json    # text | json，默认 text
```

两个值都在启动时校验，写错直接拒绝启动而不是静默回退。参照数据源同理，前缀是 `REFERENCE_SOURCE_`。

> 运行日志与**审计记录**是两回事，刻意分开：审计是领域记录、有完整性要求，走 `audit.Logger`；
> 日志是给运维看的诊断。合并会导致审计记录跟着运维调的日志级别一起变。

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

轮换**只重新封装每条记录的 DEK**——不解密、不重写载荷，所以便宜，也可以重复运行
（再跑一次会报告"没有需要处理的"）。`kek_id` 必须跟着密钥材料一起改：用同一个 id 配新密钥会让所有凭据变得不可读，
而轮换会**拒绝执行并指出这一点**，不是静默跳过。

**它不能撤销泄露。** 如果旧 KEK 和一份数据库副本一起泄露，那些凭据已经失守，只能在数据源侧重新登记。
轮换做到的是：**让这次泄露不再适用于之后写入的任何东西**。这一条与其边界写在
[threat-model §6.0](docs/threat-model.md) 里。

参考数据源（独立进程，用来验证 Upstream Kit）：

```sh
cp config/referencesource.example.toml config/referencesource.toml
export TAPTAP_LEANCLOUD_APP_KEY=...   # 或 GOOGLE_CLIENT_SECRET=...

go build ./cmd/referencesource
./referencesource -config config/referencesource.toml
```

## 接口契约

- **业务面 `/v1`**：[`docs/openapi.yaml`](docs/openapi.yaml)（OpenAPI 3.1）。`go test` 会断言它与实际路由**双向一致**：文档里写了而路由没挂的端点、路由挂了而文档没写的端点，都会让构建失败。
- **协议面 `/oauth`**：按 RFC 6749 / 7009 / 7662 / 8414 / 8628 / 9728，从 `/.well-known/oauth-authorization-server` 发现。这里**不重述**——多一份副本就多一处会漂移的地方。

## 前端

前端是 SvelteKit 构建出的静态 SPA，`go:embed` 进同一个二进制，挂在 `/app/*`。

```sh
make web     # npm ci + vite build，产物直接写进 internal/webui/dist
make build
```

关键一点：**`go build ./cmd/re0auth` 不需要 Node。** 未构建前端时，`internal/webui` 嵌入的是一份占位文件，
服务器在 `/app` 返回一个说明页而不是白屏；`make web` 把占位换成真正的应用。
CI 会先构建前端并断言 `internal/webui/dist/index.html` 存在——否则测试会在占位上跑绿，而那正是最坏的假阳性。

前端**不渲染任何服务端数据**：它带着浏览器自己的会话 cookie 去调 `/v1`，同意页显示的每个字都来自那一次响应。
它不签发令牌、不拼跳转 URL、不持有授权状态。

## 验证

```sh
gofmt -l .
go vet ./...
go test ./...
```

前端：

```sh
cd web && npm ci && npm run check
```

浏览器端到端（自己构建并启动 re0auth，加一个假身份提供方，无需先跑任何东西）：

```sh
make e2e      # 或 cd web && npx playwright install chromium && npx playwright test
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
