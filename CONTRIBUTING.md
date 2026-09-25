# 贡献指南

感谢为本项目贡献代码！

## 先读这个

- [`SECURITY.md`](SECURITY.md) —— **漏洞不要开公开 issue**，走私下披露。同时它列了已记录的限制（哪些还不持久、哪些是演示桩），可省下无谓的沟通。
- [`docs/architecture.md`](docs/architecture.md) —— 组件模型与不变量。项目把**不变量当产品**，破坏不变量的改动需要先改文档。
- [`docs/positioning.md`](docs/positioning.md) —— 定位与非目标。**明确提出不做什么**，请先确认你的改动在范围内。

## 开发环境

要求 Go 版本见 `go.mod`。提交前请本地通过：

```sh
gofmt -l .        # 必须为空
go vet ./...
go test ./...
golangci-lint run --timeout=5m ./...
```

静态检查器要装成 CI 固定的那个版本——版本不对齐的 linter 会在他人的发布节奏上把绿变红，
而 `.golangci.yml` 里每条规则的理由都以那个版本为准：

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
```

`make check` 把上面这些串成一个入口（外加 `internal/archtest` 的依赖防火墙与前端
`svelte-check`）。**linter 是硬要求**：没装就拒绝运行并打印上面那条安装命令，与 `sbom`
对 SBOM 生成器的做法一致——本地绿必须等于 CI 绿，跳过 linter 的绿是假的。

单元测试使用内存实现，**任何平台都能跑，不需要数据库**。

### Postgres 集成测试（可选，但改动存储层时必跑）

`internal/store/postgres` 的测试由 `TEST_DATABASE_URL` 门控，未设置时自动 skip：

```sh
docker run -d --rm -e POSTGRES_PASSWORD=x -p 5432:5432 postgres:16
TEST_DATABASE_URL='postgres://postgres:x@localhost:5432/postgres?sslmode=disable' \
  go test ./internal/store/postgres/
```

CI 在 Linux 上带 Postgres 服务跑全量（含集成测试）。**"我机器上能跑"不是证据**——尤其是 SQL。

### 项目约定（不是风格偏好，是设计）

- **字段、参数、JSON key 一律 `snake_case`**。
- **协议平面**（`/oauth/`、`/.well-known/`）返回 `application/x-www-form-urlencoded` 的输入与 `{error, error_description}`；
  **业务平面**（`/v1/`）返回 JSON 与 RFC 9457 `problem+json`。**两者绝不混用**，各面有独立子 mux / 错误写出器 / panic 恢复；`/auth`、`/bind`、`/app` 等浏览器面是纯文本或重定向。
- **令牌明文绝不落盘**：存储只存 `sha256(value)`。
- **凭据绝不返回给下游**：没有例外。上游凭据在数据源手里，Re0Auth 本地保存的是源签发的令牌，账号导出、grant/binding 视图与 `raw` 都不包含任何凭据。
- **元数据不能撒谎**：`/.well-known/*` 里广告的能力必须真的实现。曾出现过广告了 DPoP 却不校验的情况，现已用测试锁死。

## 分层与依赖方向（机器强制，不是自觉）

代码落在哪一层由依赖方向决定，边界由 `internal/archtest` 在 `go test ./...` / `make check` 里强制：

- **公开库**（`audit`、`httpclient`、`idp`、`oauth`、`upstreamkit`(+`conformance`)、`vault`、`tapsign`、`taptapoauth`、`referencesource`）：
  可被**进程外的独立服务**导入。它们（含传递依赖）**不得** import `internal/`。
- **内部实现**（`internal/...`）：只在本模块内使用。
- **组合根**（`cmd/*`）：唯一允许认识所有人的地方，也是唯一允许导入 `internal/store/postgres` 的地方。
- **`internal/core`**：依赖图的底，不得依赖任何内部包；v1 **不承载生产装配**——见
  [`docs/core-runtime-decision.md`](docs/core-runtime-decision.md)（ADR-0002）。

新增业务模块的落点（照做即可）：

1. 领域逻辑与**端口**（`interface`）放 `internal/<domain>/`；
2. 存储实现在 `internal/store/postgres/`，实现该端口；
3. HTTP 路由挂 `internal/httpapi/`，把新依赖塞进 `Config`；
4. 在 `cmd/re0auth` 组合根装配——**普通构造函数，不需要是 `core.Component`**。

新增**顶层包**时，必须同步登记到 `internal/archtest/deps_test.go` 的 `publicLibraries`，否则 CI 直接失败
（"先更新表再合并"）。

## 提交

- 一个 PR 做一件事。重构和功能分开。
- 新增行为要有测试；修 bug 要先有能复现它的测试。
- 改了契约（协议、API、组件能力）请同步文档；文档是契约的一部分。

## 第三方代码

- 不要提交你无权提交的代码（包括从别处复制、或来源不明的 vendored 代码）。
- 引入新依赖请在 PR 描述里说明理由，并更新 [`NOTICE`](NOTICE)。

## 许可与换牌约定

感谢为本项目贡献代码！通过提交任何形式的贡献（Pull Request、补丁、文档、测试用例等），您同意以下约定：

1. 您的贡献将按项目**现行许可**（当前为 MPL-2.0，见 [LICENSE](LICENSE)）发布；您保留对贡献的版权，归属记录将保留在提交记录中。
2. 您授予本项目及其维护者对您贡献的**全球的、永久的、不可撤销的、免版税的**使用、修改、复制、许可与再许可权利。
3. 您授予本项目、其维护者及所有使用者对您贡献的**全球的、永久的、不可撤销的、非排他的、免版税的专利许可**，允许制造、委托制造、使用、许诺销售、销售、进口及以其他方式转移您的贡献（单独使用或与本项目结合时必然涉及的由您拥有或受控的专利权利要求）。若您或您的关联方就本项目对本项目、其维护者或任何使用者提起专利侵权诉讼，则本项目及维护者依本约定授予您的所有许可，自该诉讼提起之日起立即终止。
4. 您同意：维护者有权在**提前公告**（不少于 30 天，公告于仓库 README 与 GitHub Discussions）后，将整个代码库（含您的既有贡献）变更许可至以下清单内的任一许可：
   **AGPL-3.0-or-later、GPL-3.0-or-later、MPL-2.0、Apache-2.0、MIT**（均为 OSI 认可的开源许可）。
   在此前提下，维护者无需单独征询贡献者同意，亦无需支付任何补偿；清单外的许可按第 6 条扩展流程增补。
5. 您保证您有权作出上述授权（如您受雇于他人，请先获得雇主同意）。
6. 上述清单可由维护者扩展，扩展须经同款公告（不少于 30 天）。
7. 本约定不接受任何反要约，并在此明确拒绝所有此类要约。