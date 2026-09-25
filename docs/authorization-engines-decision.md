# ADR-0010：两个授权服务器引擎并存——`oauth`（源侧）与 OP（Re0Auth 自己）

> 状态：**已接受（v1）**。本文回答一个反复被问到的审计问题：「仓库里有一套手写的授权服务器，
> 而实际挂载的是 `zitadel/oidc` 的 OP——它是不是迁移没做完留下的死代码？」
> 答案是不是。**它活着，只是朝着相反的方向。**
> 配套阅读：[oidc-decision.md](./oidc-decision.md)（ADR-0001，OP 的来源）、
> [architecture.md](./architecture.md) §4.4/§4.12、[upstream-protocol.md](./upstream-protocol.md)。

## 1. 决策

仓库里有两套授权服务器实现，它们**不是同一个东西的两个版本**：

| | 引擎 | 面对谁 | 由谁装配 | 承载的契约 |
|---|---|---|---|---|
| **源侧** | `oauth`（手写，公开库） | 数据源要"对外暴露一个 OAuth 2.0 AS 面" | Upstream Kit 的 `Hooks.OAuth`，数据源自己装配 | [upstream-protocol.md](./upstream-protocol.md) 的授权面 |
| **自侧** | `internal/oidchttp` + `internal/oidcstore` + 一个 store 适配器（`zitadel/oidc`） | 下游 RP（玩家侧一次 OIDC 接入） | `cmd/re0auth` 组合根 | OIDC / OAuth 2.1 的完整面 |

`cmd/re0auth` **不装配** `oauth` 的授权服务器，只使用这个公开库里与引擎无关的部分：客户端模型、
客户端注册表、scope 目录，以及 `oauth.TokenAdmins`（清理**迁移前那个把 `oauth` 当自己 OP 的部署**
留下的表）。**这不等于该引擎已退役**——它作为 Kit 的源侧引擎仍然在服役，见 §2。

## 2. 背景（实证）

- **它在生产路径上活着**：`referencesource/source.go` 构造
  `oauth.NewService(clients, tokens, deps.Logger, oauth.Config{...})`，并把它作为
  `upstreamkit.Hooks{OAuth: as}` 交给 Kit；`cmd/referencesource` 是一个能真跑的进程，
  它的 `/oauth/*` 由这套引擎提供。Kit 的一致性测试（`upstreamkit/conformance`）也压在这条路上。
- **它恰好不在 `cmd/re0auth` 的装配里**：组合根只用
  `oauth.TokenAdmins{oidcStore}`、`oauth.NewMemoryClientRegistry()`、`oauth.NewClient(...)`。
  当年那个部署用它当 OP，迁移到 OIDC 后（ADR-0001）留下的是**表**（迁移 `0001` 的那几张），
  由 `TokenAdmins` 与 `LegacyPurger` 在抹除时清理——**留的是数据，不是引擎**。
- `internal/wiring/oauth.go` 也构造它，但 `internal/wiring` 不参与生产装配（ADR-0002），
  所以那不构成"生产接线"。

## 3. 为什么保留两个（而不是合并成一个）

- **方向相反，合规重量也不同。** 下游那侧要深：discovery 两份文档、JWKS 与轮换、PKCE 强制、
  设备流与轮询节流、内省白名单、令牌响应契约——这是最难的面，用成熟库（ADR-0001 已裁定）。
  源侧要薄：一个数据源需要的是"能发带 scope 的 token 给一个 OAuth 客户端"，把 OP 的依赖树
  塞给每个数据源，正好违背"适配成本接近零"这个 Kit 存在的理由。
- **装配成本就是设计目标。** `oauth` 是公开库（`internal/archtest` 强制它不 import `internal/`，
  也不依赖框架），数据源装几个钩子即可；换成 OP 级别的依赖，接入方要先接受一套它不需要的运行时。
- **两套并存不是"两面墙各砌一半"**：机制可以共享（客户端模型、scope 目录、store 端口都在
  `oauth` 里，OP 也用它们），策略与合规面各自裁定。

## 4. 代价与残余

- **公共库的缺陷是对外真缺陷。** 第三轮审计里那条「`oauth` 遗留引擎的设备决策是丢失更新」
  就是活例：从 `cmd/re0auth` 装配不可达，但对装着 Kit 的数据源可达。**不能因为"我们自己不用"
  而降低它的守卫标准**——这正是本文存在的原因：它容易被误判成死代码，而误判会带来错误的取舍。
- **命名会误导。** "`oauth`" 现在不等于"Re0Auth 的授权服务器"（那是 OP）。文档与注释提到它时，
  要写清是哪一侧；`upstreamkit` 里指向它的注释应同时指向本文。
- **条目级差异要有据可查**：两套引擎在设备流的客户端认证语义、刷新轮换、内省范围上不必逐条一致
  （它们服务不同的规范面），但**凡是写成"契约"的性质，两边各自都要有守卫**。

## 5. 重新评估的触发条件

- Kit 的源侧面需要 OIDC（discovery/JWKS/`id_token`）或客户端认证的完整形态——那已经超出"薄"的定义；
- 数据源反馈"装 Kit 比接一个现成库更重"，即 §3 的成本论证不再成立；
- `oauth` 的维护成本（含上面那条"对外真缺陷"的修复力度）超过"基于 `zitadel/oidc` 写一层薄封装"。

触发前，本决策不变：**两侧各一个引擎，源侧手写、自侧用库**。
