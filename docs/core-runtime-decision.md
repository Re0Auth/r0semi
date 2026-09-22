# ADR-0002：组件运行时（`core` / `wiring`）暂不进入生产组合根

> 状态：**已接受（v1）**。本文与 [architecture.md](./architecture.md) §3/§8 配套，
> 机器闸门见 `internal/archtest`。重新评估的触发条件写在 §5，未触发前不改变本决策。

## 1. 决策

`internal/core`（组件运行时）与 `internal/wiring`（能力键与 `core.Component` 装配）
在 v1 保持为**实验性库**：它们有实现、有测试，但**生产组合根 `cmd/re0auth` 不经过它们**，
而是继续用普通的构造函数装配（`oauth.NewService(...)`、`httpapi.New(...)`）。

因此，能力封闭（I1）与依赖驱动 fail-closed（I5）是**库层属性**，不是 v1 生产部署的门禁。
对外文档不得暗示相反结论（[architecture.md](./architecture.md) §3 的"生产接入状态"注记即本文的执行）。

## 2. 背景（实证）

- `internal/wiring` 只实现了 8 个组件里的 1 个（`OAuthComponent`）。
- 非测试代码里没有任何 `app.Use(...)` 调用者；`KeyClients` / `KeyTokens` / `KeyLog`
  **没有任何提供者**——组件图从未被真实配置装配过。
- `cmd/re0auth/main.go` 直接依次构造服务；组装逻辑集中在组合根（符合"组合根唯一认识所有人"）。
- [architecture.md](./architecture.md) §3 已如实写明这一点，本文只是把它固定为决策而非待办。

### 2.1 同一篇论文，两种裁剪

`core` 与姊妹项目 r0semi-mp（Rust）引用的是同一篇论文，但做了**方向相反**的裁剪：

| 论文机制 | 本项目的落地 | r0semi-mp 的落地 |
|---|---|---|
| 空间可组合性（provide/consume 契约） | **运行时采纳**：`Key` / `Provides` / `Inject` + `reconcile` 激活 | **编译期采纳**：trait 契约 + 组合根 + 依赖方向矩阵 |
| 时间可组合性（运行时逆操作追踪） | **运行时采纳**：`Context.Effect` + LIFO 栈 | **不做**：Rust RAII + 重启即换 |
| 反应式 coeffect 通知 | **采纳**：依赖变化驱动 activate/deactivate | **改造**：只用事件总线，且只用于事件不用于命令 |
| HMR / 动态加载 / 形式化 calculus | 拒绝 | 拒绝 |

差异的根因是**语言能力，不是品味**：

- **时间**：Rust 有 `Drop`，temporal composability 近乎白送；Go 没有 RAII，`defer` 只到函数作用域。
  本项目用运行时 effect 栈补这个缺口，在 Go 里比照抄 Rust 更可辩护。
- **空间**：Rust 有 sealed trait / 单态化 / crate 私有，编译期即可封闭；Go 只有包级 `internal/`
  与结构化接口，没有类型级封闭。所以本项目用运行时 key 申报补。

因此"r0semi-mp 更实用"不等于"本项目该照搬"——**Go 确实缺这两个机制**。但反过来，
"本项目采纳了运行时机制"也不等于"运行时机制必须在生产里启用"；那是下一节的问题。

## 3. 为什么

1. **抽象时机（抽象等第二个实现出现时）**：组件图是为 8 个组件设计的预测性抽象，
   而实际只有一个节点。现在把它接进生产，是"为一个还不存在的第二组合预付成本"。
2. **不要在未验证的假设上盖房子**：`Provides`/`Inject` 模型假定生产里每个部件都能表达成
   "声明依赖 → 激活"。但 `httpapi.Config` 有 21 个字段、大量模式相关（OIDC vs 内建、admin /
   federation / frontend 开关），而 `core.Inject` **没有可选依赖**。这个缺口只有在真正装配全图时
   才会暴露——图没跑过，就不该据此改生产。先跑图、再决策，与"先让前提可证伪"一致。
3. **防火墙先行，接口可以等**：真正必须"第一天就有"的是依赖方向，而不是 DI 容器。
   `internal/archtest` 现在用 `go list` 强制：公开库不得依赖 `internal/`、数据库适配器只许
   组合根导入、`core` 不依赖任何内部包。这是便宜的、防未来的那一道；能力封闭作为生产门禁可以等。
4. **诚实优于虚假保证**：若把未强制的 `core` 说成"生产里 I1 成立"，就是拿一个没人守着的断言当事实——
   这正是本项目在别处（`dependencies.md` §4）反复警惕的"元数据不能撒谎"。
5. **I1 只覆盖依赖图，不等于沙箱**：`core` 的能力封闭只约束**对能力存储的访问**。第一方组件照样能
   import 任何包、开 goroutine、读文件、调上游——它不是通用隔离。而恶意第三方威胁**已被"进程外"
   排除**（[architecture.md](./architecture.md) §2 明确拒绝进程内第三方，论文 §6.3 亦自陈语言级
   confinement 对恶意代码无效）。于是 `core` 剩下的价值是**第一方的依赖图纪律 + I2 的 effect 化零化**，
   而不是安全边界。跨包那层"谁 import 谁"的真正约束，现由 `internal/archtest` 用机器守着——
   那正是"便宜、且必须第一天就有"的那道。两者互补，不互相替代。

## 4. 后果

- 生产组合根没有能力封闭（I1 不由机器在运行时强制）；这被明确接受，而非隐去。
- `core` / `wiring` 的测试继续作为其自身正确性的证据，但**不构成生产保证**。
- 新增领域服务继续走"接口包定义端口 + 组合根装配"，不会为了迎合 `core` 而改变端口形状。

## 5. 重新评估的触发条件

出现以下任一条时，重开本决策：

1. **第二个组合出现**：第二份二进制 / 部署形态复用同一套组件图（那时才有"第二实现"可抽象）。
2. **安全需求要求生产级能力封闭**：某条威胁模型要求 I1 在部署中由机器强制，而非库层自证。
3. **引擎接缝增加**：授权引擎从两个变成三个及以上，接缝数量让手工装配开始出错。

## 6. 若将来采纳：先跑图，再切生产

不要直接改 `cmd/re0auth`。先在 e2e 里把完整领域图**平行装配一遍**（不改变生产路径），
用真实配置形态暴露 §3.2 的两类问题——可选/模式相关的组合，以及内建 `oauth.Service` 与
OpenID Provider `http.Handler` 的**两种类型**如何落到同一个能力键。图跑通、问题收敛后，
再以一个独立提交把组合根切过去。

## 7. 对后续业务开发的直接含义

本节是"照着做就不会撞墙"的部分：

1. **不要为了用 `core` 而改端口形状。** 新业务继续按既有模式落地：在领域包里定义**端口**（`interface`），
   在 `internal/store/postgres` 里实现，在 `cmd/re0auth` 组合根装配。能力键与 `core.Component`
   只存在于 `internal/wiring`，且 v1 不承载生产装配。
2. **新业务服务不需要是 `core.Component`。** 它是普通结构体 + 构造函数，返回窄接口；HTTP 层在
   `internal/httpapi` 里按已有形态挂路由。这既是现状，也是 ADR-0002 下的预期状态。
3. **新增公开库前先想一遍边界。** 要放进公开层的内容必须能脱离 `internal/` 独立编译；若做不到，
   它属于 `internal/`。边界不是自觉，见下条。
4. **依赖方向由机器守。** `internal/archtest` 在 `go test ./...` 与 `make check` 里强制：
   公开库不得依赖 `internal/`；`internal/store/postgres` 只许 `cmd/*` 导入；`internal/core` 不依赖
   任何内部包。**新增顶层包必须在这里登记**（`publicLibraries`），否则 CI 直接红——这是"先更新表
   再合并"的机器化，不是可选项。
5. **`Context.Effect` / `defer` 用于 I2。** 明文零化的正确姿势仍由 `vault.Use` 的回调作用域承担；
   无论将来是否启用 `core`，都不要把明文带出 acquire 作用域。

## 8. 参考

- 论文：Yifan Shi, Wei Zhang, Tianyi Cui. *A Programming Paradigm for Spatiotemporal Composability*（Cordis）。
  见 [architecture.md](./architecture.md) §9。
- [architecture.md](./architecture.md) §2（采纳/裁剪表）、§3（核心抽象与生产接入状态）、§4（包分层）、
  §5（安全不变量）、§8（已决/待决）
- [dependencies.md](./dependencies.md) §4（元数据不能撒谎、假时钟、重试等反面教训）
- `internal/archtest`（本文的机器闸门）
