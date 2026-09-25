# 管理面：应用注册 / 审核 / 吊销 / Kill Switch（v1）

> 状态：已实现（v1）。实现必须以此为准；偏离需先改本文件。
> 相关：[architecture.md](./architecture.md) §4（组件）、[api-design.md](./api-design.md) §4、[threat-model.md](./threat-model.md) D5。
> 机器可读契约在 [openapi.yaml](./openapi.yaml) 的 `admin` 标签下，由 `internal/httpapi/openapi_test.go` 与实际路由双向断言。

## 0. 一个决定：管理员是"配置出来的账号"，不是"注册出来的角色"

Re0Auth 不自建账号体系（[account-model.md](./account-model.md) §0）：登录只回答"屏幕前的人是谁"。
管理面因此**不引入角色表**，也**不允许任何账号通过某种操作把自己抬成管理员**。

管理员 = 其 `usr_…` 出现在部署的**允许列表**里的账号：

```toml
[admin]
subjects = ["usr_01J...", "usr_01K..."]
```

或环境变量 `RE0AUTH_ADMIN_SUBJECTS`（逗号分隔，优先于文件）。

- **纯授权，不涉及认证**：认证仍走 `/auth` 的会话（会话 + CSRF，与 `/v1` 其它写操作一致）。
- **写操作要求“最近登录”**：还有一个 step-up 窗口 `[admin].reauth_window` / `RE0AUTH_ADMIN_REAUTH_WINDOW`
  （默认 `15m`，`0` 关闭）。窗口过期后，suspend/delete/Kill Switch 等写操作返回
  `403 reauth_required`，管理员需重新登录；读操作不受影响。理由：没有第二因素可提示，
  “最近认证过”是能对被盗或长期闲置的管理会话施加的最强约束。
- **默认关闭**：允许列表为空时，`/v1/admin/*` **根本不挂载**。一个挂载了却谁都不许进的管理面，是一把没有锁的门。
- **对非管理员它不存在**：已登录但不在列表里的账号，访问 `/v1/admin/*` 得到 `404 not_found`，与访问一个不存在的路径毫无区别。管理面不向用不上它的人做广告。

**为什么不做角色/权限系统**：现在只有一种管理动作，多个角色只会是"一个角色"。等真的出现"只读审计员 / 只能吊销不能注册"这类需求时再加，且那时也应当是允许列表里的一个字段，而不是一张能被提权的表。

## 1. 面

全部在 `/v1` 下（业务平面：JSON + problem+json），全部**会话 + 非安全方法要求 CSRF**。

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/v1/admin/clients` | 全部客户端（含 `suspended`），供审核/inventory |
| `POST` | `/v1/admin/clients` | 注册一个客户端；机密客户端的 secret **只在此处返回一次** |
| `POST` | `/v1/admin/clients/{client_id}/suspend` | 暂停客户端并**吊销其全部令牌** |
| `POST` | `/v1/admin/clients/{client_id}/activate` | 恢复（**不**恢复已吊销的令牌） |
| `DELETE` | `/v1/admin/clients/{client_id}` | 删除注册并吊销其全部令牌；幂等 |
| `POST` | `/v1/admin/kill_switch` | 按 `all` / `client` / `subject` / `bindings` 批量吊销令牌与绑定（`all` 与 `subject` 另清会话，需持久会话） |

实现：`internal/admin`（逻辑 + 审计）与 `internal/httpapi/admin_routes.go`（传输）。
两个端口极窄——`Clients`（注册表）与 `Revoker`（令牌批量删除）——所以同一套逻辑既跑 Postgres，也跑内存存储。

## 2. 客户端生命周期

`active` ⇄ `suspended`（`oauth.ClientStatus`，落库在 `oauth_clients.status`）。

**`suspended` 不是"被拒绝"，是"不存在"**。注册表的 `Get` 对暂停客户端返回 `ErrClientNotFound`，于是它在**每一个协议入口**（authorize / token / introspect / discovery 的注册表查询）的表现，和一个从未注册过的 `client_id` 完全一样。这样运维的决定无法被外部区分于"这个 id 本来就没有"。

`GET /v1/admin/clients` 是唯一能看到它的地方——审核视图里它必须还在，否则"我暂停了谁"就没人答得上来。

停用先于吊销：`SuspendClient` 先写状态、再删令牌。于是即使删令牌失败，客户端也**无法再签发新令牌**——失败方向是安全的。

## 3. 注册：只有管理员能建，secret 只出现一次

`POST /v1/admin/clients` 直接以 `active` 建立。**没有自助注册，也没有"待审核"队列。**
理由：RFC 7591 动态客户端注册本就不在 v1（[oidc-decision.md](./oidc-decision.md) O-9），而一条由陌生人提交、由人审批的申请，会引入垃圾提交面和一条 secret 的安全投递链（批了之后 secret 怎么还给申请人？），收益与复杂度不成比例。等真有官方开发者门户时再单独立项。

- 机密客户端：服务端生成 secret，**只在 `201` 响应里返回一次**；库里只存 `sha256`，之后任何读取（包括管理员）都拿不回来。丢了就重新注册。
- 公开客户端：无 secret，响应里没有该字段。

## 4. 吊销：粒度与边界

### 4.1 单客户端
`suspend` / `DELETE` 都是"停用/删除注册 + 删该客户端的全部令牌"。
`DELETE` 两半都会执行，不因注册本就不存在而跳过删令牌——**重试要能真的把活着的访问切断**，所以幂等。

### 4.2 Kill Switch（`POST /v1/admin/kill_switch`）

恰好一个 target：

| target | 令牌 | 会话 | 客户端 | 数据源绑定 |
|---|---|---|---|---|
| `all` | 全部 access + refresh | **全部浏览器会话**（有持久会话时） | 不动 | **全部** |
| `client` | 该客户端全部 | 不动 | **暂停** | 不动（绑定属于人，不属于客户端） |
| `subject` | 该账号全部 | **该账号的全部** | 不动 | **该账号的全部** |
| `bindings` | 不动 | 不动 | 不动 | **全部**（窄形态：只断数据、不掉登录） |

**绑定半边（D5 的另一半，已实现）**：对每条绑定 **本地一定切断**（先撕碎 vault 密文、再删绑定行），并尽源所能通知上游：

- 若源声明了级联撤销（`cascade_revocation`），先尝试它——那会结束整个上游会话（所有设备登出）；级联 fail-closed，失败则回落到普通解绑。
- 否则普通解绑：调源的 revocation endpoint（`token_class: long_lived` 的源报告为 `unsupported`，不假装成功）。
- 源已不在配置里的**孤儿绑定**：没有源可通知，但仍会被本地清除，计为 `orphaned`。
- 一个源失败**不会**中止其它绑定；每条绑定的结局计入 `bindings` 对象（`total`/`revoked`/`cascade`/`unsupported`/`unavailable`/`orphaned`/`failed`）。

**它仍做不到什么，必须说清楚：**

- **不直接操作任何上游凭据**——原始平台凭据（如 TapTap stoken）在**数据源**手里，Re0Auth 从不持有；
  它自己 vault 里那份是**源签发的令牌**，Kill Switch 只用它去**请求源**动手（两层凭据的区分见
  [api-design.md](./api-design.md) §5）。源不能撤销、或不可达，会如实出现在 `bindings.unsupported` / `bindings.unavailable`，而不是被折叠成成功。
- **`subject` 清会话依赖会话索引**（`session_subjects`）：登录时把会话令牌记到账号名下，注销时移除、过期由 sweep 清理。
  索引行**写在 scs commit 会话行之前**（两者在同一个请求里，但顺序相反），所以 sweep 只清理**超过宽限期**
  仍没有会话行的孤儿。没有这条宽限，sweep 会把「正在登录」的会话当孤儿删掉——之后没有任何路径会重写它，
  于是这次 `subject` Kill Switch 会**漏掉这条活会话**，而 `sessions_revoked` 看着完整。
  **没有持久会话的部署（内存模式）一条会话都清不掉**——scs 会话只是一个不透明 Cookie，`memstore` 既没有 subject 概念也没有枚举 API，`all` 都没有可以遍历的东西可删；该模式下会话本来也不持久，重启进程才是重置手段。
  有持久会话的部署，`subject` 会让该账号在所有浏览器掉登录，`all` 清全部。

  理由：scs 会话只是一个不透明 Cookie，存储层只看到编码后的字节，没有任何“这个会话属于谁”的概念。索引因此由 Re0Auth 自己在登录时写；写失败则拒绝该会话（fail-closed），否则就会出现一个运维永远碰不到的会话。

响应返回**真实数字**（`tokens_revoked` / `sessions_revoked` / `clients_suspended` / `bindings`），因为事故响应者要的是数字，不是一句“已处理”。

## 5. 审计

每个管理动作写一条 `audit.Event`：`Action`（如 `admin.client.suspend`）、`Subject`（被操作的客户端/账号）、`Provider = "admin"`、`Outcome`，`Detail["actor"]` 是**发起操作的管理员 `usr_`**。

审计失败**不回滚**已发生的安全动作（停用/删除），而是打 `slog.Error`。理由：动作已经发生，拒绝承认它只会让运维**既没有动作也没有记录**。日志那行才是告警。

### 5.1 读取审计日志（`GET /v1/admin/audit`、`GET /v1/admin/audit/verify`）

审计日志的**读**侧。和上面的管理端点一样是**管理员专属**：日志描述的是**每一个账号**，
所以一个已登录但不在允许列表里的账号拿到的是 **404**，与不存在的路径无差别——日志不向读不了它的人广告自己。

- **按插入顺序（`id`）倒序，不按事件自带的 `time`**。时间戳由发包组件提供，时钟漂移——或者能让某个组件回填时间的人——
  否则就能重排历史。`time` 仍然返回，只是**排序不由它决定**。
- **`?subject=` 收的是账号 id（`usr_…`），不是日志里存的假名**。翻译由服务端做（见 architecture.md §4.17）。
  账号被抹除后密钥已销毁，该过滤条件解析为空 → **返回空页**，这是正确答案而不是缺陷。
- **分页**：`?limit=` / `?cursor=`，`id` 的**排他上界**，所以逐页走不会重复也不会漏。
  最后一页**不带** `next_cursor`——调用方以此判断停止；给一个陈旧的游标会让它循环。
- **`verify` 把「链断了」当作 `200` + `ok:false` 返回，而不是 5xx**：对一个「日志被动过吗」的问题，
  「被动过」是一次成功的回答；用 5xx 回答只会把发现埋进传输故障里。`legacy` 报告链建立之前的行数——
  报告而不是跳过，否则会**夸大检查的覆盖面**。
- **它不覆盖什么**：从**尾部**删行。没有外部锚点时那是不可见的，这个端点不假装能看见（§4.16）。
- 读路径**不会**创建假名密钥：查询一个从未出现过的账号是**无副作用**的，否则「有没有发生过事」这个只读问题会写入状态。

## 6. v1 明确不做 / 后续

- **自助注册 + 待审核队列**：见 §3，延后。
- **管理前端已实现**：`/app/admin`（不在玩家导航里链接，非管理员访问得到普通错误页）。
  支持客户端注册（一次性密钥）、暂停/恢复/删除、Kill Switch 与审计查看；`reauth_required`
  会显示“重新登录”入口。审计浏览器化仍可后接。
- **角色/权限细分**：见 §0，等有真实需求再加，且不得引入可提权的表。
