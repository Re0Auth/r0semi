# ADR-0004：浏览器句柄的所有权——同意句柄不得被另一个账号批准

> 状态：**已接受**。落地：`internal/auth/auth.go`（`Bind` / `OwnerMatches` / `Unbind`）、
> `internal/httpapi/authorization_routes.go`（`consentHandle`）、
> `internal/httpapi/device_routes.go`，
> 测试见 `internal/httpapi/consent_owner_test.go`。

## 1. 背景

同意流程把「用户正在批准哪个请求」放在**服务端句柄**里：`/oauth/authorize` 由 OP 创建一个 auth
request，登录钩子把它绑到浏览器会话（`sessions.Bind(ctx, "authz", id)`），前端随后用
`GET /v1/authorization_requests/{id}` 读取、用 `POST …/decision` 决定。

问题是这个绑定是**会话**属性，不是**账号**属性，而：

- `SignIn` 会 `RenewToken`，而 scs 的 `RenewToken` **保留会话的所有值**——这是**故意的**：同意流程
  在用户登录**之前**就创建了句柄，它必须活过这次登录，否则正常流程会变成 404。
- `mode=login` 也**没有**「必须已登出」的检查（只有 `mode=="link"` 要求已登录）。

于是：账号 A 在某个浏览器里发起授权 → **同一个浏览器** B 登录（A 没有登出）→ 句柄仍然绑在这个会话上
→ B 可以读取并批准它，`sub = B`。**下游拿到的是 B 的令牌，而请求是 A 发起的。**

严重度低（需要同一浏览器 + 不登出就换账号），但它是一个真实的授权归属错误：用户批准的东西与实际
被授权的人不是同一个。

## 2. 决策

**一、句柄在创建时记下它是为谁创建的。**

记录点放在 `auth.Manager.Bind` 本身，而不是各个调用方：

```go
func (m *Manager) Bind(ctx context.Context, kind, id string) {
	m.sessions.Put(ctx, handleKey(kind, id), "1")
	if user, ok := m.User(ctx); ok {
		m.sessions.Put(ctx, ownerKey(kind, id), string(user))  // 仅当已登录
	}
}
```

放在 `Bind` 里而不是组合根，是因为**任何**调用方（`cmd` 的登录钩子、`/bind`、设备验证页、以及测试夹具）
都自动获得它——接线漏一处就是漏洞。`Unbind` 同时清除两个键。

**二、使用时做一次强一致校验，不符即 404。**

```go
func (m *Manager) OwnerMatches(ctx, kind, id, user) bool {
	owner := m.sessions.GetString(ctx, ownerKey(kind, id))
	return owner == "" || owner == string(user)
}
```

- **空 owner ⇒ 允许**：句柄是在没人登录时创建的（最常见的形状——用户在同意页上才被送去登录）。
  此时**没有账号可绑**，"谁先登录谁拥有"就是流程本身。这不是缺口，是设计。
- **不一致 ⇒ 拒绝，而且是 404 不是 403**：一个返回 403 的句柄等于确认"它存在，只是不归你"。
  读与决策走**同一个** `consentHandle` 助手，返回**同一个** 404 文案，两种失败无法区分。

**三、设备流一并收口。** 设备的 `user_code` 绑定形状相同（验证页需要登录，所以会记录 owner），
`handleDeviceDecision` 因此加同一个校验——否则 `Bind` 记下的 owner 在设备流里是死数据。语义一致：
「这个 code 是在**另一个账号**手里载入的」不能批准。

## 3. 为什么不选另外两条路

- **在 `SignIn` 里清掉全部 `handle_*`**：会打破匿名→登录的同意流程。那个流程**依赖**句柄活过登录。
  要修就得改 OP 的 auth request 生命周期或让前端重建请求——代价远大于收益。
- **把绑定挪到 decision POST**：会丢掉「用户批准的那个 code/handle 是这个浏览器**显示过**的」这条保证。
  这是设计取舍，不是加固步骤。

## 4. 后果

- 关掉「A 的请求被 B 批准」，且与同一仓库里**上游绑定流已有的先例**一致
  （`federation.CompleteBind` 比较 `flow.User != user`）。
- **不覆盖**经典 OAuth 同意钓鱼：攻击者构造一个 `/oauth/authorize` URL 让受害者访问并批准。那条路
  与句柄所有权无关（句柄全程属于受害者自己的会话），缓解手段是同意页显示客户端名与 scope——已经存在。
- 匿名创建的句柄仍然「谁先登录谁拥有」。这是刻意的，也是上一条的同一个理由。
- 会话里多一个键（`owner_<kind>_<id>`），随 `Unbind` 一起消失。

## 5. 测试

`internal/httpapi/consent_owner_test.go`，两个方向：

- `TestConsentApprovedByTheAccountThatStartedIt` —— 正常流必须继续工作（否则"修"成了锁死）。
- `TestConsentHandleCannotBeUsedByAnotherAccount` —— A 创建 → B 在同一浏览器登录 → A 的句柄读与决策
  都是 404；同时断言 **B 能在自己的句柄上成功**，证明这是所有权校验而不是一刀切拒绝。

夹具侧：假 IdP 的身份现在由授权码决定（`code=c` 保持原样的 42，其余派生成不同账号），
`signInAs` 因此能在同一个浏览器里放进两个账号。既有调用方不受影响。

## 6. 受影响文档

- [api-design.md](./api-design.md) §4：`/v1/authorization_requests/{id}` 与 `/decision` 的「句柄绑定」
  描述现在也包含账号归属
- [account-model.md](./account-model.md) §5–§7：会话与同意交互
- [browser-plane-decision.md](./browser-plane-decision.md)（ADR-0003）：同一批发现的另一半
