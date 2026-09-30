# Generates docs/security-audit-9.md from the round-9 raw+verify JSON.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

$verify = @{}
foreach ($f in Get-ChildItem _audit\round9\verify\S*.json) {
  try { $j = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
  foreach ($v in $j.verified) { $verify[$v.id] = $v }
}

$all = @()
foreach ($f in Get-ChildItem _audit\round9\raw\S*.json | Sort-Object Name) {
  $j = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
  foreach ($x in $j.findings) {
    $v = $verify[$x.id]
    $sev = if ($v -and $v.final_severity) { $v.final_severity } else { $x.severity }
    $status = if ($v) { $v.status } else { 'unverified' }
    $all += [pscustomobject]@{
      Id=$x.id; Scope=$j.scope; Sev=$sev; Status=$status; Orig=$x.severity; Cat=$x.category
      Conf=$x.confidence; Title=$x.title; Loc=($x.locations -join '; ')
      Evidence=$x.evidence; Why=$x.why; Exploit=$x.exploit; Rec=$x.recommendation
      VerifyReason=if ($v) { $v.reason } else { '' }
    }
  }
}

function Esc([string]$s) {
  if ($null -eq $s) { return '' }
  return ($s -replace '\|','\|' -replace "`r?`n",' ')
}
function Rank([string]$s) { switch ($s) { 'critical' {0} 'high' {1} 'medium' {2} 'low' {3} 'info' {4} 'informational' {5} default {6} } }

$high   = $all | Where-Object { $_.Sev -in 'critical','high' } | Sort-Object { Rank $_.Sev }, Id
$medium = $all | Where-Object { $_.Sev -eq 'medium' } | Sort-Object Id
$low    = $all | Where-Object { $_.Sev -eq 'low' } | Sort-Object Id
$info   = $all | Where-Object { $_.Sev -in 'info','informational','none' } | Sort-Object Id

$sb = [System.Text.StringBuilder]::new()

# ---------------- preamble ----------------
[void]$sb.AppendLine(@'
# 第九轮安全与性能审计报告（上线前 · 独立轮次）

> 本报告是第 9 轮上线前独立审计。**刻意不依赖前几轮的审计结论**：审计员只读当前生产代码，
> 禁止引用 `AUDIT-ISSUES.md`、`docs/security-audit-*.md`、`internal/zzprobe/**`、`_audit/**`、`audit/**`。
> 完整原始数据在 `_audit/round9/`（`raw/` 发现、`verify/` 对抗性验证、`matrix9.csv` 汇总）。

## 0. 执行摘要

| 指标 | 值 |
|---|---|
| 目标 | `C:\git\r0semi` — Re0Auth，Go 1.27 OIDC/OAuth2 身份与授权层 |
| 代码规模 | 655 个 Go 文件 / 约 138,113 行（另有 SvelteKit 前端） |
| 审计环境 | Windows 11 + PowerShell 7；**无 Docker、无本地 PostgreSQL** |
| 方法 | 15 个分域发现子代理 → 15 个对抗性验证子代理（共 30 个）；每条发现必须给出 `file:line` 证据 |
| 原始发现 | 157 条 |
| 验证后 | **0 critical · 8 high · 30 medium · 95 low · 22 info** |
| 基线门禁 | `go build` / `go vet` / `go test ./...` / `go test -race` / `gofmt -l` / `govulncheck` / `gitleaks` **全部通过** |

**一句话结论：**这份代码的工程化程度和纵深防御明显高于同类项目（中间件顺序、平面隔离、
密钥处理、审计链、限流与预算设计都经过反复打磨），但仍有 **8 条 High** 足以在上线前阻断，
其中 5 条集中在“降级路径/边界路径没有走主路径的约束”这一共同模式上。

### 上线阻断（建议先修）

| 编号 | 严重度 | 一句话 |
|---|---|---|
| S02-1 | High | `prompt=login` / `max_age` 不会真正重新认证，OP 把“同意点击时刻”伪造成新的 `auth_time` 并签名 |
| S08-2 | High | `storage.dsn_env` 指向非 `DATABASE_URL` 时，driver 推断为 postgres 但不解析 DSN，静默退回内存存储（跳过审计密钥、持久化、防篡改链） |
| S10-1 | High | 并发上限的“单客户端半量”按 `(平面,客户端)` 计数，一个地址可用两个平面吃满整个进程级信号量 |
| S13-1 | High | 压缩协商的 406 分支在限流器与并发上限**之前**返回，完全绕过两道反滥用边界 |
| S13-5 | High | 内存 OP 存储的所有 map 无上限；refresh 轮换每次留下一个存活 30 天的 tombstone，5 分钟清扫全表且持全局锁 |
| S03-1 | High | `return_to` 无长度上限且被整段写进服务端 session；匿名请求即可把内存/`sessions.data` 撑爆 |
| S06-1 | High | OIDC discovery / JWKS 由 go-oidc 用无上限 `io.ReadAll` 读取（自带 1 MiB 上限不覆盖此路径），可被配置的 IdP 用 gzip 炸弹打爆 |
| S14-2 | High | `federation.CompleteBind` 未取 per-binding 锁，可在一键 Kill Switch / Unbind / 账号擦除之后复活绑定与上游凭据 |

### 其它值得注意的 Medium（部分）

- **S06-2**：设置了 `HTTP(S)_PROXY` 时，SSRF 的私网拦截作用在代理地址而非目标地址上——守卫失效。
- **S05-1**：刷新时把上游任何 400/401/403 都判定为“授权已死”并**加密销毁**绑定（含可能只是可重试的配置错误）。
- **S09-1**：`-migrate-down` 路径的 DSN 解析错误可能把带密码的连接串写进日志。
- **S09-2**：`Tokens.RevokeTokens` 文档声称在事务里，实际不在，批量 Kill Switch / 擦除可能半执行。
- **S14-5**：refresh family 撤销与轮换非原子，重放竞争可能留下新世代 token。
- **S07-1**：凭据型出站请求依赖注入的 `Doer` 的跳转策略；`net/http` 会把自定义认证头复制到跨主机跳转目标。
- **S08-4 / S11-6 / S12-1 / S15-1 / S15-3**：擦除成功口径不实、审计校验持有连接 45s 无并发约束、前端 `fetch` 超时在读取 body 前被解除、备份加密失败会留下明文 dump、备份 CronJob 无 `activeDeadlineSeconds`。

### 基线自动化门禁（本轮实跑）

| 门禁 | 命令 | 结果 |
|---|---|---|
| 构建 | `go build ./...` | 通过 |
| 静态检查 | `go vet ./...` | 通过 |
| 单元/集成测试 | `go test ./...`（无 Postgres，跳过 DB 集成） | 全部 ok |
| 数据竞争 | `go test -race`（oauth、vault、ratelimit、memory、compress、federation、oidchttp、oidcstore、httpapi、auth、observability、admin、lifecycle、account、webui） | 全部 ok |
| 格式 | `gofmt -l .` | 无输出 |
| 依赖漏洞 | `govulncheck ./...` | `No vulnerabilities found` |
| 密钥泄露 | `gitleaks detect`（310 commits / 14.33 MB） | `no leaks found` |

**未能执行的部分：**无 Docker、无本地 PostgreSQL，因此容器镜像构建/Trivy 扫描、K8s 清单实际
apply、以及所有 `TEST_DATABASE_URL` 集成测试无法在本机运行；相关结论均为代码级静态分析与
既有单元测试推断（报告中已逐条标注）。

'@)

# ---------------- High ----------------
[void]$sb.AppendLine("## 1. 高危发现（High，共 $($high.Count) 条）`n")
$i = 0
foreach ($x in $high) {
  $i++
  [void]$sb.AppendLine("### H$i. $($x.Id) — $($x.Title)`n")
  [void]$sb.AppendLine("- **严重度 / 类别：** $($x.Sev) / $($x.Cat)；原判 $($x.Orig)，验证结论 **$($x.Status)**")
  [void]$sb.AppendLine("- **位置：** ``$($x.Loc)``")
  $fence = '```'
  [void]$sb.AppendLine("- **证据：**`n`n$fence go`n$($x.Evidence)`n$fence`n")
  [void]$sb.AppendLine("- **成因与影响：** $($x.Why)`n")
  [void]$sb.AppendLine("- **触发/利用：** $($x.Exploit)`n")
  [void]$sb.AppendLine("- **修复建议：** $($x.Rec)`n")
  if ($x.VerifyReason) { [void]$sb.AppendLine("- **验证备注：** $((Esc $x.VerifyReason))`n") }
}

# ---------------- Medium ----------------
[void]$sb.AppendLine("## 2. 中危发现（Medium，共 $($medium.Count) 条）`n")
[void]$sb.AppendLine('| ID | 类别 | 标题 | 位置 | 简述 |')
[void]$sb.AppendLine('|---|---|---|---|---|')
foreach ($x in $medium) {
  $w = Esc $x.Why; if ($w.Length -gt 260) { $w = $w.Substring(0,260) + '…' }
  [void]$sb.AppendLine("| $($x.Id) | $($x.Cat) | $(Esc $x.Title) | ``$(Esc $x.Loc)`` | $w |")
}
[void]$sb.AppendLine()

# ---------------- Low ----------------
[void]$sb.AppendLine("## 3. 低危发现（Low，共 $($low.Count) 条）`n")
[void]$sb.AppendLine('| ID | 类别 | 标题 | 位置 |')
[void]$sb.AppendLine('|---|---|---|---|')
foreach ($x in $low) {
  [void]$sb.AppendLine("| $($x.Id) | $($x.Cat) | $(Esc $x.Title) | ``$(Esc $x.Loc)`` |")
}
[void]$sb.AppendLine()

# ---------------- Info ----------------
[void]$sb.AppendLine("## 4. 信息级（Info，共 $($info.Count) 条）`n")
[void]$sb.AppendLine('| ID | 类别 | 标题 | 位置 |')
[void]$sb.AppendLine('|---|---|---|---|')
foreach ($x in $info) {
  [void]$sb.AppendLine("| $($x.Id) | $($x.Cat) | $(Esc $x.Title) | ``$(Esc $x.Loc)`` |")
}
[void]$sb.AppendLine()

[void]$sb.AppendLine(@'
## 5. 去重与关联（同一根因的多条编号）

对抗性验证按“根本原因”去重后，以下编号指向同一处代码：

| 根因 | 相关编号 | 建议合并后的严重度 |
|---|---|---|
| `federation.CompleteBind` 未取 per-binding 锁 | S14-2（high）、S05-2（medium） | High |
| 设备授权被批准后可无限次兑换 | S01-1（medium）、S04-1（medium） | Medium（仅在自定义嵌入 / 上游套件路径可达；随包 OP 不受影响） |
| 内存 `MemoryDeviceStore` 无删除/无清扫 | S01-2、S04-3、S14-8 | Medium |
| 内存 OIDC 存储在全局锁下全表扫描 | S13-2、S13-3、S14-6、S14-7、S14-1 | Medium/High |
| readiness 探针 panic 后卡死 503 | S10-2（medium）、S14-9（low） | Medium |
| `Registry.Register` 无同步写 map | S04-8、S14-10 | Low |
| Kill Switch 无法清掉在途 bind flow / 客户端行缺失时提前返回 | S11-3、S11-5 | Low |
| `oauth.MemoryStore` 无上限无清扫 | S01-2、S13-10 | Low（仅内存模式/自定义嵌入） |

## 6. 方法论与可达性说明（重要）

- **严重度是“可达性加权”后的结果。** 发现阶段给出的 14 条 high 中，有 6 条在验证阶段被降级，
  因为它们的利用面在生产二进制中并不挂载或需要非默认配置：
  - `oauth` 包那套手写 AS 的 device / token 端点**没有被 `cmd/re0auth` 挂载**；
    生产的设备流走 zitadel OP + `internal/oidchttp` 的组合（S01-1 / S04-1 因此降为 medium）。
  - `internal/store/memory` 只在没有 `DATABASE_URL` 的部署形态下使用；这类部署本身即
    “重启即失”的定位，但仍是 ADR-0001 认可的部署模式，故内存增长类问题保留 medium/high 分级。
  - 涉及 `referencesource`（演示数据源，明确不发布）的性能/DoS 条目（S06-4、S06-5）按
    “第三方复制该套件时才会命中”计入 medium。
- **无 Docker / 无 Postgres 的边界：** 所有 SQL、迁移、审计链、备份脚本、K8s 清单、
  Dockerfile、CI 相关结论均为静态审读；凡依赖数据库运行时行为的结论，验证代理已明确标注
  “read, not executed”。若要补齐，建议在一台带 Postgres 的机器上跑
  `TEST_DATABASE_URL=... go test ./internal/store/postgres/` 并实际构建镜像过 Trivy。

## 7. 上线前建议处置顺序

1. **P0（阻断）**：S02-1、S08-2、S10-1、S13-1、S14-2、S06-1。
2. **P0/P1（取决于部署形态）**：S03-1、S13-5 —— 若上线用内存模式，这两条同样是阻断级；
   若用 Postgres，S13-5 转移到数据库行增长与清扫成本，S03-1 转移到 `sessions.data` 增长。
3. **P1**：S05-1、S06-2、S08-1、S09-1、S09-2、S14-5、S07-1、S07-2、S10-2、S11-6、S12-1、S15-1、S15-3。
4. **P2**：其余 medium（尤其是“口径不诚实/可观测性缺失”类：S08-4、S11-4、S09-7）。
5. **P3（上线后清理）**：95 条 low，多数是边界正确性、指标基数、内存布局与文档契约漂移。

## 8. 原始数据索引

| 路径 | 内容 |
|---|---|
| `_audit/round9/raw/S01..S15.json` | 15 个分域的原始发现（含证据、利用、修复建议） |
| `_audit/round9/verify/S01..S15.json` | 逐条对抗性验证结论（confirmed / downgraded / rejected + 理由） |
| `_audit/round9/matrix9.csv` | 157 条的最终严重度矩阵 |
| `_audit/round9/summary9.txt` | 纯文本摘要 |
| `_audit/round9/README.md` | 本轮范围与独立性约定 |

*报告由 Lead 汇总：8 条 High 均由 Lead 亲自到源码逐条复核并确认。*
'@)

$out = Join-Path $PWD 'docs\security-audit-9.md'
[System.IO.File]::WriteAllText($out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "wrote $out ($($sb.Length) chars)"
Write-Host "high=$($high.Count) medium=$($medium.Count) low=$($low.Count) info=$($info.Count)"
