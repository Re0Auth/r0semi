# 第五轮审计（上线前）—— 原始记录归档

本目录是第五轮对抗性审计的**原始材料**，结论性内容不在这里：

- 上线前问题清单（125 条待办的裁定表）：仓库根目录的 [`AUDIT-ISSUES.md`](../../AUDIT-ISSUES.md)
- 本轮汇总报告：[`docs/security-audit-5.md`](../security-audit-5.md)

本目录是那两份文档逐条引用到的**证据本体**：报告里写的「见 `<路径>`」，指的就是这里的文件。

## 目录

| 路径 | 内容 |
|---|---|
| `BRIEF.md` | 派给 12 个区域审计代理的共享简报（环境事实、证据标准、探针写法与禁令） |
| `round5-report.md` | 区域报告收齐后主代理写的汇总草稿，`security-audit-5.md` 的前身 |
| `findings/` | 12 份区域报告 + 12 份对抗性复核报告（`*-VERIFIED.md`）+ 3 份运行时碎片（`_` 前缀） |
| `probes/` | 探针的可执行部分：前端 bundle / scope / CSP 校验脚本（`.mjs`）、e2e 规格（`.spec.ts`）、打标签的 PowerShell 助手，以及两个只在审计机上用过的 Go 小工具 |

## 怎么复现

区域报告里标 `CONFIRMED` 的每一条，证据都是仓库内 `internal/zzprobe/` 下的一条测试：

```sh
go build ./... && go vet ./... && go test ./...        # 绿：探针被 audit5 标签排除
go test -tags audit5 -count=1 ./internal/zzprobe/...   # 红：这就是证据
```

默认构建不含探针（`internal/zzprobe/` 的测试文件都带 `//go:build audit5`），CI 与 `Makefile`
也不引用该标签；红灯只在显式带标签时出现，这是本项目的证据口径：一条发现必须有一条会失败的测试。

`probes/` 下的脚本与工具是审计当时的辅助手段，不进任何构建或测试路径。其中
`probes/e2e/` 的四份规格按 `web/e2e/` 的邻居关系写相对 import（`./fixtures`、`./helpers`），
归档位置下不能直接跑：要复现就先拷进 `web/e2e/`。

## 归档时做过的改动（如实记录）

1. **路径重写**：审计工作副本的 `scratchpad/audit/` → 本目录，审计机上的绝对路径前缀 → `.`。
   那条工作副本路径对任何其他人都打不开，重写后本目录内的互相引用在仓库里都能打开。
   正文（`AUDIT-ISSUES.md`、`security-audit-5.md`）与 18 个探针文件的头注释同步重写。
2. **两个 Go 工具加 `//go:build ignore`**：`probes/tools/genkey/main.go` 与
   `probes/tools/livecheck/main.go` 是被 `go run` 调用的独立工具（审计机上没有 openssl），
   加标签后不进入 `go build ./...` / `go vet ./...` / `golangci-lint ./...` 的包图。
3. **未入库**：`runtime/`（31 MB 的构建产物与运行时残留）与审计机的独立 module 文件。
   本目录不含任何凭据，也没有真实第三方地址——报告里的主机名都是 `example` 类占位。

> 本目录是**记录**，不是待办清单。这里的区域报告保留当时的严重度与判断，其中 30 余条已被
> 独立的对抗性复核推翻或降级。以 `AUDIT-ISSUES.md` 的裁定为准。
