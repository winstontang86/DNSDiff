# 项目重构说明

> 本文档记录项目从扁平目录到标准 Go 项目布局的重构经过，并说明当前的目录/包规划。随着代码演进（新增 `formcheck`、`validate`、白名单、重试等能力），文档已同步最新状态；`comm/` 兼容层在稳定后已移除，现仓库中 **不再保留兼容层**。

## 重构目标

按标准 Go 项目布局重新组织代码，提升可维护性、可测试性与可扩展性：
- `cmd/` 只放可执行入口；
- `internal/` 放业务逻辑、仅供本仓库使用；
- `pkg/` 放可被外部引用的基础库；
- 各包命名使用完整英文单词（`parser`、`saver`、`statistics`），避免歧义；
- 依赖方向单向：`cmd → internal → pkg`。

## 当前目录结构

```
dnsdiff/
├── cmd/                        # 可执行程序入口
│   ├── dnsdiff/
│   │   ├── main.go             # 参数解析 / 生产者 / 消费者 / 保存协程编排
│   │   └── diff_logic.go       # 首次/重试/交叉/Answer 合并对比逻辑
│   ├── dnscmp/
│   │   └── main.go             # 双 pcap 离线对比
│   ├── dnsreplay/
│   │   └── main.go             # DNS 重放
│   └── formcheck/              # DNS 报文格式校验
│       ├── main.go
│       ├── processor.go
│       ├── reporter.go
│       └── stats.go
├── internal/                   # 内部包（不对外暴露）
│   ├── app/                    # 应用层：配置、日志、白名单
│   │   ├── config.go
│   │   ├── logger.go
│   │   └── whitelist.go
│   ├── diff/                   # DNS 报文对比与差异码定义
│   │   ├── diff.go
│   │   └── diff_rr.go
│   ├── dnet/                   # DNS 网络请求（UDP/TCP）
│   │   └── dnet.go
│   ├── parser/                 # pcap 解析
│   │   └── parser.go
│   ├── saver/                  # 差异结果落盘
│   │   └── saver.go
│   ├── statistics/             # 统计汇总 / CSV 输出
│   │   └── statistics.go
│   └── validate/               # DNS 报文 RFC 校验
│       ├── validate.go
│       ├── header.go
│       ├── question.go
│       ├── rr.go
│       ├── association.go
│       ├── errors.go
│       ├── result.go
│       ├── validate.md
│       └── DNS的rfc规则.md
├── pkg/                        # 可对外引用的包
│   ├── DNS_msg.md              # DNS / EDNS(0) / ECS 报文结构详解
│   ├── types/                  # 数据类型与转换
│   │   ├── types.go
│   │   └── convert.go
│   └── utils/                  # 哈希、Key 生成、zone 提取等工具
│       └── utils.go
├── bin/                        # 编译产物
├── log/                        # 运行日志
├── go.mod / go.sum
├── build.sh                    # 构建脚本
├── whitelist.yaml              # 白名单示例（YAML + 正则）
├── README.md
├── QUICKSTART.md
└── REFACTOR.md                 # 本文件
```

## 包重命名历史

| 旧位置 | 新位置 | 说明 |
|--------|--------|------|
| `diff/` | `internal/diff/` | 对比逻辑移入 internal |
| `dnet/` | `internal/dnet/` | 网络请求移入 internal |
| `parse/` | `internal/parser/` | 重命名为完整英文单词 |
| `save/` | `internal/saver/` | 重命名为完整英文单词 |
| `stat/` | `internal/statistics/` | 重命名为完整英文单词 |
| `comm/` (部分) | `pkg/types/` | 数据类型独立 |
| `comm/` (部分) | `pkg/utils/` | 工具函数独立 |
| `dnsdiff/main.go` | `cmd/dnsdiff/main.go` | main 移入 cmd |
| `dnscmp/main.go` | `cmd/dnscmp/main.go` | main 移入 cmd |
| `dnsreplay/main.go` | `cmd/dnsreplay/main.go` | main 移入 cmd |
| *新增* | `cmd/formcheck/` | 新增 DNS 报文格式校验工具 |
| *新增* | `internal/validate/` | 新增 RFC 报文校验库 |
| *新增* | `internal/app/whitelist.go` | 新增 YAML + 正则白名单 |
| *新增* | `cmd/dnsdiff/diff_logic.go` | 独立出首次/重试/交叉/合并对比逻辑 |

## 新增 / 增强模块

### `internal/app`
- `config.go` — 命令行掩码等配置解析，如 `ParseHexMask`。
- `logger.go` — 统一日志初始化（logrus + lumberjack），供各工具共用。
- `whitelist.go` — `WhitelistManager`：YAML 解析 + 正则预编译 + `IsWhitelisted(diffType, domain)`。

### `internal/diff`
- 引入差异等级（`CRITICAL / WARNING / NORMAL / IGNORE`）并按等级聚合形成 `DefaultMask`。
- 细分差异位：新增 `DIFF_BIT_HEAD_AA`、`DIFF_BIT_HEAD_RCODE_SF`、`DIFF_BIT_ANSWER_01`、`DIFF_BIT_ANSWER_CNAME`、`DIFF_BIT_AUTH_CNAME`、`DIFF_BIT_ADD_CNAME`、`DIFF_BIT_ADD_OPT_ECS`、`DIFF_BIT_ADD_OPT_COOKIE`。
- `Comparator` 新增 `WhitelistChecker` 接口字段与 `ApplyWhitelist` 方法。
- `DiffCode2Str` 输出 tag 与白名单规则 `diff_type` 一一对应。

### `internal/validate`
- 完整 RFC 校验库，支持请求/响应格式校验与关联校验；错误位/警告位各占 `uint64`。
- 为 `cmd/formcheck` 提供底层能力。

### `cmd/dnsdiff/diff_logic.go`
封装四阶段对比：
1. `firstCmp` — rspMap 查找 + 可选的线上网络请求；
2. `retryCmp` — origin/test 各重试 2 次；
3. `crossCmp` — 交叉对比；
4. `handleMergedAnswerCmp` — 三次均为 `ANSWER_RR_DIFF` 时的 Answer 合并对比。

### `cmd/formcheck`
新增工具：
- `processor.go`：pcap 扫描与多 worker 并发校验；支持主动探测（`-d`）。
- `reporter.go`：异常报文输出。
- `stats.go`：错误/警告位汇总与 `checksummary_MMDD_HHMMSS.csv` 输出。

## Import 路径规范

```go
import (
    "dnsdiff/internal/app"
    "dnsdiff/internal/diff"
    "dnsdiff/internal/dnet"
    "dnsdiff/internal/parser"
    "dnsdiff/internal/saver"
    "dnsdiff/internal/statistics"
    "dnsdiff/internal/validate"
    "dnsdiff/pkg/types"
    "dnsdiff/pkg/utils"
)
```

- 不再使用 `dnsdiff/comm`（兼容层已移除）。
- Go 标准库存在 `go/parser`，引用内部解析器时必须带完整路径 `dnsdiff/internal/parser` 以避免冲突。

## 构建脚本

`build.sh` 会编译四个工具到 `bin/`：
```bash
#!/bin/bash
echo "start build"
go build -o bin/dnsdiff   ./cmd/dnsdiff
go build -o bin/dnsreplay ./cmd/dnsreplay
go build -o bin/dnscmp    ./cmd/dnscmp
go build -o bin/formcheck ./cmd/formcheck
echo "build end"
```

## 依赖关系

```
cmd/
  ├─> internal/app
  ├─> internal/diff
  ├─> internal/dnet
  ├─> internal/parser
  ├─> internal/saver
  ├─> internal/statistics
  ├─> internal/validate   (formcheck)
  ├─> pkg/types
  └─> pkg/utils

internal/parser
  ├─> internal/statistics
  ├─> pkg/types
  └─> pkg/utils

internal/dnet    -> pkg/types
internal/saver   -> pkg/types
internal/statistics -> internal/diff, pkg/utils
internal/validate -> pkg/types
pkg/utils        -> pkg/types
```

- 无循环依赖；
- `pkg/types` 不依赖 `pkg/utils`；
- `internal/*` 不对外暴露。

## 设计原则

1. **高内聚低耦合**：每个包职责单一，入口（`cmd/`）尽量薄。
2. **分层清晰**：`cmd → internal → pkg`，方向单一。
3. **标准布局**：遵循 Go 社区项目布局规范。
4. **可测试**：每个包旁边放置 `_test.go`，`go test ./...` 即可全量运行。

## 改动简记

- 目录重命名与内部/公共包划分；
- 新增 `cmd/formcheck` 与 `internal/validate`；
- 新增 `internal/app/whitelist.go` 与 `whitelist.yaml` 示例；
- 将 `dnsdiff` 主逻辑（重试、交叉、合并）从 `main.go` 拆到 `cmd/dnsdiff/diff_logic.go`；
- `dnsdiff` 命令行由短参数升级为 **长短参数并存**，并带友好的 `-h` 中文帮助；
- 统计输出增加 CSV 文件，列为 `DNS Type, Zone, Diff Code, Diff desc, Count`；
- 移除 `comm/` 兼容层。

## 后续建议

- 继续提升关键路径的单元测试覆盖率；
- 增加性能基准测试（pcap 数万条样本的端到端耗时）；
- 为 `dnscmp` 也接入白名单；
- 考虑将 `DefaultMask` 做成分等级的 cli 开关（如 `-level=critical|warning|all`）。
