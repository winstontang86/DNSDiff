# dnsdiff

## 背景
一个用于 DNS 服务升级或搬迁前的对比工具。假设原有的 DNS 服务器为 `origin`（线上/基准），新的服务器为 `test`（被测）。`test` 可以是同一个 DNS 服务器的新版本，也可以是待迁移的另一台服务器。稳妥起见，新旧版本对于同样的请求应当返回内容一致。

## 功能
1. 支持对 tcpdump 抓包得到的 pcap 文件进行 DNS 请求重放。重放时保持 DNS 请求的二进制内容不变，网络层的源 IP 会变更为工具运行机器的本机 IP。
2. 支持限速重放。
3. 能将实际返回内容与 pcap 中 `origin` 机器的返回内容进行对比；也支持抓包仅包含请求（需要工具同时向 `origin` 和 `test` 发起请求）。
4. 对比存在非预期差异的记录会分别保存到 `diffold-MMDDhhmmss.txt` 与 `diffnew-MMDDhhmmss.txt` 文件，便于 Beyond Compare 等工具对比查看。
5. 能输出统计信息：按 qtype 分类、按二级域名（zone）聚合；统计结果分别写入 `diffstat-MMDDhhmm.txt`（汇总）与 `diffstat-MMDDhhmm.csv`（详情，便于上传为在线表格）。
6. 具备**智能重试**、**交叉对比**、**Answer 合并对比**能力，能自动消化缓存/TTL 轮转等原因造成的瞬时差异。
7. 支持基于 YAML 的**正则白名单**，可忽略指定域名的特定差异类型。
8. 注意！在源机器抓包时，只抓往这台机器 53 端口的请求以及这台机器 53 端口出的响应，其他包请勿抓取，命令形如：
   ```
   tcpdump -iany -nn "(dst host 9.208.51.5 and dst port 53) or (src host 9.208.51.5 and src port 53)"
   ```

## 工具清单
本仓库提供四个工具：

| 工具 | 说明 |
| --- | --- |
| `dnsdiff` | DNS 请求重放 + 对比工具，支持智能重试、交叉对比、Answer 合并对比 |
| `dnscmp` | 对两份 rsp pcap 进行分析对比（不发网络请求） |
| `dnsreplay` | 指定速率进行 pcap 重放（不做对比） |
| `formcheck` | 对 pcap 文件中的 DNS 报文进行深度格式校验（RFC 合规性） |

### 编译
将代码 clone 到有 Go 环境的机器（Linux 需要 `sudo yum install -y libpcap-devel`），运行：

```bash
./build.sh
```

脚本会在 `bin/` 目录下生成四个可执行文件：`dnsdiff`、`dnscmp`、`dnsreplay`、`formcheck`。

## diffcode 说明

差异用 32 位位掩码 `diffCode` 表达，每一位代表一类差异。代码定义见 [internal/diff/diff.go](internal/diff/diff.go)。

```text
// 整体匹配
DIFF_BIT_NOMATCH        = 0x00000001  // 未匹配（单边 nil 等）
DIFF_BIT_NOMATCHKEY     = 0x00000002  // 未匹配主键
DIFF_BIT_NOMATCHDOMAIN  = 0x00000004  // 未匹配域名
// Header 段
DIFF_BIT_HEAD_RCODE     = 0x00000010  // Rcode 差异（不含 SERVFAIL）
DIFF_BIT_HEAD_OPCODE    = 0x00000020  // Opcode 差异
DIFF_BIT_HEAD_QFLAG     = 0x00000040  // QR/TC/RD/RA/Z 等标志差异
DIFF_BIT_HEAD_AA        = 0x00000080  // AA 标志差异（单独标记）
DIFF_BIT_HEAD_RCODE_SF  = 0x00000100  // 涉及 SERVFAIL 的 Rcode 差异（单独标记）
// Question 段
DIFF_BIT_QUEST_LEN      = 0x00001000
DIFF_BIT_QUEST_QNAME    = 0x00002000
DIFF_BIT_QUEST_QTYPE    = 0x00004000
DIFF_BIT_QUEST_QCLASS   = 0x00008000
// Answer 段
DIFF_BIT_ANSWER_01      = 0x00010000  // 一边为空、另一边非空
DIFF_BIT_ANSWER_LEN     = 0x00020000  // 条数不一致（不允许 partial 时）
DIFF_BIT_ANSWER_CNAME   = 0x00040000  // CNAME 链首尾不一致
DIFF_BIT_ANSWER_RRDIFF  = 0x00080000  // RR 内容差异
// Authority 段
DIFF_BIT_AUTH_LEN       = 0x00100000
DIFF_BIT_AUTH_RRDIFF    = 0x00200000
DIFF_BIT_AUTH_CNAME     = 0x00400000
// Additional 段（未开启 ignore-additional 时才比较）
DIFF_BIT_ADD_LEN        = 0x01000000
DIFF_BIT_ADD_RRDIFF     = 0x02000000
DIFF_BIT_ADD_CNAME      = 0x04000000
// Additional 段 OPT (EDNS) 选项级差异
DIFF_BIT_ADD_OPT_ECS    = 0x08000000  // ECS (EDNS Client Subnet) 选项差异
DIFF_BIT_ADD_OPT_COOKIE = 0x10000000  // DNS Cookie 选项差异
```

### 差异等级
每个差异码被归入一个等级，`DefaultMask` 为 `CRITICAL + WARNING + NOMATCH* 三类` 的合集：

| 等级 | 含义 | 典型差异码 |
| --- | --- | --- |
| `CRITICAL` | 关键差异，必须关注 | RCODE/OPCODE/QFLAG/QUEST_*、ANSWER_01、ANSWER_CNAME |
| `WARNING`  | 警告，多为可解释的偶发差异 | HEAD_AA、HEAD_RCODE_SF、ANSWER_RRDIFF、AUTH_RRDIFF、ADD_OPT_ECS/COOKIE |
| `NORMAL`   | 通常不阻塞迁移 | ANSWER_LEN、AUTH_LEN、ADD_RRDIFF、ADD_CNAME |
| `IGNORE`   | 默认忽略 | NOMATCH*、ADD_LEN |

程序通过 `-m/-mask` 指定"非预期差异掩码"，只有命中该掩码的差异才会进入差异文件与告警统计。不指定时使用 `DefaultMask`。

## dnsdiff
从 pcap 文件重放 DNS 请求，并将结果与 `origin`（pcap 内或指定的线上服务器）进行对比。具备智能重试机制。

### 重试与合并逻辑
1. **首次对比**：
   - `-query-only=false`（默认）：先尝试从 pcap 解析出的 `rspMap` 中定位 origin 响应；找不到时若提供了 `-o/-origin-ip`，则向线上服务器发起查询。
   - `-query-only=true`：pcap 仅含请求，必须指定 `-o/-origin-ip`，程序会同时向 `origin` 与 `test` 发送查询。
2. **重试对比**：首次对比存在非预期差异，且指定了 `-o/-origin-ip` 时，对 `origin` 与 `test` 各再发起 2 次请求进行对比。任意一次结果相等即判为相等（消化缓存未命中/命中、轮转 RR 等瞬态差异）。
3. **交叉对比**：重试两次仍不相等时，使用"第 1 次 origin vs 第 2 次 test"、"第 2 次 origin vs 第 1 次 test"两组交叉对比，任意一组相等也判为相等。
4. **Answer 合并对比**：若三次结果均为 `DIFF_BIT_ANSWER_RRDIFF`，把所有 origin 的 Answer 段合并、所有 test 的 Answer 段合并，再做一次 RR 集合比较；用于消化"同一域名的 RR 集合在小集合内轮转"的情形。
5. 以上步骤任一通过后 `diffCode` 被清零；全部未通过则采用最后一次对比结果，经白名单过滤后写入差异文件与统计。

### 命令行参数
`dnsdiff` 采用长短参数形式，两者等价：

```
必选:
  -i, -input <path>          pcap 抓包文件路径
  -t, -test-ip <ip>          被测服务器 IP
  -q, -qps <n>               每秒请求速率（最小 2，默认 100）

origin 相关:
  -o, -origin-ip <ip>        线上/基准服务器 IP
                             （-query-only 或 -retry 时必须提供）

对比选项:
  -m, -mask <hex>            非预期差异掩码（默认为 DefaultMask 的十六进制）
  -allow-partial             Answer 段 A/AAAA 允许部分匹配（默认 true）
  -ignore-additional         忽略 Additional 段（默认 true）
  -retry                     首次有差异时触发重试对比（默认 true）
  -query-only                pcap 仅包含请求，origin 也要走网络请求（默认 false）
  -w, -whitelist <path>      白名单 YAML 配置路径（可选，未指定时尝试加载 ./whitelist.yaml）

运行参数:
  -c, -concurrency <n>       消费者协程数（默认 1000）
  -l, -level <level>         日志级别：debug/info/warn/error（默认 info）
```

### 使用示例
```bash
# 基本用法：非 query-only，origin 从 pcap 中获取
./dnsdiff -i traffic.pcap -t 10.0.0.1 -q 5000

# 启用重试，origin 从线上服务器获取
./dnsdiff -i traffic.pcap -t 10.0.0.1 -o 10.0.0.2 -q 8000 -retry

# query-only：pcap 只有请求
./dnsdiff -i requests.pcap -t 10.0.0.1 -o 10.0.0.2 -q 3000 -query-only

# 使用白名单
./dnsdiff -i traffic.pcap -t 10.0.0.1 -o 10.0.0.2 -w whitelist.yaml
```

### 输出文件
- `diffold-MMDDhhmmss.txt`：有非预期差异的记录中 origin 端的响应。
- `diffnew-MMDDhhmmss.txt`：对应的 test 端响应。
- `diffstat-MMDDhhmm.txt`：汇总统计（每个 qtype × diffCode 的计数）。
- `diffstat-MMDDhhmm.csv`：差异详情表格，列：`DNS Type, Zone, Diff Code, Diff desc, Count`。
- `log/udns_dial.log`：运行日志（JSON 格式，可用 `jq` 解析）。

## dnscmp
对两份 rsp pcap（通常为在 origin/test 两侧同时抓包的结果）进行离线对比，不产生网络请求。对比产物与 `dnsdiff` 相同。

```
Usage of ./dnscmp:
  -t string   Test server pcap file (required)
  -o string   Online/origin server pcap file (required)
  -a int      忽略 Additional 段，1=是，0=否（默认 1）
  -p int      允许 Answer 部分匹配，1=是，0=否（默认 1）
  -m string   非预期差异掩码（十六进制，默认 DefaultMask）
  -l string   日志级别（默认 info）
```

> 说明：`dnscmp` 当前不从命令行加载白名单配置，如需要请使用 `dnsdiff`。

## dnsreplay
从 pcap 读取 DNS 请求，按指定 QPS 重放到目标服务器；不做对比。

```
Usage of ./dnsreplay:
  -f string   pcap 文件路径（必填）
  -d string   目标服务器 IP（必填）
  -r int      每秒请求速率（至少 10，默认 1）
  -c int      消费者协程数（默认 1000）
  -p string   强制重放协议：udp | tcp，空表示跟随原始抓包（默认空）
```

## formcheck
对 pcap 中的 DNS 报文做深度格式校验，支持请求/响应/关联校验，并可对响应进行主动重放后再校验。
校验结果写入 `checksummary_MMDD_HHMMSS.csv`。

```
Usage of ./formcheck:
  -f string   pcap 文件路径（必填）
  -d string   目标 IP 过滤（可选；若指定则会对响应做主动探测以进行关联校验）
  -c string   校验模式：req | rsp | all（默认 all）
  -proto      强制发送协议：udp | tcp | default（默认 default，跟随 pcap）
  -n int      worker 协程数（默认 1000）
  -qps int    主动探测时的 QPS 限速（0 表示不限速，默认 0）
  -warn       打印带有 warning 的报文（error 总会打印）
  -h          查看帮助
```

详细的错误码/警告码及 RFC 规则说明参见：
- [internal/validate/validate.md](internal/validate/validate.md)
- [internal/validate/DNS的rfc规则.md](internal/validate/DNS的rfc规则.md)

## 白名单（YAML + 正则）
`dnsdiff` 启动时会尝试加载工作目录下的 `whitelist.yaml`，也可以通过 `-w` 显式指定。示例见 [whitelist.yaml](whitelist.yaml)。

规则格式：
```yaml
whitelist:
  - diff_type: ANSWER_RR_DIFF       # 差异类型 tag，见下表
    patterns:
      - '(?i)\.db\.$'               # Go regexp 语法；支持大小写不敏感 (?i)
      - '(?i)cdn\.'
    description: "Ignore ANSWER_RR_DIFF for db/cdn domains"  # 可选
```

支持的 `diff_type` 标签（与 diffCode 的 `DiffCode2Str` 一致）：
`NOMATCH`、`NOMATCHKEY`、`NOMATCHDOMAIN`、`RCODE_DIFF`、`OPCODE_DIFF`、`QFLAG_DIFF`、`AA_FLAG_DIFF`、`RCODE_SERVFAIL_DIFF`、`QUEST_LEN_DIFF`、`QNAME_DIFF`、`QTYPE_DIFF`、`QCLASS_DIFF`、`ANSWER_01_DIFF`、`ANSWER_LEN_DIFF`、`ANSWER_CNAME_DIFF`、`ANSWER_RR_DIFF`、`AUTH_LEN_DIFF`、`AUTH_RR_DIFF`、`AUTH_CNAME_DIFF`、`ADD_LEN_DIFF`、`ADD_RR_DIFF`、`ADD_CNAME_DIFF`、`ADD_OPT_ECS_DIFF`、`ADD_OPT_COOKIE_DIFF`。

---

## 项目结构

```
dnsdiff/
├── cmd/                        # 可执行程序入口
│   ├── dnsdiff/                # DNS 请求重放 + 对比（含重试/合并/白名单）
│   │   ├── main.go
│   │   └── diff_logic.go       # 首次/重试/交叉/合并对比逻辑
│   ├── dnscmp/                 # 双 pcap 离线对比
│   │   └── main.go
│   ├── dnsreplay/              # DNS 重放
│   │   └── main.go
│   └── formcheck/              # DNS 报文格式校验
│       ├── main.go
│       ├── processor.go
│       ├── reporter.go
│       └── stats.go
├── internal/                   # 内部包（不对外暴露）
│   ├── app/                    # 配置、日志、白名单
│   │   ├── config.go
│   │   ├── logger.go
│   │   └── whitelist.go
│   ├── diff/                   # DNS 报文对比与差异码
│   │   ├── diff.go
│   │   └── diff_rr.go
│   ├── dnet/                   # DNS 网络请求（UDP/TCP）
│   │   └── dnet.go
│   ├── parser/                 # pcap 解析
│   │   └── parser.go
│   ├── saver/                  # 差异文件落盘
│   │   └── saver.go
│   ├── statistics/             # 统计/csv 输出
│   │   └── statistics.go
│   └── validate/               # DNS 报文 RFC 校验
│       ├── validate.go
│       ├── header.go
│       ├── question.go
│       ├── rr.go
│       ├── association.go
│       ├── errors.go
│       ├── result.go
│       ├── validate.md         # 校验器文档
│       └── DNS的rfc规则.md      # RFC 规则摘要
├── pkg/                        # 可对外引用的包
│   ├── DNS_msg.md              # DNS/EDNS/ECS 报文结构说明
│   ├── types/                  # 公共数据类型
│   │   ├── types.go
│   │   └── convert.go
│   └── utils/                  # 哈希、Key 生成、zone 提取等工具
│       └── utils.go
├── bin/                        # 编译产物
├── log/                        # 运行日志
├── build.sh                    # 构建脚本
├── whitelist.yaml              # 白名单示例
├── README.md                   # 本文件
├── QUICKSTART.md               # 快速上手
└── REFACTOR.md                 # 重构历史说明
```

### 依赖层次
```
cmd/  →  internal/*  →  pkg/*
```
`pkg/utils` 依赖 `pkg/types`；`pkg/types` 不反向依赖 `pkg/utils`，避免循环依赖。

### Import 路径规范
新代码统一使用以下路径：
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

### 测试
```bash
# 所有包
go test ./...

# 指定包 + 覆盖率
go test -cover ./internal/diff ./internal/validate

# 生成 HTML 覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 相关文档
- [QUICKSTART.md](QUICKSTART.md) — 快速上手
- [REFACTOR.md](REFACTOR.md) — 目录与包的重构说明
- [pkg/DNS_msg.md](pkg/DNS_msg.md) — DNS / EDNS(0) / ECS 报文结构详解
- [internal/validate/validate.md](internal/validate/validate.md) — formcheck / validate 包使用说明
- [internal/validate/DNS的rfc规则.md](internal/validate/DNS的rfc规则.md) — RFC 规则摘要