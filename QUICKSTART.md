# 快速开始指南

本指南面向第一次使用本项目的读者，内容与当前代码同步。详细背景、差异码、白名单等请参考 [README.md](README.md)。

## 目录结构概览

```
dnsdiff/
├── cmd/                    # 可执行程序入口
│   ├── dnsdiff/           # DNS 重放 + 对比（支持重试）
│   ├── dnscmp/            # 双 pcap 对比
│   ├── dnsreplay/         # DNS 请求重放
│   └── formcheck/         # DNS 报文格式校验
├── internal/              # 内部包
│   ├── app/              # 配置 / 日志 / 白名单
│   ├── diff/             # 对比逻辑与差异码
│   ├── dnet/             # 网络请求
│   ├── parser/           # pcap 解析
│   ├── saver/            # 差异结果保存
│   ├── statistics/       # 统计汇总 / CSV 输出
│   └── validate/         # RFC 校验
├── pkg/                  # 可对外引用的包
│   ├── types/           # 数据类型
│   └── utils/           # 工具函数
├── bin/                  # 编译产物
└── log/                  # 运行日志
```

## 编译项目

### 方式 1：使用构建脚本（推荐）

```bash
./build.sh
```

会在 `bin/` 目录下生成四个可执行文件：
- `bin/dnsdiff`
- `bin/dnscmp`
- `bin/dnsreplay`
- `bin/formcheck`

### 方式 2：手动编译

```bash
mkdir -p bin
go build -o bin/dnsdiff   ./cmd/dnsdiff
go build -o bin/dnscmp    ./cmd/dnscmp
go build -o bin/dnsreplay ./cmd/dnsreplay
go build -o bin/formcheck ./cmd/formcheck
```

### 方式 3：直接 `go run`

```bash
go run ./cmd/dnsdiff   -h
go run ./cmd/dnscmp    -h
go run ./cmd/dnsreplay -h
go run ./cmd/formcheck -h
```

> Linux 需预装 libpcap：`sudo yum install -y libpcap-devel`。

## 使用示例

### 1. dnsdiff — 完整对比工具

`dnsdiff` 采用 **长短参数** 两种形式（等价）。核心能力：
- 首次对比：默认从 pcap 解析出的 `rspMap` 中获取 origin 响应；`-query-only` 模式下改为向 `-o/-origin-ip` 发起网络请求。
- 重试对比：`-retry` 开启（默认）且指定了 `-o/-origin-ip` 时，对 origin 与 test 各再发起 2 次请求。
- 交叉对比：重试仍不一致时，将第 1 次 origin × 第 2 次 test、第 2 次 origin × 第 1 次 test 交叉比对。
- Answer 合并：三次均为 `ANSWER_RR_DIFF` 时，合并全部 Answer 段做最终 RR 集合比较。

```bash
# 基本用法（origin 从 pcap 获取）
./bin/dnsdiff -i traffic.pcap -t 10.0.0.1 -q 5000

# 带线上服务器的重试对比
./bin/dnsdiff -i traffic.pcap -t 10.0.0.1 -o 10.0.0.2 -q 8000 -retry

# query-only：pcap 中只有请求
./bin/dnsdiff -i requests.pcap -t 10.0.0.1 -o 10.0.0.2 -q 3000 -query-only

# 完整参数示例
./bin/dnsdiff \
  -i traffic.pcap \       # 或 -input
  -t 10.0.0.1 \            # 或 -test-ip
  -o 10.0.0.2 \            # 或 -origin-ip
  -q 5000 \                # 或 -qps，最小 2
  -m 0x35F0B7 \            # 或 -mask，默认 DefaultMask
  -allow-partial \          # 允许 Answer 部分匹配（默认 true）
  -ignore-additional \      # 忽略 Additional 段（默认 true）
  -retry \                  # 开启重试（默认 true）
  -query-only=false \       # 是否仅请求模式
  -w whitelist.yaml \       # 白名单 YAML
  -c 1000 \                # 或 -concurrency，消费者协程数
  -l info                    # 或 -level
```

### 2. dnscmp — 双 pcap 对比

只对比两份 pcap，不产生任何网络请求；其他行为和 `dnsdiff` 一致（同样生成差异文件与统计）。

```bash
./bin/dnscmp \
  -t test.pcap \          # 被测 pcap（必填）
  -o online.pcap \         # 线上 pcap（必填）
  -a 1 \                    # 忽略 Additional，1=是 / 0=否
  -p 1 \                    # 允许 Answer 部分匹配
  -m 0x35F0B7 \             # 非预期差异掩码
  -l info                    # 日志级别
```

### 3. dnsreplay — DNS 重放

```bash
./bin/dnsreplay \
  -f test.pcap \          # pcap 路径（必填）
  -d 10.0.0.1 \            # 目标 IP（必填）
  -r 1000 \                 # QPS（最小 10，默认 1）
  -c 1000 \                 # 消费者协程数
  -p tcp                     # 强制协议：udp / tcp / 空（跟随 pcap）
```

### 4. formcheck — 报文格式校验

对 pcap 中的 DNS 报文进行结构 / RFC / 关联校验，输出 `checksummary_MMDD_HHMMSS.csv`。

```bash
./bin/formcheck \
  -f traffic.pcap \       # pcap 路径（必填）
  -d 10.0.0.1 \            # 目标 IP 过滤；指定后会做主动探测
  -c all \                  # 模式：req | rsp | all
  -proto default \           # 强制协议：udp | tcp | default
  -n 1000 \                  # worker 协程数
  -qps 0 \                   # 主动探测 QPS（0 不限）
  -warn                      # 打印带 warning 的报文（error 总打印）
```

## 输出与查看

### 日志
所有工具日志（默认）写入：
```
log/udns_dial.log        # dnsdiff/dnscmp/dnsreplay
log/formcheck.log        # formcheck
```
日志为 JSON 格式，可使用 `jq` 查看：
```bash
tail -f log/udns_dial.log | jq .
```

### 差异文件（dnsdiff / dnscmp）
文件名带时间戳，便于区分多次运行：
```
diffold-MMDDhhmmss.txt    # origin 侧响应
diffnew-MMDDhhmmss.txt    # test 侧响应
diffstat-MMDDhhmm.txt     # 汇总统计
diffstat-MMDDhhmm.csv     # 详情（DNS Type, Zone, Diff Code, Diff desc, Count）
```

### 控制台统计
`dnsdiff`、`dnscmp` 结束时会在控制台打印 Total summary，包括按 qtype × diffCode 分桶的计数。

## 抓包建议
建议仅抓对象机器 53 端口相关流量，避免无效数据：
```bash
tcpdump -iany -nn \
  "(dst host 9.208.51.5 and dst port 53) or (src host 9.208.51.5 and src port 53)" \
  -w traffic.pcap
```

## 常见问题

### Q1. 差异文件没有产生？
说明没有任何差异落到"非预期掩码"（`-m/-mask`）里。可以：
- 用 `-l debug` 查看日志中被过滤或被忽略的 diffCode。
- 放宽掩码（例如把 `DIFF_BIT_ANSWER_RRDIFF` 加进来）看看是否符合预期。
- 检查白名单是否过宽（`log/udns_dial.log` 中有 `Whitelist applied` 的记录）。

### Q2. origin 响应从哪里来？
- 默认（`-query-only=false`）从 pcap 解析出的 `rspMap` 中查找；找不到且指定了 `-o/-origin-ip`，会走网络补发。
- `-query-only=true`：必须指定 `-o/-origin-ip`，全部走网络请求。

### Q3. 重试机制作用？
`-retry` 开启且指定了 `-o/-origin-ip`，可消化：
1. origin 首次转发命中权威、重试命中缓存导致的 AA 差异；
2. 域名 RR 在小集合内轮转导致的 `ANSWER_RR_DIFF`；
3. 偶发的 SERVFAIL / 上游超时。

### Q4. dnscmp 支持白名单吗？
当前版本的 `dnscmp` 不读取白名单配置。需要白名单时请使用 `dnsdiff`。

### Q5. 编译提示找不到包？
在仓库根目录执行：
```bash
go mod tidy
./build.sh
```
确保根目录存在 `go.mod`，且在仓库根目录下执行编译命令。

### Q6. 如何清理产物？
```bash
rm -rf bin/
rm -f diffold-*.txt diffnew-*.txt diffstat-*.txt diffstat-*.csv checksummary_*.csv
rm -rf log/*.log
```

## 开发指南

### Import 路径规范
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
不要引入 `dnsdiff/comm`（已不复存在，仓库内不再提供兼容层）。

### 运行测试
```bash
go test ./...
go test -cover ./internal/diff ./internal/validate
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

### 代码检查
```bash
go fmt ./...
go vet ./...
golangci-lint run   # 如已安装
```

## 相关文档
- [README.md](README.md) — 项目说明（含差异码/白名单详解）
- [REFACTOR.md](REFACTOR.md) — 目录重构历史
- [pkg/DNS_msg.md](pkg/DNS_msg.md) — DNS / EDNS(0) / ECS 报文结构
- [internal/validate/validate.md](internal/validate/validate.md) — formcheck/validate 包文档
- [internal/validate/DNS的rfc规则.md](internal/validate/DNS的rfc规则.md) — RFC 规则摘要

---

祝您使用愉快！🎉
