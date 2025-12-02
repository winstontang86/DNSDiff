# 快速开始指南

## 项目重构说明

本项目已按照标准Go项目布局进行重构。如果您是第一次使用重构后的代码，请阅读本指南。

## 目录结构概览

```
dnsdiff/
├── cmd/                    # 可执行程序入口
│   ├── dnsdiff/           # DNS对比工具（支持网络重试）
│   ├── dnscmp/            # DNS对比工具（仅对比pcap）
│   └── dnsreplay/         # DNS重放工具
├── internal/              # 内部库
│   ├── app/              # 应用配置和日志
│   ├── diff/             # 对比逻辑
│   ├── dnet/             # 网络请求
│   ├── parser/           # pcap解析
│   ├── saver/            # 结果保存
│   └── statistics/       # 统计信息
├── pkg/                  # 公共库
│   ├── types/           # 数据类型
│   └── utils/           # 工具函数
├── comm/                 # 兼容层（向后兼容）
├── bin/                  # 编译输出
└── log/                  # 日志目录
```

## 编译项目

### 方式1：使用构建脚本（推荐）

```bash
./build.sh
```

这将在项目根目录生成三个可执行文件：
- `dnsdiff` - DNS对比工具（支持网络重试）
- `dnscmp` - DNS对比工具（仅对比pcap）
- `dnsreplay` - DNS重放工具

### 方式2：手动编译

```bash
# 编译到bin目录（推荐）
mkdir -p bin
go build -o bin/dnsdiff ./cmd/dnsdiff
go build -o bin/dnscmp ./cmd/dnscmp
go build -o bin/dnsreplay ./cmd/dnsreplay

# 或编译到项目根目录
go build -o dnsdiff ./cmd/dnsdiff
go build -o dnscmp ./cmd/dnscmp
go build -o dnsreplay ./cmd/dnsreplay
```

### 方式3：直接运行

```bash
go run ./cmd/dnsdiff -h
go run ./cmd/dnscmp -h
go run ./cmd/dnsreplay -h
```

## 使用示例

### 1. dnsdiff - 完整对比工具

支持从pcap文件解析、网络重试、结果保存。具有智能重试机制：
- 首次对比：根据qonly参数决定originMsg获取方式（map或网络请求）
- 重试对比：如果首次有差异，对origin和test各发起两次请求进行对比
- Answer段合并对比：当三次都是DIFF_BIT_ANSWER_RRDIFF时，合并Answer段进行最终对比

```bash
# 基本用法
./dnsdiff -f test.pcap -tip 10.0.0.1 -oip 10.0.0.2

# 完整参数
./dnsdiff \
  -f test.pcap \              # pcap文件路径（必需）
  -tip 10.0.0.1 \           # 测试服务器IP（必需）
  -oip 10.0.0.2 \           # 线上服务器IP（qo=1时必需）
  -c 100 \                    # 消费者数量（默认1000）
  -qps 1000 \                 # QPS限制（默认1，最小10）
  -l info \                   # 日志级别（debug/info/warn/error）
  -m 0xFF00 \                 # 预期差异掩码
  -rt 1 \                     # 差异重试开关（1=是，0=否）
  -qo 0 \                     # 仅查询模式（pcap只包含请求）（1=是，0=否）
  -ia 1 \                     # 忽略Additional段（1=是，0=否）
  -ap 1 \                     # 允许部分匹配（1=是，0=否）
  -w config.yaml              # 白名单配置文件（可选）
```

### 2. dnscmp - 轻量级对比工具

仅对比两个pcap文件，不进行网络请求。

```bash
# 基本用法
./dnscmp -t test.pcap -o online.pcap

# 完整参数
./dnscmp \
  -t test.pcap \              # 测试pcap文件（必需）
  -o online.pcap \            # 线上pcap文件（必需）
  -l info \                   # 日志级别（info/debug/warn/error）
  -m 0xFF00 \                 # 预期差异掩码
  -a 1 \                      # 忽略Additional段（1=是，0=否）
  -p 1                        # 允许部分匹配（1=是，0=否）
```

### 3. dnsreplay - DNS重放工具

从pcap文件读取DNS请求并重放到指定服务器。

```bash
# 基本用法
./dnsreplay -f test.pcap -d 10.0.0.1

# 完整参数
./dnsreplay \
  -f test.pcap \              # pcap文件路径（必需）
  -d 10.0.0.1 \           # 目标服务器IP（必需）
  -c 100 \                    # 消费者数量（默认1000）
  -r 1000                     # QPS限制（默认1）
```

## 查看结果

### 日志文件

所有工具的日志都输出到：
```
log/udns_dial.log
```

日志格式为JSON，便于解析和分析。

### 差异文件

dnsdiff和dnscmp会生成两个差异文件：
```
diff_old.txt    # 线上服务器的响应
diff_new.txt    # 测试服务器的响应
```

可以使用Beyond Compare等工具对比这两个文件。

### 统计信息

程序结束时会在控制台输出统计信息：
- 总请求数
- 差异数量
- 各类型差异的详细统计
- 按域名zone分组的统计

## 开发指南

### 添加新功能

1. **添加新的内部包**
   ```bash
   mkdir internal/newfeature
   # 创建 internal/newfeature/newfeature.go
   ```

2. **添加新的公共类型**
   ```bash
   # 编辑 pkg/types/types.go
   ```

3. **添加新的工具函数**
   ```bash
   # 编辑 pkg/utils/utils.go
   ```

### Import路径

新代码应使用以下import路径：

```go
import (
    // 应用层
    "dnsdiff/internal/app"
    
    // 业务逻辑层
    "dnsdiff/internal/diff"
    "dnsdiff/internal/dnet"
    "dnsdiff/internal/parser"
    "dnsdiff/internal/saver"
    "dnsdiff/internal/statistics"
    
    // 基础库层
    "dnsdiff/pkg/types"
    "dnsdiff/pkg/utils"
)
```

**注意**：不要使用`dnsdiff/comm`，这是为向后兼容保留的兼容层。

### 运行测试

```bash
# 运行所有测试
go test ./...

# 运行特定包的测试
go test ./internal/parser
go test ./pkg/utils

# 运行测试并显示覆盖率
go test -cover ./...

# 生成覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 代码检查

```bash
# 格式化代码
go fmt ./...

# 静态检查
go vet ./...

# 使用golangci-lint（如果已安装）
golangci-lint run
```

## 常见问题

### Q1: 编译时提示找不到包

**A**: 确保您在项目根目录（dnsdiff/）下执行编译命令，并且go.mod文件存在。

```bash
cd /path/to/dnsdiff
go mod tidy
go build ./cmd/dnsdiff
```

### Q2: 旧代码如何迁移？

**A**: 旧代码可以继续使用comm包，无需立即修改。如需迁移：

```go
// 旧代码
import "dnsdiff/comm"
req := comm.DNSReq{}
key := comm.GenU64Key(...)

// 新代码
import (
    "dnsdiff/pkg/types"
    "dnsdiff/pkg/utils"
)
req := types.DNSReq{}
key := utils.GenU64Key(...)
```

### Q3: 如何查看详细日志？

**A**: 使用`-l debug`参数启用调试日志：

```bash
./dnsdiff -p test.pcap -t 10.0.0.1 -r 10.0.0.2 -l debug
```

然后查看日志文件：
```bash
tail -f log/udns_dial.log | jq .
```

### Q4: 编译后的文件在哪里？

**A**: 
- 使用`build.sh`：在项目根目录
- 使用`go build -o bin/xxx`：在bin/目录
- 使用`go build`：在当前目录

### Q5: qonly参数的作用是什么？

**A**: qonly（query only）参数用于指定pcap文件是否只包含DNS请求：
- `qo=0`（默认）：pcap包含请求和响应，首次对比时originMsg从map中获取
- `qo=1`：pcap只包含请求，首次对比时originMsg通过网络请求获取

这影响重试逻辑中第一次对比的originMsg获取方式。

### Q6: 如何清理编译产物？

**A**:
```bash
# 清理bin目录
rm -rf bin/

# 清理根目录的可执行文件
rm -f dnsdiff dnscmp dnsreplay

# 清理日志
rm -rf log/*.log

# 清理差异文件
rm -f diff_*.txt
```

## 相关文档

- [STRUCTURE.md](STRUCTURE.md) - 详细的目录结构说明
- [REFACTOR_SUMMARY.md](REFACTOR_SUMMARY.md) - 重构总结
- [README.md](README.md) - 项目说明

## 获取帮助

如有问题，请：
1. 查看相关文档
2. 使用`-h`参数查看命令帮助
3. 查看日志文件排查问题
4. 联系项目维护者

## 贡献代码

欢迎贡献代码！请遵循以下规范：

1. **代码风格**: 遵循Go官方代码规范
2. **包组织**: 新功能放在internal/或pkg/下
3. **测试**: 为新功能添加单元测试
4. **文档**: 更新相关文档
5. **提交**: 使用清晰的commit message

---

**祝您使用愉快！** 🎉
