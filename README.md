# dnsdiff

## 背景
一个用于dns服务升级或搬迁前的对比工具。假设原有的dns服务器为old，新的服务器为new。new可以说同一个dns服务器的新版本，也可以是待迁移的别的服务器。稳妥起见，新旧版本对于同样的请求应该返回内容一样。

## 功能：
1、支持对tcpdump抓包的pcap文件进行请求重放。重放的时候保持dns的请求二进制内容不变，网络层的源ip会变更为使用工具的本机ip。    
2、支持指定限速进行重放。  
3、能根据返回的dns内容跟pcap里面old机器的返回内容进行对比。  
4、对比的差异不符合预期的会保存到diffold.txt文件，新的会保存到diffnew.txt文件，方便使用对比工具对比（比如beyound compare）。  
5、能输出统计信息。统计信息按qtype分类，然后是每个二级域名的统计，对比的diffcode参阅代码里面的定义说明。统计结果会存放在 diffstat.txt 文件里面。  
6、注意！在源机器抓包的时候，只抓往这个机器53端口请求的和这个机器53端口返回的，其他的包不要抓，命令形如：tcpdump -iany -nn "(dst host 9.208.51.5 and dst port 53) or (src host 9.208.51.5 and src port 53)"  

## diffcode说明
diffcode 如下：  
	DNS_EQUAL    = 0  
	DNS_NOTEQUAL = -1  
	// 整体比较    
	DIFF_BIT_NOMATCH       = 0x00000001  
	DIFF_BIT_NOMATCHKEY    = 0x00000002  
	DIFF_BIT_NOMATCHDOMAIN = 0x00000004  
	// 头部关节字段  
	DIFF_BIT_HEAD_RCODE   = 0x00000010  
	DIFF_BIT_HEAD_OPCODE  = 0x00000020  
	DIFF_BIT_HEAD_QFLAG   = 0x00000040  
	/* 这三个不在这里判断了，改成在具体的段内容判断的时候判定了  
	DIFF_BIT_HEAD_ANCOUNT = 0x00000100 // answers  
	DIFF_BIT_HEAD_NSCOUNT = 0x00000200 // authorities  
	DIFF_BIT_HEAD_ARCOUNT = 0x00000400 // additionals  
	*/  
	// question关键字段  
	DIFF_BIT_QUEST_LEN    = 0x00001000  
	DIFF_BIT_QUEST_QNAME  = 0x00002000  
	DIFF_BIT_QUEST_QTYPE  = 0x00004000  
	DIFF_BIT_QUEST_QCLASS = 0x00008000  
	// answer 关键字段  
	DIFF_BIT_ANSWER_LEN    = 0x00010000  
	DIFF_BIT_ANSWER_RRDIFF = 0x00020000  
	// authority 关键字段  
	DIFF_BIT_AUTH_LEN    = 0x00100000  
	DIFF_BIT_AUTH_RRDIFF = 0x00200000  
	// additional 关键字段  
	DIFF_BIT_ADD_LEN    = 0x01000000  
	DIFF_BIT_ADD_RRDIFF = 0x02000000  
  

## 工具使用：
本仓库提供三个工具：   
dnsdiff  进行dns请求重放+比较的工具（支持智能重试）   
dnsreplay  进行dns请求重放的工具，可以指定重放速率   
dnscmp  对rsp的pcap进行分析对比的工具（支持智能重试）   

使用的话，直接把代码clone到一个有golang的环境，直接执行build.sh就可以获得编译结果工具文件

## 重要参数说明

### dnsdiff新增参数
- **-qo**：Query only mode，指定pcap是否只包含请求
  - 0：包含请求和响应（默认）
  - 1：只包含请求
- **-rt**：Retry on diff，是否在差异时启用重试机制
- **-ia**：Ignore additional，是否忽略Additional段
- **-ap**：Allow partial match，是否允许部分匹配

### 重试逻辑说明
1. **首次对比**：根据qonly参数决定originMsg获取方式
2. **重试对比**：如果首次有差异，对origin和test各发起两次请求
3. **Answer段合并**：当三次都是DIFF_BIT_ANSWER_RRDIFF时，合并Answer段最终对比

### dnsdiff
功能描述：这个dnsdiff工具可以从pcap包进行重放并对比，重放的时候可以指定重放速度。具有智能重试机制：
- 首次对比：根据qonly参数决定originMsg获取方式（map或网络请求）
- 重试对比：如果首次有差异，对origin和test各发起两次请求进行对比
- Answer段合并对比：当三次都是DIFF_BIT_ANSWER_RRDIFF时，合并Answer段进行最终对比

对比差异码前面有说明。对比会生成4个文件：  
diffold-xxxxx.txt 对比有差异的响应中源机器响应，用于beyondcompare对比    
diffnew-xxxxx.txt 对比有差异的响应中被测机器的响应  
diffstat-xxxx.txt 统计汇总信息  
diffstat-xxxx.csv 统计差异详情文件，使用表格方式，方便上传为在线文档处理

$ ./dnsdiff -h  
Usage of ./dnsdiff:  
  -ap int  
        Allow partial match: 0=no, 1=yes (default: 1)  
  -c int  
        Number of consumer goroutines (default: 1000)  
  -f string  
        Path to the pcap file (required)  
  -ia int  
        Ignore additional section: 0=no, 1=yes (default: 1)  
  -l string  
        Log level: info, debug, warn, error (default: info)  
  -m string  
        Expected diff mask (hex format, e.g., 0xFF00) (default "0x35F0B7")  
  -oip string  
        Online/Origin server IP address (required when qo=1)  
  -qo int  
        Query only mode (pcap contains only requests): 0=no, 1=yes (default: 0)  
  -qps int  
        Rate limit in requests per second (minimum: 10) (default 1)  
  -rt int  
        Enable retry on diff: 0=no, 1=yes (default: 1)  
  -tip string  
        Test server IP address (required)  
  -w string  
        Path to whitelist config file in YAML format (optional)


### dnscmp
功能描述：这个工具对现网流量对比的两个pcap文件进行分析对比。对比会生成4个文件，同上面的dnsdiff    

Usage of ./dnscmp:  
  -a int  
        Ignore Addition (default 1)  
  -l string  
        Log level info debug (default "info")  
  -m string  
        Expected diff mask (hex format, e.g., 0xFF00) (default "0x35F0B7")  
  -o string  
        Online server pcap file (required)  
  -p int  
        Allow partial match (default 1)  
  -t string  
        Test server pcap file (required)


### dnsrepaly
功能描述：利用抓包pcap文件，指定速度重放。  

Usage of ./dnsreplay:  
  -c int  
        Number of consumers (default 1000)  
  -d string  
        Destination IP (required)  
  -f string  
        Path to the pcap file (required)  
-r int  
        Rate limit (requests per second) (default 1)

---

## 项目目录结构说明

### 概述

本项目已按照标准Go项目布局进行重构，采用清晰的分层架构，提高代码的可维护性和可扩展性。

### 目录结构

```
dnsdiff/
├── cmd/                    # 可执行程序入口
│   ├── dnsdiff/           # DNS对比工具（支持网络重试）
│   │   └── main.go
│   ├── dnscmp/            # DNS对比工具（仅对比pcap文件）
│   │   └── main.go
│   └── dnsreplay/         # DNS重放工具
│       └── main.go
├── internal/              # 内部库（不对外暴露）
│   ├── app/              # 应用层逻辑
│   │   ├── config.go     # 配置管理
│   │   └── logger.go     # 日志初始化
│   ├── diff/             # DNS消息对比逻辑
│   │   └── diff.go
│   ├── dnet/             # DNS网络请求
│   │   └── dnet.go
│   ├── parser/           # pcap文件解析
│   │   └── parser.go
│   ├── saver/            # 差异结果保存
│   │   └── saver.go
│   └── statistics/       # 统计信息收集
│       └── statistics.go
├── pkg/                  # 可对外暴露的库
│   ├── types/           # 公共数据类型
│   │   ├── types.go     # 数据结构定义
│   │   ├── convert.go   # 类型转换函数
│   │   └── utils.go     # 说明文档（避免循环依赖）
│   └── utils/           # 工具函数库
│       └── utils.go     # Hash、Key生成等工具函数
├── comm/                 # 兼容层（向后兼容）
│   └── comm.go          # 类型和函数别名
├── bin/                  # 编译输出目录
├── log/                  # 日志目录
├── go.mod
├── go.sum
├── build.sh             # 构建脚本
├── README.md            # 项目说明
└── STRUCTURE.md         # 本文档
```

### 各目录职责

#### cmd/ - 可执行程序入口

包含三个独立的命令行工具：

- **dnsdiff**: 完整的DNS对比工具，支持从pcap文件解析、网络重试、结果保存
- **dnscmp**: 轻量级DNS对比工具，仅对比两个pcap文件的内容
- **dnsreplay**: DNS请求重放工具，用于压力测试

#### internal/ - 内部库

遵循Go的internal包约定，这些包只能被本项目内部使用，不对外暴露。

##### internal/app - 应用层逻辑
- `config.go`: 配置解析和管理
- `logger.go`: 日志系统初始化

##### internal/diff - 对比逻辑
- DNS消息的详细对比
- 差异码定义和计算
- 对比策略配置

##### internal/dnet - 网络请求
- DNS查询的UDP/TCP实现
- 超时和重试控制
- 网络错误处理

##### internal/parser - pcap解析
- pcap文件读取和解析
- DNS数据包提取
- 请求/响应分类

##### internal/saver - 结果保存
- 差异结果格式化
- 文件写入管理
- 并发安全保证

##### internal/statistics - 统计信息
- 对比结果统计
- 性能指标收集
- 报告生成

#### pkg/ - 公共库

可以被外部项目引用的包。

##### pkg/types - 数据类型
- `DNSReq`: DNS请求结构
- `DNSRsp`: DNS响应结构
- `RspMap`: 响应映射表
- `SaveChan`: 保存通道类型
- 类型转换函数

##### pkg/utils - 工具函数
- `Hash64`: 哈希计算
- `GenU64Key`: 生成64位键
- `GenSecdKey`: 生成二级键
- `Domain2Zone`: 域名转zone
- `Find4diff`: 查找对比响应

#### comm/ - 兼容层

为保持向后兼容而保留的包，提供类型和函数别名。新代码应直接使用`pkg/types`和`pkg/utils`。

### 编译和使用

#### 编译所有程序

```bash
# 使用构建脚本
./build.sh

# 或手动编译
go build -o dnsdiff ./cmd/dnsdiff
go build -o dnscmp ./cmd/dnscmp
go build -o dnsreplay ./cmd/dnsreplay
```

#### 使用示例

```bash
# DNS对比（支持网络重试）
./dnsdiff -f test.pcap -tip 10.0.0.1 -oip 10.0.0.2

# DNS对比（仅对比文件）
./dnscmp -t test.pcap -o online.pcap

# DNS重放
./dnsreplay -f test.pcap -d 10.0.0.1
```

### 依赖关系

```
cmd/
  ├─> internal/app
  ├─> internal/diff
  ├─> internal/dnet
  ├─> internal/parser
  ├─> internal/saver
  ├─> internal/statistics
  ├─> pkg/types
  └─> pkg/utils

internal/parser
  ├─> internal/statistics
  ├─> pkg/types
  └─> pkg/utils

internal/dnet
  └─> pkg/types

internal/saver
  └─> pkg/types

internal/statistics
  ├─> internal/diff
  └─> pkg/utils

pkg/utils
  └─> pkg/types

comm/ (兼容层)
  ├─> pkg/types
  └─> pkg/utils
```

### 设计原则

1. **高内聚低耦合**: 每个包职责单一，依赖关系清晰
2. **分层架构**: cmd -> internal -> pkg，层次分明
3. **向后兼容**: 保留comm包作为兼容层
4. **标准布局**: 遵循Go社区的标准项目布局
5. **可测试性**: 各包独立，便于单元测试

### 重构要点

#### 包重命名
- `parse` -> `internal/parser`
- `save` -> `internal/saver`
- `stat` -> `internal/statistics`
- `diff` -> `internal/diff`
- `dnet` -> `internal/dnet`

#### 新增包
- `internal/app`: 应用层配置和日志管理
- `pkg/types`: 公共数据类型
- `pkg/utils`: 工具函数库

#### 代码移动
- 所有main.go移至cmd/目录
- 工具函数从comm拆分到pkg/utils
- 类型定义集中到pkg/types

### 注意事项

1. **避免循环依赖**: pkg/types和pkg/utils之间不能相互依赖
2. **internal包限制**: internal下的包不能被外部项目引用
3. **兼容层使用**: 旧代码可继续使用comm包，新代码应使用pkg包
4. **import冲突**: 注意Go标准库的parser包，使用时需明确包路径

### 后续优化建议

1. 为各个包添加单元测试
2. 添加性能基准测试
3. 完善错误处理和日志记录
4. 考虑添加配置文件支持
5. 增加更多的统计维度