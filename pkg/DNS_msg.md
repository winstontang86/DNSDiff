## DNS Message Structure (Classic DNS / EDNS(0) / ECS)

本文用“文字画图”的方式，把一个典型的 DNS 报文结构拆开说明，并把 **EDNS(0) 的 OPT 记录**以及 **ECS（EDNS Client Subnet）选项**所在的位置标清楚。

内容包括：

- **整个 DNS 报文的总体结构**
- **经典（无 EDNS）的 DNS 报文结构细节**
- **带 EDNS OPT 记录的报文结构**
- **带 ECS（EDNS Client Subnet）选项的 OPT 记录结构**
- **综合例子：带 ECS 的 DNS 查询报文结构图**

---

### 1. DNS 报文总体结构（逻辑视图）

无论查询还是响应，一个 DNS 报文在逻辑上都由 5 个 Section 顺序组成：

```text
+---------------------+
|        HEADER       |  固定 12 字节
+---------------------+
|       QUESTION      |  可变（0~QDCOUNT 个问题）
+---------------------+
|        ANSWER       |  可变（0~ANCOUNT 条 RR）
+---------------------+
|      AUTHORITY      |  可变（0~NSCOUNT 条 RR）
+---------------------+
|      ADDITIONAL     |  可变（0~ARCOUNT 条 RR）
+---------------------+
```

- **QUESTION**：查询的“问题”，描述“我要问什么”。
- **ANSWER/AUTHORITY/ADDITIONAL**：都是 RR（Resource Record，资源记录）列表。
- **EDNS(0)**：通过在 **ADDITIONAL** 中插入一条特殊 RR（OPT RR）来携带扩展能力。

#### RR（资源记录）的通用外层结构

ANSWER / AUTHORITY / ADDITIONAL 中的每一条 RR（包括 OPT 这种“伪 RR”）在二进制上都遵循同一套外层结构：

```text
+-------------------------------+
|              NAME             |  variable（可压缩）
+-------------------------------+
|              TYPE             |  16 bits
+-------------------------------+
|              CLASS            |  16 bits
+-------------------------------+
|               TTL             |  32 bits
+-------------------------------+
|            RDLENGTH           |  16 bits
+-------------------------------+
|               RDATA           |  variable (RDLENGTH bytes)
+-------------------------------+
```

> 注意：**OPT RR** 虽然在“外形”上也是 RR，但其 `CLASS/TTL/RDATA` 字段语义被 EDNS(0) 重新定义。

---

### 2. DNS Header 结构（固定 12 字节）

Header 固定 12 字节：

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
|              ID               |             FLAGS             |
+-------------------------------+-------------------------------+
|            QDCOUNT            |            ANCOUNT            |
+-------------------------------+-------------------------------+
|            NSCOUNT            |            ARCOUNT            |
+-------------------------------+-------------------------------+
```

- **ID (16 bits)**：事务 ID。查询与响应要一致，用于配对。
- **QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT**：各 Section 的条目数。
  - `ARCOUNT`（Additional RR 数量）：如果带 EDNS(0)，通常至少会包含 1 条 OPT RR，因此常见 `ARCOUNT>=1`。

#### FLAGS（16 bits）更准确的位拆分

DNS Flags 的位意义如下：

- bit 15：`QR`（0=Query，1=Response）
- bit 14..11：`OPCODE`（0=Standard Query）
- bit 10：`AA`（Authoritative Answer，仅响应中有效）
- bit 9：`TC`（Truncated，报文被截断）
- bit 8：`RD`（Recursion Desired，期望递归）
- bit 7：`RA`（Recursion Available，支持递归，仅响应中有效）
- bit 6：`Z`（保留，必须为 0）
- bit 5：`AD`（Authenticated Data，RFC 4035，DNSSEC 验证通过）
- bit 4：`CD`（Checking Disabled，RFC 4035，禁用 DNSSEC 校验）
- bit 3..0：`RCODE`（响应码，NOERROR=0，NXDOMAIN=3 等）

文字图示（按高位到低位）：

```text
  15   14 13 12 11   10  9   8   7   6   5   4   3 2 1 0
+----+-------------+----+---+---+---+---+---+---+---------+
| QR |   OPCODE    | AA |TC |RD |RA | Z |AD |CD |  RCODE  |
+----+-------------+----+---+---+---+---+---+---+---------+
```

> 补充：**扩展 RCODE（EXTENDED RCODE）** 并不在经典 FLAGS 里，而是在 EDNS(0) 的 OPT RR 中额外提供（见后文）。实际 12-bit 的扩展 RCODE 可理解为：
>
> 
> \[
> \text{RCODE(12-bit)} = (\text{EXT\_RCODE} \ll 4) \,|\, \text{RCODE}
> \]

---

### 3. Question 段结构（每个 Question）

每个 Question 条目：

```text
+-------------------------------+
|            QNAME              |  variable
+-------------------------------+
|            QTYPE              |  16 bits
+-------------------------------+
|            QCLASS             |  16 bits
+-------------------------------+
```

#### QNAME：域名编码（Label 序列，以 0 结尾）

域名以“标签长度 + 标签内容”的方式编码，最后用 `0x00` 结束。

例如 `www.example.com.`：

```text
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
|3| w  w  w |7| e  x  a  m  p  l  e |3| c  o  m |0|
```

#### QTYPE：查询类型

常见值：

- `0x0001` = A
- `0x001c` = AAAA
- `0x000f` = MX
- `0x0002` = NS

#### QCLASS：查询类

通常 `0x0001` = IN（Internet）。

---

### 4. RR（Resource Record）结构细节（经典 DNS）

在 ANSWER / AUTHORITY / ADDITIONAL 中的“普通 RR”都遵循下面结构：

```text
+-------------------------------+
|              NAME             |  variable（可压缩）
+-------------------------------+
|              TYPE             |  16 bits
+-------------------------------+
|              CLASS            |  16 bits
+-------------------------------+
|               TTL             |  32 bits
+-------------------------------+
|            RDLENGTH           |  16 bits
+-------------------------------+
|               RDATA           |  variable (RDLENGTH bytes)
+-------------------------------+
```

- **NAME**：域名，编码同 QNAME。
  - **可以使用压缩指针**（compression pointer）。常见形式：前两位为 `11`，即一个 16-bit 指针的高两位为 1：
    - 指针范围：`0xC000` ~ `0xFFFF`
    - 偏移值：`pointer & 0x3FFF`，表示从报文起始处计算的偏移。
- **TYPE/CLASS/TTL/RDATA**：随记录类型定义不同。

RDATA 举例：

- **A**：4 字节 IPv4 地址
- **AAAA**：16 字节 IPv6 地址
- **NS/CNAME/PTR**：域名（同 QNAME 编码规则）

---

### 5. 带 EDNS(0) 的报文结构：OPT RR 在哪里？

EDNS(0) 不会改变 DNS 的 5-section 总体结构，而是在 **ADDITIONAL** 中放入一条 **OPT RR**（TYPE=41）。

```text
HEADER
QUESTION
ANSWER
AUTHORITY
ADDITIONAL
  ├─ (可能还有其他 Additional RR)
  └─ OPT RR (TYPE=41)  <-- EDNS(0) 的入口
```

#### OPT RR 的“外形”仍是 RR，但字段语义变了

OPT RR 的外层布局（仍然沿用 RR 的通用格式），但含义如下：

```text
; OPT RR 外层结构（TYPE=41）
+-------------------------------+
| NAME                          |  必须为 0x00 (root)
+-------------------------------+
| TYPE                          |  41 (OPT)
+-------------------------------+
|(原CLASS) UDP payload size     |  16 bits（复用 CLASS 字段）
+-------------------------------+
|(原TTL) EXTENDED RCODE         |  8 bits（复用 TTL 高 8 位）
+-------------------------------+
|(原TTL) EDNS VERSION           |  8 bits（复用 TTL 次高 8 位）
+-------------------------------+
|(原TTL) Z (EDNS flags)         |  16 bits（复用 TTL 低 16 位）
+-------------------------------+
| RDLENGTH                      |  16 bits
+-------------------------------+
| OPTIONS (RDATA)               |  可变（多个 EDNS 选项串接）
+-------------------------------+
```

更关键的点：

- **NAME：固定为根标签 `0x00`。**
- **CLASS** → **UDP payload size**：常见 1232 / 4096 等，表示“我能接收的 UDP DNS 最大 payload”。
- **TTL(32-bit)** 被拆成：
  - 高 8：`EXTENDED RCODE`（扩展应答码高位）
  - 次高 8：`EDNS VERSION`（常见 0）
  - 低 16：`Z`（EDNS 标志位）

#### Z（EDNS flags）里最常用的是 DO 位

Z 为 16 bits，其中最常用的是 **DO（DNSSEC OK）** 位：

- **DO 位**：表示“我希望返回 DNSSEC 相关记录”（如 RRSIG / DNSKEY 等）。
- DO 位位于 `Z` 的 bit 15（也有人称其为 `0x8000`）。

---

### 6. EDNS Options（OPT RR 的 OPTIONS）通用结构

OPT RR 的 `RDATA` 由多个 option 串接而成，每个 option 使用 TLV 结构：

```text
+------------------------+
| OPTION-CODE            |  16 bits
+------------------------+
| OPTION-LENGTH          |  16 bits
+------------------------+
| OPTION-DATA            |  OPTION-LENGTH bytes
+------------------------+
```

- 多个选项直接拼接。
- OPT RR 的 `RDLENGTH` 是所有 options 的总长度。

---

### 7. ECS 和DNS cookie
#### 7.1 ECS（EDNS Client Subnet）选项结构（RFC 7871）

ECS 是一种 EDNS 选项，放在 OPT RR 的 OPTIONS 中。

#### 编号的一个容易混淆点

- `OPT RR` 的 **TYPE = 41**：表示这条 RR 是 OPT。
- `ECS option` 的 **OPTION-CODE = 8**（十进制 8，十六进制 `0x0008`）：表示这是 ECS 选项。

>  
> 根据 RFC 7871，**ECS 的 Option Code 是 8**。

#### ECS 的 OPTION-DATA 结构

ECS 的 OPTION-DATA 为：

```text
+-------------------------------+
| FAMILY                        |  16 bits
+-------------------------------+
| SOURCE PREFIX-LENGTH          |  8 bits
+-------------------------------+
| SCOPE PREFIX-LENGTH           |  8 bits
+-------------------------------+
| ADDRESS                       |  variable, ceil(SOURCE/8) bytes
+-------------------------------+
```

字段含义：

- **FAMILY**：
  - `0x0001` = IPv4
  - `0x0002` = IPv6
- **SOURCE PREFIX-LENGTH**：
  - 单位是 bit。
  - 例如 IPv4 /24 就是 24。
- **SCOPE PREFIX-LENGTH**：
  - 单位也是 bit。
  - 查询中通常为 0；响应中可能非 0（表示缓存覆盖范围）。
- **ADDRESS**：只携带前缀覆盖的那部分地址字节数：
  - 字节数 = `ceil(SOURCE_PREFIX_LENGTH / 8)`
  - 多出来的无效比特必须为 0。

因此：

```text
ECS OPTION-LENGTH = 2(FAMILY) + 1(SOURCE) + 1(SCOPE) + ADDRESS_BYTES
```

---

#### 7.2 DNS Cookie（EDNS Cookie Option，RFC 7873）

DNS Cookie 是一个 EDNS 选项，用来让服务端在不保存状态（或尽量少状态）的前提下，对“源地址/源端口”的可达性做轻量校验，降低 UDP 反射/放大类攻击的成本。

- **OPTION-CODE**：RFC 7873 指定为 `10`（十六进制 `0x000A`）。
- **放置位置**：在 OPT RR 的 `OPTIONS`（RDATA）里，和 ECS 一样按 TLV 串接。

##### 7.2.1 外层 TLV（与其他 EDNS option 相同）

```text
EDNS OPTION (TLV)
+------------------------+
| OPTION-CODE            |  16 bits  (DNS Cookie = 10 / 0x000A)
+------------------------+
| OPTION-LENGTH          |  16 bits
+------------------------+
| OPTION-DATA            |  OPTION-LENGTH bytes
+------------------------+
```

##### 7.2.2 Cookie 的 OPTION-DATA 结构

Cookie option 的 OPTION-DATA 由两段组成：

- **Client Cookie**：固定 8 字节
- **Server Cookie**：可选，长度 0..32 字节

```text
DNS Cookie OPTION-DATA
+-------------------------------+
| Client Cookie                 |  8 bytes (mandatory)
+-------------------------------+
| Server Cookie                 |  0..32 bytes (optional)
+-------------------------------+
```

因此：

- `OPTION-LENGTH = 8 + len(ServerCookie)`
- 允许的 `OPTION-LENGTH` 范围：
  - **最小 8**（只有 Client Cookie）
  - **最大 40**（8 + 32）

##### 7.2.3 抓包时你会看到什么？（按字节布局示意）

以“只带 Client Cookie（8B）”为例：

```text
00 0A  00 08  <8 bytes client-cookie>
|code| |len |  |------ data ------|
```

以“带 Client+Server Cookie（例如 Server=16B）”为例：

```text
00 0A  00 18  <8 bytes client-cookie> <16 bytes server-cookie>
|code| |len |  |------ data ------| |------- data --------|
```

##### 7.2.4 解析/校验要点（排障常用）

- **OPTION-LENGTH < 8**：不符合 RFC 7873（Client Cookie 必须完整存在），应视为格式错误。
- **OPTION-LENGTH > 40**：不符合 RFC 7873（Server Cookie 最大 32B），应视为格式错误。
- **Server Cookie 是否存在**：由 `OPTION-LENGTH` 决定；`==8` 表示只有 Client Cookie。
- **与 RDLENGTH 的关系**：Cookie 只是 OPTIONS 里的一项，OPT RR 的 `RDLENGTH` 必须能够完整包含：
  - `OPTION-CODE(2) + OPTION-LENGTH(2) + OPTION-DATA(OPTION-LENGTH)`
  - 以及同一个 OPT RR 中其他 option 的完整 TLV。

---

### 8. 综合例子：带 ECS 的 DNS 查询报文结构图

目标：客户端查询 `www.example.com` 的 A 记录，并带 ECS（IPv4 /24）。

假设：

- DNS ID = `0x1234`
- RD=1（希望递归）
- QDCOUNT=1
- ARCOUNT=1（仅 1 条 OPT RR）
- EDNS UDP payload size = 4096 (`0x1000`)
- ECS：FAMILY=IPv4，SOURCE=24，SCOPE=0
- 客户端地址为 `203.0.113.55`，/24 上报则 ADDRESS = `203.0.113.0` 的前三个字节：`CB 00 71`

#### 8.1 整体报文（从上到下的线性布局）

```text
+-------------------------------+
| HEADER (12 bytes)             |
+-------------------------------+
| QUESTION                       \
|   QNAME (www.example.com.)      \
|   QTYPE (A)                      >  QDCOUNT=1
|   QCLASS (IN)                   /
+-------------------------------+
| ADDITIONAL                      \
|   OPT RR (EDNS(0))               >  ARCOUNT=1
|     OPTIONS: ECS                 /
+-------------------------------+
```

#### 8.2 Header（12B）示意

```text
ID      = 0x1234
FLAGS   = 0x0100  (RD=1, QR=0)
QDCOUNT = 1
ANCOUNT = 0
NSCOUNT = 0
ARCOUNT = 1
```

#### 8.3 Question：QNAME/QTYPE/QCLASS

`www.example.com.` 编码：

```text
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
```

Question 结构：

```text
QNAME  = www.example.com.
QTYPE  = 0x0001 (A)
QCLASS = 0x0001 (IN)
```

#### 8.4 Additional：OPT RR（包含 ECS）

OPT RR 头部：

```text
; NAME = root
00

; TYPE = OPT (41)
00 29

; UDP payload size = 4096
10 00

; EXTENDED RCODE = 0, EDNS VERSION = 0
00 00

; Z (EDNS flags) = 0x0000
00 00

; RDLENGTH = 4 + ECS_OPTION_LENGTH
; 因为 OPTIONS 至少包含：
;   OPTION-CODE(2) + OPTION-LENGTH(2) + OPTION-DATA(variable)
```

ECS option（注意：Option Code 是 `0x0008`）：

```text
+-------------------------------+
| OPTION-CODE   = 0x0008        |  ECS
+-------------------------------+
| OPTION-LENGTH = 2+1+1+3 = 7   |
+-------------------------------+
| FAMILY        = 0x0001        |  IPv4
+-------------------------------+
| SOURCE PREFIX = 0x18          |  24
+-------------------------------+
| SCOPE PREFIX  = 0x00          |  0
+-------------------------------+
| ADDRESS       = CB 00 71      |  203.0.113.0/24
+-------------------------------+
```

因此本例：

- `ECS option` 总长度 = `2 + 2 + 7 = 11` 字节（包含 option 头和 option data）
- `OPT RDLENGTH = 11`（如果只有 ECS 一个 option）

把 OPT RR 拼起来的“文字画图”版本（按字段顺序）：

```text
; OPT RR (in ADDITIONAL)
+--------+
| 00     | NAME = root
+--------+--------+
| 00 29  | TYPE = OPT (41)
+--------+--------+
| 10 00  | UDP payload size = 4096
+--------+--------+
| 00     | EXTENDED RCODE
+--------+
| 00     | EDNS VERSION
+--------+--------+
| 00 00  | Z (flags)
+--------+--------+
| 00 0b  | RDLENGTH = 11 (only one ECS option)
+--------+--------+
| 00 08  | OPTION-CODE = ECS (8)
+--------+--------+
| 00 07  | OPTION-LENGTH = 7
+--------+--------+
| 00 01  | FAMILY = IPv4 (1)
+--------+
| 18     | SOURCE PREFIX = 24
+--------+
| 00     | SCOPE PREFIX = 0
+--------+--------+--------+
| CB     | 00     | 71     | ADDRESS bytes
+--------+--------+--------+
```

---

### 9. 快速对照表：你在抓包里会看到什么？

- **EDNS(0) 是否存在？** 看 `ARCOUNT` 是否包含 OPT RR，以及 ADDITIONAL 里是否有 TYPE=41 的 RR。
- **UDP payload size**：在 OPT RR 的“CLASS”位置。
- **DO 位**：在 OPT RR 的 `Z` 字段中，通常为 `0x8000`。
- **ECS 是否存在？** 在 OPT RR 的 OPTIONS 里找 `OPTION-CODE=8`。
- **ECS 的前缀长度**：看 `SOURCE PREFIX-LENGTH`。

---

### 10. 附：典型 DNS 报文结构（不带 EDNS）的最小查询

一个“最小”的经典 DNS 查询通常只有：

```text
HEADER
QUESTION (QDCOUNT=1)
; ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
```

当你看到 ARCOUNT=0 时，就意味着没有额外 RR（也就没有 EDNS OPT）。

---

### 11. 附：常见 RR 类型的 RDATA 结构要求（RFC 对照 + 文字图示）

本节补充一些在解析/校验时最常遇到的 RR 类型的 **RDATA（二进制）结构**与 RFC 关键约束点，便于你在抓包、写校验器或排查 `unpack` 报错时快速定位。

> 说明：RR 的外层结构（`NAME/TYPE/CLASS/TTL/RDLENGTH/RDATA`）对所有 RR 都一致，下面只展开 **RDATA** 的内部格式。

---

#### 11.1 A / AAAA（RFC 1035）

- **A (TYPE=1)**：RDATA 固定 4 字节 IPv4。
- **AAAA (TYPE=28)**：RDATA 固定 16 字节 IPv6（RFC 3596）。

```text
A RDATA
+-------------------------------+
| IPv4 Address                  |  32 bits
+-------------------------------+

AAAA RDATA
+-------------------------------+
| IPv6 Address                  |  128 bits
+-------------------------------+
```

- **关键约束**：
  - `RDLENGTH` 必须分别等于 `4` / `16`，否则应视为格式错误。

---

#### 11.2 NS / CNAME / PTR（RFC 1035）

这三类的 RDATA 都是 **一个域名（domain name）**：

- **NS (TYPE=2)**：`NSDNAME`（域名）
- **CNAME (TYPE=5)**：`CNAME`（域名）
- **PTR (TYPE=12)**：`PTRDNAME`（域名）

```text
NS / CNAME / PTR RDATA
+-------------------------------+
| Domain Name                   |  variable (labels, may compress)
+-------------------------------+
```

- **关键约束**：
  - RDATA 内部的域名编码遵循“label 序列以 0 结尾 / 允许压缩指针”的规则。
  - 如果解析时压缩指针指向的 offset **不是合法 label 起点**（例如指到某个 RR 字段中间），会触发类似 `ErrRdata` 的错误。

---

#### 11.3 MX（RFC 1035）

MX 记录包含一个 16-bit 优先级和一个交换域名：

```text
MX RDATA
+-------------------------------+
| PREFERENCE                    |  16 bits
+-------------------------------+
| EXCHANGE (Domain Name)        |  variable
+-------------------------------+
```

- **关键约束**：
  - `PREFERENCE` 是无符号整数；语义上用于排序（越小优先级越高）。
  - `EXCHANGE` 必须是可解析的域名编码（含合法 label / 合法压缩指针）。

---

#### 11.4 TXT（RFC 1035）

TXT RDATA 是一个或多个 `<character-string>` 串接。

`<character-string>` 的 wire 格式：`length(1B) + bytes(length)`，长度范围 0..255。

```text
TXT RDATA (one or more strings)
+--------+-------------------+  +--------+-------------------+  ...
|  len   | bytes[len]        |  |  len   | bytes[len]        |
+--------+-------------------+  +--------+-------------------+
  1B          len bytes          1B          len bytes
```

- **关键约束**：
  - `RDATA` 必须能被完整拆成若干段 `len + len bytes`，不能越界。
  - 文本内容允许是任意 8-bit 值；如果要显示为可读字符串，通常需要做转义（`
`、`\DDD` 等）。

---

#### 11.5 SRV（RFC 2782）

SRV 用于服务发现：优先级、权重、端口、目标域名。

```text
SRV RDATA
+-------------------------------+
| PRIORITY                      |  16 bits
+-------------------------------+
| WEIGHT                        |  16 bits
+-------------------------------+
| PORT                          |  16 bits
+-------------------------------+
| TARGET (Domain Name)          |  variable
+-------------------------------+
```

- **关键约束**：
  - `PORT` 取值 0..65535。
  - `TARGET` 为 `.`（根域名）时表示“服务不可用”（一种惯例用法）。

---

#### 11.6 SOA（RFC 1035）

SOA 是排障时最常见、也最容易因为“域名压缩指针错误”导致 `unpack` 报错的类型之一。

SOA RDATA 结构：

```text
SOA RDATA
+-------------------------------+
| MNAME (Domain Name)           |  variable
+-------------------------------+
| RNAME (Domain Name)           |  variable
+-------------------------------+
| SERIAL                        |  32 bits
+-------------------------------+
| REFRESH                       |  32 bits
+-------------------------------+
| RETRY                         |  32 bits
+-------------------------------+
| EXPIRE                        |  32 bits
+-------------------------------+
| MINIMUM                       |  32 bits
+-------------------------------+
```

- **字段含义**：
  - **MNAME**：主域名服务器（primary name server）。
  - **RNAME**：管理员邮箱（将 `@` 替换为 `.` 的域名表示形式）。
  - **SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM**：区域维护相关计时字段。

- **关键约束（非常重要）**：
  - `MNAME`、`RNAME` 都是“域名编码”，允许压缩，但压缩指针必须指向报文内 **合法的 label 起点**。
  - 5 个 32-bit 字段必须完整存在；如果 `RDLENGTH` 不足以容纳，或域名解析提前失败，都会导致解包失败。

---

#### 11.7 NAPTR（RFC 3403）

NAPTR（Naming Authority Pointer）常见于 ENUM、SIP 相关域名解析等场景，用于“基于规则把一个域名重写/映射到另一个域名或服务描述”。

NAPTR RDATA 结构：

```text
NAPTR RDATA
+-------------------------------+
| ORDER                         |  16 bits
+-------------------------------+
| PREFERENCE                    |  16 bits
+-------------------------------+
| FLAGS                         |  <character-string>
+-------------------------------+
| SERVICES                      |  <character-string>
+-------------------------------+
| REGEXP                        |  <character-string>
+-------------------------------+
| REPLACEMENT (Domain Name)     |  variable
+-------------------------------+
```

- **字段含义（排障常用）**：
  - **ORDER**：用于排序，值越小越先处理。
  - **PREFERENCE**：同一 `ORDER` 内的次级排序，值越小越优先。
  - **FLAGS**：控制后续处理行为的标志（例如 `"U"`/`"S"`/`"A"`/`"P"` 等；实际含义取决于应用协议）。
  - **SERVICES**：服务参数（如 `"E2U+sip"`、`"SIPS+D2T"` 等）。
  - **REGEXP**：正则重写规则（一个 `<character-string>`，通常是类似 `!pattern!replacement!flags` 的格式）。
  - **REPLACEMENT**：域名（domain name）。当 `FLAGS` 表明需要继续做 DNS 查询时，会用它作为下一跳名字；当使用 `REGEXP` 时此字段通常为 `.`。

- **关键约束**：
  - `FLAGS/SERVICES/REGEXP` 都是 RFC 1035 的 `<character-string>` 编码：`len(1B) + bytes(len)`，长度范围 `0..255`。
  - `REPLACEMENT` 是“域名编码”，允许压缩指针；指针必须指向报文内 **合法的 label 起点**。
  - 解析时要确保 `RDLENGTH` 足够容纳：
    - `ORDER(2) + PREFERENCE(2)`
    - 以及 3 个 `<character-string>`（每个至少 1 字节长度字段）
    - 再加上 `REPLACEMENT` 的域名编码。

---

#### 11.8 OPT（EDNS(0)，RFC 6891）

OPT 是“伪 RR”，其外层仍长得像 RR，但字段语义被重新解释（前文第 5/6/7 节已讲核心结构，这里补充校验要点）。

```text
OPT RR（外层）
+-------------------------------+
| NAME = 0x00 (root)            |
+-------------------------------+
| TYPE = 41                     |
+-------------------------------+
| UDP payload size (CLASS)      |  16 bits
+-------------------------------+
| EXT-RCODE | VERSION | Z       |  32 bits split
+-------------------------------+
| RDLENGTH                      |  16 bits
+-------------------------------+
| OPTIONS (TLV list)            |  variable
+-------------------------------+
```

- **关键约束**：
  - `NAME` 必须为根（wire 为单字节 `0x00`）。
  - `OPTIONS` 必须能按 TLV：`code(2) + length(2) + data(length)` 完整切分。

---

#### 11.9 DNS name compression（压缩指针）相关的 RFC 约束（RFC 1035 4.1.4）

域名在 message 内可以用压缩来复用后缀，最常见是一个 2 字节指针：

```text
Compression pointer (2 bytes)
+--+--+-------------------------+
|11|11|      OFFSET (14 bits)   |
+--+--+-------------------------+
```

- **关键约束**：
  - 指针的 `OFFSET` 是“从 DNS 报文起始处算起”的偏移。
  - 指针必须指向一个“域名的合法编码位置”，也就是：
    - 目标处应当是 `0x00`（根结束）或一个合法 label length（0..63）或另一个指针（`0xC0..`）。
    - 不能指向某个 label 的中间、RR 的 `TYPE/CLASS/TTL/RDLENGTH` 字段中间等。
  - 实现通常还会限制“指针跳转次数”，防止循环指针导致死循环。

---

### 12.（实践建议）做 RR 校验/排障时最常用的几条规则

- **RDLENGTH 必须与类型匹配**：
  - A=4、AAAA=16 这类固定长度最容易先验判错。
- **RDATA 内的域名最容易出问题**：
  - CNAME/NS/PTR/MX/SOA/SRV 等都包含域名；压缩指针算错会直接导致解包失败。
- **显示与 wire 是两码事**：
  - 抓包工具/库把不可打印字符显示成 `\DDD`（如 `\000`、`\255`）只是“presentation format”，wire 上仍然是原始字节。
- **OPT RR 的 option code 不要混淆**：
  - `TYPE=41` 是 OPT RR 的类型。
  - `OPTION-CODE` 例如 ECS 是 `8`（`0x0008`）。
