DNS 报文 RFC 合法性校验规则（用于 `formcheck` / `validate`）

### 目标与输出
- **目标**：使用 RFC 规则对 DNS 的请求与响应做“wire-format 级别”的严格合法性检查。
- **输出**：
  - **`ErrorBits` (`uint64`)**：表示 **error 级别** 的非法（通常可视为 FORMERR/协议硬错误/无法可靠解析）。
  - **`WarningBits` (`uint64`)**：表示 **warning 级别** 的非法或不推荐用法（可解析但不规范/可能造成兼容性问题）。
- **适用范围**：
  - 经典 DNS 消息格式 + EDNS(0) + 常用扩展位（AD/CD/DO/ECS 等）。
  - 不区分“客户端/服务器实现细节”，只关注线上抓到的 **wire-format 是否符合 RFC**。
  - 不涉及具体 RR 类型内部 RDATA 的业务语义（A/AAAA/MX… 的业务含义），仅做 **格式/结构约束**。

### 主要参考 RFC
- RFC 1034, RFC 1035（基础 DNS）
- RFC 2181（Clarifications）
- RFC 2308（Negative Caching）
- RFC 4035（DNSSEC flags：AD/CD；以及 DO 的配合语义）
- RFC 5155（NSEC3，DNSSEC 证明）
- RFC 6891（EDNS(0)，OPT 伪 RR）
- RFC 7871（ECS：EDNS Client Subnet）
- RFC 7766（DNS over TCP）
- 以及后续扩展 RFC（如 RFC 1996 NOTIFY、RFC 2136 UPDATE 等）

---

## 1. 单字段规则（字段级严格校验）

### 1.1 整体消息结构（DNS Message Format）
DNS 消息结构（RFC 1035 4.1）：
- Header（12 字节）
- Question section（0~N 个 Question）
- Answer section（0~N 个 RR）
- Authority section（0~N 个 RR）
- Additional section（0~N 个 RR）

#### 1.1.1 总长度限制
- **UDP**
  - 无 EDNS：实现必须支持接收至少 **512 字节**（RFC 1035）。
  - 有 EDNS：长度限制由 **EDNS UDP payload size** + 传输层限制决定（常见 4096 或更大，RFC 6891）。
- **TCP**
  - 报文前有 **2 字节长度字段**（RFC 7766），长度 ≤ 65535。
  - 内部 DNS 消息本身也不能超过 65535 字节。

#### 1.1.2 合法性校验要点
- **消息长度 < 12 字节**（无法容纳 header）⇒ **Error**。
- 各 section 实际解析出的条目数必须与 header 中的 `QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT` 一致（RFC 1035 4.1.1）⇒ 不一致为 **Error**（TC=0 时）。
- **消息整体长度 > 65535** ⇒ **Error**。

> 备注：`TC`（截断）属于 header flags 语义，不等同于“解析数量不一致”。

---

### 1.2 Header（12 字节）的字段与限制（RFC 1035 4.1.1）

Header 布局：

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

#### 1.2.1 ID（Transaction ID）
- 16 bit 无符号整数。
- **响应必须回显请求的 ID**（RFC 1035 4.1.1）。
- 单包字段合法性：`0..65535` 任意值均可。
- **请求与响应配对校验**：响应包的 `ID != 对应请求ID` ⇒ **Error**（见“字段关联规则/请求响应之间”）。

#### 1.2.2 QR（Query/Response）
- `0`=Query，`1`=Response。
- **客户端发出请求**：`QR` 应为 0，否则 **Error**。
- **服务器发出响应**：`QR` 必须为 1，否则 **Error**。

#### 1.2.3 Opcode（4 bit）
常见值：
- `0` QUERY
- `2` STATUS
- `4` NOTIFY（RFC 1996）
- `5` UPDATE（RFC 2136）

校验：
- 对普通查询/响应：`Opcode != 0` ⇒ **Warning**。
- `Opcode` 不在 `{0, 2, 4, 5}` ⇒ **Error**（保留/未知操作码不应出现在严格校验对象中）。

#### 1.2.4 AA（Authoritative Answer）
- 仅响应中有意义。
- 查询包中的 `AA` 理论上应为 0。

校验：
- 查询包 `AA != 0` ⇒ **Warning**。

#### 1.2.5 TC（Truncated）
- UDP 响应超出可发送大小时应截断并置 `TC=1`。

校验：
- 查询包 `TC != 0` ⇒ **Error**。
- 响应包 `TC=1`：不代表格式错误，但代表内容不完整 ⇒ **Warning**。

#### 1.2.6 RD（Recursion Desired）
- 请求中置 1 表示希望递归。
- 响应通常回显请求的 RD。

校验：
- **如果请求 RD=1，则响应 RD 也必须为 1**，否则 **Error**。

#### 1.2.7 RA（Recursion Available）
- 仅响应中有意义。
- 请求中一般应为 0。

校验：
- 请求 `RA=1` ⇒ **Warning**。

#### 1.2.8 Z / AD / CD（保留位 + DNSSEC 位）
- RFC 1035：保留位 Z 必须为 0。
- RFC 4035 引入 AD/CD。

校验：
- `Z`（保留位）不为 0 ⇒ **Error**。
- `AD/CD` 任意组合值都允许（语义约束见关联规则）。

#### 1.2.9 RCODE（4 bit 基本 + EDNS 扩展）
- 基础 RCODE（4 bit，RFC 1035）：0..15。
- EDNS 扩展：通过 OPT 的 EXTENDED-RCODE（高 8 bit）与 header 低 4 bit 组合成 12-bit（RFC 6891）。

校验：
- **无 EDNS**：RCODE > 5 ⇒ **Warning**（保留/未知错误码）。
- **有 EDNS**：组合后的 RCODE 未知也应接受，但若组合值 **> 22** ⇒ **Warning**（超出常见/已注册范围）。

#### 1.2.10 QDCOUNT / ANCOUNT / NSCOUNT / ARCOUNT
TC=0 时校验：
- 解析出的 Question 数量 != `QDCOUNT` ⇒ **Error**。
- 解析出的 Answer RR 数量 != `ANCOUNT` ⇒ **Error**。
- 解析出的 Authority RR 数量 != `NSCOUNT` ⇒ **Error**。
- 解析出的 Additional RR 数量 != `ARCOUNT` ⇒ **Error**。

额外约束：
- 请求体中 `ANCOUNT > 0` ⇒ **Warning**（请求通常不带 Answer）。
- 请求体中 `NSCOUNT > 0` ⇒ **Warning**（请求通常不带 Authority）。
- 标准查询：`QDCOUNT = 1` 是惯例，`QDCOUNT > 1` ⇒ **Warning**（规范不禁止但几乎不被支持）。

---

### 1.3 Question Section（RFC 1035 4.1.2）
Question 格式：
- `QNAME`：domain name（允许压缩指针）
- `QTYPE`：16 bit
- `QCLASS`：16 bit

#### 1.3.1 QNAME（域名编码，RFC 1035 3.1）
- label 序列，每个 label：`[len:1][content:len]`，`len` 范围 0..63。
- 以 `0x00` 结尾表示根（“.”）。
- 压缩指针：高两 bit = `11`（0xC0），低 14 bit 为偏移。

校验：
- 任一 label 长度 > 63 ⇒ **Error**。
- 名字总长度（含长度字节）> 255 ⇒ **Error**。
- **实现级增强校验**：非根 label 的内容不允许出现不可打印字符（例如控制字符）。这是比 RFC 允许“任意 octet”更严格的约束，用于发现抓包中明显异常/不可展示的域名数据 ⇒ **Warning**。
- 压缩指针：
  - 只能出现在 `QNAME` / `RR NAME` / RDATA 中“域名字段”里 ⇒ 否则 **Error**。
  - 指针偏移必须在消息范围内 ⇒ 越界 **Error**。
  - 必须检测指针循环/无限递归 ⇒ 发现循环 **Error**。

#### 1.3.2 QTYPE（16 bit）
校验：
- 未知 QTYPE 必须接受（RFC 3597），可按 opaque 处理。
- `QTYPE > 255` ⇒ **Warning**（非常见/扩展类型）。
- Question 中不允许出现伪 RR 类型（如 `OPT=41`）⇒ **Error**。

#### 1.3.3 QCLASS（16 bit）
校验：
- 非 `IN(1)` ⇒ **Warning**。

---

### 1.4 Resource Record（RR）通用格式（RFC 1035 3.2.1 / 4.1.3）
RR 格式：
- `NAME`（域名，允许压缩）
- `TYPE`（16 bit）
- `CLASS`（16 bit）
- `TTL`（32 bit）
- `RDLENGTH`（16 bit）
- `RDATA`（RDLENGTH 字节）

#### 1.4.1 NAME
同 QNAME 规则：label ≤ 63，总长 ≤ 255，指针合法且无环。

#### 1.4.2 TYPE / CLASS
校验：
- RR 的 `TYPE` 不允许为 `ANY(255)` ⇒ **Error**。
- `CLASS != IN(1)` ⇒ **Warning**。

#### 1.4.3 TTL
校验：
- `TTL` 为无符号 32 bit，`0..4294967295` 都合法。
- `TTL > 2147483647` ⇒ **Warning**（避免实现误用有符号导致负数/溢出）。

#### 1.4.4 RDLENGTH / RDATA（长度与越界）
校验：
- `RDLENGTH` 不得导致越过消息末尾 ⇒ 越界 **Error**。
- 已知类型可做基本长度校验（示例）：
  - A：`RDLENGTH == 4`，否则 **Error**。
  - AAAA：`RDLENGTH == 16`，否则 **Error**。
  - SOA：至少包含 2 个域名 + 5×32bit，否则 **Error**。
- 未知类型（RFC 3597）：只要不越界即可。

---

### 1.5 EDNS(0)：OPT 伪 RR（RFC 6891）
- OPT RR **只允许出现在 Additional Section**。
- 严格校验：每条消息 **最多 1 个 OPT**，>1 可视为 FORMERR。

#### 1.5.1 OPT RR 字段约束
- `NAME`：必须为 root（单字节 `0x00`）⇒ 否则 **Error**。
- `TYPE`：必须为 `41` ⇒ 否则 **Error**。
- `CLASS`：UDP payload size（16 bit）
  - `0` 无意义 ⇒ **Warning**。
  - `< 512` ⇒ **Warning**（严格实现通常要求至少 512）。
- `TTL` 被拆成：
  - EXTENDED-RCODE（高 8 bit）
  - EDNS Version（中 8 bit）
  - Z/Flags（低 16 bit，含 DO 位）

#### 1.5.2 EXTENDED-RCODE
校验：
- 请求包中 EXTENDED-RCODE 必须为 0 ⇒ 非 0 记 **Error**。

#### 1.5.3 EDNS Version
校验：
- 当前版本为 0（RFC 6891）。
- 请求若 version != 0 ⇒ **Error**（严格校验）。

#### 1.5.4 Z/Flags（含 DO 位）
校验：
- 除 DO 之外的其他保留位不应置 1。
- 若出现除 DO 外的其他 bit 非 0 ⇒ **Warning**（协议违规，通常可忽略这些位）。

#### 1.5.5 EDNS Options（RDATA）
每个 option：
- `OPTION-CODE`（16 bit）
- `OPTION-LENGTH`（16 bit）
- `OPTION-DATA`（OPTION-LENGTH 字节）

校验：
- option 解析不得越界 ⇒ 越界 **Error**。
- 所有 option 的 `(4 + OPTION-LENGTH)` 总和必须等于 OPT 的 `RDLENGTH` ⇒ 不等为 **Error**。
- 未知 option 必须忽略（RFC 6891）⇒ 不应因此报错。

---

### 1.6 ECS（EDNS Client Subnet，RFC 7871，OPTION-CODE=8）
ECS option 数据格式：
- FAMILY：16 bit（1=IPv4，2=IPv6）
- SOURCE PREFIX-LENGTH：8 bit
- SCOPE PREFIX-LENGTH：8 bit
- ADDRESS：可变长，`ceil(SOURCE_PREFIX/8)` 字节

校验：
- `OptionLen == 2 + 1 + 1 + AddressLen`，否则 **Error**。
- FAMILY=1（IPv4）：`AddressLen <= 4`，否则 **Error**。
- FAMILY=2（IPv6）：`AddressLen <= 16`，否则 **Error**。
- prefix 超出地址位数（IPv4>32，IPv6>128）⇒ **Error**。

---

### 1.7 负面响应结构（RFC 2308 视角：NXDOMAIN / NODATA）
校验原则：
- 规范角度不强制“必须有 SOA”，但若有 SOA，其 owner/class/结构必须合法。
- 对权威服务器输出做严格校验时，可加更强约束：
  - NXDOMAIN 或 NOERROR/NODATA 响应建议携带 SOA（用于负缓存 TTL）⇒ 缺失可记 **Warning**。

---

## 2. 字段关联规则（跨字段/跨报文）

### 2.1 基础关联规则（请求与响应之间）
- 收到一个 DNS 响应：
  - **`Header.ID` 必须与之前发出的某个未完成请求的 ID 完全匹配** ⇒ 不匹配为 **Error**。
- 收到一个 DNS 响应：
  - **`Header.Opcode`、`Header.RD`、Question Section 必须与对应请求完全一致（逐字节复制）** ⇒ 不一致为 **Error**。

### 2.2 响应报文内部关联限制

#### 2.2.1 基于 RCODE 的关联限制
- `RCODE = 0 (NoError)`：
  - 若是“有数据的正向回答”，`ANCOUNT` 应 > 0。
  - 若为 NODATA（域名存在但类型不存在），则 `ANCOUNT` 必须为 0。
- `RCODE = 0 且 ANCOUNT = 0 (NODATA)`：
  - `NSCOUNT` 必须 > 0，Authority 必须包含 SOA ⇒ 不满足为 **Error**。
- `RCODE = 3 (NXDOMAIN)`：
  - `ANCOUNT` 必须为 0 ⇒ 否则 **Warning**。
  - `NSCOUNT` 必须 > 0 且 Authority 必须包含 SOA ⇒ 不满足为 **Error**。
- `RCODE ∈ {1,2,4,5}`（FormErr/ServFail/NotImp/Refused）：
  - `ANCOUNT/NSCOUNT/ARCOUNT` 通常应为 0 ⇒ 若不为 0 记 **Warning**（实现可能仍带解释性记录，但不常见）。

#### 2.2.2 基于 Flags 的关联限制
- `Header.TC = 1`：
  - 只能在 **UDP 响应**中为 1。
  - **TCP 响应中 `TC` 必须为 0** ⇒ 否则 **Error**。
- `Header.AA = 1`：
  - 表示权威性语义提示，本规则不做“权威真实性”判断。

#### 2.2.3 基于 Answer 内容的关联限制
- Answer 包含 **CNAME**：
  - 同一个 owner name 不应同时拥有“除 DNSSEC 相关记录外”的其他类型记录（RFC 1034 3.6.2） ⇒ 冲突为 **Error**。
- Answer 包含 **DNAME**：
  - 与 CNAME 类似：同 owner 不应与其他类型并存（DNSSEC 记录除外） ⇒ 冲突为 **Error**。

### 2.3 EDNS(0) 相关关联限制
- 报文包含 OPT：
  - **最多一个 OPT**；OPT 必须在 Additional Section ⇒ 否则 **Error**。
- 请求包含 ECS：
  - 若响应也包含 ECS：
    - `Family` 与 `Source Netmask` 必须与请求一致 ⇒ 否则 **Error**。
    - `Scope Netmask <= Source Netmask` ⇒ 否则 **Warning**。

### 2.4 DNSSEC 相关关联限制（RFC 4033-4035 / 5155）
- 请求 DO=1：
  - 服务器应尽量返回 DNSSEC 相关记录（如 RRSIG/DS/DNSKEY），缺失可记 **Warning**（与实现策略相关）。
- 响应 AD=1：
  - `AD` 不应与 `CD` 同时为 1 ⇒ 同时为 1 记 **Error**。
  - `AD=1` 时 RCODE 应为成功类（如 NoError/NXDOMAIN），不应为 ServFail ⇒ 否则 **Error**。
- 请求 CD=1：
  - 响应 `CD` 必须回显为 1 ⇒ 否则 **Error**。
  - 响应 `AD` 必须为 0 ⇒ 否则 **Error**。
- 响应包含 RRSIG：
  - RRSIG 应伴随其签名的 RRset 同时出现 ⇒ 缺失为 **Error**。
- NXDOMAIN 或 NODATA 且 DO=1：
  - Authority 应包含 NSEC 或 NSEC3 证明 ⇒ 缺失为 **Warning**（与权威实现策略相关）。

### 2.5 DNS 请求报文内部关联限制
- `Opcode = 0 (QUERY)`：
  - `QDCOUNT` 通常必须为 1；`QDCOUNT=0` ⇒ **Error**；`QDCOUNT>1` ⇒ **Warning**。
  - `ANCOUNT` 和 `NSCOUNT` 应为 0 ⇒ 若不为 0 记 **Warning**。
- `Opcode = 5 (UPDATE)`：
  - `QDCOUNT` 必须为 1。
  - `NSCOUNT`（Prerequisite）与 `ANCOUNT`（Update）由 UPDATE 语义决定，这里仅做数量与解析一致性检查。
- `ARCOUNT = 1`：
  - Additional 的那条记录若不是 OPT ⇒ **Warning**（标准查询中非常不常见）。

---

## 3. 通用合规性原则
- **未知 TYPE / CLASS / EDNS option**：必须允许存在，按 opaque 处理；只有越界/结构非法才算错误。
- **域名语义 vs 格式**：wire-format 里域名可为任意 octet 序列；不能因为“不像合法主机名”就判为格式错误。
- **CNAME 与其他类型并存**属于“语义冲突”，但仍可在此作为协议层检查项（因为 RFC 明确约束）。
- **压缩指针**：
  - 仅限域名字段使用；
  - 必须指向消息内部；
  - 必须检测循环与越界。
