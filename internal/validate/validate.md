# validate 包文档

`validate` 包提供了对 DNS 报文（请求和响应）进行深度校验的功能，旨在发现不符合 RFC 规范或潜在的异常行为。它不仅支持单个报文的格式校验，还支持请求与响应之间的关联校验。

## 主要功能

1.  **报文结构校验**：检查报文长度、格式完整性、尾部多余数据等。
2.  **头部校验**：检查 DNS 头部字段（如 QR, Opcode, Z, RCODE 等）是否符合规范。
3.  **段校验**：
    *   **Question**: 检查域名长度、标签长度、QTYPE/QCLASS 有效性。
    *   **Resource Records**: 检查 RR 格式、TTL、Class、特定类型（A, AAAA, SOA）的 RDLENGTH。
4.  **EDNS 校验**：检查 OPT 记录的位置、版本、扩展 RCODE、Z 标志位等。
5.  **ECS (EDNS Client Subnet) 校验**：检查 ECS 选项的格式、地址长度、前缀范围。
6.  **关联校验**：对比请求和响应，检查 ID、Opcode、Question、ECS 信息的一致性，以及逻辑上的合理性（如 NXDOMAIN 不应有 Answer）。

## 主要 API

### `ValidateReq`
```go
func ValidateReq(rawReq []byte) (errBits, warningBits uint64, msg *dns.Msg, err error)
```
校验 DNS 请求报文。
- **输入**: 原始请求字节。
- **输出**: 错误位、警告位、解析后的 `dns.Msg` 对象、致命错误。

### `ValidateRsp`
```go
func ValidateRsp(rawReq, rawRsp []byte) (errBits, warningBits uint64, msg *dns.Msg, err error)
```
校验 DNS 响应报文，并可选地执行关联校验。
- **输入**: 原始请求字节（可选，若为 nil 则不进行关联校验）、原始响应字节。
- **输出**: 错误位、警告位、解析后的 `dns.Msg` 对象、致命错误。

### `ValidateRaw`
```go
func ValidateRaw(rawData []byte) (errBits, warningBits uint64, msg *dns.Msg, isResponse bool, err error)
```
校验原始 DNS 报文，自动根据 QR 位判断是请求还是响应。

## 校验规则

校验结果通过 `uint64` 类型的位掩码返回，分为错误（Error）和警告（Warning）。

### 错误码 (Error Bits)

表示严重的格式错误或违规。

| 位 | 名称 | 描述 |
| :--- | :--- | :--- |
| **消息结构** | | |
| 0 | `ErrMsgTooShort` | 消息长度 < 12 字节 |
| 1 | `ErrMsgTooLong` | 消息长度 > 65535 字节 |
| 2 | `ErrMsgSectionCountMismatch` | TC=0 时 Header 计数与实际解析不符 |
| 3 | `ErrFormUnpack` | `dns.Msg.Unpack` 解析失败 |
| 4 | `ErrDataTrailing` | 解析后存在多余尾部数据 |
| **Header** | | |
| 7 | `ErrHeaderQRReq` | 请求包 QR != 0 |
| 8 | `ErrHeaderQRRsp` | 响应包 QR != 1 |
| 9 | `ErrHeaderOpcodeInvalid` | Opcode 无效 (非 0, 2, 4, 5) |
| 10 | `ErrHeaderTCReq` | 请求包 TC != 0 |
| 11 | `ErrHeaderZNotZero` | Z 位 (保留位) != 0 |
| 12 | `ErrHeaderCountMismatch` | Header 计数与实际记录数不匹配 |
| **Question** | | |
| 15 | `ErrQNameLabelTooLong` | 标签长度 > 63 |
| 16 | `ErrQNameTooLong` | 域名总长度 > 255 |
| 17 | `ErrQNamePtrOutOfBounds` | 压缩指针越界 |
| 18 | `ErrQNamePtrLoop` | 压缩指针循环 |
| 19 | `ErrQTypeOPT` | Question 段出现 OPT 记录 |
| 20 | `ErrQuestionNoQuestion` | 查询包中无 Question |
| 21 | `ErrQNameLabelHasNonPrintable` | 标签包含不可打印字符 |
| **Resource Records** | | |
| 23 | `ErrRRTypeANY` | RR 中使用 TYPE=ANY |
| 24 | `ErrRRRdataOverflow` | RDLENGTH 超出消息末尾 |
| 25 | `ErrRRTypeA_RdLen` | A 记录 RDLENGTH != 4 |
| 26 | `ErrRRTypeAAAA_RdLen` | AAAA 记录 RDLENGTH != 16 |
| 27 | `ErrRRTypeSOA_RdLen` | SOA 记录 RDLENGTH 过短 |
| 28 | `ErrRRNamePtrLoop` | RR 名称指针循环 |
| 29 | `ErrRRNamePtrOutOfBounds` | RR 名称指针越界 |
| 30 | `ErrRRTypeNAPTR_RdLen` | NAPTR 记录 RDLENGTH 过短 |
| **EDNS** | | |
| 33 | `ErrEDNSOPTNameNotRoot` | OPT Name != root (.) |
| 34 | `ErrEDNSOPTNotInAdditional` | OPT 不在 Additional 段 |
| 35 | `ErrEDNSMultipleOPT` | 存在多个 OPT 记录 |
| 36 | `ErrEDNSExtRcodeInReq` | 请求中 Extended-RCODE != 0 |
| 37 | `ErrEDNSVersionNotZero` | EDNS Version != 0 |
| 38 | `ErrEDNSOptionsTotalLen` | Options 总长度不匹配 |
| 39 | `ErrEDNSOptionOverflow` | Option 解析溢出 |
| **ECS** | | |
| 43 | `ErrECSIPv4AddrLen` | IPv4 AddressLen > 4 |
| 44 | `ErrECSIPv6AddrLen` | IPv6 AddressLen > 16 |
| 45 | `ErrECSPrefixTooLarge` | Source Prefix 超出范围 |
| 46 | `ErrECSLengthMismatch` | ECS RDLENGTH 不匹配 |
| **关联校验** | | |
| 49 | `ErrAssocIDMismatch` | 响应 ID != 请求 ID |
| 50 | `ErrAssocOpcodeMismatch` | 响应 Opcode != 请求 Opcode |
| 51 | `ErrAssocRDMismatch` | 请求 RD=1 但响应 RD=0 |
| 52 | `ErrAssocQuestionMismatch` | 响应 Question != 请求 Question |
| 54 | `ErrAssocNoErrorEmpty` | RCODE=0 但无记录 |
| 55 | `ErrAssocADWithCD` | AD=1 且 CD=1 (互斥) |
| 56 | `ErrAssocCDNotCopied` | 请求 CD=1 但响应 CD=0 |
| 57 | `ErrAssocECSFamilyMismatch` | ECS Family 不匹配 |
| 58 | `ErrAssocECSSourcePrefixMismatch` | ECS Source Prefix 不匹配 |

### 警告码 (Warning Bits)

表示轻微问题、不推荐的用法或潜在异常。

| 位 | 名称 | 描述 |
| :--- | :--- | :--- |
| **Header** | | |
| 0 | `WarnHeaderOpcodeNonZero` | 标准查询 Opcode != 0 |
| 1 | `WarnHeaderAAInReq` | 请求中 AA != 0 |
| 2 | `WarnHeaderTCInRsp` | 响应 TC=1 (截断) |
| 3 | `WarnHeaderRAInReq` | 请求中 RA=1 |
| 4 | `WarnHeaderRcodeNoEDNS` | 无 EDNS 时 RCODE > 5 |
| 5 | `WarnHeaderRcodeExtUnknown` | 扩展 RCODE > 22 |
| 6 | `WarnHeaderQDCountMultiple` | QDCOUNT > 1 |
| 7 | `WarnHeaderANCountInReq` | 请求中 ANCOUNT > 0 |
| 8 | `WarnHeaderNSCountInReq` | 请求中 NSCOUNT > 0 |
| **Question** | | |
| 11 | `WarnQTypeUnknown` | QTYPE > 255 |
| 12 | `WarnQClassNotIN` | QCLASS != IN |
| **RR** | | |
| 15 | `WarnRRClassNotIN` | RR CLASS != IN |
| 16 | `WarnRRTTLTooHigh` | TTL > 2^31-1 |
| 17 | `WarnRRTTLZero` | TTL = 0 |
| 18 | `WarnRRDeprecatedType` | 已弃用的 RR 类型 |
| 19 | `WarnRRUnusualType` | 不常见的 RR 类型 |
| **EDNS** | | |
| 22 | `WarnEDNSUDPSizeZero` | UDP Payload Size = 0 |
| 23 | `WarnEDNSUDPSizeSmall` | UDP Payload Size < 512 |
| 24 | `WarnEDNSZFlagsReserved` | Z flags 保留位被设置 |
| **关联校验** | | |
| 28 | `WarnAssocNODATANoAuthority` | NODATA 但 Authority 无 SOA |
| 29 | `WarnAssocNXDOMAINNoAuthority` | NXDOMAIN 但 Authority 无 SOA |
| 30 | `WarnAssocErrorHasRecords` | 错误响应包含记录 |
| 31 | `WarnAssocTCInTCP` | TCP 响应中 TC=1 |
| 32 | `WarnAssocADWithCDRequest` | 请求 CD=1 但响应 AD=1 |
| 33 | `WarnAssocECSScopeTooLarge` | 响应 Scope > 请求 Source |
| 34 | `WarnAssocDNAMEWithOther` | DNAME 与其他类型共存 |
| 35 | `WarnECSScopePrefixNonZero` | 请求中 ECS scope prefix 不为 0 |
| 36 | `WarnAssocNXDOMAINHasAnswer` | NXDOMAIN 但 ANCOUNT > 0 |

## 使用示例

```go
package main

import (
	"fmt"
	"github.com/miekg/dns"
	"dns/dnsdiff/internal/validate"
)

func main() {
	// 构造一个示例请求
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	rawReq, _ := req.Pack()

	// 校验请求
	errBits, warnBits, _, err := validate.ValidateReq(rawReq)
	if err != nil {
		fmt.Printf("Fatal error: %v\n", err)
		return
	}

	if validate.HasErrors(errBits) {
		fmt.Printf("Errors: %v\n", validate.GetErrorDescription(errBits))
	}
	if validate.HasWarnings(warnBits) {
		fmt.Printf("Warnings: %v\n", validate.GetWarningDescription(warnBits))
	}
}
```
