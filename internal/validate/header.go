package validate

import (
	"encoding/binary"
	"fmt"

	"github.com/miekg/dns"
)

// DNSHeaderSize DNS头部固定大小(12字节)
const DNSHeaderSize = 12

// MaxMessageLength DNS消息最大长度(65535字节)
const MaxMessageLength = 65535

// ValidOpcodes 有效的opcode值 {0, 2, 4, 5}
var ValidOpcodes = map[int]bool{
	0: true, // QUERY - 标准查询
	2: true, // STATUS - 服务器状态
	4: true, // NOTIFY - 通知
	5: true, // UPDATE - 动态更新
}

// parseRawHeader 直接从原始DNS报文字节中提取头部信息
// 这是必要的，因为miekg/dns在解析过程中可能会修正某些值
func parseRawHeader(data []byte) (*RawHeaderInfo, error) {
	if len(data) < DNSHeaderSize {
		return nil, ErrDataTooShortError
	}

	h := &RawHeaderInfo{}

	// 字节0-1: ID
	h.ID = binary.BigEndian.Uint16(data[0:2])

	// 字节2: QR(1) + Opcode(4) + AA(1) + TC(1) + RD(1)
	flags1 := data[2]
	h.QR = (flags1 & 0x80) != 0          // bit 7
	h.Opcode = int((flags1 >> 3) & 0x0F) // bits 6-3
	h.AA = (flags1 & 0x04) != 0          // bit 2
	h.TC = (flags1 & 0x02) != 0          // bit 1
	h.RD = (flags1 & 0x01) != 0          // bit 0

	// 字节3: RA(1) + Z(1) + AD(1) + CD(1) + RCODE(4)
	// RFC 4035布局: RA(1) + Z(1) + AD(1) + CD(1) + RCODE(4)
	flags2 := data[3]
	h.RA = (flags2 & 0x80) != 0  // bit 7
	h.Z = (flags2 & 0x40) != 0   // bit 6 (Z, 必须为0)
	h.AD = (flags2 & 0x20) != 0  // bit 5 (可信数据)
	h.CD = (flags2 & 0x10) != 0  // bit 4 (禁用检查)
	h.Rcode = int(flags2 & 0x0F) // bits 3-0

	// 字节4-5: QDCOUNT
	h.QDCount = binary.BigEndian.Uint16(data[4:6])

	// 字节6-7: ANCOUNT
	h.ANCount = binary.BigEndian.Uint16(data[6:8])

	// 字节8-9: NSCOUNT
	h.NSCount = binary.BigEndian.Uint16(data[8:10])

	// 字节10-11: ARCOUNT
	h.ARCount = binary.BigEndian.Uint16(data[10:12])

	return h, nil
}

// ErrDataTooShortError 当数据长度不足以构成DNS头部时返回此错误
var ErrDataTooShortError = &ValidationError{Message: "数据长度不足以构成DNS头部"}

// ValidationError 表示一个校验错误
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// validateHeader 检查DNS头部字段是否符合RFC规范
func validateHeader(result *ValidationResult, rawHeader *RawHeaderInfo, msg *dns.Msg, isRequest bool) {
	if rawHeader == nil || msg == nil {
		return
	}

	// H10: 检查Z位(必须为0, RFC 1035/4035)
	if rawHeader.Z {
		result.AddError(ErrHeaderZNotZero, "Z位(保留位)不为零")
	}

	// H05: 检查Opcode有效性 - 必须在{0, 2, 4, 5}范围内
	if !ValidOpcodes[rawHeader.Opcode] {
		result.AddError(ErrHeaderOpcodeInvalid,
			fmt.Sprintf("无效的Opcode: %d (必须为0, 2, 4或5)", rawHeader.Opcode))
	}

	// H04: 对于标准查询，Opcode应为0
	if rawHeader.Opcode != 0 {
		result.AddWarning(WarnHeaderOpcodeNonZero,
			fmt.Sprintf("Opcode为%d (非零, 标准查询应为0)", rawHeader.Opcode))
	}

	// 检查section计数是否匹配(当TC=0时)
	if !rawHeader.TC {
		validateSectionCounts(result, rawHeader, msg)
	}

	// 请求或响应特定的检查
	if isRequest {
		validateRequestHeader(result, rawHeader, msg)
	} else {
		validateResponseHeader(result, rawHeader, msg)
	}
}

// validateSectionCounts 检查原始头部中的section计数是否与解析后的消息匹配
// M03: TC=0时section计数不匹配
func validateSectionCounts(result *ValidationResult, rawHeader *RawHeaderInfo, msg *dns.Msg) {
	var mismatches []string

	// 检查QDCOUNT
	if int(rawHeader.QDCount) != len(msg.Question) {
		mismatches = append(mismatches, fmt.Sprintf("QDCount(原始=%d,解析=%d)", rawHeader.QDCount, len(msg.Question)))
	}

	// 检查ANCOUNT
	if int(rawHeader.ANCount) != len(msg.Answer) {
		mismatches = append(mismatches, fmt.Sprintf("ANCount(原始=%d,解析=%d)", rawHeader.ANCount, len(msg.Answer)))
	}

	// 检查NSCOUNT
	if int(rawHeader.NSCount) != len(msg.Ns) {
		mismatches = append(mismatches, fmt.Sprintf("NSCount(原始=%d,解析=%d)", rawHeader.NSCount, len(msg.Ns)))
	}

	// 检查ARCOUNT
	if int(rawHeader.ARCount) != len(msg.Extra) {
		mismatches = append(mismatches, fmt.Sprintf("ARCount(原始=%d,解析=%d)", rawHeader.ARCount, len(msg.Extra)))
	}

	// 如果有任何不匹配,统一报告一个错误
	if len(mismatches) > 0 {
		result.AddError(ErrHeaderCountMismatch, fmt.Sprintf("Count字段不匹配: %v", mismatches))
	}
}

// validateRequestHeader 检查DNS请求特有的头部字段
func validateRequestHeader(result *ValidationResult, rawHeader *RawHeaderInfo, msg *dns.Msg) {
	// H02: 请求的QR位应为0
	if rawHeader.QR {
		result.AddError(ErrHeaderQRReq, "请求中QR位被设置(应为0)")
	}

	// H07: 请求的TC位应为0
	if rawHeader.TC {
		result.AddError(ErrHeaderTCReq, "请求中TC位被设置(应为0)")
	}

	// H06: 请求中的AA位不寻常(应为0)
	if rawHeader.AA {
		result.AddWarning(WarnHeaderAAInReq, "请求中AA位被设置(不寻常)")
	}

	// H09: 请求中的RA位不寻常(应为0)
	if rawHeader.RA {
		result.AddWarning(WarnHeaderRAInReq, "请求中RA位被设置(不寻常)")
	}

	// H13: 标准查询中QDCOUNT > 1不寻常
	if rawHeader.QDCount > 1 {
		result.AddWarning(WarnHeaderQDCountMultiple,
			fmt.Sprintf("QDCOUNT=%d (>1不寻常)", rawHeader.QDCount))
	}

	// H14: 请求中ANCOUNT > 0不寻常(UPDATE操作除外)
	if rawHeader.ANCount > 0 && rawHeader.Opcode != 5 {
		result.AddWarning(WarnHeaderANCountInReq,
			fmt.Sprintf("请求中ANCOUNT=%d (不寻常)", rawHeader.ANCount))
	}

	// H15: 请求中NSCOUNT > 0不寻常(UPDATE操作除外)
	if rawHeader.NSCount > 0 && rawHeader.Opcode != 5 {
		result.AddWarning(WarnHeaderNSCountInReq,
			fmt.Sprintf("请求中NSCOUNT=%d (不寻常)", rawHeader.NSCount))
	}

	// H11: 无EDNS时RCODE > 5 - 稍后在知道是否有EDNS时检查
	// 此检查在validateRcodeWithEDNS中完成
}

// validateResponseHeader 检查DNS响应特有的头部字段
func validateResponseHeader(result *ValidationResult, rawHeader *RawHeaderInfo, msg *dns.Msg) {
	// H03: 响应的QR位应为1
	if !rawHeader.QR {
		result.AddError(ErrHeaderQRRsp, "响应中QR位未设置(应为1)")
	}

	// H08: TC位表示截断(警告)
	if rawHeader.TC {
		result.AddWarning(WarnHeaderTCInRsp, "响应被截断(TC位被设置)")
	}
}

// validateRcodeWithEDNS 根据EDNS存在情况检查RCODE有效性
func validateRcodeWithEDNS(result *ValidationResult, rawHeader *RawHeaderInfo, hasEDNS bool, extendedRcode uint8) {
	if hasEDNS {
		// 组合扩展RCODE和头部RCODE
		// full_rcode = (EXTENDED-RCODE << 4) | (header_rcode & 0xF)
		fullRcode := (int(extendedRcode) << 4) | (rawHeader.Rcode & 0x0F)

		// H12: 扩展RCODE > 22为未知值
		if fullRcode > 22 {
			result.AddWarning(WarnHeaderRcodeExtUnknown,
				fmt.Sprintf("扩展RCODE=%d (>22为未知值)", fullRcode))
		}
	} else {
		// H11: 无EDNS时，RCODE > 5不寻常
		if rawHeader.Rcode > 5 {
			result.AddWarning(WarnHeaderRcodeNoEDNS,
				fmt.Sprintf("无EDNS时RCODE=%d (>5不寻常)", rawHeader.Rcode))
		}
	}
}
