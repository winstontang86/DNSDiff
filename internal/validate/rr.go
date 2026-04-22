package validate

import (
	"fmt"

	"github.com/miekg/dns"
)

// MaxTTLValue 最大安全TTL值(2^31-1, 避免被当作负数解释)
const MaxTTLValue uint32 = 2147483647

// ECSOptionCode ECS选项码
const ECSOptionCode = 8

// validateResourceRecords 校验Answer、Authority和Additional段
func validateResourceRecords(result *ValidationResult, msg *dns.Msg, isRequest bool) {
	if msg == nil {
		return
	}

	// 校验Answer段
	for i, rr := range msg.Answer {
		validateRR(result, rr, "Answer", i)
	}

	// 校验Authority段
	for i, rr := range msg.Ns {
		validateRR(result, rr, "Authority", i)
	}

	// 校验Additional段并检查OPT记录
	var optRecord *dns.OPT
	optCount := 0
	for i, rr := range msg.Extra {
		validateRR(result, rr, "Additional", i)

		// 统计和跟踪OPT记录以进行EDNS校验
		if opt, ok := rr.(*dns.OPT); ok {
			optCount++
			if optRecord == nil {
				optRecord = opt
			}
		}
	}

	// E03: 只允许一个OPT记录
	if optCount > 1 {
		result.AddError(ErrEDNSMultipleOPT,
			fmt.Sprintf("存在多个OPT记录: 发现%d个 (最多1个)", optCount))
	}

	// 如果存在OPT记录则校验EDNS
	if optRecord != nil {
		validateEDNS(result, optRecord, isRequest)
	}
}

// validateRR 校验单个资源记录
func validateRR(result *ValidationResult, rr dns.RR, section string, index int) {
	if rr == nil {
		return
	}

	header := rr.Header()
	if header == nil {
		return
	}

	// 跳过OPT记录，它们单独校验
	if header.Rrtype == dns.TypeOPT {
		if section != "Additional" {
			result.AddError(ErrEDNSOPTNotInAdditional,
				fmt.Sprintf("%s[%d]中出现OPT记录 (必须在Additional段)", section, index))
		}
		return
	}

	// 校验RR名称(与QNAME相同的规则)
	validateDomainName(result, header.Name, index)

	// R05: TYPE=255(ANY)不应在RR中使用
	if header.Rrtype == dns.TypeANY {
		result.AddError(ErrRRTypeANY,
			fmt.Sprintf("%s[%d]中TYPE=ANY(255) (不应在RR中使用)", section, index))
	}

	// R06: CLASS != IN(1)不寻常
	if header.Class != dns.ClassINET && header.Class != dns.ClassANY && header.Class != dns.ClassNONE {
		result.AddWarning(WarnRRClassNotIN,
			fmt.Sprintf("%s[%d]中CLASS=%d (期望1/IN)", section, index, header.Class))
	}

	// R07: TTL > 2^31-1可能被当作负数处理
	if header.Ttl > MaxTTLValue {
		result.AddWarning(WarnRRTTLTooHigh,
			fmt.Sprintf("%s[%d]中TTL=%d (>2^31-1可能被当作负数)", section, index, header.Ttl))
	}

	// TTL=0警告
	if header.Ttl == 0 {
		result.AddWarning(WarnRRTTLZero,
			fmt.Sprintf("%s[%d]中TTL=0", section, index))
	}

	// 类型特定的RDLENGTH校验
	validateRRRdataLength(result, rr, section, index)
}

// validateRRRdataLength 执行类型特定的RDLENGTH校验
func validateRRRdataLength(result *ValidationResult, rr dns.RR, section string, index int) {
	header := rr.Header()

	switch rr.(type) {
	case *dns.A:
		// R09: A记录RDLENGTH必须为4
		if header.Rdlength != 4 {
			result.AddError(ErrRRTypeA_RdLen,
				fmt.Sprintf("%s[%d]中A记录RDLENGTH=%d (期望4)", section, index, header.Rdlength))
		}

	case *dns.AAAA:
		// R10: AAAA记录RDLENGTH必须为16
		if header.Rdlength != 16 {
			result.AddError(ErrRRTypeAAAA_RdLen,
				fmt.Sprintf("%s[%d]中AAAA记录RDLENGTH=%d (期望16)", section, index, header.Rdlength))
		}

	case *dns.SOA:
		// R11: SOA记录RDLENGTH必须至少为2个域名 + 5*4字节
		// 最小值: 1(根名) + 1(根名) + 20 = 22字节
		if header.Rdlength < 22 {
			result.AddError(ErrRRTypeSOA_RdLen,
				fmt.Sprintf("%s[%d]中SOA记录RDLENGTH=%d (过短, 最小约22)", section, index, header.Rdlength))
		}
	}

	// 由于部分RR类型在miekg/dns中可能无法完整解析为具体结构体，
	// 这里补充基于 rr.Header().Rrtype 的RDLENGTH基础约束校验。
	// NAPTR (RFC 3403): ORDER(2) + PREFERENCE(2) + 3个<character-string>(每个至少1字节len) + REPLACEMENT(至少1字节root)
	// 最小RDLENGTH = 2+2 + (1+1+1) + 1 = 8
	if header.Rrtype == dns.TypeNAPTR {
		if header.Rdlength < 8 {
			result.AddError(ErrRRTypeNAPTR_RdLen,
				fmt.Sprintf("%s[%d]中NAPTR记录RDLENGTH=%d (过短, 最小8)", section, index, header.Rdlength))
		}
	}
}

// validateEDNS 校验EDNS OPT记录
func validateEDNS(result *ValidationResult, opt *dns.OPT, isRequest bool) {
	if opt == nil {
		return
	}

	header := opt.Header()

	// E01: OPT NAME必须为root(空名称 = ".")
	if header.Name != "." {
		result.AddError(ErrEDNSOPTNameNotRoot,
			fmt.Sprintf("OPT NAME='%s' (必须为root '.')", header.Name))
	}

	// E02: OPT必须在Additional段中(在validateRR中按段检查)
	// 已在段迭代期间检查

	// 解析TTL字段获取EDNS参数
	ttl := opt.Hdr.Ttl
	extendedRcode := uint8((ttl >> 24) & 0xFF)
	version := uint8((ttl >> 16) & 0xFF)
	zFlags := uint16(ttl & 0xFFFF)
	doFlag := (zFlags & 0x8000) != 0

	// E06: 请求中EXTENDED-RCODE必须为0
	if isRequest && extendedRcode != 0 {
		result.AddError(ErrEDNSExtRcodeInReq,
			fmt.Sprintf("请求中EXTENDED-RCODE=%d (必须为0)", extendedRcode))
	}

	// E07: EDNS版本必须为0
	if version != 0 {
		result.AddError(ErrEDNSVersionNotZero,
			fmt.Sprintf("EDNS版本=%d (仅支持版本0)", version))
	}

	// E08: Z flags(除DO位外)必须为0
	reservedFlags := zFlags & 0x7FFF // 除DO外的所有位
	if reservedFlags != 0 {
		result.AddWarning(WarnEDNSZFlagsReserved,
			fmt.Sprintf("EDNS Z flags保留位被设置: 0x%04X (DO=%v)", reservedFlags, doFlag))
	}

	// E04/E05: UDP Payload Size检查
	udpSize := opt.UDPSize()
	if udpSize == 0 {
		result.AddWarning(WarnEDNSUDPSizeZero, "EDNS UDP payload size为0")
	} else if udpSize < 512 {
		result.AddWarning(WarnEDNSUDPSizeSmall,
			fmt.Sprintf("EDNS UDP payload size=%d (<512)", udpSize))
	}

	// 校验EDNS选项
	validateEDNSOptions(result, opt, isRequest)

	// 存储扩展RCODE用于RCODE校验
	result.ExtendedRcode = extendedRcode
}

// validateEDNSOptions 校验EDNS选项包括ECS
func validateEDNSOptions(result *ValidationResult, opt *dns.OPT, isRequest bool) {
	if opt == nil {
		return
	}

	for _, option := range opt.Option {
		if option == nil {
			continue
		}

		// ECS选项校验
		if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
			validateECS(result, ecs, isRequest)
		}
	}
}

// validateECS 校验EDNS Client Subnet选项
func validateECS(result *ValidationResult, ecs *dns.EDNS0_SUBNET, isRequest bool) {
	if ecs == nil {
		return
	}

	family := ecs.Family
	sourcePrefix := ecs.SourceNetmask
	scopePrefix := ecs.SourceScope

	// 计算预期地址长度
	expectedAddrLen := (int(sourcePrefix) + 7) / 8

	switch family {
	case 1: // IPv4
		// E11: IPv4地址长度必须 <= 4
		if expectedAddrLen > 4 {
			result.AddError(ErrECSIPv4AddrLen,
				fmt.Sprintf("ECS IPv4 source prefix=%d 需要>4字节", sourcePrefix))
		}
		// E13: IPv4前缀必须 <= 32
		if sourcePrefix > 32 {
			result.AddError(ErrECSPrefixTooLarge,
				fmt.Sprintf("ECS IPv4 source prefix=%d (最大32)", sourcePrefix))
		}

	case 2: // IPv6
		// E12: IPv6地址长度必须 <= 16
		if expectedAddrLen > 16 {
			result.AddError(ErrECSIPv6AddrLen,
				fmt.Sprintf("ECS IPv6 source prefix=%d 需要>16字节", sourcePrefix))
		}
		// E13: IPv6前缀必须 <= 128
		if sourcePrefix > 128 {
			result.AddError(ErrECSPrefixTooLarge,
				fmt.Sprintf("ECS IPv6 source prefix=%d (最大128)", sourcePrefix))
		}

	default:
		// 未知family - 可能是未来扩展，不报错
	}

	// 存储ECS信息用于关联校验
	if isRequest {
		result.RequestECS = &ECSInfo{
			Family:       family,
			SourcePrefix: sourcePrefix,
			ScopePrefix:  scopePrefix,
		}
	} else {
		result.ResponseECS = &ECSInfo{
			Family:       family,
			SourcePrefix: sourcePrefix,
			ScopePrefix:  scopePrefix,
		}
	}

	// 请求中scope prefix应为0
	if isRequest && scopePrefix != 0 {
		result.AddWarning(WarnECSScopePrefixNonZero,
			fmt.Sprintf("请求中ECS scope prefix=%d (应为0)", scopePrefix))
	}
}
