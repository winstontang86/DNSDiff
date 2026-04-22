package validate

import (
	"fmt"

	"github.com/miekg/dns"
)

// validateAssociation 执行请求与响应之间的关联校验
func validateAssociation(result *ValidationResult, reqResult *ValidationResult, reqMsg, rspMsg *dns.Msg) {
	if reqResult == nil || reqMsg == nil || rspMsg == nil {
		return
	}

	reqHeader := reqResult.RawHeader
	rspHeader := result.RawHeader

	if reqHeader == nil || rspHeader == nil {
		return
	}

	// A01: 响应ID必须与请求ID匹配
	if reqHeader.ID != rspHeader.ID {
		result.AddError(ErrAssocIDMismatch,
			fmt.Sprintf("ID不匹配: 请求=%d, 响应=%d", reqHeader.ID, rspHeader.ID))
	}

	// A02: 响应Opcode必须与请求Opcode匹配
	if reqHeader.Opcode != rspHeader.Opcode {
		result.AddError(ErrAssocOpcodeMismatch,
			fmt.Sprintf("Opcode不匹配: 请求=%d, 响应=%d", reqHeader.Opcode, rspHeader.Opcode))
	}

	// A03: 如果请求RD=1，响应RD也应为1
	if reqHeader.RD && !rspHeader.RD {
		result.AddError(ErrAssocRDMismatch, "RD不匹配: 请求RD=1但响应RD=0")
	}

	// A04: 响应Question必须与请求Question匹配
	reqQCount := len(reqMsg.Question)
	rspQCount := len(rspMsg.Question)

	if reqQCount != rspQCount {
		result.AddError(ErrAssocQuestionMismatch,
			fmt.Sprintf("Question数量不匹配: 请求=%d, 响应=%d", reqQCount, rspQCount))
	} else {
		for i := 0; i < reqQCount; i++ {
			reqQ := reqMsg.Question[i]
			rspQ := rspMsg.Question[i]

			if reqQ.Name != rspQ.Name || reqQ.Qtype != rspQ.Qtype || reqQ.Qclass != rspQ.Qclass {
				result.AddError(ErrAssocQuestionMismatch,
					fmt.Sprintf("Question[%d]不匹配: 请求=%s/%d/%d, 响应=%s/%d/%d",
						i, reqQ.Name, reqQ.Qtype, reqQ.Qclass,
						rspQ.Name, rspQ.Qtype, rspQ.Qclass))
				break
			}
		}
	}

	// DNSSEC相关的关联检查
	validateDNSSECAssociation(result, reqHeader, rspHeader)

	// RCODE相关的关联检查
	validateRcodeAssociation(result, rspHeader, rspMsg)

	// ECS关联检查
	if reqResult.RequestECS != nil && result.ResponseECS != nil {
		validateECSAssociation(result, reqResult.RequestECS, result.ResponseECS)
	}

	// Answer内容关联检查
	validateAnswerAssociation(result, rspMsg)
}

// validateDNSSECAssociation 检查DNSSEC相关字段的关联
func validateDNSSECAssociation(result *ValidationResult, reqHeader, rspHeader *RawHeaderInfo) {
	// A11: AD=1和CD=1互斥
	if rspHeader.AD && rspHeader.CD {
		result.AddError(ErrAssocADWithCD, "响应中AD=1和CD=1互斥")
	}

	// A12: 如果请求CD=1，响应CD也必须为1
	if reqHeader.CD && !rspHeader.CD {
		result.AddError(ErrAssocCDNotCopied, "CD不匹配: 请求CD=1但响应CD=0")
	}

	// A13: 如果请求CD=1，响应AD应为0
	if reqHeader.CD && rspHeader.AD {
		result.AddWarning(WarnAssocADWithCDRequest,
			"响应中AD=1但请求CD=1(禁用检查)")
	}
}

// validateRcodeAssociation 检查RCODE相关的关联
func validateRcodeAssociation(result *ValidationResult, rspHeader *RawHeaderInfo, rspMsg *dns.Msg) {
	rcode := rspHeader.Rcode
	anCount := len(rspMsg.Answer)
	nsCount := len(rspMsg.Ns)
	arCount := len(rspMsg.Extra)

	switch rcode {
	case dns.RcodeSuccess: // NOERROR (0)
		// A08: RCODE=0但完全没有记录
		if anCount == 0 && nsCount == 0 && arCount == 0 {
			result.AddError(ErrAssocNoErrorEmpty,
				"RCODE=0(NoError)但ANCOUNT+NSCOUNT+ARCOUNT=0")
		}

		// A05: NODATA(RCODE=0, ANCOUNT=0)应在Authority中有SOA
		if anCount == 0 && nsCount > 0 {
			hasSOA := false
			for _, rr := range rspMsg.Ns {
				if _, ok := rr.(*dns.SOA); ok {
					hasSOA = true
					break
				}
			}
			if !hasSOA {
				result.AddWarning(WarnAssocNODATANoAuthority,
					"NODATA响应(RCODE=0, ANCOUNT=0)但Authority段中无SOA")
			}
		}

	case dns.RcodeNameError: // NXDOMAIN (3)
		// A06: NXDOMAIN不应有Answer记录
		if anCount > 0 {
			result.AddWarning(WarnAssocNXDOMAINHasAnswer,
				fmt.Sprintf("NXDOMAIN但ANCOUNT=%d (应为0)", anCount))
		}

		// A07: NXDOMAIN应在Authority中有SOA
		hasSOA := false
		for _, rr := range rspMsg.Ns {
			if _, ok := rr.(*dns.SOA); ok {
				hasSOA = true
				break
			}
		}
		if !hasSOA {
			result.AddWarning(WarnAssocNXDOMAINNoAuthority,
				"NXDOMAIN响应但Authority段中无SOA")
		}

	case dns.RcodeFormatError, dns.RcodeServerFailure, dns.RcodeNotImplemented, dns.RcodeRefused:
		// A09: 错误响应(1,2,4,5)通常不应有记录
		if anCount > 0 || nsCount > 0 {
			result.AddWarning(WarnAssocErrorHasRecords,
				fmt.Sprintf("错误响应(RCODE=%d)但包含记录: AN=%d, NS=%d",
					rcode, anCount, nsCount))
		}
	}
}

// validateECSAssociation 检查请求与响应之间的ECS相关关联
func validateECSAssociation(result *ValidationResult, reqECS, rspECS *ECSInfo) {
	// A14: 响应ECS Family必须与请求ECS Family匹配
	if reqECS.Family != rspECS.Family {
		result.AddError(ErrAssocECSFamilyMismatch,
			fmt.Sprintf("ECS Family不匹配: 请求=%d, 响应=%d",
				reqECS.Family, rspECS.Family))
	}

	// A15: 响应ECS SourcePrefix必须与请求ECS SourcePrefix匹配
	if reqECS.SourcePrefix != rspECS.SourcePrefix {
		result.AddError(ErrAssocECSSourcePrefixMismatch,
			fmt.Sprintf("ECS SourcePrefix不匹配: 请求=%d, 响应=%d",
				reqECS.SourcePrefix, rspECS.SourcePrefix))
	}

	// A16: 响应ScopePrefix应 <= 请求SourcePrefix
	if rspECS.ScopePrefix > reqECS.SourcePrefix {
		result.AddWarning(WarnAssocECSScopeTooLarge,
			fmt.Sprintf("ECS ScopePrefix=%d > SourcePrefix=%d",
				rspECS.ScopePrefix, reqECS.SourcePrefix))
	}
}

// validateAnswerAssociation 检查Answer段内容的关联
func validateAnswerAssociation(result *ValidationResult, rspMsg *dns.Msg) {
	if rspMsg == nil || len(rspMsg.Answer) == 0 {
		return
	}

	// 按所有者名称分组记录
	recordsByName := make(map[string][]dns.RR)
	for _, rr := range rspMsg.Answer {
		name := rr.Header().Name
		recordsByName[name] = append(recordsByName[name], rr)
	}

	// 检查每个名称组中的CNAME/DNAME冲突
	for name, records := range recordsByName {
		hasDNAME := false
		hasOther := false

		for _, rr := range records {
			rrtype := rr.Header().Rrtype
			switch rrtype {
			case dns.TypeDNAME:
				hasDNAME = true
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
				// DNSSEC记录允许与CNAME/DNAME共存
			default:
				hasOther = true
			}
		}

		// A18: DNAME不应与其他类型共存(DNSSEC除外)
		if hasDNAME && hasOther {
			result.AddWarning(WarnAssocDNAMEWithOther,
				fmt.Sprintf("名称%s的DNAME记录与其他类型共存", name))
		}
	}
}

// validateResponseInternal 执行响应的内部一致性检查
func validateResponseInternal(result *ValidationResult, rspMsg *dns.Msg, isTCP bool) {
	if rspMsg == nil || result.RawHeader == nil {
		return
	}

	// A10: TCP中不应出现TC=1
	if isTCP && result.RawHeader.TC {
		result.AddWarning(WarnAssocTCInTCP, "TCP响应中TC=1(不应被截断)")
	}
}
