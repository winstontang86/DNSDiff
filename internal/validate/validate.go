package validate

import (
	"fmt"

	"github.com/miekg/dns"
)

// ValidateReq 校验DNS请求报文
// 参数:
//   - rawReq: 原始DNS请求字节
//
// 返回:
//   - errBits: 表示严重问题的错误位
//   - warningBits: 表示轻微问题的警告位
//   - msg: 解析后的DNS消息(解析失败时为nil)
//   - details: 错误和警告的详细描述
//   - error: 校验无法继续时的致命错误
func ValidateReq(rawReq []byte) (errBits, warningBits uint64, msg *dns.Msg, details []string, err error) {
	result := NewValidationResult()

	// M01: 检查最小数据长度(12字节)
	if len(rawReq) < DNSHeaderSize {
		result.AddError(ErrMsgTooShort,
			fmt.Sprintf("消息过短: %d字节 (最小%d)", len(rawReq), DNSHeaderSize))
		return result.ErrorBits, result.WarningBits, nil, result.Details, nil
	}

	// M02: 检查最大数据长度(65535字节)
	if len(rawReq) > MaxMessageLength {
		result.AddError(ErrMsgTooLong,
			fmt.Sprintf("消息过长: %d字节 (最大%d)", len(rawReq), MaxMessageLength))
		return result.ErrorBits, result.WarningBits, nil, result.Details, nil
	}

	// 步骤2: 解析原始头部以获取miekg/dns可能修正之前的原始值
	rawHeader, parseErr := parseRawHeader(rawReq)
	if parseErr != nil {
		result.AddError(ErrMsgTooShort, parseErr.Error())
		return result.ErrorBits, result.WarningBits, nil, result.Details, nil
	}
	result.RawHeader = rawHeader

	// 步骤3: 尝试用miekg/dns解析
	msg = new(dns.Msg)
	if unpackErr := msg.Unpack(rawReq); unpackErr != nil {
		result.AddError(ErrFormUnpack, fmt.Sprintf("dns.Msg.Unpack失败: %v", unpackErr))
		return result.ErrorBits, result.WarningBits, nil, result.Details, nil
	}
	result.Msg = msg

	// 步骤4: 检查尾部数据
	packed, packErr := msg.Pack()
	if packErr == nil && len(packed) < len(rawReq) {
		result.AddError(ErrDataTrailing,
			fmt.Sprintf("可能存在尾部数据: 原始=%d, 重打包=%d", len(rawReq), len(packed)))
	}

	// 步骤5: 校验头部
	validateHeader(result, rawHeader, msg, true)

	// 步骤6: 校验question段
	validateQuestion(result, msg, true)

	// 步骤7: 校验资源记录段
	validateResourceRecords(result, msg, true)

	// 步骤8: 检查EDNS并校验RCODE
	if opt := msg.IsEdns0(); opt != nil {
		result.HasEDNS = true
		validateRcodeWithEDNS(result, rawHeader, true, result.ExtendedRcode)
	} else {
		validateRcodeWithEDNS(result, rawHeader, false, 0)
	}

	return result.ErrorBits, result.WarningBits, msg, result.Details, nil
}

// ValidateRsp 校验DNS响应报文，可选地与其请求进行关联校验
// 参数:
//   - rawReq: 原始DNS请求字节(仅校验响应结构时可为nil)
//   - rawRsp: 原始DNS响应字节
//
// 返回:
//   - errBits: 表示严重问题的错误位
//   - warningBits: 表示轻微问题的警告位
//   - msg: 解析后的DNS响应消息(解析失败时为nil)
//   - details: 错误和警告的详细描述
//   - error: 校验无法继续时的致命错误
func ValidateRsp(rawReq, rawRsp []byte) (errBits, warningBits uint64, msg *dns.Msg, details []string, err error) {
	result := NewValidationResult()

	// M01: 检查响应的最小数据长度
	if len(rawRsp) < DNSHeaderSize {
		result.AddError(ErrMsgTooShort,
			fmt.Sprintf("响应过短: %d字节 (最小%d)", len(rawRsp), DNSHeaderSize))
		return result.ErrorBits, result.WarningBits, nil, result.Details, nil
	}

	// M02: 检查最大数据长度
	if len(rawRsp) > MaxMessageLength {
		result.AddError(ErrMsgTooLong,
			fmt.Sprintf("响应过长: %d字节 (最大%d)", len(rawRsp), MaxMessageLength))
		return result.ErrorBits, result.WarningBits, nil, result.Details, nil
	}

	// 步骤2: 解析原始响应头部
	rawHeader, parseErr := parseRawHeader(rawRsp)
	if parseErr != nil {
		result.AddError(ErrMsgTooShort, parseErr.Error())
		return result.ErrorBits, result.WarningBits, nil, result.Details, nil
	}
	result.RawHeader = rawHeader

	// 步骤3: 尝试用miekg/dns解析响应
	msg = new(dns.Msg)
	if unpackErr := msg.Unpack(rawRsp); unpackErr != nil {
		result.AddError(ErrFormUnpack, fmt.Sprintf("dns.Msg.Unpack失败: %v", unpackErr))
		return result.ErrorBits, result.WarningBits, nil, result.Details, nil
	}
	result.Msg = msg

	// 步骤4: 检查尾部数据
	packed, packErr := msg.Pack()
	if packErr == nil && len(packed) < len(rawRsp) {
		result.AddError(ErrDataTrailing,
			fmt.Sprintf("可能存在尾部数据: 原始=%d, 重打包=%d", len(rawRsp), len(packed)))
	}

	// 步骤5: 校验头部
	validateHeader(result, rawHeader, msg, false)

	// 步骤6: 校验question段
	validateQuestion(result, msg, false)

	// 步骤7: 校验资源记录段
	validateResourceRecords(result, msg, false)

	// 步骤8: 检查EDNS并校验RCODE
	if opt := msg.IsEdns0(); opt != nil {
		result.HasEDNS = true
		validateRcodeWithEDNS(result, rawHeader, true, result.ExtendedRcode)
	} else {
		validateRcodeWithEDNS(result, rawHeader, false, 0)
	}

	// 步骤9: 如果提供了请求，执行关联校验
	if rawReq != nil && len(rawReq) >= DNSHeaderSize {
		reqResult := NewValidationResult()
		reqHeader, headErr := parseRawHeader(rawReq)
		if headErr != nil {
			reqResult.AddError(ErrMsgTooShort, headErr.Error())
		}
		reqResult.RawHeader = reqHeader

		reqMsg := new(dns.Msg)
		if unpackErr := reqMsg.Unpack(rawReq); unpackErr == nil {
			reqResult.Msg = reqMsg

			// 如果存在，从请求中提取ECS
			if opt := reqMsg.IsEdns0(); opt != nil {
				for _, option := range opt.Option {
					if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
						reqResult.RequestECS = &ECSInfo{
							Family:       ecs.Family,
							SourcePrefix: ecs.SourceNetmask,
							ScopePrefix:  ecs.SourceScope,
						}
						break
					}
				}
			}

			// 执行关联校验
			validateAssociation(result, reqResult, reqMsg, msg)
		}
	}

	return result.ErrorBits, result.WarningBits, msg, result.Details, nil
}

// ValidateRspWithTCP 校验带TCP上下文的DNS响应
func ValidateRspWithTCP(rawReq, rawRsp []byte, isTCP bool) (errBits, warningBits uint64, msg *dns.Msg, details []string, err error) {
	// 调用ValidateRsp执行完整校验
	errBits, warningBits, msg, details, err = ValidateRsp(rawReq, rawRsp)
	if err != nil || msg == nil {
		return
	}

	// 创建result用于TCP特定校验
	result := NewValidationResult()
	result.Msg = msg
	result.ErrorBits = errBits
	result.WarningBits = warningBits
	// 继承之前的details
	result.Details = details

	// 从rawRsp重新获取RawHeader（或者我们可以从ValidateRsp内部获取，但这里简单起见重新解析）
	if len(rawRsp) >= DNSHeaderSize {
		rawHeader, _ := parseRawHeader(rawRsp)
		result.RawHeader = rawHeader
	}

	// 执行TCP特定的校验
	validateResponseInternal(result, msg, isTCP)

	return result.ErrorBits, result.WarningBits, msg, result.Details, nil
}

// ValidateRaw 校验原始DNS报文，不知道它是请求还是响应
// 通过检查QR位来确定类型
func ValidateRaw(rawData []byte) (errBits, warningBits uint64, msg *dns.Msg, isResponse bool, details []string, err error) {
	if len(rawData) < DNSHeaderSize {
		return ErrMsgTooShort, 0, nil, false, nil, nil
	}

	// 检查QR位以确定是请求还是响应
	flags := rawData[2]
	isResponse = (flags & 0x80) != 0

	if isResponse {
		errBits, warningBits, msg, details, err = ValidateRsp(nil, rawData)
	} else {
		errBits, warningBits, msg, details, err = ValidateReq(rawData)
	}

	return errBits, warningBits, msg, isResponse, details, err
}

// ValidateMsg 校验已解析的DNS消息
// 当你有dns.Msg但没有原始字节时很有用
// 注意: 这不能执行原始头部校验或尾部数据检测
func ValidateMsg(msg *dns.Msg, isRequest bool) (errBits, warningBits uint64, details []string) {
	if msg == nil {
		return ErrFormUnpack, 0, nil
	}

	result := NewValidationResult()
	result.Msg = msg

	// 从消息创建伪原始头部
	rawHeader := &RawHeaderInfo{
		ID:      msg.Id,
		QR:      msg.Response,
		Opcode:  msg.Opcode,
		AA:      msg.Authoritative,
		TC:      msg.Truncated,
		RD:      msg.RecursionDesired,
		RA:      msg.RecursionAvailable,
		Z:       msg.Zero,
		AD:      msg.AuthenticatedData,
		CD:      msg.CheckingDisabled,
		Rcode:   msg.Rcode,
		QDCount: uint16(len(msg.Question)),
		ANCount: uint16(len(msg.Answer)),
		NSCount: uint16(len(msg.Ns)),
		ARCount: uint16(len(msg.Extra)),
	}
	result.RawHeader = rawHeader

	// 校验头部(但计数总是匹配的，因为我们直接使用msg)
	validateHeader(result, rawHeader, msg, isRequest)

	// 校验question段
	validateQuestion(result, msg, isRequest)

	// 校验资源记录段
	validateResourceRecords(result, msg, isRequest)

	// 检查EDNS并校验RCODE
	if opt := msg.IsEdns0(); opt != nil {
		result.HasEDNS = true
		// 从OPT获取扩展RCODE
		extRcode := uint8((opt.Hdr.Ttl >> 24) & 0xFF)
		validateRcodeWithEDNS(result, rawHeader, true, extRcode)
	} else {
		validateRcodeWithEDNS(result, rawHeader, false, 0)
	}

	return result.ErrorBits, result.WarningBits, result.Details
}

// GetErrorDescription 返回错误位的可读描述
func GetErrorDescription(errBits uint64) []string {
	var descriptions []string
	for bit, name := range ErrorBitNames {
		if errBits&bit != 0 {
			descriptions = append(descriptions, name)
		}
	}
	return descriptions
}

// GetWarningDescription 返回警告位的可读描述
func GetWarningDescription(warningBits uint64) []string {
	var descriptions []string
	for bit, name := range WarningBitNames {
		if warningBits&bit != 0 {
			descriptions = append(descriptions, name)
		}
	}
	return descriptions
}

// IsError 检查特定错误位是否被设置
func IsError(errBits, bit uint64) bool {
	return errBits&bit != 0
}

// IsWarning 检查特定警告位是否被设置
func IsWarning(warningBits, bit uint64) bool {
	return warningBits&bit != 0
}

// HasErrors 如果有任何错误位被设置则返回true
func HasErrors(errBits uint64) bool {
	return errBits != 0
}

// HasWarnings 如果有任何警告位被设置则返回true
func HasWarnings(warningBits uint64) bool {
	return warningBits != 0
}
