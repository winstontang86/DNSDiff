package validate

// ============================================================================
// 错误位 - 表示DNS报文格式错误或无效的严重问题
// 使用uint64支持最多64种不同的错误类型
// 每个bit位置代表一种特定的错误条件
// 每个段之间预留2个位用于以后扩展
// ============================================================================

// 错误位位置 (0-63)
const (
	// Bits 0-6: 消息整体结构错误 (M01-M03) [使用0-4, 预留5-6]
	ErrMsgTooShort             uint64 = 1 << 0 // M01: 消息长度 < 12字节
	ErrMsgTooLong              uint64 = 1 << 1 // M02: 消息长度 > 65535字节
	ErrMsgSectionCountMismatch uint64 = 1 << 2 // M03: TC=0时section计数不匹配
	ErrFormUnpack              uint64 = 1 << 3 // miekg/dns库解析失败
	ErrDataTrailing            uint64 = 1 << 4 // 解析完成后有多余尾部数据
	// 预留: 5, 6

	// Bits 7-14: Header段错误 (H02-H10) [使用7-12, 预留13-14]
	ErrHeaderQRReq         uint64 = 1 << 7  // H02: 请求包QR != 0
	ErrHeaderQRRsp         uint64 = 1 << 8  // H03: 响应包QR != 1
	ErrHeaderOpcodeInvalid uint64 = 1 << 9  // H05: Opcode不在{0, 2, 4, 5}范围内
	ErrHeaderTCReq         uint64 = 1 << 10 // H07: 请求包TC != 0
	ErrHeaderZNotZero      uint64 = 1 << 11 // H10: Z位(bit 11) != 0
	ErrHeaderCountMismatch uint64 = 1 << 12 // Header中Count字段与实际记录数不匹配
	// 预留: 13, 14

	// Bits 15-22: Question段错误 (Q01-Q06) [使用15-20, 预留21-22]
	ErrQNameLabelTooLong         uint64 = 1 << 15 // Q01: 单个标签长度 > 63
	ErrQNameTooLong              uint64 = 1 << 16 // Q02: 域名总长度 > 255字节
	ErrQNamePtrOutOfBounds       uint64 = 1 << 17 // Q03: 压缩指针越界
	ErrQNamePtrLoop              uint64 = 1 << 18 // Q04: 检测到压缩指针循环
	ErrQTypeOPT                  uint64 = 1 << 19 // Q06: Question段中出现QTYPE=41(OPT)
	ErrQuestionNoQuestion        uint64 = 1 << 20 // 查询包中没有问题
	ErrQNameLabelHasNonPrintable uint64 = 1 << 21 // Q08: 标签包含不可打印字符
	// 预留: 22

	// Bits 23-32: 资源记录错误 (R05, R08-R12) [使用23-30, 预留31-32]
	ErrRRTypeANY            uint64 = 1 << 23 // R05: RR中使用了TYPE=255(ANY)
	ErrRRRdataOverflow      uint64 = 1 << 24 // R08: RDLENGTH超出消息末尾
	ErrRRTypeA_RdLen        uint64 = 1 << 25 // R09: A记录RDLENGTH != 4
	ErrRRTypeAAAA_RdLen     uint64 = 1 << 26 // R10: AAAA记录RDLENGTH != 16
	ErrRRTypeSOA_RdLen      uint64 = 1 << 27 // R11: SOA记录RDLENGTH过短
	ErrRRNamePtrLoop        uint64 = 1 << 28 // 名称压缩指针循环
	ErrRRNamePtrOutOfBounds uint64 = 1 << 29 // 名称压缩指针越界
	ErrRRTypeNAPTR_RdLen    uint64 = 1 << 30 // R12: NAPTR记录RDLENGTH过短
	// 预留: 31, 32

	// Bits 33-42: EDNS错误 (E01-E10) [使用33-39, 预留40-42]
	ErrEDNSOPTNameNotRoot     uint64 = 1 << 33 // E01: OPT NAME != root (0x00)
	ErrEDNSOPTNotInAdditional uint64 = 1 << 34 // E02: OPT不在Additional段中
	ErrEDNSMultipleOPT        uint64 = 1 << 35 // E03: 存在多个OPT记录
	ErrEDNSExtRcodeInReq      uint64 = 1 << 36 // E06: 请求中EXTENDED-RCODE != 0
	ErrEDNSVersionNotZero     uint64 = 1 << 37 // E07: EDNS Version != 0
	ErrEDNSOptionsTotalLen    uint64 = 1 << 38 // E09: Options总长度 != RDLENGTH
	ErrEDNSOptionOverflow     uint64 = 1 << 39 // E10: Option解析溢出
	// 预留: 40, 41, 42

	// Bits 43-48: ECS错误 (E11-E14) [使用43-46, 预留47-48]
	ErrECSIPv4AddrLen    uint64 = 1 << 43 // E11: ECS FAMILY=1且AddressLen > 4
	ErrECSIPv6AddrLen    uint64 = 1 << 44 // E12: ECS FAMILY=2且AddressLen > 16
	ErrECSPrefixTooLarge uint64 = 1 << 45 // E13: Source Prefix超出地址位数
	ErrECSLengthMismatch uint64 = 1 << 46 // E14: ECS RDLENGTH不匹配
	// 预留: 47, 48

	// Bits 49-60: 关联校验错误 (A01-A15) [使用49-59, 预留60]
	ErrAssocIDMismatch       uint64 = 1 << 49 // A01: 响应ID != 请求ID
	ErrAssocOpcodeMismatch   uint64 = 1 << 50 // A02: 响应Opcode != 请求Opcode
	ErrAssocRDMismatch       uint64 = 1 << 51 // A03: 请求RD=1但响应RD=0
	ErrAssocQuestionMismatch uint64 = 1 << 52 // A04: 响应Question != 请求Question
	// 预留: 53
	ErrAssocNoErrorEmpty            uint64 = 1 << 54 // A08: RCODE=0但AN+NS+AR=0
	ErrAssocADWithCD                uint64 = 1 << 55 // A11: AD=1且CD=1(冲突)
	ErrAssocCDNotCopied             uint64 = 1 << 56 // A12: 请求CD=1但响应CD=0
	ErrAssocECSFamilyMismatch       uint64 = 1 << 57 // A14: 响应ECS.Family != 请求
	ErrAssocECSSourcePrefixMismatch uint64 = 1 << 58 // A15: 响应ECS.SourcePrefix != 请求
	ErrAssocCNAMEWithOther          uint64 = 1 << 59 // A17: CNAME与其他非DNSSEC类型共存
	// 预留: 60, 61, 62, 63
)

// ============================================================================
// 警告位 - 表示轻微问题或已弃用的特性
// 使用uint64支持最多64种不同的警告类型
// 每个段之间预留2个位用于以后扩展
// ============================================================================

// 警告位位置 (0-63)
const (
	// Bits 0-10: Header警告 (H04, H06, H08-H09, H11-H15) [使用0-8, 预留9-10]
	WarnHeaderOpcodeNonZero   uint64 = 1 << 0 // H04: 标准查询但Opcode != 0
	WarnHeaderAAInReq         uint64 = 1 << 1 // H06: 请求中AA != 0
	WarnHeaderTCInRsp         uint64 = 1 << 2 // H08: 响应TC=1(被截断)
	WarnHeaderRAInReq         uint64 = 1 << 3 // H09: 请求中RA=1
	WarnHeaderRcodeNoEDNS     uint64 = 1 << 4 // H11: 无EDNS时RCODE > 5
	WarnHeaderRcodeExtUnknown uint64 = 1 << 5 // H12: 扩展RCODE > 22
	WarnHeaderQDCountMultiple uint64 = 1 << 6 // H13: QDCOUNT > 1
	WarnHeaderANCountInReq    uint64 = 1 << 7 // H14: 请求中ANCOUNT > 0
	WarnHeaderNSCountInReq    uint64 = 1 << 8 // H15: 请求中NSCOUNT > 0
	// 预留: 9, 10

	// Bits 11-14: Question警告 (Q05, Q07) [使用11-12, 预留13-14]
	WarnQTypeUnknown uint64 = 1 << 11 // Q05: QTYPE > 255(未知/扩展类型)
	WarnQClassNotIN  uint64 = 1 << 12 // Q07: QCLASS != 1(IN)
	// 预留: 13, 14

	// Bits 15-21: RR警告 (R06-R07) [使用15-19, 预留20-21]
	WarnRRClassNotIN     uint64 = 1 << 15 // R06: RR CLASS != 1(IN)
	WarnRRTTLTooHigh     uint64 = 1 << 16 // R07: TTL > 2^31-1
	WarnRRTTLZero        uint64 = 1 << 17 // TTL为零
	WarnRRDeprecatedType uint64 = 1 << 18 // 已弃用的RR类型
	WarnRRUnusualType    uint64 = 1 << 19 // 不常见的RR类型
	// 预留: 20, 21

	// Bits 22-27: EDNS警告 (E04-E05, E08) [使用22-25, 预留26-27]
	WarnEDNSUDPSizeZero    uint64 = 1 << 22 // E04: UDP Payload Size = 0
	WarnEDNSUDPSizeSmall   uint64 = 1 << 23 // E05: UDP Payload Size < 512
	WarnEDNSZFlagsReserved uint64 = 1 << 24 // E08: Z flags保留位被设置
	// 预留: 25，26, 27

	// Bits 28-37: 关联校验警告 (A05, A07, A09-A10, A13, A16-A18) [使用28-35, 预留36-37]
	WarnAssocNODATANoAuthority   uint64 = 1 << 28 // A05: NODATA但Authority无SOA
	WarnAssocNXDOMAINNoAuthority uint64 = 1 << 29 // A07: NXDOMAIN但Authority无SOA
	WarnAssocErrorHasRecords     uint64 = 1 << 30 // A09: 错误响应但包含记录
	WarnAssocTCInTCP             uint64 = 1 << 31 // A10: TCP响应中TC=1
	WarnAssocADWithCDRequest     uint64 = 1 << 32 // A13: 请求CD=1但响应AD=1
	WarnAssocECSScopeTooLarge    uint64 = 1 << 33 // A16: 响应Scope > 请求Source
	WarnAssocDNAMEWithOther      uint64 = 1 << 34 // A18: DNAME与其他非DNSSEC类型共存
	WarnECSScopePrefixNonZero    uint64 = 1 << 35 // 请求中ECS scope prefix不为0
	WarnAssocNXDOMAINHasAnswer   uint64 = 1 << 36 // A06: NXDOMAIN但ANCOUNT > 0
	// 预留: 37
	// Bits 38-63: 预留用于未来扩展
)

// ErrorBitNames 错误位到可读名称的映射
var ErrorBitNames = map[uint64]string{
	// 消息结构错误
	ErrMsgTooShort:             "ErrMsgTooShort",
	ErrMsgTooLong:              "ErrMsgTooLong",
	ErrMsgSectionCountMismatch: "ErrMsgSectionCountMismatch",
	ErrFormUnpack:              "ErrFormUnpack",
	ErrDataTrailing:            "ErrDataTrailing",

	// Header错误
	ErrHeaderQRReq:         "ErrHeaderQRReq",
	ErrHeaderQRRsp:         "ErrHeaderQRRsp",
	ErrHeaderOpcodeInvalid: "ErrHeaderOpcodeInvalid",
	ErrHeaderTCReq:         "ErrHeaderTCReq",
	ErrHeaderZNotZero:      "ErrHeaderZNotZero",
	ErrHeaderCountMismatch: "ErrHeaderCountMismatch",

	// Question错误
	ErrQNameLabelTooLong:         "ErrQNameLabelTooLong",
	ErrQNameTooLong:              "ErrQNameTooLong",
	ErrQNamePtrOutOfBounds:       "ErrQNamePtrOutOfBounds",
	ErrQNamePtrLoop:              "ErrQNamePtrLoop",
	ErrQTypeOPT:                  "ErrQTypeOPT",
	ErrQuestionNoQuestion:        "ErrQuestionNoQuestion",
	ErrQNameLabelHasNonPrintable: "ErrQNameLabelHasNonPrintable",

	// RR错误
	ErrRRTypeANY:            "ErrRRTypeANY",
	ErrRRRdataOverflow:      "ErrRRRdataOverflow",
	ErrRRTypeA_RdLen:        "ErrRRTypeA_RdLen",
	ErrRRTypeAAAA_RdLen:     "ErrRRTypeAAAA_RdLen",
	ErrRRTypeSOA_RdLen:      "ErrRRTypeSOA_RdLen",
	ErrRRNamePtrLoop:        "ErrRRNamePtrLoop",
	ErrRRNamePtrOutOfBounds: "ErrRRNamePtrOutOfBounds",
	ErrRRTypeNAPTR_RdLen:    "ErrRRTypeNAPTR_RdLen",

	// EDNS错误
	ErrEDNSOPTNameNotRoot:     "ErrEDNSOPTNameNotRoot",
	ErrEDNSOPTNotInAdditional: "ErrEDNSOPTNotInAdditional",
	ErrEDNSMultipleOPT:        "ErrEDNSMultipleOPT",
	ErrEDNSExtRcodeInReq:      "ErrEDNSExtRcodeInReq",
	ErrEDNSVersionNotZero:     "ErrEDNSVersionNotZero",
	ErrEDNSOptionsTotalLen:    "ErrEDNSOptionsTotalLen",
	ErrEDNSOptionOverflow:     "ErrEDNSOptionOverflow",

	// ECS错误
	ErrECSIPv4AddrLen:    "ErrECSIPv4AddrLen",
	ErrECSIPv6AddrLen:    "ErrECSIPv6AddrLen",
	ErrECSPrefixTooLarge: "ErrECSPrefixTooLarge",
	ErrECSLengthMismatch: "ErrECSLengthMismatch",

	// 关联校验错误
	ErrAssocIDMismatch:              "ErrAssocIDMismatch",
	ErrAssocOpcodeMismatch:          "ErrAssocOpcodeMismatch",
	ErrAssocRDMismatch:              "ErrAssocRDMismatch",
	ErrAssocQuestionMismatch:        "ErrAssocQuestionMismatch",
	ErrAssocNoErrorEmpty:            "ErrAssocNoErrorEmpty",
	ErrAssocADWithCD:                "ErrAssocADWithCD",
	ErrAssocCDNotCopied:             "ErrAssocCDNotCopied",
	ErrAssocECSFamilyMismatch:       "ErrAssocECSFamilyMismatch",
	ErrAssocECSSourcePrefixMismatch: "ErrAssocECSSourcePrefixMismatch",
	ErrAssocCNAMEWithOther:          "ErrAssocCNAMEWithOther",
}

// WarningBitNames 警告位到可读名称的映射
var WarningBitNames = map[uint64]string{
	// Header警告
	WarnHeaderOpcodeNonZero:   "WarnHeaderOpcodeNonZero",
	WarnHeaderAAInReq:         "WarnHeaderAAInReq",
	WarnHeaderTCInRsp:         "WarnHeaderTCInRsp",
	WarnHeaderRAInReq:         "WarnHeaderRAInReq",
	WarnHeaderRcodeNoEDNS:     "WarnHeaderRcodeNoEDNS",
	WarnHeaderRcodeExtUnknown: "WarnHeaderRcodeExtUnknown",
	WarnHeaderQDCountMultiple: "WarnHeaderQDCountMultiple",
	WarnHeaderANCountInReq:    "WarnHeaderANCountInReq",
	WarnHeaderNSCountInReq:    "WarnHeaderNSCountInReq",

	// Question警告
	WarnQTypeUnknown: "WarnQTypeUnknown",
	WarnQClassNotIN:  "WarnQClassNotIN",

	// RR警告
	WarnRRClassNotIN:     "WarnRRClassNotIN",
	WarnRRTTLTooHigh:     "WarnRRTTLTooHigh",
	WarnRRTTLZero:        "WarnRRTTLZero",
	WarnRRDeprecatedType: "WarnRRDeprecatedType",
	WarnRRUnusualType:    "WarnRRUnusualType",

	// EDNS警告
	WarnEDNSUDPSizeZero:    "WarnEDNSUDPSizeZero",
	WarnEDNSUDPSizeSmall:   "WarnEDNSUDPSizeSmall",
	WarnEDNSZFlagsReserved: "WarnEDNSZFlagsReserved",

	// 关联校验警告
	WarnAssocNODATANoAuthority:   "WarnAssocNODATANoAuthority",
	WarnAssocNXDOMAINNoAuthority: "WarnAssocNXDOMAINNoAuthority",
	WarnAssocErrorHasRecords:     "WarnAssocErrorHasRecords",
	WarnAssocTCInTCP:             "WarnAssocTCInTCP",
	WarnAssocADWithCDRequest:     "WarnAssocADWithCDRequest",
	WarnAssocECSScopeTooLarge:    "WarnAssocECSScopeTooLarge",
	WarnAssocDNAMEWithOther:      "WarnAssocDNAMEWithOther",
	WarnECSScopePrefixNonZero:    "WarnECSScopePrefixNonZero",
	WarnAssocNXDOMAINHasAnswer:   "WarnAssocNXDOMAINHasAnswer",
}
