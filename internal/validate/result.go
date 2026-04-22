package validate

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ECSInfo 存储ECS选项信息用于关联校验
type ECSInfo struct {
	Family       uint16 // 地址族(1=IPv4, 2=IPv6)
	SourcePrefix uint8  // 源前缀长度
	ScopePrefix  uint8  // 作用域前缀长度
	Address      []byte // 地址数据
}

// ValidationResult 保存DNS报文校验的结果
type ValidationResult struct {
	// ErrorBits 包含表示畸形报文的严重问题
	ErrorBits uint64

	// WarningBits 包含轻微问题或已弃用特性
	WarningBits uint64

	// Msg 是解析后的DNS消息(如果解析失败则为nil)
	Msg *dns.Msg

	// RawHeader 包含从原始数据解析的原始头部值
	RawHeader *RawHeaderInfo

	// ExtendedRcode 来自EDNS OPT记录(无EDNS时为0)
	ExtendedRcode uint8

	// HasEDNS 表示是否存在EDNS OPT记录
	HasEDNS bool

	// RequestECS 存储请求中的ECS信息(用于响应校验)
	RequestECS *ECSInfo

	// ResponseECS 存储响应中的ECS信息
	ResponseECS *ECSInfo

	// Details 提供发现问题的可读描述
	Details []string
}

// RawHeaderInfo 存储直接从原始字节解析的原始头部值
// 如果miekg/dns在解析过程中修正了这些值，它们可能与dns.Msg中的值不同
type RawHeaderInfo struct {
	ID      uint16 // 事务ID
	QR      bool   // 查询/响应标志
	Opcode  int    // 操作码
	AA      bool   // 权威应答
	TC      bool   // 截断标志
	RD      bool   // 期望递归
	RA      bool   // 可用递归
	Z       bool   // 保留的Z位(bit 6, 必须为0)
	AD      bool   // 可信数据(bit 5)
	CD      bool   // 禁用检查(bit 4)
	Rcode   int    // 响应码
	QDCount uint16 // 原始头部中的问题计数
	ANCount uint16 // 原始头部中的应答计数
	NSCount uint16 // 原始头部中的授权计数
	ARCount uint16 // 原始头部中的附加计数
}

// NewValidationResult 创建新的ValidationResult
func NewValidationResult() *ValidationResult {
	return &ValidationResult{
		Details: make([]string, 0),
	}
}

// AddError 设置错误位并添加详细消息
func (r *ValidationResult) AddError(bit uint64, detail string) {
	r.ErrorBits |= bit
	if detail != "" {
		r.Details = append(r.Details, "[错误] "+detail)
	}
}

// AddWarning 设置警告位并添加详细消息
func (r *ValidationResult) AddWarning(bit uint64, detail string) {
	r.WarningBits |= bit
	if detail != "" {
		r.Details = append(r.Details, "[警告] "+detail)
	}
}

// HasError 检查特定错误位是否被设置
func (r *ValidationResult) HasError(bit uint64) bool {
	return r.ErrorBits&bit != 0
}

// HasWarning 检查特定警告位是否被设置
func (r *ValidationResult) HasWarning(bit uint64) bool {
	return r.WarningBits&bit != 0
}

// HasAnyError 检查是否有任何错误位被设置
func (r *ValidationResult) HasAnyError() bool {
	return r.ErrorBits != 0
}

// HasAnyWarning 检查是否有任何警告位被设置
func (r *ValidationResult) HasAnyWarning() bool {
	return r.WarningBits != 0
}

// IsValid 如果没有发现错误则返回true
func (r *ValidationResult) IsValid() bool {
	return r.ErrorBits == 0
}

// GetFullRcode 返回组合的RCODE(扩展 + 头部)
func (r *ValidationResult) GetFullRcode() int {
	if r.RawHeader == nil {
		return 0
	}
	return (int(r.ExtendedRcode) << 4) | (r.RawHeader.Rcode & 0x0F)
}

// ErrorNames 返回所有被设置的错误位的名称
func (r *ValidationResult) ErrorNames() []string {
	return getBitNames(r.ErrorBits, ErrorBitNames)
}

// WarningNames 返回所有被设置的警告位的名称
func (r *ValidationResult) WarningNames() []string {
	return getBitNames(r.WarningBits, WarningBitNames)
}

// getBitNames 从bits值中提取被设置位的名称
func getBitNames(bits uint64, nameMap map[uint64]string) []string {
	var names []string
	for bit, name := range nameMap {
		if bits&bit != 0 {
			names = append(names, name)
		}
	}
	return names
}

// String 返回校验结果的可读表示
func (r *ValidationResult) String() string {
	var sb strings.Builder

	sb.WriteString("校验结果:\n")
	sb.WriteString(fmt.Sprintf("  有效: %v\n", r.IsValid()))
	sb.WriteString(fmt.Sprintf("  错误位: 0x%016X\n", r.ErrorBits))
	sb.WriteString(fmt.Sprintf("  警告位: 0x%016X\n", r.WarningBits))

	if len(r.ErrorNames()) > 0 {
		sb.WriteString(fmt.Sprintf("  错误: %v\n", r.ErrorNames()))
	}

	if len(r.WarningNames()) > 0 {
		sb.WriteString(fmt.Sprintf("  警告: %v\n", r.WarningNames()))
	}

	if len(r.Details) > 0 {
		sb.WriteString("  详情:\n")
		for _, d := range r.Details {
			sb.WriteString(fmt.Sprintf("    - %s\n", d))
		}
	}

	return sb.String()
}

// Merge 将另一个ValidationResult合并到此结果中
func (r *ValidationResult) Merge(other *ValidationResult) {
	if other == nil {
		return
	}
	r.ErrorBits |= other.ErrorBits
	r.WarningBits |= other.WarningBits
	r.Details = append(r.Details, other.Details...)
}
