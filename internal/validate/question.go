package validate

import (
	"fmt"
	"unicode"

	"github.com/miekg/dns"
)

// MaxDomainNameLength 域名最大长度(RFC 1035)
const MaxDomainNameLength = 255

// MaxLabelLength 单个标签最大长度(RFC 1035)
const MaxLabelLength = 63

// TypeOPT OPT伪RR类型(EDNS)
const TypeOPT = 41

// validateQuestion 检查Question段是否符合RFC规范
func validateQuestion(result *ValidationResult, msg *dns.Msg, isRequest bool) {
	if msg == nil {
		return
	}

	// 检查问题数量
	if len(msg.Question) == 0 {
		if isRequest {
			result.AddError(ErrQuestionNoQuestion, "查询中没有问题")
		}
		return
	}

	// 校验每个问题
	for i, q := range msg.Question {
		validateSingleQuestion(result, &q, i)
	}
}

// validateSingleQuestion 校验单个DNS问题
func validateSingleQuestion(result *ValidationResult, q *dns.Question, index int) {
	// 校验域名
	validateDomainName(result, q.Name, index)

	// 校验QTYPE
	validateQType(result, q.Qtype, index)

	// 校验QCLASS
	validateQClass(result, q.Qclass, index)
}

// validateDomainName 检查域名是否符合RFC 1035规范
func validateDomainName(result *ValidationResult, name string, index int) {
	// Q02: 检查总长度(包括wire格式中的长度字节)
	// 表示格式中最大约253-254个字符
	if len(name) > MaxDomainNameLength {
		result.AddError(ErrQNameTooLong,
			fmt.Sprintf("[%d]域名过长: %d字节 (最大%d)", index, len(name), MaxDomainNameLength))
	}

	// 检查各个标签
	nameToParse := name
	if len(nameToParse) > 0 && nameToParse[len(nameToParse)-1] == '.' {
		nameToParse = nameToParse[:len(nameToParse)-1]
	}

	if len(nameToParse) > 0 {
		labels := splitLabels(nameToParse)
		for _, label := range labels {
			// Q01: 单个标签长度 > 63
			if len(label) > MaxLabelLength {
				result.AddError(ErrQNameLabelTooLong,
					fmt.Sprintf("[%d]标签过长: %d字节 (最大%d)", index, len(label), MaxLabelLength))
			}

			// Q08: 非根label不允许包含不可打印字符
			if hasNonPrintableLabelChar(label) {
				result.AddError(ErrQNameLabelHasNonPrintable,
					fmt.Sprintf("[%d]标签包含不可打印字符: %q", index, label))
			}
		}
	}
}

// hasNonPrintableLabelChar 检查label中是否包含不可打印字符。
// 注意：这里只对非根label做检查（根label不包含任何字符）。
func hasNonPrintableLabelChar(label string) bool {
	for _, r := range label {
		// RFC 1035 在wire格式层面允许任意8-bit值；但在本工具的展示字符串校验中，
		// 我们认为非根label出现不可打印字符属于明显异常。
		if !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

// splitLabels 将域名分割成标签。
//
// 注意：miekg/dns 在将 wire-format 的域名转换为字符串时，会把不可打印字节编码成 `\DDD`（十进制）形式。
// 例如：wire label 为 `77 00 41`，在字符串中可能表现为 `w\000A`。
// 为了让“不可打印字符检测”对这种情况生效，这里会把 `\DDD` 解析回单字节再参与后续校验。
func splitLabels(name string) []string {
	var labels []string
	var current []byte

	flush := func() {
		if len(current) > 0 {
			labels = append(labels, string(current))
			current = current[:0]
		}
	}

	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '.':
			flush()

		case '\\':
			// 尝试解析 \DDD（十进制）形式
			if i+3 < len(name) && isDigit(name[i+1]) && isDigit(name[i+2]) && isDigit(name[i+3]) {
				v := int(name[i+1]-'0')*100 + int(name[i+2]-'0')*10 + int(name[i+3]-'0')
				if v >= 0 && v <= 255 {
					current = append(current, byte(v))
					i += 3
					continue
				}
			}

			// 其它转义：RFC1035 的“quoted”字符（比如 `\.`、`\\`），把后一个字节当作字面值
			if i+1 < len(name) {
				i++
				current = append(current, name[i])
			}

		default:
			current = append(current, name[i])
		}
	}

	flush()
	return labels
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// validateQType 检查QTYPE是否有效
func validateQType(result *ValidationResult, qtype uint16, index int) {
	// Q06: OPT(41)不应出现在Question段中
	if qtype == dns.TypeOPT {
		result.AddError(ErrQTypeOPT,
			fmt.Sprintf("Question段(%d)中出现QTYPE=OPT(41) (应仅在Additional段中)", index))
		return
	}

	// Q05: QTYPE > 255为未知/扩展类型
	if qtype > 255 {
		result.AddWarning(WarnQTypeUnknown,
			fmt.Sprintf("idx=%d,QTYPE=%d (>255为未知/扩展类型)", index, qtype))
	}
}

// validateQClass 检查QCLASS是否有效
func validateQClass(result *ValidationResult, qclass uint16, index int) {
	// Q07: QCLASS != 1(IN)不寻常
	if qclass != dns.ClassINET {
		result.AddWarning(WarnQClassNotIN,
			fmt.Sprintf("QCLASS=%d idx=%d (期望1/IN)", qclass, index))
	}
}
