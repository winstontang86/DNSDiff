// Package diff 基于dns.Msg进行dns回包报文比较
package diff

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	DNS_EQUAL    = 0
	DNS_NOTEQUAL = -1
	// DiffCode 差异码
	// 整体比较
	DIFF_BIT_NOMATCH       = 0x00000001
	DIFF_BIT_NOMATCHKEY    = 0x00000002
	DIFF_BIT_NOMATCHDOMAIN = 0x00000004
	// 头部字段
	DIFF_BIT_HEAD_RCODE    = 0x00000010
	DIFF_BIT_HEAD_OPCODE   = 0x00000020
	DIFF_BIT_HEAD_QFLAG    = 0x00000040
	DIFF_BIT_HEAD_AA       = 0x00000080 // AA标志差异，从QFLAG中独立出来以便细粒度过滤
	DIFF_BIT_HEAD_RCODE_SF = 0x00000100 // 涉及SERVFAIL的Rcode差异，从RCODE中独立出来
	// question关键字段
	DIFF_BIT_QUEST_LEN    = 0x00001000
	DIFF_BIT_QUEST_QNAME  = 0x00002000
	DIFF_BIT_QUEST_QTYPE  = 0x00004000
	DIFF_BIT_QUEST_QCLASS = 0x00008000
	// answer 关键字段
	DIFF_BIT_ANSWER_01     = 0x00010000
	DIFF_BIT_ANSWER_LEN    = 0x00020000
	DIFF_BIT_ANSWER_CNAME  = 0x00040000
	DIFF_BIT_ANSWER_RRDIFF = 0x00080000
	// authority 关键字段
	/*如果响应是权威的 (AA flag is set) 或是一个查询引导 (Referral):
		1、Authority段的差异是高优先级警报。2、使用集合对比策略来比较NS记录集。3、对于NXDOMAIN响应，严格对比SOA记录的关键字段。
	如果响应是非权威的 (AA flag is NOT set):
		1、Authority段的差异是低优先级信息，甚至可以忽略。你的对比焦点应该完全放在Answer段。
	*/
	DIFF_BIT_AUTH_LEN    = 0x00100000
	DIFF_BIT_AUTH_RRDIFF = 0x00200000
	DIFF_BIT_AUTH_CNAME  = 0x00400000
	// additional 关键字段 修改了edns配置的时候需要关注，其他时候可以不关注
	DIFF_BIT_ADD_LEN    = 0x01000000
	DIFF_BIT_ADD_RRDIFF = 0x02000000
	DIFF_BIT_ADD_CNAME  = 0x04000000
	// additional段 OPT (EDNS) 选项级别差异
	DIFF_BIT_ADD_OPT_ECS    = 0x08000000 // ECS (EDNS Client Subnet) 选项差异
	DIFF_BIT_ADD_OPT_COOKIE = 0x10000000 // DNS Cookie 选项差异

	// 差异等级
	DIFF_LEVEL_CRITICAL = 0
	DIFF_LEVEL_WARNING  = 1
	DIFF_LEVEL_NORMAL   = 2
	DIFF_LEVEL_IGNORE   = 3
)

// 差异码和差异登记的映射关系
var diffLevelMap = map[uint32]int{
	DIFF_BIT_NOMATCH:       DIFF_LEVEL_IGNORE,
	DIFF_BIT_NOMATCHKEY:    DIFF_LEVEL_IGNORE,
	DIFF_BIT_NOMATCHDOMAIN: DIFF_LEVEL_IGNORE,

	DIFF_BIT_HEAD_RCODE:    DIFF_LEVEL_CRITICAL,
	DIFF_BIT_HEAD_OPCODE:   DIFF_LEVEL_CRITICAL,
	DIFF_BIT_HEAD_QFLAG:    DIFF_LEVEL_CRITICAL,
	DIFF_BIT_HEAD_AA:       DIFF_LEVEL_WARNING, // AA标志在转发场景下常见（缓存命中与未命中）
	DIFF_BIT_HEAD_RCODE_SF: DIFF_LEVEL_WARNING, // SERVFAIL通常由上游超时或冷启动引起

	DIFF_BIT_QUEST_LEN:    DIFF_LEVEL_CRITICAL,
	DIFF_BIT_QUEST_QNAME:  DIFF_LEVEL_CRITICAL,
	DIFF_BIT_QUEST_QTYPE:  DIFF_LEVEL_CRITICAL,
	DIFF_BIT_QUEST_QCLASS: DIFF_LEVEL_CRITICAL,

	DIFF_BIT_ANSWER_01:     DIFF_LEVEL_CRITICAL,
	DIFF_BIT_ANSWER_LEN:    DIFF_LEVEL_NORMAL,
	DIFF_BIT_ANSWER_CNAME:  DIFF_LEVEL_CRITICAL,
	DIFF_BIT_ANSWER_RRDIFF: DIFF_LEVEL_WARNING,

	DIFF_BIT_AUTH_LEN:    DIFF_LEVEL_NORMAL,
	DIFF_BIT_AUTH_RRDIFF: DIFF_LEVEL_WARNING,
	DIFF_BIT_AUTH_CNAME:  DIFF_LEVEL_WARNING,

	DIFF_BIT_ADD_LEN:    DIFF_LEVEL_IGNORE,
	DIFF_BIT_ADD_RRDIFF: DIFF_LEVEL_NORMAL,
	DIFF_BIT_ADD_CNAME:  DIFF_LEVEL_NORMAL,

	DIFF_BIT_ADD_OPT_ECS:    DIFF_LEVEL_WARNING,
	DIFF_BIT_ADD_OPT_COOKIE: DIFF_LEVEL_WARNING,
}

var diffFlags = [...]struct {
	mask uint32
	tag  string
}{
	{DIFF_BIT_NOMATCH, "NOMATCH"},
	{DIFF_BIT_NOMATCHKEY, "NOMATCHKEY"},
	{DIFF_BIT_NOMATCHDOMAIN, "NOMATCHDOMAIN"},
	{DIFF_BIT_HEAD_RCODE, "RCODE_DIFF"},
	{DIFF_BIT_HEAD_OPCODE, "OPCODE_DIFF"},
	{DIFF_BIT_HEAD_QFLAG, "QFLAG_DIFF"},
	{DIFF_BIT_HEAD_AA, "AA_FLAG_DIFF"},
	{DIFF_BIT_HEAD_RCODE_SF, "RCODE_SERVFAIL_DIFF"},
	{DIFF_BIT_QUEST_LEN, "QUEST_LEN_DIFF"},
	{DIFF_BIT_QUEST_QNAME, "QNAME_DIFF"},
	{DIFF_BIT_QUEST_QTYPE, "QTYPE_DIFF"},
	{DIFF_BIT_QUEST_QCLASS, "QCLASS_DIFF"},
	{DIFF_BIT_ANSWER_01, "ANSWER_01_DIFF"},
	{DIFF_BIT_ANSWER_LEN, "ANSWER_LEN_DIFF"},
	{DIFF_BIT_ANSWER_CNAME, "ANSWER_CNAME_DIFF"},
	{DIFF_BIT_ANSWER_RRDIFF, "ANSWER_RR_DIFF"},
	{DIFF_BIT_AUTH_LEN, "AUTH_LEN_DIFF"},
	{DIFF_BIT_AUTH_RRDIFF, "AUTH_RR_DIFF"},
	{DIFF_BIT_AUTH_CNAME, "AUTH_CNAME_DIFF"},
	{DIFF_BIT_ADD_LEN, "ADD_LEN_DIFF"},
	{DIFF_BIT_ADD_RRDIFF, "ADD_RR_DIFF"},
	{DIFF_BIT_ADD_CNAME, "ADD_CNAME_DIFF"},
	{DIFF_BIT_ADD_OPT_ECS, "ADD_OPT_ECS_DIFF"},
	{DIFF_BIT_ADD_OPT_COOKIE, "ADD_OPT_COOKIE_DIFF"},
}

var (
	DefaultMask  = uint32(0x00000000)
	CriticalMask = uint32(0x00000000)
	WarningMask  = uint32(0x00000000)
)

// WhitelistChecker 白名单检查器接口
type WhitelistChecker interface {
	IsWhitelisted(diffType string, domain string) bool
}

// Comparator 配置项
type Comparator struct {
	AllowPartialMatch  bool             // 允许answer的A和AAAA类型rr部分匹配
	IgnoreAdditional   bool             // 是否忽略additional
	DiffUnexpectedMask uint32           // 差异不符合预期掩码
	WhitelistChecker   WhitelistChecker // 白名单检查器（可选）
}

// init 函数在 main 函数执行前自动运行，用于初始化
func init() {
	// 遍历 diffLevelMap 来构建掩码
	for diffCode, level := range diffLevelMap {
		switch level {
		case DIFF_LEVEL_CRITICAL:
			// 使用位或操作符 "|" 将所有严重级别的差异码合并到 CriticalMask 中
			CriticalMask |= diffCode
		case DIFF_LEVEL_WARNING:
			// 将所有警告级别的差异码合并到 WarningMask 中
			WarningMask |= diffCode
		default: // 忽略其他级别的差异码
		}
	}
	DefaultMask = CriticalMask | WarningMask | DIFF_BIT_NOMATCH | DIFF_BIT_NOMATCHKEY | DIFF_BIT_NOMATCHDOMAIN
}

// bitSet 设置对应bit位
func bitSet(data *uint32, bit uint32) bool {
	(*data) |= bit
	return ((*data) & bit) != 0
}

// Compare 对比两个*dns.Msg类型的DNS报文
// 分段比较原则，遇到验证差异，立即返回
func (c *Comparator) Compare(msg1, msg2 *dns.Msg, diffCode *uint32) error {
	if msg1 == nil && msg2 == nil {
		//return DNS_EQUAL
		return nil
	}
	if msg2 == nil || msg1 == nil {
		bitSet(diffCode, DIFF_BIT_NOMATCH)
		return nil
	}
	// 对比头部
	err := c.compareHeader(msg1, msg2, diffCode)
	if *diffCode&CriticalMask != 0 {
		return err
	}
	// 任意一方Truncated时，继续后面段对比
	// 对比Question
	err = c.cmpQuestions(msg1.Question, msg2.Question, diffCode)
	if *diffCode&CriticalMask != 0 {
		return err
	}
	// 对比 answers
	err = c.CmpAnswers(msg1.Answer, msg2.Answer, diffCode)
	if *diffCode&CriticalMask != 0 {
		return err
	}
	// 对比Authority
	err = c.cmpAuthAddRRs(msg1.Ns, msg2.Ns, diffCode, true)
	if *diffCode&CriticalMask != 0 {
		return err
	}
	// 对比Additional
	if !c.IgnoreAdditional {
		err = c.cmpAuthAddRRs(msg1.Extra, msg2.Extra, diffCode, false)
		if *diffCode&CriticalMask != 0 {
			return err
		}
	}
	return nil
}

// 对比Header关键字段
// 返回值：返回值在diffCode中
func (c *Comparator) compareHeader(msg1, msg2 *dns.Msg, diffCode *uint32) error {
	if msg1.Opcode != msg2.Opcode {
		bitSet(diffCode, DIFF_BIT_HEAD_OPCODE)
	}
	if msg1.Rcode != msg2.Rcode {
		// 涉及SERVFAIL的Rcode差异单独标记，与其他Rcode差异区分
		if msg1.Rcode == dns.RcodeServerFailure || msg2.Rcode == dns.RcodeServerFailure {
			bitSet(diffCode, DIFF_BIT_HEAD_RCODE_SF)
		} else {
			bitSet(diffCode, DIFF_BIT_HEAD_RCODE)
		}
	}
	// AA标志差异单独标记，与其他标志差异区分
	if msg1.Authoritative != msg2.Authoritative {
		bitSet(diffCode, DIFF_BIT_HEAD_AA)
	}
	// 其余标志差异（AA已单独处理，TC统一归入QFLAG）
	if msg1.Response != msg2.Response ||
		msg1.Truncated != msg2.Truncated ||
		msg1.RecursionDesired != msg2.RecursionDesired ||
		msg1.RecursionAvailable != msg2.RecursionAvailable ||
		msg1.Zero != msg2.Zero {
		bitSet(diffCode, DIFF_BIT_HEAD_QFLAG)
	}
	if len(msg1.Question) != len(msg2.Question) {
		bitSet(diffCode, DIFF_BIT_QUEST_LEN)
	}
	return nil
}

// cmpQuestions 对比DNS返回体中的Question段
// 返回值：返回值在diffCode中
func (c *Comparator) cmpQuestions(q1, q2 []dns.Question, diffCode *uint32) error {
	len1 := len(q1)
	len2 := len(q2)
	// 处理空列表特殊情况
	if len1 == 0 && len2 == 0 {
		return nil
	}
	// 检查长度差异
	if len1 != len2 {
		bitSet(diffCode, DIFF_BIT_QUEST_LEN)
		return nil
	}
	// 逐个比较Question
	for i := range len1 {
		// 比较域名（不区分大小写）
		if !strings.EqualFold(q1[i].Name, q2[i].Name) {
			bitSet(diffCode, DIFF_BIT_QUEST_QNAME)
		}
		// 比较查询类型
		if q1[i].Qtype != q2[i].Qtype {
			bitSet(diffCode, DIFF_BIT_QUEST_QTYPE)
		}
		// 比较查询类
		if q1[i].Qclass != q2[i].Qclass {
			bitSet(diffCode, DIFF_BIT_QUEST_QCLASS)
		}

		// 发现关键差异后提前退出（Question段差异属于CRITICAL级别）
		if *diffCode&CriticalMask != 0 {
			break
		}
	}
	return nil
}

// CmpAnswers 对比Answer段的RR集合
// 通常是一个返回体内的Answer的RR集合对比，也支持多次dig结果合并后的对比
/* 回复多条 RR的有回复相同的，也有回复多条不同的 name 的 rr，形如：
Queries
 www.baidu.com: type A, class IN
Answers
 www.baidu.com: type CNAME, class IN, cname www.a.shifen.com
 www.a.shifen.com: type CNAME, class IN, cname www.wshifen.com
 www.wshifen.com: type A, class IN, addr 103.235.46.96
 www.wshifen.com: type A, class IN, addr 103.235.47.188
Additional records
*/
func (c *Comparator) CmpAnswers(rrs1, rrs2 []dns.RR, diffCode *uint32) error {
	len1 := len(rrs1)
	len2 := len(rrs2)
	// 处理空列表特殊情况
	if len1 == 0 && len2 == 0 {
		return nil
	}
	// 单个为0，判定为不同
	if len1 == 0 || len2 == 0 {
		bitSet(diffCode, DIFF_BIT_ANSWER_01)
		return nil
	}
	// 条数不同且不允许部分一致，判定为不同
	if len1 != len2 && !c.AllowPartialMatch {
		bitSet(diffCode, DIFF_BIT_ANSWER_LEN)
		return nil
	}
	// 预处理RR列表，分离CNAME和其他记录
	cname1, other1 := c.preProcRRs(rrs1)
	cname2, other2 := c.preProcRRs(rrs2)
	// 对比CNAME链（只比较首尾一致）
	isSameCname := c.sameCnameChains(cname1, cname2)
	if !isSameCname {
		// CNAME链不一致，但如果A/AAAA结果一致，可以忽略CNAME差异
		if c.sameAResults(other1, other2) {
			logrus.Debug("Answer section: CNAME chain differs but A/AAAA results are same, ignoring CNAME diff")
		} else {
			bitSet(diffCode, DIFF_BIT_ANSWER_CNAME)
			return nil
		}
	}
	// 对比其他类型的RR记录
	rrdiff := c.cmpRRSet(other1, other2)
	if rrdiff == RRSetAllEqual {
		// 完全相同
		return nil
	}
	if rrdiff == RRSetPartEqual && c.AllowPartialMatch {
		// 部分相同且允许部分匹配
		logrus.WithFields(logrus.Fields{
			"rrs1_count": len(other1),
			"rrs2_count": len(other2),
		}).Debug("Answer section: partial match passed")
		return nil
	}

	// 存在差异
	bitSet(diffCode, DIFF_BIT_ANSWER_RRDIFF)
	return nil
}

// cmpAuthAddRRs 针对Auth和Add段的RR比较函数，由于错误码不同，Add的retDeta为10
func (c *Comparator) cmpAuthAddRRs(rrs1, rrs2 []dns.RR, diffCode *uint32, isAuth bool) error {
	len1 := len(rrs1)
	len2 := len(rrs2)
	// 处理空列表特殊情况
	if len1 == 0 && len2 == 0 {
		//return DNS_EQUAL
		return nil
	}
	// 单个为0，判定为不同; 条数都不同，判定为不同
	if (len1 == 0 || len2 == 0) || (len1 != len2 && !c.AllowPartialMatch) {
		if isAuth {
			bitSet(diffCode, DIFF_BIT_AUTH_LEN)
		} else {
			bitSet(diffCode, DIFF_BIT_ADD_LEN)
		}
		return nil
	}
	// 处理RR 列表
	cname1, other1 := c.preProcRRs(rrs1)
	cname2, other2 := c.preProcRRs(rrs2)
	// 对比CNAME链（只比较首尾一致）
	isSameCname := c.sameCnameChains(cname1, cname2)
	if !isSameCname {
		// CNAME链不一致，但如果A/AAAA结果一致，可以忽略CNAME差异
		if c.sameAResults(other1, other2) {
			logrus.Debug("Auth/Add section: CNAME chain differs but A/AAAA results are same, ignoring CNAME diff")
		} else {
			if isAuth {
				bitSet(diffCode, DIFF_BIT_AUTH_CNAME)
			} else {
				bitSet(diffCode, DIFF_BIT_ADD_CNAME)
			}
			return nil
		}
	}
	// 对比其他类型
	rrdiff := c.cmpRRSet(other1, other2)
	if rrdiff == RRSetAllEqual ||
		(rrdiff != RRSetAllDiff && c.AllowPartialMatch) {
		//return DNS_EQUAL
	} else {
		if isAuth {
			bitSet(diffCode, DIFF_BIT_AUTH_RRDIFF)
		} else {
			bitSet(diffCode, DIFF_BIT_ADD_RRDIFF)
		}
	}

	// Additional段不忽略时，比较OPT (EDNS) 中的ECS和Cookie选项
	if !isAuth {
		c.cmpOPTRecords(rrs1, rrs2, diffCode)
	}

	return nil
}

// DiffCode2Str 将 diffcode 转换为字符串
func DiffCode2Str(diffcode uint32) string {
	var builder strings.Builder
	builder.Grow(128) // 预分配内存（按平均长度估算）

	for _, flag := range diffFlags {
		if diffcode&flag.mask != 0 {
			if builder.Len() > 0 {
				builder.WriteByte('|')
			}
			builder.WriteString(flag.tag)
		}
	}
	if builder.Len() == 0 {
		return "EQUAL"
	}
	return builder.String()
}

// ApplyWhitelist 应用白名单过滤，移除白名单中的差异位
// 返回过滤后的diffCode
func (c *Comparator) ApplyWhitelist(diffCode uint32, domain string) uint32 {
	if c.WhitelistChecker == nil || diffCode == 0 {
		return diffCode
	}

	// 遍历所有差异位，检查是否在白名单中
	filteredCode := diffCode
	for _, flag := range diffFlags {
		if diffCode&flag.mask != 0 {
			// 检查该差异类型是否在白名单中
			if c.WhitelistChecker.IsWhitelisted(flag.tag, domain) {
				// 从diffCode中移除该位
				filteredCode &^= flag.mask
				logrus.Debugf("Whitelist applied: %s for domain %s", flag.tag, domain)
			}
		}
	}

	return filteredCode
}
