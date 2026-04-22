// Package diff RR comparison functions for DNS resource records
package diff

import (
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type IPv4Rdata [4]byte
type IPv6Rdata [16]byte

var (
	RRSetAllEqual  = 0
	RRSetPartEqual = 1
	RRSetAllDiff   = 2
)

// preProcRRs 预处理RR列表，
// 目的是将cname记录和非cname记录分开；目的2是对一些已知类型，把要比较的内容拼在key上，后续直接使用key进行比较
// 返回:
//   - cnameMap: map[string]string, CNAME: name -> target
//   - otherMap: map[string]struct{}, 存储A/AAAA和其他类型记录的key集合
/*
记录类型关键字段
AA (IP)
AAAAAAAA (IP)
CNAMETarget (string)不区分大小写比较
MXPreference, Mx两者都需匹配，Mx不区分大小写
NSNs (string)不区分大小写比较
TXTTxt ([]string)比较字符串切片，区分大小写
SOANs, Mbox, TimersSerial 字段通常需忽略或特殊处理
SRVPriority, Weight, Port, Target所有字段都需匹配，Target不区分大小写
PTRPtr (string)不区分大小写比较
*/
func (c *Comparator) preProcRRs(rrs []dns.RR) (map[string]string, map[string]struct{}) {
	cnameMap := make(map[string]string, len(rrs))
	otherMap := make(map[string]struct{}, len(rrs))

	// 预分配 strings.Builder，减少内存分配
	var keyBuilder strings.Builder
	keyBuilder.Grow(512) // 预分配合理大小
	// 用不同类型的核心字段拼成string做key，name type class是必须的（class差异基本不存在，忽略）
	// 注意：TTL 差异不参与比较，统一忽略
	for _, rr := range rrs {
		// P0: Skip OPT pseudo-records (EDNS). OPT uses CLASS for UDP payload size
		// and TTL for extended RCODE/version/flags, which differ between servers
		// and produce meaningless diffs in the Additional section.
		if _, isOPT := rr.(*dns.OPT); isOPT {
			continue
		}

		hdr := rr.Header()
		name := strings.ToLower(hdr.Name) // 统一小写处理
		rrType := dns.TypeToString[hdr.Rrtype]

		switch rr := rr.(type) {
		case *dns.CNAME:
			// CNAME: name -> target（CNAME 通常不需要比较 TTL）
			cnameMap[name] = strings.ToLower(rr.Target)

		case *dns.A:
			// A记录: "name|A|ip" -> rr
			// 使用 strings.Builder 减少字符串拼接开销
			keyBuilder.Reset()
			keyBuilder.WriteString(name)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrType)
			keyBuilder.WriteByte('|')
			keyBuilder.Write(rr.A)
			otherMap[keyBuilder.String()] = struct{}{}

		case *dns.AAAA:
			// AAAA记录: "name|AAAA|ip" -> rr
			keyBuilder.Reset()
			keyBuilder.WriteString(name)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrType)
			keyBuilder.WriteByte('|')
			keyBuilder.Write(rr.AAAA)
			otherMap[keyBuilder.String()] = struct{}{}

		case *dns.SOA:
			// SOA记录: "name|SOA|ns|mbox" -> rr
			// SOA记录的关键字段是NS和Mbox，序列号等字段可能不同
			keyBuilder.Reset()
			keyBuilder.WriteString(name)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrType)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(strings.ToLower(rr.Ns))
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(strings.ToLower(rr.Mbox))
			otherMap[keyBuilder.String()] = struct{}{}

		case *dns.MX:
			// MX记录: "name|MX|preference|mx"
			keyBuilder.Reset()
			keyBuilder.WriteString(name)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrType)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(strings.ToLower(rr.Mx))
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(strconv.Itoa(int(rr.Preference)))
			otherMap[keyBuilder.String()] = struct{}{}

		case *dns.NS:
			// NS记录: "name|NS|ns"
			keyBuilder.Reset()
			keyBuilder.WriteString(name)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrType)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(strings.ToLower(rr.Ns))
			otherMap[keyBuilder.String()] = struct{}{}

		case *dns.TXT:
			// TXT记录: "name|TXT|txt_content"
			// 使用 \x00 作为 Txt 切片元素分隔符，避免与字段分隔符 "|" 冲突
			keyBuilder.Reset()
			keyBuilder.WriteString(name)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrType)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(strings.Join(rr.Txt, "\x00"))
			otherMap[keyBuilder.String()] = struct{}{}

		case *dns.PTR:
			// PTR记录: "name|PTR|ptr"
			keyBuilder.Reset()
			keyBuilder.WriteString(name)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrType)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(strings.ToLower(rr.Ptr))
			otherMap[keyBuilder.String()] = struct{}{}

		default:
			// 兜底逻辑：使用 dns.Copy 解决 Data Race，避免直接修改原始 RR
			rrCopy := dns.Copy(rr)
			if rrCopy == nil {
				rrCopy = rr // 降级：直接使用（避免修改原始 RR）
			}
			rrCopy.Header().Ttl = 0 // 统一忽略 TTL，安全修改副本

			keyBuilder.Reset()
			keyBuilder.WriteString(name)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrType)
			keyBuilder.WriteByte('|')
			keyBuilder.WriteString(rrCopy.String())
			otherMap[keyBuilder.String()] = struct{}{}
		}
	}

	return cnameMap, otherMap
}

// sameCnameChains 比较CNAME链（仅比较首尾一致）
// 策略：只要首跳（查询域名的第一个CNAME target）和尾跳（链最终指向的target）一致即可
// 中间的CNAME链路不要求完全一致，适用于不同DNS服务器可能返回不同中间链的场景
// CNAME: name -> target
func (c *Comparator) sameCnameChains(cname1, cname2 map[string]string) bool {
	// 两者都为空，认为相同
	if len(cname1) == 0 && len(cname2) == 0 {
		return true
	}
	// 一方为空另一方不为空，不同
	if len(cname1) == 0 || len(cname2) == 0 {
		return false
	}

	// 找到首跳：在cname1中找到不是其他CNAME target的name（即链的起点）
	first1, last1 := getCnameFirstAndLast(cname1)
	first2, last2 := getCnameFirstAndLast(cname2)

	// 比较首跳的 name 和 target
	if first1.name != first2.name || first1.target != first2.target {
		return false
	}
	// 比较尾跳的 target（链的最终指向）
	if last1 != last2 {
		return false
	}

	return true
}

// cnameHop 表示CNAME链中的一跳
type cnameHop struct {
	name   string
	target string
}

// getCnameFirstAndLast 从CNAME map中提取链的首跳和尾跳target
// 首跳：name不是任何其他CNAME的target（即链的入口）
// 尾跳：target不是任何其他CNAME的name（即链的末端指向）
func getCnameFirstAndLast(cnameMap map[string]string) (first cnameHop, lastTarget string) {
	if len(cnameMap) == 0 {
		return
	}

	// 构建所有target的集合和所有name的集合
	targets := make(map[string]struct{}, len(cnameMap))
	names := make(map[string]struct{}, len(cnameMap))
	for name, target := range cnameMap {
		targets[target] = struct{}{}
		names[name] = struct{}{}
	}

	// 找首跳：name不在targets中（即不是别人的target，是链的起点）
	for name, target := range cnameMap {
		if _, isTarget := targets[name]; !isTarget {
			first = cnameHop{name: name, target: target}
			break
		}
	}

	// 找尾跳：从首跳开始沿链走到底
	lastTarget = first.target
	visited := make(map[string]bool, len(cnameMap))
	visited[first.name] = true
	for {
		nextTarget, exists := cnameMap[lastTarget]
		if !exists || visited[lastTarget] {
			// 链结束或检测到环
			break
		}
		visited[lastTarget] = true
		lastTarget = nextTarget
	}

	return
}

// sameAResults 比较两组RR中的A和AAAA记录是否一致
// 用于当CNAME链不一致时，通过最终的IP记录一致性来判断是否存在实质差异
func (c *Comparator) sameAResults(other1, other2 map[string]struct{}) bool {
	// 从other集合中提取A和AAAA记录
	aSet1 := buildAResultSet(other1)
	aSet2 := buildAResultSet(other2)

	// 两者都为空，不认为A/AAAA一致（因为没有A/AAAA记录可比较）
	if len(aSet1) == 0 && len(aSet2) == 0 {
		return false
	}

	// 长度不同，不一致
	if len(aSet1) != len(aSet2) {
		return false
	}

	// 逐条检查
	for k := range aSet1 {
		if _, ok := aSet2[k]; !ok {
			return false
		}
	}
	return true
}

// buildAResultSet 从otherMap中提取A和AAAA类型的记录key集合
// otherMap中的key格式为 "name|TYPE|data"，只提取TYPE为A或AAAA的记录
func buildAResultSet(otherMap map[string]struct{}) map[string]struct{} {
	aSet := make(map[string]struct{})
	for k := range otherMap {
		// key格式: "name|TYPE|data"，提取TYPE部分
		firstPipe := strings.IndexByte(k, '|')
		if firstPipe < 0 {
			continue
		}
		rest := k[firstPipe+1:]
		secondPipe := strings.IndexByte(rest, '|')
		if secondPipe < 0 {
			continue
		}
		rrType := rest[:secondPipe]
		if rrType == "A" || rrType == "AAAA" {
			aSet[k] = struct{}{}
		}
	}
	return aSet
}

// cmpRRSet RR集合的通用比较函数
/*
全相同返回0  RRSetAllEqual
部分相同返回1  RRSetPartEqual
全部不同返回2RRSetAllDiff
*/
func (c *Comparator) cmpRRSet(m1, m2 map[string]struct{}) int {
	len1 := len(m1)
	len2 := len(m2)

	// 处理空集合
	if len1 == 0 && len2 == 0 {
		return RRSetAllEqual
	}
	if len1 == 0 || len2 == 0 {
		return RRSetAllDiff
	}

	// 快速路径：如果长度不同且不允许部分匹配，直接判定为不同
	if len1 != len2 && !c.AllowPartialMatch {
		return RRSetAllDiff
	}

	// 统计匹配和不匹配的数量
	matchCnt := 0
	diffCnt := 0

	// 遍历第一个集合，检查每个RR是否在第二个集合中
	for k := range m1 {
		_, exists := m2[k]
		if !exists {
			// key不存在，记录为差异
			diffCnt++
			// 优化：如果不允许部分匹配且已有差异，提前退出
			if !c.AllowPartialMatch {
				return RRSetAllDiff
			}
			continue
		}
		// key上特殊组装的，只要key一样，内容就是一样的
		matchCnt++
		// 加速：如果允许部分匹配，只要有一条匹配就可以提前返回
		if c.AllowPartialMatch && matchCnt > 0 {
			return RRSetPartEqual
		}
	}
	// 总差异是：len1+len2-2*matchCnt
	// 判断匹配程度
	if matchCnt == len1 && len1 == len2 {
		// 完全匹配
		return RRSetAllEqual
	}
	if matchCnt == 0 {
		// 完全不匹配
		return RRSetAllDiff
	}
	// 部分匹配
	return RRSetPartEqual
}

// extractOPT 从RR列表中查找第一个OPT伪记录。
// 如果没有找到OPT记录，返回nil。
func extractOPT(rrs []dns.RR) *dns.OPT {
	for _, rr := range rrs {
		if opt, ok := rr.(*dns.OPT); ok {
			return opt
		}
	}
	return nil
}

// extractECS 从OPT记录中提取第一个EDNS0_SUBNET（ECS）选项。
// 如果OPT为nil或不包含ECS选项，返回nil。
func extractECS(opt *dns.OPT) *dns.EDNS0_SUBNET {
	if opt == nil {
		return nil
	}
	for _, option := range opt.Option {
		if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
			return ecs
		}
	}
	return nil
}

// extractCookie 从OPT记录中提取第一个EDNS0_COOKIE选项。
// 如果OPT为nil或不包含Cookie选项，返回nil。
func extractCookie(opt *dns.OPT) *dns.EDNS0_COOKIE {
	if opt == nil {
		return nil
	}
	for _, option := range opt.Option {
		if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
			return cookie
		}
	}
	return nil
}

// sameECS 比较两个ECS选项是否相同。
// 比较Family、SourceNetmask和Address（按SourceNetmask掩码对齐后比较）。
// SourceScope是响应侧的缓存覆盖范围提示，对比时忽略。
func sameECS(ecs1, ecs2 *dns.EDNS0_SUBNET) bool {
	if ecs1.Family != ecs2.Family {
		return false
	}
	if ecs1.SourceNetmask != ecs2.SourceNetmask {
		return false
	}
	// 按SourceNetmask掩码对齐后比较地址
	var mask net.IPMask
	switch ecs1.Family {
	case 1: // IPv4地址族
		mask = net.CIDRMask(int(ecs1.SourceNetmask), 32)
	case 2: // IPv6地址族
		mask = net.CIDRMask(int(ecs1.SourceNetmask), 128)
	default:
		// 未知地址族：降级为直接字节比较
		return ecs1.Address.Equal(ecs2.Address)
	}
	masked1 := ecs1.Address.Mask(mask)
	masked2 := ecs2.Address.Mask(mask)
	return masked1.Equal(masked2)
}

// cmpOPTRecords 比较两条消息Additional段中的OPT（EDNS）记录。
// 仅比较ECS和Cookie选项，其他EDNS选项均忽略。
func (c *Comparator) cmpOPTRecords(rrs1, rrs2 []dns.RR, diffCode *uint32) {
	opt1 := extractOPT(rrs1)
	opt2 := extractOPT(rrs2)

	// 比较ECS选项
	ecs1 := extractECS(opt1)
	ecs2 := extractECS(opt2)
	if (ecs1 == nil) != (ecs2 == nil) {
		// 一侧有ECS，另一侧没有
		bitSet(diffCode, DIFF_BIT_ADD_OPT_ECS)
	} else if ecs1 != nil && ecs2 != nil {
		if !sameECS(ecs1, ecs2) {
			bitSet(diffCode, DIFF_BIT_ADD_OPT_ECS)
		}
	}

	// 比较Cookie选项
	cookie1 := extractCookie(opt1)
	cookie2 := extractCookie(opt2)
	if (cookie1 == nil) != (cookie2 == nil) {
		// 一侧有Cookie，另一侧没有
		bitSet(diffCode, DIFF_BIT_ADD_OPT_COOKIE)
	} else if cookie1 != nil && cookie2 != nil {
		if cookie1.Cookie != cookie2.Cookie {
			bitSet(diffCode, DIFF_BIT_ADD_OPT_COOKIE)
		}
	}
}
