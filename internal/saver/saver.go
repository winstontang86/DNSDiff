// Package saver 保存差异回包的文本到两个 diff 文件，方便 beyondcompared 对比
package saver

import (
	"bufio"
	"dnsdiff/pkg/types"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// SaveDiff 保存到两个差异文件中，方便用beyondcompare 对比查看
func SaveDiff(save <-chan types.SaveChan) error {
	// 文件添加月日时后缀
	diffCnt := 0
	now := time.Now()
	timeSuffix := now.Format("0102150405")
	diffOldFile := fmt.Sprintf("%s-%s.txt", "./diffold", timeSuffix)
	diffNewFile := fmt.Sprintf("%s-%s.txt", "./diffnew", timeSuffix)
	// 创建或打开文件
	oldFile, err := os.OpenFile(diffOldFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer oldFile.Close()
	newFile, err := os.OpenFile(diffNewFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer newFile.Close()
	// 创建文件缓冲
	oldWriter := bufio.NewWriter(oldFile)
	newWriter := bufio.NewWriter(newFile)
	defer oldWriter.Flush()
	defer newWriter.Flush()
	// 不断的从通道中读取数据，并保存到文件
	for data := range save {
		diffCnt++
		logrus.Infof("Save: diffCnt= %d", diffCnt)
		if data.Old == nil && data.New == nil {
			logrus.WithFields(logrus.Fields{
				"Old": data.Old,
				"New": data.New,
			}).Errorf("Save: data.Old and data.New is nil!")
			continue
		}
		procLayerData(data.Old, oldWriter, diffCnt)
		procLayerData(data.New, newWriter, diffCnt)
	}

	return nil
}

// procLayerData 处理层
// 函数支持msg为nil的情况
func procLayerData(msg *dns.Msg, buffw *bufio.Writer, num int) error {
	if buffw == nil {
		return nil
	}
	dnsid := 0
	domain := "unknown"
	if msg != nil && len(msg.Question) > 0 {
		dnsid = int(msg.Id)
		domain = msg.Question[0].Name
	}
	// BuildDNSContent 支持msg为nil的情况
	content := BuildDNSContent(msg, num)
	if _, err := buffw.WriteString(content); err != nil {
		// 打印错误日志，逻辑继续
		logrus.WithFields(logrus.Fields{
			"dnsid":  dnsid,
			"domain": domain,
		}).Errorf("Save: write file error! %v", err)
	}

	return nil
}

// BuildDNSContent 构造DNS内容的字符串表示（dns.Msg 类型）
// 函数支持msg为nil的情况
// 优化点：1.对记录排序避免顺序差异 2.使用清晰的分隔符 3.固定列宽对齐
func BuildDNSContent(msg *dns.Msg, num int) string {
	var sb strings.Builder
	// 如果msg是nil，只打印一个头，没有内容
	if msg == nil {
		sb.WriteString(fmt.Sprintf("#===== [%04d] START ===== diff number: %d | dnsid: %d =====\n", num, num, 0))
		sb.WriteString(";; opcode: QUERY, rcode: 0 (NOERROR)\n")
		sb.WriteString(";; (empty content)\n")
		sb.WriteString(fmt.Sprintf("#===== [%04d] END ======= diff number: %d | dnsid: %d =====\n\n", num, num, 0))
		return sb.String()
	}

	// 获取查询域名用于标题
	queryDomain := "unknown"
	if len(msg.Question) > 0 {
		queryDomain = msg.Question[0].Name
	}

	// 头部信息 - 使用更清晰的分隔符格式
	sb.WriteString(fmt.Sprintf("#===== [%04d] START ===== diff number: %d | dnsid: %d | domain: %s =====\n",
		num, num, msg.Id, queryDomain))
	sb.WriteString(fmt.Sprintf(";; opcode: %s, rcode: %d (%s)\n",
		dns.OpcodeToString[msg.Opcode], msg.Rcode, dns.RcodeToString[msg.Rcode]))

	flags := []string{}
	if msg.Response {
		flags = append(flags, "qr")
	}
	if msg.Authoritative {
		flags = append(flags, "aa")
	}
	if msg.Truncated {
		flags = append(flags, "tc")
	}
	if msg.RecursionDesired {
		flags = append(flags, "rd")
	}
	if msg.RecursionAvailable {
		flags = append(flags, "ra")
	}
	if msg.Zero {
		flags = append(flags, "z")
	}
	if msg.AuthenticatedData {
		flags = append(flags, "ad")
	}
	if msg.CheckingDisabled {
		flags = append(flags, "cd")
	}
	sb.WriteString(fmt.Sprintf(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		strings.Join(flags, " "),
		len(msg.Question),
		len(msg.Answer),
		len(msg.Ns),
		len(msg.Extra)))

	// 问题部分
	if len(msg.Question) > 0 {
		sb.WriteString(";; QUESTION SECTION:\n")
		for _, q := range msg.Question {
			sb.WriteString(fmt.Sprintf("  %-40s  %-6s  %s\n",
				formatDomainName(q.Name),
				dns.ClassToString[q.Qclass],
				dns.TypeToString[q.Qtype]))
		}
	}
	// 回答部分
	if len(msg.Answer) > 0 {
		sb.WriteString(";; ANSWER SECTION:\n")
		for _, rr := range msg.Answer {
			sb.WriteString(formatRR(rr))
		}
	}
	// 权威部分 - 排序后输出
	if len(msg.Ns) > 0 {
		sb.WriteString(";; AUTHORITY SECTION:\n")
		for _, rr := range sortRRs(msg.Ns) {
			sb.WriteString(formatRR(rr))
		}
	}
	// 附加部分 - 排序后输出（跳过OPT记录，OPT单独处理）
	if len(msg.Extra) > 0 {
		extraRRs := filterNonOPT(msg.Extra)
		if len(extraRRs) > 0 {
			sb.WriteString(";; ADDITIONAL SECTION:\n")
			for _, rr := range sortRRs(extraRRs) {
				sb.WriteString(formatRR(rr))
			}
		}
	}
	// EDNS0 信息
	if opt := msg.IsEdns0(); opt != nil {
		sb.WriteString(";; OPT PSEUDOSECTION:\n")
		sb.WriteString(fmt.Sprintf("; EDNS: version: %d, flags: %s; udp: %d\n",
			opt.Version(),
			ednsFlagsToString(opt),
			opt.UDPSize()))
	}

	// end行 - 使用与start对应的格式
	sb.WriteString(fmt.Sprintf("#===== [%04d] END ======= diff number: %d | dnsid: %d =====\n\n", num, num, msg.Id))

	return sb.String()
}

// sortRRs 对资源记录进行排序，避免顺序不同导致的差异
// 排序规则：先按类型，再按名称，最后按数据内容
func sortRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) <= 1 {
		return rrs
	}
	// 复制切片，避免修改原始数据
	sorted := make([]dns.RR, len(rrs))
	copy(sorted, rrs)

	sort.Slice(sorted, func(i, j int) bool {
		hi, hj := sorted[i].Header(), sorted[j].Header()
		// 1. 先按记录类型排序
		if hi.Rrtype != hj.Rrtype {
			return hi.Rrtype < hj.Rrtype
		}
		// 2. 再按名称排序
		if hi.Name != hj.Name {
			return hi.Name < hj.Name
		}
		// 3. 最后按完整字符串排序（包含数据部分）
		return sorted[i].String() < sorted[j].String()
	})
	return sorted
}

// filterNonOPT 过滤掉OPT记录（OPT记录单独处理）
func filterNonOPT(rrs []dns.RR) []dns.RR {
	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); !ok {
			result = append(result, rr)
		}
	}
	return result
}

// 辅助函数：格式化资源记录
// 使用固定列宽格式化，便于BeyondCompare对比
func formatRR(rr dns.RR) string {
	header := rr.Header()

	// 基本字段 - 使用固定宽度
	parts := []string{
		formatDomainName(header.Name),
		strconv.Itoa(int(header.Ttl)),
		dns.ClassToString[header.Class],
		dns.TypeToString[header.Rrtype],
	}

	// 特殊类型处理
	switch v := rr.(type) {
	case *dns.A:
		if v.A != nil {
			parts = append(parts, v.A.String())
		}
	case *dns.AAAA:
		if v.AAAA != nil {
			parts = append(parts, v.AAAA.String())
		}
	case *dns.CNAME:
		parts = append(parts, formatDomainName(v.Target))
	case *dns.MX:
		parts = append(parts, fmt.Sprintf("%d %s", v.Preference, formatDomainName(v.Mx)))
	case *dns.NS:
		parts = append(parts, formatDomainName(v.Ns))
	case *dns.TXT:
		parts = append(parts, strings.Join(v.Txt, " "))
	case *dns.SOA:
		parts = append(parts, fmt.Sprintf("%s %s %d %d %d %d %d",
			formatDomainName(v.Ns),
			formatDomainName(v.Mbox),
			v.Serial,
			v.Refresh,
			v.Retry,
			v.Expire,
			v.Minttl))
	case *dns.SRV:
		parts = append(parts, fmt.Sprintf("%d %d %d %s",
			v.Priority,
			v.Weight,
			v.Port,
			formatDomainName(v.Target)))
	case *dns.PTR:
		parts = append(parts, formatDomainName(v.Ptr))
	case *dns.DS:
		parts = append(parts, fmt.Sprintf("%d %d %d %s",
			v.KeyTag, v.Algorithm, v.DigestType, v.Digest))
	default:
		// 从 rr.String() 中提取 rdata 部分，避免 name/ttl/class/type 重复输出
		// rr.String() 格式通常为 "name\tttl\tclass\ttype\trdata"
		rrStr := rr.String()
		fields := strings.SplitN(rrStr, "\t", 5)
		if len(fields) >= 5 {
			parts = append(parts, fields[4])
		} else {
			// 兜底：如果格式不符合预期，使用完整字符串
			parts = append(parts, rrStr)
		}
	}

	// 使用固定列宽和空格对齐，而非tab（tab在不同编辑器显示不一致）
	return fmt.Sprintf("  %-40s  %-7s  %-5s  %-8s  %s\n",
		parts[0],                     // Name
		parts[1],                     // TTL
		parts[2],                     // Class
		parts[3],                     // Type
		strings.Join(parts[4:], " ")) // Data
}

// 格式化域名（保留末尾点）
func formatDomainName(name string) string {
	if name == "." || name == "" {
		return name
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// EDNS标志转换
func ednsFlagsToString(opt *dns.OPT) string {
	var flags []string
	if opt.Do() {
		flags = append(flags, "do")
	}
	// 其他EDNS标志可以在此扩展
	return strings.Join(flags, " ")
}
