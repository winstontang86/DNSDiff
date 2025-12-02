// Package saver 保存差异回包的文本到两个 diff 文件，方便 beyondcompared 对比
package saver

import (
	"bufio"
	"dnsdiff/pkg/types"
	"fmt"
	"os"
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
	// buildDNSContent 支持msg为nil的情况
	content := buildDNSContent(msg, num)
	if _, err := buffw.WriteString(content); err != nil {
		// 打印错误日志，逻辑继续
		logrus.WithFields(logrus.Fields{
			"dnsid":  dnsid,
			"domain": domain,
		}).Errorf("Save: write file error! %v", err)
	}

	return nil
}

// buildDNSContent 构造DNS内容的字符串表示（dns.Msg 类型）
// 函数支持msg为nil的情况
func buildDNSContent(msg *dns.Msg, num int) string {
	var sb strings.Builder
	// 如果msg是nil，只打印一个头，没有内容
	if msg == nil {
		sb.WriteString(
			fmt.Sprintf(
				"# star %d------------------The number %d----------------***#\n;; opcode: %s, rcode: %d, id: %d\n",
				num, num, "query", 0, 0))
		return sb.String()
	}
	// 头部信息
	sb.WriteString(
		fmt.Sprintf("# star %d------------------The number %d----------------***#\n;; opcode: %s, rcode: %d, id: %d\n",
			num, num, dns.OpcodeToString[msg.Opcode], msg.Rcode, msg.Id))

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
			sb.WriteString(fmt.Sprintf("%-30s\t%s\t%s\n",
				formatDomainName(q.Name),
				dns.TypeToString[q.Qtype],
				dns.ClassToString[q.Qclass]))
		}
	}
	// 回答部分
	if len(msg.Answer) > 0 {
		sb.WriteString(";; ANSWER SECTION:\n")
		for _, rr := range msg.Answer {
			sb.WriteString(formatRR(rr))
		}
	}
	// 权威部分
	if len(msg.Ns) > 0 {
		sb.WriteString(";; AUTHORITY SECTION:\n")
		for _, rr := range msg.Ns {
			sb.WriteString(formatRR(rr))
		}
	}
	// 附加部分
	if len(msg.Extra) > 0 {
		sb.WriteString(";; ADDITIONAL SECTION:\n")
		for _, rr := range msg.Extra {
			sb.WriteString(formatRR(rr))
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

	return sb.String()
}

// 辅助函数：格式化资源记录
func formatRR(rr dns.RR) string {
	header := rr.Header()

	// 基本字段
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
		parts = append(parts, rr.String())
	}

	return fmt.Sprintf("%-30s\t%-7s\t%-5s\t%-8s\t%s\n",
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
