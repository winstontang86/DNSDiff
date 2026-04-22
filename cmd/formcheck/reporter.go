package main

import (
	"dnsdiff/internal/saver"
	"dnsdiff/internal/validate"
	"dnsdiff/pkg/types"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Reporter 负责记录详情日志
type Reporter struct {
	mu   sync.Mutex
	file *os.File
}

// NewReporter 创建新的报告器
func NewReporter() (*Reporter, error) {
	filename := fmt.Sprintf("checkdetail_%s.txt", time.Now().Format("0102_150405")) // mmddhhmmss
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return &Reporter{file: file}, nil
}

// Close 关闭文件
func (r *Reporter) Close() {
	if r.file != nil {
		r.file.Close()
	}
}

// WriteReq 写入请求详情
func (r *Reporter) WriteReq(req *types.DNSReq, errBits, warnBits uint64, msg *dns.Msg, details []string) {
	r.write("REQ", req.ClientIP, req.ClientPort, req.Time, req.RawData, errBits, warnBits, msg, details)
}

// WriteRsp 写入响应详情
func (r *Reporter) WriteRsp(rsp *types.DNSRsp, errBits, warnBits uint64, msg *dns.Msg, details []string) {
	r.write("RSP", rsp.ClientIP, rsp.ClientPort, rsp.Time, rsp.RawData, errBits, warnBits, msg, details)
}

func (r *Reporter) write(typ, ip, port string, ts time.Time, raw []byte, errBits, warnBits uint64, msg *dns.Msg, details []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] [%s:%s] [Type: %s]\n", ts.Format("15:04:05.000"), ip, port, typ))

	// 打印错误位名称
	if errBits != 0 {
		sb.WriteString("Errors:   ")
		var names []string
		for i := 0; i < 64; i++ {
			bit := uint64(1) << i
			if errBits&bit != 0 {
				if name, ok := validate.ErrorBitNames[bit]; ok {
					names = append(names, name)
				} else {
					names = append(names, fmt.Sprintf("Unknown(0x%x)", bit))
				}
			}
		}
		sb.WriteString(strings.Join(names, ", ") + "\n")
	}

	// 打印警告位名称
	if warnBits != 0 {
		sb.WriteString("Warnings: ")
		var names []string
		for i := 0; i < 64; i++ {
			bit := uint64(1) << i
			if warnBits&bit != 0 {
				if name, ok := validate.WarningBitNames[bit]; ok {
					names = append(names, name)
				} else {
					names = append(names, fmt.Sprintf("Unknown(0x%x)", bit))
				}
			}
		}
		sb.WriteString(strings.Join(names, ", ") + "\n")
	}

	// 打印详细描述
	if len(details) > 0 {
		sb.WriteString("Details:\n")
		for _, d := range details {
			sb.WriteString(fmt.Sprintf("  - %s\n", d))
		}
	}

	// 打印报文详情
	if msg != nil {
		// 复用 saver 包的格式化能力
		// 注意：BuildDNSContent 的第二个参数是 diff number，这里我们不需要，传 0 即可
		// 但 BuildDNSContent 会打印 START/END 标记，我们可能需要稍微容忍一下，或者自己封装
		// 鉴于 BuildDNSContent 已经包含了比较好的格式化，直接用即可。
		content := saver.BuildDNSContent(msg, 0)
		sb.WriteString(content)
	} else {
		// 解析失败，打印 Hex Dump
		sb.WriteString("Parse Failed. Hex Dump:\n")
		sb.WriteString(hex.Dump(raw))
		sb.WriteString("\n")
	}

	sb.WriteString("--------------------------------------------------\n")
	r.file.WriteString(sb.String())
}
