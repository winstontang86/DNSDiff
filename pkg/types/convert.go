package types

import (
	"fmt"

	"github.com/miekg/dns"
)

// DNSRspToMsg 从 *DNSRsp 中获取 *dns.Msg
// 该函数将 DNSRsp 结构中的 RawData 数据转换为标准的 dns.Msg 格式
func DNSRspToMsg(rsp *DNSRsp) (*dns.Msg, error) {
	if rsp == nil {
		return nil, fmt.Errorf("DNSRspToMsg: rsp is nil")
	}

	if len(rsp.RawData) == 0 {
		return nil, fmt.Errorf("DNSRspToMsg: rsp.RawData is empty")
	}

	// 使用 BytesToDNSMsg 进行转换
	return BytesToDNSMsg(rsp.RawData)
}

// BytesToDNSMsg 直接使用标准库解析DNS二进制数据
func BytesToDNSMsg(data []byte) (*dns.Msg, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("DNS解析失败: %w", err)
	}
	return msg, nil
}
