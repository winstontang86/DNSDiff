package types

import (
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

// DNSRspToMsg 从 *DNSRsp 中获取 *dns.Msg
// 该函数将 DNSRsp 结构中的 layers.DNS 数据转换为标准的 dns.Msg 格式
func DNSRspToMsg(rsp *DNSRsp) (*dns.Msg, error) {
	if rsp == nil {
		return nil, fmt.Errorf("DNSRspToMsg: rsp is nil")
	}

	if rsp.DnsData == nil {
		return nil, fmt.Errorf("DNSRspToMsg: rsp.DnsData is nil")
	}

	// 使用 LayersDNSToMsg 进行转换
	return LayersDNSToMsg(rsp.DnsData)
}

// LayersDNSToMsg 将 *layers.DNS 转换为 *dns.Msg
// 该函数通过获取 layers.DNS 的原始二进制数据，然后使用 dns.Msg.Unpack 进行解析
func LayersDNSToMsg(layerDNS *layers.DNS) (*dns.Msg, error) {
	if layerDNS == nil {
		return nil, fmt.Errorf("LayersDNSToMsg: layerDNS is nil")
	}

	// 获取 DNS 层的原始二进制数据
	rawData := layerDNS.LayerContents()
	if len(rawData) == 0 {
		return nil, fmt.Errorf("LayersDNSToMsg: empty DNS data")
	}

	// 使用 BytesToDNSMsg 进行转换
	msg, err := BytesToDNSMsg(rawData)
	if err != nil {
		return nil, fmt.Errorf("LayersDNSToMsg: failed to convert DNS data: %w", err)
	}

	if msg == nil {
		return nil, fmt.Errorf("LayersDNSToMsg: converted msg is nil")
	}

	return msg, nil
}

// BytesToDNSMsg 直接使用标准库解析DNS二进制数据
func BytesToDNSMsg(data []byte) (*dns.Msg, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("DNS解析失败: %w", err)
	}
	return msg, nil
}
