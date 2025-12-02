// Package types 定义DNS处理相关的公共数据类型
package types

import (
	"time"

	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

const (
	// UseClientInfo 是否使用客户端信息作为key的一部分
	UseClientInfo bool = true
)

// RspMap 响应报文map
// qclass+opcode+dnsid+qtype组合成 uint64 的 key
// qname 作为 map 的 key，如果数据量非常大，用hash缓存uint64会省空间，但有可能会出现冲突
// dnsrsp 作为 map 的 value
type RspMap map[uint64]map[string]*DNSRsp

// DNSReq DNS请求报文，DNS 报文内容直接在 data 中保存原始二进制数据
type DNSReq struct {
	ClientIP   string
	ClientPort string
	IsTCP      bool
	Time       time.Time
	RawData    []byte // DNS报文原始二进制数据
}

// DNSRsp DNS响应报文
type DNSRsp struct {
	ClientIP   string
	ClientPort string
	IsTCP      bool
	Time       time.Time
	DnsData    *layers.DNS
	Req        *DNSReq // 关联的请求
}

// SaveChan 保存差异用的
type SaveChan struct {
	Old *dns.Msg
	New *dns.Msg
}
