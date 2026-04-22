package types

import (
	"testing"

	"github.com/miekg/dns"
)

// 辅助函数：创建一个简单的 DNS 请求报文
func createTestDNSRequest(name string, qtype uint16) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	data, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return data
}

// 辅助函数：创建一个简单的 DNS 响应报文
func createTestDNSResponse(name string, qtype uint16) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	rr, _ := dns.NewRR(name + ". 300 IN A 1.2.3.4")
	msg.Answer = []dns.RR{rr}
	data, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return data
}

func TestBytesToDNSMsg_ValidData(t *testing.T) {
	rawData := createTestDNSRequest("example.com", dns.TypeA)

	msg, err := BytesToDNSMsg(rawData)
	if err != nil {
		t.Fatalf("未预期的错误: %v", err)
	}
	if msg == nil {
		t.Fatal("期望非 nil 消息")
	}
	if len(msg.Question) != 1 {
		t.Errorf("期望 1 个 question，得到 %d", len(msg.Question))
	}
	if msg.Question[0].Name != "example.com." {
		t.Errorf("期望域名 example.com.，得到 %s", msg.Question[0].Name)
	}
	if msg.Question[0].Qtype != dns.TypeA {
		t.Errorf("期望查询类型 A，得到 %d", msg.Question[0].Qtype)
	}
}

func TestBytesToDNSMsg_EmptyData(t *testing.T) {
	_, err := BytesToDNSMsg([]byte{})
	if err == nil {
		t.Error("期望错误，但未得到")
	}
}

func TestBytesToDNSMsg_InvalidData(t *testing.T) {
	invalidData := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	_, err := BytesToDNSMsg(invalidData)
	if err == nil {
		t.Error("期望错误，但未得到")
	}
}

func TestBytesToDNSMsg_ResponseData(t *testing.T) {
	rawData := createTestDNSResponse("example.com", dns.TypeA)

	msg, err := BytesToDNSMsg(rawData)
	if err != nil {
		t.Fatalf("未预期的错误: %v", err)
	}
	if msg == nil {
		t.Fatal("期望非 nil 消息")
	}
	if !msg.Response {
		t.Error("期望 Response=true")
	}
	if len(msg.Answer) != 1 {
		t.Errorf("期望 1 条 answer，得到 %d", len(msg.Answer))
	}
}

func TestDNSRspToMsg_NilRsp(t *testing.T) {
	_, err := DNSRspToMsg(nil)
	if err == nil {
		t.Error("期望 nil rsp 返回错误")
	}
}

func TestDNSRspToMsg_EmptyRawData(t *testing.T) {
	rsp := &DNSRsp{
		RawData: []byte{},
	}
	_, err := DNSRspToMsg(rsp)
	if err == nil {
		t.Error("期望空 RawData 返回错误")
	}
}

func TestDNSRspToMsg_ValidRsp(t *testing.T) {
	rawData := createTestDNSResponse("example.com", dns.TypeA)
	rsp := &DNSRsp{
		ClientIP:   "10.0.0.1",
		ClientPort: "12345",
		RawData:    rawData,
	}

	msg, err := DNSRspToMsg(rsp)
	if err != nil {
		t.Fatalf("未预期的错误: %v", err)
	}
	if msg == nil {
		t.Fatal("期望非 nil 消息")
	}
	if !msg.Response {
		t.Error("期望 Response=true")
	}
	if len(msg.Question) != 1 {
		t.Fatalf("期望 1 个 question，得到 %d", len(msg.Question))
	}
	if msg.Question[0].Name != "example.com." {
		t.Errorf("期望域名 example.com.，得到 %s", msg.Question[0].Name)
	}
}

func TestDNSRspToMsg_InvalidRawData(t *testing.T) {
	rsp := &DNSRsp{
		RawData: []byte{0xFF, 0xFF, 0xFF, 0xFF},
	}
	_, err := DNSRspToMsg(rsp)
	if err == nil {
		t.Error("期望无效 RawData 返回错误")
	}
}

func TestDNSRspToMsg_NilRawData(t *testing.T) {
	rsp := &DNSRsp{
		RawData: nil,
	}
	_, err := DNSRspToMsg(rsp)
	if err == nil {
		t.Error("期望 nil RawData 返回错误")
	}
}

// 测试常量
func TestUseClientInfo(t *testing.T) {
	if !UseClientInfo {
		t.Error("期望 UseClientInfo 为 true")
	}
}

// 测试 RspMap 类型的基本使用
func TestRspMap_BasicUsage(t *testing.T) {
	rspMap := make(RspMap)

	rawData := createTestDNSResponse("test.com", dns.TypeA)
	rsp := &DNSRsp{
		ClientIP:   "10.0.0.1",
		ClientPort: "12345",
		RawData:    rawData,
	}

	key := uint64(1<<48 | 0<<32 | uint64(dns.TypeA)<<16 | 1234)
	secdMap := make(map[string]*DNSRsp)
	secdMap["test.com."] = rsp
	rspMap[key] = secdMap

	// 验证可以正确读取
	if _, ok := rspMap[key]; !ok {
		t.Error("期望在 RspMap 中找到 key")
	}
	if got, ok := rspMap[key]["test.com."]; !ok || got != rsp {
		t.Error("期望在二级 map 中找到 rsp")
	}
}

// 测试 SaveChan 类型
func TestSaveChan_BasicUsage(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	sc := SaveChan{
		Old: msg,
		New: msg,
	}

	if sc.Old == nil || sc.New == nil {
		t.Error("期望 SaveChan 的 Old 和 New 不为 nil")
	}
}

// 测试 DNSReq 类型
func TestDNSReq_Fields(t *testing.T) {
	req := &DNSReq{
		ClientIP:   "192.168.1.1",
		ClientPort: "53",
		IsTCP:      true,
		RawData:    []byte{0x00, 0x01},
	}

	if req.ClientIP != "192.168.1.1" {
		t.Errorf("ClientIP 不匹配")
	}
	if req.ClientPort != "53" {
		t.Errorf("ClientPort 不匹配")
	}
	if !req.IsTCP {
		t.Error("期望 IsTCP 为 true")
	}
}

// 测试 DNSRsp 与 Req 关联
func TestDNSRsp_WithReq(t *testing.T) {
	req := &DNSReq{
		ClientIP:   "10.0.0.1",
		ClientPort: "12345",
		RawData:    createTestDNSRequest("example.com", dns.TypeA),
	}

	rsp := &DNSRsp{
		ClientIP:   "10.0.0.1",
		ClientPort: "12345",
		RawData:    createTestDNSResponse("example.com", dns.TypeA),
		Req:        req,
	}

	if rsp.Req == nil {
		t.Error("期望 Req 不为 nil")
	}
	if rsp.Req.ClientIP != rsp.ClientIP {
		t.Error("期望 Req 和 Rsp 的 ClientIP 一致")
	}
}
