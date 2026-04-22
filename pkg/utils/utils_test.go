package utils

import (
	"dnsdiff/pkg/types"
	"testing"

	"github.com/miekg/dns"
)

// 辅助函数：创建一个简单的 DNS 响应
func createTestDNSRsp(name string, qtype uint16, id uint16, clientIP, clientPort string) *types.DNSRsp {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.Id = id
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	rr, _ := dns.NewRR(name + ". 300 IN A 1.2.3.4")
	msg.Answer = []dns.RR{rr}
	data, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return &types.DNSRsp{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		RawData:    data,
	}
}

// ==================== Hash64 ====================

func TestHash64_BasicUsage(t *testing.T) {
	data := []byte("hello world")
	hash := Hash64(data)
	if hash == 0 {
		t.Error("hash 不应为 0")
	}
}

func TestHash64_Deterministic(t *testing.T) {
	data := []byte("test data")
	hash1 := Hash64(data)
	hash2 := Hash64(data)
	if hash1 != hash2 {
		t.Errorf("相同数据的 hash 应该相同: %d != %d", hash1, hash2)
	}
}

func TestHash64_DifferentData(t *testing.T) {
	hash1 := Hash64([]byte("data1"))
	hash2 := Hash64([]byte("data2"))
	if hash1 == hash2 {
		t.Error("不同数据的 hash 不应该相同")
	}
}

func TestHash64_EmptyData(t *testing.T) {
	// 空数据也应该能正常计算 hash
	hash := Hash64([]byte{})
	_ = hash // 只要不 panic 就行
}

// ==================== GenU64Key ====================

func TestGenU64Key_BasicUsage(t *testing.T) {
	key := GenU64Key(dns.ClassINET, dns.TypeA, 1234, 0)
	if key == 0 {
		t.Error("key 不应为 0")
	}
}

func TestGenU64Key_DifferentInputs(t *testing.T) {
	tests := []struct {
		name      string
		qclass    uint16
		qtype     uint16
		dnsID     uint16
		opcode    int
		expectKey uint64
	}{
		{
			name:      "标准 A 查询",
			qclass:    dns.ClassINET,
			qtype:     dns.TypeA,
			dnsID:     1234,
			opcode:    0,
			expectKey: uint64(dns.ClassINET)<<48 | uint64(0)<<32 | uint64(dns.TypeA)<<16 | uint64(1234),
		},
		{
			name:      "AAAA 查询",
			qclass:    dns.ClassINET,
			qtype:     dns.TypeAAAA,
			dnsID:     5678,
			opcode:    0,
			expectKey: uint64(dns.ClassINET)<<48 | uint64(0)<<32 | uint64(dns.TypeAAAA)<<16 | uint64(5678),
		},
		{
			name:      "不同 opcode",
			qclass:    dns.ClassINET,
			qtype:     dns.TypeA,
			dnsID:     100,
			opcode:    5,
			expectKey: uint64(dns.ClassINET)<<48 | uint64(5)<<32 | uint64(dns.TypeA)<<16 | uint64(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenU64Key(tt.qclass, tt.qtype, tt.dnsID, tt.opcode)
			if result != tt.expectKey {
				t.Errorf("期望 key=%d，得到 %d", tt.expectKey, result)
			}
		})
	}
}

func TestGenU64Key_Uniqueness(t *testing.T) {
	// 不同参数生成的 key 应该不同
	key1 := GenU64Key(dns.ClassINET, dns.TypeA, 1234, 0)
	key2 := GenU64Key(dns.ClassINET, dns.TypeAAAA, 1234, 0)
	key3 := GenU64Key(dns.ClassINET, dns.TypeA, 5678, 0)
	key4 := GenU64Key(dns.ClassINET, dns.TypeA, 1234, 5)

	keys := []uint64{key1, key2, key3, key4}
	seen := make(map[uint64]bool)
	for i, k := range keys {
		if seen[k] {
			t.Errorf("key[%d] = %d 重复", i, k)
		}
		seen[k] = true
	}
}

// ==================== GenSecdKey ====================

func TestGenSecdKey_WithClientInfo(t *testing.T) {
	// UseClientInfo 为 true
	result := GenSecdKey("example.com.", "10.0.0.1", "12345")
	expected := "example.com.*10.0.0.1:12345"
	if result != expected {
		t.Errorf("期望 %q，得到 %q", expected, result)
	}
}

func TestGenSecdKey_DifferentInputs(t *testing.T) {
	key1 := GenSecdKey("a.com.", "1.1.1.1", "100")
	key2 := GenSecdKey("b.com.", "1.1.1.1", "100")
	key3 := GenSecdKey("a.com.", "2.2.2.2", "100")
	key4 := GenSecdKey("a.com.", "1.1.1.1", "200")

	if key1 == key2 {
		t.Error("不同域名应生成不同 key")
	}
	if key1 == key3 {
		t.Error("不同 IP 应生成不同 key")
	}
	if key1 == key4 {
		t.Error("不同端口应生成不同 key")
	}
}

// ==================== Domain2Zone ====================

func TestDomain2Zone(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "三级域名",
			domain:   "www.example.com",
			expected: "www.example.com",
		},
		{
			name:     "四级域名取后三级",
			domain:   "sub.www.example.com",
			expected: "www.example.com",
		},
		{
			name:     "五级域名取后三级",
			domain:   "a.b.c.example.com",
			expected: "c.example.com",
		},
		{
			name:     "两级域名直接返回",
			domain:   "example.com",
			expected: "example.com",
		},
		{
			name:     "一级域名直接返回",
			domain:   "com",
			expected: "com",
		},
		{
			name:     "末尾有点号",
			domain:   "www.example.com.",
			expected: "www.example.com",
		},
		{
			name:     "空域名",
			domain:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Domain2Zone(tt.domain)
			if result != tt.expected {
				t.Errorf("期望 %q，得到 %q", tt.expected, result)
			}
		})
	}
}

func TestDomain2Zone_LongZoneFallback(t *testing.T) {
	// 构造一个三级 zone 超过 30 字符的域名
	// 例如 "subdomain.this-is-a-very-long-second-level.com"
	domain := "x.this-is-a-very-long-second-level-label.com"
	result := Domain2Zone(domain)
	// 三级 zone 超过 30 字符，应降级为两级
	expected := "this-is-a-very-long-second-level-label.com"
	if result != expected {
		t.Errorf("期望 %q，得到 %q", expected, result)
	}
}

// ==================== Find4diff ====================

func TestFind4diff_NilRsp(t *testing.T) {
	rspMap := make(types.RspMap)
	result, err := Find4diff(nil, rspMap)
	if err != nil {
		t.Errorf("nil rsp 不应返回错误: %v", err)
	}
	if result != nil {
		t.Error("nil rsp 应返回 nil 结果")
	}
}

func TestFind4diff_Success(t *testing.T) {
	// 创建测试数据
	rsp := createTestDNSRsp("example.com", dns.TypeA, 1234, "10.0.0.1", "12345")
	msg, _ := types.DNSRspToMsg(rsp)

	// 构建 rspMap
	rspMap := make(types.RspMap)
	key := GenU64Key(msg.Question[0].Qclass, msg.Question[0].Qtype, msg.Id, msg.Opcode)
	secdKey := GenSecdKey(msg.Question[0].Name, rsp.ClientIP, rsp.ClientPort)
	secdMap := make(map[string]*types.DNSRsp)
	oldRsp := createTestDNSRsp("example.com", dns.TypeA, 1234, "10.0.0.1", "12345")
	secdMap[secdKey] = oldRsp
	rspMap[key] = secdMap

	// 查找
	result, err := Find4diff(rsp, rspMap)
	if err != nil {
		t.Fatalf("未预期的错误: %v", err)
	}
	if result == nil {
		t.Fatal("期望非 nil 结果")
	}
	if result != oldRsp {
		t.Error("期望找到 oldRsp")
	}
}

func TestFind4diff_NoFirstKey(t *testing.T) {
	rsp := createTestDNSRsp("example.com", dns.TypeA, 1234, "10.0.0.1", "12345")
	rspMap := make(types.RspMap) // 空 map

	result, err := Find4diff(rsp, rspMap)
	if err == nil {
		t.Error("期望找不到 first key 返回错误")
	}
	if result != nil {
		t.Error("期望 nil 结果")
	}
}

func TestFind4diff_NoSecondKey(t *testing.T) {
	rsp := createTestDNSRsp("example.com", dns.TypeA, 1234, "10.0.0.1", "12345")
	msg, _ := types.DNSRspToMsg(rsp)

	rspMap := make(types.RspMap)
	key := GenU64Key(msg.Question[0].Qclass, msg.Question[0].Qtype, msg.Id, msg.Opcode)
	secdMap := make(map[string]*types.DNSRsp)
	// 不放入匹配的 secdKey，使用不同的客户端信息
	secdMap["other.com.*9.9.9.9:999"] = rsp
	rspMap[key] = secdMap

	result, err := Find4diff(rsp, rspMap)
	if err == nil {
		t.Error("期望找不到 secd key 返回错误")
	}
	if result != nil {
		t.Error("期望 nil 结果")
	}
}

func TestFind4diff_InvalidRawData(t *testing.T) {
	rsp := &types.DNSRsp{
		ClientIP:   "10.0.0.1",
		ClientPort: "12345",
		RawData:    []byte{0xFF, 0xFF}, // 无效数据
	}
	rspMap := make(types.RspMap)

	_, err := Find4diff(rsp, rspMap)
	if err == nil {
		t.Error("期望无效 RawData 返回错误")
	}
}

// ==================== Benchmarks ====================

func BenchmarkHash64(b *testing.B) {
	data := []byte("benchmark test data for hash64")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash64(data)
	}
}

func BenchmarkGenU64Key(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenU64Key(dns.ClassINET, dns.TypeA, uint16(i), 0)
	}
}

func BenchmarkDomain2Zone(b *testing.B) {
	domains := []string{
		"www.example.com",
		"a.b.c.d.example.com",
		"example.com",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, d := range domains {
			Domain2Zone(d)
		}
	}
}
