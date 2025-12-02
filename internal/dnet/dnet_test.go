package dnet

import (
	"dnsdiff/pkg/types"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

func TestParseDNSResponse(t *testing.T) {
	// Create a simple DNS response
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("93.184.216.34"),
	})

	// Pack the message
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS message: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid DNS response",
			data:    data,
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid DNS data",
			data:    []byte{0x00, 0x01, 0x02},
			wantErr: true,
		},
		{
			name:    "nil data",
			data:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDNSResponse(tt.data)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if result != nil {
					t.Error("Expected nil result on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Error("Expected non-nil result")
				}
			}
		})
	}
}

func TestParseDNSResponse_ValidResponse(t *testing.T) {
	// Create a DNS response with multiple records
	msg := new(dns.Msg)
	msg.SetQuestion("test.example.com.", dns.TypeA)
	msg.Response = true
	msg.Authoritative = true
	msg.RecursionAvailable = true

	// Add answer
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "test.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("192.0.2.1"),
	})

	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS message: %v", err)
	}

	result, err := parseDNSResponse(data)
	if err != nil {
		t.Fatalf("parseDNSResponse failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Verify basic properties
	if !result.QR {
		t.Error("Expected QR flag to be true")
	}

	if len(result.Questions) == 0 {
		t.Error("Expected at least one question")
	}

	if len(result.Answers) == 0 {
		t.Error("Expected at least one answer")
	}
}

func TestSendAndRecvUDP_InvalidAddress(t *testing.T) {
	// Create a simple DNS query
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS message: %v", err)
	}

	req := &types.DNSReq{
		ClientIP:   "127.0.0.1",
		ClientPort: "12345",
		IsTCP:      false,
		Time:       time.Now(),
		RawData:    data,
	}

	tests := []struct {
		name     string
		targetIP string
		wantErr  bool
	}{
		{
			name:     "invalid IP address",
			targetIP: "invalid.ip.address",
			wantErr:  true,
		},
		{
			name:     "unreachable IP",
			targetIP: "192.0.2.1", // TEST-NET-1, should be unreachable
			wantErr:  true,
		},
		{
			name:     "empty IP",
			targetIP: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sendAndRecvUDP(req, tt.targetIP)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

func TestSendAndRecvTCP_InvalidAddress(t *testing.T) {
	// Create a simple DNS query
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS message: %v", err)
	}

	req := &types.DNSReq{
		ClientIP:   "127.0.0.1",
		ClientPort: "12345",
		IsTCP:      true,
		Time:       time.Now(),
		RawData:    data,
	}

	tests := []struct {
		name     string
		targetIP string
		wantErr  bool
	}{
		{
			name:     "invalid IP address",
			targetIP: "invalid.ip.address",
			wantErr:  true,
		},
		{
			name:     "unreachable IP",
			targetIP: "192.0.2.1", // TEST-NET-1, should be unreachable
			wantErr:  true,
		},
		{
			name:     "empty IP",
			targetIP: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sendAndRecvTCP(req, tt.targetIP)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

func TestSendAndRecv_InvalidRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *types.DNSReq
		target  string
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			target:  "8.8.8.8",
			wantErr: true,
		},
		{
			name: "empty raw data",
			req: &types.DNSReq{
				ClientIP:   "127.0.0.1",
				ClientPort: "12345",
				IsTCP:      false,
				Time:       time.Now(),
				RawData:    []byte{},
			},
			target:  "192.0.2.1",
			wantErr: true,
		},
		{
			name: "invalid DNS data",
			req: &types.DNSReq{
				ClientIP:   "127.0.0.1",
				ClientPort: "12345",
				IsTCP:      false,
				Time:       time.Now(),
				RawData:    []byte{0x00, 0x01},
			},
			target:  "192.0.2.1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.req == nil {
				// Test that nil request causes panic (current behavior)
				defer func() {
					if r := recover(); r == nil {
						t.Error("Expected panic for nil request, but no panic occurred")
					}
				}()
				_, _ = SendAndRecv(tt.req, tt.target)
			} else {
				_, err := SendAndRecv(tt.req, tt.target)
				if tt.wantErr && err == nil {
					t.Error("Expected error but got none")
				}
			}
		})
	}
}

func TestSendAndRecv_ProtocolSelection(t *testing.T) {
	// Create a valid DNS query
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS message: %v", err)
	}

	tests := []struct {
		name  string
		isTCP bool
	}{
		{
			name:  "UDP protocol",
			isTCP: false,
		},
		{
			name:  "TCP protocol",
			isTCP: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.DNSReq{
				ClientIP:   "127.0.0.1",
				ClientPort: "12345",
				IsTCP:      tt.isTCP,
				Time:       time.Now(),
				RawData:    data,
			}

			// Use an unreachable IP to avoid actual network calls
			// We just want to verify the function doesn't panic
			_, err := SendAndRecv(req, "192.0.2.1")
			// Error is expected since we're using an unreachable IP
			if err == nil {
				t.Log("Unexpected success (network might be configured differently)")
			}
		})
	}
}

func TestDNSPort(t *testing.T) {
	if DNS_PORT != "53" {
		t.Errorf("Expected DNS_PORT to be '53', got '%s'", DNS_PORT)
	}
}

func TestParseDNSResponse_DifferentRecordTypes(t *testing.T) {
	tests := []struct {
		name      string
		setupMsg  func() *dns.Msg
		wantErr   bool
		checkFunc func(*testing.T, *layers.DNS)
	}{
		{
			name: "A record",
			setupMsg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.SetQuestion("example.com.", dns.TypeA)
				msg.Response = true
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("93.184.216.34"),
				})
				return msg
			},
			wantErr: false,
			checkFunc: func(t *testing.T, result *layers.DNS) {
				if len(result.Answers) == 0 {
					t.Error("Expected at least one answer")
				}
			},
		},
		{
			name: "AAAA record",
			setupMsg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.SetQuestion("example.com.", dns.TypeAAAA)
				msg.Response = true
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
				})
				return msg
			},
			wantErr: false,
			checkFunc: func(t *testing.T, result *layers.DNS) {
				if len(result.Answers) == 0 {
					t.Error("Expected at least one answer")
				}
			},
		},
		{
			name: "CNAME record",
			setupMsg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.SetQuestion("www.example.com.", dns.TypeCNAME)
				msg.Response = true
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   "www.example.com.",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Target: "example.com.",
				})
				return msg
			},
			wantErr: false,
			checkFunc: func(t *testing.T, result *layers.DNS) {
				if len(result.Answers) == 0 {
					t.Error("Expected at least one answer")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.setupMsg()
			data, err := msg.Pack()
			if err != nil {
				t.Fatalf("Failed to pack DNS message: %v", err)
			}

			result, err := parseDNSResponse(data)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != nil && tt.checkFunc != nil {
					tt.checkFunc(t, result)
				}
			}
		})
	}
}

func BenchmarkParseDNSResponse(b *testing.B) {
	// Create a DNS response
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("93.184.216.34"),
	})

	data, err := msg.Pack()
	if err != nil {
		b.Fatalf("Failed to pack DNS message: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseDNSResponse(data)
	}
}
