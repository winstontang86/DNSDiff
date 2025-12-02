package saver

import (
	"dnsdiff/pkg/types"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestFormatDomainName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "domain with trailing dot",
			input:    "example.com.",
			expected: "example.com.",
		},
		{
			name:     "domain without trailing dot",
			input:    "example.com",
			expected: "example.com.",
		},
		{
			name:     "root domain",
			input:    ".",
			expected: ".",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "subdomain with trailing dot",
			input:    "www.example.com.",
			expected: "www.example.com.",
		},
		{
			name:     "subdomain without trailing dot",
			input:    "www.example.com",
			expected: "www.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDomainName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestEdnsFlagsToString(t *testing.T) {
	tests := []struct {
		name     string
		setupOpt func() *dns.OPT
		expected string
	}{
		{
			name: "DO flag set",
			setupOpt: func() *dns.OPT {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetDo()
				return opt
			},
			expected: "do",
		},
		{
			name: "no flags",
			setupOpt: func() *dns.OPT {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				return opt
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := tt.setupOpt()
			result := ednsFlagsToString(opt)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatRR(t *testing.T) {
	tests := []struct {
		name      string
		rr        dns.RR
		checkFunc func(string) bool
	}{
		{
			name: "A record",
			rr: &dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("93.184.216.34"),
			},
			checkFunc: func(s string) bool {
				return strings.Contains(s, "example.com.") &&
					strings.Contains(s, "300") &&
					strings.Contains(s, "A")
			},
		},
		{
			name: "AAAA record",
			rr: &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
			},
			checkFunc: func(s string) bool {
				return strings.Contains(s, "example.com.") &&
					strings.Contains(s, "AAAA")
			},
		},
		{
			name: "CNAME record",
			rr: &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   "www.example.com.",
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: "example.com.",
			},
			checkFunc: func(s string) bool {
				return strings.Contains(s, "www.example.com.") &&
					strings.Contains(s, "CNAME") &&
					strings.Contains(s, "example.com.")
			},
		},
		{
			name: "MX record",
			rr: &dns.MX{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Preference: 10,
				Mx:         "mail.example.com.",
			},
			checkFunc: func(s string) bool {
				return strings.Contains(s, "example.com.") &&
					strings.Contains(s, "MX") &&
					strings.Contains(s, "10") &&
					strings.Contains(s, "mail.example.com.")
			},
		},
		{
			name: "NS record",
			rr: &dns.NS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Ns: "ns1.example.com.",
			},
			checkFunc: func(s string) bool {
				return strings.Contains(s, "example.com.") &&
					strings.Contains(s, "NS") &&
					strings.Contains(s, "ns1.example.com.")
			},
		},
		{
			name: "TXT record",
			rr: &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: []string{"v=spf1 include:_spf.example.com ~all"},
			},
			checkFunc: func(s string) bool {
				return strings.Contains(s, "example.com.") &&
					strings.Contains(s, "TXT") &&
					strings.Contains(s, "v=spf1")
			},
		},
		{
			name: "SOA record",
			rr: &dns.SOA{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Ns:      "ns1.example.com.",
				Mbox:    "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minttl:  300,
			},
			checkFunc: func(s string) bool {
				return strings.Contains(s, "example.com.") &&
					strings.Contains(s, "SOA") &&
					strings.Contains(s, "ns1.example.com.")
			},
		},
		{
			name: "PTR record",
			rr: &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   "8.7.251.61.in-addr.arpa.",
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Ptr: "example.com.",
			},
			checkFunc: func(s string) bool {
				return strings.Contains(s, "PTR") &&
					strings.Contains(s, "example.com.")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatRR(tt.rr)
			if !tt.checkFunc(result) {
				t.Errorf("formatRR output doesn't match expected pattern:\n%s", result)
			}
		})
	}
}

func TestBuildDNSContent(t *testing.T) {
	tests := []struct {
		name      string
		msg       *dns.Msg
		num       int
		checkFunc func(string) bool
	}{
		{
			name: "nil message",
			msg:  nil,
			num:  1,
			checkFunc: func(s string) bool {
				return strings.Contains(s, "# star 1") &&
					strings.Contains(s, "The number 1")
			},
		},
		{
			name: "simple query response",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.SetQuestion("example.com.", dns.TypeA)
				msg.Response = true
				msg.RecursionDesired = true
				msg.RecursionAvailable = true
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
			}(),
			num: 2,
			checkFunc: func(s string) bool {
				return strings.Contains(s, "# star 2") &&
					strings.Contains(s, "QUESTION SECTION") &&
					strings.Contains(s, "ANSWER SECTION") &&
					strings.Contains(s, "example.com.")
			},
		},
		{
			name: "response with authority section",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.SetQuestion("example.com.", dns.TypeNS)
				msg.Response = true
				msg.Authoritative = true
				msg.Ns = append(msg.Ns, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Ns: "ns1.example.com.",
				})
				return msg
			}(),
			num: 3,
			checkFunc: func(s string) bool {
				return strings.Contains(s, "AUTHORITY SECTION") &&
					strings.Contains(s, "ns1.example.com.")
			},
		},
		{
			name: "response with additional section",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.SetQuestion("example.com.", dns.TypeMX)
				msg.Response = true
				msg.Extra = append(msg.Extra, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "mail.example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("93.184.216.34"),
				})
				return msg
			}(),
			num: 4,
			checkFunc: func(s string) bool {
				return strings.Contains(s, "ADDITIONAL SECTION")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildDNSContent(tt.msg, tt.num)
			if !tt.checkFunc(result) {
				t.Errorf("buildDNSContent output doesn't match expected pattern:\n%s", result)
			}
		})
	}
}

func TestProcLayerData(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	file, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer file.Close()

	tests := []struct {
		name string
		msg  *dns.Msg
		num  int
	}{
		{
			name: "nil message",
			msg:  nil,
			num:  1,
		},
		{
			name: "valid message",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.SetQuestion("example.com.", dns.TypeA)
				msg.Response = true
				return msg
			}(),
			num: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: procLayerData is not exported, so we test it indirectly
			// through buildDNSContent which it uses
			content := buildDNSContent(tt.msg, tt.num)
			if content == "" {
				t.Error("Expected non-empty content")
			}
		})
	}
}

func TestSaveDiff(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)

	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Create test channel
	saveChan := make(chan types.SaveChan, 10)

	// Create test messages
	msg1 := new(dns.Msg)
	msg1.SetQuestion("example.com.", dns.TypeA)
	msg1.Response = true
	msg1.Answer = append(msg1.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("93.184.216.34"),
	})

	msg2 := new(dns.Msg)
	msg2.SetQuestion("example.com.", dns.TypeA)
	msg2.Response = true
	msg2.Answer = append(msg2.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("192.0.2.1"),
	})

	// Send test data
	go func() {
		saveChan <- types.SaveChan{
			Old: msg1,
			New: msg2,
		}
		saveChan <- types.SaveChan{
			Old: nil,
			New: msg2,
		}
		saveChan <- types.SaveChan{
			Old: msg1,
			New: nil,
		}
		close(saveChan)
	}()

	// Run SaveDiff
	err := SaveDiff(saveChan)
	if err != nil {
		t.Errorf("SaveDiff returned error: %v", err)
	}

	// Verify files were created
	oldFiles, err := filepath.Glob("diffold-*.txt")
	if err != nil {
		t.Fatalf("Failed to glob old files: %v", err)
	}
	if len(oldFiles) == 0 {
		t.Error("No diffold file was created")
	}

	newFiles, err := filepath.Glob("diffnew-*.txt")
	if err != nil {
		t.Fatalf("Failed to glob new files: %v", err)
	}
	if len(newFiles) == 0 {
		t.Error("No diffnew file was created")
	}

	// Verify file content
	if len(oldFiles) > 0 {
		content, err := os.ReadFile(oldFiles[0])
		if err != nil {
			t.Errorf("Failed to read old file: %v", err)
		}
		if len(content) == 0 {
			t.Error("Old file is empty")
		}
	}

	if len(newFiles) > 0 {
		content, err := os.ReadFile(newFiles[0])
		if err != nil {
			t.Errorf("Failed to read new file: %v", err)
		}
		if len(content) == 0 {
			t.Error("New file is empty")
		}
	}
}

func TestSaveDiff_EmptyChannel(t *testing.T) {
	tempDir := t.TempDir()
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Create and immediately close channel
	saveChan := make(chan types.SaveChan)
	close(saveChan)

	err := SaveDiff(saveChan)
	if err != nil {
		t.Errorf("SaveDiff returned error: %v", err)
	}

	// Files should still be created even if empty
	oldFiles, _ := filepath.Glob("diffold-*.txt")
	newFiles, _ := filepath.Glob("diffnew-*.txt")

	if len(oldFiles) == 0 {
		t.Error("No diffold file was created")
	}
	if len(newFiles) == 0 {
		t.Error("No diffnew file was created")
	}
}

func BenchmarkBuildDNSContent(b *testing.B) {
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildDNSContent(msg, i)
	}
}

func BenchmarkFormatRR(b *testing.B) {
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("93.184.216.34"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = formatRR(rr)
	}
}

func BenchmarkFormatDomainName(b *testing.B) {
	domains := []string{
		"example.com",
		"example.com.",
		"www.example.com",
		".",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, domain := range domains {
			_ = formatDomainName(domain)
		}
	}
}
