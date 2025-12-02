package statistics

import (
	"dnsdiff/internal/diff"
	"dnsdiff/pkg/utils"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestNewDiffStat(t *testing.T) {
	ds := newDiffStat()

	if ds == nil {
		t.Fatal("newDiffStat returned nil")
	}

	if ds.total == nil {
		t.Error("total map is nil")
	}

	if ds.diff == nil {
		t.Error("diff map is nil")
	}

	if ds.staticmap == nil {
		t.Error("staticmap is nil")
	}

	if len(ds.total) != 0 {
		t.Errorf("Expected empty total map, got %d entries", len(ds.total))
	}

	if len(ds.diff) != 0 {
		t.Errorf("Expected empty diff map, got %d entries", len(ds.diff))
	}

	if len(ds.staticmap) != 0 {
		t.Errorf("Expected empty staticmap, got %d entries", len(ds.staticmap))
	}
}

func TestGetStat(t *testing.T) {
	s := GetStat()

	if s == nil {
		t.Fatal("GetStat returned nil")
	}

	// Verify it returns the same instance
	s2 := GetStat()
	if s != s2 {
		t.Error("GetStat should return the same instance")
	}
}

func TestAddKV(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value int
	}{
		{
			name:  "add positive value",
			key:   "test_key_1",
			value: 100,
		},
		{
			name:  "add zero value",
			key:   "test_key_2",
			value: 0,
		},
		{
			name:  "add negative value",
			key:   "test_key_3",
			value: -50,
		},
		{
			name:  "overwrite existing key",
			key:   "test_key_1",
			value: 200,
		},
	}

	// Create a fresh DiffStat for testing
	ds := newDiffStat()
	stat = ds

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AddKV(tt.key, tt.value)
			if err != nil {
				t.Errorf("AddKV returned error: %v", err)
			}

			ds.lock.RLock()
			val, exists := ds.staticmap[tt.key]
			ds.lock.RUnlock()

			if !exists {
				t.Errorf("Key %s was not added to staticmap", tt.key)
			}

			if val != tt.value {
				t.Errorf("Expected value %d for key %s, got %d", tt.value, tt.key, val)
			}
		})
	}
}

func TestDiffStat_Add(t *testing.T) {
	tests := []struct {
		name     string
		qtype    uint16
		domain   string
		diffcode uint32
		expMask  uint32
	}{
		{
			name:     "add A record with RCODE diff",
			qtype:    dns.TypeA,
			domain:   "example.com.",
			diffcode: diff.DIFF_BIT_HEAD_RCODE,
			expMask:  diff.DefaultMask,
		},
		{
			name:     "add AAAA record with answer diff",
			qtype:    dns.TypeAAAA,
			domain:   "test.example.com.",
			diffcode: diff.DIFF_BIT_ANSWER_RRDIFF,
			expMask:  diff.DefaultMask,
		},
		{
			name:     "add CNAME record with no diff",
			qtype:    dns.TypeCNAME,
			domain:   "www.example.com.",
			diffcode: 0,
			expMask:  diff.DefaultMask,
		},
		{
			name:     "add MX record with multiple diffs",
			qtype:    dns.TypeMX,
			domain:   "mail.example.com.",
			diffcode: diff.DIFF_BIT_HEAD_RCODE | diff.DIFF_BIT_ANSWER_LEN,
			expMask:  diff.DefaultMask,
		},
		{
			name:     "add with zero mask",
			qtype:    dns.TypeA,
			domain:   "zero.example.com.",
			diffcode: diff.DIFF_BIT_HEAD_RCODE,
			expMask:  0x00000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := newDiffStat()

			ds.Add(tt.qtype, tt.domain, tt.diffcode, tt.expMask)

			// Verify total map
			ds.lock.RLock()
			defer ds.lock.RUnlock()

			if _, exists := ds.total[tt.qtype]; !exists {
				t.Errorf("qtype %d not found in total map", tt.qtype)
				return
			}

			maskedDiffcode := tt.diffcode & tt.expMask

			if count, exists := ds.total[tt.qtype][maskedDiffcode]; !exists {
				t.Errorf("diffcode 0x%08X not found in total map for qtype %d", maskedDiffcode, tt.qtype)
			} else if count != 1 {
				t.Errorf("Expected count 1, got %d", count)
			}

			// Verify diff map (only if diffcode != 0 after masking)
			if maskedDiffcode != 0 {
				if _, exists := ds.diff[tt.qtype]; !exists {
					t.Errorf("qtype %d not found in diff map", tt.qtype)
					return
				}

				// Extract zone from domain using the same logic as utils.Domain2Zone
				zone := utils.Domain2Zone(tt.domain)
				if _, exists := ds.diff[tt.qtype][zone]; !exists {
					t.Errorf("zone %s not found in diff map for qtype %d (domain: %s)", zone, tt.qtype, tt.domain)
				}
			}
		})
	}
}

func TestDiffStat_Add_Concurrent(t *testing.T) {
	ds := newDiffStat()

	// Test concurrent access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				ds.Add(dns.TypeA, "example.com.", diff.DIFF_BIT_HEAD_RCODE, diff.DefaultMask)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify count
	ds.lock.RLock()
	count := ds.total[dns.TypeA][diff.DIFF_BIT_HEAD_RCODE]
	ds.lock.RUnlock()

	expectedCount := 1000
	if count != expectedCount {
		t.Errorf("Expected count %d, got %d", expectedCount, count)
	}
}

func TestDiffStat_PrintSummary(t *testing.T) {
	ds := newDiffStat()

	// Add some test data
	ds.staticmap["test_key"] = 123
	ds.Add(dns.TypeA, "example.com.", diff.DIFF_BIT_HEAD_RCODE, diff.DefaultMask)
	ds.Add(dns.TypeAAAA, "test.com.", diff.DIFF_BIT_ANSWER_LEN, diff.DefaultMask)

	// This should not panic
	ds.PrintSummary()
}

func TestDiffStat_PrintfDiffStat(t *testing.T) {
	// Create temporary directory for test output
	tempDir := t.TempDir()
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)

	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	ds := newDiffStat()

	// Add some test data
	ds.staticmap["test_key"] = 456
	ds.Add(dns.TypeA, "example.com.", diff.DIFF_BIT_HEAD_RCODE, diff.DefaultMask)
	ds.Add(dns.TypeAAAA, "test.com.", diff.DIFF_BIT_ANSWER_RRDIFF, diff.DefaultMask)
	ds.Add(dns.TypeMX, "mail.example.com.", diff.DIFF_BIT_HEAD_OPCODE, diff.DefaultMask)

	// Call PrintfDiffStat
	ds.PrintfDiffStat()

	// Verify files were created
	files, err := filepath.Glob("diffstat-*.txt")
	if err != nil {
		t.Fatalf("Failed to glob files: %v", err)
	}
	if len(files) == 0 {
		t.Error("No .txt file was created")
	}

	csvFiles, err := filepath.Glob("diffstat-*.csv")
	if err != nil {
		t.Fatalf("Failed to glob CSV files: %v", err)
	}
	if len(csvFiles) == 0 {
		t.Error("No .csv file was created")
	}

	// Verify file content is not empty
	if len(files) > 0 {
		info, err := os.Stat(files[0])
		if err != nil {
			t.Errorf("Failed to stat file: %v", err)
		} else if info.Size() == 0 {
			t.Error("Output file is empty")
		}
	}

	if len(csvFiles) > 0 {
		info, err := os.Stat(csvFiles[0])
		if err != nil {
			t.Errorf("Failed to stat CSV file: %v", err)
		} else if info.Size() == 0 {
			t.Error("CSV file is empty")
		}
	}
}

func TestDnsTypeToStr(t *testing.T) {
	tests := []struct {
		name     string
		dnsType  uint16
		expected string
	}{
		{
			name:     "A record",
			dnsType:  dns.TypeA,
			expected: "A",
		},
		{
			name:     "AAAA record",
			dnsType:  dns.TypeAAAA,
			expected: "AAAA",
		},
		{
			name:     "CNAME record",
			dnsType:  dns.TypeCNAME,
			expected: "CNAME",
		},
		{
			name:     "MX record",
			dnsType:  dns.TypeMX,
			expected: "MX",
		},
		{
			name:     "NS record",
			dnsType:  dns.TypeNS,
			expected: "NS",
		},
		{
			name:     "TXT record",
			dnsType:  dns.TypeTXT,
			expected: "TXT",
		},
		{
			name:     "SOA record",
			dnsType:  dns.TypeSOA,
			expected: "SOA",
		},
		{
			name:     "unknown type",
			dnsType:  65535,
			expected: "Reserved", // 65535 在 dns.TypeToString 中映射为 "Reserved"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dnsTypeToStr(tt.dnsType)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDiffStat_Integration(t *testing.T) {
	// Create a fresh DiffStat
	ds := newDiffStat()

	// Simulate a complete workflow
	AddKV("total_queries", 1000)
	AddKV("total_responses", 950)

	// Add various diff records
	domains := []string{
		"example.com.",
		"test.example.com.",
		"www.example.com.",
		"mail.example.com.",
	}

	qtypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeMX,
		dns.TypeCNAME,
	}

	diffcodes := []uint32{
		diff.DIFF_BIT_HEAD_RCODE,
		diff.DIFF_BIT_ANSWER_LEN,
		diff.DIFF_BIT_ANSWER_RRDIFF,
		0, // No diff
	}

	for _, domain := range domains {
		for _, qtype := range qtypes {
			for _, diffcode := range diffcodes {
				ds.Add(qtype, domain, diffcode, diff.DefaultMask)
			}
		}
	}

	// Verify data was added
	ds.lock.RLock()
	totalCount := 0
	for _, codeMap := range ds.total {
		for _, count := range codeMap {
			totalCount += count
		}
	}
	ds.lock.RUnlock()

	expectedTotal := len(domains) * len(qtypes) * len(diffcodes)
	if totalCount != expectedTotal {
		t.Errorf("Expected total count %d, got %d", expectedTotal, totalCount)
	}

	// Test print functions (should not panic)
	ds.PrintSummary()
}

func BenchmarkDiffStat_Add(b *testing.B) {
	ds := newDiffStat()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ds.Add(dns.TypeA, "example.com.", diff.DIFF_BIT_HEAD_RCODE, diff.DefaultMask)
	}
}

func BenchmarkAddKV(b *testing.B) {
	ds := newDiffStat()
	stat = ds

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AddKV("test_key", i)
	}
}

func BenchmarkDnsTypeToStr(b *testing.B) {
	types := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeMX,
		65535, // Unknown type
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, t := range types {
			_ = dnsTypeToStr(t)
		}
	}
}
