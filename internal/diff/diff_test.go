package diff

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestInit(t *testing.T) {
	// Test that init() properly initializes masks
	if DefaultMask == 0 {
		t.Error("DefaultMask should not be 0 after init")
	}

	if CriticalMask == 0 {
		t.Error("CriticalMask should not be 0 after init")
	}

	if WarningMask == 0 {
		t.Error("WarningMask should not be 0 after init")
	}

	// Verify DefaultMask includes CriticalMask and WarningMask
	if (DefaultMask & CriticalMask) != CriticalMask {
		t.Error("DefaultMask should include all CriticalMask bits")
	}

	if (DefaultMask & WarningMask) != WarningMask {
		t.Error("DefaultMask should include all WarningMask bits")
	}
}

func TestBitSet(t *testing.T) {
	tests := []struct {
		name     string
		initial  uint32
		bit      uint32
		expected uint32
	}{
		{
			name:     "set first bit",
			initial:  0x00000000,
			bit:      0x00000001,
			expected: 0x00000001,
		},
		{
			name:     "set multiple bits",
			initial:  0x00000001,
			bit:      0x00000010,
			expected: 0x00000011,
		},
		{
			name:     "set already set bit",
			initial:  0x00000001,
			bit:      0x00000001,
			expected: 0x00000001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.initial
			result := bitSet(&data, tt.bit)

			if !result {
				t.Error("bitSet should return true")
			}

			if data != tt.expected {
				t.Errorf("Expected 0x%08X, got 0x%08X", tt.expected, data)
			}
		})
	}
}

func TestComparator_Compare_NilMessages(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	tests := []struct {
		name         string
		msg1         *dns.Msg
		msg2         *dns.Msg
		expectedDiff uint32
	}{
		{
			name:         "both nil",
			msg1:         nil,
			msg2:         nil,
			expectedDiff: 0,
		},
		{
			name:         "first nil",
			msg1:         nil,
			msg2:         new(dns.Msg),
			expectedDiff: DIFF_BIT_NOMATCH,
		},
		{
			name:         "second nil",
			msg1:         new(dns.Msg),
			msg2:         nil,
			expectedDiff: DIFF_BIT_NOMATCH,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diffCode uint32
			err := c.Compare(tt.msg1, tt.msg2, &diffCode)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if diffCode != tt.expectedDiff {
				t.Errorf("Expected diffCode 0x%08X, got 0x%08X", tt.expectedDiff, diffCode)
			}
		})
	}
}

func TestComparator_CompareHeader(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	tests := []struct {
		name         string
		msg1         *dns.Msg
		msg2         *dns.Msg
		expectedBits uint32
	}{
		{
			name: "identical headers",
			msg1: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Opcode:             dns.OpcodeQuery,
					Rcode:              dns.RcodeSuccess,
					Response:           true,
					Authoritative:      false,
					Truncated:          false,
					RecursionDesired:   true,
					RecursionAvailable: true,
				},
			},
			msg2: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Opcode:             dns.OpcodeQuery,
					Rcode:              dns.RcodeSuccess,
					Response:           true,
					Authoritative:      false,
					Truncated:          false,
					RecursionDesired:   true,
					RecursionAvailable: true,
				},
			},
			expectedBits: 0,
		},
		{
			name: "different opcode",
			msg1: &dns.Msg{
				MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeQuery},
			},
			msg2: &dns.Msg{
				MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeUpdate},
			},
			expectedBits: DIFF_BIT_HEAD_OPCODE,
		},
		{
			name: "different rcode",
			msg1: &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			},
			msg2: &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
			},
			expectedBits: DIFF_BIT_HEAD_RCODE,
		},
		{
			name: "different flags",
			msg1: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: true,
				},
			},
			msg2: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response:           true,
					RecursionDesired:   false,
					RecursionAvailable: true,
				},
			},
			expectedBits: DIFF_BIT_HEAD_QFLAG,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diffCode uint32
			err := c.compareHeader(tt.msg1, tt.msg2, &diffCode)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if (diffCode & tt.expectedBits) != tt.expectedBits {
				t.Errorf("Expected bits 0x%08X not set in diffCode 0x%08X", tt.expectedBits, diffCode)
			}
		})
	}
}

func TestComparator_CmpQuestions(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	tests := []struct {
		name         string
		q1           []dns.Question
		q2           []dns.Question
		expectedBits uint32
	}{
		{
			name: "identical questions",
			q1: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			q2: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			expectedBits: 0,
		},
		{
			name: "case insensitive domain",
			q1: []dns.Question{
				{Name: "Example.COM.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			q2: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			expectedBits: 0,
		},
		{
			name: "different domain",
			q1: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			q2: []dns.Question{
				{Name: "test.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			expectedBits: DIFF_BIT_QUEST_QNAME,
		},
		{
			name: "different qtype",
			q1: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			q2: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			},
			expectedBits: DIFF_BIT_QUEST_QTYPE,
		},
		{
			name: "different qclass",
			q1: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			q2: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS},
			},
			expectedBits: DIFF_BIT_QUEST_QCLASS,
		},
		{
			name: "different length",
			q1: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			q2: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				{Name: "test.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			expectedBits: DIFF_BIT_QUEST_LEN,
		},
		{
			name:         "both empty",
			q1:           []dns.Question{},
			q2:           []dns.Question{},
			expectedBits: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diffCode uint32
			err := c.cmpQuestions(tt.q1, tt.q2, &diffCode)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if (diffCode & tt.expectedBits) != tt.expectedBits {
				t.Errorf("Expected bits 0x%08X not set in diffCode 0x%08X", tt.expectedBits, diffCode)
			}
		})
	}
}

func TestComparator_CmpAnswers(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	tests := []struct {
		name         string
		rrs1         []dns.RR
		rrs2         []dns.RR
		expectedBits uint32
	}{
		{
			name:         "both empty",
			rrs1:         []dns.RR{},
			rrs2:         []dns.RR{},
			expectedBits: 0,
		},
		{
			name: "one empty",
			rrs1: []dns.RR{},
			rrs2: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				},
			},
			expectedBits: DIFF_BIT_ANSWER_01,
		},
		{
			name: "identical A records",
			rrs1: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				},
			},
			rrs2: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				},
			},
			expectedBits: 0,
		},
		{
			name: "different A records",
			rrs1: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				},
			},
			rrs2: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
			},
			expectedBits: DIFF_BIT_ANSWER_RRDIFF,
		},
		{
			name: "identical CNAME chains",
			rrs1: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "example.com.",
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				},
			},
			rrs2: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "example.com.",
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				},
			},
			expectedBits: 0,
		},
		{
			name: "different CNAME chains",
			rrs1: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "example.com.",
				},
			},
			rrs2: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "other.com.",
				},
			},
			expectedBits: DIFF_BIT_ANSWER_CNAME,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diffCode uint32
			err := c.CmpAnswers(tt.rrs1, tt.rrs2, &diffCode)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.expectedBits != 0 && (diffCode&tt.expectedBits) != tt.expectedBits {
				t.Errorf("Expected bits 0x%08X not set in diffCode 0x%08X", tt.expectedBits, diffCode)
			}

			if tt.expectedBits == 0 && diffCode != 0 {
				t.Errorf("Expected no diff, but got diffCode 0x%08X", diffCode)
			}
		})
	}
}

func TestComparator_PreProcRRs(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	tests := []struct {
		name          string
		rrs           []dns.RR
		expectedCname int
		expectedOther int
	}{
		{
			name:          "empty",
			rrs:           []dns.RR{},
			expectedCname: 0,
			expectedOther: 0,
		},
		{
			name: "only A records",
			rrs: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
			},
			expectedCname: 0,
			expectedOther: 2,
		},
		{
			name: "only CNAME records",
			rrs: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "example.com.",
				},
			},
			expectedCname: 1,
			expectedOther: 0,
		},
		{
			name: "mixed records",
			rrs: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "example.com.",
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				},
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
				},
			},
			expectedCname: 1,
			expectedOther: 2,
		},
		{
			name: "various record types",
			rrs: []dns.RR{
				&dns.MX{
					Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Preference: 10,
					Mx:         "mail.example.com.",
				},
				&dns.NS{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns1.example.com.",
				},
				&dns.TXT{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{"v=spf1 include:_spf.example.com ~all"},
				},
			},
			expectedCname: 0,
			expectedOther: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cnameMap, otherMap := c.preProcRRs(tt.rrs)

			if len(cnameMap) != tt.expectedCname {
				t.Errorf("Expected %d CNAME records, got %d", tt.expectedCname, len(cnameMap))
			}

			if len(otherMap) != tt.expectedOther {
				t.Errorf("Expected %d other records, got %d", tt.expectedOther, len(otherMap))
			}
		})
	}
}

func TestComparator_SameCnameChains(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	tests := []struct {
		name     string
		cname1   map[string]string
		cname2   map[string]string
		expected bool
	}{
		{
			name:     "both empty",
			cname1:   map[string]string{},
			cname2:   map[string]string{},
			expected: true,
		},
		{
			name: "identical chains",
			cname1: map[string]string{
				"www.example.com.": "example.com.",
			},
			cname2: map[string]string{
				"www.example.com.": "example.com.",
			},
			expected: true,
		},
		{
			name: "different targets",
			cname1: map[string]string{
				"www.example.com.": "example.com.",
			},
			cname2: map[string]string{
				"www.example.com.": "other.com.",
			},
			expected: false,
		},
		{
			// 链式CNAME尾跳不同：cname1的链最终指向final1，cname2的链最终指向final2
			name: "different chain last target",
			cname1: map[string]string{
				"www.example.com.": "mid.example.com.",
				"mid.example.com.": "final1.example.com.",
			},
			cname2: map[string]string{
				"www.example.com.": "mid.example.com.",
				"mid.example.com.": "final2.example.com.",
			},
			expected: false,
		},
		{
			name: "one empty",
			cname1: map[string]string{
				"www.example.com.": "example.com.",
			},
			cname2:   map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.sameCnameChains(tt.cname1, tt.cname2)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestComparator_CmpRRSet(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	tests := []struct {
		name     string
		m1       map[string]struct{}
		m2       map[string]struct{}
		expected int
	}{
		{
			name:     "both empty",
			m1:       map[string]struct{}{},
			m2:       map[string]struct{}{},
			expected: RRSetAllEqual,
		},
		{
			name: "identical sets",
			m1: map[string]struct{}{
				"key1": {},
				"key2": {},
			},
			m2: map[string]struct{}{
				"key1": {},
				"key2": {},
			},
			expected: RRSetPartEqual, // With AllowPartialMatch=true, identical sets return RRSetPartEqual
		},
		{
			name: "partial match",
			m1: map[string]struct{}{
				"key1": {},
				"key2": {},
			},
			m2: map[string]struct{}{
				"key1": {},
				"key3": {},
			},
			expected: RRSetPartEqual,
		},
		{
			name: "completely different",
			m1: map[string]struct{}{
				"key1": {},
				"key2": {},
			},
			m2: map[string]struct{}{
				"key3": {},
				"key4": {},
			},
			expected: RRSetAllDiff,
		},
		{
			name: "one empty",
			m1: map[string]struct{}{
				"key1": {},
			},
			m2:       map[string]struct{}{},
			expected: RRSetAllDiff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.cmpRRSet(tt.m1, tt.m2)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}

	// Additional test with AllowPartialMatch=false for identical sets
	t.Run("identical_sets_no_partial_match", func(t *testing.T) {
		cNoPartial := &Comparator{
			AllowPartialMatch:  false,
			IgnoreAdditional:   true,
			DiffUnexpectedMask: DefaultMask,
		}

		m1 := map[string]struct{}{
			"key1": {},
			"key2": {},
		}
		m2 := map[string]struct{}{
			"key1": {},
			"key2": {},
		}

		result := cNoPartial.cmpRRSet(m1, m2)
		expected := RRSetAllEqual
		if result != expected {
			t.Errorf("Expected %d for identical sets with AllowPartialMatch=false, got %d", expected, result)
		}
	})
}

func TestDiffCode2Str(t *testing.T) {
	tests := []struct {
		name     string
		diffcode uint32
		contains []string
	}{
		{
			name:     "no diff",
			diffcode: 0,
			contains: []string{"EQUAL"},
		},
		{
			name:     "RCODE diff",
			diffcode: DIFF_BIT_HEAD_RCODE,
			contains: []string{"RCODE_DIFF"},
		},
		{
			name:     "multiple diffs",
			diffcode: DIFF_BIT_HEAD_RCODE | DIFF_BIT_ANSWER_LEN,
			contains: []string{"RCODE_DIFF", "ANSWER_LEN_DIFF"},
		},
		{
			name:     "NOMATCH",
			diffcode: DIFF_BIT_NOMATCH,
			contains: []string{"NOMATCH"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DiffCode2Str(tt.diffcode)

			for _, expected := range tt.contains {
				if !contains(result, expected) {
					t.Errorf("Expected result to contain %q, got %q", expected, result)
				}
			}
		})
	}
}

func TestComparator_Compare_Integration(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	// Create two identical messages
	msg1 := new(dns.Msg)
	msg1.SetQuestion("example.com.", dns.TypeA)
	msg1.Response = true
	msg1.RecursionDesired = true
	msg1.RecursionAvailable = true
	msg1.Answer = append(msg1.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34"),
	})

	msg2 := new(dns.Msg)
	msg2.SetQuestion("example.com.", dns.TypeA)
	msg2.Response = true
	msg2.RecursionDesired = true
	msg2.RecursionAvailable = true
	msg2.Answer = append(msg2.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34"),
	})

	var diffCode uint32
	err := c.Compare(msg1, msg2, &diffCode)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if diffCode != 0 {
		t.Errorf("Expected no diff for identical messages, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
	}
}

func TestComparator_ApplyWhitelist(t *testing.T) {
	// Mock whitelist checker
	mockChecker := &mockWhitelistChecker{
		whitelist: map[string]map[string]bool{
			"RCODE_DIFF": {
				"example.com.": true,
			},
		},
	}

	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
		WhitelistChecker:   mockChecker,
	}

	tests := []struct {
		name         string
		diffCode     uint32
		domain       string
		expectedCode uint32
	}{
		{
			name:         "no whitelist match",
			diffCode:     DIFF_BIT_HEAD_RCODE,
			domain:       "other.com.",
			expectedCode: DIFF_BIT_HEAD_RCODE,
		},
		{
			name:         "whitelist match",
			diffCode:     DIFF_BIT_HEAD_RCODE,
			domain:       "example.com.",
			expectedCode: 0,
		},
		{
			name:         "zero diffcode",
			diffCode:     0,
			domain:       "example.com.",
			expectedCode: 0,
		},
		{
			name:         "multiple diffs, partial whitelist",
			diffCode:     DIFF_BIT_HEAD_RCODE | DIFF_BIT_ANSWER_LEN,
			domain:       "example.com.",
			expectedCode: DIFF_BIT_ANSWER_LEN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.ApplyWhitelist(tt.diffCode, tt.domain)
			if result != tt.expectedCode {
				t.Errorf("Expected 0x%08X, got 0x%08X", tt.expectedCode, result)
			}
		})
	}
}

func TestComparator_ApplyWhitelist_NilChecker(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
		WhitelistChecker:   nil,
	}

	diffCode := uint32(DIFF_BIT_HEAD_RCODE)
	result := c.ApplyWhitelist(diffCode, "example.com.")

	if result != diffCode {
		t.Errorf("Expected diffCode unchanged when WhitelistChecker is nil")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Mock whitelist checker for testing
type mockWhitelistChecker struct {
	whitelist map[string]map[string]bool
}

func (m *mockWhitelistChecker) IsWhitelisted(diffType string, domain string) bool {
	if domains, ok := m.whitelist[diffType]; ok {
		return domains[domain]
	}
	return false
}

// ==================== cmpAuthAddRRs 测试 ====================

func TestComparator_CmpAuthAddRRs(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	tests := []struct {
		name         string
		rrs1         []dns.RR
		rrs2         []dns.RR
		isAuth       bool
		expectedBits uint32
	}{
		{
			name:         "both empty auth",
			rrs1:         []dns.RR{},
			rrs2:         []dns.RR{},
			isAuth:       true,
			expectedBits: 0,
		},
		{
			name: "one empty auth",
			rrs1: []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns1.example.com.",
				},
			},
			rrs2:         []dns.RR{},
			isAuth:       true,
			expectedBits: DIFF_BIT_AUTH_LEN,
		},
		{
			name: "one empty additional",
			rrs1: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("1.2.3.4"),
				},
			},
			rrs2:         []dns.RR{},
			isAuth:       false,
			expectedBits: DIFF_BIT_ADD_LEN,
		},
		{
			name: "identical auth NS records",
			rrs1: []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns1.example.com.",
				},
			},
			rrs2: []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns1.example.com.",
				},
			},
			isAuth:       true,
			expectedBits: 0,
		},
		{
			name: "different auth RR records",
			rrs1: []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns1.example.com.",
				},
			},
			rrs2: []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns2.example.com.",
				},
			},
			isAuth:       true,
			expectedBits: DIFF_BIT_AUTH_RRDIFF,
		},
		{
			name: "different additional RR records",
			rrs1: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("1.2.3.4"),
				},
			},
			rrs2: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("5.6.7.8"),
				},
			},
			isAuth:       false,
			expectedBits: DIFF_BIT_ADD_RRDIFF,
		},
		{
			name: "different auth CNAME chains",
			rrs1: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "real1.example.com.",
				},
			},
			rrs2: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "real2.example.com.",
				},
			},
			isAuth:       true,
			expectedBits: DIFF_BIT_AUTH_CNAME,
		},
		{
			name: "different additional CNAME chains",
			rrs1: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "real1.example.com.",
				},
			},
			rrs2: []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "real2.example.com.",
				},
			},
			isAuth:       false,
			expectedBits: DIFF_BIT_ADD_CNAME,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diffCode uint32
			err := c.cmpAuthAddRRs(tt.rrs1, tt.rrs2, &diffCode, tt.isAuth)

			if err != nil {
				t.Errorf("未预期的错误: %v", err)
			}

			if tt.expectedBits != 0 && (diffCode&tt.expectedBits) != tt.expectedBits {
				t.Errorf("期望位 0x%08X 未在 diffCode 0x%08X 中设置", tt.expectedBits, diffCode)
			}

			if tt.expectedBits == 0 && diffCode != 0 {
				t.Errorf("期望无差异，但得到 diffCode 0x%08X", diffCode)
			}
		})
	}
}

// ==================== Compare 完整流程测试 ====================

func TestComparator_Compare_FullFlow(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("header_rcode_diff_stops_early", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Rcode = dns.RcodeSuccess

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Rcode = dns.RcodeNameError

		var diffCode uint32
		err := c.Compare(msg1, msg2, &diffCode)
		if err != nil {
			t.Fatalf("未预期的错误: %v", err)
		}
		if (diffCode & DIFF_BIT_HEAD_RCODE) == 0 {
			t.Error("期望 RCODE 差异被检测到")
		}
	})

	t.Run("question_diff_stops_early", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true

		msg2 := new(dns.Msg)
		msg2.SetQuestion("other.com.", dns.TypeA)
		msg2.Response = true

		var diffCode uint32
		err := c.Compare(msg1, msg2, &diffCode)
		if err != nil {
			t.Fatalf("未预期的错误: %v", err)
		}
		if (diffCode & DIFF_BIT_QUEST_QNAME) == 0 {
			t.Error("期望 QNAME 差异被检测到")
		}
	})

	t.Run("with_auth_and_additional", func(t *testing.T) {
		cFull := &Comparator{
			AllowPartialMatch:  true,
			IgnoreAdditional:   false, // 不忽略 additional
			DiffUnexpectedMask: DefaultMask,
		}

		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		msg1.Ns = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
		}
		msg1.Extra = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}

		// msg2 完全相同
		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		msg2.Ns = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
		}
		msg2.Extra = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}

		var diffCode uint32
		err := cFull.Compare(msg1, msg2, &diffCode)
		if err != nil {
			t.Fatalf("未预期的错误: %v", err)
		}
		if diffCode != 0 {
			t.Errorf("期望完全相同消息无差异，但得到 0x%08X", diffCode)
		}
	})

	t.Run("answer_one_empty_diff", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		// msg2 没有 answer

		var diffCode uint32
		err := c.Compare(msg1, msg2, &diffCode)
		if err != nil {
			t.Fatalf("未预期的错误: %v", err)
		}
		if (diffCode & DIFF_BIT_ANSWER_01) == 0 {
			t.Error("期望 ANSWER_01 差异被检测到")
		}
	})
}

// ==================== preProcRRs 更多 RR 类型测试 ====================

func TestComparator_PreProcRRs_AllTypes(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("SOA record", func(t *testing.T) {
		rrs := []dns.RR{
			&dns.SOA{
				Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:   "ns1.example.com.",
				Mbox: "admin.example.com.",
			},
		}
		cnameMap, otherMap := c.preProcRRs(rrs)
		if len(cnameMap) != 0 {
			t.Errorf("SOA 不应产生 CNAME 记录")
		}
		if len(otherMap) != 1 {
			t.Errorf("期望 1 条 other 记录，得到 %d", len(otherMap))
		}
	})

	t.Run("PTR record", func(t *testing.T) {
		rrs := []dns.RR{
			&dns.PTR{
				Hdr: dns.RR_Header{Name: "4.3.2.1.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300},
				Ptr: "example.com.",
			},
		}
		cnameMap, otherMap := c.preProcRRs(rrs)
		if len(cnameMap) != 0 {
			t.Errorf("PTR 不应产生 CNAME 记录")
		}
		if len(otherMap) != 1 {
			t.Errorf("期望 1 条 other 记录，得到 %d", len(otherMap))
		}
	})

	t.Run("default type (SRV)", func(t *testing.T) {
		rrs := []dns.RR{
			&dns.SRV{
				Hdr:      dns.RR_Header{Name: "_http._tcp.example.com.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 300},
				Priority: 10,
				Weight:   20,
				Port:     80,
				Target:   "server.example.com.",
			},
		}
		cnameMap, otherMap := c.preProcRRs(rrs)
		if len(cnameMap) != 0 {
			t.Errorf("SRV 不应产生 CNAME 记录")
		}
		if len(otherMap) != 1 {
			t.Errorf("期望 1 条 other 记录，得到 %d", len(otherMap))
		}
	})

	t.Run("case insensitive comparison", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "EXAMPLE.COM.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "NS1.EXAMPLE.COM.",
			},
		}
		rrs2 := []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
		}
		_, other1 := c.preProcRRs(rrs1)
		_, other2 := c.preProcRRs(rrs2)

		// 应该生成相同的 key
		for k := range other1 {
			if _, ok := other2[k]; !ok {
				t.Errorf("大小写不敏感比较失败，key1=%s 在 other2 中未找到", k)
			}
		}
	})
}

// ==================== CmpRRSet NoPartialMatch 测试 ====================

func TestComparator_CmpRRSet_NoPartialMatch(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  false,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("different length", func(t *testing.T) {
		m1 := map[string]struct{}{
			"key1": {},
			"key2": {},
		}
		m2 := map[string]struct{}{
			"key1": {},
		}
		result := c.cmpRRSet(m1, m2)
		if result != RRSetAllDiff {
			t.Errorf("期望 RRSetAllDiff，得到 %d", result)
		}
	})

	t.Run("same length different keys", func(t *testing.T) {
		m1 := map[string]struct{}{
			"key1": {},
			"key2": {},
		}
		m2 := map[string]struct{}{
			"key3": {},
			"key4": {},
		}
		result := c.cmpRRSet(m1, m2)
		if result != RRSetAllDiff {
			t.Errorf("期望 RRSetAllDiff，得到 %d", result)
		}
	})

	t.Run("partial match returns AllDiff", func(t *testing.T) {
		m1 := map[string]struct{}{
			"key1": {},
			"key2": {},
		}
		m2 := map[string]struct{}{
			"key1": {},
			"key3": {},
		}
		result := c.cmpRRSet(m1, m2)
		if result != RRSetAllDiff {
			t.Errorf("期望 AllowPartialMatch=false 时部分匹配返回 RRSetAllDiff，得到 %d", result)
		}
	})
}

// ==================== CmpAnswers NoPartialMatch 测试 ====================

func TestComparator_CmpAnswers_NoPartialMatch(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  false,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("different count returns ANSWER_LEN", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}
		rrs2 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		var diffCode uint32
		c.CmpAnswers(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ANSWER_LEN) == 0 {
			t.Errorf("期望 ANSWER_LEN 差异被检测到，得到 0x%08X", diffCode)
		}
	})
}

func BenchmarkComparator_Compare(b *testing.B) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	msg1 := new(dns.Msg)
	msg1.SetQuestion("example.com.", dns.TypeA)
	msg1.Response = true
	msg1.Answer = append(msg1.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34"),
	})

	msg2 := new(dns.Msg)
	msg2.SetQuestion("example.com.", dns.TypeA)
	msg2.Response = true
	msg2.Answer = append(msg2.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34"),
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)
	}
}

func BenchmarkDiffCode2Str(b *testing.B) {
	diffcodes := []uint32{
		0,
		DIFF_BIT_HEAD_RCODE,
		DIFF_BIT_HEAD_RCODE | DIFF_BIT_ANSWER_LEN,
		DefaultMask,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, code := range diffcodes {
			_ = DiffCode2Str(code)
		}
	}
}

// ==================== P0: AA flag separated from QFLAG ====================

func TestComparator_CompareHeader_AAFlag(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("AA flag diff only -> DIFF_BIT_HEAD_AA not QFLAG", func(t *testing.T) {
		msg1 := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:           true,
				Authoritative:      true,
				RecursionDesired:   true,
				RecursionAvailable: true,
			},
		}
		msg2 := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:           true,
				Authoritative:      false,
				RecursionDesired:   true,
				RecursionAvailable: true,
			},
		}
		var diffCode uint32
		c.compareHeader(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_HEAD_AA) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_AA to be set, got 0x%08X", diffCode)
		}
		if (diffCode & DIFF_BIT_HEAD_QFLAG) != 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_QFLAG to NOT be set when only AA differs, got 0x%08X", diffCode)
		}
	})

	t.Run("AA diff is WARNING level, does not block body comparison", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Authoritative = true
		msg1.RecursionDesired = true
		msg1.RecursionAvailable = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Authoritative = false // different AA
		msg2.RecursionDesired = true
		msg2.RecursionAvailable = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"), // different IP
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// AA diff should be set
		if (diffCode & DIFF_BIT_HEAD_AA) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_AA, got 0x%08X", diffCode)
		}
		// Answer diff should also be detected (AA is WARNING, not CRITICAL, so comparison continues)
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) == 0 {
			t.Errorf("Expected DIFF_BIT_ANSWER_RRDIFF because AA diff is WARNING and body comparison should continue, got 0x%08X", diffCode)
		}
	})

	t.Run("other flag diffs still use QFLAG", func(t *testing.T) {
		msg1 := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:           true,
				RecursionDesired:   true,
				RecursionAvailable: true,
			},
		}
		msg2 := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:           true,
				RecursionDesired:   false, // RD differs
				RecursionAvailable: true,
			},
		}
		var diffCode uint32
		c.compareHeader(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_HEAD_QFLAG) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_QFLAG for RD diff, got 0x%08X", diffCode)
		}
		if (diffCode & DIFF_BIT_HEAD_AA) != 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_AA to NOT be set, got 0x%08X", diffCode)
		}
	})
}

// ==================== P0: OPT record filtering in preProcRRs ====================

func TestComparator_PreProcRRs_OPTFiltered(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("OPT records are filtered out in preProcRRs", func(t *testing.T) {
		rrs := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
			},
		}
		cnameMap, otherMap := c.preProcRRs(rrs)

		if len(cnameMap) != 0 {
			t.Errorf("Expected 0 CNAME, got %d", len(cnameMap))
		}
		// OPT should be filtered, only A record remains
		if len(otherMap) != 1 {
			t.Errorf("Expected 1 other record (OPT filtered), got %d", len(otherMap))
		}
	})

	t.Run("Additional section with different OPT records are equal", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}, // UDP payload = 4096
			},
		}
		rrs2 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}, // different UDP payload
			},
		}

		var diffCode uint32
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, false)

		if diffCode != 0 {
			t.Errorf("Expected no diff when only OPT records differ (should be filtered), got 0x%08X (%s)",
				diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("Additional section only OPT treated as both empty", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
			},
		}
		rrs2 := []dns.RR{
			&dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
			},
		}

		var diffCode uint32
		// Note: cmpAuthAddRRs checks len(rrs1) and len(rrs2) BEFORE preProcRRs,
		// so both have len=1, pass the length check, then preProcRRs filters OPT,
		// resulting in empty cnameMap and empty otherMap for both sides.
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, false)

		if diffCode != 0 {
			t.Errorf("Expected no diff for OPT-only additional sections, got 0x%08X (%s)",
				diffCode, DiffCode2Str(diffCode))
		}
	})
}

// ==================== P1: SERVFAIL Rcode separated ====================

func TestComparator_CompareHeader_ServfailRcode(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("NOERROR vs SERVFAIL -> RCODE_SF not RCODE", func(t *testing.T) {
		msg1 := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
		msg2 := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}

		var diffCode uint32
		c.compareHeader(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_HEAD_RCODE_SF) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_RCODE_SF, got 0x%08X", diffCode)
		}
		if (diffCode & DIFF_BIT_HEAD_RCODE) != 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_RCODE to NOT be set for SERVFAIL, got 0x%08X", diffCode)
		}
	})

	t.Run("SERVFAIL vs NXDOMAIN -> RCODE_SF", func(t *testing.T) {
		msg1 := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}
		msg2 := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}

		var diffCode uint32
		c.compareHeader(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_HEAD_RCODE_SF) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_RCODE_SF, got 0x%08X", diffCode)
		}
	})

	t.Run("NOERROR vs NXDOMAIN -> RCODE (not SF)", func(t *testing.T) {
		msg1 := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
		msg2 := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}

		var diffCode uint32
		c.compareHeader(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_HEAD_RCODE) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_RCODE for non-SERVFAIL rcode diff, got 0x%08X", diffCode)
		}
		if (diffCode & DIFF_BIT_HEAD_RCODE_SF) != 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_RCODE_SF to NOT be set, got 0x%08X", diffCode)
		}
	})

	t.Run("SERVFAIL rcode diff is WARNING, does not block body comparison", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Rcode = dns.RcodeSuccess
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Rcode = dns.RcodeServerFailure
		// SERVFAIL typically has no answer

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_HEAD_RCODE_SF) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_RCODE_SF, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		// SERVFAIL is WARNING, so body comparison should continue
		if (diffCode & DIFF_BIT_ANSWER_01) == 0 {
			t.Errorf("Expected DIFF_BIT_ANSWER_01 (one empty answer), got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("NOERROR vs NXDOMAIN is CRITICAL, stops early", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Rcode = dns.RcodeSuccess
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Rcode = dns.RcodeNameError

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_HEAD_RCODE) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_RCODE, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		// RCODE is CRITICAL, should stop early without comparing Answer
		if (diffCode & DIFF_BIT_ANSWER_01) != 0 {
			t.Errorf("Expected no ANSWER_01 because RCODE CRITICAL stops early, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

// ==================== P1: Truncated response skips body comparison ====================

func TestComparator_Compare_Truncated(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("one side truncated, different answers -> only TC diff, no answer diff", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Truncated = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Truncated = false
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// TC标志差异应通过QFLAG检测到
		if (diffCode & DIFF_BIT_HEAD_QFLAG) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_QFLAG for TC diff, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		// Answer diff should NOT be detected (body comparison skipped)
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) != 0 {
			t.Errorf("Expected no ANSWER_RRDIFF when truncated, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("both truncated, same content -> only TC not set, no diff", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Truncated = true

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Truncated = true

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// 双方都Truncated -> 无QFLAG差异（TC相同）
		if (diffCode & DIFF_BIT_HEAD_QFLAG) != 0 {
			t.Errorf("Expected no DIFF_BIT_HEAD_QFLAG when both truncated, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("both truncated, different answers -> body comparison skipped", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Truncated = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Truncated = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// Body comparison should be skipped even though both truncated
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) != 0 {
			t.Errorf("Expected no ANSWER_RRDIFF when both truncated, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("neither truncated, normal comparison proceeds", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// Normal comparison should detect answer diff
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) == 0 {
			t.Errorf("Expected DIFF_BIT_ANSWER_RRDIFF for non-truncated msgs, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

// ==================== DiffCode2Str for new diff codes ====================

func TestDiffCode2Str_NewCodes(t *testing.T) {
	tests := []struct {
		name     string
		diffcode uint32
		expected string
	}{
		{
			name:     "AA flag diff",
			diffcode: DIFF_BIT_HEAD_AA,
			expected: "AA_FLAG_DIFF",
		},
		{
			name:     "SERVFAIL rcode diff",
			diffcode: DIFF_BIT_HEAD_RCODE_SF,
			expected: "RCODE_SERVFAIL_DIFF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DiffCode2Str(tt.diffcode)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// ==================== Init masks include new diff codes ====================

func TestInit_NewDiffCodes(t *testing.T) {
	// DIFF_BIT_HEAD_AA should be WARNING level
	if diffLevelMap[DIFF_BIT_HEAD_AA] != DIFF_LEVEL_WARNING {
		t.Errorf("Expected DIFF_BIT_HEAD_AA to be WARNING level")
	}
	// DIFF_BIT_HEAD_RCODE_SF should be WARNING level
	if diffLevelMap[DIFF_BIT_HEAD_RCODE_SF] != DIFF_LEVEL_WARNING {
		t.Errorf("Expected DIFF_BIT_HEAD_RCODE_SF to be WARNING level")
	}
	// 新增差异码应在WarningMask中
	if (WarningMask & DIFF_BIT_HEAD_AA) == 0 {
		t.Errorf("Expected WarningMask to include DIFF_BIT_HEAD_AA")
	}
	if (WarningMask & DIFF_BIT_HEAD_RCODE_SF) == 0 {
		t.Errorf("Expected WarningMask to include DIFF_BIT_HEAD_RCODE_SF")
	}
	// 新增差异码不应在CriticalMask中
	if (CriticalMask & DIFF_BIT_HEAD_AA) != 0 {
		t.Errorf("Expected CriticalMask to NOT include DIFF_BIT_HEAD_AA")
	}
	if (CriticalMask & DIFF_BIT_HEAD_RCODE_SF) != 0 {
		t.Errorf("Expected CriticalMask to NOT include DIFF_BIT_HEAD_RCODE_SF")
	}
	// 新增差异码应在DefaultMask中
	if (DefaultMask & DIFF_BIT_HEAD_AA) == 0 {
		t.Errorf("Expected DefaultMask to include DIFF_BIT_HEAD_AA")
	}
	if (DefaultMask & DIFF_BIT_HEAD_RCODE_SF) == 0 {
		t.Errorf("Expected DefaultMask to include DIFF_BIT_HEAD_RCODE_SF")
	}
}

// ==================== OPT (EDNS) ECS and Cookie comparison ====================

// helper: create an OPT RR with given UDP size and options
func makeOPT(udpSize uint16, options ...dns.EDNS0) *dns.OPT {
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: udpSize},
	}
	for _, o := range options {
		opt.Option = append(opt.Option, o)
	}
	return opt
}

func makeECS(family uint16, srcMask uint8, srcScope uint8, addr net.IP) *dns.EDNS0_SUBNET {
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: srcMask,
		SourceScope:   srcScope,
		Address:       addr,
	}
}

func makeCookie(cookie string) *dns.EDNS0_COOKIE {
	return &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: cookie,
	}
}

func TestComparator_CmpOPTRecords_ECS(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("same ECS -> no diff", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{makeOPT(4096, ecs2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) != 0 {
			t.Errorf("Expected no ECS diff for identical ECS, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("different ECS address -> ECS diff", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.1.0").To4())
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{makeOPT(4096, ecs2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) == 0 {
			t.Errorf("Expected ECS diff for different addresses, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("different ECS source netmask -> ECS diff", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		ecs2 := makeECS(1, 16, 0, net.ParseIP("10.0.0.0").To4())
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{makeOPT(4096, ecs2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) == 0 {
			t.Errorf("Expected ECS diff for different netmask, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("different ECS scope does NOT cause diff", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		ecs2 := makeECS(1, 24, 24, net.ParseIP("10.0.0.0").To4()) // different scope
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{makeOPT(4096, ecs2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) != 0 {
			t.Errorf("Expected no ECS diff when only scope differs (scope is ignored), got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("one side has ECS, other doesn't -> ECS diff", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{makeOPT(4096)} // no ECS

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) == 0 {
			t.Errorf("Expected ECS diff when one side missing ECS, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("neither side has OPT -> no diff", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		rrs2 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if diffCode != 0 {
			t.Errorf("Expected no diff when neither side has OPT, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("one side has OPT with ECS, other has no OPT -> ECS diff", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{} // no OPT at all

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) == 0 {
			t.Errorf("Expected ECS diff, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("same ECS address masked to source netmask -> no diff", func(t *testing.T) {
		// 10.0.0.55/24 and 10.0.0.99/24 -> both mask to 10.0.0.0/24
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.55").To4())
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.0.99").To4())
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{makeOPT(4096, ecs2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) != 0 {
			t.Errorf("Expected no ECS diff for addresses that match after masking, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("IPv6 ECS same -> no diff", func(t *testing.T) {
		ecs1 := makeECS(2, 48, 0, net.ParseIP("2001:db8:1::1"))
		ecs2 := makeECS(2, 48, 0, net.ParseIP("2001:db8:1::2")) // /48 masks to same
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{makeOPT(4096, ecs2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) != 0 {
			t.Errorf("Expected no ECS diff for same IPv6 /48, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("different UDP size but same ECS -> no ECS diff", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		rrs1 := []dns.RR{makeOPT(4096, ecs1)}
		rrs2 := []dns.RR{makeOPT(1232, ecs2)} // different UDP size

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) != 0 {
			t.Errorf("Expected no ECS diff when only UDP size differs, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

func TestComparator_CmpOPTRecords_Cookie(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("same cookie -> no diff", func(t *testing.T) {
		cookie1 := makeCookie("24a5ac1234567890")
		cookie2 := makeCookie("24a5ac1234567890")
		rrs1 := []dns.RR{makeOPT(4096, cookie1)}
		rrs2 := []dns.RR{makeOPT(4096, cookie2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_COOKIE) != 0 {
			t.Errorf("Expected no cookie diff for identical cookies, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("different cookie -> cookie diff", func(t *testing.T) {
		cookie1 := makeCookie("24a5ac1234567890")
		cookie2 := makeCookie("24a5ac0987654321")
		rrs1 := []dns.RR{makeOPT(4096, cookie1)}
		rrs2 := []dns.RR{makeOPT(4096, cookie2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_COOKIE) == 0 {
			t.Errorf("Expected cookie diff for different cookies, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("one side has cookie, other doesn't -> cookie diff", func(t *testing.T) {
		cookie1 := makeCookie("24a5ac1234567890")
		rrs1 := []dns.RR{makeOPT(4096, cookie1)}
		rrs2 := []dns.RR{makeOPT(4096)} // no cookie

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_COOKIE) == 0 {
			t.Errorf("Expected cookie diff when one side missing cookie, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("neither side has cookie -> no diff", func(t *testing.T) {
		rrs1 := []dns.RR{makeOPT(4096)}
		rrs2 := []dns.RR{makeOPT(4096)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_COOKIE) != 0 {
			t.Errorf("Expected no cookie diff when neither side has cookie, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

func TestComparator_CmpOPTRecords_Combined(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("both ECS and Cookie differ -> both bits set", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		cookie1 := makeCookie("aaaa1111")
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.1.0").To4())
		cookie2 := makeCookie("bbbb2222")

		rrs1 := []dns.RR{makeOPT(4096, ecs1, cookie1)}
		rrs2 := []dns.RR{makeOPT(4096, ecs2, cookie2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) == 0 {
			t.Errorf("Expected ECS diff, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		if (diffCode & DIFF_BIT_ADD_OPT_COOKIE) == 0 {
			t.Errorf("Expected Cookie diff, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("ECS differs but Cookie same -> only ECS bit", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		cookie := makeCookie("samecookie")
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.1.0").To4())

		rrs1 := []dns.RR{makeOPT(4096, ecs1, cookie)}
		rrs2 := []dns.RR{makeOPT(4096, ecs2, makeCookie("samecookie"))}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) == 0 {
			t.Errorf("Expected ECS diff, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		if (diffCode & DIFF_BIT_ADD_OPT_COOKIE) != 0 {
			t.Errorf("Expected no Cookie diff, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("unknown EDNS options are ignored", func(t *testing.T) {
		// EDNS0_LOCAL represents an unknown/local option
		local1 := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3}}
		local2 := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte{4, 5, 6}}

		rrs1 := []dns.RR{makeOPT(4096, local1)}
		rrs2 := []dns.RR{makeOPT(4096, local2)}

		var diffCode uint32
		c.cmpOPTRecords(rrs1, rrs2, &diffCode)

		if diffCode != 0 {
			t.Errorf("Expected no diff for unknown EDNS options, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

func TestComparator_Compare_WithOPTECS(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("full message comparison detects ECS diff in Additional", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		msg1.Extra = []dns.RR{makeOPT(4096, ecs1)}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.1.0").To4())
		msg2.Extra = []dns.RR{makeOPT(4096, ecs2)}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_OPT_ECS) == 0 {
			t.Errorf("Expected ECS diff in full comparison, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		// Answer should be equal
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) != 0 {
			t.Errorf("Expected no answer diff, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("IgnoreAdditional=true skips OPT comparison", func(t *testing.T) {
		cIgnore := &Comparator{
			AllowPartialMatch:  true,
			IgnoreAdditional:   true,
			DiffUnexpectedMask: DefaultMask,
		}

		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		msg1.Extra = []dns.RR{makeOPT(4096, ecs1)}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.1.0").To4())
		msg2.Extra = []dns.RR{makeOPT(4096, ecs2)}

		var diffCode uint32
		cIgnore.Compare(msg1, msg2, &diffCode)

		if diffCode != 0 {
			t.Errorf("Expected no diff when IgnoreAdditional=true, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("OPT with different UDP size but same ECS -> only OPT-level comparison, no ADD_LEN or ADD_RR_DIFF", func(t *testing.T) {
		ecs := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		msg1.Extra = []dns.RR{makeOPT(4096, ecs)}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		msg2.Extra = []dns.RR{makeOPT(1232, makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4()))}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// OPT records are filtered from preProcRRs, so no ADD_RR_DIFF
		if (diffCode & DIFF_BIT_ADD_RRDIFF) != 0 {
			t.Errorf("Expected no ADD_RR_DIFF (OPT filtered from RR comparison), got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		// Same ECS, so no ECS diff
		if (diffCode & DIFF_BIT_ADD_OPT_ECS) != 0 {
			t.Errorf("Expected no ECS diff, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

func TestDiffCode2Str_OPTCodes(t *testing.T) {
	tests := []struct {
		name     string
		diffcode uint32
		expected string
	}{
		{
			name:     "ECS diff",
			diffcode: DIFF_BIT_ADD_OPT_ECS,
			expected: "ADD_OPT_ECS_DIFF",
		},
		{
			name:     "Cookie diff",
			diffcode: DIFF_BIT_ADD_OPT_COOKIE,
			expected: "ADD_OPT_COOKIE_DIFF",
		},
		{
			name:     "both ECS and Cookie",
			diffcode: DIFF_BIT_ADD_OPT_ECS | DIFF_BIT_ADD_OPT_COOKIE,
			expected: "ADD_OPT_ECS_DIFF|ADD_OPT_COOKIE_DIFF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DiffCode2Str(tt.diffcode)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// ==================== sameAResults 补充测试 ====================

func TestComparator_SameAResults(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("both empty -> false (no A/AAAA to compare)", func(t *testing.T) {
		other1 := map[string]struct{}{}
		other2 := map[string]struct{}{}
		if c.sameAResults(other1, other2) {
			t.Error("Expected false when both otherMaps are empty")
		}
	})

	t.Run("identical A records -> true", func(t *testing.T) {
		other1 := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04": {},
		}
		other2 := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04": {},
		}
		if !c.sameAResults(other1, other2) {
			t.Error("Expected true for identical A records")
		}
	})

	t.Run("different A records -> false", func(t *testing.T) {
		other1 := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04": {},
		}
		other2 := map[string]struct{}{
			"example.com.|A|\x05\x06\x07\x08": {},
		}
		if c.sameAResults(other1, other2) {
			t.Error("Expected false for different A records")
		}
	})

	t.Run("different count of A records -> false", func(t *testing.T) {
		other1 := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04": {},
			"example.com.|A|\x05\x06\x07\x08": {},
		}
		other2 := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04": {},
		}
		if c.sameAResults(other1, other2) {
			t.Error("Expected false for different A record count")
		}
	})

	t.Run("mixed types, only A/AAAA compared", func(t *testing.T) {
		other1 := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04":  {},
			"example.com.|NS|ns1.example.com.": {},
		}
		other2 := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04":  {},
			"example.com.|NS|ns2.example.com.": {},
		}
		if !c.sameAResults(other1, other2) {
			t.Error("Expected true: A records are the same, NS differences should be ignored")
		}
	})

	t.Run("no A/AAAA records in either set -> false", func(t *testing.T) {
		other1 := map[string]struct{}{
			"example.com.|NS|ns1.example.com.": {},
		}
		other2 := map[string]struct{}{
			"example.com.|NS|ns1.example.com.": {},
		}
		if c.sameAResults(other1, other2) {
			t.Error("Expected false when no A/AAAA records exist")
		}
	})

	t.Run("one set has A, other has no A -> false", func(t *testing.T) {
		other1 := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04": {},
		}
		other2 := map[string]struct{}{
			"example.com.|NS|ns1.example.com.": {},
		}
		if c.sameAResults(other1, other2) {
			t.Error("Expected false when one side has A and other does not")
		}
	})

	t.Run("identical AAAA records -> true", func(t *testing.T) {
		ipv6 := net.ParseIP("2001:db8::1")
		key := "example.com.|AAAA|" + string(ipv6)
		other1 := map[string]struct{}{key: {}}
		other2 := map[string]struct{}{key: {}}
		if !c.sameAResults(other1, other2) {
			t.Error("Expected true for identical AAAA records")
		}
	})
}

// ==================== buildAResultSet 补充测试 ====================

func TestBuildAResultSet(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		result := buildAResultSet(map[string]struct{}{})
		if len(result) != 0 {
			t.Errorf("Expected empty set, got %d entries", len(result))
		}
	})

	t.Run("only A records", func(t *testing.T) {
		input := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04": {},
			"example.com.|A|\x05\x06\x07\x08": {},
		}
		result := buildAResultSet(input)
		if len(result) != 2 {
			t.Errorf("Expected 2 A records, got %d", len(result))
		}
	})

	t.Run("only AAAA records", func(t *testing.T) {
		input := map[string]struct{}{
			"example.com.|AAAA|some_ipv6_bytes": {},
		}
		result := buildAResultSet(input)
		if len(result) != 1 {
			t.Errorf("Expected 1 AAAA record, got %d", len(result))
		}
	})

	t.Run("mixed types extracts only A and AAAA", func(t *testing.T) {
		input := map[string]struct{}{
			"example.com.|A|\x01\x02\x03\x04":      {},
			"example.com.|AAAA|some_ipv6_bytes":    {},
			"example.com.|NS|ns1.example.com.":     {},
			"example.com.|MX|mail.example.com.|10": {},
			"example.com.|TXT|v=spf1":              {},
		}
		result := buildAResultSet(input)
		if len(result) != 2 {
			t.Errorf("Expected 2 (1 A + 1 AAAA), got %d", len(result))
		}
	})

	t.Run("malformed key no first pipe", func(t *testing.T) {
		input := map[string]struct{}{
			"nopipe": {},
		}
		result := buildAResultSet(input)
		if len(result) != 0 {
			t.Errorf("Expected 0 for malformed key, got %d", len(result))
		}
	})

	t.Run("malformed key no second pipe", func(t *testing.T) {
		input := map[string]struct{}{
			"name|onlyone": {},
		}
		result := buildAResultSet(input)
		if len(result) != 0 {
			t.Errorf("Expected 0 for malformed key, got %d", len(result))
		}
	})
}

// ==================== getCnameFirstAndLast 补充测试 ====================

func TestGetCnameFirstAndLast(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		first, last := getCnameFirstAndLast(map[string]string{})
		if first.name != "" || first.target != "" || last != "" {
			t.Errorf("Expected empty results for empty map, got first=%+v, last=%q", first, last)
		}
	})

	t.Run("single entry", func(t *testing.T) {
		m := map[string]string{
			"www.example.com.": "example.com.",
		}
		first, last := getCnameFirstAndLast(m)
		if first.name != "www.example.com." || first.target != "example.com." {
			t.Errorf("Expected first={www.example.com. -> example.com.}, got %+v", first)
		}
		if last != "example.com." {
			t.Errorf("Expected last=example.com., got %q", last)
		}
	})

	t.Run("chain of three", func(t *testing.T) {
		m := map[string]string{
			"www.example.com.": "mid.example.com.",
			"mid.example.com.": "final.example.com.",
		}
		first, last := getCnameFirstAndLast(m)
		if first.name != "www.example.com." {
			t.Errorf("Expected first.name=www.example.com., got %q", first.name)
		}
		if first.target != "mid.example.com." {
			t.Errorf("Expected first.target=mid.example.com., got %q", first.target)
		}
		if last != "final.example.com." {
			t.Errorf("Expected last=final.example.com., got %q", last)
		}
	})

	t.Run("circular chain detection", func(t *testing.T) {
		// a -> b -> c -> a 形成环
		m := map[string]string{
			"a.example.com.": "b.example.com.",
			"b.example.com.": "c.example.com.",
			"c.example.com.": "a.example.com.",
		}
		// 环形链中所有name都是某个target，所以首跳可能选到任意节点
		// 主要测试不会死循环
		first, last := getCnameFirstAndLast(m)
		_ = first
		_ = last
	})
}

// ==================== sameCnameChains 更多场景 ====================

func TestComparator_SameCnameChains_MoreCases(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("same first hop, different middle, same last -> false (first target differs)", func(t *testing.T) {
		cname1 := map[string]string{
			"www.example.com.":  "mid1.example.com.",
			"mid1.example.com.": "final.example.com.",
		}
		cname2 := map[string]string{
			"www.example.com.":  "mid2.example.com.",
			"mid2.example.com.": "final.example.com.",
		}
		result := c.sameCnameChains(cname1, cname2)
		if result {
			t.Error("Expected false: first hop target differs (mid1 vs mid2)")
		}
	})

	t.Run("long chain identical -> true", func(t *testing.T) {
		cname1 := map[string]string{
			"a.": "b.",
			"b.": "c.",
			"c.": "d.",
		}
		cname2 := map[string]string{
			"a.": "b.",
			"b.": "c.",
			"c.": "d.",
		}
		if !c.sameCnameChains(cname1, cname2) {
			t.Error("Expected true for identical long chains")
		}
	})

	t.Run("different first hop name -> false", func(t *testing.T) {
		cname1 := map[string]string{
			"www1.example.com.": "example.com.",
		}
		cname2 := map[string]string{
			"www2.example.com.": "example.com.",
		}
		if c.sameCnameChains(cname1, cname2) {
			t.Error("Expected false: different first hop name")
		}
	})
}

// ==================== sameECS 补充测试 ====================

func TestSameECS(t *testing.T) {
	t.Run("different family -> false", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		ecs2 := makeECS(2, 24, 0, net.ParseIP("10.0.0.0").To4())
		if sameECS(ecs1, ecs2) {
			t.Error("Expected false for different family")
		}
	})

	t.Run("different source netmask -> false", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		ecs2 := makeECS(1, 16, 0, net.ParseIP("10.0.0.0").To4())
		if sameECS(ecs1, ecs2) {
			t.Error("Expected false for different source netmask")
		}
	})

	t.Run("unknown family falls back to direct comparison - same", func(t *testing.T) {
		ecs1 := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        99,
			SourceNetmask: 24,
			Address:       net.ParseIP("10.0.0.1").To4(),
		}
		ecs2 := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        99,
			SourceNetmask: 24,
			Address:       net.ParseIP("10.0.0.1").To4(),
		}
		if !sameECS(ecs1, ecs2) {
			t.Error("Expected true for same address with unknown family")
		}
	})

	t.Run("unknown family falls back to direct comparison - different", func(t *testing.T) {
		ecs1 := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        99,
			SourceNetmask: 24,
			Address:       net.ParseIP("10.0.0.1").To4(),
		}
		ecs2 := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        99,
			SourceNetmask: 24,
			Address:       net.ParseIP("10.0.0.2").To4(),
		}
		if sameECS(ecs1, ecs2) {
			t.Error("Expected false for different address with unknown family")
		}
	})

	t.Run("IPv4 masked comparison - same network", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.100").To4())
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.0.200").To4())
		if !sameECS(ecs1, ecs2) {
			t.Error("Expected true: same /24 network")
		}
	})

	t.Run("IPv4 different network after masking", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.1").To4())
		ecs2 := makeECS(1, 24, 0, net.ParseIP("10.0.1.1").To4())
		if sameECS(ecs1, ecs2) {
			t.Error("Expected false: different /24 network")
		}
	})

	t.Run("IPv6 masked comparison - same network", func(t *testing.T) {
		ecs1 := makeECS(2, 48, 0, net.ParseIP("2001:db8:1::1"))
		ecs2 := makeECS(2, 48, 0, net.ParseIP("2001:db8:1::ffff"))
		if !sameECS(ecs1, ecs2) {
			t.Error("Expected true: same /48 IPv6 network")
		}
	})

	t.Run("scope difference ignored", func(t *testing.T) {
		ecs1 := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
		ecs2 := makeECS(1, 24, 16, net.ParseIP("10.0.0.0").To4())
		if !sameECS(ecs1, ecs2) {
			t.Error("Expected true: scope should be ignored")
		}
	})
}

// ==================== CmpAnswers CNAME和A/AAAA联动测试 ====================

func TestComparator_CmpAnswers_CnameDiffButSameA(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("different CNAME and different A name -> CNAME diff (A key includes name)", func(t *testing.T) {
		// sameAResults比较的key包含name，所以即使IP相同但name不同也算不一致
		rrs1 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "cdn1.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "cdn1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		rrs2 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "cdn2.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "cdn2.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		var diffCode uint32
		c.CmpAnswers(rrs1, rrs2, &diffCode)

		// A记录的name不同（cdn1 vs cdn2），sameAResults返回false，所以CNAME差异会被报告
		if (diffCode & DIFF_BIT_ANSWER_CNAME) == 0 {
			t.Errorf("Expected ANSWER_CNAME when A record names differ, got 0x%08X", diffCode)
		}
	})

	t.Run("different CNAME but same A result (same name) -> no diff", func(t *testing.T) {
		// 两条CNAME首跳target不同，但A记录的name和IP完全一致
		rrs1 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "cdn1.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "final.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		rrs2 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "cdn2.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "final.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		var diffCode uint32
		c.CmpAnswers(rrs1, rrs2, &diffCode)

		// CNAME不同但A结果一致（name和IP都相同），应忽略CNAME差异
		if (diffCode & DIFF_BIT_ANSWER_CNAME) != 0 {
			t.Errorf("Expected no ANSWER_CNAME when A results are same, got 0x%08X", diffCode)
		}
	})
}

// ==================== preProcRRs TTL差异忽略测试 ====================

func TestComparator_PreProcRRs_TTLIgnored(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("A records with different TTL produce same key", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		rrs2 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		_, other1 := c.preProcRRs(rrs1)
		_, other2 := c.preProcRRs(rrs2)
		for k := range other1 {
			if _, ok := other2[k]; !ok {
				t.Error("Expected same key for A records with different TTL")
			}
		}
	})

	t.Run("SOA records with different serial produce same key", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.SOA{
				Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:     "ns1.example.com.",
				Mbox:   "admin.example.com.",
				Serial: 2024010101,
			},
		}
		rrs2 := []dns.RR{
			&dns.SOA{
				Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:     "ns1.example.com.",
				Mbox:   "admin.example.com.",
				Serial: 2024010102,
			},
		}
		_, other1 := c.preProcRRs(rrs1)
		_, other2 := c.preProcRRs(rrs2)
		for k := range other1 {
			if _, ok := other2[k]; !ok {
				t.Error("Expected same key for SOA records with different serial")
			}
		}
	})
}

// ==================== Compare 完整流程：Authority差异 ====================

func TestComparator_Compare_AuthDiff(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("authority NS diff detected", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		msg1.Ns = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		msg2.Ns = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns2.example.com.",
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_AUTH_RRDIFF) == 0 {
			t.Errorf("Expected AUTH_RRDIFF, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) != 0 {
			t.Errorf("Expected no ANSWER_RRDIFF, got 0x%08X", diffCode)
		}
	})
}

// ==================== compareHeader Question长度和Zero标志测试 ====================

func TestComparator_CompareHeader_QuestLen(t *testing.T) {
	c := &Comparator{}

	t.Run("different question count in header", func(t *testing.T) {
		msg1 := &dns.Msg{
			Question: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		}
		msg2 := &dns.Msg{
			Question: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				{Name: "test.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		}
		var diffCode uint32
		c.compareHeader(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_QUEST_LEN) == 0 {
			t.Errorf("Expected QUEST_LEN diff in header, got 0x%08X", diffCode)
		}
	})
}

func TestComparator_CompareHeader_ZeroFlag(t *testing.T) {
	c := &Comparator{}

	t.Run("different Zero flag -> QFLAG", func(t *testing.T) {
		msg1 := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response: true,
				Zero:     false,
			},
		}
		msg2 := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response: true,
				Zero:     true,
			},
		}
		var diffCode uint32
		c.compareHeader(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_HEAD_QFLAG) == 0 {
			t.Errorf("Expected QFLAG for Zero flag diff, got 0x%08X", diffCode)
		}
	})
}

// ==================== cmpAuthAddRRs AllowPartialMatch 测试 ====================

func TestComparator_CmpAuthAddRRs_PartialMatch(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("auth partial match accepted", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns2.example.com.",
			},
		}
		rrs2 := []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns3.example.com.",
			},
		}
		var diffCode uint32
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, true)

		if (diffCode & DIFF_BIT_AUTH_RRDIFF) != 0 {
			t.Errorf("Expected no AUTH_RRDIFF with partial match, got 0x%08X", diffCode)
		}
	})

	t.Run("additional partial match no diff", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}
		rrs2 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("9.10.11.12"),
			},
		}
		var diffCode uint32
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, false)

		if (diffCode & DIFF_BIT_ADD_RRDIFF) != 0 {
			t.Errorf("Expected no ADD_RRDIFF with partial match, got 0x%08X", diffCode)
		}
	})
}

// ==================== extractOPT/extractECS/extractCookie 边界测试 ====================

func TestExtractOPT_NoOPT(t *testing.T) {
	rrs := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		},
	}
	opt := extractOPT(rrs)
	if opt != nil {
		t.Error("Expected nil when no OPT record exists")
	}
}

func TestExtractECS_NilOPT(t *testing.T) {
	ecs := extractECS(nil)
	if ecs != nil {
		t.Error("Expected nil for nil OPT")
	}
}

func TestExtractCookie_NilOPT(t *testing.T) {
	cookie := extractCookie(nil)
	if cookie != nil {
		t.Error("Expected nil for nil OPT")
	}
}

func TestExtractECS_OPTWithoutECS(t *testing.T) {
	opt := makeOPT(4096, makeCookie("test"))
	ecs := extractECS(opt)
	if ecs != nil {
		t.Error("Expected nil when OPT has no ECS option")
	}
}

func TestExtractCookie_OPTWithoutCookie(t *testing.T) {
	ecs := makeECS(1, 24, 0, net.ParseIP("10.0.0.0").To4())
	opt := makeOPT(4096, ecs)
	cookie := extractCookie(opt)
	if cookie != nil {
		t.Error("Expected nil when OPT has no Cookie option")
	}
}

// ==================== Compare Truncated 跳过后续段对比测试 ====================

func TestComparator_Compare_TruncatedSkipsBody(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("one_side_truncated_skips_answer_comparison", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Truncated = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Truncated = false
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// TC标志差异应检测到
		if (diffCode & DIFF_BIT_HEAD_QFLAG) == 0 {
			t.Errorf("Expected DIFF_BIT_HEAD_QFLAG, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		// Answer/Auth/Additional 对比应跳过
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) != 0 {
			t.Errorf("Expected no ANSWER_RRDIFF when truncated, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		if (diffCode & DIFF_BIT_AUTH_RRDIFF) != 0 {
			t.Errorf("Expected no AUTH_RRDIFF when truncated, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("both_truncated_skips_body_comparison", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Truncated = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Truncated = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// 双方都Truncated，无QFLAG差异
		if (diffCode & DIFF_BIT_HEAD_QFLAG) != 0 {
			t.Errorf("Expected no QFLAG when both truncated, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		// Body comparison 应被跳过
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) != 0 {
			t.Errorf("Expected no ANSWER_RRDIFF when both truncated, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("truncated_with_different_auth_and_additional_skipped", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Truncated = true
		msg1.Ns = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
		}
		msg1.Extra = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.1.1.1"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Truncated = true
		msg2.Ns = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns2.example.com.",
			},
		}
		msg2.Extra = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("2.2.2.2"),
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		// 所有段对比都应跳过
		if diffCode != 0 {
			t.Errorf("Expected no diff when both truncated (body skipped), got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("not_truncated_comparison_proceeds_normally", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) == 0 {
			t.Errorf("Expected ANSWER_RRDIFF for non-truncated, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

// ==================== CmpAnswers 部分匹配日志分支覆盖 ====================

func TestComparator_CmpAnswers_PartialMatchAccepted(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("partial_match_A_records_no_diff", func(t *testing.T) {
		// 两组有部分交集的A记录，AllowPartialMatch=true时应通过
		rrs1 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}
		rrs2 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("9.10.11.12"),
			},
		}

		var diffCode uint32
		err := c.CmpAnswers(rrs1, rrs2, &diffCode)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if diffCode != 0 {
			t.Errorf("Expected no diff for partial A match, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})

	t.Run("fully_different_A_records_diff", func(t *testing.T) {
		// 完全不同的A记录，即使 AllowPartialMatch=true 也应报差异
		rrs1 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		rrs2 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("9.10.11.12"),
			},
		}

		var diffCode uint32
		err := c.CmpAnswers(rrs1, rrs2, &diffCode)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) == 0 {
			t.Errorf("Expected ANSWER_RRDIFF for fully different records, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

// ==================== cmpAuthAddRRs 更多边界场景 ====================

func TestComparator_CmpAuthAddRRs_MoreEdgeCases(t *testing.T) {
	t.Run("additional_different_length_no_partial_match", func(t *testing.T) {
		c := &Comparator{
			AllowPartialMatch:  false,
			IgnoreAdditional:   false,
			DiffUnexpectedMask: DefaultMask,
		}
		rrs1 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}
		rrs2 := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		var diffCode uint32
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, false)

		if (diffCode & DIFF_BIT_ADD_LEN) == 0 {
			t.Errorf("Expected ADD_LEN for additional with different lengths, got 0x%08X", diffCode)
		}
	})

	t.Run("auth_different_length_no_partial_match", func(t *testing.T) {
		c := &Comparator{
			AllowPartialMatch:  false,
			IgnoreAdditional:   true,
			DiffUnexpectedMask: DefaultMask,
		}
		rrs1 := []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns2.example.com.",
			},
		}
		rrs2 := []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
		}
		var diffCode uint32
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, true)

		if (diffCode & DIFF_BIT_AUTH_LEN) == 0 {
			t.Errorf("Expected AUTH_LEN for auth with different lengths, got 0x%08X", diffCode)
		}
	})

	t.Run("auth_all_different_no_partial", func(t *testing.T) {
		c := &Comparator{
			AllowPartialMatch:  false,
			IgnoreAdditional:   true,
			DiffUnexpectedMask: DefaultMask,
		}
		rrs1 := []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
		}
		rrs2 := []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns99.example.com.",
			},
		}
		var diffCode uint32
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, true)

		if (diffCode & DIFF_BIT_AUTH_RRDIFF) == 0 {
			t.Errorf("Expected AUTH_RRDIFF, got 0x%08X", diffCode)
		}
	})

	t.Run("additional_cname_diff_with_different_A_results", func(t *testing.T) {
		c := &Comparator{
			AllowPartialMatch:  true,
			IgnoreAdditional:   false,
			DiffUnexpectedMask: DefaultMask,
		}
		rrs1 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "real1.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "real1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		rrs2 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "real2.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "real2.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("5.6.7.8"),
			},
		}
		var diffCode uint32
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, false)

		if (diffCode & DIFF_BIT_ADD_CNAME) == 0 {
			t.Errorf("Expected ADD_CNAME, got 0x%08X", diffCode)
		}
	})

	t.Run("auth_cname_diff_but_same_A_results_ignored", func(t *testing.T) {
		c := &Comparator{
			AllowPartialMatch:  true,
			IgnoreAdditional:   true,
			DiffUnexpectedMask: DefaultMask,
		}
		rrs1 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "cdn1.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "final.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		rrs2 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "cdn2.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "final.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		var diffCode uint32
		c.cmpAuthAddRRs(rrs1, rrs2, &diffCode, true)

		if (diffCode & DIFF_BIT_AUTH_CNAME) != 0 {
			t.Errorf("Expected no AUTH_CNAME when A results are same, got 0x%08X", diffCode)
		}
	})
}

// ==================== cmpRRSet AllEqual 路径（AllowPartialMatch=true + 完全相同集合）====================

func TestComparator_CmpRRSet_AllEqualWithPartialMatch(t *testing.T) {
	// AllowPartialMatch=true 时，如果集合完全相同，cmpRRSet 第一个匹配就会立即返回 RRSetPartEqual
	// 这是已知行为（AllowPartialMatch 加速退出）
	c := &Comparator{
		AllowPartialMatch: true,
	}

	t.Run("single_element_identical_sets", func(t *testing.T) {
		m1 := map[string]struct{}{"key1": {}}
		m2 := map[string]struct{}{"key1": {}}
		result := c.cmpRRSet(m1, m2)
		// AllowPartialMatch=true 会在第一个匹配时立即返回 PartEqual
		if result != RRSetPartEqual {
			t.Errorf("Expected RRSetPartEqual with AllowPartialMatch=true, got %d", result)
		}
	})

	// AllowPartialMatch=false 时，完全相同集合返回 AllEqual
	t.Run("identical_sets_no_partial_returns_AllEqual", func(t *testing.T) {
		cNoPartial := &Comparator{AllowPartialMatch: false}
		m1 := map[string]struct{}{
			"key1": {},
			"key2": {},
			"key3": {},
		}
		m2 := map[string]struct{}{
			"key1": {},
			"key2": {},
			"key3": {},
		}
		result := cNoPartial.cmpRRSet(m1, m2)
		if result != RRSetAllEqual {
			t.Errorf("Expected RRSetAllEqual, got %d", result)
		}
	})
}

// ==================== Compare 完整流程：IgnoreAdditional=false 且 Additional 段有 Critical 差异提前退出 ====================

func TestComparator_Compare_AdditionalCriticalEarlyReturn(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  false,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("auth_critical_stops_before_additional", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		// answer 为空对比 answer 有记录 -> ANSWER_01 是 CRITICAL
		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_ANSWER_01) == 0 {
			t.Errorf("Expected ANSWER_01 (CRITICAL), got 0x%08X", diffCode)
		}
	})
}

// ==================== Compare IgnoreAdditional=false 正常对比 Additional 段 ====================

func TestComparator_Compare_AdditionalNotIgnored(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("additional_diff_detected_when_not_ignored", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.SetQuestion("example.com.", dns.TypeA)
		msg1.Response = true
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		msg1.Extra = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("10.0.0.1"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.SetQuestion("example.com.", dns.TypeA)
		msg2.Response = true
		msg2.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		msg2.Extra = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("10.0.0.2"),
			},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_ADD_RRDIFF) == 0 {
			t.Errorf("Expected ADD_RRDIFF for different additional records, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
		// Answer 应该一致
		if (diffCode & DIFF_BIT_ANSWER_RRDIFF) != 0 {
			t.Errorf("Expected no ANSWER_RRDIFF, got 0x%08X", diffCode)
		}
	})
}

// ==================== preProcRRs 重复记录去重、AAAA 不同 TTL 测试 ====================

func TestComparator_PreProcRRs_DuplicateRecords(t *testing.T) {
	c := &Comparator{AllowPartialMatch: true}

	t.Run("duplicate_A_records_produce_one_key", func(t *testing.T) {
		rrs := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		_, otherMap := c.preProcRRs(rrs)
		// 两条记录应该生成同一个 key（TTL 忽略）
		if len(otherMap) != 1 {
			t.Errorf("Expected 1 unique A record key, got %d", len(otherMap))
		}
	})

	t.Run("AAAA_records_different_TTL_same_key", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.AAAA{
				Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 100},
				AAAA: net.ParseIP("2001:db8::1"),
			},
		}
		rrs2 := []dns.RR{
			&dns.AAAA{
				Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 9999},
				AAAA: net.ParseIP("2001:db8::1"),
			},
		}
		_, other1 := c.preProcRRs(rrs1)
		_, other2 := c.preProcRRs(rrs2)

		for k := range other1 {
			if _, ok := other2[k]; !ok {
				t.Error("Expected same key for AAAA records with different TTL")
			}
		}
	})

	t.Run("CNAME_case_insensitive", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "WWW.EXAMPLE.COM.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "CDN.EXAMPLE.COM.",
			},
		}
		rrs2 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "cdn.example.com.",
			},
		}
		cname1, _ := c.preProcRRs(rrs1)
		cname2, _ := c.preProcRRs(rrs2)

		// CNAME key 和 target 都应该统一小写
		for k, v := range cname1 {
			v2, ok := cname2[k]
			if !ok {
				t.Errorf("Expected same key for CNAME with different case, key=%s", k)
			}
			if v != v2 {
				t.Errorf("Expected same target, got %q vs %q", v, v2)
			}
		}
	})

	t.Run("MX_case_insensitive_and_preference", func(t *testing.T) {
		rrs := []dns.RR{
			&dns.MX{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: 10,
				Mx:         "MAIL.EXAMPLE.COM.",
			},
		}
		_, otherMap := c.preProcRRs(rrs)
		if len(otherMap) != 1 {
			t.Errorf("Expected 1 MX record, got %d", len(otherMap))
		}
		// 验证 key 是小写的
		for k := range otherMap {
			if k != "example.com.|MX|mail.example.com.|10" {
				t.Errorf("Expected lowercased MX key, got %q", k)
			}
		}
	})

	t.Run("TXT_records_with_multiple_strings", func(t *testing.T) {
		rrs := []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{"part1", "part2", "part3"},
			},
		}
		_, otherMap := c.preProcRRs(rrs)
		if len(otherMap) != 1 {
			t.Errorf("Expected 1 TXT record, got %d", len(otherMap))
		}
	})
}

// ==================== DiffCode2Str 更多组合测试 ====================

func TestDiffCode2Str_AllFlags(t *testing.T) {
	t.Run("all_critical_flags", func(t *testing.T) {
		result := DiffCode2Str(CriticalMask)
		if result == "EQUAL" {
			t.Error("CriticalMask should produce non-EQUAL string")
		}
	})

	t.Run("all_warning_flags", func(t *testing.T) {
		result := DiffCode2Str(WarningMask)
		if result == "EQUAL" {
			t.Error("WarningMask should produce non-EQUAL string")
		}
	})

	t.Run("single_NOMATCHDOMAIN", func(t *testing.T) {
		result := DiffCode2Str(DIFF_BIT_NOMATCHDOMAIN)
		if result != "NOMATCHDOMAIN" {
			t.Errorf("Expected 'NOMATCHDOMAIN', got %q", result)
		}
	})

	t.Run("single_NOMATCHKEY", func(t *testing.T) {
		result := DiffCode2Str(DIFF_BIT_NOMATCHKEY)
		if result != "NOMATCHKEY" {
			t.Errorf("Expected 'NOMATCHKEY', got %q", result)
		}
	})

	t.Run("all_answer_flags", func(t *testing.T) {
		code := uint32(DIFF_BIT_ANSWER_01 | DIFF_BIT_ANSWER_LEN | DIFF_BIT_ANSWER_CNAME | DIFF_BIT_ANSWER_RRDIFF)
		result := DiffCode2Str(code)
		if !contains(result, "ANSWER_01_DIFF") || !contains(result, "ANSWER_LEN_DIFF") ||
			!contains(result, "ANSWER_CNAME_DIFF") || !contains(result, "ANSWER_RR_DIFF") {
			t.Errorf("Expected all answer flags in result, got %q", result)
		}
	})
}

// ==================== Compare 边界：Question 段 Critical 提前退出 ====================

func TestComparator_Compare_QuestionCriticalEarlyReturn(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   false,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("question_length_diff_stops_before_answer", func(t *testing.T) {
		msg1 := new(dns.Msg)
		msg1.MsgHdr.Response = true
		msg1.Question = []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		}
		msg1.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			},
		}

		msg2 := new(dns.Msg)
		msg2.MsgHdr.Response = true
		msg2.Question = []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			{Name: "test.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		}

		var diffCode uint32
		c.Compare(msg1, msg2, &diffCode)

		if (diffCode & DIFF_BIT_QUEST_LEN) == 0 {
			t.Errorf("Expected QUEST_LEN, got 0x%08X", diffCode)
		}
		// Answer 不应被对比
		if (diffCode & DIFF_BIT_ANSWER_01) != 0 {
			t.Errorf("Expected no ANSWER_01 because Question critical stops early, got 0x%08X", diffCode)
		}
	})
}

// ==================== CmpAnswers 边界：both empty with CNAME only ====================

func TestComparator_CmpAnswers_OnlyCname(t *testing.T) {
	c := &Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: DefaultMask,
	}

	t.Run("identical_cname_only_no_diff", func(t *testing.T) {
		rrs1 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "example.com.",
			},
		}
		rrs2 := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "example.com.",
			},
		}
		var diffCode uint32
		err := c.CmpAnswers(rrs1, rrs2, &diffCode)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if diffCode != 0 {
			t.Errorf("Expected no diff for identical CNAME-only records, got 0x%08X (%s)", diffCode, DiffCode2Str(diffCode))
		}
	})
}

// ==================== sameECS 零掩码测试 ====================

func TestSameECS_ZeroMask(t *testing.T) {
	t.Run("zero_source_netmask_all_addresses_equal", func(t *testing.T) {
		ecs1 := makeECS(1, 0, 0, net.ParseIP("10.0.0.1").To4())
		ecs2 := makeECS(1, 0, 0, net.ParseIP("192.168.1.1").To4())
		// /0 掩码意味着所有地址都相等
		if !sameECS(ecs1, ecs2) {
			t.Error("Expected true: /0 mask should make all addresses equal")
		}
	})
}

// ==================== Benchmark: 大量 RR 记录的 preProcRRs 性能 ====================

func BenchmarkComparator_PreProcRRs_LargeSet(b *testing.B) {
	c := &Comparator{AllowPartialMatch: true}

	// 构造 100 条 A 记录
	rrs := make([]dns.RR, 100)
	for i := 0; i < 100; i++ {
		rrs[i] = &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(byte(i/256/256/256), byte(i/256/256%256), byte(i/256%256), byte(i%256)),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.preProcRRs(rrs)
	}
}

// ==================== Benchmark: cmpRRSet 大集合性能 ====================

func BenchmarkComparator_CmpRRSet_LargeSet(b *testing.B) {
	c := &Comparator{AllowPartialMatch: false}

	m1 := make(map[string]struct{}, 100)
	m2 := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		key := "example.com.|A|" + net.IPv4(byte(i/256/256/256), byte(i/256/256%256), byte(i/256%256), byte(i%256)).String()
		m1[key] = struct{}{}
		m2[key] = struct{}{}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.cmpRRSet(m1, m2)
	}
}
