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
		IgnoreTTL:          true,
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
		IgnoreTTL:          true,
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
		IgnoreTTL:          true,
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
		IgnoreTTL:          true,
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
		IgnoreTTL:          true,
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
		IgnoreTTL:          true,
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
			name: "different lengths",
			cname1: map[string]string{
				"www.example.com.": "example.com.",
			},
			cname2: map[string]string{
				"www.example.com.":  "example.com.",
				"www2.example.com.": "example.com.",
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
		IgnoreTTL:          true,
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
			IgnoreTTL:          true,
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
		IgnoreTTL:          true,
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
		IgnoreTTL:          true,
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
		IgnoreTTL:          true,
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

func BenchmarkComparator_Compare(b *testing.B) {
	c := &Comparator{
		IgnoreTTL:          true,
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
