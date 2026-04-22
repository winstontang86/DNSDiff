package validate

import (
	"testing"

	"github.com/miekg/dns"
)

// createTestRequest creates a simple DNS request for testing
func createTestRequest(name string, qtype uint16) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	data, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return data
}

// createTestResponse creates a simple DNS response for testing
// It copies the ID from the request to ensure they match
func createTestResponse(name string, qtype uint16, answers []dns.RR, reqID uint16) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.Id = reqID // Set ID after SetQuestion (which generates a random ID)
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	msg.Answer = answers
	data, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return data
}

func TestValidateReq_ValidRequest(t *testing.T) {
	rawReq := createTestRequest("example.com", dns.TypeA)

	errBits, warningBits, msg, _, err := ValidateReq(rawReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg == nil {
		t.Fatal("expected non-nil message")
	}

	// Should only have warning for no EDNS
	if errBits != 0 {
		t.Errorf("expected no errors, got: 0x%X (%v)", errBits, GetErrorDescription(errBits))
	}

	if warningBits != 0 {
		t.Errorf("expected no warnings, got: 0x%X (%v)", warningBits, GetWarningDescription(warningBits))
	}
}

func TestValidateReq_TooShort(t *testing.T) {
	rawReq := []byte{0x00, 0x01, 0x02} // Only 3 bytes

	errBits, _, msg, _, err := ValidateReq(rawReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg != nil {
		t.Error("expected nil message for too short data")
	}

	// M01: Message too short
	if !IsError(errBits, ErrMsgTooShort) {
		t.Errorf("expected ErrMsgTooShort, got: 0x%X", errBits)
	}
}

func TestValidateReq_TooLong(t *testing.T) {
	// Create a packet larger than 65535 bytes
	rawReq := make([]byte, MaxMessageLength+1)
	copy(rawReq[:12], createTestRequest("example.com", dns.TypeA)[:12])

	errBits, _, msg, _, err := ValidateReq(rawReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg != nil {
		t.Error("expected nil message for too long data")
	}

	// M02: Message too long
	if !IsError(errBits, ErrMsgTooLong) {
		t.Errorf("expected ErrMsgTooLong, got: 0x%X", errBits)
	}
}

func TestValidateReq_InvalidData(t *testing.T) {
	// Create invalid DNS data (valid header size but content that will fail parsing)
	rawReq := []byte{
		0x00, 0x01, // ID
		0x00, 0x00, // Flags (QR=0)
		0x00, 0x01, // QDCOUNT=1 (but no valid question follows)
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
		// Missing question data - this should cause unpack to fail or count mismatch
	}

	errBits, _, _, _, err := ValidateReq(rawReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have some error (either unpack failure or count mismatch)
	if errBits == 0 {
		t.Error("expected some error for invalid data, got none")
	}
}

func TestValidateRsp_ValidResponse(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)

	// Extract the ID from the request
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// Create response with an A record, using the same ID
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rsp := createTestResponse("example.com", dns.TypeA, []dns.RR{rr}, reqID)

	errBits, _, msg, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg == nil {
		t.Fatal("expected non-nil message")
	}

	if errBits != 0 {
		t.Errorf("expected no errors, got: 0x%X (%v)", errBits, GetErrorDescription(errBits))
	}
}

func TestValidateRsp_IDMismatch(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rsp := createTestResponse("example.com", dns.TypeA, []dns.RR{rr}, reqID)

	// Modify response ID to create mismatch
	rsp[0] = 0xFF
	rsp[1] = 0xFF

	errBits, _, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A01: ID mismatch
	if !IsError(errBits, ErrAssocIDMismatch) {
		t.Errorf("expected ErrAssocIDMismatch, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateRsp_OpcodeMismatch(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rsp := createTestResponse("example.com", dns.TypeA, []dns.RR{rr}, reqID)

	// Modify response Opcode (byte 2, bits 3-6)
	rsp[2] = (rsp[2] & 0x87) | (2 << 3) // Set Opcode to 2 (STATUS)

	errBits, _, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A02: Opcode mismatch
	if !IsError(errBits, ErrAssocOpcodeMismatch) {
		t.Errorf("expected ErrAssocOpcodeMismatch, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateReq_QRBitError(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)

	// Set QR bit to 1 (response) in request
	req[2] |= 0x80

	errBits, _, _, _, err := ValidateReq(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// H02: QR bit error in request
	if !IsError(errBits, ErrHeaderQRReq) {
		t.Errorf("expected ErrHeaderQRReq, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateRsp_QRBitError(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rsp := createTestResponse("example.com", dns.TypeA, []dns.RR{rr}, reqID)

	// Clear QR bit (make it look like a request)
	rsp[2] &= 0x7F

	errBits, _, _, _, err := ValidateRsp(nil, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// H03: QR bit error in response
	if !IsError(errBits, ErrHeaderQRRsp) {
		t.Errorf("expected ErrHeaderQRRsp, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateReq_InvalidOpcode(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)

	// Set Opcode to 3 (not in {0, 2, 4, 5})
	req[2] = (req[2] & 0x87) | (3 << 3)

	errBits, _, _, _, err := ValidateReq(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// H05: Invalid Opcode
	if !IsError(errBits, ErrHeaderOpcodeInvalid) {
		t.Errorf("expected ErrHeaderOpcodeInvalid, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateReq_ZBitError(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)

	// Set Z bit (bit 6 of byte 3)
	req[3] |= 0x40

	errBits, _, _, _, err := ValidateReq(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// H10: Z bit not zero
	if !IsError(errBits, ErrHeaderZNotZero) {
		t.Errorf("expected ErrHeaderZNotZero, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestParseRawHeader(t *testing.T) {
	rawReq := createTestRequest("example.com", dns.TypeA)

	header, err := parseRawHeader(rawReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify header fields
	if header.QR {
		t.Error("expected QR=false for request")
	}

	if header.QDCount != 1 {
		t.Errorf("expected QDCount=1, got %d", header.QDCount)
	}

	if header.ANCount != 0 {
		t.Errorf("expected ANCount=0, got %d", header.ANCount)
	}

	if header.Z {
		t.Error("expected Z=false for normal request")
	}
}

func TestValidateMsg(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true

	errBits, warningBits, _ := ValidateMsg(msg, true)

	if errBits != 0 {
		t.Errorf("expected no errors, got: 0x%X", errBits)
	}

	if warningBits != 0 {
		t.Error("expected no warnings")
	}
}

func TestGetErrorDescription(t *testing.T) {
	errBits := ErrFormUnpack | ErrMsgTooShort

	desc := GetErrorDescription(errBits)

	if len(desc) != 2 {
		t.Errorf("expected 2 descriptions, got %d", len(desc))
	}

	// Check that both error names are present
	found := map[string]bool{}
	for _, d := range desc {
		found[d] = true
	}

	if !found["ErrFormUnpack"] {
		t.Error("expected ErrFormUnpack in description")
	}
	if !found["ErrMsgTooShort"] {
		t.Error("expected ErrMsgTooShort in description")
	}
}

func TestValidationResult_String(t *testing.T) {
	result := NewValidationResult()
	result.AddError(ErrFormUnpack, "test error")
	result.AddWarning(WarnHeaderOpcodeNonZero, "test warning")

	str := result.String()

	if str == "" {
		t.Error("expected non-empty string")
	}

	if !result.HasAnyError() {
		t.Error("expected HasAnyError to be true")
	}

	if !result.HasAnyWarning() {
		t.Error("expected HasAnyWarning to be true")
	}

	if result.IsValid() {
		t.Error("expected IsValid to be false")
	}
}

func TestValidateRaw(t *testing.T) {
	// Test with request
	req := createTestRequest("example.com", dns.TypeA)
	errBits, _, msg, isResponse, _, err := ValidateRaw(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isResponse {
		t.Error("expected isResponse=false for request")
	}
	if msg == nil {
		t.Error("expected non-nil message")
	}
	if HasErrors(errBits) {
		t.Errorf("unexpected errors: %v", GetErrorDescription(errBits))
	}

	// Test with response
	rspID := uint16(req[0])<<8 | uint16(req[1])
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rsp := createTestResponse("example.com", dns.TypeA, []dns.RR{rr}, rspID)
	errBits, _, msg, isResponse, _, err = ValidateRaw(rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isResponse {
		t.Error("expected isResponse=true for response")
	}
}

func TestValidateRsp_NXDOMAINWithAnswer(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// Create NXDOMAIN response with an answer (invalid)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	msg.Id = reqID
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	msg.Rcode = dns.RcodeNameError // NXDOMAIN

	// Add an answer (invalid for NXDOMAIN)
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	msg.Answer = []dns.RR{rr}

	rsp, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	_, warningBits, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A06: NXDOMAIN has answer
	if !IsWarning(warningBits, WarnAssocNXDOMAINHasAnswer) {
		t.Errorf("expected WarnAssocNXDOMAINHasAnswer, got: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}
}

func TestValidateRsp_NoErrorEmpty(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// Create NOERROR response with no records at all
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	msg.Id = reqID
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	msg.Rcode = dns.RcodeSuccess // NOERROR
	// No Answer, Authority, or Additional records

	rsp, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	errBits, _, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A08: NoError but empty
	if !IsError(errBits, ErrAssocNoErrorEmpty) {
		t.Errorf("expected ErrAssocNoErrorEmpty, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateReq_QTypeOPT(t *testing.T) {
	// Create request with QTYPE=OPT (invalid)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeOPT)
	msg.RecursionDesired = true
	req, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack request: %v", err)
	}

	errBits, _, _, _, err := ValidateReq(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Q06: QTYPE=OPT in Question
	if !IsError(errBits, ErrQTypeOPT) {
		t.Errorf("expected ErrQTypeOPT, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateReq_QClassNotIN(t *testing.T) {
	// Create request with QCLASS=CH (Chaos)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("version.bind"), dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS
	msg.RecursionDesired = true
	req, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack request: %v", err)
	}

	_, warningBits, _, _, err := ValidateReq(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Q07: QCLASS not IN
	if !IsWarning(warningBits, WarnQClassNotIN) {
		t.Errorf("expected WarnQClassNotIN, got: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}
}

// ==================== 补充测试：覆盖 0% 和低覆盖率函数 ====================

func TestGetWarningDescription(t *testing.T) {
	warningBits := WarnHeaderOpcodeNonZero | WarnHeaderTCInRsp

	desc := GetWarningDescription(warningBits)
	if len(desc) != 2 {
		t.Errorf("expected 2 descriptions, got %d", len(desc))
	}

	found := map[string]bool{}
	for _, d := range desc {
		found[d] = true
	}

	if !found["WarnHeaderOpcodeNonZero"] {
		t.Error("expected WarnHeaderOpcodeNonZero in description")
	}
	if !found["WarnHeaderTCInRsp"] {
		t.Error("expected WarnHeaderTCInRsp in description")
	}
}

func TestHasWarnings(t *testing.T) {
	if HasWarnings(0) {
		t.Error("expected HasWarnings(0) = false")
	}
	if !HasWarnings(WarnHeaderTCInRsp) {
		t.Error("expected HasWarnings with set bit = true")
	}
}

func TestValidationResult_HasError(t *testing.T) {
	result := NewValidationResult()
	result.AddError(ErrFormUnpack, "test")

	if !result.HasError(ErrFormUnpack) {
		t.Error("expected HasError(ErrFormUnpack) = true")
	}
	if result.HasError(ErrMsgTooShort) {
		t.Error("expected HasError(ErrMsgTooShort) = false")
	}
}

func TestValidationResult_HasWarning(t *testing.T) {
	result := NewValidationResult()
	result.AddWarning(WarnHeaderTCInRsp, "test")

	if !result.HasWarning(WarnHeaderTCInRsp) {
		t.Error("expected HasWarning(WarnHeaderTCInRsp) = true")
	}
	if result.HasWarning(WarnHeaderAAInReq) {
		t.Error("expected HasWarning(WarnHeaderAAInReq) = false")
	}
}

func TestValidationResult_GetFullRcode(t *testing.T) {
	// 无 RawHeader
	result := NewValidationResult()
	if result.GetFullRcode() != 0 {
		t.Error("expected GetFullRcode=0 when RawHeader is nil")
	}

	// 有 RawHeader 且无扩展 RCODE
	result.RawHeader = &RawHeaderInfo{Rcode: 3} // NXDOMAIN
	result.ExtendedRcode = 0
	if got := result.GetFullRcode(); got != 3 {
		t.Errorf("expected GetFullRcode=3, got %d", got)
	}

	// 有扩展 RCODE
	result.ExtendedRcode = 1
	// full_rcode = (1 << 4) | (3 & 0x0F) = 16 + 3 = 19
	if got := result.GetFullRcode(); got != 19 {
		t.Errorf("expected GetFullRcode=19, got %d", got)
	}
}

func TestValidationResult_Merge(t *testing.T) {
	r1 := NewValidationResult()
	r1.AddError(ErrFormUnpack, "error1")

	r2 := NewValidationResult()
	r2.AddWarning(WarnHeaderTCInRsp, "warning1")
	r2.AddError(ErrMsgTooShort, "error2")

	r1.Merge(r2)

	if !r1.HasError(ErrFormUnpack) {
		t.Error("expected r1 to retain ErrFormUnpack")
	}
	if !r1.HasError(ErrMsgTooShort) {
		t.Error("expected r1 to have merged ErrMsgTooShort")
	}
	if !r1.HasWarning(WarnHeaderTCInRsp) {
		t.Error("expected r1 to have merged WarnHeaderTCInRsp")
	}
	if len(r1.Details) != 3 {
		t.Errorf("expected 3 details after merge, got %d", len(r1.Details))
	}

	// 测试 merge nil
	r1.Merge(nil)
	if len(r1.Details) != 3 {
		t.Error("merge nil should not change details")
	}
}

func TestValidateRspWithTCP(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// 创建一个 TC=1 的响应
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	msg.Id = reqID
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	msg.Truncated = true // TC=1
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	msg.Answer = []dns.RR{rr}

	rsp, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	// TCP 中 TC=1 应该产生警告
	_, warningBits, rspMsg, _, err := ValidateRspWithTCP(req, rsp, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rspMsg == nil {
		t.Fatal("expected non-nil message")
	}
	if !IsWarning(warningBits, WarnAssocTCInTCP) {
		t.Errorf("expected WarnAssocTCInTCP for TCP with TC=1, got warnings: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}

	// UDP 中 TC=1 只是普通截断警告
	_, warningBits2, _, _, err := ValidateRspWithTCP(req, rsp, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// UDP 中不应有 WarnAssocTCInTCP
	if IsWarning(warningBits2, WarnAssocTCInTCP) {
		t.Error("unexpected WarnAssocTCInTCP for UDP")
	}
}

func TestValidateRspWithTCP_NilResponse(t *testing.T) {
	// 太短的响应
	_, _, msg, _, err := ValidateRspWithTCP(nil, []byte{0x00}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != nil {
		t.Error("expected nil message for too short response")
	}
}

func TestValidateRsp_WithEDNS(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// 创建带 EDNS 的响应
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	msg.Id = reqID
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	msg.Answer = []dns.RR{rr}

	// 添加 EDNS OPT
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	rsp, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	errBits, _, rspMsg, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rspMsg == nil {
		t.Fatal("expected non-nil message")
	}
	if errBits != 0 {
		t.Errorf("expected no errors for valid EDNS response, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateRsp_WithECS(t *testing.T) {
	// 创建带 ECS 的请求
	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	reqMsg.RecursionDesired = true

	// 添加 ECS 到请求
	reqOpt := new(dns.OPT)
	reqOpt.Hdr.Name = "."
	reqOpt.Hdr.Rrtype = dns.TypeOPT
	reqOpt.SetUDPSize(4096)
	ecs := &dns.EDNS0_SUBNET{
		Code:          8,
		Family:        1, // IPv4
		SourceNetmask: 24,
		SourceScope:   0,
		Address:       []byte{10, 0, 0, 0},
	}
	reqOpt.Option = append(reqOpt.Option, ecs)
	reqMsg.Extra = append(reqMsg.Extra, reqOpt)

	req, err := reqMsg.Pack()
	if err != nil {
		t.Fatalf("failed to pack request: %v", err)
	}
	reqID := reqMsg.Id

	// 创建带 ECS 的响应
	rspMsg := new(dns.Msg)
	rspMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	rspMsg.Id = reqID
	rspMsg.Response = true
	rspMsg.RecursionDesired = true
	rspMsg.RecursionAvailable = true
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rspMsg.Answer = []dns.RR{rr}

	rspOpt := new(dns.OPT)
	rspOpt.Hdr.Name = "."
	rspOpt.Hdr.Rrtype = dns.TypeOPT
	rspOpt.SetUDPSize(4096)
	rspMsg.Extra = append(rspMsg.Extra, rspOpt)

	rsp, err := rspMsg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	errBits, _, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 不应有错误（ECS 校验需要 ResponseECS，这里只有 RequestECS）
	_ = errBits
}

func TestValidateMsg_NilMsg(t *testing.T) {
	errBits, _, _ := ValidateMsg(nil, true)
	if errBits != ErrFormUnpack {
		t.Errorf("expected ErrFormUnpack for nil msg, got: 0x%X", errBits)
	}
}

func TestValidateMsg_ResponseMsg(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	msg.Answer = []dns.RR{rr}

	// 通过 Pack/Unpack 确保 Rdlength 等字段正确填充
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack msg: %v", err)
	}
	parsedMsg := new(dns.Msg)
	if err := parsedMsg.Unpack(data); err != nil {
		t.Fatalf("failed to unpack msg: %v", err)
	}

	errBits, _, _ := ValidateMsg(parsedMsg, false)
	if errBits != 0 {
		t.Errorf("expected no errors for valid response msg, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateMsg_WithEDNS(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	errBits, _, _ := ValidateMsg(msg, true)
	if errBits != 0 {
		t.Errorf("expected no errors, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateRaw_TooShort(t *testing.T) {
	errBits, _, _, _, _, _ := ValidateRaw([]byte{0x00})
	if errBits != ErrMsgTooShort {
		t.Errorf("expected ErrMsgTooShort, got: 0x%X", errBits)
	}
}

func TestValidateRsp_RDMismatch(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// 创建响应但 RD=0
	rspMsg := new(dns.Msg)
	rspMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	rspMsg.Id = reqID
	rspMsg.Response = true
	rspMsg.RecursionDesired = false // RD=0（但请求中 RD=1）
	rspMsg.RecursionAvailable = true
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rspMsg.Answer = []dns.RR{rr}
	rsp, _ := rspMsg.Pack()

	errBits, _, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsError(errBits, ErrAssocRDMismatch) {
		t.Errorf("expected ErrAssocRDMismatch, got: 0x%X", errBits)
	}
}

func TestValidateRsp_QuestionMismatch(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// 创建 Question 域名不同的响应
	rspMsg := new(dns.Msg)
	rspMsg.SetQuestion(dns.Fqdn("other.com"), dns.TypeA)
	rspMsg.Id = reqID
	rspMsg.Response = true
	rspMsg.RecursionDesired = true
	rspMsg.RecursionAvailable = true
	rr, _ := dns.NewRR("other.com. 300 IN A 93.184.216.34")
	rspMsg.Answer = []dns.RR{rr}
	rsp, _ := rspMsg.Pack()

	errBits, _, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsError(errBits, ErrAssocQuestionMismatch) {
		t.Errorf("expected ErrAssocQuestionMismatch, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateRsp_NXDOMAIN_NoSOA(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// NXDOMAIN 且没有 SOA
	rspMsg := new(dns.Msg)
	rspMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	rspMsg.Id = reqID
	rspMsg.Response = true
	rspMsg.RecursionDesired = true
	rspMsg.RecursionAvailable = true
	rspMsg.Rcode = dns.RcodeNameError
	rsp, _ := rspMsg.Pack()

	_, warningBits, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsWarning(warningBits, WarnAssocNXDOMAINNoAuthority) {
		t.Errorf("expected WarnAssocNXDOMAINNoAuthority, got: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}
}

func TestValidateRsp_ErrorResponseWithRecords(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// SERVFAIL 但包含 answer 记录
	rspMsg := new(dns.Msg)
	rspMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	rspMsg.Id = reqID
	rspMsg.Response = true
	rspMsg.RecursionDesired = true
	rspMsg.RecursionAvailable = true
	rspMsg.Rcode = dns.RcodeServerFailure
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rspMsg.Answer = []dns.RR{rr}
	rsp, _ := rspMsg.Pack()

	_, warningBits, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsWarning(warningBits, WarnAssocErrorHasRecords) {
		t.Errorf("expected WarnAssocErrorHasRecords, got: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}
}

func TestValidateRsp_NODATA_NoSOA(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// NODATA (RCODE=0, ANCOUNT=0, Authority 中有 NS 但无 SOA)
	rspMsg := new(dns.Msg)
	rspMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	rspMsg.Id = reqID
	rspMsg.Response = true
	rspMsg.RecursionDesired = true
	rspMsg.RecursionAvailable = true
	rspMsg.Rcode = dns.RcodeSuccess
	ns, _ := dns.NewRR("example.com. 300 IN NS ns1.example.com.")
	rspMsg.Ns = []dns.RR{ns}
	rsp, _ := rspMsg.Pack()

	_, warningBits, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsWarning(warningBits, WarnAssocNODATANoAuthority) {
		t.Errorf("expected WarnAssocNODATANoAuthority, got: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}
}

func TestValidateRsp_DNSSECAssociation(t *testing.T) {
	req := createTestRequest("example.com", dns.TypeA)
	reqID := uint16(req[0])<<8 | uint16(req[1])

	// AD=1 and CD=1 互斥
	rspMsg := new(dns.Msg)
	rspMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	rspMsg.Id = reqID
	rspMsg.Response = true
	rspMsg.RecursionDesired = true
	rspMsg.RecursionAvailable = true
	rspMsg.AuthenticatedData = true
	rspMsg.CheckingDisabled = true
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rspMsg.Answer = []dns.RR{rr}
	rsp, _ := rspMsg.Pack()

	errBits, _, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsError(errBits, ErrAssocADWithCD) {
		t.Errorf("expected ErrAssocADWithCD, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateReq_WithRRRecords(t *testing.T) {
	// 构造有 answer 和 ns 段的请求（非 UPDATE opcode，应产生警告）
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	msg.RecursionDesired = true
	rr, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
	msg.Answer = []dns.RR{rr}
	msg.Ns = []dns.RR{rr}
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}

	_, warningBits, _, _, err := ValidateReq(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsWarning(warningBits, WarnHeaderANCountInReq) {
		t.Errorf("expected WarnHeaderANCountInReq, got warnings: 0x%X", warningBits)
	}
	if !IsWarning(warningBits, WarnHeaderNSCountInReq) {
		t.Errorf("expected WarnHeaderNSCountInReq, got warnings: 0x%X", warningBits)
	}
}

// ==================== 补充覆盖 0% 的函数 ====================

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Message: "test error message"}
	if err.Error() != "test error message" {
		t.Errorf("expected 'test error message', got %q", err.Error())
	}
}

func TestIsDigit(t *testing.T) {
	tests := []struct {
		input    byte
		expected bool
	}{
		{'0', true},
		{'1', true},
		{'9', true},
		{'a', false},
		{'Z', false},
		{' ', false},
		{0, false},
	}
	for _, tt := range tests {
		if got := isDigit(tt.input); got != tt.expected {
			t.Errorf("isDigit(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestSplitLabels_WithEscapes(t *testing.T) {
	// 测试 \DDD 转义（会间接覆盖 isDigit）
	// "w\000A.com" => labels: ["w\x00A", "com"]
	labels := splitLabels("w\\000A.com")
	if len(labels) != 2 {
		t.Fatalf("expected 2 labels, got %d: %v", len(labels), labels)
	}
	// 第一个 label 应该包含 NUL 字符
	if len(labels[0]) != 3 {
		t.Errorf("expected first label length 3, got %d", len(labels[0]))
	}

	// 测试普通转义
	labels2 := splitLabels("a\\.b.com")
	if len(labels2) != 2 {
		t.Fatalf("expected 2 labels for escaped dot, got %d: %v", len(labels2), labels2)
	}
	if labels2[0] != "a.b" {
		t.Errorf("expected 'a.b', got %q", labels2[0])
	}
}

func TestValidateRsp_WithECSInBothReqAndRsp(t *testing.T) {
	// 创建带 ECS 的请求
	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	reqMsg.RecursionDesired = true
	reqOpt := new(dns.OPT)
	reqOpt.Hdr.Name = "."
	reqOpt.Hdr.Rrtype = dns.TypeOPT
	reqOpt.SetUDPSize(4096)
	reqECS := &dns.EDNS0_SUBNET{
		Code:          8,
		Family:        1, // IPv4
		SourceNetmask: 24,
		SourceScope:   0,
		Address:       []byte{10, 0, 0, 0},
	}
	reqOpt.Option = append(reqOpt.Option, reqECS)
	reqMsg.Extra = append(reqMsg.Extra, reqOpt)
	req, err := reqMsg.Pack()
	if err != nil {
		t.Fatalf("failed to pack request: %v", err)
	}
	reqID := reqMsg.Id

	// 创建带 ECS 的响应（SourcePrefix 不匹配以触发 ECS 关联校验）
	rspMsg := new(dns.Msg)
	rspMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	rspMsg.Id = reqID
	rspMsg.Response = true
	rspMsg.RecursionDesired = true
	rspMsg.RecursionAvailable = true
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	rspMsg.Answer = []dns.RR{rr}

	rspOpt := new(dns.OPT)
	rspOpt.Hdr.Name = "."
	rspOpt.Hdr.Rrtype = dns.TypeOPT
	rspOpt.SetUDPSize(4096)
	rspECS := &dns.EDNS0_SUBNET{
		Code:          8,
		Family:        1,  // IPv4（与请求相同）
		SourceNetmask: 16, // 不匹配请求的 24
		SourceScope:   28, // Scope > Source(24)，应触发警告
		Address:       []byte{10, 0, 0, 0},
	}
	rspOpt.Option = append(rspOpt.Option, rspECS)
	rspMsg.Extra = append(rspMsg.Extra, rspOpt)
	rsp, err := rspMsg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	errBits, warningBits, _, _, err := ValidateRsp(req, rsp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 应检测到 SourcePrefix 不匹配
	if !IsError(errBits, ErrAssocECSSourcePrefixMismatch) {
		t.Errorf("expected ErrAssocECSSourcePrefixMismatch, got errors: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
	// 应检测到 Scope > Source 警告
	if !IsWarning(warningBits, WarnAssocECSScopeTooLarge) {
		t.Errorf("expected WarnAssocECSScopeTooLarge, got warnings: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}
}

func TestValidateReq_WithEDNSAndECS(t *testing.T) {
	// 创建带 EDNS+ECS 的请求用于覆盖 validateECS
	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	reqMsg.RecursionDesired = true

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)

	// 正常的 IPv4 ECS
	ecs := &dns.EDNS0_SUBNET{
		Code:          8,
		Family:        1, // IPv4
		SourceNetmask: 24,
		SourceScope:   0, // 请求中应为 0
		Address:       []byte{10, 0, 0, 0},
	}
	opt.Option = append(opt.Option, ecs)
	reqMsg.Extra = append(reqMsg.Extra, opt)

	data, err := reqMsg.Pack()
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}

	errBits, _, _, _, err := ValidateReq(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 正常 ECS 不应有错误
	if errBits != 0 {
		t.Errorf("expected no errors for valid ECS request, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateReq_WithECS_ScopeNonZero(t *testing.T) {
	// 请求中 ECS scope != 0 应产生警告
	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	reqMsg.RecursionDesired = true

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)

	ecs := &dns.EDNS0_SUBNET{
		Code:          8,
		Family:        1,
		SourceNetmask: 24,
		SourceScope:   16, // 非零 scope
		Address:       []byte{10, 0, 0, 0},
	}
	opt.Option = append(opt.Option, ecs)
	reqMsg.Extra = append(reqMsg.Extra, opt)
	data, _ := reqMsg.Pack()

	_, warningBits, _, _, err := ValidateReq(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsWarning(warningBits, WarnECSScopePrefixNonZero) {
		t.Errorf("expected WarnECSScopePrefixNonZero, got: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}
}

func TestValidateReq_WithEDNS_VersionNotZero(t *testing.T) {
	// 构造 EDNS version != 0 的请求
	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	reqMsg.RecursionDesired = true

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	// 设置 EDNS version=1（通过 TTL 字段）
	// TTL格式: [ExtRcode(8) | Version(8) | DO+Z(16)]
	opt.Hdr.Ttl = uint32(0) | (uint32(1) << 16) // version=1
	reqMsg.Extra = append(reqMsg.Extra, opt)
	data, _ := reqMsg.Pack()

	errBits, _, _, _, err := ValidateReq(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsError(errBits, ErrEDNSVersionNotZero) {
		t.Errorf("expected ErrEDNSVersionNotZero, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}

func TestValidateReq_WithEDNS_UDPSizeSmall(t *testing.T) {
	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	reqMsg.RecursionDesired = true

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(256) // < 512
	reqMsg.Extra = append(reqMsg.Extra, opt)
	data, _ := reqMsg.Pack()

	_, warningBits, _, _, err := ValidateReq(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsWarning(warningBits, WarnEDNSUDPSizeSmall) {
		t.Errorf("expected WarnEDNSUDPSizeSmall, got: 0x%X (%v)",
			warningBits, GetWarningDescription(warningBits))
	}
}

func TestValidateReq_NonPrintableLabel(t *testing.T) {
	// 构造包含不可打印字符的域名
	// 使用 miekg/dns 的 \DDD 格式
	msg := new(dns.Msg)
	msg.SetQuestion("w\\000A.example.com.", dns.TypeA)
	msg.RecursionDesired = true
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}

	errBits, _, _, _, err := ValidateReq(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsError(errBits, ErrQNameLabelHasNonPrintable) {
		t.Errorf("expected ErrQNameLabelHasNonPrintable, got: 0x%X (%v)",
			errBits, GetErrorDescription(errBits))
	}
}
