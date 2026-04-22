package parser

import (
	"dnsdiff/pkg/types"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/miekg/dns"
)

func TestEstimateCapacity(t *testing.T) {
	tests := []struct {
		name        string
		fileSize    int64
		expectedMin int
		expectedMax int
	}{
		{
			name:        "small file",
			fileSize:    1024,
			expectedMin: 1024,
			expectedMax: 10240,
		},
		{
			name:        "medium file",
			fileSize:    100 * 1024,
			expectedMin: 1024,
			expectedMax: 102400,
		},
		{
			name:        "large file",
			fileSize:    10 * 1024 * 1024,
			expectedMin: 10240,
			expectedMax: 102400,
		},
		{
			name:        "very large file",
			fileSize:    100 * 1024 * 1024,
			expectedMin: 10240,
			expectedMax: 102400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file with specified size
			tempDir := t.TempDir()
			testFile := filepath.Join(tempDir, "test.pcap")

			f, err := os.Create(testFile)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Write dummy data to reach desired size
			if tt.fileSize > 0 {
				data := make([]byte, tt.fileSize)
				f.Write(data)
			}
			f.Close()

			capacity := estimateCapacity(testFile)

			if capacity < tt.expectedMin {
				t.Errorf("Capacity %d is less than expected minimum %d", capacity, tt.expectedMin)
			}

			if capacity > tt.expectedMax {
				t.Errorf("Capacity %d is greater than expected maximum %d", capacity, tt.expectedMax)
			}
		})
	}
}

func TestEstimateCapacity_NonExistentFile(t *testing.T) {
	capacity := estimateCapacity("/nonexistent/file.pcap")

	// Should return a reasonable default
	if capacity < 1024 || capacity > 102400 {
		t.Errorf("Expected capacity in range [1024, 102400], got %d", capacity)
	}
}

func TestParseFile_InvalidFile(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{
			name:    "non-existent file",
			file:    "/nonexistent/file.pcap",
			wantErr: true,
		},
		{
			name:    "empty path",
			file:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqArr, rspMap, err := ParseFile(tt.file, true)

			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}

			// When there's an error, reqArr and rspMap may be nil
			if !tt.wantErr {
				if reqArr == nil {
					t.Error("Expected non-nil reqArr")
				}

				if rspMap == nil {
					t.Error("Expected non-nil rspMap")
				}
			}
		})
	}
}

func TestParseFile_EmptyPcap(t *testing.T) {
	// Create an empty but valid pcap file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "empty.pcap")

	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Write pcap header
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("Failed to write pcap header: %v", err)
	}
	f.Close()

	// Parse the empty pcap
	reqArr, rspMap, err := ParseFile(testFile, true)
	if err != nil {
		t.Errorf("ParseFile returned error: %v", err)
	}

	if reqArr == nil {
		t.Error("Expected non-nil reqArr")
	}

	if rspMap == nil {
		t.Error("Expected non-nil rspMap")
	}

	if len(*reqArr) != 0 {
		t.Errorf("Expected empty reqArr, got %d entries", len(*reqArr))
	}

	if len(rspMap) != 0 {
		t.Errorf("Expected empty rspMap, got %d entries", len(rspMap))
	}
}

func TestParseFile_WithDNSPackets(t *testing.T) {
	// Create a pcap file with DNS packets
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "dns.pcap")

	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("Failed to write pcap header: %v", err)
	}

	// Create DNS query packet
	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion("example.com.", dns.TypeA)
	queryData, _ := queryMsg.Pack()
	// Create layers for query
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{61, 251, 7, 8},
		DstIP:    []byte{8, 8, 8, 8},
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Serialize query packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(queryData))

	// Write query packet
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buf.Bytes()),
		Length:        len(buf.Bytes()),
	}
	w.WritePacket(ci, buf.Bytes())

	// Create DNS response packet
	respMsg := new(dns.Msg)
	respMsg.SetReply(queryMsg)
	respMsg.Answer = append(respMsg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{61, 251, 7, 8},
	})
	respData, _ := respMsg.Pack()

	// Create layers for response
	ip2 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{8, 8, 8, 8},
		DstIP:    []byte{61, 251, 7, 8},
	}
	udp2 := &layers.UDP{
		SrcPort: 53,
		DstPort: 12345,
	}
	udp2.SetNetworkLayerForChecksum(ip2)

	// Serialize response packet
	buf2 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf2, opts, eth, ip2, udp2, gopacket.Payload(respData))

	// Write response packet
	ci2 := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buf2.Bytes()),
		Length:        len(buf2.Bytes()),
	}
	w.WritePacket(ci2, buf2.Bytes())

	f.Close()

	// Parse the pcap file
	reqArr, rspMap, err := ParseFile(testFile, true)
	if err != nil {
		t.Errorf("ParseFile returned error: %v", err)
	}

	if reqArr == nil {
		t.Fatal("Expected non-nil reqArr")
	}

	if rspMap == nil {
		t.Fatal("Expected non-nil rspMap")
	}

	if len(*reqArr) == 0 {
		t.Error("Expected at least one request")
	}

	if len(rspMap) == 0 {
		t.Error("Expected at least one response")
	}
}

func TestParseFile_SaveRspFalse(t *testing.T) {
	// Create a simple pcap with DNS response
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.pcap")

	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	f.Close()

	// Parse with saveRsp = false
	reqArr, rspMap, err := ParseFile(testFile, false)
	if err != nil {
		t.Errorf("ParseFile returned error: %v", err)
	}

	if reqArr == nil {
		t.Error("Expected non-nil reqArr")
	}

	if rspMap == nil {
		t.Error("Expected non-nil rspMap")
	}

	// Response map should be empty when saveRsp is false
	if len(rspMap) != 0 {
		t.Errorf("Expected empty rspMap when saveRsp=false, got %d entries", len(rspMap))
	}
}

func TestParseRaw2Chan(t *testing.T) {
	// Create a pcap file with DNS packets
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "raw_dns.pcap")

	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("Failed to write pcap header: %v", err)
	}

	// 1. Create DNS query packet (QR=0)
	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion("example.com.", dns.TypeA)
	queryData, _ := queryMsg.Pack()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{8, 8, 8, 8},
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(queryData))
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes())

	// 2. Create DNS response packet (QR=1)
	respMsg := new(dns.Msg)
	respMsg.SetReply(queryMsg)
	respData, _ := respMsg.Pack()

	ip2 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{8, 8, 8, 8},
		DstIP:    []byte{10, 0, 0, 1},
	}
	udp2 := &layers.UDP{
		SrcPort: 53,
		DstPort: 12345,
	}
	udp2.SetNetworkLayerForChecksum(ip2)

	buf2 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf2, opts, eth, ip2, udp2, gopacket.Payload(respData))
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buf2.Bytes()), Length: len(buf2.Bytes())}, buf2.Bytes())

	// 3. Create short packet (< 6 bytes payload) -> Should be treated as Req
	shortData := []byte{0x00, 0x01, 0x00} // 3 bytes
	buf3 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf3, opts, eth, ip, udp, gopacket.Payload(shortData))
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buf3.Bytes()), Length: len(buf3.Bytes())}, buf3.Bytes())

	f.Close()

	// Test ParseRaw2Chan
	reqChan := make(chan *types.DNSReq, 10)
	rspChan := make(chan *types.DNSRsp, 10)

	go func() {
		err := ParseRaw2Chan(testFile, reqChan, rspChan)
		if err != nil {
			t.Errorf("ParseRaw2Chan returned error: %v", err)
		}
	}()

	reqCount := 0
	rspCount := 0

	for {
		select {
		case req, ok := <-reqChan:
			if !ok {
				reqChan = nil
			} else if req != nil {
				reqCount++
			}
		case rsp, ok := <-rspChan:
			if !ok {
				rspChan = nil
			} else if rsp != nil {
				rspCount++
				if len(rsp.RawData) == 0 {
					t.Error("Expected non-empty RawData in response")
				}
				if rsp.Req != nil {
					t.Error("Expected nil Req in response")
				}
			}
		}
		if reqChan == nil && rspChan == nil {
			break
		}
	}

	// Expected: 1 normal query + 1 short packet (treated as query) = 2 Reqs
	//           1 normal response = 1 Rsp
	if reqCount != 2 {
		t.Errorf("Expected 2 requests, got %d", reqCount)
	}
	if rspCount != 1 {
		t.Errorf("Expected 1 response, got %d", rspCount)
	}
}

func TestParseRaw2Chan_NilChannels(t *testing.T) {
	// Create a simple pcap file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.pcap")

	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	f.Close()

	// Test with nil channels (should not panic)
	err = ParseRaw2Chan(testFile, nil, nil)
	if err != nil {
		t.Errorf("ParseRaw2Chan with nil channels returned error: %v", err)
	}
}

func TestParseRaw2Chan_InvalidFile(t *testing.T) {
	reqChan := make(chan *types.DNSReq, 10)
	rspChan := make(chan *types.DNSRsp, 10)

	err := ParseRaw2Chan("/nonexistent/file.pcap", reqChan, rspChan)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestParseOne(t *testing.T) {
	// Create a DNS query packet
	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion("example.com.", dns.TypeA)
	_, _ = queryMsg.Pack()

	// Create packet layers
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{61, 251, 7, 8},
		DstIP:    []byte{8, 8, 8, 8},
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Create DNS layer
	dnsLayer := &layers.DNS{
		ID:      queryMsg.Id,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp, dnsLayer)

	// Parse packet
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	reqCnt := 0
	rspCnt := 0

	req, rsp, err := parseOne(packet, &reqCnt, &rspCnt)

	if err != nil {
		t.Errorf("parseOne returned error: %v", err)
	}

	if req == nil {
		t.Error("Expected non-nil request")
	}

	if rsp != nil {
		t.Error("Expected nil response for query packet")
	}

	if reqCnt != 1 {
		t.Errorf("Expected reqCnt=1, got %d", reqCnt)
	}

	if rspCnt != 0 {
		t.Errorf("Expected rspCnt=0, got %d", rspCnt)
	}
}

func BenchmarkEstimateCapacity(b *testing.B) {
	tempDir := b.TempDir()
	testFile := filepath.Join(tempDir, "bench.pcap")

	f, _ := os.Create(testFile)
	data := make([]byte, 1024*1024) // 1MB file
	f.Write(data)
	f.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = estimateCapacity(testFile)
	}
}

func BenchmarkParseFile(b *testing.B) {
	// Create a test pcap file
	tempDir := b.TempDir()
	testFile := filepath.Join(tempDir, "bench.pcap")

	f, _ := os.Create(testFile)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	f.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseFile(testFile, true)
	}
}
