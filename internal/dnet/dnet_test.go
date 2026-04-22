package dnet

import (
	"dnsdiff/pkg/types"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// mockUDPServer 启动一个简单的 UDP 服务器，回显收到的数据
func mockUDPServer(t *testing.T) (string, func()) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			// Echo back
			conn.WriteTo(buf[:n], addr)
		}
	}()

	if conn == nil {
		t.Fatalf("failed to listen udp: conn is nil")
	}
	localAddr := conn.LocalAddr()
	if localAddr == nil {
		t.Fatalf("failed to listen udp: local addr is nil")
	}
	_, port, _ := net.SplitHostPort(localAddr.String())
	return port, func() { conn.Close() }
}

// mockTCPServer 启动一个简单的 TCP 服务器，回显收到的数据（处理长度前缀）
func mockTCPServer(t *testing.T) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen tcp: %v", err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read length prefix
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				length := binary.BigEndian.Uint16(lenBuf)

				// Read data
				data := make([]byte, length)
				if _, err := io.ReadFull(c, data); err != nil {
					return
				}

				// Echo back with length prefix
				c.Write(lenBuf)
				c.Write(data)
			}(conn)
		}
	}()

	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port, func() { l.Close() }
}

func TestSendAndRecvUDP(t *testing.T) {
	port, closeFunc := mockUDPServer(t)
	defer closeFunc()

	// Save original port and restore after test
	originalPort := DNS_PORT
	DNS_PORT = port
	defer func() { DNS_PORT = originalPort }()

	reqData := []byte("test-udp-data")
	req := &types.DNSReq{
		ClientIP:   "127.0.0.1",
		ClientPort: "12345",
		IsTCP:      false,
		RawData:    reqData,
	}

	rsp, err := SendAndRecv(req, "127.0.0.1")
	if err != nil {
		t.Fatalf("SendAndRecv UDP failed: %v", err)
	}

	if string(rsp.RawData) != string(reqData) {
		t.Errorf("expected response %s, got %s", string(reqData), string(rsp.RawData))
	}
	if rsp.IsTCP {
		t.Error("expected IsTCP to be false")
	}
}

func TestSendAndRecvTCP(t *testing.T) {
	port, closeFunc := mockTCPServer(t)
	defer closeFunc()

	// Save original port and restore after test
	originalPort := DNS_PORT
	DNS_PORT = port
	defer func() { DNS_PORT = originalPort }()

	reqData := []byte("test-tcp-data")
	req := &types.DNSReq{
		ClientIP:   "127.0.0.1",
		ClientPort: "12345",
		IsTCP:      true,
		RawData:    reqData,
	}

	rsp, err := SendAndRecv(req, "127.0.0.1")
	if err != nil {
		t.Fatalf("SendAndRecv TCP failed: %v", err)
	}

	if string(rsp.RawData) != string(reqData) {
		t.Errorf("expected response %s, got %s", string(reqData), string(rsp.RawData))
	}
	if !rsp.IsTCP {
		t.Error("expected IsTCP to be true")
	}
}

func TestSendAndRecvError(t *testing.T) {
	// Test connection error
	originalPort := DNS_PORT
	DNS_PORT = "0" // Invalid port or closed port
	defer func() { DNS_PORT = originalPort }()

	req := &types.DNSReq{
		IsTCP:   false,
		RawData: []byte("test"),
	}

	// Should fail because port 0 is usually invalid or not listening
	// Note: Dialing UDP to localhost usually succeeds even if no one is listening,
	// but Read will timeout.
	// Let's set a very short timeout for this test if possible, but dnet has hardcoded 5s timeout.
	// So we might just test TCP connection error which is immediate.

	req.IsTCP = true
	_, err := SendAndRecv(req, "127.0.0.1")
	if err == nil {
		t.Error("expected error for TCP connection to closed port, got nil")
	}
}
