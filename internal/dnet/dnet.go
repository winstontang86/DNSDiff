// Package dnet 封装dns请求
package dnet

import (
	"dnsdiff/pkg/types"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	DNS_PORT = "53"
)

// SendAndRecv 发送 DNS 请求并接收响应
func SendAndRecv(req *types.DNSReq, targetIP string) (*types.DNSRsp, error) {
	var response []byte
	var err error
	// 根据请求的协议类型发送请求和接收结果
	if req.IsTCP {
		response, err = sendAndRecvTCP(req, targetIP)
	} else {
		response, err = sendAndRecvUDP(req, targetIP)
	}
	if err != nil {
		return nil, err
	}

	return &types.DNSRsp{
		ClientIP:   req.ClientIP,
		ClientPort: req.ClientPort,
		IsTCP:      req.IsTCP,
		Time:       time.Now(),
		RawData:    response,
		Req:        req,
	}, nil
}

// sendAndRecvUDP 使用 UDP 协议发送 DNS 请求并接收响应
func sendAndRecvUDP(req *types.DNSReq, targetIP string) ([]byte, error) {
	addr := net.JoinHostPort(targetIP, DNS_PORT)
	conn, err := net.DialTimeout("udp", addr, 5*time.Second) // 设置连接超时时间
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(req.RawData)
	if err != nil {
		return nil, fmt.Errorf("failed to send UDP data: %v", err)
	}

	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 设置读取超时时间
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to receive UDP data: %v", err)
	}

	return buffer[:n], nil
}

// sendAndRecvTCP 使用 TCP 协议发送 DNS 请求并接收响应
func sendAndRecvTCP(req *types.DNSReq, targetIP string) ([]byte, error) {
	addr := net.JoinHostPort(targetIP, DNS_PORT)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second) // 设置连接超时时间
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %v", err)
	}
	defer conn.Close()

	// 设置读取超时时间，防止服务器不响应导致永久阻塞
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 发送数据长度前缀
	dataLen := len(req.RawData)
	dataLenBytes := []byte{byte(dataLen >> 8), byte(dataLen & 0xff)}
	if _, err := conn.Write(dataLenBytes); err != nil {
		return nil, fmt.Errorf("failed to send TCP length: %v", err)
	}

	// 发送原始数据
	if _, err := conn.Write(req.RawData); err != nil {
		return nil, fmt.Errorf("failed to send TCP data: %v", err)
	}

	// 读取响应长度前缀
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read response length: %v", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// 读取完整响应数据
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return nil, fmt.Errorf("failed to read response data: %v", err)
	}

	return respData, nil
}
