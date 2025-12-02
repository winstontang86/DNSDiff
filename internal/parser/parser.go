// Package parser 解析pcap文件
package parser

import (
	"dnsdiff/internal/statistics"
	"dnsdiff/pkg/types"
	"dnsdiff/pkg/utils"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

// 注意！这里的包级全局变量没有带锁，设计上就是需要先进行解析再做其他操作，
// 如果场景变量，该用 sync.Map 或 sync.RWMutex 来实现，性能稍微差一点点
// 优化：移除固定大容量预分配，改为在函数内部动态分配，减少内存浪费
var (
	// 响应存储 map（延迟初始化）
	rspMap types.RspMap
	// 请求存储 slice（延迟初始化）
	reqArr []types.DNSReq
)

// Parse2Chan chan谁负责生产谁负责 close，所以这个函数会 close 掉 reqChan 和 rspChan
func Parse2Chan(pcapFile string, reqChan chan<- *types.DNSReq, rspChan chan<- *types.DNSRsp) error {
	rspCnt := 0
	reqCnt := 0

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		req, rsp, err := parseOne(&packet, &reqCnt, &rspCnt)
		if err != nil {
			logrus.Error(err)
			continue
		}
		if reqChan != nil && req != nil {
			reqChan <- req
		}
		if rspChan != nil && rsp != nil {
			rspChan <- rsp
		}
	}
	logrus.WithFields(logrus.Fields{
		"reqCnt": reqCnt,
		"rspCnt": rspCnt,
	}).Info("parse end")
	if reqChan != nil {
		close(reqChan)
	}
	if rspChan != nil {
		close(rspChan)
	}

	return nil
}

// ParseFile 从 pcap 文件中解析出 DNS 请求和响应
// 注意！ 次函数不能并行执行，而且建议在整个程序的前面阶段单独执行，否则有多协程并发问题
//
// 内存优化：
// 1. 根据文件大小动态估算初始容量
// 2. 使用合理的预分配避免频繁扩容
//
// NOCA:golint/fnsize(设计如此)
func ParseFile(pcapFile string, saveRsp bool) (*[]types.DNSReq, types.RspMap, error) {
	rspCnt := 0
	reqCnt := 0
	repeatCnt := 0

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return &reqArr, rspMap, err
	}
	defer handle.Close()

	// 内存优化：根据文件大小动态估算初始容量
	// 经验值：平均每个 DNS 包约 200-500 字节（含以太网帧）
	// 使用保守估计避免过度分配
	estimatedCapacity := estimateCapacity(pcapFile)

	// 初始化全局变量（使用估算容量）
	reqArr = make([]types.DNSReq, 0, estimatedCapacity)
	rspMap = make(types.RspMap, estimatedCapacity)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		networkLayer := packet.NetworkLayer()
		transportLayer := packet.TransportLayer()
		// 确保网络层和传输层存在
		if networkLayer == nil || transportLayer == nil {
			logrus.Error("Parse: Network or transport layer not found")
			continue
		}
		// 检查是否有 DNS 层
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dnsPacket, ok := dnsLayer.(*layers.DNS)
			if !ok {
				logrus.Error("Parse: Failed to get DNS layer")
				continue
			}
			srcIP, dstIP := networkLayer.NetworkFlow().Endpoints()
			srcPort, dstPort := transportLayer.TransportFlow().Endpoints()
			// 获取传输层协议
			isTcp := false
			if transportLayer.LayerType() == layers.LayerTypeTCP {
				isTcp = true
			}
			rawDnsData := dnsLayer.LayerContents()
			// 请求和响应分别处理
			if !dnsPacket.QR { // DNS Query
				// 将 DNS 请求的原始数据保存到 DNSReq 结构中
				req := types.DNSReq{
					ClientIP:   srcIP.String(),
					ClientPort: srcPort.String(),
					IsTCP:      isTcp,
					Time:       packet.Metadata().Timestamp,
					RawData:    rawDnsData,
				}
				reqArr = append(reqArr, req)
				reqCnt++
			} else { // DNS Response
				if !saveRsp {
					continue
				}
				// 用 dns 的原始二进制数据转换成 dns.Msg
				msg, err := types.BytesToDNSMsg(rawDnsData)
				if err != nil || msg == nil || len(msg.Question) == 0 {
					logrus.Error("Parse: Failed to trans DNS msg")
					continue
				}
				if len(dnsPacket.Questions) > 0 {
					rsp := &types.DNSRsp{
						ClientIP:   dstIP.String(),
						ClientPort: dstPort.String(),
						IsTCP:      isTcp,
						Time:       packet.Metadata().Timestamp,
						DnsData:    dnsPacket,
					}
					domain := msg.Question[0].Name
					key := utils.GenU64Key(msg.Question[0].Qclass, msg.Question[0].Qtype, msg.Id, msg.Opcode)
					if _, exists := rspMap[key]; !exists {
						rspMap[key] = make(map[string]*types.DNSRsp)
					}
					secdKey := utils.GenSecdKey(domain, rsp.ClientIP, rsp.ClientPort)
					logrus.Debugf("parseFile secdkey=%s", secdKey)
					if _, exists := rspMap[key][secdKey]; exists {
						logrus.WithFields(logrus.Fields{
							"id":     msg.Id,
							"type":   msg.Question[0].Qtype,
							"domain": domain,
						}).Warning("Parse: Same ID+Type+Qname rsp is existed. Overwrite!")
						repeatCnt++
					}
					rspMap[key][secdKey] = rsp
					rspCnt++
				} else {
					logrus.Error("Parse: DNS Question is empty")
				}
			}
		} else {
			logrus.Error("Parse: DNS layer not found")
		}
	}
	/*logrus.WithFields(logrus.Fields{
	"reqCnt": reqCnt, "reqLen": len(reqArr), "rspCnt": rspCnt, "rspLen": len(rspMap)}).Info("parse end")*/
	statistics.AddKV(pcapFile+" reqCnt", reqCnt)
	statistics.AddKV(pcapFile+" rspCnt", rspCnt)
	statistics.AddKV(pcapFile+" reqLen", len(reqArr))
	statistics.AddKV(pcapFile+" rspLen(first key)", len(rspMap))
	statistics.AddKV(pcapFile+" repeatCnt", repeatCnt)
	return &reqArr, rspMap, nil
}

func parseOne(packet *gopacket.Packet, reqCnt, rspCnt *int) (*types.DNSReq, *types.DNSRsp, error) {
	var req *types.DNSReq
	var rsp *types.DNSRsp
	networkLayer := (*packet).NetworkLayer()
	transportLayer := (*packet).TransportLayer()
	// 确保网络层和传输层存在
	if networkLayer == nil || transportLayer == nil {
		return nil, nil, fmt.Errorf("parse: network or transport layer not found")
	}
	// 检查是否有 DNS 层
	if dnsLayer := (*packet).Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dnsPacket, ok := dnsLayer.(*layers.DNS)
		if !ok {
			return nil, nil, fmt.Errorf("parse: failed to get DNS layer")
		}
		srcIP, dstIP := networkLayer.NetworkFlow().Endpoints()
		srcPort, dstPort := transportLayer.TransportFlow().Endpoints()
		// 获取传输层协议
		isTcp := false
		if transportLayer.LayerType() == layers.LayerTypeTCP {
			isTcp = true
		}

		// 请求和响应分别处理
		if !dnsPacket.QR { // DNS Query
			rawDnsData := dnsLayer.LayerContents()
			// 将 DNS 请求的原始数据保存到 DNSReq 结构中
			req = &types.DNSReq{
				ClientIP:   srcIP.String(),
				ClientPort: srcPort.String(),
				IsTCP:      isTcp,
				Time:       (*packet).Metadata().Timestamp,
				RawData:    rawDnsData,
			}
			(*reqCnt)++
		} else { // DNS Response

			if len(dnsPacket.Questions) > 0 {
				rsp = &types.DNSRsp{
					ClientIP:   dstIP.String(),
					ClientPort: dstPort.String(),
					IsTCP:      isTcp,
					Time:       (*packet).Metadata().Timestamp,
					DnsData:    dnsPacket,
				}
				(*rspCnt)++
			} else {
				return nil, nil, fmt.Errorf("parse: DNS Question is empty")
			}
		}
	} else {
		return nil, nil, fmt.Errorf("parse: DNS layer not found")
	}
	return req, rsp, nil
}

// estimateCapacity 根据文件大小估算初始容量
// 返回合理的初始容量，避免过度分配或频繁扩容
func estimateCapacity(pcapFile string) int {
	const (
		minCapacity    = 1024       // 最小容量
		maxCapacity    = 1024 * 100 // 最大初始容量（10万）
		avgPacketSize  = 400        // 平均每个 DNS 包大小（字节，含以太网帧）
		dnsPacketRatio = 0.8        // DNS 包占总包的比例（保守估计）
	)

	// 使用 os.Stat 获取文件大小
	var fileSize int64
	if stat, err := os.Stat(pcapFile); err == nil {
		fileSize = stat.Size()
	}

	if fileSize <= 0 {
		// 如果无法获取文件大小，返回中等容量
		return minCapacity * 10 // 10240
	}

	// 估算 DNS 包数量
	estimatedPackets := int(float64(fileSize) / avgPacketSize * dnsPacketRatio)

	// 限制在合理范围内
	if estimatedPackets < minCapacity {
		return minCapacity
	}
	if estimatedPackets > maxCapacity {
		return maxCapacity
	}

	return estimatedPackets
}
