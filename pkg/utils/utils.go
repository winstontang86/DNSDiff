// Package utils 提供DNS处理相关的工具函数
package utils

import (
	"dnsdiff/pkg/types"
	"fmt"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/sirupsen/logrus"
)

// Hash64 使用 XXHash 算法计算 hash 值
func Hash64(data []byte) uint64 {
	return xxhash.Sum64(data)
}

// GenU64Key qclass+opcode+dnsid+qtype组合成 uint64 的 key
func GenU64Key(qclass, qtype, dnsID uint16, opcode int) uint64 {
	key := uint64(qclass)<<48 | uint64(opcode)<<32 | uint64(qtype)<<16 | uint64(dnsID)
	return key
}

// GenSecdKey 生成二级缓存的key
func GenSecdKey(qname, clientip, clientport string) string {
	if types.UseClientInfo {
		return qname + "*" + clientip + ":" + clientport
	}
	return qname
}

// Domain2Zone 将域名转换为对应的zone
func Domain2Zone(domain string) string {
	// 去除末尾的点号（如果存在）
	domain = strings.TrimSuffix(domain, ".")

	// 切分
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return domain
	}

	labelCnt := len(parts)
	if labelCnt < 3 {
		return domain
	}

	// 默认三级，如果长度太长就改成两级
	zone := parts[labelCnt-3] + "." + parts[labelCnt-2] + "." + parts[labelCnt-1]
	if len(zone) > 30 {
		zone = parts[labelCnt-2] + "." + parts[labelCnt-1]
	}
	return zone
}

// Find4diff 查找一个dns响应报文对应的用于对比的响应报文
func Find4diff(newRsp *types.DNSRsp, rspmap types.RspMap) (*types.DNSRsp, error) {
	var originRsp *types.DNSRsp
	if newRsp == nil {
		return originRsp, nil
	}
	newMsg, err := types.DNSRspToMsg(newRsp)
	if err != nil || newMsg == nil || len(newMsg.Question) == 0 {
		return originRsp, err
	}
	logrus.WithFields(logrus.Fields{
		"dnsid":  newMsg.Id,
		"domain": newMsg.Question[0].Name,
	}).Debug("Find4diff: starting compare")

	// 从m 中找到对应的回应报文，如果查找不到返回错误码
	domain := newMsg.Question[0].Name
	key := GenU64Key(newMsg.Question[0].Qclass, newMsg.Question[0].Qtype, newMsg.Id, newMsg.Opcode)
	secdMap, ok := rspmap[key]
	if !ok {
		err := fmt.Errorf("Find4diff: no such first key=%d", key)
		return originRsp, err
	}
	secdKey := GenSecdKey(domain, newRsp.ClientIP, newRsp.ClientPort)
	originRsp, ok = secdMap[secdKey]
	if !ok {
		err := fmt.Errorf("Find4diff: no such secdkey=%s", secdKey)
		return originRsp, err
	}

	return originRsp, nil
}
