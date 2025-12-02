// Package statistics 统计信息
package statistics

import (
	"dnsdiff/internal/diff"
	"dnsdiff/pkg/utils"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// 统计信息
var stat = newDiffStat()

// DiffStat 对比统计
// total [DNSType][diffcode]cnt
// diff  [DNSType][zone][diffcode]cnt
// 符合预期的保存摘要 不符合预期的保存详情
type DiffStat struct {
	total     map[uint16]map[uint32]int
	diff      map[uint16]map[string]map[uint32]int
	staticmap map[string]int
	lock      sync.RWMutex
}

func init() {
	stat = newDiffStat()
}

// newDiffStat 初始化 DiffStat 结构体
func newDiffStat() *DiffStat {
	return &DiffStat{
		total:     make(map[uint16]map[uint32]int),
		diff:      make(map[uint16]map[string]map[uint32]int),
		staticmap: make(map[string]int),
	}
}

// GetStat 获取统计结构体指针
func GetStat() *DiffStat {
	return stat
}

// AddKV 添加一条统计记录
func AddKV(key string, value int) error {
	stat.lock.Lock()
	defer stat.lock.Unlock()
	stat.staticmap[key] = value
	return nil
}

// Add 添加一条diff统计记录
// 注意！ domain 一定不是原始的 byte 数组里面的那个 qname，是解码后的人可识别的域名
func (ds *DiffStat) Add(qtype uint16, domain string, diffcode, expMask uint32) {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	zone := utils.Domain2Zone(domain)
	diffcode &= expMask
	if diffcode != 0 {
		if _, ok := ds.diff[qtype]; !ok {
			ds.diff[qtype] = make(map[string]map[uint32]int)
		}
		if _, ok := ds.diff[qtype][zone]; !ok {
			ds.diff[qtype][zone] = make(map[uint32]int)
		}
		ds.diff[qtype][zone][diffcode]++
	}
	if _, ok := ds.total[qtype]; !ok {
		ds.total[qtype] = make(map[uint32]int)
	}

	ds.total[qtype][diffcode]++
}

// PrintSummary 打印 DiffStat 的统计表
func (ds *DiffStat) PrintSummary() {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	// Define column widths
	const (
		dnsTypeWidth  = 10
		diffCodeWidth = 10
		countWidth    = 10
	)
	fmt.Println("Total summary:")
	fmt.Printf("%v\n", ds.staticmap)
	fmt.Printf("%-*s\t%-*s\t\t%-*s\n", dnsTypeWidth, "DNS Type", diffCodeWidth, "Diff Code", countWidth, "Count")
	fmt.Printf("%-*s\t%-*s\t\t%-*s\n", dnsTypeWidth, "----------", diffCodeWidth, "-----------", countWidth, "-------")

	for dnsType, codeMap := range ds.total {
		for diffCode, count := range codeMap {
			fmt.Printf("%-*s\t0x%0*X\t\t%*d\n", dnsTypeWidth, dnsTypeToStr(dnsType), diffCodeWidth, diffCode, countWidth, count)
		}
	}
}

// PrintfDiffStat 打印 DiffStat 的统计表
func (ds *DiffStat) PrintfDiffStat() {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	now := time.Now()
	timeSuffix := now.Format("01021504")
	statFile := fmt.Sprintf("%s-%s.txt", "./diffstat", timeSuffix)
	statCsv := fmt.Sprintf("%s-%s.csv", "./diffstat", timeSuffix)

	// 打开文件用于写入
	file, err := os.OpenFile(statFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Failed to open file for writing: %v", err)
		return
	}
	csvFile, err := os.OpenFile(statCsv, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Failed to open file for writing: %v", err)
		return
	}
	defer file.Close()
	defer csvFile.Close()

	// 打印 Diff 到csv文件
	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	// 写入CSV表头
	csvHeader := []string{"DNS Type", "Zone", "Diff Code", "Diff desc", "Count"}
	if err := csvWriter.Write(csvHeader); err != nil {
		log.Printf("Failed to write CSV header: %v", err)
		return
	}
	// 写入 Diff 详情到 CSV
	for dnsType, zoneMap := range ds.diff {
		typeStr := dnsTypeToStr(dnsType)
		for zone, diffMap := range zoneMap {
			for diffCode, count := range diffMap {
				record := []string{
					typeStr,
					zone,
					fmt.Sprintf("0x%08X", diffCode), // 保持十六进制格式
					diff.DiffCode2Str(diffCode),
					strconv.FormatUint(uint64(count), 10),
				}
				if err := csvWriter.Write(record); err != nil {
					log.Printf("Failed to write CSV record: %v", err)
					continue
				}
			}
		}
	}
	// 定义列宽
	const (
		dnsTypeWidth  = 10
		zoneWidth     = 45
		diffCodeWidth = 10
		countWidth    = 10
	)
	// 打印总统计到文件
	fmt.Fprintln(file, "\nTotal summary:")
	fmt.Fprintf(file, "%v\n", ds.staticmap)
	fmt.Fprintf(file, "%-*s\t%-*s\t%-*s\n", dnsTypeWidth, "DNS Type", diffCodeWidth, "Diff Code", countWidth, "Count")
	fmt.Fprintf(file, "%-*s\t%-*s\t%-*s\n", dnsTypeWidth, "----------", diffCodeWidth, "-----------",
		countWidth, "-------")

	for dnsType, codeMap := range ds.total {
		for diffCode, count := range codeMap {
			fmt.Fprintf(file, "%-*s\t0x%0*X\t\t%*d\n", dnsTypeWidth, dnsTypeToStr(dnsType),
				diffCodeWidth, diffCode, countWidth, count)
		}
	}
}

// dnsTypeToStr 将 DNS 类型码转换为字符串表示
func dnsTypeToStr(dnsType uint16) string {
	if str, ok := dns.TypeToString[dnsType]; ok {
		return str
	}
	return strconv.Itoa(int(dnsType))
}
