package main

import (
	"dnsdiff/internal/validate"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"sync"
)

// CheckStats 维护校验统计信息
type CheckStats struct {
	mu            sync.Mutex
	TotalPackets  int64
	ErrorCounts   map[uint64]int64
	WarningCounts map[uint64]int64
}

// NewCheckStats 创建新的统计对象
func NewCheckStats() *CheckStats {
	return &CheckStats{
		ErrorCounts:   make(map[uint64]int64),
		WarningCounts: make(map[uint64]int64),
	}
}

// Record 记录一次校验结果
func (s *CheckStats) Record(errBits, warnBits uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalPackets++

	// 统计错误位
	for i := 0; i < 64; i++ {
		bit := uint64(1) << i
		if errBits&bit != 0 {
			s.ErrorCounts[bit]++
		}
	}

	// 统计警告位
	for i := 0; i < 64; i++ {
		bit := uint64(1) << i
		if warnBits&bit != 0 {
			s.WarningCounts[bit]++
		}
	}
}

// SaveCSV 将统计结果保存到 CSV 文件
func (s *CheckStats) SaveCSV(filename string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	if err := writer.Write([]string{"Type", "BitName", "Count", "Description"}); err != nil {
		return err
	}

	// 辅助结构用于排序
	type record struct {
		Type  string
		Bit   uint64
		Name  string
		Count int64
		Desc  string // 暂时没有描述映射，留空或填名称
	}
	var records []record

	// 收集错误统计
	for bit, count := range s.ErrorCounts {
		name, ok := validate.ErrorBitNames[bit]
		if !ok {
			name = fmt.Sprintf("UnknownErrorBit(0x%x)", bit)
		}
		records = append(records, record{
			Type:  "Error",
			Bit:   bit,
			Name:  name,
			Count: count,
		})
	}

	// 收集警告统计
	for bit, count := range s.WarningCounts {
		name, ok := validate.WarningBitNames[bit]
		if !ok {
			name = fmt.Sprintf("UnknownWarningBit(0x%x)", bit)
		}
		records = append(records, record{
			Type:  "Warning",
			Bit:   bit,
			Name:  name,
			Count: count,
		})
	}

	// 排序：先按类型（Error在前），再按 Bit 值从小到大
	sort.Slice(records, func(i, j int) bool {
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type // Error < Warning
		}
		return records[i].Bit < records[j].Bit
	})

	// 写入数据
	for _, r := range records {
		if err := writer.Write([]string{r.Type, r.Name, fmt.Sprintf("%d", r.Count), r.Desc}); err != nil {
			return err
		}
	}

	return nil
}
