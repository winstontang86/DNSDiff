package app

import (
	"dnsdiff/internal/diff"
	"fmt"
	"strconv"
	"strings"
)

// CompareConfig 对比配置
type CompareConfig struct {
	AllowPartialMatch  bool   // 是否允许部分匹配
	IgnoreAdditional   bool   // 是否忽略Additional段
	DiffUnexpectedMask uint32 // 预期差异掩码
}

// DefaultCompareConfig 返回默认对比配置
func DefaultCompareConfig() *CompareConfig {
	return &CompareConfig{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: diff.DefaultMask,
	}
}

// ParseHexMask 解析十六进制掩码字符串
func ParseHexMask(maskStr string) (uint32, error) {
	mask, err := strconv.ParseUint(strings.TrimPrefix(maskStr, "0x"), 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid hex format: %v", err)
	}
	return uint32(mask), nil
}

// ToComparator 转换为diff.Comparator
func (c *CompareConfig) ToComparator() diff.Comparator {
	return diff.Comparator{
		AllowPartialMatch:  c.AllowPartialMatch,
		IgnoreAdditional:   c.IgnoreAdditional,
		DiffUnexpectedMask: c.DiffUnexpectedMask,
	}
}
