package app

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// WhitelistConfig 白名单配置结构
type WhitelistConfig struct {
	// Whitelist 白名单规则列表
	Whitelist []WhitelistRule `yaml:"whitelist"`
}

// WhitelistRule 单条白名单规则
type WhitelistRule struct {
	// DiffType 差异类型，如 ANSWER_RR_DIFF, AUTH_RR_DIFF 等
	DiffType string `yaml:"diff_type"`
	// Patterns 域名正则表达式列表，支持正则匹配
	Patterns []string `yaml:"patterns"`
	// Description 规则描述（可选）
	Description string `yaml:"description,omitempty"`
}

// WhitelistManager 白名单管理器
type WhitelistManager struct {
	config *WhitelistConfig
	// 预编译的正则规则：diffType -> compiled regex patterns
	regexRules map[string][]*regexp.Regexp
}

// NewWhitelistManager 创建白名单管理器
func NewWhitelistManager() *WhitelistManager {
	return &WhitelistManager{
		config:     &WhitelistConfig{},
		regexRules: make(map[string][]*regexp.Regexp),
	}
}

// LoadFromFile 从YAML文件加载白名单配置
func (wm *WhitelistManager) LoadFromFile(filename string) error {
	// 检查文件是否存在
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// 文件不存在，返回空配置（不报错）
		return nil
	}

	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read whitelist config file: %w", err)
	}

	// 解析YAML
	if err := yaml.Unmarshal(data, wm.config); err != nil {
		return fmt.Errorf("failed to parse whitelist config: %w", err)
	}

	// 构建正则规则
	wm.buildRegexRules()

	return nil
}

// buildRegexRules 构建预编译的正则规则
func (wm *WhitelistManager) buildRegexRules() {
	wm.regexRules = make(map[string][]*regexp.Regexp)

	for _, rule := range wm.config.Whitelist {
		diffType := strings.ToUpper(strings.TrimSpace(rule.DiffType))
		if diffType == "" {
			continue
		}

		// 编译正则表达式
		compiledPatterns := make([]*regexp.Regexp, 0, len(rule.Patterns))
		for _, pattern := range rule.Patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}

			// 编译正则表达式
			re, err := regexp.Compile(pattern)
			if err != nil {
				// 使用logrus记录警告信息到日志
				logrus.Warnf("invalid regex pattern '%s' for diff type '%s': %v", pattern, diffType, err)
				continue
			}
			compiledPatterns = append(compiledPatterns, re)
		}

		if len(compiledPatterns) > 0 {
			wm.regexRules[diffType] = append(wm.regexRules[diffType], compiledPatterns...)
		}
	}
}

// IsWhitelisted 检查指定的域名和差异类型是否在白名单中
// diffType: 差异类型字符串，如 "ANSWER_RR_DIFF"
// domain: 域名，如 "test.mig.db.example.com"
func (wm *WhitelistManager) IsWhitelisted(diffType string, domain string) bool {
	if len(wm.regexRules) == 0 {
		return false
	}

	diffType = strings.ToUpper(strings.TrimSpace(diffType))
	domain = strings.TrimSpace(domain)

	// 查找该差异类型的规则
	patterns, exists := wm.regexRules[diffType]
	if !exists {
		return false
	}

	// 检查是否匹配任一正则表达式
	for _, pattern := range patterns {
		if pattern.MatchString(domain) {
			return true
		}
	}

	return false
}

// GetRuleCount 获取规则数量
func (wm *WhitelistManager) GetRuleCount() int {
	return len(wm.config.Whitelist)
}

// GetDiffTypes 获取所有配置的差异类型
func (wm *WhitelistManager) GetDiffTypes() []string {
	types := make([]string, 0, len(wm.regexRules))
	for diffType := range wm.regexRules {
		types = append(types, diffType)
	}
	return types
}

// CreateExampleConfig 创建示例配置文件
func CreateExampleConfig(filename string) error {
	example := &WhitelistConfig{
		Whitelist: []WhitelistRule{
			{
				DiffType:    "ANSWER_RR_DIFF",
				Patterns:    []string{`.*\.mig\.db\.example\.com$`, `test\.example\.com$`},
				Description: "Ignore ANSWER_RR_DIFF for migration database domains",
			},
			{
				DiffType:    "AUTH_RR_DIFF",
				Patterns:    []string{`.*\.staging\.example\.com$`},
				Description: "Ignore AUTH_RR_DIFF for staging environment",
			},
			{
				DiffType:    "ANSWER_LEN_DIFF",
				Patterns:    []string{`.*\.cdn\.example\.com$`},
				Description: "Ignore ANSWER_LEN_DIFF for CDN domains",
			},
		},
	}

	data, err := yaml.Marshal(example)
	if err != nil {
		return fmt.Errorf("failed to marshal example config: %w", err)
	}

	// 确保目录存在
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write example config: %w", err)
	}

	return nil
}
