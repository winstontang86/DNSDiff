package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWhitelistManager_LoadFromFile(t *testing.T) {
	// 创建临时配置文件
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_whitelist.yaml")

	configContent := `whitelist:
  - diff_type: ANSWER_RR_DIFF
    patterns:
      - ".*\\.mig\\.db\\.example\\.com$"
      - "^test\\.example\\.com$"
    description: "Test rule 1"
  - diff_type: AUTH_RR_DIFF
    patterns:
      - ".*\\.staging\\.example\\.com$"
    description: "Test rule 2"
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// 测试加载配置
	wm := NewWhitelistManager()
	err = wm.LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// 验证规则数量
	if wm.GetRuleCount() != 2 {
		t.Errorf("Expected 2 rules, got %d", wm.GetRuleCount())
	}

	// 验证差异类型
	diffTypes := wm.GetDiffTypes()
	if len(diffTypes) != 2 {
		t.Errorf("Expected 2 diff types, got %d", len(diffTypes))
	}
}

func TestWhitelistManager_IsWhitelisted(t *testing.T) {
	// 创建临时配置文件
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_whitelist.yaml")

	configContent := `whitelist:
  - diff_type: ANSWER_RR_DIFF
    patterns:
      - ".*\\.mig\\.db\\.example\\.com$"
      - "^test\\.example\\.com$"
  - diff_type: AUTH_RR_DIFF
    patterns:
      - ".*\\.staging\\.example\\.com$"
      - "(?i).*\\.test\\..*"
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	wm := NewWhitelistManager()
	err = wm.LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name     string
		diffType string
		domain   string
		expected bool
	}{
		// 正则匹配测试 - 迁移数据库域名
		{
			name:     "Regex match - mig.db subdomain",
			diffType: "ANSWER_RR_DIFF",
			domain:   "server1.mig.db.example.com",
			expected: true,
		},
		{
			name:     "Regex match - another mig.db subdomain",
			diffType: "ANSWER_RR_DIFF",
			domain:   "api.mig.db.example.com",
			expected: true,
		},
		{
			name:     "Regex no match - base mig.db domain",
			diffType: "ANSWER_RR_DIFF",
			domain:   "mig.db.example.com",
			expected: false, // 正则要求以.mig.db.example.com结尾
		},
		// 精确匹配测试
		{
			name:     "Exact match",
			diffType: "ANSWER_RR_DIFF",
			domain:   "test.example.com",
			expected: true,
		},
		{
			name:     "Exact no match",
			diffType: "ANSWER_RR_DIFF",
			domain:   "test2.example.com",
			expected: false,
		},
		// 测试环境匹配
		{
			name:     "Staging domain match",
			diffType: "AUTH_RR_DIFF",
			domain:   "api.staging.example.com",
			expected: true,
		},
		// 大小写不敏感测试
		{
			name:     "Case insensitive match",
			diffType: "AUTH_RR_DIFF",
			domain:   "API.TEST.example.com",
			expected: true,
		},
		// 差异类型测试
		{
			name:     "Different diff type - match",
			diffType: "AUTH_RR_DIFF",
			domain:   "dev.staging.example.com",
			expected: true,
		},
		{
			name:     "Different diff type - no match",
			diffType: "AUTH_RR_DIFF",
			domain:   "dev.production.example.com",
			expected: false,
		},
		// 不存在的差异类型
		{
			name:     "Non-existent diff type",
			diffType: "NONEXISTENT_DIFF",
			domain:   "test.example.com",
			expected: false,
		},
		// 大小写测试
		{
			name:     "Case insensitive - diff type",
			diffType: "answer_rr_diff",
			domain:   "test.example.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wm.IsWhitelisted(tt.diffType, tt.domain)
			if result != tt.expected {
				t.Errorf("IsWhitelisted(%q, %q) = %v, expected %v",
					tt.diffType, tt.domain, result, tt.expected)
			}
		})
	}
}

func TestWhitelistManager_LoadFromFile_NotExist(t *testing.T) {
	wm := NewWhitelistManager()
	err := wm.LoadFromFile("nonexistent_file.yaml")
	// 文件不存在应该返回nil（不报错）
	if err != nil {
		t.Errorf("Expected no error for non-existent file, got: %v", err)
	}
}

func TestWhitelistManager_LoadFromFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.yaml")

	invalidContent := `whitelist:
  - diff_type: ANSWER_RR_DIFF
    patterns:
      - ".*\\.mig\\.db\\.example\\.com$"
    invalid_field: [unclosed bracket
`

	err := os.WriteFile(configFile, []byte(invalidContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	wm := NewWhitelistManager()
	err = wm.LoadFromFile(configFile)
	// 无效的YAML应该返回错误
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

func TestWhitelistManager_LoadFromFile_InvalidRegex(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid_regex.yaml")

	invalidContent := `whitelist:
  - diff_type: ANSWER_RR_DIFF
    patterns:
      - ".*\\.mig\\.db\\.example\\.com$"  # valid
      - "[invalid regex"                 # invalid regex
      - "^test\\.example\\.com$"          # valid
`

	err := os.WriteFile(configFile, []byte(invalidContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	wm := NewWhitelistManager()
	err = wm.LoadFromFile(configFile)
	// 应该成功加载，但跳过无效的正则表达式
	if err != nil {
		t.Errorf("Expected success with invalid regex warning, got error: %v", err)
	}

	// 应该只加载有效的正则表达式
	if wm.GetRuleCount() != 1 {
		t.Errorf("Expected 1 rule, got %d", wm.GetRuleCount())
	}
}

func TestCreateExampleConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "example.yaml")

	err := CreateExampleConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to create example config: %v", err)
	}

	// 验证文件存在
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		t.Error("Example config file was not created")
	}

	// 验证可以加载
	wm := NewWhitelistManager()
	err = wm.LoadFromFile(configFile)
	if err != nil {
		t.Errorf("Failed to load example config: %v", err)
	}

	// 验证有规则
	if wm.GetRuleCount() == 0 {
		t.Error("Example config has no rules")
	}
}

func TestWhitelistManager_ComplexRegexPatterns(t *testing.T) {
	// 创建临时配置文件
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "complex_regex.yaml")

	configContent := `whitelist:
  - diff_type: ANSWER_RR_DIFF
    patterns:
      - ".*\\.(staging|test)\\..*"           # 包含staging或test
      - ".*v[0-9]+\\..*"                    # 版本号模式
      - "(?i).*cdn.*\\..*"                  # 大小写不敏感CDN
      - "^api-[a-z]+-[0-9]+\\..*"           # API服务名模式
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	wm := NewWhitelistManager()
	err = wm.LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "Staging domain",
			domain:   "app.staging.example.com",
			expected: true,
		},
		{
			name:     "Test domain",
			domain:   "api.test.example.com",
			expected: true,
		},
		{
			name:     "Version domain",
			domain:   "service.v2.example.com",
			expected: true,
		},
		{
			name:     "Version with patch",
			domain:   "service.v2.1.example.com",
			expected: true,
		},
		{
			name:     "CDN domain lowercase",
			domain:   "content.cdn.example.com",
			expected: true,
		},
		{
			name:     "CDN domain uppercase",
			domain:   "content.CDN.example.com",
			expected: true,
		},
		{
			name:     "API service pattern",
			domain:   "api-users-123.example.com",
			expected: true,
		},
		{
			name:     "No match - production",
			domain:   "app.production.example.com",
			expected: false,
		},
		{
			name:     "No match - no version",
			domain:   "service.example.com",
			expected: false,
		},
		{
			name:     "No match - invalid API pattern",
			domain:   "api-users.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wm.IsWhitelisted("ANSWER_RR_DIFF", tt.domain)
			if result != tt.expected {
				t.Errorf("IsWhitelisted(ANSWER_RR_DIFF, %q) = %v, expected %v",
					tt.domain, result, tt.expected)
			}
		})
	}
}
