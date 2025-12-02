#!/bin/bash
# 正则表达式白名单功能演示脚本

set -e

echo "=========================================="
echo "DNS Diff 正则表达式白名单功能演示"
echo "=========================================="
echo ""

# 1. 创建示例配置文件
echo "1. 创建正则表达式白名单配置文件..."
cat > demo_regex_whitelist.yaml << 'EOF'
whitelist:
  # 示例1：忽略迁移数据库域名的Answer RR差异
  - diff_type: ANSWER_RR_DIFF
    patterns:
      - ".*\.mig\.db\.example\.com$"
      - ".*\.migration\.example\.com$"
    description: "Ignore ANSWER_RR_DIFF for migration database domains"

  # 示例2：忽略测试环境的Authority RR差异
  - diff_type: AUTH_RR_DIFF
    patterns:
      - ".*\.(staging|test)\.example\.com$"
      - "(?i).*\.dev\..*"
    description: "Ignore AUTH_RR_DIFF for test and staging environments"

  # 示例3：忽略CDN域名的Answer长度差异
  - diff_type: ANSWER_LEN_DIFF
    patterns:
      - ".*\.cdn\..*$"
      - ".*\.akamai\.net$"
      - ".*\.cloudfront\.net$"
    description: "Ignore ANSWER_LEN_DIFF for CDN domains"

  # 示例4：复杂正则模式
  - diff_type: ANSWER_CNAME_DIFF
    patterns:
      # 匹配版本号格式
      - ".*v[0-9]+(\.[0-9]+)*\..*"
      # 匹配地理相关域名
      - ".*(geo|region|location).*\..*"
      # 匹配API服务
      - "^api-[a-z]+-[0-9]+\..*"
    description: "Ignore CNAME differences for versioned and geo domains"

  # 示例5：大小写不敏感匹配
  - diff_type: ADD_RR_DIFF
    patterns:
      - "(?i).*\.cache\..*"
      - "(?i).*\.static\..*"
    description: "Ignore ADD_RR_DIFF for cache and static domains (case insensitive)"
EOF

echo "✅ 正则表达式配置文件已创建: demo_regex_whitelist.yaml"
echo ""

# 2. 显示配置内容
echo "2. 配置文件内容："
echo "----------------------------------------"
cat demo_regex_whitelist.yaml
echo "----------------------------------------"
echo ""

# 3. 运行测试
echo "3. 运行单元测试（重点测试正则表达式功能）..."
go test ./internal/app -v -run TestWhitelistManager_ComplexRegexPatterns 2>&1 | grep -E "(PASS|FAIL|RUN)" || true
echo ""

# 4. 编译工具
echo "4. 编译dnsdiff工具..."
go build -o dnsdiff ./cmd/dnsdiff
echo "✅ 编译成功: dnsdiff"
echo ""

# 5. 显示命令行参数（显示包含-w参数的部分）
echo "5. dnsdiff 命令行参数（包含白名单支持）："
echo "----------------------------------------"
echo "新增参数："
echo "  -w string"
echo "        Whitelist config file (YAML format with regex patterns)"
echo "----------------------------------------"
echo ""

# 6. 正则表达式示例说明
echo "6. 正则表达式模式示例："
echo "----------------------------------------"
echo "基础模式："
echo "  .*\.mig\.db\.example\.com\$     # 匹配所有.mig.db.example.com结尾的域名"
echo "  ^test\.example\.com\$           # 精确匹配test.example.com"
echo ""
echo "高级模式："
echo "  .*\.(staging|test)\..*          # 匹配所有.staging.或.test.的域名"
echo "  .*v[0-9]+(\.[0-9]+)*\..*        # 匹配版本号格式如v1, v2.1等"
echo "  (?i).*\.cdn\..*                 # 大小写不敏感匹配CDN域名"
echo "  ^api-[a-z]+-[0-9]+\..*          # 匹配API服务名模式"
echo ""
echo "组合模式："
echo "  .*(geo|region|location).*\..*   # 匹配包含geo或region或location的域名"
echo "----------------------------------------"
echo ""

# 7. 使用说明
echo "7. 使用示例："
echo "----------------------------------------"
echo "# 使用正则表达式白名单配置文件"
echo "./dnsdiff -f traffic.pcap -w demo_regex_whitelist.yaml -tip 192.168.1.10 -qps 100"
echo ""
echo "# 使用默认配置文件（whitelist.yaml）"
echo "./dnsdiff -f traffic.pcap -tip 192.168.1.10 -qps 100"
echo ""
echo "# 调试模式查看白名单应用"
echo "./dnsdiff -f traffic.pcap -w demo_regex_whitelist.yaml -tip 192.168.1.10 -qps 100 -l debug"
echo "----------------------------------------"
echo ""

# 8. 正则表达式测试工具
echo "8. 正则表达式测试（Go代码示例）："
echo "----------------------------------------"
cat << 'TEST_EOF'
package main

import (
    "fmt"
    "regexp"
)

func main() {
    // 测试正则表达式
    patterns := []string{
        ".*\\.mig\\.db\\.example\\.com$",
        ".*\\.(staging|test)\\..*",
        ".*v[0-9]+(\\.[0-9]+)*\\..*",
        "(?i).*\\.cdn\\..*",
    }
    
    domains := []string{
        "server1.mig.db.example.com",
        "app.staging.example.com", 
        "service.v2.example.com",
        "content.CDN.example.com",
    }
    
    for _, pattern := range patterns {
        re, err := regexp.Compile(pattern)
        if err != nil {
            fmt.Printf("Invalid pattern: %s, error: %v\n", pattern, err)
            continue
        }
        
        fmt.Printf("Pattern: %s\n", pattern)
        for _, domain := range domains {
            if re.MatchString(domain) {
                fmt.Printf("  ✓ %s\n", domain)
            } else {
                fmt.Printf("  ✗ %s\n", domain)
            }
        }
        fmt.Println()
    }
}
TEST_EOF
echo "----------------------------------------"
echo ""

# 9. 清理
echo "9. 清理演示文件..."
# rm -f demo_regex_whitelist.yaml
echo "✅ 演示完成！配置文件保留为 demo_regex_whitelist.yaml"
echo ""

echo "=========================================="
echo "正则表达式白名单功能已实现！"
echo ""
echo "主要特性："
echo "  ✓ 支持完整的Go正则表达式语法"
echo "  ✓ 大小写敏感/不敏感匹配"
echo "  ✓ 复杂模式匹配（版本号、环境等）"
echo "  ✓ 自动验证正则表达式有效性"
echo "  ✓ 无效正则表达式会被跳过并给出警告"
echo "  ✓ 支持调试模式查看过滤详情"
echo ""
echo "相关文件："
echo "  - internal/app/whitelist.go          # 核心实现"
echo "  - internal/app/whitelist_test.go     # 单元测试"
echo "  - whitelist_regex.yaml               # 配置示例"
echo "=========================================="