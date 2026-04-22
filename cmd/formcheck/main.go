package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"dnsdiff/internal/app"

	"github.com/sirupsen/logrus"
)

func main() {
	// 参数解析
	pcapFile := flag.String("f", "", "Path to pcap file (required)")
	targetIP := flag.String("d", "", "Target IP to filter (optional)")
	checkMode := flag.String("c", "all", "Check mode: req | rsp | all")
	qps := flag.Int("qps", 0, "Rate limit (requests per second) when active probing is enabled (d is set). 0 means no limit")
	printWarnings := flag.Bool("warn", false, "Print packets with warnings (errors are always printed)")
	forceProto := flag.String("proto", "default", "Force send protocol: udp | tcp | default (follow pcap)")
	workerNum := flag.Int("n", 1000, "Number of worker goroutines (default: 1000)")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()

	if *help || *pcapFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// 校验模式检查
	if *checkMode != "req" && *checkMode != "rsp" && *checkMode != "all" {
		fmt.Println("Invalid check mode. Must be one of: req, rsp, all")
		os.Exit(1)
	}

	// 校验协议参数
	if *forceProto != "udp" && *forceProto != "tcp" && *forceProto != "default" {
		fmt.Println("Invalid protocol. Must be one of: udp, tcp, default")
		os.Exit(1)
	}

	// 初始化日志（参考 dnsdiff 方式）
	app.InitLogger(&app.LogConfig{
		Level:      "debug",
		Filename:   "log/formcheck.log",
		MaxSize:    100,
		MaxBackups: 5,
	})
	logrus.Info("Starting formcheck...")

	// 初始化组件
	stats := NewCheckStats()
	reporter, err := NewReporter()
	if err != nil {
		logrus.Fatalf("Failed to create reporter: %v", err)
	}
	defer reporter.Close()

	processor := NewProcessor(*pcapFile, *targetIP, *checkMode, *qps, *printWarnings, *forceProto, *workerNum, stats, reporter)

	// 执行处理
	startTime := time.Now()
	if err := processor.Run(); err != nil {
		logrus.Fatalf("Processing failed: %v", err)
	}
	duration := time.Since(startTime)

	// 保存统计结果
	csvFile := fmt.Sprintf("checksummary_%s.csv", time.Now().Format("0102_150405"))
	if err := stats.SaveCSV(csvFile); err != nil {
		logrus.Errorf("Failed to save CSV: %v", err)
	}

	logrus.Infof("Done! Processed %d packets in %v.", stats.TotalPackets, duration)
	logrus.Infof("Summary saved to %s", csvFile)
}
