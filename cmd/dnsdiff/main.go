// 注意，这个工具依赖libcap，所以 linux 需要sudo yum install -y libpcap-devel
package main

import (
	"context"
	"dnsdiff/internal/app"
	"dnsdiff/internal/diff"
	"dnsdiff/internal/parser"
	"dnsdiff/internal/saver"
	"dnsdiff/internal/statistics"
	"dnsdiff/pkg/types"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	wgProducer sync.WaitGroup
	wgConsumer sync.WaitGroup
	wgSaver    sync.WaitGroup

	// 比较条件设定
	cmper = diff.Comparator{
		AllowPartialMatch:  true,
		IgnoreAdditional:   true,
		DiffUnexpectedMask: diff.DefaultMask,
	}
	testIP   = ""
	originIP = ""
	// qonly 为 true 时，表示 pcap 包里面只有 req，需要同时对 test server 和 origin server 发送请求
	qonly = false
	// 第一次对比有差异的情况下是否要重试对比
	retryFlag = true
	// 生产者协程，负责按指定速率从 reqArr 中取出请求，并发送到 chan
	reqChan  = make(chan *types.DNSReq, 10240)
	saveChan = make(chan types.SaveChan, 10240)
)

const (
	defaultConsumerNum = 1000
)

// main 函数
/* 三类协程：
生产者，不断的把请求发送到 chan 中
消费者，不断从 chan 中取出请求，并发进行网络请求和对结果进行对比
保存者，将差异结果保存到文件中
*/
// NOCA:golint/fnsize(设计如此)
func main() {
	// 自定义 Usage 输出
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `dnsdiff - DNS响应对比工具

用法:
  dnsdiff -i <pcap文件> -t <测试服务器IP> [选项...]

必选参数:
  -i, -input <path>          pcap抓包文件路径
  -t, -test-ip <ip>          测试服务器IP地址
  -q, -qps <n>               每秒请求速率 (最小值: 2, 默认: 100)

服务器参数:
  -o, -origin-ip <ip>        线上/基准服务器IP地址
                             (当 -query-only 或 -retry 时必填)

对比选项:
  -m, -mask <hex>            差异检测掩码，十六进制格式 (默认: 0x%X)
  -allow-partial             允许Answer段A/AAAA记录部分匹配 (默认: true)
  -ignore-additional         忽略Additional段的对比 (默认: true)
  -retry                     首次有差异时是否重试对比 (默认: true)
  -query-only                仅请求模式，pcap仅含请求报文，需同时向两台
                             服务器发送请求进行响应对比 (默认: false)
  -w, -whitelist <path>      白名单配置文件路径，YAML格式 (可选)

运行参数:
  -c, -concurrency <n>       消费者协程数 (默认: 1000)
  -l, -level <level>         日志级别: debug, info, warn, error (默认: info)

示例:
  # 基本用法
  dnsdiff -i traffic.pcap -t 10.0.0.1 -q 5000

  # 指定线上服务器IP，启用重试对比
  dnsdiff -i traffic.pcap -t 10.0.0.1 -o 10.0.0.2 -q 8000 -retry

  # 仅请求模式
  dnsdiff -i requests.pcap -t 10.0.0.1 -o 10.0.0.2 -q 3000 -query-only

  # 使用白名单
  dnsdiff -i traffic.pcap -t 10.0.0.1 -o 10.0.0.2 -w whitelist.yaml
`, diff.DefaultMask)
	}

	// 定义命令行参数变量
	var (
		expMaskStr     string
		pcapFile       string
		rateLimit      int
		testSvrIP      string
		onlineIP       string
		allowPartial   bool
		ignoreAddition bool
		logLevel       string
		consumerNum    int
		qonlyFlag      bool
		retry          bool
		whitelistFile  string
	)

	// 绑定参数
	flag.StringVar(&expMaskStr, "m", fmt.Sprintf("0x%X", diff.DefaultMask), "差异检测掩码")
	flag.StringVar(&expMaskStr, "mask", fmt.Sprintf("0x%X", diff.DefaultMask), "同 -m")

	flag.StringVar(&pcapFile, "i", "", "pcap抓包文件路径 (必填)")
	flag.StringVar(&pcapFile, "input", "", "同 -i")

	flag.IntVar(&rateLimit, "q", 100, "每秒请求速率")
	flag.IntVar(&rateLimit, "qps", 100, "同 -q")

	flag.StringVar(&testSvrIP, "t", "", "测试服务器IP地址 (必填)")
	flag.StringVar(&testSvrIP, "test-ip", "", "同 -t")

	flag.StringVar(&onlineIP, "o", "", "线上/基准服务器IP地址")
	flag.StringVar(&onlineIP, "origin-ip", "", "同 -o")

	flag.BoolVar(&allowPartial, "allow-partial", true, "允许Answer段A/AAAA记录部分匹配")
	flag.BoolVar(&ignoreAddition, "ignore-additional", true, "忽略Additional段的对比")
	flag.BoolVar(&retry, "retry", true, "首次有差异时是否重试对比")
	flag.BoolVar(&qonlyFlag, "query-only", false, "仅请求模式")

	flag.StringVar(&whitelistFile, "w", "", "白名单配置文件路径")
	flag.StringVar(&whitelistFile, "whitelist", "", "同 -w")

	flag.IntVar(&consumerNum, "c", defaultConsumerNum, "消费者协程数")
	flag.IntVar(&consumerNum, "concurrency", defaultConsumerNum, "同 -c")

	flag.StringVar(&logLevel, "l", "info", "日志级别")
	flag.StringVar(&logLevel, "level", "info", "同 -l")

	// 解析命令行参数
	flag.Parse()

	// 解析十六进制掩码
	expMask, err := app.ParseHexMask(expMaskStr)
	if err != nil {
		log.Fatalf("Invalid hex format for -m: %v", err)
	}

	// 校验必填参数
	var paramErrors []string
	if pcapFile == "" {
		paramErrors = append(paramErrors, "缺少必填参数 -i/-input (pcap文件路径)")
	}
	if testSvrIP == "" {
		paramErrors = append(paramErrors, "缺少必填参数 -t/-test-ip (测试服务器IP)")
	}
	if rateLimit < 2 {
		paramErrors = append(paramErrors, "参数 -q/-qps 的值必须 >= 2")
	}
	if qonlyFlag && onlineIP == "" {
		paramErrors = append(paramErrors, "仅请求模式(-query-only)下必须指定 -o/-origin-ip (线上服务器IP)")
	}
	if retry && onlineIP == "" && !qonlyFlag {
		logrus.Warnf("提示: 启用重试(-retry)但未指定 -o/-origin-ip，rspMap中找不到响应时无法从线上服务器获取")
	}
	if len(paramErrors) > 0 {
		fmt.Fprintf(os.Stderr, "\n参数错误:\n")
		for _, e := range paramErrors {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	testIP = testSvrIP
	originIP = onlineIP
	qonly = qonlyFlag
	retryFlag = retry
	cmper.IgnoreAdditional = ignoreAddition
	cmper.AllowPartialMatch = allowPartial
	cmper.DiffUnexpectedMask = expMask

	// 初始化日志系统
	app.InitLogger(&app.LogConfig{
		Level:      logLevel,
		Filename:   "log/udns_dial.log",
		MaxSize:    100,
		MaxBackups: 5,
	})

	// 加载白名单配置
	if whitelistFile != "" {
		whitelistMgr := app.NewWhitelistManager()
		if err := whitelistMgr.LoadFromFile(whitelistFile); err != nil {
			log.Fatalf("Failed to load whitelist config: %v", err)
		}
		cmper.WhitelistChecker = whitelistMgr
		logrus.Infof("Whitelist loaded: %d rules, diff types: %v",
			whitelistMgr.GetRuleCount(), whitelistMgr.GetDiffTypes())
	} else {
		// 尝试加载默认配置文件
		defaultWhitelist := "whitelist.yaml"
		whitelistMgr := app.NewWhitelistManager()
		if err := whitelistMgr.LoadFromFile(defaultWhitelist); err == nil {
			cmper.WhitelistChecker = whitelistMgr
			logrus.Infof("Default whitelist loaded: %d rules", whitelistMgr.GetRuleCount())
		}
	}

	// 从 pcap 文件中解析出 DNS 请求和响应
	saveRsp := !qonly
	reqArr, rspMap, err := parser.ParseFile(pcapFile, saveRsp)
	if err != nil || reqArr == nil || (rspMap == nil && !qonly) {
		log.Fatalf("Parse error! error:%v", err)
	}
	logrus.Infof("Main process started! reqArr len: %d, rspMap len: %d", len(*reqArr), len(rspMap))
	// 启动多个消费者协程工作
	for i := 0; i < consumerNum; i++ {
		wgConsumer.Add(1)
		go consumer(rspMap, i)
	}
	// 启动生产者协程
	wgProducer.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorf("Producer panic recovered: %v", r)
			}
			wgProducer.Done()
		}()
		// 创建一个限速器
		limiter := rate.NewLimiter(rate.Limit(rateLimit), 10)
		for i := 0; i < len(*reqArr); i++ {
			// 等待下一个时间间隔
			err := limiter.Wait(context.Background())
			if err != nil {
				logrus.Errorf("Producer limiter wait error: %v", err)
				break
			}
			reqChan <- &(*reqArr)[i]
		}
		logrus.Info("Producer: all requests sent!")
		close(reqChan) // 关闭通道，表示所有请求已发送完毕
	}()

	// 保存者协程，将差异结果保存到文件中
	wgSaver.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorf("Saver panic recovered: %v", r)
			}
			wgSaver.Done()
		}()
		err := saver.SaveDiff(saveChan)
		if err != nil {
			logrus.Errorf("SaveDiff error: %v", err)
		}
	}()
	wgProducer.Wait()
	wgConsumer.Wait()
	close(saveChan)
	logrus.Info("Main process: all consumers finished! close saveChan")
	wgSaver.Wait()
	// 打印统计信息
	statistics.GetStat().PrintfDiffStat()
	statistics.GetStat().PrintSummary()
	logrus.Info("\nMain process done! ")
}
