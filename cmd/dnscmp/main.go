// 注意，这个工具依赖libcap，所以 linux 需要sudo yum install -y libpcap-devel
package main

import (
	"dnsdiff/internal/app"
	"dnsdiff/internal/diff"
	"dnsdiff/internal/parser"
	"dnsdiff/internal/saver"
	"dnsdiff/internal/statistics"
	"dnsdiff/pkg/types"
	"dnsdiff/pkg/utils"
	"flag"
	"fmt"
	"log"
	"sync"

	"github.com/sirupsen/logrus"
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
	saveChan = make(chan types.SaveChan, 10240)
)

// main 函数
/* 三类协程：
生产者，不断的把请求发送到 chan 中
消费者，不断从 chan 中取出请求，并发进行网络请求和对结果进行对比
保存者，将差异结果保存到文件中
*/
func main() {
	// 定义命令行参数
	testPcapFile := flag.String("t", "", "Test server pcap file")
	originPcapFile := flag.String("o", "", "Online server pcap file")
	allowPartial := flag.Int("p", 1, "Allow partial match")
	ignoreAddition := flag.Int("a", 1, "Ignore Addition")
	logLevel := flag.String("l", "info", "Log level info debug ")
	var expMaskStr string
	flag.StringVar(&expMaskStr, "m", fmt.Sprintf("0x%X", diff.DefaultMask),
		"Expected diff mask (hex format, e.g., 0xFF00)")

	// 解析命令行参数
	flag.Parse()

	// 解析十六进制掩码
	expMask, err := app.ParseHexMask(expMaskStr)
	if err != nil {
		log.Fatalf("Invalid hex format for -m: %v", err)
	}

	// 检查是否提供了 pcap 文件路径
	if *testPcapFile == "" || *originPcapFile == "" {
		flag.Usage()
		log.Fatalf("Parameters error! Please check your input! -h for help")
	}

	// 配置对比器
	cmper.IgnoreAdditional = *ignoreAddition == 1
	cmper.AllowPartialMatch = *allowPartial == 1
	cmper.DiffUnexpectedMask = expMask

	// 初始化日志系统
	app.InitLogger(&app.LogConfig{
		Level:      *logLevel,
		Filename:   "log/udns_dial.log",
		MaxSize:    100,
		MaxBackups: 5,
	})

	// 从 src pcap 文件中解析出 DNS 请求和响应
	testRspeqArr, testRspMap, err := parser.ParseFile(*testPcapFile, true)
	if err != nil || testRspeqArr == nil || testRspMap == nil {
		log.Fatalf("Parse error! error:%v", err)
	}
	if len(testRspMap) == 0 {
		log.Fatalf("Test pcap file has no valid DNS responses")
	}
	logrus.Infof("Main process started! testRspeqArr len: %d, testRspMap len: %d", len(*testRspeqArr), len(testRspMap))
	// 开始进行diff pcap分析和对比
	err = compare(*originPcapFile, testRspMap)
	if err != nil {
		log.Fatalf("Compare error! error:%v", err)
	}
	// 保存者协程，将差异结果保存到文件中
	err = saveFile()
	if err != nil {
		log.Fatalf("Save error! error:%v", err)
	}
	wgProducer.Wait()
	wgConsumer.Wait()
	wgSaver.Wait()
	// 打印统计信息
	statistics.GetStat().PrintfDiffStat()
	statistics.GetStat().PrintSummary()
	logrus.Info("\nMain process done! ")
}

func compare(onlinePcap string, testRspMap types.RspMap) error {
	// 从 pcap 文件中解析出 DNS 请求和响应p
	orginRspChan := make(chan *types.DNSRsp, 10000)

	wgProducer.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorf("Producer panic recovered: %v", r)
			}
			wgProducer.Done()
		}()

		err := parser.ParseRaw2Chan(onlinePcap, nil, orginRspChan)
		if err != nil {
			logrus.Errorf("Parse error: %v", err)
		}
	}()
	wgConsumer.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorf("Consumer panic recovered: %v", r)
			}
			wgConsumer.Done()
		}()
		rspCnt := 0
		for orginRsp := range orginRspChan {
			rspCnt++
			// 从测试结果map中查找匹配的rsp用于比较
			testRsp, err := utils.Find4diff(orginRsp, testRspMap)
			if err != nil || testRsp == nil {
				logrus.Errorf("Find4diff error: %v", err)
				continue
			}
			// 将DNSRsp转换为dns.Msg
			originMsg, oerr := types.DNSRspToMsg(orginRsp)
			testMsg, terr := types.DNSRspToMsg(testRsp)
			// 如果两个都转换失败，跳过
			if oerr != nil && terr != nil {
				logrus.Errorf("DNSRspToMsg both failed: origin=%v, test=%v", oerr, terr)
				continue
			}
			// 对结果进行比较
			diffCode := uint32(0)
			err = cmper.Compare(originMsg, testMsg, &diffCode)
			if err != nil {
				logrus.Errorf("Compare error: %v", err)
			}
			// 如果有非预期差异，保存结果
			if (diffCode & cmper.DiffUnexpectedMask) != 0 {
				diffElem := types.SaveChan{
					Old: originMsg,
					New: testMsg,
				}
				saveChan <- diffElem
				logrus.Infof("Compare diffCode= 0x%X", diffCode)
			}
			// 统计（优先使用有效的msg）
			var statMsg = testMsg
			if statMsg == nil {
				statMsg = originMsg
			}
			if statMsg != nil && len(statMsg.Question) > 0 {
				statistics.GetStat().Add(statMsg.Question[0].Qtype, statMsg.Question[0].Name, diffCode, cmper.DiffUnexpectedMask)
			}
		}
		statistics.AddKV(onlinePcap+" rspCnt", rspCnt)
		// chan 谁生产谁负责 close
		close(saveChan)
		logrus.Info("compare finished! close saveChan")
	}()
	return nil
}

// saveFile 保存差异结果
func saveFile() error {
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
	return nil
}
