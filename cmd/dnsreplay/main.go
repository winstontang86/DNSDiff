// 注意，这个工具依赖libcap，所以 linux 需要sudo yum install -y libpcap-devel
package main

import (
	"context"
	"dnsdiff/internal/app"
	"dnsdiff/internal/dnet"
	"dnsdiff/internal/parser"
	"dnsdiff/pkg/types"
	"flag"
	"log"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	wgProducer sync.WaitGroup
	wgConsumer sync.WaitGroup

	dstIP          = "127.0.0.1"
	replayProtocol = "" // 空表示跟随请求包的类型
	// 生产者协程，负责按指定速率从 reqArr 中取出请求，并发送到 chan
	reqChan = make(chan *types.DNSReq, 80960)
)

const (
	defaultConsumerNum = 1000
)

// main 函数
/* 三类协程：
生产者，不断的把请求发送到 chan 中
消费者，不断从 chan 中取出请求，并发进行网络请求
*/
func main() {
	// 定义命令行参数
	pcapFile := flag.String("f", "", "Path to the pcap file")
	rateLimit := flag.Int("r", 1, "Rate limit (requests per second)")
	testIP := flag.String("d", "", "Destination IP")
	consumerNum := flag.Int("c", defaultConsumerNum, "Number of consumers")
	// 重放协议，默认空，根据抓包类型重放，可以指定udp或tcp
	protocol := flag.String("p", "", "Protocol (udp or tcp, default empty)")

	// 解析命令行参数
	flag.Parse()

	// 检查是否提供了 pcap 文件路径
	if *pcapFile == "" || *testIP == "" || *rateLimit < 10 {
		flag.Usage()
		log.Fatalf("Parmeters error! Please check your input! -h for help")
	}
	dstIP = *testIP
	replayProtocol = *protocol

	// 初始化日志系统
	app.InitLogger(&app.LogConfig{
		Level:      "debug",
		Filename:   "log/udns_dial.log",
		MaxSize:    100,
		MaxBackups: 5,
	})

	// 从 pcap 文件中解析出 DNS 请求和响应
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logrus.Errorf("Panic: %v", err)
			}
		}()
		err := parser.ParseRaw2Chan(*pcapFile, reqChan, nil)
		if err != nil {
			log.Fatalf("Parse error! error:%v", err)
		}
	}()

	// 启动多个消费者协程工作
	rateByWorker := float64(*rateLimit) / float64(*consumerNum)
	for i := 0; i < *consumerNum; i++ {
		wgConsumer.Add(1)
		go consumer(rateByWorker, i)
	}

	wgProducer.Wait()
	wgConsumer.Wait()
	logrus.Info("\nMain process done! ")
}

func consumer(rateByWorker float64, idx int) {
	defer wgConsumer.Done()
	limiter := rate.NewLimiter(rate.Limit(rateByWorker), 1)
	//logrus.Debugf("Consumer %d started", idx)
	// 不断从 reqChan 中取出请求，并发进行网络请求和对结果进行对比
	for req := range reqChan {
		// 等待下一个时间间隔
		err := limiter.Wait(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		// 网络请求
		// Protocol conversion: only need to change IsTCP flag
		// sendAndRecvTCP/sendAndRecvUDP will handle length prefix internally
		if strings.ToLower(replayProtocol) == "tcp" {
			req.IsTCP = true
		}
		if strings.ToLower(replayProtocol) == "udp" {
			req.IsTCP = false
		}
		rsp, err := dnet.SendAndRecv(req, dstIP)
		if err == nil && rsp != nil {
			logrus.Infof("SendAndRecv ok! len= %d", len(rsp.RawData))

		} else {
			// 打印错误日志
			logrus.Errorf("SendAndRecv error: %v", err)
		}
	}
	logrus.Debugf("Consumer %d finished", idx)
}
