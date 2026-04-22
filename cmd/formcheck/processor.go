package main

import (
	"context"
	"dnsdiff/internal/dnet"
	"dnsdiff/internal/parser"
	"dnsdiff/internal/validate"
	"dnsdiff/pkg/types"
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

const (
	defaultChanSize = 2000
	defaultWorkers  = 100
)

// Processor 核心处理逻辑
type Processor struct {
	pcapFile string
	targetIP string
	mode     string
	qps      int
	stats    *CheckStats
	reporter *Reporter
	// printWarnings 控制是否输出仅包含 warning 的包（error 包始终输出）
	printWarnings bool
	// forceProto 强制发送协议：udp | tcp | default（跟随 pcap）
	forceProto string
	workerNum  int
}

// NewProcessor 创建处理器
func NewProcessor(pcapFile, targetIP, mode string, qps int, printWarnings bool, forceProto string, workerNum int,
	stats *CheckStats, reporter *Reporter) *Processor {
	return &Processor{
		pcapFile:      pcapFile,
		targetIP:      targetIP,
		mode:          mode,
		qps:           qps,
		stats:         stats,
		reporter:      reporter,
		printWarnings: printWarnings,
		forceProto:    forceProto,
		workerNum:     workerNum,
	}
}

type saveItem struct {
	isReq      bool
	req        *types.DNSReq
	rsp        *types.DNSRsp
	errBits    uint64
	warnBits   uint64
	msg        *dns.Msg
	errDescs   []string
	relatedReq *types.DNSReq
}

// Run 执行处理
func (p *Processor) Run() error {
	var rspChan chan *types.DNSRsp
	reqChan := make(chan *types.DNSReq, defaultChanSize)
	saveChan := make(chan *saveItem, defaultChanSize)
	// 某些模式下完全不消费 rspChan
	needDrainRsp := false
	if (p.mode == "rsp" || p.mode == "all") && p.targetIP != "" {
		needDrainRsp = true
	}
	if p.mode == "req" {
		// req 模式也不使用 rspChan，避免 parse 阻塞
		needDrainRsp = true
	}
	if !needDrainRsp {
		rspChan = make(chan *types.DNSRsp, defaultChanSize)
	}
	var wg sync.WaitGroup

	// parse 协程：负责 close reqChan/rspChan
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := parser.ParseRaw2Chan(p.pcapFile, reqChan, rspChan); err != nil {
			logrus.Errorf("Parse failed: %v", err)
		}
	}()

	// validate 协程：根据 mode/targetIP 决定消费与校验逻辑，最后 close saveChan
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.validate(reqChan, rspChan, saveChan)
		close(saveChan)
	}()

	// save 协程：串行落盘
	wg.Add(1)
	go func() {
		defer wg.Done()
		for it := range saveChan {
			if it.isReq {
				p.reporter.WriteReq(it.req, it.errBits, it.warnBits, it.msg, it.errDescs)
			} else {
				// 如果有关联请求，先打印关联请求作为上下文
				if it.relatedReq != nil {
					reqMsg := new(dns.Msg)
					// 尝试解析以便打印详情
					var descs []string
					if err := reqMsg.Unpack(it.relatedReq.RawData); err == nil {
						descs = []string{"[Context] Associated Request"}
					} else {
						reqMsg = nil
						descs = []string{"[Context] Associated Request (Parse Failed)"}
					}
					// 打印关联请求，不带错误位
					p.reporter.WriteReq(it.relatedReq, 0, 0, reqMsg, descs)
				}
				p.reporter.WriteRsp(it.rsp, it.errBits, it.warnBits, it.msg, it.errDescs)
			}
		}
	}()

	wg.Wait()
	return nil
}

func (p *Processor) validate(reqChan <-chan *types.DNSReq, rspChan <-chan *types.DNSRsp, saveChan chan<- *saveItem) {
	// 在线主动发包限速器（仅 targetIP != "" 且需要发包时使用）
	var limiter *rate.Limiter
	if p.targetIP != "" && p.qps > 0 {
		limiter = rate.NewLimiter(rate.Limit(p.qps), 1)
	}

	// targetIP != ""：在线模式（主动发包），采用 worker pool 并发处理
	if p.targetIP != "" {
		workers := p.workerNum
		if p.qps > 1 && p.qps < workers {
			workers = p.qps
		}

		jobs := make(chan *types.DNSReq, defaultChanSize)
		var wg sync.WaitGroup

		workerFn := func() {
			defer wg.Done()
			for req := range jobs {
				// req 校验
				if p.mode == "req" || p.mode == "all" {
					errBits, warnBits, msg, details, err := validate.ValidateReq(req.RawData)
					if err != nil {
						logrus.Errorf("ValidateReq failed: %v", err)
						continue
					}
					p.stats.Record(errBits, warnBits)
					if errBits != 0 || (p.printWarnings && warnBits != 0) {
						saveChan <- &saveItem{isReq: true, req: req, errBits: errBits, warnBits: warnBits, msg: msg, errDescs: details}
					}
				}

				// rsp 校验（主动发包）
				if p.mode == "rsp" || p.mode == "all" {
					if limiter != nil {
						if err := limiter.Wait(context.Background()); err != nil {
							logrus.Errorf("Limiter wait error: %v", err)
							continue
						}
					}
					// 根据 forceProto 参数调整请求的协议类型
					switch p.forceProto {
					case "udp":
						req.IsTCP = false
					case "tcp":
						req.IsTCP = true
						// default: 保持原 pcap 中的协议类型
					}
					netRsp, err := dnet.SendAndRecv(req, p.targetIP)
					if err != nil {
						// 网络错误不算 form 校验错误，打印后继续
						logrus.Errorf("SendAndRecv failed: %v", err)
						continue
					}
					rawRsp := netRsp.RawData
					// 使用 ValidateRspWithTCP 以便进行 TCP 特定的校验（如 TCP 响应中不应出现 TC=1）
					errBits, warnBits, msg, details, err := validate.ValidateRspWithTCP(req.RawData, rawRsp, netRsp.IsTCP)
					if err != nil {
						logrus.Errorf("ValidateRspWithTCP failed: %v", err)
						continue
					}
					p.stats.Record(errBits, warnBits)
					if errBits != 0 || (p.printWarnings && warnBits != 0) {
						item := &saveItem{isReq: false, rsp: netRsp, errBits: errBits, warnBits: warnBits, msg: msg, errDescs: details}

						// 定义关联错误掩码
						assocErrorMask := validate.ErrAssocIDMismatch |
							validate.ErrAssocOpcodeMismatch |
							validate.ErrAssocRDMismatch |
							validate.ErrAssocQuestionMismatch |
							validate.ErrAssocNoErrorEmpty |
							validate.ErrAssocADWithCD |
							validate.ErrAssocCDNotCopied |
							validate.ErrAssocECSFamilyMismatch |
							validate.ErrAssocECSSourcePrefixMismatch |
							validate.ErrAssocCNAMEWithOther

						// 如果有关联校验错误，带上关联请求
						if (errBits & assocErrorMask) != 0 {
							item.relatedReq = req
						}
						saveChan <- item
					}
				}
			}
		}

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go workerFn()
		}

		for req := range reqChan {
			jobs <- req
		}
		close(jobs)
		wg.Wait()
		return
	}

	// targetIP == ""：纯离线模式
	// 约束：不做请求/响应关联校验。all 模式下也只是“分别校验 req + 分别校验 rsp”。
	reqOpen := true
	rspOpen := rspChan != nil
	for reqOpen || rspOpen {
		select {
		case req, ok := <-reqChan:
			if !ok {
				reqOpen = false
				reqChan = nil
				continue
			}
			if p.mode != "rsp" { // req 或 all 都校验请求
				errBits, warnBits, msg, details, err := validate.ValidateReq(req.RawData)
				if err != nil {
					logrus.Errorf("ValidateReq failed: %v", err)
					continue
				}
				p.stats.Record(errBits, warnBits)
				if errBits != 0 || (p.printWarnings && warnBits != 0) {
					saveChan <- &saveItem{isReq: true, req: req, errBits: errBits, warnBits: warnBits, msg: msg, errDescs: details}
				}
			}

		case rsp, ok := <-rspChan:
			if !ok {
				rspOpen = false
				rspChan = nil
				continue
			}
			if p.mode != "req" { // rsp 或 all 都校验响应
				rawRsp := rsp.RawData
				if len(rawRsp) == 0 {
					continue
				}

				// 无关联：rawReq 传 nil
				errBits, warnBits, msg, details, err := validate.ValidateRspWithTCP(nil, rawRsp, rsp.IsTCP)
				if err != nil {
					logrus.Errorf("ValidateRspWithTCP failed: %v", err)
					continue
				}
				p.stats.Record(errBits, warnBits)
				if errBits != 0 || (p.printWarnings && warnBits != 0) {
					saveChan <- &saveItem{isReq: false, rsp: rsp, errBits: errBits, warnBits: warnBits, msg: msg, errDescs: details}
				}
			}
		}
	}
}
