package main

import (
	"fmt"
	"sync"

	"dnsdiff/internal/diff"
	"dnsdiff/internal/dnet"
	"dnsdiff/internal/statistics"
	"dnsdiff/pkg/types"
	"dnsdiff/pkg/utils"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// consumer 消费者函数
func consumer(rspMap types.RspMap, idx int) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Consumer %d panic recovered: %v", idx, r)
		}
		wgConsumer.Done()
	}()

	for req := range reqChan {
		processRequest(req, rspMap)
	}

	logrus.Debugf("Consumer %d finished", idx)
}

// processRequest 处理单个DNS请求的完整对比流程
func processRequest(req *types.DNSReq, rspMap types.RspMap) {
	// 第一次对比
	firstResult, err := firstCmp(req, rspMap)
	// 第一次对比出错，打印错误，继续对比
	if err != nil {
		logrus.Errorf("First comparison failed: %v, clientip: %s, port: %s", err, req.ClientIP, req.ClientPort)
	}
	if !retryFlag {
		resultStatDiffSave(firstResult)
		return
	}

	// 检查 originIP 是否为空，如果为空则无法进行重试对比
	if originIP == "" {
		logrus.Warnf("Retry skipped: originIP is empty, use first result")
		resultStatDiffSave(firstResult)
		return
	}

	// 第一次对比有差异或出错，进行重试
	retryResults := retryCmp(req)
	if len(retryResults) == 0 {
		// 使用第一次的结果
		if firstResult != nil {
			logrus.Errorf("Retry comparison failed: %v, domain: %s, dnsid: %d, type: %d",
				err, firstResult.domain, firstResult.dnsID, firstResult.qtype)
			resultStatDiffSave(firstResult)
		} else {
			logrus.Errorf("retryCmp return empty first also nil. No comparison result available")
		}
		return
	}

	// 如果重试结果为空且第一次也失败了，跳过此请求
	if len(retryResults) == 0 && firstResult == nil {
		logrus.Errorf("All comparison attempts failed for request")
		return
	}

	// 确保 firstResult 不为 nil 才继续处理（nilaway 保护）
	if firstResult == nil {
		logrus.Errorf("First comparison result is nil, cannot process retry results")
		return
	}

	// 处理对比结果
	processRetryResults(firstResult, retryResults)
}

// processRetryResults 处理重试结果，包括白名单过滤、交叉对比和合并RR对比
// 所有有差异的情况直接打印最后一次的对比结果
/*
 * 重试对比可以解决的问题：
 * 1、首次是转发获取的结果，权威直接返回了 aa 标记，后面可能是命中缓存，没有 aa 标记的 flag 差异问题
 * 2、域名的返回结果在一个小集合里面轮转，而且轮转的缓存时间很短的时候导致的 RRDiff 差异问题
 * 3、【未解决】不同的机器因为转发到不同的内网权威或不同的 unbound 机器，不同的机器因为所在地域不同或者出口 ip 不同，权威返回内容不同
 * 4、【未解决】一些域名首次请求，unbound 处理超时，导致返回 rcode 不同的情况。这个可以在对比前把所有请求在 tip 上先请求一遍
 * 5、
 */
func processRetryResults(firstResult *cmpResult, retryResults []*cmpResult) {
	baseResult := firstResult
	anyEqual := false
	for _, retryResult := range retryResults {
		if retryResult == nil {
			continue
		}
		// 应用白名单过滤后判断是否相等（不修改原始值）
		filteredDiffCode := cmper.ApplyWhitelist(retryResult.diffCode, retryResult.domain)
		// 最终打印的采用最后一次的！
		baseResult = retryResult
		// 有一次相等就中断
		if (filteredDiffCode & cmper.DiffUnexpectedMask) == 0 {
			anyEqual = true
			break
		}
	}

	// 任意一次重试相等则判定为相等
	if anyEqual {
		if baseResult != nil {
			baseResult.diffCode = 0
			resultStatDiffSave(baseResult)
		} else {
			logrus.Errorf("[processRetryResults]No comparison result available")
		}
		return
	} else {
		logrus.Infof("All retry results are different, domain: %s, dnsid: %d, type: %d",
			baseResult.domain, baseResult.dnsID, baseResult.qtype)
	}

	// 重试都不相等，进行交叉对比
	if len(retryResults) == 2 {
		crossDiffCode := crossCmp(retryResults)
		if (crossDiffCode & cmper.DiffUnexpectedMask) == 0 {
			// 交叉对比没有差异，判定为相等
			if baseResult != nil {
				baseResult.diffCode = 0
				resultStatDiffSave(baseResult)
			} else {
				logrus.Errorf("crossCmp is diff, but base is nil, No comparison result available")
			}
			return
		}
	}

	// 确保有有效的结果可以处理
	if baseResult == nil {
		logrus.Errorf("No valid comparison result available")
		return
	}

	// 三次是RRDiff，尝试合并RR进行对比
	if isAllAnswerRRDiff(firstResult, retryResults) {
		bRRSame, err := handleMergedAnswerCmp(firstResult, retryResults)
		if err == nil && bRRSame {
			baseResult.diffCode = 0
			resultStatDiffSave(baseResult)
			return
		}
	}
	// 处理最终结果
	resultStatDiffSave(baseResult)
}

// handleMergedAnswerCmp 处理合并Answer段的对比逻辑
// 当所有对比结果都是DIFF_BIT_ANSWER_RRDIFF时，合并所有Answer段再对比
// 返回
//
//	bool：是否RRDiff
//	error：对比过程中的错误
func handleMergedAnswerCmp(firstResult *cmpResult, retryResults []*cmpResult) (bool, error) {
	bRRSame := false

	// 收集所有 origin 和 test 的 msg（只添加非空消息）
	var originMsgs []*dns.Msg
	var testMsgs []*dns.Msg

	if firstResult != nil {
		if firstResult.originMsg != nil {
			originMsgs = append(originMsgs, firstResult.originMsg)
		}
		if firstResult.testMsg != nil {
			testMsgs = append(testMsgs, firstResult.testMsg)
		}
	}
	for _, retryResult := range retryResults {
		if retryResult == nil {
			continue
		}
		if retryResult.originMsg != nil {
			originMsgs = append(originMsgs, retryResult.originMsg)
		}
		if retryResult.testMsg != nil {
			testMsgs = append(testMsgs, retryResult.testMsg)
		}
	}

	// 确保有有效的消息可以进行合并对比
	if len(originMsgs) == 0 || len(testMsgs) == 0 {
		logrus.Warnf("No valid messages available for merged answer comparison")
		return bRRSame, nil
	}

	// 合并 Answer 段并对比
	mergedOriginAnswers := mergeAnswers(originMsgs)
	mergedTestAnswers := mergeAnswers(testMsgs)
	diffCode := cmpMergeAnswer(mergedOriginAnswers, mergedTestAnswers)

	// 更新最终结果的diffCode
	if (diffCode & cmper.DiffUnexpectedMask) == 0 {
		bRRSame = true
	}
	return bRRSame, nil
}

// isAllAnswerRRDiff 检查是否所有对比结果都是 DIFF_BIT_ANSWER_RRDIFF
func isAllAnswerRRDiff(firstResult *cmpResult, retryResults []*cmpResult) bool {
	if firstResult == nil || firstResult.diffCode != diff.DIFF_BIT_ANSWER_RRDIFF {
		return false
	}

	// 至少需要一个有效的重试结果
	hasValidRetry := false
	for _, retryResult := range retryResults {
		if retryResult == nil {
			continue
		}
		hasValidRetry = true
		if retryResult.diffCode != diff.DIFF_BIT_ANSWER_RRDIFF {
			return false
		}
	}

	// 如果没有任何有效的重试结果，不应该进行合并对比
	if !hasValidRetry {
		return false
	}

	return true
}

// cmpResult 对比结果
type cmpResult struct {
	originMsg *dns.Msg
	testMsg   *dns.Msg
	diffCode  uint32
	domain    string
	dnsID     uint16
	qtype     uint16
}

// firstCmp 第一次对比
// 如果qonly是true，则发送请求到两个服务器进行对比；否则origin从rspMap中找到对比的rsp
func firstCmp(req *types.DNSReq, rspMap types.RspMap) (*cmpResult, error) {
	if req == nil {
		return nil, fmt.Errorf("firstCmp: req is nil")
	}

	// 解析请求以获取查询信息
	reqMsg, err := types.BytesToDNSMsg(req.RawData)
	if err != nil || reqMsg == nil || len(reqMsg.Question) == 0 {
		return nil, fmt.Errorf("firstCmp: failed to parse request: %v", err)
	}

	var originMsg *dns.Msg
	var testMsg *dns.Msg
	var originErr, testErr error

	// 发送请求到测试服务器
	testRsp, terr := dnet.SendAndRecv(req, testIP)
	if terr == nil {
		testMsg, testErr = types.DNSRspToMsg(testRsp)
	} else {
		testErr = terr
	}
	// 尝试从 rspMap 中获取 origin 响应（非 qonly 模式）
	var originRsp *types.DNSRsp
	needRequestOrigin := qonly // qonly 模式必须从线上获取

	if !qonly {
		// 非 qonly 模式：先尝试从 rspMap 中查找响应
		// 非qonly的时候，needRequestOrigin值是false，先改成true，查找到了再修改成false
		needRequestOrigin = true
		question := reqMsg.Question[0]
		key := utils.GenU64Key(question.Qclass, question.Qtype, reqMsg.Id, reqMsg.Opcode)
		secdKey := utils.GenSecdKey(question.Name, req.ClientIP, req.ClientPort)

		secdMap, ok := rspMap[key]
		if ok {
			originRsp, ok = secdMap[secdKey]
			if ok {
				needRequestOrigin = false // MUST
			} else {
				logrus.Infof("firstCmp: no response found in rspMap for secdKey=%s. request origin srv", secdKey)
			}
		} else {
			logrus.Infof("firstCmp: no response found in rspMap for key=%d. request origin srv", key)
		}
	}

	// 如果需要从线上服务器获取 origin 响应
	if needRequestOrigin {
		if originIP == "" {
			return nil, fmt.Errorf("firstCmp originIP is empty, cannot request origin server")
		} else {
			netOriginRsp, oerr := dnet.SendAndRecv(req, originIP)
			if oerr == nil {
				originMsg, originErr = types.DNSRspToMsg(netOriginRsp)
			} else {
				originErr = oerr
			}
		}
	} else {
		// 从 rspMap 中找到了响应
		originMsg, originErr = types.DNSRspToMsg(originRsp)
	}
	// 检查是否至少有一个响应可用
	if originErr != nil && testErr != nil {
		return nil, fmt.Errorf("firstCmp: both origin and test failed: origin=%v, test=%v", originErr, testErr)
	}
	// 执行对比
	diffCode := uint32(0)
	err = cmper.Compare(originMsg, testMsg, &diffCode)

	// 构造结果
	result := &cmpResult{
		originMsg: originMsg,
		testMsg:   testMsg,
		diffCode:  diffCode,
	}
	if len(reqMsg.Question) > 0 {
		result.domain = reqMsg.Question[0].Name
		result.dnsID = reqMsg.Id
		result.qtype = reqMsg.Question[0].Qtype
	}

	return result, err
}

// digAndCmp 执行单次请求和对比
func digAndCmp(req *types.DNSReq) (*cmpResult, error) {
	if testIP == "" || originIP == "" {
		return nil, fmt.Errorf("testIP or originIP is empty")
	}
	// 使用 WaitGroup 并行发送请求
	var wg sync.WaitGroup
	var testRsp, originRsp *types.DNSRsp
	var terr, oerr error

	wg.Add(2)
	// 并行发送请求到测试服务器
	go func() {
		defer func() {
			if r := recover(); r != nil {
				terr = fmt.Errorf("test server request panic: %v", r)
			}
			wg.Done()
		}()
		testRsp, terr = dnet.SendAndRecv(req, testIP)
	}()
	// 并行发送请求到线上机器
	go func() {
		defer func() {
			if r := recover(); r != nil {
				oerr = fmt.Errorf("origin server request panic: %v", r)
			}
			wg.Done()
		}()
		originRsp, oerr = dnet.SendAndRecv(req, originIP)
	}()
	wg.Wait()

	if terr != nil || oerr != nil {
		return nil, fmt.Errorf("SendAndRecv error: %v, %v", terr, oerr)
	}
	// 转换为 dns.Msg
	originMsg, oerr := types.DNSRspToMsg(originRsp)
	testMsg, terr := types.DNSRspToMsg(testRsp)
	if oerr != nil && terr != nil { //一个没问题就继续对比
		return nil, fmt.Errorf("DNSRspToMsg error: %v, %v", oerr, terr)
	}
	// 执行对比
	diffCode := uint32(0)
	err := cmper.Compare(originMsg, testMsg, &diffCode)

	// 提取域名和其他信息
	result := &cmpResult{
		originMsg: originMsg,
		testMsg:   testMsg,
		diffCode:  diffCode,
	}
	// 优先使用 originMsg 的信息，如果为空则尝试使用 testMsg
	if originMsg != nil && len(originMsg.Question) > 0 {
		result.domain = originMsg.Question[0].Name
		result.dnsID = originMsg.Id
		result.qtype = originMsg.Question[0].Qtype
	} else if testMsg != nil && len(testMsg.Question) > 0 {
		result.domain = testMsg.Question[0].Name
		result.dnsID = testMsg.Id
		result.qtype = testMsg.Question[0].Qtype
	}

	return result, err
}

// retryCmp 执行重试对比（各发送两次请求）
// 本函数不返回 error，如果出错了就是 result 的切片长度为空
// 如果重试一次就一样了就不用继续重试了
func retryCmp(req *types.DNSReq) []*cmpResult {
	results := make([]*cmpResult, 0, 2)
	for i := 0; i < 2; i++ {
		result, err := digAndCmp(req)
		if err != nil || result == nil {
			logrus.Warnf("Retry comparison %d failed: %v", i+1, err)
			continue
		}
		results = append(results, result)
		if (result.diffCode & cmper.DiffUnexpectedMask) == 0 {
			return results
		}
	}
	return results
}

// crossCmp 执行交叉对比
// 将第一次的originMsg和第二次的testMsg对比，以及第一次的testMsg和第二次的originMsg对比
// 如果任意一次交叉对比没有差异，返回diffCode为0；否则返回最后一次的diffCode
func crossCmp(results []*cmpResult) uint32 {
	if len(results) < 2 {
		return 0
	}

	// 安全检查：确保有足够的非空消息进行交叉对比
	if results[0] == nil || results[1] == nil {
		logrus.Warnf("Cross comparison skipped: nil results")
		return 0
	}
	if results[0].originMsg == nil || results[0].testMsg == nil ||
		results[1].originMsg == nil || results[1].testMsg == nil {
		logrus.Warnf("Cross comparison skipped: missing messages")
		return 0
	}

	// 第一次交叉对比：results[0].originMsg vs results[1].testMsg
	crossCode1 := uint32(0)
	err := cmper.Compare(results[0].originMsg, results[1].testMsg, &crossCode1)
	if err != nil {
		logrus.Warnf("Cross comparison 1 failed: %v", err)
	} else if (crossCode1 & cmper.DiffUnexpectedMask) == 0 {
		// 第一次交叉对比没有差异，直接返回0
		return 0
	}

	// 第二次交叉对比：results[1].originMsg vs results[0].testMsg
	crossCode2 := uint32(0)
	err = cmper.Compare(results[1].originMsg, results[0].testMsg, &crossCode2)
	if err != nil {
		logrus.Warnf("Cross comparison 2 failed: %v", err)
	} else if (crossCode2 & cmper.DiffUnexpectedMask) == 0 {
		// 第二次交叉对比没有差异，返回0
		return 0
	}

	// 两次交叉对比都有差异，返回最后一次的diffCode
	return crossCode2
}

// mergeAnswers 合并多个 dns.Msg 的 Answer 段
func mergeAnswers(msgs []*dns.Msg) []dns.RR {
	if len(msgs) == 0 {
		return nil
	}

	// 直接合并所有 Answer，不去重
	answers := make([]dns.RR, 0)
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		answers = append(answers, msg.Answer...)
	}

	return answers
}

// cmpMergeAnswer 仅对比 Answer 段
func cmpMergeAnswer(originAnswers, testAnswers []dns.RR) uint32 {
	diffCode := uint32(0)
	err := cmper.CmpAnswers(originAnswers, testAnswers, &diffCode)
	if err != nil {
		logrus.Warnf("CmpAnswers error: %v", err)
	}
	return diffCode
}

// resultStatDiffSave 处理差异结果（保存和统计）
func resultStatDiffSave(result *cmpResult) {
	if result == nil {
		return
	}

	// 应用白名单过滤
	originalDiffCode := result.diffCode
	if result.diffCode != 0 && len(result.domain) > 0 {
		result.diffCode = cmper.ApplyWhitelist(result.diffCode, result.domain)
		if originalDiffCode != result.diffCode {
			logrus.Infof("Whitelist filtered diffCode from 0x%X to 0x%X for domain %s",
				originalDiffCode, result.diffCode, result.domain)
		}
	}

	// 如果有非预期差异，保存结果
	if (result.diffCode & cmper.DiffUnexpectedMask) != 0 {
		diffElem := types.SaveChan{
			Old: result.originMsg,
			New: result.testMsg,
		}
		saveChan <- diffElem
		logrus.WithFields(logrus.Fields{
			"dnsid":    result.dnsID,
			"domain":   result.domain,
			"diffCode": fmt.Sprintf("0x%X", result.diffCode),
		}).Info("Consumer: diff not match expected")
	}

	// 统计
	if len(result.domain) > 0 {
		statistics.GetStat().Add(result.qtype, result.domain, result.diffCode, cmper.DiffUnexpectedMask)
	}
}
