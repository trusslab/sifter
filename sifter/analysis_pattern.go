package sifter

import (
	"fmt"
	"math"
	"sort"

	"github.com/google/syzkaller/prog"
)

type Grouping int

const (
	TimeGrouping Grouping = iota
	SyscallGrouping
)

type GroupingMethod interface {
	setThreshold(th uint64)
	toBreakDown(te *TraceEvent) bool
	update(te *TraceEvent)
	reset()
}

type TimeGroupingMethod struct {
	threshold uint64
	ts        map[uint64]uint64
}

func newTimeGroupingMethod() *TimeGroupingMethod {
	tg := new(TimeGroupingMethod)
	tg.ts = make(map[uint64]uint64)
	return tg
}

func (tg *TimeGroupingMethod) setThreshold(th uint64) {
	tg.threshold = th
}

func (tg *TimeGroupingMethod) toBreakDown(te *TraceEvent) bool {
	return te.ts - tg.ts[te.id] > tg.threshold
}

func (tg *TimeGroupingMethod) update(te *TraceEvent) {
	switch te.typ {
	case 0:
		for pid, _ := range tg.ts {
			tg.ts[pid] = 0
		}
	case 1:
		tg.ts[te.id] = te.ts
	}
}

func (tg *TimeGroupingMethod) reset() {
	tg.ts = make(map[uint64]uint64)
}

type SyscallGroupingMethod struct {
	threshold uint64
	counter   map[uint64]uint64
}

func newSyscallGroupingMethod() *SyscallGroupingMethod {
	sg := new(SyscallGroupingMethod)
	sg.counter = make(map[uint64]uint64)
	return sg
}

func (sg *SyscallGroupingMethod) setThreshold(th uint64) {
	sg.threshold = th
}

func (sg *SyscallGroupingMethod) toBreakDown(te *TraceEvent) bool {
	return sg.counter[te.id] > sg.threshold
}

func (sg *SyscallGroupingMethod) update(te *TraceEvent) {
	switch te.typ {
	case 0:
		for pid, _ := range sg.counter {
			sg.counter[pid] = sg.threshold + 1
		}
	case 1:
		sg.counter[te.id] = 0
	case 2:
		sg.counter[te.id] += 1
	}
}

func (sg *SyscallGroupingMethod) reset() {
	sg.counter = make(map[uint64]uint64)
}

type TaggedSyscall struct {
	syscall *Syscall
	tags	[]int
}

func (a *PatternAnalysis) NewTaggedSyscall(s *Syscall, t []int) *TaggedSyscall {
	if _, ok := a.taggedSyscalls[s]; !ok {
		a.taggedSyscalls[s] = make(map[string]*TaggedSyscall)
	}

	if _, ok := a.taggedSyscalls[s][fmt.Sprint(t)]; !ok {
		newTaggedSyscall := new(TaggedSyscall)
		newTaggedSyscall.syscall = s
		newTaggedSyscall.tags = append([]int(nil), t...)
		a.taggedSyscalls[s][fmt.Sprint(t)] = newTaggedSyscall
	}

	return a.taggedSyscalls[s][fmt.Sprint(t)]
}

func (a *TaggedSyscall) Equal(b *TaggedSyscall, tagsMask []bool) bool {
	if a.syscall != b.syscall {
		return false
	}

	if len(a.tags) != len(b.tags) {
		return false
	}

	for i, _ := range a.tags {
		if (tagsMask == nil || !tagsMask[i]) && a.tags[i] != b.tags[i] {
			return false
		}
	}
	return true
}

type TaggedSyscallNode struct {
	next     []*TaggedSyscallNode
	syscall  *TaggedSyscall
	flag     AnalysisFlag
	tag      int
	events   []*TraceEvent
	seqStart *TaggedSyscallNode
}

func NewTaggedSyscallNode(n *TaggedSyscallNode) *TaggedSyscallNode {
	newNode := new(TaggedSyscallNode)
	newNode.syscall = n.syscall
	newNode.flag = n.flag
	newNode.tag = n.tag
	newNode.next = make([]*TaggedSyscallNode, 0)
	return newNode
}

func NewTaggedSyscallEndNode(flag AnalysisFlag, tag int) *TaggedSyscallNode {
	newEndNode := new(TaggedSyscallNode)
	newEndNode.syscall = new(TaggedSyscall)
	newEndNode.flag = flag
	newEndNode.tag = tag
	return newEndNode
}

func (a *PatternAnalysis) newTaggedSyscallEndNode(flag AnalysisFlag) *TaggedSyscallNode {
	newEndNode := NewTaggedSyscallEndNode(flag, a.tagCounter)
	a.tagCounter += 1
	return newEndNode
}

func (n *TaggedSyscallNode) findChildWithSyscall(s *Syscall) int {
	for i, next := range n.next {
		if next.syscall.syscall == s {
			return i
		}
	}
	return -1
}

func (n *TaggedSyscallNode) findChild(s *TaggedSyscall) int {
	for i, next := range n.next {
		if next.syscall.Equal(s, nil) {
			return i
		}
	}
	return -1
}

func (n *TaggedSyscallNode) findEndChild() int {
	for i, next := range n.next {
		if next.syscall.syscall == nil {
			return i
		}
	}
	return -1
}

func (n *TaggedSyscallNode) isLeaf() bool {
	return len(n.next) == 1 && n.findEndChild() >= 0
}

func (n *TaggedSyscallNode) String() string {
	if n.syscall.syscall == nil {
		return "*"
	} else {
		return fmt.Sprintf("%v%x", n.syscall.syscall.name, n.syscall.tags)
	}
}

type AnalysisUnit int

const (
	ProcessLevel AnalysisUnit = iota
	TraceLevel
)

type AnalysisUnitKey struct {
	trace *Trace
	fd   uint64
	pid  uint64
}

func (k AnalysisUnitKey) String() string {
	return fmt.Sprintf("%v tgid:%d pid:%d fd:%d", k.trace.name, uint32(k.pid), k.pid >> 32, k.fd)
}

func (a *PatternAnalysis) newAnalysisUnitKey(te *TraceEvent) (bool, AnalysisUnitKey) {
	if regID, fd := te.GetFD(); regID != -1 {
		switch a.unitOfAnalysis {
		case ProcessLevel:
			return true, AnalysisUnitKey{te.trace, fd, te.id}
		case TraceLevel:
			return true, AnalysisUnitKey{te.trace, fd, 0}
		}
	}
	return false, AnalysisUnitKey{te.trace, 0, 0}
}

type FilterPolicy int

const (
	ShortSeqWithInterSeq FilterPolicy = iota
	LongSeq
)

type FilterState struct {
	lastSeqId        int
	lastNode         *TaggedSyscallNode
	recordedSeqs     map[int]bool
	pid              uint64
}

type Seq struct {
	id int
	ts uint64
}

type PatternAnalysis struct {
	taggedSyscalls    map[*Syscall]map[string]*TaggedSyscall

	groupingMethods   map[Grouping]GroupingMethod
	lastNodeOfPid     map[uint64]*TaggedSyscallNode
	seqTreeRoot       *TaggedSyscallNode
	patTreeRoot       *TaggedSyscallNode
	seqSeqTreeRoot    *TaggedSyscallNode
	tagCounter        int

	unitOfAnalysis    AnalysisUnit

	seqInterval       map[AnalysisUnitKey]map[int][]uint64
	seqOccurence      map[AnalysisUnitKey]map[int]int
	seqOrder          map[int]map[int]int
	seqOrderCounter   map[int]map[int]int
	seqOrderTh        float64

	keySeqs           map[AnalysisUnitKey][]Seq
	seqSeqGraph       map[int]map[int][]int

	uniqueSyscallList []*TaggedSyscall
	uniqueSyscallIDMap map[*TaggedSyscall]int
	seqTags           []int
	seqTreeList       [][]*TaggedSyscallNode
	seqOrderList      map[int]uint64
	seqSeqList        map[int]uint64

	filterPolicy      FilterPolicy
	filterStates      map[AnalysisUnitKey]*FilterState
	filterDelayedSyscalls  []*TraceEvent
	seqPolicyTreeRoot *TaggedSyscallNode

	debugEnable       bool
}

func (a *PatternAnalysis) String() string {
	return "pattern analysis"
}

func (a *PatternAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.taggedSyscalls = make(map[*Syscall]map[string]*TaggedSyscall)
	a.lastNodeOfPid = make(map[uint64]*TaggedSyscallNode)
	a.seqTreeRoot = new(TaggedSyscallNode)
	a.seqTreeRoot.syscall = new(TaggedSyscall)
	a.patTreeRoot = new(TaggedSyscallNode)
	a.patTreeRoot.syscall = new(TaggedSyscall)
	a.seqSeqTreeRoot = new(TaggedSyscallNode)
	a.seqSeqTreeRoot.syscall = new(TaggedSyscall)
	a.seqInterval = make(map[AnalysisUnitKey]map[int][]uint64)
	a.seqOccurence = make(map[AnalysisUnitKey]map[int]int)
	a.seqOrder = make(map[int]map[int]int)
	a.seqOrderCounter = make(map[int]map[int]int)
	a.filterStates = make(map[AnalysisUnitKey]*FilterState)
	a.SetFilterPolicy(a.filterPolicy)

	a.seqTreeList = make([][]*TaggedSyscallNode, 0)
	a.uniqueSyscallList = make([]*TaggedSyscall, 0)
	a.uniqueSyscallIDMap = make(map[*TaggedSyscall]int)
	a.seqOrderList = make(map[int]uint64)
	a.seqSeqList = make(map[int]uint64)

	a.keySeqs = make(map[AnalysisUnitKey][]Seq)
	a.seqSeqGraph = make(map[int]map[int][]int)

	a.debugEnable = false
}

func (a *PatternAnalysis) SetFilterPolicy(p FilterPolicy) {
	a.filterPolicy = p

	switch p {
	case ShortSeqWithInterSeq:
		a.seqPolicyTreeRoot = a.seqTreeRoot
	case LongSeq:
		a.seqPolicyTreeRoot = a.seqSeqTreeRoot
	default:
		fmt.Printf("Invalid sequence policy!")
	}
}

func (a *PatternAnalysis) SetPatternOrderThreshold(th float64) {
	a.seqOrderTh = th
}

func (a *PatternAnalysis) SetUnitOfAnalysis(u AnalysisUnit) {
	a.unitOfAnalysis = u
}

func (a *PatternAnalysis) SetGroupingThreshold (g Grouping, th uint64) {
	if a.groupingMethods == nil {
		a.groupingMethods = make(map[Grouping]GroupingMethod)
	}

	switch g {
	case TimeGrouping:
		a.groupingMethods[g] = newTimeGroupingMethod()
	case SyscallGrouping:
		a.groupingMethods[g] = newSyscallGroupingMethod()
	default:
		fmt.Printf("Invalid grouping method!")
	}

	a.groupingMethods[g].setThreshold(th)
}

func (a *PatternAnalysis) toBreakDown(te *TraceEvent) bool {
	breakDown := false
	for _, gm := range a.groupingMethods {
		if gm.toBreakDown(te) {
			breakDown = true
		}
	}
	return breakDown
}

func (a *PatternAnalysis) buildSeqTree(te *TraceEvent) {
	if (te.flag & TraceEventFlagBadData) != 0 {
		return
	}

	if te.typ == 0 {
		for pid, n := range a.lastNodeOfPid {
			if n != a.seqTreeRoot {
				if idx := n.findEndChild(); idx == -1 {
					newEndNode := a.newTaggedSyscallEndNode(TrainFlag)
					n.next = append(n.next, newEndNode)
					a.lastNodeOfPid[pid] = a.seqTreeRoot
				}
			}
		}
	} else if te.typ == 1 || (te.typ == 2 && (te.flag & TraceEventFlagUseFD) != 0) {
		_, key := a.newAnalysisUnitKey(te)
		if _, ok := a.seqInterval[key]; !ok {
//			fmt.Printf("new key %v %d\n", te.info.name, fd)
			a.seqInterval[key] = make(map[int][]uint64)
			a.seqOccurence[key] = make(map[int]int)
		}

		if _, ok := a.lastNodeOfPid[te.id]; ok {
			if a.toBreakDown(te) {
				if a.lastNodeOfPid[te.id] != a.seqTreeRoot {
					if idx := a.lastNodeOfPid[te.id].findEndChild(); idx == -1 {
						newEndNode := a.newTaggedSyscallEndNode(TrainFlag)
						a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newEndNode)
					}
					a.lastNodeOfPid[te.id] = a.seqTreeRoot
				}
			} else if idx := a.lastNodeOfPid[te.id].findEndChild(); idx != -1 && a.lastNodeOfPid[te.id] != a.seqTreeRoot {
				a.lastNodeOfPid[te.id] = a.seqTreeRoot
			}
		} else {
//			fmt.Printf("new pid %v %d\n", te.info.name, te.id)
			a.lastNodeOfPid[te.id] = a.seqTreeRoot
		}

		if idx := a.lastNodeOfPid[te.id].findChild(a.NewTaggedSyscall(te.syscall, te.tags)); idx != -1 {
			a.lastNodeOfPid[te.id] = a.lastNodeOfPid[te.id].next[idx]
		} else {
			newNextNode := new(TaggedSyscallNode)
			newNextNode.syscall = a.NewTaggedSyscall(te.syscall, te.tags)
			newNextNode.flag = TrainFlag
			//newNextNode.tag = a.tagCounter
			//a.tagCounter += 1
			a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newNextNode)
			a.lastNodeOfPid[te.id] = newNextNode
		}
		a.lastNodeOfPid[te.id].events = append(a.lastNodeOfPid[te.id].events, te)
	}

	for _, gm := range a.groupingMethods {
		gm.update(te)
	}

	return
}

func (a *PatternAnalysis) Reset() {
	a.lastNodeOfPid = make(map[uint64]*TaggedSyscallNode)
	a.filterStates = make(map[AnalysisUnitKey]*FilterState)
	a.debugEnable = false

	for _, gm := range a.groupingMethods {
		gm.reset()
	}
}

func (a *PatternAnalysis) potentialSeqIds(n *TaggedSyscallNode, seqIds *[]int) {
	if idx := n.findEndChild(); idx != -1 {
		*seqIds = append(*seqIds, n.next[idx].tag)
		return
	}

	for _, next := range n.next {
		a.potentialSeqIds(next, seqIds)
	}
}

func (a *PatternAnalysis) checkInterSeqOrderPolicy(seqId int, filterState *FilterState) bool {
	var seqOrderViolated []int
	for seqIdRecorded, _ := range filterState.recordedSeqs {
		order := a.seqOrder[seqIdRecorded][seqId]
		//if seq != seqId && (order == 0 || order == 2) {
		if seqIdRecorded != seqId && order == 2 {
			seqOrderViolated = append(seqOrderViolated, seqIdRecorded)
		}
	}
	return len(seqOrderViolated) == 0
}

func (a *PatternAnalysis) checkInterSeqSeqPolicy(seqId int, filterState *FilterState) bool {
	if _, ok := a.seqSeqGraph[filterState.lastSeqId][-1]; ok {
		return true
	}
	ctr, ok := a.seqSeqGraph[filterState.lastSeqId][seqId]
	return (ok && ctr[0] != 0) || filterState.lastSeqId == 0
}

func (a *PatternAnalysis) testFilterPolicy(te *TraceEvent) (string, int, int) {
	errMsg := ""
	errNum := 0
	delayNum := 0

	if te.typ == 0 {
		if te.id == 0x80010000 {
			for pid, _ := range a.lastNodeOfPid {
				a.lastNodeOfPid[pid] = a.seqPolicyTreeRoot
			}
		}
	} else if te.typ == 1 || (te.typ == 2 && (te.flag & TraceEventFlagUseFD) != 0) {
start:
		_, key := a.newAnalysisUnitKey(te)
		if _, ok := a.filterStates[key]; !ok {
			a.filterStates[key] = new(FilterState)
			a.filterStates[key].lastNode = a.seqPolicyTreeRoot
			a.filterStates[key].recordedSeqs = make(map[int]bool)
		}

		filterState := a.filterStates[key]

		if filterState.pid != 0 && filterState.pid != te.id {
			errMsg += fmt.Sprintf("syscall delayed")
			delayNum += 1
			a.filterDelayedSyscalls = append(a.filterDelayedSyscalls, te)
		} else {
			if idx := filterState.lastNode.findChild(a.NewTaggedSyscall(te.syscall, te.tags)); idx != -1 {
				hasValidSeq := false
				var seqIds []int
				a.potentialSeqIds(filterState.lastNode.next[idx], &seqIds)
				for _, seqId := range seqIds {
					if a.checkInterSeqOrderPolicy(seqId, filterState) && a.checkInterSeqSeqPolicy(seqId, filterState) {
						hasValidSeq = true
					}
				}

				if a.filterPolicy == LongSeq {
					hasValidSeq = true
				}
				if !hasValidSeq {
					var recordedSeqIds []int
					for k, _ := range filterState.recordedSeqs {
						recordedSeqIds = append(recordedSeqIds, k)
					}
					errMsg += fmt.Sprintf("no seq in seq%x satisfies inter-seq order with seq%x and inter-seq seq with seq[%x]", seqIds, recordedSeqIds, filterState.lastSeqId)
					errNum += 1
				} else {
					if endIdx := filterState.lastNode.next[idx].findEndChild(); endIdx != -1 {
						filterState.recordedSeqs[seqIds[0]] = true
						filterState.lastNode = a.seqPolicyTreeRoot
						filterState.lastSeqId = seqIds[0]
						filterState.pid = 0

						if len(a.filterDelayedSyscalls) != 0 {
							delay := te.ts
							te, a.filterDelayedSyscalls = a.filterDelayedSyscalls[0], a.filterDelayedSyscalls[1:]
							delay = delay - te.ts
							errMsg += fmt.Sprintf("process delayed syscall at [%v.%09d] after %v ns. ", te.ts/1000000000, te.ts%1000000000, delay)
							delayNum += 1
							goto start
						}
					} else {
						filterState.pid = te.id
						filterState.lastNode = filterState.lastNode.next[idx]

						if len(a.filterDelayedSyscalls) != 0 {
							for i, delayedSyscall := range a.filterDelayedSyscalls {
								if delayedSyscall.id == te.id {
									delay := te.ts
									te = a.filterDelayedSyscalls[i]
									a.filterDelayedSyscalls = append(a.filterDelayedSyscalls[:i], a.filterDelayedSyscalls[i+1:]...)
									delay = delay - te.ts
									errMsg += fmt.Sprintf("process delayed syscall at [%v.%09d] after %v ns. ", te.ts/1000000000, te.ts%1000000000, delay)
									delayNum += 1
									goto start
								}
							}
						}
					}
				}
			} else {
				errMsg += fmt.Sprintf("%v->%v%v no matching pattern", filterState.lastNode, te.syscall.name, te.tags)
				errMsg += fmt.Sprintf(" valid next(")
				for i, nn := range filterState.lastNode.next {
					errMsg += fmt.Sprintf("%v", nn)
					if i != len(filterState.lastNode.next)-1 {
						errMsg += fmt.Sprintf(", ")
					}
				}
				errMsg += fmt.Sprintf(")")
				errNum += 1
			}
		}
	}
	return errMsg, errNum, delayNum
}

func (a *PatternAnalysis) testSeqTreeModel(te *TraceEvent) (string, int) {
	errMsg := ""
	errNum := 0
	if te.typ == 0 {
		if te.id == 0x80010000 {
			for pid, _ := range a.lastNodeOfPid {
				a.lastNodeOfPid[pid] = a.seqTreeRoot
			}
		}
	} else if te.typ == 1 {
		if _, ok := a.lastNodeOfPid[te.id]; !ok {
			a.lastNodeOfPid[te.id] = a.seqTreeRoot
		}

//		if idx := a.lastNodeOfPid[te.id].findEndChild(); a.lastNodeOfPid[te.id] != a.seqTreeRoot && idx != -1 {
//			a.lastNodeOfPid[te.id] = a.seqTreeRoot
//		}

		if _, ok := a.lastNodeOfPid[te.id]; ok {
			if a.toBreakDown(te) {
				if a.lastNodeOfPid[te.id].findEndChild() == -1 && a.lastNodeOfPid[te.id] != a.seqTreeRoot {
					errMsg += fmt.Sprintf("syscall sequence ended unexpectedly. ")
					errNum += 1
				}
				a.lastNodeOfPid[te.id] = a.seqTreeRoot
			} else if a.lastNodeOfPid[te.id].findEndChild() != -1 && a.lastNodeOfPid[te.id] != a.seqTreeRoot {
				a.lastNodeOfPid[te.id] = a.seqTreeRoot
			}
		} else {
			a.lastNodeOfPid[te.id] = a.seqTreeRoot
		}

		if idx := a.lastNodeOfPid[te.id].findChild(a.NewTaggedSyscall(te.syscall, te.tags)); idx != -1 {
			a.lastNodeOfPid[te.id] = a.lastNodeOfPid[te.id].next[idx]
		} else {
			errMsg += fmt.Sprintf("%v->%v%v no matching pattern", a.lastNodeOfPid[te.id], te.syscall.name, te.tags)
			errMsg += fmt.Sprintf(" valid next(")
			for i, nn := range a.lastNodeOfPid[te.id].next {
				errMsg += fmt.Sprintf("%v", nn)
				if i != len(a.lastNodeOfPid[te.id].next)-1 {
					errMsg += fmt.Sprintf(", ")
				}
			}
			errMsg += fmt.Sprintf(")")
			errNum += 1
		}
	}

	for _, gm := range a.groupingMethods {
		gm.update(te)
	}

	return errMsg, errNum
}

func (a *PatternAnalysis) ProcessTraceEvent(te *TraceEvent, flag AnalysisFlag, opt int) (string, int, int) {
	msg := ""
	update := 0
	delay := 0

	if flag == TrainFlag {
		a.buildSeqTree(te)
	} else if flag == TestFlag {
		//msg, update = a.testSeqTreeModel(te)
		a.unitOfAnalysis = TraceLevel
		msg, update, delay = a.testFilterPolicy(te)
	}
	return msg, update, delay
}

func (a *PatternAnalysis) _MergeTrees(dst *TaggedSyscallNode, src *TaggedSyscallNode, root *TaggedSyscallNode, depth *int) {
	*depth += 1
	if *depth != 1 {//&& dst.syscall.Equal(src.syscall) {
		dst.events = append(dst.events, src.events...)
	}
//	fmt.Printf("merge (%v to %v), ", src, dst)
//	for _, srcNext := range src.next {
//		if *depth == 1 && srcNext.syscall.syscall == nil {
//			continue
//		}
//
//		if idx := dst.findChild(srcNext.syscall); idx != -1 {
//			if dst.findEndChild() == -1 || dst == root {
//				a._MergeTrees(dst.next[idx], srcNext, root, depth)
//			} else {
//				newDepth := 0
//				a._MergeTrees(root, src, root, &newDepth)
//			}
//		} else {
//			dst.next = append(dst.next, srcNext)
//		}
//	}
	if (dst.findEndChild() == -1 && src.findEndChild() == -1) || dst == root {
		for _, srcNext := range src.next {
			if *depth == 1 && srcNext.syscall.syscall == nil {
				continue
			}

			if idx := dst.findChild(srcNext.syscall); idx != -1 {
				a._MergeTrees(dst.next[idx], srcNext, root, depth)
			} else {
				dst.next = append(dst.next, srcNext)
			}
		}
	} else {
		newDepth := 0
		a._MergeTrees(root, src, root, &newDepth)
	}

	if *depth == 1 {
		if idx := src.findEndChild(); idx >= 0 {
			src.next = []*TaggedSyscallNode{src.next[idx]}
		} else {
			src.next = []*TaggedSyscallNode{a.newTaggedSyscallEndNode(TrainFlag)}
		}
	}
	*depth -= 1
//	fmt.Printf("return %v", *depth)
}

func (a *PatternAnalysis) MergeTrees(dst *TaggedSyscallNode, src *TaggedSyscallNode, root *TaggedSyscallNode) {
	depth := 0
	a._MergeTrees(dst, src, root, &depth)
}

func (a *PatternAnalysis) getPatternEnd(sn *TaggedSyscallNode, pn *TaggedSyscallNode) *TaggedSyscallNode {
//	fmt.Printf("gp %v\n", sn)
	if matchIdx := pn.findChild(sn.syscall); matchIdx >= 0 {
		pn = pn.next[matchIdx]
		if pn.findEndChild() >= 0 {
//			fmt.Printf("gp match but has end\n")
			return sn
		} else if len(sn.next) == 1 {
//			fmt.Printf("gp match one\n")
			return a.getPatternEnd(sn.next[0], pn)
		} else {
			a.MergeTrees(a.patTreeRoot, pn, a.patTreeRoot)
//			fmt.Printf("gp match but no end\n")
			return sn
		}
	}
	return nil
}

func (a *PatternAnalysis) getPatternEnds(sn *TaggedSyscallNode, pn *TaggedSyscallNode, ends *[]*TaggedSyscallNode) {
//	fmt.Printf("gp %v\n", sn)
	if matchIdx := pn.findChild(sn.syscall); matchIdx >= 0 {
		pn = pn.next[matchIdx]
		if pn.findEndChild() >= 0 {
//			fmt.Printf("gp match end\n")
			*ends = append(*ends, sn)
			a.MergeTrees(a.patTreeRoot, pn, a.patTreeRoot)
		} else {
//			fmt.Printf("gp match but no end\n")
			for _, snNext := range sn.next {
				a.getPatternEnds(snNext, pn, ends)
			}
		}
	}
}

func (a *PatternAnalysis) purgeTree(osn *TaggedSyscallNode, opn *TaggedSyscallNode) bool {
	purged := false
	for _, sn := range osn.next {
//		fmt.Printf("purge sn:%v opn:%v\n", sn, opn)
		ends := make([]*TaggedSyscallNode, 0)
		a.getPatternEnds(sn, a.patTreeRoot, &ends)

		if len(ends) != 0 {
			for _, ne := range ends {
				if ne.seqStart != sn {
					purged = true
				}
			}
		}

		if purged {
			for _, ne := range ends {
				if ne.seqStart != sn {
					ne.seqStart = sn
					a.MergeTrees(a.seqTreeRoot, ne, a.seqTreeRoot)
				}
			}
			if osn != a.seqTreeRoot {
				a.MergeTrees(a.seqTreeRoot, osn, a.seqTreeRoot)
			}
		} else if a.purgeTree(sn, a.patTreeRoot) {
			purged = true
		}
	}
	return purged
}

//func (a *PatternAnalysis) purgeTree(osn *TaggedSyscallNode, opn *TaggedSyscallNode) bool {
//	purged := false
//	for _, sn := range osn.next {
////		fmt.Printf("purge sn:%v opn:%v\n", sn, opn)
//		if ne := a.getPatternEnd(sn, a.patTreeRoot); ne != nil && ne.seqStart != sn {
////			fmt.Printf("pattern end:%v\n", ne)
//			ne.seqStart = sn
//			if idx := ne.findEndChild(); idx != -1 && len(ne.next) != 1 {
//				a.MergeTrees(a.seqTreeRoot, ne, a.seqTreeRoot)
////				fmt.Printf("\n")
//			}
//			if osn != a.seqTreeRoot {
//				a.MergeTrees(a.seqTreeRoot, osn, a.seqTreeRoot)
//			}
//			purged = true
//		} else if a.purgeTree(sn, a.patTreeRoot) {
//			purged = true
//		}
////		fmt.Printf("else\n")
//	}
//	return purged
//}

func (a *PatternAnalysis) extractPattern(osn *TaggedSyscallNode, opn *TaggedSyscallNode) bool {
	extracted := false
	for _, sn := range osn.next {
		pn := opn
//		fmt.Printf("extract sn:%v pn:%v ", sn, pn)
		if matchIdx := pn.findChild(sn.syscall); matchIdx >= 0 {
			pn = pn.next[matchIdx]
//			fmt.Printf("c1 \n")
		} else if pn.findEndChild() == -1 || pn == a.patTreeRoot {
//			fmt.Printf("c2 \n")
			extracted = true
			if sn.syscall.syscall == nil && pn != a.patTreeRoot {
				a.MergeTrees(a.patTreeRoot, pn, a.patTreeRoot)
//				fmt.Printf("\n")
				pn = pn.next[len(pn.next)-1]
			} else {
				pn.next = append(pn.next, NewTaggedSyscallNode(sn))
				pn = pn.next[len(pn.next)-1]
			}
		} else {
//			fmt.Printf("c3 \n")
			if sn.syscall.syscall != nil {
				if idx := a.patTreeRoot.findChild(sn.syscall); idx >= 0 {
					pn = a.patTreeRoot.next[idx]
				} else {
					pn.next = append(pn.next, NewTaggedSyscallNode(sn))
					pn = pn.next[len(pn.next)-1]
				}
			}
		}

		if a.extractPattern(sn, pn) {
			extracted = true
		}
	}
	return extracted
}

func getPidsUniqueString(n *TaggedSyscallNode) string {
	s := ""
	pidsUnique := true
	pidMap := make(map[uint64]bool)
	for _, te := range n.events {
		if _, ok := pidMap[te.id]; !ok {
			pidMap[te.id] = true
		} else {
			pidsUnique = false
			break
		}
	}
	if pidsUnique && len(n.events) != 0 {
		s += fmt.Sprintf(" [u]")
	}
	return s
}

func (n *TaggedSyscallNode) print(depth *int, depthsWithChildren map[int]bool, hasNext bool, a *PatternAnalysis) {
	*depth = *depth + 1

	s := ""
	if !hasNext {
		depthsWithChildren[*depth] = false
		s += "└"
	} else {
		depthsWithChildren[*depth] = true
		s += "├"
	}

	if n.syscall.syscall == nil {
		if len(n.next) != 0 {
			s += "start"
		} else {
			if n.flag == TrainFlag {
				s += fmt.Sprintf("[%v]end - seq%x", *depth, n.tag)
			} else if n.flag == TestFlag {
				s += fmt.Sprintf("[%v]end - seq%x*", *depth, n.tag)
			}
		}
	} else {
		s += fmt.Sprintf("[%v]%v%x (%v)", *depth, n.syscall.syscall.name, n.syscall.tags, len(n.events))
		s += fmt.Sprintf("%v", getPidsUniqueString(n))
	}

	indent := ""
	for i := 1; i < *depth; i++ {
		if depthsWithChildren[i] == true && i != *depth{
			indent += "|   "
		} else {
			indent += "    "
		}
	}
	fmt.Printf("%v%v\n", indent, s)

	for i, next := range n.next {
		next.print(depth, depthsWithChildren, i != len(n.next)-1, a)
	}

	*depth = *depth - 1
}

func (n *TaggedSyscallNode) Print(a *PatternAnalysis) {
	depth := 0
	depthsWithOtherChildren := make(map[int]bool)
	n.print(&depth, depthsWithOtherChildren, false, a)
}

func (a *PatternAnalysis) genTreeEdgeList(node *TaggedSyscallNode, nodeID map[*TaggedSyscallNode]int, nodeEdgeNext *[][]int) {
	for _, next := range node.next {
		if idx := next.findEndChild(); idx != -1 {
			*nodeEdgeNext = append(*nodeEdgeNext, []int{nodeID[node], a.uniqueSyscallIDMap[next.syscall], 0})
		} else {
			if _, ok := nodeID[next]; !ok {
				nodeID[next] = len(nodeID)
			}
			*nodeEdgeNext = append(*nodeEdgeNext, []int{nodeID[node], a.uniqueSyscallIDMap[next.syscall], nodeID[next]})
			a.genTreeEdgeList(next, nodeID, nodeEdgeNext)
		}
	}
}

func (a *PatternAnalysis) GetTreeEdgeList(root *TaggedSyscallNode) [][]int {
	nodeEdgeNext := make([][]int, 0)
	nodeID := make(map[*TaggedSyscallNode]int)
	nodeID[root] = 0
	a.genTreeEdgeList(root, nodeID, &nodeEdgeNext)
	return nodeEdgeNext
}

func (a *PatternAnalysis) genSeqTreeList(node *TaggedSyscallNode, nodeStack []*TaggedSyscallNode) {
	nodeStack = append(nodeStack, node)
	if idx := node.findEndChild(); idx != -1 && node != a.seqTreeRoot {
		var pattern []*TaggedSyscallNode
		for i, n := range nodeStack {
			if i != 0 {
				pattern = append(pattern, n)
			}
		}
		a.seqTreeList = append(a.seqTreeList, pattern)
		a.seqTags = append(a.seqTags, node.next[idx].tag)
	} else {
		for _, next := range node.next {
			a.genSeqTreeList(next, nodeStack)
		}
	}
	nodeStack = nodeStack[:len(nodeStack)-1]
}

func (a *PatternAnalysis) genUniqueNodeList(node *TaggedSyscallNode) {
	if node.syscall.syscall != nil {
		if _, ok := a.uniqueSyscallIDMap[node.syscall]; !ok {
			a.uniqueSyscallList = append(a.uniqueSyscallList, node.syscall)
			a.uniqueSyscallIDMap[node.syscall] = len(a.uniqueSyscallList)
		}
	}
	for _, next := range node.next {
		a.genUniqueNodeList(next)
	}
}

func (a *PatternAnalysis) genSeqOrderList() {
	seqOccurence := make(map[int][]int)
	for _, tag := range a.seqTags {
		seqOccurence[tag] = make([]int, 3)
	}
	for key, _ := range a.seqInterval {
		for _, tag := range a.seqTags {
			seqOccurence[tag][0] += a.seqOccurence[key][tag]
			if a.seqOccurence[key][tag] != 0 {
				seqOccurence[tag][1] += 1
			}
			if a.seqOccurence[key][tag] > 1 {
				seqOccurence[tag][2] = 1
			}
		}
	}
	for i, iTag := range a.seqTags {
		var order uint64
		for j, jTag := range a.seqTags {
			if i == j {
				if seqOccurence[jTag][2] == 0 {
					order = order | (1 << j)
				}
			} else {
				if a.seqOrder[iTag][jTag] == 1 {
					order = order | (1 << j)
				}
			}
		}
		a.seqOrderList[i] = order
	}
}

func (a *PatternAnalysis) genSeqSeqList() {
	for i, iTag := range a.seqTags {
		var nexts uint64
		for j, jTag := range a.seqTags {
			if _, ok := a.seqSeqGraph[iTag][-1]; ok {
				nexts = nexts | (1 << j)
			} else if stat, ok := a.seqSeqGraph[iTag][jTag]; ok && stat[0] > 0 {
				nexts = nexts | (1 << j)
			}
		}
		a.seqSeqList[i] = nexts
	}
}

func (a *PatternAnalysis) GetPatternTimeInterval(n *TaggedSyscallNode) {
	if idx := n.findEndChild(); idx != -1 && n != a.seqTreeRoot {
		tag := n.next[idx].tag
		fmt.Printf("get seq time interval of tag:%v len:%v\n", tag, len(n.events))
		for _, te := range n.events {
			_, key := a.newAnalysisUnitKey(te)
			if _, ok := a.seqInterval[key]; !ok {
				a.seqInterval[key] = make(map[int][]uint64)
				a.seqOccurence[key] = make(map[int]int)
			}
			if interval, ok := a.seqInterval[key][tag]; !ok {
				a.seqInterval[key][tag] = []uint64{te.ts, te.ts}
			} else {
				if te.ts < interval[0] {
					a.seqInterval[key][tag][0] = te.ts
				}
				if te.ts > interval[1] {
					a.seqInterval[key][tag][1] = te.ts
				}
			}
			a.seqOccurence[key][tag] += 1
		}
	}
	for _, next := range n.next {
		a.GetPatternTimeInterval(next)
	}
}

func (a *PatternAnalysis) AnalyzeInterSeqOrder() {
	a.GetPatternTimeInterval(a.seqTreeRoot)

	fmt.Printf("analysis unit keys:\n")
	for key, seqInterval := range a.seqInterval {
		fmt.Printf("%v\n", key)
		for i, ni := range seqInterval {
			if _, ok := a.seqOrder[i]; !ok {
				a.seqOrder[i] = make(map[int]int)
				a.seqOrderCounter[i] = make(map[int]int)
			}
			for j, nj := range seqInterval {
				if _, ok := a.seqOrder[i][j]; !ok {
					a.seqOrder[i][j] = 0
					a.seqOrderCounter[i][j] = 0
				}

				//if i == 5 {
				//	fmt.Printf("i:%v j:%v\n", ni, nj)
				//	fmt.Printf("%v\n", a.seqOrder[i][j])
				//}
				if i == j || (ni[0] == 0 && ni[1] == 0) || (nj[0] == 0 && nj[1] == 0) {
					continue
				} else if ni[1] < nj[0] {
					a.seqOrderCounter[i][j] += 1
					if a.seqOrder[i][j] == 0 || a.seqOrder[i][j] == 1 {
						a.seqOrder[i][j] = 1
					} else {
						a.seqOrder[i][j] = 3
					}
				} else if ni[0] > nj[1] {
					a.seqOrderCounter[i][j] += 1
					if a.seqOrder[i][j] == 0 || a.seqOrder[i][j] == 2 {
						a.seqOrder[i][j] = 2
					} else {
						a.seqOrder[i][j] = 3
					}
				} else {
					a.seqOrderCounter[i][j] += 1
					a.seqOrder[i][j] = 3
				}
			}
		}
	}

	var tags []int
	tagMax := 0
	for k, _ := range a.seqOrder {
		tags = append(tags, k)
		if k > tagMax {
			tagMax = k
		}
	}
	tagW := len(fmt.Sprintf("%x", tagMax))
	ctrMax := int(math.Pow(10, float64(tagW))-1)

	sort.Ints(tags)
	for i, tag := range tags {
		if i == 0 {
			fmt.Printf("%*d ", 2*tagW+19, tag)
		} else {
			fmt.Printf("%*x ", tagW, tag)
		}
	}
	seqOccurence := make(map[int][]int)
	for _, tag := range tags {
		seqOccurence[tag] = make([]int, 3)
	}
	for key, _ := range a.seqInterval {
		for _, tag := range tags {
			seqOccurence[tag][0] += a.seqOccurence[key][tag]
			if a.seqOccurence[key][tag] != 0 {
				seqOccurence[tag][1] += 1
			}
			if a.seqOccurence[key][tag] > 1 {
				seqOccurence[tag][2] = 1
			}
		}
	}
	fmt.Printf("\n")
	for _, ks := range tags {
		fmt.Printf("%*x (%8d/%4d) ", tagW, ks, seqOccurence[ks][0], seqOccurence[ks][1])
		if seqOccurence[ks][2] == 0 {
			fmt.Printf("u ")
		} else {
			fmt.Printf("  ")
		}
		for _, kd := range tags {
			vd := a.seqOrder[ks][kd]
			if vd == 0 {
				fmt.Printf("%*s ", tagW, "-")
			} else if vd == 1 {
				fmt.Printf("%*s ", tagW, ">")
			} else if vd == 2 {
				fmt.Printf("%*s ", tagW, "<")
			} else if vd == 3 {
				fmt.Printf("%*s ", tagW, " ")
			} else {
				fmt.Printf("%*d ", tagW, vd)
			}
		}
		fmt.Printf("\n")
		fmt.Printf("                      ")
		for _, kd := range tags {
			vd := a.seqOrderCounter[ks][kd]
			if a.seqOrder[ks][kd] == 1 || a.seqOrder[ks][kd] == 2 {
				n := 0
				if seqOccurence[ks][1] < seqOccurence[kd][1] {
					n = seqOccurence[ks][1]
				} else {
					n = seqOccurence[kd][1]
				}
				if vd < int(a.seqOrderTh * float64(n)) {
					a.seqOrder[ks][kd] = 3
					fmt.Printf("%*dt", tagW, vd)
				} else if vd <= ctrMax {
					fmt.Printf("%*d ", tagW, vd)
				} else {
					fmt.Printf("%d+", ctrMax)
				}
			} else {
				fmt.Printf("%*s ", tagW, " ")
			}
		}
		fmt.Printf("\n")
	}
}

func (a *PatternAnalysis) addSeqToSeqs(n *TaggedSyscallNode) {
	if idx := n.findEndChild(); idx != -1 && n != a.seqTreeRoot {
		tag := n.next[idx].tag
		for _, te := range n.events {
			_, key := a.newAnalysisUnitKey(te)
			a.keySeqs[key] = append(a.keySeqs[key], Seq{tag, te.ts})
		}
	}
	for _, next := range n.next {
		a.addSeqToSeqs(next)
	}
}

func (a *PatternAnalysis) getSeqNodes(node *TaggedSyscallNode, seq int) (*TaggedSyscallNode, *TaggedSyscallNode) {
	this := NewTaggedSyscallNode(node)
	if this.syscall.syscall == nil && this.tag == seq {
		return this, nil
	}

	for _, next := range node.next {
		if child, end := a.getSeqNodes(next, seq); child != nil {
			if child.syscall.syscall != nil {
				this.next = append(this.next, child)
				if this.syscall.syscall == nil {
					fmt.Printf("gsn start %v\n", child.syscall.syscall.name)
				} else {
					fmt.Printf("gsn %v %v\n", this.syscall.syscall.name, child.syscall.syscall.name)
				}
				return this, end
			} else {
				fmt.Printf("gsn %v end\n", this.syscall.syscall.name)
				return this, this
			}
		}
	}

	return nil, nil
}

func (a *PatternAnalysis) _buildSeqSeqTree(node *TaggedSyscallNode, seq int, seqsVisited *[]int) {
	*seqsVisited = append(*seqsVisited, seq)

	fmt.Printf("gsn %x \n", seq)
	start, end := a.getSeqNodes(a.seqTreeRoot, seq)
	if end != nil {
		fmt.Printf("gsn ret %v %v %v %v\n", node, start, end, start.next)
		a.MergeTrees(node, start, a.seqSeqTreeRoot)
		node = end
	}

	_, nextHasEnd := a.seqSeqGraph[seq][-1]
	_, nextHasSelf := a.seqSeqGraph[seq][seq]
	if !(nextHasEnd || nextHasSelf) {
		nextVisited := false
		for next, _ := range a.seqSeqGraph[seq] {
			for _, seqVisited := range *seqsVisited {
				if seqVisited == next {
					nextVisited = true
				}
			}
		}
		if !nextVisited {
			for next, _ := range a.seqSeqGraph[seq] {
				a._buildSeqSeqTree(node, next, seqsVisited)
			}
		}
	}
	*seqsVisited = (*seqsVisited)[:len(*seqsVisited)-1]
}

func (a *PatternAnalysis) buildSeqSeqTree() {
	a.seqSeqGraph[-1] = make(map[int][]int)
	for next, _ := range a.seqSeqGraph {
		if next != -1 {
			a.seqSeqGraph[-1][next] = make([]int, 2)
		}
	}

	seqVisited := make([]int, 0)
	a._buildSeqSeqTree(a.seqSeqTreeRoot, -1, &seqVisited)
}

func (a *PatternAnalysis) AnalyzeInterSeqSeq() {
	a.unitOfAnalysis = ProcessLevel
	a.addSeqToSeqs(a.seqTreeRoot)

	for key, _ := range a.keySeqs {
		sort.Slice(a.keySeqs[key], func(i, j int) bool {
			return a.keySeqs[key][i].ts < a.keySeqs[key][j].ts
		})
	}

	fmt.Printf("inter-seq seq debug:\n")
	for _, seqs := range a.keySeqs {
		var lastSeq Seq
		for _, seq := range seqs {
			fmt.Printf("%x %x %.9f\n", lastSeq.id, seq.id, float64(seq.ts)/1000000000)
			if _, ok := a.seqSeqGraph[lastSeq.id]; !ok {
				a.seqSeqGraph[lastSeq.id] = make(map[int][]int)
			}
			if _, ok := a.seqSeqGraph[lastSeq.id][seq.id]; !ok {
				a.seqSeqGraph[lastSeq.id][seq.id] = make([]int, 2)
			}
			a.seqSeqGraph[lastSeq.id][seq.id][0] += 1
			if a.seqSeqGraph[lastSeq.id][seq.id][1] < int(seq.ts - lastSeq.ts) {
				a.seqSeqGraph[lastSeq.id][seq.id][1] = int(seq.ts - lastSeq.ts)
			}
			lastSeq = seq
		}
	}

	for srcSeq, dstSeqs := range a.seqSeqGraph {
		for _, stat := range dstSeqs {
			//if stat[1] > 1000000 {
			if stat[1] > 250000000 {
				a.seqSeqGraph[srcSeq][-1] = make([]int, 2)
			}
		}
	}

	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Printf("inter-seq seq:\n")
	for src, dsts := range a.seqSeqGraph {
		fmt.Printf("%3x: ", src)
		if _, ok := a.seqSeqGraph[src][-1]; ok {
			fmt.Printf("drop all: ")
		}
		for dst, stat := range dsts {
			fmt.Printf("%3x(%d) ", dst, stat)
		}
		fmt.Printf("\n")
	}
	fmt.Print("--------------------------------------------------------------------------------\n")
}

func (a *PatternAnalysis) appendEndNode(n *TaggedSyscallNode, root *TaggedSyscallNode) {
	if idx := n.findEndChild(); idx != -1 {
		return
	} else if len(n.next) == 0 && n != root {
		newEndNode := a.newTaggedSyscallEndNode(TrainFlag)
		n.next = append(n.next, newEndNode)
		return
	}

	for _, next := range n.next {
		a.appendEndNode(next, root)
	}
}

//func (a *PatternAnalysis) getSyscallTags(node *TaggedSyscallNode, syscallTags *map[*Syscall][]map[int]bool) {
//	if node.syscall.syscall == nil && node != a.seqTreeRoot {
//		return
//	}
//
//	if (node.syscall.tags) != 0 {
//		if _, ok := syscallTags[node.syscall]; !ok {
//			syscallTags[node.syscall] = make([]map[int]bool, len(node.syscall.tags))
//			syscallTagsDrop[node.syscall] = make([]bool, len(node.syscall.tags))
//			for i, _ := range node.syscall.tags {
//				syscallTags[node.syscall][i] = make(map[int]bool)
//				syscallTagsDrop[node.syscall][i] = true
//			}
//		}
//		for i, tag := range node.syscall.tags {
//			syscallTags[node.syscall][i][tag] = true
//		}
//	}
//
//	for _, next := range n.next {
//		getSyscallTags(next, syscallTags)
//	}
//}
//
//func (a *PatternAnalysis) dropTags(node *TaggedSyscallNode, syscallTags *map[*Syscall][]map[int]bool, syscallTagsDrop *map[*Syscall][]bool) {
//	if node.syscall.syscall == nil && node != a.seqTreeRoot {
//		return
//	}
//
//	for syscall, tags := range syscallTags {
//		syscallInNext := false
//		syscallNexts := []*TaggedSyscall
//		//Check if all variants of a TaggedSyscall present in the next 
//		for _, next := node.next {
//			if next.syscall == sycall {
//				syscallInNext = true
//				for i, tag := range tags {
//					tags[i][node.syscall.tags[i]] = true
//				}
//				for _, nn := next.next {
//					syscallNexts = append(syscallNexts, nn)
//				}
//			}
//		}
//		if !syscallInNext {
//			continue
//		}
//
//		for i, tag := range tags {
//			allTagValuesPresent := true
//			for tv, present := range tag {
//				if !present {
//					allTagValuesPresent = false
//					break
//				}
//			}
//			if !allTagValuesPresent && syscallTagsDrop[node.syscall][i] {
//				syscallTagsDrop[node.syscall][i] = false
//			}
//		}
//
//		//Check if all variants have same nexts
//		for _, next := node.next {
//			if next.syscall == syscall
//			tags
//		}
//	}
//}
//
//func (a *PatternAnalysis) dedup() {
//	syscallTags := make(map[*Syscall][]map[int]bool)
//	syscallTagsDrop := make(map[*Syscall][]bool)
//	getSyscallTags(a.seqTreeRoot, syscallTags)
//	dropTags(syscallSeqTree, syscall, tagsMask)
//}

func (a *PatternAnalysis) getTaggedSyscallNexts(n *TaggedSyscallNode, syscallNexts map[*Syscall][]map[int]map[*TaggedSyscall]bool, syscallTagsDrop map[*Syscall][]bool) {
	if n.syscall.syscall == nil && n != a.seqTreeRoot {
		return
	}

	if len(n.syscall.tags) != 0 {
		if _, ok := syscallNexts[n.syscall.syscall]; !ok {
			syscallNexts[n.syscall.syscall] = make([]map[int]map[*TaggedSyscall]bool, len(n.syscall.tags))
			syscallTagsDrop[n.syscall.syscall] = make([]bool, len(n.syscall.tags))
			for i, _ := range n.syscall.tags {
				syscallNexts[n.syscall.syscall][i] = make(map[int]map[*TaggedSyscall]bool)
				syscallTagsDrop[n.syscall.syscall][i] = true
			}
		}
		for i, tag := range n.syscall.tags {
			if _, ok := syscallNexts[n.syscall.syscall][i][tag]; !ok {
				syscallNexts[n.syscall.syscall][i][tag] = make(map[*TaggedSyscall]bool)
			}
			for _, next := range n.next {
				if next.syscall.syscall == nil {
					syscallNexts[n.syscall.syscall][i][tag][nil] = true
				} else {
					syscallNexts[n.syscall.syscall][i][tag][next.syscall] = true
				}
			}
		}
	}

	for _, next := range n.next {
		a.getTaggedSyscallNexts(next, syscallNexts, syscallTagsDrop)
	}
}

func (a *PatternAnalysis) dropTags() {
	fmt.Printf("Dropping tags\n")
	taggedSyscallNexts := make(map[*Syscall][]map[int]map[*TaggedSyscall]bool)
	syscallTagsDrop := make(map[*Syscall][]bool)
	a.getTaggedSyscallNexts(a.seqTreeRoot, taggedSyscallNexts, syscallTagsDrop)
	for syscall, syscallNexts := range taggedSyscallNexts {
		fmt.Printf("%v: ", syscall.name)
		for tagi, tagvNexts := range syscallNexts {
			fmt.Printf("tag[%v] ", tagi)
			nextsRef := make(map[*TaggedSyscall]bool)
			for _, nexts := range tagvNexts {
				if len(nextsRef) == 0 {
					nextsRef = nexts
				} else {
					if fmt.Sprint(nexts) != fmt.Sprint(nextsRef) {
						fmt.Printf("x ")
						syscallTagsDrop[syscall][tagi] = false
					}
				}
			}
		}
		fmt.Printf("\n")
	}
}

func (a *PatternAnalysis) extractAndPurge() {
	a.appendEndNode(a.seqTreeRoot, a.seqTreeRoot)
	fmt.Print("sequence tree before purging\n")
	a.seqTreeRoot.Print(a)
//	i := 0
	for {
//		i += 1
//		fmt.Print("--------------------------------------------------------------------------------\n")
//		fmt.Printf("purging #%v\n", i)
		extracted := a.extractPattern(a.seqTreeRoot, a.patTreeRoot)
//		fmt.Print("--------------------------------------------------------------------------------\n")
//		fmt.Print("pattern tree\n")
//		a.patTreeRoot.Print(a)
//		fmt.Print("--------------------------------------------------------------------------------\n")
//		fmt.Print("sequence tree\n")
//		a.seqTreeRoot.Print(a)
		purged := a.purgeTree(a.seqTreeRoot, a.patTreeRoot)
//		fmt.Print("--------------------------------------------------------------------------------\n")
//		fmt.Printf("purging #%v purged=%v extracted=%v\n", i, purged, extracted)
//		fmt.Print("--------------------------------------------------------------------------------\n")
//		fmt.Print("pattern tree\n")
//		a.patTreeRoot.Print(a)
//		fmt.Print("--------------------------------------------------------------------------------\n")
//		fmt.Print("sequence tree\n")
//		a.seqTreeRoot.Print(a)
		if !purged && !extracted {
			break
		}
	}

	a.appendEndNode(a.seqTreeRoot, a.seqTreeRoot)
}

func (a *PatternAnalysis) PostProcess(opt int) {
	if opt == 0 {
		return
	}
	a.dropTags()

//	a.appendEndNode(a.seqTreeRoot, a.seqTreeRoot)
//	fmt.Print("sequence tree before purging\n")
//	a.seqTreeRoot.Print(a)
	a.unitOfAnalysis = TraceLevel
	a.seqInterval = make(map[AnalysisUnitKey]map[int][]uint64)
	a.seqOccurence = make(map[AnalysisUnitKey]map[int]int)
////	i := 0
//	for {
////		i += 1
////		fmt.Print("--------------------------------------------------------------------------------\n")
////		fmt.Printf("purging #%v\n", i)
//		extracted := a.extractPattern(a.seqTreeRoot, a.patTreeRoot)
////		fmt.Print("--------------------------------------------------------------------------------\n")
////		fmt.Print("pattern tree\n")
////		a.patTreeRoot.Print(a)
////		fmt.Print("--------------------------------------------------------------------------------\n")
////		fmt.Print("sequence tree\n")
////		a.seqTreeRoot.Print(a)
//		purged := a.purgeTree(a.seqTreeRoot, a.patTreeRoot)
////		fmt.Print("--------------------------------------------------------------------------------\n")
////		fmt.Printf("purging #%v purged=%v extracted=%v\n", i, purged, extracted)
////		fmt.Print("--------------------------------------------------------------------------------\n")
////		fmt.Print("pattern tree\n")
////		a.patTreeRoot.Print(a)
////		fmt.Print("--------------------------------------------------------------------------------\n")
////		fmt.Print("sequence tree\n")
////		a.seqTreeRoot.Print(a)
//		if !purged && !extracted {
//			break
//		}
//	}
//	a.appendEndNode(a.seqTreeRoot, a.seqTreeRoot)
	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Print("pattern tree\n")
	a.patTreeRoot.Print(a)
	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Print("sequence tree after purging\n")
	a.seqTreeRoot.Print(a)
	a.AnalyzeInterSeqOrder()
	a.AnalyzeInterSeqSeq()
	a.buildSeqSeqTree()
	a.appendEndNode(a.seqSeqTreeRoot, a.seqSeqTreeRoot)
	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Print("sequence tree after rebuild\n")
	a.seqSeqTreeRoot.Print(a)
	a.GenSeqPolicy()
}

func (a *PatternAnalysis) GenSeqPolicy() {
	fmt.Print("--------------------------------------------------------------------------------\n")
	nodeStack := make([]*TaggedSyscallNode, 0)
	a.genSeqTreeList(a.seqTreeRoot, nodeStack)
	a.genUniqueNodeList(a.seqTreeRoot)
	a.genSeqOrderList()
	a.genSeqSeqList()
	fmt.Print("syscalls:\n")
	for sci, sc := range a.uniqueSyscallList {
		fmt.Printf("%2d: %v%x\n", sci, sc.syscall.name, sc.tags)
	}
	fmt.Print("syscall seq tree:\n")
	for seqi, p := range a.seqTreeList {
		fmt.Printf("%2d: ", seqi)
		for _, s := range p {
			for sci, sc := range a.uniqueSyscallList {
				if s.syscall.Equal(sc, nil) {
					fmt.Printf("%2d ", sci)
					break
				}
			}
		}
		fmt.Print("\n")
	}
	fmt.Print("--------------------------------------------------------------------------------\n")
}

func (a *PatternAnalysis) PrintResult(v Verbose) {
//	fmt.Print("--------------------------------------------------------------------------------\n")
//	fmt.Print("sequence tree\n")
//	a.seqTreeRoot.Print(a)
	a.extractAndPurge()
//	fmt.Print("--------------------------------------------------------------------------------\n")
//	fmt.Print("pattern tree\n")
//	a.patTreeRoot.Print(a)
//	fmt.Print("--------------------------------------------------------------------------------\n")
//	fmt.Print("sequence tree after purging\n")
//	a.seqTreeRoot.Print(a)
}

func (a *PatternAnalysis) GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint {
	return nil
}
