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
	ts        map[uint32]uint64
}

func newTimeGroupingMethod() *TimeGroupingMethod {
	tg := new(TimeGroupingMethod)
	tg.ts = make(map[uint32]uint64)
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
	tg.ts = make(map[uint32]uint64)
}

type SyscallGroupingMethod struct {
	threshold uint64
	counter   map[uint32]uint64
}

func newSyscallGroupingMethod() *SyscallGroupingMethod {
	sg := new(SyscallGroupingMethod)
	sg.counter = make(map[uint32]uint64)
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
	sg.counter = make(map[uint32]uint64)
}

type TaggedSyscall struct {
	syscall *Syscall
	tags	[]int
}

func NewTaggedSyscall(s *Syscall, t []int) *TaggedSyscall {
	newTaggedSyscall := new(TaggedSyscall)
	newTaggedSyscall.syscall = s
	newTaggedSyscall.tags = append([]int(nil), t...)
	return newTaggedSyscall
}

func (a *TaggedSyscall) Equal(b *TaggedSyscall) bool {
	if a.syscall != b.syscall {
		return false
	}

	if len(a.tags) != len(b.tags) {
		return false
	}

	for i, _ := range a.tags {
		if a.tags[i] != b.tags[i] {
			return false
		}
	}
	return true
}

type TaggedSyscallNode struct {
	next    []*TaggedSyscallNode
	syscall *TaggedSyscall
	flag    AnalysisFlag
	tag     int
	events  []*TraceEvent
	pt      int
}

func NewTaggedSyscallNode(n *TaggedSyscallNode) *TaggedSyscallNode {
	newNode := new(TaggedSyscallNode)
	newNode.syscall = n.syscall
	newNode.flag = n.flag
	newNode.tag = n.tag
	return newNode
}

func NewTaggedSyscallEndNode(flag AnalysisFlag, tag int) *TaggedSyscallNode {
	newEndNode := new(TaggedSyscallNode)
	newEndNode.syscall = new(TaggedSyscall)
	newEndNode.flag = flag
	newEndNode.tag = tag
	return newEndNode
}

func (n *TaggedSyscallNode) findChild(s *TaggedSyscall) int {
	for i, next := range n.next {
		if next.syscall.Equal(s) {
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
		return fmt.Sprintf("%v%v", n.syscall.syscall.name, n.syscall.tags)
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
	pid  uint32
}

func (k AnalysisUnitKey) String() string {
	return fmt.Sprintf("%v pid:%d fd:%d", k.trace.name, k.pid, k.fd)
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

type FilterState struct {
	lastSeqTag       int
	lastNode         *TaggedSyscallNode
	patternRecorded  map[int]bool
}

type PatternTimestamp struct {
	tag int
	ts  uint64
}

type PatternAnalysis struct {
	groupingMethods   map[Grouping]GroupingMethod
	lastNodeOfPid     map[uint32]*TaggedSyscallNode
	seqTreeRoot       *TaggedSyscallNode
	patTreeRoot       *TaggedSyscallNode
	tagCounter        int
	patternInterval   map[AnalysisUnitKey]map[int][]uint64
	patternOccurence  map[AnalysisUnitKey]map[int]int
	patternOrder      map[int]map[int]int
	patternOrderCtr   map[int]map[int]int
	patternOrderTh    float64

	unitOfAnalysis    AnalysisUnit

	uniqueSyscallList []*TaggedSyscall
	seqTags           []int
	seqTreeList       [][]*TaggedSyscallNode
	seqOrderList      map[int]uint64
	seqSeqList        map[int]uint64

	filterStates      map[AnalysisUnitKey]*FilterState
	filterDelayedCall []*TraceEvent

	patternSequences  map[AnalysisUnitKey][]PatternTimestamp
	patternSeqGraph   map[int]map[int]int

	debugEnable       bool
}

func (a *PatternAnalysis) String() string {
	return "pattern analysis"
}

func (a *PatternAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.lastNodeOfPid = make(map[uint32]*TaggedSyscallNode)
	a.seqTreeRoot = new(TaggedSyscallNode)
	a.seqTreeRoot.syscall = new(TaggedSyscall)
	a.patTreeRoot = new(TaggedSyscallNode)
	a.patTreeRoot.syscall = new(TaggedSyscall)
	a.patternInterval = make(map[AnalysisUnitKey]map[int][]uint64)
	a.patternOccurence = make(map[AnalysisUnitKey]map[int]int)
	a.patternOrder = make(map[int]map[int]int)
	a.patternOrderCtr = make(map[int]map[int]int)
	a.filterStates = make(map[AnalysisUnitKey]*FilterState)

	a.seqTreeList = make([][]*TaggedSyscallNode, 0)
	a.uniqueSyscallList = make([]*TaggedSyscall, 0)
	a.seqOrderList = make(map[int]uint64)
	a.seqSeqList = make(map[int]uint64)

	a.patternSequences = make(map[AnalysisUnitKey][]PatternTimestamp)
	a.patternSeqGraph = make(map[int]map[int]int)

	a.debugEnable = false
}

func (a *PatternAnalysis) SetPatternOrderThreshold(th float64) {
	a.patternOrderTh = th
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
					newEndNode := NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)
					n.next = append(n.next, newEndNode)
					a.tagCounter += 1
					a.lastNodeOfPid[pid] = a.seqTreeRoot
				}
			}
		}
	} else if te.typ == 1 {
		_, key := a.newAnalysisUnitKey(te)
//		_, fd := te.GetFD()
		if _, ok := a.patternInterval[key]; !ok {
//			fmt.Printf("new key %v %d\n", te.info.name, fd)
			a.patternInterval[key] = make(map[int][]uint64)
			a.patternOccurence[key] = make(map[int]int)
		}

		if _, ok := a.lastNodeOfPid[te.id]; ok {
			if a.toBreakDown(te) {
				if a.lastNodeOfPid[te.id] != a.seqTreeRoot {
//					if idx := a.lastNodeOfPid[te.id].findEndChild(); idx != -1 {
//						if a.lastNodeOfPid[te.id].next[idx].tag == 5 {
//							if a.debugEnable == false {
//								a.debugEnable = true
//							} else {
//								fmt.Printf("debug twice\n")
//							}
//						}
//					}
					if idx := a.lastNodeOfPid[te.id].findEndChild(); idx == -1 {
						newEndNode := NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)
						a.tagCounter += 1
						a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newEndNode)
					}
					a.lastNodeOfPid[te.id] = a.seqTreeRoot
				}
			} else if idx := a.lastNodeOfPid[te.id].findEndChild(); idx != -1 && a.lastNodeOfPid[te.id] != a.seqTreeRoot {
//				if a.lastNodeOfPid[te.id].next[idx].tag == 5 {
//					if a.debugEnable == false {
//						a.debugEnable = true
//					} else {
//						fmt.Printf("init twice\n")
//					}
//				}
				a.lastNodeOfPid[te.id] = a.seqTreeRoot
			}
		} else {
//			fmt.Printf("new pid %v %d\n", te.info.name, te.id)
			a.lastNodeOfPid[te.id] = a.seqTreeRoot
		}

		if idx := a.lastNodeOfPid[te.id].findChild(NewTaggedSyscall(te.syscall, te.tags)); idx != -1 {
			a.lastNodeOfPid[te.id] = a.lastNodeOfPid[te.id].next[idx]
		} else {
			newNextNode := new(TaggedSyscallNode)
			newNextNode.syscall = NewTaggedSyscall(te.syscall, te.tags)
			newNextNode.flag = TrainFlag
			newNextNode.tag = a.tagCounter
			a.tagCounter += 1
			a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newNextNode)
			a.lastNodeOfPid[te.id] = newNextNode
		}
		a.lastNodeOfPid[te.id].events = append(a.lastNodeOfPid[te.id].events, te)
	} else if te.typ == 2 && (te.flag & TraceEventFlagUseFD) != 0 {
		_, nr := te.GetNR()
		_, key := a.newAnalysisUnitKey(te)
		idx := -1
		fd := uint64(0)
		switch nr {
		case 21:
			idx, fd = te.GetFD2("fd")
		case 23, 24:
			idx, fd = te.GetFD2("oldfd")
		}
		if idx != -1 {
			key.fd = fd
		}
		if _, ok := a.patternInterval[key]; ok {
			fmt.Printf("%v %v kernel module fd(%d)\n", te.trace.name, te.syscall.name, key.fd)
		}
	}

	for _, gm := range a.groupingMethods {
		gm.update(te)
	}

	return
}

func (a *PatternAnalysis) Reset() {
	a.lastNodeOfPid = make(map[uint32]*TaggedSyscallNode)
	a.filterStates = make(map[AnalysisUnitKey]*FilterState)
	a.debugEnable = false

	for _, gm := range a.groupingMethods {
		gm.reset()
	}
}

func (a *PatternAnalysis) testFilterPolicy(te *TraceEvent) (string, int) {
	errMsg := ""
	errNum := 0
	if te.typ == 0 {
		if te.id == 0x80010000 {
			for pid, _ := range a.lastNodeOfPid {
				a.lastNodeOfPid[pid] = a.seqTreeRoot
			}
		}
	} else if te.typ == 1 {
		_, key := a.newAnalysisUnitKey(te)
		if _, ok := a.filterStates[key]; !ok {
			a.filterStates[key] = new(FilterState)
			a.filterStates[key].lastNode = a.seqTreeRoot
			a.filterStates[key].patternRecorded = make(map[int]bool)
		}

		filterState := a.filterStates[key]
		if idx := filterState.lastNode.findEndChild(); idx != -1 && filterState.lastNode != a.seqTreeRoot {
			thisSeqId := filterState.lastNode.next[idx].tag
			var seqOrderViolated []int
			var seqOrderViolatedPolicy []int
			for p, _ := range filterState.patternRecorded {
				order := a.patternOrder[p][thisSeqId]
				//if p != thisSeqId && (order == 0 || order == 2) {
				if p != thisSeqId && order == 2 {
					seqOrderViolated = append(seqOrderViolated, p)
					seqOrderViolatedPolicy = append(seqOrderViolatedPolicy, order)
				}
			}
			if len(seqOrderViolated) == 0 {
				filterState.patternRecorded[thisSeqId] = true
			} else {
				errMsg += fmt.Sprintf("seq%x violates inter-seq order with seq%x %v", thisSeqId, seqOrderViolated, seqOrderViolatedPolicy)
				errNum += 1
			}
			filterState.lastNode = a.seqTreeRoot

//			if filterState.lastSeqTag == 0 {
//				filterState.lastSeqTag = thisSeqId
//			} else if ctr, ok := a.patternSeqGraph[filterState.lastSeqTag][thisSeqId]; !ok || ctr == 0 {
//				errMsg += fmt.Sprintf("seq%x violates inter-seq seq with seq%x", thisSeqId, filterState.lastSeqTag)
//				errNum += 1
//			} else {
//				filterState.lastSeqTag = thisSeqId
//			}
		}

		if idx := filterState.lastNode.findChild(NewTaggedSyscall(te.syscall, te.tags)); idx != -1 {
			filterState.lastNode = filterState.lastNode.next[idx]
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
	return errMsg, errNum
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

		if idx := a.lastNodeOfPid[te.id].findChild(NewTaggedSyscall(te.syscall, te.tags)); idx != -1 {
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

	if flag == TrainFlag {
		a.buildSeqTree(te)
	} else if flag == TestFlag {
		//msg, update = a.testSeqTreeModel(te)
		msg, update = a.testFilterPolicy(te)
	}
	return msg, update, 0
}

//func (a *PatternAnalysis) MergeTrees(dst *TaggedSyscallNode, src *TaggedSyscallNode) {
//	dst.events = append(dst.events, src.events...)
//	dst.pt = 0
//	for _, srcNext := range src.next {
//		isInDst := false
//		var dstNext *TaggedSyscallNode
//		for _, dstNext = range dst.next {
//			if dstNext.syscall.Equal(srcNext.syscall) {
//				isInDst = true
//				break
//			}
//		}
//		if isInDst {
//			a.MergeTrees(dstNext, srcNext)
//		} else {
//			dst.next = append(dst.next, srcNext)
//		}
//	}
//}

func (a *PatternAnalysis) _MergeTrees(dst *TaggedSyscallNode, src *TaggedSyscallNode, root *TaggedSyscallNode, depth *int) {
	*depth += 1
	if dst.syscall.Equal(src.syscall) {
		dst.events = append(dst.events, src.events...)
	}
	dst.pt = 0
	//fmt.Printf("merge (%v to %v), ", src, dst)
	for _, srcNext := range src.next {
		if *depth == 1 && srcNext.syscall.syscall == nil {
			continue
		}

		if idx := dst.findChild(srcNext.syscall); idx != -1 {
			if dst.findEndChild() == -1 || dst == root {
				a._MergeTrees(dst.next[idx], srcNext, root, depth)
			} else {
				a._MergeTrees(root, src, root, depth)
			}
		} else {
			dst.next = append(dst.next, srcNext)
		}
	}
	//fmt.Printf("return ")
}

func (a *PatternAnalysis) MergeTrees(dst *TaggedSyscallNode, src *TaggedSyscallNode, root *TaggedSyscallNode) {
	depth := 0
	a._MergeTrees(dst, src, root, &depth)
}

func (a *PatternAnalysis) getPatternEnd(sn *TaggedSyscallNode, pn *TaggedSyscallNode) *TaggedSyscallNode {
	if matchIdx := pn.findChild(sn.syscall); matchIdx >= 0 {
		pn = pn.next[matchIdx]
		if pn.findEndChild() >= 0 {
			return sn
		} else if len(sn.next) == 1 {
			return a.getPatternEnd(sn.next[0], pn)
		}
	}
	return nil
}

func (a *PatternAnalysis) PurgeTree2(osn *TaggedSyscallNode, opn *TaggedSyscallNode) bool {
	purged := false
	for _, sn := range osn.next {
		//fmt.Printf("purge sn:%v opn:%v\n", sn, opn)
		if ne := a.getPatternEnd(sn, a.patTreeRoot); ne != nil && ne.pt == 0 {
			//fmt.Printf("pattern end:%v\n", ne)
			ne.pt = 1
			if idx := ne.findEndChild(); idx != -1 && len(ne.next) != 1 {
				a.MergeTrees(a.seqTreeRoot, ne, a.seqTreeRoot)
				//fmt.Printf("\n")
				if idx := ne.findEndChild(); idx >= 0 {
					ne.next = []*TaggedSyscallNode{ne.next[idx]}
				} else {
					ne.next = []*TaggedSyscallNode{NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)}
					a.tagCounter += 1
				}
			}
			if osn != a.seqTreeRoot {
				a.MergeTrees(a.seqTreeRoot, osn, a.seqTreeRoot)
				if idx := osn.findEndChild(); idx >= 0 {
					osn.next = []*TaggedSyscallNode{osn.next[idx]}
				} else {
					osn.next = []*TaggedSyscallNode{NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)}
					a.tagCounter += 1
				}
			}
			purged = true
		} else if a.PurgeTree2(sn, a.patTreeRoot) {
			purged = true
		}
		//fmt.Printf("else\n")
	}
	return purged
}

func (a *PatternAnalysis) extractPattern(osn *TaggedSyscallNode, opn *TaggedSyscallNode) bool {
	extracted := false
	for _, sn := range osn.next {
		pn := opn
		//fmt.Printf("extract sn:%v pn:%v ", sn, pn)
		if matchIdx := pn.findChild(sn.syscall); matchIdx >= 0 {
			pn = pn.next[matchIdx]
			//fmt.Printf("c1 \n")
		} else if pn.findEndChild() == -1 || pn == a.patTreeRoot {
			//fmt.Printf("c2 \n")
			extracted = true
			if sn.syscall.syscall == nil && pn != a.patTreeRoot {
				a.MergeTrees(a.patTreeRoot, pn, a.patTreeRoot)
				//fmt.Printf("\n")
				pn.next = []*TaggedSyscallNode{NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)}
				a.tagCounter += 1
				pn = pn.next[len(pn.next)-1]
			} else {
				pn.next = append(pn.next, NewTaggedSyscallNode(sn))
				pn = pn.next[len(pn.next)-1]
			}
		} else {
			//fmt.Printf("c3 \n")
			pn = a.patTreeRoot
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
	pidMap := make(map[uint32]bool)
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
		s += fmt.Sprintf("[%v]%v%v (%v)", *depth, n.syscall.syscall.name, n.syscall.tags, len(n.events))
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
		found := false
		for _, syscall := range a.uniqueSyscallList {
			if syscall.Equal(node.syscall) {
				found = true
			}
		}
		if !found {
			a.uniqueSyscallList = append(a.uniqueSyscallList, node.syscall)
		}
	}
	for _, next := range node.next {
		a.genUniqueNodeList(next)
	}
}

func (a *PatternAnalysis) genSeqOrderList() {
	patternOccurence := make(map[int][]int)
	for _, tag := range a.seqTags {
		patternOccurence[tag] = make([]int, 3)
	}
	for key, _ := range a.patternInterval {
		for _, tag := range a.seqTags {
			patternOccurence[tag][0] += a.patternOccurence[key][tag]
			if a.patternOccurence[key][tag] != 0 {
				patternOccurence[tag][1] += 1
			}
			if a.patternOccurence[key][tag] > 1 {
				patternOccurence[tag][2] = 1
			}
		}
	}
	for i, iTag := range a.seqTags {
		var order uint64
		for j, jTag := range a.seqTags {
			if i == j {
				if patternOccurence[jTag][2] == 0 {
					order = order | (1 << j)
				}
			} else {
				if a.patternOrder[iTag][jTag] == 1 {
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
			if a.patternSeqGraph[iTag][jTag] > 0 {
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
			if interval, ok := a.patternInterval[key][tag]; !ok {
				a.patternInterval[key][tag] = []uint64{te.ts, te.ts}
			} else {
				if te.ts < interval[0] {
					a.patternInterval[key][tag][0] = te.ts
				}
				if te.ts > interval[1] {
					a.patternInterval[key][tag][1] = te.ts
				}
			}
			a.patternOccurence[key][tag] += 1
		}
	}
	for _, next := range n.next {
		a.GetPatternTimeInterval(next)
	}
}

func (a *PatternAnalysis) AnalyzeInterPatternOrder() {
	a.GetPatternTimeInterval(a.seqTreeRoot)

	fmt.Printf("analysis unit keys:\n")
	for key, patternInterval := range a.patternInterval {
		fmt.Printf("%v\n", key)
		for i, ni := range patternInterval {
			if _, ok := a.patternOrder[i]; !ok {
				a.patternOrder[i] = make(map[int]int)
				a.patternOrderCtr[i] = make(map[int]int)
			}
			for j, nj := range patternInterval {
				if _, ok := a.patternOrder[i][j]; !ok {
					a.patternOrder[i][j] = 0
					a.patternOrderCtr[i][j] = 0
				}

				//if i == 5 {
				//	fmt.Printf("i:%v j:%v\n", ni, nj)
				//	fmt.Printf("%v\n", a.patternOrder[i][j])
				//}
				if i == j || (ni[0] == 0 && ni[1] == 0) || (nj[0] == 0 && nj[1] == 0) {
					continue
				} else if ni[1] < nj[0] {
					a.patternOrderCtr[i][j] += 1
					if a.patternOrder[i][j] == 0 || a.patternOrder[i][j] == 1 {
						a.patternOrder[i][j] = 1
					} else {
						a.patternOrder[i][j] = 3
					}
				} else if ni[0] > nj[1] {
					a.patternOrderCtr[i][j] += 1
					if a.patternOrder[i][j] == 0 || a.patternOrder[i][j] == 2 {
						a.patternOrder[i][j] = 2
					} else {
						a.patternOrder[i][j] = 3
					}
				} else {
					a.patternOrderCtr[i][j] += 1
					a.patternOrder[i][j] = 3
				}
			}
		}
	}

	var tags []int
	tagMax := 0
	for k, _ := range a.patternOrder {
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
	patternOccurence := make(map[int][]int)
	for _, tag := range tags {
		patternOccurence[tag] = make([]int, 3)
	}
	for key, _ := range a.patternInterval {
		for _, tag := range tags {
			patternOccurence[tag][0] += a.patternOccurence[key][tag]
			if a.patternOccurence[key][tag] != 0 {
				patternOccurence[tag][1] += 1
			}
			if a.patternOccurence[key][tag] > 1 {
				patternOccurence[tag][2] = 1
			}
		}
	}
	fmt.Printf("\n")
	for _, ks := range tags {
		fmt.Printf("%*x (%8d/%4d) ", tagW, ks, patternOccurence[ks][0], patternOccurence[ks][1])
		if patternOccurence[ks][2] == 0 {
			fmt.Printf("u ")
		} else {
			fmt.Printf("  ")
		}
		for _, kd := range tags {
			vd := a.patternOrder[ks][kd]
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
			vd := a.patternOrderCtr[ks][kd]
			if a.patternOrder[ks][kd] == 1 || a.patternOrder[ks][kd] == 2 {
				n := 0
				if patternOccurence[ks][1] < patternOccurence[kd][1] {
					n = patternOccurence[ks][1]
				} else {
					n = patternOccurence[kd][1]
				}
				if vd < int(a.patternOrderTh * float64(n)) {
					a.patternOrder[ks][kd] = 3
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

func (a *PatternAnalysis) addPatternToSequences(n *TaggedSyscallNode) {
	if idx := n.findEndChild(); idx != -1 && n != a.seqTreeRoot {
		tag := n.next[idx].tag
		for _, te := range n.events {
			_, key := a.newAnalysisUnitKey(te)
			a.patternSequences[key] = append(a.patternSequences[key], PatternTimestamp{tag, te.ts})
		}
	}
	for _, next := range n.next {
		a.addPatternToSequences(next)
	}
}

func (a *PatternAnalysis) AnalyzeInterPatternSequence() {
//	a.unitOfAnalysis = ProcessLevel
	a.addPatternToSequences(a.seqTreeRoot)

	for key, _ := range a.patternSequences {
		sort.Slice(a.patternSequences[key], func(i, j int) bool {
			return a.patternSequences[key][i].ts < a.patternSequences[key][j].ts
		})
	}

	for _, seq := range a.patternSequences {
		lastTag := 0
		for _, tagTimestamp := range seq {
			//if lastTag != 0 {
				if _, ok := a.patternSeqGraph[lastTag]; !ok {
					a.patternSeqGraph[lastTag] = make(map[int]int)
				}
				a.patternSeqGraph[lastTag][tagTimestamp.tag] += 1
			//}
			lastTag = tagTimestamp.tag
		}
	}

	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Printf("pattern seq:\n")
	for src, dsts := range a.patternSeqGraph {
		fmt.Printf("%3x: ", src)
		for dst, ctr := range dsts {
			fmt.Printf("%3x(%d) ", dst, ctr)
		}
		fmt.Printf("\n")
	}
	fmt.Print("--------------------------------------------------------------------------------\n")
}

func (a *PatternAnalysis) appendEndNode(n *TaggedSyscallNode) {
	if idx := n.findEndChild(); idx != -1 {
		return
	} else if len(n.next) == 0 {
		newEndNode := NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)
		n.next = append(n.next, newEndNode)
		a.tagCounter += 1
		return
	}

	for _, next := range n.next {
		a.appendEndNode(next)
	}
}

func (a *PatternAnalysis) PostProcess(opt int) {
	if opt == 0 {
		return
	}

	a.appendEndNode(a.seqTreeRoot)
	fmt.Print("sequence tree before purging\n")
	a.seqTreeRoot.Print(a)
	//i := 0
	for {
		//i += 1
		//fmt.Print("--------------------------------------------------------------------------------\n")
		//fmt.Printf("purging #%v\n", i)
		extracted := a.extractPattern(a.seqTreeRoot, a.patTreeRoot)
		//fmt.Print("--------------------------------------------------------------------------------\n")
		//fmt.Print("pattern tree\n")
		//a.patTreeRoot.Print(a)
		//fmt.Print("--------------------------------------------------------------------------------\n")
		//fmt.Print("sequence tree\n")
		//a.seqTreeRoot.Print(a)
		purged := a.PurgeTree2(a.seqTreeRoot, a.patTreeRoot)
		//fmt.Print("--------------------------------------------------------------------------------\n")
		//fmt.Printf("purging #%v purged=%v extracted=%v\n", i, purged, extracted)
		//fmt.Print("--------------------------------------------------------------------------------\n")
		//fmt.Print("pattern tree\n")
		//a.patTreeRoot.Print(a)
		//fmt.Print("--------------------------------------------------------------------------------\n")
		//fmt.Print("sequence tree\n")
		//a.seqTreeRoot.Print(a)
		if !purged && !extracted {
			break
		}
	}
	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Print("pattern tree\n")
	a.patTreeRoot.Print(a)
	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Print("sequence tree after purging\n")
	a.seqTreeRoot.Print(a)
	a.AnalyzeInterPatternOrder()
	a.AnalyzeInterPatternSequence()
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
		fmt.Printf("%2d: %v%v\n", sci, sc.syscall.name, sc.tags)
	}
	fmt.Print("syscall seq tree:\n")
	for seqi, p := range a.seqTreeList {
		fmt.Printf("%2d: ", seqi)
		for _, s := range p {
			for sci, sc := range a.uniqueSyscallList {
				if s.syscall.Equal(sc) {
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
	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Print("sequence tree\n")
	a.seqTreeRoot.Print(a)
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
