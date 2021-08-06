package sifter

import (
	"encoding/binary"
	"fmt"
)

type Grouping int

const (
	TimeGrouping Grouping = iota
	SyscallGrouping
)

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

type TaggedSyscallNode struct {
	next    []*TaggedSyscallNode
	syscall *TaggedSyscall
	counts  map[Flag]uint64
	flag    Flag
	tag     int
	events  []*TraceEvent
	pt      int
}

func NewTaggedSyscallNode(n *TaggedSyscallNode) *TaggedSyscallNode {
	newNode := new(TaggedSyscallNode)
	newNode.syscall = n.syscall
	newNode.flag = n.flag
	newNode.counts = make(map[Flag]uint64)
	newNode.tag = n.tag
	return newNode
}

func NewTaggedSyscallEndNode(flag Flag, tag int) *TaggedSyscallNode {
	newEndNode := new(TaggedSyscallNode)
	newEndNode.syscall = new(TaggedSyscall)
	newEndNode.flag = flag
	newEndNode.counts = make(map[Flag]uint64)
	newEndNode.counts[flag] += 1
	newEndNode.tag = tag
	return newEndNode
}

type ProcFDKey struct {
	info *TraceInfo
	fd   uint64
}

type PatternAnalysis struct {
	groupingThreshold map[Grouping]uint64
	lastNodeOfPid     map[uint32]*TaggedSyscallNode
	lastEventOfPid    map[uint32]*TraceEvent
	firstAndLastOfPid map[uint32][]*TraceEvent
	eventCounterOfPid map[uint32]uint64
	seqTreeRoot       *TaggedSyscallNode
	patTreeRoot       *TaggedSyscallNode
	tagCounter        int
	moduleSyscalls    map[*Syscall]bool
	patternInterval   map[ProcFDKey]map[int][]uint64
	patternOrder      map[int]map[int]int
}

func (a *PatternAnalysis) String() string {
	return "pattern analysis"
}

func (a *PatternAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.lastNodeOfPid = make(map[uint32]*TaggedSyscallNode)
	a.lastEventOfPid = make(map[uint32]*TraceEvent)
	a.firstAndLastOfPid = make(map[uint32][]*TraceEvent)
	a.eventCounterOfPid = make(map[uint32]uint64)
	a.seqTreeRoot = new(TaggedSyscallNode)
	a.seqTreeRoot.syscall = new(TaggedSyscall)
	a.patTreeRoot = new(TaggedSyscallNode)
	a.patTreeRoot.syscall = new(TaggedSyscall)
	a.moduleSyscalls = make(map[*Syscall]bool)
	a.patternInterval = make(map[ProcFDKey]map[int][]uint64)
	a.patternOrder = make(map[int]map[int]int)

	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			a.moduleSyscalls[syscall] = true
		}
	}
}

func (a *PatternAnalysis) SetGroupingThreshold (g Grouping, th uint64) {
	if a.groupingThreshold == nil {
		a.groupingThreshold = make(map[Grouping]uint64)
	}
	a.groupingThreshold[g] = th
}

func (a *PatternAnalysis) toBreakDown(te *TraceEvent) bool {
	breakDownSeq := false
	for g, th := range a.groupingThreshold {
		switch g {
		case TimeGrouping:
			if te.ts - a.lastEventOfPid[te.id].ts > th {
				breakDownSeq = true
			}
		case SyscallGrouping:
			if a.eventCounterOfPid[te.id] > th {
				breakDownSeq = true
			}
		}
	}
	return breakDownSeq
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

func (a *PatternAnalysis) buildSeqTree(te *TraceEvent) {
	if (te.id & 0x80000000) == 0 {
		if _, ok := a.firstAndLastOfPid[te.id]; !ok {
			a.firstAndLastOfPid[te.id] = append(a.firstAndLastOfPid[te.id], te)
			a.firstAndLastOfPid[te.id] = append(a.firstAndLastOfPid[te.id], nil)
		} else {
			a.firstAndLastOfPid[te.id][1] = te
		}
	}

	if (te.id & 0x80000000) != 0 {
		for pid, n := range a.lastNodeOfPid {
			if n != a.seqTreeRoot {
				if idx := n.findEndChild(); idx >= 0 {
					n.next[idx].counts[TrainFlag] += 1
				} else {
					newEndNode := NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)
					n.next = append(n.next, newEndNode)
					a.tagCounter += 1
					a.lastNodeOfPid[pid] = a.seqTreeRoot
				}
			}
			a.lastEventOfPid[pid] = te
			a.eventCounterOfPid[pid] = 0
		}
	} else if _, ok := a.moduleSyscalls[te.syscall]; ok {
		reg0 := binary.LittleEndian.Uint64(te.data[0:8])
		if _, ok := a.patternInterval[ProcFDKey{te.info, reg0}]; !ok {
			a.patternInterval[ProcFDKey{te.info, reg0}] = make(map[int][]uint64)
		}

		if _, ok := a.lastEventOfPid[te.id]; ok {
			if a.toBreakDown(te) {
				if a.lastNodeOfPid[te.id] != a.seqTreeRoot {
					if idx := a.lastNodeOfPid[te.id].findEndChild(); idx >= 0 {
						a.lastNodeOfPid[te.id].next[idx].counts[TrainFlag] += 1
					} else {
						newEndNode := NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)
						a.tagCounter += 1
						a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newEndNode)
					}
					a.lastNodeOfPid[te.id] = a.seqTreeRoot
				}
			} else if idx := a.lastNodeOfPid[te.id].findEndChild(); idx >= 0 && a.lastNodeOfPid[te.id] != a.seqTreeRoot {
				a.lastNodeOfPid[te.id] = a.seqTreeRoot
			}
		} else {
			a.lastNodeOfPid[te.id] = a.seqTreeRoot
		}

		nextExist := false
		for _, next := range a.lastNodeOfPid[te.id].next {
			if next.syscall.Equal(NewTaggedSyscall(te.syscall, te.tags)) {
				next.counts[TrainFlag] += 1
				a.lastNodeOfPid[te.id] = next
				nextExist = true
			}
		}

		if !nextExist {
			newNextNode := new(TaggedSyscallNode)
			newNextNode.syscall = NewTaggedSyscall(te.syscall, te.tags)
			newNextNode.flag = TrainFlag
			newNextNode.counts = make(map[Flag]uint64)
			newNextNode.counts[TrainFlag] += 1
			newNextNode.tag = a.tagCounter
			a.tagCounter += 1
			a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newNextNode)
			a.lastNodeOfPid[te.id] = newNextNode
		}
		a.lastNodeOfPid[te.id].events = append(a.lastNodeOfPid[te.id].events, te)
		a.lastEventOfPid[te.id] = te
		a.eventCounterOfPid[te.id] = 0
	} else {
		a.eventCounterOfPid[te.id] += 1
	}

	return
}

func (a *PatternAnalysis) Reset() {
	a.lastNodeOfPid = make(map[uint32]*TaggedSyscallNode)
	a.lastEventOfPid = make(map[uint32]*TraceEvent)
	a.eventCounterOfPid = make(map[uint32]uint64)
}

func (a *PatternAnalysis) testSeqTreeModel(te *TraceEvent) (string, int) {
	if te.id & 0x80000000 != 0 {
		if te.id == 0x80010000 {
			for pid, _ := range a.lastNodeOfPid {
				a.lastNodeOfPid[pid] = a.seqTreeRoot
			}
		}
	} else if _, ok := a.moduleSyscalls[te.syscall]; ok {
		if _, ok := a.lastNodeOfPid[te.id]; !ok {
			a.lastNodeOfPid[te.id] = a.seqTreeRoot
		}

		if idx := a.lastNodeOfPid[te.id].findEndChild(); a.lastNodeOfPid[te.id] != a.seqTreeRoot && idx != -1 {
			a.lastNodeOfPid[te.id] = a.seqTreeRoot
		} else if idx := a.lastNodeOfPid[te.id].findChild(NewTaggedSyscall(te.syscall, te.tags)); idx != -1 {
			a.lastNodeOfPid[te.id] = a.lastNodeOfPid[te.id].next[idx]
		} else {
			last := ""
			if a.lastNodeOfPid[te.id].syscall.syscall == nil {
				last += "*"
			} else {
				last += fmt.Sprintf("%v%v", a.lastNodeOfPid[te.id].syscall.syscall.name, a.lastNodeOfPid[te.id].syscall.tags)
			}
			return fmt.Sprintf("r3 %v->%v%v no matching pattern", last, te.syscall.name, te.tags), 1
		}
	}
	return "", 0
}

func (a *PatternAnalysis) ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int) {
	msg := ""
	update := 0

	if flag == TrainFlag {
		a.buildSeqTree(te)
	} else if flag == TestFlag {
		msg, update = a.testSeqTreeModel(te)
	}
	return msg, update
}

//func (a *PatternAnalysis) MergeTrees(dst *TaggedSyscallNode, src *TaggedSyscallNode) {
//	for f, _ := range dst.counts {
//		dst.counts[f] += src.counts[f]
//	}
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

func (a *PatternAnalysis) MergeTrees(dst *TaggedSyscallNode, src *TaggedSyscallNode) {
	for f, _ := range dst.counts {
		dst.counts[f] += src.counts[f]
	}
	dst.events = append(dst.events, src.events...)
	dst.pt = 0
	for _, srcNext := range src.next {
		isInDst := false
		var dstNext *TaggedSyscallNode
		for _, dstNext = range dst.next {
			if dstNext.syscall.Equal(srcNext.syscall) {
				isInDst = true
				break
			}
		}
		if isInDst {
			if dst.findEndChild() < 0 {
				a.MergeTrees(dstNext, srcNext)
			}
		} else {
			dst.next = append(dst.next, srcNext)
		}
	}
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
		if ne := a.getPatternEnd(sn, a.patTreeRoot); ne != nil && ne.pt == 0 {
			ne.pt = 1
			a.MergeTrees(a.seqTreeRoot, ne)
			if idx := ne.findEndChild(); idx >= 0 {
				ne.next = []*TaggedSyscallNode{ne.next[idx]}
			} else {
				ne.next = []*TaggedSyscallNode{NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)}
				a.tagCounter += 1
			}
			purged = true
		} else if a.PurgeTree2(sn, a.patTreeRoot) {
			purged = true
		}
	}
	return purged
}

func (a *PatternAnalysis) PurgeTree(n *TaggedSyscallNode) {
	for _, next := range n.next {
		toBreak := false
		for _, pn := range a.patTreeRoot.next {
			if next.syscall.Equal(pn.syscall) && !next.isLeaf() {
				toBreak = true
				break
			}
		}
		if toBreak {
			a.MergeTrees(a.seqTreeRoot, next)
			if idx := next.findEndChild(); idx >= 0 {
				next.next = []*TaggedSyscallNode{next.next[idx]}
			} else {
				next.next = []*TaggedSyscallNode{NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)}
				a.tagCounter += 1
			}
		} else {
			a.PurgeTree(next)
		}
	}
}

func (a *PatternAnalysis) CheckNewIndependentNode() bool {
	hasIndependentNode := false
	for _, n := range a.seqTreeRoot.next {
		if n.findEndChild() >= 0 {
			notInPurgedList := true
			for _, pn := range a.patTreeRoot.next {
				if n.syscall.Equal(pn.syscall) {
					notInPurgedList = false
				}
			}
			if notInPurgedList {
				a.patTreeRoot.next = append(a.patTreeRoot.next, n)
				hasIndependentNode = true
			}
		}
	}
	return hasIndependentNode
}

func (a *PatternAnalysis) extractPattern(osn *TaggedSyscallNode, opn *TaggedSyscallNode) bool {
	extracted := false
	for _, sn := range osn.next {
		pn := opn
		if matchIdx := pn.findChild(sn.syscall); matchIdx >= 0 {
			pn = pn.next[matchIdx]
		} else if pn.findEndChild() == -1 || pn == a.patTreeRoot {
			extracted = true
			if sn.syscall.syscall == nil {
				a.MergeTrees(a.patTreeRoot, pn)
				pn.next = []*TaggedSyscallNode{NewTaggedSyscallEndNode(TrainFlag, a.tagCounter)}
				a.tagCounter += 1
				pn = pn.next[len(pn.next)-1]
			} else {
				pn.next = append(pn.next, NewTaggedSyscallNode(sn))
				pn = pn.next[len(pn.next)-1]
			}
		} else {
			pn = a.patTreeRoot
		}

		if a.extractPattern(sn, pn) {
			extracted = true
		}
	}
	return extracted
}

func (a *PatternAnalysis) getPhaseString(n *TaggedSyscallNode) string {
	s := ""

	if len(n.events) == 0 {
		return s
	}

	phaseFlag := 0
	startEvent := n.events[0]
	endEvent := n.events[len(n.events)-1]
	startEventProcStartTime := a.firstAndLastOfPid[startEvent.id][0].ts
	startEventProcEndTime := a.firstAndLastOfPid[startEvent.id][1].ts
	startEventProcTime := startEventProcEndTime - startEventProcStartTime
	endEventProcStartTime := a.firstAndLastOfPid[endEvent.id][0].ts
	endEventProcEndTime := a.firstAndLastOfPid[endEvent.id][1].ts
	endEventProcTime := endEventProcEndTime - endEventProcStartTime
	startEventTimePct := float64((startEvent.ts - startEventProcStartTime)) / float64(startEventProcTime)
	endEventTimePct := float64((endEvent.ts - endEventProcStartTime)) / float64(endEventProcTime)
	//s += fmt.Sprintf(" %.4f %.4f", startEventTimePct, endEventTimePct)
	//s += fmt.Sprintf(" %e %e", float64(startEvent.ts - startEventProcStartTime), float64(endEvent.ts - endEventProcStartTime))
	//s += fmt.Sprintf(" %e %e", float64(startEventProcEndTime - startEvent.ts), float64(endEventProcEndTime - endEvent.ts))
	if startEvent.ts - startEventProcStartTime < 100000000 && endEvent.ts - endEventProcStartTime < 100000000 {
		phaseFlag |= (1 << 0)
	}
	if startEventProcEndTime - startEvent.ts < 100000000 && endEventProcEndTime - endEvent.ts < 100000000 {
		phaseFlag |= (1 << 4)
	}
	if startEventTimePct < 0.001 && endEventTimePct < 0.001 {
		phaseFlag |= (1 << 1)
	}
	if startEventTimePct > 0.999 && endEventTimePct > 0.999 {
		phaseFlag |= (1 << 5)
	}

	if phaseFlag != 0 {
		s += fmt.Sprintf(" [")
		if initFlag := (phaseFlag & 0x0000000f) >> 0; initFlag != 0 {
			s += fmt.Sprintf("i%v", initFlag)
		}
		if termFlag := (phaseFlag & 0x000000f0) >> 4; termFlag != 0 {
			s += fmt.Sprintf("t%v", termFlag)
		}
		s += fmt.Sprintf("]")
	}

	return s
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
				s += fmt.Sprintf("[%v]end - seq%v (%v/%v)", *depth, n.tag, n.counts[TrainFlag], n.counts[TestFlag])
			} else if n.flag == TestFlag {
				s += fmt.Sprintf("[%v]end - seq%v* (%v/%v)", *depth, n.tag, n.counts[TrainFlag], n.counts[TestFlag])
			}
		}
	} else {
		s += fmt.Sprintf("[%v]%v%v", *depth, n.syscall.syscall.name, n.syscall.tags)
		s += fmt.Sprintf("%v", a.getPhaseString(n))
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

func findRangeOfTrace(n *TaggedSyscallNode, key ProcFDKey) (bool, uint64, uint64) {
	var first, last uint64
	found := false
	for _, event := range n.events {
		if event.info == key.info && binary.LittleEndian.Uint64(event.data[0:8]) == key.fd {
			if first == 0 {
				first = event.ts
				found = true
			}
			last = event.ts
		}
	}
	return found, first, last
}

func (a *PatternAnalysis) GetPatternTimeInterval(n *TaggedSyscallNode) {
	fmt.Printf("GetPatternTimeInterval\n")
	if idx := n.findEndChild(); idx != -1 {
		tag := n.next[idx].tag
		for key, _ := range a.patternInterval {
			if found, first, last := findRangeOfTrace(n, key); found {
				a.patternInterval[key][tag] = append(a.patternInterval[key][tag], first)
				a.patternInterval[key][tag] = append(a.patternInterval[key][tag], last)
			}
		}
	}

	for _, next := range n.next {
		a.GetPatternTimeInterval(next)
	}
}

func (a *PatternAnalysis) AnalyzeIntraPatternOrder() {
	a.GetPatternTimeInterval(a.seqTreeRoot)

	for key, patternInterval := range a.patternInterval {
		fmt.Printf("%v %v\n", key.info.name, key.fd)
		for i, ni := range patternInterval {
			if _, ok := a.patternOrder[i]; !ok {
				a.patternOrder[i] = make(map[int]int)
			}
			for j, nj := range patternInterval {
				if _, ok := a.patternOrder[i][j]; !ok {
					a.patternOrder[i][j] = 0
				}

				if i == j || (ni[0] == 0 && ni[1] == 0) || (nj[0] == 0 && nj[1] == 0) {
					continue
				} else if ni[1] < nj[0] {
					if a.patternOrder[i][j] == 0 || a.patternOrder[i][j] == 1 {
						a.patternOrder[i][j] = 1
					} else {
						a.patternOrder[i][j] = 3
					}
				} else if ni[0] > nj[1] {
					if a.patternOrder[i][j] == 0 || a.patternOrder[i][j] == 2 {
						a.patternOrder[i][j] = 2
					} else {
						a.patternOrder[i][j] = 3
					}
				} else {
					a.patternOrder[i][j] = 3
				}
				//if i == 3 && j == 7 {
				//	fmt.Printf("i:%v j:%v\n", ni, nj)
				//	fmt.Printf("%v\n" ,a.patternOrder[i][j])
				//}
			}
		}
	}
	fmt.Printf("\t")
	var tags []int
	for k, _ := range a.patternOrder {
		fmt.Printf("%03d ", k)
		tags = append(tags, k)
	}
	fmt.Printf("\n")
	for _, ks := range tags {
		fmt.Printf("%03d\t", ks)
		for _, kd := range tags {
			vd := a.patternOrder[ks][kd]
			if vd == 0 {
				fmt.Printf(" -  ")
			} else if vd == 1 {
				fmt.Printf(" >  ")
			} else if vd == 2 {
				fmt.Printf(" <  ")
			} else if vd == 3 {
				fmt.Printf("    ")
			} else {
				fmt.Printf("%03d ", vd)
			}
		}
		fmt.Printf("\n")
	}
}

func (a *PatternAnalysis) PrintResult(v Verbose) {
	fmt.Print("sequence tree before purging\n")
	a.seqTreeRoot.Print(a)
	i := 0
	/*
	for {
		if !a.CheckNewIndependentNode() {
			break
		}

		a.PurgeTree(a.seqTreeRoot)
		if v >= DebugV {
			fmt.Print("--------------------------------------------------------------------------------\n")
			fmt.Printf("purging #%v.1\n", i)
			a.seqTreeRoot.Print()
		}
		a.PurgeTree(a.seqTreeRoot)
		if v >= DebugV {
			fmt.Print("--------------------------------------------------------------------------------\n")
			fmt.Printf("purging #%v.2\n", i)
			a.seqTreeRoot.Print()
		}
		i += 1
	}
	*/
	for {
		i += 1
		extracted := a.extractPattern(a.seqTreeRoot, a.patTreeRoot)
		purged := a.PurgeTree2(a.seqTreeRoot, a.patTreeRoot)

		if v >= DebugV {
			fmt.Print("--------------------------------------------------------------------------------\n")
			fmt.Printf("purging #%v purged=%v extracted=%v\n", i, purged, extracted)
			a.seqTreeRoot.Print(a)
		}

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
	//fmt.Print("--------------------------------------------------------------------------------\n")
	//a.AnalyzeIntraPatternOrder()

}


