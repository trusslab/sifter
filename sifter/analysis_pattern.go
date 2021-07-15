package sifter

import (
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

type PatternAnalysis struct {
	groupingMode      Grouping
	groupingThreshold uint64
	lastNodeOfPid     map[uint32]*TaggedSyscallNode
	lastEventOfPid    map[uint32]*TraceEvent
	eventCounterOfPid map[uint32]uint64
	patternTreeRoot   *TaggedSyscallNode
	purgedTreeRoot    *TaggedSyscallNode
	tagCounter        int
	moduleSyscalls    map[*Syscall]bool
}

func (a *PatternAnalysis) String() string {
	return "pattern analysis"
}

func (a *PatternAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.lastNodeOfPid = make(map[uint32]*TaggedSyscallNode)
	a.lastEventOfPid = make(map[uint32]*TraceEvent)
	a.eventCounterOfPid = make(map[uint32]uint64)
	a.patternTreeRoot = new(TaggedSyscallNode)
	a.patternTreeRoot.syscall = new(TaggedSyscall)
	a.purgedTreeRoot = new(TaggedSyscallNode)
	a.purgedTreeRoot.syscall = new(TaggedSyscall)
	a.moduleSyscalls = make(map[*Syscall]bool)

	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			a.moduleSyscalls[syscall] = true
		}
	}
}

func (a *PatternAnalysis) SetGroupingThreshold (g Grouping, th uint64) {
	a.groupingMode = g
	a.groupingThreshold = th
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

func (a *PatternAnalysis) ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int) {
	msgs := make([]string, 0)

	if (te.id & 0x80000000) != 0 {
		for pid, n := range a.lastNodeOfPid {
			if n != a.patternTreeRoot {
				if idx := n.endChildIdx(); idx >= 0 {
					n.next[idx].counts[flag] += 1
				} else {
					newEndNode := NewTaggedSyscallEndNode(flag, a.tagCounter)
					n.next = append(n.next, newEndNode)
					a.tagCounter += 1
					a.lastNodeOfPid[pid] = a.patternTreeRoot
					msgs = append(msgs, fmt.Sprintf("new seq%d", newEndNode.tag))
				}
			}
			a.lastEventOfPid[pid] = te
			a.eventCounterOfPid[pid] = 0
		}
	} else if _, ok := a.moduleSyscalls[te.syscall]; ok {

		if event, ok := a.lastEventOfPid[te.id]; ok {
			breakDownSeq := false
			switch a.groupingMode {
			case TimeGrouping:
				if te.ts - event.ts > a.groupingThreshold {
					breakDownSeq = true
				}
			case SyscallGrouping:
				if a.eventCounterOfPid[te.id] > a.groupingThreshold {
					breakDownSeq = true
				}
			}

			if breakDownSeq {
				if a.lastNodeOfPid[te.id] != a.patternTreeRoot {
					if idx := a.lastNodeOfPid[te.id].endChildIdx(); idx >= 0 {
						a.lastNodeOfPid[te.id].next[idx].counts[flag] += 1
					} else {
						newEndNode := NewTaggedSyscallEndNode(flag, a.tagCounter)
						a.tagCounter += 1
						a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newEndNode)
						msgs = append(msgs, fmt.Sprintf("new seq%d", newEndNode.tag))
					}
					a.lastNodeOfPid[te.id] = a.patternTreeRoot
				}
			}
		} else {
			a.lastNodeOfPid[te.id] = a.patternTreeRoot
		}

		nextExist := false
		for _, next := range a.lastNodeOfPid[te.id].next {
			if next.syscall.Equal(NewTaggedSyscall(te.syscall, te.tags)) {
				next.counts[flag] += 1
				a.lastNodeOfPid[te.id] = next
				nextExist = true
			}
		}

		if !nextExist {
			newNextNode := new(TaggedSyscallNode)
			newNextNode.syscall = NewTaggedSyscall(te.syscall, te.tags)
			newNextNode.flag = flag
			newNextNode.counts = make(map[Flag]uint64)
			newNextNode.counts[flag] += 1
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

	updatedRangesLen := len(msgs)
	updatedRangesMsg := ""
	for i, msg := range msgs {
		updatedRangesMsg += msg
		if i != updatedRangesLen-1 {
			updatedRangesMsg += ", "
		}
	}
	return updatedRangesMsg, updatedRangesLen
}

func (a *PatternAnalysis) MergeTrees(dst *TaggedSyscallNode, src *TaggedSyscallNode) {
	for f, _ := range dst.counts {
		dst.counts[f] += src.counts[f]
	}
	dst.events = append(dst.events, src.events...)
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
			a.MergeTrees(dstNext, srcNext)
		} else {
			dst.next = append(dst.next, srcNext)
		}
	}
}

func (n *TaggedSyscallNode) endChildIdx() int {
	for i, next := range n.next {
		if next.syscall.syscall == nil {
			return i
		}
	}
	return -1
}

func (n *TaggedSyscallNode) isLeaf() bool {
	return len(n.next) == 1 && n.endChildIdx() >= 0
}

func (a *PatternAnalysis) PurgeTree(n *TaggedSyscallNode) {
	for _, next := range n.next {
		toBreak := false
		for _, pn := range a.purgedTreeRoot.next {
			if next.syscall.Equal(pn.syscall) && !next.isLeaf() {
				toBreak = true
				break
			}
		}
		if toBreak {
			a.MergeTrees(a.patternTreeRoot, next)
			if idx := next.endChildIdx(); idx >= 0 {
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
	for _, n := range a.patternTreeRoot.next {
		if n.endChildIdx() >= 0 {
			notInPurgedList := true
			for _, pn := range a.purgedTreeRoot.next {
				if n.syscall.Equal(pn.syscall) {
					notInPurgedList = false
				}
			}
			if notInPurgedList {
				a.purgedTreeRoot.next = append(a.purgedTreeRoot.next, n)
				hasIndependentNode = true
			}
		}
	}
	return hasIndependentNode
}

func (n *TaggedSyscallNode) print(depth *int, depthsWithChildren map[int]bool, hasNext bool) {
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
		next.print(depth, depthsWithChildren, i != len(n.next)-1)
	}

	*depth = *depth - 1
}

func (n *TaggedSyscallNode) Print() {
	depth := 0
	depthsWithOtherChildren := make(map[int]bool)
	n.print(&depth, depthsWithOtherChildren, false)
}

func (a *PatternAnalysis) PrintResult(v Verbose) {
	fmt.Print("pattern tree before purging\n")
	a.patternTreeRoot.Print()
	i := 0
	for {
		if !a.CheckNewIndependentNode() {
			break
		}

		a.PurgeTree(a.patternTreeRoot)
		if v >= DebugV {
			fmt.Print("--------------------------------------------------------------------------------\n")
			fmt.Printf("purging #%v.1\n", i)
			a.patternTreeRoot.Print()
		}
		a.PurgeTree(a.patternTreeRoot)
		if v >= DebugV {
			fmt.Print("--------------------------------------------------------------------------------\n")
			fmt.Printf("purging #%v.2\n", i)
			a.patternTreeRoot.Print()
		}
		i += 1
	}
	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Print("purge tree\n")
	a.purgedTreeRoot.Print()
	fmt.Print("--------------------------------------------------------------------------------\n")
	fmt.Print("pattern tree after purging\n")
	a.patternTreeRoot.Print()
}


