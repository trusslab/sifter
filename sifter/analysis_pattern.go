package sifter

import (
	"fmt"
)

type TaggedSyscall struct {
	syscall *Syscall
	tags	[]int
}

type TaggedSyscallNode struct {
	next    []*TaggedSyscallNode
	syscall *TaggedSyscall
	counts  map[Flag]uint64
	flag    Flag
	tag     int
}

type PatternAnalysis struct {
	groupingThreshold uint64
	lastNodeOfPid     map[uint32]*TaggedSyscallNode
	lastEventOfPid    map[uint32]*TraceEvent
	patternTreeRoot   *TaggedSyscallNode
	tagCounter        int
}

func (a *PatternAnalysis) String() string {
	return "pattern analysis"
}

func (a *PatternAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.lastNodeOfPid = make(map[uint32]*TaggedSyscallNode)
	a.lastEventOfPid = make(map[uint32]*TraceEvent)
	a.patternTreeRoot = new(TaggedSyscallNode)
	a.patternTreeRoot.syscall = new(TaggedSyscall)
}

func (a *PatternAnalysis) SetGroupingThreshold (th uint64) {
	a.groupingThreshold = th
}

func taggedSyscallEqual(te *TraceEvent, ts *TaggedSyscall) bool {
	if te.syscall != ts.syscall {
		return false
	}

	if len(te.tags) != len(ts.tags) {
		return false
	}

	for i, _ := range te.tags {
		if te.tags[i] != ts.tags[i] {
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
				hasNilNext := false
				for i, _ := range n.next {
					if n.next[i].syscall.syscall == nil {
						n.next[i].counts[flag] += 1
						hasNilNext = true
						break
					}
				}

				if !hasNilNext {
					newEndNode := new(TaggedSyscallNode)
					newEndNode.syscall = new(TaggedSyscall)
					newEndNode.flag = flag
					newEndNode.counts = make(map[Flag]uint64)
					newEndNode.counts[flag] += 1
					newEndNode.tag = a.tagCounter
					n.next = append(n.next, newEndNode)
					a.tagCounter += 1
					a.lastNodeOfPid[pid] = a.patternTreeRoot
					msgs = append(msgs, "new seq")
				}
			}
			a.lastEventOfPid[pid] = te
		}
	} else {

		if event, ok := a.lastEventOfPid[te.id]; ok {
			if te.ts - event.ts > a.groupingThreshold {
				if a.lastNodeOfPid[te.id] != a.patternTreeRoot {
					hasNilNext := false
					for i, _ := range a.lastNodeOfPid[te.id].next {
						if a.lastNodeOfPid[te.id].next[i].syscall.syscall == nil {
							a.lastNodeOfPid[te.id].next[i].counts[flag] += 1
							hasNilNext = true
							break
						}
					}

					if !hasNilNext {
						newEndNode := new(TaggedSyscallNode)
						newEndNode.syscall = new(TaggedSyscall)
						newEndNode.flag = flag
						newEndNode.counts = make(map[Flag]uint64)
						newEndNode.counts[flag] += 1
						newEndNode.tag = a.tagCounter
						a.tagCounter += 1
						a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newEndNode)
						msgs = append(msgs, "new seq")
					}
					a.lastNodeOfPid[te.id] = a.patternTreeRoot
				}
			}
		} else {
			a.lastNodeOfPid[te.id] = a.patternTreeRoot
		}

		nextExist := false
		for _, next := range a.lastNodeOfPid[te.id].next {
			if taggedSyscallEqual(te, next.syscall) {
				next.counts[flag] += 1
				a.lastNodeOfPid[te.id] = next
				nextExist = true
			}
		}

		if !nextExist {
			newNextNode := new(TaggedSyscallNode)
			newNextNode.syscall = new(TaggedSyscall)
			newNextNode.syscall.syscall = te.syscall
			for _, t := range te.tags {
				newNextNode.syscall.tags = append(newNextNode.syscall.tags, t)
			}
			newNextNode.flag = flag
			newNextNode.counts = make(map[Flag]uint64)
			newNextNode.counts[flag] += 1
			newNextNode.tag = a.tagCounter
			a.tagCounter += 1
			a.lastNodeOfPid[te.id].next = append(a.lastNodeOfPid[te.id].next, newNextNode)
			a.lastNodeOfPid[te.id] = newNextNode
			msgs = append(msgs, "new next")
		}
		a.lastEventOfPid[te.id] = te
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

func (n *TaggedSyscallNode) Print(depth *int, depthsWithChildren map[int]bool, hasNext bool) {
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
				s += fmt.Sprintf("[%v]end - seq* (%v/%v)", *depth, n.counts[TrainFlag], n.counts[TestFlag])
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
		next.Print(depth, depthsWithChildren, i != len(n.next)-1)
	}

	*depth = *depth - 1
}

func (a *PatternAnalysis) PrintResult() {
	depth := 0
	depthsWithOtherChildren := make(map[int]bool)
	a.patternTreeRoot.Print(&depth, depthsWithOtherChildren, false)
}


