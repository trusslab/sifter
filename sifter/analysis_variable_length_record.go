package sifter

import (
	"fmt"

	"github.com/google/syzkaller/prog"
)

type VlrSequenceNode struct {
	next       []*VlrSequenceNode
	record     *VlrRecord
	counts     map[AnalysisFlag]uint64
	events     []*TraceEvent
	tag        int
	flag       AnalysisFlag
}

type VlrAnalysis struct {
	vlrSequenceRoot []*VlrSequenceNode
	vlrHeaderCount  map[uint64]int
	tagCounter      int
	check           int // 0: header; 1: seq; 2: seq and tag
}

func (a VlrAnalysis) String() string {
	return "vlr analysis"
}

func (a *VlrAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.vlrHeaderCount = make(map[uint64]int)
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			for _, _ = range syscall.vlrMaps {
				a.vlrSequenceRoot = append(a.vlrSequenceRoot, new(VlrSequenceNode))
			}
		}
	}
}

func (a *VlrAnalysis) Reset() {
}

func (a *VlrAnalysis) ProcessTraceEvent(te *TraceEvent, flag AnalysisFlag, opt int) (string, int, int) {
	if te.typ != 1 || te.syscall.vlrMaps == nil {
		return "", 0, 0
	}

	if (te.flag & TraceEventFlagBadData) != 0 {
		return "", 0, 0
	}

	updateOL := 0
	updateMsg := ""
	updateNum := 0
	updateFlag := 0
	for i, vlr := range te.syscall.vlrMaps {
		offset := vlr.offset
		node := a.vlrSequenceRoot[i]
		_, size := te.GetData(48+vlr.lenOffset, 8)
		_, start := te.GetData(56, 8) // Special case for binder
		offset += start

		for {
			_, tr := te.GetData(48+offset, 4)
			var matchedRecord *VlrRecord
			if offset < vlr.offset + size {
				for j, record := range vlr.records {
					if tr == record.header {
						matchedRecord = vlr.records[j]
						break
					}
				}
			}

			if matchedRecord != nil {
				a.vlrHeaderCount[matchedRecord.header] += 1
				updateMsg += matchedRecord.name
			} else {
				if offset < vlr.offset + size && a.check >= 0 {
					updateMsg += fmt.Sprintf("unknown vlr header (%x) at offset:%d", tr, offset+48)
					updateOL = 1
				} else {
					updateMsg += "end"
				}
			}

			nextVlrRecordIdx := -1
			for j, nextRecord := range node.next {
				if nextRecord.record == matchedRecord {
					nextVlrRecordIdx = j
					break
				}
			}

			if nextVlrRecordIdx >= 0 {
				node = node.next[nextVlrRecordIdx]
				if flag == TestFlag && node.flag == TestFlag {
					updateFlag = 1
				}
			} else {
				newNode := new(VlrSequenceNode)
				newNode.record = matchedRecord
				newNode.counts = make(map[AnalysisFlag]uint64)
				node.next = append(node.next, newNode)
				node = newNode
				if flag == TestFlag {
					node.flag = TestFlag
					updateFlag = 1
				}
				if a.check >= 1 {
					updateNum += 1
					updateMsg += "*"
				}
			}

			node.counts[flag] += 1

			if matchedRecord != nil {
				updateMsg += "->"
				offset += matchedRecord.size
			} else {
				if updateFlag == 1 {
					node.tag = -1
				} else if updateNum != 0 {
					a.tagCounter += 1
					node.tag = a.tagCounter
				}
				node.events = append(node.events, te)
				if a.check >= 2 {
					te.tags = append(te.tags, node.tag)
				}
				break
			}
		}
	}
	return updateMsg, updateNum, updateOL
}

func (n *VlrSequenceNode) _Print(depth *int, depthsWithChildren map[int]bool, hasNext bool) {
	*depth = *depth + 1

	s := ""
	if !hasNext {
		depthsWithChildren[*depth] = false
		s += "└"
	} else {
		depthsWithChildren[*depth] = true
		s += "├"
	}

	if n.record == nil {
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
		s += fmt.Sprintf("[%v]%v", *depth, n.record.name)
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
		next._Print(depth, depthsWithChildren, i != len(n.next)-1)
	}

	*depth = *depth - 1
}

func (n *VlrSequenceNode) Print() {
	depth := 0
	depthsWithOtherChildren := make(map[int]bool)
	n._Print(&depth, depthsWithOtherChildren, false)
}

func (a *VlrAnalysis) PostProcess(opt int) {
}

func (a *VlrAnalysis) PrintResult(v Verbose) {
	for i, _ := range a.vlrSequenceRoot {
		a.vlrSequenceRoot[i].Print()
	}
}

func (a *VlrAnalysis) GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint {
	return nil
}
