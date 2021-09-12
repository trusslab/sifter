package sifter

import (
	"fmt"

	"github.com/google/syzkaller/prog"
)

type Node struct {
	syscall *Syscall
	tags    []int
	flag    Flag
}

func (n *Node) String() string {
	return fmt.Sprintf("%v%v", n.syscall.name, n.tags)
}

type Edge struct {
	next    *Node
	prevs   []*Node
	flag    Flag
	counts  map[Flag]uint64
}

func (e *Edge) String() string {
	s := fmt.Sprintf("->n[%v] prevs(", e.next)
	for i, n := range e.prevs {
		s += fmt.Sprintf("%v", n)
		if i != len(e.prevs)-1 {
			s += fmt.Sprintf("->")
		}
	}
	s += fmt.Sprintf(") (%v/%v)", e.counts[TrainFlag], e.counts[TestFlag])
	return s
}

type SequenceAnalysis struct {
	seqLen   int
	nodes    []*Node
	prevs    []*Node
	seqGraph map[*Node][]*Edge
}

func (a SequenceAnalysis) String() string {
	return "sequence analysis"
}

func (a *SequenceAnalysis) SetLen(l int) {
	a.seqLen = l
}

func tagsEqual (t1 []int, t2 []int) bool {
	if (len(t1) != len(t2)) {
		return false
	}

	for i := 0; i < len(t1); i++ {
		if t1[i] != t2[i] {
			return false
		}
	}
	return true
}

func (a SequenceAnalysis) edgesEqual(e1 *Edge, e2 *Edge) bool {
	if e1.next != e2.next {
		return false
	}

	for i := 0; i < a.seqLen; i++ {
		if e1.prevs[i] != e2.prevs[i] {
			return false
		}
	}
	return true
}

func (a *SequenceAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.seqGraph = make(map[*Node][]*Edge)
	a.prevs = make([]*Node, a.seqLen+1)
}

func (a *SequenceAnalysis) Reset() {
}

func (a *SequenceAnalysis) lastNode() *Node {
	return a.prevs[a.seqLen]
}

func (a *SequenceAnalysis) findEdge(te *TraceEvent, nextNode *Node, flag Flag) (bool, *Edge) {
	lastNode := a.lastNode()

	newEdge := new(Edge)
	newEdge.next = nextNode
	newEdge.prevs = a.prevs[0:a.seqLen]
	newEdge.flag = flag
	newEdge.counts = make(map[Flag]uint64)
	newEdge.counts[flag] = 1

	for _, edge := range a.seqGraph[lastNode] {
		if a.edgesEqual(newEdge, edge) {
			edge.counts[flag] += 1
			if flag == TestFlag && edge.flag == TestFlag {
				return true, edge
			} else {
				return false, edge
			}
		}
	}
	a.seqGraph[lastNode] = append(a.seqGraph[lastNode], newEdge)
	return true, newEdge
}

func (a *SequenceAnalysis) findNode(te *TraceEvent, flag Flag) (bool, *Node) {
	for i, node := range a.nodes {
		if te.syscall == node.syscall && tagsEqual(te.tags, node.tags) {
			if flag == TestFlag && node.flag == TestFlag {
				return true, a.nodes[i]
			} else {
				return false, a.nodes[i]
			}
		}
	}
	a.nodes = append(a.nodes, &Node{te.syscall, te.tags, flag})
	newNode := a.nodes[len(a.nodes)-1]
	a.seqGraph[newNode] = make([]*Edge, 0)
	return true, newNode
}

func (a *SequenceAnalysis) ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int, int) {
	if te.typ != 1 {
		return "", 0, 0
	}

	updateMsg := ""
	updateNum := 0

	updateNode, nextNode := a.findNode(te, flag)
	if updateNode {
		updateMsg += fmt.Sprintf("new n[%v] ", nextNode)
		updateNum += 1
	}

	if a.prevs[0] != nil {
		updateEdge, edge := a.findEdge(te, nextNode, flag)
		if updateEdge {
			updateMsg += fmt.Sprintf("new e:n[%v]%v", a.lastNode(), edge)
			updateNum += 1
		}
	}

	a.prevs = a.prevs[1:]
	a.prevs = append(a.prevs, nextNode)
	return updateMsg, updateNum, 0
}

func (a *SequenceAnalysis) PostProcess(flag Flag) {
}

func (a *SequenceAnalysis) PrintResult(v Verbose) {
	for node, edges := range a.seqGraph {
		fmt.Printf("%v\n", node)
		for _, edge := range edges {
			fmt.Printf("  %v\n", edge)
		}
	}
}

func (a *SequenceAnalysis) GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint {
	return nil
}
