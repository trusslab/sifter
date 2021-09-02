package sifter

import (
	"fmt"
)

type Node struct {
	syscall *Syscall
	tags    []int
	flag    Flag
}

type Edge struct {
	next    *Node
	prevs   []*Node
	flag    Flag
	counts  map[Flag]uint64
}

type SequenceAnalysis struct {
	seqLen   int
	nodes    []Node
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

func (a *SequenceAnalysis) ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int, int) {
	if te.typ != 1 {
		return "", 0, 0
	}

	updateMsg := ""
	updateNum := 0

	currNode := a.prevs[a.seqLen]
	var nextNode *Node
	for i, node := range a.nodes {
		if te.syscall == node.syscall && tagsEqual(te.tags, node.tags) {
			nextNode = &a.nodes[i]
		}
	}
	if nextNode == nil {
		a.nodes = append(a.nodes, Node{te.syscall, te.tags, flag})
		nextNode = &a.nodes[len(a.nodes)-1]
	}

	if nextNode == nil || nextNode.flag == TestFlag {
		updateMsg += fmt.Sprintf("new n[%v %v] ", te.syscall.name, te.tags)
		updateNum += 1
	}

	if a.prevs[0] != nil {
		newEdge := new(Edge)
		newEdge.next = nextNode
		newEdge.prevs = a.prevs[0:a.seqLen]
		newEdge.flag = flag
		newEdge.counts = make(map[Flag]uint64)
		newEdge.counts[flag] = 1
		var existedEdge *Edge
		if edges, ok := a.seqGraph[currNode]; ok {
			for i, edge := range edges {
				if a.edgesEqual(newEdge, edge) {
					existedEdge = edges[i]
					existedEdge.counts[flag] += 1
				}
			}
		} else {
			a.seqGraph[currNode] = make([]*Edge, 0)
		}
		if existedEdge == nil {
			a.seqGraph[currNode] = append(a.seqGraph[currNode], newEdge)
		}

		if existedEdge == nil || existedEdge.flag == TestFlag {
			updateMsg += fmt.Sprintf("new e:n[%v %v]->n[%v %v] prevs(", currNode.syscall.name, currNode.tags, nextNode.syscall.name, nextNode.tags)
			for _, n := range newEdge.prevs {
				updateMsg += fmt.Sprintf("%v %v->", n.syscall.name, n.tags)
			}
			updateMsg += fmt.Sprintf(")")
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
		fmt.Printf("%v %v\n", node.syscall.name, node.tags)
		for _, edge := range edges {
			fmt.Printf("  ->%v %v (", edge.next.syscall.name, edge.next.tags)
			for i, prevNode := range edge.prevs {
				fmt.Printf("%v %v", prevNode.syscall.name, prevNode.tags)
				if i != len(edge.prevs)-1 {
					fmt.Printf(", ")
				}
			}
			fmt.Printf(") (%v/%v)\n", edge.counts[TrainFlag], edge.counts[TestFlag])
		}
	}
}

