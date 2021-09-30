package sifter

import (
	"github.com/google/syzkaller/prog"
)

type AnalysisFlag int

const (
	TrainFlag AnalysisFlag = iota
	TestFlag
)

type Analysis interface {
	String() string
	Init(TracedSyscalls *map[string][]*Syscall)
	Reset()
	ProcessTraceEvent(te *TraceEvent, flag AnalysisFlag, opt int) (string, int, int)
	PostProcess(opt int)
	PrintResult(v Verbose)
	GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint
}
