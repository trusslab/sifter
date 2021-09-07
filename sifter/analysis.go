package sifter

import (
	"github.com/google/syzkaller/prog"
)

type Flag int

const (
	TrainFlag Flag = iota
	TestFlag
)

type Analysis interface {
	String() string
	Init(TracedSyscalls *map[string][]*Syscall)
	Reset()
	ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int, int)
	PostProcess(flag Flag)
	PrintResult(v Verbose)
	GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint
}

