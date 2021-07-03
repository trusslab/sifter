package sifter

type Flag int

const (
	TrainFlag Flag = iota
	TestFlag
)

type Analysis interface {
	String() string
	Init(TracedSyscalls *map[string][]*Syscall)
	ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int)
	PrintResult()
}

