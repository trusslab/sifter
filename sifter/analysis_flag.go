package sifter

import (
	"encoding/binary"
	"fmt"
//	"math"

	"github.com/google/syzkaller/prog"
)

type FlagSet struct {
	values map[uint64]int
}

func (flags *FlagSet) Update(v uint64, f Flag) int {
	count, ok := flags.values[v]

	if f == TrainFlag {
		flags.values[v] += 1
	}

	return count
}

func newFlagSet() FlagSet {
	newFlags := FlagSet{}
	newFlags.values = make(map[uint64]int)
	return newFlags
}

type FlagAnalysis struct {
	argRanges map[*ArgMap][]FlagSet
	regRanges map[*Syscall][]FlagSet
	vlrRanges map[*VlrMap]map[*VlrRecord][]FlagSet
	moduleSyscalls map[*Syscall]bool
}

func (a *FlagAnalysis) String() string {
	return "flag analysis"
}

func (a *FlagAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argRanges = make(map[*ArgMap][]FlagSet)
	a.regRanges = make(map[*Syscall][]FlagSet)
	a.vlrRanges = make(map[*VlrMap]map[*VlrRecord][]FlagSet)
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			for _, arg := range syscall.def.Args {
				if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
					a.regRanges[syscall] = append(a.regRanges[syscall], newFlagSet())
				}
			}
			for _, arg := range syscall.argMaps {
				if structArg, ok := arg.arg.(*prog.StructType); ok {
					for _, field := range structArg.Fields {
						if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
							a.argRanges[arg] = append(a.argRanges[arg], newFlagSet())
						}
					}
				} else {
					a.argRanges[arg] = append(a.argRanges[arg], newFlagSet())
				}
			}
			for _, vlr := range syscall.vlrMaps {
				a.vlrRanges[vlr] = make(map[*VlrRecord][]FlagSet)
				for _, record := range vlr.records {
					if structArg, ok := record.arg.(*prog.StructType); ok {
						for _, f := range structArg.Fields {
							if structField, ok := f.(*prog.StructType); ok {
								for _, field := range structField.Fields {
									if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
										a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], newFlagSet())
									}
								}
							} else {
								if _, isFlagsArg := f.(*prog.FlagsType); isFlagsArg {
									a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], newFlagSet())
								}
							}
						}
					}
				}
			}
		}
	}

	a.moduleSyscalls = make(map[*Syscall]bool)
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			a.moduleSyscalls[syscall] = true
		}
	}
}

func (a *FlagAnalysis) Reset() {
}

func (a *FlagAnalysis) ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int) {
	if (te.id & 0x80000000) != 0 {
		return "", 0
	}

	if _, ok := a.moduleSyscalls[te.syscall]; !ok {
		return "", 0
	}

	msgs := make([]string, 0)
	var offset uint64
	for i, arg := range te.syscall.def.Args {
		f := 0
		if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
			_, tr := te.GetData(offset, 8)
			if a.regRanges[te.syscall][f].Update(tr, flag) == 0 {
				msgs = append(msgs, fmt.Sprintf("reg[%v] new flag %x", i, tr))
			}
			te.tags = append(te.tags, int(tr))
			f += 1
		}
		offset += 8
	}
	for _, arg := range te.syscall.argMaps {
		f := 0
		if structArg, ok := arg.arg.(*prog.StructType); ok {
			for _, field := range structArg.Fields {
				if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
					_, tr := te.GetData(offset, field.Size())
					if a.argRanges[arg][f].Update(tr, flag) == 0{
						msgs = append(msgs, fmt.Sprintf("%v::%v new flag %x", arg.name, field.Name(), tr))
					}
					te.tags = append(te.tags, int(tr))
					f += 1
				}
				offset += field.Size()
			}
		} else {
			if flagArg, isFlagsArg := arg.arg.(*prog.FlagsType); isFlagsArg {
				_, tr := te.GetData(offset, flagArg.Size())
				if a.argRanges[arg][f].Update(tr, flag) == 0{
					msgs = append(msgs, fmt.Sprintf("%v new flag %x", arg.name, tr))
				}
				te.tags = append(te.tags, int(tr))
				f += 1
			}
			offset += arg.size
		}
	}
	for _, vlr := range te.syscall.vlrMaps {
		size := uint64(binary.LittleEndian.Uint32(te.data[48:56]))
		start := uint64(binary.LittleEndian.Uint32(te.data[56:64]))
		offset += start
		for {
			tr := uint64(binary.LittleEndian.Uint32(te.data[offset:offset+4]))
			var matchedRecord *VlrRecord
			if offset < size+vlr.offset+48 {
				for i, record := range vlr.records {
					if tr == record.header {
						matchedRecord = vlr.records[i]
						break
					}
				}
			}
			offset += 4
			if matchedRecord != nil {
				structArg, _ := matchedRecord.arg.(*prog.StructType)
				for i, field := range structArg.Fields {
					f := 0
					if i == 0 {
						continue
					}
					if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
						_, tr := te.GetData(offset, field.Size())
						if a.vlrRanges[vlr][matchedRecord][f].Update(tr, flag) == 0{
							msgs = append(msgs, fmt.Sprintf("%v new flag %x", field.Name(), tr))
						}
						te.tags = append(te.tags, int(tr))
						f += 1
					}
					offset += field.Size()
				}
				continue;
			} else {
				break;
			}
		}
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

func (a *FlagAnalysis) PrintResult(v Verbose) {
//	for syscall, regRange := range a.regRanges {
//		fmt.Printf("\n%v\n", syscall.name)
//		for i := 0; i < 6; i++ {
//			fmt.Printf("reg[%v] %v\n", i, regRange[i*2:i*2+2])
//		}
//		for _, arg := range syscall.argMaps {
//			fmt.Printf("%v %v\n", arg.name, a.argRanges[arg])
//		}
//		for _, vlr := range syscall.vlrMaps {
//			fmt.Printf("\n%v %v\n", vlr.name, len(vlr.records))
//			for _, record := range vlr.records {
//				fmt.Printf("%v %v\n", record.name, a.vlrRanges[vlr][record])
//			}
//		}
//	}
}


