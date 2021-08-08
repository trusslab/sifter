package sifter

import (
	"fmt"

	"github.com/google/syzkaller/prog"
)

type FlagSet struct {
	values map[uint64]int
}

func (flags *FlagSet) Update(v uint64, f Flag) int {
	count, _ := flags.values[v]

	if f == TrainFlag {
		flags.values[v] += 1
	}

	return count
}

func newFlagSet() *FlagSet {
	newFlags := new(FlagSet)
	newFlags.values = make(map[uint64]int)
	return newFlags
}

func (flags *FlagSet) String() string {
	s := ""
	for flag, count := range flags.values {
		s += fmt.Sprintf("%x(%d) ", flag, count)
	}
	return s
}

type FlagAnalysis struct {
	argFlags map[*ArgMap]map[int]*FlagSet
	regFlags map[*Syscall]map[int]*FlagSet
	vlrFlags map[*VlrMap]map[*VlrRecord]map[int]*FlagSet
	moduleSyscalls map[*Syscall]bool
}

func (a *FlagAnalysis) String() string {
	return "flag analysis"
}

func (a *FlagAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argFlags = make(map[*ArgMap]map[int]*FlagSet)
	a.regFlags = make(map[*Syscall]map[int]*FlagSet)
	a.vlrFlags = make(map[*VlrMap]map[*VlrRecord]map[int]*FlagSet)
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			a.regFlags[syscall] = make(map[int]*FlagSet)
			for i, arg := range syscall.def.Args {
				if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
					a.regFlags[syscall][i] = newFlagSet()
				}
			}
			for _, arg := range syscall.argMaps {
				a.argFlags[arg] = make(map[int]*FlagSet)
				if structArg, ok := arg.arg.(*prog.StructType); ok {
					for i, field := range structArg.Fields {
						if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
							a.argFlags[arg][i] = newFlagSet()
						}
					}
				} else {
					a.argFlags[arg][0] = newFlagSet()
				}
			}
			for _, vlr := range syscall.vlrMaps {
				a.vlrFlags[vlr] = make(map[*VlrRecord]map[int]*FlagSet)
				for _, record := range vlr.records {
					a.vlrFlags[vlr][record] = make(map[int]*FlagSet)
					if structArg, ok := record.arg.(*prog.StructType); ok {
						for fi, f := range structArg.Fields {
							if structField, ok := f.(*prog.StructType); ok {
								for ffi, field := range structField.Fields {
									if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
										a.vlrFlags[vlr][record][ffi+fi*100] = newFlagSet()
									}
								}
							} else {
								if _, isFlagsArg := f.(*prog.FlagsType); isFlagsArg {
									a.vlrFlags[vlr][record][fi*100] = newFlagSet()
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
		if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
			_, tr := te.GetData(offset, 8)
			if a.regFlags[te.syscall][i].Update(tr, flag) == 0 {
				msgs = append(msgs, fmt.Sprintf("reg[%v] new flag %x", i, tr))
			}
			te.tags = append(te.tags, int(tr))
		}
		offset += 8
	}
	for _, arg := range te.syscall.argMaps {
		if structArg, ok := arg.arg.(*prog.StructType); ok {
			for fi, field := range structArg.Fields {
				if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
					_, tr := te.GetData(offset, field.Size())
					if a.argFlags[arg][fi].Update(tr, flag) == 0{
						msgs = append(msgs, fmt.Sprintf("%v::%v new flag %x", arg.name, field.Name(), tr))
					}
					te.tags = append(te.tags, int(tr))
				}
				offset += field.Size()
			}
		} else {
			if flagArg, isFlagsArg := arg.arg.(*prog.FlagsType); isFlagsArg {
				_, tr := te.GetData(offset, flagArg.Size())
				if a.argFlags[arg][0].Update(tr, flag) == 0{
					msgs = append(msgs, fmt.Sprintf("%v new flag %x", arg.name, tr))
				}
				te.tags = append(te.tags, int(tr))
			}
			offset += arg.size
		}
	}
	for _, vlr := range te.syscall.vlrMaps {
		_, size := te.GetData(48, 8)
		_, start := te.GetData(56, 8)
		offset += start
		for {
			_, tr := te.GetData(48+offset, 4)
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
				for fi, f := range structArg.Fields {
					if fi == 0 {
						continue
					}
					if structField, ok := f.(*prog.StructType); ok {
						fieldOffset := uint64(0)
						for ffi, field := range structField.Fields {
							if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
								_, tr := te.GetData(offset+fieldOffset, field.Size())
								if a.vlrFlags[vlr][matchedRecord][ffi+fi*100].Update(tr, flag) == 0{
									msgs = append(msgs, fmt.Sprintf("%v::%v new flag %x", f.Name(), field.Name(), tr))
								}
								te.tags = append(te.tags, int(tr))
							}
							fieldOffset += field.Size()
						}
					} else {
						if _, isFlagsArg := f.(*prog.FlagsType); isFlagsArg {
							_, tr := te.GetData(offset, f.Size())
							if a.vlrFlags[vlr][matchedRecord][fi*100].Update(tr, flag) == 0{
								msgs = append(msgs, fmt.Sprintf("%v new flag %x", f.Name(), tr))
							}
							te.tags = append(te.tags, int(tr))
						}
					}
					offset += f.Size()
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
	for syscall, _ := range a.moduleSyscalls {
		s := ""
		for i, regFlag := range a.regFlags[syscall] {
			s += fmt.Sprintf("reg[%v]: %v\n", i, regFlag)
		}
		for _, argMap := range syscall.argMaps {
			arg := argMap.arg
			if structArg, ok := arg.(*prog.StructType); ok {
				for i, argFlag := range a.argFlags[argMap] {
					s += fmt.Sprintf("%v::%v: %v\n", argMap.name, structArg.Fields[i].Name(), argFlag)
				}
			} else {
				s += fmt.Sprintf("%v %v\n", argMap.name, a.argFlags[argMap][0])
			}
		}
		for _, vlrMap := range syscall.vlrMaps {
			fmt.Printf("\nvlr %v %v\n", vlrMap.name, len(vlrMap.records))
			for _, vlrRecord := range vlrMap.records {
				for i, vlrFlag := range a.vlrFlags[vlrMap][vlrRecord] {
					structArg, _ := vlrRecord.arg.(*prog.StructType)
					fi := i / 100
					ffi := i % 100
					if ffi == 0 {
						s += fmt.Sprintf("%v::%v: %v\n", vlrRecord.name, structArg.Fields[fi].Name(), vlrFlag)
					} else {
						structField, _ := structArg.Fields[fi].(*prog.StructType)
						s += fmt.Sprintf("%v::%v::%v: %v\n", vlrRecord.name, structArg.Fields[fi].Name(), structField.Fields[ffi], vlrFlag)
					}
				}
			}
		}
		if len(s) != 0 {
			fmt.Print("--------------------------------------------------------------------------------\n")
			fmt.Printf("%v\n%s", syscall.name, s)
		}
	}
}


