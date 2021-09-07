package sifter

import (
	"fmt"

	"github.com/google/syzkaller/prog"
)

type FlagSet struct {
	values map[uint64]int
	idx    int
}

func (flags *FlagSet) Update(v uint64, f Flag) int {
	count, _ := flags.values[v]

	if f == TrainFlag {
		flags.values[v] += 1
	}

	return count
}

func newFlagSet(idx int) *FlagSet {
	newFlags := new(FlagSet)
	newFlags.values = make(map[uint64]int)
	newFlags.idx = idx
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
	argFlags map[*ArgMap]map[prog.Type]*FlagSet
	regFlags map[*Syscall]map[prog.Type]*FlagSet
	vlrFlags map[*VlrMap]map[*VlrRecord]map[prog.Type]*FlagSet
	moduleSyscalls map[*Syscall]bool
}

func (a *FlagAnalysis) String() string {
	return "flag analysis"
}

func (a *FlagAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argFlags = make(map[*ArgMap]map[prog.Type]*FlagSet)
	a.regFlags = make(map[*Syscall]map[prog.Type]*FlagSet)
	a.vlrFlags = make(map[*VlrMap]map[*VlrRecord]map[prog.Type]*FlagSet)
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			idx := 0
			a.regFlags[syscall] = make(map[prog.Type]*FlagSet)
			for i, arg := range syscall.def.Args {
				if syscall.def.CallName == "ioctl" && i == 1 {
					a.regFlags[syscall][arg] = newFlagSet(idx)
					idx += 1
				}

				if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
					a.regFlags[syscall][arg] = newFlagSet(idx)
					idx += 1
				}
			}
			for _, argMap := range syscall.argMaps {
				a.argFlags[argMap] = make(map[prog.Type]*FlagSet)
				if structArg, ok := argMap.arg.(*prog.StructType); ok {
					for _, field := range structArg.Fields {
						if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
							a.argFlags[argMap][field] = newFlagSet(idx)
							idx += 1
						}
					}
				} else {
					a.argFlags[argMap][argMap.arg] = newFlagSet(idx)
					idx += 1
				}
			}
			for _, vlr := range syscall.vlrMaps {
				a.vlrFlags[vlr] = make(map[*VlrRecord]map[prog.Type]*FlagSet)
				for _, record := range vlr.records {
					a.vlrFlags[vlr][record] = make(map[prog.Type]*FlagSet)
					if structArg, ok := record.arg.(*prog.StructType); ok {
						for _, f := range structArg.Fields {
							if structField, ok := f.(*prog.StructType); ok {
								for _, ff := range structField.Fields {
									if _, isFlagsArg := ff.(*prog.FlagsType); isFlagsArg {
										a.vlrFlags[vlr][record][ff] = newFlagSet(idx)
										idx += 1
									}
								}
							} else {
								if _, isFlagsArg := f.(*prog.FlagsType); isFlagsArg {
									a.vlrFlags[vlr][record][f] = newFlagSet(idx)
									idx += 1
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

func (a *FlagAnalysis) ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int, int) {
	if te.typ != 1 {
		return "", 0, 0
	}

	msgs := make([]string, 0)
	var offset uint64
	for i, arg := range te.syscall.def.Args {
		if te.syscall.def.CallName == "ioctl" && i == 1 {
			_, tr := te.GetData(offset, 8)
			if a.regFlags[te.syscall][arg].Update(tr, flag) == 0 {
				msgs = append(msgs, fmt.Sprintf("reg[%v] new flag %x", i, tr))
			}
		}
		if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
			_, tr := te.GetData(offset, 8)
			if a.regFlags[te.syscall][arg].Update(tr, flag) == 0 {
				msgs = append(msgs, fmt.Sprintf("reg[%v] new flag %x", i, tr))
			}
			te.tags = append(te.tags, int(tr))
		}
		offset += 8
	}
	offset = 48
	for _, argMap := range te.syscall.argMaps {
		if structArg, ok := argMap.arg.(*prog.StructType); ok {
			for _, field := range structArg.Fields {
				if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
					_, tr := te.GetData(offset, field.Size())
					if a.argFlags[argMap][field].Update(tr, flag) == 0{
						msgs = append(msgs, fmt.Sprintf("%v::%v new flag %x", argMap.name, field.Name(), tr))
					}
					te.tags = append(te.tags, int(tr))
				}
				offset += field.Size()
			}
		} else {
			if flagArg, isFlagsArg := argMap.arg.(*prog.FlagsType); isFlagsArg {
				_, tr := te.GetData(offset, flagArg.Size())
				if a.argFlags[argMap][argMap.arg].Update(tr, flag) == 0{
					msgs = append(msgs, fmt.Sprintf("%v new flag %x", argMap.name, tr))
				}
				te.tags = append(te.tags, int(tr))
			}
			offset += argMap.size
		}
	}
	for _, vlr := range te.syscall.vlrMaps {
		_, size := te.GetData(48+vlr.lenOffset, 8)
		_, start := te.GetData(56, 8) // Special case for binder
		offset += start
		for {
			_, tr := te.GetData(offset, 4)
			var vlrRecord *VlrRecord
			if offset < size+vlr.offset+48 {
				for i, record := range vlr.records {
					if tr == record.header {
						vlrRecord = vlr.records[i]
						break
					}
				}
			}
			offset += 4
			if vlrRecord != nil {
				structArg, _ := vlrRecord.arg.(*prog.StructType)
				for i, f := range structArg.Fields {
					if i == 0 {
						continue
					}
					if structField, ok := f.(*prog.StructType); ok {
						fieldOffset := uint64(0)
						for _, ff := range structField.Fields {
							if _, isFlagsArg := ff.(*prog.FlagsType); isFlagsArg {
								_, tr := te.GetData(offset+fieldOffset, ff.Size())
								if a.vlrFlags[vlr][vlrRecord][ff].Update(tr, flag) == 0 {
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v new flag %x", vlrRecord.name, f.FieldName(), ff.FieldName(), tr))
								}
								te.tags = append(te.tags, int(tr))
							}
							fieldOffset += ff.Size()
						}
					} else {
						if _, isFlagsArg := f.(*prog.FlagsType); isFlagsArg {
							_, tr := te.GetData(offset, f.Size())
							if a.vlrFlags[vlr][vlrRecord][f].Update(tr, flag) == 0 {
								msgs = append(msgs, fmt.Sprintf("%v_%v new flag %x", vlrRecord.name, f.FieldName(), tr))
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
	return updatedRangesMsg, updatedRangesLen, 0
}

func (a *FlagAnalysis) PostProcess(flag Flag) {
}

func (a *FlagAnalysis) PrintResult(v Verbose) {
	for syscall, _ := range a.moduleSyscalls {
		s := ""
		for i, arg := range syscall.def.Args {
			if syscall.def.CallName == "ioctl" && i == 1 {
				if flags, ok := a.regFlags[syscall][arg]; ok {
					s += fmt.Sprintf("reg[%v]: %x", i, flags)
				}
			}
			if flags, ok := a.regFlags[syscall][arg]; ok {
				s += fmt.Sprintf("reg[%v]: %v\n", i, flags)
			}
		}
		for _, argMap := range syscall.argMaps {
			if structArg, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structArg.Fields {
					if flags, ok := a.argFlags[argMap][field]; ok {
						 s += fmt.Sprintf("%v_%v: %v\n", argMap.name, field.FieldName(), flags)
					}
				}
			} else {
				if flags, ok := a.argFlags[argMap][argMap.arg]; ok {
					s += fmt.Sprintf("%v: %v\n", argMap.name, flags)
				}
			}
		}
		for _, vlrMap := range syscall.vlrMaps {
			fmt.Printf("\n%v (%v)\n", vlrMap.name, len(vlrMap.records))
			for _, vlrRecord := range vlrMap.records {
				structArg, _ := vlrRecord.arg.(*prog.StructType)
				for _, f := range structArg.Fields {
					if structField, isStructArg := f.(*prog.StructType); isStructArg {
						for _, ff := range structField.Fields {
							if flags, ok := a.vlrFlags[vlrMap][vlrRecord][ff]; ok {
								s += fmt.Sprintf("%v_%v_%v: %v\n", vlrRecord.name, f.FieldName(), ff.FieldName(), flags)
							}
						}
					} else {
						if flags, ok := a.vlrFlags[vlrMap][vlrRecord][f]; ok {
							s += fmt.Sprintf("%v_%v: %v\n", vlrRecord.name, f.FieldName(), flags)
						}
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

func (a *FlagAnalysis) GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint {
	var constraint *TaggingConstraint
	if depth == 0 {
		if f, ok := a.regFlags[syscall][arg]; ok {
			fmt.Printf("add tagging constraint to %v %v\n", syscall.name, arg.FieldName())
			constraint = new(TaggingConstraint)
			constraint.idx = f.idx
			return constraint
		}
	} else {
		if f, ok := a.argFlags[argMap][arg]; ok {
			fmt.Printf("add tagging constraint to %v %v\n", syscall.name, arg.FieldName())
			constraint = new(TaggingConstraint)
			constraint.idx = f.idx
		}
	}
//	var constraint *ValuesConstraint
//	if depth == 0 {
//		if f, ok := a.regFlags[syscall][arg]; ok {
//			fmt.Printf("add values constraint to %v %v\n", syscall.name, arg.FieldName())
//			constraint = new(ValuesConstraint)
//			for v, _ := range f.values {
//				constraint.values = append(constraint.values, v)
//			}
//			return constraint
//		}
//	} else {
//		if f, ok := a.argFlags[argMap][arg]; ok {
//			fmt.Printf("add values constraint to %v %v\n", syscall.name, arg.FieldName())
//			constraint = new(ValuesConstraint)
//			for v, _ := range f.values {
//				constraint.values = append(constraint.values, v)
//			}
//			return constraint
//		}
//	}
	return nil
}

