package sifter

import (
	"fmt"

	"github.com/google/syzkaller/prog"
)

type FlagSet struct {
	values map[uint64][]int
	idx    int
}

func (flags *FlagSet) Update(v uint64, f AnalysisFlag, opt int) (bool, bool) {
	_, ok := flags.values[v]
	if !ok {
		flags.values[v] = make([]int, 2)
	}

	update := false
	updateOL := false
	if f == TrainFlag {
		if opt == 0 {
			flags.values[v][0] += 1
			update = !ok
		} else if opt == 1 {
			if flags.values[v][0] == 0 {
				updateOL = true
			}
		}
	} else if f == TestFlag {
		if flags.values[v][0] == 0 {
			flags.values[v][1] += 1
			if flags.values[v][1] > 10 {
				fmt.Printf("Warning: might have a false positive\n")
				update = true
			} else {
				updateOL = true
			}
		}
	}

	return update, updateOL
}

func (flags *FlagSet) RemoveOutlier() bool {
	sum := 0
	for _, c := range flags.values {
		sum += c[0]
	}
	freqThreshold := 0.0001
	absThreshold := 10
	outliers := make([]string, 0)
	for v, c := range flags.values {
		if float64(c[0]) / float64(sum) < freqThreshold && c[0] < absThreshold {
			outliers = append(outliers, fmt.Sprintf("%v\n", v))
			//delete(flags.values, v)
			flags.values[v][0] = 0
		}
	}
	if len(outliers) > 0 {
		fmt.Printf("flags outliers:\n")
		for _, outlier := range outliers {
			fmt.Printf("%v", outlier)
		}
	}
	return len(outliers) != 0
}

func newFlagSet(idx int) *FlagSet {
	newFlags := new(FlagSet)
	newFlags.values = make(map[uint64][]int)
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

func (a *FlagAnalysis) ProcessTraceEvent(te *TraceEvent, flag AnalysisFlag, opt int) (string, int, int) {
	if te.typ != 1 {
		return "", 0, 0
	}

	var ol []bool
	msgs := make([]string, 0)
	var offset uint64
	for i, arg := range te.syscall.def.Args {
		if te.syscall.def.CallName == "ioctl" && i == 1 {
			_, tr := te.GetData(offset, 8)
			update, updateOL := a.regFlags[te.syscall][arg].Update(tr, flag, opt)
			if update || updateOL {
				msgs = append(msgs, fmt.Sprintf("reg[%v] new flag %x", i, tr))
				ol  = append(ol, updateOL)
			}
			if (flag == TestFlag) || (flag == TrainFlag && !updateOL) {
				te.tags = append(te.tags, int(tr))
			} else {
				te.flag = te.flag | TraceEventFlagBadData
			}
		}
		if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
			_, tr := te.GetData(offset, 8)
			update, updateOL := a.regFlags[te.syscall][arg].Update(tr, flag, opt)
			if update || updateOL {
				msgs = append(msgs, fmt.Sprintf("reg[%v] new flag %x", i, tr))
				ol  = append(ol, updateOL)
			}
			if (flag == TestFlag) || (flag == TrainFlag && !updateOL) {
				te.tags = append(te.tags, int(tr))
			} else {
				te.flag = te.flag | TraceEventFlagBadData
			}
		}
		offset += 8
	}
	offset = 48
	for _, argMap := range te.syscall.argMaps {
		if structArg, ok := argMap.arg.(*prog.StructType); ok {
			for _, field := range structArg.Fields {
				if _, isFlagsArg := field.(*prog.FlagsType); isFlagsArg {
					_, tr := te.GetData(offset, field.Size())
					update, updateOL := a.argFlags[argMap][field].Update(tr, flag, opt)
					if update || updateOL {
						msgs = append(msgs, fmt.Sprintf("%v::%v new flag %x", argMap.name, field.Name(), tr))
						ol  = append(ol, updateOL)
					}
					if (flag == TestFlag) || (flag == TrainFlag && !updateOL) {
						te.tags = append(te.tags, int(tr))
					} else {
						te.flag = te.flag | TraceEventFlagBadData
					}
				}
				offset += field.Size()
			}
		} else {
			if flagArg, isFlagsArg := argMap.arg.(*prog.FlagsType); isFlagsArg {
				_, tr := te.GetData(offset, flagArg.Size())
				update, updateOL := a.argFlags[argMap][argMap.arg].Update(tr, flag, opt)
				if update || updateOL {
					msgs = append(msgs, fmt.Sprintf("%v new flag %x", argMap.name, tr))
					ol  = append(ol, updateOL)
				}
				if (flag == TestFlag) || (flag == TrainFlag && !updateOL) {
					te.tags = append(te.tags, int(tr))
				} else {
					te.flag = te.flag | TraceEventFlagBadData
				}
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
								update, updateOL := a.vlrFlags[vlr][vlrRecord][ff].Update(tr, flag, opt)
								if update || updateOL {
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v new flag %x", vlrRecord.name, f.FieldName(), ff.FieldName(), tr))
									ol  = append(ol, updateOL)
								}
								if (flag == TestFlag) || (flag == TrainFlag && !updateOL) {
									te.tags = append(te.tags, int(tr))
								} else {
									te.flag = te.flag | TraceEventFlagBadData
								}
							}
							fieldOffset += ff.Size()
						}
					} else {
						if _, isFlagsArg := f.(*prog.FlagsType); isFlagsArg {
							_, tr := te.GetData(offset, f.Size())
							update, updateOL := a.vlrFlags[vlr][vlrRecord][f].Update(tr, flag, opt)
							if update || updateOL {
								msgs = append(msgs, fmt.Sprintf("%v_%v new flag %x", vlrRecord.name, f.FieldName(), tr))
								ol  = append(ol, updateOL)
							}
							if (flag == TestFlag) || (flag == TrainFlag && !updateOL) {
								te.tags = append(te.tags, int(tr))
							} else {
								te.flag = te.flag | TraceEventFlagBadData
							}
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
	updateMsg := ""
	updateFP := 0
	updateTP := 0
	for i, msg := range msgs {
		updateMsg += msg
		if ol[i] {
			updateMsg += " outlier"
			updateTP += 1
		} else {
			updateFP += 1
		}
		if i != len(msg)-1 {
			updateMsg += ", "
		}
	}
	return updateMsg, updateFP, updateTP
}

func (a *FlagAnalysis) PostProcess(opt int) {
	if opt == 0 {
		a.RemoveOutliers()
	}
}

func (a *FlagAnalysis) RemoveOutliers() {
	fmt.Printf("removing outlier flag:\n")
	for syscall, _ := range a.moduleSyscalls {
		fmt.Printf("%v\n", syscall.name)
		for i, arg := range syscall.def.Args {
			if flags, ok := a.regFlags[syscall][arg]; ok {
				fmt.Printf("reg[%v]:\n", i)
				if flags.RemoveOutlier() {
					fmt.Printf("%v\n", flags)
				}
			}
		}
		for _, argMap := range syscall.argMaps {
			if structArg, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structArg.Fields {
					if flags, ok := a.argFlags[argMap][field]; ok {
						fmt.Printf("%v_%v:\n", argMap.name, field.FieldName())
						if flags.RemoveOutlier() {
							fmt.Printf("%v\n", flags)
						}
					}
				}
			} else {
				if flags, ok := a.argFlags[argMap][argMap.arg]; ok {
					fmt.Printf("%v:\n", argMap.name)
					if flags.RemoveOutlier() {
						fmt.Printf("%v\n", flags)
					}
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
								fmt.Printf("%v_%v_%v:\n", vlrRecord.name, f.FieldName(), ff.FieldName())
								if flags.RemoveOutlier() {
									fmt.Printf("%v\n", flags)
								}
							}
						}
					} else {
						if flags, ok := a.vlrFlags[vlrMap][vlrRecord][f]; ok {
							fmt.Printf("%v_%v:\n", vlrRecord.name, f.FieldName())
							if flags.RemoveOutlier() {
								fmt.Printf("%v\n", flags)
							}
						}
					}
				}
			}
		}
	}
}

func (a *FlagAnalysis) PrintResult(v Verbose) {
	for syscall, _ := range a.moduleSyscalls {
		s := ""
		for i, arg := range syscall.def.Args {
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

