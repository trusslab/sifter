package sifter

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

type FlagSet struct {
	values map[uint64]map[*Trace]int
	idx    int
	offset uint64
	size   uint64
}

func (flags *FlagSet) Update(v uint64, te *TraceEvent, f AnalysisFlag, opt int, tag bool) (bool, bool) {
	_, ok := flags.values[v]
	if !ok {
		flags.values[v] = make(map[*Trace]int)
	}

	update := false
	updateOL := false
	if f == TrainFlag {
		if opt == 0 {
			flags.values[v][te.trace] += 1
			update = !ok
		} else if opt == 1 {
			if _, ok := flags.values[v][nil]; ok {
				updateOL = true
			} else if _, ok := flags.values[v]; !ok {
				update = true
			}
		}
	} else if f == TestFlag {
		if _, ok := flags.values[v][nil]; ok {
			flags.values[v][nil] += 1
			if flags.values[v][nil] > 10 {
				fmt.Printf("Warning: might have a false positive\n")
				update = true
			} else {
				updateOL = true
			}
		} else if _, ok := flags.values[v]; !ok {
			update = true
		}
	}

	if (f == TestFlag) || (f == TrainFlag && !updateOL) {
		if tag {
			te.tags = append(te.tags, int(v))
		}
	} else {
		te.flag = te.flag | TraceEventFlagBadData
	}
	return update, updateOL
}

func (flags *FlagSet) RemoveOutlier(traceNum int) bool {
	sum := 0
	for _, traceCounts := range flags.values {
		for _, count := range traceCounts {
			sum += count
		}
	}
	traceThreshold := 0.10
	outliers := make([]string, 0)
	for v, traceCounts := range flags.values {
		if float64(len(traceCounts)) / float64(traceNum) < traceThreshold {
			outliers = append(outliers, fmt.Sprintf("%v(%v/%v)\n", v, sum, len(traceCounts)))
			flags.values[v][nil] = 0
		}
	}
	if len(outliers) > 0 {
		fmt.Printf("remove:\n")
		for _, outlier := range outliers {
			fmt.Printf("%v", outlier)
		}
	}
	return len(outliers) != 0
}

func newFlagSet(idx int, offset uint64, size uint64) *FlagSet {
	newFlags := new(FlagSet)
	newFlags.values = make(map[uint64]map[*Trace]int)
	newFlags.idx = idx
	newFlags.offset = offset
	newFlags.size = size
	return newFlags
}

func (flags *FlagSet) String() string {
	s := ""
	for flag, traceCounts := range flags.values {
		counts := 0
		for _, count := range traceCounts {
			counts += count
		}
		s += fmt.Sprintf("0x%x(%d/%d) ", flag, counts, len(traceCounts))
	}
	return s
}

type FlagAnalysis struct {
	argFlags map[*ArgMap]map[prog.Type]*FlagSet
	regFlags map[*Syscall]map[prog.Type]*FlagSet
	vlrFlags map[*VlrMap]map[*VlrRecord]map[prog.Type]*FlagSet
	moduleSyscalls map[*Syscall]bool
	traces map[*Trace]bool
}

func (a *FlagAnalysis) String() string {
	return "flag analysis"
}

func (a *FlagAnalysis) isFlagsType(arg prog.Type, syscall *Syscall) bool {
	if arg.Dir() == prog.DirOut {
		return false
	}
	if syscall.def.CallName == "ioctl" && arg == syscall.def.Args[1] {
		return true
	}
	if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
		return true
	}
	flagStrings := []string{"flag", "flags", "type"}
	for _, flagString := range flagStrings {
		if strings.Contains(arg.FieldName(), flagString) {
			return true
		}
	}
	return false
}

func (a *FlagAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argFlags = make(map[*ArgMap]map[prog.Type]*FlagSet)
	a.regFlags = make(map[*Syscall]map[prog.Type]*FlagSet)
	a.vlrFlags = make(map[*VlrMap]map[*VlrRecord]map[prog.Type]*FlagSet)
	a.traces = make(map[*Trace]bool)
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			var offset uint64
			idx := 0
			a.regFlags[syscall] = make(map[prog.Type]*FlagSet)
			for _, arg := range syscall.def.Args {
				if a.isFlagsType(arg, syscall) {
					a.regFlags[syscall][arg] = newFlagSet(idx, offset, 8)
					idx += 1
				}
				offset += 8
			}
			offset = 48
			for _, argMap := range syscall.argMaps {
				a.argFlags[argMap] = make(map[prog.Type]*FlagSet)
				if structArg, ok := argMap.arg.(*prog.StructType); ok {
					for _, field := range structArg.Fields {
						if a.isFlagsType(field, syscall) {
							a.argFlags[argMap][field] = newFlagSet(idx, offset, field.Size())
							idx += 1
						}
						offset += field.Size()
					}
				} else {
					if a.isFlagsType(argMap.arg, syscall) {
						a.argFlags[argMap][argMap.arg] = newFlagSet(idx, offset, argMap.size)
						idx += 1
					}
					offset += argMap.size
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
									if a.isFlagsType(ff, syscall) {
										a.vlrFlags[vlr][record][ff] = newFlagSet(idx, offset, 0)
										idx += 1
									}
								}
							} else {
								if a.isFlagsType(f, syscall) {
									a.vlrFlags[vlr][record][f] = newFlagSet(idx, offset, 0)
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

	a.traces[te.trace] = true

	var ol []bool
	msgs := make([]string, 0)
	var offset uint64
	for i, arg := range te.syscall.def.Args {
		if flags, ok := a.regFlags[te.syscall][arg]; ok {
			_, tr := te.GetData(offset, 8)
			update, updateOL := flags.Update(tr, te, flag, opt, true)
			if update || updateOL {
				msgs = append(msgs, fmt.Sprintf("reg[%v] new flag %x", i, tr))
				ol  = append(ol, updateOL)
			}
		}
		offset += 8
	}
	offset = 48
	for _, argMap := range te.syscall.argMaps {
		arrayLen := argMap.length
		isArray := (arrayLen != 1)
		if isArray {
			_, tr := te.GetData(48+argMap.lenOffset, 4)
			if arrayLen < int(tr) {
				fmt.Printf("number of elements in array %v, %x, exceeds the size of tracing buffer!\n", argMap.name, tr)
			} else {
				arrayLen = int(tr)
			}
		}
		for i := 0; i < arrayLen; i++ {
			if structArg, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structArg.Fields {
					if flags, ok := a.argFlags[argMap][field]; ok {
						_, tr := te.GetData(offset, field.Size())
						update, updateOL := flags.Update(tr, te, flag, opt, !isArray)
						if update || updateOL {
							msgs = append(msgs, fmt.Sprintf("%v::%v new flag %x", argMap.name, field.Name(), tr))
							ol  = append(ol, updateOL)
						}
					}
					offset += field.Size()
				}
			} else {
				if flags, ok := a.argFlags[argMap][argMap.arg]; ok {
					_, tr := te.GetData(offset, argMap.arg.Size())
					update, updateOL := flags.Update(tr, te, flag, opt, !isArray)
					if update || updateOL {
						msgs = append(msgs, fmt.Sprintf("%v new flag %x", argMap.name, tr))
						ol  = append(ol, updateOL)
					}
				}
				offset += argMap.arg.Size()
			}
		}
	}
	for _, vlrMap := range te.syscall.vlrMaps {
		_, size := te.GetData(48+vlrMap.lenOffset, 8)
		_, start := te.GetData(56, 8) // Special case for binder
		offset += start
		for {
			_, tr := te.GetData(offset, 4)
			var vlrRecord *VlrRecord
			if offset < size+vlrMap.offset+48 {
				for i, record := range vlrMap.records {
					if tr == record.header {
						vlrRecord = vlrMap.records[i]
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
							if flags, ok := a.vlrFlags[vlrMap][vlrRecord][ff]; ok {
								_, tr := te.GetData(offset+fieldOffset, ff.Size())
								update, updateOL := flags.Update(tr, te, flag, opt, false)
								if update || updateOL {
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v new flag %x", vlrRecord.name, f.FieldName(), ff.FieldName(), tr))
									ol  = append(ol, updateOL)
								}
							}
							fieldOffset += ff.Size()
						}
					} else {
						if flags, ok := a.vlrFlags[vlrMap][vlrRecord][f]; ok {
							_, tr := te.GetData(offset, f.Size())
							update, updateOL := flags.Update(tr, te, flag, opt, false)
							if update || updateOL {
								msgs = append(msgs, fmt.Sprintf("%v_%v new flag %x", vlrRecord.name, f.FieldName(), tr))
								ol  = append(ol, updateOL)
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
	traceNum := len(a.traces)
	for syscall, _ := range a.moduleSyscalls {
		fmt.Printf("%v\n", syscall.name)
		for i, arg := range syscall.def.Args {
			if flags, ok := a.regFlags[syscall][arg]; ok {
				fmt.Printf("reg[%v]:\n", i)
				if flags.RemoveOutlier(traceNum) {
					fmt.Printf("%v\n", flags)
				}
			}
		}
		for _, argMap := range syscall.argMaps {
			if structArg, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structArg.Fields {
					if flags, ok := a.argFlags[argMap][field]; ok {
						fmt.Printf("%v_%v:\n", argMap.name, field.FieldName())
						if flags.RemoveOutlier(traceNum) {
							fmt.Printf("%v\n", flags)
						}
					}
				}
			} else {
				if flags, ok := a.argFlags[argMap][argMap.arg]; ok {
					fmt.Printf("%v:\n", argMap.name)
					if flags.RemoveOutlier(traceNum) {
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
								if flags.RemoveOutlier(traceNum) {
									fmt.Printf("%v\n", flags)
								}
							}
						}
					} else {
						if flags, ok := a.vlrFlags[vlrMap][vlrRecord][f]; ok {
							fmt.Printf("%v_%v:\n", vlrRecord.name, f.FieldName())
							if flags.RemoveOutlier(traceNum) {
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

