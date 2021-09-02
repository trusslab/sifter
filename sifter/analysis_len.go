package sifter

import (
	"fmt"
	"math"

	"github.com/google/syzkaller/prog"
)

type LenRange struct {
	values  map[uint64]int
	upper   uint64
	lower   uint64
}

func newLenRange() *LenRange {
	lenRange := new(LenRange)
	lenRange.values = make(map[uint64]int)
	lenRange.lower = math.MaxInt64
	lenRange.upper = 0
	return lenRange
}

func (r *LenRange) String() string {
	if r.lower == math.MaxInt64 && r.upper == 0 {
		return ""
	} else {
		return fmt.Sprintf("[%v, %v] %v", r.lower, r.upper, r.values)
	}
}

func (r *LenRange) Update(v uint64, flag Flag) (bool, bool) {
	updateLower := false
	updateUpper := false
	if (r.lower > v) {
		if flag == TrainFlag {
			r.lower = v
		}
		updateLower = true
	}
	if (r.upper < v) {
		if flag == TrainFlag {
			r.upper = v
		}
		updateUpper = true
	}
	r.values[v] += 1
	return updateLower, updateUpper
}

type LenAnalysis struct {
	argLenRanges map[*ArgMap]map[prog.Type]*LenRange
	regLenRanges map[*Syscall]map[prog.Type]*LenRange
	vlrLenRanges map[*VlrMap]map[*VlrRecord]map[prog.Type]*LenRange
	lenContainingSyscall map[*Syscall]bool
}

func (a *LenAnalysis) String() string {
	return "length analysis"
}

func (a *LenAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argLenRanges = make(map[*ArgMap]map[prog.Type]*LenRange)
	a.regLenRanges = make(map[*Syscall]map[prog.Type]*LenRange)
	a.vlrLenRanges = make(map[*VlrMap]map[*VlrRecord]map[prog.Type]*LenRange)
	a.lenContainingSyscall = make(map[*Syscall]bool)

	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			a.regLenRanges[syscall] = make(map[prog.Type]*LenRange)
			for _, arg := range syscall.def.Args {
				if _, ok := arg.(*prog.LenType); ok {
					a.regLenRanges[syscall][arg] = newLenRange()
				}
			}
			for _, argMap := range syscall.argMaps {
				a.argLenRanges[argMap] = make(map[prog.Type]*LenRange)
				if structArg, ok := argMap.arg.(*prog.StructType); ok {
					for _, field := range structArg.Fields {
						if _, ok := field.(*prog.LenType); ok {
							a.argLenRanges[argMap][field] = newLenRange()
						}
					}
				} else {
					if _, ok := argMap.arg.(*prog.LenType); ok {
						a.argLenRanges[argMap][argMap.arg] = newLenRange()
					}
				}
			}
			for _, vlrMap := range syscall.vlrMaps {
				a.vlrLenRanges[vlrMap] = make(map[*VlrRecord]map[prog.Type]*LenRange)
				for _, vlrRecord := range vlrMap.records {
					a.vlrLenRanges[vlrMap][vlrRecord] = make(map[prog.Type]*LenRange)
					if structArg, ok := vlrRecord.arg.(*prog.StructType); ok {
						for _, f := range structArg.Fields {
							if structField, ok := f.(*prog.StructType); ok {
								for _, ff := range structField.Fields {
									if _, ok := ff.(*prog.LenType); ok {
										a.vlrLenRanges[vlrMap][vlrRecord][ff] = newLenRange()
									}
								}
							} else {
								if _, ok := f.(*prog.LenType); ok {
									a.vlrLenRanges[vlrMap][vlrRecord][f] = newLenRange()
								}
							}
						}
					}
				}
			}
		}
	}
}

func (a *LenAnalysis) Reset() {
}

func (a *LenAnalysis) ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int, int) {
	if te.typ != 1 {
		return "", 0, 0
	}

	a.lenContainingSyscall[te.syscall] = true

	msgs := make([]string, 0)
	var offset uint64
	for i, arg := range te.syscall.def.Args {
		if _, ok := arg.(*prog.LenType); ok {
			_, tr := te.GetData(uint64(i*8), arg.Size())
			updateLower, updateUpper := a.regLenRanges[te.syscall][arg].Update(tr, flag)
			if updateLower {
				msgs = append(msgs, fmt.Sprintf("reg[%v]:l %x", i, tr))
			}
			if updateUpper {
				msgs = append(msgs, fmt.Sprintf("reg[%v]:u %x", i, tr))
			}
		}
	}
	offset = 48
	for _, argMap := range te.syscall.argMaps {
		if structArg, ok := argMap.arg.(*prog.StructType); ok {
			for _, field := range structArg.Fields {
				if _, ok := field.(*prog.LenType); ok {
					_, tr := te.GetData(offset, field.Size())
					updateLower, updateUpper := a.argLenRanges[argMap][field].Update(tr, flag)
					if updateLower {
						msgs = append(msgs, fmt.Sprintf("%v_%v:l %x", argMap.name, field.FieldName(), tr))
					}
					if updateUpper {
						msgs = append(msgs, fmt.Sprintf("%v_%v:u %x", argMap.name, field.FieldName(), tr))
					}
				}
				offset += field.Size()
			}
		} else {
			if _, ok := argMap.arg.(*prog.LenType); ok {
				_, tr := te.GetData(offset, argMap.arg.Size())
				updateLower, updateUpper := a.argLenRanges[argMap][argMap.arg].Update(tr, flag)
				if updateLower {
					msgs = append(msgs, fmt.Sprintf("%v:l %x", argMap.name, tr))
				}
				if updateUpper {
					msgs = append(msgs, fmt.Sprintf("%v:u %x", argMap.name, tr))
				}
			}
			offset += argMap.size
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
					if structField, isStructArg := f.(*prog.StructType); isStructArg {
						for _, ff := range structField.Fields {
							if _, ok := ff.(*prog.LenType); ok {
								_, tr = te.GetData(offset, ff.Size())
								updateLower, updateUpper := a.vlrLenRanges[vlrMap][vlrRecord][ff].Update(tr, flag)
								if updateLower {
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v:l %x", vlrRecord.name, f.FieldName(), ff.FieldName(), tr))
								}
								if updateUpper {
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v:u %x", vlrRecord.name, f.FieldName(), ff.FieldName(), tr))
								}
							}
							offset += ff.Size()
						}
					} else {
						if _, ok := f.(*prog.LenType); ok {
							_, tr = te.GetData(offset, f.Size())
							updateLower, updateUpper := a.vlrLenRanges[vlrMap][vlrRecord][f].Update(tr, flag)
							if updateLower {
								msgs = append(msgs, fmt.Sprintf("%v_%v:l %x", vlrRecord.name, f.FieldName(), tr))
							}
							if updateUpper {
								msgs = append(msgs, fmt.Sprintf("%v_%v:u %x", vlrRecord.name, f.FieldName(), tr))
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

func (a *LenAnalysis) PostProcess(flag Flag) {
}

func (a *LenAnalysis) PrintResult(v Verbose) {
	for syscall, _ := range a.lenContainingSyscall {
		s := ""
		for i, arg := range syscall.def.Args {
			if lenRange, ok := a.regLenRanges[syscall][arg]; ok {
				s += fmt.Sprintf("reg[%v]: %v\n", i, lenRange)
			}
		}
		for _, argMap := range syscall.argMaps {
			if structField, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structField.Fields {
					if lenRange, ok := a.argLenRanges[argMap][field]; ok {
						s += fmt.Sprintf("%v_%v: %v\n", argMap.name, field.FieldName(), lenRange)
					}
				}
			} else {
				if lenRange, ok := a.argLenRanges[argMap][argMap.arg]; ok {
					fmt.Printf("%v: %v\n", argMap.name, lenRange)
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
							if lenRange, ok := a.vlrLenRanges[vlrMap][vlrRecord][ff]; ok {
								s += fmt.Sprintf("%v_%v_%v: %v\n", vlrRecord.name, f.FieldName(), ff.FieldName(), lenRange)
							}
						}
					} else {
						if lenRange, ok := a.vlrLenRanges[vlrMap][vlrRecord][f]; ok {
							s += fmt.Sprintf("%v_%v: %v\n", vlrRecord.name, f.FieldName(), lenRange)
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


