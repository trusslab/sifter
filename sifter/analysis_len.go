package sifter

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
)

type LenRange struct {
	values  map[uint64]int
	upper   uint64
	lower   uint64
	upperOL uint64
	lowerOL uint64
}

func newLenRange() *LenRange {
	lenRange := new(LenRange)
	lenRange.values = make(map[uint64]int)
	lenRange.lower = math.MaxInt64
	lenRange.upper = 0
	return lenRange
}

func (r *LenRange) String() string {
	s := ""
	if len(r.values) != 0 {
		s += fmt.Sprintf("[%v, %v] [", r.lower, r.upper)
		for v, ctr := range r.values {
			s += fmt.Sprintf("%v,%v ", v, ctr)
		}
		if s[len(s)-1:] == " " {
			s = s[0:len(s)-1]
		}
		s += "]"
	}
	return s
}

func (r *LenRange) Update(v uint64, te *TraceEvent, flag AnalysisFlag, opt int) (bool, bool, bool, bool) {
	updateLower := false
	updateUpper := false
	updateLowerOL := false
	updateUpperOL := false

	if r.lower > v {
		if flag == TrainFlag && opt == 0 {
			r.lower = v
		} else if r.lowerOL > v {
			updateLowerOL = true
		}
		updateLower = true
	}
	if r.upper < v {
		if flag == TrainFlag && opt == 0 {
			r.upper = v
		} else if r.upperOL < v {
			updateUpperOL = true
		}
		updateUpper = true
	}
	if flag == TrainFlag && opt == 0 {
		r.values[v] += 1
	}

	return updateLower, updateUpper, updateLowerOL, updateUpperOL
}

func mean(vMap map[uint64]int, vKeys []uint64) float64 {
	var vProductSum float64
	teNum := 0
	for v, ctr := range vMap {
		vProductSum += float64(v) * float64(ctr)
		teNum += ctr
	}
	return vProductSum / float64(teNum)
}

func median(vMap map[uint64]int, vKeys []uint64) uint64 {
	var median uint64
	teNum := 0
	for _, ctr := range vMap {
		teNum += ctr
	}

	teAcc := 0
	for _, vKey := range vKeys {
		if teAcc + vMap[vKey] > teNum / 2 {
			median = vKey
			break
		}
		teAcc += vMap[vKey]
	}
	return median
}

func diff(a uint64, b uint64) uint64 {
	if a > b {
		return a - b
	} else {
		return b - a
	}
}

func meanAbsDev(vMap map[uint64]int, mean float64) float64 {
	teSum := 0
	var vDiffProductSum float64
	for v, ctr := range vMap {
		vDiffProductSum += math.Abs(float64(v) - mean) * float64(ctr)
		teSum += ctr
	}
	return vDiffProductSum / float64(teSum)
}

func medianAbsDev(vMap map[uint64]int, median uint64) uint64 {
	var mad uint64
	vDevMap := make(map[uint64]int)
	for v, ctr := range vMap {
		absDev := diff(v, median)
		vDevMap[absDev] += ctr
	}

	devNum := 0
	var vDevKeys []uint64
	for vDevKey, vDevNum := range vDevMap {
		vDevKeys = append(vDevKeys, vDevKey)
		devNum += vDevNum
	}
	sort.Slice(vDevKeys, func(i, j int) bool {return vDevKeys[i] < vDevKeys[j]})

	devAcc := 0
	for _, vDevKey := range vDevKeys {
		if devAcc + vDevMap[vDevKey] > devNum / 2 {
			mad = vDevKey
			break
		}
	}
	return mad
}

func genRange(mean float64, dev float64, c float64) (uint64, uint64) {
	var lower, upper uint64
	if mean != 0 {
		signedLower := mean - (c * dev)
		if signedLower < 0 {
			lower = 0
		} else {
			lower = uint64(signedLower)
		}
		if math.MaxUint64 - uint64(c * dev) > uint64(mean) {
			upper = uint64(mean + (c * dev))
		} else {
			upper = math.MaxUint64
		}
	} else {
		lower = uint64(mean)
		upper = uint64(mean)
	}
	return lower, upper
}

func (r *LenRange) RemoveOutlier() bool {
	if len(r.values) == 0 {
		return false
	}

	var vKeys []uint64
	for v, _ := range r.values {
		vKeys = append(vKeys, v)
	}
	sort.Slice(vKeys, func(i, j int) bool {return vKeys[i] < vKeys[j]})

	mean0 := mean(r.values, vKeys)
	meanAbsDev0 := meanAbsDev(r.values, mean0)
	median0 := median(r.values, vKeys)
	medianAbsDev0 := medianAbsDev(r.values, median0)
	fmt.Printf("0 median: %v mad: %v mean: %v mad: %v\n", median0, medianAbsDev0, mean0, meanAbsDev0)

	devThreshold := 10000.0
	update := false
	if meanAbsDev0 != 0 {
		outliers := make([]string, 0)
		for _, v := range vKeys {
			//z := 0.6745 * float64(diff(v, mean) / medianAbsDev)
			z := math.Abs(float64(v) - mean0) / meanAbsDev0
			if z > devThreshold {
				outliers = append(outliers, fmt.Sprintf("%v %v\n", v, z))
				delete(r.values, v)
				update = true
			}
		}
		if len(outliers) > 0 {
			fmt.Printf("len outliers:\n")
			for _, outlier := range outliers {
				fmt.Printf("%v", outlier)
			}
		}
	}

	vKeys = make([]uint64, 0)
	for v, _ := range r.values {
		vKeys = append(vKeys, v)
	}
	sort.Slice(vKeys, func(i, j int) bool {return vKeys[i] < vKeys[j]})

	mean1 := mean(r.values, vKeys)
	meanAbsDev1 := meanAbsDev(r.values, mean1)
	median1 := median(r.values, vKeys)
	medianAbsDev1 := medianAbsDev(r.values, median1)
	fmt.Printf("1 median: %v mad: %v mean: %v mad: %v\n", median1, medianAbsDev1, mean1, meanAbsDev1)
	r.lower, r.upper = genRange(mean1, meanAbsDev1, 100000)
	r.lowerOL, r.upperOL = genRange(mean1, meanAbsDev1, 10000000)
	fmt.Printf("new lower:%d upper:%d lowerOL:%d upperOL:%d\n", r.lower, r.upper, r.lowerOL, r.upperOL)

	return update
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

func (a *LenAnalysis) isLenType(arg prog.Type) bool {
	if _, isLenArg := arg.(*prog.LenType); isLenArg {
		return true
	}
	lenStrings := []string{"size", "len", "length"}
	for _, lenString := range lenStrings {
		if strings.Contains(arg.FieldName(), lenString) {
			return true
		}
	}
	return false
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
				if a.isLenType(arg) {
					a.regLenRanges[syscall][arg] = newLenRange()
				}
			}
			for _, argMap := range syscall.argMaps {
				a.argLenRanges[argMap] = make(map[prog.Type]*LenRange)
				if structArg, ok := argMap.arg.(*prog.StructType); ok {
					for _, field := range structArg.Fields {
						if a.isLenType(field) {
							a.argLenRanges[argMap][field] = newLenRange()
						}
					}
				} else {
					if a.isLenType(argMap.arg) {
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
									if a.isLenType(ff) {
										a.vlrLenRanges[vlrMap][vlrRecord][ff] = newLenRange()
									}
								}
							} else {
								if a.isLenType(f) {
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

func (a *LenAnalysis) ProcessTraceEvent(te *TraceEvent, flag AnalysisFlag, opt int) (string, int, int) {
	if te.typ != 1 {
		return "", 0, 0
	}

	a.lenContainingSyscall[te.syscall] = true

	var ol []bool
	msgs := make([]string, 0)
	var offset uint64
	for i, arg := range te.syscall.def.Args {
		if lenRange, ok := a.regLenRanges[te.syscall][arg]; ok {
			_, tr := te.GetData(uint64(i*8), arg.Size())
			updateLower, updateUpper, lowerOL, upperOL := lenRange.Update(tr, te, flag, opt)
			if updateLower {
				msgs = append(msgs, fmt.Sprintf("reg[%v]:l %x", i, tr))
				ol = append(ol, lowerOL)
			}
			if updateUpper {
				msgs = append(msgs, fmt.Sprintf("reg[%v]:u %x", i, tr))
				ol = append(ol, upperOL)
			}
		}
	}
	offset = 48
	for _, argMap := range te.syscall.argMaps {
		if structArg, ok := argMap.arg.(*prog.StructType); ok {
			for _, field := range structArg.Fields {
				if lenRange, ok := a.argLenRanges[argMap][field]; ok {
					_, tr := te.GetData(offset, field.Size())
					updateLower, updateUpper, lowerOL, upperOL := lenRange.Update(tr, te, flag, opt)
					if updateLower {
						msgs = append(msgs, fmt.Sprintf("%v_%v:l %x", argMap.name, field.FieldName(), tr))
						ol = append(ol, lowerOL)
					}
					if updateUpper {
						msgs = append(msgs, fmt.Sprintf("%v_%v:u %x", argMap.name, field.FieldName(), tr))
						ol = append(ol, upperOL)
					}
				}
				offset += field.Size()
			}
		} else {
			if lenRange, ok := a.argLenRanges[argMap][argMap.arg]; ok {
				_, tr := te.GetData(offset, argMap.arg.Size())
				updateLower, updateUpper, lowerOL, upperOL := lenRange.Update(tr, te, flag, opt)
				if updateLower {
					msgs = append(msgs, fmt.Sprintf("%v:l %x", argMap.name, tr))
					ol = append(ol, lowerOL)
				}
				if updateUpper {
					msgs = append(msgs, fmt.Sprintf("%v:u %x", argMap.name, tr))
					ol = append(ol, upperOL)
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
							if lenRange, ok := a.vlrLenRanges[vlrMap][vlrRecord][ff]; ok {
								_, tr = te.GetData(offset, ff.Size())
								updateLower, updateUpper, lowerOL, upperOL := lenRange.Update(tr, te, flag, opt)
								if updateLower {
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v:l %x", vlrRecord.name, f.FieldName(), ff.FieldName(), tr))
									ol = append(ol, lowerOL)
								}
								if updateUpper {
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v:u %x", vlrRecord.name, f.FieldName(), ff.FieldName(), tr))
									ol = append(ol, upperOL)
								}
							}
							offset += ff.Size()
						}
					} else {
						if lenRange, ok := a.vlrLenRanges[vlrMap][vlrRecord][f]; ok {
							_, tr = te.GetData(offset, f.Size())
							updateLower, updateUpper, lowerOL, upperOL := lenRange.Update(tr, te, flag, opt)
							if updateLower {
								msgs = append(msgs, fmt.Sprintf("%v_%v:l %x", vlrRecord.name, f.FieldName(), tr))
								ol = append(ol, lowerOL)
							}
							if updateUpper {
								msgs = append(msgs, fmt.Sprintf("%v_%v:u %x", vlrRecord.name, f.FieldName(), tr))
								ol = append(ol, upperOL)
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
			te.flag = te.flag | TraceEventFlagBadData
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

func (a *LenAnalysis) PostProcess(opt int) {
	if opt == 0 {
		a.RemoveOutliers()
	}
}

func (a *LenAnalysis) RemoveOutliers() {
	fmt.Printf("removing outlier len:\n")
	for syscall, _ := range a.lenContainingSyscall {
		fmt.Printf("%v\n", syscall.name)
		for i, arg := range syscall.def.Args {
			if lenRange, ok := a.regLenRanges[syscall][arg]; ok {
				fmt.Printf("reg[%v]:\n", i)
				if lenRange.RemoveOutlier() {
					fmt.Printf("%v\n", lenRange)
				}
			}
		}
		for _, argMap := range syscall.argMaps {
			if structField, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structField.Fields {
					if lenRange, ok := a.argLenRanges[argMap][field]; ok {
						fmt.Printf("%v_%v:\n", argMap.name, field.FieldName())
						if lenRange.RemoveOutlier() {
							fmt.Printf("%v\n", lenRange)
						}
					}
				}
			} else {
				if lenRange, ok := a.argLenRanges[argMap][argMap.arg]; ok {
					fmt.Printf("%v:\n", argMap.name)
					if lenRange.RemoveOutlier() {
						fmt.Printf("%v\n", lenRange)
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
							if lenRange, ok := a.vlrLenRanges[vlrMap][vlrRecord][ff]; ok {
								fmt.Printf("%v_%v_%v:\n", vlrRecord.name, f.FieldName(), ff.FieldName())
								if lenRange.RemoveOutlier() {
									fmt.Printf("%v\n", lenRange)
								}
							}
						}
					} else {
						if lenRange, ok := a.vlrLenRanges[vlrMap][vlrRecord][f]; ok {
							fmt.Printf("%v_%v:\n", vlrRecord.name, f.FieldName())
							if lenRange.RemoveOutlier() {
								fmt.Printf("%v\n", lenRange)
							}
						}
					}
				}
			}
		}
	}
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

func (a *LenAnalysis) GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint {
	var constraint *RangeConstraint
	if depth == 0 {
		if r, ok := a.regLenRanges[syscall][arg]; ok {
			fmt.Printf("add constraint to %v %v\n", syscall.name, arg.FieldName())
			constraint = new(RangeConstraint)
			constraint.l = r.lower
			constraint.u = r.upper
			return constraint
		}
	} else {
		if r, ok := a.argLenRanges[argMap][arg]; ok {
			fmt.Printf("add constraint to %v %v %v\n", syscall.name, argMap.name, arg.FieldName())
			constraint = new(RangeConstraint)
			constraint.l = r.lower
			constraint.u = r.upper
			return constraint
		}
	}
	return nil
}

