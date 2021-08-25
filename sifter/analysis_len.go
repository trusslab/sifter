package sifter

import (
	"fmt"
	"math"

	"github.com/google/syzkaller/prog"
)

type LenAnalysis struct {
	argRanges map[*ArgMap][]uint64
	regRanges map[*Syscall][]uint64
	vlrRanges map[*VlrMap]map[*VlrRecord][]uint64
	lenRanges map[prog.Type][]uint64
	lenContainingSyscall map[*Syscall]bool
}

func (a *LenAnalysis) String() string {
	return "length analysis"
}

func (a *LenAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argRanges = make(map[*ArgMap][]uint64)
	a.regRanges = make(map[*Syscall][]uint64)
	a.vlrRanges = make(map[*VlrMap]map[*VlrRecord][]uint64)
	a.lenRanges = make(map[prog.Type][]uint64)
	a.lenContainingSyscall = make(map[*Syscall]bool)

	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			for _, arg := range syscall.def.Args {
				if _, ok := arg.(*prog.LenType); ok {
					a.lenRanges[arg] = []uint64{math.MaxInt64, 0}
				}
			}
			for _, arg := range syscall.argMaps {
				if structArg, ok := arg.arg.(*prog.StructType); ok {
					for _, field := range structArg.Fields {
						if _, ok := field.(*prog.LenType); ok {
							a.lenRanges[field] = []uint64{math.MaxInt64, 0}
						}
					}
				} else {
					if _, ok := arg.arg.(*prog.LenType); ok {
						a.lenRanges[arg.arg] = []uint64{math.MaxInt64, 0}
					}
				}
			}
			for _, vlr := range syscall.vlrMaps {
				a.vlrRanges[vlr] = make(map[*VlrRecord][]uint64)
				for _, record := range vlr.records {
					if structArg, ok := record.arg.(*prog.StructType); ok {
						for _, f := range structArg.Fields {
							if structField, ok := f.(*prog.StructType); ok {
								for _, field := range structField.Fields {
									if _, ok := field.(*prog.LenType); ok {
										a.lenRanges[field] = []uint64{math.MaxInt64, 0}
									}
								}
							} else {
								if _, ok := f.(*prog.LenType); ok {
									a.lenRanges[f] = []uint64{math.MaxInt64, 0}
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

func (a *LenAnalysis) ProcessTraceEvent(te *TraceEvent, flag Flag) (string, int) {
	if te.typ != 1 {
		return "", 0
	}

	a.lenContainingSyscall[te.syscall] = true

	msgs := make([]string, 0)
	var offset uint64
	for i, arg := range te.syscall.def.Args {
		if _, ok := arg.(*prog.LenType); ok {
			_, tr := te.GetData(uint64(i*8), arg.Size())
			if (a.lenRanges[arg][0] > tr) {
				if flag == TrainFlag {
					a.lenRanges[arg][0] = tr
				}
				msgs = append(msgs, fmt.Sprintf("reg[%v]:l %x", i, tr))
			}
			if (a.lenRanges[arg][1] < tr) {
				if flag == TrainFlag {
					a.lenRanges[arg][1] = tr
				}
				msgs = append(msgs, fmt.Sprintf("reg[%v]:u %x", i, tr))
			}

		}
//	for i := 0; i < 6; i++ {
//		if i < 1 {
//		_, tr := te.GetData(offset, 8)
//		if (a.regRanges[te.syscall][i*2+0] > tr) {
//			if flag == TrainFlag {
//				a.regRanges[te.syscall][i*2+0] = tr
//			}
//			msgs = append(msgs, fmt.Sprintf("reg[%v]:l %x", i, tr))
//		}
//		if (a.regRanges[te.syscall][i*2+1] < tr) {
//			if flag == TrainFlag {
//				a.regRanges[te.syscall][i*2+1] = tr
//			}
//			msgs = append(msgs, fmt.Sprintf("reg[%v]:u %x", i, tr))
//		}
//		}
//		offset += 8
	}
	offset = 48
	for _, arg := range te.syscall.argMaps {
		if structArg, ok := arg.arg.(*prog.StructType); ok {
			for _, field := range structArg.Fields {
				if _, ok := field.(*prog.LenType); ok {
					_, tr := te.GetData(offset, field.Size())
					if (a.lenRanges[field][0] > tr) {
						if flag == TrainFlag {
							a.lenRanges[field][0] = tr
						}
						msgs = append(msgs, fmt.Sprintf("%v:l %x", arg.name, tr))
					}
					if (a.lenRanges[field][1] < tr) {
						if flag == TrainFlag {
							a.lenRanges[field][1] = tr
						}
						msgs = append(msgs, fmt.Sprintf("%v:u %x", arg.name, tr))
					}

				}
//				if _, isPtrArg := field.(*prog.PtrType); !isPtrArg && field.FieldName() != "ptr" {
//					_, tr := te.GetData(offset, field.Size())
//					if (a.argRanges[arg][2*i+0] > tr) {
//						if flag == TrainFlag {
//							a.argRanges[arg][2*i+0] = tr
//						}
//						msgs = append(msgs, fmt.Sprintf("%v:l %x", arg.name, tr))
//					}
//					if (a.argRanges[arg][2*i+1] < tr) {
//						if flag == TrainFlag {
//							a.argRanges[arg][2*i+1] = tr
//						}
//						msgs = append(msgs, fmt.Sprintf("%v:u %x", arg.name, tr))
//					}
//				}
				offset += field.Size()
			}
		} else {
			if _, ok := arg.arg.(*prog.LenType); ok {
				_, tr := te.GetData(offset, arg.arg.Size())
				if (a.lenRanges[arg.arg][0] > tr) {
					if flag == TrainFlag {
						a.lenRanges[arg.arg][0] = tr
					}
					msgs = append(msgs, fmt.Sprintf("%v:l %x", arg.name, tr))
				}
				if (a.lenRanges[arg.arg][1] < tr) {
					if flag == TrainFlag {
						a.lenRanges[arg.arg][1] = tr
					}
					msgs = append(msgs, fmt.Sprintf("%v:u %x", arg.name, tr))
				}

			}
//			if _, isPtrArg := arg.arg.(*prog.PtrType); !isPtrArg && arg.arg.FieldName() != "ptr" {
//				_, tr := te.GetData(offset, arg.arg.Size())
//				if (a.argRanges[arg][0] > tr) {
//					if flag == TrainFlag {
//						a.argRanges[arg][0] = tr
//					}
//					msgs = append(msgs, fmt.Sprintf("%v:l %x", arg.name, tr))
//				}
//				if (a.argRanges[arg][1] < tr) {
//					if flag == TrainFlag {
//						a.argRanges[arg][1] = tr
//					}
//					msgs = append(msgs, fmt.Sprintf("%v:u %x", arg.name, tr))
//				}
//			}
			offset += arg.size
		}
	}
	for _, vlr := range te.syscall.vlrMaps {
		_, size := te.GetData(48+vlr.lenOffset, 8)
		_, start := te.GetData(56, 8) // Special case for binder
		offset += start
		for {
			_, tr := te.GetData(offset, 4)
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
				for i, f := range structArg.Fields {
					if i == 0 {
						continue
					}
					if structField, isStructArg := f.(*prog.StructType); isStructArg {
						for _, field := range structField.Fields {
							if _, ok := field.(*prog.LenType); ok {
								if (a.lenRanges[field][0] > tr) {
									if flag == TrainFlag {
										a.lenRanges[field][0] = tr
									}
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v:l %x", matchedRecord.name, f.FieldName(), field.FieldName(), tr))
								}
								if (a.lenRanges[field][1] < tr) {
									if flag == TrainFlag {
										a.lenRanges[field][1] = tr
									}
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v:u %x", matchedRecord.name, f.FieldName(), field.FieldName(), tr))
								}
							}
						}
					} else {
						if _, ok := f.(*prog.LenType); ok {
							if (a.lenRanges[f][0] > tr) {
								if flag == TrainFlag {
									a.lenRanges[f][0] = tr
								}
								msgs = append(msgs, fmt.Sprintf("%v_%v:l %x", matchedRecord.name, f.FieldName(), tr))
							}
							if (a.lenRanges[f][1] < tr) {
								if flag == TrainFlag {
									a.lenRanges[f][1] = tr
								}
								msgs = append(msgs, fmt.Sprintf("%v_%v:u %x", matchedRecord.name, f.FieldName(), tr))
							}
						}
					}
//					if _, isPtrArg := field.(*prog.PtrType); !isPtrArg && field.FieldName() != "ptr" && field.FieldName() != "cookie" && field.FieldName() != "ref" {
//						_, tr = te.GetData(offset, field.Size())
//						if (a.vlrRanges[vlr][matchedRecord][2*i+0] > tr) {
//							if flag == TrainFlag {
//								a.vlrRanges[vlr][matchedRecord][2*i+0] = tr
//							}
//							msgs = append(msgs, fmt.Sprintf("%v_%v:l [%v]:%x", matchedRecord.name, field.FieldName(), offset, tr))
//						}
//						if (a.vlrRanges[vlr][matchedRecord][2*i+1] < tr) {
//							if flag == TrainFlag {
//								a.vlrRanges[vlr][matchedRecord][2*i+1] = tr
//							}
//							msgs = append(msgs, fmt.Sprintf("%v_%v:u [%v]:%x", matchedRecord.name, field.FieldName(), offset, tr))
//						}
//					}
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

func (a *LenAnalysis) PrintResult(v Verbose) {
	for syscall, _ := range a.lenContainingSyscall {
		fmt.Printf("\n%v\n", syscall.name)
		for i, arg := range syscall.def.Args {
			if lenRange, ok := a.lenRanges[arg]; ok {
				fmt.Printf("reg[%v] %v\n", i, lenRange)
			}
		}
		for _, arg := range syscall.argMaps {
			if structField, ok := arg.arg.(*prog.StructType); ok {
				for _, field := range structField.Fields {
					if lenRange, ok := a.lenRanges[field]; ok {
						fmt.Printf("%v_%v %v\n", arg.name, field.FieldName(), lenRange)
					}
				}
			} else {
				if lenRange, ok := a.lenRanges[arg.arg]; ok {
					fmt.Printf("%v %v\n", arg.name, lenRange)
				}
			}
		}
	}
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


