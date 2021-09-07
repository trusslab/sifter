package sifter

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"github.com/google/syzkaller/prog"
)

type Mode int

const (
	TracerMode Mode = iota
	FilterMode
	AnalyzerMode
)

type Verbose int

const (
	InfoV Verbose = iota
	ResultV
	UpdateV
	DebugV
	AllTraceV
)

type ArgMap struct {
	name     string
	path     string
	datatype string
	size     uint64
	offset   uint64
	arg      prog.Type
}

type VlrRecord struct {
	header   uint64
	name     string
	size     uint64
	arg      prog.Type
}

type VlrMap struct {
	name     string
	size     uint64
	offset   uint64
	records  []*VlrRecord
	arg      prog.Type
	lenOffset uint64
}

type Syscall struct {
	name			string
	def				*prog.Syscall
	argMaps			[]*ArgMap
	vlrMaps			[]*VlrMap
	size			uint64
	traceSizeBits   int
	traceFile		*os.File
	traceReader		*bufio.Reader
}

func (syscall *Syscall) TraceSizeBits() int {
	return syscall.traceSizeBits
}

func (syscall *Syscall) TraceSizeMask() uint32 {
	return uint32(math.Pow(2, float64(syscall.traceSizeBits))-1)
}

func (syscall *Syscall) TraceSize() int {
	return int(math.Pow(2, float64(syscall.traceSizeBits)))
}

func (syscall *Syscall) AddArgMap(arg prog.Type, argName string, srcPath string, argType string) {
	for _, argMap := range syscall.argMaps {
		if argMap.name == argName {
			return
		}
	}
	var size uint64
	if arg.Varlen() {
		return
	} else {
		size = arg.Size()
	}
	newArgMap := &ArgMap{
		arg: arg,
		name: argName,
		path: srcPath,
		datatype: argType,
		size: size,
		offset: syscall.size,
	}
	syscall.argMaps = append(syscall.argMaps, newArgMap)
	syscall.size += size
}

func (syscall *Syscall) AddVlrMap(arg *prog.ArrayType, parentArgMap *ArgMap, argName string) {
	newVlrMap := &VlrMap {
		arg: arg,
		name: argName,
		size: 512,
		offset: syscall.size,
	}
	if parentStructArg, isStructArg := parentArgMap.arg.(*prog.StructType); isStructArg {
		var offset uint64
		for _, field := range parentStructArg.Fields {
			if lenArg, isLenArg := field.(*prog.LenType); isLenArg && parentArgMap.name+"_"+lenArg.Path[0] == argName {
				newVlrMap.lenOffset = parentArgMap.offset + offset
			}
			offset += field.Size()
		}
	}
	for _, record := range arg.Type.(*prog.UnionType).Fields {
		structArg, _ := record.(*prog.StructType)
		newVlrRecord := &VlrRecord {
			header: structArg.Fields[0].(*prog.ConstType).Val,
			name: structArg.FldName,
			size: structArg.Size(),
			arg: structArg,
		}
		newVlrMap.records = append(newVlrMap.records, newVlrRecord)
	}
	syscall.vlrMaps = append(syscall.vlrMaps, newVlrMap)
	syscall.size += 512
}

type TraceInfo struct {
	name    string
	pidComm map[uint32]string
}

func newTraceInfo(name string) *TraceInfo {
	traceInfo := new(TraceInfo)
	traceInfo.name = name
	traceInfo.pidComm = make(map[uint32]string)
	return traceInfo
}

type TraceEvent struct {
	ts      uint64
	id      uint32
	syscall *Syscall
	info    *TraceInfo
	data    []byte
	tags    []int
	typ     int
	ret     uint64
}

func newTraceEvent(ts uint64, id uint32, info *TraceInfo, syscall *Syscall) *TraceEvent {
	traceEvent := new(TraceEvent)
	traceEvent.ts = ts
	traceEvent.id = id
	traceEvent.info = info
	traceEvent.syscall = syscall
	if (id & 0x80000000 != 0) {
		traceEvent.data = make([]byte, (id & 0x0000ffff))
		traceEvent.typ = 0
	} else if syscall == nil {
		traceEvent.data = make([]byte, 48)
		traceEvent.typ = 2
	} else {
		traceEvent.data = make([]byte, 48 + syscall.size)
		traceEvent.typ = 1
	}
	return traceEvent
}

func (te *TraceEvent) GetFD() (int, uint64) {
	if te.syscall.def == nil {
		return -1, 0
	}
	for i, arg := range te.syscall.def.Args {
		//if res, ok := arg.(*prog.ResourceType); ok && res.FldName == "fd" {
		if _, ok := arg.(*prog.ResourceType); ok {
			return i, uint64(binary.LittleEndian.Uint32(te.data[i*8+4:i*8+8]))
		}
	}
	return -1, 0
}

func (te *TraceEvent) GetData(offset uint64, size uint64) (bool, uint64) {
	ok := false
	var data uint64

	if offset > 0 && offset+size < uint64(len(te.data)) {
		switch size {
		case 1:
			data = uint64(te.data[offset])
		case 2:
			data = uint64(binary.LittleEndian.Uint16(te.data[offset:offset+size]))
		case 4:
			data = uint64(binary.LittleEndian.Uint32(te.data[offset:offset+size]))
		case 8:
			if offset <= 40 {
				data = uint64(binary.LittleEndian.Uint32(te.data[offset+4:offset+size]))
			} else {
				data = binary.LittleEndian.Uint64(te.data[offset:offset+size])
			}
		}
	}

	return ok, data
}

func (te *TraceEvent) GetNR() (bool, uint64) {
	if te.typ == 1 || te.typ == 2 {
		if te.syscall.def != nil {
			return true, te.syscall.def.NR
		}
	}
	return false, 0
}

type ArgConstraint interface {
	String(argName string, retName string, allowValue string, rejectValue string) string
}

type RangeConstraint struct {
	l uint64
	u uint64
}

func (rc *RangeConstraint) String(argName string, retName string, allowValue string, rejectValue string) string {
	s := ""
	s += fmt.Sprintf("if (%v < 0x%x || %v > 0x%x) {\n", argName, rc.l, argName, rc.u)
	s += fmt.Sprintf("    %v = %v;\n", retName, rejectValue)
	s += fmt.Sprintf("}\n")
	return s
}

type ValuesConstraint struct {
	values []uint64
}

func (vc *ValuesConstraint) String(argName string, retName string, allowValue string, rejectValue string) string {
	s := ""
	s += fmt.Sprintf("if (")
	for i, v := range vc.values {
		s += fmt.Sprintf("%v != 0x%x\n", argName, v)
		if i != len(vc.values) - 1 {
			s += fmt.Sprintf(" && ")
		} else {
			s += fmt.Sprintf("{\n")
		}
	}
	s += fmt.Sprintf("    %v = %v;\n", retName, rejectValue)
	s += fmt.Sprintf("}\n")
	return s
}

