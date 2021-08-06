package sifter

import (
	"bufio"
	"encoding/binary"
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

func (syscall *Syscall) AddVlrMap(arg *prog.ArrayType, argName string) {
	newVlrMap := &VlrMap {
		arg: arg,
		name: argName,
		size: 512,
		offset: syscall.size,
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
}

func newTraceEvent(ts uint64, id uint32, info *TraceInfo, syscall *Syscall) *TraceEvent {
	traceEvent := new(TraceEvent)
	traceEvent.ts = ts
	traceEvent.id = id
	traceEvent.info = info
	traceEvent.syscall = syscall
	if (id & 0x80000000 != 0) {
		traceEvent.data = make([]byte, (id & 0x0000ffff))
	} else if syscall == nil {
		traceEvent.data = make([]byte, 48)
	} else {
		traceEvent.data = make([]byte, 48 + syscall.size)
	}
	return traceEvent
}

func (te *TraceEvent) GetFD() (int, uint64) {
	for i, arg := range te.syscall.def.Args {
		if res, ok := arg.(*prog.ResourceType); ok && res.FldName == "fd" {
			return i, binary.LittleEndian.Uint64(te.data[i*8:i*8+8])
		}
	}
	return -1, 0
}

