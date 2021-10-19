package sifter

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
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
	syscalls        map[uint64]*Syscall
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

type Trace struct {
	name    string
	pidComm map[uint64]string
	events  []*TraceEvent
}

func newTrace(name string) *Trace {
	trace := new(Trace)
	trace.name = name
	trace.pidComm = make(map[uint64]string)
	return trace
}

func (t *Trace) Size() int {
	return len(t.events)
}

func (t *Trace) SortEvents() {
	sort.Slice(t.events, func(i, j int) bool {
		return t.events[i].ts < t.events[j].ts
	})
}

func (t *Trace) ClearEvents() {
	t.events = nil
}

func (t *Trace) ReadTracedPidComm() error {
	pidCommFilePath := fmt.Sprintf("%v/traced_pid_tgid_comm_map.log", t.name)
	pidCommFile, err := os.Open(pidCommFilePath)
	if err != nil {
		return fmt.Errorf("cannot open %v", pidCommFilePath)
	}

	defer pidCommFile.Close()

	bs := bufio.NewScanner(pidCommFile)
	for bs.Scan() {
		entry := strings.SplitN(bs.Text(), " ", 2)
		pid, err := strconv.Atoi(entry[0])
		if err == nil {
			t.pidComm[uint64(pid)] = entry[1]
		} else {
			return err
		}
	}
	return nil
}

func (t *Trace) ReadSyscallTrace(syscall *Syscall) error {
	traceFilePath := fmt.Sprintf("%v/raw_trace_%v.dat", t.name, syscall.name)
	traceFile, err := os.Open(traceFilePath)
	if err != nil {
		return fmt.Errorf("cannot open %v", traceFilePath)
	}

	defer traceFile.Close()

	br := bufio.NewReader(traceFile)
	for {
		var ts uint64
		var id uint64
		var nr uint32
		if err = binary.Read(br, binary.LittleEndian, &ts); err != nil {
			if err.Error() == "EOF" {
				return nil
			} else {
				return fmt.Errorf("%v ended unexpectedly (1): %v", traceFilePath, err)
			}
		}

		if err = binary.Read(br, binary.LittleEndian, &id); err != nil {
			return fmt.Errorf("%v ended unexpectedly (2): %v", traceFilePath, err)
		}
		te := newTraceEvent(ts, id, t, syscall)
		switch (te.typ) {
		case 0:
			if _, err = io.ReadFull(br, te.data); err != nil {
				return fmt.Errorf("%v ended unexpectedly (3): %v", traceFilePath, err)
			}
		case 1:
			if _, err = io.ReadFull(br, te.data); err != nil {
				return fmt.Errorf("%v ended unexpectedly (4): %v", traceFilePath, err)
			}
		case 2:
			if _, err = io.ReadFull(br, te.data); err != nil {
				return fmt.Errorf("%v ended unexpectedly (5): %v", traceFilePath, err)
			}
			if err = binary.Read(br, binary.LittleEndian, &nr); err != nil {
				return fmt.Errorf("%v ended unexpectedly (6): %v", traceFilePath, err)
			}

			if _, ok := syscall.syscalls[uint64(nr)]; !ok {
				newSyscall := new(Syscall)
				newSyscall.name = fmt.Sprintf("syscall_%v", nr)
				newSyscall.def = new(prog.Syscall)
				newSyscall.def.NR = uint64(nr)
				newSyscall.def.Name = fmt.Sprintf("syscall_%v", nr)
				newSyscall.def.CallName = fmt.Sprintf("syscall_%v", nr)
				syscall.syscalls[uint64(nr)] = newSyscall
			}
			te.syscall = syscall.syscalls[uint64(nr)]
		}

		if te.ts != 0 {
			t.events = append(t.events, te)
		}
	}
}

func (t *Trace) FindEventBefore(id uint64, nr uint64, ts uint64, start int) int {
	for i := start; i < len(t.events); i++ {
		te := t.events[i]
		if ts < te.ts {
			return -1
		}
		if te.id == id && te.syscall.def.NR == nr {
			return i
		}
	}
	return -1
}

func (t *Trace) ReadSyscallReturnTrace() error {
	traceFilePath := fmt.Sprintf("%v/raw_trace_syscall_return.dat", t.name)
	traceFile, err := os.Open(traceFilePath)
	if err != nil {
		return fmt.Errorf("cannot open %v", traceFilePath)
	}

	defer traceFile.Close()

	lastEvent := make(map[uint64]int)
	br := bufio.NewReader(traceFile)
	for {
		var ts uint64
		var id uint64
		var nr uint64
		var ret uint64
		if err = binary.Read(br, binary.LittleEndian, &ts); err != nil {
			if err.Error() == "EOF" {
				return nil
			} else {
				return fmt.Errorf("%v ended unexpectedly (1): %v", traceFilePath, err)
			}
		}
		if err = binary.Read(br, binary.LittleEndian, &id); err != nil {
			return fmt.Errorf("%v ended unexpectedly (2): %v", traceFilePath, err)
		}
		if id & 0x8000000000000000 != 0 {
			data := make([]byte, (id & 0x00000000ffffffff))
			_, err = io.ReadFull(br, data)
			continue
		}
		if err = binary.Read(br, binary.LittleEndian, &nr); err != nil {
			return fmt.Errorf("%v ended unexpectedly (3): %v", traceFilePath, err)
		}
		if err = binary.Read(br, binary.LittleEndian, &ret); err != nil {
			return fmt.Errorf("%v ended unexpectedly (4): %v", traceFilePath, err)
		}

		start := 0
		if idx, ok := lastEvent[id]; ok {
			start = idx+1
		}
		i := t.FindEventBefore(id, nr, ts, start)
		if i == -1 {
			if nr != 0xffffffffffffffff {
			fmt.Printf("[%.9f] (%d:%d) nr:%d ret:0x%x. cannot resolve the calling syscall\n", float64(ts)/1000000000.0, uint32(id), id>>32, nr, ret)
			}
		} else {
			t.events[i].ret = ret
			t.events[i].retTs = ts
			lastEvent[id] = i
		}
	}
}

const (
	TraceEventFlagBadData = 1
	TraceEventFlagUseFD = 2
)

type TraceEvent struct {
	ts      uint64
	id      uint64
	syscall *Syscall
	trace   *Trace
	data    []byte
	tags    []int
	flag    int
	typ     int
	ret     uint64
	retTs   uint64

	fdCached    uint64
	fdIdxCached int

}

func newTraceEvent(ts uint64, id uint64, trace *Trace, syscall *Syscall) *TraceEvent {
	traceEvent := new(TraceEvent)
	traceEvent.ts = ts
	traceEvent.id = id
	traceEvent.trace = trace
	traceEvent.syscall = syscall
	traceEvent.fdIdxCached = -1

	if (id & 0x8000000000000000 != 0) {
		traceEvent.data = make([]byte, (id & 0x00000000ffffffff))
		traceEvent.typ = 0
	} else if syscall.def == nil {
		traceEvent.data = make([]byte, 48)
		traceEvent.typ = 2
		if traceEvent.id & 0x4000000000000000 != 0 {
			traceEvent.id = traceEvent.id & 0x0fffffffffffffff
			traceEvent.flag = TraceEventFlagUseFD
		}
	} else {
		traceEvent.data = make([]byte, 48 + syscall.size)
		traceEvent.typ = 1
	}
	return traceEvent
}

func (te *TraceEvent) String() string {
	s := fmt.Sprintf("[%v.%09d] ", te.ts/1000000000, te.ts%1000000000)
	if te.typ == 0{
		switch (te.id & 0x0fffffff00000000) >> 32 {
		case 1:
			s += "trace start\n"
		case 2:
			s += fmt.Sprintf("trace lost %v events\n", binary.LittleEndian.Uint32(te.data))
		default:
			s += fmt.Sprintf("trace got unknown event id:%v\n", te.id)
		}
	} else {
		if comm, ok := te.trace.pidComm[te.id]; ok {
			s += comm
		}
		s += fmt.Sprintf("(%v:%v) %v %v ", uint32(te.id), uint32(te.id>>32), te.syscall.name, te.tags)
		if regID, fd := te.GetFD(); regID != -1 {
			s += fmt.Sprintf("fd(%d) ", fd)
		}
		if te.retTs != 0 {
			s += fmt.Sprintf("ret 0x%x ", te.ret)
		} else {
			s += fmt.Sprintf("ret unresolved ")
		}
		s += "\n"
		for bi, b := range te.data {
			if bi % 64 == 0 {
				s += fmt.Sprintf("  | %8d: ", bi)
			}
			if bi % 4 == 0 {
				s += fmt.Sprintf(" ")
			}
			s += fmt.Sprintf("%02x ", b)
			if bi % 64 == 63 || bi == len(te.data)-1 {
				s += fmt.Sprintf("\n")
			}
		}
//		if ok, flag := te.GetData(0, 8); ok && te.syscall.def.NR == 220 {
//			if flag & 0x00000400 == 0 {
//				fmt.Printf("clone 0x%x without CLONE_FILES\n", flag)
//			}
//		}
	}
	return s
}

func (te *TraceEvent) GetFD() (int, uint64) {
	if te.fdIdxCached != -1 {
		return te.fdIdxCached, te.fdCached
	}

	if te.syscall.def == nil {
		return -1, 0
	}

	for i, arg := range te.syscall.def.Args {
		if _, ok := arg.(*prog.ResourceType); ok {
			te.fdIdxCached = i
			te.fdCached = binary.LittleEndian.Uint64(te.data[i*8:i*8+8])
			return te.fdIdxCached, te.fdCached
		}
	}
	return -1, 0
}

func (te *TraceEvent) GetFD2(name string) (int, uint64) {
	if te.syscall.def == nil {
		return -1, 0
	}

	for i, arg := range te.syscall.def.Args {
		if res, ok := arg.(*prog.ResourceType); ok && res.FldName == name {
			return i, binary.LittleEndian.Uint64(te.data[i*8:i*8+8])
		}
	}
	return -1, 0
}

func (te *TraceEvent) GetData(offset uint64, size uint64) (bool, uint64) {
	ok := false
	var data uint64

	if offset > 0 && offset+size <= uint64(len(te.data)) {
		switch size {
		case 1:
			data = uint64(te.data[offset])
		case 2:
			data = uint64(binary.LittleEndian.Uint16(te.data[offset:offset+size]))
		case 4:
			data = uint64(binary.LittleEndian.Uint32(te.data[offset:offset+size]))
		case 8:
			data = binary.LittleEndian.Uint64(te.data[offset:offset+size])
		}
		ok = true
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

type TaggingConstraint struct {
	idx int
}

func (tc *TaggingConstraint) String(argName string, retName string, allowValue string, rejectValue string) string {
	s := ""
	s += fmt.Sprintf("id_key.tag[%v] = %v;\n", tc.idx, argName)
	return s
}

