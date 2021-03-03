package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"strconv"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

type Mode int

const (
	TracerMode Mode = iota
	FilterMode
)

type Flags struct {
	mode   string
	trace  string
	config string
	fd     string
	dev    string
	entry  string
	outdir string
	out    string
	seqlen int
	unroll int
}

type Section struct {
	t      int
	buf    *bytes.Buffer
}

type ArgMap struct {
	mapType  int
	name     string
	path     string
	datatype string
}

type SeqArg struct {
	name      string
	hashTable map[uint16]map[uint16]bool
	tidMap    map[uint16]uint32
	tids      []uint16
}

type Context struct {
	name           string
	syscallNum     string
	syscallArgs    string
	defaultRetType string
	defaultRetVal  string
	errorRetVal    string
}

type Sifter struct {
	mode		    Mode
	target          *prog.Target
	structs         []*prog.StructType
	syscalls        []*prog.Syscall
	moduleSyscalls  map[string][]*prog.Syscall

	traceFile       *os.File
	traceScanner    *bufio.Scanner

	argMaps          []*ArgMap
	seqArgs          []*SeqArg

	structId        int
	sections        map[string]*bytes.Buffer

	outName         string
	outSourceFile   string
	outConfigFile   string
//	syscallEntry    string
	fdName          string
	devName         string
	seqLen          int
	loopUnroll      int
	ctx             Context
}

func (sifter *Sifter) TidToSyscall(tid uint16) (uint32) {
	var syscall uint32 = 0
	if tid & 0x8000 == 0x8000 {
		syscall = sifter.seqArgs[0].tidMap[tid]
	} else {
		syscall = uint32(tid)
	}
	return syscall
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func NewSifter(target *prog.Target, f Flags) (*Sifter, error) {
	sifter := new(Sifter)
	sifter.target = target
	sifter.fdName = f.fd
	sifter.devName = f.dev
//	sifter.syscallEntry = f.entry
	sifter.outName = f.out+"_"+f.mode
	sifter.outSourceFile = filepath.Join(f.outdir, sifter.outName+".c")
	sifter.outConfigFile = filepath.Join(f.outdir, sifter.outName+".cfg")
	sifter.seqLen = f.seqlen
	sifter.loopUnroll = f.unroll
	sifter.sections = make(map[string]*bytes.Buffer)
	sifter.argMaps = []*ArgMap{}
	sifter.seqArgs = []*SeqArg{}
	sifter.syscalls = make([]*prog.Syscall, 512)
	sifter.moduleSyscalls = make(map[string][]*prog.Syscall)
	sifter.structId = 0

	//ctx["kprobe"] = Context{name: "struct user_pt_regs", syscallNum: "NA", syscallArgs:"regs"}
	if f.mode == "tracer" {
		sifter.mode = TracerMode
		sifter.ctx = Context{
			name: "sys_enter_args",
			syscallNum: "id",
			syscallArgs: "regs",
			defaultRetType: "int",
			defaultRetVal: "0",
			errorRetVal: "1",
		}
	} else if f.mode == "filter" {
		sifter.mode = FilterMode
		sifter.ctx = Context{
			name: "struct seccomp_data",
			syscallNum: "nr",
			syscallArgs: "args",
			defaultRetType: "int",
			defaultRetVal: "SECCOMP_RET_ALLOW",
			errorRetVal: "SECCOMP_RET_ERRNO",
		}

		file, err := os.Open(f.trace)
		if err != nil {
			return nil, fmt.Errorf("failed to open trace file. err: %v", err)
		}

		sifter.traceFile = file;
		sifter.traceScanner = bufio.NewScanner(file)
		sifter.traceScanner.Scan()
		if err := sifter.traceScanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to parse trace file. err: %v", err)
		}

		mapsHeader := strings.Fields(sifter.traceScanner.Text())
		if (mapsHeader[0] != "m") {
			return nil, fmt.Errorf("failed to parse trace file. expected 'm'")
		}
	} else {
		return nil, fmt.Errorf("invalid mode. expected \"tracer\"/\"filter\"")
	}

	_, err := os.Stat(f.outdir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(f.outdir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create output dir %v", f.outdir)
		}
	}

	for _, syscall := range sifter.target.Syscalls {
		// Build original syscall list
		if !strings.Contains(syscall.Name, "$") && !strings.Contains(syscall.Name, "syz_") {
			sifter.syscalls[syscall.NR] = syscall
		}
		// Find out path of driver
		if len(sifter.devName) == 0 && syscall.CallName == "syz_open_dev" {
			if ret, ok := syscall.Ret.(*prog.ResourceType); ok {
				if ret.String() == sifter.fdName {
					if devName, ok := extractStringConst(syscall.Args[0]); ok {
						sifter.devName = filepath.Base(strings.Replace(devName, "#", "0", 1))
					}
				}
			}
		}
		// Scan for syscalls using the driver
		for _, args := range syscall.Args {
			if args.Name() == sifter.fdName {
				callName := syscall.CallName
				if callName == "ioctl" {
					fmt.Printf("trace syscall %v\n", syscall.Name)
					sifter.moduleSyscalls[callName] = append(sifter.moduleSyscalls[callName], syscall)
				} else {
					fmt.Printf("trace syscall %v\n", callName)
					sifter.moduleSyscalls[callName] = append(sifter.moduleSyscalls[callName], sifter.target.SyscallMap[callName])
				}
			}
		}
	}

	if len(sifter.devName) == 0 {
		return nil, fmt.Errorf("cannot find dev for %v", sifter.fdName)
	} else {
		fmt.Printf("trace dev: %v\n", sifter.devName)
	}

	syscallMax := 0
	for i, s := range sifter.syscalls {
		if s != nil {
			syscallMax = i
		}
	}
	sifter.syscalls = sifter.syscalls[:syscallMax]

	return sifter, nil
}

func (sifter *Sifter) GetSection(name string) *bytes.Buffer {
	var s *bytes.Buffer
	if section, ok := sifter.sections[name]; ok {
		s = section
	} else {
		s = new(bytes.Buffer)
		sifter.sections[name] = s
	}
	return s
}

func fixName(name string) string {
	fixChar := []string{".", "$", "-", ">", "[", "]"}
	for _, char := range fixChar {
		name = strings.Replace(name, char, "_", -1)
	}
	return name
}

func (sifter *Sifter) NewArgMap(name string, dataType string, mapType int) (*ArgMap) {
	newArgMap := &ArgMap{
		name: fixName(name),
		path: name,
		datatype: dataType,
		mapType: mapType,
	}
	sifter.argMaps = append(sifter.argMaps, newArgMap)
	return newArgMap
}

func (sifter *Sifter) NewSeqArg(name string) {
	newSeqArg := new(SeqArg)
	newSeqArg.name = fixName(name)
	newSeqArg.hashTable = make(map[uint16]map[uint16]bool)
	newSeqArg.tidMap = make(map[uint16]uint32)
	sifter.seqArgs = append(sifter.seqArgs, newSeqArg)
}

func (sifter *Sifter) AddStruct(s *prog.StructType) {
	// Return if the struct is already added
	for _, _s := range sifter.structs {
		if _s.Name() == s.Name() {
			return
		}
	}

	fmt.Printf("add new struct: %v\n", s.Name())
	// Scan for dependencies and insert
	for i, _s := range sifter.structs {
		for _, field := range _s.StructDesc.Fields {
			if field.Name() == s.Name() {
				sifter.structs = append(sifter.structs, s)
				copy(sifter.structs[i+1:], sifter.structs[i:])
				sifter.structs[i] = s
				return
			}
		}
	}
	sifter.structs = append(sifter.structs, s)
}

func (sifter *Sifter) GenerateCheckArg(s *strings.Builder, arg *ArgMap) {
	argType := arg.datatype
	argName := arg.path
	mapType := arg.mapType
	sifter.traceScanner.Scan()
	if err := sifter.traceScanner.Err(); err != nil {
		failf("failed to parse trace file. err: %v", err)
	}
	mapEntry := strings.Fields(sifter.traceScanner.Text())
	if len(mapEntry) != 2 {
		failf("failed to parse trace file. expected 2 entries but got %v",
			  sifter.traceScanner.Text())
	}

	if mapType == 0 {
		min, _ := strconv.ParseInt(mapEntry[0], 10, 64)
		max, _ := strconv.ParseInt(mapEntry[1], 10, 64)

		if max > math.MaxInt32 {
			fmt.Printf("%v %v max %v exceeds max of int32_t. Is it a pointer?\n", argType, argName, max)
			fmt.Fprintf(s, "//check_arg_range(%v, %v, %v);", argName, min, max)
		} else if min == max {
			fmt.Fprintf(s, "check_arg_value(%v, %v);\n", argName, min)
		} else {
			fmt.Fprintf(s, "check_arg_range(%v, %v, %v);\n", argName, min, max)
		}
	}
	if mapType == 1 {
		zeros, _ := strconv.ParseUint(mapEntry[0], 10, 64)
		ones, _ := strconv.ParseUint(mapEntry[1], 10, 64)

		if argType == "uint64_t" {
			fmt.Fprintf(s, "check_arg_bits(%v, %vU, %vU);\n", argName, zeros, ones)
		} else {
			fmt.Fprintf(s, "check_arg_bits(%v, %v, %v);\n", argName, zeros, ones)
		}
	}
}

func (sifter *Sifter) GenerateUpdateArg(s *strings.Builder, arg *ArgMap) {
	argType := arg.datatype
	argName := arg.path
	argMap := arg.name
	if arg.mapType == 0 {
		fmt.Fprintf(s, "{\n")
		fmt.Fprintf(s, "int i = 0;\n")
		fmt.Fprintf(s, "%v *%v_min = bpf_%v_lookup_elem(&i);\n", argType, argMap, argMap)
		fmt.Fprintf(s, "if (%v_min) {\n", argMap)
		fmt.Fprintf(s, "    if (%v < *%v_min) {\n", argName, argMap)
		fmt.Fprintf(s, "        *%v_min = %v;\n", argMap, argName)
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "i = 1;\n")
		fmt.Fprintf(s, "%v *%v_max = bpf_%v_lookup_elem(&i);\n", argType, argMap, argMap)
		fmt.Fprintf(s, "if (%v_max) {\n", argMap)
		fmt.Fprintf(s, "    if (%v > *%v_max) {\n", argName, argMap)
		fmt.Fprintf(s, "        *%v_max = %v;\n", argMap, argName)
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "}\n")
	}
	if arg.mapType == 1 {
		fmt.Fprintf(s, "{\n")
		fmt.Fprintf(s, "int i = 0;\n")
		fmt.Fprintf(s, "%v *%v_zeros = bpf_%v_lookup_elem(&i);\n", argType, argMap, argMap)
		fmt.Fprintf(s, "if (%v_zeros) {\n", argMap)
		fmt.Fprintf(s, "    *%v_zeros |= ~%v;\n", argMap, argName)
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "i = 1;\n")
		fmt.Fprintf(s, "%v *%v_ones = bpf_%v_lookup_elem(&i);\n", argType, argMap, argMap)
		fmt.Fprintf(s, "if (%v_ones) {\n", argMap)
		fmt.Fprintf(s, "    *%v_ones |= %v;\n", argMap, argName)
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "}\n")
	}
}

func indent(s string, indent int) string {
	s = strings.TrimSuffix(s, "\n")
	s = strings.Replace(s, "\n", "\n"+strings.Repeat(" ", 4*indent), -1)
	return s + "\n"
}

func (sifter *Sifter) GenerateTraceArg(arg *ArgMap) string {
	var s strings.Builder
	if (sifter.mode == TracerMode) {
		sifter.GenerateUpdateArg(&s, arg)
	} else if (sifter.mode == FilterMode){
		sifter.GenerateCheckArg(&s, arg)
	}
	return s.String()
}

func (sifter *Sifter) GenerateCopyFromUser(src string, dst *string, argType string) string {
	var s strings.Builder
	*dst = fmt.Sprintf("v%v", sifter.structId)
	fmt.Fprintf(&s, "%v %v;\n", argType, *dst)
	//fmt.Fprintf(&s, "bpf_probe_read_sleepable(&%v, sizeof(%v), (void *)%v);\n", *dst, *dst, src)
	fmt.Fprintf(&s, "if (bpf_probe_read_sleepable(&%v, sizeof(%v), (void *)%v) < 0)\n", *dst, *dst, src)
	fmt.Fprintf(&s, "    return %v;\n", sifter.ctx.errorRetVal)
	sifter.structId += 1
	return s.String()
}

func (sifter *Sifter) IsVarLenRecord(arg *prog.UnionType) (bool, int, []uint64) {
	headerSize := -1
	headers := []uint64{}
	for _, t := range arg.Fields {
		if structure, ok := t.(*prog.StructType); ok {
			if header, ok := structure.Fields[0].(*prog.ConstType); ok {
				if headerSize == -1 {
					headerSize = (int)(header.TypeSize)
				}
				if headerSize == (int)(header.TypeSize) {
					headers = append(headers, header.Val)
				} else {
					goto isNotVLR
				}
			} else {
				goto isNotVLR
			}
		} else {
			goto isNotVLR
		}
	}
	return true, headerSize, headers
isNotVLR:
	return false, 0, nil
}

func (sifter *Sifter) GenerateTraceVLR(s *bytes.Buffer, arg *prog.UnionType, headerSize int, headers []uint64) {
	vlrName := arg.Name()
	sifter.NewSeqArg(vlrName)
	fmt.Fprintf(s, "    uint%v_t header;\n", headerSize*8)
	fmt.Fprintf(s, "    bpf_probe_read_sleepable(&header, %v, ptr);\n", headerSize)
	fmt.Fprintf(s, "    ptr = (void *)(uintptr_t)(ptr + %v);\n", headerSize)
	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "    update_%v_seq(pid, IOC_NR(header));\n", vlrName)
	} else if sifter.mode == FilterMode {
		fmt.Fprintf(s, "    %v", indent(sifter.GenerateSeqCheck(vlrName, "IOC_NR(header)"), 1))
	}
	fmt.Fprintf(s, "    switch (header) {\n")
	for i, record := range arg.Fields {
		rName := record.(*prog.StructType).FldName
		fmt.Fprintf(s, "    case %v: {//%v\n", headers[i], rName)
		for j, rf:= range record.(*prog.StructType).Fields {
			if j == 0 {
				continue
			}
			switch rft := rf.(type) {
			case *prog.StructType:
				sifter.AddStruct(rft)
				rfArgName := ""
				fmt.Fprintf(s, "        %v", indent(sifter.GenerateCopyFromUser("ptr", &rfArgName, "struct "+rft.Name()), 2))
				for _, sf := range rft.Fields {
//					depth := 0
//					sifter.GenerateRecursiveTracer(sf, s, rfArgName, false, &depth, 1)

//					switch sf.(type) {
//					case *prog.LenType, *prog.IntType, *prog.ConstType:
//						argType := fmt.Sprintf("uint%v_t", sf.TypeBitSize())
//						argName := fmt.Sprintf("vlr_%v_%v_%v", rName, rf.FieldName(), sf.FieldName())
//						m := sifter.NewArgMap(argName, argType, 0)
//						fmt.Fprintf(s, "        %v %v;\n", argType, argName)
//						fmt.Fprintf(s, "        bpf_probe_read_sleepable(&%v, %v, ptr);\n", argName, sf.Size())
//						fmt.Fprintf(s, "        %v", sifter.GenerateTraceArg(m, 2))
//						fmt.Fprintf(s, "        ptr = (void *)(uintptr_t)(ptr + %v);\n", sf.Size())
//					case *prog.FlagsType:
//						argType := fmt.Sprintf("uint%v_t", sf.TypeBitSize())
//						argName := fmt.Sprintf("vlr_%v_%v_%v", rName, rf.FieldName(), sf.FieldName())
//						m := sifter.NewArgMap(argName, argType, 1)
//						fmt.Fprintf(s, "        %v %v;\n", argType, argName)
//						fmt.Fprintf(s, "        bpf_probe_read_sleepable(&%v, %v, ptr);\n", argName, sf.Size())
//						fmt.Fprintf(s, "        %v", sifter.GenerateTraceArg(m, 2))
//						fmt.Fprintf(s, "        ptr = (void *)(uintptr_t)(ptr + %v);\n", sf.Size())
//					default:
//						fmt.Fprintf(s, "        //Skip %v\n", sf.Name())
//						fmt.Fprintf(s, "        ptr = (void *)(uintptr_t)(ptr + %v);\n", sf.Size())
//					}

					switch sf.(type) {
					case *prog.LenType, *prog.IntType, *prog.ConstType:
						argType := fmt.Sprintf("uint%v_t", sf.TypeBitSize())
						argName := fmt.Sprintf("%v.%v", rfArgName, sf.FieldName())
						m := sifter.NewArgMap(argName, argType, 0)
						fmt.Fprintf(s, "        %v", indent(sifter.GenerateTraceArg(m), 2))
					case *prog.FlagsType:
						argType := fmt.Sprintf("uint%v_t", sf.TypeBitSize())
						argName := fmt.Sprintf("%v.%v", rfArgName, sf.FieldName())
						m := sifter.NewArgMap(argName, argType, 1)
						fmt.Fprintf(s, "        %v", indent(sifter.GenerateTraceArg(m), 2))
					default:
						fmt.Fprintf(s, "        //Skip %v\n", sf.Name())
					}
				}
				fmt.Fprintf(s, "        ptr = (void *)(uintptr_t)(ptr + sizeof(%v));\n", rfArgName)
			case *prog.LenType, *prog.IntType, *prog.ConstType:
				argType := fmt.Sprintf("uint%v_t", rf.TypeBitSize())
				argName := ""
				fmt.Fprintf(s, "        %v", indent(sifter.GenerateCopyFromUser("ptr", &argName, argType), 2))
				m := sifter.NewArgMap(argName, argType, 0)
				fmt.Fprintf(s, "        %v", indent(sifter.GenerateTraceArg(m), 2))
				fmt.Fprintf(s, "        ptr = (void *)(uintptr_t)(ptr + %v);\n", rf.Size())
			case *prog.FlagsType:
				argType := fmt.Sprintf("uint%v_t", rf.TypeBitSize())
				argName := ""
				fmt.Fprintf(s, "        %v", indent(sifter.GenerateCopyFromUser("ptr", &argName, argType), 2))
				m := sifter.NewArgMap(argName, argType, 1)
				fmt.Fprintf(s, "        %v", indent(sifter.GenerateTraceArg(m), 2))
				fmt.Fprintf(s, "        ptr = (void *)(uintptr_t)(ptr + %v);\n", rf.Size())
			default:
				fmt.Fprintf(s, "        //Skip %v\n", rf.Name())
				fmt.Fprintf(s, "        ptr = (void *)(uintptr_t)(ptr + %v);\n", rf.Size())
			}
		}
		fmt.Fprintf(s, "        break;\n")
		fmt.Fprintf(s, "    }\n")
	}
	fmt.Fprintf(s, "    }\n")
}

func (sifter *Sifter) GenerateTraceArray(s *bytes.Buffer, arg prog.Type, argName string, iter int) {
	fmt.Fprintf(s, "    void *buffer = (void *)%v;\n", argName)
	fmt.Fprintf(s, "    void *ptr = buffer + /*fill*/;\n")
	fmt.Fprintf(s, "    void *end = buffer + /*fill*/;\n")
	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "    uint32_t pid = get_current_pid();\n")
	}
	ss := new(bytes.Buffer)
	if iter == -1 {
		iter = sifter.loopUnroll
		switch t := arg.(type) {
		case *prog.UnionType:
			isVLR, headerSize, headers := sifter.IsVarLenRecord(t)
			if !isVLR {
				fmt.Fprintf(ss, "    /*fill*/;\n")
				break
			}
			sifter.GenerateTraceVLR(ss, t, headerSize, headers)
		}
	}

	for i := 0; i < iter; i++ {
		fmt.Fprintf(s, "    if (ptr < end) {\n")
		fmt.Fprintf(s, "%v\n", ss.String())
		fmt.Fprintf(s, "    } else {\n")
		fmt.Fprintf(s, "        goto out;\n")
		fmt.Fprintf(s, "    }\n")
	}
	fmt.Fprintf(s, "out:\n")
}

func (sifter *Sifter) GenerateRecursiveTracer(arg prog.Type, s *bytes.Buffer, path string, fromPointer bool, depth *int, depthLimit int) {
	if depthLimit != -1 && *depth >= depthLimit {
		return
	}

	argType := ""
	switch tt := arg.(type) {
	case *prog.BufferType:
		fmt.Fprintf(s, "    //arg %v %v %v\n", arg, arg.Name(), arg.FieldName())
	case *prog.ArrayType:
		if tt.IsVarlen {
			fmt.Fprintf(s, "    //arg %v %v %v varlen\n", arg, arg.Name(), arg.FieldName())
		} else {
			fmt.Fprintf(s, "    //arg %v %v %v\n", arg, arg.Name(), arg.FieldName())
		}
	case *prog.StructType:
		if tt.IsVarlen {
			fmt.Fprintf(s, "    //arg %v %v %v varlen %v\n", arg, arg.Name(), arg.FieldName(), tt)
			return
		} else {
			fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
		}
		argType = fmt.Sprintf("struct %v", tt.String())
	case *prog.UnionType:
		fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
	default:
		argType = fmt.Sprintf("uint%v_t", 8*tt.Size())
		fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
	}

	switch t := arg.(type) {
	case *prog.PtrType:
		if *depth != 0 {
			path = path + "." + arg.FieldName()
		}
		*depth += 1
		sifter.GenerateRecursiveTracer(t.Type, s, path, true, depth, -1)
		*depth -= 1
	case *prog.StructType:
		structPath := ""
		if fromPointer {
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateCopyFromUser(path, &structPath, argType), 1))
		} else {
			structPath = path + "." + arg.FieldName()
		}

		sifter.AddStruct(t)
		for _, field := range t.Fields {
			sifter.GenerateRecursiveTracer(field, s, structPath, false, depth, -1)
		}
	case *prog.LenType, *prog.IntType, *prog.ConstType:
		if c, ok := t.(*prog.ConstType); ok && c.IsPad {
			break
		}

		argName := ""
		if fromPointer {
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateCopyFromUser(path, &argName, argType), 1))
		} else if *depth == 0 {
			argName = path
		} else {
			argName = path + "." + arg.FieldName()
		}

		m := sifter.NewArgMap(argName, argType, 0)
		fmt.Fprintf(s, "    %v", indent(sifter.GenerateTraceArg(m), 1))
	case *prog.FlagsType:
		argName := ""
		if fromPointer {
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateCopyFromUser(path, &argName, argType), 1))
		} else if *depth == 0 {
			argName = path
		} else {
			argName = path + "." + arg.FieldName()
		}

		m := sifter.NewArgMap(argName, argType, 1)
		fmt.Fprintf(s, "    %v", indent(sifter.GenerateTraceArg(m), 1))
	case *prog.ArrayType:
		iter := 0
		if t.IsVarlen {
			iter = -1
		} else {

		}

		argName := ""
		if fromPointer {
			argName = path
		} else if *depth == 0 {
			argName = path
		} else {
			argName = path + "." + arg.FieldName()
		}
		sifter.GenerateTraceArray(s, t.Type, argName, iter)
	case *prog.VmaType:
	case *prog.UnionType:
	case *prog.BufferType:
	case *prog.ResourceType:
	default:
		fmt.Println("Unhandled type", t)
	}

}

func (sifter *Sifter) GenerateSyscallTracer(syscalls []*prog.Syscall) {
	syscall := syscalls[0]
	if len(syscalls) > 1 {
		fmt.Printf("%v has multiple variations. Only %v is traced!\n", syscall.CallName, syscall.Name)
	}

	s := sifter.GetSection("level1_tracing")
	traceFuncName := "trace_" + syscall.CallName
	fmt.Fprintf(s, "%v __always_inline %v(%v *ctx) {\n", sifter.ctx.defaultRetType, traceFuncName, sifter.ctx.name)
	fmt.Fprintf(s, "    %v ret = %v;\n", sifter.ctx.defaultRetType, sifter.ctx.defaultRetVal)
	for i, arg := range syscall.Args {
		path := fmt.Sprintf("ctx->%v[%v]", sifter.ctx.syscallArgs, i)
		offset := 0
		sifter.GenerateRecursiveTracer(arg, s, path, false, &offset, -1)
	}
	fmt.Fprintf(s, "    return ret;\n")
	fmt.Fprintf(s, "}\n\n")
}

func (sifter *Sifter) GenerateIoctlTracer(syscalls []*prog.Syscall) {
	s := sifter.GetSection("level1_tracing")
//	fmt.Fprintf(s, "SEC(\"kprobe/%v\")\n", sifter.syscallEntry)
//	fmt.Fprintf(s, "int kprobe_%v(struct user_pt_regs *ctx) {\n", sifter.syscallEntry)
	fmt.Fprintf(s, "%v __always_inline trace_ioctl(%v *ctx) {\n", sifter.ctx.defaultRetType, sifter.ctx.name)
	fmt.Fprintf(s, "    %v ret = %v;\n", sifter.ctx.defaultRetType, sifter.ctx.defaultRetVal)
	fmt.Fprintf(s, "    uint64_t ioctl_cmd = ctx->%v[1];\n", sifter.ctx.syscallArgs)
	fmt.Fprintf(s, "    switch (ioctl_cmd) {\n")
	for _, syscall := range syscalls {
		commands := syscall.Name
		cmd, ok := syscall.Args[1].(*prog.ConstType)
		if !ok {
			failf("failed to get const command value for %v", commands)
		}
		if !strings.Contains(commands, "_compact_") {
			traceFuncName := fmt.Sprintf("trace_ioctl_0x%x", cmd.Val)
			sifter.GenerateIoctlCmdTracer(traceFuncName, sifter.target.SyscallMap[commands])
			fmt.Fprintf(s, "    case 0x%x: //%v\n", cmd.Val, commands)
			fmt.Fprintf(s, "        ret = %v(ctx);\n", traceFuncName)
			fmt.Fprintf(s, "        break;\n")
			cmdId := uint16((cmd.Val & ((1 << 8)-1)) | 0x8000)
			sifter.seqArgs[0].tidMap[cmdId] = uint32(cmd.Val)
		}
	}
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    return ret;\n")
	fmt.Fprintf(s, "}\n\n")
}

func (sifter *Sifter) GenerateIoctlCmdTracer(name string, syscall *prog.Syscall) {
	s := sifter.GetSection("level2_tracing")
	fmt.Fprintf(s, "%v __always_inline %v(%v *ctx) {\n", sifter.ctx.defaultRetType, name, sifter.ctx.name)
	fmt.Fprintf(s, "    %v ret = %v;\n", sifter.ctx.defaultRetType, sifter.ctx.defaultRetVal)
	path := fmt.Sprintf("ctx->%v[2]", sifter.ctx.syscallArgs)
	offset := 0
	sifter.GenerateRecursiveTracer(syscall.Args[2], s, path, true, &offset, -1)
	fmt.Fprintf(s, "    return ret;\n")
	fmt.Fprintf(s, "}\n\n")
}

//from "github.com/google/syzkaller/pkg/host/syscalls_linux.go"
func extractStringConst(typ prog.Type) (string, bool) {
	ptr, ok := typ.(*prog.PtrType)
	if !ok {
		panic("first open arg is not a pointer to string const")
	}
	str, ok := ptr.Type.(*prog.BufferType)
	if !ok || str.Kind != prog.BufferString || len(str.Values) == 0 {
		return "", false
	}
	v := str.Values[0]
	for len(v) != 0 && v[len(v)-1] == 0 {
		v = v[:len(v)-1] // string terminating \x00
	}
	return v, true
}

func (sifter *Sifter) SyscallNumber(name string) (uint64){
	for _, constant := range sifter.target.Consts {
		if constant.Name == "__NR_" + name {
			return constant.Value
		}
	}
	failf("cannot find syscall number for %v", name)
	return 0xffffffffffffffff
}

func ToFdMask(syscall *prog.Syscall) (uint8) {
	if syscall == nil {
		return 0
	}

	var mask uint8 = 0
	for i, arg := range syscall.Args {
		switch v := arg.(type) {
		case *prog.ResourceType:
			if v.TypeName == "fd" {
				mask += uint8(math.Pow(2, float64(i)))
			}
		}
	}
	return mask
}

func (sifter *Sifter) GenerateSeqTraceFunc(s *bytes.Buffer, name string) {
	fmt.Fprintf(s, "void __always_inline update_%v_seq(int pid, uint16_t id) {\n", name)
	fmt.Fprintf(s, "    seq_rb_elem *rb = bpf_%v_seq_rb_lookup_elem(&pid);\n", name)
	fmt.Fprintf(s, "    if (rb) {\n")
	fmt.Fprintf(s, "        uint8_t next;\n");
	fmt.Fprintf(s, "        bpf_spin_lock(&rb->lock);\n")
	fmt.Fprintf(s, "        next = rb->next;\n")
	fmt.Fprintf(s, "        next += 1;\n")
	fmt.Fprintf(s, "        rb->next = next;\n")
	fmt.Fprintf(s, "        bpf_spin_unlock(&rb->lock);\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "        if (next-1 < 128)\n")
	fmt.Fprintf(s, "            rb->id0[next-1] = id;\n")
	fmt.Fprintf(s, "        else\n")
	fmt.Fprintf(s, "            rb->id1[next-129] = id;\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "        uint8_t *ctr = bpf_%v_seq_rb_ctr_lookup_elem(&pid);\n", name)
	fmt.Fprintf(s, "        if (ctr && (next == 0 || next == 128 || id == (uint16_t)-1)) {\n")
	fmt.Fprintf(s, "            *ctr += 1;\n")
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
}

func (sifter *Sifter) GenerateSeqCheckFuncN(s *bytes.Buffer, name string) {
	fmt.Fprintf(s, "void __always_inline update_%v_seq(uint8_t next_id)\n", name)
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int i = 0;\n")
	fmt.Fprintf(s, "    int *%v_seq_next_idx = bpf_%v_seq_next_lookup_elem(&i);\n", name, name)
	fmt.Fprintf(s, "    if (%v_seq_next_idx) {\n", name)
	fmt.Fprintf(s, "        int next_idx = *%v_seq_next_idx;\n", name)
	fmt.Fprintf(s, "        bpf_%v_seq_rb_update_elem(&next_idx, &next_id, BPF_ANY);\n", name)
	fmt.Fprintf(s, "        if (*%v_seq_next_idx == SEQ_RB_SIZE-1)\n", name)
	fmt.Fprintf(s, "            *%v_seq_next_idx = 0;\n", name)
	fmt.Fprintf(s, "        else\n")
	fmt.Fprintf(s, "            *%v_seq_next_idx += 1;\n", name)
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "uint8_t __always_inline next_%v_id(uint32_t next)\n", name)
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    uint8_t *next_id = bpf_%v_id_map_lookup_elem(&next);\n", name)
	fmt.Fprintf(s, "    if (next_id) {\n")
	fmt.Fprintf(s, "        return *next_id;\n")
	fmt.Fprintf(s, "    } else {\n")
	fmt.Fprintf(s, "        return 255;\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline get_%v_seq_1()\n", name)
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int i = 0;\n")
	fmt.Fprintf(s, "    int *next_idx = bpf_%v_seq_next_lookup_elem(&i);\n", name)
	fmt.Fprintf(s, "    if (next_idx) {\n")
	fmt.Fprintf(s, "        int last_idx = 0; \n")
	fmt.Fprintf(s, "        if (*next_idx == 0)\n")
	fmt.Fprintf(s, "            last_idx = SEQ_RB_SIZE - 1;\n")
	fmt.Fprintf(s, "        else\n")
	fmt.Fprintf(s, "            last_idx = *next_idx - 1;\n")
	fmt.Fprintf(s, "        uint8_t *last_id = bpf_%v_seq_rb_lookup_elem(&last_idx);\n", name)
	fmt.Fprintf(s, "        if (last_id)\n")
	fmt.Fprintf(s, "            return *last_id;\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    return 255;//XXX should return error\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline check_%v_id_seq_1(uint8_t next_id)\n", name)
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int last_id = get_%v_seq_1();\n", name)
	fmt.Fprintf(s, "    uint64_t *next_ids = bpf_%v_id_seq_1_map_lookup_elem(&last_id);\n", name)
	fmt.Fprintf(s, "    if (next_ids && (*next_ids & (1 << next_id))) {\n")
	fmt.Fprintf(s, "        return SECCOMP_RET_ALLOW;\n")
	fmt.Fprintf(s, "    } else {\n")
	fmt.Fprintf(s, "        return SECCOMP_RET_ERRNO;\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
}

func (sifter *Sifter) GenerateSeqCheckFunc(s *bytes.Buffer, name string) {
	fmt.Fprintf(s, "uint8_t __always_inline next_%v_id(uint32_t next)\n", name)
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    uint8_t *next_id = bpf_%v_id_map_lookup_elem(&next);\n", name)
	fmt.Fprintf(s, "    if (next_id) {\n")
	fmt.Fprintf(s, "        return *next_id;\n")
	fmt.Fprintf(s, "    } else {\n")
	fmt.Fprintf(s, "        return 255;\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline get_%v_seq_1()\n", name)
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int i = 0;\n")
	fmt.Fprintf(s, "    uint8_t *last_id = bpf_%v_seq_rb_lookup_elem(&i);\n", name)
	fmt.Fprintf(s, "    if (last_id)\n")
	fmt.Fprintf(s, "           return *last_id;\n")
	fmt.Fprintf(s, "    return 255;\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline check_%v_id_seq_1(uint8_t next_id)\n", name)
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int last_id = get_%v_seq_1();\n", name)
	fmt.Fprintf(s, "    uint64_t *next_ids = bpf_%v_id_seq_1_map_lookup_elem(&last_id);\n", name)
	fmt.Fprintf(s, "    if (next_ids && (*next_ids & (1 << next_id))) {\n")
	fmt.Fprintf(s, "        return SECCOMP_RET_ALLOW;\n")
	fmt.Fprintf(s, "    } else {\n")
	fmt.Fprintf(s, "        return SECCOMP_RET_ERRNO;\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
}

func (sifter *Sifter) GenerateSeqCheck(name string, next string) string {
	var s strings.Builder
	fmt.Fprintf(&s, "uint8_t next_id = next_%v_id(%v);\n", name, next)
	fmt.Fprintf(&s, "ret = check_%v_id_seq_1(next_id);\n", name)
	fmt.Fprintf(&s, "if (ret == SECCOMP_RET_ALLOW) {\n")
	fmt.Fprintf(&s, "    int i = 0;\n")
	fmt.Fprintf(&s, "    bpf_%v_seq_rb_update_elem(&i, &next_id, BPF_ANY);\n", name)
	fmt.Fprintf(&s, "} else {\n")
	fmt.Fprintf(&s, "    goto out;\n")
	fmt.Fprintf(&s, "}\n")

//	fmt.Fprintf(&s, "uint8_t next_id = next_%v_id(%v);\n", name, next)
//	fmt.Fprintf(&s, "ret = check_%v_id_seq_1(next_id);\n", name)
//	fmt.Fprintf(&s, "if (ret == SECCOMP_RET_ALLOW) {\n")
//	fmt.Fprintf(&s, "    update_syscall_seq(next_id);\n")
//	fmt.Fprintf(&s, "} else {\n")
//	fmt.Fprintf(&s, "    goto out;\n")
//	fmt.Fprintf(&s, "}\n")
	return s.String()
}

func (sifter *Sifter) GenerateProgSection() {
	// Generate syscall tracing logic
	sifter.NewSeqArg("syscall")
	for key, syscalls := range sifter.moduleSyscalls {
		if key == "ioctl" {
			sifter.GenerateIoctlTracer(syscalls)
		} else {
			sifter.GenerateSyscallTracer(syscalls)
		}
	}

	if sifter.mode == TracerMode {
		s := sifter.GetSection("main")
		fmt.Fprintf(s, "uint16_t __always_inline arg_to_id(sys_enter_args *ctx) {\n")
		fmt.Fprintf(s, "    int nr = ctx->id;\n")
		fmt.Fprintf(s, "    int fd_is_dev = 0;\n")
		fmt.Fprintf(s, "    uint16_t id = 0xffff;\n")
		fmt.Fprintf(s, "    char dev [] = \"%v\";\n", sifter.devName)
		fmt.Fprintf(s, "    uint8_t *fd_mask = bpf_syscall_fd_mask_lookup_elem(&nr);\n")
		fmt.Fprintf(s, "    if (fd_mask) {\n")
		fmt.Fprintf(s, "        for (int i = 0; i < 5; i++) {\n")
		fmt.Fprintf(s, "            if ((*fd_mask >> i) & 0x01 &&\n")
		fmt.Fprintf(s, "                (bpf_check_fd(dev, ctx->regs[i]))) {\n")
		fmt.Fprintf(s, "                fd_is_dev = 1;\n")
		fmt.Fprintf(s, "                break;\n")
		fmt.Fprintf(s, "            }\n")
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    if (fd_is_dev) {\n")
		fmt.Fprintf(s, "        if (nr == %v) {\n", sifter.SyscallNumber("ioctl"))
		fmt.Fprintf(s, "            id = ID_IOCTL(ctx->regs[1]);\n")
		fmt.Fprintf(s, "            trace_ioctl(ctx);\n")
		for key, _ := range sifter.moduleSyscalls {
			if key != "ioctl" {
				fmt.Fprintf(s, "        } else if (nr == %v) {\n", sifter.SyscallNumber(key))
				fmt.Fprintf(s, "            id = nr;\n")
				fmt.Fprintf(s, "            trace_%v(ctx);\n", key)
			}
		}
		fmt.Fprintf(s, "        } else {\n")
		fmt.Fprintf(s, "            id = nr;\n")
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    return id;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "SEC(\"tracepoint/raw_syscalls/sys_enter\")\n")
		fmt.Fprintf(s, "int sys_enter_prog(sys_enter_args *ctx) {\n")
		fmt.Fprintf(s, "    uint16_t id = arg_to_id(ctx);\n")
		fmt.Fprintf(s, "    if (id != 0xffff) {\n")
		fmt.Fprintf(s, "        uint32_t pid = get_current_pid();\n")
		fmt.Fprintf(s, "        update_syscall_seq(pid, id);\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    return 0;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "SEC(\"kprobe/do_exit\")\n")
		fmt.Fprintf(s, "int kprobe_do_exit(struct user_pt_regs *ctx) {\n")
		fmt.Fprintf(s, "    uint32_t pid = get_current_pid();\n")
		fmt.Fprintf(s, "    update_syscall_seq(pid, (uint16_t)-1);\n")
		fmt.Fprintf(s, "    return 0;\n")
		fmt.Fprintf(s, "}\n")
	} else if sifter.mode == FilterMode {
		s := sifter.GetSection("main")
		fmt.Fprintf(s, "int __always_inline check_dev_path(char *path)\n")
		fmt.Fprintf(s, "{\n")
		fmt.Fprintf(s, "    char dev_path[] = \"/dev/%v\";\n", sifter.devName)
		fmt.Fprintf(s, "    char path_char = '\\0';\n")
		fmt.Fprintf(s, "    for (int i = 0; i < sizeof(dev_path); i++) {\n")
		fmt.Fprintf(s, "        bpf_probe_read_sleepable(&path_char, 1, (void *)(path+i));\n")
		fmt.Fprintf(s, "        if (dev_path[i] != path_char) {\n")
		fmt.Fprintf(s, "            return 0;\n")
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    return 1;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "void __always_inline check_dev_open(struct seccomp_data *ctx) {\n")
		fmt.Fprintf(s, "    if (check_dev_path((char *)ctx->args[1])) {\n")
		fmt.Fprintf(s, "        int i = 0;\n")
		fmt.Fprintf(s, "        int init_map = 1;\n")
		fmt.Fprintf(s, "        if (bpf_init_map_update_elem(&i, &init_map, BPF_NOEXIST) != EEXIST) {\n")
		fmt.Fprintf(s, "            init_syscall_fd_mask();\n")
		for _, seq := range sifter.seqArgs {
			fmt.Fprintf(s, "            init_%v_id_map();\n", seq.name)
			fmt.Fprintf(s, "            init_%v_id_seq_1_map();\n", seq.name)
		}
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    return;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "SEC(\"seccomp\")\n")
		fmt.Fprintf(s, "int filter(struct seccomp_data *ctx)\n")
		fmt.Fprintf(s, "{\n")
		fmt.Fprintf(s, "    uint32_t nr = ctx->nr;\n")
		fmt.Fprintf(s, "    int ret = SECCOMP_RET_ALLOW;\n")
		fmt.Fprintf(s, "    if (nr == %v) {\n", sifter.SyscallNumber("openat"))
		fmt.Fprintf(s, "        check_dev_open(ctx);\n")
		fmt.Fprintf(s, "    } else if (nr != %v && check_syscall_fd(ctx)) {\n", sifter.SyscallNumber("close"))
		fmt.Fprintf(s, "        if (nr == %v) {\n", sifter.SyscallNumber("ioctl"))
		fmt.Fprintf(s, "            nr = ctx->args[1];\n")
		fmt.Fprintf(s, "            ret = trace_ioctl(ctx);\n")
		for key, _ := range sifter.moduleSyscalls {
			if key != "ioctl" && key != "close" {
				fmt.Fprintf(s, "        } else if (nr == %v) {\n", sifter.SyscallNumber(key))
				fmt.Fprintf(s, "            ret = trace_%v(ctx);\n", key)
			}
		}
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "        if (ret == SECCOMP_RET_ALLOW) {\n")
		fmt.Fprintf(s, "            %v", indent(sifter.GenerateSeqCheck("syscall", "nr"), 3))
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "out:\n")
		fmt.Fprintf(s, "    return ret;\n")
		fmt.Fprintf(s, "}\n")
	}
}

func (sifter *Sifter) ParseSeqPolicy(seq *SeqArg) {
	sifter.traceScanner.Scan()
	if err := sifter.traceScanner.Err(); err != nil {
		failf("failed to parse trace file. err: %v when parsing sequence section %v", err, seq.name)
	}

	seqHeader := strings.Fields(sifter.traceScanner.Text())
	if len(seqHeader) != 2 || seqHeader[0] != "r" {
		failf("failed to parse trace file. expected 'r <n>' but got %v when parsing sequence section %v",
			  sifter.traceScanner.Text(), seq.name)
	}

	sequences, _ := strconv.ParseInt(seqHeader[1], 10, 32)
	for i := 0; i < int(sequences); i++ {
		sifter.traceScanner.Scan()
		if err := sifter.traceScanner.Err(); err != nil {
			failf("failed to parse trace file. err: %v when parsing sequence section %v", err, seq.name)
		}
		seqEntry := strings.Fields(sifter.traceScanner.Text())

		var currId, nextId uint16
		var currLen, nextLen int
		t1, _ := strconv.ParseInt(seqEntry[0], 10, 32)
		currLen = int(t1)
		t2, _ := strconv.ParseInt(seqEntry[1], 10, 32)
		nextLen = int(t2)
		for ic := 0; ic < currLen; ic++ {
			if currLen - ic == 1 {
				tmp, _ := strconv.ParseInt(seqEntry[2+ic], 10, 32)
				currId = uint16(tmp)
			}
		}
		for in := 0; in < nextLen; in++ {
			tmp, _ := strconv.ParseInt(seqEntry[2+currLen+in], 10, 32)
			nextId = uint16(tmp)
//			if nextId == 0 {
//				continue
//			}

			if nextIds, ok := seq.hashTable[currId]; ok {
				nextIds[nextId] = true
			} else {
				seq.hashTable[currId] = make(map[uint16]bool)
				seq.hashTable[currId][nextId] = true
				seq.tids = append(seq.tids, currId)
			}
		}
	}

	sort.Slice(seq.tids, func(i, j int) bool { return seq.tids[i] < seq.tids[j] })
	fmt.Printf("\n%v sequences:\n", seq.name)
	for _, k := range seq.tids {
		fmt.Printf("%v | ", k)
		for next, _ := range seq.hashTable[k] {
			fmt.Printf("%v ", next)
		}
		fmt.Printf("\n")
	}

}

func (sifter *Sifter) GenerateInitArgMaps() (string) {
	var s strings.Builder
	for _, m := range sifter.argMaps {
		if m.mapType == 0 {
			fmt.Fprintf(&s, "i = 0;\n")
			fmt.Fprintf(&s, "%v *%v_min = bpf_%v_lookup_elem(&i);\n", m.datatype, m.name, m.name)
			fmt.Fprintf(&s, "if (%v_min) {\n", m.name)
			fmt.Fprintf(&s, "    *%v_min = -1;\n", m.name)
			fmt.Fprintf(&s, "}\n")
			fmt.Fprintf(&s, "i = 1;\n")
			fmt.Fprintf(&s, "%v *%v_max = bpf_%v_lookup_elem(&i);\n", m.datatype, m.name, m.name)
			fmt.Fprintf(&s, "if (%v_max) {\n", m.name)
			fmt.Fprintf(&s, "    *%v_max = 0;\n", m.name)
			fmt.Fprintf(&s, "}\n")
		}
		if m.mapType == 1 {
			fmt.Fprintf(&s, "i = 0;\n")
			fmt.Fprintf(&s, "%v *%v_zeros = bpf_%v_lookup_elem(&i);\n", m.datatype, m.name, m.name)
			fmt.Fprintf(&s, "if (%v_zeros) {\n", m.name)
			fmt.Fprintf(&s, "    *%v_zeros = 0;\n", m.name)
			fmt.Fprintf(&s, "}\n")
			fmt.Fprintf(&s, "i = 1;\n")
			fmt.Fprintf(&s, "%v *%v_ones = bpf_%v_lookup_elem(&i);\n", m.datatype, m.name, m.name)
			fmt.Fprintf(&s, "if (%v_ones) {\n", m.name)
			fmt.Fprintf(&s, "    *%v_ones = 0;\n", m.name)
			fmt.Fprintf(&s, "}\n")
		}
	}
	return s.String()

}

func (sifter *Sifter) GenerateInitSection() {
	s := sifter.GetSection("init")
	if (sifter.mode == TracerMode) {
		fmt.Fprintf(s, "void __always_inline init() {\n")
		fmt.Fprintf(s, "    int32_t i = 0;\n")
		fmt.Fprintf(s, "    int *init = bpf_init_map_lookup_elem(&i);\n")
		fmt.Fprintf(s, "    if (init && *init == 0) {\n")
		fmt.Fprintf(s, "        *init = 1;\n")
		fmt.Fprintf(s, "        %v\n", indent(sifter.GenerateInitArgMaps(), 2))
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "}\n\n")
	} else if (sifter.mode == FilterMode){
		fmt.Fprintf(s, "void __always_inline init_syscall_fd_mask() {\n")
		fmt.Fprintf(s, "    int id = 0;\n")
		fmt.Fprintf(s, "    uint8_t mask;\n")
		for _, syscall := range sifter.syscalls {
			fmt.Fprintf(s, "    mask = %v;\n", ToFdMask(syscall))
			fmt.Fprintf(s, "    bpf_syscall_fd_mask_update_elem(&id, &mask, BPF_ANY);\n")
			fmt.Fprintf(s, "    id++;\n")
		}
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")

		for _, seq := range sifter.seqArgs {
			fmt.Fprintf(s, "void __always_inline init_%v_id_map() {\n", seq.name)
			fmt.Fprintf(s, "    uint8_t id = 0;\n")
			fmt.Fprintf(s, "    uint32_t %v;\n", seq.name)
			for _, k := range seq.tids {
				fmt.Fprintf(s, "    %v = %v;\n", seq.name, sifter.TidToSyscall(k))
				fmt.Fprintf(s, "    bpf_%v_id_map_update_elem(&%v, &id, BPF_ANY);\n", seq.name, seq.name)
				fmt.Fprintf(s, "    id++;\n")
			}
			fmt.Fprintf(s, "}\n")
			fmt.Fprintf(s, "\n")
			fmt.Fprintf(s, "void __always_inline init_%v_id_seq_1_map() {\n", seq.name)
			fmt.Fprintf(s, "    int id = 0;\n")
			fmt.Fprintf(s, "    uint64_t next_%vs;\n", seq.name)
			for _, k := range seq.tids {
				var nexts uint64 = 0
				for next, _ := range seq.hashTable[k] {
					offset := 0
					for i, _k := range seq.tids {
						if _k == next {
							offset = i
						}
					}
					nexts += uint64(math.Pow(2, float64(offset)))
				}
				fmt.Fprintf(s, "    next_%vs = %v;\n", seq.name, nexts)
				fmt.Fprintf(s, "    bpf_%v_id_seq_1_map_update_elem(&id, &next_%vs, BPF_ANY);\n", seq.name, seq.name)
				fmt.Fprintf(s, "    id++;\n")
			}
			fmt.Fprintf(s, "}\n")
			fmt.Fprintf(s, "\n")
		}
	}
}

func (sifter *Sifter) GenerateMapSection() {
	s := sifter.GetSection("map")
	fmt.Fprintf(s, "DEFINE_BPF_MAP(init_map, ARRAY, int, int, 1)\n")
	fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_fd_mask, ARRAY, int, uint8_t, %v);\n", len(sifter.syscalls))

	if sifter.mode == TracerMode {
		for _, arg := range sifter.argMaps {
			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v, ARRAY, int, %v, 2)\n", arg.name, arg.datatype)
		}
		for _, seq := range sifter.seqArgs {
			fmt.Fprintf(s, "DEFINE_BPF_MAP_F(%v_seq_rb, ARRAY, int, seq_rb_elem, 32768, BPF_F_LOCK);\n", seq.name)
			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_seq_rb_ctr, ARRAY, int, uint8_t, 32768);\n", seq.name)
		}
	} else if sifter.mode == FilterMode {
		fmt.Fprintf(s, "#define SEQ_RB_SIZE 8\n")
		for _, seq := range sifter.seqArgs {
			idNum := len(seq.hashTable)
			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_seq_rb, ARRAY, int, uint8_t, 1);\n", seq.name)
			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_id_map, HASH, uint32_t, uint8_t, %v);\n", seq.name, idNum)
			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_id_seq_1_map, ARRAY, int, uint64_t, %v);\n", seq.name, idNum)

//			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_seq_next, ARRAY, int, int, 1);\n", seq.name)
//			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_seq_rb, ARRAY, int, uint8_t, SEQ_RB_SIZE);\n", seq.name)
//			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_id_map, HASH, uint32_t, uint8_t, %v);\n", seq.name, idNum)
//			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_id_seq_1_map, ARRAY, int, uint64_t, %v);\n", seq.name, idNum)
		}
	}
	fmt.Fprintf(s, "\n")
}

func (sifter *Sifter) GenerateStructSection() {
	s := sifter.GetSection("struct")
	for _, structure := range sifter.structs {
		fmt.Fprintf(s, "struct %v {\n", structure.Name())
		fieldPadNum := 0
		for _, field := range structure.StructDesc.Fields {
			fieldType := ""
			fieldIsArray := false
			var fieldLen uint64 = 0
			fieldIsPad := false
			fieldGetPadNum := 0
			_, err := fmt.Sscanf(field.FieldName(), "pad%d", &fieldGetPadNum)
			if err == nil {
				fieldPadNum = fieldGetPadNum
			}
			switch tt := field.(type) {
			case *prog.BufferType:
//                fmt.Fprintf(s, "    //arg %v %v %v\n", arg, arg.Name(), arg.FieldName())
				if field.Name() == "string" {
					fieldIsArray = true
					fieldLen = tt.Size()
					fieldType = "char";
				} else if field.Name() == "array" {
					fieldIsArray = true
					fieldLen = tt.Size()
					fieldType = "char";
				} else {
					fmt.Fprintf(s, "    //fixme\n")
				}
			case *prog.ConstType:
				if field.(*prog.ConstType).IsPad {
					fieldIsPad = true
					fieldPadNum += 1
					fieldLen = tt.Size()
					fieldType = "char"
				} else {
					fieldType = fmt.Sprintf("uint%v_t", 8*tt.Size())
				}
			case *prog.ArrayType:
//                fmt.Fprintf(s, "    //arg %v %v %v\n", arg, arg.Name(), arg.FieldName())
				fieldIsArray = true
				if field.(*prog.ArrayType).IsVarlen {
					fieldLen = 0;
				} else {
					fieldLen = (8*tt.Size()/field.(*prog.ArrayType).Type.TypeBitSize())
				}
				//fieldLen = (field.Size())
				//fieldType = fmt.Sprintf("uint%v_t", field.(*prog.ArrayType).Type.TypeBitSize())
				fieldType = fmt.Sprintf("uint%v_t", tt.Type.TypeBitSize())
			case *prog.StructType:
//                fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
				fieldType = fmt.Sprintf("struct %v", tt.String())
//            case *prog.UnionType:
//                fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
			default:
				fieldType = fmt.Sprintf("uint%v_t", 8*tt.Size())
//                fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
			}
			if fieldIsArray {
				if fieldLen == 0 {
				fmt.Fprintf(s, "    %v %v[%v]; //%v varlen\n", fieldType, field.FieldName(), fieldLen, field.Name())
				} else {
				fmt.Fprintf(s, "    %v %v[%v]; //%v\n", fieldType, field.FieldName(), fieldLen, field.Name())
				}
			} else if fieldIsPad {
				//fmt.Fprintf(s, "    %v pad%v; //%v\n", fieldType, fieldPadNum, field.Name())
				fmt.Fprintf(s, "    %v pad%v[%v]; //%v\n", fieldType, fieldPadNum, fieldLen, field.Name())
			} else {
				fmt.Fprintf(s, "    %v %v; //%v\n", fieldType, field.FieldName(), field.Name())
			}
		}
		fmt.Fprintf(s, "};\n\n")
	}
	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "typedef struct {\n")
		fmt.Fprintf(s, "    uint64_t ignore;\n")
		fmt.Fprintf(s, "    int64_t id;\n")
		fmt.Fprintf(s, "    uint64_t regs[6];\n")
		fmt.Fprintf(s, "} sys_enter_args;\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "typedef struct {\n")
		fmt.Fprintf(s, "    struct bpf_spin_lock lock;\n")
		fmt.Fprintf(s, "    uint8_t next;\n")
		fmt.Fprintf(s, "    uint16_t id0[128];\n")
		fmt.Fprintf(s, "    uint16_t id1[128];\n")
		fmt.Fprintf(s, "} seq_rb_elem;\n")
		fmt.Fprintf(s, "\n")
	}
}

func (sifter *Sifter) GenerateHelperSection() {
	s := sifter.GetSection("helper")
	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "int __always_inline get_current_pid() {\n")
		fmt.Fprintf(s, "    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();\n")
		fmt.Fprintf(s, "    int pid = current_pid_tgid >> 32;\n")
		fmt.Fprintf(s, "    return pid;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")

		for _, seq := range sifter.seqArgs {
			sifter.GenerateSeqTraceFunc(s, seq.name)
		}

	} else if sifter.mode == FilterMode {
		fmt.Fprintf(s, "#define bpf_printk(fmt, ...)                                   \\\n")
		fmt.Fprintf(s, "({                                                             \\\n")
		fmt.Fprintf(s, "    char ____fmt[] = fmt;                                      \\\n")
		fmt.Fprintf(s, "    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \\\n")
		fmt.Fprintf(s, "})\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "#define check_arg_value(arg, val)         \\\n")
		fmt.Fprintf(s, "    if (arg != val)                       \\\n")
		fmt.Fprintf(s, "        return SECCOMP_RET_ERRNO;\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "#define check_arg_range(arg, min, max)    \\\n")
		fmt.Fprintf(s, "    if (arg < min || arg > max)           \\\n")
		fmt.Fprintf(s, "        return SECCOMP_RET_ERRNO;\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "#define check_arg_bits(arg, zeros, ones)  \\\n")
		fmt.Fprintf(s, "    if (arg & zeros || (arg & ~ones) != 0)\\\n")
		fmt.Fprintf(s, "        return SECCOMP_RET_ERRNO;\n")
		fmt.Fprintf(s, "\n")

		for _, seq := range sifter.seqArgs {
			sifter.GenerateSeqCheckFunc(s, seq.name)
			//sifter.GenerateSeqCheckFuncN(s, name)
		}
	}
	fmt.Fprintf(s, "int __always_inline check_syscall_fd(%v *ctx)\n", sifter.ctx.name)
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int fd_is_dev = 0;\n")
	fmt.Fprintf(s, "    int syscall_nr = ctx->%v;\n", sifter.ctx.syscallNum)
	fmt.Fprintf(s, "    uint8_t *fd_mask = bpf_syscall_fd_mask_lookup_elem(&syscall_nr);\n")
	fmt.Fprintf(s, "    if (fd_mask) {\n")
	fmt.Fprintf(s, "        char dev [] = \"%v\";\n", sifter.devName)
	fmt.Fprintf(s, "        #pragma unroll\n")
	fmt.Fprintf(s, "        for (int i = 0; i < 5; i++) {\n")
	fmt.Fprintf(s, "            if ((*fd_mask >> i) & 0x01 && \n")
	fmt.Fprintf(s, "                (bpf_check_fd(dev, ctx->%v[i]))) {\n", sifter.ctx.syscallArgs)
	fmt.Fprintf(s, "                fd_is_dev = 1;\n")
	fmt.Fprintf(s, "                break;\n")
	fmt.Fprintf(s, "            }\n")
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    return fd_is_dev;\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
}

func (sifter *Sifter) GenerateHeaderSection() {
	s := sifter.GetSection("header")
	fmt.Fprintf(s, "#include <linux/seccomp.h>\n")
	fmt.Fprintf(s, "#include <linux/bpf.h>\n")
	fmt.Fprintf(s, "#include <linux/unistd.h>\n")
	fmt.Fprintf(s, "#include <linux/ptrace.h>\n")
	fmt.Fprintf(s, "#include <bpf_helpers.h>\n")
	fmt.Fprintf(s, "#include <linux/errno.h>\n")
	fmt.Fprintf(s, "#include <sys/types.h>\n")
	fmt.Fprintf(s, "#include \"tracer_id.h\"\n")
	fmt.Fprintf(s, "\n")
}

func (sifter *Sifter) GenerateSource() {
	licenseSec := sifter.GetSection("license")
	fmt.Fprintf(licenseSec, "char _license[] SEC(\"license\") = \"GPL\";\n")

	sifter.GenerateProgSection()
	if sifter.mode == FilterMode {
		for _, seq := range sifter.seqArgs {
			sifter.ParseSeqPolicy(seq)
		}
		sifter.traceFile.Close()
	}
	sifter.GenerateInitSection()
	sifter.GenerateMapSection()
	sifter.GenerateStructSection()
	sifter.GenerateHelperSection()
	sifter.GenerateHeaderSection()
}

func (sifter *Sifter) WriteSourceFile() {
	outf, err := os.Create(sifter.outSourceFile)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()
	outf.Write(sifter.sections["header"].Bytes())
	outf.Write(sifter.sections["struct"].Bytes())
	outf.Write(sifter.sections["map"].Bytes())
	outf.Write(sifter.sections["helper"].Bytes())
	outf.Write(sifter.sections["init"].Bytes())
	outf.Write(sifter.sections["level2_tracing"].Bytes())
	outf.Write(sifter.sections["level1_tracing"].Bytes())
	outf.Write(sifter.sections["main"].Bytes())
	outf.Write(sifter.sections["license"].Bytes())
}

func (sifter *Sifter) WriteAgentConfigFile() {
	outf, err := os.Create(sifter.outConfigFile)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()

	s := new(bytes.Buffer)
	fmt.Fprintf(s, "%v %v\n", sifter.outName, 8*sifter.target.PtrSize)

	//fmt.Fprintf(s, "p 1 %v %v\n", sifter.syscallEntry, sifter.syscallEntry)

	for _, m := range sifter.argMaps {
		fmt.Fprintf(s, "m %v %v\n", m.mapType, m.name)
	}
	for _, seq := range sifter.seqArgs {
		fmt.Fprintf(s, "r %v %v_seq_rb\n", sifter.seqLen, seq.name)
	}

	fmt.Fprintf(s, "p 2 raw_syscalls sys_enter\n")

	fmt.Fprintf(s, "l 0 syscall_fd_mask %v\n", len(sifter.syscalls))
	for i, syscall := range sifter.syscalls {
		if i%20 == 0 {
			fmt.Fprintf(s, "        ")
		}
		fmt.Fprintf(s, "%v ", ToFdMask(syscall))
		if i%20 == 19 {
			fmt.Fprintf(s, "\n")
		}
	}
	fmt.Fprintf(s, "\n")

	outf.Write(s.Bytes())
}

func main() {
	var flags Flags
	flag.StringVar(&flags.mode,   "mode", "", "mode (tracer/filter)")
	flag.StringVar(&flags.trace,  "trace", "", "tracing result file")
	flag.StringVar(&flags.config, "config", "", "Syzkaller configuration file")
	flag.StringVar(&flags.fd,     "fd", "", "file descriptor name of the kernel module in Syzkaller")
	flag.StringVar(&flags.dev,    "dev", "", "device file of the kernel module")
//	flag.StringVar(&flags.entry,  "entry", "", "syscall entry function")
	flag.StringVar(&flags.outdir, "outdir", "gen", "output file directory")
	flag.StringVar(&flags.out,    "out", "", "output file base name")
	flag.IntVar(&flags.seqlen,    "seqlen", 4, "syscall sequence length for tracing")
	flag.IntVar(&flags.unroll,    "unroll", 5, "loop unroll times")
	flag.Parse()

	cfg, err := mgrconfig.LoadFile(flags.config)
	if err != nil {
		failf("failed to load config file. err: %v", err)
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		failf("failed to get target %v/%v. err: %v", cfg.TargetOS, cfg.TargetArch, err)
	}

	sifter, err := NewSifter(target, flags)
	if err != nil {
		failf("failed to initialize sifter. err: %v", err)
	}

	sifter.GenerateSource()
	sifter.WriteSourceFile()
	if sifter.mode == TracerMode {
		sifter.WriteAgentConfigFile()
	}
}
