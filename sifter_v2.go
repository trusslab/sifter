package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
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
)

type Flags struct {
	mode    string
	trace   string
	config  string
	fd      string
	dev     string
	entry   string
	outdir  string
	out     string
	unroll  int
	verbose int
}

type Section struct {
	t      int
	buf    *bytes.Buffer
}

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

type Context struct {
	name           string
	syscallNum     string
	syscallArgs    string
	defaultRetType string
	defaultRetVal  string
	errorRetVal    string
}

type Syscall struct {
	name			string
	def				*prog.Syscall
	argMaps			[]*ArgMap
	vlrMaps			[]*VlrMap
	size			uint64
	traceFile		*os.File
	traceReader		*bufio.Reader
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

type TraceEvent struct {
	ts				uint64
	id				uint32
	syscall			*Syscall
	data			[]byte
}

func newTraceEvent(ts uint64, id uint32, syscall *Syscall) *TraceEvent {
	traceEvent := new(TraceEvent)
	traceEvent.ts = ts
	traceEvent.id = id
	traceEvent.syscall = syscall
	if (id & 0x80000000 != 0) {
		traceEvent.data = make([]byte, (id & 0x0000ffff))
	} else {
		traceEvent.data = make([]byte, 48 + syscall.size)
	}
	return traceEvent
}

type Sifter struct {
	mode		    Mode
	verbose         Verbose
	target          *prog.Target
	structs         []*prog.StructType
	syscalls        []*prog.Syscall
	moduleSyscalls  map[string][]*Syscall

	stackVarId      int
	sections        map[string]*bytes.Buffer

	trace			[]*TraceEvent

	analyses		[]analysis

	outName         string
	outSourceFile   string
	outConfigFile   string
	fdName          string
	devName         string
	loopUnroll      int
	depthLimit		int
	ctx             Context
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func isVariant(syscall string) bool {
	return strings.Contains(syscall, "$") || strings.Contains(syscall, "syz_")
}

func newSifter(target *prog.Target, f Flags) (*Sifter, error) {
	sifter := new(Sifter)
	sifter.target = target
	sifter.fdName = f.fd
	sifter.devName = f.dev
	sifter.outName = f.out+"_"+f.mode
	sifter.outSourceFile = filepath.Join(f.outdir, sifter.outName+".c")
	sifter.outConfigFile = filepath.Join(f.outdir, sifter.outName+".cfg")
	sifter.loopUnroll = f.unroll
	sifter.sections = make(map[string]*bytes.Buffer)
	sifter.syscalls = make([]*prog.Syscall, 512)
	sifter.moduleSyscalls = make(map[string][]*Syscall)
	sifter.trace = make([]*TraceEvent, 0)
	sifter.stackVarId = 0
	sifter.depthLimit = math.MaxInt32
	sifter.verbose = Verbose(f.verbose)

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
	} else if f.mode == "analyzer" {
		sifter.mode = AnalyzerMode
		sifter.ctx = Context{
			name: "sys_enter_args",
			syscallNum: "id",
			syscallArgs: "regs",
			defaultRetType: "int",
			defaultRetVal: "0",
			errorRetVal: "1",
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
		//if !strings.Contains(syscall.Name, "$") && !strings.Contains(syscall.Name, "syz_") {
		if !isVariant(syscall.Name) {
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
		for _, arg := range syscall.Args {
			if arg.Name() == sifter.fdName {
				callName := syscall.CallName
				if callName == "ioctl" {
					fmt.Printf("trace syscall %v\n", syscall.Name)
					tracedSyscall := new(Syscall)
					tracedSyscall.name = fixName(syscall.Name)
					tracedSyscall.def = syscall
					tracedSyscall.argMaps = []*ArgMap{}
					sifter.moduleSyscalls[callName] = append(sifter.moduleSyscalls[callName], tracedSyscall)
				} else {
					fmt.Printf("trace syscall %v\n", callName)
					tracedSyscall := new(Syscall)
					tracedSyscall.name = fixName(syscall.Name)
					tracedSyscall.def = sifter.target.SyscallMap[callName]
					tracedSyscall.argMaps = []*ArgMap{}
					sifter.moduleSyscalls[callName] = append(sifter.moduleSyscalls[callName], tracedSyscall)
				}
			}
//			if vma, ok := arg.(*prog.VmaType); ok {
//					fmt.Printf("vma %v %v\n", syscall.Name, vma.FldName)
//			}
//			if vma, ok := arg.(*prog.VmaType); ok && vma.FldName == "addr" {
//				callName := syscall.CallName
//				if !isVariant(syscall.Name) {
//					//fmt.Printf("vma %v\n", syscall.Name)
//					sifter.moduleSyscalls[callName] = append(sifter.moduleSyscalls[callName], sifter.target.SyscallMap[callName])
//				}
//			}
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

func (sifter *Sifter) GenerateCopyFromUser(src string, dst *string, argType string) string {
	var s strings.Builder
	*dst = fmt.Sprintf("v%v", sifter.stackVarId)
	fmt.Fprintf(&s, "%v %v;\n", argType, *dst)
	fmt.Fprintf(&s, "if (bpf_probe_read_sleepable(&%v, sizeof(%v), (void *)%v) < 0)\n", *dst, *dst, src)
	fmt.Fprintf(&s, "    return %v;\n", sifter.ctx.errorRetVal)
	sifter.stackVarId += 1
	return s.String()
}

func (sifter *Sifter) GenerateArgMapLookup(argMap string, argType string) string{
	var s strings.Builder
	fmt.Fprintf(&s, "%v *%v_p = bpf_%v_lookup_elem(&idx);\n", argType, argMap, argMap)
	fmt.Fprintf(&s, "if (!%v_p)\n", argMap)
	fmt.Fprintf(&s, "    return %v;\n", sifter.ctx.errorRetVal)
	return s.String()
}

func indent(s string, indent int) string {
	s = strings.TrimSuffix(s, "\n")
	s = strings.Replace(s, "\n", "\n"+strings.Repeat(" ", 4*indent), -1)
	return s + "\n"
}

func isIgnoredArg(arg prog.Type) bool {
	ret := true
	switch t := arg.(type) {
	case *prog.PtrType:
		ret = false
	case *prog.StructType:
		if !t.IsVarlen {
			ret = false
		}
	case *prog.LenType, *prog.IntType, *prog.ConstType, *prog.FlagsType:
		ret = false
	//case *prog.ArrayType, *prog.VmaType, *prog.UnionType, *prog.BufferType, *prog.ResourceType:
	case *prog.ArrayType:
		ret = false
	case *prog.VmaType, *prog.UnionType, *prog.BufferType, *prog.ResourceType:
	default:
		fmt.Println("Unhandled type", t)
	}
	return ret
}

func argTypeName(arg prog.Type) string {
	name := "Unhandled"
	switch t := arg.(type) {
	case *prog.StructType:
		name = fmt.Sprintf("struct %v", t.Name())
	case *prog.LenType, *prog.IntType, *prog.ConstType, *prog.FlagsType:
		name = fmt.Sprintf("uint%v_t", 8*t.Size())
	}
	return name
}

func typeDebugInfo(arg prog.Type) string {
	debugInfo := ""
	if arg.Varlen() {
		debugInfo = fmt.Sprintf("//arg %v %v %v varlen\n", arg, arg.Name(), arg.FieldName())
	} else {
		debugInfo = fmt.Sprintf("//arg %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size())
	}
	return debugInfo
}

func (sifter *Sifter) GenerateArgTracer(s *bytes.Buffer, syscall *Syscall, arg prog.Type, srcPath string, argName string, dstPath string, depth *int) {
	_, thisIsPtr := arg.(*prog.PtrType);
	if *depth == 0 && !thisIsPtr || *depth >= sifter.depthLimit || isIgnoredArg(arg) {
		return
	}

	fmt.Fprintf(s, "    %v", typeDebugInfo(arg))

	accessOp := ""
	derefOp := ""
	if *depth == 0 {
		argName = argName + "_" + arg.FieldName()
	} else if dstPath == "" {
		// Parent arg is a pointer and the userspace data hasn't been copied to stack
		argType := argTypeName(arg)
		fmt.Fprintf(s, "    %v", indent(sifter.GenerateCopyFromUser(srcPath, &srcPath, argType), 1))
		fmt.Fprintf(s, "    %v", indent(sifter.GenerateArgMapLookup(argName, argType), 1))
		syscall.AddArgMap(arg, argName, srcPath, argType)

		dstPath = argName + "_p"
		derefOp = "*"
		accessOp = "->"
	} else {
		// Parent arg is a struct and the userspace data has been copied to stack
		srcPath = srcPath + "." + arg.FieldName()
		argName = argName + "_" + arg.FieldName()
		dstPath = dstPath + arg.FieldName()
		accessOp = "."
	}

	switch t := arg.(type) {
	case *prog.PtrType:
		if *depth > 0 {
			fmt.Fprintf(s, "    %v%v = %v;\n", derefOp, dstPath, srcPath)
		}
		*depth += 1
		sifter.GenerateArgTracer(s, syscall, t.Type, srcPath, argName, "", depth)
		*depth -= 1
	case *prog.StructType:
		sifter.AddStruct(t)
		for _, field := range t.Fields {
			sifter.GenerateArgTracer(s, syscall, field, srcPath, argName, dstPath+accessOp, depth)
		}
	case *prog.LenType, *prog.IntType, *prog.ConstType, *prog.FlagsType:
		fmt.Fprintf(s, "    %v%v = %v;\n", derefOp, dstPath, srcPath)
	case *prog.ArrayType:
		if isVLR, _, _ := sifter.IsVarLenRecord(t); isVLR {
			syscall.AddVlrMap(t, argName)
		}
		fmt.Fprintf(s, "    vlr %v%v = %v; %v\n", derefOp, dstPath, srcPath, argName)
	}
}

func (sifter *Sifter) GenerateSyscallTracer(syscall *Syscall) {
	s := sifter.GetSection("level2_tracing")
	fmt.Fprintf(s, "%v __always_inline trace_%v(%v *ctx, int pid) {\n", sifter.ctx.defaultRetType, syscall.name, sifter.ctx.name)
	fmt.Fprintf(s, "    int i = 0;\n")
	fmt.Fprintf(s, "    uint32_t *ctr = bpf_%v_ctr_lookup_elem(&i);\n", syscall.name)
	fmt.Fprintf(s, "    if (!ctr)\n")
	fmt.Fprintf(s, "    	return 1;\n")
	fmt.Fprintf(s, "    int idx = *ctr & 0x000003ff;\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "    syscall_ent_t *ent = bpf_%v_ent_lookup_elem(&idx);\n", syscall.name)
	fmt.Fprintf(s, "    if (ent) {\n")
	fmt.Fprintf(s, "    	ent->ts = bpf_ktime_get_ns();\n")
	fmt.Fprintf(s, "    	ent->id = pid;\n")
	fmt.Fprintf(s, "    	ent->args[0] = ctx->regs[0];\n")
	fmt.Fprintf(s, "    	ent->args[1] = ctx->regs[1];\n")
	fmt.Fprintf(s, "    	ent->args[2] = ctx->regs[2];\n")
	fmt.Fprintf(s, "    	ent->args[3] = ctx->regs[3];\n")
	fmt.Fprintf(s, "    	ent->args[4] = ctx->regs[4];\n")
	fmt.Fprintf(s, "    	ent->args[5] = ctx->regs[5];\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    %v ret = %v;\n", sifter.ctx.defaultRetType, sifter.ctx.defaultRetVal)
	for i, arg := range syscall.def.Args {
		path := fmt.Sprintf("ctx->%v[%v]", sifter.ctx.syscallArgs, i)
		offset := 0
		sifter.GenerateArgTracer(s, syscall, arg, path, syscall.name, "", &offset)
	}
	fmt.Fprintf(s, "    *ctr = *ctr + 1;\n")
	fmt.Fprintf(s, "    return ret;\n")
	fmt.Fprintf(s, "}\n\n")
}

func (sifter *Sifter) GenerateIoctlTracer(syscalls []*Syscall) {
	s := sifter.GetSection("level1_tracing")
	fmt.Fprintf(s, "%v __always_inline trace_ioctl(%v *ctx, int pid) {\n", sifter.ctx.defaultRetType, sifter.ctx.name)
	fmt.Fprintf(s, "    %v ret = %v;\n", sifter.ctx.defaultRetType, sifter.ctx.defaultRetVal)
	fmt.Fprintf(s, "    uint64_t ioctl_cmd = ctx->%v[1];\n", sifter.ctx.syscallArgs)
	fmt.Fprintf(s, "    switch (ioctl_cmd) {\n")
	for _, syscall := range syscalls {
		cmd, ok := syscall.def.Args[1].(*prog.ConstType)
		if !ok {
			failf("failed to get const command value for %v", syscall.name)
		}
		if !strings.Contains(syscall.name, "_compact_") {
			sifter.GenerateSyscallTracer(syscall)
			fmt.Fprintf(s, "    case 0x%x:\n", cmd.Val)
			fmt.Fprintf(s, "        ret = trace_%v(ctx, pid);\n", syscall.name)
			fmt.Fprintf(s, "        break;\n")
		}
	}
	fmt.Fprintf(s, "    }\n")
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

func (sifter *Sifter) GenerateProgSection() {
	// Generate syscall tracing logic
	for key, syscalls := range sifter.moduleSyscalls {
		if key == "ioctl" {
			sifter.GenerateIoctlTracer(syscalls)
		} else {
			syscall := syscalls[0]
			if len(syscalls) > 1 {
				fmt.Printf("%v has multiple variants. Only %v is traced!\n", syscall.def.CallName, syscall.name)
			}
			sifter.GenerateSyscallTracer(syscall)
		}
	}

	if sifter.mode == TracerMode {
		s := sifter.GetSection("main")
		fmt.Fprintf(s, "void __always_inline trace_syscalls(sys_enter_args *ctx, int pid) {\n")
		fmt.Fprintf(s, "    int nr = ctx->id;\n")
		fmt.Fprintf(s, "    int fd_is_dev = 0;\n")
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
		fmt.Fprintf(s, "            trace_ioctl(ctx, pid);\n")
		for key, syscalls := range sifter.moduleSyscalls {
			if key != "ioctl" {
				fmt.Fprintf(s, "        } else if (nr == %v) {\n", sifter.SyscallNumber(key))
				fmt.Fprintf(s, "            trace_%v(ctx, pid);\n", syscalls[0].name)
			}
		}
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    return;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "SEC(\"tracepoint/raw_syscalls/sys_enter\")\n")
		fmt.Fprintf(s, "int sys_enter_prog(sys_enter_args *ctx) {\n")
		fmt.Fprintf(s, "    int pid = is_current_pid_traced();\n")
		fmt.Fprintf(s, "    if (pid == 0)\n")
		fmt.Fprintf(s, "        return 0;\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "    trace_syscalls(ctx, pid);\n")
		fmt.Fprintf(s, "    return 0;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "SEC(\"tracepoint/raw_syscalls/sys_exit\")\n")
		fmt.Fprintf(s, "int sys_exit_prog(sys_exit_args *ctx) {\n")
		fmt.Fprintf(s, "	int nr = ctx->id;\n")
		fmt.Fprintf(s, "	uint32_t data = 1;\n")
		fmt.Fprintf(s, "    uint32_t current_pid = get_current_pid();\n")
		fmt.Fprintf(s, "	uint32_t child_pid = ctx->ret;\n")
		fmt.Fprintf(s, "	bool is_32bit = (process_mode() == 32);\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "	if (is_comm_setting_syscall(nr, is_32bit)) {\n")
		fmt.Fprintf(s, "		if (is_current_prog_target()) {\n")
		fmt.Fprintf(s, "			bpf_traced_pid_map_update_elem(&current_pid, &data, BPF_ANY);\n")
		fmt.Fprintf(s, "		}\n")
		fmt.Fprintf(s, "	} else if (is_forking_syscall(nr, is_32bit)) {\n")
		fmt.Fprintf(s, "		if (is_current_pid_traced()) {\n")
		fmt.Fprintf(s, "			bpf_traced_pid_map_update_elem(&child_pid, &data, BPF_ANY);\n")
		fmt.Fprintf(s, "		}\n")
		fmt.Fprintf(s, "	}\n")
		fmt.Fprintf(s, "	return 0;\n")
		fmt.Fprintf(s, "}\n")
//		fmt.Fprintf(s, "\n")
//		fmt.Fprintf(s, "SEC(\"kprobe/do_exit\")\n")
//		fmt.Fprintf(s, "int kprobe_do_exit(struct user_pt_regs *ctx) {\n")
//		fmt.Fprintf(s, "    uint32_t pid = get_current_pid();\n")
//		fmt.Fprintf(s, "    update_syscall_seq(pid, (uint16_t)-1);\n")
//		fmt.Fprintf(s, "    return 0;\n")
//		fmt.Fprintf(s, "}\n")
	}
}

func (sifter *Sifter) GenerateMapSection() {
	s := sifter.GetSection("map")
	fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_fd_mask, ARRAY, int, uint8_t, %v);\n", len(sifter.syscalls))

	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(traced_pid_map, HASH, uint32_t, uint32_t, 128);\n")
		fmt.Fprintf(s, "DEFINE_BPF_MAP(target_prog_comm_map, HASH, comm_string, uint32_t, 128);\n")
		for _, syscalls := range sifter.moduleSyscalls {
			for _, syscall := range syscalls {
				fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_ctr, ARRAY, int, uint32_t, 1)\n", syscall.name)
				fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_ent, ARRAY, int, syscall_ent_t, 1024)\n", syscall.name)
				for _, arg := range syscall.argMaps {
					fmt.Fprintf(s, "DEFINE_BPF_MAP(%v, ARRAY, int, %v, 1024)\n", arg.name, arg.datatype)
				}
			}
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
		fmt.Fprintf(s, "    uint64_t ignore;\n")
		fmt.Fprintf(s, "    int64_t id;\n")
		fmt.Fprintf(s, "    uint64_t ret;\n")
		fmt.Fprintf(s, "} sys_exit_args;\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "typedef struct {\n")
		fmt.Fprintf(s, "	uint64_t ts;\n")
		fmt.Fprintf(s, "	uint32_t id;\n")
		fmt.Fprintf(s, "	uint64_t args[6];\n")
		fmt.Fprintf(s, "} syscall_ent_t;\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "typedef struct {\n")
		fmt.Fprintf(s, "	char chars[16];\n")
		fmt.Fprintf(s, "} comm_string;\n")
		fmt.Fprintf(s, "\n")
	}
}

func (sifter *Sifter) GenerateHelperSection() {
	s := sifter.GetSection("helper")
	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "int __always_inline get_current_pid() {\n")
		fmt.Fprintf(s, "    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();\n")
		fmt.Fprintf(s, "    int pid = current_pid_tgid & 0x00000000ffffffff;\n")
		fmt.Fprintf(s, "    return pid;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "#define TIF_32BIT       22  /* 32bit process */\n")
		fmt.Fprintf(s, "#define _TIF_32BIT      (1 << TIF_32BIT)\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "int __always_inline process_mode() {\n")
		fmt.Fprintf(s, "	uint64_t current = bpf_get_current_task();\n")
		fmt.Fprintf(s, "	uint64_t flags;\n")
		fmt.Fprintf(s, "	int ret = bpf_probe_read(&flags, 8, (void *)current);\n")
		fmt.Fprintf(s, "	if (ret != 0)\n")
		fmt.Fprintf(s, "		return 0;\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "	return (flags & _TIF_32BIT)? 32 : 64;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "bool __always_inline is_current_prog_target() {\n")
		fmt.Fprintf(s, "	comm_string comm = {};\n")
		fmt.Fprintf(s, "	if (bpf_get_current_comm(&comm, 16))\n")
		fmt.Fprintf(s, "		return false;\n")
		fmt.Fprintf(s, "	return (bpf_target_prog_comm_map_lookup_elem(&comm) != NULL);\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "int __always_inline is_current_pid_traced() {\n")
		fmt.Fprintf(s, "    uint32_t current_pid = get_current_pid();\n")
		fmt.Fprintf(s, "    if (bpf_traced_pid_map_lookup_elem(&current_pid) != NULL) {\n")
		fmt.Fprintf(s, "        return current_pid;\n")
		fmt.Fprintf(s, "    } else {\n")
		fmt.Fprintf(s, "        return 0;\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "bool __always_inline is_forking_syscall(int nr, int is_32bit) {\n")
		fmt.Fprintf(s, "	if (is_32bit) {\n")
		fmt.Fprintf(s, "		return (nr == 2 || nr == 120 || nr == 190);\n")
		fmt.Fprintf(s, "	} else {\n")
		fmt.Fprintf(s, "		return (nr == 220);\n")
		fmt.Fprintf(s, "	}\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "bool __always_inline is_comm_setting_syscall(int nr, bool is_32bit) {\n")
		fmt.Fprintf(s, "	if (is_32bit) {\n")
		fmt.Fprintf(s, "		return (nr == 11 || nr == 387);\n")
		fmt.Fprintf(s, "	} else {\n")
		fmt.Fprintf(s, "		return (nr == 167 || nr == 281);\n")
		fmt.Fprintf(s, "	}\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
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
	outf.Write(sifter.sections["level2_tracing"].Bytes())
	outf.Write(sifter.sections["level1_tracing"].Bytes())
	outf.Write(sifter.sections["main"].Bytes())
	outf.Write(sifter.sections["license"].Bytes())
}

type analysis interface {
	String() string
	Init(TracedSyscalls *map[string][]*Syscall)
	ProcessTraceEvent(te *TraceEvent) (string, int)
	PrintResult()
}

type VlrSequenceNode struct {
	next    []*VlrSequenceNode
	record  *VlrRecord
	count   uint64
	events  []*TraceEvent
}

type VlrAnalysis struct {
	vlrSequenceRoot []*VlrSequenceNode
}

func (a VlrAnalysis) String() string {
	return "vlr analysis"
}

func (a *VlrAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			for _, _ = range syscall.vlrMaps {
				a.vlrSequenceRoot = append(a.vlrSequenceRoot, new(VlrSequenceNode))
			}
		}
	}
}

func (a *VlrAnalysis) ProcessTraceEvent(te *TraceEvent) (string, int) {
	if (te.id & 0x80000000) != 0 {
		return "", 0
	}

	if te.syscall.vlrMaps == nil {
		return "", 0
	}

	updateMsg := ""
	updateNum := 0
	for i, vlr := range te.syscall.vlrMaps {
		offset := vlr.offset
		node := a.vlrSequenceRoot[i]
		size := uint64(binary.LittleEndian.Uint32(te.data[48:56]))
		start := uint64(binary.LittleEndian.Uint32(te.data[56:64]))
		offset += start

		for {
			tr := uint64(binary.LittleEndian.Uint32(te.data[48+offset:48+offset+4]))
			var matchedRecord *VlrRecord
			if offset < size {
				for j, record := range vlr.records {
					if tr == record.header {
						matchedRecord = vlr.records[j]
						break
					}
				}
			}

			if matchedRecord != nil {
				updateMsg += matchedRecord.name
			} else {
				updateMsg += "end"
			}
			nextVlrRecordIdx := -1
			for j, nextRecord := range node.next {
				if nextRecord.record == matchedRecord {
					nextVlrRecordIdx = j
					break
				}
			}
			if nextVlrRecordIdx >= 0 {
				node = node.next[nextVlrRecordIdx]
				node.count += 1
			} else {
				newNode := new(VlrSequenceNode)
				newNode.record = matchedRecord
				node.next = append(node.next, newNode)
				node = newNode
				node.count = 1
				updateNum += 1
				updateMsg += "*"
			}
			if matchedRecord != nil {
				updateMsg += "->"
				offset += matchedRecord.size
			} else {
				node.events = append(node.events, te)
				break
			}
		}
	}
	return updateMsg, updateNum
}

func (n *VlrSequenceNode) _Print(depth *int, depthsWithChildren map[int]bool, hasNext bool) {
	*depth = *depth + 1

	s := ""
	if !hasNext {
		depthsWithChildren[*depth] = false
		s += "└"
	} else {
		depthsWithChildren[*depth] = true
		s += "├"
	}

	if n.record == nil {
		if len(n.next) != 0 {
			s += "start"
		} else {
			s += fmt.Sprintf("[%v]end (%v)", *depth, n.count)
		}
	} else {
		s += fmt.Sprintf("[%v]%v", *depth, n.record.name)
	}

	indent := ""
	for i := 1; i < *depth; i++ {
		if depthsWithChildren[i] == true && i != *depth{
			indent += "|   "
		} else {
			indent += "    "
		}
	}
	fmt.Printf("%v%v\n", indent, s)

	for i, next := range n.next {
		next._Print(depth, depthsWithChildren, i != len(n.next)-1)
	}

	*depth = *depth - 1
}

func (n *VlrSequenceNode) Print() {
	depth := 0
	depthsWithOtherChildren := make(map[int]bool)
	n._Print(&depth, depthsWithOtherChildren, false)
}

func (a *VlrAnalysis) PrintResult() {
	for i, _ := range a.vlrSequenceRoot {
		a.vlrSequenceRoot[i].Print()
	}
}

type Node struct {
	syscall *Syscall
}

type Edge struct {
	next *Node
	prevs []*Node
}

type SequenceAnalysis struct {
	seqLen   int
	nodes    []Node
	prevs    []*Node
	seqGraph map[*Node][]*Edge
}

func (a SequenceAnalysis) String() string {
	return "sequence analysis"
}

func (a SequenceAnalysis) edgesEqual(e1 *Edge, e2 *Edge) bool {
	if e1.next != e2.next {
		return false
	}

	for i := 0; i < a.seqLen; i++ {
		if e1.prevs[i] != e2.prevs[i] {
			return false
		}
	}
	return true
}

func (a *SequenceAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.seqGraph = make(map[*Node][]*Edge)
	a.prevs = make([]*Node, a.seqLen+1)
}

func (a *SequenceAnalysis) ProcessTraceEvent(te *TraceEvent) (string, int) {
	if (te.id & 0x80000000) != 0 {
		return "", 0
	}

	updateMsg := ""
	updateNum := 0

	currNode := a.prevs[a.seqLen]
	var nextNode *Node
	for i, node := range a.nodes {
		if te.syscall == node.syscall {
			nextNode = &a.nodes[i]
		}
	}
	if nextNode == nil {
		a.nodes = append(a.nodes, Node{te.syscall})
		nextNode = &a.nodes[len(a.nodes)-1]
		updateMsg += fmt.Sprintf("add n[%v]", te.syscall.name)
		updateNum += 1
	}

	if a.prevs[0] != nil {
		currEdge := new(Edge)
		currEdge.next = nextNode
		currEdge.prevs = a.prevs[0:a.seqLen]
		edgeExisted := false
		if edges, ok := a.seqGraph[currNode]; ok {
			for _, edge := range edges {
				if a.edgesEqual(currEdge, edge) {
					edgeExisted = true
				}
			}
		} else {
			a.seqGraph[currNode] = make([]*Edge, 0)
		}
		if !edgeExisted {
			a.seqGraph[currNode] = append(a.seqGraph[currNode], currEdge)
			updateMsg += fmt.Sprintf("add e:n[%v]->n[%v] prevs(", currNode.syscall.name, nextNode.syscall.name)
			for _, n := range currEdge.prevs {
				updateMsg += fmt.Sprintf("%v->", n.syscall.name)
			}
			updateMsg += fmt.Sprintf(")")
			updateNum += 1
		}
	}

	a.prevs = a.prevs[1:]
	a.prevs = append(a.prevs, nextNode)
	return updateMsg, updateNum
}

func (a *SequenceAnalysis) PrintResult() {
	for node, edges := range a.seqGraph {
		fmt.Printf("%v\n", node.syscall.name)
		for _, edge := range edges {
			fmt.Printf("  ->%v (", edge.next.syscall.name)
			for i, prevNode := range edge.prevs {
				fmt.Printf("%v", prevNode.syscall.name)
				if i != len(edge.prevs)-1 {
					fmt.Printf(", ")
				}
			}
			fmt.Printf(")\n")
		}
	}
}

func (sifter *Sifter) IsVarLenRecord(arg *prog.ArrayType) (bool, int, []uint64) {
	headerSize := -1
	headers := []uint64{}
	unions, ok := arg.Type.(*prog.UnionType)
	if !ok {
		goto isNotVLR
	}

	for _, t := range unions.Fields {
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

type ValueRangeAnalysis struct {
	argRanges map[*ArgMap][]uint64
	regRanges map[*Syscall][]uint64
	vlrRanges map[*VlrMap]map[*VlrRecord][]uint64
}

func (a *ValueRangeAnalysis) String() string {
	return "value range analysis"
}

func (a *ValueRangeAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argRanges = make(map[*ArgMap][]uint64)
	a.regRanges = make(map[*Syscall][]uint64)
	a.vlrRanges = make(map[*VlrMap]map[*VlrRecord][]uint64)
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			for i := 0; i < 6; i++ {
				a.regRanges[syscall] = append(a.regRanges[syscall], math.MaxInt64)
				a.regRanges[syscall] = append(a.regRanges[syscall], 0)
			}
			for _, arg := range syscall.argMaps {
				if structArg, ok := arg.arg.(*prog.StructType); ok {
					for _, _ = range structArg.Fields {
						a.argRanges[arg] = append(a.argRanges[arg], math.MaxInt64)
						a.argRanges[arg] = append(a.argRanges[arg], 0)
					}
				} else {
					a.argRanges[arg] = append(a.argRanges[arg], math.MaxInt64)
					a.argRanges[arg] = append(a.argRanges[arg], 0)
				}
			}
			for _, vlr := range syscall.vlrMaps {
				a.vlrRanges[vlr] = make(map[*VlrRecord][]uint64)
				for _, record := range vlr.records {
					if structArg, ok := record.arg.(*prog.StructType); ok {
						for _, f := range structArg.Fields {
							if structField, ok := f.(*prog.StructType); ok {
								for _, _ = range structField.Fields {
									a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], math.MaxInt64)
									a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], 0)
								}
							} else {
								a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], math.MaxInt64)
								a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], 0)
							}
						}
					}
				}
			}
		}
	}
}

func (a *ValueRangeAnalysis) ProcessTraceEvent(te *TraceEvent) (string, int) {
	if (te.id & 0x80000000) != 0 {
		return "", 0
	}

	msgs := make([]string, 0)
	var offset uint64
	for i := 0; i < 6; i++ {
		tr := binary.LittleEndian.Uint64(te.data[offset:offset+8])
		if (a.regRanges[te.syscall][i*2+0] > tr) {
			a.regRanges[te.syscall][i*2+0] = tr
			msgs = append(msgs, fmt.Sprintf("reg[%v]:l %x", i, tr))
		}
		if (a.regRanges[te.syscall][i*2+1] < tr) {
			a.regRanges[te.syscall][i*2+1] = tr
			msgs = append(msgs, fmt.Sprintf("reg[%v]:u %x", i, tr))
		}
		offset += 8
	}
	for _, arg := range te.syscall.argMaps {
		if structArg, ok := arg.arg.(*prog.StructType); ok {
			for i, field := range structArg.Fields {
				if _, isPtrArg := field.(*prog.PtrType); !isPtrArg {
					tr := binary.LittleEndian.Uint64(te.data[offset:offset+field.Size()])
					if (a.argRanges[arg][2*i+0] > tr) {
						a.argRanges[arg][2*i+0] = tr
						msgs = append(msgs, fmt.Sprintf("%v:l %x", arg.name, tr))
					}
					if (a.argRanges[arg][2*i+1] < tr) {
						a.argRanges[arg][2*i+1] = tr
						msgs = append(msgs, fmt.Sprintf("%v:u %x", arg.name, tr))
					}
				}
				offset += field.Size()
			}
		} else {
			if _, isPtrArg := arg.arg.(*prog.PtrType); !isPtrArg {
				tr := binary.LittleEndian.Uint64(te.data[offset:offset+arg.size])
				if (a.argRanges[arg][0] > tr) {
					a.argRanges[arg][0] = tr
					msgs = append(msgs, fmt.Sprintf("%v:l %x", arg.name, tr))
				}
				if (a.argRanges[arg][1] < tr) {
					a.argRanges[arg][1] = tr
					msgs = append(msgs, fmt.Sprintf("%v:u %x", arg.name, tr))
				}
			}
			offset += arg.size
		}
	}
	for _, vlr := range te.syscall.vlrMaps {
		size := uint64(binary.LittleEndian.Uint32(te.data[48:56]))
		start := uint64(binary.LittleEndian.Uint32(te.data[56:64]))
		offset += start
		for {
			tr := uint64(binary.LittleEndian.Uint32(te.data[offset:offset+4]))
			var matchedRecord *VlrRecord
			if offset < size {
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
				for i, field := range structArg.Fields {
					if _, isPtrArg := field.(*prog.PtrType); !isPtrArg {
						if (field.Size() == 4) {
							tr = uint64(binary.LittleEndian.Uint32(te.data[offset:offset+field.Size()]))
						} else {
							tr = binary.LittleEndian.Uint64(te.data[offset:offset+field.Size()])
						}
						if (a.vlrRanges[vlr][matchedRecord][2*i+0] > tr) {
							a.vlrRanges[vlr][matchedRecord][2*i+0] = tr
							msgs = append(msgs, fmt.Sprintf("%v_%v:l [%v]:%x", matchedRecord.name, field.FieldName(), offset, tr))
						}
						if (a.vlrRanges[vlr][matchedRecord][2*i+1] < tr) {
							a.vlrRanges[vlr][matchedRecord][2*i+1] = tr
							msgs = append(msgs, fmt.Sprintf("%v_%v:u [%v]:%x", matchedRecord.name, field.FieldName(), offset, tr))
						}
					}
					offset += field.Size()
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

func (a *ValueRangeAnalysis) PrintResult() {
	for syscall, regRange := range a.regRanges {
		fmt.Printf("\n%v\n", syscall.name)
		for i := 0; i < 6; i++ {
			fmt.Printf("reg[%v] %v\n", i, regRange[i*2:i*2+2])
		}
		for _, arg := range syscall.argMaps {
			fmt.Printf("%v %v\n", arg.name, a.argRanges[arg])
		}
		for _, vlr := range syscall.vlrMaps {
			fmt.Printf("\n%v %v\n", vlr.name, len(vlr.records))
			for _, record := range vlr.records {
				fmt.Printf("%v %v\n", record.name, a.vlrRanges[vlr][record])
			}
		}
	}
}

func (sifter *Sifter) DoAnalyses() int {

	lastUpdatedTeIdx := 0
	updatedTeNum := 0
	for i, te := range sifter.trace {
		hasUpdate := false
		updateMsg := ""
		for _, analysis := range sifter.analyses {
			if msg, update := analysis.ProcessTraceEvent(te); update > 0 {
				updateMsg += fmt.Sprintf("  ├ %v: %v\n", analysis, msg)
				hasUpdate = true
				updatedTeNum += 1
			}
		}
		if sifter.verbose >= UpdateV {
			if hasUpdate && sifter.verbose >= UpdateV {
				timeElapsed := te.ts - sifter.trace[lastUpdatedTeIdx].ts
				fmt.Printf("  | %v events / %v.%09d sec elapsed\n", i-lastUpdatedTeIdx, timeElapsed/1000000000, timeElapsed%1000000000)
				fmt.Printf("[%v.%09d] %x %d\n", te.ts/1000000000, te.ts%1000000000, te.id, updatedTeNum)
				fmt.Printf("%v", updateMsg)
				fmt.Printf("  ├ % x\n", te.data)
				lastUpdatedTeIdx = i
			}
			if i == len(sifter.trace)-1 {
				fmt.Printf("[%v.%09d] %x end\n", te.ts/1000000000, te.ts%1000000000, te.id)
			}
		}
	}

	if sifter.verbose >= ResultV {
		for _, analysis := range sifter.analyses {
			fmt.Printf("----------------------------------------------------------------\n")
			fmt.Printf("%v result:\n", analysis)
			analysis.PrintResult()
		}
	}
	return updatedTeNum
}

func (sifter *Sifter) ReadSyscallTrace(dirPath string) {
	for _, syscalls := range sifter.moduleSyscalls {
		for _, syscall := range syscalls {
			fileName := fmt.Sprintf("%v/raw_trace_%v.dat", dirPath, syscall.name)
			file, err := os.Open(fileName)
			if err != nil {
				failf("failed to open trace file: %v", fileName)
			}

			syscall.traceFile = file
			syscall.traceReader = bufio.NewReader(file)
		}
	}
	for _, syscalls := range sifter.moduleSyscalls {
		for _, syscall := range syscalls {
			for {
				var ts uint64
				var id uint32
				err := binary.Read(syscall.traceReader, binary.LittleEndian, &ts)
				err = binary.Read(syscall.traceReader, binary.LittleEndian, &id)
				traceEvent := newTraceEvent(ts, id, syscall)
				_, err = io.ReadFull(syscall.traceReader, traceEvent.data)

				if err != nil {
					if err.Error() != "EOF" {
						fmt.Printf("trace, %v, ended unexpectedly: %v\n", syscall.name, err)
					}
					break;
				}

				sifter.trace = append(sifter.trace, traceEvent)
			}
		}
	}
	sort.Slice(sifter.trace, func(i, j int) bool {
		return sifter.trace[i].ts < sifter.trace[j].ts
	})
}

func (sifter *Sifter) WriteAgentConfigFile() {
	outf, err := os.Create(sifter.outConfigFile)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()

	s := new(bytes.Buffer)
	fmt.Fprintf(s, "%v %v\n", sifter.outName, 8*sifter.target.PtrSize)

	for _, syscalls := range sifter.moduleSyscalls {
		for _, syscall := range syscalls {
			fmt.Fprintf(s, "s %v %v", len(syscall.argMaps)+1, syscall.name)
			fmt.Fprintf(s, " 60 %v_ent", syscall.name)
			for _, arg := range syscall.argMaps {
				fmt.Fprintf(s, " %v %v", arg.size, arg.name)
			}
			fmt.Fprintf(s, "\n")
		}
	}

	fmt.Fprintf(s, "p 2 raw_syscalls sys_enter\n")
	fmt.Fprintf(s, "p 2 raw_syscalls sys_exit\n")

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

func Subsets(set []int, num int) [][]int {
	subsets := make([][]int, 0)
	if num != 0 {
		for i := 0; i <= len(set)-num; i++ {
			elementSubset := []int{set[i]}
			subSubsets := Subsets(set[i+1:], num-1)
			if len(subSubsets) != 0 {
				for _, subSubset := range subSubsets {
					newSubset := append(elementSubset, subSubset...)
					subsets = append(subsets, newSubset)
				}
			} else {
				subsets = append(subsets, elementSubset)
			}
		}
	}
	return subsets
}

func main() {
	var flags Flags
	flag.StringVar(&flags.mode,   "mode", "", "mode (tracer/filter)")
	flag.StringVar(&flags.trace,  "trace", "", "tracing result file")
	flag.StringVar(&flags.config, "config", "", "Syzkaller configuration file")
	flag.StringVar(&flags.fd,     "fd", "", "file descriptor name of the kernel module in Syzkaller")
	flag.StringVar(&flags.dev,    "dev", "", "device file of the kernel module")
	flag.StringVar(&flags.outdir, "outdir", "gen", "output file directory")
	flag.StringVar(&flags.out,    "out", "", "output file base name")
	flag.IntVar(&flags.unroll,    "unroll", 5, "loop unroll times")
	flag.IntVar(&flags.verbose,   "v", 0, "verbosity")
	flag.Parse()

	cfg, err := mgrconfig.LoadFile(flags.config)
	if err != nil {
		failf("failed to load config file. err: %v", err)
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		failf("failed to get target %v/%v. err: %v", cfg.TargetOS, cfg.TargetArch, err)
	}

	sifter, err := newSifter(target, flags)
	if err != nil {
		failf("failed to initialize sifter. err: %v", err)
	}

	sifter.GenerateSource()
	if sifter.mode == TracerMode {
		sifter.WriteSourceFile()
		sifter.WriteAgentConfigFile()
	} else if sifter.mode == AnalyzerMode {
		traceDir := "./trace"
		traceFiles, err := ioutil.ReadDir(traceDir)
		if err != nil {
			failf("failed to open trace directory %v", traceDir)
		}

		traceFileNum := len(traceFiles)
		iter := 10
		ratio := 0.9
		trainingFileNum := int(float64(traceFileNum) * ratio)
		testingFileNum := traceFileNum - trainingFileNum
		set := make([]int, traceFileNum)
		for i := 0; i < traceFileNum; i++ {
			set[i] = i
		}
		testingFileIdxSets := Subsets(set, testingFileNum)

		testingUpdateSum := 0
		testingUpdates := make([]int, iter)
		trainingUpdates := make([]int, iter)
		for i := 0; i < iter; i ++ {
			r := rand.Int31n(int32(len(testingFileIdxSets)))
			sifter.analyses = nil
			sifter.trace = nil
			var vra ValueRangeAnalysis
			var sa SequenceAnalysis
			var vlra VlrAnalysis
			sa.seqLen = 4

			sifter.analyses = append(sifter.analyses, &vra)
			sifter.analyses = append(sifter.analyses, &sa)
			sifter.analyses = append(sifter.analyses, &vlra)

			for _, analysis := range sifter.analyses {
				analysis.Init(&sifter.moduleSyscalls)
			}

			testingFiles := make([]os.FileInfo, 0)
			trainingFiles := make([]os.FileInfo, 0)
			for j := 0; j < traceFileNum; j++ {
				isTestingFileIdx := false
				for k := 0; k < testingFileNum; k++ {
					if j == testingFileIdxSets[r][k] {
						isTestingFileIdx = true
					}
				}

				if isTestingFileIdx {
					testingFiles = append(testingFiles, traceFiles[j])
				} else {
					trainingFiles = append(trainingFiles, traceFiles[j])
				}
			}

			for _, file := range trainingFiles {
				sifter.ReadSyscallTrace(traceDir+"/"+file.Name())
				trainingUpdates[i] += sifter.DoAnalyses()
			}
			fmt.Printf("#trainging updates: %v\n", trainingUpdates[i])

			for _, file := range testingFiles {
				sifter.ReadSyscallTrace(traceDir+"/"+file.Name())
				testingUpdates[i] += sifter.DoAnalyses()
			}
			testingUpdateSum +=	testingUpdates[i]
			fmt.Printf("#testing updates: %v\n", testingUpdates[i])
		}
		fmt.Printf("#Avg testing error: %v\n", testingUpdateSum/iter)

	}
}
