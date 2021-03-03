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
}

type Section struct {
	t      int
	buf    *bytes.Buffer
}

type ArgMap struct {
	mapType  int
	name     string
	datatype string
}

type Sifter struct {
	mode		    Mode
	target          *prog.Target
	logFile         *os.File
	scanner         *bufio.Scanner
	seqPolicy	    map[uint16]map[uint16]bool
	seqIdSyscallMap map[uint16]uint32
	seqKeys         []uint16
	v               int
	sections        []*bytes.Buffer
	argMaps         []*ArgMap
	structs         []*prog.StructType
	outName         string
	outSourceFile   string
	outConfigFile   string
	syscallEntry    string
	fdName          string
	devName         string
	seqLen          int
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
	sifter.syscallEntry = f.entry
	sifter.outName = f.out+"_"+f.mode
	sifter.outSourceFile = filepath.Join(f.outdir, sifter.outName+".c")
	sifter.outConfigFile = filepath.Join(f.outdir, sifter.outName+".cfg")
	sifter.seqLen = f.seqlen
	if f.mode == "tracer" {
		sifter.mode = TracerMode
	} else if f.mode == "filter" {
		sifter.mode = FilterMode

		file, err := os.Open(f.trace)
		if err != nil {
			failf("failed to load trace file. err: %v", err)
		}
		sifter.logFile = file;
		sifter.scanner = bufio.NewScanner(file)

		sifter.scanner.Scan()
		if err != nil {
			failf("failed to load config file. err: %v", err)
		}
		mapsHeader := strings.Fields(sifter.scanner.Text())
		if (mapsHeader[0] != "m") {
			failf("failed to parse trace file. expected 'm'")
		}
	} else {
		failf("invalid mode. expected \"tracer\"/\"filter\"")
	}

	_, err := os.Stat(f.outdir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(f.outdir, 0755)
		if err != nil {
			failf("failed to create output dir %v", f.outdir)
		}
	}

	sifter.lazyInit()
	return sifter, nil
}

func (sifter *Sifter) lazyInit() {
	sifter.sections = []*bytes.Buffer{}
	sifter.argMaps = []*ArgMap{}
	sifter.seqPolicy = make(map[uint16]map[uint16]bool)
	sifter.seqIdSyscallMap = make(map[uint16]uint32)
	sifter.v = 0
}

func (sifter *Sifter) NewSection() *bytes.Buffer {
	s := new(bytes.Buffer)
	sifter.sections = append([]*bytes.Buffer{s}, sifter.sections...)
	return s
}

func fixName(name string) string {
	fixChar := []string{".", "$", "-", ">", "[", "]"}
	for _, char := range fixChar {
		name = strings.Replace(name, char, "_", -1)
	}
	return name
}

func (sifter *Sifter) NewArgMap(name string, dataType string, mapType int) {
	name = fixName(name)
	newArgMap := &ArgMap{
		name:name,
		datatype: dataType,
		mapType: mapType,
	}
	sifter.argMaps = append(sifter.argMaps, newArgMap)
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

func (sifter *Sifter) GenerateCheckArg(s *bytes.Buffer, argType string, argName string, argMap string, mapType int) {
	sifter.scanner.Scan()
	if err := sifter.scanner.Err(); err != nil {
		failf("failed to parse trace file. err: %v", err)
	}
	mapEntry := strings.Fields(sifter.scanner.Text())
	if len(mapEntry) != 2 {
		failf("failed to parse trace file. expected 2 entries.")
	}

	if mapType == 0 {
//		fmt.Println("m0 ", sifter.scanner.Text())
		min, _ := strconv.ParseInt(mapEntry[0], 10, 64)
		max, _ := strconv.ParseInt(mapEntry[1], 10, 64)

		if max > math.MaxInt32 {
			fmt.Printf("%v max %v overflows uint32_t\n", argName, max)
			fmt.Fprintf(s, "    //check_arg_range(%v, %v, %v);\n", argName, min, max)
		} else {
			fmt.Fprintf(s, "    check_arg_range(%v, %v, %v);\n", argName, min, max)
		}

	}
	if mapType == 1 {
//		fmt.Println("m1 ", sifter.scanner.Text())
		zeros, _ := strconv.ParseInt(mapEntry[0], 10, 64)
		ones, _ := strconv.ParseInt(mapEntry[1], 10, 64)

		fmt.Fprintf(s, "    check_arg_bits(%v, %v, %v);\n", argName, zeros, ones)
	}
}

func GenerateUpdateArg(s *bytes.Buffer, argType string, argName string, argMap string, mapType int) {
	if mapType == 0 {
		fmt.Fprintf(s, "    {\n")
		fmt.Fprintf(s, "    int i = 0;\n")
		fmt.Fprintf(s, "    %v *%v_min = bpf_%v_lookup_elem(&i);\n", argType, argMap, argMap)
		fmt.Fprintf(s, "    if (%v_min) {\n", argMap)
		fmt.Fprintf(s, "        if (%v < *%v_min)\n", argName, argMap)
		fmt.Fprintf(s, "            *%v_min = %v;\n", argMap, argName)
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    i = 1;\n")
		fmt.Fprintf(s, "    %v *%v_max = bpf_%v_lookup_elem(&i);\n", argType, argMap, argMap)
		fmt.Fprintf(s, "    if (%v_max) {\n", argMap)
		fmt.Fprintf(s, "        if (%v > *%v_max)\n", argName, argMap)
		fmt.Fprintf(s, "            *%v_max = %v;\n", argMap, argName)
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    }\n")
	}
	if mapType == 1 {
		fmt.Fprintf(s, "    {\n")
		fmt.Fprintf(s, "    int i = 0;\n")
		fmt.Fprintf(s, "    %v *%v_zeros = bpf_%v_lookup_elem(&i);\n", argType, argMap, argMap)
		fmt.Fprintf(s, "    if (%v_zeros) {\n", argMap)
		fmt.Fprintf(s, "        *%v_zeros |= ~%v;\n", argMap, argName)
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    i = 1;\n")
		fmt.Fprintf(s, "    %v *%v_ones = bpf_%v_lookup_elem(&i);\n", argType, argMap, argMap)
		fmt.Fprintf(s, "    if (%v_ones) {\n", argMap)
		fmt.Fprintf(s, "        *%v_ones |= %v;\n", argMap, argName)
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    }\n")
	}
}

func GenerateCopyFromUser(sifter *Sifter, s *bytes.Buffer, path string, argType string, argName string) {
	argName = fmt.Sprintf("v%v", sifter.v)
	fmt.Fprintf(s, "    %v %v;\n", argType, argName)
	fmt.Fprintf(s, "    bpf_probe_read_sleepable(&%v, sizeof(%v), (void *)%v);\n", argName, argName, path)
	sifter.v += 1
}

func GenerateRecursiveTracer(sifter *Sifter, arg prog.Type, s *bytes.Buffer, path string, fromPointer bool, depth *int) {
	argType := ""
	switch tt := arg.(type) {
	case *prog.BufferType:
		fmt.Fprintf(s, "    //arg %v %v %v\n", arg, arg.Name(), arg.FieldName())
	case *prog.ArrayType:
		if arg.(*prog.ArrayType).IsVarlen {
			fmt.Fprintf(s, "    //arg %v %v %v varlen\n", arg, arg.Name(), arg.FieldName())
		} else {
			fmt.Fprintf(s, "    //arg %v %v %v\n", arg, arg.Name(), arg.FieldName())
		}
	case *prog.StructType:
		if arg.(*prog.StructType).IsVarlen {
			fmt.Fprintf(s, "    //arg %v %v %v varlen %v\n", arg, arg.Name(), arg.FieldName(), tt)
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
		GenerateRecursiveTracer(sifter, arg.(*prog.PtrType).Type, s, path, true, depth)
		*depth -= 1
	case *prog.StructType:
		structPath := ""
		if fromPointer {
			structPath = fmt.Sprintf("v%v", sifter.v)
			GenerateCopyFromUser(sifter, s, path, argType, structPath)
		} else {
			structPath = path + "." + arg.FieldName()
		}

		sifter.AddStruct(arg.(*prog.StructType))
		for _, field := range arg.(*prog.StructType).StructDesc.Fields {
			GenerateRecursiveTracer(sifter, field, s, structPath, false, depth)
		}
	case *prog.LenType, *prog.IntType, *prog.ConstType:
		if c, ok := t.(*prog.ConstType); ok && c.IsPad {
			break
		}

		argName := ""
		if fromPointer {
			argName = fmt.Sprintf("v%v", sifter.v)
			GenerateCopyFromUser(sifter, s, path, argType, argName)
		} else if *depth == 0 {
			argName = path
		} else {
			argName = path + "." + arg.FieldName()
		}

		sifter.NewArgMap(argName, argType, 0)
		if (sifter.mode == TracerMode) {
			GenerateUpdateArg(s, argType, argName, fixName(argName), 0)
		} else if (sifter.mode == FilterMode){
			sifter.GenerateCheckArg(s, argType, argName, fixName(argName), 0)
		}
	case *prog.FlagsType:
		argName := ""
		if fromPointer {
			argName = fmt.Sprintf("v%v", sifter.v)
			GenerateCopyFromUser(sifter, s, path, argType, argName)
		} else if *depth == 0 {
			argName = path
		} else {
			argName = path + "." + arg.FieldName()
		}

		sifter.NewArgMap(argName, argType, 1)
		if (sifter.mode == TracerMode) {
			GenerateUpdateArg(s, argType, argName, fixName(argName), 1)
		} else if (sifter.mode == FilterMode){
			sifter.GenerateCheckArg(s, argType, argName, fixName(argName), 1)
		}
	case *prog.VmaType:
	case *prog.UnionType:
	case *prog.ArrayType:
	case *prog.BufferType:
	case *prog.ResourceType:
	default:
		fmt.Println("Unhandled type", t)
	}

}

func (sifter *Sifter) GenerateSyscallTracer(name string, syscall *prog.Syscall) {
	s := sifter.NewSection()
	fmt.Fprintf(s, "void __always_inline %v(sys_enter_args *arg) {\n", name)
	for i, arg := range syscall.Args {
		path := fmt.Sprintf("arg->regs[%v]", i)
		offset := 0
		GenerateRecursiveTracer(sifter, arg, s, path, false, &offset)
	}
	fmt.Fprintf(s, "}\n\n")
}

func (sifter *Sifter) GenerateIoctlTracer(name string, syscall *prog.Syscall) {
	s := sifter.NewSection()
	fmt.Fprintf(s, "void __always_inline %v(struct user_pt_regs *ctx) {\n", name)
	path := "ctx->regs[2]"
	offset := 0
	GenerateRecursiveTracer(sifter, syscall.Args[2], s, path, true, &offset)
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

func (sifter *Sifter) GenerateProgSection() {
	// Find out device associated syscalls to be traced
	tracedSyscalls := map[string][]string{}
	for _, syscall := range sifter.target.Syscalls {
		// Find out path of driver
		if len(sifter.devName) == 0  && syscall.CallName == "syz_open_dev" {
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
				tracedSyscalls[syscall.CallName] = append(tracedSyscalls[syscall.CallName], syscall.Name)
			}
		}
	}

	if len(sifter.devName) == 0 {
		failf("cannot find dev for %v", sifter.fdName)
	} else {
		fmt.Printf("trace syscall using dev: %v\n", sifter.devName)
	}

	if sifter.mode == TracerMode {
	//TODO move ioctl tracers under tracepoint
	// generate sequence sifter
	s := sifter.NewSection()
	fmt.Fprintf(s, "#define IOC_NR(cmd) (cmd & ((1 << 8)-1))\n")
	fmt.Fprintf(s, "uint16_t __always_inline arg_to_id(sys_enter_args *arg) {\n")
	fmt.Fprintf(s, "    int nr = arg->id;\n")
	fmt.Fprintf(s, "    int fd_is_dev = 0;\n")
	fmt.Fprintf(s, "    uint16_t id = 0xffff;\n")
	fmt.Fprintf(s, "    char dev [] = \"%v\";\n", sifter.devName)
	fmt.Fprintf(s, "    uint8_t *fd_mask = bpf_syscall_fd_mask_lookup_elem(&nr);\n")
	fmt.Fprintf(s, "    if (fd_mask) {\n")
	fmt.Fprintf(s, "        for (int i = 0; i < 5; i++) {\n")
	fmt.Fprintf(s, "            if ((*fd_mask >> i) & 0x01 &&\n")
	fmt.Fprintf(s, "                (bpf_check_fd(dev, arg->regs[i]))) {\n")
	fmt.Fprintf(s, "                fd_is_dev = 1;\n")
	fmt.Fprintf(s, "                break;\n")
	fmt.Fprintf(s, "            }\n")
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    if (fd_is_dev) {\n")
	fmt.Fprintf(s, "        if (nr == %v) {\n", sifter.SyscallNumber("ioctl"))
	fmt.Fprintf(s, "            id = 0x8000 | IOC_NR(arg->regs[1]);\n")
	for key, _ := range tracedSyscalls {
		if key != "ioctl" {
			fmt.Fprintf(s, "        } else if (nr == %v) {\n", sifter.SyscallNumber(key))
			fmt.Fprintf(s, "            id = nr;\n")
			fmt.Fprintf(s, "            trace_%v(arg);\n", key)
		}
	}
	fmt.Fprintf(s, "        } else {\n")
	fmt.Fprintf(s, "            id = nr;\n")
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    return id;\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "void __always_inline update_syscall_seq(int pid, uint16_t id) {\n")
	fmt.Fprintf(s, "    seq_rb_elem *rb = bpf_syscall_seq_rb_lookup_elem(&pid);\n")
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
	fmt.Fprintf(s, "        uint8_t *ctr = bpf_syscall_seq_rb_ctr_lookup_elem(&pid);\n")
	fmt.Fprintf(s, "        if (ctr && (next == 0 || next == 128 || id == (uint16_t)-1)) {\n")
	fmt.Fprintf(s, "            *ctr += 1;\n")
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline get_current_pid() {\n")
	fmt.Fprintf(s, "    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();\n")
	fmt.Fprintf(s, "    int pid = current_pid_tgid >> 32;\n")
	fmt.Fprintf(s, "    return pid;\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "SEC(\"tracepoint/raw_syscalls/sys_enter\")\n")
	fmt.Fprintf(s, "int sys_enter_prog(sys_enter_args *arg) {\n")
	fmt.Fprintf(s, "    uint16_t id = arg_to_id(arg);\n")
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

	// Generate tracing code
	for key, syscall := range tracedSyscalls {
		if key == "ioctl" {
			s := sifter.NewSection()
			fmt.Fprintf(s, "SEC(\"kprobe/%v\")\n", sifter.syscallEntry)
			fmt.Fprintf(s, "int kprobe_%v(struct user_pt_regs *ctx) {\n", sifter.syscallEntry)
			fmt.Fprintf(s, "    uint64_t ioctl_cmd = ctx->regs[1];\n")
			fmt.Fprintf(s, "    switch (ioctl_cmd) {\n")
			for _, commands := range syscall {
				cmd, ok := sifter.target.SyscallMap[commands].Args[1].(*prog.ConstType)
				if !ok {
					failf("failed to get const command value for %v", commands)
				}
				if !strings.Contains(commands, "_compact_") {
					traceFuncName := fmt.Sprintf("trace_ioctl_0x%x", cmd.Val)
					sifter.GenerateIoctlTracer(traceFuncName, sifter.target.SyscallMap[commands])
					fmt.Fprintf(s, "    case 0x%x: //%v\n", cmd.Val, commands)
					fmt.Fprintf(s, "        %v(ctx);\n", traceFuncName)
					fmt.Fprintf(s, "        break;\n")
				}
			}
			fmt.Fprintf(s, "    }\n")
			fmt.Fprintf(s, "    return 0;\n")
			fmt.Fprintf(s, "}\n\n")
		} else {
			traceFuncName := "trace_" + key
			sifter.GenerateSyscallTracer(traceFuncName, sifter.target.SyscallMap[key])
		}
	}
	} else if sifter.mode == FilterMode {
	s := sifter.NewSection()
	fmt.Fprintf(s, "void __always_inline init_syscall_fd_mask_array()\n")
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    uint8_t syscall_fd_mask_ary[292] = {\n")
	fmt.Fprintf(s, "        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 4, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0,\n")
	fmt.Fprintf(s, "        0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0,\n")
	fmt.Fprintf(s, "        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 0, 0, 1, 1, 5, 3, 1, 1,\n")
	fmt.Fprintf(s, "        1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 0, 16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 0, 0, 8, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,\n")
	fmt.Fprintf(s, "        0, 1, 0, 0, 0, 5, 1, 1, 0, 0, 0, 1\n")
	fmt.Fprintf(s, "    };\n")
	fmt.Fprintf(s, "    #pragma unroll\n")
	fmt.Fprintf(s, "    for (int i = 0; i < 292; i++) {\n")
	fmt.Fprintf(s, "        int j = i; // to make loop unrolling work\n")
	fmt.Fprintf(s, "        bpf_syscall_fd_mask_update_elem(&j, &syscall_fd_mask_ary[i], BPF_ANY);\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline check_syscall_fd(struct seccomp_data *ctx)\n")
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int fd_is_dev = 0;\n")
	fmt.Fprintf(s, "    int syscall_nr = ctx->nr;\n")
	fmt.Fprintf(s, "    uint8_t *fd_mask = bpf_syscall_fd_mask_lookup_elem(&syscall_nr);\n")
	fmt.Fprintf(s, "    if (fd_mask) {\n")
	fmt.Fprintf(s, "        char dev [] = \"kgsl-3d0\";\n")
	fmt.Fprintf(s, "        #pragma unroll\n")
	fmt.Fprintf(s, "        for (int i = 0; i < 5; i++) {\n")
	fmt.Fprintf(s, "            if ((*fd_mask >> i) & 0x01 && \n")
	fmt.Fprintf(s, "                (bpf_check_fd(dev, ctx->args[i]))) {\n")
	fmt.Fprintf(s, "                fd_is_dev = 1;\n")
	fmt.Fprintf(s, "                break;\n")
	fmt.Fprintf(s, "            }\n")
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    return fd_is_dev;\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline check_dev_path(char *path)\n")
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    char dev_path[] = \"/dev/kgsl-3d0\";\n")
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
	fmt.Fprintf(s, "            init_syscall_fd_mask_array();\n")
	fmt.Fprintf(s, "            init_syscall_id_map();\n")
	fmt.Fprintf(s, "            init_id_seq_1_map();\n")
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    return;\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "uint8_t __always_inline next_syscall_id(struct seccomp_data *ctx)\n")
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    uint64_t next_syscall = 0;\n")
	fmt.Fprintf(s, "    if (ctx->nr == __NR_ioctl)\n")
	fmt.Fprintf(s, "        next_syscall = ctx->args[1];\n")
	fmt.Fprintf(s, "    else\n")
	fmt.Fprintf(s, "        next_syscall = ctx->nr;\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "    uint8_t *next_id = bpf_syscall_id_map_lookup_elem(&next_syscall);\n")
	fmt.Fprintf(s, "    if (next_id) {\n")
	fmt.Fprintf(s, "        return *next_id;\n")
	fmt.Fprintf(s, "    } else {\n")
	fmt.Fprintf(s, "        return 255;\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline get_syscall_seq_1()\n")
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int i = 0;\n")
	fmt.Fprintf(s, "    uint8_t *last_id = bpf_syscall_seq_rb_lookup_elem(&i);\n")
	fmt.Fprintf(s, "    if (last_id)\n")
	fmt.Fprintf(s, "           return *last_id;\n")
	fmt.Fprintf(s, "    return 0;//XXX should return error\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "int __always_inline check_id_seq_1(struct seccomp_data *ctx, uint8_t next_id)\n")
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int last_id = get_syscall_seq_1();\n")
	fmt.Fprintf(s, "    uint64_t *next_ids = bpf_id_seq_1_map_lookup_elem(&last_id);\n")
	fmt.Fprintf(s, "    if (next_ids && (*next_ids & (1 << next_id))) {\n")
	fmt.Fprintf(s, "        return SECCOMP_RET_ALLOW;\n")
	fmt.Fprintf(s, "    } else {\n")
	fmt.Fprintf(s, "        return SECCOMP_RET_ERRNO;\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n")
	fmt.Fprintf(s, "\n")
	// Generate tracing code
	fmt.Fprintf(s, "SEC(\"seccomp\")\n")
	fmt.Fprintf(s, "int filter(struct seccomp_data *ctx)\n")
	fmt.Fprintf(s, "{\n")
	fmt.Fprintf(s, "    int ret = SECCOMP_RET_ALLOW;\n")
	fmt.Fprintf(s, "    if (ctx->nr == __NR_openat) {\n")
	fmt.Fprintf(s, "        check_dev_open(ctx);\n")
	fmt.Fprintf(s, "    } else if (ctx->nr == __NR_ioctl && check_syscall_fd(ctx)) {\n")
	fmt.Fprintf(s, "        uint8_t next_id = next_syscall_id(ctx);\n")
	fmt.Fprintf(s, "        ret = check_id_seq_1(ctx, next_id);\n")
	fmt.Fprintf(s, "        if (ret == SECCOMP_RET_ALLOW) {\n")
	fmt.Fprintf(s, "            int i = 0;\n")
	fmt.Fprintf(s, "            bpf_syscall_seq_rb_update_elem(&i, &next_id, BPF_ANY);\n")
	fmt.Fprintf(s, "        } else {\n")
	fmt.Fprintf(s, "            goto out;\n")
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "        uint64_t ioctl_cmd = ctx->args[1];\n")
	fmt.Fprintf(s, "        switch (ioctl_cmd) {\n")
	for key, syscall := range tracedSyscalls {
		if key == "ioctl" {
			for _, commands := range syscall {
				cmd, ok := sifter.target.SyscallMap[commands].Args[1].(*prog.ConstType)
				if !ok {
					failf("failed to get const command value for %v", commands)
				}
				if !strings.Contains(commands, "_compact_") {
					traceFuncName := fmt.Sprintf("trace_ioctl_0x%x", cmd.Val)
					sifter.GenerateIoctlTracer(traceFuncName, sifter.target.SyscallMap[commands])
					fmt.Fprintf(s, "        case 0x%x: //%v\n", cmd.Val, commands)
					fmt.Fprintf(s, "            ret = %v(ctx);\n", traceFuncName)
					fmt.Fprintf(s, "            break;\n")

					cmdId := uint16((cmd.Val & ((1 << 8)-1)) | 0x8000)
					sifter.seqIdSyscallMap[cmdId] = uint32(cmd.Val)
				}
			}
		}
	}
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "out:\n")
	fmt.Fprintf(s, "    return ret;\n")
	fmt.Fprintf(s, "}\n")
	}
}

func (sifter *Sifter) ParseSeqPolicy() {
	sifter.scanner.Scan()
	if err := sifter.scanner.Err(); err != nil {
		failf("failed to parse trace file. err: %v",err)
	}

	seqHeader := strings.Fields(sifter.scanner.Text())
	if len(seqHeader) != 2 {
		failf("failed to parse trace file. expected 'r <n>' but got %v",
			  sifter.scanner.Text())
	}
	if seqHeader[0] != "r" {
		failf("failed to parse trace file. expected 'r' but got %v",
			  sifter.scanner.Text())
	}

	sequences, _ := strconv.ParseInt(seqHeader[1], 10, 32)
	for i := 0; i < int(sequences); i++ {
		sifter.scanner.Scan()
		if err := sifter.scanner.Err(); err != nil {
			failf("failed to parse trace file. err: %v",err)
		}
		seqEntry := strings.Fields(sifter.scanner.Text())

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
			if nextId == 0 {
				continue
			}

			if nextIds, ok := sifter.seqPolicy[currId]; ok {
				nextIds[nextId] = true
			} else {
				sifter.seqPolicy[currId] = make(map[uint16]bool)
				sifter.seqPolicy[currId][nextId] = true
				sifter.seqKeys = append(sifter.seqKeys, currId)
			}
		}
	}
	sort.Slice(sifter.seqKeys, func(i, j int) bool { return sifter.seqKeys[i] < sifter.seqKeys[j] })
	for _, k := range sifter.seqKeys {
		fmt.Printf("%v | ", k)
		for next, _ := range sifter.seqPolicy[k] {
			fmt.Printf("%v ", next)
		}
		fmt.Printf("\n")
	}
}

func (sifter *Sifter) GenerateInitArgMaps(indent int) (string) {
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
	ret := strings.Replace(s.String(), "\n", "\n"+strings.Repeat(" ", 4*indent), -1)
	return ret

}

func (sifter *Sifter) GenerateInitSection() {
	s := sifter.NewSection()
	if (sifter.mode == TracerMode) {
		fmt.Fprintf(s, "void __always_inline init() {\n")
		fmt.Fprintf(s, "    int32_t i = 0;\n")
		fmt.Fprintf(s, "    int *init = bpf_init_map_lookup_elem(&i);\n")
		fmt.Fprintf(s, "    if (init && *init == 0) {\n")
		fmt.Fprintf(s, "        *init = 1;\n")
		fmt.Fprintf(s, "        %v\n", sifter.GenerateInitArgMaps(2))
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "}\n\n")
	} else if (sifter.mode == FilterMode){
		fmt.Fprintf(s, "void __always_inline init_syscall_id_map() {\n")
		fmt.Fprintf(s, "    uint8_t id = 0;\n")
		fmt.Fprintf(s, "    uint64_t syscall;\n")
		for _, k := range sifter.seqKeys {
			var key uint32
			if k & 0x8000 == 0x8000 {
				key = sifter.seqIdSyscallMap[k]
			} else {
				key = uint32(k)
			}
			fmt.Fprintf(s, "    syscall = %v;\n", key)
			fmt.Fprintf(s, "    bpf_syscall_id_map_update_elem(&syscall, &id, BPF_ANY);\n")
			fmt.Fprintf(s, "    id++;\n")
		}
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "void __always_inline init_id_seq_1_map() {\n")
		fmt.Fprintf(s, "    int id = 0;\n")
		fmt.Fprintf(s, "    uint64_t next_syscalls;\n")
		for _, k := range sifter.seqKeys {
			var nexts uint64 = 0
			for next, _ := range sifter.seqPolicy[k] {
				offset := 0
				for i, _k := range sifter.seqKeys {
					if _k == next {
						offset = i
					}
				}
				nexts += uint64(math.Pow(2, float64(offset)))
			}
			fmt.Fprintf(s, "    next_syscalls = %v;\n", nexts)
			fmt.Fprintf(s, "    bpf_id_seq_1_map_update_elem(&id, &next_syscalls, BPF_ANY);\n")
			fmt.Fprintf(s, "    id++;\n")
		}
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
	}
}

func (sifter *Sifter) GenerateMapSection() {
	s := sifter.NewSection()
	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(init_map, ARRAY, int, int, 2)\n")
		for _, bpfMap := range sifter.argMaps {
			fmt.Fprintf(s, "DEFINE_BPF_MAP(%v, ARRAY, int, %v, 2)\n", bpfMap.name, bpfMap.datatype)
		}
		fmt.Fprintf(s, "DEFINE_BPF_MAP_F(syscall_seq_rb, ARRAY, int, seq_rb_elem, 32768, BPF_F_LOCK);\n")
		fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_seq_rb_ctr, ARRAY, int, uint8_t, 32768);\n")
	} else if sifter.mode == FilterMode {
		idNum := len(sifter.seqPolicy)
		fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_id_map, HASH, uint64_t, uint8_t, %v);\n", idNum)
		fmt.Fprintf(s, "DEFINE_BPF_MAP(id_seq_1_map, ARRAY, int, uint64_t, %v);\n", idNum)
		fmt.Fprintf(s, "DEFINE_BPF_MAP(init_map, ARRAY, int, int, 1)\n")
		fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_seq_rb, ARRAY, int, uint8_t, 1);\n")
	}
	if sifter.target.Arch == "arm" {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_fd_mask, ARRAY, int, uint8_t, 398);\n")
	}
	if sifter.target.Arch == "arm64" {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_fd_mask, ARRAY, int, uint8_t, 292);\n")
	}
	fmt.Fprintf(s, "\n")
}

func (sifter *Sifter) GenerateStructSection() {
	s := sifter.NewSection()
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
				fieldType = fmt.Sprintf("uint%v_t", field.(*prog.ArrayType).Type.TypeBitSize(), )
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

func (sifter *Sifter) GenerateHelperSection() {
	s := sifter.NewSection()
	if sifter.mode == FilterMode {
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
		fmt.Fprintf(s, "    if (arg & zeros || ~arg & ones)       \\\n")
		fmt.Fprintf(s, "        return SECCOMP_RET_ERRNO;\n")
		fmt.Fprintf(s, "\n")
	}
}

func (sifter *Sifter) GenerateHeaderSection() {
	s := sifter.NewSection()
	fmt.Fprintf(s, "#include <linux/seccomp.h>\n")
	fmt.Fprintf(s, "#include <linux/bpf.h>\n")
	fmt.Fprintf(s, "#include <linux/unistd.h>\n")
	fmt.Fprintf(s, "#include <linux/ptrace.h>\n")
	fmt.Fprintf(s, "#include <bpf_helpers.h>\n")
	fmt.Fprintf(s, "#include <linux/errno.h>\n")
	fmt.Fprintf(s, "#include <sys/types.h>\n")
	fmt.Fprintf(s, "\n")
}

func (sifter *Sifter) GenerateTracer() {
	licenseSec := sifter.NewSection()
	fmt.Fprintf(licenseSec, "char _license[] SEC(\"license\") = \"GPL\";\n")

	sifter.GenerateProgSection()
	if sifter.mode == FilterMode {
		sifter.ParseSeqPolicy()
	}
	sifter.GenerateInitSection()
	sifter.GenerateMapSection()
	sifter.GenerateStructSection()
	sifter.GenerateHelperSection()
	sifter.GenerateHeaderSection()
}

func (sifter *Sifter) WriteTracerFile() {
//	postfix := ""
//	if sifter.mode == TracerMode {
//		postfix = "tracer"
//	} else if sifter.mode == FilterMode {
//		postfix = "filter"
//	}
//	file := filepath.Join(sifter.outDir, sifter.outName+"_"+postfix+".c")
	outf, err := os.Create(sifter.outSourceFile)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()
	for _, section := range sifter.sections {
		outf.Write(section.Bytes())
	}
}

func (sifter *Sifter) WriteAgentConfigFile() {
	outf, err := os.Create(sifter.outConfigFile)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()

	s := new(bytes.Buffer)
	bitness := 0
	if sifter.target.Arch == "arm" {
		bitness = 32
	}
	if sifter.target.Arch == "arm64" {
		bitness = 64
	}
	fmt.Fprintf(s, "%v %v\n", sifter.outName, bitness)

	fmt.Fprintf(s, "p 1 %v %v\n", sifter.syscallEntry, sifter.syscallEntry)

	for _, m := range sifter.argMaps {
		fmt.Fprintf(s, "m %v %v\n", m.mapType, m.name)
	}

	fmt.Fprintf(s, "p 2 raw_syscalls sys_enter\n")
	if sifter.target.Arch == "arm" {
		fmt.Fprintf(s, "l 0 syscall_fd_mask 398\n")
		//                      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9
		fmt.Fprintf(s, "        0 0 0 1 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 1\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 0 0 0 0\n")
		fmt.Fprintf(s, "        1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 1 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 1 0 1 0 1 1 0 1 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        1 1 0 0 0 0 0 3 0 0 0 0 0 0 1 0 0 1 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0\n")
		fmt.Fprintf(s, "        1 0 0 0 0 1 0 0 1 0 0 1 0 0 1 0 0 1 0 1\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 5 1 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 1 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0\n")
		fmt.Fprintf(s, "        0 0 1 1 1 1 1 1 1 5 5 2 1 1 1 0 0 0 0 0\n")
		fmt.Fprintf(s, "        5 1 3 0 0 0 1 0 1 1 0 0 1 1 1 1 0 3 0 0\n")
		fmt.Fprintf(s, "        1 1 0 0 0 1 0 0 9 0 1 1 0 1 1 1 0 0 0 1\n")
		fmt.Fprintf(s, "        0 0 5 0 0 0 0 1 0 0 0 5 1 1 0 0 0 1\n")
	}
	if sifter.target.Arch == "arm64" {
		fmt.Fprintf(s, "l 0 syscall_fd_mask 292\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 1 0 0 1 0 0 1 0 0 1 0 0 0\n")
		fmt.Fprintf(s, "        0 4 0 0 1 1 0 1 1 1 0 0 1 1 1 1 0 1 1 0\n")
		fmt.Fprintf(s, "        0 0 0 0 1 0 1 1 1 0 1 0 1 1 1 1 1 1 0 0\n")
		fmt.Fprintf(s, "        0 1 1 1 1 1 1 1 1 1 1 3 0 0 1 1 5 3 1 1\n")
		fmt.Fprintf(s, "        1 0 1 1 1 0 1 1 1 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 16 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 8 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		fmt.Fprintf(s, "        0 0 0 8 0 1 0 1 1 1 0 0 0 1 0 0 1 0 0 0\n")
		fmt.Fprintf(s, "        0 1 0 0 0 5 1 1 0 0 0 1\n")
	}

	fmt.Fprintf(s, "r %v syscall_seq_rb\n", sifter.seqLen)

	outf.Write(s.Bytes())
}

func main() {
	var flags Flags
	flag.StringVar(&flags.mode,   "mode", "", "mode")
	flag.StringVar(&flags.trace,  "trace", "", "trace file")
	flag.StringVar(&flags.config, "config", "", "configuration file")
	flag.StringVar(&flags.fd,     "fd", "", "file descriptor name")
	flag.StringVar(&flags.dev,    "dev", "", "driver file name")
	flag.StringVar(&flags.entry,  "entry", "", "syscall entry function")
	flag.StringVar(&flags.outdir, "outdir", "gen", "output file directory")
	flag.StringVar(&flags.out,    "out", "", "output file base name")
	flag.IntVar(&flags.seqlen,    "seqlen", 4, "syscall sequence length")
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

	sifter.GenerateTracer()
	sifter.WriteTracerFile()
	if sifter.mode == TracerMode {
		sifter.WriteAgentConfigFile()
	}
}
