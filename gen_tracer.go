package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagFd     = flag.String("fd", "", "file descriptor name")
	flagDev    = flag.String("dev", "", "driver file name")
	flagEntry  = flag.String("entry", "", "syscall entry function")
	flagOutDir = flag.String("outdir", "gen", "output file directory")
	flagOut    = flag.String("out", "", "output file base name")
	flagSeqLen = flag.Int("seqlen", 4, "syscall sequence length")
)

type Section struct {
	t   int
	buf *bytes.Buffer
}

type BpfMinMaxMap struct {
	name     string
	datatype string
}

type BpfFlagsMap struct {
	name    string
	datatype string
}

type Tracer struct {
    target      *prog.Target
    v           int
	sections    []*bytes.Buffer
	filterSecs  []*bytes.Buffer
	minMaxMaps  []*BpfMinMaxMap
	flagsMaps   []*BpfFlagsMap
	structs     []*prog.StructType
	outDir      string
	outName     string
	syscallEntry string
	fdName      string
	devName     string
	headers     []string
	seqLen      int
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func NewTracer(target *prog.Target, dev string, fd string, entry string, out string, outdir string, l int) (*Tracer, error) {
	tracer := new(Tracer)
    tracer.target = target
	tracer.fdName = fd
	tracer.devName = dev
	tracer.syscallEntry = entry
	tracer.outName = out
	tracer.outDir = outdir
	tracer.seqLen = l
	tracer.lazyInit()
	return tracer, nil
}

func (tracer *Tracer) lazyInit() {
	tracer.minMaxMaps = []*BpfMinMaxMap{}
	tracer.flagsMaps = []*BpfFlagsMap{}
	tracer.sections = []*bytes.Buffer{}
	tracer.v = 0
}

func (tracer *Tracer) NewSection() *bytes.Buffer {
	s := new(bytes.Buffer)
	tracer.sections = append([]*bytes.Buffer{s}, tracer.sections...)
	return s
}

func (tracer *Tracer) NewFilterSection() *bytes.Buffer {
	s := new(bytes.Buffer)
	tracer.filterSecs = append([]*bytes.Buffer{s}, tracer.filterSecs...)
	return s
}

func fixName(name string) string {
	fixChar := []string{".", "$", "-", ">", "[", "]"}
	for _, char := range fixChar {
		name = strings.Replace(name, char, "_", -1)
	}
	return name
}

func (tracer *Tracer) NewMinMaxMap(name string, datatype string) {
	name = fixName(name)
	newMap := &BpfMinMaxMap{name: name, datatype: datatype}
	tracer.minMaxMaps = append(tracer.minMaxMaps, newMap)
}

func (tracer *Tracer) NewFlagsMap(name string, datatype string) {
	name = fixName(name)
	newMap := &BpfFlagsMap{name: name, datatype: datatype}
	tracer.flagsMaps = append(tracer.flagsMaps, newMap)
}

func (tracer *Tracer) AddStruct(s *prog.StructType) {
    // Return if the struct is already added
    for _, _s := range tracer.structs {
        if _s.Name() == s.Name() {
            return
        }
    }

    fmt.Printf("add new struct: %v\n", s.Name())
    // Scan for dependencies and insert
    for i, _s := range tracer.structs {
		for _, field := range _s.StructDesc.Fields {
            if field.Name() == s.Name() {
                tracer.structs = append(tracer.structs, s)
                copy(tracer.structs[i+1:], tracer.structs[i:])
                tracer.structs[i] = s
                return
            }
        }
    }
    tracer.structs = append(tracer.structs, s)
}

func GenerateUpdateMinMax(s *bytes.Buffer, argType string, argName string, argMap string) {
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

func GenerateUpdateFlags(s *bytes.Buffer, argType string, argName string, argMap string) {
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

func GenerateCopyFromUser(tracer *Tracer, s *bytes.Buffer, path string, argType string, argName string) {
    argName = fmt.Sprintf("v%v", tracer.v)
    fmt.Fprintf(s, "    %v %v;\n", argType, argName)
    fmt.Fprintf(s, "    bpf_probe_read_sleepable(&%v, sizeof(%v), (void *)%v);\n", argName, argName, path)
    tracer.v += 1
}

func GenerateRecursiveTracer(tracer *Tracer, arg prog.Type, s *bytes.Buffer, path string, fromPointer bool, depth *int) {
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
		GenerateRecursiveTracer(tracer, arg.(*prog.PtrType).Type, s, path, true, depth)
		*depth -= 1
	case *prog.StructType:
		structPath := ""
		if fromPointer {
			structPath = fmt.Sprintf("v%v", tracer.v)
            GenerateCopyFromUser(tracer, s, path, argType, structPath)
		} else {
			structPath = path + "." + arg.FieldName()
		}

        tracer.AddStruct(arg.(*prog.StructType))
		for _, field := range arg.(*prog.StructType).StructDesc.Fields {
			GenerateRecursiveTracer(tracer, field, s, structPath, false, depth)
		}
	case *prog.LenType, *prog.IntType, *prog.ConstType:
        if c, ok := t.(*prog.ConstType); ok && c.IsPad {
            break
        }

		argName := ""
		if fromPointer {
			argName = fmt.Sprintf("v%v", tracer.v)
            GenerateCopyFromUser(tracer, s, path, argType, argName)
		} else if *depth == 0 {
			argName = path
		} else {
			argName = path + "." + arg.FieldName()
		}

		tracer.NewMinMaxMap(argName, argType)
		GenerateUpdateMinMax(s, argType, argName, fixName(argName))
	case *prog.FlagsType:
		argName := ""
		if fromPointer {
			argName = fmt.Sprintf("v%v", tracer.v)
            GenerateCopyFromUser(tracer, s, path, argType, argName)
		} else if *depth == 0 {
			argName = path
		} else {
			argName = path + "." + arg.FieldName()
		}

		tracer.NewFlagsMap(argName, argType)
		GenerateUpdateFlags(s, argType, argName, fixName(argName))
	case *prog.UnionType:
	case *prog.ArrayType:
	case *prog.BufferType:
	case *prog.ResourceType:
	default:
		fmt.Println("Unhandled type", t)
	}

}

func GenerateSyscallTracer(target *prog.Target, tracer *Tracer, name string, syscall *prog.Syscall) {
	s := tracer.NewSection()
	fmt.Fprintf(s, "void __always_inline %v(sys_enter_args *arg) {\n", name)
	for i, arg := range syscall.Args {
		path := fmt.Sprintf("arg->regs[%v]", i)
		offset := 0
		GenerateRecursiveTracer(tracer, arg, s, path, false, &offset)
	}
	fmt.Fprintf(s, "}\n\n")
}

func GenerateIoctlTracer(target *prog.Target, tracer *Tracer, name string, syscall *prog.Syscall) {
	s := tracer.NewSection()
	fmt.Fprintf(s, "void __always_inline %v(struct user_pt_regs *ctx) {\n", name)
	path := "ctx->regs[2]"
    offset := 0
	GenerateRecursiveTracer(tracer, syscall.Args[2], s, path, true, &offset)
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

func (tracer *Tracer) SyscallNumber(name string) (uint64){
	for _, constant := range tracer.target.Consts {
		if constant.Name == "__NR_" + name {
			return constant.Value
		}
	}
	failf("cannot find syscall number for %v", name)
	return 0xffffffffffffffff
}

func (tracer *Tracer) GenerateProgSection() {
	// Find out device associated syscalls to be traced
	tracedSyscalls := map[string][]string{}
	for _, syscall := range tracer.target.Syscalls {
		// Find out path of driver
		if len(tracer.devName) == 0  && syscall.CallName == "syz_open_dev" {
            if ret, ok := syscall.Ret.(*prog.ResourceType); ok {
                if ret.String() == tracer.fdName {
                    if devName, ok := extractStringConst(syscall.Args[0]); ok {
                        tracer.devName = filepath.Base(strings.Replace(devName, "#", "0", 1))
                    }
                }
            }
		}
		// Scan for syscalls using the driver
		for _, args := range syscall.Args {
			if args.Name() == tracer.fdName {
				tracedSyscalls[syscall.CallName] = append(tracedSyscalls[syscall.CallName], syscall.Name)
			}
		}
	}

    if len(tracer.devName) == 0 {
        failf("cannot find dev for %v", tracer.fdName)
    } else {
        fmt.Printf("trace syscall using dev: %v\n", tracer.devName)
    }

	//TODO move ioctl tracers under tracepoint
    // generate sequence tracer
    s := tracer.NewSection()
    fmt.Fprintf(s, "#define IOC_NR(cmd) (cmd & ((1 << 8)-1))\n")
    fmt.Fprintf(s, "uint16_t __always_inline arg_to_id(sys_enter_args *arg) {\n")
    fmt.Fprintf(s, "    int nr = arg->id;\n")
    fmt.Fprintf(s, "    int fd_is_dev = 0;\n")
    fmt.Fprintf(s, "    uint16_t id = 0xffff;\n")
    fmt.Fprintf(s, "    char dev [] = \"%v\";\n", tracer.devName)
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
    fmt.Fprintf(s, "        if (nr == %v) {\n", tracer.SyscallNumber("ioctl"))
    fmt.Fprintf(s, "            id = 0x8000 | IOC_NR(arg->regs[1]);\n")
	for key, _ := range tracedSyscalls {
		if key != "ioctl" {
			fmt.Fprintf(s, "        } else if (nr == %v) {\n", tracer.SyscallNumber(key))
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
			s := tracer.NewSection()
			fmt.Fprintf(s, "SEC(\"kprobe/%v\")\n", tracer.syscallEntry)
			fmt.Fprintf(s, "int kprobe_%v(struct user_pt_regs *ctx) {\n", tracer.syscallEntry)
			fmt.Fprintf(s, "    uint64_t ioctl_cmd = ctx->regs[1];\n")
			//fmt.Fprintf(s, "    uint64_t ioctl_arg = ctx->regs[2];\n")
			fmt.Fprintf(s, "    switch (ioctl_cmd) {\n")
			for _, commands := range syscall {
				cmd, ok := tracer.target.SyscallMap[commands].Args[1].(*prog.ConstType)
				if !ok {
					failf("failed to get const command value for %v", commands)
				}
                if !strings.Contains(commands, "_compact_") {
                    traceFuncName := fmt.Sprintf("trace_ioctl_0x%x", cmd.Val)
                    GenerateIoctlTracer(tracer.target, tracer, traceFuncName, tracer.target.SyscallMap[commands])
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
			GenerateSyscallTracer(tracer.target, tracer, traceFuncName, tracer.target.SyscallMap[key])
		}
	}

}

func (tracer *Tracer) GenerateInitSection() {
	s := tracer.NewSection()
	fmt.Fprintf(s, "void __always_inline init() {\n")
	fmt.Fprintf(s, "    int32_t i = 0;\n")
	fmt.Fprintf(s, "    int *init = bpf_init_map_lookup_elem(&i);\n")
	fmt.Fprintf(s, "    if (init && *init == 0) {\n")
	fmt.Fprintf(s, "        *init = 1;\n")
	for _, bpfMap := range tracer.minMaxMaps {
		fmt.Fprintf(s, "        i = 0;\n")
		fmt.Fprintf(s, "        %v *%v_min = bpf_%v_lookup_elem(&i);\n", bpfMap.datatype, bpfMap.name, bpfMap.name)
		fmt.Fprintf(s, "        if (%v_min) {\n", bpfMap.name)
		fmt.Fprintf(s, "            *%v_min = -1;\n", bpfMap.name)
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "        i = 1;\n")
		fmt.Fprintf(s, "        %v *%v_max = bpf_%v_lookup_elem(&i);\n", bpfMap.datatype, bpfMap.name, bpfMap.name)
		fmt.Fprintf(s, "        if (%v_max) {\n", bpfMap.name)
		fmt.Fprintf(s, "            *%v_max = 0;\n", bpfMap.name)
		fmt.Fprintf(s, "        }\n")
	}
	for _, bpfMap := range tracer.flagsMaps {
		fmt.Fprintf(s, "        i = 0;\n")
		fmt.Fprintf(s, "        %v *%v_zeros = bpf_%v_lookup_elem(&i);\n", bpfMap.datatype, bpfMap.name, bpfMap.name)
		fmt.Fprintf(s, "        if (%v_zeros) {\n", bpfMap.name)
		fmt.Fprintf(s, "            *%v_zeros = 0;\n", bpfMap.name)
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "        i = 1;\n")
		fmt.Fprintf(s, "        %v *%v_ones = bpf_%v_lookup_elem(&i);\n", bpfMap.datatype, bpfMap.name, bpfMap.name)
		fmt.Fprintf(s, "        if (%v_ones) {\n", bpfMap.name)
		fmt.Fprintf(s, "            *%v_ones = 0;\n", bpfMap.name)
		fmt.Fprintf(s, "        }\n")
	}
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "}\n\n")
}

func (tracer *Tracer) GenerateMapSection() {
	s := tracer.NewSection()
	fmt.Fprintf(s, "DEFINE_BPF_MAP(init_map, ARRAY, int, int, 2)\n")
	for _, bpfMap := range tracer.minMaxMaps {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(%v, ARRAY, int, %v, 2)\n", bpfMap.name, bpfMap.datatype)
	}
	for _, bpfMap := range tracer.flagsMaps {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(%v, ARRAY, int, %v, 2)\n", bpfMap.name, bpfMap.datatype)
	}
    fmt.Fprintf(s, "DEFINE_BPF_MAP_F(syscall_seq_rb, ARRAY, int, seq_rb_elem, 32768, BPF_F_LOCK);\n")
    fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_seq_rb_ctr, ARRAY, int, uint8_t, 32768);\n")
	if tracer.target.Arch == "arm" {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_fd_mask, ARRAY, int, uint8_t, 398);\n")
	}
	if tracer.target.Arch == "arm64" {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_fd_mask, ARRAY, int, uint8_t, 292);\n")
	}
	fmt.Fprintf(s, "\n")
}

func (tracer *Tracer) GenerateStructSection() {
	s := tracer.NewSection()
    for _, structure := range tracer.structs {
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

func (tracer *Tracer) GenerateHeaderSection() {
	s := tracer.NewSection()
	fmt.Fprintf(s, "#include <linux/seccomp.h>\n")
	fmt.Fprintf(s, "#include <linux/bpf.h>\n")
	fmt.Fprintf(s, "#include <linux/unistd.h>\n")
	fmt.Fprintf(s, "#include <linux/ptrace.h>\n")
	fmt.Fprintf(s, "#include <bpf_helpers.h>\n")
	fmt.Fprintf(s, "#include <linux/errno.h>\n")
	fmt.Fprintf(s, "#include <sys/types.h>\n")
	for _, header := range tracer.headers {
		fmt.Fprintf(s, "#include <%v>\n", header)
	}
	fmt.Fprintf(s, "\n")
}

func (tracer *Tracer) GenerateTracer() {
	licenseSec := tracer.NewSection()
	fmt.Fprintf(licenseSec, "char _license[] SEC(\"license\") = \"GPL\";\n")

	tracer.GenerateProgSection()
	tracer.GenerateInitSection()
	tracer.GenerateMapSection()
	tracer.GenerateStructSection()
	tracer.GenerateHeaderSection()
}

func (tracer *Tracer) WriteTracerFile() {
	file := filepath.Join(tracer.outDir, tracer.outName+".c")
	outf, err := os.Create(file)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()
	for _, section := range tracer.sections {
		outf.Write(section.Bytes())
	}
}

func (tracer *Tracer) WriteAgentConfigFile() {
	file := filepath.Join(tracer.outDir, tracer.outName+"_agent.cfg")
	outf, err := os.Create(file)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()

	s := new(bytes.Buffer)
	bitness := 0
	if tracer.target.Arch == "arm" {
		bitness = 32
	}
	if tracer.target.Arch == "arm64" {
		bitness = 64
	}
	fmt.Fprintf(s, "%v %v\n", tracer.outName, bitness)

	fmt.Fprintf(s, "p 1 %v %v\n", tracer.syscallEntry, tracer.syscallEntry)

	for _, bpfMap := range tracer.minMaxMaps {
		fmt.Fprintf(s, "m 0 %v\n", bpfMap.name)
	}
	for _, bpfMap := range tracer.flagsMaps {
		fmt.Fprintf(s, "m 0 %v\n", bpfMap.name)
	}

	fmt.Fprintf(s, "p 2 raw_syscalls sys_enter\n")
	if tracer.target.Arch == "arm" {
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
	if tracer.target.Arch == "arm64" {
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

	fmt.Fprintf(s, "r %v syscall_seq_rb\n", tracer.seqLen)

	outf.Write(s.Bytes())
}

func main() {
	flag.Parse()

	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		failf("failed to load config file. err: %v", err)
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		failf("failed to get target %v/%v. err: %v", cfg.TargetOS, cfg.TargetArch, err)
	}

	out := cfg.TargetOS + "_" + cfg.TargetArch + "_" + *flagOut
	tracer, err := NewTracer(target, *flagDev, *flagFd, *flagEntry, out, *flagOutDir, *flagSeqLen)
	if err != nil {
		failf("failed to create tracer. err: %v", err)
	}

	_, err = os.Stat(tracer.outDir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(tracer.outDir, 0755)
		if err != nil {
			failf("failed to create output dir %v", tracer.outDir)
		}
	}

	tracer.GenerateTracer()
	tracer.WriteTracerFile()
	tracer.WriteAgentConfigFile()
}
