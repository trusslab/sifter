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
	flagEntry  = flag.String("entry", "", "syscall entry function")
	flagOutDir = flag.String("outdir", "gen", "output file directory")
	flagOut    = flag.String("out", "", "output file base name")
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
	////    handlers        map[string]string
	////    resources
	////    syscalls
	//    sections    map[string]*Section
	v           int
	sections    []*bytes.Buffer
	filterSecs  []*bytes.Buffer
	minMaxMaps  []*BpfMinMaxMap
	flagsMaps   []*BpfFlagsMap
	//minMaxMaps []*BpfMinMaxMap
	structs     []*prog.StructType
	outDir      string
	outName     string
	syscallEntry string
	fdName      string
	headers     []string
}

func NewTracer(fd string, entry string, out string, outdir string) (*Tracer, error) {
	tracer := new(Tracer)
	tracer.fdName = fd
	tracer.syscallEntry = entry
	tracer.outName = out
	tracer.outDir = outdir
	tracer.lazyInit()
	return tracer, nil
}

func (tracer *Tracer) lazyInit() {
	//    target.sections["license"] = &Section{t: 0, buf: new(bytes.Buffer)})
	//    target.sections["header"] = &Section{t: 0, buf: new(bytes.Buffer)})
	//    target.sections["map"] = &Section{t: 0, buf: new(bytes.Buffer)})
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

func (tracer *Tracer) NewMinMaxMap(name string, datatype string) {
	fixChar := []string{".", "$"}
	for _, char := range fixChar {
		name = strings.Replace(name, char, "_", -1)
	}
	newMap := &BpfMinMaxMap{name: name, datatype: datatype}
	tracer.minMaxMaps = append(tracer.minMaxMaps, newMap)
}

func (tracer *Tracer) NewFlagsMap(name string, datatype string) {
	fixChar := []string{".", "$"}
	for _, char := range fixChar {
		name = strings.Replace(name, char, "_", -1)
	}
	newMap := &BpfFlagsMap{name: name, datatype: datatype}
	tracer.flagsMaps = append(tracer.flagsMaps, newMap)
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

func (tracer *Tracer) WriteAgentFile() {
	file := filepath.Join(tracer.outDir, tracer.outName+"_agent.cpp")
	outf, err := os.Create(file)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()

	s := new(bytes.Buffer)
	fmt.Fprintf(s, "#include <bpf/BpfMap.h>\n")
	fmt.Fprintf(s, "#include <bpf/BpfUtils.h>\n")
	fmt.Fprintf(s, "#include <libbpf_android.h>\n")
	fmt.Fprintf(s, "#include <iostream>\n")
	fmt.Fprintf(s, "#include <sstream>\n")
	for _, header := range (*tracer).headers {
		fmt.Fprintf(s, "#include <%v>\n", header)
	}
	fmt.Fprintf(s, "\n")

	fmt.Fprintf(s, "using android::base::unique_fd;\n")
	fmt.Fprintf(s, "\n")

	fmt.Fprintf(s, "android::base::unique_fd get_bpf_obj_fd(const char *path) {\n")
	fmt.Fprintf(s, "    int fd = bpf_obj_get(path);\n")
	fmt.Fprintf(s, "    std::cout << \"fd(\" << fd << \"): \" << path << \"\\n\";\n")
	fmt.Fprintf(s, "    return android::base::unique_fd(fd);\n")
	fmt.Fprintf(s, "}\n\n")

	fmt.Fprintf(s, "int main() {\n")
	fmt.Fprintf(s, "    char const *prog_path = \"/sys/fs/bpf/prog_%v_kprobe_%v\";\n", (*tracer).outName, (*tracer).syscallEntry)
	fmt.Fprintf(s, "    int prog_fd = bpf_obj_get(prog_path);\n")
	fmt.Fprintf(s, "    std::cout << \"fd(\" << prog_fd << \"): \" << prog_path << \"\\n\";\n")
	fmt.Fprintf(s, "    int result = bpf_attach_kprobe(prog_fd, BPF_PROBE_ENTRY, \"%v\", \"%v\", 0);\n", (*tracer).syscallEntry, (*tracer).syscallEntry)
	fmt.Fprintf(s, "    if (result < 0) {\n")
	fmt.Fprintf(s, "        std::cout << \"bpf_attach_kprobe return \" << result << \" \" << errno << \"\\n\";\n")
	fmt.Fprintf(s, "        return 1;\n")
	fmt.Fprintf(s, "    }\n")

	for i, bpfMap := range (*tracer).minMaxMaps {
		fmt.Fprintf(s, "    unique_fd map_fd_%v = get_bpf_obj_fd(\"/sys/fs/bpf/map_%v_%v\");\n", i, (*tracer).outName, bpfMap.name)
	}
    minMaxSize := len((*tracer).minMaxMaps)
	for i, bpfMap := range (*tracer).flagsMaps {
		fmt.Fprintf(s, "    unique_fd map_fd_%v = get_bpf_obj_fd(\"/sys/fs/bpf/map_%v_%v\");\n", i + minMaxSize, (*tracer).outName, bpfMap.name)
	}
	fmt.Fprintf(s, "\n")
	fmt.Fprintf(s, "    std::cout << \"\\nPress enter to read map values...\\n\";\n")
	fmt.Fprintf(s, "    std::cin.get();\n")

	fmt.Fprintf(s, "    int key;\n")
	for i, bpfMap := range (*tracer).minMaxMaps {
		fmt.Fprintf(s, "    {\n")
		fmt.Fprintf(s, "    %v min, max;\n", bpfMap.datatype)
		fmt.Fprintf(s, "    int ret_min, ret_max;\n")
		fmt.Fprintf(s, "    key = 0;\n")
		fmt.Fprintf(s, "    ret_min = android::bpf::findMapEntry(map_fd_%v, &key, &min);\n", i)
		fmt.Fprintf(s, "    key = 1;\n")
		fmt.Fprintf(s, "    ret_max = android::bpf::findMapEntry(map_fd_%v, &key, &max);\n", i)
		fmt.Fprintf(s, "    if (ret_min == 0 && ret_max == 0) {\n")
		fmt.Fprintf(s, "        std::cout << \"%v\" << \"[\"<< min << \", \" << max << \"]\\n\";\n", bpfMap.name)
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    }\n")
	}
	for i, bpfMap := range (*tracer).flagsMaps {
		fmt.Fprintf(s, "    {\n")
		fmt.Fprintf(s, "    %v zeros, ones;\n", bpfMap.datatype)
		fmt.Fprintf(s, "    int ret_zeros, ret_ones;\n")
		fmt.Fprintf(s, "    key = 0;\n")
		fmt.Fprintf(s, "    ret_zeros = android::bpf::findMapEntry(map_fd_%v, &key, &zeros);\n", i + minMaxSize)
		fmt.Fprintf(s, "    key = 1;\n")
		fmt.Fprintf(s, "    ret_ones = android::bpf::findMapEntry(map_fd_%v, &key, &ones);\n", i + minMaxSize)
		fmt.Fprintf(s, "    if (ret_zeros == 0 && ret_ones == 0) {\n")
		fmt.Fprintf(s, "        std::cout << \"%v\" << \"[\"<< zeros << \", \" << ones << \"]\\n\";\n", bpfMap.name)
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    }\n")
	}

	fmt.Fprintf(s, "}\n")

	outf.Write(s.Bytes())
}

func (tracer *Tracer) AddStruct(s *prog.StructType) {
    // Return if the struct is already added
    for _, _s := range tracer.structs {
        if _s.Name() == s.Name() {
            return
        }
    }

    fmt.Println("Add new struct ", (*s).Name())
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

func fixName(name string) string {
	fixChar := []string{".", "$"}
	for _, char := range fixChar {
		name = strings.Replace(name, char, "_", -1)
	}
	return name
}

func generateUpdateMinMax(s *bytes.Buffer, argType string, argName string, argMap string) {
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
	fmt.Fprintf(s, "        if (%v > *%v_max) {\n", argName, argMap)
	fmt.Fprintf(s, "            *%v_max = %v;\n", argMap, argName)
	fmt.Fprintf(s, "        }\n")
	fmt.Fprintf(s, "    }\n")
	fmt.Fprintf(s, "    }\n")

//	fmt.Fprintf(s, "    {\n")
//	fmt.Fprintf(s, "    i = 0;\n")
//	fmt.Fprintf(s, "    min = bpf_%v_lookup_elem(&i);\n", argMap)
//	fmt.Fprintf(s, "    if (min) {\n")
//	fmt.Fprintf(s, "        if (%v < *min)\n", argName)
//	fmt.Fprintf(s, "            *min = %v;\n", argName)
//	fmt.Fprintf(s, "    }\n")
//	fmt.Fprintf(s, "    i = 1;\n")
//	fmt.Fprintf(s, "    max = bpf_%v_lookup_elem(&i);\n", argMap)
//	fmt.Fprintf(s, "    if (max) {\n")
//	fmt.Fprintf(s, "        if (%v > *max)\n", argName)
//	fmt.Fprintf(s, "            *max = %v;\n", argName)
//	fmt.Fprintf(s, "    }\n")
//	fmt.Fprintf(s, "    }\n")
}

func generateUpdateFlags(s *bytes.Buffer, argType string, argName string, argMap string) {
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

func generateCopyFromUser(tracer *Tracer, s *bytes.Buffer, path string, argType string, argName string) {
    argName = fmt.Sprintf("v%v", tracer.v)
    fmt.Fprintf(s, "    %v %v;\n", argType, argName)
    fmt.Fprintf(s, "    bpf_probe_read_sleepable(&%v, sizeof(%v), (void *)%v);\n", argName, argName, path)
    tracer.v += 1
}

func generateRecursiveTracer(tracer *Tracer, arg prog.Type, s *bytes.Buffer, path string, fromPointer bool, offset *int) {
	argType := ""
	switch tt := arg.(type) {
	case *prog.BufferType:
		fmt.Fprintf(s, "    //arg %v %v %v\n", arg, arg.Name(), arg.FieldName())
        //*offset += 8*tt.Size();
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
        if *offset == 0 {
		    generateRecursiveTracer(tracer, arg.(*prog.PtrType).Type, s, path, true, offset)
        } else {
            srcPath := path + "." + arg.FieldName()
            generateRecursiveTracer(tracer, arg.(*prog.PtrType).Type, s, srcPath, true, offset)
        }
	case *prog.StructType:
		structPath := ""
		if fromPointer {
			structPath = fmt.Sprintf("v%v", tracer.v)
            generateCopyFromUser(tracer, s, path, argType, structPath)
		} else {
			structPath = path + "." + arg.FieldName()
		}

        tracer.AddStruct(arg.(*prog.StructType))
		for _, field := range arg.(*prog.StructType).StructDesc.Fields {
			generateRecursiveTracer(tracer, field, s, structPath, false, offset)
		}
	case *prog.LenType, *prog.IntType, *prog.ConstType:
        if c, ok := t.(*prog.ConstType); ok && c.IsPad {
            break
        }

		argName := ""
		if fromPointer {
			argName = fmt.Sprintf("v%v", tracer.v)
            generateCopyFromUser(tracer, s, path, argType, argName)
		} else {
			argName = path + "." + arg.FieldName()
		}

		tracer.NewMinMaxMap(argName, argType)
		generateUpdateMinMax(s, argType, argName, fixName(argName))
	case *prog.FlagsType:
		argName := ""
		if fromPointer {
			argName = fmt.Sprintf("v%v", tracer.v)
            generateCopyFromUser(tracer, s, path, argType, argName)
		} else {
			argName = path + "." + arg.FieldName()
		}

		tracer.NewFlagsMap(argName, argType)
		generateUpdateFlags(s, argType, argName, fixName(argName))
	case *prog.UnionType:
	case *prog.ArrayType:
	case *prog.BufferType:
	case *prog.ResourceType:
	default:
		fmt.Println("Unhandled type", t)
	}
    *offset += 4

}

func generateIoctlTracer(target *prog.Target, tracer *Tracer, name string, syscall *prog.Syscall) {
	s := tracer.NewSection()
	fmt.Fprintf(s, "void __always_inline %v(struct user_pt_regs *ctx) {\n", name)
	//fmt.Fprintf(s, "    int i = 0;\n")
	//fmt.Fprintf(s, "    uint32_t *min, *max;\n")
	path := "ctx->regs[2]"
    offset := 0
	generateRecursiveTracer(tracer, syscall.Args[2], s, path, true, &offset)
	fmt.Fprintf(s, "}\n\n")
}

func generateStruct(tracer *Tracer) {
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
}

func generateTracer(target *prog.Target, tracer *Tracer) { //, sections *[]*bytes.Buffer) {
	tracedSyscalls := map[string][]string{}

	// Find out device associated syscalls to be traced
	for _, syscall := range target.Syscalls {
		for _, args := range syscall.Args {
			if args.Name() == tracer.fdName {
				tracedSyscalls[syscall.CallName] = append(tracedSyscalls[syscall.CallName], syscall.Name)
			}
		}
	}

	licenseSec := tracer.NewSection()
	fmt.Fprintf(licenseSec, "char _license[] SEC(\"license\") = \"GPL\";\n")

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
				cmd, ok := target.SyscallMap[commands].Args[1].(*prog.ConstType)
				if !ok {
					failf("failed to get const command value for %v", commands)
				}
                if !strings.Contains(commands, "_compact_") {
                    traceFuncName := fmt.Sprintf("trace_ioctl_0x%x", cmd.Val)
                    generateIoctlTracer(target, tracer, traceFuncName, target.SyscallMap[commands])
                    fmt.Fprintf(s, "    case 0x%x: //%v\n", cmd.Val, commands)
                    fmt.Fprintf(s, "        %v(ctx);\n", traceFuncName)
                    fmt.Fprintf(s, "        break;\n")
                }
			}
			fmt.Fprintf(s, "    }\n")
			fmt.Fprintf(s, "    return 0;\n")
			fmt.Fprintf(s, "}\n\n")

		} else {

		}
	}

	initSec := tracer.NewSection()
	fmt.Fprintf(initSec, "void __always_inline init() {\n")
	fmt.Fprintf(initSec, "    int32_t i = 0;\n")
	fmt.Fprintf(initSec, "    int *init = bpf_init_map_lookup_elem(&i);\n")
	fmt.Fprintf(initSec, "    if (init && *init == 0) {\n")
	fmt.Fprintf(initSec, "        *init = 1;\n")
	for _, bpfMap := range (*tracer).minMaxMaps {
		fmt.Fprintf(initSec, "        i = 0;\n")
		fmt.Fprintf(initSec, "        %v *%v_min = bpf_%v_lookup_elem(&i);\n", bpfMap.datatype, bpfMap.name, bpfMap.name)
		fmt.Fprintf(initSec, "        if (%v_min) {\n", bpfMap.name)
		fmt.Fprintf(initSec, "            *%v_min = -1;\n", bpfMap.name)
		fmt.Fprintf(initSec, "        }\n")
		fmt.Fprintf(initSec, "        i = 1;\n")
		fmt.Fprintf(initSec, "        %v *%v_max = bpf_%v_lookup_elem(&i);\n", bpfMap.datatype, bpfMap.name, bpfMap.name)
		fmt.Fprintf(initSec, "        if (%v_max) {\n", bpfMap.name)
		fmt.Fprintf(initSec, "            *%v_max = 0;\n", bpfMap.name)
		fmt.Fprintf(initSec, "        }\n")
	}
	for _, bpfMap := range (*tracer).flagsMaps {
		fmt.Fprintf(initSec, "        i = 0;\n")
		fmt.Fprintf(initSec, "        %v *%v_zeros = bpf_%v_lookup_elem(&i);\n", bpfMap.datatype, bpfMap.name, bpfMap.name)
		fmt.Fprintf(initSec, "        if (%v_zeros) {\n", bpfMap.name)
		fmt.Fprintf(initSec, "            *%v_zeros = 0;\n", bpfMap.name)
		fmt.Fprintf(initSec, "        }\n")
		fmt.Fprintf(initSec, "        i = 1;\n")
		fmt.Fprintf(initSec, "        %v *%v_ones = bpf_%v_lookup_elem(&i);\n", bpfMap.datatype, bpfMap.name, bpfMap.name)
		fmt.Fprintf(initSec, "        if (%v_ones) {\n", bpfMap.name)
		fmt.Fprintf(initSec, "            *%v_ones = 0;\n", bpfMap.name)
		fmt.Fprintf(initSec, "        }\n")
	}
	fmt.Fprintf(initSec, "    }\n")
	fmt.Fprintf(initSec, "}\n\n")

	mapSec := tracer.NewSection()
	fmt.Fprintf(mapSec, "DEFINE_BPF_MAP(init_map, ARRAY, int, int, 2)\n")
	for _, bpfMap := range (*tracer).minMaxMaps {
		fmt.Fprintf(mapSec, "DEFINE_BPF_MAP(%v, ARRAY, int, %v, 2)\n", bpfMap.name, bpfMap.datatype)
	}
	for _, bpfMap := range (*tracer).flagsMaps {
		fmt.Fprintf(mapSec, "DEFINE_BPF_MAP(%v, ARRAY, int, %v, 2)\n", bpfMap.name, bpfMap.datatype)
	}
	fmt.Fprintf(mapSec, "\n")
    //fmt.Println("arg stack size ", len((*tracer).minMaxMaps)+4)

	helperSec := tracer.NewSection()
	fmt.Fprintf(helperSec, "\n")

	generateStruct(tracer)

	headerSec := tracer.NewSection()
	fmt.Fprintf(headerSec, "#include <linux/seccomp.h>\n")
	fmt.Fprintf(headerSec, "#include <linux/bpf.h>\n")
	fmt.Fprintf(headerSec, "#include <linux/unistd.h>\n")
	fmt.Fprintf(headerSec, "#include <linux/ptrace.h>\n")
	fmt.Fprintf(headerSec, "#include <bpf_helpers.h>\n")
	fmt.Fprintf(headerSec, "#include <linux/errno.h>\n")
	fmt.Fprintf(headerSec, "#include <sys/types.h>\n")
	for _, header := range tracer.headers {
		fmt.Fprintf(headerSec, "#include <%v>\n", header)
	}
	fmt.Fprintf(headerSec, "\n")

}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func main() {
	flag.Parse()

	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		fmt.Println(err)
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		fmt.Println(err)
	}

    out := cfg.TargetOS + "_" + cfg.TargetArch + "_" + *flagOut
	tracer, err := NewTracer(*flagFd, *flagEntry, out, *flagOutDir)
	if err != nil {
		fmt.Println(err)
	}

    _, err = os.Stat(tracer.outDir)
    if os.IsNotExist(err) {
        err = os.MkdirAll(tracer.outDir, 0755)
        if err != nil {
		    fmt.Println(err)
        }
    }

	generateTracer(target, tracer)

	tracer.WriteTracerFile()
	tracer.WriteAgentFile()
}
