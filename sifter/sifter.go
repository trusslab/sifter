package sifter

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

type Flags struct {
	Mode     string
	Trace    string
	Config   string
	Fd       string
	Dev      string
	Entry    string
	Outdir   string
	Out      string
	Unroll   int
	Iter     int
	TraceNum int
	Split    float64
	Verbose  int
}

type Context struct {
	name           string
	syscallNum     string
	syscallArgs    string
	defaultRetType string
	defaultRetVal  string
	errorRetVal    string
}

type AnalysisRound struct {
	flag   AnalysisFlag
	ac     []AnalysisConfig
//	traces []*Trace
	files []os.FileInfo
}

type AnalysisConfig struct {
	a    Analysis
	opt  int
}

type Sifter struct {
	mode           Mode
	verbose        Verbose
	target         *prog.Target
	structs        []*prog.StructType
	syscalls       []*prog.Syscall
	moduleSyscalls map[string][]*Syscall
	otherSyscall   *Syscall

	stackVarId int
	sections   map[string]*bytes.Buffer

	traceDir   string
	traceFiles []os.FileInfo
	traces     map[string]*Trace

	analysisRounds  []AnalysisRound
	analysesConfigs [][]AnalysisConfig
	analyses        []Analysis
	trainTestSplit  float64
	trainTestIter   int
	testFileIdxSets [][]int

	outName       string
	outSourceFile string
	outConfigFile string
	fdName        string
	devName       string
	loopUnroll    int
	depthLimit    int
	traceNum      int
	ctx           Context
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func isVariant(syscall string) bool {
	return strings.Contains(syscall, "$") || strings.Contains(syscall, "syz_")
}

func NewSifter(f Flags) (*Sifter, error) {
	cfg, err := mgrconfig.LoadFile(f.Config)
	if err != nil {
		failf("failed to load config file. err: %v", err)
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		failf("failed to get target %v/%v. err: %v", cfg.TargetOS, cfg.TargetArch, err)
	}

	s := new(Sifter)
	s.target = target
	s.fdName = f.Fd
	s.devName = f.Dev
	s.outName = f.Out + "_" + f.Mode
	s.outSourceFile = filepath.Join(f.Outdir, s.outName+".c")
	s.outConfigFile = filepath.Join(f.Outdir, s.outName+".cfg")
	s.loopUnroll = f.Unroll
	s.sections = make(map[string]*bytes.Buffer)
	s.syscalls = make([]*prog.Syscall, 512)
	s.moduleSyscalls = make(map[string][]*Syscall)
	s.traceDir = f.Trace
	s.traces = make(map[string]*Trace)
	s.stackVarId = 0
	s.depthLimit = math.MaxInt32
	s.verbose = Verbose(f.Verbose)
	s.trainTestSplit = f.Split
	s.trainTestIter = f.Iter
	s.traceNum = f.TraceNum

	if f.Mode == "tracer" {
		s.mode = TracerMode
		s.ctx = Context{
			name:           "sys_enter_args",
			syscallNum:     "id",
			syscallArgs:    "regs",
			defaultRetType: "int",
			defaultRetVal:  "0",
			errorRetVal:    "1",
		}
	} else if f.Mode == "filter" {
		s.mode = FilterMode
		s.ctx = Context{
			name: "struct seccomp_data",
			syscallNum: "nr",
			syscallArgs: "args",
			defaultRetType: "int",
			defaultRetVal: "SECCOMP_RET_ALLOW",
			errorRetVal: "SECCOMP_RET_ERRNO",
		}
	} else if f.Mode == "analyzer" {
		s.mode = AnalyzerMode
		s.ctx = Context{
			name:           "sys_enter_args",
			syscallNum:     "id",
			syscallArgs:    "regs",
			defaultRetType: "int",
			defaultRetVal:  "0",
			errorRetVal:    "1",
		}
	} else {
		return nil, fmt.Errorf("invalid mode. expected \"tracer\"/\"filter\"")
	}

	_, err = os.Stat(f.Outdir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(f.Outdir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create output dir %v", f.Outdir)
		}
	}

	s.otherSyscall = new(Syscall)
	s.otherSyscall.name = "other_syscalls"
	s.otherSyscall.traceSizeBits = 18
	s.otherSyscall.syscalls = make(map[uint64]*Syscall)

	for _, syscall := range s.target.Syscalls {
		// Build original syscall list
		//if !strings.Contains(syscall.Name, "$") && !strings.Contains(syscall.Name, "syz_") {
		if !isVariant(syscall.Name) {
			s.syscalls[syscall.NR] = syscall
		}
		// Find out path of driver
		if len(s.devName) == 0 && syscall.CallName == "syz_open_dev" {
			if ret, ok := syscall.Ret.(*prog.ResourceType); ok {
				if ret.String() == s.fdName {
					if devName, ok := extractStringConst(syscall.Args[0]); ok {
						s.devName = filepath.Base(strings.Replace(devName, "#", "0", 1))
					}
				}
			}
		}
		// Scan for syscalls using the kernel module
		toModule := false
		for _, arg := range syscall.Args {
			if arg.Name() == s.fdName {
				toModule = true
			}
//			if vma, ok := arg.(*prog.VmaType); ok {
//					fmt.Printf("vma %v %v\n", syscall.Name, vma.FldName)
//			}
//			if vma, ok := arg.(*prog.VmaType); ok && vma.FldName == "addr" {
//				callName := syscall.CallName
//				if !isVariant(syscall.Name) {
//					//fmt.Printf("vma %v\n", syscall.Name)
//					s.moduleSyscalls[callName] = append(s.moduleSyscalls[callName], s.target.SyscallMap[callName])
//				}
//			}
		}

		if toModule {
			callName := syscall.CallName
			if callName == "ioctl" {
				fmt.Printf("trace syscall %v\n", syscall.Name)
				tracedSyscall := new(Syscall)
				tracedSyscall.name = fixName(syscall.Name)
				tracedSyscall.def = syscall
				tracedSyscall.argMaps = []*ArgMap{}
				tracedSyscall.traceSizeBits = 12
				s.moduleSyscalls[callName] = append(s.moduleSyscalls[callName], tracedSyscall)
			} else {
				fmt.Printf("trace syscall %v\n", callName)
				tracedSyscall := new(Syscall)
				tracedSyscall.name = fixName(syscall.Name)
				tracedSyscall.def = s.target.SyscallMap[callName]
				tracedSyscall.argMaps = []*ArgMap{}
				tracedSyscall.traceSizeBits = 10
				s.moduleSyscalls[callName] = append(s.moduleSyscalls[callName], tracedSyscall)
			}
		} else if _, ok := s.otherSyscall.syscalls[syscall.NR]; !ok {
			otherSyscall := new(Syscall)
			otherSyscall.name = fixName(syscall.Name)
			otherSyscall.def = syscall
			otherSyscall.traceSizeBits = 18
			s.otherSyscall.syscalls[syscall.NR] = otherSyscall
		}
	}

	if len(s.devName) == 0 {
		return nil, fmt.Errorf("cannot find dev for %v", s.fdName)
	} else {
		fmt.Printf("trace dev: %v\n", s.devName)
	}

	syscallMax := 0
	for i, syscall := range s.syscalls {
		if syscall != nil {
			syscallMax = i
		}
	}
	s.syscalls = s.syscalls[:syscallMax]

	return s, nil
}

func (sifter *Sifter) Mode() Mode {
	return sifter.mode
}

func (sifter *Sifter) Iter() int {
	return sifter.trainTestIter
}

func (sifter *Sifter) CreateAnalysisRound(round int, flag AnalysisFlag, files []os.FileInfo) int {
	sifter.analysisRounds = append(sifter.analysisRounds, AnalysisRound{flag, make([]AnalysisConfig, 0), files})
	return len(sifter.analysisRounds)-1
}

func (sifter *Sifter) AddAnalysisToRound(round int, a Analysis, opt int) {
	if len(sifter.analysisRounds) < round+1 {
		return
	}

	analysisExist := false
	for _, analysis := range sifter.analyses {
		if analysis.String() == a.String() {
			analysisExist = true
		}
	}

	if !analysisExist {
		sifter.analyses = append(sifter.analyses, a)
		a.Init(&sifter.moduleSyscalls)
	}

	sifter.analysisRounds[round].ac = append(sifter.analysisRounds[round].ac, AnalysisConfig{a, opt})
}

func (sifter *Sifter) ClearAnalysis() {
	sifter.analyses = make([]Analysis, 0)
	sifter.analysisRounds = make([]AnalysisRound, 0)
}

func (sifter *Sifter) GetAnalysis(name string) Analysis {
	for _, a := range sifter.analyses {
		if a.String() == name {
			return a
		}
	}
	return nil
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

func (sifter *Sifter) GenerateStackVar(name *string, argType string) string {
	var s strings.Builder
	*name = fmt.Sprintf("v%v", sifter.stackVarId)
	fmt.Fprintf(&s, "%v %v;\n", argType, *name)
	sifter.stackVarId += 1
	return s.String()
}

func (sifter *Sifter) GenerateCopyFromUser(src string, dst string, off string) string {
	var s strings.Builder
	fmt.Fprintf(&s, "if (bpf_probe_read_sleepable(&%v, sizeof(%v), (void *)%v+%v) < 0)\n", dst, dst, src, off)
	fmt.Fprintf(&s, "    return %v;\n", sifter.ctx.errorRetVal)
	return s.String()
}

func (sifter *Sifter) GenerateArgMapLookup(argMap string, argType string) string {
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
	case *prog.ConstType:
		if !t.IsPad {
			ret = false
		}
	case *prog.LenType, *prog.IntType, *prog.FlagsType:
		ret = false
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
	case *prog.ArrayType:
		if isVLR, _, _ := IsVarLenRecord(t); isVLR {
			name = "buffer_512_t"
		} else {
			if structArg, ok := t.Type.(*prog.StructType); ok {
				name = fmt.Sprintf("struct %v", structArg.Name())
			} else {
				name = "Unhandled array"
			}
		}
	case *prog.ResourceType:
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

func (sifter *Sifter) CheckArgConstraints(syscall *Syscall, arg prog.Type, parentArgMap *ArgMap, depth int) []ArgConstraint {
	var constraints []ArgConstraint
	for _, analysis := range sifter.analyses {
		if c := analysis.GetArgConstraint(syscall, arg, parentArgMap, depth); c != nil {
			constraints = append(constraints, c)
		}
	}
	return constraints
}

func (sifter *Sifter) GetArrayLen(syscall *Syscall, parentArgMap *ArgMap, depth int, arrayFieldName string) (*prog.Type, int) {
	var arrayLen *prog.Type
	if structArg, ok := parentArgMap.arg.(*prog.StructType); ok {
		for i, field := range(structArg.Fields) {
			if lenArg, ok := field.(*prog.LenType); ok && lenArg.Path[0] == arrayFieldName {
				arrayLen = &parentArgMap.arg.(*prog.StructType).Fields[i]
			}
		}
		if arrayLen != nil {
			constraints := sifter.CheckArgConstraints(syscall, *arrayLen, parentArgMap, depth)
			for _, c := range constraints {
				if rangeConstraint, ok := c.(*RangeConstraint); ok {
					return arrayLen, int(rangeConstraint.u)
				}
			}
			return arrayLen, -1
		}
	}
	return nil, 0
}

func minElementSize(arg prog.Type) int {
	minSize := math.MaxInt32
	switch t := arg.(type) {
	case *prog.StructType:
		minSize = int(t.Size())
	case *prog.UnionType:
		for _, unionField := range(t.Fields) {
			if structField, ok := unionField.(*prog.StructType); ok {
				if int(structField.Size()) < minSize {
					minSize = int(structField.Size())
				}
			}
		}
	}
	return minSize
}

func (sifter *Sifter) GenerateArgTracer(s *bytes.Buffer, syscall *Syscall, arg prog.Type, srcPath string, argName string, dstPath string, parentArgMap *ArgMap, depth *int) {
	_, thisIsPtr := arg.(*prog.PtrType)
	if *depth == 0 && !thisIsPtr || *depth >= sifter.depthLimit || isIgnoredArg(arg) {
		return
	}

	fmt.Fprintf(s, "    %v", typeDebugInfo(arg))

	accessOp := ""
	derefOp := ""
	dataInStack := true
	argType := argTypeName(arg)
	if *depth == 0 {
		argName = argName + "_" + arg.FieldName()
	} else if dstPath == "" {
		// Parent arg is a pointer and the userspace data hasn't been copied to stack
		dataInStack = false

		syscall.AddArgMap(arg, argName, srcPath, argType)
		for _, argMap := range syscall.argMaps {
			if argMap.name == argName {
				parentArgMap = argMap
			}
		}
		parentArgMap = syscall.argMaps[len(syscall.argMaps)-1]

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
	fmt.Printf("%v %v\n", syscall.name, argName)

	switch t := arg.(type) {
	case *prog.PtrType:
		if !dataInStack {
			stackVarName := ""
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateStackVar(&stackVarName, argType), 1))
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateCopyFromUser(srcPath, stackVarName, "0"), 1))
			srcPath = stackVarName
			if sifter.mode == TracerMode || sifter.mode == AnalyzerMode {
				fmt.Fprintf(s, "    %v", indent(sifter.GenerateArgMapLookup(argName, argType), 1))
			}
		}
		if *depth > 0 {
			if sifter.mode == TracerMode || sifter.mode == AnalyzerMode {
				fmt.Fprintf(s, "    %v%v = %v;\n", derefOp, dstPath, srcPath)
			}
		}
		*depth += 1
		sifter.GenerateArgTracer(s, syscall, t.Type, srcPath, argName, "", parentArgMap, depth)
		*depth -= 1
	case *prog.StructType:
		if !dataInStack {
			stackVarName := ""
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateStackVar(&stackVarName, argType), 1))
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateCopyFromUser(srcPath, stackVarName, "0"), 1))
			srcPath = stackVarName
			if sifter.mode == TracerMode || sifter.mode == AnalyzerMode {
				fmt.Fprintf(s, "    %v", indent(sifter.GenerateArgMapLookup(argName, argType), 1))
			}
		}
		sifter.AddStruct(t)
		for _, field := range t.Fields {
			sifter.GenerateArgTracer(s, syscall, field, srcPath, argName, dstPath+accessOp, parentArgMap, depth)
		}
	case *prog.LenType, *prog.IntType, *prog.ConstType, *prog.FlagsType:
		if !dataInStack {
			stackVarName := ""
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateStackVar(&stackVarName, argType), 1))
			fmt.Fprintf(s, "    %v", indent(sifter.GenerateCopyFromUser(srcPath, stackVarName, "0"), 1))
			srcPath = stackVarName
			if sifter.mode == TracerMode || sifter.mode == AnalyzerMode {
				fmt.Fprintf(s, "    %v", indent(sifter.GenerateArgMapLookup(argName, argType), 1))
			}
		}
		if sifter.mode == TracerMode || sifter.mode == AnalyzerMode {
			fmt.Fprintf(s, "    %v%v = %v;\n", derefOp, dstPath, srcPath)
		}
		if sifter.mode == FilterMode {
			constraints := sifter.CheckArgConstraints(syscall, arg, parentArgMap, *depth)
			for _, c := range constraints {
				fmt.Fprintf(s, "    %v", indent(c.String(srcPath, "ret", sifter.ctx.defaultRetVal, sifter.ctx.errorRetVal), 1))
			}
		}
	case *prog.ArrayType:
		if t.IsVarlen {
			isVLR := false
			vlrHeaderSize := 0
			if isVLR, vlrHeaderSize, _ = IsVarLenRecord(t); isVLR {
				syscall.AddVlrMap(t, parentArgMap, argName)
			} else {
				sifter.AddStruct(t.Type.(*prog.StructType))
			}
			if sifter.mode == FilterMode {
				parentVarName := strings.Split(srcPath, ".")[0]
				arrayFieldName := strings.Split(srcPath, ".")[1]
				arrayLen, arrayLenRangeEnd := sifter.GetArrayLen(syscall, parentArgMap, *depth, arrayFieldName)
				arrayLenName := fmt.Sprintf("%v.%v", parentVarName, (*arrayLen).FieldName())
				if !dataInStack {
					stackVarName := ""
					vlrHeaderVarName := ""
					vlrRecordTypes := make(map[string]string)
					vlrTypeStackVarNames := make(map[string]string)
					if isVLR {
						headerType := fmt.Sprintf("uint%d_t", vlrHeaderSize*8)
						fmt.Fprintf(s, "    %v", indent(sifter.GenerateStackVar(&vlrHeaderVarName, headerType), 1))
						for _, field := range(t.Type.(*prog.UnionType).Fields) {
							vlrRecordType := ""
							if len(field.(*prog.StructType).Fields) > 1 {
								//vlrRecordType = fmt.Sprintf("struct %v", field.(*prog.StructType).Fields[1].Name())
								vlrRecordType = argTypeName(field.(*prog.StructType).Fields[1])
								if _, ok := vlrTypeStackVarNames[vlrRecordType]; !ok {
									if structArg, ok := field.(*prog.StructType).Fields[1].(*prog.StructType); ok {
										sifter.AddStruct(structArg)
									}
									newStackVarName := ""
									fmt.Fprintf(s, "    %v", indent(sifter.GenerateStackVar(&newStackVarName, vlrRecordType), 1))
									vlrTypeStackVarNames[vlrRecordType] = newStackVarName
								}
							}
							vlrRecordTypes[field.FieldName()] = vlrRecordType
						}
					} else {
						fmt.Fprintf(s, "    %v", indent(sifter.GenerateStackVar(&stackVarName, argType), 1))
					}
					endLabelName := fmt.Sprintf("array_%v_end", stackVarName)
					//newSrcPath := stackVarName
					fmt.Fprintf(s, "    int offset = 0;\n")
					if (*arrayLen).(*prog.LenType).BitSize == 0 {
						fmt.Fprintf(s, "    int end = %v * sizeof(%v);\n", arrayLenName, stackVarName)
					} else {
						fmt.Fprintf(s, "    int end = %v;\n", arrayLenName)
						arrayLenRangeEnd = arrayLenRangeEnd / minElementSize(t.Type)
					}
					arrayLenRangeMax := 20
					for i := 0; i < arrayLenRangeEnd && i < arrayLenRangeMax; i++ {
						if isVLR {
							fmt.Fprintf(s, "    %v", indent(sifter.GenerateCopyFromUser(srcPath, vlrHeaderVarName, "offset"), 1))
							fmt.Fprintf(s, "    offset += sizeof(%v);\n", vlrHeaderVarName)
							fmt.Fprintf(s, "    switch(%v) {\n", vlrHeaderVarName)
							for _, field := range(t.Type.(*prog.UnionType).Fields) {
								fmt.Fprintf(s, "    case 0x%x:\n", field.(*prog.StructType).Fields[0].(*prog.ConstType).Val)
								if vlrRecordType, ok := vlrRecordTypes[field.FieldName()]; ok && vlrRecordType != "" {
									fmt.Fprintf(s, "        %v\n", indent(sifter.GenerateCopyFromUser(srcPath, vlrTypeStackVarNames[vlrRecordType], "offset"), 2))
									fmt.Fprintf(s, "        offset += sizeof(%v);\n", vlrTypeStackVarNames[vlrRecordType])
								}
								fmt.Fprintf(s, "        break;\n")
							}
							fmt.Fprintf(s, "    }\n")
							fmt.Fprintf(s, "    if (offset >= end) {\n")
							fmt.Fprintf(s, "        goto %v;\n", endLabelName)
							fmt.Fprintf(s, "    }\n")
						} else {
							fmt.Fprintf(s, "    %v\n", indent(sifter.GenerateCopyFromUser(srcPath, stackVarName, "offset"), 1))
							//sifter.AddStruct(t.Type.(*prog.StructType))
							//for _, field := range t.Fields {
							//	sifter.GenerateArgTracer(s, syscall, field, newSrcPath, argName, dstPath+accessOp, parentArgMap, depth)
							//}
							fmt.Fprintf(s, "    offset += sizeof(%v);\n", stackVarName)
							fmt.Fprintf(s, "    if (offset + sizeof(%v) > end) {\n", stackVarName)
							fmt.Fprintf(s, "        goto %v;\n", endLabelName)
							fmt.Fprintf(s, "    }\n")
						}
					}
					fmt.Fprintf(s, "%v:\n", endLabelName)
				}
			}
		} else {
			for i := 0; i < int(t.RangeBegin); i++ {
				if sifter.mode == TracerMode || sifter.mode == AnalyzerMode {
					fmt.Fprintf(s, "    %v%v[%v] = %v[%v];\n", derefOp, dstPath, i, srcPath, i)
				}
				if sifter.mode == FilterMode {
					constraints := sifter.CheckArgConstraints(syscall, arg, parentArgMap, *depth)
					for _, c := range constraints {
						fmt.Fprintf(s, "    %v", indent(c.String(fmt.Sprintf("%v[%v]", srcPath, i), "ret", sifter.ctx.defaultRetVal, sifter.ctx.errorRetVal), 1))
					}
				}
			}
		}
	}
}

func (sifter *Sifter) GenerateOtherSyscallsTracer() {
	s := sifter.GetSection("level2_tracing")
	fmt.Fprintf(s, "%v __always_inline trace_other_syscalls(%v *ctx, uint64_t pid, uint64_t flag) {\n", sifter.ctx.defaultRetType, sifter.ctx.name)
	fmt.Fprintf(s, "    %v ret = %v;\n", sifter.ctx.defaultRetType, sifter.ctx.defaultRetVal)
	if sifter.mode == TracerMode || sifter.mode == AnalyzerMode {
		fmt.Fprintf(s, "    int i = 0;\n")
		fmt.Fprintf(s, "    uint32_t *ctr = bpf_other_syscalls_ctr_lookup_elem(&i);\n")
		fmt.Fprintf(s, "    if (!ctr)\n")
		fmt.Fprintf(s, "    	return 1;\n")
		fmt.Fprintf(s, "    int idx = *ctr & 0x%08x;\n", sifter.otherSyscall.TraceSizeMask())
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "    syscall_ent_t *ent = bpf_other_syscalls_ent_lookup_elem(&idx);\n")
		fmt.Fprintf(s, "    if (ent) {\n")
		fmt.Fprintf(s, "    	ent->ts = bpf_ktime_get_ns();\n")
		fmt.Fprintf(s, "    	ent->id = pid | flag;\n")
		fmt.Fprintf(s, "    	ent->args[0] = ctx->regs[0];\n")
		fmt.Fprintf(s, "    	ent->args[1] = ctx->regs[1];\n")
		fmt.Fprintf(s, "    	ent->args[2] = ctx->regs[2];\n")
		fmt.Fprintf(s, "    	ent->args[3] = ctx->regs[3];\n")
		fmt.Fprintf(s, "    	ent->args[4] = ctx->regs[4];\n")
		fmt.Fprintf(s, "    	ent->args[5] = ctx->regs[5];\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "    int *nr = bpf_other_syscalls_nr_lookup_elem(&idx);\n")
		fmt.Fprintf(s, "    if (!nr)\n")
		fmt.Fprintf(s, "    	return 1;\n")
		fmt.Fprintf(s, "    *nr = ctx->id;\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "    *ctr = *ctr + 1;\n")
	}
	fmt.Fprintf(s, "    return ret;\n")
	fmt.Fprintf(s, "}\n\n")
}

func (sifter *Sifter) GenerateSyscallTracer(syscall *Syscall) {
	s := sifter.GetSection("level2_tracing")
	fmt.Fprintf(s, "%v __always_inline trace_%v(%v *ctx, uint64_t pid) {\n", sifter.ctx.defaultRetType, syscall.name, sifter.ctx.name)
	fmt.Fprintf(s, "    %v ret = %v;\n", sifter.ctx.defaultRetType, sifter.ctx.defaultRetVal)
	if sifter.mode == TracerMode || sifter.mode == AnalyzerMode {
		fmt.Fprintf(s, "    int i = 0;\n")
		fmt.Fprintf(s, "    uint32_t *ctr = bpf_%v_ctr_lookup_elem(&i);\n", syscall.name)
		fmt.Fprintf(s, "    if (!ctr)\n")
		fmt.Fprintf(s, "    	return 1;\n")
		fmt.Fprintf(s, "    int idx = *ctr & 0x%08x;\n", syscall.TraceSizeMask())
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
		for i, arg := range syscall.def.Args {
			path := fmt.Sprintf("ctx->%v[%v]", sifter.ctx.syscallArgs, i)
			offset := 0
			sifter.GenerateArgTracer(s, syscall, arg, path, syscall.name, "", nil, &offset)
		}
		fmt.Fprintf(s, "    *ctr = *ctr + 1;\n")
	}
	if sifter.mode == FilterMode {
		fmt.Fprintf(s, "    struct syscall_id_key id_key;\n")
		fmt.Fprintf(s, "    id_key.nr = ctx->nr;\n")
		fmt.Fprintf(s, "    id_key.tag[0] = 0;\n")
		fmt.Fprintf(s, "    id_key.tag[1] = 0;\n")
		fmt.Fprintf(s, "    id_key.tag[2] = 0;\n")
		for i, arg := range syscall.def.Args {
			path := fmt.Sprintf("ctx->%v[%v]", sifter.ctx.syscallArgs, i)
			offset := 0
			sifter.GenerateArgTracer(s, syscall, arg, path, syscall.name, "", nil, &offset)
			if sifter.mode == FilterMode {
				constraints := sifter.CheckArgConstraints(syscall, arg, nil, 0)
				for _, c := range constraints {
					fmt.Fprintf(s, "    %v", indent(c.String(path, "ret", sifter.ctx.defaultRetVal, sifter.ctx.errorRetVal), 1))
				}
			}
		}
		if a := sifter.GetAnalysis("pattern analysis"); a != nil {
			fmt.Fprintf(s, "    bpf_syscall_id_curr_update_elem(&pid, &id_key, BPF_ANY);\n")
		}
	}
	fmt.Fprintf(s, "    return ret;\n")
	fmt.Fprintf(s, "}\n\n")
}

func (sifter *Sifter) GenerateIoctlTracer(syscalls []*Syscall) {
	s := sifter.GetSection("level1_tracing")
	fmt.Fprintf(s, "%v __always_inline trace_ioctl(%v *ctx, uint64_t pid) {\n", sifter.ctx.defaultRetType, sifter.ctx.name)
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

func (sifter *Sifter) SyscallNumber(name string) uint64 {
	for _, constant := range sifter.target.Consts {
		if constant.Name == "__NR_"+name {
			return constant.Value
		}
	}
	failf("cannot find syscall number for %v", name)
	return 0xffffffffffffffff
}

func ToFdMask(syscall *prog.Syscall) uint8 {
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
	sifter.GenerateOtherSyscallsTracer()

	if sifter.mode == TracerMode {
		s := sifter.GetSection("main")
		fmt.Fprintf(s, "void __always_inline trace_syscalls(sys_enter_args *ctx, uint64_t pid) {\n")
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
		fmt.Fprintf(s, "        } else {\n")
		fmt.Fprintf(s, "            trace_other_syscalls(ctx, pid, 0x40000000);\n")
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "    } else {\n")
		fmt.Fprintf(s, "        trace_other_syscalls(ctx, pid, 0);\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    return;\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "SEC(\"tracepoint/raw_syscalls/sys_enter\")\n")
		fmt.Fprintf(s, "int sys_enter_prog(sys_enter_args *ctx) {\n")
		fmt.Fprintf(s, "    uint32_t pid = is_current_pid_traced();\n")
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
		fmt.Fprintf(s, "		uint32_t pid = is_current_pid_traced();\n")
		fmt.Fprintf(s, "		if (pid != 0) {\n")
		fmt.Fprintf(s, "			comm_string comm;\n")
		fmt.Fprintf(s, "			bpf_get_current_comm(&comm, 16);\n")
		fmt.Fprintf(s, "			bpf_traced_pid_comm_map_update_elem(&pid, &comm, BPF_ANY);\n")
		fmt.Fprintf(s, "		}\n")
		fmt.Fprintf(s, "	} else if (is_forking_syscall(nr, is_32bit)) {\n")
		fmt.Fprintf(s, "		if (is_current_pid_traced()) {\n")
		fmt.Fprintf(s, "			bpf_traced_pid_map_update_elem(&child_pid, &data, BPF_ANY);\n")
		fmt.Fprintf(s, "		}\n")
		fmt.Fprintf(s, "	}\n")
		fmt.Fprintf(s, "	return 0;\n")
		fmt.Fprintf(s, "}\n")
	}
	if sifter.mode == FilterMode {
		s := sifter.GetSection("main")
		fmt.Fprintf(s, "SEC(\"seccomp\")\n")
		fmt.Fprintf(s, "int filter(struct seccomp_data *ctx)\n")
		fmt.Fprintf(s, "{\n")
		fmt.Fprintf(s, "    uint32_t nr = ctx->nr;\n")
		fmt.Fprintf(s, "    uint64_t pid = bpf_get_current_pid_tgid();\n")
		fmt.Fprintf(s, "    int ret = SECCOMP_RET_ALLOW;\n")
		fmt.Fprintf(s, "    if (nr == %v) {\n", sifter.SyscallNumber("openat"))
		fmt.Fprintf(s, "        check_dev_open(ctx);\n")
		fmt.Fprintf(s, "    } else if (nr != %v && check_syscall_fd(ctx)) {\n", sifter.SyscallNumber("close"))
		fmt.Fprintf(s, "        if (nr == %v) {\n", sifter.SyscallNumber("ioctl"))
		fmt.Fprintf(s, "            ret = trace_ioctl(ctx, pid);\n")
		for key, syscalls := range sifter.moduleSyscalls {
			if key != "ioctl" && key != "close" {
				fmt.Fprintf(s, "        } else if (nr == %v) {\n", sifter.SyscallNumber(key))
				fmt.Fprintf(s, "            ret = trace_%v(ctx, pid);\n", syscalls[0].name)
			}
		}
		fmt.Fprintf(s, "        } else {\n")
		fmt.Fprintf(s, "            ret = SECCOMP_RET_ERRNO | EINVAL;\n")
		fmt.Fprintf(s, "        }\n")
		if a := sifter.GetAnalysis("pattern analysis"); a != nil {
			fmt.Fprintf(s, "        if (ret == SECCOMP_RET_ALLOW) {\n")
			fmt.Fprintf(s, "            if (check_seq(pid)) {\n")
			fmt.Fprintf(s, "                ret = SECCOMP_RET_ALLOW;\n")
			fmt.Fprintf(s, "            } else {\n")
			fmt.Fprintf(s, "                ret = SECCOMP_RET_ERRNO | EINVAL;\n")
			fmt.Fprintf(s, "            }\n")
			fmt.Fprintf(s, "        }\n")
			fmt.Fprintf(s, "        bpf_syscall_id_curr_delete_elem(&pid);\n")
		}
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    return ret;\n")
		fmt.Fprintf(s, "}\n")
	}
}

func (sifter *Sifter) GenerateMapSection() {
	s := sifter.GetSection("map")
	fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_fd_mask, ARRAY, int, uint8_t, %v);\n", len(sifter.syscalls))

	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "DEFINE_BPF_MAP(traced_pid_map, HASH, uint32_t, uint32_t, 1024);\n")
		fmt.Fprintf(s, "DEFINE_BPF_MAP(traced_pid_comm_map, HASH, uint32_t, comm_string, 1024);\n")
		fmt.Fprintf(s, "DEFINE_BPF_MAP(target_prog_comm_map, HASH, comm_string, uint32_t, 128);\n")
		for _, syscalls := range sifter.moduleSyscalls {
			for _, syscall := range syscalls {
				fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_ctr, ARRAY, int, uint32_t, 1)\n", syscall.name)
				fmt.Fprintf(s, "DEFINE_BPF_MAP(%v_ent, ARRAY, int, syscall_ent_t, %v)\n", syscall.name, syscall.TraceSize())
				for _, arg := range syscall.argMaps {
					fmt.Fprintf(s, "DEFINE_BPF_MAP(%v, ARRAY, int, %v, %v)\n", arg.name, arg.datatype, syscall.TraceSize())
				}
			}
		}
		fmt.Fprintf(s, "DEFINE_BPF_MAP(other_syscalls_ctr, ARRAY, int, uint32_t, 1)\n")
		fmt.Fprintf(s, "DEFINE_BPF_MAP(other_syscalls_ent, ARRAY, int, syscall_ent_t, %v)\n", sifter.otherSyscall.TraceSize())
		fmt.Fprintf(s, "DEFINE_BPF_MAP(other_syscalls_nr, ARRAY, int, int, %v)\n", sifter.otherSyscall.TraceSize())
	}
	if sifter.mode == FilterMode {
		if a := sifter.GetAnalysis("pattern analysis"); a != nil {
			pa, _ := a.(*PatternAnalysis)
			fmt.Fprintf(s, "#define SC_ID_MAX %d\n", len(pa.uniqueSyscallList))
			fmt.Fprintf(s, "#define SC_SEQ_MAX %d\n", len(pa.seqTreeList))
			fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_id_map, HASH, struct syscall_id_key, uint8_t, SC_ID_MAX);\n")
			fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_id_curr, HASH, uint64_t, struct syscall_id_key, 128);\n")
			fmt.Fprintf(s, "DEFINE_BPF_MAP(syscall_seq_tree, ARRAY, int, struct syscall_seq, SC_SEQ_MAX);\n")
			fmt.Fprintf(s, "DEFINE_BPF_MAP_F(syscall_seq_curr, ARRAY, int, struct syscall_seq_curr, 1, BPF_F_LOCK);\n")
		}
		fmt.Fprintf(s, "DEFINE_BPF_MAP(init_map, ARRAY, int, int, 1);\n")
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
					fieldType = "char"
				} else if field.Name() == "array" {
					fieldIsArray = true
					fieldLen = tt.Size()
					fieldType = "char"
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
				//fmt.Fprintf(s, "    //arg %v %v %v\n", arg, arg.Name(), arg.FieldName())
				fieldIsArray = true
				if field.(*prog.ArrayType).IsVarlen {
					fieldLen = 0
				} else {
					fieldLen = (8 * tt.Size() / field.(*prog.ArrayType).Type.TypeBitSize())
				}
				//fieldLen = (field.Size())
				//fieldType = fmt.Sprintf("uint%v_t", field.(*prog.ArrayType).Type.TypeBitSize())
				fieldType = fmt.Sprintf("uint%v_t", tt.Type.TypeBitSize())
			case *prog.StructType:
				//fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
				fieldType = fmt.Sprintf("struct %v", tt.String())
//			case *prog.UnionType:
//				fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
			default:
				fieldType = fmt.Sprintf("uint%v_t", 8*tt.Size())
				//fmt.Fprintf(s, "    //arg %v %v %v %v %v\n", arg, arg.Name(), arg.FieldName(), arg.Size(), tt)
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
	if sifter.mode == FilterMode {
		fmt.Fprintf(s, "struct syscall_id_key {\n")
		fmt.Fprintf(s, "	uint32_t nr;\n")
		fmt.Fprintf(s, "	uint32_t tag[3];\n")
		fmt.Fprintf(s, "};\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "#define SC_SEQ_LEN_MAX 10\n")
		fmt.Fprintf(s, "struct syscall_seq {\n")
		fmt.Fprintf(s, "	uint8_t id[SC_SEQ_LEN_MAX];\n")
		fmt.Fprintf(s, "};\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "struct syscall_seq_curr {\n")
		fmt.Fprintf(s, "	struct bpf_spin_lock lock;\n")
		fmt.Fprintf(s, "	int l;\n")
		fmt.Fprintf(s, "	int u;\n")
		fmt.Fprintf(s, "	uint32_t idx;\n")
		fmt.Fprintf(s, "	uint64_t seqs;\n")
		fmt.Fprintf(s, "	uint8_t last_seq_id;\n")
		fmt.Fprintf(s, "};\n")
	}
}

func (sifter *Sifter) GenerateHelperSection() {
	s := sifter.GetSection("helper")
	fmt.Fprintf(s, "#define bpf_printk(fmt, ...)                                   \\\n")
	fmt.Fprintf(s, "({                                                             \\\n")
	fmt.Fprintf(s, "    char ____fmt[] = fmt;                                      \\\n")
	fmt.Fprintf(s, "    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \\\n")
	fmt.Fprintf(s, "})\n")
	fmt.Fprintf(s, "\n")
	if sifter.mode == TracerMode {
		fmt.Fprintf(s, "int __always_inline get_current_pid() {\n")
		fmt.Fprintf(s, "    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();\n")
		fmt.Fprintf(s, "    uint32_t pid = current_pid_tgid & 0x00000000ffffffff;\n")
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
		fmt.Fprintf(s, "uint32_t __always_inline is_current_pid_traced() {\n")
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
	if sifter.mode == FilterMode {
		if a := sifter.GetAnalysis("pattern analysis"); a != nil {
			pa, _ := a.(*PatternAnalysis)
			fmt.Fprintf(s, "bool __always_inline check_seq_order(uint8_t seq_id, uint64_t seq_seq, uint64_t seqs_curr) {\n")
			fmt.Fprintf(s, "    uint64_t seq_order;\n")
			fmt.Fprintf(s, "    switch (seq_id) {\n")
			for pi, _ := range pa.seqTreeList {
				fmt.Fprintf(s, "    case %d: seq_order= 0x%x; break;\n", pi, pa.seqOrderList[pi])
			}
			fmt.Fprintf(s, "    default: return false;\n")
			fmt.Fprintf(s, "    }\n")
			fmt.Fprintf(s, "    if ((seq_order & seqs_curr) == 0 && ((1 << seq_id) & seq_seq) != 0) {\n")
			fmt.Fprintf(s, "        return true;\n")
			fmt.Fprintf(s, "    } else {\n")
			fmt.Fprintf(s, "        return false;\n")
			fmt.Fprintf(s, "    }\n")
			fmt.Fprintf(s, "}\n")
			fmt.Fprintf(s, "\n")
			fmt.Fprintf(s, "bool __always_inline check_seq(uint64_t pid) {\n")
			fmt.Fprintf(s, "    int i = 0;\n")
			fmt.Fprintf(s, "    struct syscall_id_key *id_key_ptr = bpf_syscall_id_curr_lookup_elem(&pid);\n")
			fmt.Fprintf(s, "    if (!id_key_ptr) {\n")
			fmt.Fprintf(s, "        goto return_error;\n")
			fmt.Fprintf(s, "    }\n")
			fmt.Fprintf(s, "    struct syscall_id_key id_key;\n")
			fmt.Fprintf(s, "    id_key.nr = id_key_ptr->nr;\n")
			fmt.Fprintf(s, "    id_key.tag[0] = id_key_ptr->tag[0];\n")
			fmt.Fprintf(s, "    id_key.tag[1] = id_key_ptr->tag[1];\n")
			fmt.Fprintf(s, "    id_key.tag[2] = id_key_ptr->tag[2];\n")
			fmt.Fprintf(s, "    uint8_t *this_id = bpf_syscall_id_map_lookup_elem(&id_key);\n")
			fmt.Fprintf(s, "    if (!this_id) {\n")
			fmt.Fprintf(s, "        bpf_printk(\"id lookup failed nr = %%d\\n\", id_key.nr);\n")
			fmt.Fprintf(s, "        bpf_printk(\"id lookup failed %%x %%x %%x\\n\", id_key.tag[0], id_key.tag[1], id_key.tag[2]);\n")
			fmt.Fprintf(s, "        goto return_error;\n")
			fmt.Fprintf(s, "    }\n")
			fmt.Fprintf(s, "\n")
			fmt.Fprintf(s, "    struct syscall_seq_curr *seq_curr = bpf_syscall_seq_curr_lookup_elem(&i);\n")
			fmt.Fprintf(s, "    if (!seq_curr) {\n")
			fmt.Fprintf(s, "        goto return_error;\n")
			fmt.Fprintf(s, "    }\n")
			fmt.Fprintf(s, "    bpf_spin_lock(&seq_curr->lock)\n")
			fmt.Fprintf(s, "\n")
			fmt.Fprintf(s, "    int l = -1;\n")
			fmt.Fprintf(s, "    int u = -1;\n")
			fmt.Fprintf(s, "    bool end = false;\n")
			fmt.Fprintf(s, "    uint32_t idx = seq_curr->idx;\n")
			fmt.Fprintf(s, "    uint32_t shift = idx * 6;\n")
			fmt.Fprintf(s, "    uint64_t syscall_seq;\n")
			for i := 0; i < len(pa.seqTreeList); i++ {
				fmt.Fprintf(s, "    syscall_seq = ")
				for ssi, ss := range pa.seqTreeList[i] {
					syscallID := 0
					for usi, us := range pa.uniqueSyscallList {
						if us.Equal(ss.syscall) {
							syscallID = usi
							break
						}
					}
					fmt.Fprintf(s, "(%d << %d)", syscallID+1, ssi*6)
					if ssi == len(pa.seqTreeList[i]) - 1 {
						fmt.Fprintf(s, "\n;")
					} else {
						fmt.Fprintf(s, " | ")
					}
				}
				fmt.Fprintf(s, "    if (*this_id == ((syscall_seq >> shift) & 0x3f)) {\n")
				fmt.Fprintf(s, "        if (l < 0)\n")
				fmt.Fprintf(s, "            l = %v;\n", i)
				fmt.Fprintf(s, "        if (idx == %v)\n", len(pa.seqTreeList[i])-1)
				fmt.Fprintf(s, "            end = true;\n")
				fmt.Fprintf(s, "        u = %v;\n", i)
				fmt.Fprintf(s, "    }\n")
			}
			fmt.Fprintf(s, "    bool ok = false;\n")
			for i := 0; i < len(pa.seqTreeList); i++ {
				fmt.Fprintf(s, "    if (%d >= l && %d <= u) { ok |= check_seq_order(%d, syscall_seq_seq, seq_curr->seqs); }\n", i, i, i)
			}
			fmt.Fprintf(s, "\n")
			fmt.Fprintf(s, "    if (ok) {\n")
			fmt.Fprintf(s, "        if (end) {\n")
			fmt.Fprintf(s, "            seq_curr->seqs |= (1 << l);\n")
			fmt.Fprintf(s, "            seq_curr->last_seq_id = l;\n")
			fmt.Fprintf(s, "            seq_curr->l = 0;\n")
			fmt.Fprintf(s, "            seq_curr->u = SC_SEQ_MAX - 1;\n")
			fmt.Fprintf(s, "            seq_curr->idx = 0;\n")
			fmt.Fprintf(s, "        } else if (l != -1 && u != -1) {\n")
			fmt.Fprintf(s, "            seq_curr->l = l;\n")
			fmt.Fprintf(s, "            seq_curr->u = u;\n")
			fmt.Fprintf(s, "            seq_curr->idx += 1;\n")
			fmt.Fprintf(s, "        } else {\n")
			fmt.Fprintf(s, "            goto unlock_and_return_error;\n")
			fmt.Fprintf(s, "        }\n")
			fmt.Fprintf(s, "    }\n")
			fmt.Fprintf(s, "\n")
			fmt.Fprintf(s, "    bpf_spin_unlock(&seq_curr->lock);\n")
			fmt.Fprintf(s, "    return ok;\n")
			fmt.Fprintf(s, "unlock_and_return_error:\n")
			fmt.Fprintf(s, "    bpf_spin_unlock(&seq_curr->lock);\n")
			fmt.Fprintf(s, "return_error:\n")
			fmt.Fprintf(s, "    return false;\n")
			fmt.Fprintf(s, "}\n")
			fmt.Fprintf(s, "\n")
		}
		fmt.Fprintf(s, "void __always_inline init_syscall_fd_mask() {\n")
		fmt.Fprintf(s, "    int id = 0;\n")
		fmt.Fprintf(s, "    uint8_t mask;\n")
		for i, syscall := range sifter.syscalls {
			fmt.Fprintf(s, "    mask = %d; // %d \n", ToFdMask(syscall), i)
			fmt.Fprintf(s, "    bpf_syscall_fd_mask_update_elem(&id, &mask, BPF_ANY);\n")
			fmt.Fprintf(s, "    id++;\n")
		}
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		fmt.Fprintf(s, "void __always_inline init_syscall_seq_curr() {\n")
		fmt.Fprintf(s, "    int i = 0;\n")
		fmt.Fprintf(s, "    struct syscall_seq_curr *seq_curr = bpf_syscall_seq_curr_lookup_elem(&i);\n")
		fmt.Fprintf(s, "    if (seq_curr) {\n")
		fmt.Fprintf(s, "        seq_curr->l = 0;\n")
		fmt.Fprintf(s, "        seq_curr->u = SC_SEQ_MAX - 1;\n")
		fmt.Fprintf(s, "        seq_curr->idx = 0;\n")
		fmt.Fprintf(s, "        seq_curr->seqs = 0;\n")
		fmt.Fprintf(s, "        seq_curr->last_seq_id = 0;\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "}\n")
		fmt.Fprintf(s, "\n")
		if a := sifter.GetAnalysis("pattern analysis"); a != nil {
			pa, _ := a.(*PatternAnalysis)
			fmt.Fprintf(s, "void __always_inline init_syscall_id_map() {\n")
			fmt.Fprintf(s, "    struct syscall_id_key key;\n")
			fmt.Fprintf(s, "    uint8_t id = 0;\n")
			for i, syscall := range pa.uniqueSyscallList {
				fmt.Fprintf(s, "    id = %d; key.nr = %d; ", i+1, syscall.syscall.def.NR)
				for ti, t := range syscall.tags {
					fmt.Fprintf(s, "key.tag[%d] = 0x%x; ", ti, t)
				}
				for ti := len(syscall.tags); ti < 3; ti++ {
					fmt.Fprintf(s, "key.tag[%d] = 0 ;", ti)
				}
				fmt.Fprintf(s, "\n")
				fmt.Fprintf(s, "    bpf_syscall_id_map_update_elem(&key, &id, BPF_ANY);\n")
			}
			fmt.Fprintf(s, "}\n")
			fmt.Fprintf(s, "\n")
			fmt.Fprintf(s, "void __always_inline init_syscall_seq_tree() {\n")
			fmt.Fprintf(s, "    int id = 0;\n")
			fmt.Fprintf(s, "    struct syscall_seq seqs;\n")
			for pi, pattern := range pa.seqTreeList {
				fmt.Fprintf(s, "    id = %d; ", pi)
				for psi, ps := range pattern {
					idx := 0
					for usi, us := range pa.uniqueSyscallList {
						if us.Equal(ps.syscall) {
							idx = usi
							break
						}
					}
					fmt.Fprintf(s, "seqs.id[%d] = %d; ", psi, idx+1)
				}
				for psi := len(pattern); psi < 10; psi++ {
					fmt.Fprintf(s, "seqs.id[%d] = 0; ", psi)
				}
				fmt.Fprintf(s, "\n")
				fmt.Fprintf(s, "    bpf_syscall_seq_tree_update_elem(&id, &seqs, BPF_ANY);\n")
			}
			fmt.Fprintf(s, "}\n")
			fmt.Fprintf(s, "\n")
		}
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
		fmt.Fprintf(s, "            init_syscall_id_map();\n")
		fmt.Fprintf(s, "            init_syscall_seq_tree();\n")
		fmt.Fprintf(s, "            init_syscall_seq_curr();\n")
		fmt.Fprintf(s, "        }\n")
		fmt.Fprintf(s, "    }\n")
		fmt.Fprintf(s, "    return;\n")
		fmt.Fprintf(s, "}\n")
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

func (sifter *Sifter) CleanSections() {
	sifter.sections = make(map[string]*bytes.Buffer)
}

func IsVarLenRecord(arg *prog.ArrayType) (bool, int, []uint64) {
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

func toSecString(ns uint64) string {
	return fmt.Sprintf("%v.%09d", ns/1000000000, ns%1000000000)
}

func (sifter *Sifter) DoAnalyses(name string, flag AnalysisFlag, analysesConfigs []AnalysisConfig) (int, int) {
	lastUpdatedTeIdx := 0
	updatedTeNum := 0
	updatedTeOLNum := 0
	var lastTe *TraceEvent

	for i, _ := range sifter.traces[name].events {
		te := sifter.traces[name].events[i]

		if lastTe != nil && te.ts == lastTe.ts && te.syscall == lastTe.syscall {
			continue
		} else {
			lastTe = te
		}

		updateMsg := ""
		hasUpdate := false
		hasUpdateOL := false
		for _, ac := range analysesConfigs {
			if msg, update, updateOL := ac.a.ProcessTraceEvent(te, flag, ac.opt); update > 0 || updateOL > 0 {
				updateMsg += fmt.Sprintf("%v: %v;", ac.a, msg)
				if updateOL > 0 {
					hasUpdateOL = true
				} else {
					hasUpdate = true
				}
			}
		}
		if hasUpdateOL {
			updatedTeOLNum += 1
		} else if hasUpdate {
			updatedTeNum += 1
		}

		if sifter.verbose >= UpdateV {
			if sifter.verbose < AllTraceV && updateMsg != "" {
				timeElapsed := te.ts - sifter.traces[name].events[lastUpdatedTeIdx].ts
				fmt.Printf("  | %v events / %v sec elapsed\n", i-lastUpdatedTeIdx, toSecString(timeElapsed))
				lastUpdatedTeIdx = i
			}

			if sifter.verbose >= AllTraceV || updateMsg != "" {
				fmt.Printf("%v", te)
				fmt.Printf("  ├ update(%v/%v) %v\n", updatedTeNum, updatedTeOLNum, updateMsg)
			}
		}
	}

	if sifter.verbose >= ResultV {
		for _, ac := range analysesConfigs {
			fmt.Printf("================================================================================\n")
			fmt.Printf("%v result:\n", ac.a)
			ac.a.PrintResult(sifter.verbose)
		}
		fmt.Print("================================================================================\n")
	}

	for _, ac := range analysesConfigs {
		ac.a.Reset()
	}
	return updatedTeNum, updatedTeOLNum
}

func (sifter *Sifter) ReadSyscallTrace(dirPath string) int {

	trace := newTrace(dirPath)
	if err := trace.ReadTracedPidComm(); err != nil {
		fmt.Printf("failed to read traced pid comm map: %v\n", err)
	}

	for _, syscalls := range sifter.moduleSyscalls {
		for _, syscall := range syscalls {
			if err := trace.ReadSyscallTrace(syscall); err != nil {
				fmt.Printf("failed to read syscall trace: %v\n", err)
				trace.ClearEvents()
				return 0
			}
		}
	}
	if err := trace.ReadSyscallTrace(sifter.otherSyscall); err != nil {
		fmt.Printf("failed to read syscall trace: %v\n", err)
		trace.ClearEvents()
		return 0
	}

	trace.SortEvents()

	sifter.traces[dirPath] = trace

	return trace.Size()
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
			fmt.Fprintf(s, "s %v %v %v", syscall.TraceSizeBits(), len(syscall.argMaps)+1, syscall.name)
			fmt.Fprintf(s, " 60 %v_ent", syscall.name)
			for _, arg := range syscall.argMaps {
				fmt.Fprintf(s, " %v %v", arg.size, arg.name)
			}
			fmt.Fprintf(s, "\n")
		}
	}

	fmt.Fprintf(s, "s %v 2 other_syscalls 60 other_syscalls_ent 4 other_syscalls_nr\n", sifter.otherSyscall.TraceSizeBits())

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

func (sifter *Sifter) ReadTraceDir(dir string) {
	var err error
	sifter.traceFiles, err = ioutil.ReadDir(dir)
	if err != nil {
		failf("failed to open trace directory %v", dir)
	}
}

func (sifter *Sifter) GetTrainTestFiles() ([]os.FileInfo, []os.FileInfo) {
	testFiles := make([]os.FileInfo, 0)
	trainFiles := make([]os.FileInfo, 0)
	trainRatio := sifter.trainTestSplit / (1 + sifter.trainTestSplit)
	trainFileNum := int(float64(sifter.traceNum) * trainRatio)
	testFileNum := sifter.traceNum - trainFileNum
	usedFileMap := make(map[int32]bool)
	for {
		if len(testFiles) == testFileNum {
			break
		} else {
			r := rand.Int31n(int32(len(sifter.traceFiles)))
			if _, ok := usedFileMap[r]; !ok {
				testFiles = append(testFiles, sifter.traceFiles[r])
				usedFileMap[r] = true
			}
		}
	}
	for {
		if len(trainFiles) == trainFileNum {
			break
		} else {
			r := rand.Int31n(int32(len(sifter.traceFiles)))
			if _, ok := usedFileMap[r]; !ok {
				trainFiles = append(trainFiles, sifter.traceFiles[r])
				usedFileMap[r] = true
			}
		}
	}

	return trainFiles, testFiles
}

func (sifter *Sifter) AnalyzeSinlgeTrace() {
	var la LenAnalysis
	var fa FlagAnalysis
	var vlra VlrAnalysis
	var pa PatternAnalysis
	//var sa SequenceAnalysis
	//sa.SetLen(0)
	//sa.SetUnitOfAnalysis(ProcessLevel)
	pa.SetGroupingThreshold(TimeGrouping, 1000000000)
	pa.SetGroupingThreshold(SyscallGrouping, 1)
	pa.SetPatternOrderThreshold(0.8)
	//pa.SetUnitOfAnalysis(TraceLevel)
	pa.SetUnitOfAnalysis(ProcessLevel)

	fi, err := os.Stat(sifter.traceDir)
	if err != nil {
		fmt.Printf("failed to open trace: %v", err)
	}

	r := 0
	r = sifter.CreateAnalysisRound(0, TrainFlag, []os.FileInfo{fi})
	sifter.AddAnalysisToRound(r, &la, 0)
	sifter.AddAnalysisToRound(r, &fa, 0)
	r = sifter.CreateAnalysisRound(0, TrainFlag, []os.FileInfo{fi})
	sifter.AddAnalysisToRound(r, &la, 1)
	sifter.AddAnalysisToRound(r, &fa, 1)
	sifter.AddAnalysisToRound(r, &vlra, 0)
	sifter.AddAnalysisToRound(r, &pa, 0)
	//sifter.AddAnalysisToRound(1, &sa, 0)

	for _, round := range sifter.analysisRounds {
//		for _, file := range round.files {
			sifter.ReadSyscallTrace(sifter.traceDir)
			sifter.DoAnalyses(sifter.traceDir, round.flag, round.ac)
//		}
	}
	fmt.Print("--------------------------------------------------------------------------------\n")

//	for _, analysis := range sifter.analyses {
//		analysis.PostProcess(TrainFlag)
//	}
}

func fileNames(files []os.FileInfo) string {
	s := ""
	for i, file := range files {
		s += fmt.Sprintf("%v", file.Name())
		if i != len(files) - 1 {
			s += ", "
		}
	}
	return s
}

func (sifter *Sifter) TrainAndTest() {
	sifter.ReadTraceDir(sifter.traceDir)

	fpsTotal := make(map[int]int)
	tpsTotal := make(map[int]int)
	for i := 0; i < sifter.Iter(); i ++ {
		sifter.ClearAnalysis()
		var la LenAnalysis
		var fa FlagAnalysis
		var vlra VlrAnalysis
		var pa PatternAnalysis
		//var sa SequenceAnalysis
		//sa.SetLen(0)
		//sa.SetUnitOfAnalysis(TraceLevel)
		pa.SetGroupingThreshold(TimeGrouping, 1000000000)
		pa.SetGroupingThreshold(SyscallGrouping, 1)
		pa.SetPatternOrderThreshold(0.8)
		//pa.SetUnitOfAnalysis(TraceLevel)
		pa.SetUnitOfAnalysis(ProcessLevel)

		trainFiles, testFiles := sifter.GetTrainTestFiles()

		r := 0
		r = sifter.CreateAnalysisRound(0, TrainFlag, trainFiles)
		sifter.AddAnalysisToRound(r, &la, 0)
		sifter.AddAnalysisToRound(r, &fa, 0)
		r = sifter.CreateAnalysisRound(1, TrainFlag, trainFiles)
		sifter.AddAnalysisToRound(r, &la, 1)
		sifter.AddAnalysisToRound(r, &fa, 1)
		sifter.AddAnalysisToRound(r, &vlra, 0)
		sifter.AddAnalysisToRound(r, &pa, 1)
		//sifter.AddAnalysisToRound(r, &sa, 0)
		r = sifter.CreateAnalysisRound(2, TestFlag, testFiles)
		sifter.AddAnalysisToRound(r, &la, 1)
		sifter.AddAnalysisToRound(r, &fa, 1)
		sifter.AddAnalysisToRound(r, &vlra, 0)
		sifter.AddAnalysisToRound(r, &pa, 0)

		traceSize := make([]int, len(sifter.analysisRounds))
		fps := make([]int, len(sifter.analysisRounds))
		tps := make([]int, len(sifter.analysisRounds))

		fmt.Print("================================================================================\n")
		fmt.Printf("#Iter %v\n", i)
		for ri, round := range sifter.analysisRounds {
			fmt.Print("================================================================================\n")
			fmt.Printf("#Round %v: %v\n", ri, fileNames(round.files))
			for fi, file := range round.files {
				fmt.Printf("#Trace %v-%v-%v: %v\n", i, ri, fi, file.Name())
				filePath := sifter.traceDir + "/" + file.Name()
				traceSize[ri] += sifter.ReadSyscallTrace(filePath)
				fp, tp := sifter.DoAnalyses(filePath, round.flag, round.ac)
				fps[ri] += fp
				tps[ri] += tp
				fpsTotal[ri] += fp
				tpsTotal[ri] += tp

				sifter.traces[filePath].ClearEvents()
			}

			for _, ac := range round.ac {
				ac.a.PostProcess(ac.opt)
			}

			fmt.Printf("#trace size: %v\n", traceSize[ri])
			fmt.Printf("#updates: %v/%v\n", fps[ri], tps[ri])
			fmt.Print("================================================================================\n")
		}
		fmt.Print("================================================================================\n")
	}
	fmt.Printf("#Testing error:\n")
	fmt.Printf("#FP:%d TP:%d\n", fpsTotal[2], tpsTotal[2])
	fmt.Printf("#Avg FP: %.3f\n", float64(fpsTotal[2])/float64(sifter.Iter()))
}
