package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/trusslab/sifter/sifter"
)

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func main() {
	var flags sifter.Flags
	flag.StringVar(&flags.Mode,   "mode", "", "mode (tracer/filter)")
	flag.StringVar(&flags.Trace,  "trace", "", "tracing result file")
	flag.StringVar(&flags.Config, "config", "", "Syzkaller configuration file")
	flag.StringVar(&flags.Fd,     "fd", "", "file descriptor name of the kernel module in Syzkaller")
	flag.StringVar(&flags.Dev,    "dev", "", "device file of the kernel module")
	flag.StringVar(&flags.Outdir, "outdir", "gen", "output file directory")
	flag.StringVar(&flags.Out,    "out", "", "output file base name")
	flag.IntVar(&flags.Unroll,    "unroll", 5, "loop unroll times")
	flag.IntVar(&flags.Iter,      "iter", 10, "training-testing iterations")
	flag.Float64Var(&flags.Split, "split", 4, "train-test split ratio (train set size/test set size)")
	flag.IntVar(&flags.Verbose,   "v", 0, "verbosity")
	flag.Parse()

	s, err := sifter.NewSifter(flags)
	if err != nil {
		failf("failed to initialize sifter. err: %v", err)
	}

	s.GenerateSource()
	if s.Mode() == sifter.TracerMode {
		s.WriteSourceFile()
		s.WriteAgentConfigFile()
	} else if s.Mode() == sifter.AnalyzerMode {
		traceDir := "./trace"
		s.ReadTraceDir(traceDir)

		testUpdateSum := 0
		for i := 0; i < s.Iter(); i ++ {
			s.ClearAnalysis()
			var vra sifter.ValueRangeAnalysis
			var sa sifter.SequenceAnalysis
			var vlra sifter.VlrAnalysis
			var pa sifter.PatternAnalysis
			sa.SetLen(0)
			pa.SetGroupingThreshold(sifter.TimeGrouping, 10000)

			s.AddAnalysis(&vra)
			s.AddAnalysis(&vlra)
			s.AddAnalysis(&sa)
			s.AddAnalysis(&pa)

			var testSize, trainSize, testUpdates, trainUpdates int
			trainFiles, testFiles := s.GetTrainTestFiles()
			//for {
			//	trainFiles, testFiles = s.GetTrainTestFiles()
			//	if testFiles[0].Name() == "googlemap_40m" {
			//		break
			//	}
			//}

			fmt.Printf("Run %v\n", i)
			fmt.Printf("#training apps:\n")
			for i, file := range trainFiles {
				if i != len(trainFiles) - 1 {
					fmt.Printf("%v, ", file.Name())
				} else {
					fmt.Printf("%v\n", file.Name())
				}
			}
			for _, file := range trainFiles {
				s.ClearTrace()
				s.ReadTracedPidComm(traceDir+"/"+file.Name())
				trainSize += s.ReadSyscallTrace(traceDir+"/"+file.Name())
				trainUpdates += s.DoAnalyses(sifter.TrainFlag)
			}
			fmt.Printf("#training size: %v\n", trainSize)
			fmt.Printf("#training updates: %v\n", trainUpdates)

			fmt.Printf("#testing apps:\n")
			for i, file := range testFiles {
				if i != len(testFiles) - 1 {
					fmt.Printf("%v,", file.Name())
				} else {
					fmt.Printf("%v\n", file.Name())
				}
			}
			for _, file := range testFiles {
				s.ClearTrace()
				s.ReadTracedPidComm(traceDir+"/"+file.Name())
				testSize += s.ReadSyscallTrace(traceDir+"/"+file.Name())
				testUpdates += s.DoAnalyses(sifter.TestFlag)
			}
			testUpdateSum += testUpdates
			fmt.Printf("#testing size: %v\n", testSize)
			fmt.Printf("#testing updates: %v\n", testUpdates)
		}
		fmt.Printf("#Avg testing error: %.3f\n", float64(testUpdateSum)/float64(s.Iter()))

	}
}
