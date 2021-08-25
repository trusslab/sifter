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
	flag.IntVar(&flags.TraceNum,  "n", 0, "number of traces to be used")
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
		s.TrainAndTest()
		//s.AnalyzeSinlgeTrace()
	}
}
