package main

import (
	"embed"
	"flag"
	"fmt"
	"os"

	"github.com/cilium/ebpf/rlimit"
)

//go:embed envprobe.bpf.o
//go:embed recon.bpf.o
var bpfFS embed.FS

const (
	libartDefault = "/apex/com.android.art/lib64/libart.so"
	symLNL        = "_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_"
	symCNT        = "_ZN3art6Thread18CreateNativeThreadEP7_JNIEnvP8_jobjectmb"
	envSlots      = 240
	reconNArgs    = 5
	NCAP          = 16
)

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "jniprobe: "+err.Error())
		os.Exit(1)
	}
}

type config struct {
	pid       int
	name      string
	runSec    int
	offsets   string
	libart    string
	modes     string
	only      string
	exclude   string
	noReturns bool
	maxDepth  int
	grep      string
	classRe   string
	methodRe  string
	from      string
	tid       int
	verbose   bool
	count     bool
	jsonOut   bool
	noColor   bool
	stack     bool
}

func parseFlags(args []string) config {
	var c config
	fs := flag.NewFlagSet("jniprobe", flag.ExitOnError)
	fs.IntVar(&c.pid, "p", 0, "target pid")
	fs.IntVar(&c.pid, "pid", 0, "target pid")
	fs.StringVar(&c.name, "n", "", "match process by cmdline substring")
	fs.StringVar(&c.name, "name", "", "match process by cmdline substring")
	fs.IntVar(&c.runSec, "run", 0, "run N seconds then exit")
	fs.StringVar(&c.offsets, "offsets", "auto", "auto | path to jni_offsets.json")
	fs.StringVar(&c.libart, "libart", libartDefault, "libart path")
	fs.StringVar(&c.modes, "m", "all", "modes: call,new,field,class,string,other,all (default all)")
	fs.StringVar(&c.modes, "mode", "all", "modes: call,new,field,class,string,other,all (default all)")
	fs.StringVar(&c.only, "only", "", "comma list of JNI function names/prefixes to keep")
	fs.StringVar(&c.exclude, "exclude", "", "comma list of JNI function names/prefixes to drop")
	fs.BoolVar(&c.noReturns, "no-returns", false, "do not capture return values")
	fs.IntVar(&c.maxDepth, "max-depth", 0, "max call-tree depth (0 = unlimited)")
	fs.StringVar(&c.grep, "g", "", "show only calls whose rendered text contains this")
	fs.StringVar(&c.grep, "grep", "", "show only calls whose rendered text contains this")
	fs.StringVar(&c.classRe, "class", "", "regex on class name")
	fs.StringVar(&c.methodRe, "method", "", "regex on method name/signature")
	fs.StringVar(&c.from, "from", "", "only calls whose caller module contains this")
	fs.IntVar(&c.tid, "tid", 0, "only this thread id")
	fs.BoolVar(&c.verbose, "v", false, "also print un-parsed JNI functions")
	fs.BoolVar(&c.verbose, "verbose", false, "also print un-parsed JNI functions")
	fs.BoolVar(&c.count, "count", false, "aggregate distinct calls instead of streaming")
	fs.BoolVar(&c.jsonOut, "json", false, "JSON output")
	fs.BoolVar(&c.noColor, "no-color", false, "disable color")
	fs.BoolVar(&c.stack, "S", false, "print user call stack for matched lines")
	fs.BoolVar(&c.stack, "stack", false, "print user call stack for matched lines")
	fs.Parse(args)
	return c
}

func main() {
	args := os.Args[1:]
	if len(args) >= 1 && args[0] == "env" {
		fatal(rlimit.RemoveMemlock())
		runEnv()
		return
	}
	if len(args) >= 1 && args[0] == "dump" {
		runDump(args)
		return
	}
	c := parseFlags(args)
	fatal(rlimit.RemoveMemlock())
	runProbe(c)
}
