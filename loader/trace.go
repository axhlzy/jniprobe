package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// reconEvt must match struct evt_t in bpf/recon.bpf.c exactly.
type reconEvt struct {
	Pid     uint32
	Tid     uint32
	Kind    uint32
	Pad     uint32
	Ip      uint64
	Rc      uint64
	Ts      uint64
	Depth   int32
	Pad2    uint32
	Caller  uint64
	A       [reconNArgs]uint64
	Ncap    uint32
	Argkind uint32
	Res1    uint32
	Res2    uint32
	Cap     [NCAP]uint64
	Cap2    [NCAP]uint64
	Vgr     uint64
	Vgoff   int64
	Vstk    uint64
	Stackid int32
	Pad3    uint32
}

// slots whose return values are always captured (needed to feed name caches).
var alwaysWatch = map[string]bool{
	"GetMethodID": true, "GetStaticMethodID": true, "GetFieldID": true, "GetStaticFieldID": true,
	"FindClass": true, "GetObjectClass": true, "NewObject": true, "NewObjectV": true,
	"NewObjectA": true, "AllocObject": true, "GetStringUTFChars": true, "NewStringUTF": true,
}

// ---------------- module map (for --from and stack frames) ----------------

type moduleRange struct {
	lo, hi uint64
	name   string
}

func loadModules(pid int) ([]moduleRange, map[string]uint64) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, nil
	}
	var out []moduleRange
	bias := map[string]uint64{}
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 {
			continue
		}
		rng := strings.SplitN(f[0], "-", 2)
		if len(rng) != 2 {
			continue
		}
		lo, _ := strconv.ParseUint(rng[0], 16, 64)
		hi, _ := strconv.ParseUint(rng[1], 16, 64)
		fo, _ := strconv.ParseUint(f[2], 16, 64)
		name := f[5]
		if i := strings.LastIndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		out = append(out, moduleRange{lo, hi, name})
		if fo == 0 {
			if _, ok := bias[name]; !ok {
				bias[name] = lo
			}
		}
	}
	return out, bias
}

func moduleOf(mods []moduleRange, addr uint64) string {
	for _, m := range mods {
		if addr >= m.lo && addr < m.hi {
			return m.name
		}
	}
	return ""
}

type modCache struct {
	mu     sync.Mutex
	ranges []moduleRange
	bias   map[string]uint64
	pid    int
	last   time.Time
}

func (m *modCache) reload(pid int) {
	r, b := loadModules(pid)
	m.mu.Lock()
	m.ranges = r
	m.bias = b
	m.pid = pid
	m.last = time.Now()
	m.mu.Unlock()
}
func (m *modCache) of(addr uint64) string {
	m.mu.Lock()
	name := moduleOf(m.ranges, addr)
	stale := time.Since(m.last) > 300*time.Millisecond
	m.mu.Unlock()
	if name == "" && stale {
		m.mu.Lock()
		r, b := loadModules(m.pid)
		m.ranges = r
		m.bias = b
		m.last = time.Now()
		name = moduleOf(m.ranges, addr)
		m.mu.Unlock()
	}
	return name
}

// lookup returns the module name and its load bias (offset 0 mapping) for addr.
func (m *modCache) lookup(addr uint64) (string, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := moduleOf(m.ranges, addr)
	if name == "" {
		return "", 0
	}
	return name, m.bias[name]
}

// ---------------- per-thread frame (entry + return pairing) ----------------

type frame struct {
	slot       int
	ts         uint64
	call       string
	caller     string
	a1, a2, a3 uint64
}

func runProbe(c config) {
	pid := c.pid
	if pid == 0 && c.name != "" {
		var err error
		pid, err = resolvePidByName(c.name)
		fatal(err)
	}
	if pid == 0 {
		fmt.Println("usage: jniprobe -p <pid> | -n <name> [options]\nrun `jniprobe -h` for flags")
		os.Exit(2)
	}

	var offsets map[uint64]int
	var err error
	if c.offsets == "" || c.offsets == "auto" {
		offsets, err = offsetsFromScan(pid)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[!] auto offset scan failed ("+err.Error()+"), trying /data/local/tmp/jni_offsets.json")
			offsets, err = offsetsFromFile("/data/local/tmp/jni_offsets.json")
		}
	} else {
		offsets, err = offsetsFromFile(c.offsets)
	}
	fatal(err)
	if len(offsets) < 100 {
		fatal(fmt.Errorf("only %d slot offsets resolved", len(offsets)))
	}
	base, execLo, execHi, err := libartBase(pid)
	fatal(err)
	_ = execLo
	_ = execHi

	f := newFilters(c)
	mc := &modCache{}
	mc.reload(pid)
	go func() {
		for {
			time.Sleep(2 * time.Second)
			mc.reload(pid)
		}
	}()

	obj, err := bpfFS.ReadFile("recon.bpf.o")
	fatal(err)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	fatal(err)
	coll, err := ebpf.NewCollection(spec)
	fatal(err)
	defer coll.Close()

	ex, err := link.OpenExecutable(c.libart)
	fatal(err)

	// configure BPF: base + which slots snapshot args / have return probes.
	fatal(coll.Maps["cfg"].Put(uint32(0), base))
	if c.stack {
		_ = coll.Maps["cfg"].Put(uint32(1), uint64(1))
	}
	callSet := map[int]bool{}
	retSet := map[int]bool{}
	for off, slot := range offsets {
		nm := slotName(slot)
		if midIdx, ok := isCallMethod(nm); ok {
			callSet[slot] = true
			kind := uint8(3)
			if strings.HasSuffix(nm, "A") {
				kind = 1
			} else if strings.HasSuffix(nm, "V") {
				kind = 2
			}
			_ = coll.Maps["argkind"].Put(off, kind)
			_ = coll.Maps["argidx"].Put(off, uint8(midIdx+1))
		}
		if alwaysWatch[nm] {
			retSet[slot] = true
		} else if !c.noReturns && slotRet(slot) != "void" && f.matchSlot(slot) {
			retSet[slot] = true
		}
	}
	// a slot may map to several offsets (union of candidate tables); probe them all.
	var retOffsets []uint64
	for off, slot := range offsets {
		if retSet[slot] {
			_ = coll.Maps["hasret"].Put(off, uint8(1))
			retOffsets = append(retOffsets, off)
		}
	}

	var links []link.Link
	add := func(l link.Link, e error) {
		if e == nil {
			links = append(links, l)
		}
	}
	attached := 0
	for off := range offsets {
		l, e := ex.Uprobe("", coll.Programs["up_all"], &link.UprobeOptions{Address: off, PID: pid})
		add(l, e)
		attached++
	}
	retN := 0
	for _, off := range retOffsets {
		if l, e := ex.Uretprobe("", coll.Programs["up_ret"], &link.UprobeOptions{Address: off, PID: pid}); e == nil {
			add(l, e)
			retN++
		}
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	mr, _ := openMem(pid)
	if mr != nil {
		defer mr.f.Close()
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	fatal(err)
	defer rd.Close()

	stop := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sig:
		case <-stop:
		}
		rd.Close()
	}()

	fmt.Printf("[*] jniprobe: pid=%d libart=%s base=0x%x slots=%d probes=%d(+%d ret)\n",
		pid, c.libart, base, len(offsets), attached, retN)
	fmt.Printf("[*] modes=%s only=%q exclude=%q grep=%q from=%q verbose=%v count=%v stack=%v\n",
		c.modes, c.only, c.exclude, c.grep, c.from, c.verbose, c.count, c.stack)
	fmt.Println("[*] interactive: only <re> | from <so> | grep <str> | mode <m> | clear | stats | quit  (Ctrl-C to stop)")

	cs := newCaches()
	frames := map[[2]int32]frame{}
	counts := map[string]int{}
	total := 0

	stackMap := coll.Maps["stackmap"]
	printStack := func(ind string, id int32, lr uint64) {
		if !c.stack || c.count || stackMap == nil || id < 0 {
			return
		}
		var buf [32]uint64
		if err := stackMap.Lookup(uint32(id), &buf); err != nil {
			return
		}
		frame := func(idx int, a uint64) {
			if nm, b := mc.lookup(a); nm != "" {
				fmt.Printf("%s   #%d %s+0x%x\n", ind, idx, nm, a-b)
			} else {
				fmt.Printf("%s   #%d 0x%x\n", ind, idx, a)
			}
		}
		n := 0
		for _, a := range buf {
			if a == 0 {
				break
			}
			frame(n, a)
			n++
			if n == 1 && lr != 0 { // caller's return address lives in LR, not the FP chain
				frame(n, lr)
				n++
			}
		}
	}

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			applyCommand(f, counts, line)
		}
	}()

	if c.runSec > 0 {
		go func() {
			time.Sleep(time.Duration(c.runSec) * time.Second)
			close(stop)
			rd.Close()
		}()
	}

	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		var e reconEvt
		if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e) != nil {
			continue
		}
		total++
		if c.tid != 0 && int(e.Tid) != c.tid {
			continue
		}

		if e.Kind == 1 {
			handleReturn(&e, frames, cs, mr, f, c, counts)
			continue
		}

		slot, ok := offsets[e.Ip-base]
		if !ok {
			continue
		}
		nm := slotName(slot)
		caller := mc.of(e.Caller)

		if retSet[slot] && e.Depth >= 0 {
			fr := frame{slot: slot, ts: e.Ts, a1: e.A[1], a2: e.A[2], a3: e.A[3], caller: caller}
			if !callSet[slot] {
				fr.call = fmt.Sprintf("%s(%s)", nm, renderGeneric(&e, slot, cs, mr))
			}
			frames[[2]int32{int32(e.Tid), e.Depth}] = fr
		}

		if !f.matchSlot(slot) {
			continue
		}
		if c.maxDepth > 0 && e.Depth > int32(c.maxDepth) {
			continue
		}

		if isCall, ok := isCallMethod(nm); ok {
			call, known := describeCall(&e, nm, cs, mr)
			key := [2]int32{int32(e.Tid), e.Depth}
			if fr, ok := frames[key]; ok {
				fr.call = call
				frames[key] = fr
			}
			cls, meth := splitClassMethod(call)
			if known || c.verbose {
				if f.matchLine(cls, meth, call, caller) {
					tag := ""
					if c.verbose {
						tag = fmt.Sprintf("  [caller=0x%x %s]", e.Caller, caller)
					}
					emit(c, counts, fmt.Sprintf("%s-> %s%s", indentStr(e.Depth), call, tag))
					printStack(indentStr(e.Depth), e.Stackid, e.Caller)
				}
			}
			_ = isCall
			continue
		}

		line := fmt.Sprintf("%s(%s)", nm, renderGeneric(&e, slot, cs, mr))
		if f.matchLine("", nm, line, caller) {
			emit(c, counts, fmt.Sprintf("%s-> %s", indentStr(e.Depth), line))
			printStack(indentStr(e.Depth), e.Stackid, e.Caller)
		}
	}

	fmt.Printf("\n[*] done: %d events\n", total)
	printStats(counts, 25)
}

// handleReturn feeds name caches and prints the "<- call = ret" line.
func handleReturn(e *reconEvt, frames map[[2]int32]frame, cs *caches, mr *memReader,
	f *filters, c config, counts map[string]int) {
	if e.Depth < 0 {
		return
	}
	key := [2]int32{int32(e.Tid), e.Depth}
	fr, ok := frames[key]
	if !ok {
		return
	}
	delete(frames, key)

	switch slotName(fr.slot) {
	case "GetMethodID", "GetStaticMethodID", "GetFieldID", "GetStaticFieldID":
		if mr != nil && e.Rc != 0 {
			nm := mr.cstr(fr2a(fr, 2))
			sg := mr.cstr(fr2a(fr, 3))
			if validName(nm) && validSig(sg) {
				cs.idName[e.Rc] = nm + sg
			}
			cs.idClass[e.Rc] = fr2a(fr, 1)
		}
	case "FindClass":
		if mr != nil && e.Rc != 0 {
			nm := mr.cstr(fr2a(fr, 1))
			if validName(nm) {
				dotted := strings.ReplaceAll(nm, "/", ".")
				cs.classNames[e.Rc] = dotted
				if obj := cs.resolveObj(mr, e.Rc); obj != 0 {
					cs.nameByClass[obj] = dotted
				}
			}
		}
	case "GetObjectClass":
		if mr != nil && e.Rc != 0 {
			if op := cs.resolveObj(mr, fr2a(fr, 1)); op != 0 {
				if cp := cs.resolveObj(mr, e.Rc); cp != 0 {
					cs.objClass[op] = cp
				}
			}
		}
	case "NewObject", "NewObjectV", "NewObjectA", "AllocObject":
		if mr != nil && e.Rc != 0 {
			if op := cs.resolveObj(mr, e.Rc); op != 0 {
				if cp := cs.resolveObj(mr, fr2a(fr, 1)); cp != 0 {
					cs.objClass[op] = cp
				}
			}
		}
	case "GetStringUTFChars":
		if mr != nil && e.Rc != 0 {
			cs.jstr[fr2a(fr, 1)] = mr.cstr(e.Rc) // jstring(a1) -> text(rc)
		}
	case "NewStringUTF":
		if mr != nil && e.Rc != 0 {
			cs.jstr[e.Rc] = mr.cstr(fr2a(fr, 1))
		}
	}

	if f.matchSlot(fr.slot) && fr.call != "" {
		if c.maxDepth > 0 && e.Depth > int32(c.maxDepth) {
			return
		}
		dur := float64(e.Ts-fr.ts) / 1e6
		ret := fmtRet(cs, mr, slotRet(fr.slot), e.Rc)
		cls, meth := splitClassMethod(fr.call)
		line := fmt.Sprintf("%s<- %s = %s  (%.3f ms)", indentStr(e.Depth), fr.call, ret, dur)
		if f.matchLine(cls, meth, fr.call+ret, fr.caller) {
			emit(c, counts, line)
		}
	}
}

func fr2a(fr frame, idx int) uint64 {
	switch idx {
	case 1:
		return fr.a1
	case 2:
		return fr.a2
	case 3:
		return fr.a3
	}
	return 0
}

func splitClassMethod(call string) (string, string) {
	if i := strings.LastIndexByte(call, '.'); i >= 0 {
		rest := call[i+1:]
		if j := strings.IndexByte(rest, '('); j >= 0 {
			return call[:i], rest[:j]
		}
		return call[:i], rest
	}
	return "", call
}

func emit(c config, counts map[string]int, line string) {
	if c.count {
		counts[line]++
		return
	}
	if c.jsonOut {
		b, _ := json.Marshal(map[string]string{"line": line})
		fmt.Println(string(b))
		return
	}
	fmt.Println(line)
}

func printStats(counts map[string]int, top int) {
	if len(counts) == 0 {
		return
	}
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range counts {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	fmt.Println("[*] top calls:")
	for i, x := range arr {
		if i >= top {
			break
		}
		fmt.Printf("    %6d  %s\n", x.v, x.k)
	}
}

func renderGeneric(e *reconEvt, slot int, c *caches, mr *memReader) string {
	types := slotArgs(slot)
	if len(types) == 0 {
		return fmt.Sprintf("a1=0x%x a2=0x%x a3=0x%x", e.A[1], e.A[2], e.A[3])
	}
	var parts []string
	for i := 1; i < len(types) && i < reconNArgs; i++ {
		s := fmtArg(c, mr, types[i], e.A[i])
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ", ")
}

func applyCommand(f *filters, counts map[string]int, line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	cmd := fields[0]
	arg := strings.TrimSpace(strings.TrimPrefix(line, cmd))
	switch cmd {
	case "only":
		f.mu.Lock()
		f.only = splitList(arg)
		f.mu.Unlock()
		fmt.Println("[cmd] only =", arg)
	case "exclude":
		f.mu.Lock()
		f.exclude = splitList(arg)
		f.mu.Unlock()
		fmt.Println("[cmd] exclude =", arg)
	case "from":
		f.mu.Lock()
		f.from = splitList(arg)
		f.mu.Unlock()
		fmt.Println("[cmd] from =", arg)
	case "grep":
		f.mu.Lock()
		f.grep = arg
		f.mu.Unlock()
		fmt.Println("[cmd] grep =", arg)
	case "mode":
		f.mu.Lock()
		f.modes = map[string]bool{}
		for _, m := range splitList(arg) {
			f.modes[m] = true
		}
		f.mu.Unlock()
		fmt.Println("[cmd] mode =", arg)
	case "clear":
		f.mu.Lock()
		f.only, f.exclude, f.from = nil, nil, nil
		f.grep = ""
		f.classRe, f.methodRe = nil, nil
		f.modes = map[string]bool{"all": true}
		f.mu.Unlock()
		fmt.Println("[cmd] filters cleared")
	case "stats":
		printStats(counts, 25)
	case "quit", "exit":
		os.Exit(0)
	default:
		fmt.Println("[cmd] unknown:", cmd)
	}
}
