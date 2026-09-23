package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type envDump struct {
	Pid   uint32
	Site  uint32
	Reg   uint32
	Pad   uint32
	Env   uint64
	Table uint64
	Slots [envSlots]uint64
}

// runEnv (`jniprobe env`) captures a live JNIEnv* and dumps the JNINativeInterface
// table to /data/local/tmp/jni_offsets.json. Only needed to (re)generate offsets;
// normally `--offsets auto` scans the table instead.
func runEnv() {
	obj, err := bpfFS.ReadFile("envprobe.bpf.o")
	fatal(err)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	fatal(err)
	coll, err := ebpf.NewCollection(spec)
	fatal(err)
	defer coll.Close()

	ex, err := link.OpenExecutable(libartDefault)
	fatal(err)
	lnl, err := ex.Uprobe(symLNL, coll.Programs["up_lnl"], nil)
	fatal(err)
	defer lnl.Close()
	if cnt, err := ex.Uprobe(symCNT, coll.Programs["up_cnt"], nil); err == nil {
		defer cnt.Close()
	}
	fmt.Println("[+] env probe attached; trigger an app load (e.g. `am get-current-user`)")

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	fatal(err)
	defer rd.Close()
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		var d envDump
		if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &d) != nil {
			continue
		}
		base, lo, hi, err := libartBase(int(d.Pid))
		if err != nil {
			continue
		}
		in := 0
		for _, v := range d.Slots {
			if v >= lo && v < hi {
				in++
			}
		}
		if float64(in)/float64(len(d.Slots)) < 0.5 {
			continue
		}
		keys := []int{}
		for i, v := range d.Slots {
			if v >= lo && v < hi {
				keys = append(keys, i)
			}
		}
		sort.Ints(keys)
		var sb strings.Builder
		sb.WriteString("{\n")
		for n, i := range keys {
			if n > 0 {
				sb.WriteString(",\n")
			}
			fmt.Fprintf(&sb, "  \"%d\": \"0x%x\"", i, d.Slots[i]-base)
		}
		sb.WriteString("\n}\n")
		out := "/data/local/tmp/jni_offsets.json"
		fatal(os.WriteFile(out, []byte(sb.String()), 0666))
		fmt.Printf("[+] %d slots written to %s\n", len(keys), out)
		break
	}
}
