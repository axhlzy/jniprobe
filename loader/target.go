package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ---------------- libart / target ----------------

func libartBase(pid int) (base, execLo, execHi uint64, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, 0, 0, err
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if !strings.Contains(ln, "libart.so") {
			continue
		}
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
		if base == 0 {
			base = lo - fo
		}
		if strings.Contains(f[1], "r-xp") {
			execLo, execHi = lo, hi
		}
	}
	if base == 0 {
		return 0, 0, 0, fmt.Errorf("libart not mapped in pid %d", pid)
	}
	return base, execLo, execHi, nil
}

func libartDataRanges(pid int) ([][2]uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	var out [][2]uint64
	for _, ln := range strings.Split(string(data), "\n") {
		if !strings.Contains(ln, "libart.so") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 6 || strings.Contains(f[1], "x") {
			continue // skip executable
		}
		rng := strings.SplitN(f[0], "-", 2)
		if len(rng) != 2 {
			continue
		}
		lo, _ := strconv.ParseUint(rng[0], 16, 64)
		hi, _ := strconv.ParseUint(rng[1], 16, 64)
		if hi > lo {
			out = append(out, [2]uint64{lo, hi})
		}
	}
	return out, nil
}

func resolvePidByName(sub string) (int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmd, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		if strings.Contains(string(cmd), sub) {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("no process matching %q", sub)
}

// ---------------- memory reader ----------------

type memReader struct{ f *os.File }

func openMem(pid int) (*memReader, error) {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return &memReader{f}, nil
}
func (m *memReader) u64(a uint64) (uint64, bool) {
	var b [8]byte
	if _, err := m.f.ReadAt(b[:], int64(a)); err != nil {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[:]), true
}
func (m *memReader) u32(a uint64) (uint32, bool) {
	var b [4]byte
	if _, err := m.f.ReadAt(b[:], int64(a)); err != nil {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[:]), true
}
func (m *memReader) cstr(addr uint64) string {
	if addr == 0 || m == nil {
		return ""
	}
	buf := make([]byte, 256)
	n, _ := m.f.ReadAt(buf, int64(addr))
	if n <= 0 {
		return ""
	}
	if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf)
}

// runDump: `jniprobe dump <pid> <hexaddr> [words]` — raw memory peeker.
func runDump(args []string) {
	if len(args) < 3 {
		fmt.Println("usage: jniprobe dump <pid> <hexaddr> [words]")
		os.Exit(2)
	}
	dpid, _ := strconv.Atoi(args[1])
	addr, _ := strconv.ParseUint(strings.TrimPrefix(args[2], "0x"), 16, 64)
	words := 16
	if len(args) >= 4 {
		words, _ = strconv.Atoi(args[3])
	}
	mr, err := openMem(dpid)
	fatal(err)
	defer mr.f.Close()
	for i := 0; i < words; i++ {
		v, ok := mr.u64(addr + uint64(i)*8)
		mark := " "
		if ok {
			mark = "*"
		}
		fmt.Printf("  +0x%03x %016x %s\n", i*8, v, mark)
	}
}
