package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// offsetsFromFile reads a slot->offset json (also accepted: it is optional).
func offsetsFromFile(path string) (map[uint64]int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := map[uint64]int{}
	for k, v := range m {
		slot, err := strconv.Atoi(k)
		if err != nil || slot < 0 || slot >= len(jniSchema) {
			continue
		}
		off, err := strconv.ParseUint(strings.TrimSpace(v), 0, 64)
		if err != nil {
			continue
		}
		out[off] = slot
	}
	return out, nil
}

// offsetsFromScan finds JNINativeInterface tables by scanning libart's data
// segments for 233 consecutive pointers that all fall inside its exec segment
// (reserved0..3 must be zero). ART ships more than one such table (fast +
// CheckJNI), and we cannot tell which one the process uses, so we union all
// candidates: each table's slot i maps offset -> i.
func offsetsFromScan(pid int) (map[uint64]int, error) {
	base, execLo, execHi, err := libartBase(pid)
	if err != nil {
		return nil, err
	}
	mr, err := openMem(pid)
	if err != nil {
		return nil, err
	}
	defer mr.f.Close()
	ranges, err := libartDataRanges(pid)
	if err != nil {
		return nil, err
	}
	n := len(jniSchema) // 233
	out := map[uint64]int{}
	tables := 0
	for _, r := range ranges {
		for p := r[0]; p+uint64(n)*8 <= r[1]; p += 8 {
			bad := false
			for i := 0; i < 4; i++ {
				v, ok := mr.u64(p + uint64(i)*8)
				if !ok || v != 0 {
					bad = true
					break
				}
			}
			if bad {
				continue
			}
			okAll := true
			for i := 4; i < n; i++ {
				v, ok := mr.u64(p + uint64(i)*8)
				if !ok || v < execLo || v >= execHi {
					okAll = false
					break
				}
			}
			if !okAll {
				continue
			}
			tables++
			for i := 4; i < n; i++ {
				v, _ := mr.u64(p + uint64(i)*8)
				out[v-base] = i
			}
			p += uint64(n)*8 - 8 // skip past this table
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("JNINativeInterface table not found in pid %d", pid)
	}
	fmt.Printf("[*] auto-offsets: %d candidate table(s), %d slot offsets\n", tables, len(out))
	return out, nil
}
