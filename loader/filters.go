package main

import (
	"regexp"
	"strings"
	"sync"
)

type filters struct {
	mu       sync.Mutex
	modes    map[string]bool
	only     []string
	exclude  []string
	grep     string
	classRe  *regexp.Regexp
	methodRe *regexp.Regexp
	from     []string
	tid      int
}

func newFilters(c config) *filters {
	f := &filters{modes: map[string]bool{}, tid: c.tid}
	for _, m := range strings.Split(c.modes, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			f.modes[m] = true
		}
	}
	f.only = splitList(c.only)
	f.exclude = splitList(c.exclude)
	f.grep = c.grep
	if c.classRe != "" {
		f.classRe = regexp.MustCompile(c.classRe)
	}
	if c.methodRe != "" {
		f.methodRe = regexp.MustCompile(c.methodRe)
	}
	if c.from != "" {
		f.from = splitList(c.from)
	}
	return f
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// matchSlot: does the mode/only/exclude config want this slot at all?
func (f *filters) matchSlot(slot int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := slotName(slot)
	cat := category(name)
	allow := f.modes["all"]
	if !allow {
		if f.modes[cat] {
			allow = true
		}
	}
	if len(f.only) > 0 {
		allow = false
		for _, o := range f.only {
			if strings.HasPrefix(name, o) || strings.Contains(name, o) {
				allow = true
				break
			}
		}
	}
	for _, x := range f.exclude {
		if strings.HasPrefix(name, x) || strings.Contains(name, x) {
			allow = false
		}
	}
	return allow
}

func (f *filters) matchLine(cls, method, line, callerMod string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.grep != "" && !strings.Contains(line, f.grep) {
		return false
	}
	if f.classRe != nil && !f.classRe.MatchString(cls) {
		return false
	}
	if f.methodRe != nil && !f.methodRe.MatchString(method) {
		return false
	}
	if len(f.from) > 0 {
		ok := false
		for _, x := range f.from {
			if strings.Contains(callerMod, x) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
