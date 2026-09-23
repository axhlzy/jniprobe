package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// caches holds everything learned at runtime to turn opaque JNI ids/refs into
// readable names.
type caches struct {
	idName      map[uint64]string // jmethodID/jfieldID -> "name(sig)"
	idClass     map[uint64]uint64 // jmethodID/jfieldID -> declaring jclass ref
	classNames  map[uint64]string // jclass ref -> "a.b.C"
	nameByClass map[uint64]string // mirror::Class* -> "a.b.C"
	objClass    map[uint64]uint64 // mirror::Object* -> mirror::Class*
	jstr        map[uint64]string // jstring -> text
}

func newCaches() *caches {
	return &caches{
		idName:      map[uint64]string{},
		idClass:     map[uint64]uint64{},
		classNames:  map[uint64]string{},
		nameByClass: map[uint64]string{},
		objClass:    map[uint64]uint64{},
		jstr:        map[uint64]string{},
	}
}

// ART JNI refs: a local ref is (pointer to a 4-byte IRTable slot) | kind. The
// slot holds a compressed heap reference; heap base is 0 on Android (heap is
// mapped below 4GB), so the slot value is the object pointer itself.
func (c *caches) resolveObj(mr *memReader, v uint64) uint64 {
	if mr == nil || v == 0 || v < 0x100000 {
		return 0 // 0, null, or an encoded global ref we don't decode
	}
	obj, ok := mr.u32(v &^ 7)
	if !ok || obj == 0 {
		return 0
	}
	return uint64(obj)
}

// classNameOfRef resolves a jclass/jobject/jarray ref to a class name.
func (c *caches) classNameOfRef(mr *memReader, v uint64) string {
	if v == 0 {
		return "null"
	}
	obj := c.resolveObj(mr, v)
	if obj == 0 {
		if n, ok := c.classNames[v]; ok {
			return n
		}
		return "0x" + strconv.FormatUint(v, 16)
	}
	if n, ok := c.nameByClass[obj]; ok { // ref already is a Class object
		return n
	}
	if cp, ok := mr.u32(obj); ok {
		if n, ok := c.nameByClass[uint64(cp)]; ok {
			return n
		}
	}
	return "0x" + strconv.FormatUint(obj, 16)
}

func (c *caches) objClassName(mr *memReader, v uint64) string {
	if v == 0 {
		return "null"
	}
	if s, ok := c.jstr[v]; ok {
		return "\"" + s + "\""
	}
	n := c.classNameOfRef(mr, v)
	if strings.HasPrefix(n, "0x") {
		return n
	}
	return n + "@0x" + strconv.FormatUint(v, 16)
}

func isNumeric(t string) bool {
	switch t {
	case "jint", "jsize", "jlong", "jshort", "jbyte", "jchar", "jboolean", "jfloat", "jdouble":
		return true
	}
	return false
}

func fmtNumeric(t string, v uint64) string {
	switch t {
	case "jboolean":
		return strconv.FormatBool(v&0xff != 0)
	case "jbyte":
		return strconv.FormatInt(int64(int8(v)), 10)
	case "jchar":
		return fmt.Sprintf("'%c'", rune(v&0xffff))
	case "jshort":
		return strconv.FormatInt(int64(int16(v)), 10)
	case "jint", "jsize":
		return strconv.FormatInt(int64(int32(v)), 10)
	case "jlong":
		return strconv.FormatInt(int64(v), 10)
	case "jfloat":
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(v))), 'g', -1, 32)
	case "jdouble":
		return strconv.FormatFloat(math.Float64frombits(v), 'g', -1, 64)
	}
	return "0x" + strconv.FormatUint(v, 16)
}

// fmtArg / fmtRet decode a JNI argument/return by its schema type.
func fmtArg(c *caches, mr *memReader, typ string, v uint64) string {
	switch {
	case typ == "JNIEnv*" || typ == "":
		return ""
	case isNumeric(typ):
		return fmtNumeric(typ, v)
	case typ == "jclass":
		return c.classNameOfRef(mr, v)
	case typ == "jmethodID" || typ == "jfieldID":
		if n, ok := c.idName[v]; ok {
			return n
		}
		return "0x" + strconv.FormatUint(v, 16)
	case typ == "jstring":
		if s, ok := c.jstr[v]; ok {
			return "\"" + s + "\""
		}
		return c.classNameOfRef(mr, v)
	case strings.HasPrefix(typ, "jobject") || strings.HasPrefix(typ, "jarray") || strings.HasPrefix(typ, "jthrowable"):
		return c.objClassName(mr, v)
	case typ == "const char*" || typ == "char*":
		if v == 0 {
			return "NULL"
		}
		return "\"" + mr.cstr(v) + "\""
	}
	return "0x" + strconv.FormatUint(v, 16)
}

func fmtRet(c *caches, mr *memReader, typ string, v uint64) string {
	switch {
	case typ == "void" || typ == "":
		return "void"
	case isNumeric(typ):
		return fmtNumeric(typ, v)
	case typ == "jclass":
		return c.classNameOfRef(mr, v)
	case typ == "jstring":
		if s, ok := c.jstr[v]; ok {
			return "\"" + s + "\""
		}
		return c.classNameOfRef(mr, v)
	case typ == "jmethodID" || typ == "jfieldID":
		if n, ok := c.idName[v]; ok {
			return n
		}
		return "0x" + strconv.FormatUint(v, 16)
	case strings.HasPrefix(typ, "jobject") || strings.HasPrefix(typ, "jarray") || strings.HasPrefix(typ, "jthrowable"):
		return c.objClassName(mr, v)
	case typ == "const char*" || typ == "char*":
		if v == 0 {
			return "NULL"
		}
		return "\"" + mr.cstr(v) + "\""
	}
	return "0x" + strconv.FormatUint(v, 16)
}

// ---------------- call-variant argument snapshots ----------------

func parseParams(sig string) []string {
	var out []string
	if len(sig) == 0 || sig[0] != '(' {
		return out
	}
	i := 1
	for i < len(sig) && sig[i] != ')' {
		start := i
		switch sig[i] {
		case 'L':
			for i < len(sig) && sig[i] != ';' {
				i++
			}
			i++
		case '[':
			i++
			for i < len(sig) && sig[i] == '[' {
				i++
			}
			if i < len(sig) && sig[i] == 'L' {
				for i < len(sig) && sig[i] != ';' {
					i++
				}
				i++
			} else {
				i++
			}
		default:
			i++
		}
		if start < i && i <= len(sig) {
			out = append(out, sig[start:i])
		}
	}
	return out
}

func fmtJV(t string, v uint64, c *caches, mr *memReader) string {
	switch t {
	case "Z":
		return strconv.FormatBool(v&0xff != 0)
	case "B":
		return strconv.FormatInt(int64(int8(v)), 10)
	case "C":
		return fmt.Sprintf("'%c'", rune(v&0xffff))
	case "S":
		return strconv.FormatInt(int64(int16(v)), 10)
	case "I":
		return strconv.FormatInt(int64(int32(v)), 10)
	case "J":
		return strconv.FormatInt(int64(v), 10)
	case "F":
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(v))), 'g', -1, 32)
	case "D":
		return strconv.FormatFloat(math.Float64frombits(v), 'g', -1, 64)
	}
	return c.objClassName(mr, v)
}

func decodeA(e *reconEvt, params []string, c *caches, mr *memReader) []string {
	out := make([]string, 0, len(params))
	for i, t := range params {
		if i >= NCAP {
			out = append(out, "?")
			continue
		}
		out = append(out, fmtJV(t, e.Cap[i], c, mr))
	}
	return out
}

func decodeV(e *reconEvt, params []string, c *caches, mr *memReader) []string {
	out := make([]string, 0, len(params))
	grOffs := e.Vgoff
	stack := e.Vstk
	grBase := e.Vgr - 128
	for _, t := range params {
		if t == "F" || t == "D" {
			out = append(out, "?")
			continue
		}
		var val uint64
		if e.Vgr != 0 && grOffs < 0 {
			idx := int((int64(e.Vgr) + grOffs - int64(grBase)) / 8)
			if idx >= 0 && idx < NCAP {
				val = e.Cap[idx]
			}
			grOffs += 8
		} else {
			idx := int((stack - e.Vstk) / 8)
			if idx >= 0 && idx < NCAP {
				val = e.Cap2[idx]
			}
			stack += 8
		}
		out = append(out, fmtJV(t, val, c, mr))
	}
	return out
}

func decodeDirect(e *reconEvt, params []string, c *caches, mr *memReader) []string {
	out := make([]string, 0, len(params))
	for i, t := range params {
		if i >= int(e.Ncap) || i >= 2 {
			out = append(out, "?")
			continue
		}
		out = append(out, fmtJV(t, e.Cap[i], c, mr))
	}
	return out
}

func describeCall(e *reconEvt, nm string, c *caches, mr *memReader) (string, bool) {
	midIdx, ok := isCallMethod(nm)
	if !ok {
		return "", false
	}
	mid := e.A[midIdx]
	full, known := c.idName[mid]
	if !known {
		return fmt.Sprintf("%s mid=0x%x (?)", nm, mid), false
	}
	mname, msig := splitNameSig(full)
	cls := c.classNameOfRef(mr, e.A[1])
	if strings.HasPrefix(cls, "0x") {
		if cl, ok := c.idClass[mid]; ok {
			cls = c.classNameOfRef(mr, cl)
		}
	}
	if cls == "" {
		cls = "?"
	}
	params := parseParams(msig)
	var args []string
	switch {
	case strings.HasSuffix(nm, "A"):
		args = decodeA(e, params, c, mr)
	case strings.HasSuffix(nm, "V"):
		args = decodeV(e, params, c, mr)
	default:
		args = decodeDirect(e, params, c, mr)
	}
	return fmt.Sprintf("%s.%s(%s)", cls, mname, strings.Join(args, ", ")), true
}

func splitNameSig(s string) (string, string) {
	if i := strings.IndexByte(s, '('); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

func isCallMethod(n string) (int, bool) {
	if strings.HasPrefix(n, "NewObject") {
		return 2, true
	}
	if strings.HasPrefix(n, "Call") && strings.Contains(n, "Method") {
		if strings.Contains(n, "Nonvirtual") {
			return 3, true
		}
		return 2, true
	}
	return 0, false
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 200 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
func validSig(s string) bool {
	if len(s) == 0 || len(s) > 300 {
		return false
	}
	switch s[0] {
	case '(', 'L', '[', 'Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D':
	default:
		return false
	}
	return true
}

func indentStr(d int32) string {
	if d <= 0 {
		return ""
	}
	if d > 24 {
		d = 24
	}
	return strings.Repeat("  ", int(d))
}
