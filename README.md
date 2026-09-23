# jniprobe — an eBPF-based Android JNI call tracer

Traces JNI (`JNINativeInterface`) calls of a target Android app from the **kernel side**
using **uprobe + eBPF**, printing **arguments, return values, call tree, duration and call
stacks**. It performs **no code injection** (no Frida / no ptrace / no Zygisk), so it is
essentially invisible to user-space apps and does not trip anti-debug / anti-Frida checks.

```
-> com.test.jnifull.Target.addInts(3, 4)
   #0 libart.so+0x67ed00
   #1 libjnifull.so+0xbc68
   #2 libjnifull.so+0x65c0
   #3 libart.so+0x2c23a4
<- com.test.jnifull.Target.addInts(3, 4) = 7  (0.005 ms)
```

---

## 1. How it works

In ART every JNI function implementation is referenced by the process-global
**`JNINativeInterface` function table** (233 slots). `libart.so` is stripped (no
`art::JNI*` symbols), so the only way in is to read this table at runtime to get the
addresses of the JNI implementations and then attach **uprobes** to them:

```
uprobe@libart:slot_offset
  ├─ entry: read x0..x4 args; for Call* variants snapshot jvalue*/va_list per AArch64 ABI
  └─ uretprobe: read x0 return value, pair with entry by (tid, depth)
```

- **Arguments**: `...A` reads a `jvalue*`; `...V` parses an AArch64 `va_list` (GPR save area +
  overflow stack); variadic-C args are taken from the entry registers. Argument memory is
  snapshotted **inside BPF at event time**, avoiding races with the volatile user stack.
- **Opaque handle decoding**: `jmethodID/jfieldID` are resolved from a cache built by observing
  `GetMethodID` return values; `jclass/jobject` go through ART's indirect reference table
  (IRTable): `ref → slot(u32) → object → *(u32)object = Class`, with class names cached from
  `FindClass` as `Class* → "a.b.C"`.
- **Call tree / returns**: BPF keeps a per-thread depth; entry and return are paired by `(tid, depth)`.
- **Call stacks**: `BPF_MAP_TYPE_STACK_TRACE` + `bpf_get_stackid(BPF_F_USER_STACK)`, frames
  resolved to `module+offset`; the caller's return address (LR) captured at entry is re-inserted
  right after the first frame.
- **Offset discovery**: default `auto` — scan the target's `libart.so` data segments for a run of
  233 consecutive pointers that all fall inside its executable segment (`reserved0..3 == 0`),
  which is the function table. ART ships more than one such table (fast + CheckJNI) and we cannot
  tell which one the process uses, so we **union all candidates** (same slot, different offsets →
  same slot index), attach to all, and whichever table is in use fires.

---

## 2. Requirements

| Item | Requirement |
|---|---|
| Target device | Linux kernel **5.8+** (validated on Android 13 / GKI 5.10.107) with `CONFIG_BPF_SYSCALL` / `CONFIG_UPROBE_EVENTS` / `CONFIG_BPF_EVENTS` / `CONFIG_DEBUG_INFO_BTF`; **root** (Magisk is fine); SELinux Permissive recommended |
| Build host | Linux (validated on aarch64 Debian 12): `clang` (with BPF target), `bpftool`, `libbpf` headers, `make`, `go 1.21+`; the target kernel's `vmlinux.h` (for compiling, optional) |

> The userspace loader is written in **Go + `cilium/ebpf`** (pure Go, static arm64, runs directly
> on Android — no NDK / libbpf needed).

---

## 3. Layout

```
jniprobe/
├─ bpf/
│  ├─ recon.bpf.c        # main program: uprobe/uretprobe, arg snapshots, return, depth, stack
│  └─ envprobe.bpf.c     # env probe: capture JNIEnv* and dump the function table (offsets.json)
├─ loader/               # Go userspace program (subcommands env/dump/default trace)
│  ├─ main.go            # entry / flag parsing / config
│  ├─ target.go          # pid resolution, libart maps, /proc/pid/mem reader, dump mode
│  ├─ offsets.go         # offset sources: scan(auto) / file(json)
│  ├─ schema.go          # slot -> JNI function name / return type / category
│  ├─ decode.go          # handle & arg/ret decoding, IRTable resolution, caches
│  ├─ filters.go         # -m/--only/--exclude/-g/--class/--method/--from filters
│  ├─ env.go             # env mode implementation
│  ├─ trace.go           # trace loop (attach, pairing, call tree, stack, interactive cmds)
│  ├─ jni_names.go       # 233 JNI function names (jni.h order, generated)
│  └─ jni_schema.go      # 233 entries of arg/return types (generated)
├─ test/jni_fulltest/    # NDK JNI full-coverage test (deepCall chain); build.ps1 / build.sh + cpp/ + src/
├─ Makefile              # clang compile BPF + Go cross build
└─ (build outputs: jniprobe, *.bpf.o — not committed)
```

---

## 4. Build

```bash
cd jniprobe
# needs vmlinux.h (generated from the target kernel BTF; compile-time only, not runtime)
#   scp root@<device>:/sys/kernel/btf/vmlinux ./vmlinux_android.btf
#   bpftool btf dump file vmlinux_android.btf format c > vmlinux.h
make build          # -> ./jniprobe (static arm64 executable)
```

Key points in the `Makefile`: `clang -target bpf -D__TARGET_ARCH_arm64` compiles the `.o`, and
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` produces the static binary.

Deploy:

```bash
adb push jniprobe /data/local/tmp/jniprobe
adb shell su -c "chmod 755 /data/local/tmp/jniprobe"
```

---

## 5. Usage

```
jniprobe -p <pid> [options]        or   jniprobe -n <name>

Target
  -p, --pid <pid>             target PID
  -n, --name <substr>         match cmdline and resolve PID automatically
      --run <sec>             run N seconds then exit (otherwise Ctrl-C)

Offset source (default auto, usually nothing to do)
      --offsets <auto|path>   auto=scan target libart memory; or give jni_offsets.json
      --libart <path>         override libart path

What to trace (default: everything)
  -m, --mode <list>           call,new,field,class,string,other,all (default all)
      --only <prefix list>    keep only these JNI functions (comma separated, prefix/substr)
      --exclude <prefix list> drop these
      --no-returns            do not capture return values / call tree (lower overhead)
      --max-depth <n>         max call-tree depth

Filters
  -g, --grep <substr>         show only lines whose rendered text contains this
      --class <regex>         match class name
      --method <regex>        match method name/signature
      --from <module>         show only calls issued by the given .so
      --tid <id>              show only this thread

Output
  -S, --stack                 print a user call stack for matched lines
  -v, --verbose               also print un-parsed function calls
      --count                 aggregate mode (count distinct calls)
      --json                  structured output
      --no-color

Interactive (type in the terminal to change filters live)
  only <re> | from <so> | grep <str> | mode <m> | clear | stats | quit

Other subcommands
  jniprobe env                capture the env table once into /data/local/tmp/jni_offsets.json
  jniprobe dump <pid> <addr> [words]   read target memory (debug)
```

### Examples

```bash
# only Call*Method*, only those issued by one .so, with call stacks
/data/local/tmp/jniprobe -p $PID -m call --from libil2cpp.so -S

# only calls related to a method, with return values / duration
/data/local/tmp/jniprobe -p $PID -g onProductDetailsResponse

# full trace for 10 seconds then exit
/data/local/tmp/jniprobe -p $PID --run 10
```

---

## 6. Test (`test/jni_fulltest`)

An NDK-built **JNI full-coverage test** (262 assertions covering almost every
`JNINativeInterface` function) plus a multi-level native call chain
`deepCall → deep1 → deep2 → deep3 → FindClass` to verify call stacks.

**Build only** (this is also what CI does; CI does not run it):

```powershell
pwsh -File test/jni_fulltest/build.ps1                 # Windows (needs NDK_HOME/ANDROID_SDK_ROOT/JAVA_HOME)
```
```bash
ANDROID_SDK_ROOT=<sdk> bash test/jni_fulltest/build.sh  # Linux / CI
```

Artifacts: `test/jni_fulltest/build/arm64-v8a/libjnifull.so`, `build/dex/classes.dex`.

**Run (real device + root only)**: `app_process` is an Android-only binary; a plain
Linux/CI runner cannot execute it.

```bash
adb push test/jni_fulltest/build/arm64-v8a/libjnifull.so \
         test/jni_fulltest/build/dex/classes.dex /data/local/tmp/jnifull/
adb shell su -c "cd /data/local/tmp/jnifull && CLASSPATH=./classes.dex JNI_LIB_PATH=./libjnifull.so JNI_NO_WAIT=1 \
  app_process /system/bin com.test.jnifull.Main"
```

To attach the probe before the test starts: launch it via `app_process` to obtain the pid,
attach `jniprobe -p <pid>`, then let it proceed.
Expected: `JNI table coverage: 262 passed, 0 failed, 1 skipped` and lines like `Target.addInts(3, 4) = 7`.

---

## 7. Known limitations

- **Incomplete indirect-reference decoding**: most `jclass/jobject` resolve to class names
  (IRTable path), but the "compact" encoding used by `IsInstanceOf`/`IsSameObject` is not decoded
  yet and is shown as hex.
- **`jmethodID/jfieldID`** are only resolved for IDs obtained via `GetMethodID` while attached.
- **`float/double` `va_list` arguments** show `?` (the FP save area is not snapshotted).
- Stack frames may break after entering ART (some ART frames lack a frame pointer).
- The union of candidate tables makes the probe count large (~690 entry + several return).

## 8. Transparency note

uprobe/eBPF is kernel-side instrumentation: no code injection, no ptrace, no changes to the
app's memory layout, no extra threads, no Frida — so the app itself cannot perceive it and
anti-debug / anti-Frida logic is not triggered. (The only "trace" is the kernel-installed
uprobe breakpoint, which is kernel-managed.)
