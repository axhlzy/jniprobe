# jniprobe — 基于 eBPF 的 Android JNI 调用追踪器

在内核侧用 **uprobe + eBPF** 追踪目标 App 的 JNI（`JNINativeInterface`）调用，
打印**参数、返回值、调用树、耗时、调用栈**。全程**不注入任何代码**（无 Frida / 无 ptrace /
无 Zygisk），对用户态 App 基本无感

```
-> com.test.jnifull.Target.addInts(3, 4)
   #0 libart.so+0x67ed00
   #1 libjnifull.so+0xbc68
   #2 libjnifull.so+0x65c0
   #3 libart.so+0x2c23a4
<- com.test.jnifull.Target.addInts(3, 4) = 7  (0.005 ms)
```

---

## 1. 原理

ART 里所有 JNI 函数实现都挂在进程全局的 **`JNINativeInterface` 函数表**上（233 个槽）。
`libart.so` 被 strip，没有 `art::JNI*` 符号，所以唯一的入口是**运行期读这张表**拿到各 JNI
实现的地址，然后对它们挂 **uprobe**：

```
uprobe@libart:slot_offset
  ├─ 入口: 读 x0..x4 参数；对 Call* 变体按 AArch64 ABI 快照 jvalue*/va_list
  └─ uretprobe: 读 x0 返回值，按 (tid, depth) 与入口配对
```

- **参数**：`...A` 读 `jvalue*`；`...V` 解析 AArch64 `va_list`（GPR 保存区+溢出栈）；
  变参 C 直接从入口寄存器取。参数内存都在**事件发生当下**于 BPF 里快照，避免异步读栈被覆盖。
- **不透明句柄解码**：`jmethodID/jfieldID` 用运行期观察到的 `GetMethodID` 返回值缓存反解；
  `jclass/jobject` 走 ART 的间接引用表（IRTable）：`ref → 槽(u32) → 对象 → *(u32)对象 = Class`，
  类名用 `FindClass` 建立 `Class* → "a.b.C"` 缓存。
- **调用树 / 返回**：BPF 维护 per-thread 深度，`(tid, depth)` 配对入口与返回。
- **调用栈**：`BPF_MAP_TYPE_STACK_TRACE` + `bpf_get_stackid(BPF_F_USER_STACK)`，帧解析为
  模块名+偏移；入口处的调用者返回地址（LR）会补回第一帧之后。
- **偏移推导**：默认 `auto`——扫描目标进程 `libart.so` 的 data 段，找到 233 个连成一排、
  全部落在其可执行段内的指针数组（`reserved0..3 == 0`）即函数表。ART 有多张表
  （fast + CheckJNI），无法判断进程用哪张，故**合并所有候选表**（同槽 offset 都映射到同一槽号），
  全部挂点，哪张在用哪张触发。

---

## 2. 环境要求

| 项 | 要求 |
|---|---|
| 目标设备 | Linux 内核 **5.8+**（本文在 Android 13 / GKI 5.10.107 验证），需开启 `CONFIG_BPF_SYSCALL` / `CONFIG_UPROBE_EVENTS` / `CONFIG_BPF_EVENTS` / `CONFIG_DEBUG_INFO_BTF`；**root**（Magisk 即可）；SELinux 建议 Permissive |
| 构建机 | Linux（本文 aarch64 Debian 12）：`clang`(带 BPF target)、`bpftool`、`libbpf` 头文件、`make`、`go 1.21+`；目标内核的 `vmlinux.h`（用于编译，可选） |

> 交叉编译后端用 **Go + `cilium/ebpf`**（纯 Go，静态 arm64，直接跑在 Android 上，
> 不需要 NDK / libbpf）。

---

## 3. 目录结构

```
jniprobe/
├─ bpf/
│  ├─ recon.bpf.c        # 主程序：uprobe/uretprobe，参数快照、返回值、深度、栈
│  └─ envprobe.bpf.c     # env 探针：抓 JNIEnv* 并 dump 函数表（生成 offsets.json）
├─ loader/               # Go 用户态程序（子命令 env/dump/默认追踪）
│  ├─ main.go            # 入口 / 参数解析 / 配置
│  ├─ target.go          # pid 解析、libart 映射、/proc/pid/mem 读取、dump 模式
│  ├─ offsets.go         # 偏移来源：扫描(auto) / 文件(json)
│  ├─ schema.go          # 槽 → JNI 函数名 / 返回类型 / 类别
│  ├─ decode.go          # 句柄与参数/返回值解码、IRTable 解析、caches
│  ├─ filters.go         # -m/--only/--exclude/-g/--class/--method/--from 过滤
│  ├─ env.go             # env 模式实现
│  ├─ trace.go           # 追踪主循环（挂点、配对、调用树、栈、交互命令）
│  ├─ jni_names.go       # 233 个 JNI 函数名（jni.h 顺序，生成）
│  └─ jni_schema.go      # 233 项 参数类型/返回类型（生成）
├─ test/jni_fulltest/    # NDK JNI 全接口覆盖测试（deepCall 多层链）；build.ps1 / build.sh + cpp/ + src/
├─ Makefile              # clang 编 BPF + Go 交叉编译
└─ （构建产物 jniprobe、*.bpf.o 不提交）
```

---

## 4. 构建

```bash
cd jniprobe
# 需要 vmlinux.h（从目标内核 BTF 生成；仅用于编译，不影响运行）
#   scp root@<device>:/sys/kernel/btf/vmlinux ./vmlinux_android.btf
#   bpftool btf dump file vmlinux_android.btf format c > vmlinux.h
make build          # -> ./jniprobe （静态 arm64 可执行）
```

`Makefile` 关键点：`clang -target bpf -D__TARGET_ARCH_arm64` 编 `.o`，
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` 出静态二进制。

部署：

```bash
adb push jniprobe /data/local/tmp/jniprobe
adb shell su -c "chmod 755 /data/local/tmp/jniprobe"
```

---

## 5. 使用

```
jniprobe -p <pid> [选项]        或   jniprobe -n <进程名>

目标
  -p, --pid <pid>             目标 PID
  -n, --name <substr>         按 cmdline 匹配并自动解析 PID
      --run <sec>             跑 N 秒自动退出（不加则 Ctrl-C 停）

偏移来源（默认 auto，一般不用管）
      --offsets <auto|路径>   auto=扫描目标 libart 内存推导; 或给 jni_offsets.json
      --libart <path>         覆盖 libart 路径

监听范围（默认全量）
  -m, --mode <list>           call,new,field,class,string,other,all（默认 all）
      --only <前缀列表>       只保留这些 JNI 函数（逗号分隔，支持前缀/子串）
      --exclude <前缀列表>    排除
      --no-returns            不抓返回值/调用树（开销更低）
      --max-depth <n>         调用树最大深度

过滤
  -g, --grep <substr>         渲染文本包含该子串才显示
      --class <regex>         类名匹配
      --method <regex>        方法名/签名匹配
      --from <模块>           只看由指定 .so 发起的调用
      --tid <id>              只看某线程

输出
  -S, --stack                 对命中行打印用户态调用栈
  -v, --verbose               显示未解析函数的原始参数
      --count                 聚合模式（按 distinct 调用计数）
      --json                  结构化输出
      --no-color

运行时交互（终端输入，实时改过滤）
  only <re> | from <so> | grep <str> | mode <m> | clear | stats | quit

其它子命令
  jniprobe env                抓一次 env 表写入 /data/local/tmp/jni_offsets.json
  jniprobe dump <pid> <地址> [字数]   读目标内存（调试用）
```

### 常用示例

```bash
# 只看 Call*Method* 系列，且只看某 so 发起、带调用栈
/data/local/tmp/jniprobe -p $PID -m call --from libil2cpp.so -S

# 只看某个方法相关，并看返回值/耗时
/data/local/tmp/jniprobe -p $PID -g onProductDetailsResponse

# 全量跑 10 秒后退出
/data/local/tmp/jniprobe -p $PID --run 10
```

---

## 6. 测试（`test/jni_fulltest`）

NDK 编译的 **JNI 全接口覆盖测试**（262 项断言，覆盖 `JNINativeInterface` 几乎全部函数），
外加多层调用链 `deepCall → deep1 → deep2 → deep3 → FindClass` 用于验证调用栈。

**只构建**（CI 也是这一步；CI 不运行）：

```powershell
pwsh -File test/jni_fulltest/build.ps1                 # Windows（需 NDK_HOME/ANDROID_SDK_ROOT/JAVA_HOME）
```
```bash
ANDROID_SDK_ROOT=<sdk> bash test/jni_fulltest/build.sh  # Linux / CI
```

产物：`test/jni_fulltest/build/arm64-v8a/libjnifull.so`、`build/dex/classes.dex`。

**运行（需真机 + root）**：`app_process` 是 Android 专有可执行文件，普通 Linux/CI 跑不了。

```bash
adb push test/jni_fulltest/build/arm64-v8a/libjnifull.so \
         test/jni_fulltest/build/dex/classes.dex /data/local/tmp/jnifull/
adb shell su -c "cd /data/local/tmp/jnifull && CLASSPATH=./classes.dex JNI_LIB_PATH=./libjnifull.so JNI_NO_WAIT=1 \
  app_process /system/bin com.test.jnifull.Main"
```

想在测试跑起来前先挂探针：先以 `app_process` 拉起它拿到 pid，`jniprobe -p <pid>` 挂上后再放行即可。
预期输出 `JNI table coverage: 262 passed, 0 failed, 1 skipped` 与 `Target.addInts(3, 4) = 7` 等。

---

## 7. 已知限制

- **间接引用解码不完整**：多数 `jclass/jobject` 能解成类名（IRTable 路径），但
  `IsInstanceOf`/`IsSameObject` 一类的“紧凑编码”引用暂未解，仍显示十六进制。
- **`jmethodID/jfieldID`** 只对“挂上之后 `Get` 过”的 ID 能反解。
- **`float/double` 的 `va_list` 参数**显示 `?`（FP 保存区未快照）。
- 进入 ART 之后的栈帧可能中断（部分 ART 帧无 frame pointer）