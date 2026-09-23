# NDK JNI 全接口覆盖测试

在 Android 上验证 JNIIEnv 函数表的完整可用性：用 NDK 编译一个 `libjnifull.so`，
由 Java `main` 通过 `System.load()` 加载，再用 `app_process` 启动 ART 执行测试。
测试覆盖 `JNINativeInterface` 的 **262 项断言，0 失败，1 跳过**（详见文末）。

## 目录结构

```
jni_fulltest/
├─ cpp/jnifull.c              # .so 源码：run_all_tests() 逐项调用 JNIEnv 全部函数
├─ src/com/test/jnifull/
│   ├─ Main.java              # 入口：等待按键 -> System.load -> 调用各 native -> 汇总退出
│   ├─ NativeTest.java        # native 声明（静态注册 + JNI_OnLoad 动态注册）
│   ├─ Target.java            # 被访问的目标类（全类型字段/方法、静态成员、同步方法）
│   ├─ SubTarget.java         # 子类，用于 CallNonvirtual*
│   ├─ Calc.java / CalcImpl.java  # 接口分派测试
│   └─ Temp.java              # 用于 RegisterNatives/UnregisterNatives
├─ build.ps1                  # 编译 .so + javac + d8 + 推送到设备
├─ run.ps1                    # 用 app_process 启动测试
└─ build/                     # 构建产物（arm64-v8a/libjnifull.so, dex/classes.dex, classes/）
```

## 环境要求

| 依赖 | 版本 / 位置（默认，可用环境变量覆盖） |
|------|----------------------------------------|
| Android NDK | `$env:NDK_HOME`，默认 `D:\Android\Sdk\ndk\26.1.10909125` |
| Android SDK | `$env:ANDROID_SDK_ROOT`，默认 `D:\Android\Sdk`（用到 build-tools 34.0.0 的 `d8.bat`、`platforms/android-33/android.jar`） |
| JDK | `$env:JAVA_HOME` 下的 `javac` |
| adb | 已在 PATH，且设备在线（`adb devices`） |
| 设备 | arm64-v8a / Android（本例 Pixel 6 / Android 13 / API 33） |

## 构建并推送

```powershell
pwsh -File build.ps1
```

脚本依次执行：

1. `aarch64-linux-android33-clang -shared -fPIC -O2` → `build/arm64-v8a/libjnifull.so`
2. `javac -source 8 -target 8 -classpath android.jar` → `build/classes`
3. `d8 --min-api 33` → `build/dex/classes.dex`
4. `adb push` 两个产物到 `/data/local/tmp/jnifull/` 并 `chmod 755`

## 运行

```powershell
# 交互：启动后等待你按任意键（回车）再开始测试
pwsh -File run.ps1

# 通过 root(su) 运行
pwsh -File run.ps1 -su

# 无人值守：跳过按键等待
pwsh -File run.ps1 -nowait
```

启动时会停在：

```
[Java] >>> Press any key (Enter) to start the test ...
```

按一下回车即开始。`-nowait`（或环境变量 `JNI_NO_WAIT=1`）会跳过该等待。
脚本用 `adb shell -t` 分配 pty，保证按键等待生效。

### 不依赖脚本，手动运行

```powershell
adb shell -t "cd /data/local/tmp/jnifull && \
  CLASSPATH=/data/local/tmp/jnifull/classes.dex \
  JNI_LIB_PATH=/data/local/tmp/jnifull/libjnifull.so \
  app_process /system/bin com.test.jnifull.Main"
```

- `CLASSPATH`：dex 路径，`app_process` 据此建立 `PathClassLoader`。
- `JNI_LIB_PATH`：`Main` 读取后传给 `System.load()`（默认即 `/data/local/tmp/jnifull/libjnifull.so`）。
- 加 `JNI_NO_WAIT=1` 可跳过按键等待。

## 输出与退出码

- 结束打印：`[Java] JNI table coverage: 262 passed, 0 failed, 1 skipped`
- 退出码：失败数为 0 时返回 `0`，否则非 0（便于 CI 判定）。
- 运行时会看到一段 `java.lang.IllegalStateException: throw-new-test` 栈——这是第 12 节故意调用
  `ExceptionDescribe()` 产生的**预期输出**，不是错误。

## 覆盖范围（16 组）

1. `GetVersion` / `FindClass` / `DefineClass`(错误路径) / `GetSuperclass` / `IsAssignableFrom`
2. 对象创建与判定：`NewObject`(+V/+A)、`AllocObject`、`GetObjectClass`、`IsInstanceOf`
3. 引用/局部帧/监视器：`NewGlobalRef`、`NewLocalRef`、`NewWeakGlobalRef`、`Delete*Ref`、
   `GetObjectRefType`、`EnsureLocalCapacity`、`Push/PopLocalFrame`、`MonitorEnter/Exit`、`IsSameObject`
4. 实例调用：`Call<Type>Method` + `...V` + `...A`（Object/Boolean/Byte/Char/Short/Int/Long/Float/Double/Void）
5. 非虚调用：`CallNonvirtual<Type>Method` + `V/A`
6. 静态调用：`CallStatic<Type>Method` + `V/A`
7. 字段：`Get/Set<Type>Field` 与 `Get/SetStatic<Type>Field`（全 8 种基本类型 + Object/String）
8. 字符串：`NewString(UTF)`、`GetString(UTF)Chars/Length/Region`、`GetStringCritical` + `Release*`
9. 数组：8 种基本数组的 `New/Get/Set...Region`、`Get/Release...ArrayElements`、
   `GetPrimitiveArrayCritical`、`NewObjectArray`、`Get/SetObjectArrayElement`、`GetArrayLength`
10. `NewDirectByteBuffer` / `GetDirectBufferAddress` / `GetDirectBufferCapacity`
11. 反射桥：`ToReflectedMethod/Field`、`FromReflectedMethod/Field`
12. 异常：`Throw`、`ThrowNew`、`ExceptionOccurred/Describe/Clear/Check`
13. 接口分派
14. `RegisterNatives` / `UnregisterNatives`
15. `GetModule`（见下，跳过）
16. `GetJavaVM` / `GetEnv` / `AttachCurrentThread` / `AttachCurrentThreadAsDaemon` / `DetachCurrentThread`

### 为什么有一项 SKIP（`GetModule`）

`[SKIP]` 表示**本平台不适用**，而非失败：

- NDK 19–29 的全部 `jni.h` 都未声明 `GetModule`，它不属于 NDK 的 JNI 契约；
- 运行时探测证实 ART 的 JNIEnv 函数表共 233 槽，末项为 `GetObjectRefType`（slot 232），其后全为 `0x0`；
- `GetModule` 是桌面 JDK 的 JPMS 扩展，Android/ART 无模块系统，故不存在。

未测的还有：4 个 `reserved` 槽（任何 VM 中均为 NULL）与 `FatalError()`（会终止进程）。
