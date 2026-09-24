# SO 层分析（Native Analysis）

> 何时读：用户提到"分析这个 so/native 函数/so 里的加密/字符串引用/交叉引用/逆向 so/找不到导出/STRIPPED"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。静态工具（Python）在项目根 `tools/`，Frida 模块在 `scripts/monitors/` 和 `scripts/utils/`（命令里的 `scripts/...` 为技能相对：复制执行先 `cd .kilo/skill/frida-mobile-security` 或展开全路径 `.kilo/skill/frida-mobile-security/scripts/...`）。

---

## 一、分层分析原则

当上层 hook 失效时，按此递推下钻到更底层：

```
Java/ObjC → Java.use / ObjC.classes
  ↓ 被绕过时
JNI Bridge → RegisterNatives 劫持
  ↓
Native .so → Interceptor.attach(导出函数)
  ↓
libc → Interceptor.attach(libc 函数)
  ↓
syscall → Interceptor.attach(syscall)
  ↓
SVC #0 → Stalker / inline hook
```

完整调用链：`Java/ObjC → JNI/Runtime → Native .so → libc → syscall → svc`

### 常见下钻场景

| 现象 | 原因 | 下钻到 |
|------|------|--------|
| crypto_monitor 无输出 | 非 Java 层 | native_hooker |
| file_monitor 无输出 | 函数内联 | syscall_tracer |
| network_monitor 无 connect | 使用 sendto(UDP) | 检查 recvfrom |
| network_monitor 无输出 | Binder/Unix Socket | syscall_tracer(traceAll:true) |
| dl_monitor 无输出 | 自定义 linker | syscall_tracer (mmap+PROT_EXEC) |
| native_hooker 无输出 | SO 尚未加载 | spawn 模式或 dl_monitor |
| native_hooker [STRIPPED] | 去符号 | dlsym_tracer |
| ssl_plaintext 无输出 | 非标准 HTTP 库 | network_monitor(showPayload:true) |

---

## 二、Dex2C 按需分析

Dex2C = Java 方法编译成 ARM 机器码进 .so，DEX 里只剩 native 声明。**脱壳无效，做按需定位分析**（需要看哪个函数就定位哪个，不做全量逆向）。

**精髓**：Java 的 GC、反射、动态特性在 C 里难实现，所以 Dex2C 只迁移关键方法（加密、签名、校验），不是全部代码——目标函数通常就是那几个关键方法，按需定位即可。

**分析优先级（从轻到重）**：
```
① 动态 hook（默认，零成本）：拿明文/密文/key/返回值/调用链
② unidbg 模拟执行（复现算法）：PC 上直接跑 .so，无需真机/IDA
③ Ghidra 伪代码（理解内部）：MCP 命令行反编译，比 IDA 轻
④ IDA（基本不用）：重量级，仅当需要深度交互逆向时
```

### 2.0 动态 hook 优先（不用开反汇编工具）

```bash
# native_hooker 直接抓参数/返回值/中间值
frida -H 127.0.0.1:8888 -f com.app -l scripts/core/utils.js -l scripts/monitors/native_hooker.js \
  -e 'var CONFIG_OVERRIDE={native_hooker:{targetLibs:["libTdxAndroidCore"],hookPatterns:["encrypt"]}};'
```

- 输出：参数(hexdump)/返回值/调用栈（Thread.backtrace）
- 90% 场景到此为止：明文、密文、key、算法参数、返回值全拿到
- 需要 key 来源 → hook 上层调用者；需要中间值 → 下钻子函数 hook

### 2.1 unidbg 模拟执行（复现算法，无需真机/IDA）

**场景**：hook 拿到数据但需要「复现算法」（写脚本模拟）、或 hook 拿不到完整逻辑时。

**原理**：unidbg 在 PC 上模拟 Android 运行环境，直接调用 .so 的 JNI 方法，传入参数拿返回值，逐步参数打桩看中间状态。

```java
// 1. 建 emulator，加载目标 so
Emulator emulator = AndroidEmulatorBuilder.for64Bit().build();
Memory memory = emulator.getMemory();
memory.setLibraryResolver(new AndroidResolver(23));
DalvikVM vm = emulator.createDalvikVM(new File("libTdxAndroidCore.so"));
vm.setJni(new MyJni());  // 打桩 JNI 调用

// 2. 调用 JNI 方法（Java_com_tdx_crypto_Encrypt_encrypt）
byte[] in = "hello".getBytes();
ByteArray arg = new ByteArray(in);
Object ret = vm.callStaticJniMethodObject(emulator,
    "com/tdx/crypto/Encrypt/encrypt([B)[B", arg);
// 3. 拿到密文，对比真机 hook 结果验证
```

- 依赖：JDK + Maven/Gradle 工程（unidbg 是 Java 库，非 pip 包；Maven 坐标 `com.github.zhkl0228:unidbg-android`）+ 目标 so 从设备 `adb pull`
- 优点：不碰真机、不碰 IDA、可断点/打桩/打印中间值
- 代价：环境搭建一次（约 1 小时），JNI 打桩需按目标类补

**典型用途**：
- 复现加密算法（输入→输出，写脚本批量跑）
- 逆向 key 派生（Hook 打桩 JNI 调用，看 key 参数）
- 绕过时间/环境校验（打桩 System.currentTimeMillis / getDeviceId）

### 2.2 Ghidra 伪代码（命令行，比 IDA 轻）

```bash
# 导入 so（ARM64），对话内直接反编译目标偏移
ghidra_import_file ./libTdxAndroidCore.so
# 转到 scan_register_natives 输出的偏移，看伪代码
```

- 已集成 `ghidra_*` MCP 工具，命令行/对话驱动，无需手动开 GUI
- 配合 `tools/so.py strref`（字符串引用）快速定位关键逻辑

### 2.3 定位流程

```
Step 1: 定位 native 方法实现
  模块: utils + scan_register_natives.js（hook RegisterNatives 动态注册）
  输出: com.app.crypto.Encrypt.encrypt → libxxx.so + 0x1A2F4
  ├── [Dex2C 常见] 动态注册 → 直接拿到 so+offset
  └── [无输出] 静态注册 → Module.findExportByName("libxxx.so", "Java_...")

Step 2: 按需选择分析手段（见上 2.0/2.1/2.2）
  ├── 只要数据 → native_hooker 动态抓
  ├── 要复现算法 → unidbg 模拟执行
  └── 要理解内部 → Ghidra 反编译该偏移
```

## 三、SO 动态分析

### 2.1 native_hooker（任意 native 函数）

```bash
frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/native_hooker.js \
  -e 'var CONFIG_OVERRIDE={native_hooker:{targetLibs:["libencrypt"],hookPatterns:["encrypt","aes","xor"]}};'
```

- 默认模式: encrypt/decrypt/aes/rsa/des/sha/hmac/base64/xor
- 命中后自动打印参数(hexdump)/返回值/调用栈
- `[STRIPPED]` → 追加 `dlsym_tracer` 看运行时解析
- 没找到明显 crypto so → 清空 targetLibs 扫描全部 /data/ so

### 2.2 native_crypto_monitor（OpenSSL/BoringSSL）

- 监控 EVP 加解密函数，内置 fallback 链：`EVP_CIPHER_CTX_cipher || EVP_CIPHER_CTX_get0_cipher`
- 无输出时扩展 CRYPTO_SOS 列表：Flutter app 加 `libflutter.so`，Cronet 加 `libcronet.so`
- 用 `tools/so.py svc` 或内存常量扫描定位自研算法

### 2.3 dl_monitor（SO 生命周期）

```bash
frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/dl_monitor.js
```

- 加载/卸载/符号解析全生命周期
- 无输出 → 自定义 linker → syscall_tracer (mmap+PROT_EXEC)

### 2.4 动态加载库的 hook 时机

```javascript
// 监控 dlopen 以便在目标库加载时立即 hook
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
Interceptor.attach(android_dlopen_ext, {
    onEnter: function (args) { this.path = args[0].readCString(); },
    onLeave: function (retval) {
        if (this.path && this.path.indexOf("libtarget") !== -1) {
            var mod = Process.findModuleByName("libtarget.so");
            // ... 执行 hook
        }
    }
});
```

### 2.5 导入函数 hook（导入 ≠ 导出）

目标 so 里调用的 `strncmp`/`memcmp` 等是**导入符号**，`Module.findExportByName("<目标so>", "strncmp")` 永远返回 null。正确姿势：hook libc 导出 + 按调用者过滤：

```javascript
var addr = Module.findExportByName("libc.so", "strncmp");
Interceptor.attach(addr, {
    onEnter: function (args) {
        var caller = Process.findModuleByAddress(this.returnAddress);
        if (!caller || caller.name.indexOf("libfoo.so") === -1) return;  // 不过滤会被系统属性查询刷屏数千行
        console.log("[strncmp] '" + args[0].readUtf8String() + "' vs '" + args[1].readUtf8String() + "'");
    }
});
```

- 模块未加载时装不上 → `Utils.waitForModule("libfoo.so", cb)`（spawn 早期 so 尚未 dlopen，直接 find 会静默失败）
- **注意竞态**：`waitForModule` 是轮询（~100ms），so 加载后**立即调用**的 init/构造函数会漏 hook；对这类目标用 `native_hooker.js`（dlopen 同步安装）或 `init_hook.js`（call_constructors 抢时机）
- **先确认前置条件**：目标可能只在输入满足条件（长度/格式）时才走到比较函数。用 `tools/so.py disasm <so> --symbol <JNI导出>` 看判断分支，或 hook JNI 入口打印参数/返回值

---

## 四、SO 静态分析（Ghidra MCP）

Ghidra MCP 支持反编译 + 调试（`ghidra_*` 工具），用于分析 so 的逻辑。

### 3.1 工作流

1. 从设备提取 so：`adb pull`（或 `scripts/utils/so_dump.js` 动态 dump）
2. 导入 Ghidra：`ghidra_import_file`（ELF 自动识别；显式指定 ARM64 用 `AARCH64:LE:64:v8A`，ARM32 用 `ARM:LE:32:v7`）
3. 反编译定位关键函数
4. 结合动态 hook 验证（native_hooker + 调用栈）

### 3.2 符号/字符串定位工具

| 工具 | 用途 |
|------|------|
| `tools/so.py info/strings/dump` | ELF 侦察（段/依赖/导出/导入/重定位/vaddr↔offset）/ 字符串枚举 / 按址读字节 |
| `tools/so.py strref` | 定位字符串引用（adr / adrp+add / adrp+ldr——Ghidra 自动 xref 失效的 adr 也能命中） |
| `tools/so.py callers` | 定位函数调用者（BL / B / B.cond / CBZ / TBZ，可 `--bl-only`） |
| `tools/so.py disasm` | 快速反汇编（按 symbol/vaddr，capstone；Ghidra 未启动时的 fallback，`--grep` 过滤） |
| `tools/so.py jni` | JNI 导出签名侦察（JNI 调用点清单 + Java 第 1 参类型推断：jstring/jbyteArray/…） |
| `tools/emu_run.py` | 单函数离线仿真（Unicorn）；内置观测层 `--watch-code/--watch-regs/--watch-buf/--watch-read/--watch-write/--scan`（超限自动聚合，防日志爆炸）；JNI/桩日志 `--log-jni/--trace-stubs/--stub name=val/--dump-jni-out FILE` |
| `tools/trace_recon.py` | 仿真 trace 状态重建：观测日志 → 缓冲状态序列（COPY/PASS 自动分段，支持 `--json`） |
| `tools/cipher_lab.py` | 密码结构判定器：`layers`（层写法双轨迹判定）/ `table`（白盒表 S(Y⊕k)⊕c 反推）/ `schedule`（轮密钥→标准 AES-128 编排归因，出主密钥） |
| `tools/so.py svc` | 扫描内联 SVC 指令（检测代码特征） |
| `tools/fix_elf.py` | 修复 ELF header（dump 后） |
| `tools/patch_gadget_threadnames.py` | patch gadget 线程名 |
| `lief`（pip） | ELF 改写：dump so 的 header/段表修复重建、patch 常量、加节/改 `DT_NEEDED`、重定位与 `.init_array` 提取、内存 dump 回写成标准 ELF |
| `z3-solver`（pip） | 约束求解：从"条件/结果"反推输入（校验/序列号、签名构造）；不执行代码，不可逆哈希无效 |

### 3.3 算法结构复原流水线（仿真 / 真机 双路径）

观测 → 重建 → 判定 三段式，两个来源共用同一条管道（日志格式 `[wr] addr size=N val=0xV pc=0xPC`）：

- **仿真路径（优先）**：`tools/emu_run.py --watch-code/--watch-buf/--watch-read/--watch-write/--scan`（可反复、可 poke、无检测）
- **真机路径**（目标无法仿真 / VM 化 / 依赖运行时）：`scripts/monitors/mem_trace.js` + `tools/frida_run.py -e @cfg.js`
  配置示例：`var CONFIG_OVERRIDE={mem_trace:{ranges:[{module:"libfoo.so",off:0x15038,size:24,mode:"w"}]}};`
- **重建**：`tools/trace_recon.py <日志> --base <armed 行打印的实际地址> --size N [--copy-pc ...]`
- **判定**：`tools/cipher_lab.py layers`（层结构，双轨迹）/ `table`（`S(Y⊕k)⊕c` 表反推）/ `schedule`（AES 系编排归因，可直接出主密钥）
- **边界**：① 白盒表若带线性编码（真·Chow 式），`layers/table` 不适用，需 DFA/BGE（未实现）② `mem_trace` 基于 MemoryAccessMonitor：默认单次触发（稳定），`rearm:true` 可在标准 server 上滚动捕获（魔改 server 有崩溃记录）③ `details.pc` 在部分 frida 版本不存在，取 `from`（模块内已兼容）

### 3.4 定位目标函数的方法（优先级从高到低）

1. **导出符号** → `Module.findExportByName()`
2. **已知特征码** → `Memory.scan()` + 特征字节
3. **通过调用者定位** → hook 调用者，从 context/returnAddress 反查
4. **通过字符串引用定位** → 搜索字符串 → 交叉引用
5. **通过 PLT/GOT 表** → 解析 ELF 结构
6. **通过 JNI RegisterNatives** → 监听动态注册
7. **通过 Stalker 追踪** → 大面积代码追踪 + 特征分析

### 3.4 处理去符号/STRIPPED 库

```javascript
// 扫描已知字节模式
Memory.scan(mod.base, mod.size, "55 48 89 E5", { onMatch: function (address, size) { } });
```

### 3.5 SO 分析顺序（`tools/so.py` 离线工具）

一个 so 从"有什么"到"要 hook 什么"的标准下钻顺序（离线、可复现，不依赖 Ghidra/Frida/设备）：

```
info/strings 发现 → strref 引用 → disasm 上下文 → jni hook 前置 → (svc 下钻 / emu_run 复算)
```

1. **发现**：`tools/so.py info <so>` 看段/依赖/导出/导入/重定位（`--grep NAME` 直接在导出表里找函数，`--json` 供脚本消费）；`tools/so.py strings <so> --grep PAT` 找明文常量/日志串（输出 vaddr+file offset 双列）
2. **引用**：拿到关键字符串 vaddr → `tools/so.py strref <so> 0xSTR` 反查引用点（支持 `adr` / `adrp+add` / `adrp+ldr`，混淆下 Ghidra 自动 xref 失效也能命中）
3. **上下文**：`tools/so.py disasm <so> --addr 0x… --count N` 读引用点所在函数；有符号直接 `--symbol <导出>`；要调用链用 `tools/so.py callers <so> 0xFUNC`（BL/B/B.cond/CBZ/TBZ）
4. **判型**：hook 前 `tools/so.py jni <so> --symbol Java_…` 判 Java 第 1 参类型（jstring/jbyteArray/…——按错类型读会把进程打崩在 agent 里）
5. **下钻**：`tools/so.py svc <so>` 看是否绕过 libc 直接 syscall（决定 hook 层）；算法复算接 `tools/emu_run.py <so> --sym … [--jni]`

旧工具 → 新命令：

| 旧 | 新 |
|---|---|
| `elfinfo.py <so> [--json] [--v2o a]` | `so.py info <so> [--json] [--v2o a]` |
| `elfinfo.py <so> --strings [N] --grep P` | `so.py strings <so> --min N --grep P` |
| `elfinfo.py <so> --dump a:l` | `so.py dump <so> a:l [--off]` |
| `disasm.py <so> …` | `so.py disasm <so> …` |
| `find_strref.py <so> <a>` | `so.py strref <so> <a>` |
| `find_branch_callers.py <so> <a>` | `so.py callers <so> <a>` |
| `scan_inline_svc.py <so>` | `so.py svc <so>` |
| `jni_sig.py <so> …` | `so.py jni <so> …` |

---

## 五、JNI 层分析

### RegisterNatives 劫持（动态注册跟踪）

```javascript
var RegisterNatives = Module.findExportByName("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
Interceptor.attach(RegisterNatives, {
    onEnter: function (args) {
        var methods = args[2];
        var count = args[3].toInt32();
        for (var i = 0; i < count; i++) {
            var name = methods.add(i * 3 * Process.pointerSize).readPointer().readCString();
            var signature = methods.add(i * 3 * Process.pointerSize + Process.pointerSize).readPointer().readCString();
            var fnPtr = methods.add(i * 3 * Process.pointerSize + Process.pointerSize * 2).readPointer();
            console.log("[RegisterNatives]", name, signature, fnPtr);
        }
    }
});
```

### JNI 参数类型判读（hook 前置，避免崩在 agent）

`Java_*` 导出的第 3 参（env、thiz 之后的第一个 Java 参数）可能是 `jstring`、`jbyteArray`、`jobject`……**按错类型读会把进程打崩在注入 agent 里**（tombstone pc 落在 `memfd:*`、`#00 GetStringUTFChars` 帧，极易误判为反调试）。

1. **静态判型（首选）**：`python3 tools/so.py jni <so> --symbol <JNI导出>` —— 扫 `ldr xR,[xM,#imm]; blr xR` 解析 JNI API（arm64 offset = index×8），输出 `jbyteArray` / `jstring` / … 结论（L3 的 `bar`/`init` 实测判出 `jbyteArray`）
2. **反汇编口径**：`ldr x8,[env]`（取 vtable）→ `ldr x8,[x8,#off]` → `blr x8`；常用 offset：`0x5c0=GetByteArrayElements`、`0x558=GetArrayLength`（jstring 系不在这些槽位，别按直觉猜）
3. **Frida 读 byte[]**（偏移取自目标 so 自身反汇编，不凭猜）：

```javascript
function readJbyteArray(env, arr) {
    var vt = env.readPointer();
    var getLen = new NativeFunction(vt.add(0x558).readPointer(), 'int', ['pointer', 'pointer']);
    var getElems = new NativeFunction(vt.add(0x5c0).readPointer(), 'pointer', ['pointer', 'pointer', 'pointer']);
    var n = getLen(env, arr);
    return new Uint8Array(getElems(env, arr, ptr(0)).readByteArray(n));
}
```

完整实现见 `owasp.mstg.uncrackable3/hook_l3_dump.js` 的 `readJbyteArray`。

### NewStringUTF 字符串捕获

```javascript
var NewStringUTF = Module.findExportByName("libart.so", "_ZN3art3JNI12NewStringUTFEP7_JNIEnvPKc");
```

---

## 六、操作系统层（libc / syscall）

### 文件操作链

```
高层: fopen() / fgets()
  ↓
中层: open() / openat() / read() / __read_chk()
  ↓
底层: syscall(__NR_openat, ...) / svc #0
```

### 线程操作链

```
高层: pthread_create() / java.lang.Thread.start()
  ↓
中层: clone() / __clone()
  ↓
底层: syscall(__NR_clone, ...)
```

### syscall 追踪

```javascript
var syscall = Module.findExportByName("libc.so", "syscall");
if (syscall) {
    Interceptor.attach(syscall, {
        onEnter: function (args) {
            var nr = args[0].toInt32();
            var SYSCALL_NAMES = {
                56: "openat", 63: "read", 64: "write", 220: "clone",
                98: "futex", 101: "ptrace", 78: "readlinkat", 61: "write"
            };
            var name = SYSCALL_NAMES[nr] || ("sys_" + nr);
            console.log("[syscall]", name, "called from:", DebugSymbol.fromAddress(this.returnAddress));
        }
    });
}
```

用作模块：`utils + syscall_tracer`（内置过滤，见 `scripts/monitors/syscall_tracer.js`）。

### SVC #0 内联追踪（Stalker）

`svc_tracer.js` 用 Stalker 追踪 SVC 指令。性能开销大，注意：
- 设 `duration: 30` 只追踪前 30 秒
- 设 `targetModules: ["libexec.so"]` 只追踪检测 SO
- 设 `filterSyscalls: [93, 94, 129, 131]` 只看 kill/exit
- 大量 `[anon:rwx]` 输出 = 匿名 RX 段中的检测代码，记录 PC 地址用于 function_patcher

---

## 常用组合

| 分析目标 | 模块组合 |
|---------|---------|
| Native 加密 | `utils + native_hooker(targetLibs:["libencrypt","libssl","libcrypto"])` |
| SO 加载追踪 | `utils + dl_monitor` |
| 分层下钻 | `utils + native_hooker + syscall_tracer` |
| 导入函数（strncmp/memcmp 等） | hook libc 导出 + `Process.findModuleByAddress(this.returnAddress)` 过滤（见 2.5） |
| 字符串引用定位 | `tools/so.py strref` + Ghidra |
| 内联 SVC 扫描 | `tools/so.py svc` |
| Dex2C 定位 native 实现 | `utils + scan_register_natives.js` → Ghidra 单函数逆向 |