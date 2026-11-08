# SO 层分析（Native Analysis）

> 何时读：用户提到"分析这个 so/native 函数/so 里的加密/字符串引用/交叉引用/逆向 so/找不到导出/STRIPPED"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。静态工具（Python）在项目根 `tools/`，Frida 模块在 `scripts/monitors/` 和 `scripts/utils/`（命令里的 `scripts/...` 为技能相对：复制执行先 `cd .kilo/skill/frida-mobile-security` 或展开全路径 `.kilo/skill/frida-mobile-security/scripts/...`）。
> 要**找漏洞**（而非理解功能）、或怀疑堆越界 / UAF / double-free 时，走
> [native-audit.md ›「一、审计环」](native-audit.md#一审计环)：先定可达面再深审。

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

#### 2.0.1 先定位 Dex2C 入口（Java → native 那一层）

```js
// cfg.js
var CONFIG_OVERRIDE = { dex2c_entry: { classes: ["com.a.B"], methods: ["encrypt"] } };
```
```bash
frida -H 127.0.0.1:27042 -n Gadget -l scripts/core/utils.js -l cfg.js \
  -l scripts/utils/dex2c_entry.js -q -t 15
```

- 拿到 `so+offset` → Ghidra 只反汇编这一个函数
- 磁盘 so 可能是加密的（offset 处反汇编是无效指令）→ 先用 `utils/so_dump.js` dump 运行时模块再分析
- 输出 `native=false / data_=0` → 该方法运行时已被壳回填成 Java，不是 Dex2C；改用 `utils/dex_finder.js` dump 内存 dex
- `scan_register_natives.js` 只在 spawn（注册时在场）有效；attach 场景用 `dex2c_entry.js`

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

### 3.0 Ghidra vs IDA：不是"谁更智能"，是"谁能修"

两者对**正常 so** 的自动分析能力接近，差距出现在**畸形 so**（加壳/脱壳产物）上，而且差异是可解释的：

| 能力 | Ghidra | IDA | 说明 |
|------|--------|-----|------|
| 读 `.dynsym` 导出 | 读 `sh_size` 声明的项数 | 也读 `sh_size`，但会**交叉验证 DT_HASH** | 本例：段头谎报 3 项，Ghidra 只认 1 个名字，IDA 认出全部 539 项 |
| 重定位 | 解析 PT_DYNAMIC 的 DT_RELA，**自动应用到反编译视图** | 同样解析 | Ghidra 应用后 `DAT_` 会显示 `image_base+addend` |
| 建函数 | 保守：只跟 `bl`/`b`/入口形态 | 激进：符号 + 启发式 + 用户脚本 | 本例 Ghidra 3837 → 修符号后 4200 |
| 反编译质量 | 够用，命名差（`FUN_`） | 更好，尤其是 C++ 与异常处理 | 交叉验证时用 IDA |
| 脚本 | Java/Python，MCP 可跑 inline | IDAPython，生态更成熟 | 批量处理两边都能做 |

**结论**：不是 Ghidra "不够智能需要写脚本引导"，而是**两者都依赖 ELF 结构可信**。结构被伪造时，先修结构（§3.1.1），再谈工具选择。修好之后 Ghidra 完全够用；IDA 的价值在反编译可读性和交叉验证。

**决策顺序**：

```
so 是加壳/脱壳产物？
├─ 是 → 先做 C1~C6 验收（§3.5.1）→ 修段头 → 再导入
│        └─ 修完仍缺符号 → IDA 交叉验证（它更愿意猜）
└─ 否 → Ghidra 直接导入，按 §3.5 下钻
```

### 3.1 工作流

1. 从设备提取 so：`adb pull`（或 `scripts/utils/so_dump.js` 动态 dump）
2. 导入 Ghidra：`ghidra_import_file`（ELF 自动识别；显式指定 ARM64 用 `AARCH64:LE:64:v8A`，ARM32 用 `ARM:LE:32:v7`）
3. 反编译定位关键函数
4. 结合动态 hook 验证（native_hooker + 调用栈）

### 3.1.1 加壳 SO 的静态前置：先信 DT_*，别信 section header

部分加固壳会把 **section header 改成假值**（典型：`.dynsym` 的 `sh_size` 只声明 3 项，真实 539 项），目的是让 IDA/Ghidra/`readelf` 都看不见导出表。**权威来源永远是 PT_DYNAMIC 里的 DT_\***：

| 信息 | 权威来源 | 假值表现 |
|------|---------|---------|
| 符号数 | `DT_HASH.nchain`（其次 `DT_GNU_HASH` 推算） | `.dynsym` 的 `sh_size` 被改小 |
| 重定位 | `DT_RELA`/`DT_RELASZ`、`DT_JMPREL`/`DT_PLTRELSZ` | `.rela.dyn` 段被从段表抹掉 |
| 依赖/符号名 | `DT_NEEDED`、`DT_SONAME`、`DT_STRTAB`+`DT_STRSZ` | `.dynamic` 段名可能被改 |

判定公式（拿到 `nchain` 就能反推真实符号数）：

```
dynsym_entries = DT_HASH.nchain
一致性校验：DT_SYMTAB + nchain*24 == DT_VERSYM   （本例 0x2f8 + 539*24 = 0x3580 ✓）
```

`tools/so.py info` 已按此顺序取数，并在 `broken_sections` 里直接报出伪造项：

```
.dynsym: sh_size=0x48 declares 3 entries, but DT_HASH.nchain says 539 — section header forged
reloc_source: DT_RELA+DT_JMPREL (section headers missing/forged)
```

**这一步的收益不是"好看"，是能不能分析**。实测同一个脱壳镜像：

| 指标 | 段头未修（信 sh_size） | 段头修正（信 DT_HASH） |
|------|----------------------|----------------------|
| Ghidra 导入符号 | 1 个（只有 `JNI_OnLoad`） | 782 个 |
| 有名字的函数 | 1 | 730 |
| `.text` 代码覆盖 | 57.8% | 76.7% |
| 反编译 `JNI_OnLoad` | 全是 `FUN_xxxx`，看不出调用语义 | 子调用可读 |

**修复方法**：把 `.dynsym` 的 `sh_size` 改成 `nchain*24`，把畸形 `.symtab` 改成 `SHT_NULL`。改完再导入 Ghidra。

**符号建了不等于函数体建了**：Ghidra 导入符号时会先建 Function 对象，但此时还没反汇编，body 只有 1 条指令。必须**先反汇编、再删除这些空函数、再重建**，否则 `get_function_by_address` 返回 `body=1`、反编译为空。顺序错了就只能看到空壳。

```java
// 反汇编完成后，清理 body<=4 的"符号空壳"再重建
for (Function f : fm.getFunctions(true))
    if (f.getBody().getNumAddresses() <= 4) fm.removeFunction(f.getEntryPoint());
// 然后按 bl/b 目标 + 入口形态 createFunction
```

### 3.2 符号/字符串定位工具
| 工具 | 用途 |
|------|------|
| `tools/so.py info/strings/dump` | ELF 侦察（段/依赖/导出/导入/重定位/vaddr↔offset）/ 字符串枚举 / 按址读字节 |
| `tools/so.py strref` | 定位字符串引用（adr / adrp+add / adrp+ldr——Ghidra 自动 xref 失效的 adr 也能命中） |
| `tools/so.py callers` | 定位函数调用者（BL / B / B.cond / CBZ / TBZ，可 `--bl-only`） |
| `tools/so.py disasm` | 快速反汇编（按 symbol/vaddr，capstone；Ghidra 未启动时的 fallback，`--grep` 过滤） |
| `tools/so.py jni` | JNI 导出签名侦察（JNI 调用点清单 + Java 第 1 参类型推断：jstring/jbyteArray/…） |
| `tools/emu_run.py` | 单函数离线仿真（Unicorn）。**加载即自动**：重定位分流（函数/数据导入）、`DT_INIT_ARRAY`、syscall 层（`svc #0` 兜底）、内置 `mem*/str*/calloc/pthread/ptrace/fopen/…` 桩；未桩导入打印 `[!] unstubbed`。观测 `--watch-*/--scan`（超限聚合）；日志 `--log-jni/--trace-stubs/--stub/--dump-jni-out`；复杂调用 `--setup` + `--ret-str/--out-arg/--no-init/--no-syscalls`（见 §3.6） |
| `tools/emu_setup.py` | emu_run 的 setup 助手库：`std_string/std_vector/call_sret/read_std_string/install_stub/patch_data_import/ctype_table/cstr`（见 §3.6） |
| `tools/trace_recon.py` | 仿真 trace 状态重建：观测日志 → 缓冲状态序列（COPY/PASS 自动分段，支持 `--json`） |
| `tools/cipher_lab.py` | 密码结构判定器：`layers`（层写法双轨迹判定）/ `table`（白盒表 S(Y⊕k)⊕c 反推）/ `schedule`（轮密钥→标准 AES-128 编排归因，出主密钥） |
| `tools/vmp.py` | **字节码 VM / VMP 壳逆向**（profile 驱动）：`disasm` / `verify`（trace 校验，命中率 <95% 退出码 1）/ `trace` / `model` / `profile`。换壳只换 `tools/vmp_profiles/*.json` |
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

函数命名（"这个函数是干什么的"）见 [so-func-naming.md ›「无符号函数命名」](so-func-naming.md)；定位未知函数仍用字节特征扫描：

```javascript
// 扫描已知字节模式
Memory.scan(mod.base, mod.size, "55 48 89 E5", { onMatch: function (address, size) { } });
```

### 3.5 SO 分析顺序（`tools/so.py` 离线工具）
一个 so 从"有什么"到"要 hook 什么"的标准下钻顺序（离线、可复现，不依赖 Ghidra/Frida/设备）：

```
info/strings 发现 → strref 引用 → disasm 上下文 → jni hook 前置 → (svc 下钻 / emu_run 复算)
```

### 3.5.1 "脱干净"的验收判据（脱壳 so 的完成定义）

"dump 出来了"不等于"脱干净"。按下面 6 条逐项验收，任一条不满足，后续静态分析都会被误导：

| # | 判据 | 怎么验 | 不合格的表现 |
|---|------|--------|-------------|
| **C1** | 段表与内存一致 | `so.py info` 的 PT_LOAD vs `adb shell cat /proc/<pid>/maps` 的 r-x/r--/rw- 区间逐条对齐 | 段数/权限/边界不符 → dump 有截断 |
| **C2** | 代码段已解密 | 入口处磁盘是壳魔数（`UPX!` 等），内存是合法指令（`bti c` / `stp x29,x30`） | 入口仍是魔数 → 解密区没抓到 |
| **C3** | 代码可连续反汇编 | 从入口线性反汇编，成功率 ≥ 99% | 大量非法指令 → 见下方三种成因 |
| **C4** | 符号表可信 | `DT_HASH.nchain` == `.dynsym` 实际项数；导出函数能被 `so.py --grep` 找到 | 只认 3 个符号 → 段头伪造（见 §3.1.1） |
| **C5** | 重定位可解析 | `so.py info` 的 `relocations` 数量 == `DT_RELASZ/24 + DT_PLTRELSZ/24` | 显示 0 条 → 段表被抹，需走 DT_RELA |
| **C6** | 数据引用能对上 | Ghidra 里 `JNI_OnLoad` 的参数是 `&DAT_xxx` 而不是裸整数；字符串引用可跳转 | 全是 `0x781b...` 绝对地址 → `.data` 未去重定位 |

**C3 不合格有三种成因，别一律判成"壳没解完"**（按排查成本从低到高）：

| 成因 | 判据 | 处理 |
|---|---|---|
| **① dump 工具填了 `0xCC`** | 非法指令字节全是 `CC`，且集中在未映射页 | dump 脚本按 PT_LOAD 枚举（`dumpPrecise`），别用整段 dump（`dumpSimple` 会把未映射页填 `0xCC`） |
| **② 段边界截断** | 非法指令只出现在段尾 | 先过 C1（段表 vs `/proc/<pid>/maps` 对齐）；边界不对就重 dump |
| **③ 代码真的没解密** | 非法指令散布全文，且入口处仍是壳魔数 | 回到脱壳流程，确认抓取时机（要等解密函数跑完） |

**最便宜的排除法**：若 APK 里还有原始 so，直接比 `.text` 段——差异区间就是问题范围，比反汇编扫描快得多。

**C6 是最容易漏的一条**。内存 dump 的指针是**运行时绝对地址**（`0x781b3395d0`），磁盘原文件对应位置全是 0。来源有两类，必须分开处理：

| 来源 | 特征 | 处理 |
|------|------|------|
| ELF 标准重定位 | 在 `DT_RELA` 表里有记录（`R_AARCH64_RELATIVE`，type=1027） | 值 = `base + addend`；改成 `addend` 即还原 |
| **壳自填的函数指针表** | **不在 RELA 表里**，磁盘上是 0 | 只能扫描 `[0x781b2..., 0x781b4...)` 区间并减去模块基址 |

第二类是本项目踩到的坑：`.rodata` 里有 **511 个**壳运行时填入的函数指针（含 VM 的 opcode 分派表），RELA 表完全不覆盖。不还原的话 `br x9` 分派表全是非法地址，Ghidra 反编译退化成一行 `FUN_xxx()`。

```python
# 先按 RELA 还原（精确、可验证）
for rel in rela_table:
    if rel.type == R_AARCH64_RELATIVE and read_u64(rel.off) == base + rel.addend:
        write_u64(rel.off, rel.addend)

# 再扫残留（壳自填，无 RELA）
for off in range(rodata_start, data_end, 8):
    v = read_u64(off)
    if base <= v < base + module_size:
        write_u64(off, v - base)
```

判据是**同一份产物在两种工具里读到同一个地址**：文件里 `0x781b3395d0`，Ghidra 读出 `0x1f35d0`（image_base 0x100000 + 0xf35d0），两侧对得上才算干净。

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

### 3.5.2 字节码 VM 逆向（VMP 型壳）

当 `JNI_OnLoad` 只做「初始化运行时 + 启动解释器」、业务方法在 `.text` 里找不到时，业务逻辑很可能被编译成了**自定义字节码**。识别与还原路径：

**第一步：认出 VM 而不是普通代码**

```c
// JNI_OnLoad 的典型形态：取运行时 → 存 JavaVM → 启动解释器 → 返回版本
rt = FUN_xxx();                    // 分配运行时
FUN_yyy(rt, vm);                   // 存 JavaVM
FUN_zzz(rt, &table1, &table2, bytecode, &selector, 0);
return FUN_vvv(rt);
```

其中第 3 个参数是**字节码指针**，第 5 个是**分派索引**。真正的解释器函数特征：

- 从参数里取一个 `u8`，`lsl #3` 或 `lsl #2` 后 `ldr` 表项，再 `br` —— 跳转表分派
- 有软件栈（`sp` 上的一块固定区域，栈顶指针存在栈槽里）
- handler 里大量 `ldrb`/`strb` 按偏移读写那块区域

**第二步：定位 opcode 表，别假设项数**

表在 `.rodata`，形式是连续的函数指针数组。**不要假设 256 项**——壳普遍只放实际用到的项数（常见 100~200），其后紧跟另一张 continuation 表。两种交叉验证：

1. 表后面紧跟的连续指针数组从哪开始（长度即真实项数）
2. 解释器入口 `memcpy(dst, table, N)` 的 N

工具：`python3 tools/ptr_table.py <so> --scan --only-code --classify vm` —— 按「全代码指针 + 项数是否 2 的幂」标注 handler 表候选。

表里被最多 opcode 共用的那个 handler 就是 **default/nop**，可以用来判断指令流是否解对（正常字节码里它占 10~30%，乱码数据里不会集中在单个值）。

**注意壳会在运行时重填这张表**：静态看是非法地址时，按 §3.5.1 的 C6 还原（`.rodata` 里不在 RELA 表内的运行时指针快照）。

**第三步：从动态 trace 反推编码，不要静态猜**

每条 handler 自定义 pc 推进量与操作数布局，按固定长度切分命中率接近 0。正确顺序：

```
① 反编译 handler 正文    → 看它怎么读 pc、怎么推进、操作数在哪几位
② 仿真/真机跑通           → 拿 (pc, opcode) 序列
③ 用 trace 反推解码公式   → 假设 op_n = f(byte[pc_n+L-1], op_{n-1})，解 f
④ 反汇编字节码            → 输出可读清单
```

归纳出来的通用形式（换壳只改参数）：

```
op_n = decode(byte[pc_n + L - 1], op_{n-1} ^ K)
decode(x, k) = (((A - x) & M1) | ((x - B) & M2)) ^ k
```

其中 `L` 由 handler 决定（变长）、`A/B/M1/M2/K` 是壳自己的常量。**opcode 链式差分**是这类壳的共同特征：整体 dump 出来看是均匀随机分布，不能用熵判断"这是不是字节码"。

**第四步：验收（唯一的硬判据）**

| 检查 | 通过标准 | 失败说明 |
|------|---------|---------|
| **trace 命中率** | **> 95%** | 公式错，或 profile 的常量错 |
| opcode 值域 | 集中在几十个值 | 边界算错 |
| default handler 占比 | 10~30% | 解码规则错 |
| 高频 opcode | 对应 `push`/`ld`/`st`/`call` 类 handler | 表读错 |

剩余未命中若能归因到某个明确分支（如"条件满足时 key 被强制"），是可解释边界，不是模型错误。

**第五步：工具化 —— 用 `tools/vmp.py`**

模型与引擎分离：编码模型放 `<包名>/tools/vm_profiles/<name>.json`（样本事实），
引擎与模板在 `tools/`。`vmp.py` 会自动扫描各样本目录，`-p <name>` 直接用名字即可。

```bash
python3 tools/vmp.py profile list                          # 看有哪些现成模型
python3 tools/vmp.py trace  <so> -p <profile> --sel 0 --out trace.json
python3 tools/vmp.py verify <so> -p <profile> --trace trace.json   # 命中率 < 95% 退出码 1
python3 tools/vmp.py disasm <so> -p <profile> --trace trace.json --vm <key>
python3 tools/vmp.py model --stats                         # handler 指令模型（Ghidra 导出后）
```

**换一个壳 = 写一个 profile**，需要填：`key_xor` / `decode{4 个常量}` / `opcodes`（opcode→语义名）/ `handler_table_file_va` / `handler_count` / `bytecode_file_va`；`trace` 子命令还要 `entry_va` / `dispatch_hook_pc` / `frame_*_off`。

**边界**：opcode 语义名表（`opcodes`）是逐个反编译 handler 归纳出来的，新壳只能给通用名（`op_<hex>`），随分析进展补全。

### 3.6 复杂函数离线仿真（emu_run 广度 + setup 助手）> 环境模拟（JNI 槽位 / syscall / TLS 打桩）见 [so-emulation.md ›「3. 环境模拟」](so-emulation.md#3-环境模拟)；hooks.py 契约见 [›「5. 写好 hooks.py（与 emu_setup 协作）」](so-emulation.md#5-写好-hookspy与-emu_setup-协作)。

设计目标：**广度优先**——尽量能模拟任意 so 函数；极难/需完整运行时的才升级 unidbg（深度），动态验证仍可走 Frida。

**加载即自动处理**（无需 setup）：重定位分流（`JUMP_SLOT`→函数桩 / `GLOB_DAT`→数据单元，内置 `_ctype_` 表）、`DT_INIT_ARRAY`（C++ 全局对象）、syscall 层（`svc #0` → 常用 syscall 假实现）、内置 libc 桩（`mem*/str*/calloc/realloc/sprintf/pthread_*/ptrace/fopen/…`）。未桩导入首次命中打印 `[!] unstubbed: <name> -> 0`（避免静默 ret 0）。

**复杂调用**：`--setup hooks.py` + `tools/emu_setup.py` 助手库；helper 表与 libc++ 布局见 [so-emulation.md ›「5. 写好 hooks.py（与 emu_setup 协作）」](so-emulation.md#5-写好-hookspy与-emu_setup-协作)。

`--setup` 接受两种钩子，按需要选：

| 钩子 | 签名 | 何时用 |
|---|---|---|
| `setup` | `setup(h)` | 只挂环境（poke/桩/额外映射） |
| `prepare` | `prepare(h, so_path, data) -> JavaVM*` | 需要自建 JNI/JavaVM 表（脱壳镜像、VM 壳）。**与 `probe_layout --setup` / `vmp trace --setup` 同一契约**，同一份脚本三处通用 |

`prepare` 在 `build_jni` **之前**执行，返回值写进 `h.jni_vm`，之后 `--args "vm,0"` 才能解析 `vm` 记号。
`env` 同理：`prepare` 若已建 JNIEnv，就不再重复建。

> 脱壳镜像上跑 VM 壳入口时通常要加 `--no-init`：`DT_INIT` 可能指向 CFF 内部块，跑进去会不返回。

- CLI 便捷项：`--ret-str`（sret 返回 `std::string` 自动解码）、`--out-arg N:LEN`（调用后 dump 第 N 参指向缓冲）、`--no-init` / `--no-syscalls`（关自动项）
- **升级线**：需真 linker / 真 syscall / 线程 / Java VM 语义 → unidbg；动态调试 → Frida

### 3.7 结构体恢复（偏移聚合）

只在伪代码到处是 `*(a1 + 0x18)`、`ldr w8, [x0, #0xc]` 时才做；判断单个函数用途不需要。

1. **聚合**：以同一入参（一般是 x0 / `this`）为键，收集全部 `ldr/str/ldrb/strh` 的偏移与访问宽度（`w`=4、`x`=8、`b`=1、`h`=2 字节）。
2. **扩展**：从直接 caller/callee 起一跳一跳收；**偏移集合不再增长就停**（不设终止条件会顺着调用图爆掉）。
3. **大小** = `max(offset) + 该偏移的访问宽度`。
4. **类型判据看指令**：被 `blr` 调用 → 函数指针；offset 0 处 `ldr x8,[x0]; ldr x8,[x8,#N]; blr x8` → vtable；喂 `strlen/printf` → char*；`and #1`/`tst` → flags；`add/sub #1` 且成对出现 → refcount；两个指针字段互相回指 → 链表。

**sret 例外**：`x8` 指向返回缓冲，不是 `this`；从 x8 聚合出的偏移不要混进结构体。

**闭环验证（关键）**：把布局建成 Ghidra struct（datatype 组工具，名字现查 `ghidra_search_tools "struct"`），再**重反编译所有相关函数**并套用该类型——错位的偏移会直接显形，比读注释可靠。全函数一致后写进 REPORT.md；无 Ghidra 时用 `so.py disasm` 按同样规则聚合。

> 工具：`python3 tools/probe_layout.py <so> --entry JNI_OnLoad --at/--hook/--multi-hook`（`--help` 看参数）

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
- 设 `targetModules: ["<shell>.so"]` 只追踪检测 SO
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
| Dex2C 定位 native 实现 | `utils + dex2c_entry.js`（attach）/ `scan_register_natives.js`（spawn）→ Ghidra 单函数逆向 |