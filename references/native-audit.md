# SO 漏洞审计（可达面优先）

> **何时读**：① 要审 `.so` 找漏洞；② 怀疑 native 层堆越界 / UAF / double-free，或要定位"谁写坏了这块内存"；③ 崩溃后归因。
> **不适用**：只是理解功能 / 定位函数 / 离线复算 → [native-analysis.md](native-analysis.md)。
> 路径基准：项目根。Frida 模块写 `scripts/<子目录>/<模块>`（相对 skill 根）；独立工具写 `tools/<工具>`。

**本文只写"审哪里、按什么顺序、用什么手段、怎么判"。** 需要机制细节时，会在**用到它的那句话里**说明"那段讲什么"再给指针，
不另列"相关手册"清单。

---

## 一、审计环

```
① 可达面 → ② 分诊 → ③ 深审（含内存手段）→ ④ 归因 → ⑤ 无触发路径时 fuzz 兜底
     ↑                                                    │
     └────────────── 未闭环线索回流 ───────────────────────┘
```

**顺序不能换**：先确定"哪些代码真的能被外部调到"，再决定审谁。
反过来（从导出表逐个审）会把力气花在不可达代码上。

---

## 二、① 可达面（先做，别跳）

**工具**：`scripts/monitors/api_reach.js`（纯观测：只计数，不改返回值、不读业务语义）

```bash
frida -H 127.0.0.1:27042 -n Gadget \
  -l .kilo/skill/frida-mobile-security/scripts/core/utils.js \
  -l .kilo/skill/frida-mobile-security/scripts/monitors/api_reach.js \
  -e 'var CONFIG_OVERRIDE={api_reach:{targets:["com.foo.Bar"],methodPrefix:"native"}}'
```
REPL：`ApiReach.report()` 打印「可达 / 未命中」两张表；`ApiReach.missed()` 只列未命中。

**流程**
1. 一次只用一个入口组件触发，记录该输入的命中集合；
2. **换多形态输入各跑一遍，取并集**：页数、书签树、链接注释、加密、嵌入字体、表单/注释……
3. 并集 = 真实可达面。

### 两类"没调到"必须分开（关键判据）

| 现象 | 判定 | 处理 |
|---|---|---|
| 类里**有**调用方，只是这次输入没触发 | **输入未覆盖 ⇒ 仍可达** | 补输入再测；**不能据此判定不审** |
| 类里**没有**调用方（Java 侧搜不到，换输入仍 0 次） | **代码级不可达** | 可不审，但报告里要写明"为何不可达" |

同一份 PDF 库：**无书签** PDF 下 `nativeGetSiblingBookmark` / `nativeGetBookmarkTitle` /
`nativeGetBookmarkDestIndex` 均为 **0 次**（看着"不可达"）；换成**带书签树**的 PDF 后，三者各 **14 次**。

从导出表逐个审的代价：`nativeLoadPages`（3 参 `openPage` → 栈上变长数组）与
`nativeOpenMemDocument`（`byte[]` → 拷贝缓冲泄漏）在该 App 均为**代码级不可达**；
可达面落在 **fd 读取 + 渲染 + 书签** 这条路径上。

---

## 三、② 分诊（决定审计顺序）

按 **攻击面 × 危险度** 排序：

| 维度 | 高分特征 |
|---|---|
| 输入可控性 | JNI 导出 / `RegisterNatives` 映射 / socket·文件读取的调用者 / 协议解析入口 / 深链参数落点 |
| 危险 sink | `memcpy/memmove/strcpy/sprintf/alloca`、`malloc(算术表达式)`、数组索引、循环边界、`double→int` |
| 结构复杂度 | 大函数、多循环嵌套、指针算术、手写长度校验 |
| **目标来源** | **自研库优先**；上游库（pdfium / libpng / ffmpeg…）**必须上覆盖率引导**才有意义 |

---

## 四、③ 深审

### 4.1 前置：Ghidra 两件事（不做就无法审）

**工具**：`tools/ghidra/so_audit_prep.java`（Ghidra inline body，用 `run_script_inline` 注入）

```text
args: --proto <原型规格文件>
```

**PLT 导入桩命名**：不命名时反编译只显示 `func_0x…`，你无法判断它是 `free`、`resize` 还是 `WriteInto`。
把 `WriteInto`（**返回可写 data 指针**，配 `resize` 用"先拿指针再填充"）读成 `resize`（返回 `this`），
会把一段正确实现判成栈溢出。脚本读重定位表 + 扫 `adrp`/`ldr` 还原 `GOT → 符号`，把每个桩建成同名函数；可重复执行。

**原型批量回填**：JNI 函数前两个参数固定是 `JNIEnv*` 与 `jobject`。Ghidra 不知道这点时会按
`undefined1[16]` 处理，11 个参数被拆成 18 个、间接调用也丢参。原型从 jadx 里的
`private native …` 声明抄下来，按 `地址|返回类型|参数类型` 写进规格文件即可。

**离线核对导入表**：`so.py info --json` 已含逐条重定位（`relocations.entries`：`offset/type/symbol`）
与符号大小（`exports[].size`）；文本视图只打印按类型统计，要明细就加 `--json` 再用 `jq`/python 取。
把 GOT 槽对到 PLT 桩仍需按 `adrp`+`ldr` 反查（上面的脚本已做这步）。

### 4.2 逐函数审什么

| 类型 | 检查点 |
|---|---|
| 缓冲区 | 两段式取长（`GetTitle(NULL,0)` → 分配 → 填充 → `NewString`）；长度单位（**字节 vs 字符**）；NUL 终止；分配量是否 ≥ 写入量 |
| 整数 | `(int)` 截断/饱和；`size` 乘加溢出；有符号/无符号混用 |
| 生命周期 | `ReleaseXxxArrayElements` 模式（`0` / `JNI_COMMIT` / `JNI_ABORT`）；`new[]`/`malloc` 是否释放；**上游不复制入参时缓冲由谁负责** |
| 空值 | JNI 入参（`jstring`/`jobject`/数组）与句柄是否判空 |
| 回调 | 自定义 `GetBlock`：**短读是否当成功**（`pread` 返回 `0 ≤ n < size`） |
| 资源 | 无界栈 VLA（`sub sp, sp, n*8`，`n` 来自 Java 且无上界）；大 `alloca` |

机制与 API 细节：`api-reference.md` › [「1.3 Native 库层（.so / .dylib）」](api-reference.md#13-native-库层so--dylib)。
函数定位优先级（导出 → 特征码 → 调用者 → 字符串引用 → PLT/GOT → RegisterNatives → Stalker）见
[native-analysis.md ›「3.4 定位目标函数的方法（优先级从高到低）」](native-analysis.md#34-定位目标函数的方法优先级从高到低)；
函数大到读不下去时，用 [native-analysis.md ›「3.6 复杂函数离线仿真（emu_run 广度 + setup 助手）」](native-analysis.md#36-复杂函数离线仿真emu_run-广度--setup-助手)
跑起来看它读写哪块内存。

### 4.3 内存类问题的验证手段

#### 4.3.1 先判环境能力（决定可用手段）

| 手段 | 前提 | 说明 |
|------|------|------|
| ASan / HWASan / UBSan / TSan | **有源码**（编译期插桩） | 闭源 .so 不可用 |
| malloc debug | userdebug/eng ROM；或应用 debuggable；或 env `LIBC_DEBUG_MALLOC_OPTIONS`（仅 execve 进程） | user 版 + 非 debuggable 应用**不可用** |
| Scudo 自带检查 | Android 11+（默认分配器） | 堆损坏时 abort 并打 `Scudo ERROR` |
| GWP-ASan | Android 11+（App 级 14+） | 采样检测，无需源码 |
| MTE | ARMv8.5+ 硬件（Pixel 8 起） | 硬件 tag 检查 |
| Frida 内存守卫 | 任意（能注入即可） | 覆盖堆越界 / 非法释放，见 §4.3.4 |
| tombstone 归因 | 任意 | 崩溃后的定位手段，见 §五 |

判定命令：

```bash
adb shell getprop ro.build.type          # user / userdebug / eng
adb shell getprop ro.debuggable
adb shell getprop ro.build.version.sdk   # <30 无 Scudo/GWP-ASan
adb shell "su -c 'strings /system/bin/linker64 | grep -m2 LIBC_DEBUG_MALLOC'"
```

`ro.build.type=user` + 非 debuggable 应用 → malloc debug 整条路不通，直接走 §4.3.4 与 §五。

#### 4.3.2 选路

```
有没有触发路径（能把外部输入喂到目标函数）？
├─ 有 → 打开内存守卫（Frida memguard）或 malloc debug（设备支持时），边喂边看
└─ 无 → 函数级 fuzz（tools/emu_run.py + 变异），见 §六
崩溃之后 → tombstone 归因，见 §五
```

#### 4.3.3 malloc debug（仅设备支持时）

三条启用路径：

| 路径 | 适用 | 做法 |
|------|------|------|
| 属性 | userdebug/eng | `setprop libc.debug.malloc.options "guard backtrace free_track"` |
| 环境变量 | 任意 ROM 的 **execve** 进程（验证机制/自测） | `LIBC_DEBUG_MALLOC_OPTIONS=guard\ verbose /system/bin/toybox echo x` |
| `wrap.sh` | debuggable 应用 | APK 内 `lib/<abi>/wrap.sh` 里 `export LIBC_DEBUG_MALLOC_OPTIONS=...` 后 `exec "$@"` |

选项：

| 选项 | 作用 | 代价 |
|------|------|------|
| `guard` | 分配前后加 guard page，抓线性越界写 | 中 |
| `free_track` | 抓 use-after-free / double-free | 中 |
| `backtrace` | 报错带调用栈 | 低 |
| `fill` | 释放后填充，暴露读已释放数据 | 低 |
| `leak_track` | 泄漏追踪 | 高 |
| `verbose` | 每次分配/释放都打印 | 极高，勿常开 |

生效判定：`adb shell "su -c 'grep -c libc_malloc_debug /proc/<pid>/maps'"` > 0（fork 出来的进程不打印 banner，只能靠 maps 判断）。

**坑（设备约束）**

- **App 由 zygote fork，不重跑 linker 初始化**：属性只在 zygote 启动时读一次，**只重启 App 无效**
- **`libc.debug.malloc.program` 对 App 无效**：zygote 阶段进程名不匹配，无法只对单个 App 生效
- **不要在运行中的系统上 `setprop ctl.restart zygote`**：在 APatch/LSPosed 等改过的设备上会导致 system_server 半启动、框架卡死
- **不要用开机脚本设 `ro.debuggable=1`**：会改变全系统调试路径，导致卡开机
- 想让 App 生效只有"zygote 启动前设属性"一条路，而那时属性是**全系统**生效（含 system_server），`guard`+`backtrace` 会把启动拖到超时
- 结论：**user 版 + 非 debuggable 应用，不要在这条路上投入**；换 userdebug/eng 设备或 userdebug 模拟器镜像

#### 4.3.4 Frida 内存守卫（通用，推荐）

模块：`scripts/monitors/native_memguard.js`

```bash
frida -H 127.0.0.1:27042 -n Gadget \
  -l scripts/core/utils.js -l scripts/monitors/native_memguard.js -q -t 150
```

配置（`CONFIG_OVERRIDE.native_memguard`）：

| 键 | 默认 | 说明 |
|----|------|------|
| `trackAlloc` | true | 维护 指针→大小 表（越界检测依赖它） |
| `checkCopies` | true | 检查 memcpy/memmove/memset |
| `checkStrcpy` | false | 检查 strcpy/strncpy/strcat（会读源串，风险略高） |
| `maxEntries` | 50000 | 分配表上限（FIFO 淘汰） |
| `minCopySize` | 8 | 小于该长度不检查（降噪） |
| `logBigCopy` | 4096 | 超过该长度的拷贝即使不越界也打印；调大可降噪 |
| `backtrace` | true | 打印调用栈（含 `so+offset`） |

输出解读：

```
[MEMGUARD] memcpy 越界: dst=0x... 分配=32 写入=48
          bt: libhtsfx.so+0x1234 <- libc.so+0x...
```

`bt` 第一帧通常就是出错函数，直接 `tools/so.py disasm <so> --addr 0x1234` 或导入 Ghidra 定位。

局限：只覆盖**堆**分配（栈/全局越界抓不到，需 ASan/MTE）；`strcpy` 系列靠读源串估算长度，源串不可读时会跳过。

### 4.4 跨函数追链

Ghidra 的 `analyze_dataflow` 走的是函数内 PCode 图，**在调用边界就终止**——这是 API 行为，
见 [api-reference.md ›「1.3 Native 库层（.so / .dylib）」](api-reference.md#13-native-库层so--dylib)。
因此源→汇的链路只能手工串：

```
sink → get_function_callers → decompile 每个 caller → 判参数来源（analyze_dataflow backward）
     → 是形参就再上一层 → 直到命中 source 或判定"外部不可控"
```

先用 `analyze_call_graph(start, end)` 判断 source→sink 是否**存在路径**，有路径才展开，
否则会在全调用图里乱走。

---

## 五、④ 归因：tombstone

tombstone 是 Android `debuggerd` 在 native 崩溃（SIGSEGV/SIGABRT 等）时生成的转储文件，
不是检测工具，是**崩溃后的定位依据**。

```bash
adb shell "su -c 'ls -lt /data/tombstones/ | head -3'"
adb shell "su -c 'cat /data/tombstones/tombstone_00'" > tombstone_00.txt
```

关键字段：

```
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0
backtrace:
  #00 pc 0000000000123456  /data/app/.../libhtsfx.so (offset 0x123456)
  #01 pc 0000000000234567  /data/app/.../libtZFProtocol.so
```

`pc` 的偏移直接就是 `so+offset`，与 memguard 的 `bt` 同一套定位方式。符号化：

```bash
python3 tools/so.py disasm <so> --addr 0x123456 --count 20
```

有带符号的 `.so` 时，`ndk-stack -sym <符号目录> -i tombstone_XX` 能把栈帧直接翻成
`函数 (文件:行)`，省掉逐帧手工查（NDK 自带；r21 只有 `-i`，新版才有 `-dump`）；
无符号时退回 `so+offset` + `so.py disasm`。

> Frida 动态验证时，`NativeFunction` 默认 `exceptions:'steal'` 会把段错误**吞成可捕获的 JS 异常**，
> 进程不死也不产生 tombstone —— 只靠它判"没崩"会误判。两种取值的差别见
> [api-reference.md ›「NativeFunction 的异常语义（必读坑）」](api-reference.md#nativefunction-的异常语义必读坑)。

---

## 六、⑤ 没有触发路径时：函数级 fuzz

用 `tools/emu_run.py`（Unicorn）把目标函数单独跑起来喂变异参数。**七步**：

| 步骤 | 动作 | 命令/要点 |
|---|---|---|
| 1 选目标 | 小体积 + 有 JNI/C 导出 + 处理外部数据（列表/解析/分配） | 优先 100KB 以下、导出 5-20 个；看导出/体积见 [native-analysis.md ›「3.5 SO 分析顺序（tools/so.py 离线工具）」](native-analysis.md#35-so-分析顺序toolssopy-离线工具) |
| 2 判型 | 拿签名 + 看参数去向（是否直接进 `NewByteArray`/`malloc`/`memcpy`） | 判型见 §6.2；反汇编看数据流用 `so.py disasm` |
| 3 基线 | 用正常值跑通，确认桩调用 | `emu_run.py <so> --sym <符号> --jni --args "env,0,<正常值>" --trace-stubs` |
| 4 变异 | 整型扫边界；指针喂畸形/超长 | 整型：`0 / 负数 / INT_MAX`；字符串/缓冲：`--poke-str`、`--poke` |
| 5 判定 | Unicorn 非法内存访问 = 越界；桩收到异常参数（如 `size=0xffffffff`）= 上游缺陷 | 看 `[stub]` 行与异常输出 |
| 6 **可达性验证** | **真机 hook 同一导出，看参数是否来自外部输入** | 这一步决定第 5 步的发现是否成立（见 §二） |
| 7 产物 | `so+offset` + 调用栈 + 参数来源结论 | 不可控就降级，不写成漏洞 |

### 6.1 真机主动触发（不依赖 UI 操作）

SO 导出靠 UI 去"碰"效率低，正确做法是**用 Frida 控制输入**，两种方式：

**方式 A：直接调用**（适合无状态纯函数）

```js
Java.perform(function () {
  var C = Java.use("<Java类>");        // native 方法所在的 Java 类
  var inst = null;
  Java.choose("<Java类>", {            // 实例方法：先取运行中的实例
    onMatch: function (o) { if (inst === null) inst = Java.retain(o); },
    onComplete: function () {
      if (inst === null) inst = C.$new();       // 没有实例就自己造
      var arr = Java.array('int', [1, 2, 3]);   // 构造参数
      var r = inst.<native方法>(103, arr, 1000, 3, Java.use("java.util.ArrayList").$new(), 0);
      console.log("[call] -> " + r);
    }
  });
});
```

要点：方法 `mods=0x102`（public+native）**不是静态**，必须先拿实例；参数语义不对时会返回 `null`——**"无反应"不等于"无漏洞"**。

**方式 B：hook 真实调用 + 变异参数**（推荐，语义天然正确）

```js
Java.perform(function () {
  var C = Java.use("<Java类>");
  var n = 0;
  C.<native方法>.implementation = function (a, b, c, d, e, f) {
    n++;
    if (n <= 6) console.log("[real] a=" + a + " bLen=" + b.length + " c=" + c + " eSize=" + e.size() + " f=" + f);
    // 变异：把长度类参数放大 / 传空容器，看 native 是否校验
    try { console.log("  [mut] " + this.<native方法>(a, b, c + 10000, d, e, f)); }
    catch (ex) { console.log("  [mut-exc] " + String(ex).substring(0, 140)); }
    return this.<native方法>(a, b, c, d, e, f);   // 原参数走正常流程
  };
});
```

好处：不用猜参数含义，先看真实值，再针对性变异；变异失败（抛异常/返回 null）说明有校验，崩溃才是命中。

### 6.2 判型与参数摆放

`Java_*` 导出前两参固定是 `JNIEnv*` / `jobject`，业务参数从第三参起（`--args "env,0,<值>"`）；
纯 C 导出按 ABI 直摆，不加 `--jni`。类型判读的完整做法（`so.py jni`、JNI vtable 偏移、
`readJbyteArray` 实现）见
[native-analysis.md ›「JNI 参数类型判读（hook 前置，避免崩在 agent）」](native-analysis.md#jni-参数类型判读hook-前置避免崩在-agent)。

参数是否"外部可控"必须真机确认——离线看到的只是"代码可能性"，不是"攻击面"（见 §二）。

### 6.3 先确认哪个导出真被调用

直接用 `scripts/monitors/native_hooker.js`（按 `targetLibs` + `hookPatterns` 命中导出，
打印参数 / 返回值 / 调用栈；懒加载的库在 dlopen 时同步装上，不必自己写轮询）。
需要按**类**统计而非按导出时，用 §二 的 `api_reach.js`。确认命中后再用 §6.1 方式 B 做参数变异。

---

## 七、坑速查

| 坑 | 现象 | 解法 |
|---|---|---|
| 不命名 PLT 桩 | 反编译 `func_0x…` → 误读导入函数语义 → **假阳性** | `tools/ghidra/so_audit_prep.java` |
| 不回填 JNI 原型 | `JNIEnv*` 当 `undefined1[16]`，参数错位 | 同上 `--proto` |
| 用单一输入判可达 | 书签类 native 看着 0 次，换带书签 PDF 立刻 14 次 | 多形态输入取并集（§二） |
| 把上游库当主战场 | 投入大、产出低 | 先审自研库；上游库必须覆盖率引导 |
| 只判"有没有崩" | Frida 默认 `exceptions:'steal'` 把真崩溃吞成 JS 异常 | [api-reference.md ›「NativeFunction 的异常语义（必读坑）」](api-reference.md#nativefunction-的异常语义必读坑) |
| 在 user 版真机折腾 malloc debug | 属性只在 zygote 启动时读，改一个 App 不生效；重启 zygote 会卡框架 | 见 §4.3.3「坑」；改走 §4.3.4 |
| 离线仿真看到崩溃就写漏洞 | 参数在真机上不可控 | §六 第 6 步必须做真机可达性验证 |
| hook 上了但没输出 | 可能是时机、类名、或检测拦截 | [troubleshooting.md ›「Hook 不生效 / 模块无输出」](troubleshooting.md#hook-不生效--模块无输出) |
| 调试中进程闪退 | 可能是壳保护或检测 | [troubleshooting.md ›「进程闪退 / 不稳定」](troubleshooting.md#进程闪退--不稳定)；加固壳另看 [anti-detection.md ›「Phase 1：定位检测 so」](anti-detection.md#phase-1定位检测-so) 与 [anti-detection.md ›「症状速查」](anti-detection.md#症状速查) |
