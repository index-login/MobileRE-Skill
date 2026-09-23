# 反 Frida 检测 Pipeline（环境对抗）

> 何时读：用户提到"绕过检测/过掉反调试/挂上就闪退/防注入/加固壳/SVC/TracerPid/GDB"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。绕过模块在 `scripts/bypass/`，监控模块在 `scripts/monitors/`（命令里的 `scripts/...` 为技能相对：复制执行先 `cd .kilo/skill/frida-mobile-security` 或展开全路径 `.kilo/skill/frida-mobile-security/scripts/...`）。

---

## 前置快速检测（无需 Frida，独立工具）

- `tools/debug-gdb.py <包名>`（`py -3` 运行）— ptrace 反调试检测（TracerPid + 进程存活）；附加成功但进程随后消失 = 存在反调试
- `tools/check-anti-inject.bat <包名>` — SO 注入检测（ptrace + mem 注入）
- `tools/check-janus.bat <apk路径>` — APK 元数据提取

## 前置 Frida 环境检测（验证注入是否成功）

- `scripts/checklist/fridainject.js` — **frida 环境检测项**：

```bash
frida -U -f com.app -l scripts/core/utils.js -l scripts/checklist/fridainject.js
```

- 原理：hook `Activity.onCreate` 弹窗"Frida Hook 代码注入成功!!!"
- 判读：弹窗出现 → Frida 注入成功、无 Java 层检测；弹窗不出现 / 进程被杀 / 无输出 → 存在 frida 环境检测，转入下方 Pipeline
- 用途：挂载前先确认"能不能挂上"，是反检测的 0 号判断

## Pipeline 全览

Phase 1 之后分流，不要盲目走全部 Phase：

```
Phase 1: exit_blocker + so_loader_tracer → 定位检测 so + 观察退出信号
  ↓
  ├── 分支 A（线程检测）：thread_blocker 或 thread_monitor → function_patcher
  │   适用：exit_blocker 捕获到 BLOCKED，调用栈来自 pthread_create
  │
  └── 分支 B（init_array 检测）：Phase 0 → init_hook + hasSvc0
       适用：exit_blocker BLOCKED 来自 init_array 路径，或 exit_blocker 无 BLOCKED（svc #0 绕过）
       ↓
       Phase 3: dlsym_tracer → 发现运行时解密的符号
       Phase 5: shellcode_detector → 定位 mmap + PROT_EXEC shellcode
       Phase 6: function_patcher → 对已知偏移直接 NOP
```

---

## Phase 0（前置）：验证 linker64 偏移

`init_hook.js` 依赖 linker64 的 `call_constructors` 符号。加载 init_hook.js 后检查日志中是否出现 `[+] call_constructors found @ 0x...`。如果没有，说明当前设备 linker64 没有导出该符号：

```bash
# 方法 1：设备上直接查
adb shell "readelf -sW /apex/com.android.runtime/bin/linker64 | grep call_constructors"

# 方法 2：离线反汇编
adb pull /system/bin/linker64 /tmp/linker64
llvm-objdump -d /tmp/linker64 | grep "call_constructors"
# 示例输出（API 29）:
# 3ca08: bc 50 00 94  bl #0x50cf8 <call_constructors>
# → offset = 0x50cf8
```

找到对应 API Level 的 offset 后，更新到 `init_hook.js` 的 `fallbackOffsets` 列表中。

---

## Phase 1：定位检测 so

模块: `scripts/core/utils.js + scripts/bypass/exit_blocker.js + scripts/bypass/so_loader_tracer.js`

`exit_blocker` 用 `Interceptor.replace` 替换 `exit_group/_exit/abort/kill/tgkill` 及其 syscall 对应项，真正阻止进程退出。`so_loader_tracer` 记录闪退前最后加载的 so。

输出示例：
```
[*] do_dlopen OK: /data/app/.../lib/libDetect.so base=0x7a12340000 256KB
[!] BLOCKED: exit_group status=0 (count=1)
```
→ Detector SO = `libDetect.so`

**路由决策**：
- 调用栈来自 `pthread_create` → **分支 A**（线程检测），跳至下方
- 调用栈来自 `init_array` 或 无 BLOCKED 日志 → **分支 B**，继续 Phase 2

---

## 分支 A：thread_blocker 主动阻断（线程检测模式）

模块: `utils + thread_blocker(blockCallers:["libmsaoaidsec.so"]) + exit_blocker`

输出示例：
```
[+] pthread_create REPLACED (blocking: libmsaoaidsec.so)
[!] [THREAD_BLOCKER] BLOCKED pthread_create from libmsaoaidsec.so + 0x1CEF8 (count=1)
  thread entry: libmsaoaidsec.so + 0x1D234
```
→ 检测线程在创建前被拦截，无需 NOP 任何代码。

备选（被动 NOP 模式）: `utils + exit_blocker + thread_monitor(callerFilter:["libmsaoaidsec.so"])`

---

## Phase 2（分支 B）：init_hook 抢时机（init_array 检测）

so 加载流程：`do_dlopen → call_constructors → init_proc → init_array → JNI_OnLoad`

普通 `android_dlopen_ext` hook 在 `call_constructors` 之后才触发，init_array 已执行完毕。必须用 `init_hook.js`。

**init_hook 自动做三件事：**
1. 在 call_constructors 处拦截，早于 init_array
2. `autoHideFrida:true`（默认）→ 自动激活 frida_feature_hider，隐藏 /proc 中的 Frida 特征
3. `probeCallers:true`（默认）→ 自动 hook pthread_create，当调用者来自目标 so 时打印完整调用栈（so+offset），直接拿到检测函数偏移

模块: `utils + frida_feature_hider(indirectHook:true) + init_hook(onModuleInit:[{moduleName:"libmsaoaidsec.so"}], probeCallers:true, autoHideFrida:true) + exit_blocker`

输出示例：
```
[*] call_constructors: libmsaoaidsec.so found @ 0x7a12340000 size=256KB
[!] autoHideFrida: FridaFeatureHider activated for libmsaoaidsec.so
[+] probeCallers: pthread_create hooked, filtering for libmsaoaidsec.so

[!] [INIT_HOOK] pthread_create called FROM libmsaoaidsec.so + 0x1CEF8
  thread entry: libmsaoaidsec.so + 0x1D234
=== Detection call chain from libmsaoaidsec.so (8 frames) ===
  [0] [caller] libmsaoaidsec.so + 0x1CEF8 | sub_1CEF8
  [1] [detect] libmsaoaidsec.so + 0x26C58 | sub_26C58
  [2] libmsaoaidsec.so + 0x26334 | sub_26334
  [3] libc.so + 0x8b1a0 | pthread_create+0xa0
=== These offsets can be fed to function_patcher for bypass ===
```
→ 直接拿到三个检测函数偏移（0x1CEF8, 0x26C58, 0x26334），无需 IDA 静态分析。

### 加固壳特别说明

若目标 app 使用加固壳（so 从 `files/` 路径动态加载），策略调整为：
1. `frida_feature_hider` 使用 `indirectHook:true`（延迟由 init_hook 激活），避免与 exit_blocker 的 Interceptor.replace 冲突
2. `init_hook` 的 `onModuleInit` 只监听**检测 so**（如 `libexecmain.so`），不监听**壳 so**（如 `libexec.so`）。壳 so 的 init_array 负责解密主程序，全量 NOP 会导致 SIGILL
3. 回调中使用 `patchInitArray`（含 `hasSvc0` 扫描），只 patch 含 `svc #0` 指令的函数

---

## Phase 3：发现检测逻辑

模块: `utils + exit_blocker + init_hook(onModuleInit:[{moduleName:"libDetect.so"}]) + dlsym_tracer`

输出示例：
```
[!] do_dlsym: pthread_create
[!] do_dlsym: strstr
```
→ `pthread_create` = 检测代码创建了线程做持续扫描

---

## Phase 4：exit_blocker 持续开启

**全分析过程必须加载 exit_blocker。** 进程被保活后检测线程可能进入死循环——这是正常现象，你正在阻止其退出操作。

---

## Phase 5：定位闪退偏移

模块: `utils + exit_blocker + init_hook(onModuleInit:[{moduleName:"libDetect.so"}]) + shellcode_detector`

输出示例：
```
[!] [SHELLCODE] mmap len=28 prot=rwx addr=0x7a56780000
Call stack:
  [0] libDetect.so + 0x234e0 | 0x7a123634e0 sub_234E0
  [1] libDetect.so + 0x1b8d4 | 0x7a1235b8d4 sub_1B8D4
  [2] libc.so + 0x8b1a0 | 0x7a4568b1a0 pthread_create+0xa0
```
→ 栈顶 `[0]` 的偏移就是闪退函数：`libDetect.so + 0x234e0`

---

## Phase 6：精确 bypass

模块: `utils + init_hook(onModuleInit:[{moduleName:"libDetect.so"}]) + function_patcher`

在 init_hook 回调中调用：
```javascript
var FP = global.FunctionPatcher;
FP.patchBatch([
    {module: "libDetect.so", offset: 0x234e0},
    {module: "libDetect.so", offset: 0x26334},
]);
```

验证：去掉 `exit_blocker` 后 app 正常运行不闪退。

---

## 症状速查

| 症状 | 模式 | 模块组合 |
|------|------|---------|
| exit_blocker BLOCKED + 调用栈来自 pthread_create | 线程检测 | `thread_blocker(blockCallers)` 或 `thread_monitor(callerFilter)` → `function_patcher` |
| 已知 IDA so+offset | 已分析目标 | `function_patcher.patchBatch([...])` |
| 加固壳延迟加载 so + 检测线程 | 壳多阶段 | `thread_blocker(blockCallers)` + `waitForModule` |
| exit_blocker 无 BLOCKED 但进程退出 | init_array SVC | `init_hook` + `hasSvc0` |

---

## 经验积累

以下是从实战文章中沉淀的绕过模式。**当用户提供新的绕过经验文章时，在此处按模板追加。**

### 模式 1: 死兆星线程检测

- **来源**: 死兆星安全分析文章
- **症状**: `exit_blocker` BLOCKED，调用栈来自 `pthread_create`，入口在检测 so 内
- **检测原理**: 独立线程周期性扫描 `/proc/self/maps`、Frida 端口、线程名
- **绕过方案**: `thread_blocker(blockCallers:["检测so名"])` 在 `pthread_create` 阶段拦截
- **备选方案**: `thread_monitor(callerFilter)` 取偏移 → `function_patcher` NOP 掉检测函数的入口

### 模式 2: 梆梆已知偏移

- **来源**: 梆梆加固分析文章
- **症状**: 已有 IDA 静态分析结果，知道检测函数的 so+offset
- **检测原理**: 扫描函数 + 杀进程函数分散在加固壳中
- **绕过方案**: `function_patcher.patchBatch([{module:"xx.so", offset:0x...}, ...])` 直接 NOP
- **注意事项**: 不能全量 NOP 壳 so 的 init_array，只 NOP 已知检测偏移

### 模式 3: 爱加密延迟阻断

- **来源**: 爱加密加固分析文章
- **症状**: 加固壳先加载壳 so（`libexec.so`），解密后再动态加载主 so（`libexecmain.so`），检测线程在解密阶段已创建
- **检测原理**: 多层检测 + 延迟加载，线程检测先于主 so 加载
- **绕过方案**: `thread_blocker(blockCallers:["libexec.so"], waitForModule:[{name:"libexecmain.so", intervalMs:100, timeoutMs:30000}])`
- **注意事项**: `waitForModule` 用 dlopen RTLD_NOLOAD 轮询等待主 so 加载完成

### 模式 4: init_array SVC 直接退出

- **来源**: sunlife APP 实战分析
- **症状**: `exit_blocker` 无任何 BLOCKED 日志，进程直接消失
- **检测原理**: 在 init_array 中使用 `svc #0` 内联汇编直接调用 `exit_group`，完全绕过 libc
- **绕过方案**:
  1. 离线 `llvm-objdump` 反汇编 linker64 找到 `call_constructors` offset
  2. `init_hook` 在 `call_constructors` 处拦截
  3. `hasSvc0` 扫描 init_array 中的每个函数，只 NOP 含 `svc #0` 指令的函数
- **注意事项**: 加固壳场景下不能全量 NOP init_array，壳的解密函数也在其中

### 模式 5: clone() 线程定位 + PROT_NONE 暗杀

- **来源**: 看雪《安卓逆向 某头部银行app 过frida检测 脱壳 定位登录接口加解密函数全过程》(2026.3)
- **症状**: `frida -f` 注入后进程不闪退，但存在强制退出弹框；检测线程由 `clone()` 直接创建而非走 `pthread_create`
- **检测原理**: 检测 so 通过 `libc.so` 的 `clone()` 函数直接创建子线程（绕过 pthread 封装），子线程周期性扫描 Frida 端口/`/proc/self/maps`/线程名
- **模块**: `thread_monitor(resolveRealEntry:true)` — 自动从 `args[3].add(96).readPointer()` 提取真实线程入口；`thread_blocker(strategy:"clone_prot_none")` — 对检测入口 PROT_NONE 暗杀
- **绕过方案**:
  1. 先用 `thread_monitor(resolveRealEntry:true)` 摸清全部 clone 真实入口来源 so+offset
  2. 对纯检测 so：`thread_blocker(strategy:"clone_prot_none", blockCallers:["libDetect.so"])` 暗杀入口使其崩溃
  3. 或拿到偏移后喂给 `function_patcher.patchBatch([...])` 精确 NOP
- **注意**: **不能无脑全量 NOP/暗杀同一 so 的所有 clone 线程入口。** 该文章中一个 so 同时承担了解密和检测双重职责（壳的解密 so），暗杀其全部 clone 入口导致 app 无响应。遇到此情况有两个选择：
  1. 只用 `thread_monitor(resolveRealEntry:true)` 拿偏移，切换 `function_patcher` 精确 NOP 单条检测函数入口
  2. 放弃 native 层对抗，切换到模式 6（Dialog 弹框绕过）在 Java 层用调用栈回溯定位检测触发点

### 模式 6: Dialog/Toast 弹框绕过

- **来源**: 看雪《安卓逆向 某头部银行app 过frida检测 脱壳 定位登录接口加解密函数全过程》(2026.3)
- **症状**: `frida -f` 注入后进程不死、`exit_blocker` 无 BLOCKED，但 app 弹出强制退出对话框/Toast 阻止操作
- **检测原理**: app 的 Java 层检测逻辑触发后不走 `exit()` 流程，而是弹出 `AlertDialog` 并在用户点击确定后调用 `finish()` 或 `System.exit()`；进程存活但无法继续使用
- **绕过方案**:
  1. Hook `AlertDialog.Builder.create()` / `show()` → 直接拦截返回 null 阻止弹框
  2. 更精准：通过拦截处的 `Java.stackTrace` 回溯调用方，再 hook 真正触发弹框的业务方法
  3. 如果弹框是自定义 View，枚举已加载类搜索 `Dialog`/`Exit`/`Force` 关键词定位后 hook
- **注意**: 直接拦截 `create()` 可能导致 app 正常弹框也消失；优先用调用栈回溯找到检测触发点后再精准 hook

### 模式 7: TrustManagerImpl SSL 证书锁定绕过

- **来源**: 看雪《安卓逆向 某头部银行app 过frida检测 脱壳 定位登录接口加解密函数全过程》(2026.3)
- **症状**: Charles/小黄鸟安装证书后仍无法抓包，app 发起 HTTPS 请求失败或返回证书错误
- **检测原理**: app 在 `TrustManagerImpl.checkTrusted()` 中做了额外证书校验（白名单固定证书、SSL Pinning），不信任用户安装的代理 CA 证书
- **绕过方案**: Hook `javax.net.ssl.TrustManager` 的 `checkServerTrusted` / `checkClientTrusted` 使其不做任何校验直接返回；如果已 hook OkHttp（走 `ssl_plaintext`），但证书校验在更底层 TrustManager 层执行，需同时 hook
- **注意**: `ssl_plaintext` 模块 hook 的是 OkHttp/Retrofit 的请求/响应体，若 SSL Pinning 在 TrustManager 层先拦截会导致 OkHttp 层拿不到连接；需优先过 TrustManager 再配合 `ssl_plaintext` 抓明文

---

### 追加模板

当用户提供新的绕过文章时，按以下格式在下方追加：

```
### 模式 N: [简要描述]

- **来源**: [文章标题/来源]
- **症状**: [exit_blocker 的输出信号、调用栈特征、进程行为]
- **检测原理**: [检测机制简述]
- **绕过方案**: [模块组合 + 关键 CONFIG]
- **注意事项**: [踩坑记录、与现有模式的差异]
```