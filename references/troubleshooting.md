# 故障诊断（Troubleshooting）

> 何时读：用户提到"模块无输出/闪退/ANR/hook 不生效/报错/环境异常"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。模块位置见 SKILL.md 模块目录（Frida 模块 `scripts/<子目录>/` 相对 skill 根；独立工具在项目根 `tools/`）。如以下排查表无法解决，搜索最新实践：`https://weixin.sogou.com/weixin?type=2&query=frida+<关键词>`

---

## Hook 不生效 / 模块无输出

| 现象 | 可能原因 | 排查 |
|------|---------|------|
| crypto_monitor 无输出 | Java.available=false | native-analysis.md → native_hooker |
| crypto_monitor 无输出 | 自定义 ClassLoader | hook ClassLoader.loadClass |
| crypto_monitor 无输出 | 加密在 native 层 | dl_monitor 确认 crypto so |
| file_monitor 无输出 | 函数内联 | syscall_tracer |
| network_monitor 无 connect | UDP (sendto) | 检查 recvfrom |
| network_monitor 无输出 | Binder/Unix Socket | syscall_tracer(traceAll:true) |
| dl_monitor 无输出 | 自定义 linker | syscall_tracer (mmap+PROT_EXEC) |
| native_hooker 无输出 | SO 尚未加载 | spawn 模式或 dl_monitor |
| ssl_plaintext 无输出 | 非标准 HTTP 库 | network_monitor(showPayload:true) |

---

## 进程闪退 / 不稳定

| 现象 | 可能原因 | 排查 |
|------|---------|------|
| 加载 Frida 后闪退 | Frida 被检测 | 加载 exit_blocker → anti-detection.md |
| exit_blocker 后仍闪退 | sigaction(SIGKILL)+raise | 额外 hook signal + kill/tgkill |
| exit_blocker 后仍闪退 | 内联 _exit() | syscall_tracer (syscall 93/94) |
| hook 后 ANR/卡死 | onEnter 耗时操作 | 改为异步 send() |
| Interceptor.replace 崩溃 | 参数签名不匹配 | 检查 NativeFunction 参数类型 |
| TypeError: not a function | replace/attach 冲突 | exit_blocker(blockSyscall:false) 或 indirectHook |
| 进程退出但无 BLOCKED | SVC #0 内联 exit_group | anti-detection.md 分支 B |
| 主进程存活但 logcat 有子进程 SIGSEGV | 反调试 fork 子进程自杀（ptrace 自检等） | 别判「Frida 导致闪退」：`ps` 确认主 PID 存活，再看子进程崩溃栈 |
| 函数中部 inline hook 后 SIGABRT（stack corruption） | Frida trampoline 干扰栈 canary / 完整性自检 | 优先 hook 函数入口；必须看中部时改用 Stalker 观察（不改指令） |

---

## Constructor 窗口常见陷阱

### 壳 so 解密函数被误 patch → SIGILL

**症状：** `init_hook(mode:'patch')` 后 app 直接 SIGILL 崩溃，或卡在启动页无响应。

**原因：** 壳 so（如 `libexec.so`、`libDexHelper.so`）的 init_array 同时包含解密函数和检测函数。`mode:'patch'` 只 patch 含 `SVC #0` 的函数，但有些检测函数不用 SVC（如直接 `BRK #1` 或 `pthread_create` 创建检测线程），这些函数被 patch 后不会 SEGV，但解密函数被误 patch 会导致后续代码全错 → SIGILL。

**排查：**
1. 先用 `mode:'inspect'` 看每个 init_array 函数的 hexdump 和 heuristic 标签
2. 标记为 `>> func prologue` 或 `>> likely kill/exit` 的可以 patch
3. 标记为空或 `>> already RET` 的跳过
4. 如果 inspect 输出中某个函数首指令是 `FF 43 01 D1`（`SUB SP, SP, #0x50`）— 大概率是解密函数，不能 patch
5. 加密壳常在 init_array 里有 10+ 个函数，其中只有 1-2 个是检测函数

### 匿名 RX 段中的检测代码未被 patch

**症状：** `init_hook(mode:'patch')` 后主进程稳定，但子进程（`:remote`、`:push`）仍闪退。

**原因：** 壳在 constructor 中调用 `mmap` 分配匿名可执行内存，将检测代码写入其中后执行。这些代码不在 ELF 的 init_array 里，`init_hook` 的 ELF 解析无法发现。

**排查：**
1. 用 `svc_tracer` 追踪闪退时的 SVC 指令，输出 PC 地址
2. 如果 PC 地址不属于任何已知 SO（`[anon:rwx]`），说明检测代码在匿名 RX 段
3. 用 `shellcode_detector` 定位 mmap+PROT_EXEC 的调用栈
4. 对匿名段中的 SVC 指令地址用 `function_patcher` 定点 patch

### dispatch 分发块被误当函数入口

**症状：** patch 某个 init_array 函数后 app 卡死但不崩溃。

**原因：** 加固壳使用控制流平坦化，存在一个 public 的 dispatch 分发块（根据 W0 选择分支）。如果 patch 了这个分发块，所有通过它路由的函数都会失效。

**排查：**
1. inspect 输出中，如果看到某个函数首指令是 `MOV` 或 `CMP` 操作 W0/W8 寄存器而非 `STP x29,x30`，可能是分发块
2. 分发块的特征：短函数（< 20 条指令），大量条件跳转，操作 W0/W8 做分支选择
3. 不要 patch 分发块，而是 patch 分发块跳转到的 fatal 分支

---

## SVC tracer 排查

### SVC tracer 无输出

| 症状 | 可能原因 | 排查 |
|------|---------|------|
| 加载后无任何日志 | Stalker 未跟进目标线程 | 检查 `followNewThreads` 是否成功，`traceChildThreads:true` 是否开启 |
| 有初始化日志但无 SVC 事件 | 目标 SO 尚未加载 | `spawn` 模式 + `duration` 设长一些（120s），或用 `so_loader_tracer` 确认加载时机 |
| 过滤了所有 SVC | `filterSyscalls` 配置太窄 | 临时设为 `filterSyscalls:[]` 看全量 SVC |
| SVC 在 libc 内被跳过 | `skipLibcSvc:true` 生效 | 壳的 direct SVC 在匿名 RX 段而非 libc；若确实需要看 libc 内的 SVC，设 `skipLibcSvc:false` |
| 进程闪退前一瞬间才有输出 | 检测在 Stalker 跟进前就执行了 | 配合 `init_hook` 在 constructor 前启动 Stalker，或增大 `sleepBeforeInit` |
| 大量 `[anon:rwx]` 输出 | 匿名 RX 段中的检测代码 | 正常，记录 PC 地址用于 function_patcher |

### SVC tracer 导致 app 卡死

**症状：** 加载 `svc_tracer` 后 app 极其缓慢或 ANR。

**原因：** Stalker 对每条指令做 instrumentation，开销极大。如果 stalking 了所有线程 + 所有模块，性能会下降 10-100 倍。

**排查：**
1. 设置 `duration: 30` 只追踪前 30 秒
2. 设置 `targetModules: ["libexec.so"]` 只追踪检测 SO
3. 设置 `filterSyscalls: [93, 94, 129, 131]` 只看 kill/exit
4. 设置 `traceChildThreads: false` 只追踪主线程
5. 如果仍然卡死，临时用 `duration: 10` 极短时间窗口

---

## init_hook 排查

### call_constructors 找不到

**症状：** `init_hook.js DISABLED: call_constructors address not resolved`

**原因：** 不同 Android 版本的 linker64 内部符号变化。高版本（API 34+）linker 可能 strip 了 `call_constructors` 符号，或改名。

**排查（按优先级）：**
1. 确认 `call_constructors` 符号：
   ```bash
   adb shell "readelf -sW /apex/com.android.runtime/bin/linker64 | grep call_constructors"
   ```
2. 如果无输出，搜索静态符号表：
   ```bash
   adb shell "readelf -s /apex/com.android.runtime/bin/linker64 | grep call_constructors"
   ```
3. 如果都找不到，需要离线反汇编 linker64 找偏移：
   ```bash
   adb pull /apex/com.android.runtime/bin/linker64 /tmp/linker64
   llvm-objdump -d /tmp/linker64 | grep "bl.*call_constructors"
   ```
   找到 `bl #0x????? <call_constructors>` 后，将偏移加入 `fallbackOffsets` 列表
4. 如果 linker64 路径不同（某些厂商定制 ROM），用 `adb shell "ls /apex/com.android.runtime/bin/"` 确认实际路径

### init_hook 拦截了但 callback 没触发

**症状：** `init_hook.js ready` 但 `call_constructors: xxx found` 从未出现。

**原因：**
- `onModuleInit` 配置的 moduleName 与实际 SO 文件名不匹配（注意大小写）
- SO 在 `call_constructors` 之前就已经加载了（如系统库）
- 使用了 `android_dlopen_ext` 以外的加载方式（如直接 `mmap` + 手动解析 ELF）

**排查：**
1. 设 `logAllConstructors: true` 看所有 call_constructors 调用
2. 设 `sleepBeforeInit: 10` 给 SO 加载留足时间
3. 用 `so_loader_tracer` 确认 SO 的实际文件名和加载路径

---

## 多进程场景诊断

### 主进程稳定但子进程闪退

**症状：** 主进程 patch 后稳定运行，但 `:remote`、`:pushservice` 等子进程启动后闪退。

**原因：** 子进程独立加载 SO，init_array 重新执行，检测代码未被 patch。

**排查：**
1. 用 `frida -U -n com.app:remote` 单独 attach 子进程
2. 子进程加载轻量 agent（只含 `exit_blocker` + `init_hook(mode:'patch')`），不加载主进程的全部监控模块
3. 确认子进程的 SO 加载链：`adb logcat | grep "do_dlopen"` 看子进程加载了哪些 SO
4. 在 anti-detection.md 中参考模式（多 so 协作 + 子进程）

### 子进程 attach 失败

**症状：** `frida -U -n com.app:remote` 报 `ProcessNotFoundError`。

**原因：**
- 子进程启动后立即闪退，来不及 attach
- 子进程名不是 `com.app:remote` 而是其他格式

**排查：**
1. 用 `frida -U -f com.app` spawn 主进程，同时监控子进程创建：
   ```bash
   adb shell "while true; do ps -A | grep com.app; sleep 0.5; done"
   ```
2. 看到子进程 PID 后立即 `frida -U -p <PID>` attach
3. 如果子进程存活时间太短（< 1 秒），用 `frida -U -f com.app` 启动后在 init_hook 回调中 spawn 子进程 agent

---

## 仿真排查（Unicorn）

### 仿真结果不确定 / 每次输出不同

先查 `timeout` 单位：Unicorn 2.x 的 `emu_start(..., timeout=N)` 按**微秒**解释（文档写毫秒）；`timeout=300000`（以为 5 分钟）实为 0.3 秒，会把仿真硬截断在任意 PC，表现为"结果随机/提前 return"，容易误判为"目标代码非确定性"。`timeout=0` = 不限。

```bash
# 玩具验证：死循环 + timeout=50000，若 ~50ms 返回则为微秒语义
python3 -c "import time;from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN;\
uc=Uc(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN);uc.mem_map(0x1000,0x1000);uc.mem_write(0x1000,bytes.fromhex('00000014'));\
t=time.time();uc.emu_start(0x1000,0x1004,timeout=50000);print('elapsed',time.time()-t)"
```

`uniharness.call()/run()` 默认已是 `timeout=0`。

---

## 环境版本

| 现象 | 原因 | 排查 |
|------|------|------|
| frida 连不上（-U / -H） | server 未启动 / 未 forward / 版本不匹配 | 见下「frida 通道自检」 |
| Java.perform 报错 | 非 JVM 进程 | `frida-ps -U` 确认进程类型 |
| ARM64 vs ARM32 符号不匹配 | 64位设备 32位 so | `file` 命令检查架构 |
| iOS arm64e PAC 崩溃 | 指针认证 | 见 api-reference.md |
| Android 高版本 linker64 符号消失 | linker 重构 | `Module.enumerateExports("linker64")` |

### frida 通道自检（连不上时按序查）

1. 设备在场：`adb devices -l`
2. server 在跑：`adb shell su -c "ps -A | grep -i frida"`；没有则用 `nohup ... &` 启动（**`-D` 会挂住 adb shell 不返回**，容易误判未启动）：
   ```bash
   adb shell "su -c 'nohup <设备上 frida-server 路径> -l 127.0.0.1:8888 > /dev/null 2>&1 &'"
   ```
3. 通道验证：`adb forward tcp:8888 tcp:8888; frida-ps -H 127.0.0.1:8888`（能列出进程即通）
4. 版本对齐：本地 `frida --version` 必须与设备上 server 版本一致，否则报协议错误

### Windows（PowerShell）环境坑

- `python` 可能是 Python 2.7（如 drozer 自带），统一用 `py -3` / `python3`
- 二进制重定向会被按文本重编码：`adb exec-out screencap -p > x.png` 必须 `cmd /c "..."` 包一层，否则 PNG 损坏
- heredoc（`<<EOF`）不可用：多行脚本先落地成 .py 文件再执行
- `adb pull` 不支持通配符：先 `adb shell pm path <pkg>` 取（带 hash 的）绝对路径再 pull

---

## Root 检测绕过排查

### File.exists/exists 通配 hook 不生效

**症状：** `root_bypass.js` 加载后，File.exists 仍返回 true。

**原因：**
- ART AOT 内联：关键方法被编译为 native 代码后直接执行，Frida Java hook 不触发
- 检测在 native 层直接调用 libc 的 `access`/`stat` 等函数，不经过 Java File API

**排查：**
1. 试 `Java.deoptimizeEverything()` 强制回退到解释执行（KuGou 实战经验）
2. 同时开启 `root_bypass` 的 `hookNativeFile: true`（native 层 libc 文件访问 hook）
3. 如果检测方使用了 `java.io.File` 的 `list()` 方法，确保 `root_bypass` 也 hook 了 `list`/`listFiles`

### SystemProperties.get 返回异常值

**症状：** `ro.build.tags` 返回 "test-keys"，`ro.debuggable` 返回 "1"。

**原因：** 部分设备即使 root 后，这些属性值也可能取决于内核命令行或 init.rc，而非 build.prop。

**排查：**
1. 确认 hook 了正确的 `SystemProperties.get` 重载（`get(String)`、`get(String, String)`、`getInt`、`getLong`、`getBoolean`）
2. 如果应用使用 `android.os.Build` 静态字段（而非 SystemProperties），需要额外反射修改 Build 类
3. 用 `adb shell getprop ro.build.tags` 确认设备实际值

---

## Native 加密监控排查

### native_crypto_monitor 无输出

**症状：** 加载后所有 [OK] 日志都打印了，但业务操作时无加密数据输出。

**原因：**
- Spawn 模式下 SO 尚未加载，hook 装不上
- 应用使用非标准 SO 名称（如 libcrypto_flutter.so、libflutter.so 内嵌 BoringSSL）
- 应用使用自研加密算法（非 OpenSSL/BoringSSL）

**排查：**
1. 确认 SO 加载顺序：`adb logcat | grep "native_crypto_monitor"` 看 dlopen 触发日志
2. 扩展 CRYPTO_SOS 列表：Flutter app 可能需要加 `libflutter.so`，Cronet 可能需要加 `libcronet.so`
3. 用 `check_openssl_imports.js` 扫描 SO 的导入表确认是否使用 OpenSSL ⚠️ 需开发
4. 用 `find_crypto_constants.js` 扫描内存中的 AES S-Box / SM4 / MD5 init 常量（自研算法也能定位）⚠️ 需开发
5. 如果 SO 是 STRIPPED 的（无导出），用 `enum_evp_cipher_exports.js` 确认 EVP 函数是否存在 ⚠️ 需开发

### API 级别不兼容

**症状：** `native_crypto_monitor` 的 `EVP_CIPHER_CTX_cipher` 返回 null。

**原因：** BoringSSL 在不同 Android 版本中 API 有差异（如 `EVP_CIPHER_CTX_cipher` 在较新版本已废弃，需用 `EVP_CIPHER_CTX_get0_cipher`）。

**排查：**
1. 脚本已内置 fallback 链：`EVP_CIPHER_CTX_cipher || EVP_CIPHER_CTX_get0_cipher`
2. 如果仍失败，在设备上 `adb shell "readelf -sW /apex/com.android.runtime/lib64/libcrypto.so | grep EVP_CIPHER"` 确认实际导出名称

---

## 易盾加固排查

### 网易云音乐易盾：MSA 慢层 bypass 后仍闪退

**症状：** `hook_msa_antidbg.js` 绕过 MSA 慢层后，App 仍闪退。`exit_blocker` 日志显示 BLOCKED 来自 libnesec.so。⚠️ 需开发

**原因：** 易盾双 SDK 架构：MSA 慢层负责扫描检测（可拦），libnesec 快层负责 inline SVC kill（需 init_hook）。

**排查：**
1. 先用 `so_loader_tracer` 确认 libnesec.so 的加载时机
2. 加载 `init_hook(mode:'inspect')` 枚举 libnesec.so 的 init_array
3. 对含 `svc #0` 的 init_array 函数用 `init_hook(mode:'patch')` 打 RET
4. 注意：libnesec.so 的 init_array 可能同时包含解密和检测函数，不能全量 NOP

### 招商银行：CmbShield bypass 后 DEC SDK 仍检测

**症状：** `cmb_shield_bypass.js` 绕过 CmbShield 后，DEC SDK 的 ClassLoader 检测仍触发。⚠️ 需开发

**原因：** 三套 SDK 独立运行：CmbShield（native 层）、RootBeer（Java 层）、DEC SDK（Java 层 ClassLoader + 环境变量）。绕过一套不影响另一套。

**排查：**
1. 用 `cmb_all_in_one.js`（679 行）替代逐套绕过，一次性覆盖全部三套 SDK ⚠️ 需开发
2. 如需单独分析 DEC：`cmb_dec_bypass.js` 专项处理 ClassLoader 突破 + Tier A/B/C 分层屏蔽 ⚠️ 需开发

---

## 知识来源

遇到本文档未覆盖的问题时，优先搜索微信公众号中的高质量实战文章：

```
https://weixin.sogou.com/weixin?type=2&query=frida+<关键词>
```

搜索关键词建议：`反调试 绕过`、`init_array 检测`、`加固壳 frida`、`多进程 检测`、`SVC 绕过`、`call_constructors`。

常用高质量公众号：看雪学苑、非攻code、安全后厨、编码安全、哆啦安全、TLPT-Security、Root0fTrust。