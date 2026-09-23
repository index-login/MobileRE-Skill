---
name: frida-mobile-security
description: 用于 Android/iOS 移动应用安全逆向分析：Frida 动态插桩、绕过反调试/反注入/加固壳、脱壳、加密与 native SO 层 hook、运行时行为分析、jadx-mcp 静态攻击面分析。内置工具链：一键脱壳 unpack.py、ELF 侦察 elfinfo.py、非交互 Frida 运行 frida_run.py、快速反汇编 disasm.py、监控/绕过模块、独立检测工具（注入/调试/签名）。用户提到"绕过检测/闪退/脱壳/加密/抓包/行为摸底/内存扫描/分析 so/ELF 侦察/快速反汇编/检查证书"等意图时使用。
---

# Frida Mobile Security — 逆向分析总控

**模块优先，决策树驱动。** 本文件是总控：任务路由 + 决策树导航 + 模块目录。各技巧域的详细打法在项目根 `references/` 分域文件（全量索引 `references/_index.md`），按需读取。

> 路径基准：`references/*` 相对项目根；`scripts/*` 相对本文件所在目录（`.kilo/skill/frida-mobile-security/`）。**给用户的 frida CLI 命令必须写全路径**（如 `-l .kilo/skill/frida-mobile-security/scripts/core/utils.js`），或让用户先 `cd .kilo/skill/frida-mobile-security`；`tools/frida_run.py -l scripts/...` 短路径自动解析（实测：短路径直接跑 frida CLI 会 `Errno 2`）。

**硬性规则：`scripts/core/utils.js` 必须作为第一个 `-l` 参数加载。**

---

## 快速命令卡片

```bash
# 从项目根执行：先 cd .kilo/skill/frida-mobile-security，或把 scripts/ 展开为 .kilo/skill/frida-mobile-security/scripts/
# 例：frida -U -f com.app -l .kilo/skill/frida-mobile-security/scripts/core/utils.js -l .kilo/skill/frida-mobile-security/scripts/monitors/crypto_monitor.js

# 加解密自吐
frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/crypto_monitor.js

# 行为摸底
frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/file_monitor.js -l scripts/monitors/network_monitor.js -l scripts/monitors/thread_monitor.js

# 反检测 Phase 1 (保活 + 定位检测 so)
frida -U -f com.app -l scripts/core/utils.js -l scripts/bypass/exit_blocker.js -l scripts/bypass/so_loader_tracer.js

# HTTP 明文拦截
frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/ssl_plaintext.js

# Native 函数发现
frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/native_hooker.js

# 跨组件 Intent 污点追踪
frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/intent_tracker.js

# 内存敏感数据扫描 + 密码输入监听
frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/memory_scanner.js
```

> 通道说明：`-U` 是 USB 直连；走端口转发时换成 `-H 127.0.0.1:8888`（先 `adb forward tcp:8888 tcp:8888`）。
> Agent 无人值守运行用 `tools/frida_run.py`（非交互：加载 → 观察 N 秒 → 存活报告 → detach）；也可直接用原生 `frida -F -q -t N -o log`（静默、定时退出、落盘）。frida CLI 是 REPL，stdin EOF 会自动退出，不能直接在后台跑。Windows 控制台打印非 UTF-8 payload 会崩输出线程：优先 `-o` 落盘或设 `PYTHONIOENCODING=utf-8`。
> 设备操控用 `tools/device_ui.py`：元素树 `elements`、按文本/ID 点击 `tap --text/--id`（现 dump 现定位，无 ref 失效问题）、等待 `wait-for`、常亮 `stayon`、清空 `clear`。

运行时配置通过 `-e 'var CONFIG_OVERRIDE={...}'` 注入，见 §五。

---

## 〇、环境自检（连设备后先跑，三条）

```bash
adb devices -l                                               # 1. 设备在线
adb shell su -c "ps -A | grep -i frida"                      # 2. server 是否在跑
adb forward tcp:8888 tcp:8888; frida-ps -H 127.0.0.1:8888    # 3. 通道验证（有进程列表即通）
```

启动 frida-server 用 `nohup ... &`（`-D` 会挂住 adb shell 不返回，容易误判未启动）。server 版本需与本地 `frida` CLI 一致：

```bash
adb shell "su -c 'nohup <设备上 frida-server 路径> -l 127.0.0.1:8888 > /dev/null 2>&1 &'"
```

---

## 一、任务路由

匹配用户意图 → 加载对应 references 分域 → 按决策树执行。**不要逐章浏览。**

| 意图关键词 | 手法域名 | 加载 |
|-----------|---------|------|
| "绕过检测" "过掉反调试" "挂上就闪退" "防注入" "加固壳" "SVC" "TracerPid" "GDB" | 环境对抗 | `references/anti-detection.md` |
| "脱壳" "加固解密" "提取 dex" "so 提取" | 脱壳 | `references/unpacking.md`（**默认 `tools/unpack.py` 一键跑；深挖/异常才用底层脚本**） |
| "加密明文" "算法" "密钥" "AES" "hook 方法" "修改参数" "伪造返回值" "SSL 证书" "TrustManager" "onReceivedSslError" | 加密/功能 hook | `references/crypto-hook.md` |
| "看网络请求" "抓包" "还原协议" "行为摸底" "全程监控" "污点追踪" "内存扫描" "Intent" "Serializable" | 行为分析 | `references/behavior-analysis.md` |
| "分析这个类" "攻击面" "序列化" "WebView" "深链" "Provider" "反序列化" | 静态分析 | `references/static-analysis.md` |
| "分析这个 so" "native 函数" "so 里的加密" "字符串引用" "交叉引用" "逆向 so" "找不到导出" | SO 层分析 | `references/native-analysis.md` |
| "模块无输出" "闪退" "ANR" "hook 不生效" "报错" | 故障诊断 | `references/troubleshooting.md` |
| "写自定义 hook" "API 用法" "Stalker" "RegisterNatives" "内存搜索" | API 参考 | `references/api-reference.md` |

### 前置判断：检测是否已绕过

```
用户是否已能稳定挂载 Frida？
├─ [否] "挂上就闪退" → 加载 anti-detection.md
├─ [是] 已用 hluda/魔改 frida/已跑过 exit_blocker → 跳过反检测，直接匹配任务
└─ [不确定] → 快速探路：utils + exit_blocker + so_loader_tracer
     ├─ exit_blocker 有 BLOCKED → 存在检测但已被保活 → 可继续
     └─ exit_blocker 无日志且进程正常 → 无检测 → 可继续
```

---

## 二、决策树导航

每种技巧在对应 references 有完整决策树，此处只给入口：

| 技巧域 | 入口决策树 | 详细 |
|-------|-----------|------|
| 加密算法 | Step 1 crypto_monitor → Step 2 native_hooker → Step 3 network_monitor | crypto-hook.md |
| 网络协议 | Step 1 network_monitor → 明文/密文分流 | behavior-analysis.md |
| 行为摸底 | file + network + thread 三模块画像 → 按信号追加 | behavior-analysis.md |
| 反检测 | Phase 1 保活 → 分支 A/B → Phase 2-6 | anti-detection.md |
| 跨组件污点 | intent_tracker → 三链路对齐 | behavior-analysis.md |
| 内存敏感数据 | memory_scanner 自动扫描 + 交互式搜索 | crypto-hook.md |
| SO 层分析 | 分层下钻：Java → JNI → .so → libc → syscall → svc | native-analysis.md |
| 静态攻击面 | 攻击面枚举 → 逐类审查 → 序列化链路 | static-analysis.md |

---

## 三、模块目录

`scripts/` 下全部模块，按用途分类。`utils.js` 始终首个加载。

### core/

| 模块 | 用途 |
|------|------|
| `utils.js` | 公共工具（日志格式化/hexdump/backtrace），**必须首个加载** |

### monitors/（被动观察，不修改行为）

| 模块 | 用途 | 归属 |
|------|------|------|
| `crypto_monitor.js` | Java 层加解密自吐（算法/密钥/IV/明文） | crypto-hook |
| `native_crypto_monitor.js` | OpenSSL/BoringSSL 加密监控 | crypto-hook |
| `native_hooker.js` | 任意 native 函数 hook（加密/发送/校验） | native-analysis |
| `jni_bridge_monitor.js` | 方法索引桥加固分析（梆梆/360 VMP/Dex2C 特征） | native-analysis |
| `ssl_plaintext.js` | OkHttp/Retrofit HTTP 明文 | crypto-hook |
| `memory_scanner.js` | 内存敏感数据扫描 + 密码输入监听 | crypto-hook |
| `file_monitor.js` | 文件读写监控 | behavior-analysis |
| `network_monitor.js` | 网络连接/收发监控 | behavior-analysis |
| `thread_monitor.js` | 线程创建监控 | behavior-analysis |
| `dl_monitor.js` | SO 加载/卸载监控 | native-analysis |
| `proc_monitor.js` | 子进程/命令执行监控 | behavior-analysis |
| `mem_trace.js` | 设备侧内存访问追踪（MemoryAccessMonitor；输出 trace_recon 同格式日志；默认单次触发，`rearm` 可选） | native-analysis |
| `syscall_tracer.js` | syscall 层追踪 | native-analysis |
| `svc_tracer.js` | SVC #0 指令追踪（Stalker） | native-analysis |
| `intent_tracker.js` | 跨组件 Intent 污点追踪 | behavior-analysis |

### bypass/（主动干预，修改行为）

| 模块 | 用途 | 归属 |
|------|------|------|
| `exit_blocker.js` | 拦截 exit_group/_exit/abort/kill/tgkill 保活 | anti-detection |
| `thread_blocker.js` | 阻断检测线程 pthread_create | anti-detection |
| `init_hook.js` | call_constructors 抢时机（init_array 检测） | anti-detection |
| `frida_feature_hider.js` | 隐藏 Frida 特征（/proc/线程/内存） | anti-detection |
| `function_patcher.js` | 已知偏移 NOP patch | anti-detection |
| `shellcode_detector.js` | 定位 mmap+PROT_EXEC shellcode | anti-detection |
| `dlsym_tracer.js` | 追踪运行时符号解析 | anti-detection |
| `so_loader_tracer.js` | 记录 do_dlopen 路径+基址 | anti-detection |
| `root_bypass.js` | Root 检测绕过（File.exists/系统属性） | anti-detection |

### utils/（Frida 内存工具，JS）

| 工具 | 用途 | 归属 |
|------|------|------|
| `so_dump.js` | 内存 dump SO（脱壳提取） | unpacking |
| `dex_cache_dump.js` | DexCache 精确 dump（免疫假 DEX/抹 magic） | unpacking |
| `dex_finder.js` | 内存搜索 + 指纹校验 + 去重（**备选**：frida-dexdump 不可用时直接用） | unpacking |
| `dex_defineclass_dump.js` | DefineClass 被动拦截 dump | unpacking |
| `codeitem_dump.js` | 二代壳提取：主动 loadClass 触发回填 + 整 DEX dump | unpacking |
| `scan_register_natives.js` | 定位 native 方法实现（Dex2C 按需分析） | native-analysis |

### tools/（项目根：独立工具，无 Frida 依赖）

按 `python3 tools/<工具> ...` 直接跑（工作目录 = 项目根）。检测项（注入/调试/Janus）见 §六。

| 工具 | 用途 | 归属 |
|------|------|------|
| `unpack.py` | **脱壳一键入口**（线性流水线：回填+补充+自动pull+fix-checksum+去重+方法体标记） | unpacking |
| `dex_rebuilder.py` | ① `--fix-checksum` 重算 checksum（默认操作）② CodeItem 离线重组回填 | unpacking |
| `dex_dedupe.py` | 产物去重/校验 | unpacking |
| `find_strref.py` | 字符串引用定位 | native-analysis |
| `find_branch_callers.py` | 交叉引用/调用者定位 | native-analysis |
| `elfinfo.py` | ELF 侦察（段/依赖/导出/导入/重定位/vaddr↔offset，模拟 harness 前置） | native-analysis |
| `fix_elf.py` | 修复 ELF header | unpacking |
| `fix_axml.py` | 修复爱加密魔改 AXML（Manifest 多 4 字节填充+headerSize 谎报 0x000C，jadx/apktool 无法解析时用） | static-analysis |
| `patch_gadget_threadnames.py` | patch gadget 线程名 | native-analysis |
| `scan_inline_svc.py` | 扫描内联 SVC 指令 | native-analysis |
| `frida_run.py` | **非交互 Frida 运行器**（spawn/attach → 加载 → 观察 N 秒 → 存活报告 → detach；`-l` 支持 skill 内相对路径；`-e @cfg.js` 注入 CONFIG_OVERRIDE） | native-analysis |
| `device_ui.py` | 设备交互（text/tap/swipe/key/shot/logs/launch/clear/foreground/size） | behavior-analysis |
| `disasm.py` | 快速反汇编（capstone，按 symbol/vaddr；Ghidra 未启动时的 fallback） | native-analysis |
| `jni_sig.py` | JNI 导出签名侦察（JNI 调用点清单 + Java 第 1 参类型推断：jstring/jbyteArray/…，hook native 前置） | native-analysis |
| `emu_run.py` / `uniharness.py` | 离线仿真（rev-unicorn-debug）：单函数模拟 / JNI·libc 打桩基座；emu_run 内置观测层（`--watch-code/--watch-regs/--watch-buf/--watch-read/--watch-write/--scan`，超限自动聚合） | native-analysis |
| `trace_recon.py` | 仿真 trace 状态重建：观测日志 → 缓冲状态序列（COPY/PASS 自动分段） | native-analysis |
| `cipher_lab.py` | 密码结构判定器：`layers` 层写法双轨迹判定 / `table` 白盒表反推 / `schedule` 编排归因（出主密钥） | native-analysis |

### templates/ + checklist/

| 文件 | 用途 |
|------|------|
| `templates/analysis.py` | Python 工作流模板（推荐，自动处理模块加载顺序） |
| `templates/custom_hook.js` | 自定义 hook 模板 |
| `checklist/webview_ssl_check.js` | WebView SSL 检测清单 |
| `checklist/fridainject.js` | **frida 环境检测项**：注入后弹窗不出现/进程被杀 = 存在检测（验证注入是否成功） |

---

## 四、分层分析原则

当上层 hook 失效时，按此递推下钻（完整方法见 native-analysis.md）：

```
Java/ObjC → JNI/Runtime → Native .so → libc → syscall → SVC #0
```

常见下钻：crypto_monitor 无输出→native_hooker；file_monitor 无输出→syscall_tracer；network_monitor 无 connect→检查 recvfrom；dl_monitor 无输出→syscall_tracer(mmap+PROT_EXEC)。

---

## 五、运行时配置（CONFIG_OVERRIDE）

所有模块接受 `CONFIG_OVERRIDE`，通过 `-e` 或 Python dict 注入：

```javascript
var CONFIG_OVERRIDE = {
    file_monitor:     { filterPath: ["/data/data/com.target/"] },
    network_monitor:  { showPayload: true },
    crypto_monitor:   { showStack: true },
    native_hooker:    { targetLibs: ["libencrypt.so"] },
    ssl_plaintext:    { urlFilter: ["api.example.com"] },
    exit_blocker:     { showBacktrace: false },
    init_hook:        { onModuleInit: [{ moduleName: "libDetect.so" }], probeCallers: true, autoHideFrida: true },
    thread_blocker:   { blockCallers: ["libmsaoaidsec.so"] },
    frida_feature_hider: { indirectHook: true },
};
```

各模块特有配置见对应 references 文件。

---

## 六、独立检测工具（前置，无需 Frida）

项目根 `tools/` 下 bat 脚本，Agent 不能代跑，输出命令让用户自行执行（方便截图取证）。Python 工具可直接跑（`python3 tools/janus_check.py ...`、`py -3 tools/debug-gdb.py ...`，本机 `python` 可能是 Python 2）。

| 工具 | 检测目标 | 用法 |
|------|---------|------|
| `check-anti-inject.bat` | 防注入（ptrace + /proc/pid/mem） | `tools/check-anti-inject.bat <包名>` |
| `debug-gdb.py` | 防调试（ptrace / TracerPid） | `py -3 tools/debug-gdb.py <包名>` |
| `check-janus.bat` | APK 元数据提取（GetAPKInfo.jar） | `tools/check-janus.bat <apk路径>` |
| `janus_check.py` | **Janus 备选检测**：apksigner V1/V2/V3 签名验证（不解析 Manifest，免疫加固魔改） | `python3 tools/janus_check.py <apk路径>` |

首次分析新 App：check-janus → debug-gdb → check-anti-inject → Frida Phase 1。所有工具前置条件：root + SELinux Permissive。注意 `debug-gdb.py` 附加成功后目标若被反调试杀死，属于**检测到反调试**（正结论），非工具失败。

**GetAPKInfo.jar 解析失败（爱加密等魔改 Manifest，报 `0x000c0003`）时，直接用 `janus_check.py`**——经 apksigner 验证签名方案（V1+V2 通过 = Janus 安全），效果与 GetAPKInfo.jar 一致。

**冒烟自检（可选，验证整套链路）**：L2/L3 回归与离线复算的预期结果见 `references/smoke-test.md`。

---

## 七、交互式协作流程

需要用户在 app 上手动操作时（点击按钮/切换页面触发行为）：

```
配置 analysis.py（TIMEOUT=0 手动停止、LOG_TO_FILE=True 日志落盘）
→ 运行 → 用户操作 app → 停止 → 读日志 → 改 CUSTOM_HOOK_SCRIPT → 再运行
```

日志分析：读 `.txt` 日志，按时间戳锚定用户操作窗口，关联多模块信号。详见 `references/behavior-analysis.md` 交叉分析。

---

## references 指引（全量索引：`references/_index.md`）

| 场景 | 读取 |
|------|------|
| 反检测 Pipeline / 经验模式 / 检测工具 | `references/anti-detection.md` |
| 脱壳流程 / 壳识别 / 提取修复 | `references/unpacking.md` |
| 加密决策树 / SSL/TLS / Hook 模板 / Python 工作流 | `references/crypto-hook.md` |
| 行为摸底 / 网络协议 / 污点追踪 / 交叉分析 | `references/behavior-analysis.md` |
| 攻击面枚举 / 序列化 / WebView / jadx-mcp | `references/static-analysis.md` |
| SO 层分析 / Ghidra / unidbg / 分层下钻 / 字符串引用 | `references/native-analysis.md` |
| 故障排查（无输出/闪退/init_hook 陷阱） | `references/troubleshooting.md` |
| Frida API 手册（写自定义 hook 时） | `references/api-reference.md` |
| 参考文章索引（脱壳原理/攻击面方法论） | `references/articles.md` |