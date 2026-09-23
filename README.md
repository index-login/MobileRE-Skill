# MobileRE-Skill — 综合移动端逆向分析 Agent 技能集

<div align="center">

**一个让 AI Agent（Kilo）真正"会逆向"的完整技能系统** —— 不只是 Frida 脚本，而是覆盖静态分析、动态分析、脱壳、反检测、Native 逆向、安全合规的完整逆向工作流。

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v0.6.0-2ea44f?style=flat-square)](https://github.com/index-login/MobileRE-Skill/releases)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=flat-square&logo=android&logoColor=white)](https://developer.android.com/)
[![Frida](https://img.shields.io/badge/Frida-FF6B57?style=flat-square&logo=frida&logoColor=white)](https://frida.re/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Jadx](https://img.shields.io/badge/Jadx-6C5CE7?style=flat-square&logo=java&logoColor=white)](https://github.com/skylot/jadx)
[![Ghidra](https://img.shields.io/badge/Ghidra-9B9B9B?style=flat-square&logo=github&logoColor=white)](https://ghidra-sre.org/)
[![Kilo](https://img.shields.io/badge/Agent-Kilo-orange?style=flat-square&logo=github&logoColor=white)](https://kilo.ai/docs)

**English README** · [English](README.en.md)

如果这个项目对你有帮助，欢迎 ⭐ Star 支持！

</div>

---

## 使用场景

你只需要**用一句话描述需求**，AI 按决策树自动完成整个分析流程：

| 场景 | 一句话需求示例 | AI 会做什么 |
|------|---------------|------------|
| 🎯 **加固脱壳** | "帮我脱壳这个 App" | 多种方式按场景选择：一键脱壳（默认回填/修复/去重/方法体标记）；或内存 DEX dump（panda/mem 双 dumper，ptrace-free，反调试下更隐蔽） |
| 🔐 **加密分析** | "看下这个 App 的加密算法和密钥" | Java + Native 双层加解密自吐：算法/密钥/IV/明文；签名/自研/魔改算法也能还原并离线复算 |
| 🛡️ **反检测绕过** | "挂上 Frida 就闪退，帮我绕过" | 6 阶段 Pipeline：定位检测 SO → 抢 init_array → 保活 → NOP 闪退函数 |
| 🔍 **行为摸底** | "这个 App 偷偷干了什么" | 文件/网络/线程/进程/Intent 全程监控，输出行为画像 |
| 🧩 **Dex2C/VMP 分析** | "这个加密是 native 的，帮我分析逻辑" | 定位 `so+offset`，hook 优先 / unidbg 复现 / Ghidra 伪代码 |
| 🧬 **静态攻击面** | "帮我审计这个 App 的攻击面" | 从 Manifest 枚举 exported 组件/Provider/WebView，source→sink 追踪 |
| 🧪 **安全合规测试** | "帮我检查这个 App 的安全合规" | 自动运行合规检测（注入/调试/WebView SSL/元数据），出具结果 |
| 🧷 **SO 符号/结构恢复** | "这个 so 去符号了，帮我还原函数名和结构体" | 离线 ELF 侦察（`elfinfo`/`find_*`）→ Ghidra MCP 交叉引用推理 → 重命名 + 结构定义 |
| 🦄 **离线模拟执行** | "不跑真机，帮我模拟这个 native 函数" | Unicorn 加载 .so，JNI/libc/syscall 打桩，直接跑目标函数拿结果 |

> 所有操作由 AI 完成，你不需要手敲命令或运行脚本。

---

## 这是什么

一个 **AI 逆向分析 Agent 的完整技能系统**，不是脚本合集：

- 🧠 **Agent 大脑**（`.kilo/agent/reverser.md`）— 逆向分析角色定义，按决策树自动选模块
- 📚 **领域知识**（`references/` 项目级 wiki + `.kilo/skill/`）— 9 大技巧域手册（全量索引 `_index.md`）+ 动态分析总控 + Native 深度能力（符号/结构恢复、离线模拟执行、内存 DEX 脱壳）
- 🔧 **能力单元**（`scripts/`）— 24 个 Frida 模块（monitors 15 + bypass 9）+ 26 个独立工具 + 检测清单
- 🛠️ **合规检测** — 注入、调试、WebView SSL、APK 元数据/签名
- 🔌 **MCP 集成**（`kilo.json`）— jadx-mcp（Java 反编译）+ ghidra-mcp（二进制分析）

## 与传统工具箱的区别

| 维度 | 传统逆向工具箱 | 本 Skill |
|------|---------------|----------|
| 使用者 | 人类工程师 | **AI Agent**（Kilo 等） |
| 交互方式 | 手敲命令 | **一句话描述需求** |
| 核心交付 | 脚本/工具 | **Skill 文档 + Agent 定义**（`.kilo/`） |
| 决策依据 | 人的经验 | **SKILL.md 决策树** |
| 反馈闭环 | 无 | **Feedback 机制**自动记录失败路径 |
| 静态分析 | 手动开 JADX | **jadx-mcp** 让 AI 直接读类源码 |

---

## 架构

```
┌────────────────────────────────────────────────────────────┐
│                 AI Agent (Kilo)                             │
│  .kilo/agent/reverser.md  — Agent 角色定义                  │
│  .kilo/skill/.../SKILL.md — 任务路由 + 决策树 + 模块索引    │
│  feedback/FEEDBACK.md     — agent 级反馈闭环（项目根）              │
├────────────────────────────────────────────────────────────┤
│               Frida 动态 Hook 模块（skill scripts/）        │
│  monitors/ (15 个) — 纯观察，不修改行为                     │
│  bypass/   (9 个)  — 主动干预，修改 app 行为                │
│  utils/            — 内存 dump / 运行时 JS 工具             │
├────────────────────────────────────────────────────────────┤
│               独立工具（项目根 tools/）                      │
│  elfinfo · disasm · unpack · dex_* · frida_run · device_ui │
│  emu_run · trace_recon · cipher_lab · fix_elf · 检测        │
├────────────────────────────────────────────────────────────┤
│               MCP 集成（kilo.json 配置）                    │
│  jadx-mcp  — AI 直接读 Java 源码反编译                      │
│  ghidra-mcp — AI 直接反汇编/调试二进制                      │
├────────────────────────────────────────────────────────────┤
│              合规检测能力                                    │
│  注入检测 · 调试检测 · WebView SSL · APK 元数据/签名验证    │
└────────────────────────────────────────────────────────────┘
```

## 关键技术

- **一键脱壳**：`unpack.py` 6 步线性流水线（默认回填 → 补充扫描 → 自动 pull → 修复 checksum → 去重 → 方法体标记），一代/抽取壳通吃，产物直接拖 jadx
- **反检测 Pipeline**：6 阶段自动递进（定位检测 SO → 抢 init_array → 追踪符号 → 保活 → 检测 shellcode → NOP 闪退函数）
- **分层下钻**：`Java → JNI → Native → libc → syscall → SVC`，上层 hook 被绕过自动降级到更低层
- **Dex2C/VMP 分析**：hook 优先拿数据 → unidbg 复现算法 → Ghidra 伪代码，不需要 IDA 重工具
- **Native 深度逆向**：无符号函数/结构恢复（离线 ELF 侦察 + Ghidra 交叉引用推理）、Unicorn 单函数模拟执行（JNI/libc/syscall 打桩）、内存 DEX 脱壳（双 dumper 交叉验证，ptrace-free）

---

## 项目结构

```
MobileRE-Skill/
├── references/                      # 技巧手册 wiki（项目级，索引见 _index.md）
│   ├── _index.md                    # 索引：作用 / 何时读 / 是否常驻
│   ├── unpacking.md                 # 脱壳
│   ├── anti-detection.md            # 环境对抗
│   ├── crypto-hook.md               # 加密/功能 hook
│   ├── behavior-analysis.md         # 行为分析
│   ├── static-analysis.md           # 静态攻击面
│   ├── native-analysis.md           # SO 层分析
│   ├── troubleshooting.md           # 故障诊断
│   ├── api-reference.md             # Frida API 参考
│   ├── articles.md                  # 参考文章索引
│   └── smoke-test.md                # 冒烟自检（回归清单，其它资料）
├── .kilo/
│   ├── agent/
│   │   └── reverser.md              # Agent 角色定义（工作纪律 + 重要手册清单）
│   └── skill/
│       ├── frida-mobile-security/   # 动态分析总控（Frida + jadx/ghidra MCP）
│       │   ├── SKILL.md             # 总控：任务路由 + 决策树 + 模块目录
│       │   └── scripts/             # Frida JS 模块（由 frida -l 加载）
│       │       ├── core/utils.js        # 公共工具（始终首个加载）
│       │       ├── monitors/            # 15 个监控模块（纯观察）
│       │       ├── bypass/              # 9 个干预模块（反检测等）
│       │       ├── utils/               # 内存 dump JS（so_dump / dex_* / codeitem）
│       │       ├── checklist/           # 检测清单脚本
│       │       └── templates/           # 模板（analysis.py / custom_hook.js）
│       ├── rev-symbol/              # 无符号 .so 函数命名（Ghidra MCP）
│       ├── rev-struct/              # 结构体恢复（偏移访问聚合）
│       ├── rev-unicorn-debug/       # Unicorn 模拟调试（工具在 tools/）
│       ├── rev-dex-dumper/          # 运行时 DEX 脱壳（panda + mem，ptrace-free）
│       └── karpathy-guidelines/     # 编码准则（开发辅助）
├── tools/                           # 独立工具（py/bat/jar，无 Frida 依赖）
│   ├── elfinfo.py                   # ELF 侦察（段/依赖/导出入/重定位/vaddr↔offset）
│   ├── disasm.py / find_strref.py / find_branch_callers.py   # 反汇编 / 字符串 / 调用者
│   ├── unpack.py                    # 一键脱壳入口
│   ├── dex_rebuilder.py / dex_dedupe.py                      # DEX 修复 / 去重
│   ├── fix_elf.py / fix_axml.py / scan_inline_svc.py / patch_gadget_threadnames.py
│   ├── frida_run.py                 # 非交互 Frida 运行（无人值守）
│   ├── device_ui.py                 # 设备交互（元素树/点击/输入/截图）
│   ├── emu_run.py / uniharness.py   # Unicorn 离线仿真（含 --watch-* 观测层）
│   ├── trace_recon.py / cipher_lab.py  # 观测日志→状态重建 / 密码结构判定（层/表/编排）
│   ├── check-anti-inject.bat / check-janus.bat / debug-gdb.py / janus_check.py  # 检测项
│   └── hap_parser.py                # HAP（鸿蒙）包信息解析
├── feedback/FEEDBACK.md            # agent 级反馈闭环（本地保留，不入库）
├── requirements.txt                # Python 依赖（frida/unicorn/capstone/…）
├── kilo.json                       # MCP 配置（jadx-mcp / ghidra-mcp，本地保留，不入库）
├── AGENTS.md                       # 开发规范（AI 编码约束）
└── README.md / README.en.md        # 本文件
```

---

## 环境搭建

### 宿主机要求

| 工具 | 用途 | 下载 |
|------|------|------|
| Python 3.9+ | 运行 Python 分析脚本 | https://www.python.org/downloads/ |
| Frida CLI | Frida 命令行工具 | `pip install frida-tools` |
| ADB | Android 调试桥 | Android SDK Platform-Tools |
| Android NDK | GDB 调试客户端 | https://developer.android.com/ndk/downloads |
| Java Runtime | APK 信息提取 | https://www.oracle.com/java/technologies/downloads/ |
| JADX | Java 反编译 | https://github.com/skylot/jadx |
| Ghidra | 二进制分析 | https://ghidra-sre.org/ |

### Python 依赖

```bash
pip install -r requirements.txt
```

| 包 | 用途 |
|----|------|
| `frida` / `frida-tools` | Frida 动态插桩 |
| `unicorn` | CPU 模拟执行（SO 离线分析 / 模拟调试） |
| `capstone` | 反汇编（模拟追踪/指令级调试） |
| `keystone-engine` | 汇编（模拟打桩） |
| `pyelftools` | ELF 解析（`elfinfo.py` 等工具） |

### MCP 配套（让 AI 直接读源码/反汇编）

通过 `kilo.json` 集成，AI 分析时直接调用，无需手动开 GUI：

| MCP | 作用 | 安装 |
|-----|------|------|
| **jadx-mcp** | AI 直接读 Java 类源码（`jadx_get_class_source` 等） | [jadx-ai-mcp](https://github.com/zinja-coder/jadx-ai-mcp) |
| **ghidra-mcp** | AI 直接反汇编/调试二进制（`ghidra_import_file` 等） | [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) |

### 测试机准备

```bash
# 1. 推送 frida-server
adb push frida-server-<版本>-android-arm64 /data/local/tmp/fuckserver
adb shell "chmod 755 /data/local/tmp/fuckserver"
adb shell "su -c '/data/local/tmp/fuckserver -D'"

# 2. 推送 AndKittyInjector（合规检测用）
adb push AndKittyInjector /data/local/tmp/AndKittyInjector
adb shell "chmod 755 /data/local/tmp/AndKittyInjector"

# 3. 推送 gdbserver64（调试检测用）
adb push gdbserver64 /data/local/tmp/gdbserver64
adb shell "chmod 755 /data/local/tmp/gdbserver64"
```

---

## 设计原则

- **单一职责** — 一个模块做一件事，monitors/ 只观察不修改，bypass/ 只干预不监控
- **可组合** — 模块通过 `-l` 参数自由组合，不互相依赖
- **可观测** — 所有 hook 点必须有日志输出，不静默吞掉
- **可复现** — 脚本能在其他设备上跑，不依赖特定路径硬编码
- **最小权限** — 只 hook 需要的目标，不做全量扫描

## 许可

[MIT](LICENSE) 许可。

## 免责声明

本项目仅供**教育和合法授权**的安全测试使用：

- 请勿用于任何未经授权的 App 分析、破解或逆向
- 使用者须确保拥有对目标 App 进行测试的合法授权
- 因使用本项目造成的任何法律责任由使用者自行承担
- 如侵犯了您的权益，请联系作者删除相关内容

## 支持

- ⭐ Star 本项目
- 🐛 遇到问题提交 Issue
- 🧩 有新的检测项/模块想法，欢迎讨论
