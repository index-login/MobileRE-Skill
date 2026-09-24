# MobileRE-Skill — AI-Powered Mobile Reverse Engineering Agent Skill

<div align="center">

**A complete RE skill system that turns an AI Agent (Kilo) into a real reverse engineer** — not just Frida scripts, but a full workflow covering static analysis, dynamic analysis, unpacking, anti-detection bypass, native reversing, and security compliance.

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v0.6.0-2ea44f?style=flat-square)](https://github.com/index-login/MobileRE-Skill/releases)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=flat-square&logo=android&logoColor=white)](https://developer.android.com/)
[![Frida](https://img.shields.io/badge/Frida-FF6B57?style=flat-square&logo=frida&logoColor=white)](https://frida.re/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Jadx](https://img.shields.io/badge/Jadx-6C5CE7?style=flat-square&logo=java&logoColor=white)](https://github.com/skylot/jadx)
[![Ghidra](https://img.shields.io/badge/Ghidra-9B9B9B?style=flat-square&logo=github&logoColor=white)](https://ghidra-sre.org/)
[![Kilo](https://img.shields.io/badge/Agent-Kilo-orange?style=flat-square&logo=github&logoColor=white)](https://kilo.ai/docs)

**中文 README** · [中文](README.md)

If this project helps you, a ⭐ Star is appreciated!

</div>

---

## Use Cases

Just **describe your need in one sentence** — the AI follows the decision tree and completes the whole analysis:

| Scenario | Example request | What the AI does |
|----------|-----------------|------------------|
| 🎯 **Unpacking** | "Unpack this app for me" | Multiple methods by scenario: one-command Frida unpacking (restore/fix/dedupe/method-body marking), or in-memory DEX dump (panda + mem dumpers, ptrace-free, stealthier under anti-debugging) |
| 🔐 **Crypto analysis** | "Find this app's crypto algorithm and keys" | Java + Native dual-layer crypto auto-dump: algorithm/key/IV/plaintext; signature / custom / obfuscated algorithms are also recovered and replayable offline |
| 🛡️ **Anti-detection bypass** | "Frida crashes on attach, bypass it" | 6-phase pipeline: locate detection SO → hook init_array → keep alive → NOP crash functions |
| 🔍 **Behavior profiling** | "What is this app doing in secret?" | File/network/thread/process/Intent monitoring, behavior profile output |
| 🧩 **Dex2C/VMP analysis** | "This crypto is native, analyze the logic" | Locate `so+offset`, hook-first / unidbg replay / Ghidra pseudocode |
| 🧬 **Static attack surface** | "Audit this app's attack surface" | Enumerate exported components/Provider/WebView from Manifest, source→sink tracking |
| 🧪 **Security compliance** | "Check this app's security compliance" | Auto-run compliance checks (injection/debug/WebView SSL/metadata), report results |
| 🧷 **SO symbol/struct recovery** | "This .so is stripped, recover function names and structs" | Offline SO static analysis (`so.py` info/strings/strref/callers) → Ghidra MCP cross-reference inference → rename + struct definition |
| 🦄 **Offline emulation** | "Emulate this native function without a device" | Unicorn loads the .so, stubs JNI/libc/syscalls, runs the target function and returns results |

> All operations are done by the AI — no need to type commands or run scripts yourself.

---

## What Is This

A **complete RE agent skill system**, not a script collection:

- 🧠 **Agent brain** (`.kilo/agent/reverser.md`) — RE role definition, auto-selects modules via the decision tree
- 📚 **Domain knowledge** (`references/` project wiki + `.kilo/skill/`) — 9 technique domain manuals (full index in `_index.md`) + dynamic analysis control + native deep-dive capabilities (symbol/struct recovery, offline emulation, in-memory DEX dump)
- 🔧 **Capability units** (`scripts/`) — 24 Frida modules (monitors 15 + bypass 9) + 21 standalone tools + checklists
- 🛠️ **Compliance detection** — injection, debugging, WebView SSL, APK metadata/signature
- 🔌 **MCP integration** (`kilo.json`) — jadx-mcp (Java decompile) + ghidra-mcp (binary analysis)

## vs Traditional Toolkits

| Dimension | Traditional RE Toolkit | This Skill |
|-----------|------------------------|------------|
| User | Human engineer | **AI Agent** (Kilo etc.) |
| Interaction | Type commands | **Describe in one sentence** |
| Core deliverable | Scripts/tools | **Skill docs + Agent definition** (`.kilo/`) |
| Decision basis | Human experience | **SKILL.md decision tree** |
| Feedback loop | None | **Feedback mechanism** auto-logs failures |
| Static analysis | Manually open JADX | **jadx-mcp** lets AI read class source directly |

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                 AI Agent (Kilo)                             │
│  .kilo/agent/reverser.md  — Agent role definition           │
│  .kilo/skill/.../SKILL.md — task routing + decision tree    │
│  feedback/FEEDBACK.md     — agent-level feedback loop       │
├────────────────────────────────────────────────────────────┤
│               Frida Dynamic Hook Modules (skill scripts/)   │
│  monitors/ (15) — observe only, no behavior modification    │
│  bypass/   (9)  — actively modify app behavior              │
│  utils/            — in-memory dump / runtime JS tools      │
├────────────────────────────────────────────────────────────┤
│               Standalone Tools (tools/ at repo root)        │
│  so.py · unpack · dex_* · frida_run · device_ui             │
│  emu_run · trace_recon · cipher_lab · fix_elf · det         │
├────────────────────────────────────────────────────────────┤
│               MCP Integration (kilo.json)                   │
│  jadx-mcp  — AI reads Java source directly                  │
│  ghidra-mcp — AI disassembles/debugs binaries directly      │
├────────────────────────────────────────────────────────────┤
│              Compliance Detection Capabilities              │
│  Injection · Debugging · WebView SSL · APK metadata/sig     │
└────────────────────────────────────────────────────────────┘
```

## Key Technologies

- **One-command unpacking**: `unpack.py` 6-step linear pipeline (auto restore → supplement scan → auto pull → fix checksum → dedupe → method-body marking), covers 1st/2nd-gen shells, output ready for jadx
- **Anti-detection pipeline**: 6-phase auto progression (locate detection SO → hook init_array → trace symbols → keep alive → detect shellcode → NOP crash functions)
- **Layered descent**: `Java → JNI → Native → libc → syscall → SVC`, auto-descends when top-level hooks are bypassed
- **Dex2C/VMP analysis**: hook-first for data → unidbg to replay algorithms → Ghidra pseudocode, no heavy IDA needed
- **Native deep-dive**: symbol/struct recovery (offline ELF recon + Ghidra cross-reference inference), Unicorn single-function emulation (JNI/libc/syscall stubs), in-memory DEX dump (dual dumpers cross-validated, ptrace-free)

---

## Project Structure

```
MobileRE-Skill/
├── references/                      # Technique manuals wiki (project-level, index in _index.md)
│   ├── _index.md                    # Index: purpose / when to read / resident
│   ├── unpacking.md                 # Unpacking
│   ├── anti-detection.md            # Environment countermeasures
│   ├── crypto-hook.md               # Crypto/function hook
│   ├── behavior-analysis.md         # Behavior analysis
│   ├── static-analysis.md           # Static attack surface
│   ├── native-analysis.md           # SO-layer analysis
│   ├── troubleshooting.md           # Troubleshooting
│   ├── api-reference.md             # Frida API reference
│   ├── articles.md                  # Article index
│   └── smoke-test.md                # Smoke self-test (misc)
├── .kilo/
│   ├── agent/
│   │   └── reverser.md              # Agent role definition (work discipline + key manuals)
│   └── skill/
│       ├── frida-mobile-security/   # Dynamic analysis control (Frida + jadx/ghidra MCP)
│       │   ├── SKILL.md             # Control: task routing + decision tree + module index
│       │   └── scripts/             # Frida JS modules (loaded via frida -l)
│       │       ├── core/utils.js        # Common utils (always loaded first)
│       │       ├── monitors/            # 15 monitoring modules (observe only)
│       │       ├── bypass/              # 9 intervention modules (anti-detection etc.)
│       │       ├── utils/               # In-memory dump JS (so_dump / dex_* / codeitem)
│       │       ├── checklist/           # Check items
│       │       └── templates/           # Templates (analysis.py / custom_hook.js)
│       ├── rev-symbol/              # Stripped .so function naming (Ghidra MCP)
│       ├── rev-struct/              # Struct recovery (offset-access aggregation)
│       ├── rev-unicorn-debug/       # Unicorn emulation debug (tools live in tools/)
│       ├── rev-dex-dumper/          # Runtime DEX dump (panda + mem, ptrace-free)
│       └── karpathy-guidelines/     # Coding guidelines (dev aid)
├── tools/                           # Standalone tools (py/bat/jar, no Frida)
│   ├── so.py                        # SO static analysis all-in-one (ELF recon/strings/bytes/disasm/xrefs/SVC/JNI typing)
│   ├── unpack.py                    # One-command unpacking entry
│   ├── dex_rebuilder.py / dex_dedupe.py                      # DEX repair / dedupe
│   ├── fix_elf.py / fix_axml.py / patch_gadget_threadnames.py
│   ├── frida_run.py                 # Non-interactive Frida runner (unattended)
│   ├── device_ui.py                 # Device UI (elements/tap/text/shot)
│   ├── emu_run.py / uniharness.py   # Unicorn offline emulation (--watch-* observability)
│   ├── trace_recon.py / cipher_lab.py  # log -> state reconstruction / cipher structure adjudication
│   ├── check-anti-inject.bat / check-janus.bat / debug-gdb.py / janus_check.py  # Detection
│   └── hap_parser.py                # HAP (HarmonyOS) package info parser
├── feedback/FEEDBACK.md            # Agent-level feedback loop (local only, not committed)
├── requirements.txt                # Python deps (frida/unicorn/capstone/…)
├── kilo.json                       # MCP config (jadx-mcp / ghidra-mcp; local only, not committed)
├── AGENTS.md                       # Dev conventions (AI coding constraints)
└── README.md / README.en.md        # This file
```

---

## Setup

### Host requirements

| Tool | Purpose | Download |
|------|---------|----------|
| Python 3.9+ | Python analysis scripts | https://www.python.org/downloads/ |
| Frida CLI | Frida CLI | `pip install frida-tools` |
| ADB | Android debug bridge | Android SDK Platform-Tools |
| Android NDK | GDB client | https://developer.android.com/ndk/downloads |
| Java Runtime | APK metadata | https://www.oracle.com/java/technologies/downloads/ |
| JADX | Java decompiler | https://github.com/skylot/jadx |
| Ghidra | Binary analysis | https://ghidra-sre.org/ |

### Python dependencies

```bash
pip install -r requirements.txt
```

| Package | Purpose |
|---------|---------|
| `frida` / `frida-tools` | Frida dynamic instrumentation |
| `unicorn` | CPU emulation (offline SO analysis / emulation debug) |
| `capstone` | Disassembly (emulation tracing / instruction-level debug) |
| `keystone-engine` | Assembly (emulation stubs) |
| `pyelftools` | ELF parsing (`so.py` / `uniharness.py` etc.) |
| `lief` | ELF rewriting (dump repair/rebuild, patch constants, add sections/`DT_NEEDED`) |
| `z3-solver` | Constraint solving (infer inputs from condition/result; pairs with the emu observation layer) |

### MCP setup (AI reads source / disassembly directly)

Configured in `kilo.json`:

| MCP | Purpose | Install |
|-----|---------|---------|
| **jadx-mcp** | AI reads Java class source (`jadx_get_class_source` etc.) | [jadx-ai-mcp](https://github.com/zinja-coder/jadx-ai-mcp) |
| **ghidra-mcp** | AI disassembles/debugs binaries (`ghidra_import_file` etc.) | [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) |

### Test device setup

```bash
# 1. Push frida-server
adb push frida-server-<version>-android-arm64 /data/local/tmp/fuckserver
adb shell "chmod 755 /data/local/tmp/fuckserver"
adb shell "su -c '/data/local/tmp/fuckserver -D'"

# 2. Push AndKittyInjector (for compliance checks)
adb push AndKittyInjector /data/local/tmp/AndKittyInjector
adb shell "chmod 755 /data/local/tmp/AndKittyInjector"

# 3. Push gdbserver64 (for debug detection)
adb push gdbserver64 /data/local/tmp/gdbserver64
adb shell "chmod 755 /data/local/tmp/gdbserver64"
```

---

## Design Principles

- **Single responsibility** — one module one job; monitors/ observe only, bypass/ modify only
- **Composable** — modules combine via `-l`, no interdependency
- **Observable** — every hook point logs output, never silently swallowed
- **Reproducible** — scripts run on other devices, no hardcoded paths
- **Least privilege** — hook only what's needed, no full scans

## License

[MIT](LICENSE).

## Disclaimer

This project is for **education and legally authorized security testing** only:

- Do not use it for any unauthorized app analysis, cracking, or reverse engineering
- Users must ensure they have legal authorization to test the target app
- Any legal liability arising from use of this project is borne by the user
- If any rights are infringed, please contact the author for removal

## Support

- ⭐ Star this project
- 🐛 Open an issue if you run into problems
- 🧩 Ideas for new checks/modules are welcome
