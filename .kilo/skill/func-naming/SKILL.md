---
name: func-naming
description: 已知地址判断函数用途/算法（无符号函数命名）：先查 .dynsym，再取字符串/魔数/成对调用特征，最后回填命名。SO 层深挖的单步能力，入口仍在 frida-mobile-security；恢复结构体用 rev-struct，判漏洞用 native-audit。
---

# func-naming - 无符号函数命名

输入一个地址，输出"它是什么函数 / 什么算法"。

## 何时用 / 何时不用

| 用 | 不用 |
|---|---|
| 已有地址（callers / strref / 崩溃偏移 / hook 栈），函数无符号 | 函数已有符号 → 先查 `.dynsym`，命中直接用 |
| 要判断算法（哈希/编码/压缩/加解密） | 要恢复参数布局 → skill `rev-struct` |
| 要给报告/后续 hook 一个可读名字 | 要判漏洞/可达性 → `references/native-audit.md` |

## 前置

1. `.so` 已拉到本地（`adb pull`）。
2. 记录地址来源（哪条字符串 / 哪个 caller / 哪个崩溃偏移）。
3. `so.py` 可用；`llvm-nm` 在 NDK bin 下（不在 PATH）。
4. 不熟 `so.py` / Ghidra 的完整用法时，先看 [native-analysis.md ›「3.5 SO 分析顺序（tools/so.py 离线工具）」](../../../references/native-analysis.md) 与 [「四、SO 静态分析（Ghidra MCP）」](../../../references/native-analysis.md)。

## 步骤

### 1. 先查符号表（30 秒，最容易漏）

```bash
python3 tools/so.py info <so> --json
# NDK: llvm-nm -D --defined-only <so> | findstr /i <addr>
```

命中即用符号名结束。C++ mangled（`_Z...`）用 `llvm-cxxfilt` 还原签名。

### 2. 确认函数起点

地址来自字符串 xref 时，xref 可能落在内联 `assert`/尾部。向上找序言（`stp x29, x30` / `sub sp, sp`）再继续。

### 3. 取特征（离线优先）

```bash
python3 tools/so.py strings <so> --grep <PAT> --min 8   # 找语义字符串
python3 tools/so.py strref  <so> 0x<STR_VADDR>          # 串 → 引用点
python3 tools/so.py disasm  <so> --addr 0x<FUNC> --count 60
python3 tools/so.py callers <so> 0x<FUNC>               # 调用者
```

需要伪代码、数据 xref、改名时上 Ghidra（见下一步）。

### 4. Ghidra 接手（伪代码 / 数据 xref / 改名）

**so.py 是快查，Ghidra 是语义；两者协作，不是替代。**

1. callee 全是 `func_0x…` → 先跑 `tools/ghidra/so_audit_prep.java` 做 PLT 命名（见 [native-audit.md ›「4.1 前置：Ghidra 两件事（不做就无法审）」](../../../references/native-audit.md)）
2. 导入：**只传 `file_path`**，不要传 `language`——对 ELF 传 language 会按 **Raw Binary** 导入（0 函数、1 符号）
3. 地址换算：`Ghidra 地址 = so.py 地址 + image_base`（默认 `0x100000`，用 `ghidra_get_current_program_info` 确认）
4. 伪代码：`ghidra_decompile_function`
5. 间接引用：`so.py callers` 为 0 时用 `ghidra_get_function_xrefs`（含 DATA/虚表引用）
6. 改名：`ghidra_rename_function_by_address` → 重反编译调用方，确认新名已传播

> 字符串 xref 用 `so.py strref` 更快；Ghidra 对未定义数据的 xref 可能查不到。
>
> Ghidra 工作流（导入/连接/工具组）见 [native-analysis.md ›「四、SO 静态分析（Ghidra MCP）」](../../../references/native-analysis.md)。

### 5. 特征比对

| 看到 | 结论 |
|---|---|
| `0x67452301` `0xEFCDAB89` `0x98BADCFE` `0x10325476` | MD5 |
| `0xEDB88320` | CRC32 |
| `0x63 0x7C 0x77 0x7B` | AES S-Box |
| Base64 字符表 | Base64 |
| `0x78` / `0x9C` 开头 | zlib |
| `p = A(size)` … `B(p)` | malloc/free |
| `A(lock)` … `B(lock)` | lock/unlock |
| `fd = A(path, flags)` … `B(fd)` | open/close |
| `sub_XXX(2, 1, 0)` | socket(AF_INET, SOCK_STREAM, 0) |
| 错误返回 `-1` / 失败返回 `NULL` / 成功返回 `0` | 文件·分配·状态函数 |

完整表（魔数、成对调用、参数/返回值模式、caller 递归）见手册。

**识别出来之后去哪**（避免在大方向上原地打转）：

| 结论 | 下一步 |
|---|---|
| 加解密 / 哈希 / 编码 | [crypto-hook.md ›「一、加密算法分析决策树」](../../../references/crypto-hook.md)（hook 明文/密钥） |
| 参数是对象/结构体 | skill `rev-struct`（恢复布局） |
| 能被外部输入走到 | [native-audit.md ›「SO 漏洞审计（可达面优先）」](../../../references/native-audit.md)（可达性/漏洞） |
| 静态看不清、需要真实参数 | [api-reference.md ›「Frida API 参考手册」](../../../references/api-reference.md) + [native-analysis.md ›「三、SO 动态分析」](../../../references/native-analysis.md) |
| 需要离线复算 | [native-analysis.md ›「3.6 复杂函数离线仿真（emu_run 广度 + setup 助手）」](../../../references/native-analysis.md) 或 skill `rev-unicorn-debug` |

### 6. 命名 + 回填 + 验证

- 写进 `REPORT.md`：地址 / 建议名 / 置信度 / 依据
- Ghidra 里 `ghidra_rename_function`（可选）
- 重新反编译调用点，看新名字是否自洽；不自洽就降置信度并记录反例

## 卡壳出口

| 症状 | 处理 |
|---|---|
| `strref` 无命中 | 可能经表/重定位引用：Ghidra xrefs 或 `disasm --grep "adrp\|adr"` |
| xref 落在 `assert` 尾段 | 回找 prologue，从函数起点重来 |
| `callers` 返回 0 | 先用 `ghidra_get_function_xrefs`（含 DATA/虚表）；再在 `.data`/`.rela.dyn` 搜 8 字节小端地址 |
| 混淆 / 静态链接库 / JNI 动态注册 | 见手册卡壳树 |

详细处理与实例：[references/so-func-naming.md ›「5. 卡壳树（真实场景）」](../../../references/so-func-naming.md#5-卡壳树真实场景)。

## 产出

- `REPORT.md` 命名表（地址 / 名称 / 置信度 / 依据）
- 必要时 Ghidra 重命名
