# 无符号函数命名（SO Function Naming）

> 何时读：已知一个地址，要判断"这个函数是干什么的"；`func-naming` 流程卡走不通时来这里查卡壳树。

## 1. 数据源：离线 vs Ghidra

| 需要的数据 | 离线（无 Ghidra，确定性） | Ghidra MCP |
|---|---|---|
| 导入 / 导出 / 依赖 / 重定位 / 段 / vaddr↔offset | `so.py info <so> --json` | `ghidra_list_imports` / `ghidra_list_exports` / `ghidra_list_external_locations` |
| 字符串 | `so.py strings <so> --grep PAT` | `ghidra_list_strings` / `ghidra_search_strings` |
| 字符串 → 代码引用 | `so.py strref <so> <str_vaddr>` | `ghidra_get_xrefs_to` |
| 函数调用者 | `so.py callers <so> <func_vaddr>` | `ghidra_get_function_callers` |
| 被调用者 | 从反汇编/伪代码读 | `ghidra_get_function_callees` |
| 伪代码 | — | `ghidra_decompile_function` |
| 整库导出 | — | `ghidra_batch_decompile` + `ghidra_get_bulk_xrefs` |

离线工具不需要 Ghidra 实例：**`so.py` 负责快速侦察（字符串、xref、反汇编、调用者），`Ghidra` 负责语义（伪代码、类型、数据/虚表 xref、改名）**。两者互补，不是替代。只恢复单个函数时按需查，不要整库导出。

**Ghidra 导入的两个坑（实测）**：

- 导入 ELF 时**不要传 `language`**：传了会按 **Raw Binary** 导入（0 函数、1 符号）；不传才会自动识别 ELF（本次得到 6784 个函数 / 7208 个符号）。
- Ghidra 会把 ELF 重定位到 `image_base`（默认 `0x100000`）：**`Ghidra 地址 = ELF vaddr + image_base`**。用 `ghidra_get_current_program_info` 确认。

`so.py` 的完整命令/参数见 [native-analysis.md ›「3.5 SO 分析顺序（`tools/so.py` 离线工具）」](native-analysis.md)；Ghidra 的导入/连接/工具组见 [「四、SO 静态分析（Ghidra MCP）」](native-analysis.md)。

## 2. 第 0 步：先查符号表（最容易漏）

很多"无符号"库其实在 `.dynsym` 里保留了导出符号（C++ mangled 也能读）：

```bash
llvm-nm -D --defined-only <so> | findstr /i <addr>        # Windows
llvm-nm -D --defined-only <so> | grep -i <addr>           # Linux/macOS
python3 tools/so.py info <so> --json                       # 导出/导入表
```

实例（`libtztZFProtocol.so`）：

```
0x1c2448 -> dtls1_write_bytes
0x1c2484 -> do_dtls1_write
```

`_Z...` 形式的 mangled 名可以直接反推 C++ 签名（`c++filt` 或 `llvm-cxxfilt`）。**命中即结束，不要继续推断。**

## 3. 内部特征

在函数里找：

- **字符串常量**：最直接，日志/协议名/错误串常直接说明用途
- **魔数**：
  - MD5：`0x67452301` `0xEFCDAB89` `0x98BADCFE` `0x10325476`
  - CRC32：`0xEDB88320`
  - Base64 字符表：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
  - AES S-Box：`0x63 0x7C 0x77 0x7B ...`
  - zlib 头：`0x78` / `0x9C`
- **代码结构**：循环形态、位运算、常量轮转（rotate）、查表方式

命中已知算法就直接给结论，不必继续。

## 4. 交叉引用

### 4.1 成对调用（符号缺失时的强信号）

> callee 显示为 `func_0x…` 时，先跑 `tools/ghidra/so_audit_prep.java` 做 PLT 命名（见 [native-audit.md ›「4.1 前置：Ghidra 两件事（不做就无法审）」](native-audit.md)）；否则成对调用/返回值模式都无从判断。

```c
// alloc / free
p = sub_A(0x100);      // 参数是 size，返回指针
...
sub_B(p);              // 参数是同一个指针

// lock / unlock
sub_A(lock);           // 临界区前
...
sub_B(lock);           // 临界区后，同一个锁对象

// open / close
fd = sub_A("/path", 0); // 路径 + flags，返回句柄
...
sub_B(fd);

// pthread_create / join
sub_A(&tid, 0, fn, arg);
...
sub_B(tid, &ret);
```

### 4.2 参数模式

```c
sub_XXX(2, 1, 0);      // socket(AF_INET, SOCK_STREAM, 0)
sub_XXX(fd, &var, 16); // connect/bind：地址结构 + IPv4 长度 16
sub_XXX(dst, src, n);  // memcpy/memmove
sub_XXX(ptr, 0, 0x100);// memset
ret = sub_XXX(fd, buf, n); // read/write
if (sub_XXX(s1, s2) == 0)  // strcmp
```

### 4.3 返回值模式

```c
if ((fd = sub_XXX(...)) == -1) goto err;   // 文件/socket 错误返回 -1
if (!(p = sub_XXX(size))) goto err;        // 分配失败返回 NULL
if (sub_XXX(...) != 0) goto err;           // 成功返回 0
len = sub_XXX(str);                        // strlen 类
```

### 4.4 调用者（有界递归）

- 只有非自动生成的符号才算"已命名"（排除 `FUN_` / `sub_` / `thunk_` / `LAB_` / `j_`）
- 直接调用者无名 → 继续向上，**最多 3 层**，遇到第一个命名符号即停
- 仍然无名 → 回到内部特征 + 网络检索
- 同时看调用者如何使用返回值（判断语义）

## 5. 卡壳树（真实场景）

| 症状 | 处理 |
|---|---|
| `strref` 无命中 | 字符串可能经表/重定位引用：Ghidra `ghidra_get_xrefs_to`；或 `so.py disasm --grep "adrp|adr"` 人工复核 |
| `strref` 命中点在内联 `assert` 尾段 | 该点不是函数起点：向上找 prologue（`stp x29, x30` / `sub sp, sp`），从起点重新 `disasm` |
| `callers` 返回 0 处 | 很可能是**虚表/函数指针**调用：先用 `ghidra_get_function_xrefs`（含 DATA 引用），再在 `.data` / `.data.rel.ro` / `.rela.dyn` 搜 8 字节小端地址 |
| Ghidra 导入后 0 函数 / 1 符号 | 导入时传了 `language` → 按 Raw Binary；删掉该参数重新导入 |
| Ghidra 里地址对不上 | `image_base` 偏移（默认 `0x100000`）：加基址，或 `ghidra_set_image_base 0x0` 对齐 |
| 导出表很大但地址对不上 | `.dynsym` 的 `st_value` 与实际不一致（重定位/加密壳）→ 先修 ELF 或动态取模块基址 |
| 混淆（OLLVM 等） | 常量/结构失效：改用动态 hook 取参数与返回值（`scripts/monitors/native_hooker.js`，见 [native-analysis.md ›「三、SO 动态分析」](native-analysis.md)），或 `emu_run` 复算（[「3.6 复杂函数离线仿真」](native-analysis.md)） |
| JNI 动态注册 | `scripts/utils/scan_register_natives.js` 拿到 `fnPtr` → 直接对应 Java 方法名（见 [native-analysis.md ›「五、JNI 层分析」](native-analysis.md)） |
| 需要离线复算但依赖运行时 | `tools/emu_run.py`（[native-analysis.md ›「3.6 复杂函数离线仿真（emu_run 广度 + setup 助手）」](native-analysis.md)）或 skill `rev-unicorn-debug` |
| 静态链接库（OpenSSL/BoringSSL 等） | 用特征字符串 + 版本串定位（如 `SSL3_RT_MAX_PLAIN_LENGTH`、`dtls1_read_failed`），再对照上游源码命名 |
| 函数被内联/拆分 | 以调用点的行为为准，不要强求函数边界 |
| 反编译里 callee 全是 `func_0x…` | 先跑 `tools/ghidra/so_audit_prep.java` 做 PLT 命名；否则成对调用/返回值模式都判不了 |

### 5.1 实例：`libtztZFProtocol.so`（so.py → Ghidra）

1. `so.py strings --grep "SSL3_RT_MAX_PLAIN_LENGTH"` → 字符串 `0x35c94c`
2. `so.py strref <so> 0x35c94c` → 引用点 `0x1c246c`（落在内联 assert 尾段）
3. 回找 prologue → 函数起点 `0x1c2448`
4. `so.py callers <so> 0x1c2448` → **0**（间接调用）
5. Ghidra 导入（不传 `language`）→ 地址 `0x1c2448 + 0x100000 = 0x2c2448` → 符号 **`dtls1_write_bytes`**
6. `ghidra_get_function_xrefs 0x2c2448` → `00551830 [DATA]`（虚表/函数指针）
7. `ghidra_rename_function_by_address` 改名 → 重反编译调用方，新名已传播

## 6. 检索

本地推不出来时按特征搜：

- 魔数：`0x67452301 0xEFCDAB89 algorithm`
- 代码形态：`rotate left xor constant algorithm`
- 函数内唯一字符串
- 参数模式：`function(int, int, 0) socket`

## 7. 输出模板

```
## Symbol Recovery Analysis: <address>

### Function Characteristics
- Strings: <...>
- Constants: <...>
- Called imports: <...>

### Cross-Reference Analysis
- Callers: <...>
- Callees: <...>

### Inference
- Suggested name: <...>
- Confidence: High / Medium / Low
- Reasoning: <...>

### Similar Open Source
- <link>
```

## 8. 交接（命名之后）

| 命名结论 | 去处 |
|---|---|
| 加解密 / 哈希 / 编码 | [crypto-hook.md ›「一、加密算法分析决策树」](crypto-hook.md)：hook 明文、密钥、SSL |
| 参数是对象/结构体 | skill `rev-struct`：偏移聚合恢复布局 |
| 能被外部输入走到 | [native-audit.md ›「SO 漏洞审计（可达面优先）」](native-audit.md)：可达性 → 分诊 → 深审 |
| 需要真实参数/运行时 | [native-analysis.md ›「三、SO 动态分析」](native-analysis.md)：`native_hooker` |
| 需要离线复算 | [native-analysis.md ›「3.6 复杂函数离线仿真（emu_run 广度 + setup 助手）」](native-analysis.md)：`emu_run` / skill `rev-unicorn-debug` |

## 9. 只能靠模型判断的部分（链接解决不了）

- 魔数/结构命中后的**误报排除**（同一常数可能来自别的算法）
- 多个候选命名之间的**取舍**与置信度标注
- 混淆或新算法没有已知特征时，**是否继续深挖**
- 函数在业务上的**语义**（"这是签名"还是"这是校验"）
- **何时停止**：证据是否足够、要不要转动态/仿真
