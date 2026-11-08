---
name: vmp-analysis
description: 字节码 VM / VMP 壳逆向的执行流水线：从"确认是 VM"到"反汇编出可读指令"的 8 步固定流程。用 profile 描述编码模型（换壳只换 JSON），用动态 trace 反推 opcode 编码，用命中率 > 95% 验收。当目标是"业务方法在 .text 里找不到、JNI_OnLoad 只启动解释器"、或已有 opcode 表但不知道指令怎么解时使用。SO 层深挖的单步能力，入口仍在 frida-mobile-security。
---

# vmp-analysis — 字节码 VM / VMP 壳逆向

**目标**：把一段自定义字节码变成可读指令清单，并说清编码模型。

**核心约束**：每条 handler 自定义 pc 推进与操作数布局，**静态猜格式命中率接近 0**。
必须先拿到动态 trace，再用它反推编码。

路径基准：项目根。工具在 `tools/`。

## 何时用 / 何时不用

| 用 | 不用 |
|---|---|
| `JNI_OnLoad` 只做「初始化运行时 + 启动解释器」 | 普通 native 函数 → `references/native-analysis.md` |
| `.text` 里找不到业务方法，但有跳转表 + 软件栈 | 只是算法加密（AES/国密）→ `references/crypto-hook.md` |
| 已有 opcode 表，但指令流解不出 | 要审漏洞 → `references/native-audit.md` |
| 想复用已有壳的编码模型 | 要还原 2000+ 函数 → skill `so-function-recovery` |

## 前置

```bash
# 1) 确认工具可用
python3 tools/vmp.py --help
python3 tools/vmp.py profile list          # 看有没有现成模型可复用

# 2) SO 已脱壳且能反汇编
python3 tools/so.py info <so>              # 看 broken_sections / dynsym_defined
```

**先查 `profile list`**：已解出的壳有现成模型，命中就不用从零建模。

## 步骤

### 1. 确认是 VM，不是普通代码

三个可观测特征（`references/native-analysis.md` ›「3.5.2」第一步）：

| 特征 | 怎么看 |
|---|---|
| 跳转表分派 | 从参数取 `u8` → `lsl #3`/`lsl #2` → `ldr` 表项 → `br` |
| 有软件栈 | `sp` 上一块固定区域，栈顶指针存在栈槽里 |
| handler 按偏移读写那块区域 | 大量 `ldrb`/`strb` + 固定偏移 |

`JNI_OnLoad` 的典型形态：

```c
rt = FUN_xxx();                                        // 分配运行时
FUN_yyy(rt, vm);                                       // 存 JavaVM
FUN_zzz(rt, &tbl1, &tbl2, bytecode, &selector, 0);     // 启动解释器
return FUN_vvv(rt);
```

### 2. 找 opcode 表

```bash
python3 tools/ptr_table.py <so> --scan --only-code --classify vm
```

输出里标 `handler 表候选（项数非 2^n）` 的那张。**不要假设 256 项** ——
壳普遍只放实际用到的项数，其后紧跟 continuation 表。

交叉验证项数：
- 表后紧邻的下一张表起点 − 本表起点
- 解释器入口 `memcpy(dst, table, N)` 的 N

### 3. 反编译 dispatch，取 6 个字段

打开解释器主循环，对着反汇编填下表（这是 `vmp.py trace` 需要的）：

| 字段 | 从哪读 |
|---|---|
| `entry_va` | **解释器入口，不是 JNI_OnLoad**。反编译 JNI_OnLoad，找它内部调用的 `FUN_zzz(rt,&tbl1,&tbl2,bytecode,&selector,0)`，`FUN_zzz` 就是入口 |
| `dispatch_hook_pc` | 找 `ldr xN,[tbl, xIdx, lsl#3]`，取它的**前一条**指令地址 |
| `frame_pc_off` | dispatch 把「当前 pc」存到 `[sp+0xNN]` 的那个偏移 |
| `frame_idx_off` | 同上，存 opcode 索引的偏移（1 字节） |
| `frame_key_off` | 同上，存 key 的偏移（1 字节） |
| `selector_arg_reg` | selector 由哪个寄存器传入（多数 x5） |

### 4. 写 profile

```bash
python3 tools/vmp.py profile new <壳名>
```

生成骨架后按每个字段的 `_comment` 填。**先填 `[engine]` 组**：

| 字段 | 取法 |
|---|---|
| `key_xor` | handler 取指代码里的 xor 立即数（多 handler 交叉验证） |
| `decode{sub_hi,mask_hi,sub_lo,mask_lo}` | 字节→opcode 的那几条指令：`sub + and + or`（或 `bfm/bfi`）的立即数 |
| `handler_table_file_va` | 步骤 2 找到的表地址 |
| `handler_count` | 步骤 2 的项数 |
| `bytecode_file_va` | 调用解释器时第 3 参数指向的地址（`adrp+add` 算） |

`opcodes` 先全填 `op_<hex>` 占位，**条目数 = `handler_count`**（多填会把 continuation 表误当 opcode）。

再填 `[engine]` 的 `operand_layout`（opcode → 操作数宽度）：

| kind | 含义 |
|---|---|
| `none` | 无操作数 |
| `u8` / `u16` / `u32` / `u64` | 立即数，按宽度读 |
| `u16x4` | 16 位值 ×4 当帧偏移（`lea`/`st64` 这类） |
| `idx8` | 8 位索引（辅助分派 / 表索引） |

**不填会用内置默认值（只对某个已解出的壳成立）** → `disasm` 的 operand 列会系统性错，
而 `verify` 仍然通过（它只校验 opcode 链），表现为"长度对、语义错"。
取法：逐 handler 反编译，看它从 body 里读几个字节、按什么宽度。

### 5. 跑 trace 拿真实序列

```bash
# 简单壳：不需要 setup
python3 tools/vmp.py trace <so> -p <profile> --sel 0 --out trace.json

# 脱壳镜像 / 复杂壳：用 setup 脚本挂环境
cp tools/emu_setup_template.py <包名>/tools/setup_<name>.py
python3 tools/vmp.py trace <so> -p <profile> --setup <包名>/tools/setup_<name>.py --out trace.json
```

**setup 脚本先不加第 5 步**，跑一遍看 `[!] unstubbed` 日志再逐个补桩 —— 不要预猜。

常见报错：

| 现象 | 处理 |
|---|---|
| `WRITE_UNMAPPED` 在 `[sp+...]` | 栈太小 → profile `stack_size` 加倍（VM 栈帧可达数百 KB） |
| `WRITE_UNMAPPED` 在堆地址 | arena 不够 → profile `arena_presize` |
| `unstubbed: pthread_getspecific` 等 | 按日志在 setup 第 5 步补桩 |
| 跑不返回 | `DT_INIT` 指向 CFF 内部块 → `--no-init` 跳过 |

### 6. 校验编码模型（硬判据）

```bash
python3 tools/vmp.py verify <so> -p <profile> --trace trace.json
```

**命中率必须 > 95%**。低于此值按未命中样例定位：

| 未命中特征 | 说明 |
|---|---|
| 全部不命中 | `decode` 常量错，或 `key_xor` 错 |
| 集中在某个 opcode 范围 | 有「强制 key」分支 → profile 填 `forced_key` |
| 只在跳转后不命中 | 跨函数跳转被当成顺序转移（正常，`L > 4096` 已被跳过） |

### 7. 反汇编

```bash
python3 tools/vmp.py disasm <so> -p <profile> --trace trace.json --vm <key>
python3 tools/vmp.py disasm <so> -p <profile> --trace trace.json --list-vms   # 先看有哪些 VM
```

输出五列：`pc / op / name / operand / raw`。有 trace 时长度准确；无 trace 退化按
`static_insn_len` 推测，输出会标注。

### 8. handler 语义命名（迭代）

`opcodes` 里的 `op_<hex>` 占位要逐个换成真名：

```bash
# 看某个 handler 的指令模型（需先跑 Ghidra 脚本 so_vm_model_handlers.java）
python3 tools/vmp.py model --op 0x39
python3 tools/vmp.py model --stats
```

对着 handler 的反编译结果判断语义，改 profile 的 `opcodes`，再跑 `disasm` 确认可读性提升。

**这一步是增量的**：先命名高频 opcode（`disasm` 末尾的频次表按降序），低频的留着占位。

## 卡壳出口

| 症状 | 先查 |
|---|---|
| 找不到 opcode 表 | `ptr_table --scan`（不加 `--only-code`，表可能混有数据项） |
| 表项数是 2 的幂但解不出 | 可能真是 256 项全展开；也可能是 continuation 表 → 用 `memcpy` 长度验证 |
| `verify` 命中率 0% | `decode` 四常量顺序搞反（`sub_hi`/`sub_lo` 互换） |
| `trace` 一次 dispatch 都没有 | `dispatch_hook_pc` 错，或 hook 在 dispatch 之后 |
| `trace` 次数远多于预期 | `selector_hook_pc` 反复改写寄存器 → 只在 `--sel` 非 0 时才 hook |
| 栈写穿 | `stack_size` 加倍 |
| handler 反编译全是 `unaff_` | 命中 CFF 内部块 → `ghidra_get_function_by_address` 找真身 |
| `verify` 过 95% 但 operand 列明显不对 | `operand_layout` 没填或填错（用的是内置默认值） |

## 产出

- `<包名>/tools/vm_profiles/<name>.json`（编码模型，样本事实；`vmp.py` 自动发现）
- `trace.json`（动态执行路径）
- 反汇编清单（`disasm --json` 可落盘）
- 关键结论写 `REPORT.md`：VM 数量、各 VM 业务、编码公式、opcode 语义表

## 工具清单

**通用工具**（`tools/`，任何壳可用）

| 工具 | 作用 |
|---|---|
| `tools/vmp.py` | 主入口：`profile list/new/show` / `trace` / `verify` / `disasm` / `model` |
| `tools/vmp_profiles/_template.json` | profile 骨架（每字段带"怎么取这个值"的注释） |
| `<包名>/tools/vm_profiles/<壳>.json` | 已解出的编码模型；`vmp.py profile list` 自动汇总所有样本目录 |
| `tools/ptr_table.py` | `--scan --only-code --classify vm` 找 handler 表候选 |
| `tools/emu_setup_template.py` | `--setup` 脚本骨架（4 步通用 + 按日志补桩） |
| `tools/so.py` | `info` 看段/符号，`disasm` 单函数反汇编 |
| `tools/emu_run.py` | 单函数仿真（VM 入口也可直接跑） |

**Ghidra 脚本**（`tools/ghidra/`，索引见 `tools/ghidra/README.md`）

| 脚本 | 作用 |
|---|---|
| `so_vm_split_handlers.java` | 把被并成大函数的 handler 区按跳转表拆开 |
| `so_vm_name_handlers.java` | 按 opcode 表给 handler 命名 |
| `so_vm_model_handlers.java` | 提取 handler 指令模型（`vmp.py model` 的数据源） |
| `so_vm_frame_vars.java` | 给共享栈帧建具名变量 |
| `so_vm_cont_table.java` | 命名 handler 表与 continuation 表 |

**样本专用工具**（`<包名>/tools/`，换壳需重写或改 profile）

| 工具 | 作用 |
|---|---|
| `vm_disasm.py` | 链式 opcode 变长反汇编 + trace 自验证（通用版：`tools/vmp.py disasm`） |
| `vm_trace.py` | 动态 trace（通用版：`tools/vmp.py trace`） |
| `vm_emulate.py` | VM 离线仿真（内置样本入口别名 `--entry jni_onload/vm_interp/vm_main`） |
| `vm_tables.py` | VM 表语义判定（tbl1 加密串区间 / tbl2 FFI 语义，属样本事实） |
| `setup_*.py` | 样本运行环境（三工具通用契约 `prepare(h, so_path, data)`） |

**分界线**：能按 ELF 结构 / 通用算法判定的 → `tools/`；
需要样本的入口地址、加密区间、VM 编码常量的 → `<包名>/tools/`。

## 与 skill `so-function-recovery` 的分工

| | `so-function-recovery` | `vmp-analysis`（本 skill） |
|---|---|---|
| 解决什么 | 2000+ 函数**不知道从哪读起** | 字节码**解不出来** |
| 输入 | 脱壳 SO + Ghidra 库 | 已确认的 VM 壳 |
| 输出 | 函数台账 + 语义命名 + 逻辑闭环 | profile + trace + 反汇编清单 |
| 核心矛盾 | 工作量 vs 阅读量（**广度**） | 编码未知 vs 静态无解（**深度**） |

**是上下游，不是替代**：那边步骤 5.7 判定为 VM 壳后转到这里；这里解完字节码，
回到那边继续按台账读函数。**两边共用的只有 `ptr_table.py` / `probe_layout.py` / `setup_*.py`。**

## 参考

- 识别特征与编码推导方法论：`references/native-analysis.md` ›「3.5.2 字节码 VM 逆向（VMP 型壳）」
- 换壳工作流全量步骤：`references/so-function-recovery.md` ›「换壳工作流（0 → 1）」
- 单函数仿真（非 VM）：skill `so-emulate`
- 函数级还原（VM 之外的 2000+ 函数）：skill `so-function-recovery`
