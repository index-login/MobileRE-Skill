# SO 静态还原：非流水线的坑与约束

> **常规流水线见 skill `so-function-recovery`**（`.kilo/skill/so-function-recovery/SKILL.md`）。
> 本文件只留「不跑一遍不会知道」的事实：工具 API 差异、边界条件、失败方案。
> 路径基准：项目根。

## Ghidra 12.1.2 API 差异（写脚本必查）

写 `tools/ghidra/*.java` 前对照这张表，否则编译失败会永久阻塞整批构建。

| 想用 | 实际 |
|---|---|
| `Variable.isPhantom()` | 不存在 |
| `HighVariable.setName()` | 不存在 |
| `HighFunctionDBUtil` | 不在 `ghidra.app.decompiler` 下 |
| `VariableImpl` | 非 public，不能 new |
| `AddressSpace.STACK_SPACE` | 不存在，从 `program.getAddressFactory()` 取 |
| `new VariableStorage(Language, Address[], int[])` | 需 `ProgramArchitecture`，不是 `Language` |
| `CodeUnit.setComment(String)` | 需 `(int,String)` 或 `(CommentType,String)` |
| `Listing.getInstructionBefore/At` | 返回 `Instruction`，不是 `Address` |
| `StructureDataType.clear()` | 不存在 |
| `replaceAtOffset(off, dt, name, cmt)` | 需 5 参数，含 `length` |
| `StringDataType(len)` | 无此构造器；定长用 `ArrayDataType(CharDataType, len, 1)` |
| `Memory` 类型 | 要 `import ghidra.program.model.mem.Memory` |
| `getAddressSet(a,b)` | `Listing` 上不存在 |
| `DataTypeManager.getAllDataTypes()` | 返回 `Iterator`，不能 for-each |

### 失败脚本会永久阻塞

`C:\Users\Administrator\ghidra_scripts` 里有编译失败的 `.java` 后，
**所有后续脚本构建都会失败**，报 "N files failing in previous build(s)"。

清理两步都要做：

```powershell
# 1) 删失败源文件
Remove-Item C:\Users\Administrator\ghidra_scripts\*.java_failed
# 2) 删编译缓存（否则残留 class 仍阻塞）
Remove-Item "$env:APPDATA\ghidra\ghidra_12.1.2_PUBLIC\osgi\compiled-bundles\*" -Recurse
```

### public 类名必须等于文件名

`so_xxx.java` 里必须是 `public class so_xxx extends GhidraScript`。
MCP 的 `run_script_inline` 会生成 `McpInline_<hash>.java`，类名不匹配就报
"class could not be found"。

## 字符串符号化：Ghidra 的渲染规则

Ghidra 对字符串数据**必定创建符号**，无法通过"只建数据类型"让它显示成字符串。

| 做法 | 结果 |
|---|---|
| 只建 `TerminatedCStringDataType`，不建符号 | 自动生成 `s_<text>_<addr>` |
| 删掉自动符号 | Ghidra 重建 `DAT_xxx` |
| 符号名改成 `"/dev/qemu_pipe"` | 被净化成 `__dev_qemu_pipe_`（非法字符替换） |
| 建 `char[N]` 数组 | 仍自动建 `s_*` |
| **`char[N]` + 把自动符号改名成 `g_str_<slug>`** | **生效**，伪代码显示 `g_str_dev_qemu_pipe` |

规则：`s_` 前缀被 Ghidra 视为自动名；非 `s_` 前缀按原样显示。

## `DAT_*` 要先分类再处理

1724 个 `DAT_` 分三类，性质完全不同：

| 类 | 判据 | 处理 |
|---|---|---|
| key 表 | 内容是短字节序列，被 `str[i] ^= tbl[i & 0xF]` 引用 | 命名 `g_keytab_*` |
| `.rodata` 函数指针数组 | 值落在 `.text` 区间 | 命名 `g_vtbl_*` / `g_pfn_*` |
| 真·未知 | 其余 | 保持 `DAT_`，别乱猜 |

只处理前两类（占 22%），引用立刻可读。

## 栈变量不能事后合并

Hex-Rays/Ghidra 把 `char buf[500]` 拆成 60 个 `undefined8` 后，
改其中一个是 `Variable storage conflict`。

只能二选一：
- 反编译前用结构体声明（`so_vm_frame_struct.java` 那类）
- 接受现状，加注释

## 失败方案（不要重走）

| 方案 | 结果 | 原因 |
|---|---|---|
| 删除全部无 `bl` 引用的函数 | 覆盖 84.5% 降到 65% | `removeFunction` 连带清掉函数体内代码归属 |
| 删除无强证据碎片（1996 个） | 覆盖 73.4% 降到 57.8% | 碎片本身覆盖代码，删掉变新缺口 |
| 给 `g_shell_ctx` 建结构体（静态推断） | 伪代码更差 | 实际是 `void**` 二级指针，静态内容全零 |
| 按 5 字节切分字节码 | opcode 随机分布 | 实际变长 |
| 按 3 字节定长切分 | 只 0.2% 命中 | 实际变长 + 链式差分 |
| 假设 opcode 表 256 项 | 25 个 opcode 被误判共用 handler | 实际 138 项，其后是 continuation 表 |
| `apply_relocations` 走 section API | GOT 未填 | section header 被壳伪造 |
| 按 live-in 寄存器推断函数原型 | 大量错位 | 寄存器在 CFF 块间传递，不是参数 |
| 只按序言建函数边界 | 漏掉同族合并的第二入口 | 用指针表交叉检查 |

## PLT/GOT 恢复（脱壳产物常见缺失）

壳会伪造 section header，但 `PT_DYNAMIC` 里的 `DT_RELA` / `DT_JMPREL` 是真的。

```
每条 r_info 高 32 位 = dynsym 索引
GOT 槽 = r_offset，建标签 GOT_<sym>
遍历 .text 找 adrp x16 / ldr x17,[x16,#off] / add x16 / br x17
该模式起点的函数名 = 符号名
```

## 反编译选项：Parameter ID 的边界

Decompiler Parameter ID 分析器能补参数，但：

| 事实 | 含义 |
|---|---|
| 对 VM handler 跑会破坏已建栈槽 | 必须先排除 handler |
| 对 CFF 块跑会推出一堆假参数 | 必须排除 `switchD_*` 命名空间 |
| `getParameters()` 与反编译视图不一致 | 以反编译视图为准 |
| 跑完 `unaff_` 不降 | CFF 固有难度，与参数无关 |

## 分析器选项开关无效项

实测以下开关对 `unaff_` 无影响，不要浪费重跑时间：

- `Aggressive Instruction Finder`
- `Decompiler Parameter ID` 的 `Recovery Mode = aggressive`
- `Simplify predication`

真正有效的只有：给对参数类型、建对结构体、命名对全局。
