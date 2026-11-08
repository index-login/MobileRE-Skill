# Ghidra / IDA 批量脚本索引

> 这里只做"批量机械活"。**单函数分析走 MCP**（`ghidra_decompile_function` /
> `ghidra_get_function_xrefs` 等），不要为一次反编译写脚本。
>
> 路径基准：项目根。脚本源码在 `tools/ghidra/`、`tools/ida/`。

## 怎么调用

| 类型 | 判据 | 调用方式 |
|---|---|---|
| **class 脚本** | 文件里有 `public class <文件名> extends GhidraScript` | 先复制到 `C:\Users\Administrator\ghidra_scripts`，再 `ghidra_run_ghidra_script script_name=<文件名>` |
| **inline body** | 文件里没有 `public class` | `ghidra_run_script_inline`，把文件内容作为 `code`，参数走 `args` |
| **IDA 脚本** | `tools/ida/*.py` | IDA 内 `py_exec_file` 或 IDAPython 控制台 |

**部署差异**：class 脚本必须落在 `ghidra_scripts` 目录；inline body 不需要（MCP 生成临时文件）。
当前 `ghidra_scripts` 已部署 25 个 class 脚本，5 个 inline body 未部署（正常）。

**编译失败会永久阻塞**：`ghidra_scripts` 里残留一个编译失败的 `.java`，之后所有脚本构建都会失败。
清理两步见 [references/so-analysis-pipeline.md ›「失败脚本会永久阻塞」](../../references/so-analysis-pipeline.md)。

**public 类名必须等于文件名**：`so_xxx.java` 里必须是 `public class so_xxx`。

## 配置

class 脚本从 `$TMP/<name>.cfg`（Windows 为 `%TEMP%`）读 `key=value`；inline body 从 `args` 读。
**配置键的默认值多为某个样本的实测地址** —— 换样本必须显式覆盖，见「默认值来源」列。

## 脚本清单

### 1. 边界与结构（先做，其它步骤都依赖）

| 脚本 | 类型 | cfg / args | 作用 |
|---|---|---|---|
| `so_unpack_prep.java` | inline | `--start 0x… --end 0x… --step all\|exec\|disasm\|funcs` | 脱壳镜像三步修复：给代码段加 X 权限 → 按 4 字节反汇编 → 三策略建函数 |
| `so_boundary_rebuild.java` | inline | `start= end= step=create\|merge\|report\|all apply=1` | 函数边界重建（无 `.eh_frame` 时）。覆盖 67.5%→99.8% 的同一套流程 |
| `so_split_pointer_targets.java` | class | `in= apply= min_gap=` | 按指针表补建"第二入口"（编译器合并同族函数时漏掉的起点） |
| `so_enable_analyzers.java` | class | — | 打开 Decompiler Parameter ID / Stack.Create Param Variables（只改选项，需重跑分析器） |

### 2. 符号与类型

| 脚本 | 类型 | cfg | 作用 |
|---|---|---|---|
| `so_audit_prep.java` | inline | `--no-plt --proto <file>` | PLT 导入桩命名 + 原型批量回填（**审计前置**，不做则 `func_0x…` 无法判语义） |
| `so_make_jni_structs.java` | class | `so_make_jni.cfg` | 建 JNI 三结构体（`JNINativeInterface` / `JNIInvokeInterface` / `JNIEnv_`） |
| `so_apply_jni_types.java` | class | `so_apply_jni.cfg` | 把 `JNIEnv*` 参数标注成 `JNIEnv_ **` |
| `art_make_structs.java` | class | — | 建 7 个 ART 结构体（`art_ArtMethod` 等），来源 `references/android-headers/` |
| `so_make_structs.java` | class | — | 建 `shell_ctx_t` |
| `shell_ctx_from_dyn.java` | class | — | 用动态实测值建 `shell_ctx_t`（字段注释里写实测值） |
| `vm_runtime_from_dyn.java` | class | — | 用动态实测值建 `vm_runtime`（48 B，5 个字段） |
| `so_vm_frame_struct.java` | class | `so_vm_frame_struct.cfg`（`size`） | 建 `vm_frame` 结构体（VM 解释器共享栈帧） |

### 3. 字符串

| 脚本 | 类型 | cfg | 作用 |
|---|---|---|---|
| `so_apply_strings.java` | class | `so_apply_strings.cfg`（`lo` `hi` `min_len`） | 批量明文串 → `g_str_*` 符号（Ghidra 会强制建 `s_*`，改名才生效） |
| `so_fix_string_refs.java` | class | `so_fix_strings.cfg`（`region_lo` `region_hi`） | 串内 `DAT_` 引用还原成字符串标签 |
| `so_name_from_strings.java` | class | `so_name_from_strings.cfg`（`min_score`） | 字符串锚点命名函数（`jni_*` / `load_*` / `proc_*`） |

### 4. 参数与命名

| 脚本 | 类型 | cfg | 作用 |
|---|---|---|---|
| `so_run_paramid.java` | class | `so_paramid.cfg` | 对选定函数跑 Decompiler Parameter ID（**排除 VM handler 与 `switchD_*`**） |
| `so_name_params.java` | class | `so_name_params.cfg` | 批量命名函数参数 |
| `so_name_jni_params.java` | class | `so_name_jni_params.cfg`（`range_lo` `range_hi`） | JNI 参数按契约命名（`env` / `thiz` / …） |
| `so_inventory.java` | class | `so_inventory.cfg`（`out` `shapes_out` `str_max` `callee_max`） | **导出函数台账 + 形状指纹**（`so_ledger.py` 的输入） |
| `so_apply_rename.java` | class | `so_apply_rename.cfg`（`in` `apply` `prefix`） | 批量应用重命名（**只改生成名**，已有语义名跳过） |
| `so_dump_pseudocode.java` | class | `so_dump_pseudo.cfg`（`out` `min_size` `include_vm`） | 导出语义函数伪代码全文 |
| `so_semantic_pass.java` | inline | `so_semantic_pass.cfg` | 伪代码可读性批处理（栈槽具名等） |

### 5. VM / VMP（**默认值 = 某个样本的地址，换壳必须覆盖**）

| 脚本 | 类型 | cfg | 作用 |
|---|---|---|---|
| `so_vm_split_handlers.java` | class | `so_vm_split.cfg`（`table_va` `table_n` `big_func` `range_lo` `range_hi`） | 把被并成一个大函数的 handler 区按跳转表拆成独立函数 |
| `so_vm_name_handlers.java` | class | `so_vm_name.cfg`（`table_va` `table_n`） | 按 opcode 表给 handler 命名 `vm_op_<hex>` + plate 注释 |
| `so_vm_model_handlers.java` | class | `table_va` `table_n` `range_hi` | 提取 handler 指令模型（pc_delta / 出口 / 特征）→ JSON，供 `tools/vmp.py model` 消费 |
| `so_vm_analyze_handlers.java` | class | `table_va` `table_n` `range_hi` | 批量反编译 handler 并导出语义特征 JSON |
| `so_vm_frame_vars.java` | class | `so_vm_frame_vars.cfg`（`range_lo` `range_hi`） | 给共享 VM 栈帧建具名变量（`vm_pc` / `vm_opcode` …） |
| `so_vm_cont_table.java` | class | `so_vm_cont_table.cfg`（`handler_tbl` `handler_n` `cont_tbl` `cont_n`） | 命名 handler 表与 continuation 表 |
| `so_vm_opcodes.java` | inline | `table=` `count=` `apply=` | 按跳转表给 handler 打标签 + 语义分类注释 |

### 6. 已否决（`_rejected/`）

| 脚本 | 否决原因 |
|---|---|
| `so_infer_protos.java` | 按 live-in 寄存器推断原型 → 寄存器在 CFF 块间传递，不是参数，大量错位 |
| `so_merge_orphan_frags.java` | 碎片合并会过度（26 KB 被并成一个函数），需按跳转表重新拆分 |

结论见 [references/so-analysis-pipeline.md ›「失败方案（不要重走）」](../../references/so-analysis-pipeline.md)。

## IDA 侧

| 脚本 | 作用 |
|---|---|
| `tools/ida/ida_rebuild_elf.py` | PLT 桩命名（`plt_<import>`）/ 导入原型回填 / `BR Xn` 跳转表绑定（让 Hex-Rays 出真 switch）。`plt proto switch` 可选步骤 |
| `tools/ida/ida_vm_model.py` | IDA 侧 handler 模型提取，JSON schema 与 `so_vm_model_handlers.java` 一致 |

**何时用 IDA**：Ghidra 修完段头仍缺符号时做交叉验证（IDA 更愿意猜）；
但 VM 的 switch case 在 IDA 里常是 `JUMPOUT`，读不到 handler 正文 —— 那时回 Ghidra。
