---
name: so-function-recovery
description: 大型加固 SO 函数级还原流水线（2000+ 函数、无 .eh_frame、CFF 混淆、内嵌字节码 VM）。用台账三层筛选替代逐个读函数，用指针表交叉检查函数边界，用动态 trace 反推 VM 编码，最终产出完整逻辑闭环。当任务是"把某个 .so 的主要代码逻辑搞清楚"、要判断"分析到什么程度算完成"、或不想重复读同一批函数时使用。
---

# so-function-recovery — 大型 SO 函数级还原流水线

**目标不是读完每个函数，而是用最少的阅读量拿到完整逻辑闭环。**

路径基准：项目根。工具在 `tools/`，Ghidra 脚本在 `tools/ghidra/`。
方法论正文见 `references/so-function-recovery.md`；本 skill 是可执行的流水线。

## 何时用 / 何时不用

| 用 | 不用 |
|---|---|
| .so 有 500+ 函数，要搞清主要逻辑 | 只看一两个函数 → `references/so-func-naming.md` |
| 脱壳产物无 `.eh_frame`、函数边界乱 | 要审漏洞 → `references/native-audit.md` |
| 有 CFF / 字节码 VM 混淆 | 要复算单个算法 → skill `so-emulate` |
| 要判断"分析到什么程度算完成" | 只是查字符串/导入表 → `tools/so.py` 单条命令 |

## 前置检查（缺一项都会白干）

```bash
# 1) ELF 结构是否可用（脱壳产物常见 section header 被伪造）
python3 tools/so.py info <so>
#   判据：dynsym_defined > 0、relocations > 0、PT_LOAD 的 va_eq_off=true

# 2) Ghidra 是否已建库并完成分析
ghidra_get_current_program_info            # 确认 program 名与 image_base
ghidra_get_function_count                  # 记下基线

# 3) 清理会阻塞构建的残留脚本
#    C:\Users\Administrator\ghidra_scripts 内失败脚本会永久阻塞整批编译
#    删 McpInline_*.java + %APPDATA%\ghidra\ghidra_*\osgi\compiled-bundles\*
```

## 步骤

### 0. 先分诊 SO 类型（决定哪些步骤会空转）

本流水线默认目标是**加固壳 SO**。类型判错会让 1/5.5/5.6/5.7 全部白跑。

| 类型 | 判据 | 走哪些步骤 |
|---|---|---|
| **加固壳 SO** | `DT_INIT_ARRAY` 项数多；有 `svc` 自杀路径；有 CFF/VM | 全流程 |
| **业务 native 库** | `DT_INIT_ARRAY` < 5 项；大量 `Java_*` 导出；无 CFF | **跳过 1/5.5/5.6/5.7**，走 Java→native 反向映射 |
| **静态第三方库** | `_Z*`/`__cxa*` 密集；外部进入边极少 | 直接排除 |

```bash
python3 tools/so.py info <so> --grep Java_   # 业务库会有大量 Java_* 导出
python3 tools/so.py svc <so>                 # 有 kill/exit 才像加固壳
```

**业务库的最快路径**：jadx 列 native 声明 → 对 `Java_*` 导出（静态注册）或
`scan_register_natives.js`（动态注册）→ 只读这批函数。判据详见
`references/so-function-recovery.md` ›「〇、Step 0：先分诊 SO 类型」。

### 1. 解析 .dynamic，定位真正的执行入口

```python
# PT_DYNAMIC → DT_INIT(12) / DT_INIT_ARRAY(25) / DT_INIT_ARRAYSZ(27)
#             / DT_FINI_ARRAY(26) / DT_JNI 相关
```

**关键**：`DT_INIT` 可能指向**函数内部**（CFF 分发后的分支块）。

```bash
ghidra_get_function_by_address <DT_INIT>    # 看返回的 Entry 是否等于 DT_INIT
# 若不等，真身是返回的 Entry
```

判据：反编译若满是 `unaff_x19/x20` 且控制流不通，就是命中了内部块。

`DT_INIT_ARRAY` 每一项都是一个初始化器，按四类归档：

| 类型 | 特征 | 处理 |
|---|---|---|
| 字符串解密 | 全是 `str[i] ^= const` | 可离线复算 |
| 表安装 | 单个 `str` 到固定全局偏移 | 读目标表内容 |
| 版本探测 | `dlsym` + 条件赋值 | 读赋值常量 |
| 真实逻辑 | 有分支/循环/调用 | 需完整读 |

### 2. 导出函数台账

> **时序**：边界重建必须在导台账之前。台账的 `size`/`insns`/形状哈希都基于当时的
> 函数边界；先导台账再重建边界，函数总数会变（实测 3200 → 3916），台账全部作废。
> 顺序：`so_unpack_prep` → `so_boundary_rebuild` → `so_split_pointer_targets` → `so_inventory`。


```bash
# 配置 $TMP/so_inventory.cfg:
#   out=<ledger.tsv>
#   shapes_out=<shapes.tsv>
ghidra_run_ghidra_script script_name=so_inventory.java
```

每行 15 列：地址 / 名 / 大小 / 指令数 / 参数 / 返回类型 / 调用者数 / 被调数 /
代码引用数 / 数据引用数 / 引用来源函数 / 字符串 / 被调名 / 形状哈希 / 父命名空间。

**形状哈希** = 指令归一化成 `mnemonic + 操作数形状`（立即数/地址/符号替换为 `#`）
后 MD5。同形状 = 同模板生成，读一个代表即可。

### 3. 三层筛选，生成工作队列

```bash
python3 tools/so_ledger.py <ledger.tsv> --shapes <shapes.tsv> --so <so> \
    --report LEDGER.md --queue queue.tsv --rename rename.tsv

# 只看还剩多少
python3 tools/so_ledger.py ... --stats
```

三层含义与证据等级判据见
[references/so-function-recovery.md ›「一、先建立函数台账，再动手」](../../../references/so-function-recovery.md#一先建立函数台账再动手)。

**验收**（两道闸门，缺一不可）：

| 闸门 | 判据 | 不通过说明 |
|---|---|---|
| 镜像可信 | `empty` 形状占比 **< 5%** | `--so` 不是脱壳镜像（`.text` 仍是密文）→ 函数全被判成桩 |
| 分区有效 | T4 + X1 + X2 合计 **≥ 45%** | 分区表或形状判据有问题 |

> 先看第一道。`empty` 占比高时后面所有统计都不可信 —— 这是最容易踩的坑：
> 拿未脱壳的 SO 跑，机器形状会变成 `empty 80%+`，并产出上千条错误的
> `FUN_xxx → empty_xxx` 重命名建议。

> **T1 = 0 是正常的**：字符串锚点这一轮做完后，所有有串函数都已命名，T1 队列自然空。
> 看到 T1=0 说明串锚点已完成，不是判据失效。

### 4. 用指针表交叉检查函数边界（若在步骤 2 之前做，需重导台账）

自动分析按序言识别起点，会漏掉**同族函数合并产生的第二入口**。

```bash
# 列出所有"被指针表引用但落在函数内部"的地址
# 判据：首指令是 ldr xN,[x0] / stp x30 / str x30,[sp,#-N]! / bti
#       反例 ldrb w9,[x0] 是读数据，不是入口
ghidra_run_ghidra_script script_name=so_split_pointer_targets.java
```

**不要先删原函数**。`createFunction` 会重新界定 body，原函数自动截断。

验收：拆分后函数总数增加量 = 成功拆分数；重新导出台账，新函数应被分类器
识别为预期形状（如 `ffi_bridge`）。

### 5. 批量应用机械命名

```bash
# 配置 $TMP/so_apply_rename.cfg: in=<rename.tsv> apply=1
ghidra_run_ghidra_script script_name=so_apply_rename.java
```

脚本只改「生成名」开头的函数（`FUN_`/`leaf_`/`frag_`/`tail_`/`cff_`/`dl_`/
`thunk_`/`vm_`/`sprintf_inline_`/`mprot_`/`ptr_`），已有语义名一律跳过。
重复执行安全。

### 5.5 扫内联系统调用（对抗类壳必做）

```bash
python3 tools/so.py svc <so>
# svc @0xADDR  nr=N (name)
```

加固壳常绕过 libc 直接 `svc #0`，使 `hook kill`/`hook exit` 失效。

| nr | 名称 | 含义 |
|---|---|---|
| 129 | `kill` | **自杀点** |
| 172 | `getpid` | 取自身 pid |
| 101 | `nanosleep` | 延时 |
| 93 | `exit` | 退出 |
| 48 | `faccessat` | 探测文件 |

**先数 `nr=129` 再读代码**：检测逻辑可分散在几十个函数里，但自杀点集中且必然存在。
把 svc 地址映射到函数，得到的清单就是"检测路径的终点"。

**约束**：含 `kill` 的函数不返回。不能 hook 返回值，只能在 `svc` 指令处下断点
或在 syscall 层拦截。

### 5.6 识别 hook 引擎与 JNI 表替换（加固壳必查）

三个可静态识别的特征：

| 特征 | 判据 | 含义 |
|---|---|---|
| hook 三件套 | 同一函数调 `memcmp` + `pthread_mutex_lock/unlock` | 哈希表定位 + 字节校验 + 打补丁 |
| lookup3 哈希 | 常量 `0x9e3779b9` + `0xfeedbeef`，移位 `13/8/13/12/16/5/3/10/15` | Bob Jenkins lookup3 |
| JNI 表克隆 | `memcpy(dst, src, 0x1bf0)` + 重定位 `ToReflectedField`/`Throw`/`ExceptionClear` | 影子 JNINativeInterface |

**影响动态分析**：壳换掉了 `env->functions`，之后所有 JNI 调用走副本。
hook `libart.so` 的导出函数无效，必须 hook **表里的槽位**。

### 5.7 判定为 VM 壳时（JNI_OnLoad 只启动解释器）

业务方法不在 `.text` 里、而是被编译成自定义字节码时，不要在本流水线里硬啃 ——
走专项流程：

| 做什么 | 去哪 |
|---|---|
| 8 步执行清单（确认 → 找表 → 取字段 → 写 profile → trace → verify → disasm → 命名） | **skill `vmp-analysis`** |
| 换壳工作流的命令序列 | `references/so-function-recovery.md` ›「换壳工作流（0 → 1）」 |
| 识别特征与编码推导方法论 | `references/native-analysis.md` ›「3.5.2 字节码 VM 逆向（VMP 型壳）」 |
| 工具 | `tools/vmp.py`（`profile list` 先看有没有现成模型） |

**已有 profile 可直接复用**：`tools/vmp_profiles/` 下每个 JSON 是一套壳的编码模型。
命中就不用从零建模，直接 `trace` → `verify` → `disasm`。

### 6. 按队列读 T1 → T2 → T3

排序依据：证据等级 → 同形状成员数（读一个覆盖多个）→ 体积。

**命名证据分级**（只写有证据的名字）：

| 强度 | 证据 | 例 |
|---|---|---|
| 强 | 字符串直接说明用途 | 读 `ro.build.version.sdk` → `prop_ro_build_version_sdk` |
| 强 | 机器特征唯一确定 | FFI 桩 → `ffi_pop7w_<addr>` |
| 中 | 外部调用面收敛 | 只调两次 `munmap` → `vm_frame_free` |
| 中 | 反编译确认语义 | `*(a+0x10) = b` → `field_write_0x10` |
| 弱 | 只凭名字像 | **不要用** |

### 7. 重新导出，验证命名生效

```bash
# 配置 $TMP/so_dump_pseudo.cfg: out=<path> min_size=64 include_vm=1
ghidra_run_ghidra_script script_name=so_dump_pseudocode.java
```

验收：新命名的函数应出现在伪代码里；机械名带地址后缀便于回溯。

### 8. 写逻辑闭环文档

不是函数清单，是"它怎么工作"：

| 必须覆盖 | 内容 |
|---|---|
| 启动序列 | 所有初始化入口及归类 |
| 主流程 | 从入口到最终目的的完整调用链 |
| 外部依赖 | `dlopen`/`dlsym` 目标、被调库函数清单 |
| 数据结构 | 关键全局结构、栈帧、VM 帧布局 |
| 混淆手法 | CFF / VM / 字符串加密的算法与范围 |
| 对抗手段 | 检测项清单 + 每项实现位置 |

## 完成判据

**函数命名率不是判据。** 命名率低但逻辑闭环完整，比 100% 命名但讲不清主流程更有价值。
判据全文见 [references/so-function-recovery.md ›「十二、完成判据」](../../../references/so-function-recovery.md#十二完成判据)。

| 判据 | 验证方式 |
|---|---|
| 执行入口清楚 | `DT_INIT` / `DT_INIT_ARRAY` / `JNI_OnLoad` 全部定位到真身 |
| 主流程闭环 | 从入口到最终目的有完整调用链 |
| 外部依赖明确 | 所有 `dlopen`/`dlsym` 目标 + 被调库函数清单 |
| 数据结构清楚 | 关键全局结构、栈帧结构、VM 帧布局 |
| 混淆手法识别 | 算法与作用范围 |
| 对抗手段清楚 | 检测项清单 + 实现位置 |

## 卡壳树

| 现象 | 处理 |
|---|---|
| 反编译满是 `unaff_`、控制流不通 | 命中了 CFF 内部块 → 查所属函数真身（步骤 1） |
| 指令覆盖率 < 99% | 跑 `so_boundary_rebuild.java`，再跑步骤 4 |
| 同形状函数上千个 | 分类器判据太松 → 检查是否多条件同时满足 |
| 机械命名覆盖了语义名 | 保护名单缺前缀 → 补 `GENERATED` 列表 |
| 拆分边界后函数数没变 | 地址基准错（ELF VA vs Ghidra VA） |
| hook 无效（kill 拦不住 / libart 导出无效） | 见 [references/anti-detection.md](../../../references/anti-detection.md) 与 [references/so-function-recovery.md ›「七之三、裸系统调用」](../../../references/so-function-recovery.md#七之三裸系统调用识别与约束) |
| 台账形状哈希全是 `err` | 指令遍历越界 → 检查 body 边界 |

## 工具清单

**通用工具**（`tools/`，任何 SO 可用）

| 工具 | 作用 |
|---|---|
| `tools/ghidra/so_inventory.java` | 导出函数台账 + 形状指纹 |
| `tools/so_ledger.py` | 三层筛选、证据分级、机械命名建议 |
| `tools/ghidra/so_split_pointer_targets.java` | 按指针表补建漏掉的函数边界 |
| `tools/ghidra/so_apply_rename.java` | 批量重命名（带语义名保护） |
| `tools/ghidra/so_boundary_rebuild.java` | 函数边界重建（无 `.eh_frame` 时） |
| `tools/ghidra/so_dump_pseudocode.java` | 批量导出伪代码 |
| `tools/so.py` | ELF 侦察、字符串、反汇编、交叉引用、SVC、JNI 判型 |
| `tools/ptr_table.py` | 指针表枚举与分类、表槽位反查 |
| `tools/probe_layout.py` | 动态结构体布局探测（`--at`/`--hook`/`--multi-hook`/`--setup`） |
| `tools/check_registry.py` | 登记漂移自检 |

**样本专用工具**（`<包名>/tools/`，换样本需重写或改 profile）

| 工具 | 作用 |
|---|---|
| `<包名>/tools/setup_*.py` | 给 `probe_layout.py` / `emu_run.py` / `vmp.py trace` 准备样本环境 |

**分界线**：能按 ELF 结构/通用算法判定的 → `tools/`；
需要样本的地址、字符串、VM 编码常量的 → `<包名>/tools/`。

**VM 专项工具**（`vmp.py` / `vmp_profiles/` / 样本的 `vm_*.py`）归 skill `vmp-analysis` 管，
本节不重复列 —— 步骤 5.7 会转交过去。

## 参考

- 方法论与判据全文：`references/so-function-recovery.md`
- VM 编码反推方法论：`references/native-analysis.md` ›「3.5.2 字节码 VM 逆向（VMP 型壳）」
- 单函数仿真：`references/so-emulation.md`、skill `so-emulate`
- 单函数命名：`references/so-func-naming.md`、skill `func-naming`
