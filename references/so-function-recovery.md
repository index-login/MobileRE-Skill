# 大型 SO 函数级还原方法论

**适用**：2000+ 函数、无 `.eh_frame`、CFF 混淆、内嵌 VM 的加固 SO。
目标不是"读完每个函数"，而是**用最少的阅读量拿到完整逻辑闭环**。

路径基准：项目根。工具在 `tools/`，Ghidra 脚本在 `tools/ghidra/`。

---

## 〇、Step 0：先分诊 SO 类型（决定后面哪些步骤会空转）

本流水线以**加固壳 SO** 为默认假设（`DT_INIT`/`DT_INIT_ARRAY` 为主干、CFF、VM、
反检测、JNI 表克隆）。若目标不是加固壳，步骤 1/5.5/5.6/5.7 会全部空转。

| 类型 | 判据 | 主入口 | 走哪些步骤 |
|---|---|---|---|
| **加固壳 SO** | `DT_INIT_ARRAY` 项数多（几十项）；有 `svc` 自杀路径；有 CFF/VM；字符串加密 | `DT_INIT` / 解释器 | 全流程 |
| **业务 native 库** | `DT_INIT_ARRAY` 少（<5）；导出大量 `Java_*` 或走 `RegisterNatives`；无 CFF | `JNI_OnLoad` + `Java_*` 导出 | 跳过 1/5.5/5.6/5.7，直接走「二、反向映射」 |
| **静态第三方库** | 导出符号密集 `_Z*`/`__cxa*`；外部进入边极少 | 无 | 直接排除，不分析 |

判据命令：

```bash
python3 tools/so.py info <so>                    # 看 dynsym_defined / DT_INIT_ARRAYSZ
python3 tools/so.py info <so> --grep Java_       # 业务库会有大量 Java_* 导出
python3 tools/so.py svc <so>                     # 有 kill/exit 才像加固壳
```

### 业务 SO 的快捷路径：Java 侧 → native 实现

加固壳要自底向上（从 ELF 找入口）；业务库反过来更快——从 Java 声明清单直接定位实现：

```
① jadx 列出 native 方法声明
② 对到 so：
   ├─ 静态注册 → so.py info --grep Java_<pkg>_<Class>_<method>
   └─ 动态注册 → scripts/utils/scan_register_natives.js（spawn）/ dex2c_entry.js（attach）
③ 只读这批函数（其余是依赖库/工具函数，按台账排除）
```

这一步能把"2300 个函数"直接收敛到"业务相关的几十个"。

---

## 一、先建立"函数台账"，再动手

### 不建台账的后果

按地址顺序读 2000 个函数，其中：
- 静态库代码（libc++/zlib/openssl）不是分析目标
- 编译器生成的桩（thunk/tail-call/单指令）没有信息量
- CFF 状态机的 case 块属于父函数，单独命名是伪进展

这三类通常占 50% 以上。先分类再读，能省一半以上工作量。

### 三层筛选

```
① 代码分区   按地址划入已知区间 → 排除第三方库与 VM handler 区
② 机器形状   指令归一化后哈希去重 → 排除机械桩
③ 证据分级   有字符串 > 有具名外部调用 > 纯逻辑 → 排序
```

### 时序：边界重建必须在台账之前

台账里的 `size` / `insns` / 形状哈希都基于**当时的函数边界**。如果先导台账再跑
`so_boundary_rebuild.java`，函数总数会变（实测 3200 → 3916），台账的分母、
形状分组、证据分级全部作废，必须重导。

固定顺序：

```
so_unpack_prep（脱壳镜像修复）→ so_boundary_rebuild（边界重建）
  → so_split_pointer_targets（补第二入口）→ so_inventory（导台账）→ so_ledger
```

### 落地：`so_inventory.java` + `so_ledger.py`

```bash
# Ghidra 侧导出（配置 $TMP/so_inventory.cfg 指定 out / shapes_out）
ghidra_run_ghidra_script script_name=so_inventory.java

# Python 侧生成队列
python3 tools/so_ledger.py <out.tsv> --shapes <shapes.tsv> --so <target.so> \
    --report LEDGER.md --queue queue.tsv --rename rename.tsv \
    [--regions <分区表.json>] [--image-base 0x100000]

# 只看还剩多少
python3 tools/so_ledger.py ... --stats
```

**两个必知参数**：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--regions <json>` | 空 | 代码分区表是**样本事实**，工具不再内置。不传时全部落 `shell` 分区（只少了分类收益，不影响台账与命名） |
| `--image-base` | `0x100000` | Ghidra 镜像基址。用 `ghidra_get_current_program_info` 确认，基址不同必须显式给 |

**自动闸门**：`--so` 传了未脱壳的镜像时，所有函数会被判成 `empty` 桩。
工具在 `empty` 占比 > `--max-empty`（默认 5%）时**拒绝写 `--rename`** 并以退出码 1 结束 ——
避免把上千个真函数批量改成 `empty_xxx`。确认无误可设 `--max-empty 1` 跳过。

**`--so` 必须是脱壳后的镜像**（`.text` 已解密）。传未脱壳的原文件时，
所有函数都会被判成 `empty` 桩，并产出大量错误的 `empty_*` 重命名建议。
`--stats` 里 `不可反汇编`/`empty` 占比超过 5% 就是传错了文件。

**`--regions`** 提供代码分区表（样本事实，放在 `<包名>/tools/regions.json`）；
不传时全部落 `shell` 分区，只是少了分类收益，不影响台账与命名。

台账每行 15 列：地址 / 名 / 大小 / 指令数 / 参数 / 返回类型 / 调用者数 /
被调数 / 代码引用数 / 数据引用数 / 引用来源函数 / 字符串 / 被调名 /
形状哈希 / 父命名空间。

**形状哈希**：指令归一化成 `mnemonic + 操作数形状`（立即数、地址、符号全替换为 `#`）
再 MD5。同形状 = 同模板生成，读一个代表即可。

### 证据分级判据

| 等级 | 判据 | 处理 |
|---|---|---|
| T1 | 有字符串引用 | 读串即可定名，性价比最高 |
| T2 | 有具名外部调用 | 看调用面推断用途 |
| T3 | 纯逻辑，无串无外部调用 | 必须读伪代码 |
| T4 | 机械桩 | 跳过，批量命名 |
| X1 | 父命名空间是 `switchD_*` | CFF case 块，不单独命名 |
| X2 | 落在静态库区间 | 非分析目标 |

---

## 二、代码分区：用调用边密度判定库边界

### 判据不是"看起来像库"

不能凭函数名前缀（`_Z*`）判断。用**调用边方向性**：

| 指标 | 库代码 | 壳代码 |
|---|---|---|
| 区域内调用边 | 密集 | 中等 |
| **区域外进入边** | **极少（0~2）** | 多 |

实测：`0x1c4750–0x1c5fff` 区间的出边 590 条、入边 1 条，且 `_Z*`/`__cxa*`
命名密度 76–92% → 完全内聚的静态 libc++。

### 交叉验证

`.dynsym` 的导出符号表能直接标出库函数范围。若某区间的函数名大量出现在
`.dynsym` 且都是 `_Z` 前缀，就是静态库。

---

## 三、机械桩：必须"多条件同时满足"

### FFI 桥接桩（VM 调 native 的通道）

```asm
ldr  x20, [x0]              ; ① 从第 1 参数取栈顶指针
sub  x8,  x20, #4
str  x8,  [x0]              ; VSP -= 4
ldur w8,  [x20, #-4]        ; ② 从同一基址寄存器负偏移读
ldur w1,  [x20, #-8]
bfi  x2,  x8, #0x20, #0x20  ; ③ 拼 64 位参数
blr  x11                    ; ④ 间接调用
```

**四条必须同时满足**，缺一条就会误判：

1. 存在 `ldr xR,[x0]`
2. ≥2 条 `ldur w?,[xR,#-k]`，**基址寄存器是同一个 R**
3. 存在 `blr` / `br`
4. 全函数**无** `bl`

第 2 条的"同一寄存器"是关键。缺了它，带局部数组的真实逻辑函数
（大量 `ldur wN,[x29,#-k]` 但基址各不相同）会被误判成"弹了几十个参数"。

**反向自检**：统计出的槽数超过 20 就一定错了——AAPCS64 最多 8 个寄存器参数。

### 其余机械类型

| 类型 | 判据 |
|---|---|
| `thunk` | ≤2 条指令且全是 `b`/`br`/`ret`/`nop` |
| `tailcall` | ≤3 条指令，末条是 `b`/`br`，无 `bl` |
| `one_insn` | 恰好 1 条指令 |

### 命名规则

机械名不携带语义，**地址后缀必须保留**：

```
ffi_pop<N>w_<addr>[_t<tblbase>_s<slot>]   N = 从 VM 栈读的 32 位槽数
thunk_<addr>
tail_<addr>
one_<addr>
```

`N` 是**实测的槽数**，不是推断的参数个数（一个 64 位参数占 2 槽）。

---

## 四、CFF case 块：识别而非还原

### 识别

Ghidra 把 CFF 状态机的每个 case 拆成独立 `Function`，父命名空间是
`switchD_<addr>::`。判据：

```java
f.getParentNamespace().getName().startsWith("switchD_")
```

实测占 16.9%。这些函数体里全是 `unaff_x19[0x266]` 这类状态机上下文访问，
给它单独命名没有意义。

### 为什么不该单独还原

```c
void switchD_001c6e00::cff_1c7048(long param_1)
{
  lVar2 = unaff_x19[0x266];              // 读状态机上下文
  if (0xfef < *(long *)(lVar2 + 8) + 0x20U) {
    plVar1 = (long *)malloc(0x1000);     // 分配下一个状态块
    ...
  }
  func_0x001c7bfc(&::g_vtbl_1c95b0);     // 跳下一个状态
}
```

语义由父函数的状态机决定。单块命名只能得到"分配状态块"这类无信息结论。

### 可行路径

静态无解，只能整体还原：
- 动态 trace 记录状态转移序列
- 符号执行求解状态变量

在拿到这两者之前，**标记为 X1 并跳过**是正确的工程决策，不是放弃。

---

## 五、VM 类加固：从动态 trace 反推编码，不要静态猜

### 静态反汇编必然失败的原因

每条 handler 自定义 pc 推进量和操作数布局。按固定长度（3/5 字节）切分，
opcode 会随机分布，命中率接近 0。

### 正确顺序

```
① Ghidra 读 handler 正文      → 提取 pc 推进量 / 操作数提取方式
        ↓
② 仿真跑通（先确认能跑）      → 拿 (pc, opcode) 序列
        ↓
③ 用 trace 反推解码公式        → 必须验证命中率
        ↓
④ 反汇编字节码                → 输出可读清单
```

### 解码公式的推导方法

拿到 trace 的 `(pc_n, op_n)` 序列后：

1. 算每条指令的实际长度 `L_n = pc_{n+1} - pc_n`
2. 取每条指令的**最后一字节** `b_n`
3. 假设 `op_n = f(b_n, op_{n-1})`，用线性代数在 GF(2) 上解 `f`

归纳出的通用形式（换壳只改常量，不改公式形状）：

```
decode(x, k) = (((A - x) & M1) | ((x - B) & M2)) ^ k
op_n         = decode(byte[pc_n + L - 1], op_{n-1} ^ K)
```

`A/B/M1/M2/K` 是壳自己的常量；入口第一条指令通常还要单独处理（key 来源不同）。
这些常量全部写进 profile，代码里不出现具体数值。

### 工具：`tools/vmp.py`

模型（profile JSON）与引擎（脚本）分离，换壳只写 profile：

```bash
python3 tools/vmp.py profile list
python3 tools/vmp.py trace  <so> -p <profile> --sel 0 --out trace.json
python3 tools/vmp.py verify <so> -p <profile> --trace trace.json
python3 tools/vmp.py disasm <so> -p <profile> --trace trace.json --vm <key>
```

profile 字段见 [native-analysis.md ›「3.5.2 字节码 VM 逆向（VMP 型壳）」](native-analysis.md#352-字节码-vm-逆向vmp-型壳)。

### 验收判据

**trace 命中率必须 > 95%**。低于这个值说明公式错了或还有未覆盖的分支。

剩余未命中若能归因到某个明确分支（如"条件满足时 key 被强制为某常量"），
是可解释的边界，不是模型错误 —— 在 profile 里用 `forced_key` 描述它。

### 分派表项数不是 2 的幂

不要假设 opcode 表有 256 项。用两种方法交叉验证：

1. 表后面紧跟的连续指针数组长度
2. 解释器入口 `memcpy(dst, table, N)` 的 N

实测：handler 表 138 项（不是 256），其后 593 项是 continuation 表，
且 `0x450 + 0x1288 = 0x16D8` 与 memcpy 长度一致。

早期按 256 项读，会把 continuation 表的前几项误当 opcode，
导致 25 个 opcode 被误认为共用同一 handler。

### 换壳工作流（0 → 1）

拿到一个从没见过的 VM 壳，按这个顺序走。每步都有对应的工具或手册段落，
不需要从零写代码。

```
① 确认是 VM
   ├─ 三个可观测特征：跳转表分派 / 软件栈 / handler 按偏移读写栈
   └─ 判据：references/native-analysis.md ›「3.5.2」第一步

② 找 opcode 表
   └─ python3 tools/ptr_table.py <so> --scan --only-code --classify vm
      输出里标「handler 表候选」的那张；项数不要假设 256

③ 反编译 dispatch，取 6 个 trace 字段
   ├─ entry_va             → so.py info --grep JNI_OnLoad（或 DT_INIT 真身）
   ├─ dispatch_hook_pc     → ldr xN,[tbl,xIdx,lsl#3] 的前一条指令
   ├─ frame_pc_off         → dispatch 存 pc 的 [sp+0xNN]
   ├─ frame_idx_off        → dispatch 存 opcode 索引的偏移
   ├─ frame_key_off        → dispatch 存 key 的偏移
   └─ selector_arg_reg     → selector 由哪个寄存器传入

④ 写 profile
   ├─ python3 tools/vmp.py profile new <壳名>     （从 _template.json 复制）
   ├─ 先填 [engine]：key_xor / decode{4} / handler_table_file_va /
   │                handler_count / bytecode_file_va
   └─ opcodes 先全填 op_<hex>，条目数 == handler_count

⑤ 跑 trace
   ├─ 简单壳：python3 tools/vmp.py trace <so> -p <profile> --out trace.json
   ├─ 脱壳镜像：先 cp tools/emu_setup_template.py <包名>/tools/setup_<n>.py
   │            再 python3 tools/vmp.py trace <so> -p <profile> --setup <...>
   └─ 先不加 setup 第 5 步，按 [!] unstubbed 日志逐个补桩

⑥ 校验模型
   ├─ python3 tools/vmp.py verify <so> -p <profile> --trace trace.json
   ├─ 命中率必须 > 95%
   └─ 未命中集中在某 opcode 段 → profile 填 forced_key

⑦ 反汇编
   └─ python3 tools/vmp.py disasm <so> -p <profile> --trace trace.json --vm <key>

⑧ handler 语义命名（增量）
   ├─ python3 tools/vmp.py model --op 0xNN    （看 handler 指令模型）
   ├─ 对着反编译结果判断语义，改 profile 的 opcodes
   └─ 先命名高频 opcode（disasm 末尾的频次表按降序）
```

**完整执行清单（含常见报错与处理）见 skill `vmp-analysis`。**

---

## 六、selector 索引宽度：必须从调用点确认

多入口 VM 用 `selector[idx * W]` 索引字节码偏移。`W` 不能猜：

```asm
; vm_dispatch_entry 内
add  x8, x4, x5, LSL #2      ; ← LSL #2 = ×4，W=4
```

**自检**：如果 selector 表读出来有大量重复的 0 或交错零（如
`0x0 0x0 0x18 0x0 0x18 0x0`），宽度就是错的。正确的 u32 序列形如
`0x0 0x18 0x18 0xc4 0xdc 0xb6` —— 单调递增、无交错零。

---

## 七、`DT_INIT` 可能指向函数内部

### 现象

`DT_INIT` 反编译结果全是 `unaff_x19/x20`，且控制流完全不通。

### 原因

`DT_INIT` 指向的是 CFF 分发后的**内部分支块**，不是函数入口。

### 定位真身

1. 读 `.dynamic` 拿 `DT_INIT` 地址 `A`
2. 在 Ghidra 里看 `A` 属于哪个函数（`getFunctionContaining`）
3. 若 `A != 函数入口`，真身是 `函数入口`

实测：`DT_INIT = 0x985a0`，真身是 `0x1983e8`（3752 字节）。

### 同样适用于

- `DT_INIT_ARRAY` 的每一项
- `.init_array` 里的函数指针
- 任何从数据段取到的函数指针

---

## 七之二、指针表指向函数内部：必须补建边界

### 现象

指针表里的某个槽位指向的地址，落在已有函数 body 内部而非函数入口。
解引用该槽位会得到一个"函数中间"的地址。

### 根因：编译器合并同族函数

ARM64 编译器会把参数个数不同的同族函数合并，共享尾部代码：

```asm
0xecd5c  stp  x30, x21, [sp, #-0x20]!   ; 入口 A（10 个弹栈槽）
         ...
0xece10  ret
0xece14  ldr  x9, [x0]                  ; 入口 B（独立函数，从 ldr 开始）
         ...
```

入口 B 没有独立序言（没有 `stp x29,x30` / `sub sp,sp,#N`），
自动分析按序言识别起点时会把它并入入口 A。

### 判据：三条同时满足才拆

1. 该地址被某个指针表引用
2. 该地址落在已有函数 body **内部**（不是入口）
3. 首条指令是函数起点特征：
   - `ldr xN,[x0]` —— 取第 1 个参数（FFI 桩的典型开头）
   - `stp x30,...` / `str x30,[sp,#-N]!` —— 标准栈帧序言
   - `bti` —— BTI 入口

**反例要排除**：`ldrb w9,[x0]` 是读第 1 参数指向的字节，不是函数起点。
区分点在宽度：`ldr x`（8 字节取指针）vs `ldrb w`（1 字节取数据）。

### 拆法

```java
Function owner = getFunctionContaining(addr);
if (owner == null || getFunctionAt(addr) != null) skip;
if (addr - owner.getEntryPoint() < minGap) skip;   // 防止把序言误拆
if (!looksLikeEntry(getInstructionAt(addr))) skip;
createFunction(addr, name);   // 原函数 body 自动在 addr 前截断
```

**不要先删原函数**。`createFunction` 会重新界定 body，原函数自动截断。
先删会导致原函数前半段的代码归属丢失。

### 验收

| 指标 | 判据 |
|---|---|
| 拆分前候选数 | = 指针表中落在函数内部的槽位数 |
| 被拒绝数 | 应等于"首条指令非函数起点"的个数，且每个都能说出理由 |
| 拆分后函数总数 | 增加量 = 成功拆分数 |
| 重新导出台账 | 新函数应被分类器识别为预期形状（如 `ffi_bridge`） |

## 七之三、裸系统调用：识别与约束

### 为什么壳要绕过 libc

`kill` / `exit` / `ptrace` 是动态对抗的重点 hook 目标。加固壳直接写
`mov x8, #__NR_xxx; svc #0`，使 `hook kill` 完全失效。

### 识别

```bash
python3 tools/so.py svc <so>
# 输出：svc @0xADDR  nr=N (name)
```

ARM64 syscall 号（Android/Linux 通用）：

| nr | 名称 | 常见用途 |
|---|---|---|
| 93 | `exit` | 退出 |
| 101 | `nanosleep` | 延时 |
| 129 | `kill` | **自杀** |
| 172 | `getpid` | 取自身 pid |
| 220 | `clone` | 起线程 |
| 56/63/57 | `openat`/`read`/`close` | 读 /proc |
| 48 | `faccessat` | 探测文件 |
| 117 | `ptrace` | 反调试 |

把 `svc` 地址映射到函数（`getFunctionContaining`），得到"哪些函数直接发系统调用"。

### 自杀路径的典型形状

```
getpid → nanosleep → kill(SIGABRT) → kill(SIGKILL) → brk #1
```

多个 kill 是冗余设计：SIGABRT 可被捕获，SIGKILL 不可，`brk` 兜底。

### 分析约束（关键）

**这些函数不能 hook 返回值——它们不返回，直接杀进程。**

| 做法 | 结果 |
|---|---|
| `Interceptor.attach` 在函数入口 | 能看到调用，但拦不住 kill |
| hook `kill`/`exit` 的 PLT | **无效**，壳不走 PLT |
| hook `svc` 指令所在地址 | 有效（改 `x8` 或跳过 `svc`） |
| syscall 层拦截（seccomp / ptrace） | 有效 |

### 分诊：先数 kill 再读代码

```bash
# 1) 扫 svc，筛 nr=129
python3 tools/so.py svc <so> | grep "nr=129"
# 2) 映射到函数，得到"自杀点"清单
# 3) 这些函数优先读（它们是检测逻辑的终点）
```

比逐个读检测函数快得多：检测逻辑可以分散在几十个函数里，
但**自杀点集中且必然存在**。

## 七之四、加固壳的 hook 引擎：识别特征

### 哈希表 + 字节校验 + 互斥 的三件套

成熟加固壳的 hook 引擎通常长这样：

```c
e = hash_lookup(table, target, key);        // 1) 哈希定位记录
if (!e || e->target != target) goto direct;
ret = (*(orig_fn))(...);                    // 2) 先调原函数
pthread_mutex_lock(&lock);                  // 3) 串行化
if (memcmp(ret + e->off, e->backup, e->len) == 0)   // 4) 字节校验
    patch(ret + e->off, e->flags);          // 5) 一致才改
pthread_mutex_unlock(&lock);
```

**为什么有第 4 步**：防止和别的 hook 工具（Frida/Xposed）冲突。
字节已被改过就跳过，避免把别人写的跳转指令覆盖成半截。

**识别方法**：找同时调 `memcmp` + `pthread_mutex_lock` + `pthread_mutex_unlock`
的函数。这个组合在正常业务代码里很少见。

### 哈希函数指纹

| 常量 | 算法 |
|---|---|
| `0x9e3779b9` + `0xfeedbeef` | Bob Jenkins lookup3 |
| `0x811c9dc5` (2166136261) | FNV-1a |
| `0x9e3779b1` + `0x85ebca6b` | xxHash / MurmurHash |
| `0x5bd1e995` | MurmurHash2 |
| `-0x61c88647` (= `0x9e3779b9` 取反) | lookup3 的另一种写法 |

lookup3 的移位序列是固定的：`13/8/13/12/16/5/3/10/15`（一轮 12 字节）。

### 哈希表的三件套 = 壳自带符号表

同一套常量出现在三个函数里，说明是一张表的三个操作：

| 操作 | 特征 |
|---|---|
| 插入 | `malloc(0x50)` entry + `strdup` key + 链头插入 |
| 查找 | 哈希 + 链遍历 + `memcmp` |
| 扩容 | 桶内计数 `> 10*avg+10` 时 `malloc(nbucket << 5)` 并全量 rehash |

**用途**：缓存 `dlsym` 结果。看到这套结构就说明壳有自己的符号解析层，
`dl_*` 系列函数都是它的调用方。

**链里存的是偏移不是指针**（`entry->next - tbl->base`），这是为了兼容
不同加载基址。读伪代码时 `lVar10 = lVar10 - plVar24[4]` 就是在还原偏移。

### JNIEnv 表克隆 = 全局 JNI hook 前置

```c
dst = alloc(sizeof(JNINativeInterface));    // Android 10 = 0x1bf0
memcpy(dst, src, 0x1bf0);
// 重定位"返回表内指针"的槽位：
//   ToReflectedField / Throw / ExceptionClear / FromReflectedField
env->functions = dst;
```

**识别特征**：`memcpy` 长度等于 `0x1bf0`（或其它版本的 `sizeof(JNINativeInterface)`），
且随后对特定槽位做指针重定位。

**含义**：壳换掉了 JNI 函数表。之后所有 `(*env)->FindClass()` 都走它的副本。
动态 hook 时要 hook **表里的槽位**，而不是 `libart.so` 的导出函数。

### 参数封送的双向配对

JNI 边界两侧各有一个按类型描述符分发的函数：

| 方向 | 特征 |
|---|---|
| native → jvalue | 取参数、按 `B/C/D/F/I/J/L/S/Z` 塞进 jvalue 数组 |
| jvalue → native | 按同样的字符集从 jvalue 取出、按宽度写入结构体 |

看到成对的 8 分支 switch（case 是单字节 ASCII），就是这一对。

## 八、初始化序列：`DT_INIT_ARRAY` 是主干

### 解析

```python
# PT_DYNAMIC → DT_INIT_ARRAY(25) / DT_INIT_ARRAYSZ(27)
for i in range(size // 8):
    fn_addr = u64(dynamic[init_array_offset + i*8])
```

实测 70 项，每一项都是一个独立初始化器。

### 分类方法

| 类型 | 特征 | 处理 |
|---|---|---|
| 字符串解密 | 全是 `str[i] ^= const` | 可离线复算，不需要读全 |
| 表安装 | 单个 `str` 到固定全局偏移 | 读目标表内容即可 |
| 版本探测 | `dlsym` + 条件赋值 | 读赋值常量 |
| 真实逻辑 | 有分支、循环、调用 | 需完整读 |

### 表安装类初始化器的价值

```c
void _INIT_55(void) {
  *(void **)(g_shell_ctx.jni + 0x20) = &DAT_001fe128;
  return;
}
```

这种函数本身没有逻辑，但它**揭示了架构**：壳把"具体调哪个 ART 函数"
做成运行时可替换的指针表，启动时按探测到的版本装上对应表。

追这些表的地址，能直接拿到壳的全部外部依赖清单。

---

## 九、结构体：动态实测优于静态推断

### 静态推断的局限

壳的全局结构在静态数据段里通常是全零（运行时才填）。读 `.data` 得到的是
未初始化值。

### 动态实测

```bash
python3 tools/probe_layout.py <so> --entry JNI_OnLoad --at 0x<global_addr> --size 0x100   # 抓全局
python3 tools/probe_layout.py <so> --entry JNI_OnLoad --hook 0x<func> --arg X0            # 抓参数指向的结构
python3 tools/probe_layout.py <so> --entry JNI_OnLoad --multi-hook 0xA,0xB --multi-size 0x60  # 多 PC 一次抓
```

### 判据：字段值要"讲得通"

| 字段 | 实测值 | 判定依据 |
|---|---|---|
| `sdk_int` | `29` | 与设备 Android 10 一致 |
| `heap_size` | `0x200000` | 与 `mmap` 长度一致 |
| `build_ver` | `29` | 与 `ro.build.version.sdk` 一致 |

字段值落在合理范围（SDK 版本 21–35、页大小 4096 的倍数、
指针落在 `[base, base+size)`），才能确认偏移正确。

### 结构体放在 mmap 尾部是常见设计

```c
puVar5 = mmap(NULL, len, ...);
pvVar2 = (vm_runtime *)(puVar5 + (len - 0x30));   // 结构在尾部
```

看到"指针接近映射区末尾"时，检查是不是这种布局。

---

## 十、JNI 签名解析器：识别特征

### 特征

函数体里有一个 `strlen` + 逐字符 `switch`，case 值是单字节 ASCII：

```c
for (i = 1; i < strlen(sig); i++) {
  switch (sig[i]) {
    case 'B': /* 1 byte  */ break;
    case 'C': /* 2 bytes */ break;
    case 'D': /* 8 bytes */ break;
    case 'F': /* 4 bytes */ break;
    case 'J': /* 8 bytes */ break;
    case 'L': /* pointer */ break;
    case 'S': /* 2 bytes */ break;
    case 'Z': /* 1 byte  */ break;
  }
}
```

这 8 个字符正好是 JNI 类型描述符全集。

### 辅助判据

- 有一个 `malloc(0x80)` 或类似固定大小分配（jvalue 数组是 8 字节 × N）
- 调用点用 `ldr x8,[x9,#0xb8]` 这类大偏移（JNI 方法表槽位）
- 参数里有 `JNIEnv**`

---

## 十一、命名：只写有证据的名字

### 证据强度分级

| 强度 | 证据 | 例子 |
|---|---|---|
| 强 | 字符串直接说明用途 | 读 `ro.build.version.sdk` → `prop_ro_build_version_sdk` |
| 强 | 机器特征唯一确定 | FFI 桩 → `ffi_pop7w_<addr>` |
| 中 | 外部调用面收敛 | 只调 `munmap` 两次 → `vm_frame_free` |
| 中 | 反编译确认语义 | 看到 `*(a+0x10) = b` → `field_write_0x10` |
| 弱 | 只凭名字像 | **不要用** |

### 命名必须可回溯

机械名带地址后缀，语义名带用途关键词。禁止：

- 起一个无法验证的语义名（`process_data`、`handle_event`）
- 用 CFF case 块的局部行为命名父函数
- 把"猜测"写成"事实"

### 批量命名必须带保护

```java
// so_apply_rename.java 的核心约束
if (!isGenerated(cur)) { skippedSemantic++; continue; }
```

只改生成名开头的函数，已有语义名一律跳过。这样脚本可以重复执行，
不会覆盖人工成果。

---

## 十二、完成判据

"分析完成"不是"读完所有函数"，而是：

| 判据 | 验证方式 |
|---|---|
| 执行入口清楚 | `.dynamic` 的 `DT_INIT` / `DT_INIT_ARRAY` / `JNI_OnLoad` 全部定位到真身 |
| 主流程闭环 | 从入口到最终目的（加载什么、注册什么）有完整调用链 |
| 外部依赖明确 | 所有 `dlopen`/`dlsym` 目标、所有被调库函数清单 |
| 数据结构清楚 | 关键全局结构、栈帧结构、VM 帧布局 |
| 混淆手法识别 | CFF / VM / 字符串加密的算法与范围 |
| 对抗手段清楚 | 检测项清单 + 每项的实现位置 |

**函数命名率不是完成判据**。命名率低但逻辑闭环完整，
比 100% 命名但讲不清主流程更有价值。

> 统计口径要分清：「非生成名」含机械名与静态库代码，不能直接当语义名报出去。
> 看「在范围内语义名」= 非生成名 ∧ 非机械名 ∧ 非库区间。

---

## 十三、反模式

| 反模式 | 后果 | 正确做法 |
|---|---|---|
| 按地址/字母顺序逐个读 | 50% 时间花在库代码和机械桩上 | 先建台账，按证据分级排队 |
| 单条件判定机械桩 | 把真实逻辑误判成桩 | 多条件同时满足 |
| 静态猜 VM 指令格式 | 命中率接近 0 | 从动态 trace 反推 |
| 假设 opcode 表是 256 项 | 25 个 opcode 被误判 | 用表长 + memcpy 长度交叉验证 |
| 猜 selector 索引宽度 | 偏移全错 | 从调用点的 `LSL #N` 确认 |
| `DT_INIT` 直接当函数入口 | 全是 `unaff_`，控制流不通 | 查所属函数的真实入口 |
| 给 CFF case 块单独命名 | 伪进展 | 标记 X1 跳过，等动态 trace |
| 结构体字段靠猜 | 字段全错位 | 动态实测 + 值合理性验证 |
| 机械命名不带地址 | 无法回溯验证 | 地址后缀恒定保留 |
| 只按序言建函数 | 指针表指向的"第二入口"被漏掉 | 用指针表交叉检查函数边界 |
| hook `kill`/`exit` 的 PLT | 壳走裸 svc，hook 无效 | 扫 `svc` 找内联系统调用 |
| hook `libart.so` 导出函数 | 壳换了 JNIEnv 函数表，调用不走导出 | 找 `memcpy(0x1bf0)` 确认表克隆，hook 表槽位 |
| 补建边界前先删原函数 | 原函数前半段代码归属丢失 | 直接 `createFunction`，原函数自动截断 |
| 批量命名不设保护 | 覆盖人工成果 | 只改生成名 |

---

## 十四、工具清单

### 分层原则

| 层 | 位置 | 判据 |
|---|---|---|
| 通用 | `tools/` | 只依赖 ELF 结构或通用算法，任何 SO 可用 |
| 样本专用 | `<包名>/tools/` | 依赖该样本的地址常量、字符串、VM 编码 |

**迁移路径**：分析新目标时，先把脚本写在 `<包名>/tools/`；跑通后判断
哪部分能通用化（按 ELF 段定界、参数化常量），把通用部分抽到 `tools/`，
样本部分留下。

**反例**：把样本的地址区间（如 `0xfc000..0x11a000`）硬编码进 `tools/`
的脚本，换个 SO 就失效。

### 通用工具

| 工具 | 作用 |
|---|---|
| `tools/ghidra/so_inventory.java` | 导出函数台账 + 形状指纹 |
| `tools/ghidra/so_split_pointer_targets.java` | 按指针表补建漏掉的函数边界 |
| `tools/so_ledger.py` | 三层筛选、证据分级、机械命名建议 |
| `tools/ghidra/so_apply_rename.java` | 批量重命名（带语义名保护） |
| `tools/ghidra/so_boundary_rebuild.java` | 函数边界重建（无 `.eh_frame` 时） |
| `tools/so.py` | ELF 侦察、字符串、反汇编、交叉引用、SVC、JNI 判型 |
| `tools/ptr_table.py` | 指针表枚举与分类、表槽位反查 |
| `tools/probe_layout.py` | 动态结构体布局探测（`--at`/`--hook`/`--multi-hook`/`--setup`） |
| `tools/vmp.py` | 字节码 VM/VMP 逆向（profile 驱动：disasm/verify/trace/model/profile） |
| `tools/emu_run.py` / `tools/uniharness.py` | 单函数离线仿真 |

### 样本专用工具（`<包名>/tools/`）

| 工具 | 作用 |
|---|---|
| `vm_disasm.py` | 链式 opcode 变长反汇编 + trace 自验证（通用版：`tools/vmp.py disasm`） |
| `vm_tables.py` | VM 辅助表（tbl1 配置 / tbl2 FFI）分析 |
| `vm_emulate.py` | VM 离线仿真（GOT/JNI/桩） |
| `vm_trace.py` | 动态 trace（通用版：`tools/vmp.py trace`） |
| `setup_*.py` | 给 `probe_layout.py` 准备样本环境 |
