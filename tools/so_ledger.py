#!/usr/bin/env python3
"""
so_ledger.py — SO 函数台账分析（配合 tools/ghidra/so_inventory.java）

解决的问题
----------
大 SO（2000+ 函数）反复分析同一批函数：每次都从 PSEUDOCODE.txt 里翻，判断
"这个函数是不是已经看过"。本工具把 Ghidra 导出的清单变成**带证据等级的工作队列**，
并输出机械可判函数的重命名建议，让"再分析一遍"变成不可能。

核心思路
--------
1. 机器形状指纹去重：把指令归一化成 mnemonic+寄存器形状后哈希。
   同形状 = 同模板生成，只需读一个代表。
2. 证据分级：按"这个函数身上有多少可判线索"排序，不按地址/字母序。
   T1 有字符串 > T2 有具名外部调用 > T3 纯逻辑 > T4 机械桩。
3. 机械命名：FFI 桥接桩、单跳 thunk、tail-call 桩可直接按机器特征命名，
   不消耗分析判断。

用法
----
    # 生成台账报告 + 工作队列 + 重命名建议
    python3 tools/so_ledger.py inv.tsv --shapes shapes.tsv --so target.so \\
        --report LEDGER.md --queue queue.tsv --rename rename.tsv

    # 只看统计
    python3 tools/so_ledger.py inv.tsv --shapes shapes.tsv --so target.so --stats

    # 查看某个形状组的所有成员
    python3 tools/so_ledger.py inv.tsv --shapes shapes.tsv --group <shape>

输入
----
inv.tsv / shapes.tsv 由 Ghidra 脚本 so_inventory.java 生成。
--so 可选；给了才能做机器形状分类（capstone）。
"""

import argparse
import collections
import io
import json
import re
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    HAVE_CS = True
except ImportError:
    HAVE_CS = False

# ---------------------------------------------------------------- 常量

#: 外部符号判定：这些前缀说明是 libc/libc++/runtime，不是壳自身逻辑
EXTERNAL_PREFIX = (
    "__", "_Z", "_Unwind", "pthread_", "dl", "sig",
    "mem", "str", "sprintf", "snprintf", "sscanf", "atoi", "strto",
    "malloc", "calloc", "realloc", "free", "abort", "exit", "_exit",
    "open", "close", "read", "write", "access", "stat", "fstat", "lstat",
    "mmap", "munmap", "mprotect", "msync", "madvise",
    "prctl", "ptrace", "waitpid", "fork", "exec", "kill", "raise",
    "nanosleep", "usleep", "sleep", "clock_gettime", "gettimeofday",
    "socket", "connect", "send", "recv", "bind", "listen", "accept",
    "fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fflush",
    "syscall", "getpid", "gettid", "getuid", "geteuid", "sem_",
    "vsnprintf", "strlen", "strcmp", "strncmp", "strstr", "strchr",
    "strcpy", "strncpy", "strcat", "strncat", "strdup", "strndup",
    "memcpy", "memmove", "memset", "memcmp",
)

#: 占位名：反编译器自动生成、没有任何语义，是批量重命名的合法目标。
PLACEHOLDER_PREFIX = (
    "FUN_", "leaf_", "frag_", "cff_", "sprintf_inline_", "mprot_",
)

#: 机械名：由本工具或人工按机器特征产出，已处理完，不该再进队列。
MECHANICAL_PREFIX = (
    "ffi_pop", "thunk_", "tail_", "one_", "empty_",
)

#: 「前缀 + 纯地址」形式才算占位（如 vm_1e2e10）；
#: 带词根的是语义名（vm_push / dl_iterate_phdr），必须保护。
ADDR_ONLY_RE = re.compile(r"^(vm|dl|ptr|cff|thunk|tail|one)_[0-9a-f]{6,}$", re.I)


def is_external(name):
    return name.startswith(EXTERNAL_PREFIX)


def is_generated(name):
    """是否是「没有语义的占位名」—— 批量重命名只允许改这类。"""
    if name.startswith(PLACEHOLDER_PREFIX):
        return True
    return bool(ADDR_ONLY_RE.match(name))


def is_mechanical(name):
    """是否是「已完成的机械命名」—— 不再进工作队列。"""
    return name.startswith(MECHANICAL_PREFIX)


def is_semantic(name):
    """是否是有证据支撑的语义名。"""
    return not is_generated(name) and not is_mechanical(name)


# ---------------------------------------------------------------- 读取

def read_tsv(path):
    rows = []
    with io.open(path, encoding="utf-8") as f:
        header = f.readline().rstrip("\n").split("\t")
        for ln in f:
            p = ln.rstrip("\n").split("\t")
            if len(p) < len(header):
                p += [""] * (len(header) - len(p))
            rows.append(dict(zip(header, p)))
    return rows


def load_ledger(inv_path, shapes_path):
    inv = read_tsv(inv_path)
    shapes = {r["name"]: r for r in read_tsv(shapes_path)}
    out = []
    for r in inv:
        r["size"] = int(r["size"])
        r["insns"] = int(r["insns"])
        r["nparam"] = int(r["nparam"])
        r["callers"] = int(r["callers"])
        r["callees"] = int(r["callees"])
        r["nCodeRefs"] = int(r["nCodeRefs"])
        r["nDataRefs"] = int(r["nDataRefs"])
        r.setdefault("parentNs", "")
        s = shapes.get(r["name"])
        r["shape"] = s["shape"] if s else "?"
        out.append(r)
    return out


# ---------------------------------------------------------------- 代码分区

#: 代码分区表。**默认为空**：分区区间是样本事实，不该固化在通用工具里。
#: 用 --regions <json> 提供（格式见 load_regions）；不传时全部落 "shell" 分区，
#: 只少了分类收益，不影响台账与命名。
DEFAULT_REGIONS = []


def load_regions(path):
    """从 JSON 加载分区表。格式：
    [{"lo": "0x1bd8a8", "hi": "0x1c474f", "name": "vm_handler"}, ...]
    """
    import json
    with io.open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for e in data:
        lo = int(e["lo"], 0) if isinstance(e["lo"], str) else e["lo"]
        hi = int(e["hi"], 0) if isinstance(e["hi"], str) else e["hi"]
        out.append((lo, hi, e["name"], e.get("desc", "")))
    return out


def region_of(addr, regions=None):
    """按地址把函数划入结构性分区。

    判据不是函数名前缀，而是**调用边方向性**：
    区内调用边密集、区外进入边极少且来源本身也是库符号。

    分区表由 --regions 提供；未提供时全部落 "shell"。
    """
    for lo, hi, name, _desc in (regions if regions is not None else DEFAULT_REGIONS):
        if lo <= addr <= hi:
            return name
    return "shell"


# ---------------------------------------------------------------- 机器形状分类

class SoImage:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if HAVE_CS else None

    def disasm(self, elf_va, size):
        if self.md is None:
            return []
        return list(self.md.disasm(self.data[elf_va:elf_va + size], elf_va))

    def ptr(self, off):
        if off + 8 > len(self.data):
            return None
        return struct.unpack_from("<Q", self.data, off)[0]


def _reg(op_str):
    """从 op_str 里取第一个寄存器名（小写）。"""
    s = op_str.replace(" ", "")
    if not s:
        return ""
    return s.split(",")[0]


def classify_shape(img, elf_va, size):
    """按机器指令形态判定函数模板类型。

    返回 (kind, detail_dict)
      ffi_bridge  VM 栈参数打包器
      thunk       单条跳转（b/br/ret/nop）
      tailcall    仅末尾一条跳转，无 bl
      one_insn    单条指令
      empty       无指令
      logic       真实逻辑

    FFI 桥接桩的严格判据（必须全部满足，避免把真实逻辑误判）：
      1. 首部存在 `ldr xR,[x0]` —— 从第 1 个参数取出 VM 栈顶指针
      2. 存在 >=2 条 `ldur w?, [xR, #-k]`，**基址寄存器是同一个 R**
         （VM 栈按 4 字节向上生长，参数逐个弹）
      3. 存在 `blr` 或 `br`（间接调用真实函数）
      4. 全函数没有 `bl`（桩本身不直接调已知符号）
    """
    if img is None or img.md is None:
        return "unknown", {}
    ins = img.disasm(elf_va, size)
    if not ins:
        return "empty", {}

    mnems = [i.mnemonic for i in ins]

    # 1) 找 ldr xR,[x0] —— 帧指针寄存器
    frame_reg = None
    for i in ins:
        if i.mnemonic == "ldr":
            dst = _reg(i.op_str)
            src = i.op_str.replace(" ", "").split(",")[-1]
            if src == "[x0]" and dst.startswith("x"):
                frame_reg = dst
                break

    # 2) 统计从 frame_reg 负偏移读取的 32 位弹栈
    pops_w = pops_x = 0
    if frame_reg:
        needle = "[%s,#-" % frame_reg
        for i in ins:
            if i.mnemonic != "ldur":
                continue
            s = i.op_str.replace(" ", "")
            if needle not in s:
                continue
            if _reg(i.op_str).startswith("w"):
                pops_w += 1
            else:
                pops_x += 1

    has_bl = "bl" in mnems
    indirect = "blr" in mnems or "br" in mnems
    total_pops = pops_w + pops_x
    detail = {"pops_w": pops_w, "pops_x": pops_x, "frame_reg": frame_reg,
              "has_bl": has_bl, "indirect": indirect}

    if frame_reg and total_pops >= 2 and indirect and not has_bl:
        return "ffi_bridge", detail
    if len(ins) <= 2 and all(m in ("b", "br", "ret", "nop") for m in mnems):
        return "thunk", detail
    if len(ins) <= 3 and mnems[-1] in ("b", "br") and not has_bl:
        return "tailcall", detail
    if len(ins) == 1:
        return "one_insn", detail
    return "logic", detail


# ---------------------------------------------------------------- 证据分级

def evidence_tier(r):
    """按可判线索的强度分级。

    T1 有字符串引用      —— 直接读串就能定名
    T2 有具名外部调用     —— 调了什么 libc/API 说明用途
    T3 纯逻辑无串无外部   —— 需读伪代码
    T4 机械桩            —— 无需读
    T0 已定名            —— 语义名或已完成的机械名，不在队列里
    X1 CFF case 块       —— switchD_* 命名空间，属于某状态机的一部分
    X2 库代码            —— libc++ 等第三方静态库，不是分析目标
    """
    name = r["name"]
    if not is_generated(name) or is_mechanical(name):
        return "T0_done"
    if r.get("region") == "libcxx":
        return "X2_library"
    if r.get("parentNs", "").startswith("switchD_"):
        return "X1_cff_case"
    if r.get("machine") in ("ffi_bridge", "thunk", "tailcall", "one_insn", "empty"):
        return "T4_mechanical"
    if r["strings"]:
        return "T1_strings"
    ext = [c for c in r["calleeNames"].split("|") if c and is_external(c)]
    if ext:
        return "T2_api"
    return "T3_logic"


def ext_calls(r):
    return sorted(set(c for c in r["calleeNames"].split("|") if c and is_external(c)))


# ---------------------------------------------------------------- 机械命名

def propose_names(rows, img, tables, image_base=0x100000):
    """对机械函数生成重命名建议。

    命名规则（可读、可回溯、不误导）：
      ffi_pop<N>w_<addr>[_t<base>_s<idx>]
                  N=从 VM 栈读取的 32 位槽数（事实测量，非猜测的参数个数）
      thunk_<addr>     单条跳转
      tail_<addr>      尾跳转桩
      one_<addr>       单指令
    地址后缀恒定保留：机械名不携带语义，地址是唯一可靠身份。
    """
    # 表槽位反查：函数地址 -> [(表基址, 索引)]
    slots = collections.defaultdict(list)
    if img is not None:
        elf2row = {int(r["addr"], 16) - image_base: r for r in rows}
        for base, count in tables:
            for i in range(count):
                v = img.ptr(base + i * 8)
                if v is None:
                    continue
                r = elf2row.get(v)
                if r:
                    slots[r["name"]].append((base, i))

    proposals = []
    for r in rows:
        kind = r.get("machine")
        d = r.get("detail", {})
        short = r["addr"][-6:].lower()
        # 已经处理过的跳过：机械名只对生成名生效，不覆盖语义名或既有机械名
        if not is_generated(r["name"]):
            continue
        if kind == "ffi_bridge":
            n = d.get("pops_w", 0) + d.get("pops_x", 0)
            sl = slots.get(r["name"])
            tag = ""
            if sl:
                base, idx = sl[0]
                tag = "_t%x_s%d" % (base, idx)
            proposals.append({
                "addr": r["addr"], "old": r["name"],
                "new": "ffi_pop%dw_%s%s" % (n, short, tag),
                "reason": "FFI bridge: %d 32-bit slot(s) read from VM stack (frame reg %s), "
                          "indirect call, no direct bl" % (n, d.get("frame_reg")),
            })
        elif kind in ("thunk", "tailcall", "one_insn", "empty"):
            base = {"thunk": "thunk_", "tailcall": "tail_",
                    "one_insn": "one_", "empty": "empty_"}[kind]
            proposals.append({
                "addr": r["addr"], "old": r["name"], "new": base + short,
                "reason": "mechanical %s (%d insns)" % (kind, r["insns"]),
            })
    # 去重 + 剔除无变化项
    seen = collections.Counter()
    for p in proposals:
        seen[p["new"]] += 1
    out = []
    for p in proposals:
        if seen[p["new"]] > 1:
            p["new"] += "_" + p["addr"][-4:].lower()
        if p["old"] != p["new"]:
            out.append(p)
    return out


# ---------------------------------------------------------------- 表发现

def discover_tables(img, min_items=4):
    """扫描可写段内所有连续代码指针数组。

    复用 tools/ptr_table.py 的 ELF 段解析（按 PT_LOAD 的 W&&!X 定界），
    不写死任何样本地址区间 —— 换 SO 自动适配。
    """
    try:
        from ptr_table import elf_segments, scan_tables
    except ImportError:
        import os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from ptr_table import elf_segments, scan_tables

    segs = elf_segments(img.data)
    if not segs:
        return []
    return scan_tables(img.data, segs, min_items=min_items)


# ---------------------------------------------------------------- 报告

def build_report(rows, proposals, tables, out_path):
    total = len(rows)
    sem = [r for r in rows if not is_generated(r["name"])]
    gen = [r for r in rows if is_generated(r["name"])]

    tiers = collections.Counter(evidence_tier(r) for r in rows)
    kinds = collections.Counter(r.get("machine", "unknown") for r in rows)

    shapes = collections.defaultdict(list)
    for r in rows:
        shapes[r["shape"]].append(r)
    dup_groups = {k: v for k, v in shapes.items() if len(v) >= 2}

    lines = []
    w = lines.append
    w("# SO 函数台账")
    w("")
    w("由 `tools/so_ledger.py` 从 Ghidra 清单生成。**本文件是工作队列，不是报告。**")
    w("")
    w("## 总览")
    w("")
    w("| 项 | 数量 |")
    w("|---|---|")
    w("| 函数总数（非外部） | %d |" % total)
    w("| 已有语义名 | %d (%.1f%%) |" % (len(sem), 100.0 * len(sem) / total))
    w("| 生成名（待处理） | %d |" % len(gen))
    w("| 去重后不同机器形状 | %d |" % len(shapes))
    w("| 形状重复组（≥2） | %d，覆盖 %d 个函数 |"
      % (len(dup_groups), sum(len(v) for v in dup_groups.values())))
    w("")

    w("## 机器形状分类")
    w("")
    w("| 类型 | 数量 | 说明 | 需读伪代码 |")
    w("|---|---|---|---|")
    desc = {
        "ffi_bridge": ("VM 栈参数打包器：弹参数 + bfi 打包 + 间接调用", "否"),
        "thunk": ("单条跳转", "否"),
        "tailcall": ("尾跳转桩", "否"),
        "one_insn": ("单指令", "否"),
        "empty": ("无指令", "否"),
        "logic": ("真实逻辑", "是"),
        "unknown": ("未分类（未提供 --so）", "?")
    }
    for k in ("ffi_bridge", "thunk", "tailcall", "one_insn", "empty", "logic", "unknown"):
        if kinds[k]:
            w("| `%s` | %d | %s | %s |" % (k, kinds[k], desc[k][0], desc[k][1]))
    w("")

    w("## 证据分级（工作队列优先级）")
    w("")
    w("| 等级 | 数量 | 含义 | 处理方式 |")
    w("|---|---|---|---|")
    tier_desc = {
        "T1_strings": ("有字符串引用", "读串即可定名，最高性价比"),
        "T2_api": ("有具名外部调用", "看调用面推断用途"),
        "T3_logic": ("纯逻辑", "需读伪代码"),
        "T4_mechanical": ("机械桩", "跳过，批量命名"),
        "X1_cff_case": ("CFF 状态机 case 块", "属父函数的一部分，不单独命名"),
        "X2_library": ("libc++ 静态库代码", "非分析目标"),
        "T0_done": ("已定名", "不在队列"),
    }
    for k in ("T1_strings", "T2_api", "T3_logic", "T4_mechanical",
              "X1_cff_case", "X2_library", "T0_done"):
        if tiers[k]:
            w("| %s | %d | %s | %s |" % (k, tiers[k], tier_desc[k][0], tier_desc[k][1]))
    w("")

    w("## 机械命名建议")
    w("")
    w("共 %d 条，可直接批量应用（不涉及语义判断）。" % len(proposals))
    w("")
    w("| 建议前缀 | 数量 |")
    w("|---|---|")
    pref = collections.Counter(p["new"].split("_")[0] for p in proposals)
    for k, v in pref.most_common():
        w("| `%s_*` | %d |" % (k, v))
    w("")

    # 工作队列：T1 -> T2 -> T3，组内按去重收益
    w("## 工作队列")
    w("")
    w("排序依据：证据等级 → 同形状成员数（读一个能覆盖多个）→ 体积。")
    w("")
    for tier in ("T1_strings", "T2_api", "T3_logic"):
        sub = [r for r in rows if evidence_tier(r) == tier]
        if not sub:
            continue
        w("### %s（%d 个）" % (tier, len(sub)))
        w("")
        w("| 地址 | 名称 | 大小 | 形状成员 | 线索 |")
        w("|---|---|---|---|---|")
        sub.sort(key=lambda r: (-len(shapes[r["shape"]]), -r["size"]))
        for r in sub[:60]:
            clue = r["strings"][:50] if r["strings"] else ",".join(ext_calls(r)[:3])
            w("| `%s` | `%s` | %d | %d | %s |"
              % (r["addr"], r["name"], r["size"], len(shapes[r["shape"]]), clue))
        if len(sub) > 60:
            w("| … | 其余 %d 个见 queue.tsv | | | |" % (len(sub) - 60))
        w("")

    with io.open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return "\n".join(lines)


def write_queue(rows, shapes, out_path):
    """输出完整工作队列（TSV），供后续批量处理。"""
    order = {"T1_strings": 0, "T2_api": 1, "T3_logic": 2, "T4_mechanical": 3,
             "X1_cff_case": 4, "X2_library": 5, "T0_done": 6}
    with io.open(out_path, "w", encoding="utf-8") as f:
        f.write("tier\taddr\tname\tsize\tinsns\tshape\tgroup_size\tnparam\tstrings\tapi_calls\tmachine\tregion\tparent_ns\n")
        for r in sorted(rows, key=lambda r: (order[evidence_tier(r)],
                                             -len(shapes[r["shape"]]), -r["size"])):
            f.write("\t".join([
                evidence_tier(r), r["addr"], r["name"], str(r["size"]), str(r["insns"]),
                r["shape"], str(len(shapes[r["shape"]])), str(r["nparam"]),
                r["strings"][:120], ",".join(ext_calls(r)[:6]), r.get("machine", "?"),
                r.get("region", "?"), r.get("parentNs", ""),
            ]) + "\n")


def write_rename(proposals, out_path):
    with io.open(out_path, "w", encoding="utf-8") as f:
        f.write("addr\told\tnew\treason\n")
        for p in proposals:
            f.write("%s\t%s\t%s\t%s\n" % (p["addr"], p["old"], p["new"], p["reason"]))


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="SO 函数台账分析")
    ap.add_argument("inv", help="so_inventory.java 导出的清单 TSV")
    ap.add_argument("--shapes", required=True, help="形状指纹 TSV")
    ap.add_argument("--so", help="目标 SO（提供才能做机器形状分类）")
    ap.add_argument("--report", help="输出台账报告 Markdown")
    ap.add_argument("--queue", help="输出完整工作队列 TSV")
    ap.add_argument("--rename", help="输出重命名建议 TSV")
    ap.add_argument("--stats", action="store_true", help="只打印统计")
    ap.add_argument("--group", help="查看某个形状组的全部成员")
    ap.add_argument("--regions",
                    help="代码分区表 JSON（样本提供；不传则全部落 shell 分区）")
    ap.add_argument("--image-base", type=lambda s: int(s, 0), default=0x100000,
                    help="Ghidra 镜像基址：ELF 偏移 = 台账地址 - image_base"
                         "（默认 0x100000，用 ghidra_get_current_program_info 确认）")
    ap.add_argument("--max-empty", type=float, default=0.05,
                    help="不可反汇编函数占比上限（默认 0.05）。超过即判定 --so 不是"
                         "脱壳镜像，拒绝写 --rename 并以退出码 1 结束；"
                         "确认无误可设 1 跳过")
    args = ap.parse_args()

    rows = load_ledger(args.inv, args.shapes)
    img = SoImage(args.so) if args.so else None
    if args.so and not HAVE_CS:
        print("警告：未安装 capstone，跳过机器形状分类", file=sys.stderr)

    tables = []
    if img is not None:
        tables = discover_tables(img)
    regions = load_regions(args.regions) if args.regions else DEFAULT_REGIONS
    for r in rows:
        r["region"] = region_of(int(r["addr"], 16), regions)
        if img is not None:
            elf = int(r["addr"], 16) - args.image_base
            kind, detail = classify_shape(img, elf, r["size"])
            r["machine"] = kind
            r["detail"] = detail
        else:
            r["machine"] = "unknown"
            r["detail"] = {}

    shapes = collections.defaultdict(list)
    for r in rows:
        shapes[r["shape"]].append(r)

    if args.group:
        members = shapes.get(args.group, [])
        print("形状 %s: %d 个成员" % (args.group, len(members)))
        for m in members:
            print("  %s %-24s %5dB %3d insns" % (m["addr"], m["name"], m["size"], m["insns"]))
        return

    tiers = collections.Counter(evidence_tier(r) for r in rows)
    kinds = collections.Counter(r["machine"] for r in rows)
    regions = collections.Counter(r.get("region", "?") for r in rows)
    proposals = propose_names(rows, img, tables, args.image_base) if img is not None else []

    total = len(rows)
    empty_ratio = (kinds.get("empty", 0) / float(total)) if total else 0.0
    mirror_suspect = empty_ratio > args.max_empty

    if args.stats or not (args.report or args.queue or args.rename):
        sem = sum(1 for r in rows if is_semantic(r["name"]))
        mech = sum(1 for r in rows if is_mechanical(r["name"]))
        print("=== 台账统计 ===")
        print("  函数总数      %d" % total)
        print("  语义名        %d (%.1f%%)" % (sem, 100.0 * sem / total))
        print("  已完成机械名  %d (%.1f%%)" % (mech, 100.0 * mech / total))
        print("  不同形状      %d" % len(shapes))
        print("  不可反汇编    %d (%.1f%%)%s" % (
            kinds.get("empty", 0), 100.0 * empty_ratio,
            "   <- 超过 %.0f%%，--so 可能不是脱壳镜像" % (args.max_empty * 100)
            if mirror_suspect else ""))
        print()
        print("  代码分区:")
        for k, v in regions.most_common():
            print("    %-12s %4d (%.1f%%)" % (k, v, 100.0 * v / total))
        print()
        print("  机器形状:")
        for k, v in kinds.most_common():
            print("    %-12s %4d (%.1f%%)" % (k, v, 100.0 * v / total))
        print()
        print("  证据分级:")
        for k, v in tiers.most_common():
            print("    %-14s %4d (%.1f%%)" % (k, v, 100.0 * v / total))
        if proposals:
            print()
            print("  待应用机械命名  %d 条" % len(proposals))
        print()
        print("  发现的指针表  %d 张" % len(tables))
        return

    if mirror_suspect:
        print("[!] 不可反汇编占比 %.1f%% > %.0f%%：--so 很可能不是脱壳后的镜像"
              "（.text 仍是密文）。换成 dump 出来的 clean 镜像再试；"
              "确认无误可加 --max-empty 1 跳过本检查。"
              % (100.0 * empty_ratio, args.max_empty * 100), file=sys.stderr)
        if args.rename:
            print("[!] 已拒绝写重命名建议（错误输入会批量覆盖真函数名）",
                  file=sys.stderr)
            args.rename = None

    if args.report:
        build_report(rows, proposals, tables, args.report)
        print("报告 -> %s" % args.report)
    if args.queue:
        write_queue(rows, shapes, args.queue)
        print("队列 -> %s" % args.queue)
    if args.rename:
        write_rename(proposals, args.rename)
        print("重命名建议 %d 条 -> %s" % (len(proposals), args.rename))

    return 1 if mirror_suspect else 0


if __name__ == "__main__":
    sys.exit(main())
