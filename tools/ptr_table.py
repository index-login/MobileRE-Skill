#!/usr/bin/env python3
"""
ptr_table.py — ELF 指针表枚举与分类（通用）

用途
----
从任意 ELF（尤其是加固/脱壳后的 SO）里找出所有"连续代码指针数组"，
并按目标地址的语义分类。适用于：
  - 定位 VM 的 opcode 分派表 / handler 表
  - 定位 FFI 桩表 / 虚函数表 / 配置表
  - 判断某地址是否被某张表引用（反查表槽位）

与样本专用工具的分工
--------------------
本工具只做**机械枚举与分类**，不理解任何 VM 的编码格式。
某套 VM 的 opcode 语义、指令长度、操作数布局属于该样本的知识，
放在 `<包名>/tools/` 下，通过 profile 引用本工具的输出。

用法
----
    # 扫描所有指针表（默认扫 RW 段）
    python3 tools/ptr_table.py <so> --scan

    # 只看代码指针表（排除字符串表）
    python3 tools/ptr_table.py <so> --scan --only-code

    # 分析指定表
    python3 tools/ptr_table.py <so> --tbl 0x10c7c0

    # 反查：哪些表的哪个槽位指向该地址
    python3 tools/ptr_table.py <so> --xref 0xe1648

    # JSON 输出
    python3 tools/ptr_table.py <so> --scan --json
"""

import argparse
import json
import struct
import sys

# 指针值落在这些区间时的分类（可按需覆盖）
DEFAULT_RANGES = [
    # (lo, hi, 名称, 说明)
    (0x7800000000, 0x7900000000, "rt_snapshot", "运行时快照（libc 堆/栈地址残留）"),
]

# 小于该值的指针视为"小整数或加密数据"，不是有效地址
SMALL_PTR_MAX = 0x10000


def load(path):
    with open(path, "rb") as f:
        return f.read()


def read_q(data, va):
    """读 8 字节小端；越界返回 None。"""
    if va < 0 or va + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, va)[0]


def cstr(data, va, maxlen=200):
    """读 C 字符串；不可打印、超长或越界返回 None。"""
    if va is None or va < 0 or va >= len(data):
        return None
    end = data.find(b"\x00", va)
    if end < 0 or end - va > maxlen or end == va:
        return None
    seg = data[va:end]
    try:
        s = seg.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if all(32 <= ord(c) < 127 for c in s) else None


def elf_segments(data):
    """解析 PT_LOAD，返回 [(vaddr, filesz, flags)]。

    flags: 1=X 2=W 4=R（ELF p_flags 位）
    """
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, o)[0]
        if p_type != 1:      # PT_LOAD
            continue
        p_offset = struct.unpack_from("<Q", data, o + 8)[0]
        p_vaddr = struct.unpack_from("<Q", data, o + 16)[0]
        p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
        p_flags = struct.unpack_from("<I", data, o + 4)[0]
        segs.append((p_vaddr, p_offset, p_filesz, p_flags))
    return segs


def code_ranges(segs, data=None):
    """可执行段的 [lo, hi) 列表（用文件内偏移表示）。

    第一个 PT_LOAD 常把 ELF 头、程序头、.dynsym、.dynstr 一起包进可执行段
    （本样本 0x0..0x42000 全是元数据，真正的代码在下一个段）。
    判据：若某可执行段的起始偏移处不是有效指令，整段视为元数据区跳过。
    """
    out = []
    for (va, off, fsz, fl) in segs:
        if not (fl & 1):
            continue
        if data is not None and off == 0:
            # 首段从 0 起：检查 0x1000 处是否是代码
            if not _looks_like_code(data, 0x1000):
                continue
        out.append((off, off + fsz))
    return out


def _looks_like_code(data, off):
    """粗略判断该偏移处是否像 AArch64 指令序列。

    判据：连续 4 条 4 字节对齐的指令，且至少 3 条的高位字节符合
    AArch64 编码特征（非全 0、非全 0xff、非纯 ASCII）。
    """
    if off + 16 > len(data):
        return False
    good = 0
    for i in range(4):
        w = struct.unpack_from("<I", data, off + i * 4)[0]
        if w == 0 or w == 0xFFFFFFFF:
            continue
        # 纯 ASCII 四字节（如 "test"）不是指令
        b = struct.pack("<I", w)
        if all(32 <= c < 127 for c in b):
            continue
        good += 1
    return good >= 3


def data_ranges(segs):
    """可写且非可执行段的 [lo, hi) 列表——指针表通常在这里。"""
    return [(off, off + fsz) for (va, off, fsz, fl) in segs if (fl & 2) and not (fl & 1)]


def classify_ptr(data, v, code, extra_ranges):
    """给单个指针值分类。

    返回 (kind, text)
      null        0
      code        落在可执行段
      string      指向可打印 C 字符串
      rt_snapshot 落在运行时快照区间
      small       小于 SMALL_PTR_MAX（小整数 / 加密数据）
      data        落在文件内的数据段
      external    超出文件范围（运行时地址）
    """
    if v == 0:
        return "null", None
    for lo, hi in code:
        if lo <= v < hi:
            return "code", None
    s = cstr(data, v)
    if s:
        return "string", s
    for lo, hi, name, _desc in extra_ranges:
        if lo <= v < hi:
            return name, None
    if v < SMALL_PTR_MAX:
        return "small", None
    if 0 <= v < len(data):
        return "data", None
    return "external", None


def scan_tables(data, segs, min_items=4, ranges=None):
    """在数据段里扫描连续指针数组。

    判据：连续 >= min_items 个 8 字节值，每个都是"有效指针"
    （代码 / 字符串 / 数据段内地址）。遇到 0 或无效值终止。
    """
    code = code_ranges(segs, data)
    extra = ranges or []
    lo_hi = data_ranges(segs)
    if not lo_hi:
        # 没有 RW 段时退回全文件扫
        lo_hi = [(0, len(data))]

    def valid(v):
        if v == 0 or v >= len(data):
            return False
        for a, b in code:
            if a <= v < b:
                return True
        if cstr(data, v):
            return True
        for a, b in lo_hi:
            if a <= v < b:
                return True
        return False

    runs = []
    for lo, hi in lo_hi:
        va = (lo + 7) & ~7
        while va + 8 * min_items <= hi:
            if not valid(read_q(data, va)):
                va += 8
                continue
            start, cnt = va, 0
            while va + 8 <= hi:
                v = read_q(data, va)
                if v == 0:
                    break
                if not valid(v):
                    break
                cnt += 1
                va += 8
            if cnt >= min_items:
                runs.append((start, cnt))
    return runs


def analyze_table(data, base, limit=8192, ranges=None):
    """读一张表，逐项分类。遇到 0 终止。"""
    code = code_ranges(elf_segments(data), data)
    extra = ranges or []
    entries = []
    for i in range(limit):
        v = read_q(data, base + i * 8)
        if v is None:
            break
        kind, text = classify_ptr(data, v, code, extra)
        entries.append({"idx": i, "value": v, "kind": kind, "text": text})
        if v == 0:
            break
    kinds = {}
    for e in entries:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    return entries, {"base": base, "count": len(entries),
                     "end": base + len(entries) * 8, "kinds": kinds}


def find_xrefs(data, target, segs, ranges=None, min_items=4):
    """反查：哪些表的哪个槽位指向 target。"""
    hits = []
    for base, cnt in scan_tables(data, segs, min_items, ranges):
        for i in range(cnt):
            if read_q(data, base + i * 8) == target:
                hits.append({"table": base, "slot": i, "table_size": cnt})
    return hits


def classify_vm_table(count):
    """给"全代码指针表"猜它在 VM 里的角色（只是线索，不是结论）。

    VM 壳通常有两张相邻的纯代码指针表：
      handler 表       按 opcode 索引，项数一般不是 2 的幂（如 138）
      continuation 表  紧随其后，项数明显更多（如 593）
    项数恰好 2 的幂（256/512）时更可能是按 opcode 全展开的表。
    """
    if count <= 0:
        return ""
    if count & (count - 1) == 0:
        return "opcode 表候选（项数=2^n，全展开）"
    return "handler 表候选（项数非 2^n，需与相邻表配对确认）"


def main():
    ap = argparse.ArgumentParser(
        description="ELF 指针表枚举与分类（通用）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 tools/ptr_table.py target.so --scan
  python3 tools/ptr_table.py target.so --scan --only-code
  python3 tools/ptr_table.py target.so --tbl 0x10c7c0
  python3 tools/ptr_table.py target.so --xref 0xe1648
""")
    ap.add_argument("so", help="目标 ELF")
    ap.add_argument("--scan", action="store_true", help="扫描所有指针表")
    ap.add_argument("--tbl", help="分析指定表（ELF VA）")
    ap.add_argument("--xref", help="反查该地址被哪些表引用（ELF VA）")
    ap.add_argument("--only-code", action="store_true",
                    help="只列出目标全为代码指针的表")
    ap.add_argument("--min-items", type=int, default=4,
                    help="表最少项数（默认 4）")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("--classify", choices=["vm"],
                    help="给 --scan 结果加角色标注（vm = handler/opcode 表线索）")
    args = ap.parse_args()

    data = load(args.so)
    segs = elf_segments(data)
    if not segs:
        print("不是 ELF64 或解析失败", file=sys.stderr)
        sys.exit(1)
    code = code_ranges(segs, data)

    if args.xref:
        target = int(args.xref, 0)
        hits = find_xrefs(data, target, segs, DEFAULT_RANGES, args.min_items)
        if args.json:
            print(json.dumps(hits, ensure_ascii=False, indent=1))
            return
        if not hits:
            print("0x%x 未被任何指针表引用" % target)
            return
        print("=== 0x%x 被 %d 处引用 ===" % (target, len(hits)))
        for h in hits:
            print("  表 @0x%06x  [%d] / %d 项" % (h["table"], h["slot"], h["table_size"]))
        return

    if args.tbl:
        base = int(args.tbl, 0)
        entries, meta = analyze_table(data, base, ranges=DEFAULT_RANGES)
        if args.json:
            print(json.dumps({"meta": meta, "entries": entries},
                             ensure_ascii=False, indent=1))
            return
        print("=== 表 @0x%06x  %d 项，结束于 0x%x ===" % (base, meta["count"], meta["end"]))
        print("  类型分布: " + ", ".join("%s×%d" % (k, v)
                                       for k, v in sorted(meta["kinds"].items())))
        print()
        print("  %5s  %18s  %-14s %s" % ("idx", "value", "kind", "text"))
        for e in entries:
            print("  %5d  0x%016x  %-14s %s"
                  % (e["idx"], e["value"], e["kind"], e["text"] or ""))
        return

    if args.scan:
        runs = scan_tables(data, segs, args.min_items, DEFAULT_RANGES)
        out = []
        for base, cnt in runs:
            entries, meta = analyze_table(data, base, limit=cnt, ranges=DEFAULT_RANGES)
            kinds = meta["kinds"]
            if args.only_code and kinds.get("code", 0) != cnt:
                continue
            row = {"base": base, "count": cnt, "kinds": kinds}
            if args.classify == "vm":
                row["role"] = classify_vm_table(cnt)
            out.append(row)
        if args.json:
            print(json.dumps(out, ensure_ascii=False, indent=1))
            return
        print("=== 扫描到 %d 张指针表 ===" % len(out))
        for t in out:
            desc = ", ".join("%s×%d" % (k, v) for k, v in sorted(t["kinds"].items()))
            role = ("  <- %s" % t["role"]) if t.get("role") else ""
            print("  @0x%06x  %4d 项  [%s]%s" % (t["base"], t["count"], desc, role))
        if args.classify == "vm":
            print()
            print("role 判据：全代码指针 + 表长非 2 的幂 → handler 表候选；")
            print("          表长恰好 2 的幂 → 可能是 256 项 opcode 表（多数壳）；")
            print("          紧跟其后还有一张纯代码表 → 前者是 handler 表、后者是 continuation 表。")
        return

    ap.print_help()


if __name__ == "__main__":
    main()
