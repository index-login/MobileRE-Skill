#!/usr/bin/env python3
"""
probe_layout.py — 动态探测结构体布局（通用）

用途
----
静态推断结构体字段反复出错，因为同一个参数寄存器在不同函数里
指向完全不同的结构（哈希表 / 单例缓存 / VM arena / JNI 包装）。

本工具在 Unicorn 里跑起目标 SO，调用指定入口，然后按偏移采样，
记录每个 8 字节槽位的真实内容类型（代码指针 / 数据指针 / 小整数 /
字符串 / 空），输出可直接转成 Ghidra StructureDataType 的表格。

与样本专用工具的分工
--------------------
本工具按 **PT_LOAD 段**自动定界，不硬编码任何地址区间；
环境准备（重定位、GOT、JNI 桩）通过 `--setup` 交给样本专属脚本。
某样本特有的入口地址、全局变量地址属于该样本的知识，
放在 `<包名>/tools/` 下（如 `probe_struct.py` / `probe_ctx.py`）。

用法
----
    # dump 一个全局结构（调用入口后）
    python3 tools/probe_layout.py <so> --entry JNI_OnLoad --at 0x<全局地址> --size 0x100

    # 抓函数参数的指向结构
    python3 tools/probe_layout.py <so> --entry JNI_OnLoad --hook 0xe2e00 --arg X0 --size 0x60

    # 自动扫描
    python3 tools/probe_layout.py <so> --entry JNI_OnLoad --at 0x<全局地址> --auto --limit 0x200

    # 指针追踪
    python3 tools/probe_layout.py <so> --entry JNI_OnLoad --at 0x<全局地址> --size 8 --chase 0

    # 复杂环境：先跑 setup 脚本准备 GOT/JNI/桩
    python3 tools/probe_layout.py <so> --setup my_env.py --entry JNI_OnLoad --at 0x<全局地址>

setup 脚本约定
--------------
脚本里定义一个函数：

    def prepare(h, so_path, data):
        '''把 h 的地址空间准备到能调 entry 的状态。'''
        ...

其中 h 是 uniharness.Harness 实例，data 是 SO 的 bytes。

输出
----
    offset  value               kind          note
    +0x000  0x00000000000fd9b0  code_ptr
    +0x008  0x0000000010011688  arena_ptr
    +0x0b0  0x000000000000001d  small_int     29
"""

import argparse
import importlib.util
import struct
import sys
from pathlib import Path

# 依赖同目录的通用仿真库
sys.path.insert(0, str(Path(__file__).resolve().parent))

from uniharness import Harness  # noqa: E402


def elf_segments(data):
    """解析 PT_LOAD，返回 [(vaddr, memsz, flags)]。"""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_vaddr = struct.unpack_from("<Q", data, o + 16)[0]
        p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
        p_memsz = struct.unpack_from("<Q", data, o + 40)[0]
        p_flags = struct.unpack_from("<I", data, o + 4)[0]
        out.append((p_vaddr, p_memsz or p_filesz, p_flags))
    return out


class Layout:
    """按 ELF 段划分地址区间，用于给采样值分类。"""

    def __init__(self, data):
        self.segs = elf_segments(data)
        self.code = [(va, va + sz) for va, sz, fl in self.segs if fl & 1]
        self.rodata = [(va, va + sz) for va, sz, fl in self.segs
                       if (fl & 4) and not (fl & 2) and not (fl & 1)]
        self.data = [(va, va + sz) for va, sz, fl in self.segs
                     if (fl & 2) and not (fl & 1)]

    @staticmethod
    def _in(ranges, v):
        return any(a <= v < b for a, b in ranges)

    def classify(self, h, v):
        """给一个 8 字节值分类。返回 (kind, note)。"""
        if v == 0:
            return "null", ""
        if self._in(self.code, v):
            return "code_ptr", ""
        if self._in(self.rodata, v):
            return "rodata_ptr", ""
        if self._in(self.data, v):
            return "data_ptr", ""
        # 仿真 arena（uniharness 默认 0x10000000 起）
        if 0x10000000 <= v < 0x20000000:
            return "arena_ptr", ""
        # 运行时地址（libc / ART 内部）
        if 0x7000000000 <= v < 0x7A00000000:
            return "runtime_ptr", ""
        if v <= 0x10000:
            return "small_int", str(v)
        # 尝试当字符串读
        try:
            raw = h.read(v, 40)
            printable = sum(1 for b in raw if 32 <= b < 127)
            if printable >= 30:
                end = raw.find(b"\x00")
                s = raw[:end if end > 0 else 40].decode("utf-8", "replace")
                return "string_ptr", s
        except Exception:
            pass
        return "other", ""


def dump(h, lay, base, size, label=""):
    print("--- %s @ 0x%x (%d bytes) ---" % (label or "dump", base, size))
    try:
        raw = h.read(base, size)
    except Exception as exc:  # noqa: BLE001
        print("  读取失败: %s" % exc)
        return []
    rows = []
    for off in range(0, size, 8):
        if off + 8 > len(raw):
            break
        v = struct.unpack_from("<Q", raw, off)[0]
        kind, note = lay.classify(h, v)
        rows.append((off, v, kind, note))
        print("  +0x%03x  0x%016x  %-12s %s" % (off, v, kind, note))
    return rows


def probe_offsets(h, lay, base, offsets):
    rows = []
    for off in offsets:
        try:
            raw = h.read(base + off, 8)
            v = struct.unpack_from("<Q", raw)[0]
            kind, note = lay.classify(h, v)
            rows.append((off, v, kind, note))
            print("  +0x%03x  0x%016x  %-12s %s" % (off, v, kind, note))
        except Exception as exc:  # noqa: BLE001
            print("  +0x%03x  <读取失败: %s>" % (off, exc))
    return rows


def capture_reg(h, pc, reg_name):
    """在 pc 处抓一次寄存器值（代码 hook + 回调）。"""
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    )
    REGS = {
        "X0": UC_ARM64_REG_X0, "X1": UC_ARM64_REG_X1, "X2": UC_ARM64_REG_X2,
        "X3": UC_ARM64_REG_X3, "X4": UC_ARM64_REG_X4, "X5": UC_ARM64_REG_X5,
        "X6": UC_ARM64_REG_X6, "X7": UC_ARM64_REG_X7,
    }
    reg = REGS.get(reg_name.upper())
    if reg is None:
        raise ValueError("不支持的寄存器: %s（支持 X0..X7）" % reg_name)
    captured = {"value": None}

    def _cb(uc, address, size, user_data):
        if captured["value"] is None:
            captured["value"] = uc.reg_read(reg)

    h.hook(pc, pc, _cb)
    return captured


def capture_regs_multi(h, pcs, size, reg_names=("X0", "X1", "X2", "X3", "X4", "X5")):
    """在多个 PC 处各抓一次寄存器组 + 第 1 参指向的内存（首次命中为准）。

    返回 {pc: {"regs": [v0..v5], "mem": bytes|None}}。
    用于"一个入口跑一遍，同时看几个函数收到什么"（省掉逐个 PC 重跑）。
    """
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5,
    )
    REGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
            UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5]
    out = {}

    def make_cb(pc):
        def _cb(uc, address, size_, user_data):
            if pc in out:
                return
            vals = [uc.reg_read(r) for r in REGS]
            entry = {"regs": vals, "mem": None}
            if size > 0 and vals[0]:
                try:
                    entry["mem"] = bytes(uc.mem_read(vals[0], size))
                except Exception:  # noqa: BLE001
                    pass
            out[pc] = entry
        return _cb

    for pc in pcs:
        h.hook(pc, pc, make_cb(pc))
    return out


def load_setup(path):
    """加载 setup 脚本，返回其中的 prepare(h, so_path, data)。"""
    spec = importlib.util.spec_from_file_location("probe_setup", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, "prepare", None)
    if fn is None:
        raise AttributeError("%s 里没有 prepare(h, so_path, data) 函数" % path)
    return fn


def resolve_entry(data, entry):
    """把入口（符号名或地址）解析成 ELF VA。

    符号名从 .dynsym 查；纯数字按地址处理。
    """
    s = entry.strip()
    if s.lower().startswith("0x") or s.isdigit():
        return int(s, 0)

    # 解析 .dynsym
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("不是 ELF64，无法按符号名解析入口")
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    dyn = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] == 2:      # PT_DYNAMIC
            dyn = (struct.unpack_from("<Q", data, o + 8)[0],
                   struct.unpack_from("<Q", data, o + 32)[0])
            break
    if dyn is None:
        raise ValueError("没有 PT_DYNAMIC，无法按符号名解析入口")

    strtab = symtab = None
    symsz = 24
    o = dyn[0]
    while o < dyn[0] + dyn[1]:
        tag = struct.unpack_from("<q", data, o)[0]
        val = struct.unpack_from("<Q", data, o + 8)[0]
        if tag == 0:
            break
        if tag == 5:      # DT_STRTAB
            strtab = val
        elif tag == 6:    # DT_SYMTAB
            symtab = val
        elif tag == 11:   # DT_SYMENT
            symsz = val
        o += 16
    if strtab is None or symtab is None:
        raise ValueError("缺 DT_STRTAB / DT_SYMTAB")

    # 遍历 dynsym（用 DT_HASH 的 nchain 或 DT_GNU_HASH 估算；这里用保守上限）
    for idx in range(4096):
        base = symtab + idx * symsz
        if base + symsz > len(data):
            break
        st_name = struct.unpack_from("<I", data, base)[0]
        st_value = struct.unpack_from("<Q", data, base + 8)[0]
        st_shndx = struct.unpack_from("<H", data, base + 6)[0]
        if st_name == 0 or st_shndx == 0 or st_value == 0:
            continue
        end = data.find(b"\x00", strtab + st_name)
        if end < 0:
            continue
        name = data[strtab + st_name:end].decode("utf-8", "replace")
        if name == s:
            return st_value
    raise ValueError("符号 %s 未在 .dynsym 中找到" % s)


def main():
    ap = argparse.ArgumentParser(
        description="动态探测结构体布局（通用）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 tools/probe_layout.py <so> --entry JNI_OnLoad --at 0x<全局地址> --size 0x100
  python3 tools/probe_layout.py <so> --entry JNI_OnLoad --hook 0xe2e00 --arg X0
  python3 tools/probe_layout.py <so> --setup my_env.py --entry JNI_OnLoad --at 0x<全局地址>
""")
    ap.add_argument("so", help="目标 SO")
    ap.add_argument("--entry", default="JNI_OnLoad",
                    help="入口符号名或地址（默认 JNI_OnLoad）")
    ap.add_argument("--setup", help="环境准备脚本（定义 prepare(h, so_path, data)）")
    ap.add_argument("--at", help="dump 该固定地址（ELF VA）")
    ap.add_argument("--hook", help="在该 PC 处抓参数（ELF VA）")
    ap.add_argument("--arg", default="X0", help="--hook 时抓哪个寄存器（默认 X0）")
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0x100,
                    help="dump 字节数（默认 0x100）")
    ap.add_argument("--offsets", default="",
                    help="只采样这些偏移，逗号分隔（如 0,8,0x10）")
    ap.add_argument("--auto", action="store_true", help="扫描 0..limit")
    ap.add_argument("--limit", type=lambda s: int(s, 0), default=0x200,
                    help="自动扫描上限（默认 0x200）")
    ap.add_argument("--chase", type=lambda s: int(s, 0), default=None,
                    help="dump 后跟进该偏移处的指针，再 dump 一次")
    ap.add_argument("--chase-size", type=lambda s: int(s, 0), default=0x40,
                    help="跟进后 dump 的字节数（默认 0x40）")
    ap.add_argument("--timeout", type=int, default=5, help="仿真超时秒数")
    ap.add_argument("--multi-hook", default="",
                    help="在多个 PC 各抓 x0..x5 + 第 1 参内存（逗号分隔，如 0xbd624,0xe2e00）")
    ap.add_argument("--multi-size", type=lambda s: int(s, 0), default=0x60,
                    help="--multi-hook 每个 PC 抓取的内存字节数（默认 0x60）")
    args = ap.parse_args()

    data = Path(args.so).read_bytes()
    lay = Layout(data)
    try:
        entry_addr = resolve_entry(data, args.entry)
    except ValueError as exc:
        print("入口解析失败: %s" % exc, file=sys.stderr)
        return

    h = Harness()
    h.map_elf(args.so)
    h.setup_stack()
    h.setup_tls()

    call_args = ()
    if args.setup:
        prepare = load_setup(args.setup)
        ret = prepare(h, args.so, data)
        # setup 可返回单值（作为入口第 1 参数）或元组
        if ret is None:
            call_args = ()
        elif isinstance(ret, tuple):
            call_args = ret
        else:
            call_args = (ret,)

    multi = {}
    multi_pcs = []
    if args.multi_hook:
        multi_pcs = [int(x, 0) for x in args.multi_hook.split(",") if x.strip()]
        multi = capture_regs_multi(h, multi_pcs, args.multi_size)

    base = None
    if args.hook:
        pc = int(args.hook, 0)
        cap = capture_reg(h, pc, args.arg)
        try:
            h.call(entry_addr, args=call_args)
        except Exception as exc:  # noqa: BLE001
            print("调用入口失败: %s" % exc, file=sys.stderr)
            return
        base = cap["value"]
        if base is None:
            print("未在 0x%x 处捕获到 %s" % (pc, args.arg), file=sys.stderr)
            return
        print("捕获 %s = 0x%x" % (args.arg, base))
    else:
        try:
            h.call(entry_addr, args=call_args)
        except Exception as exc:  # noqa: BLE001
            print("调用入口失败: %s" % exc, file=sys.stderr)
            return
        if args.at:
            base = int(args.at, 0)
        elif not multi_pcs:
            print("需要 --at / --hook / --multi-hook 之一", file=sys.stderr)
            return

    if multi_pcs:
        print("\n=== multi-hook captures ===")
        for pc in multi_pcs:
            e = multi.get(pc)
            if not e:
                print("\n  hook 0x%x: 未命中" % pc)
                continue
            print("\n  hook 0x%x:" % pc)
            print("    " + " ".join("x%d=0x%x" % (i, v) for i, v in enumerate(e["regs"])))
            if e["mem"]:
                print("    [x0] %d bytes:" % len(e["mem"]))
                for off in range(0, len(e["mem"]), 8):
                    chunk = e["mem"][off:off + 8]
                    if len(chunk) < 8:
                        break
                    v = struct.unpack_from("<Q", chunk)[0]
                    kind, note = lay.classify(h, v)
                    print("      +0x%03x  0x%016x  %-12s %s" % (off, v, kind, note))

    if base is None:
        return

    if args.offsets:
        offs = [int(x, 0) for x in args.offsets.split(",") if x.strip()]
        probe_offsets(h, lay, base, offs)
    elif args.auto:
        dump(h, lay, base, args.limit, "auto-scan")
    else:
        dump(h, lay, base, args.size)

    if args.chase is not None:
        try:
            raw = h.read(base + args.chase, 8)
            ptr = struct.unpack("<Q", raw)[0]
            print()
            print("跟进 +0x%x -> 0x%x" % (args.chase, ptr))
            dump(h, lay, ptr, args.chase_size, "chase")
        except Exception as exc:  # noqa: BLE001
            print("跟进失败: %s" % exc, file=sys.stderr)


if __name__ == "__main__":
    main()
