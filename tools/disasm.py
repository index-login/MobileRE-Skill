#!/usr/bin/env python3
"""disasm.py — 快速反汇编（capstone，无需 Ghidra）

用法:
  python3 disasm.py libfoo.so --symbol Java_com_x_Y_z
  python3 disasm.py libfoo.so --addr 0xdac --size 236
  python3 disasm.py libfoo.so --addr 0x8a0 --size 0x5f8 --count 40
  python3 disasm.py libfoo.so --addr 0x10e0 --count 520            # 自动放宽窗口
  python3 disasm.py libfoo.so --addr 0x10e0 --size 0x1500 --grep "blr|ret"

说明: 地址是 ELF vaddr，`elfinfo.py` 输出的导出/段地址可直接使用。
      不传 --size 时默认窗口 0x100 字节；给了 --count 会自动放宽到够用，
      窗口耗尽会打印 [!] 截断提示（不会静默少打）。
"""
import argparse
import io
import re
import sys

import capstone
from elftools.elf.elffile import ELFFile

ARCHES = {
    "EM_AARCH64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    "EM_ARM": (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
    "EM_386": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    "EM_X86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
}


def vaddr_to_offset(elf, vaddr):
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_LOAD":
            start = seg.header.p_vaddr
            if start <= vaddr < start + seg.header.p_filesz:
                return seg.header.p_offset + (vaddr - start)
    return None


def find_symbol(elf, name):
    for secname in (".dynsym", ".symtab"):
        sec = elf.get_section_by_name(secname)
        if not sec:
            continue
        for sym in sec.iter_symbols():
            if sym.name == name:
                return sym["st_value"], sym["st_size"]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--symbol", help="symbol name (dynsym/symtab)")
    ap.add_argument("--addr", help="start vaddr, e.g. 0xdac")
    ap.add_argument("--size", type=lambda v: int(v, 0), default=0, help="byte count from --addr")
    ap.add_argument("--count", type=int, default=0, help="max instructions to print")
    ap.add_argument("--grep", default="", help="only print lines matching this regex (mnemonic/operands)")
    args = ap.parse_args()

    data = open(args.path, "rb").read()
    elf = ELFFile(io.BytesIO(data))
    machine = elf.header.e_machine
    if machine not in ARCHES:
        print("[-] unsupported machine: %s" % machine)
        return 1
    cs_arch, cs_mode = ARCHES[machine]

    explicit_size = False
    if args.symbol:
        hit = find_symbol(elf, args.symbol)
        if not hit:
            print("[-] symbol not found: %s" % args.symbol)
            return 1
        addr, sym_size = hit
        size = args.size or sym_size or 256
        explicit_size = bool(args.size or sym_size)
    elif args.addr:
        addr = int(args.addr, 0)
        size = args.size or 0
        explicit_size = bool(args.size)
    else:
        print("[-] need --symbol or --addr")
        return 1

    if not size:
        # 窗口自适应：--count N 至少要 N*4 字节（AArch64 定长 4；x86 截断提示兜底）
        size = (args.count * 4 + 0x40) if args.count else 0x100

    off = vaddr_to_offset(elf, addr)
    if off is None:
        print("[-] vaddr 0x%x not found in any PT_LOAD" % addr)
        return 1

    rx = re.compile(args.grep, re.IGNORECASE) if args.grep else None
    md = capstone.Cs(cs_arch, cs_mode)
    scanned = 0
    printed = 0
    last = None
    for ins in md.disasm(data[off:off + size], addr):
        scanned += 1
        last = ins
        line = "0x%04x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str)
        if rx and not rx.search(line):
            continue
        print(line)
        printed += 1
        if args.count and printed >= args.count:
            break
    if scanned == 0:
        print("[-] nothing disassembled (bad offset/size?)")
        return 1
    if rx and printed == 0:
        print("[i] no instruction matched --grep %r (%d scanned)" % (args.grep, scanned))
        return 1
    if last is not None and (last.address + last.size) >= (addr + size):
        if not explicit_size or (args.count and printed < args.count):
            print("[!] truncated at 0x%x (window 0x%x bytes from 0x%x); use --size N for more"
                  % (last.address + last.size, size, addr))
    return 0


if __name__ == "__main__":
    sys.exit(main())
