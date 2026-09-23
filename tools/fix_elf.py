#!/usr/bin/env python3
# fix_elf.py — 修复内存 dump 出来的 SO 文件的 ELF Section Header
# 用法: python3 fix_elf.py <dump.so> <output.so>
#
# 背景: dump 出来的 SO 文件 Section Header Table 通常指向文件外（因为 dump
# 比原始 SO 小）。IDA 能基于 Program Header 分析，但前提是 ELF Header 中
# e_shoff / e_shnum / e_shstrndx 不指向无效位置。本脚本检测越界并清零。
# 更复杂的修复（段合并、重定位回填）交给 F8LEFT/SoFixer。
#
# 来源: Frida 学习笔记 · SO Dump 与内存 Dump §4.3
import struct
import sys

# ELF32 与 ELF64 的 e_shoff / e_shnum / e_shstrndx 偏移和宽度不同
LAYOUT = {
    1: {"shoff": (32, '<I', 4), "shnum": (48, '<H', 2), "shstrndx": (50, '<H', 2)},  # ELFCLASS32
    2: {"shoff": (40, '<Q', 8), "shnum": (60, '<H', 2), "shstrndx": (62, '<H', 2)},  # ELFCLASS64
}


def fix_dump(input_path, output_path):
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    if data[:4] != b'\x7fELF':
        print("[!] 不是有效的 ELF 文件")
        return

    ei_class = data[4]  # 1=ELF32, 2=ELF64
    if ei_class not in LAYOUT:
        print(f"[!] 未知 EI_CLASS={ei_class}")
        return
    L = LAYOUT[ei_class]
    print(f"[*] ELF{'32' if ei_class == 1 else '64'}")

    e_shoff = struct.unpack_from(L["shoff"][1], data, L["shoff"][0])[0]
    e_shnum = struct.unpack_from(L["shnum"][1], data, L["shnum"][0])[0]
    e_shstrndx = struct.unpack_from(L["shstrndx"][1], data, L["shstrndx"][0])[0]
    print(f"    Section Header: offset=0x{e_shoff:x}, num={e_shnum}, strndx={e_shstrndx}")

    # Section Header 偏移指向文件外 → 清零，让 IDA 走 Program Header 路径
    if e_shoff > len(data) or e_shnum == 0:
        print("[*] 清理无效的 Section Header 引用")
        struct.pack_into(L["shoff"][1],    data, L["shoff"][0],    0)
        struct.pack_into(L["shnum"][1],    data, L["shnum"][0],    0)
        struct.pack_into(L["shstrndx"][1], data, L["shstrndx"][0], 0)

    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"[*] 修复完成: {output_path}")
    print("    IDA: File → Load file → ELF (勾 'Manual load' + 'Force load')")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python3 fix_elf.py <dump.so> <output.so>")
        sys.exit(1)
    fix_dump(sys.argv[1], sys.argv[2])