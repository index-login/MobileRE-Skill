#!/usr/bin/env python3
# find_branch_callers.py — 找出哪些 bl/b/b.cond/cbz/tbz 跳到了指定目标地址
# 用法: python3 find_branch_callers.py <bin> <target_vaddr_hex> [--bl-only]
#
# 用途: CFG-flattening 下「取串桩→错误块→真函数」要逐层反查调用者
# 支持: BL / B / B.cond / CBZ/CBNZ / TBZ/TBNZ
#
# 来源: Frida 学习笔记 · 反调试与反检测对抗（上）· 网易云音乐易盾实战
import sys
import struct


def main(path, target, bl_only):
    d = open(path, 'rb').read()
    N = len(d)

    def w(i):
        return struct.unpack_from('<I', d, i)[0]

    callers = []

    for i in range(0, N - 4, 4):
        inst = w(i)
        tgt = None
        kind = None

        if (inst & 0xfc000000) == 0x94000000:  # BL
            imm = inst & 0x3ffffff
            if imm & (1 << 25):
                imm -= (1 << 26)
            tgt = i + imm * 4
            kind = 'bl'
        elif not bl_only and (inst & 0xfc000000) == 0x14000000:  # B
            imm = inst & 0x3ffffff
            if imm & (1 << 25):
                imm -= (1 << 26)
            tgt = i + imm * 4
            kind = 'b'
        elif not bl_only and (inst & 0xff000010) == 0x54000000:  # B.cond
            imm = (inst >> 5) & 0x7ffff
            if imm & (1 << 18):
                imm -= (1 << 19)
            tgt = i + imm * 4
            kind = 'b.cond'
        elif not bl_only and (inst & 0x7e000000) == 0x34000000:  # CBZ/CBNZ
            imm = (inst >> 5) & 0x7ffff
            if imm & (1 << 18):
                imm -= (1 << 19)
            tgt = i + imm * 4
            kind = 'cbz/cbnz'
        elif not bl_only and (inst & 0x7e000000) == 0x36000000:  # TBZ/TBNZ
            imm = (inst >> 5) & 0x3fff
            if imm & (1 << 13):
                imm -= (1 << 14)
            tgt = i + imm * 4
            kind = 'tbz/tbnz'

        if tgt == target:
            callers.append((i, kind))

    print(f"目标 0x{target:x} 被 {len(callers)} 处跳转引用:")
    for a, k in callers:
        print(f"  {k:9s} @ 0x{a:x}")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("用法: python3 find_branch_callers.py <bin> <target_vaddr_hex> [--bl-only]")
        print("示例: python3 find_branch_callers.py libnesec.so 0x7add8")
        sys.exit(1)
    main(sys.argv[1], int(sys.argv[2], 16), '--bl-only' in sys.argv)