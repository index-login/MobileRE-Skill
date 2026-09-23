#!/usr/bin/env python3
# find_strref.py — 解码 arm64 adrp+add/adrp+ldr，找出哪段代码引用了指定字符串
# 用法: python3 find_strref.py <bin> <str_vaddr_hex> [<str_vaddr_hex> ...]
#
# 用途: CFG-flattening 混淆下 r2/Ghidra 自动 xref 失效时，从「检测串偏移」反查「检测函数地址」
# 步骤:
#   1. strings -a -t x <bin> | grep <关键串>  拿到串的文件偏移(=vaddr)
#   2. python3 find_strref.py <bin> <0xXXXXX>  反查引用该串的指令地址
#
# 来源: Frida 学习笔记 · 反调试与反检测对抗（上）· 网易云音乐易盾实战
import sys
import struct


def main(path, targets):
    d = open(path, 'rb').read()
    N = len(d)

    def w(i):
        return struct.unpack_from('<I', d, i)[0]

    tset = set(targets)
    hits = {}

    for i in range(0, N - 4, 4):
        inst = w(i)
        if (inst & 0x9f000000) == 0x90000000:  # ADRP
            Rd = inst & 0x1f
            imm = (((inst >> 5) & 0x7ffff) << 2) | ((inst >> 29) & 0x3)
            if imm & (1 << 20):
                imm -= (1 << 21)  # sign-extend 21 bit
            page = (i & ~0xfff) + (imm << 12)

            for j in range(i + 4, min(i + 28, N - 4), 4):  # 邻近找 add/ldr 补低位
                n2 = w(j)
                if (n2 & 0xff800000) == 0x91000000 and ((n2 >> 5) & 0x1f) == Rd:  # ADD imm
                    off = ((n2 >> 10) & 0xfff) << (12 if (n2 >> 22) & 1 else 0)
                    if page + off in tset:
                        hits.setdefault(page + off, []).append(i)
                    break
                if (n2 & 0xffc00000) == 0xf9400000 and ((n2 >> 5) & 0x1f) == Rd:  # LDR imm
                    off = ((n2 >> 10) & 0xfff) << 3
                    if page + off in tset:
                        hits.setdefault(page + off, []).append((i, 'ldr'))
                    break

    for t in targets:
        v = hits.get(t, [])
        refs = [hex(x) if isinstance(x, int) else x for x in v]
        print(f"串 vaddr 0x{t:x}: 被引用 @ {refs or '(无)'}")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("用法: python3 find_strref.py <bin> <str_vaddr_hex> [...]")
        print("示例: python3 find_strref.py libnesec.so 0x1a3b0 0x1a3d0")
        sys.exit(1)
    main(sys.argv[1], [int(x, 16) for x in sys.argv[2:]])