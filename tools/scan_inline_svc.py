#!/usr/bin/env python3
# scan_inline_svc.py — 扫描 arm64 SO 中所有内联 SVC 指令，解出系统调用号
# 用法: python3 scan_inline_svc.py <path.so>
#
# 用途: 判断某安全库有没有「绕过 libc 直接 syscall」的能力
# 示例: 发现 libnesdk 自带 exit/kill svc 表，说明 exit_blocker 对 libc 层的 hook 无效
#
# 来源: Frida 学习笔记 · 反调试与反检测对抗（上）· 网易云音乐易盾实战
import sys
import struct

NAME = {
    93: 'exit', 94: 'exit_group', 129: 'kill', 130: 'tkill', 131: 'tgkill',
    220: 'clone', 221: 'execve', 56: 'openat', 57: 'close', 63: 'read',
    64: 'write', 226: 'mprotect', 172: 'getpid', 178: 'gettid',
    260: 'wait4', 79: 'fstatat', 61: 'getdents64', 98: 'futex',
    117: 'ptrace', 215: 'munmap', 222: 'mmap',
}


def movz_x8_nr(w):
    """movz x8, #imm16 : 0xD2800008 | (imm16<<5)"""
    if (w & 0xFFE0001F) == 0xD2800008:
        return (w >> 5) & 0xFFFF
    return None


def main(path):
    d = open(path, 'rb').read()
    n = 0
    svc_list = []

    for i in range(0, len(d) - 3, 4):
        w = struct.unpack_from('<I', d, i)[0]
        if (w & 0xFFE0001F) == 0xD4000001:  # SVC #imm
            nr = None
            for back in range(1, 8):  # 往前找 movz x8, #nr
                if i - back * 4 < 0:
                    break
                m = movz_x8_nr(struct.unpack_from('<I', d, i - back * 4)[0])
                if m is not None:
                    nr = m
                    break
            nm = NAME.get(nr, '?') if nr is not None else 'NOT-FOUND'
            svc_list.append((i, nr, nm))
            print(f"  svc @0x{i:x}  nr={nr} ({nm})")
            n += 1

    print(f"\n[+] {path}: 共 {n} 条 svc 指令")

    # 汇总 kill/exit 相关的
    kill_offsets = [(off, nr, nm) for off, nr, nm in svc_list if nr in (93, 94, 129, 130, 131)]
    if kill_offsets:
        print(f"\n[!] 发现 {len(kill_offsets)} 条 kill/exit 相关 SVC（exit_blocker 无法拦截这些）:")
        for off, nr, nm in kill_offsets:
            print(f"    0x{off:x}  nr={nr} ({nm})")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("用法: python3 scan_inline_svc.py <path.so>")
        sys.exit(1)
    main(sys.argv[1])