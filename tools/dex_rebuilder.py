#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dex_rebuilder.py - DEX 修复工具（checksum 重算 + CodeItem 离线重组回填）

用途:
    1. --fix-checksum: 重算 DEX checksum（adler32），修复壳在运行时修改内存导致
       checksum 不匹配的问题（jadx 报 "Bad dex file checksum" 时用）
    2. 默认（CodeItem 重组）: 把 codeitem_dump.js 产出的 ins.bin 里的 CodeItem
       按 method_idx 回填到骨架 DEX，得到可直接用 jadx 打开的完整 DEX

用法:
    python3 dex_rebuilder.py --fix-checksum <dump.dex> -o fixed.dex
    python3 dex_rebuilder.py <skeleton.dex> <ins.bin> -o out.dex

局限:
    - 就地回填（overwrite），不重新打包 data section。若真实 CodeItem 大于占位区域，
      可能覆盖相邻数据；多数情况可用，hard 场景请用完整版 fart.py
    - 只处理 direct/virtual 方法，跳过 static/instance 字段（本来就无 code）
"""
import argparse
import base64
import re
import struct
import sys
import zlib


def adler32(data):
    """DEX checksum = adler32(从 offset 0x0C 到文件末尾)"""
    return zlib.adler32(data) & 0xFFFFFFFF


def fix_checksum(path, out_path):
    with open(path, "rb") as f:
        data = bytearray(f.read())
    if data[:4] != b"dex\n":
        print("[-] not a dex file: %s" % path)
        sys.exit(1)
    old_sum = struct.unpack_from("<I", data, 0x08)[0]
    new_sum = adler32(bytes(data[0x0C:]))
    struct.pack_into("<I", data, 0x08, new_sum)
    with open(out_path, "wb") as f:
        f.write(bytes(data))
    print("[+] checksum: 0x%08x -> 0x%08x" % (old_sum, new_sum))
    print("[+] output: %s" % out_path)
    return new_sum


def read_uleb128(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def parse_ins_bin(path):
    """解析 ins.bin，返回 method_idx -> CodeItem 字节。"""
    table = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    pattern = re.compile(
        r"\{name:[^,]*,method_idx:(\d+),offset:\d+,code_item_len:(\d+),ins:([A-Za-z0-9+/=]+)\};"
    )
    for m in pattern.finditer(content):
        idx = int(m.group(1))
        raw = base64.b64decode(m.group(3))
        table[idx] = raw
    return table


def iter_methods(data):
    """遍历所有 class_def 的 direct + virtual 方法，产出 (method_idx, code_off)。"""
    class_defs_size = struct.unpack_from("<I", data, 0x60)[0]
    class_defs_off = struct.unpack_from("<I", data, 0x64)[0]
    for i in range(class_defs_size):
        cd = class_defs_off + i * 0x20
        class_data_off = struct.unpack_from("<I", data, cd + 0x18)[0]
        if class_data_off == 0:
            continue
        pos = class_data_off
        static_fields, pos = read_uleb128(data, pos)
        instance_fields, pos = read_uleb128(data, pos)
        direct_methods, pos = read_uleb128(data, pos)
        virtual_methods, pos = read_uleb128(data, pos)
        for _ in range(static_fields + instance_fields):
            _, pos = read_uleb128(data, pos)  # field_idx_diff
            _, pos = read_uleb128(data, pos)  # access_flags
        method_idx = 0
        for _ in range(direct_methods + virtual_methods):
            diff, pos = read_uleb128(data, pos)
            method_idx += diff
            _, pos = read_uleb128(data, pos)  # access_flags
            code_off, pos = read_uleb128(data, pos)
            yield method_idx, code_off


def rebuild(skeleton_path, ins_path, out_path):
    with open(skeleton_path, "rb") as f:
        data = bytearray(f.read())
    table = parse_ins_bin(ins_path)
    replaced = 0
    skipped = 0
    for method_idx, code_off in iter_methods(data):
        if method_idx not in table:
            continue
        code = table[method_idx]
        if code_off == 0 or code_off + len(code) > len(data):
            skipped += 1
            continue
        data[code_off:code_off + len(code)] = code
        replaced += 1
    # 回填后数据变化，必须重算 checksum（否则 jadx 报 Bad dex file checksum）
    old_sum = struct.unpack_from("<I", data, 0x08)[0]
    new_sum = adler32(bytes(data[0x0C:]))
    struct.pack_into("<I", data, 0x08, new_sum)
    with open(out_path, "wb") as f:
        f.write(bytes(data))
    print("[+] ins.bin methods: %d" % len(table))
    print("[+] replaced: %d, skipped: %d" % (replaced, skipped))
    print("[+] checksum: 0x%08x -> 0x%08x" % (old_sum, new_sum))
    print("[+] output: %s" % out_path)


def main():
    parser = argparse.ArgumentParser(description="DEX 修复：checksum 重算 / CodeItem 重组回填")
    parser.add_argument("--fix-checksum", action="store_true",
                        help="只重算 checksum（jadx 报 Bad dex file checksum 时用）")
    parser.add_argument("skeleton", nargs="?", help="骨架 DEX（<size>_loadMethod.dex）")
    parser.add_argument("ins", nargs="?", help="ins.bin（codeitem_dump.js 产物）")
    parser.add_argument("-o", "--out", default="rebuilt.dex", help="输出修复后的 DEX")
    args = parser.parse_args()
    try:
        if args.fix_checksum:
            if not args.skeleton:
                print("[-] --fix-checksum 需要输入 DEX 文件")
                sys.exit(1)
            fix_checksum(args.skeleton, args.out)
        else:
            if not args.skeleton or not args.ins:
                print("[-] 用法: dex_rebuilder.py <skeleton.dex> <ins.bin> -o out.dex")
                sys.exit(1)
            rebuild(args.skeleton, args.ins, args.out)
    except Exception as e:
        print("[-] rebuild failed: %s" % e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()