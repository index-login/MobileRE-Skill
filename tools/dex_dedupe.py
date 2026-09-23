#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dex_dedupe.py - DEX 产物去重/校验工具

用途: 七猫案例表明 frida-dexdump -d 会对 ART OAT 缓存合并区重复 dump 同一段内存
      （多个 DEX 是同一大段的截取子集）。本工具:
      1. 按尾部 1KB md5 分组，识别同段重复
      2. 对大型 DEX 做字节偏移对比，检测"截取子集"关系
      3. 输出去重后的独立文件清单 + 冗余统计

用法:
    python3 dex_dedupe.py <dump目录> [-o 输出目录] [--tail 1024] [--superset-check]

输出:
    - 独立文件复制到输出目录（默认 <目录>/dedup/）
    - 打印统计：总量 / 独立量 / 冗余量
"""
import argparse
import hashlib
import os
import shutil
import sys
from collections import defaultdict


def full_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def tail_md5(path, n=1024):
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - n))
        data = f.read()
    return hashlib.md5(data).hexdigest()


def is_suffix_subset(a_path, b_path, sample=0x100000):
    """检测 a 是否为 b 的截取子集：a 的尾部与 b 的某个偏移处的字节一致。"""
    with open(a_path, "rb") as fa, open(b_path, "rb") as fb:
        fa.seek(0, 2)
        a_size = fa.tell()
        fb.seek(0, 2)
        b_size = fb.tell()
        if a_size > b_size or a_size < sample:
            return False
        # 采样 a 的中段和尾部，去 b 中找对应偏移
        offsets = [max(0, a_size // 2), max(0, a_size - sample)]
        for off in offsets:
            fa.seek(off)
            probe = fa.read(0x1000)
            if not probe:
                continue
            # 在 b 中线性找 probe 的匹配位置（b 的尾部对齐 a 的尾部）
            fb.seek(0)
            b_data = fb.read()
            idx = b_data.find(probe)
            if idx == -1:
                return False
            # 校验对齐：a 的尾部应等于 b 的对应尾部
            delta = b_size - a_size
            if idx == off + delta:
                return True
    return False


def dedupe(dump_dir, out_dir, tail, superset_check):
    files = sorted(
        f for f in os.listdir(dump_dir)
        if os.path.isfile(os.path.join(dump_dir, f)) and f.endswith(".dex")
    )
    if not files:
        print("[-] no .dex files in %s" % dump_dir)
        return

    total_disk = sum(os.path.getsize(os.path.join(dump_dir, f)) for f in files)

    # 1) 完全相同的文件（full md5）
    full_groups = defaultdict(list)
    for f in files:
        full_groups[full_md5(os.path.join(dump_dir, f))].append(f)

    # 2) 尾部一致的分组（同段截取子集）
    tail_groups = defaultdict(list)
    for f in files:
        tail_groups[tail_md5(os.path.join(dump_dir, f), tail)].append(f)

    # 3) 判定独立文件：每组尾部一致中选最大的一个
    unique = []
    for group in tail_groups.values():
        if len(group) == 1:
            unique.append(group[0])
            continue
        big = max(group, key=lambda f: os.path.getsize(os.path.join(dump_dir, f)))
        unique.append(big)
        print("[!] 尾部一致(疑似同段) %d 个，保留最大: %s" % (len(group), big))
        for f in group:
            if f != big:
                print("    - 冗余: %s (%d MB)" % (f, os.path.getsize(os.path.join(dump_dir, f)) // (1024 * 1024)))

    # 4) 可选：跨组截取子集检测（大 DEX 之间）
    if superset_check:
        unique = sorted(unique, key=lambda f: os.path.getsize(os.path.join(dump_dir, f)), reverse=True)
        drop = set()
        for i, a in enumerate(unique):
            if a in drop:
                continue
            for b in unique[i + 1:]:
                if b in drop:
                    continue
                if is_suffix_subset(
                    os.path.join(dump_dir, a), os.path.join(dump_dir, b)
                ):
                    print("[!] 截取子集: %s ⊂ %s" % (a, b))
                    drop.add(a)
                    break
        unique = [f for f in unique if f not in drop]

    # 5) 输出
    os.makedirs(out_dir, exist_ok=True)
    unique_disk = 0
    for f in unique:
        src = os.path.join(dump_dir, f)
        dst = os.path.join(out_dir, f)
        shutil.copy2(src, dst)
        unique_disk += os.path.getsize(src)

    print("\n=== 统计 ===")
    print("产物总量: %d 个文件 / %d MB" % (len(files), total_disk // (1024 * 1024)))
    print("独立 DEX: %d 个 / %d MB" % (len(unique), unique_disk // (1024 * 1024)))
    print("冗余: %d MB (%d%%)" % ((total_disk - unique_disk) // (1024 * 1024),
          (total_disk - unique_disk) * 100 // max(total_disk, 1)))
    print("去重输出: %s" % out_dir)


def main():
    parser = argparse.ArgumentParser(description="DEX 产物去重/校验")
    parser.add_argument("dump_dir", help="frida-dexdump / dex_finder 产物目录")
    parser.add_argument("-o", "--out", default="", help="去重输出目录（默认 <dump_dir>/dedup）")
    parser.add_argument("--tail", type=int, default=1024, help="尾部一致校验的字节数")
    parser.add_argument("--superset-check", action="store_true", help="跨组截取子集检测(慢)")
    args = parser.parse_args()

    out = args.out or os.path.join(args.dump_dir, "dedup")
    try:
        dedupe(args.dump_dir, out, args.tail, args.superset_check)
    except Exception as e:
        print("[-] dedupe failed: %s" % e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()