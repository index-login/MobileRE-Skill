#!/usr/bin/env python3
"""
fix_axml.py - 爱加密 AXML 魔改 Manifest 修复工具

背景：爱加密加固会在 AndroidManifest.xml (AXML) 的第一个 chunk header 后
插入 4 字节填充 (00 00 00 00)，并把 headerSize 谎报为 0x000C (标准 0x0008)。
数据流自洽 → aapt/系统可解析，但 jadx/apktool 强制校验 0x00080003 报错拒绝。

修复：删除 4 字节填充 + headerSize 回 0x0008 + size 减 4 → 压缩回标准 AXML。

用法：
  # 修复 APK 内的 AndroidManifest.xml，输出新 APK
  python3 fix_axml.py -i base.apk -o base_fixed.apk

  # 直接修复 AXML 文件（无 APK 容器）
  python3 fix_axml.py -i AndroidManifest.bin -o AndroidManifest_fixed.bin

  # 只检测不输出
  python3 fix_axml.py -i base.apk --check

验证（jadx CLI 只解资源）：
  java -cp jadx-gui-1.5.3-all.jar jadx.cli.JadxCLI --no-src -d out base_fixed.apk
"""
import argparse
import struct
import sys
import zipfile


def detect_axml_magic(data):
    """检测是否为爱加密魔改 AXML：首 chunk headerSize=0x000C + 8-11 为填充 + 12 处为 string pool"""
    if len(data) < 16:
        return False
    if data[0:2] != b'\x03\x00':
        return False
    if data[2:4] != b'\x0c\x00':
        return False
    if data[8:12] != b'\x00\x00\x00\x00':
        return False
    if data[12:14] != b'\x01\x00':
        return False
    return True


def fix_axml(data):
    """修复魔改 AXML，返回标准 AXML 字节；若无需修复返回原数据"""
    if not detect_axml_magic(data):
        return data, False
    new_len = len(data) - 4
    new = b'\x03\x00\x08\x00' + struct.pack('<I', new_len) + data[12:]
    return new, True


def verify_axml(data):
    """按 chunk size 遍历验证布局，返回 (ok, 问题描述)"""
    off = 0
    guard = 0
    while off < len(data) - 8 and guard < 64:
        ctype, hsize, csize = struct.unpack_from('<HHI', data, off)
        if csize == 0 or ctype == 0x0105:
            break
        off += csize
        guard += 1
    if off >= len(data) - 8 and guard < 64:
        return True, f"chunks={guard} total={len(data)}"
    return False, f"broken at off=0x{off:x}"

UNIT = 1024 * 1024


def human(n):
    return f"{n / UNIT:.1f}MB" if n >= UNIT else f"{n}B"


def main():
    ap = argparse.ArgumentParser(description="修复爱加密魔改 AXML (AndroidManifest.xml)")
    ap.add_argument("-i", "--input", required=True, help="输入 APK 或 AXML 文件")
    ap.add_argument("-o", "--output", help="输出文件（不填则打印检测结果）")
    ap.add_argument("-e", "--entry", default="AndroidManifest.xml", help="APK 内目标 entry（默认 AndroidManifest.xml）")
    ap.add_argument("--check", action="store_true", help="只检测不输出")
    args = ap.parse_args()

    is_apk = args.input.lower().endswith(".apk")

    if is_apk:
        zin = zipfile.ZipFile(args.input, 'r')
        if args.entry not in zin.namelist():
            print(f"[-] {args.entry} not in APK")
            sys.exit(1)
        data = zin.read(args.entry)
    else:
        data = open(args.input, 'rb').read()

    print(f"[*] {args.input} ({human(len(data))}) entry={args.entry if is_apk else '-'}")
    print(f"    header: {data[:8].hex()}")

    if not detect_axml_magic(data):
        print("[-] 未检测到爱加密魔改特征（headerSize!=0x000C 或结构不符），跳过")
        sys.exit(0)

    print("[+] 检测到爱加密 AXML 魔改：headerSize=0x000C + 4字节填充")
    if args.check:
        print("[*] --check 模式，不输出")
        sys.exit(0)

    new, _ = fix_axml(data)
    ok, desc = verify_axml(new)
    print(f"[+] 修复后 header: {new[:8].hex()} len={len(new)} layout={desc}")

    if not args.output:
        print("[-] 未指定 -o，未写出")
        sys.exit(0)

    if is_apk:
        with zipfile.ZipFile(args.output, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                content = new if item.filename == args.entry else zin.read(item.filename)
                zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                zi.compress_type = item.compress_type
                zi.external_attr = item.external_attr
                zi.internal_attr = item.internal_attr
                zi.extra = item.extra
                zi.comment = item.comment
                zout.writestr(zi, content)
        zin.close()
        print(f"[+] 已生成: {args.output}")
    else:
        open(args.output, 'wb').write(new)
        print(f"[+] 已生成: {args.output}")


if __name__ == '__main__':
    main()