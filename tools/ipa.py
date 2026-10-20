#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPA 静态侦察工具（无 Frida 依赖）。

子命令：
  meta    <ipa> [--json]            元数据：应用名称 / Bundle ID / 大小 / 版本 / MD5
  info    <ipa>                     结构概览：bundle 名 / 主二进制 / framework 体积分布
  bins    <ipa>                     Mach-O 清单：架构 / 大小 / 是否加密（cryptid）
  find    <ipa> <pattern> [...]     全量字符串搜索，定位业务代码落在哪个文件
  extract <ipa> [-o DIR]            解包（默认解到 <ipa 同目录>/<name>_extracted）

用法示例：
  python3 tools/ipa.py meta   app.ipa
  python3 tools/ipa.py meta   app.ipa --json
  python3 tools/ipa.py info   app.ipa
  python3 tools/ipa.py bins   app.ipa
  python3 tools/ipa.py find   app.ipa GenPages app.stihl.my
  python3 tools/ipa.py extract app.ipa -o out/
"""
import argparse
import hashlib
import json
import os
import plistlib
import struct
import sys
import zipfile

MAGIC_MH64 = b"\xcf\xfa\xed\xfe"
MAGIC_MH32 = b"\xce\xfa\xed\xfe"
MAGIC_FAT = b"\xca\xfe\xba\xbe"
MAGIC_FAT64 = b"\xca\xfe\xba\xbf"
MACHO_MAGICS = (MAGIC_MH64, MAGIC_MH32, MAGIC_FAT, MAGIC_FAT64)

CPU_NAMES = {
    16777228: "arm64", 16777223: "x86_64", 16777222: "arm64_32",
    12: "armv7", 7: "i386",
}
FILETYPE_NAMES = {
    1: "object", 2: "execute", 6: "dylib", 8: "bundle",
    9: "dylib_stub", 10: "dsym", 11: "kext",
}


def _cryptid(data, off):
    """Parse LC_ENCRYPTION_INFO(_64) in a thin Mach-O slice at `off`. Returns cryptid or None."""
    try:
        magic = data[off:off + 4]
        if magic == MAGIC_MH64:
            p = off + 32
        elif magic == MAGIC_MH32:
            p = off + 28
        else:
            return None
        ncmds = struct.unpack_from("<I", data, off + 16)[0]
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, p)
            if cmd in (0x2C, 0x21):  # LC_ENCRYPTION_INFO_64 / LC_ENCRYPTION_INFO
                # cmd(4) cmdsize(4) cryptoff(4) cryptsize(4) cryptid(4) -> cryptid at +16
                return struct.unpack_from("<I", data, p + 16)[0]
            if cmdsize < 8:
                return None
            p += cmdsize
    except Exception:
        return None
    return 0


def macho_info(data):
    """Return dict(archs, ftype, cryptid, fat) if data is a Mach-O, else None."""
    if len(data) < 8:
        return None
    head = data[:4]
    if head in (MAGIC_FAT, MAGIC_FAT64):
        is64 = head == MAGIC_FAT64
        esz = 32 if is64 else 20
        nfat = struct.unpack_from(">I", data, 4)[0]
        archs, first_off = [], 0
        for i in range(nfat):
            off = 8 + i * esz
            if off + esz > len(data):
                break
            cputype = struct.unpack_from(">i", data, off)[0]
            offset = struct.unpack_from(">Q" if is64 else ">I", data, off + 8)[0]
            archs.append(CPU_NAMES.get(cputype, "cpu%s" % cputype))
            if i == 0:
                first_off = offset
        return {"archs": archs, "ftype": None, "cryptid": _cryptid(data, first_off), "fat": True}
    if head in (MAGIC_MH64, MAGIC_MH32):
        cputype = struct.unpack_from("<i", data, 4)[0]
        ftype = struct.unpack_from("<I", data, 12)[0]
        return {
            "archs": [CPU_NAMES.get(cputype, "cpu%s" % cputype)],
            "ftype": ftype,
            "cryptid": _cryptid(data, 0),
            "fat": False,
        }
    return None


def app_bundle(z):
    for n in z.namelist():
        parts = n.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            return parts[1]
    return None


def read_plist(z, name):
    try:
        with z.open(name) as f:
            return plistlib.load(f)
    except Exception:
        return None


def iter_files(z):
    for i in z.infolist():
        if not i.is_dir():
            yield i.filename, i.file_size


def file_md5(path, chunk=1 << 20):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def cmd_meta(args):
    z = zipfile.ZipFile(args.ipa)
    app = app_bundle(z)
    if not app:
        print("[!] 未找到 Payload/*.app")
        return 1
    pl = read_plist(z, "Payload/%s/Info.plist" % app)
    if pl is None:
        print("[!] Info.plist 读取失败")
        return 1
    size = os.path.getsize(args.ipa)
    data = {
        "file": os.path.abspath(args.ipa),
        "size": size,
        "size_mb": round(size / 1048576.0, 2),
        "md5": file_md5(args.ipa),
        "app_name": pl.get("CFBundleDisplayName") or pl.get("CFBundleName") or app[:-4],
        "bundle_id": pl.get("CFBundleIdentifier"),
        "version": pl.get("CFBundleShortVersionString"),
        "build": pl.get("CFBundleVersion"),
        "executable": pl.get("CFBundleExecutable"),
    }
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print("应用名称 : %s" % data["app_name"])
        print("Bundle ID: %s" % data["bundle_id"])
        print("应用大小 : %s bytes (%.2f MB)" % ("{:,}".format(size), data["size_mb"]))
        print("应用版本 : %s (%s)" % (data["version"], data["build"]))
        print("文件MD5  : %s" % data["md5"])
        print("可执行   : %s" % data["executable"])
        print("文件路径 : %s" % data["file"])
    return 0


def cmd_info(args):
    z = zipfile.ZipFile(args.ipa)
    app = app_bundle(z)
    if not app:
        print("[!] 未找到 Payload/*.app")
        return 1
    print("IPA      : %s" % args.ipa)
    print("app      : %s" % app)
    pl = read_plist(z, "Payload/%s/Info.plist" % app)
    if pl:
        print("bundleId : %s" % pl.get("CFBundleIdentifier"))
        print("exec     : %s" % pl.get("CFBundleExecutable"))
        print("version  : %s (%s)" % (pl.get("CFBundleShortVersionString"), pl.get("CFBundleVersion")))
    exe = (pl or {}).get("CFBundleExecutable") or app[:-4]
    exe_path = "Payload/%s/%s" % (app, exe)
    sizes = dict(iter_files(z))
    print("main bin : %s  (%s bytes)" % (exe, "{:,}".format(sizes.get(exe_path, -1))))
    print()

    print("== Frameworks ==")
    fw = {}
    for name, size in iter_files(z):
        marker = "/Frameworks/"
        if marker in name:
            rest = name.split(marker, 1)[1]
            top = rest.split("/")[0]
            fw.setdefault(top, []).append((name, size))
    for top in sorted(fw, key=lambda t: -sum(s for _, s in fw[t])):
        total = sum(s for _, s in fw[top])
        print("  %12s  %s" % ("{:,}".format(total), top))
    print()

    print("== Top 15 largest files ==")
    for name, size in sorted(iter_files(z), key=lambda x: -x[1])[:15]:
        print("  %12s  %s" % ("{:,}".format(size), name))
    return 0


def cmd_bins(args):
    z = zipfile.ZipFile(args.ipa)
    rows = []
    for name, size in iter_files(z):
        if size < 4096:
            continue
        with z.open(name) as f:
            head = f.read(64)
        if head[:4] not in MACHO_MAGICS:
            continue
        with z.open(name) as f:
            data = f.read()
        info = macho_info(data)
        if info:
            rows.append((size, name, info))
    print("%-12s %-10s %-9s %-9s %s" % ("SIZE", "ARCH", "TYPE", "CRYPTID", "PATH"))
    for size, name, info in sorted(rows, key=lambda r: -r[0]):
        ftype = FILETYPE_NAMES.get(info["ftype"], str(info["ftype"]))
        cid = info["cryptid"]
        enc = "ENC" if cid == 1 else ("-" if cid == 0 else "?")
        print("%-12s %-10s %-9s %-9s %s" % (
            "{:,}".format(size), ",".join(info["archs"]), ftype, enc, name))
    print("\n提示：CRYPTID=ENC 表示 FairPlay 加密，需先脱壳（frida-ios-dump 等）再喂 IDA。")
    return 0


def cmd_find(args):
    z = zipfile.ZipFile(args.ipa)
    pats = [p.encode("utf-8") for p in args.pattern]
    rows = []
    for name, size in iter_files(z):
        if size < args.min_size:
            continue
        with z.open(name) as f:
            data = f.read()
        counts = [data.count(p) for p in pats]
        if any(counts):
            rows.append((sum(counts), size, name, counts))
    if not rows:
        print("[!] 未命中任何模式")
        return 0
    print("命中文件（按总命中数排序）：")
    for total, size, name, counts in sorted(rows, reverse=True):
        detail = ", ".join("%s=%d" % (args.pattern[i], counts[i])
                           for i in range(len(pats)) if counts[i])
        print("  %6d 次  %12s B  %s" % (total, "{:,}".format(size), name))
        print("            %s" % detail)
    return 0


def cmd_extract(args):
    z = zipfile.ZipFile(args.ipa)
    out = args.out or (os.path.splitext(args.ipa)[0] + "_extracted")
    z.extractall(out)
    print("[+] extracted to %s" % out)
    return 0


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="IPA 静态侦察工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("meta", help="元数据：名称 / Bundle ID / 大小 / 版本 / MD5")
    p.add_argument("ipa")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.set_defaults(func=cmd_meta)

    p = sub.add_parser("info", help="结构概览")
    p.add_argument("ipa")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("bins", help="Mach-O 清单")
    p.add_argument("ipa")
    p.set_defaults(func=cmd_bins)

    p = sub.add_parser("find", help="全量字符串搜索")
    p.add_argument("ipa")
    p.add_argument("pattern", nargs="+")
    p.add_argument("--min-size", type=int, default=4096, help="跳过小于该字节数的文件（默认 4096）")
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("extract", help="解包")
    p.add_argument("ipa")
    p.add_argument("-o", "--out", default=None)
    p.set_defaults(func=cmd_extract)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())