#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unpack.py - 脱壳一键入口（线性流水线，AI 只调一次）

用法:
    python3 unpack.py <包名> [--out 输出目录] [--host 127.0.0.1:7890]

流程（自动线性执行，无需 AI 决策）:
    1. codeitem_dump whole 模式：spawn → loadClass 全部类（默认回填函数体）→ dump 全部 DEX
    2. dex_finder 补充：内存扫描 DexCache 未覆盖的 DEX
    3. 自动 pull 产物到本地（app 私有目录 → /sdcard → 本地）
    4. 默认 fix-checksum（壳修改内存后 checksum 必失效，必须修复）
    5. 去重（dex_dedupe）
    6. 方法体标记：统计 native 方法占比 → [Dex2C]；return-void 占比高 → [Skeleton]；其余 [OK]

设计原则:
    - 默认全部回填（loadClass 对一代壳无害，对抽取壳必要，无需判断壳类型）
    - Dex2C/VMP 只标记不深挖（针对性分析在 DEX 层之外）
    - 输出: 统一目录 + 每文件状态标记

依赖:
    pip install frida-tools
    adb + frida-server（root）在设备上
    adb forward tcp:7890 tcp:7890
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import time

import frida

# ==================== 配置 ====================
DEFAULT_HOST = "127.0.0.1:8888"
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_SCRIPTS = os.path.normpath(os.path.join(
    TOOLS_DIR, os.pardir, ".kilo", "skill", "frida-mobile-security", "scripts"))
CORE = os.path.join(SKILL_SCRIPTS, "core", "utils.js")
CODEITEM_DUMP = os.path.join(SKILL_SCRIPTS, "utils", "codeitem_dump.js")
DEX_FINDER = os.path.join(SKILL_SCRIPTS, "utils", "dex_finder.js")
DEDUPE = os.path.join(TOOLS_DIR, "dex_dedupe.py")
CODEMARK = "FART] whole-dex dump done"
FINDERMARK = "DEXFINDER] done"


def adb(args, timeout=120):
    """执行 adb 命令，返回 stdout。"""
    r = subprocess.run(["adb"] + args, capture_output=True, text=True, timeout=timeout)
    return r.stdout


def resolve_device(host):
    port = host.split(":")[-1]
    adb(["forward", "tcp:%s" % port, "tcp:%s" % port])
    return frida.get_device_manager().add_remote_device(host)


def run_spawn_script(device, package, js_parts, duration, done_marker):
    """spawn → 加载脚本 → resume → 等待完成标记。返回日志列表。"""
    logs = []
    pid = device.spawn([package])
    print("[*] spawn %s pid=%d" % (package, pid), flush=True)
    session = device.attach(pid)

    combined = "\n".join(js_parts)
    script = session.create_script(combined)

    def on_message(msg, data):
        if msg["type"] == "send":
            logs.append(str(msg.get("payload", "")))
        elif msg["type"] == "error":
            logs.append("[ERROR] " + str(msg.get("description", msg)))

    script.on("message", on_message)
    script.load()
    device.resume(pid)
    print("[*] running, waiting %ds..." % duration, flush=True)

    deadline = time.time() + duration
    while time.time() < deadline:
        if any(done_marker in l for l in logs):
            break
        time.sleep(0.5)
    time.sleep(2)  # 标记后留 2s 写盘
    try:
        session.detach()
    except Exception:
        pass
    return logs


def run_codeitem_dump(device, package, duration):
    """codeitem_dump whole 模式：loadClass 回填 + 整 DEX dump。"""
    parts = []
    with open(CORE, "r", encoding="utf-8") as f:
        parts.append(f.read())
    with open(CODEITEM_DUMP, "r", encoding="utf-8") as f:
        parts.append(f.read())
    return run_spawn_script(device, package, parts, duration, CODEMARK)


def run_dex_finder(device, package, duration, deep=False):
    """dex_finder 补充：内存扫描所有 DEX。deep 默认关闭（whole 模式已覆盖，deep 只产生假 DEX 噪音）。"""
    parts = []
    with open(CORE, "r", encoding="utf-8") as f:
        parts.append(f.read())
    if not deep:
        parts.append('var CONFIG_OVERRIDE={"dex_finder":{"deepSearch":false}};')
    with open(DEX_FINDER, "r", encoding="utf-8") as f:
        parts.append(f.read())
    return run_spawn_script(device, package, parts, duration, FINDERMARK)


def pull_artifacts(package, out_dir):
    """从 app 私有目录 pull 产物（root 复制到 /sdcard 再拉取）。"""
    device_dir = "/data/data/%s/files/dump/" % package
    os.makedirs(out_dir, exist_ok=True)
    listing = adb(["shell", "su 0 sh -c 'ls %s'" % device_dir])
    files = [l.strip() for l in listing.splitlines() if l.strip() and not l.strip().startswith("ls:")]
    if not files:
        print("[-] 无产物在 %s" % device_dir)
        return 0

    print("[+] 设备端 %d 个文件，复制到 /sdcard 拉取..." % len(files))
    adb(["shell", "su 0 sh -c 'cp %s* /sdcard/'" % device_dir])
    pulled = 0
    for f in files:
        r = subprocess.run(["adb", "pull", "/sdcard/" + f, os.path.join(out_dir, f)],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            pulled += 1
    adb(["shell", "su 0 sh -c 'rm -f /sdcard/%s'" % files[0].split("_")[0]])
    print("[+] 已拉取 %d 个文件" % pulled)
    return pulled


def fix_checksum_all(out_dir):
    """全部 DEX fix-checksum（默认操作）。"""
    import glob
    import zlib
    fixed = 0
    for f in glob.glob(os.path.join(out_dir, "*.dex")):
        with open(f, "rb") as fh:
            data = bytearray(fh.read())
        if data[:4] != b"dex\n":
            continue
        new_sum = zlib.adler32(bytes(data[0x0C:])) & 0xFFFFFFFF
        struct.pack_into("<I", data, 0x08, new_sum)
        with open(f, "wb") as fh:
            fh.write(bytes(data))
        fixed += 1
    print("[+] fix-checksum: %d 个 DEX" % fixed)
    return fixed


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


def analyze_dex(path):
    """统计 DEX 方法体形态：总方法 / native / return-void / 有代码。"""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"dex\n":
        return None
    try:
        cls_defs_size = struct.unpack_from("<I", data, 0x60)[0]
        cls_defs_off = struct.unpack_from("<I", data, 0x64)[0]
    except Exception:
        return None

    total = native = return_void = coded = 0
    for i in range(min(cls_defs_size, 0x10000)):
        cd = cls_defs_off + i * 0x20
        if cd + 0x20 > len(data):
            break
        class_data_off = struct.unpack_from("<I", data, cd + 0x18)[0]
        if not class_data_off or class_data_off >= len(data):
            continue
        pos = class_data_off
        try:
            sf, pos = read_uleb128(data, pos)
            if_, pos = read_uleb128(data, pos)
            dm, pos = read_uleb128(data, pos)
            vm, pos = read_uleb128(data, pos)
            for _ in range(sf + if_):
                _, pos = read_uleb128(data, pos)
                _, pos = read_uleb128(data, pos)
            for _ in range(dm + vm):
                _, pos = read_uleb128(data, pos)
                flags, pos = read_uleb128(data, pos)
                code_off, pos = read_uleb128(data, pos)
                total += 1
                if flags & 0x100:  # ACC_NATIVE
                    native += 1
                elif code_off and code_off + 8 <= len(data):
                    coded += 1
                    insns_size = struct.unpack_from("<H", data, code_off + 4)[0]
                    if insns_size >= 1 and data[code_off + 8] == 0x0E:  # return-void
                        return_void += 1
        except Exception:
            break
    if total == 0:
        return None
    return {"total": total, "native": native, "coded": coded, "return_void": return_void}


def mark_methods(out_dir):
    """方法体标记：native 占比高 → Dex2C；return-void 占比高 → Skeleton；其余 OK。"""
    import glob
    print("\n[*] 方法体形态标记:")
    for f in sorted(glob.glob(os.path.join(out_dir, "*.dex"))):
        # 跳过小假 DEX（<10KB 无法解析或无 class_defs）
        fsize = os.path.getsize(f)
        if fsize < 10 * 1024:
            print("    [SKIP] %s (%.1f KB, 假 DEX 跳过)" % (os.path.basename(f), fsize / 1024))
            continue
        st = analyze_dex(f)
        if not st:
            print("    [SKIP] %s (无法解析)" % os.path.basename(f))
            continue
        native_ratio = st["native"] / st["total"] if st["total"] else 0
        rv_ratio = st["return_void"] / st["total"] if st["total"] else 0
        if native_ratio > 0.3:
            mark = "[Dex2C]"
        elif rv_ratio > 0.3:
            mark = "[Skeleton]"
        else:
            mark = "[OK]"
        print("    %s %s 方法=%d native=%d(%.0f%%) return_void=%d(%.0f%%)" % (
            mark, os.path.basename(f), st["total"], st["native"],
            native_ratio * 100, st["return_void"], rv_ratio * 100))


def dedupe(out_dir):
    if os.path.exists(DEDUPE):
        subprocess.run([sys.executable, DEDUPE, out_dir,
                        "-o", os.path.join(out_dir, "dedup")], timeout=300)


def main():
    parser = argparse.ArgumentParser(description="脱壳一键入口（线性流水线）")
    parser.add_argument("package", help="目标包名")
    parser.add_argument("--out", default="", help="本地输出目录（默认 <包名>_unpacked）")
    parser.add_argument("--host", default=DEFAULT_HOST, help="frida host（默认 127.0.0.1:7890）")
    parser.add_argument("--wait", type=int, default=90, help="每阶段等待秒数（默认 90，壳解析慢可加大）")
    parser.add_argument("--no-verify", action="store_true", help="跳过方法体标记")
    args = parser.parse_args()

    out_dir = args.out or args.package.replace(".", "_") + "_unpacked"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    device = resolve_device(args.host)
    print("[+] connected %s" % args.host)

    # 1. codeitem_dump whole（默认回填）
    print("\n=== 阶段1: codeitem_dump whole（loadClass 回填 + dump）===")
    adb(["shell", "su 0 sh -c 'rm -rf /data/data/%s/files/dump'" % args.package])
    run_codeitem_dump(device, args.package, args.wait)

    # 2. dex_finder 补充
    print("\n=== 阶段2: dex_finder（内存扫描补充）===")
    run_dex_finder(device, args.package, args.wait)

    # 3. pull
    print("\n=== 阶段3: pull 产物 ===")
    n = pull_artifacts(args.package, out_dir)
    if not n:
        print("[-] 无产物，退出")
        sys.exit(1)

    # 4. fix-checksum（默认）
    print("\n=== 阶段4: fix-checksum（默认）===")
    fix_checksum_all(out_dir)

    # 5. 去重
    print("\n=== 阶段5: 去重 ===")
    dedupe(out_dir)

    # 6. 方法体标记
    if not args.no_verify:
        print("\n=== 阶段6: 方法体形态标记 ===")
        mark_methods(out_dir)

    print("\n[+] 完成。产物: %s" % out_dir)
    print("[+] Dex2C/VMP 标记的方法需针对性分析（scan_register_natives / native_hooker）")


if __name__ == "__main__":
    main()