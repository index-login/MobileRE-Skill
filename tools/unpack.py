#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unpack.py - 脱壳一键入口（线性流水线，AI 只调一次）

定位：**Frida 已可注入之后的最大化采集**。不负责过检测——检测绕过属于
frida-mobile-security 的 bypass 模块，确认能挂上之后再调本工具。

用法:
    python3 unpack.py <包名> [--out 输出目录]
    python3 unpack.py <包名> --host 127.0.0.1:27042 --pid 1234    # Gadget / 任意端口
    python3 unpack.py <包名> --host 127.0.0.1:27042 --pid 1234 --ext  # Gadget 且无 root
    python3 unpack.py <包名> --all-pids                            # 多进程
    python3 unpack.py <包名> --usb                                 # USB 直连 frida-server

流程（单次 spawn/attach，同会话完成）:
    1. dex_capture：hook mmap 记录可读区间，周期扫描抢在释放前落盘
    2. dex_defineclass_dump：DefineClass 钩子，抓运行时动态定义的 DEX
    3. codeitem_dump whole：loadClass 全部类（默认回填），每 N 批增量落盘
    4. dex_finder 补充：内存扫描 DexCache 未覆盖的 DEX（同一会话内接续）
    5. 自动 pull 产物（私有目录走 root→/sdcard；--ext 走外部私有目录直拉；只此一个目录）
    6. repair：file_size（map_list）校正 + SHA-1 + Adler32
    7. 去重（dex_dedupe）
    8. 覆盖率统计（中性数字，写入 `_coverage.txt`）
    9. 清理设备端产物（`--keep` 保留）

设计原则:
    - 只负责"多脱"：不做 Dex2C/VMP 判定，不过滤可疑产物（判定交给 jadx）
    - 默认全部回填（loadClass 对一代壳无害，对抽取壳必要，无需判断壳类型）
    - 中途被杀也不能全丢：增量落盘 + 旧产物轮换为 dump.prev

依赖:
    pip install frida-tools
    adb + frida-server / Gadget 在设备上
    Gadget 或自定义端口：--host 127.0.0.1:<port>（默认自动 adb forward）
"""

import argparse
import glob
import json
import os
import re
import struct
import subprocess
import sys
import time
import zlib

import frida

# ==================== 配置 ====================
DEFAULT_HOST = "127.0.0.1:8888"
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_SCRIPTS = os.path.normpath(os.path.join(
    TOOLS_DIR, os.pardir, ".kilo", "skill", "frida-mobile-security", "scripts"))
CORE = os.path.join(SKILL_SCRIPTS, "core", "utils.js")
CODEITEM_DUMP = os.path.join(SKILL_SCRIPTS, "utils", "codeitem_dump.js")
DEX_FINDER = os.path.join(SKILL_SCRIPTS, "utils", "dex_finder.js")
DEFINE_CLASS_DUMP = os.path.join(SKILL_SCRIPTS, "utils", "dex_defineclass_dump.js")
DEX_CAPTURE = os.path.join(SKILL_SCRIPTS, "utils", "dex_capture.js")
DEDUPE = os.path.join(TOOLS_DIR, "dex_dedupe.py")
CODEMARK = "FART] whole-dex dump done"
FINDERMARK = "DEXFINDER] done"
APP_DUMP_PRIVATE = "/data/data/%s/files/dump"
APP_DUMP_EXTERNAL = "/sdcard/Android/data/%s/files/dump"
ADB_SERIAL = None


def adb_cmd(extra):
    return ["adb"] + (["-s", ADB_SERIAL] if ADB_SERIAL else []) + extra


def adb(args, timeout=120):
    """执行 adb 命令，返回 stdout（UTF-8，坏字节替换）。"""
    r = subprocess.run(adb_cmd(args), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    return r.stdout


def adb_root(cmd, timeout=120):
    """以 root 在设备上执行 shell 片段。cmd 内不要含单引号。"""
    return adb(["shell", "su 0 sh -c '%s'" % cmd], timeout=timeout)


def read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def resolve_device(args):
    """连接设备。--usb 走 USB；--host 支持任意 host:port（frida-server 或 Gadget）。"""
    if args.usb:
        return frida.get_usb_device(timeout=5)
    host = args.host
    port = "27042"
    if host.isdigit():
        host, port = "127.0.0.1", host
    elif ":" in host:
        host, port = host.rsplit(":", 1)
    if args.forward and host in ("127.0.0.1", "localhost"):
        adb(["forward", "tcp:%s" % port, "tcp:%s" % port])
    return frida.get_device_manager().add_remote_device("%s:%s" % (host, port))


def pids_of(package):
    out = adb(["shell", "pidof %s" % package]).strip()
    return [int(x) for x in out.split()] if out else []


def is_root():
    """root 判定看 su 是否可用（adb shell 本身通常是 uid 2000）。"""
    try:
        out = adb_root("id -u").strip().splitlines()
        return bool(out) and out[-1].strip() == "0"
    except Exception:
        return False


def device_dump_dir(package, ext):
    return (APP_DUMP_EXTERNAL if ext else APP_DUMP_PRIVATE) % package


def list_dir(path, ext):
    """列设备目录。ext 模式不需要 root。"""
    out = adb(["shell", "ls %s" % path]) if ext else adb_root("ls %s" % path)
    return [l.strip() for l in out.splitlines() if l.strip() and not l.strip().startswith("ls:")]


def rotate_dump(package, ext, fresh):
    """旧产物轮换为 dump.prev（默认），--fresh 时直接清空。ext 模式只能尽力清理。"""
    d = device_dump_dir(package, ext)
    if ext:
        if fresh:
            adb(["shell", "rm -rf %s" % d])
        return
    if fresh:
        adb_root("rm -rf %s %s.prev" % (d, d))
    else:
        adb_root("if [ -d %s ]; then rm -rf %s.prev; mv %s %s.prev; fi" % (d, d, d, d))


def has_dump(package, ext):
    return len(list_dir(device_dump_dir(package, ext), ext)) > 0


def stage1_source(args, ext):
    """utils +（可选）defineclass 钩子 + codeitem_dump。defineclass 必须在 loadClass 前挂上。"""
    out = device_dump_dir(args.package, ext) + "/"
    parts = [read_text(CORE)]
    override = {}
    ci = {"outputDir": out, "autoFart": not args.no_fart, "dumpOnly": bool(args.no_fart)}
    if args.batch:
        ci["batchSize"] = args.batch
    if args.delay is not None and args.delay >= 0:
        ci["batchDelay"] = args.delay
    if args.dump_every is not None and args.dump_every >= 0:
        ci["dumpEveryBatches"] = args.dump_every
    if ext:
        ci["useExternalDir"] = True
    override["codeitem_dump"] = ci
    dc = {"outputDir": out}
    if ext:
        dc["useExternalDir"] = True
    override["dex_defineclass_dump"] = dc
    cap = {"outputDir": out, "hookMmap": bool(args.mmap)}
    if ext:
        cap["useExternalDir"] = True
    override["dex_capture"] = cap
    parts.append("var CONFIG_OVERRIDE = %s;" % json.dumps(override))
    if not args.no_capture:
        parts.append(read_text(DEX_CAPTURE))
    if not args.no_defineclass:
        parts.append(read_text(DEFINE_CLASS_DUMP))
    parts.append(read_text(CODEITEM_DUMP))
    return "\n".join(parts)


def finder_source(package, deep, ext):
    parts = [read_text(CORE)]
    cfg = {"deepSearch": bool(deep), "outputDir": device_dump_dir(package, ext) + "/"}
    if ext:
        cfg["useExternalDir"] = True
    parts.append("var CONFIG_OVERRIDE = %s;" % json.dumps({"dex_finder": cfg}))
    parts.append(read_text(DEX_FINDER))
    return "\n".join(parts)


PROGRESS_RE = re.compile(r"loadClass (\d+)-(\d+) / (\d+)")


def make_script(session, source, logs):
    script = session.create_script(source)
    state = {"last": 0.0, "bucket": -1}

    def handle(text):
        logs.append(text)
        m = PROGRESS_RE.search(text)
        if m:
            end, total = int(m.group(2)), int(m.group(3))
            pct = (end * 100 // total) if total else 0
            now = time.time()
            if sys.stdout.isatty():
                if now - state["last"] >= 0.3 or end == total:
                    state["last"] = now
                    print("\r    [阶段1] %3d%%  %d/%d" % (pct, end, total), end="", flush=True)
            else:
                bucket = pct // 10
                if bucket > state["bucket"]:
                    state["bucket"] = bucket
                    print("    [阶段1] %3d%%  %d/%d" % (pct, end, total), flush=True)
            return
        if ("incremental" in text) or ("whole-dex dump done" in text) or ("DEXFINDER] done" in text):
            print("    " + text, flush=True)

    def on_message(msg, data):
        if msg.get("type") == "send":
            handle(str(msg.get("payload", "")))
        elif msg.get("type") == "error":
            handle("[ERROR] " + str(msg.get("description", msg)))

    def on_log(level, text):
        handle(str(text))

    script.on("message", on_message)
    script.set_log_handler(on_log)
    script.load()
    return script


def wait_for(logs, marker, stall=45.0, hard=0.0):
    """等到 marker 出现。stall 秒内没有任何新日志才判定卡死；hard>0 时作为绝对上限。"""
    start = time.time()
    last_len = 0
    last_change = start
    while True:
        if any(marker in l for l in logs):
            return True
        now = time.time()
        if len(logs) != last_len:
            last_len = len(logs)
            last_change = now
        if hard and now - start >= hard:
            return False
        if now - last_change >= stall:
            return False
        time.sleep(0.5)


def run_one(device, package, target, args, ext):
    """单进程：stage1 + stage2 在同一会话内完成。target=None 时 spawn。"""
    logs = []
    spawned = False
    pid = target
    if pid is None:
        try:
            pid = device.spawn([package])
            spawned = True
        except Exception as e:
            procs = device.enumerate_processes()
            if len(procs) == 1:
                pid = procs[0].pid
                print("[!] spawn 不可用（Gadget/受限环境），自动 attach pid=%d (%s)" % (pid, procs[0].name))
            else:
                raise RuntimeError("spawn 失败且进程不唯一（%d 个），请用 --pid 指定：%s" % (len(procs), e))

    print("[*] %s pid=%s" % ("spawn" if spawned else "attach", pid), flush=True)
    try:
        session = device.attach(pid)
    except Exception as e:
        print("[-] attach 失败：%s" % e)
        return logs

    try:
        print("[*] 加载阶段1（%s）..." % ("温和模式：DexCache dump + 扫描" if args.no_fart
                                        else "DefineClass + loadClass 回填"), flush=True)
        s1 = make_script(session, stage1_source(args, ext), logs)
        if spawned:
            device.resume(pid)
        print("[*] 脚本已加载，开始回填", flush=True)
        ok1 = wait_for(logs, CODEMARK, stall=args.wait, hard=args.timeout)
        if sys.stdout.isatty():
            print()
        if not ok1:
            print("[!] 阶段1 停滞 %ds（无新进度，应用可能被自身保护杀掉）" % args.wait)
            if not args.no_fart:
                print("[!] 建议加 --no-fart 重跑（跳过 loadClass，只做 DexCache + 扫描）")
        else:
            try:
                s1.unload()
            except Exception:
                pass
        time.sleep(2)

        deep = args.deep or not has_dump(package, ext)
        if deep and not args.deep:
            print("[!] 阶段1 无产物，自动启用 dex_finder deepSearch")
        print("[*] 阶段2：dex_finder 内存扫描（deep=%s）..." % deep, flush=True)
        make_script(session, finder_source(package, deep, ext), logs)
        if not wait_for(logs, FINDERMARK, stall=max(args.wait, 60), hard=args.timeout):
            print("[!] 阶段2 停滞（应用可能被杀/超时）")
    finally:
        try:
            session.detach()
        except Exception:
            pass
    return logs


def _pull_one(src, dst):
    r = subprocess.run(adb_cmd(["pull", src, dst]), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120)
    return r.returncode == 0


def pull_artifacts(package, out_dir, ext):
    """pull 产物，返回 (已拉取, 总数)。只认单一 dump 目录。"""
    os.makedirs(out_dir, exist_ok=True)
    device_dir = device_dump_dir(package, ext)
    files = list_dir(device_dir, ext)
    if not files:
        print("[-] 无产物在 %s" % device_dir)
        return 0, 0

    print("[+] 设备端 %d 个文件，拉取..." % len(files))
    pulled = 0
    for f in files:
        src = "%s/%s" % (device_dir, f)
        if not ext:
            adb_root("cp %s /sdcard/" % src)
            src = "/sdcard/" + f
        if _pull_one(src, os.path.join(out_dir, f)):
            pulled += 1
        if not ext:
            adb_root("rm -f /sdcard/%s" % f)
    print("[+] 已拉取 %d/%d 个文件" % (pulled, len(files)))
    return pulled, len(files)


def cleanup_device(package, ext, keep):
    """拉取完成后清理设备端，避免 /sdcard 与私有目录堆积垃圾。"""
    if keep:
        print("[+] --keep：保留设备端产物")
        return
    ext_dir = APP_DUMP_EXTERNAL % package
    priv_dir = APP_DUMP_PRIVATE % package
    try:
        if is_root():
            adb_root("rm -rf %s %s.prev %s %s.prev" % (priv_dir, priv_dir, ext_dir, ext_dir))
            adb_root("rm -f /data/local/tmp/fart/whole_*.dex /data/local/tmp/fart/ins.bin "
                     "/data/local/tmp/dex_dump/whole_*.dex /data/local/tmp/dex_dump/found_*.dex "
                     "/data/local/tmp/dex_dump/defineclass_*.dex /data/local/tmp/dex_dump/ins.bin")
        else:
            adb(["shell", "rm -rf %s %s.prev" % (ext_dir, ext_dir)])
        print("[+] 设备端产物已清理")
    except Exception as e:
        print("[!] 清理失败：%s（可加 --keep 跳过）" % e)


def repair_dex_all(out_dir):
    """file_size（按 map_list 校正）+ SHA-1 + Adler32。不做任何过滤。"""
    import hashlib
    fixed = 0
    for f in glob.glob(os.path.join(out_dir, "*.dex")):
        try:
            with open(f, "rb") as fh:
                data = bytearray(fh.read())
            if len(data) < 0x70 or data[:4] != b"dex\n":
                continue
            map_off = struct.unpack_from("<I", data, 0x34)[0]
            if 0x70 <= map_off <= len(data) - 4:
                n = struct.unpack_from("<I", data, map_off)[0]
                end = map_off + 4 + n * 12
                if 0 < n <= 0x10000 and end <= len(data):
                    struct.pack_into("<I", data, 0x20, end)
            data[0x0C:0x20] = hashlib.sha1(bytes(data[0x20:])).digest()
            struct.pack_into("<I", data, 0x08, zlib.adler32(bytes(data[0x0C:])) & 0xFFFFFFFF)
            with open(f, "wb") as fh:
                fh.write(bytes(data))
            fixed += 1
        except Exception:
            continue
    print("[+] repair: %d 个 DEX（file_size/SHA-1/Adler32）" % fixed)
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


def analyze_dex_full(path):
    """中性统计：类数 / 方法数 / 有代码 / native / 空体 / NOP 体。不做任何判定。"""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 0x70 or data[:4] != b"dex\n":
        return None
    try:
        cls_defs_size, cls_defs_off = struct.unpack_from("<II", data, 0x60)
    except Exception:
        return None
    if cls_defs_off < 0x70 or cls_defs_off + cls_defs_size * 0x20 > len(data):
        return None

    st = {"classes": 0, "methods": 0, "coded": 0, "native": 0, "empty": 0, "nop": 0}
    for i in range(min(cls_defs_size, 0x20000)):
        cd = cls_defs_off + i * 0x20
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
            st["classes"] += 1
            for _ in range(dm + vm):
                _, pos = read_uleb128(data, pos)
                flags, pos = read_uleb128(data, pos)
                code_off, pos = read_uleb128(data, pos)
                st["methods"] += 1
                if flags & 0x100:  # ACC_NATIVE
                    st["native"] += 1
                elif code_off and code_off + 8 <= len(data):
                    st["coded"] += 1
                    insns = struct.unpack_from("<H", data, code_off + 4)[0]
                    if insns == 0:
                        st["empty"] += 1
                    elif insns <= 64:
                        blob = data[code_off + 8:code_off + 8 + insns * 2]
                        if blob and blob.count(0) == len(blob):
                            st["nop"] += 1
                elif not (flags & 0x400):  # 非 abstract 且无 code
                    st["empty"] += 1
        except Exception:
            continue
    if st["methods"] == 0:
        return None
    return st


def report_coverage(out_dir):
    """覆盖率统计（中性数字，不做 Dex2C/VMP 判定）。不可解析的文件保留不删。"""
    print("\n[*] 覆盖率（中性统计，判定交给 jadx）")
    rows = []
    tot = {"classes": 0, "methods": 0, "coded": 0, "native": 0, "empty": 0, "nop": 0}
    unparsed = 0
    for f in sorted(glob.glob(os.path.join(out_dir, "*.dex"))):
        name = os.path.basename(f)
        st = analyze_dex_full(f)
        if not st:
            unparsed += 1
            print("    [?] %-24s 无法解析（保留）" % name)
            continue
        print("    %-24s classes=%-5d methods=%-6d coded=%-6d native=%-5d empty=%-4d nop=%d" % (
            name, st["classes"], st["methods"], st["coded"], st["native"], st["empty"], st["nop"]))
        rows.append((name, st))
        for k in tot:
            tot[k] += st[k]

    print("    TOTAL classes=%d methods=%d coded=%d native=%d empty=%d nop=%d" % (
        tot["classes"], tot["methods"], tot["coded"], tot["native"], tot["empty"], tot["nop"]))
    with open(os.path.join(out_dir, "_coverage.txt"), "w", encoding="utf-8") as fh:
        fh.write("TOTAL classes=%d methods=%d coded=%d native=%d empty=%d nop=%d unparsed=%d\n" % (
            tot["classes"], tot["methods"], tot["coded"], tot["native"], tot["empty"],
            tot["nop"], unparsed))
        for name, st in rows:
            fh.write("%s classes=%d methods=%d coded=%d native=%d empty=%d nop=%d\n" % (
                name, st["classes"], st["methods"], st["coded"], st["native"],
                st["empty"], st["nop"]))
    if unparsed:
        print("[!] %d 个文件无法解析，已原样保留（可能是 cdex / 位移表 / 假 DEX）" % unparsed)
    return rows


def dedupe(out_dir):
    if os.path.exists(DEDUPE):
        subprocess.run([sys.executable, DEDUPE, out_dir,
                        "-o", os.path.join(out_dir, "dedup")], timeout=300)


def main():
    if not sys.stdout.isatty():
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description="脱壳一键入口（检测已过后最大化采集）")
    parser.add_argument("package", help="目标包名")
    parser.add_argument("--out", default="", help="本地输出目录（默认 <包名>_unpacked）")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="frida host:port，任意端口（frida-server 或 Gadget，默认 %s）" % DEFAULT_HOST)
    parser.add_argument("--usb", action="store_true", help="直接用 USB 设备（frida-server，无需端口转发）")
    parser.add_argument("--ext", action="store_true",
                        help="产物写外部私有目录（/sdcard/Android/data/<pkg>/files/dump），无 root / Gadget 用；无 root 时自动启用")
    parser.add_argument("--no-forward", dest="forward", action="store_false", default=True,
                        help="不自动 adb forward（已手动转发 / Gadget 走内网时）")
    parser.add_argument("--serial", default=None, help="adb 序列号（多设备时必填）")
    parser.add_argument("--pid", default=None,
                        help="attach 模式：PID 或进程名（Gadget 常用；不 spawn）")
    parser.add_argument("--all-pids", action="store_true", help="attach 到该包的所有进程")
    parser.add_argument("--fresh", action="store_true", help="清空设备端产物（默认轮换为 dump.prev）")
    parser.add_argument("--wait", type=int, default=45,
                        help="停滞判定秒数：多少秒没有任何新进度才算卡死（默认 45；只要还在推进就一直等）")
    parser.add_argument("--timeout", type=int, default=0,
                        help="绝对上限秒数（默认 0 = 不设上限，仅靠停滞判定）")
    parser.add_argument("--batch", type=int, default=0, help="loadClass 每批类数（默认 100）")
    parser.add_argument("--delay", type=int, default=-1, help="批次间隔 ms（默认 300；慢速壳加大）")
    parser.add_argument("--dump-every", type=int, default=-1,
                        help="每 N 批增量落盘（默认 15；0 = 只在结束时落盘）")
    parser.add_argument("--deep", action="store_true", help="强制 dex_finder 深度搜索（抹 magic 的壳）")
    parser.add_argument("--no-fart", action="store_true",
                        help="温和模式：跳过 loadClass 回填，只做 DexCache dump + 内存扫描（脆弱的加固 App 用）")
    parser.add_argument("--no-defineclass", action="store_true",
                        help="不加载 DefineClass 钩子（默认加载）")
    parser.add_argument("--no-capture", action="store_true",
                        help="不加载 dex_capture（默认加载；mmap 钩子默认关）")
    parser.add_argument("--mmap", action="store_true",
                        help="启用 mmap 钩子（高频回调会拖慢/阻塞 loadClass，仅短时 attach 建议打开）")
    parser.add_argument("--keep", action="store_true",
                        help="保留设备端产物（默认拉取成功后清理）")
    parser.add_argument("--no-verify", action="store_true", help="跳过覆盖率统计")
    args = parser.parse_args()

    out_dir = args.out or args.package.replace(".", "_") + "_unpacked"

    global ADB_SERIAL
    ADB_SERIAL = args.serial
    device = resolve_device(args)
    print("[+] connected %s" % ("usb" if args.usb else args.host))

    ext = args.ext or not is_root()
    print("[+] 存储模式: %s" % ("外部私有目录（无 root / --ext）" if ext else "app 私有目录（root）"))

    if args.all_pids:
        targets = pids_of(args.package) or [None]
    elif args.pid:
        targets = [int(args.pid) if str(args.pid).isdigit() else args.pid]
    else:
        targets = [None]
    print("[+] targets: %s" % ", ".join("spawn" if t is None else str(t) for t in targets))

    d = device_dump_dir(args.package, ext)
    rotate_dump(args.package, ext, args.fresh)
    print("[+] 设备产物目录: %s%s" % (d, "" if (args.fresh or ext) else "（上次产物已轮换为 dump.prev）"))

    all_logs = []
    for target in targets:
        print("\n=== 采集 %s ===" % ("spawn" if target is None else "pid=%s" % target))
        try:
            all_logs += run_one(device, args.package, target, args, ext)
        except Exception as e:
            print("[-] 采集失败：%s" % e)

    print("\n=== pull 产物 ===")
    n, total = pull_artifacts(args.package, out_dir, ext)
    if not n:
        print("[-] 无产物，退出。若上次运行有结果，可在设备 %s.prev 手动拉取" % d)
        sys.exit(1)

    print("\n=== repair（file_size/SHA-1/Adler32）===")
    repair_dex_all(out_dir)

    print("\n=== 去重 ===")
    dedupe(out_dir)

    if not args.no_verify:
        print("\n=== 覆盖率统计 ===")
        cov_dir = os.path.join(out_dir, "dedup")
        report_coverage(cov_dir if os.path.isdir(cov_dir) else out_dir)

    if all_logs:
        with open(os.path.join(out_dir, "_frida.log"), "w", encoding="utf-8") as f:
            f.write("\n".join(all_logs))
        print("[+] Frida 日志: %s" % os.path.join(out_dir, "_frida.log"))

    print("\n=== 清理设备端 ===")
    if n == total:
        cleanup_device(args.package, ext, args.keep)
    else:
        print("[!] 有 %d/%d 个文件未拉取，跳过清理（确认后加 --keep 或手动删）" % (total - n, total))

    print("\n[+] 完成。产物: %s" % out_dir)


if __name__ == "__main__":
    main()
