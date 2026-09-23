#!/usr/bin/env python3
"""frida_run.py — 非交互 Frida 运行器（agent 用）

为什么需要：frida CLI 是 REPL，stdin 无输入（EOF）时会自动 detach，
无法在脚本/无人值守场景做「加载 → 观察 N 秒 → 报告 → 退出」。

用法:
  python3 frida_run.py -H 127.0.0.1:8888 -f com.app -l scripts/core/utils.js -l mod.js -t 15
  python3 frida_run.py -U -n com.app -l scripts/core/utils.js -t 10 --kill

选项:
  -H host:port  远程 frida-server（需先 adb forward tcp:8888 tcp:8888）
  -U            使用 USB 设备
  -f pkg        spawn 并挂载（推荐，hook 早于应用代码；resume 由本工具控制）
  -n name       attach 到已运行进程：支持进程名 / 包名 / App label（自动解析）
  -l file       加载脚本，可重复（首个必须是 scripts/core/utils.js；支持 skill 内相对路径）
  -t seconds    保持挂载的时长，默认 15
  --kill        结束时杀掉目标进程
  --stdio       同时转发目标进程 stdout/stderr（spawn 模式）
  --host-fallback host:port   spawn 被 server 判为 jailed 时回退到此通道
"""
import argparse
import os
import re
import subprocess
import sys
import time
from collections import deque

import frida

RECENT = deque(maxlen=40)
CRASH_PAT = re.compile(r"SIGSEGV|SIGABRT|SIGILL|Fatal signal|Process terminated")
CRASH_LOG_PAT = re.compile(
    r"FATAL EXCEPTION|F DEBUG|F libc|Fatal signal|SIGSEGV|SIGABRT|SIGILL|backtrace|has died",
    re.IGNORECASE)
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
SKILL_ROOT = os.path.join(ROOT, ".kilo", "skill", "frida-mobile-security")


def resolve_load(path):
    """-l 路径解析：原样 → skill 相对（如 scripts/core/utils.js）→ 项目根相对。"""
    if os.path.isfile(path):
        return path
    for cand in (os.path.join(SKILL_ROOT, path), os.path.join(ROOT, path)):
        if os.path.isfile(cand):
            return cand
    return path


def resolve_attach_target(dev, name):
    """名字 → (pid, name)：精确名 → 应用 identifier/label → 进程名子串 → adb shell pidof。

    Android 上 frida 的进程名多为 App label（如 'Uncrackable Level 3'），
    直接传包名会 ProcessNotFoundError——这里统一兜住，免去手工 frida-ps/pidof。
    注意：frida 绑定的 device.get_process() 只接受名字，不接受 int pid。
    """
    try:
        p = dev.get_process(name)
        return p.pid, p.name
    except frida.ProcessNotFoundError:
        pass
    try:
        for app in dev.enumerate_applications():
            if name in (app.identifier, app.name) and getattr(app, "pid", 0):
                return app.pid, app.name
    except Exception:  # noqa: BLE001
        pass
    try:
        low = name.lower()
        for p in dev.enumerate_processes():
            if p.name == name or low in p.name.lower():
                return p.pid, p.name
    except Exception:  # noqa: BLE001
        pass
    try:
        out = subprocess.run(["adb", "shell", "pidof", name], capture_output=True, timeout=10)
        pid = int(out.stdout.decode().strip().split()[0])
        if pid > 0:
            return pid, name
    except Exception:  # noqa: BLE001
        pass
    return None


def capture_crash_log(tag, serial=None, lines=800, pid=None):
    """目标死亡时尽力抓 logcat：崩溃相关行打印 + 完整日志落盘。返回 (path, hits)。"""
    cmd = ["adb"] + (["-s", serial] if serial else []) + ["logcat", "-d", "-t", str(lines)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=20)
        text = proc.stdout.decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, ["[runner] logcat 抓取失败: %s" % e]
    hits = [ln for ln in text.splitlines() if CRASH_LOG_PAT.search(ln)]
    if pid:
        scoped = [ln for ln in hits if str(pid) in ln or (tag and tag in ln)]
        if scoped:
            hits = scoped
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", tag or "target")
    ts = time.strftime("%Y%m%d_%H%M%S")
    if tag and os.path.isdir(tag):
        path = os.path.join(tag, "crash_%s.log" % ts)
    else:
        path = os.path.join(os.getcwd(), "%s.crash_%s.log" % (safe, ts))
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except Exception as e:  # noqa: BLE001
        return None, ["[runner] logcat 落盘失败: %s" % e]
    return path, hits[-30:]


def emit(line):
    RECENT.append(line)
    print(line, flush=True)


def diagnose(detach, log_text):
    sig = (detach.get("signal") or "") if detach else ""
    if sig or CRASH_PAT.search(log_text):
        return ("[runner] 死因: %s → 见 references/troubleshooting.md"
                "（函数中部 inline hook / stack-protector / .text 自完整性校验）" % (sig or "崩溃"))
    return None


def create_script(session, src, runtime=""):
    """create_script with optional runtime (v8/qjs); ignored if the build rejects it."""
    if runtime:
        try:
            return session.create_script(src, runtime=runtime)
        except TypeError:
            print("[runner] runtime param unsupported by this frida build; ignored", file=sys.stderr)
    return session.create_script(src)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-H", "--host", help="remote frida-server host:port")
    ap.add_argument("-U", "--usb", action="store_true", help="use USB device")
    ap.add_argument("-D", "--device", help="device id (frida -D)")
    ap.add_argument("-f", "--spawn", help="package name to spawn")
    ap.add_argument("-n", "--attach", help="process name / package / App label to attach")
    ap.add_argument("-p", "--pid", type=int, help="attach to pid (frida -p)")
    ap.add_argument("-F", "--frontmost", action="store_true", help="attach to frontmost app (frida -F)")
    ap.add_argument("--host-fallback", help="spawn 被 server 判为 jailed 时回退的 host:port")
    ap.add_argument("--runtime", default="", help="script runtime: v8 | qjs")
    ap.add_argument("-l", "--load", action="append", default=[], help="script file to load")
    ap.add_argument("-t", "--timeout", type=int, default=15, help="seconds to stay attached")
    ap.add_argument("--kill", action="store_true", help="kill target process at the end")
    ap.add_argument("--stdio", action="store_true", help="also pipe target stdout/stderr")
    args = ap.parse_args()
    args.load = [resolve_load(p) for p in args.load]

    if args.device:
        dev = frida.get_device(args.device, timeout=10)
    elif args.usb:
        dev = frida.get_usb_device(timeout=10)
    elif args.host:
        dev = frida.get_device_manager().add_remote_device(args.host)
    else:
        print("[runner] need -D / -U / -H", file=sys.stderr)
        return 2

    if args.frontmost:
        app = dev.get_frontmost_application()
        if app is None:
            print("[runner] no frontmost application", file=sys.stderr)
            return 2
        args.pid = app.pid
        print("[runner] frontmost: %s pid=%d" % (getattr(app, "identifier", "?"), app.pid), flush=True)

    pid = None
    spawned = False
    if args.spawn:
        spawn_kwargs = {"stdio": "pipe"} if args.stdio else {}
        try:
            pid = dev.spawn([args.spawn], **spawn_kwargs)
        except frida.NotSupportedError as e:
            msg = str(e)
            print("[runner] spawn failed: %s" % msg, file=sys.stderr)
            if "Gadget" in msg or "jailed" in msg:
                print("[runner] hint: device is treated as jailed by frida-server (restricted/patched server)."
                      " Use remote channel: adb forward tcp:8888 tcp:8888 then add -H 127.0.0.1:8888",
                      file=sys.stderr)
                if args.host_fallback:
                    dev = frida.get_device_manager().add_remote_device(args.host_fallback)
                    pid = dev.spawn([args.spawn], **spawn_kwargs)
                    print("[runner] fallback device: %s" % args.host_fallback, flush=True)
                else:
                    return 3
            else:
                raise
        spawned = True
        print("[runner] spawned %s pid=%d" % (args.spawn, pid), flush=True)
        session = dev.attach(pid)
    else:
        if args.pid is not None:
            session = dev.attach(args.pid)
            pid = args.pid
            print("[runner] attached to pid=%d" % args.pid, flush=True)
        else:
            res = resolve_attach_target(dev, args.attach)
            if res is None:
                print("[runner] target not found: %r (process name / package / label all mismatched);"
                      " check with frida-ps -H <host> or adb shell pidof;"
                      " if it is a package that is not running, use -f <pkg> to spawn" % args.attach,
                      file=sys.stderr)
                return 2
            pid, pname = res
            session = dev.attach(pid)
            print("[runner] attached to %s (pid=%d, name=%r)" % (args.attach, pid, pname), flush=True)

    detach = {}

    def _on_detached(reason, *rest):
        detach["reason"] = str(reason)
        crash = rest[0] if rest else None
        if crash is not None:
            detach["signal"] = str(getattr(crash, "signal", "") or "")
            detach["address"] = str(getattr(crash, "address", "") or "")

    session.on("detached", _on_detached)

    src = "\n".join(open(p, encoding="utf-8").read() for p in args.load)
    script = create_script(session, src, args.runtime)

    try:
        script.set_log_handler(lambda level, text: emit("[%s] %s" % (level, text)))
    except AttributeError:
        pass
    script.on("message", lambda m, d: emit("[msg] %s" % (m,)))

    if args.stdio:
        dev.on("output", lambda pid_, fd, data: emit(
            "[out:%d:%d] %s" % (pid_, fd, data.decode("utf-8", "replace").rstrip())))

    script.load()
    print("[runner] loaded: %s" % ", ".join(args.load), flush=True)

    if spawned:
        dev.resume(pid)
        print("[runner] resumed main thread", flush=True)

    time.sleep(args.timeout)

    if pid is not None:
        try:
            alive = any(p.pid == pid for p in dev.enumerate_processes())
            print("[runner] alive after %ds: %s" % (args.timeout, alive), flush=True)
            if not alive:
                tip = diagnose(detach, "\n".join(RECENT))
                if tip:
                    print(tip, flush=True)
                tag = args.spawn or args.attach or ("pid%d" % pid)
                path, hits = capture_crash_log(tag, args.device, pid=pid)
                if path:
                    print("[runner] crash log: %s (%d hit lines)" % (path, len(hits)), flush=True)
                for ln in hits:
                    print("[logcat] " + ln, flush=True)
        except Exception as e:  # noqa: BLE001
            print("[runner] enumerate failed: %s" % e, flush=True)

    if args.kill and pid is not None:
        try:
            dev.kill(pid)
            print("[runner] killed pid=%d" % pid, flush=True)
        except Exception as e:  # noqa: BLE001
            print("[runner] kill failed: %s" % e, flush=True)

    session.detach()
    print("[runner] detached", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
