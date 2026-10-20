#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Anti-injection test (AndKittyInjector) - Python port of check-anti-inject.bat.

Usage:
    python3 tools/check-anti-inject.py <package> [-s SERIAL] [--no-pause] [--wait N]

Requires root + AndKittyInjector(32/64) and libhello(32/64).so on the device.
Verdict: library visible in /proc/<pid>/maps => injection works (no protection).
"""
import argparse
import re
import subprocess
import sys
import time

CONFIG = dict(
    adb="adb",
    injector64="/data/local/tmp/AndKittyInjector",
    injector32="/data/local/tmp/AndKittyInjector32",
    lib64="/data/local/tmp/libhello64.so",
    lib32="/data/local/tmp/libhello32.so",
    launch_wait=4,
    ready_timeout=25,
    settle=3,
    post_wait=2,
)


def run(args, timeout=90):
    cmd = [CONFIG["adb"]]
    if SERIAL:
        cmd += ["-s", SERIAL]
    cmd += args
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def shell(cmd, timeout=90):
    return run(["shell", cmd], timeout)


def su(cmd, timeout=120):
    return run(["shell", "su -c '%s'" % cmd.replace("'", "'\\''")], timeout)


def resolve_serial(requested):
    r = run(["devices"])
    found = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            found.append(parts[0])
    if requested:
        if requested not in found:
            print("[FAIL] Device %s not online (online: %s)" % (requested, ", ".join(found) or "none"))
            return None, found
        return requested, found
    if not found:
        return None, found
    if len(found) > 1:
        print("[WARN] Multiple devices online, using %s (override with -s)" % found[0])
    return found[0], found


def pids(pkg):
    r = shell("pidof %s" % pkg)
    return [int(t) for t in r.stdout.split() if t.isdigit()]


def file_exists(path):
    r = su("test -f %s && echo OK || echo MISSING" % path)
    return "OK" in (r.stdout + r.stderr)


def maps_grep(pid, name):
    r = su("cat /proc/%d/maps 2>/dev/null | grep %s" % (pid, name))
    return r.returncode, (r.stdout or "").strip()


def wait_ui_ready(pkg, timeout):
    """Wait until the app is foreground/resumed; injecting during early startup
    fails with KittyInjector 'remote dlopen not found'."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = shell("dumpsys activity activities 2>/dev/null | grep -E "
                  "'mResumedActivity|topResumedActivity' | grep %s" % pkg)
        if r.stdout.strip():
            return True
        time.sleep(0.5)
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Anti-injection test via AndKittyInjector")
    parser.add_argument("pkg", help="target package name")
    parser.add_argument("-s", "--serial", default=None, help="adb device serial")
    parser.add_argument("--wait", type=int, default=CONFIG["launch_wait"],
                        help="seconds to wait after launch (default %d)" % CONFIG["launch_wait"])
    parser.add_argument("--settle", type=int, default=CONFIG["settle"],
                        help="seconds to settle after UI ready (default %d)" % CONFIG["settle"])
    parser.add_argument("--no-pause", action="store_true", help="do not wait for Enter at the end")
    args = parser.parse_args()

    global SERIAL, NO_PAUSE
    NO_PAUSE = args.no_pause
    SERIAL, _ = resolve_serial(args.serial)

    pkg = args.pkg
    print("=" * 46)
    print("  Anti-Injection Test - AndKittyInjector")
    print("  Target: %s" % pkg)
    print("  Device: %s" % (SERIAL or "(none)"))
    print("  Time:   %s" % time.strftime("%Y/%m/%d %H:%M:%S"))
    print("=" * 46)
    print()

    print("[1/5] Check ADB device...")
    if not SERIAL:
        print("[FAIL] No ADB device detected")
        return 1
    print("[OK] Device connected: %s" % SERIAL)
    su("setenforce 0")  # best effort
    print()

    print("[2/5] Ensure target is running and detect bitness...")
    p = pids(pkg)
    if p:
        print("   Target already running (no restart)")
    else:
        print("   Target not running, launching once...")
        shell("monkey -p %s 1" % pkg)
        time.sleep(args.wait)
        if wait_ui_ready(pkg, timeout=CONFIG["ready_timeout"]):
            print("   [OK] UI ready")
        else:
            print("   [WARN] UI not detected in %ds, continue anyway" % CONFIG["ready_timeout"])
        print("   Settling %ds (avoid startup-phase anti-debug window)..." % args.settle)
        time.sleep(args.settle)
        p = pids(pkg)
    if not p:
        print("[FAIL] Cannot start target process")
        return 1
    pid = p[0]
    print("[OK] Process PID: %s" % ", ".join(str(x) for x in p))
    print()
    print("   Process list (for screenshot)")
    print(shell("ps -A | grep %s" % pkg).stdout.rstrip())
    print()

    def detect_64bit(pid_now):
        r = su("cat /proc/%d/maps 2>/dev/null | grep linker64" % pid_now)
        return r.returncode == 0 and bool(r.stdout.strip())

    ok64 = detect_64bit(pid)
    if not ok64:
        fresh = pids(pkg)
        if fresh and fresh[0] != pid:
            pid = fresh[0]
            print("   PID refreshed: %d" % pid)
            ok64 = detect_64bit(pid)
    if not ok64:
        m = re.search(r"primaryCpuAbi=(\S+)",
                      shell("dumpsys package %s | grep primaryCpuAbi" % pkg).stdout)
        if m:
            print("   primaryCpuAbi: %s" % m.group(1))
            ok64 = "64" in m.group(1)
    if not ok64:
        ok64 = "64" in shell("getprop ro.product.cpu.abi").stdout
    bits = 64 if ok64 else 32
    if bits == 64:
        injector = CONFIG["injector64"]
        lib = CONFIG["lib64"]
    else:
        injector = CONFIG["injector32"]
        lib = CONFIG["lib32"]
    libname = lib.rsplit("/", 1)[-1]
    print("   Detected: %d-bit process" % bits)
    print("   Injector: %s" % injector)
    print("   Library:  %s" % lib)
    print()

    print("[3/5] Verify injector and library, check maps BEFORE injection...")
    if not file_exists(injector):
        print("   [FAIL] Injector binary not found: %s" % injector)
        print("   Build: ndk-build APP_ABI=%s" % ("arm64-v8a" if bits == 64 else "armeabi-v7a"))
        print("   Push : adb push <built> %s" % injector)
        return 1
    if not file_exists(lib):
        print("   [FAIL] Library not found: %s" % lib)
        return 1
    print("   [OK] Both injector and library found")
    rc, out = maps_grep(pid, libname)
    if rc == 0 and out:
        print("   [NOTE] Residual mapping found BEFORE injection:")
        print("   %s" % out)
    else:
        print("   Result: %s NOT found in maps -- clean" % libname)
    print()

    print("[4/5] Execute injection: %s ..." % injector)
    print("=" * 46)
    print("  RAW OUTPUT from AndKittyInjector (key evidence)")
    print("  Command: su -c '%s --package %s --libs %s'" % (injector, pkg, lib))
    print("  Mode: attach to running process (no --launch, no restart)")
    print("=" * 46)
    print()
    inj = None
    out = ""
    died_in_attach = False
    attempts = 2
    for attempt in range(1, attempts + 1):
        inj = su("%s --package %s --libs %s 2>&1" % (injector, pkg, lib), timeout=180)
        out = (inj.stdout or "") + (inj.stderr or "")
        print(out.rstrip())
        print()
        p_now = pids(pkg)
        died_in_attach = (not p_now) or ("No such process" in out) or \
                         ("/exe" in out and "No such file or directory" in out)
        if not died_in_attach:
            break
        if attempt < attempts:
            print("[RETRY %d/%d] target died during ptrace attach (anti-debug?), "
                  "relaunching and retrying..." % (attempt, attempts))
            shell("monkey -p %s 1" % pkg)
            time.sleep(args.wait)
            wait_ui_ready(pkg, timeout=CONFIG["ready_timeout"])
            time.sleep(args.settle)
            print()
    print("=" * 46)
    print("  END of AndKittyInjector output")
    print("=" * 46)
    print()
    if inj.returncode != 0:
        print("[FAIL] AndKittyInjector exit code %d - injection may have failed" % inj.returncode)
    else:
        print("[OK] AndKittyInjector completed")
    print()

    print("[5/5] Verify injection via /proc/<pid>/maps...")
    time.sleep(CONFIG["post_wait"])
    p2 = pids(pkg)
    new_pid = None
    maps_out = ""
    grep_rc = 1
    if not p2:
        print("   [WARN] Process not running after injection - may have been killed")
    else:
        print("   PID: %s" % ", ".join(str(x) for x in p2))
        for cand in p2:
            rc, out = maps_grep(cand, libname)
            if rc == 0 and out:
                grep_rc, maps_out, new_pid = 0, out, cand
                break
        if new_pid is not None:
            print("   Found in PID %d:" % new_pid)
        else:
            print("   Command: cat /proc/<pid>/maps | grep %s (checked: %s)" % (
                libname, ", ".join(str(x) for x in p2)))
        print("=" * 46)
        print(maps_out if maps_out else "(no match)")
        print("=" * 46)
    print()

    if grep_rc == 0 and maps_out:
        result = "SUCCESS"
        verdict = "no anti-injection protection detected"
        evidence = "%s loaded into process memory (see above)" % libname
    elif died_in_attach:
        result = "FAILED"
        verdict = "process killed during ptrace attach (anti-debug detected)"
        evidence = "target died while injector attached; anti-injection test inconclusive"
    else:
        result = "FAILED"
        verdict = "target may have anti-injection protection"
        evidence = "%s NOT found in maps" % libname

    print("[OK/FAIL] Injection %s" % result)
    print()
    print("=" * 46)
    print("  VERDICT")
    print("=" * 46)
    print("  Target   : %s (PID: %s)" % (pkg, ", ".join(str(x) for x in p2) if p2 else "n/a"))
    print("  Bitness  : %d-bit" % bits)
    print("  Injector : %s" % injector)
    print("  Library  : %s" % lib)
    print("  Injector exit code: %d" % inj.returncode)
    print("  %s in maps: %d (0=found, 1=not found)" % (libname, grep_rc))
    print()
    print("  [VERDICT] Injection %s - %s" % (result, verdict))
    print("  Evidence: %s" % evidence)
    print()
    print("  [NOTE] Covers ptrace + /proc/pid/mem injection. Also test:")
    print("  - LD_PRELOAD injection")
    print("  - Frida injection (Gadget / frida-server)")
    print("  - /proc/pid/maps scanning detection")
    print("  - Thread name detection (pthread_setname_np)")
    print("=" * 46)
    return 0 if result == "SUCCESS" else 1


if __name__ == "__main__":
    SERIAL = None
    NO_PAUSE = False
    code = main()
    if not NO_PAUSE and sys.stdin.isatty():
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass
    sys.exit(code)
