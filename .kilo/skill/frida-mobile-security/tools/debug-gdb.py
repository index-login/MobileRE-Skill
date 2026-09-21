#!/usr/bin/env python3
"""GDB 原生调试验证工具（替代 debug-gdb.bat）

用法: python debug-gdb.py cn.boccfc.loan.finance
流程: 启动进程 -> 检查 TracerPid -> 附加 gdbserver -> GDB 取证 -> 反调试存活检测
"""
import argparse
import os
import re
import subprocess
import sys
import time

CONFIG = dict(
    adb="adb",
    gdbserver="/data/local/tmp/gdbserver64",
    gdbserver_log="/data/local/tmp/gdbserver.log",
    port=5039,
    gdb_launcher=os.path.join(os.path.dirname(os.path.abspath(__file__)), "gdb-aarch64.cmd"),
    gdb_script=os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug.gdb"),
    attach_tries=4,
)

C_RESULT = {"ok": True}


def sh(args):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=30)
    except subprocess.TimeoutExpired:
        r = subprocess.CompletedProcess(args, 124, "", "timeout")
        return r


def adb(args):
    return sh([CONFIG["adb"]] + args)


def su(cmd):
    return adb(["shell", "su -c '%s'" % cmd.replace("'", "'\\''")])


def device_pids(pkg):
    r = adb(["shell", "pidof %s" % pkg])
    pids = set()
    for tok in r.stdout.split():
        if tok.isdigit():
            pids.add(int(tok))
    return pids


def tracer_pid(pid):
    r = su("cat /proc/%d/status 2>/dev/null | grep TracerPid" % pid)
    m = re.search(r"TracerPid:\s+(\d+)", r.stdout + r.stderr)
    if m:
        return int(m.group(1))
    if r.returncode != 0:
        return None
    return None


def netstat_port(port):
    r = su("netstat -tlnp 2>/dev/null")
    m = re.search(r"0\.0\.0\.0:%d\s+.*?LISTEN\s+(\d+)/" % port, r.stdout)
    if m:
        return int(m.group(1))
    return None


def cleanup_gdbserver():
    su("killall gdbserver64 2>/dev/null; pkill gdbserver64 2>/dev/null")
    stale = netstat_port(CONFIG["port"])
    if stale:
        su("kill -9 %d 2>/dev/null" % stale)
        time.sleep(1)


def ensure_app_running(pkg):
    pids = device_pids(pkg)
    if pids:
        return pids
    print("[提示] 目标进程未运行，正在启动...")
    adb(["shell", "monkey -p %s 1" % pkg])
    time.sleep(4)
    return device_pids(pkg)


def gdbserver_attached(pid):
    su("rm -f %s" % CONFIG["gdbserver_log"])
    proc = subprocess.Popen(
        [CONFIG["adb"], "shell",
         "su -c '%s :%d --attach %d 2>&1 | tee %s'" % (
             CONFIG["gdbserver"], CONFIG["port"], pid, CONFIG["gdbserver_log"])])
    time.sleep(2)
    owner = netstat_port(CONFIG["port"])
    if owner:
        return True, proc
    try:
        proc.terminate()
    except Exception:
        pass
    return False, proc


def report_antidebug(pkg, pid, evidence):
    print()
    print("=" * 44)
    print("  检测结论: 存在 ptrace 反调试保护")
    print("=" * 44)
    print("  目标: %s (PID: %d)" % (pkg, pid))
    print("  证据: %s" % evidence)
    print("=" * 44)
    return 1


def main():
    parser = argparse.ArgumentParser(description="GDB 原生调试验证")
    parser.add_argument("pkg", help="目标包名")
    args = parser.parse_args()
    pkg = args.pkg
    port = CONFIG["port"]

    print("=" * 44)
    print("  GDB 原生调试验证")
    print("  目标: %s" % pkg)
    print("  时间: %s" % time.strftime("%Y/%m/%d %H:%M:%S"))
    print("=" * 44)
    print()

    print("[1/7] 检查 ADB 设备...")
    r = adb(["devices"])
    if "device" not in r.stdout:
        print("[失败] 未检测到 ADB 设备")
        return 1
    print("[成功] 设备已连接")
    print()

    print("[2/7] 检查目标进程: %s..." % pkg)
    pids = ensure_app_running(pkg)
    if not pids:
        print("[失败] 无法启动目标进程")
        return 1
    pid = min(pids)
    print("[成功] 进程 PID: %s" % ", ".join(str(p) for p in sorted(pids)))
    print()

    print("  --- 调试前 TracerPid (应为 0) ---")
    tp_before = tracer_pid(pid)
    print("  结果: TracerPid = %s" % tp_before)
    if tp_before == 0:
        print("  状态: 未被调试 - 干净")
    else:
        print("  状态: 已被 PID %s 跟踪! 外部 ptrace 工具将无法附加。" % tp_before)
        print()
        print("=" * 44)
        print("  检测结论: 存在 ptrace 反调试")
        print("=" * 44)
        return 1
    print()

    print("[3/7] 启动 gdbserver (端口 %d)..." % port)
    attached = False
    last_proc = None
    for try_no in range(1, CONFIG["attach_tries"] + 1):
        cleanup_gdbserver()
        pids = ensure_app_running(pkg)
        if not pids:
            print("[失败] PID %d 已失效且无法重新拉起进程" % pid)
            break
        pid = min(pids)
        ok, proc = gdbserver_attached(pid)
        last_proc = proc
        if ok:
            attached = True
            print("[成功] gdbserver 已附加 PID %d 并在 :%d 监听" % (pid, port))
            break
        print("[重试 %d/%d] PID %d 附加失败，重新获取 PID..." % (try_no, CONFIG["attach_tries"], pid))
    if not attached:
        print()
        print("  --- gdbserver 日志 ---")
        print(su("cat %s 2>/dev/null" % CONFIG["gdbserver_log"]).stdout.strip() or "(空)")
        print()
        print("=" * 44)
        print("  检测结论: 无法附加调试器")
        print("=" * 44)
        print("  目标: %s" % pkg)
        print("  证据: 见上方 gdbserver 日志")
        print("=" * 44)
        return 1
    print()
    try:
        print("  --- 调试中 TracerPid (应为 gdbserver PID) ---")
        tp_after = tracer_pid(pid)
        print("  结果: TracerPid = %s" % tp_after)
        if tp_after and tp_after != 0:
            print("  状态: 调试器已附加 - 跟踪进程 PID %d" % tp_after)
        else:
            print("  [失败] TracerPid 仍为 0 - 调试器未附加")
        print()

        print("[4/7] 端口转发...")
        adb(["forward", "tcp:%d" % port, "tcp:%d" % port])
        print(adb(["forward", "--list"]).stdout.strip())
        print("[成功] 端口 %d 转发完成" % port)
        print()

        print("[5/7] GDB 连接并执行调试操作...")
        print()
        print("=" * 44)
        print("  以下为 GDB 原始输出")
        print("  这是调试能力的关键证据")
        print("=" * 44)
        print()
        gdb_r = subprocess.run(
            '"%s" -batch -x "%s"' % (CONFIG["gdb_launcher"], CONFIG["gdb_script"]),
            shell=True, text=True, encoding="utf-8", errors="replace")
        print()
        print("=" * 44)
        print("  调试会话结束")
        print("=" * 44)
        print()
        if gdb_r.returncode != 0:
            print("[警告] GDB 返回码 %d - 可能存在反调试" % gdb_r.returncode)

        print("[6/7] 反调试检测 - 等待 5 秒...")
        print("  如果目标存在反调试，此时会自行终止")
        time.sleep(5)
        pids_after = device_pids(pkg)
        if pid not in pids_after:
            if pids_after:
                evidence = "调试器附加后原进程 PID %d 已被终止（同包新进程 %s 系自杀后重启，非被调试进程）" % (
                    pid, ", ".join(str(p) for p in sorted(pids_after)))
            else:
                evidence = "调试器附加后进程被终止"
            return report_antidebug(pkg, pid, evidence)
        print("[成功] 原调试进程 PID %d 仍存活" % pid)
        print()

        print("[7/7] 调试后 TracerPid (应为 0)...")
        tp_after_detach = tracer_pid(pid)
        if tp_after_detach is None:
            print("  结果: TracerPid = (进程不存在)")
            return report_antidebug(pkg, pid, "调试后被调试进程 PID %d 不存在，TracerPid 无法读取" % pid)
        print("  结果: TracerPid = %d" % tp_after_detach)
        if tp_after_detach == 0:
            print("  状态: 调试器已干净分离")
        else:
            print("  注意: TracerPid 仍为 %d" % tp_after_detach)
            return report_antidebug(pkg, pid, "调试分离后 TracerPid 仍为 %d" % tp_after_detach)
        print()

        print("=" * 44)
        print("  检测结论: 无 ptrace 反调试保护")
        print("=" * 44)
        print("  目标: %s (PID: %d)" % (pkg, pid))
        print("  TracerPid 变化: %s -> %s -> %s" % (tp_before, tp_after, tp_after_detach))
        print("  调试结束后进程仍正常运行，TracerPid 已恢复为 0")
        print("=" * 44)
        return 0
    finally:
        cleanup_gdbserver()


if __name__ == "__main__":
    code = main()
    if sys.stdin.isatty():
        try:
            input("\n按任意键退出...")
        except EOFError:
            pass
    sys.exit(code)