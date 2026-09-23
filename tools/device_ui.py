#!/usr/bin/env python3
"""device_ui.py — 设备交互套件（agent 用）：元素树/输入/点击/滑动/按键/截图/日志/前台/常亮。

用法:
  python3 device_ui.py elements [--grep REGEX] [--clickable] [--json]  # 元素树
  python3 device_ui.py tap --text VERIFY | --id edit_text | <x> <y>    # 语义或坐标点击
  python3 device_ui.py wait-for --text Success [--timeout 10] [--gone] # 等元素出现/消失
  python3 device_ui.py text "hello world" [--replace] [--no-verify] # 空格自动转 %s；默认输入后校验
  python3 device_ui.py launch <pkg> | clear | stayon [on|off] | wake [--unlock]
  python3 device_ui.py swipe 540 1500 540 500 [--ms 300]
  python3 device_ui.py key BACK|HOME|ENTER|TAB|67                     # 名称或数字 keycode
  python3 device_ui.py shot [--out <file.png>]                        # 默认 shot_<时间戳>.png
  python3 device_ui.py logs [--grep REGEX] [--tail 200] [--clear]
  python3 device_ui.py foreground | size
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

KEYCODES = {
    "HOME": 3, "BACK": 4, "CALL": 5, "ENDCALL": 6, "UP": 19, "DOWN": 20,
    "LEFT": 21, "RIGHT": 22, "CENTER": 23, "VOLUME_UP": 24, "VOLUME_DOWN": 25,
    "POWER": 26, "CAMERA": 27, "ENTER": 66, "DEL": 67, "DELETE": 67,
    "TAB": 61, "SPACE": 62, "ESCAPE": 111, "MENU": 82, "APP_SWITCH": 187,
    "NOTIFICATION": 83,
}


def adb(args, binary_stdout=None):
    cmd = ["adb"] + args
    if binary_stdout:
        with open(binary_stdout, "wb") as f:
            rc = subprocess.call(cmd, stdout=f)
        return rc, ""
    proc = subprocess.run(cmd, capture_output=True)
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        out += err
    return proc.returncode, out


def sh_single_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


INPUT_CLASS_HINTS = ("EditText", "AutoCompleteTextView")


def focused_edit(elems=None):
    els = elems if elems is not None else dump_elements()
    for e in els:
        if e["focused"] and any(h in e["class"] for h in INPUT_CLASS_HINTS):
            return e
    return None


def clear_input(n=64, rounds=4):
    """清空输入框：MOVE_END + DEL xN 循环，直到字段文本不再变化（空框回显 hint）。

    返回 (ok, last_text)。无聚焦元素时无法确认清空结果 → ok=False（不再静默报 ok）。
    """
    prev = None
    last = None
    for _ in range(rounds):
        adb(["shell", "input keyevent 123"])  # MOVE_END
        adb(["shell", "input keyevent " + " ".join(["67"] * n)])  # DEL xN
        fe = focused_edit()
        if fe is None:
            return False, last
        last = fe["text"]
        if last == prev:
            break
        prev = last
    return (last is not None), last


def dump_elements(retries=2):
    """Dump UI hierarchy (uiautomator) and return parsed element list.

    用 /data/local/tmp（重启后 /sdcard 未挂载时仍可用）；dump 失败（如被杀）时重试。
    """
    path = "/data/local/tmp/mre_ui.xml"
    out = ""
    for _ in range(retries + 1):
        _, out = adb(["shell", "uiautomator", "dump", path])
        if "dumped to" in out:
            break
        time.sleep(0.8)
    _, raw = adb(["exec-out", "cat", path])
    i = raw.find("<")
    if i < 0:
        return []
    try:
        root = ET.fromstring(raw[i:])
    except ET.ParseError:
        return []
    elems = []
    for node in root.iter("node"):
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds") or "")
        if not m:
            continue
        x1, y1, x2, y2 = (int(v) for v in m.groups())
        elems.append({
            "class": node.get("class", ""),
            "text": node.get("text", ""),
            "id": node.get("resource-id", ""),
            "desc": node.get("content-desc", ""),
            "center": ((x1 + x2) // 2, (y1 + y2) // 2),
            "size": (x2 - x1, y2 - y1),
            "clickable": node.get("clickable") == "true",
            "focused": node.get("focused") == "true",
        })
    return elems


def match_element(elems, text="", id_="", desc=""):
    for e in elems:
        if text and text not in e["text"]:
            continue
        if id_ and id_ not in e["id"]:
            continue
        if desc and desc not in e["desc"]:
            continue
        return e
    return None


def fmt_element(e):
    flags = (" clickable" if e["clickable"] else "") + (" focused" if e["focused"] else "")
    return "%s text=%r id=%s desc=%r center=%s size=%dx%d%s" % (
        e["class"].rsplit(".", 1)[-1], e["text"], e["id"] or "-", e["desc"],
        e["center"], e["size"][0], e["size"][1], flags)


def screen_size():
    _, out = adb(["shell", "wm", "size"])
    m = re.search(r"(\d+)x(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (1080, 1920)


def foreground():
    """Foreground window/activity across ROM variants (mCurrentFocus may be missing)."""
    for cmd in (["shell", "dumpsys", "window"],
                ["shell", "dumpsys", "activity", "activities"],
                ["shell", "dumpsys", "window", "windows"]):
        _, out = adb(cmd)
        for ln in out.splitlines():
            if "mCurrentFocus" in ln or "mResumedActivity" in ln:
                return ln.strip()
    return ""


def main():
    ap = argparse.ArgumentParser(description="设备交互套件（adb 封装）")
    sub = ap.add_subparsers(dest="cmd", metavar="<操作>")

    p = sub.add_parser("text", help="输入文本（空格自动转 %%s；默认输入后校验字段内容）")
    p.add_argument("value")
    p.add_argument("--replace", action="store_true", help="先清空当前输入框再输入（清空结果会校验）")
    p.add_argument("--no-verify", action="store_true", help="跳过输入后校验（文本会被 App 变形时用）")

    p = sub.add_parser("tap", help="点击：坐标或元素（--text/--id/--desc 现 dump 再定位）")
    p.add_argument("x", type=int, nargs="?")
    p.add_argument("y", type=int, nargs="?")
    p.add_argument("--text", default="")
    p.add_argument("--id", default="")
    p.add_argument("--desc", default="")

    p = sub.add_parser("elements", help="元素树（uiautomator dump 解析）")
    p.add_argument("--json", action="store_true")
    p.add_argument("--grep", default="")
    p.add_argument("--clickable", action="store_true")

    p = sub.add_parser("wait-for", help="等待元素出现/消失（--gone）")
    p.add_argument("--text", default="")
    p.add_argument("--id", default="")
    p.add_argument("--desc", default="")
    p.add_argument("--gone", action="store_true")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--interval", type=float, default=0.7)

    p = sub.add_parser("stayon", help="USB 连接时保持屏幕常亮")
    p.add_argument("state", nargs="?", choices=["on", "off"], default="on")

    p = sub.add_parser("wake", help="唤醒屏幕（--unlock 顺手清锁屏）")
    p.add_argument("--unlock", action="store_true")

    p = sub.add_parser("swipe", help="滑动")
    p.add_argument("x1", type=int)
    p.add_argument("y1", type=int)
    p.add_argument("x2", type=int)
    p.add_argument("y2", type=int)
    p.add_argument("--ms", type=int, default=300)

    p = sub.add_parser("key", help="按键（名称或 keycode 数字）")
    p.add_argument("name")

    p = sub.add_parser("shot", help="截图（默认 shot_<时间戳>.png）")
    p.add_argument("--out", default="")

    p = sub.add_parser("logs", help="设备 logcat")
    p.add_argument("--grep", default="")
    p.add_argument("--tail", type=int, default=200)
    p.add_argument("--clear", action="store_true")

    p = sub.add_parser("launch", help="启动 App 并等待前台（monkey）")
    p.add_argument("pkg")
    p.add_argument("--wait", type=int, default=3)

    sub.add_parser("clear", help="清空输入框（循环 DEL，校验到字段文本稳定；无聚焦输入框时报失败）")
    sub.add_parser("foreground", help="当前前台包名/窗口")
    sub.add_parser("size", help="屏幕分辨率")

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 0

    if args.cmd == "text":
        if args.replace:
            ok, t = clear_input()
            if not ok:
                print("[!] clear failed: no focused input (tap the field first)")
                return 1
        value = args.value.replace(" ", "%s")
        rc, out = adb(["shell", "input text %s" % sh_single_quote(value)])
        if rc != 0:
            print(out.strip() or ("input text rc=%d" % rc))
            return rc
        if args.no_verify:
            print("input text ok (unverified)")
            return 0
        deadline = time.time() + 3.0
        actual = None
        while True:
            fe = focused_edit()
            actual = fe["text"] if fe else None
            matched = (actual is not None and
                       (actual == args.value if args.replace else args.value in actual))
            if matched:
                print("input text ok (verified: %r)" % actual)
                return 0
            if time.time() >= deadline:
                break
            time.sleep(0.3)
        print("[!] verify failed: field=%r, expected %r (use --no-verify to skip)"
              % (actual, args.value))
        return 1

    if args.cmd == "clear":
        ok, t = clear_input()
        if ok:
            print("clear ok (field=%r)" % t)
            return 0
        print("[!] clear unverified: no focused input (tap the field first)")
        return 1

    if args.cmd == "launch":
        adb(["shell", "monkey", "-p", args.pkg,
             "-c", "android.intent.category.LAUNCHER", "1"])
        time.sleep(max(0, args.wait))
        fg = foreground()
        if args.pkg not in fg:
            _, comp = adb(["shell", "cmd", "package", "resolve-activity", "--brief",
                           "-c", "android.intent.category.LAUNCHER", args.pkg])
            comp = (comp.strip().splitlines() or [""])[-1].strip()
            if "/" in comp:
                adb(["shell", "am", "start", "-n", comp])
                time.sleep(max(0, args.wait))
                fg = foreground()
        print(fg or "launched")
        return 0 if args.pkg in fg else 1

    if args.cmd == "tap":
        if args.text or args.id or args.desc:
            e = match_element(dump_elements(), args.text, args.id, args.desc)
            if not e:
                print("no element matched (text=%r id=%r desc=%r)" % (args.text, args.id, args.desc))
                return 1
            x, y = e["center"]
            rc, out = adb(["shell", "input tap %d %d" % (x, y)])
            print("tapped %s at %d,%d" % (fmt_element(e), x, y))
            return rc
        if args.x is None or args.y is None:
            print("usage: ui tap <x> <y>  |  ui tap --text/--id/--desc <selector>")
            return 2
        rc, out = adb(["shell", "input tap %d %d" % (args.x, args.y)])
        print(out.strip() or "tap ok")
        return rc

    if args.cmd == "elements":
        elems = dump_elements()
        if args.grep:
            rx = re.compile(args.grep, re.IGNORECASE)
            elems = [e for e in elems
                     if rx.search(e["text"]) or rx.search(e["id"]) or rx.search(e["desc"])]
        if args.clickable:
            elems = [e for e in elems if e["clickable"]]
        if args.json:
            print(json.dumps(elems, ensure_ascii=False))
        else:
            for i, e in enumerate(elems):
                print("[%d] %s" % (i, fmt_element(e)))
        return 0

    if args.cmd == "wait-for":
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            e = match_element(dump_elements(), args.text, args.id, args.desc)
            if args.gone:
                if not e:
                    print("gone: text=%r id=%r desc=%r" % (args.text, args.id, args.desc))
                    return 0
            elif e:
                print("found: " + fmt_element(e))
                return 0
            time.sleep(args.interval)
        print("timeout after %ss (gone=%s, text=%r id=%r desc=%r)"
              % (args.timeout, args.gone, args.text, args.id, args.desc))
        return 1

    if args.cmd == "stayon":
        adb(["shell", "svc power stayon %s" % ("usb" if args.state == "on" else "false")])
        _, out = adb(["shell", "settings", "get", "global", "stay_on_while_plugged_in"])
        print("stayon=%s (stay_on_while_plugged_in=%s)" % (args.state, out.strip()))
        return 0

    if args.cmd == "wake":
        adb(["shell", "input keyevent KEYCODE_WAKEUP"])
        if args.unlock:
            w, h = screen_size()
            adb(["shell", "input swipe %d %d %d %d 200" % (w // 2, int(h * 0.78), w // 2, int(h * 0.2))])
        print("wake ok" + (" (unlocked)" if args.unlock else ""))
        return 0

    if args.cmd == "swipe":
        rc, out = adb(["shell", "input swipe %d %d %d %d %d" % (args.x1, args.y1, args.x2, args.y2, args.ms)])
        print(out.strip() or "swipe ok")
        return rc

    if args.cmd == "key":
        name = args.name.upper()
        code = KEYCODES.get(name, args.name if args.name.isdigit() else None)
        if code is None:
            print("unknown key: %s (known: %s)" % (args.name, ", ".join(sorted(KEYCODES))))
            return 2
        rc, out = adb(["shell", "input keyevent %s" % code])
        print(out.strip() or "keyevent %s ok" % code)
        return rc

    if args.cmd == "shot":
        out_path = args.out or ("shot_%s.png" % time.strftime("%Y%m%d_%H%M%S"))
        rc, _ = adb(["exec-out", "screencap", "-p"], binary_stdout=out_path)
        if rc == 0:
            print(os.path.abspath(out_path))
        else:
            print("screencap failed rc=%d" % rc)
        return rc

    if args.cmd == "logs":
        if args.clear:
            adb(["logcat", "-c"])
            if not args.grep:
                print("logcat cleared")
                return 0
        rc, out = adb(["logcat", "-d", "-t", str(args.tail)])
        lines = out.splitlines()
        if args.grep:
            rx = re.compile(args.grep, re.IGNORECASE)
            lines = [ln for ln in lines if rx.search(ln)]
        for ln in lines:
            print(ln)
        return rc

    if args.cmd == "foreground":
        print(foreground() or "(unknown)")
        return 0

    if args.cmd == "size":
        rc, out = adb(["shell", "wm", "size"])
        print(out.strip())
        return rc

    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
