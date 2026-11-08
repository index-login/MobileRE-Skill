#!/usr/bin/env python3
"""fsmon_run.py — 设备侧内核文件事件采集与分析（面向 agent）。

在设备上跑 fsmon（inotify 后端），采集进程的文件访问事件，
用于回答"谁读了什么文件""脱壳产物落在哪""哪个进程写的"。

输出面向机器解析：简洁的 K=V 进度行 + 一行 `SUMMARY <json>`。
产物：<out>/fsmon_<包名>_<时间戳>_w<N>.log（规范化）+ .summary.json（完整）。

子命令
------
  capture --pkg 包名 [--watch 目录]... [--duration 秒] [--launch] [--force-stop]
          [--proc 进程名] [--children] [--profile auto|detect|uniapp|none]
          [--exclude 正则]... [--pull] [--max-lines N] [--raw]
          [--out 目录] [--serial 序列号]
  diff    --fsmon-log A --frida-log B [--show N] [--out 目录]
  compare --base A.summary.json --new B.summary.json [--show N]
  summary --log A.log

已知边界
--------
只采事件不含内容；inotify 后端（该设备无 fanotify）；
/proc 不可 watch；用 -P 做归属判定。无额外 Python 依赖。
"""
import argparse
import concurrent.futures as _fut
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

FSMON_DEFAULT = "/data/local/tmp/fsmon-android-arm64"
UNIAPP_EXCLUDES = [r"manifest\.json", r"androidPrivacy\.json", r"Code Cache", r"code_cache/"]
SENSITIVE = [
    (r"/data/local/tmp", "tool_trace_dir"),
    (r"(^|/)su(\.\w+)?$|/system/(x?bin)/su|/sbin/su", "root_su_path"),
    (r"magisk|zygisk|/data/adb", "magisk"),
    (r"frida|gadget|linjector|re\.frida", "frida_trace"),
    (r"busybox", "busybox"),
    (r"\.sh$|/system/bin/sh", "shell"),
]
WRITE_OPS = {"FSE_CREATE_FILE", "FSE_CREATE_DIR", "FSE_CREATE", "FSE_CONTENT_MODIFIED",
             "FSE_DELETE", "FSE_RENAME"}
MAGIC = [(b"dex\n", "dex"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"),
         (b"SQLite format 3", "sqlite"), (b"<?xml", "xml")]


def run(cmd, timeout=120, serial=None):
    return subprocess.run(["adb"] + (["-s", serial] if serial else []) + cmd,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def sh(cmd, timeout=120, serial=None):
    return run(["shell", cmd], timeout=timeout, serial=serial)


def root_sh(cmd, timeout=120, serial=None):
    return sh('su -c "%s"' % cmd.replace('"', '\\"'), timeout=timeout, serial=serial)


def ts_str():
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def norm_path(p):
    p = re.split(r"[\x00-\x1f\uFFFD\u2026]", str(p))[0]
    p = re.sub(r"^/sdcard/", "/storage/emulated/0/", p)
    p = re.sub(r"^/data/user/\d+/", "/data/data/", p)
    p = re.sub(r"^/data/user_de/\d+/", "/data/user_de/0/", p)
    return p


def infer_prefixes(fsmon_log, fs_paths):
    """对账作用域：优先读同批 summary.json 的 watches，否则用 fsmon 路径的公共父目录"""
    m = re.match(r"^(.*)_w\d+\.log$", fsmon_log)
    if m:
        cand = m.group(1) + ".summary.json"
        if os.path.exists(cand):
            try:
                return json.load(open(cand, encoding="utf-8")).get("watches") or []
            except Exception:
                pass
    if fs_paths:
        try:
            return [os.path.commonpath(sorted(fs_paths))]
        except ValueError:
            return []
    return []


class StreamAgg:
    def __init__(self, normalize_fh=None, raw_fh=None, excludes=None, max_lines=0):
        self.by_type, self.by_uid, self.by_proc = {}, {}, {}
        self.paths, self.notes = {}, []
        self.events = self.excluded = 0
        self.fh_n, self.fh_r = normalize_fh, raw_fh
        self.excludes = [re.compile(x) for x in (excludes or [])]
        self.max_lines, self.stopped = max_lines, False
        self.lock = threading.Lock()

    def feed(self, line, ts):
        line = line.rstrip("\r\n")
        if not line:
            return
        if not line.startswith("{"):
            if len(self.notes) < 20:
                self.notes.append(line.strip()[:120])
            return
        try:
            e = json.loads(line)
        except Exception:
            return
        p = norm_path(e.get("filename", ""))
        t = e.get("type", "?")
        if t in ("FSE_OPEN", "FSE_CLOSE", "FSE_STAT_CHANGED"):
            if self.excludes and any(r.search(p) for r in self.excludes):
                self.excluded += 1
                return
        with self.lock:
            if self.max_lines and self.events >= self.max_lines:
                self.stopped = True
                return
            self.events += 1
            self.by_type[t] = self.by_type.get(t, 0) + 1
            uid = str(e.get("uid"))
            self.by_uid[uid] = self.by_uid.get(uid, 0) + 1
            if "proc" in e:
                self.by_proc[e["proc"]] = self.by_proc.get(e["proc"], 0) + 1
            rec = self.paths.get(p)
            if rec is None:
                rec = self.paths[p] = {"count": 0, "ops": set(), "first": ts, "last": ts}
            rec["count"] += 1
            rec["ops"].add(t)
            rec["last"] = ts
            if self.fh_n:
                self.fh_n.write("%.3f %s %s %s\n" % (ts, t, e.get("proc", uid), p))
            if self.fh_r:
                self.fh_r.write(line + "\n")


def stream_once(serial, fsmon, backend, path, duration, proc=None, children=False, pid=None,
                excludes=None, max_lines=0, normalize_fh=None, raw_fh=None, grace=30):
    agg = StreamAgg(normalize_fh, raw_fh, excludes, max_lines)
    pa = ""
    if proc:
        pa += " -P %s" % proc
    if pid:
        pa += " -p %s%s" % (pid, " -c" if children else "")
    elif proc and children:
        p = (sh("pidof %s" % proc, serial=serial).stdout or "").split()
        if p:
            pa += " -p %s -c" % p[0]
    inner = ("%s -B %s -a %d -n -J%s %s 2>&1" % (fsmon, backend, duration, pa, path)).replace('"', '\\"')
    full = ["adb"] + (["-s", serial] if serial else []) + ["shell", 'su -c "%s"' % inner]

    def reader():
        p = subprocess.Popen(full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, encoding="utf-8", errors="replace", bufsize=1)
        try:
            for line in p.stdout:
                agg.feed(line, time.time())
                if agg.stopped:
                    break
        finally:
            try:
                p.terminate()
            except Exception:
                pass
            p.wait(timeout=10)

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    th.join(timeout=duration + grace)
    return agg, th.is_alive()


def probe_backend(serial, fsmon, path):
    """以错误信息判定（比"有事件"可靠：安静路径也可能 0 事件）"""
    agg, _ = stream_once(serial, fsmon, "fanotify", path, 2, grace=15)
    bad = any(("fanotify" in n.lower()) or ("not implemented" in n.lower()) for n in agg.notes)
    return ("inotify" if bad else "fanotify"), (agg.notes[:1] or [])


def compute_excludes(serial, fsmon, backend, path, seconds=3, sample_lines=20000):
    agg, _ = stream_once(serial, fsmon, backend, path, seconds, max_lines=sample_lines, grace=20)
    reads = {p: r["count"] for p, r in agg.paths.items()
             if r["ops"] and r["ops"] <= {"FSE_OPEN", "FSE_CLOSE"}}
    total = sum(reads.values())
    hot = [p for p, c in sorted(reads.items(), key=lambda kv: -kv[1]) if c > total * 0.01]
    return [re.escape(p) + "$" for p in hot[:5]], agg.events


def pkg_uid(pkg, serial):
    out = (root_sh("stat -c %%u /data/data/%s" % pkg, serial=serial).stdout or "").strip()
    if out.isdigit():
        return int(out)
    m = re.search(r"\s(\d+)\s", root_sh("ls -ldn /data/data/%s" % pkg, serial=serial).stdout or "")
    return int(m.group(1)) if m else None


def exists(path, serial):
    return "Y" in (root_sh("test -e '%s' && echo Y" % path, serial=serial).stdout or "")


def digest(s, n=10):
    return {
        "pkg": s["pkg"], "backend": s["backend"], "events": s["events"], "filtered": s["excluded_lines"],
        "uniq": s["unique_paths"], "types": dict(list(s["by_type"].items())[:6]),
        "procs": dict(list(s["by_proc"].items())[:5]),
        "writes": [[w["path"], w["count"], w["ops"]] for w in s["writes"][:n]],
        "sensitive": [[x["path"], x["hit"]] for x in s["sensitive"][:n]],
        "storms": [[x["path"], x["count"]] for x in s["read_storms"][:5]],
        "pulled": [[a["file"], a["type"], a.get("followup", "")] for a in s.get("pulled", [])],
        "warn": s["warnings"],
    }


def cmd_capture(args):
    serial, pkg, fsmon = args.serial, args.pkg, args.fsmon_path
    base = "/data/data/%s" % pkg
    defaults = [base, "/data/user_de/0/%s" % pkg, "/storage/emulated/0/Android/data/%s" % pkg]
    watches = ([args.path] if args.path else defaults) + list(args.watch or [])
    if args.profile == "detect":
        watches += ["/data/local/tmp", "/data/adb", "/sbin", "/system/xbin"]
    watches = [w for w in dict.fromkeys(watches) if exists(w, serial)]
    if not watches:
        print("ERR no_watchable_path")
        return 1
    if "OK" not in (root_sh("test -x %s && echo OK" % fsmon, serial=serial).stdout or ""):
        print("ERR fsmon_not_executable %s" % fsmon)
        return 1
    if "uid=0" not in (root_sh("id", serial=serial).stdout or ""):
        print("ERR no_root")
        return 1

    uid = pkg_uid(pkg, serial)
    if args.backend == "auto":
        backend, pnotes = probe_backend(serial, fsmon, watches[0])
    else:
        backend, pnotes = args.backend, []
    warns = []
    if backend == "inotify":
        warns.append("inotify_blind_newdir" + (":%s" % pnotes[0][:40] if pnotes else ""))
    warns.append("procfs_unsupported")
    print("INIT pkg=%s uid=%s backend=%s watches=%d" % (pkg, uid, backend, len(watches)))

    if args.force_stop:
        sh("am force-stop %s" % pkg, serial=serial)
    if args.clear_data:
        sh("pm clear %s" % pkg, serial=serial)
        warns.append("clear_data_used:%s(登录态/数据已清)" % pkg)
        print("CLEAR_DATA %s" % pkg)
    if args.launch:
        sh("monkey -p %s -c android.intent.category.LAUNCHER 1" % pkg, serial=serial)
    if args.proc and not (sh("pidof %s" % args.proc, serial=serial).stdout or "").split():
        warns.append("proc_not_running:%s" % args.proc)

    out_dir = args.out or pkg
    os.makedirs(out_dir, exist_ok=True)
    ts = ts_str()
    jobs = []
    for i, w in enumerate(watches):
        exc = list(args.exclude or [])
        if args.profile == "auto":
            auto, ev = compute_excludes(serial, fsmon, backend, w)
            exc += auto
            print("SAMPLE path=%s events=%d excl=%d" % (w, ev, len(auto)))
        jobs.append((w, exc, os.path.join(out_dir, "fsmon_%s_%s_w%d.log" % (pkg, ts, i)),
                     os.path.join(out_dir, "fsmon_%s_%s_w%d.raw.log" % (pkg, ts, i)) if args.raw else None))

    aggs, fhs = {}, []
    t0 = time.time()

    def one(w, exc, norm, raw):
        nf = open(norm, "w", encoding="utf-8")
        fhs.append(nf)
        rf = None
        if raw:
            rf = open(raw, "w", encoding="utf-8")
            fhs.append(rf)
        agg, alive = stream_once(serial, fsmon, backend, w, args.duration, proc=args.proc,
                                 children=args.children, pid=args.pid, excludes=exc,
                                 max_lines=args.max_lines, normalize_fh=nf, raw_fh=rf)
        return w, agg, alive, norm, exc

    with _fut.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        for fu in _fut.as_completed([ex.submit(one, *j) for j in jobs]):
            try:
                w, agg, alive, norm, exc = fu.result()
                aggs[w] = (agg, norm, exc)
                print("WATCH path=%s events=%d filtered=%d alive=%s log=%s"
                      % (w, agg.events, agg.excluded, int(alive), norm))
            except Exception as e:  # noqa: BLE001
                print("ERR capture %s" % e)
    for fh in fhs:
        fh.close()

    s = aggregate(pkg, uid, backend, args.duration, aggs, warns)
    jp = os.path.join(out_dir, "fsmon_%s_%s.summary.json" % (pkg, ts))
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=2)
    print("ELAPSED %.1fs" % (time.time() - t0))
    if args.pull:
        s["pulled"] = pull_artifacts(s, out_dir, ts, serial, limit=args.pull_limit)
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=2)
    print("JSON %s" % jp)
    print("SUMMARY " + json.dumps(digest(s), ensure_ascii=False))
    return 0


def aggregate(pkg, uid, backend, duration, aggs, warnings):
    by_type, by_uid, by_proc, paths = {}, {}, {}, {}
    events = excluded = 0
    notes = []
    for w, (agg, log, exc) in aggs.items():
        events += agg.events
        excluded += agg.excluded
        notes += [n for n in agg.notes if n not in notes][:5]
        for d, k in ((by_type, "by_type"), (by_uid, "by_uid"), (by_proc, "by_proc")):
            for kk, vv in getattr(agg, k).items():
                d[kk] = d.get(kk, 0) + vv
        for p, r in agg.paths.items():
            rec = paths.setdefault(p, {"count": 0, "ops": set(), "first": r["first"], "last": r["last"]})
            rec["count"] += r["count"]
            rec["ops"] |= r["ops"]
            rec["first"] = min(rec["first"], r["first"])
            rec["last"] = max(rec["last"], r["last"])
    writes = {p: r for p, r in paths.items() if r["ops"] & WRITE_OPS}
    storms = sorted(((p, r) for p, r in paths.items() if not (r["ops"] & WRITE_OPS)),
                    key=lambda kv: -kv[1]["count"])[:20]
    sensitive = []
    for p in paths:
        for rx, tag in SENSITIVE:
            if re.search(rx, p, re.I):
                sensitive.append({"path": p, "hit": tag, "count": paths[p]["count"]})
                break
    if not by_proc:
        warnings.append("no_proc_attr")
    t0 = min((r["first"] for r in paths.values()), default=0)
    return {
        "pkg": pkg, "uid": uid, "backend": backend, "duration_s": duration,
        "watches": list(aggs.keys()), "logs": [log for _, log, _ in aggs.values()],
        "excludes": {w: exc for w, (_, _, exc) in aggs.items()},
        "events": events, "excluded_lines": excluded, "unique_paths": len(paths),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "by_uid": by_uid, "by_proc": by_proc,
        "writes": sorted(({"path": p, "count": r["count"], "ops": sorted(r["ops"]),
                           "first_rel": round(r["first"] - t0, 3) if t0 else None,
                           "last_rel": round(r["last"] - t0, 3) if t0 else None} for p, r in writes.items()),
                         key=lambda x: -x["count"]),
        "read_storms": [{"path": p, "count": r["count"]} for p, r in storms],
        "sensitive": sorted(sensitive, key=lambda x: -x["count"]),
        "fsmon_notes": notes, "warnings": list(dict.fromkeys(warnings)),
    }


def analyze_artifact(fp):
    import hashlib
    info = {"type": "?", "size": os.path.getsize(fp)}
    try:
        with open(fp, "rb") as f:
            head = f.read(16)
    except OSError:
        return info
    for m, name in MAGIC:
        if head.startswith(m):
            info["type"] = name
            break
    else:
        info["type"] = "text?" if re.match(rb"[\x20-\x7e]{4,}", head) else "binary"
    if info["type"] == "zip":
        import zipfile
        try:
            with zipfile.ZipFile(fp) as z:
                info["zip_entries"] = z.namelist()[:8]
        except Exception:
            pass
    elif info["type"] == "sqlite":
        import sqlite3
        try:
            c = sqlite3.connect("file:%s?mode=ro" % fp, uri=True)
            info["tables"] = [(r[0], c.execute('select count(*) from "%s"' % r[0]).fetchone()[0])
                              for r in c.execute("select name from sqlite_master where type='table'")][:8]
            c.close()
        except Exception:
            pass
    elif info["type"] == "elf":
        info["followup"] = "so.py info"
    elif info["type"] == "dex":
        info["followup"] = "jadx"
    with open(fp, "rb") as f:
        info["md5"] = hashlib.md5(f.read()).hexdigest()
    return info


def root_cat(remote, local, serial):
    """二进制安全兜底：su -c cat（用于 /sdcard 拷贝失败时）"""
    cmd = ["adb"] + (["-s", serial] if serial else []) + ["shell", 'su -c "cat \'%s\'"' % remote]
    r = subprocess.run(cmd, capture_output=True, timeout=120)
    if r.returncode == 0 and r.stdout:
        with open(local, "wb") as f:
            f.write(r.stdout)
        return True
    return False


def pull_artifacts(summary, out_dir, ts, serial, limit=10):
    pkg = summary.get("pkg", "")
    ext = "/storage/emulated/0/Android/data/%s/" % pkg
    cand = [w["path"] for w in summary["writes"]
            if (w["path"].startswith("/data/") or w["path"].startswith(ext)) and any(
                o.startswith("FSE_CREATE") or o == "FSE_CONTENT_MODIFIED" for o in w["ops"])]
    picked = [p for p in cand if exists(p, serial)][:limit]
    if not picked:
        print("PULL n=0")
        return []
    pdir = os.path.join(out_dir, "fsmon_pull_%s" % ts)
    os.makedirs(pdir, exist_ok=True)
    root_sh("rm -rf /sdcard/fsmon_pull; mkdir -p /sdcard/fsmon_pull", serial=serial)
    for i, p in enumerate(picked):
        dst = "p%02d_%s" % (i, os.path.basename(p) or "f")
        root_sh("cp '%s' /sdcard/fsmon_pull/%s 2>/dev/null; chmod 644 /sdcard/fsmon_pull/%s 2>/dev/null"
                % (p, dst, dst), serial=serial)
    run(["pull", "/sdcard/fsmon_pull", pdir], timeout=300, serial=serial)
    root_sh("rm -rf /sdcard/fsmon_pull", serial=serial)
    if not any(f for _r, _d, fs in os.walk(pdir) for f in fs):  # 兜底：root cat
        for i, p in enumerate(picked):
            root_cat(p, os.path.join(pdir, "p%02d_%s" % (i, os.path.basename(p) or "f")), serial)
    arts = []
    for root, _dirs, files in os.walk(pdir):
        for fn in sorted(files):
            fp = os.path.join(root, fn)
            info = analyze_artifact(fp)
            info["file"] = fn
            arts.append(info)
    print("PULL n=%d dir=%s" % (len(arts), pdir))
    for a in arts:
        print("ART file=%s type=%s size=%d md5=%s %s" % (a["file"], a["type"], a["size"],
                                                         a.get("md5", "")[:12], a.get("followup", "")))
    return arts


def read_log_events(log):
    rx = re.compile(r"^([\d.]+) (\S+) (\S+) (.*)$")
    return [{"ts": float(m.group(1)), "type": m.group(2), "who": m.group(3), "path": m.group(4)}
            for m in (rx.match(l.strip()) for l in open(log, encoding="utf-8", errors="replace")) if m]


def read_frida_paths(log, excludes=None):
    out, rx = set(), re.compile(r"path=(/[^\s'\"]+)")
    for line in open(log, encoding="utf-8", errors="replace"):
        for m in rx.finditer(line):
            p = norm_path(m.group(1))
            if excludes and any(re.search(x, p) for x in excludes):
                continue
            out.add(p)
    return out


def cmd_diff(args):
    exc = list(args.exclude or [])
    fs = {e["path"] for e in read_log_events(args.fsmon_log)}
    lc = read_frida_paths(args.frida_log, exc)
    prefixes = list(args.prefix or []) or infer_prefixes(args.fsmon_log, fs)
    if prefixes:
        fs = {p for p in fs if any(p.startswith(x) for x in prefixes)}
        lc = {p for p in lc if any(p.startswith(x) for x in prefixes)}
    only_fs, only_lc = sorted(fs - lc), sorted(lc - fs)
    print("DIFF prefix=%s fsmon=%d libc=%d both=%d fs_only=%d lc_only=%d"
          % (prefixes or "-", len(fs), len(lc), len(fs & lc), len(only_fs), len(only_lc)))
    for p in only_fs[: args.show]:
        print("FS_ONLY %s" % p)
    for p in only_lc[: args.show]:
        print("LC_ONLY %s" % p)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        op = os.path.join(args.out, "fsmon_diff_%s.json" % ts_str())
        with open(op, "w", encoding="utf-8") as f:
            json.dump({"only_fsmon": only_fs, "only_libc": only_lc,
                       "counts": {"fsmon": len(fs), "libc": len(lc), "both": len(fs & lc)}},
                      f, ensure_ascii=False, indent=2)
        print("JSON %s" % op)
    return 0


def cmd_compare(args):
    a = json.load(open(args.base, encoding="utf-8"))
    b = json.load(open(args.new, encoding="utf-8"))
    wa = {w["path"] for w in a.get("writes", [])}
    wb = {w["path"] for w in b.get("writes", [])}
    new, gone = sorted(wb - wa), sorted(wa - wb)
    print("COMPARE base=%d new=%d added=%d gone=%d" % (len(wa), len(wb), len(new), len(gone)))
    for p in new[: args.show]:
        print("ADDED %s" % p)
    for p in gone[: args.show]:
        print("GONE %s" % p)
    return 0


def cmd_summary(args):
    events = read_log_events(args.log)
    paths, by_type = {}, {}
    for e in events:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        rec = paths.setdefault(e["path"], {"count": 0, "ops": set(), "first": e["ts"], "last": e["ts"]})
        rec["count"] += 1
        rec["ops"].add(e["type"])
        rec["last"] = e["ts"]
    t0 = min((r["first"] for r in paths.values()), default=0)
    writes = {p: r for p, r in paths.items() if r["ops"] & WRITE_OPS}
    s = {"pkg": "-", "uid": None, "backend": "log", "duration_s": 0, "watches": [args.log],
         "logs": [args.log], "excludes": {}, "events": len(events), "excluded_lines": 0,
         "unique_paths": len(paths), "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
         "by_uid": {}, "by_proc": {},
         "writes": sorted(({"path": p, "count": r["count"], "ops": sorted(r["ops"]),
                            "first_rel": round(r["first"] - t0, 3),
                            "last_rel": round(r["last"] - t0, 3)} for p, r in writes.items()),
                          key=lambda x: -x["count"]),
         "read_storms": [], "sensitive": [], "fsmon_notes": [], "warnings": []}
    out_dir = args.out or os.path.dirname(os.path.abspath(args.log))
    jp = os.path.join(out_dir, "fsmon_resummary_%s.json" % ts_str())
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=2)
    print("JSON %s" % jp)
    print("SUMMARY " + json.dumps(digest(s), ensure_ascii=False))
    return 0


def main():
    ap = argparse.ArgumentParser(description="kernel file-event capture/analysis (agent tool)")
    ap.add_argument("-D", "--serial")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture")
    c.add_argument("--pkg", required=True)
    c.add_argument("--path")
    c.add_argument("--watch", action="append", default=[])
    c.add_argument("--duration", type=int, default=30)
    c.add_argument("--launch", action="store_true")
    c.add_argument("--force-stop", action="store_true")
    c.add_argument("--profile", choices=["auto", "detect", "uniapp", "none"], default="auto")
    c.add_argument("--exclude", action="append", default=[])
    c.add_argument("--proc")
    c.add_argument("--pid", help="直接按 pid 过滤（-p；与 --children 组合即 -p P -c）")
    c.add_argument("--backend", choices=["auto", "inotify", "fanotify"], default="auto")
    c.add_argument("--children", action="store_true")
    c.add_argument("--clear-data", action="store_true", help="采集前 pm clear（破坏性：清登录态）")
    c.add_argument("--pull", action="store_true")
    c.add_argument("--pull-limit", type=int, default=10)
    c.add_argument("--max-lines", type=int, default=0)
    c.add_argument("--raw", action="store_true")
    c.add_argument("--fsmon-path", default=FSMON_DEFAULT)
    c.add_argument("--out")
    c.set_defaults(func=cmd_capture)

    d = sub.add_parser("diff")
    d.add_argument("--fsmon-log", required=True)
    d.add_argument("--frida-log", required=True)
    d.add_argument("--exclude", action="append", default=[])
    d.add_argument("--prefix", action="append", default=[], help="作用域前缀（默认自动推断）")
    d.add_argument("--show", type=int, default=25)
    d.add_argument("--out")
    d.set_defaults(func=cmd_diff)

    p = sub.add_parser("compare")
    p.add_argument("--base", required=True)
    p.add_argument("--new", required=True)
    p.add_argument("--show", type=int, default=25)
    p.set_defaults(func=cmd_compare)

    s = sub.add_parser("summary")
    s.add_argument("--log", required=True)
    s.add_argument("--out")
    s.set_defaults(func=cmd_summary)

    args = ap.parse_args()
    if getattr(args, "duration", 1) is not None and getattr(args, "duration", 1) < 1:
        print("ERR bad_duration")
        return 1
    if not shutil.which("adb"):
        print("ERR no_adb")
        return 1
    try:
        return args.func(args)
    except subprocess.TimeoutExpired:
        print("ERR timeout")
        return 1


if __name__ == "__main__":
    sys.exit(main())
