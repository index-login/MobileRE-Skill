#!/usr/bin/env python3
"""trace_recon.py — 仿真 trace 状态重建器（emu_run / emu2 观测日志 → 缓冲状态序列）

用途：白盒/VM/算法分析时，把 `--watch-write/--watch-read`（或 emu2 的 `--writes/--reads`）
日志重建为"缓冲随时间变化的状态序列"，自动分段：
  - COPY：连续命中 --copy-pc 的事件合并成一次整块拷贝（如 ShiftRows 写回/结构置换）
  - PASS：其余事件每累计 size 字节为一段（一轮字节层写回）
配套：tools/emu_run.py（观测层）、tools/cipher_lab.py（结构判定）

用法:
  python3 trace_recon.py <log> --base 0x10012bf0 --size 16 [--copy-pc 0x10fb24]
  python3 trace_recon.py <log> --base 0x10012bf0 --ascii --events 40 --json

选项:
  --base ADDR     缓冲基址（事件地址减基址得偏移；越界事件忽略）
  --size N        缓冲大小（默认 16）
  --copy-pc LIST  视为"整块拷贝"的 PC（逗号分隔；连续命中合并为一次 COPY）
  --kind wr|rd    解析写事件（默认）或读事件
  --ascii         每条状态附带 ASCII 视图
  --events N      先打印前 N 条原始事件（默认 0）
  --dedupe        折叠连续完全相同的条目
  --json          以 JSON 输出（items 数组）
"""
import argparse
import json
import re
import sys

LINE_RE = re.compile(
    r"\[(wr|rd)\]\s+(0x[0-9a-fA-F]+)\s+size=(\d+)(?:\s+val=(0x[0-9a-fA-F]+|\d+))?\s+pc=(0x[0-9a-fA-F]+)")


def load_events(path):
    events = []
    for enc in ("utf-8", "utf-16"):
        try:
            text = open(path, encoding=enc).read()
            break
        except Exception:  # noqa: BLE001
            text = None
    if text is None:
        raise SystemExit("cannot read %s" % path)
    for line in text.splitlines():
        m = LINE_RE.search(line)
        if m:
            kind = m.group(1)
            addr = int(m.group(2), 16)
            size = int(m.group(3))
            val = int(m.group(4), 16) if m.group(4) else 0
            pc = int(m.group(5), 16)
            events.append((kind, addr, size, val, pc))
    return events


def ascii_view(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def main():
    ap = argparse.ArgumentParser(description="仿真 trace 状态重建器")
    ap.add_argument("log")
    ap.add_argument("--base", required=True)
    ap.add_argument("--size", type=int, default=16)
    ap.add_argument("--copy-pc", default="", help="整块拷贝 PC（逗号分隔）")
    ap.add_argument("--kind", choices=["wr", "rd"], default="wr")
    ap.add_argument("--ascii", action="store_true")
    ap.add_argument("--events", type=int, default=0)
    ap.add_argument("--dedupe", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    base = int(args.base, 0)
    size = args.size
    copy_pcs = {int(x, 0) for x in args.copy_pc.split(",") if x.strip()}
    events = [e for e in load_events(args.log) if e[0] == args.kind and base <= e[1] < base + size]

    if args.events:
        print("== first %d events ==" % min(args.events, len(events)))
        for kind, addr, sz, val, pc in events[:args.events]:
            print("  [%s] +%#04x size=%d val=%#x pc=%#x" % (kind, addr - base, sz, val, pc))

    items = []
    buf = bytearray(size)
    i = 0
    n = len(events)
    while i < n:
        kind, addr, sz, val, pc = events[i]
        if pc in copy_pcs:
            while i < n and events[i][4] in copy_pcs and events[i][0] == args.kind:
                _, a, s, v, _ = events[i]
                buf[a - base:a - base + s] = v.to_bytes(s, "little")
                i += 1
            items.append(("COPY", bytes(buf)))
            continue
        acc = 0
        while i < n and events[i][4] not in copy_pcs and acc < size:
            _, a, s, v, _ = events[i]
            buf[a - base:a - base + s] = v.to_bytes(s, "little")
            acc += s
            i += 1
        items.append(("PASS", bytes(buf)))

    if args.dedupe:
        dedup = []
        for it in items:
            if not dedup or dedup[-1][1] != it[1]:
                dedup.append(it)
        items = dedup

    if args.json:
        print(json.dumps({"events": len(events), "size": size,
                          "items": [{"tag": t, "hex": b.hex()} for t, b in items]}, indent=2))
        return 0

    print("events=%d items=%d size=%d" % (len(events), len(items), size))
    for k, (tag, data) in enumerate(items):
        line = "%3d %-4s %s" % (k, tag, data.hex())
        if args.ascii:
            line += "  |%s|" % ascii_view(data)
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
