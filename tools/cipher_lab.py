#!/usr/bin/env python3
"""cipher_lab.py — 分组密码/白盒结构判定器（面向上帝视角 trace 的"半自动破译"）

三个子命令（配合 tools/emu_run.py 观测层 / tools/trace_recon.py 状态重建）:
  layers    层结构判定：两条独立轨迹的相邻状态对 → 枚举 SB/SR/MC × 顺序 × ARK 位置，
            找出"解出的轮密钥跨轨迹一致"的唯一层写法
  table     白盒表反推：对 256 项字节表求 T[Y] = S(Y⊕k) ⊕ c 的唯一 (k, c)
  schedule  密钥编排归因：轮密钥序列 × 字节置换族 → 是否满足标准 AES-128 编排；
            命中时输出主密钥

用法:
  python3 cipher_lab.py layers  states_run1.txt states_run2.txt
  python3 cipher_lab.py table   lib.vaddr.bin --off 0x130008 [--stride 256] [--count 16]
  python3 cipher_lab.py schedule keys.txt [--perm 0,5,10,...]
  （states/keys 文件：每行一个 16 字节 hex）
"""
import argparse
import itertools
import json
import sys

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")
INVS = bytes(SBOX.index(i) for i in range(256))
SR = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
SRINV = [SR.index(i) for i in range(16)]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
TRANSPOSE = [(i % 4) * 4 + i // 4 for i in range(16)]


def xb(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def mc(s):
    o = bytearray(16)
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4 * c + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        o[4 * c + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        o[4 * c + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return bytes(o)


def imc(s):
    o = bytearray(16)
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
        o[4 * c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
        o[4 * c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
        o[4 * c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
    return bytes(o)


def sb(b):
    return bytes(SBOX[x] for x in b)


def isb(b):
    return bytes(INVS[x] for x in b)


def sr(b):
    return bytes(b[SR[i]] for i in range(16))


def isr(b):
    return bytes(b[SRINV[i]] for i in range(16))


OPS = {"SB": (sb, isb), "SR": (sr, isr), "MC": (mc, imc)}


def compose(names):
    def f(b):
        for n in names:
            b = OPS[n][0](b)
        return b
    return f


def compose_inv(names):
    def f(b):
        for n in reversed(names):
            b = OPS[n][1](b)
        return b
    return f


def permute(b, M):
    return bytes(b[M[i]] for i in range(16))


def load_blocks(path, size=16):
    blocks = []
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        b = bytes.fromhex(s)
        if len(b) >= size:
            blocks.append(b[:size])
    return blocks


# ---------------- layers ----------------

def cmd_layers(args):
    run_a = load_blocks(args.states_a)
    run_b = load_blocks(args.states_b)
    orders = [()] + [seq for L in range(1, args.max_ops + 1)
                     for seq in itertools.product(("SB", "SR", "MC"), repeat=L)]
    name_of = lambda seq: "identity" if not seq else "->".join(seq)
    results = []
    for seq in orders:
        f = compose(seq)
        finv = compose_inv(seq)
        for prepend in (0, 1):
            for mode in ("ark-in", "ark-out"):
                consistent = 0
                informative = 0
                rks = []
                for i in range(min(len(run_a), len(run_b)) - 1):
                    A1, B1 = run_a[i], run_a[i + 1]
                    A2, B2 = run_b[i], run_b[i + 1]
                    X1 = sr(A1) if prepend else A1
                    X2 = sr(A2) if prepend else A2
                    if X1 == X2 and B1 == B2:
                        continue        # 该段轨迹无信息
                    informative += 1
                    if mode == "ark-in":
                        rk1 = xb(X1, finv(B1))
                        rk2 = xb(X2, finv(B2))
                    else:
                        rk1 = xb(B1, f(X1))
                        rk2 = xb(B2, f(X2))
                    if rk1 == rk2:
                        consistent += 1
                        rks.append(rk1)
                if informative:
                    results.append({"prepend": prepend, "ops": name_of(seq), "mode": mode,
                                    "consistent": consistent, "informative": informative,
                                    "full": consistent == informative, "rks": rks})
    fulls = [r for r in results if r["full"]]
    if fulls:
        print("[+] layer candidates fully consistent across runs (%d):" % len(fulls))
        for r in fulls:
            note = "" if len(fulls) == 1 else "  (equivalent rewrite; keys differ by SR/ARK order)"
            print("    prepend=%-3s ops=%-14s mode=%-7s RK(first)=%s  n=%d%s" %
                  ("SR" if r["prepend"] else "-", r["ops"], r["mode"],
                   r["rks"][0].hex(), len(r["rks"]), note))
            if args.dump_rk:
                for i, rk in enumerate(r["rks"]):
                    print("        RK[%d]=%s" % (i, rk.hex()))
    else:
        print("[-] no fully consistent candidate; top partials:")
    if not fulls or args.top:
        ranked = sorted(results, key=lambda r: (-r["consistent"], r["informative"]))
        for r in ranked[: args.top]:
            print("    prepend=%-3s ops=%-14s mode=%-7s consistent=%d/%d%s" %
                  ("SR" if r["prepend"] else "-", r["ops"], r["mode"],
                   r["consistent"], r["informative"], "  FULL" if r["full"] else ""))
    print("[i] layer form: B = ops(X ^ RK) [ark-in] | B = ops(X) ^ RK [ark-out]; X = A or SR(A) [prepend]")
    return 0 if fulls else 1


# ---------------- table ----------------

def cmd_table(args):
    data = open(args.bin, "rb").read()
    out = []
    for i in range(args.count):
        off = args.off + i * args.stride
        tab = data[off:off + 256]
        if len(tab) < 256:
            out.append({"idx": i, "off": off, "fit": False})
            continue
        found = None
        for k in range(256):
            cs = set(tab[y] ^ SBOX[y ^ k] for y in range(256))
            if len(cs) == 1:
                found = (k, next(iter(cs)))
                break
        if found:
            out.append({"idx": i, "off": off, "k": found[0], "c": found[1], "fit": True})
        else:
            out.append({"idx": i, "off": off, "fit": False})
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print("table: %s @ %#x stride=%d count=%d" % (args.bin, args.off, args.stride, args.count))
        for r in out:
            if r["fit"]:
                print("  [%2d] %#x  k=%02x c=%02x" % (r["idx"], r["off"], r["k"], r["c"]))
            else:
                print("  [%2d] %#x  no T[Y]=S(Y^k)^c fit" % (r["idx"], r["off"]))
    return 0 if any(r["fit"] for r in out) else 1


# ---------------- schedule ----------------

def key_schedule(k0, rounds=10):
    w = [k0[i * 4:i * 4 + 4] for i in range(4)]
    for i in range(4, 4 * (rounds + 1)):
        t = w[i - 1]
        if i % 4 == 0:
            t = bytes(SBOX[x] for x in (t[1:] + t[:1]))
            t = bytes([t[0] ^ RCON[i // 4 - 1]]) + t[1:]
        w.append(xb(w[i - 4], t))
    return [b"".join(w[4 * r:4 * r + 4]) for r in range(rounds + 1)]


PERMS = {
    "identity": list(range(16)),
    "SR": SR,
    "SRinv": SRINV,
    "transpose": TRANSPOSE,
    "SR∘T": [SR[TRANSPOSE[i]] for i in range(16)],
    "T∘SR": [TRANSPOSE[SR[i]] for i in range(16)],
}


def cmd_schedule(args):
    keys = load_blocks(args.keys)
    if len(keys) < 2:
        print("[-] need >=2 round keys")
        return 1
    perms = dict(PERMS)
    if args.perm:
        perms["custom"] = [int(x, 0) for x in args.perm.split(",")]
    best = None
    for name, M in perms.items():
        P = [permute(k, M) for k in keys]
        sched = key_schedule(P[0])
        matched = sum(1 for i in range(1, len(P)) if P[i] == sched[i])
        total = len(P) - 1
        first_bad = None
        for i in range(1, len(P)):
            if P[i] != sched[i]:
                first_bad = (i, [b for b in range(16) if P[i][b] != sched[i][b]])
                break
        rec = {"perm": name, "matched": matched, "total": total, "first_bad": first_bad}
        if best is None or matched > best["matched"]:
            best = rec
        if matched == total:
            asc = "".join(chr(c) if 32 <= c < 127 else "." for c in P[0])
            print("[+] full match: perm=%s  (%d/%d rounds)" % (name, matched, total))
            print("    master key = %s  (%r)" % (P[0].hex(), asc))
            rec["master"] = P[0].hex()
    if best and best["matched"] != best["total"]:
        print("[-] no full match; best: perm=%s %d/%d" % (best["perm"], best["matched"], best["total"]))
        if best["first_bad"]:
            i, bad = best["first_bad"]
            print("    first mismatch at round %d, bytes %s" % (i, bad))
    return 0 if (best and best["matched"] == best["total"]) else 1


def main():
    ap = argparse.ArgumentParser(description="分组密码/白盒结构判定器")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("layers", help="层结构判定（双轨迹）")
    p.add_argument("states_a")
    p.add_argument("states_b")
    p.add_argument("--max-ops", type=int, default=3)
    p.add_argument("--top", type=int, default=8)
    p.add_argument("--dump-rk", action="store_true", help="列出全部解出的轮密钥")
    p.set_defaults(func=cmd_layers)

    p = sub.add_parser("table", help="白盒表反推 S(Y^k)^c")
    p.add_argument("bin")
    p.add_argument("--off", required=True)
    p.add_argument("--stride", type=lambda v: int(v, 0), default=256)
    p.add_argument("--count", type=int, default=16)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_table)

    p = sub.add_parser("schedule", help="轮密钥→标准 AES-128 编排归因")
    p.add_argument("keys")
    p.add_argument("--perm", default="", help="自定义字节置换（16 个下标，逗号分隔）")
    p.set_defaults(func=cmd_schedule)

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 0
    args.off = int(args.off, 0) if getattr(args, "off", None) else None
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
