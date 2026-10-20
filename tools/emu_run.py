#!/usr/bin/env python3
"""emu_run.py — 单函数离线仿真（Unicorn，基于 uniharness.py）。

用途：不碰真机，调用 .so 内指定函数并取回返回值；内置 JNIEnv 与常见 libc 导入桩，
可复算算法（如 crackme 校验函数）。加载时自动：① 按 ELF 重定位类型区分函数导入(JUMP_SLOT,
给代码桩)与数据导入(GLOB_DAT, 给可写数据, 如 _ctype_ 内置表)；② 执行 DT_INIT/DT_INIT_ARRAY
初始化 C++ 全局对象。内置内存/字符串桩：memcpy/memmove/memset/memchr/str*/atoi/strtol。

用法:
  python3 emu_run.py <so> --sym <symbol> [选项]
  python3 emu_run.py <so> --off 0x196C [选项]

常用选项:
  --args "1,0x20,'text',zero,env"   实参（数字/单引号字符串/env 占位）
  --jni                             伪造 JNIEnv（NewStringUTF/GetStringUTFChars/... 可用）
  --imp strncmp,strlen,malloc       额外导入桩（默认已含常用 libc；未知符号返回 0）
  --stub name=val                   覆盖导入桩返回值（可重复，如 --stub getpid=1234）
  --log-jni                         JNI 调用日志：每次调用打印 [jni] name(args) -> ret（超 --watch-max 聚合）
  --dump-jni-out FILE               NewStringUTF / SetByteArrayRegion 内容追加落盘（可多次运行累积）
  --trace-stubs                     桩命中日志：name(args) -> ret（超 --watch-max 聚合 Top）
  --poke 0x15054:4=2                调用前写内存（可重复）
  --read 0x1000:32                  调用后读内存（hex+ascii，可重复）
  --trace / --timeout 10 / --raw    指令追踪 / 秒 / raw 映射（vaddr==offset 的 dump so）
  --no-init                         不执行 DT_INIT/DT_INIT_ARRAY（默认执行）
  --no-syscalls                     不装 syscall 层（默认装：svc #0 兜底，避免直接崩）
  --ret-str                         按 sret(x8) 调用并解码返回的 std::string
  --out-arg N:LEN                   调用后 dump 第 N 个实参指向的缓冲（可重复）
  --setup hooks.py                  自定义脚本：def setup(h): ...（拿到 Harness 全权；
                                    复杂函数用 `import emu_setup as E` 的助手，见 tools/emu_setup.py）

观测层（白盒/VM/算法分析用；日志解析见 tools/trace_recon.py）:
  --watch-code 0x10f9dc             命中 PC（逗号分隔）时打印寄存器/缓冲（可重复）
  --watch-regs x0,x1,x2             配合 --watch-code 的寄存器列表
  --watch-buf "x19+0x61f0:16"       打印 [REG+OFF] 指针处的 n 字节（可重复）
  --watch-read 0x1000-0x2000        内存读监视（可重复；超出 --watch-max 只聚合）
  --watch-write 0x1000-0x2000       内存写监视（可重复）
  --watch-max 100                   事件打印上限；--watch-top 15 汇总 Top PC
  --scan 2c213adb...                调用后扫描内存中的字节模式（hex，逗号分隔）
  --scan-at 0x10f9dc                在这些 PC 命中时执行扫描（可重复）
"""
import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uniharness import Harness, JNI_SLOTS  # noqa: E402


def parse_args_tokens(tokens, h, env_addr=None):
    out = []
    for tok in tokens:
        t = tok.strip()
        if not t:
            continue
        if (t.startswith("'") and t.endswith("'")) or (t.startswith('"') and t.endswith('"')):
            s = t[1:-1]
            ptr = h.alloc(len(s) + 1)
            h.write(ptr, s.encode("utf-8") + b"\x00")
            out.append(ptr)
        elif t in ("zero", "null", "0x0"):
            out.append(0)
        elif t == "env":
            out.append(env_addr or 0)
        else:
            out.append(int(t, 0))
    return out


def _ret0(uc, addr, size, user):
    from unicorn.arm64_const import UC_ARM64_REG_X0
    uc.reg_write(UC_ARM64_REG_X0, 0)


def _load_jni_names():
    names = {}
    try:
        from so import JNI_FUNCS  # noqa: PLC0415
        names.update({i: n for i, n in enumerate(JNI_FUNCS)})
    except Exception:  # noqa: BLE001
        pass
    names.update({idx: name for name, idx in JNI_SLOTS.items()})
    return names


JNI_NAMES = _load_jni_names()


def jni_name(idx):
    return JNI_NAMES.get(idx, "slot_%d" % idx)


def _read_cstr_uc(uc, ptr, limit=512):
    """读 C 串：分小块读，容忍末尾落在未映射页（整块 mem_read 会失败）。"""
    if not ptr:
        return ""
    out = bytearray()
    while len(out) < limit:
        try:
            chunk = bytes(uc.mem_read(ptr + len(out), min(16, limit - len(out))))
        except Exception:  # noqa: BLE001
            break
        out += chunk
        z = out.find(b"\x00")
        if z >= 0:
            return out[:z].decode("utf-8", "replace")
    return out.decode("utf-8", "replace")


def _escape_jni(s, limit=200):
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return s if len(s) <= limit else s[:limit] + "…"


def _dump_jni(fh, tag, payload):
    if fh is None:
        return
    fh.write("[%s] %s\n" % (tag, payload))
    fh.flush()


class JniLogger:
    """--log-jni：每次 JNI 调用打印 [jni] name(args) -> ret；超 --watch-max 只聚合 Top。"""

    def __init__(self, args):
        self.max_print = args.watch_max
        self.top = args.watch_top
        self.printed = 0
        self.counts = {}

    def wrap(self, idx, cb):
        name = jni_name(idx)

        def wrapped(uc, addr, size, user):
            cb(uc, addr, size, user)
            from unicorn.arm64_const import UC_ARM64_REG_X0
            self.counts[name] = self.counts.get(name, 0) + 1
            if self.printed < self.max_print:
                self.printed += 1
                print("[jni] %s(%s) -> %#x"
                      % (name, self._fmt_args(uc, name), uc.reg_read(UC_ARM64_REG_X0)), flush=True)

        return wrapped

    @staticmethod
    def _fmt_args(uc, name):
        from unicorn.arm64_const import (
            UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        if name == "NewStringUTF":
            return '"%s"' % _escape_jni(_read_cstr_uc(uc, x1))
        if name in ("GetStringUTFChars", "GetStringUTFLength", "GetStringLength"):
            ptr = x1
            try:
                cand = struct.unpack_from("<Q", bytes(uc.mem_read(x1, 8)), 0)[0] if x1 else 0
                if cand:
                    ptr = cand
            except Exception:  # noqa: BLE001
                pass
            return '"%s"' % _escape_jni(_read_cstr_uc(uc, ptr))
        if name in ("SetByteArrayRegion", "GetByteArrayRegion"):
            start, length, buf = (uc.reg_read(UC_ARM64_REG_X2),
                                  uc.reg_read(UC_ARM64_REG_X3), uc.reg_read(UC_ARM64_REG_X4))
            try:
                data = bytes(uc.mem_read(buf, min(length, 64))) if buf else b""
            except Exception:  # noqa: BLE001
                data = b""
            return "arr=%#x start=%#x len=%#x hex=%s%s" % (
                x1, start, length, data.hex(), "…" if length > 64 else "")
        vals = [x1, uc.reg_read(UC_ARM64_REG_X2), uc.reg_read(UC_ARM64_REG_X3), uc.reg_read(UC_ARM64_REG_X4)]
        while len(vals) > 1 and not vals[-1]:
            vals.pop()
        return " ".join("x%d=%#x" % (i + 1, v) for i, v in enumerate(vals))

    def report(self):
        total = sum(self.counts.values())
        if total - self.printed <= 0:
            return
        top = sorted(self.counts.items(), key=lambda kv: -kv[1])[:self.top]
        print("[jni] %d calls total (printed %d, cap=%d); top: %s"
              % (total, self.printed, self.max_print,
                 ", ".join("%s x%d" % (n, c) for n, c in top)), flush=True)


class StubTracer:
    """--trace-stubs：桩命中 name(args) -> ret；超 --watch-max 只聚合 Top。"""

    LIBC_REGS = ("x0", "x1", "x2", "x3")
    JNI_REGS = ("x1", "x2", "x3", "x4")

    def __init__(self, args):
        self.max_print = args.watch_max
        self.top = args.watch_top
        self.printed = 0
        self.counts = {}

    def wrap(self, name, cb, regs=None):
        regs = self.LIBC_REGS if regs is None else regs

        def wrapped(uc, addr, size, user):
            vals = [uc.reg_read(_reg_const(r)) for r in regs]
            cb(uc, addr, size, user)
            self.counts[name] = self.counts.get(name, 0) + 1
            if self.printed < self.max_print:
                self.printed += 1
                print("[stub] %s(%s) -> %#x"
                      % (name, ", ".join("%#x" % v for v in vals), uc.reg_read(_reg_const("x0"))),
                      flush=True)

        return wrapped

    def report(self):
        total = sum(self.counts.values())
        if total - self.printed <= 0:
            return
        top = sorted(self.counts.items(), key=lambda kv: -kv[1])[:self.top]
        print("[stub] %d calls total (printed %d, cap=%d); top: %s"
              % (total, self.printed, self.max_print,
                 ", ".join("%s x%d" % (n, c) for n, c in top)), flush=True)


def make_libc_stubs(h, extra, overrides=None, tracer=None):
    """Built-in host implementations for common imported libc functions.

    overrides: {name: int} 指定导入桩直接返回该值；tracer: StubTracer 包装每个桩。
    """
    overrides = overrides or {}

    def cb_override(value):
        def cb(uc, addr, size, user):
            uc.reg_write(reg("x0"), value)
        return cb

    def read_mem(addr, n):
        try:
            return bytes(h.uc.mem_read(addr, n))
        except Exception:  # noqa: BLE001
            return b""

    def read_cstr(addr, limit=65536):
        """读 C 串：分小块，遇 NUL 或未映射页即停。
        固定大块 mem_read 会因字符串靠近映射边界而整体失败（→ 误判长度 0）。"""
        out = bytearray()
        while len(out) < limit:
            try:
                chunk = bytes(h.uc.mem_read(addr + len(out), min(16, limit - len(out))))
            except Exception:  # noqa: BLE001
                break
            z = chunk.find(b"\x00")
            if z >= 0:
                return bytes(out) + chunk[:z]
            out += chunk
        return bytes(out)

    def reg(name):
        from unicorn.arm64_const import (
            UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)
        return {"x0": UC_ARM64_REG_X0, "x1": UC_ARM64_REG_X1,
                "x2": UC_ARM64_REG_X2, "x3": UC_ARM64_REG_X3}[name]

    def cb_strncmp(uc, addr, size, user):
        a, b, n = (uc.reg_read(reg("x0")), uc.reg_read(reg("x1")), uc.reg_read(reg("x2")))
        da, db = read_mem(a, n), read_mem(b, n)
        r = 0
        for i in range(min(len(da), len(db), n)):
            if da[i] != db[i]:
                r = da[i] - db[i]
                break
        uc.reg_write(reg("x0"), r & 0xFFFFFFFF)

    def cb_strcmp(uc, addr, size, user):
        a, b = uc.reg_read(reg("x0")), uc.reg_read(reg("x1"))
        pa = read_cstr(a)
        pb = read_cstr(b)
        uc.reg_write(reg("x0"), (0 if pa == pb else (pa[0] - pb[0]) if pa and pb else 1) & 0xFFFFFFFF)

    def cb_memcmp(uc, addr, size, user):
        a, b, n = (uc.reg_read(reg("x0")), uc.reg_read(reg("x1")), uc.reg_read(reg("x2")))
        da, db = read_mem(a, n), read_mem(b, n)
        r = 0
        for i in range(min(len(da), len(db), n)):
            if da[i] != db[i]:
                r = da[i] - db[i]
                break
        uc.reg_write(reg("x0"), r & 0xFFFFFFFF)

    def cb_strlen(uc, addr, size, user):
        uc.reg_write(reg("x0"), len(read_cstr(uc.reg_read(reg("x0")))))

    def cb_malloc(uc, addr, size, user):
        uc.reg_write(reg("x0"), h.alloc(max(1, uc.reg_read(reg("x0")))))

    def cb_free(uc, addr, size, user):
        pass

    def cb_memcpy(uc, addr, size, user):
        d, s, n = (uc.reg_read(reg("x0")), uc.reg_read(reg("x1")), uc.reg_read(reg("x2")))
        if n:
            uc.mem_write(d, read_mem(s, n))

    cb_memmove = cb_memcpy

    def cb_memset(uc, addr, size, user):
        d, v, n = (uc.reg_read(reg("x0")), uc.reg_read(reg("x1")) & 0xFF, uc.reg_read(reg("x2")))
        if n:
            uc.mem_write(d, bytes([v]) * n)

    def cb_memchr(uc, addr, size, user):
        s, v, n = (uc.reg_read(reg("x0")), uc.reg_read(reg("x1")) & 0xFF, uc.reg_read(reg("x2")))
        i = read_mem(s, n).find(bytes([v]))
        uc.reg_write(reg("x0"), s + i if i >= 0 else 0)

    def _cstr(addr):
        return read_cstr(addr)

    def cb_strcpy(uc, addr, size, user):
        uc.mem_write(uc.reg_read(reg("x0")), _cstr(uc.reg_read(reg("x1"))) + b"\x00")

    def cb_strncpy(uc, addr, size, user):
        d, n = uc.reg_read(reg("x0")), uc.reg_read(reg("x2"))
        s = _cstr(uc.reg_read(reg("x1")))[:n]
        uc.mem_write(d, s + b"\x00" * (n - len(s)))

    def cb_strcat(uc, addr, size, user):
        d = uc.reg_read(reg("x0"))
        uc.mem_write(d, _cstr(d) + _cstr(uc.reg_read(reg("x1"))) + b"\x00")

    def cb_strchr(uc, addr, size, user):
        s, c = uc.reg_read(reg("x0")), uc.reg_read(reg("x1")) & 0xFF
        i = _cstr(s).find(bytes([c]))
        uc.reg_write(reg("x0"), s + i if i >= 0 else 0)

    def cb_strrchr(uc, addr, size, user):
        s, c = uc.reg_read(reg("x0")), uc.reg_read(reg("x1")) & 0xFF
        i = _cstr(s).rfind(bytes([c]))
        uc.reg_write(reg("x0"), s + i if i >= 0 else 0)

    def cb_strstr(uc, addr, size, user):
        s = uc.reg_read(reg("x0"))
        needle = _cstr(uc.reg_read(reg("x1")))
        i = _cstr(s).find(needle) if needle else 0
        uc.reg_write(reg("x0"), s + i if i >= 0 else 0)

    def cb_strnlen(uc, addr, size, user):
        s, n = uc.reg_read(reg("x0")), uc.reg_read(reg("x1"))
        z = read_mem(s, n).find(b"\x00")
        uc.reg_write(reg("x0"), z if z >= 0 else n)

    def cb_atoi(uc, addr, size, user):
        m = re.match(r"\s*([+-]?[0-9]+)", _cstr(uc.reg_read(reg("x0"))).decode("latin1"))
        uc.reg_write(reg("x0"), (int(m.group(1)) if m else 0) & 0xFFFFFFFF)

    def cb_strtol(uc, addr, size, user):
        p = uc.reg_read(reg("x0"))
        base = uc.reg_read(reg("x2")) or 10
        m = re.match(r"\s*([+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))", _cstr(p).decode("latin1"))
        v, consumed = 0, 0
        if m:
            try:
                v = int(m.group(1), 0) if base == 0 else int(m.group(1), base)
            except ValueError:
                v = 0
            consumed = m.end()
        endp = uc.reg_read(reg("x1"))
        if endp:
            uc.mem_write(endp, struct.pack("<Q", p + consumed))
        uc.reg_write(reg("x0"), v & 0xFFFFFFFFFFFFFFFF)

    def _regi(i):
        from unicorn.arm64_const import (
            UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7)
        return (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7)[i]

    def cb_calloc(uc, addr, size, user):
        n = (uc.reg_read(reg("x0")) & 0xFFFFFFFF) * (uc.reg_read(reg("x1")) & 0xFFFFFFFF)
        uc.reg_write(reg("x0"), h.alloc(max(1, n)))          # h.alloc 为零初始化

    def cb_realloc(uc, addr, size, user):
        old, n = uc.reg_read(reg("x0")), uc.reg_read(reg("x1"))
        p = h.alloc(max(1, n))
        if old and n:
            try:
                uc.mem_write(p, bytes(uc.mem_read(old, n)))
            except Exception:  # noqa: BLE001
                pass
        uc.reg_write(reg("x0"), p)

    def cb_usable_size(uc, addr, size, user):
        uc.reg_write(reg("x0"), 0x1000)

    def cb_posix_memalign(uc, addr, size, user):
        memptr, sz = uc.reg_read(reg("x0")), uc.reg_read(reg("x2"))
        p = h.alloc(max(1, sz))
        if memptr:
            uc.mem_write(memptr, struct.pack("<Q", p))
        uc.reg_write(reg("x0"), 0)

    def cb_alloc_exc(uc, addr, size, user):
        uc.reg_write(reg("x0"), h.alloc(max(1, uc.reg_read(reg("x0")))))

    def cb_ret0(uc, addr, size, user):
        uc.reg_write(reg("x0"), 0)

    def cb_ret1(uc, addr, size, user):
        uc.reg_write(reg("x0"), 1)

    def cb_strtoul(uc, addr, size, user):
        p = uc.reg_read(reg("x0"))
        base = uc.reg_read(reg("x2")) or 10
        m = re.match(r"\s*([+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))", read_cstr(p).decode("latin1"))
        v, consumed = 0, 0
        if m:
            try:
                v = int(m.group(1), 0) if base == 0 else int(m.group(1), base)
            except ValueError:
                v = 0
            consumed = m.end()
        endp = uc.reg_read(reg("x1"))
        if endp:
            uc.mem_write(endp, struct.pack("<Q", p + consumed))
        uc.reg_write(reg("x0"), v & 0xFFFFFFFFFFFFFFFF)

    def cb_strtod(uc, addr, size, user):
        from unicorn.arm64_const import UC_ARM64_REG_D0
        p = uc.reg_read(reg("x0"))
        m = re.match(r"\s*([+-]?(?:[0-9]*\.[0-9]+|[0-9]+)(?:[eE][+-]?[0-9]+)?)", read_cstr(p).decode("latin1"))
        val, consumed = 0.0, 0
        if m:
            try:
                val = float(m.group(1))
            except ValueError:
                val = 0.0
            consumed = m.end()
        endp = uc.reg_read(reg("x1"))
        if endp:
            uc.mem_write(endp, struct.pack("<Q", p + consumed))
        uc.reg_write(UC_ARM64_REG_D0, struct.unpack("<Q", struct.pack("<d", val))[0])

    def _printf(uc, fmtp, arg_start, out_limit):
        from unicorn.arm64_const import UC_ARM64_REG_SP
        fmt = read_cstr(fmtp).decode("latin1")
        sp = uc.reg_read(UC_ARM64_REG_SP)
        idx = [0]

        def nxt():
            r = arg_start + idx[0]
            idx[0] += 1
            if r < 8:
                return uc.reg_read(_regi(r))
            return struct.unpack("<Q", bytes(uc.mem_read(sp + 8 * (r - 8), 8)))[0]

        out, i, n = [], 0, len(fmt)
        while i < n:
            if fmt[i] != "%":
                out.append(fmt[i]); i += 1; continue
            i += 1
            if i < n and fmt[i] == "%":
                out.append("%"); i += 1; continue
            while i < n and fmt[i] in "-+ #0.0123456789":
                i += 1
            if i >= n:
                break
            conv = fmt[i]; i += 1
            if conv == "l":
                if i < n:
                    conv = fmt[i].lower(); i += 1
                v = nxt()
                if conv in "di":
                    out.append(str(v - (1 << 64) if v >> 63 else v))
                elif conv == "u":
                    out.append(str(v & 0xFFFFFFFFFFFFFFFF))
                elif conv == "x":
                    out.append("%x" % (v & 0xFFFFFFFFFFFFFFFF))
                continue
            v = nxt()
            if conv in "di":
                sv = v & 0xFFFFFFFF
                out.append(str(sv - (1 << 32) if sv >> 31 else sv))
            elif conv == "u":
                out.append(str(v & 0xFFFFFFFF))
            elif conv in "xX":
                out.append("%x" % (v & 0xFFFFFFFF))
            elif conv == "p":
                out.append("0x%x" % v)
            elif conv == "s":
                out.append(read_cstr(v).decode("latin1", "replace"))
            elif conv == "c":
                out.append(chr(v & 0xFF))
        s = "".join(out).encode("latin1", "replace")
        return s[:max(0, out_limit - 1)] if out_limit is not None else s

    def cb_sprintf(uc, addr, size, user):
        dst = uc.reg_read(reg("x0"))
        s = _printf(uc, uc.reg_read(reg("x1")), 2, None)
        uc.mem_write(dst, s + b"\x00")
        uc.reg_write(reg("x0"), len(s))

    def cb_snprintf(uc, addr, size, user):
        dst, lim = uc.reg_read(reg("x0")), uc.reg_read(reg("x1"))
        s = _printf(uc, uc.reg_read(reg("x2")), 3, lim if lim else None)
        if dst and lim:
            uc.mem_write(dst, s + b"\x00")
        uc.reg_write(reg("x0"), len(s))

    _rng = [0x12345678]

    def cb_rand(uc, addr, size, user):
        _rng[0] = (1103515245 * _rng[0] + 12345) & 0x7FFFFFFF
        uc.reg_write(reg("x0"), (_rng[0] >> 16) & 0x7FFF)

    def cb_srand(uc, addr, size, user):
        _rng[0] = uc.reg_read(reg("x0")) & 0x7FFFFFFF

    def cb_fopen(uc, addr, size, user):
        uc.reg_write(reg("x0"), h.alloc(8))          # 假 FILE*

    def cb_fgets(uc, addr, size, user):
        uc.reg_write(reg("x0"), 0)                   # EOF

    def cb_getppid(uc, addr, size, user):
        uc.reg_write(reg("x0"), 1)

    def cb_waitpid(uc, addr, size, user):
        uc.reg_write(reg("x0"), 0xFFFFFFFFFFFFFFFF)

    def cb_ptrace(uc, addr, size, user):
        uc.reg_write(reg("x0"), 0)                   # 假装成功/未被跟踪

    def cb_gettimeofday(uc, addr, size, user):
        tv = uc.reg_read(reg("x0"))
        if tv:
            uc.mem_write(tv, b"\x00" * 16)
        uc.reg_write(reg("x0"), 0)

    def _noop(uc, addr, size, user):
        pass

    _warned = set()

    def _unknown_for(name):
        def cb(uc, addr, size, user):
            if name not in _warned:
                _warned.add(name)
                print("[!] unstubbed (--imp): %s -> 0" % name, flush=True)
            uc.reg_write(reg("x0"), 0)
        return cb

    builtins = {
        "strncmp": cb_strncmp, "strcmp": cb_strcmp, "memcmp": cb_memcmp, "strlen": cb_strlen,
        "memcpy": cb_memcpy, "memmove": cb_memmove, "memset": cb_memset, "memchr": cb_memchr,
        "strcpy": cb_strcpy, "strncpy": cb_strncpy, "strcat": cb_strcat,
        "strchr": cb_strchr, "strrchr": cb_strrchr, "strstr": cb_strstr, "strnlen": cb_strnlen,
        "atoi": cb_atoi, "strtol": cb_strtol, "strtoul": cb_strtoul, "strtoull": cb_strtoul,
        "strtod": cb_strtod, "sprintf": cb_sprintf, "snprintf": cb_snprintf,
        "malloc": cb_malloc, "free": cb_free, "calloc": cb_calloc, "realloc": cb_realloc,
        "malloc_usable_size": cb_usable_size, "posix_memalign": cb_posix_memalign,
        "aligned_alloc": cb_usable_size,
        "__cxa_guard_acquire": cb_ret1, "__cxa_guard_release": cb_ret0,
        "__cxa_atexit": cb_ret0, "__register_atfork": cb_ret0,
        "__cxa_allocate_exception": cb_alloc_exc, "__cxa_begin_catch": cb_ret0,
        "pthread_mutex_lock": cb_ret0, "pthread_mutex_unlock": cb_ret0,
        "pthread_mutex_init": cb_ret0, "pthread_mutex_destroy": cb_ret0,
        "pthread_once": cb_ret0, "pthread_self": cb_ret1,
        "pthread_key_create": cb_ret0, "pthread_setspecific": cb_ret0,
        "getenv": cb_ret0, "__errno": cb_ret0,
        "dlopen": cb_ret1, "dlclose": cb_ret0, "dlsym": cb_ret0, "dlerror": cb_ret0,
        "__android_log_print": cb_ret0, "__android_log_write": cb_ret0,
        "fopen": cb_fopen, "fgets": cb_fgets, "fclose": cb_ret0, "fread": cb_ret0,
        "fwrite": cb_ret0, "getppid": cb_getppid, "getpid": cb_getppid, "waitpid": cb_waitpid,
        "ptrace": cb_ptrace, "raise": cb_ret0, "usleep": cb_ret0, "sleep": cb_ret0,
        "nanosleep": cb_ret0, "pthread_create": cb_ret0, "pthread_join": cb_ret0,
        "pthread_exit": cb_ret0, "pthread_detach": cb_ret0,
        "rand": cb_rand, "srand": cb_srand, "gettimeofday": cb_gettimeofday,
        "__stack_chk_fail": _noop, "abort": _noop, "__cxa_finalize": _noop,
        "__cxa_free_exception": _noop, "__cxa_end_catch": _noop, "__cxa_rethrow": _noop,
    }
    result = {}
    names = set(extra) | set(builtins) | set(overrides)
    for name in names:
        if name in overrides:
            cb = cb_override(overrides[name])
        elif name in builtins:
            cb = builtins[name]
        else:
            cb = _unknown_for(name)
        if tracer is not None:
            cb = tracer.wrap(name, cb)
        result[name] = cb
    return result


def find_symbol(path, name):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec_name in (".dynsym", ".symtab"):
            sec = elf.get_section_by_name(sec_name)
            if not sec:
                continue
            for sym in sec.iter_symbols():
                if sym.name == name:
                    return sym["st_value"]
    return None


def _ctype_cell(h):
    """为 _ctype_ 数据导入分配一个"指向 ctype 表"的变量单元，返回该单元地址。"""
    tbl = h.alloc(258, align=8)
    buf = bytearray(258)
    for c in range(256):
        f = 0
        if 0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A:
            f |= 7          # isalnum
        if c == 0x20 or 0x09 <= c <= 0x0D:
            f |= 8          # isspace
        if c < 0x20 or c == 0x7F:
            f |= 0x20       # iscntrl
        buf[c + 1] = f
    h.write(tbl, bytes(buf))
    cell = h.alloc(8, align=8)
    h.write(cell, struct.pack("<Q", tbl))
    return cell


def data_import_slot(h, name):
    """数据导入(GLOB_DAT)的 GOT 目标：返回一块【可写数据】的地址（不是代码桩）。

    已知符号给可用初值（_ctype_ 造表、__sF/stdio 造零缓冲），其余给零初始化单元。
    """
    if name in ("_ctype_", "__ctype_"):
        return _ctype_cell(h)
    size = 0x100 if name in ("__sF", "stdout", "stderr", "stdin") else 8
    cell = h.alloc(size, align=8)
    h.write(cell, b"\x00" * size)
    return cell


def apply_relocations(h, path, stubs):
    """Loader-correct relocation pass:

    - R_AARCH64_RELATIVE (1027) / IRELATIVE (1032) -> r_addend (base 0 in emulation)
    - defined symbol -> st_value + r_addend (fixes R_AARCH64_ABS64 addend, e.g. RTTI vtables)
    - undefined JUMP_SLOT -> function stub (builtin libc impl or ret-0)
    - undefined GLOB_DAT  -> data slot (writable data, NOT a code stub; see data_import_slot)
    """
    from elftools.elf.elffile import ELFFile
    R_RELATIVE, R_IRELATIVE, R_GLOB_DAT = 1027, 1032, 1025
    undef_fn, undef_data = {}, {}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec_name in (".rela.plt", ".rela.dyn"):
            sec = elf.get_section_by_name(sec_name)
            if not sec:
                continue
            symtab = elf.get_section(sec["sh_link"])
            for rel in sec.iter_relocations():
                rtype = rel["r_info_type"]
                if rtype in (R_RELATIVE, R_IRELATIVE):
                    h.write(rel["r_offset"], struct.pack("<Q", rel["r_addend"]))
                    continue
                symidx = rel["r_info_sym"]
                if not symidx:
                    continue
                sym = symtab.get_symbol(symidx)
                if sym["st_shndx"] == "SHN_UNDEF":
                    if rtype == R_GLOB_DAT:
                        undef_data[rel["r_offset"]] = sym.name
                    else:
                        undef_fn[rel["r_offset"]] = sym.name
                else:
                    h.write(rel["r_offset"], struct.pack("<Q", sym["st_value"] + rel["r_addend"]))
    warned = set()

    def _unstubbed(name):
        def cb(uc, addr, size, user):
            if name not in warned:
                warned.add(name)
                print("[!] unstubbed: %s -> 0" % name, flush=True)
            from unicorn.arm64_const import UC_ARM64_REG_X0
            uc.reg_write(UC_ARM64_REG_X0, 0)
        return cb

    for offset, name in undef_fn.items():
        cb = stubs.get(name)
        h.write(offset, struct.pack("<Q", h.stub(cb if cb is not None else _unstubbed(name))))
    for offset, name in undef_data.items():
        h.write(offset, struct.pack("<Q", data_import_slot(h, name)))
    return len(undef_fn) + len(undef_data)


def run_init(h, path):
    """执行 DT_INIT / DT_INIT_ARRAY（.so 静态初始化，如 C++ 全局对象构造）。

    不跑初始化 -> std::string/std::vector 等全局对象为空（例：base64 字母表）。
    失败不致命：单个初始化器异常仅告警并跳过。返回成功执行的个数。
    """
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        dyn = ELFFile(f).get_section_by_name(".dynamic")
        if dyn is None:
            return 0
        init = arr = arrsz = 0
        for tag in dyn.iter_tags():
            t = tag.entry.d_tag
            if t == "DT_INIT":
                init = tag.entry.d_val
            elif t == "DT_INIT_ARRAY":
                arr = tag.entry.d_val
            elif t == "DT_INIT_ARRAYSZ":
                arrsz = tag.entry.d_val
    done = 0
    if arr and arrsz:
        for off in range(0, arrsz, 8):
            try:
                fn = struct.unpack("<Q", h.read(arr + off, 8))[0]
            except Exception:  # noqa: BLE001
                break
            if fn:
                try:
                    h.call(fn)
                    done += 1
                except Exception as e:  # noqa: BLE001
                    print("[!] init_array[%d] @%#x failed: %s" % (off // 8, fn, e))
    if init:
        try:
            h.call(init)
            done += 1
        except Exception as e:  # noqa: BLE001
            print("[!] DT_INIT @%#x failed: %s" % (init, e))
    return done


_SYSCALL_NR = {
    63: "read", 64: "write", 56: "openat", 57: "close", 62: "lseek", 80: "fstat",
    79: "newfstatat", 78: "readlinkat", 48: "faccessat", 29: "ioctl", 101: "nanosleep",
    113: "clock_gettime", 172: "getpid", 174: "getuid", 175: "geteuid", 176: "getgid",
    178: "gettid", 179: "sysinfo", 160: "uname", 167: "prctl", 222: "mmap",
    226: "mprotect", 215: "munmap", 318: "getrandom", 94: "exit_group", 93: "exit",
}


def install_syscalls(h, log=True):
    """装 syscall 层（UC_HOOK_INTR）：给直接 `svc #0` 的 .so 兜底，避免一碰就崩。

    默认：文件类返回"不存在/失败"（利于绕过 /proc 等检测）、getpid/uid 给固定值、
    getrandom 给确定性伪随机、mmap 走 arena、exit 停机。每个 syscall 首次命中打印一行。
    注：unicorn 2.x 在 arm64 SVC 触发 INTR 时 PC 已指向下一条（无需 +4）。
    """
    from unicorn import UC_HOOK_INTR
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X8, UC_ARM64_REG_PC)
    NEG1 = 0xFFFFFFFFFFFFFFFF
    state = {"seed": 0x12345678, "logged": set()}

    def wr(addr, data):
        try:
            h.uc.mem_write(addr, data)
        except Exception:  # noqa: BLE001
            pass

    def on_intr(uc, intno, user):
        nr = uc.reg_read(UC_ARM64_REG_X8)
        x0, x1, x2 = (uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
                      uc.reg_read(UC_ARM64_REG_X2))
        ret = 0
        if nr == 172:
            ret = 1234                                   # getpid
        elif nr in (174, 175, 176, 178):
            ret = 1000                                   # uid/gid/tid
        elif nr == 64:
            ret = x2                                     # write -> 声称写成功
        elif nr == 63:
            ret = 0                                      # read -> EOF
        elif nr == 56:
            ret = NEG1 - 1                               # openat -> ENOENT
        elif nr in (48, 78):
            ret = NEG1                                   # faccessat/readlinkat -> 失败
        elif nr in (80, 79):
            wr(x1 if nr == 80 else x2, b"\x00" * 128)    # fstat/newfstatat -> 0
        elif nr == 113:
            wr(x1, b"\x00" * 16)                         # clock_gettime -> 0
        elif nr == 318:
            n = min(x1, 4096)                            # getrandom -> 确定性伪随机
            s, buf = state["seed"], bytearray()
            for _ in range(n):
                s = (1103515245 * s + 12345) & 0x7FFFFFFF
                buf.append((s >> 16) & 0xFF)
            state["seed"] = s
            wr(x0, bytes(buf))
            ret = n
        elif nr == 222:
            ret = h.alloc(max(1, x1))                    # mmap -> arena
        elif nr == 160:
            wr(x0, b"\x00" * 390)                        # uname -> 0
        elif nr in (93, 94):
            uc.reg_write(UC_ARM64_REG_PC, h._stop_addr())  # exit/exit_group -> 停机
            return
        elif nr in (62, 57, 101, 167, 179, 226, 215):
            ret = 0
        elif nr == 29:
            ret = NEG1                                   # ioctl -> 失败
        if log:
            name = _SYSCALL_NR.get(nr, "nr_%d" % nr)
            if name not in state["logged"]:
                state["logged"].add(name)
                print("[syscall] %s(nr=%d) -> %#x" % (name, nr, ret & NEG1), flush=True)
        uc.reg_write(UC_ARM64_REG_X0, ret & NEG1)

    h.uc.hook_add(UC_HOOK_INTR, on_intr)
    return state


def build_jni(h, default_cb, jni_log=None, tracer=None, dumper=None):
    """Fake JNIEnv with functional string/array stubs. Returns env address.

    All slots are pre-filled with default_cb (ret 0) so unknown calls never jump to 0.
    jni_log: JniLogger（--log-jni）；tracer: StubTracer（--trace-stubs）；dumper: 落盘文件（--dump-jni-out）。
    """
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4)

    proxies = {}

    # 字节数组长度表挂在 Harness 上（而非模块全局）：`--setup` 里 `import emu_run` 会因
    # 主程序以 __main__ 运行而得到"第二个模块实例"，模块全局不可见。用法：h.jni_array_lens[ptr]=n
    lens = getattr(h, "jni_array_lens", None)
    if lens is None:
        lens = {}
        h.jni_array_lens = lens

    def _cbytes(ptr, limit=65536):
        """健壮读 C 串（分小块，遇 NUL/未映射即停）——固定大块读会在映射边界整体失败。"""
        out = bytearray()
        while len(out) < limit:
            try:
                chunk = bytes(h.uc.mem_read(ptr + len(out), min(16, limit - len(out))))
            except Exception:  # noqa: BLE001
                break
            z = chunk.find(b"\x00")
            if z >= 0:
                return bytes(out) + chunk[:z]
            out += chunk
        return bytes(out)

    def read_ptr(reg):
        return h.uc.reg_read(reg)

    def cb_new_string_utf(uc, addr, size, user):
        cptr = read_ptr(UC_ARM64_REG_X1)
        jptr = h.alloc(8)
        h.write(jptr, struct.pack("<Q", cptr))
        uc.reg_write(UC_ARM64_REG_X0, jptr)
        proxies[jptr] = cptr
        _dump_jni(dumper, "NewStringUTF", _read_cstr_uc(uc, cptr))

    def cb_new_string(uc, addr, size, user):
        ptr = read_ptr(UC_ARM64_REG_X1)  # jchar*（UTF-16）；同 NewStringUTF 以指针代理
        jptr = h.alloc(8)
        h.write(jptr, struct.pack("<Q", ptr))
        uc.reg_write(UC_ARM64_REG_X0, jptr)
        proxies[jptr] = ptr

    def cb_set_byte_region(uc, addr, size, user):
        arr, start, length, buf = (read_ptr(UC_ARM64_REG_X1), read_ptr(UC_ARM64_REG_X2),
                                   read_ptr(UC_ARM64_REG_X3), read_ptr(UC_ARM64_REG_X4))
        try:
            data = h.read(buf, length)
            h.write(arr + start, data)
        except Exception:  # noqa: BLE001
            return
        _dump_jni(dumper, "SetByteArrayRegion", data.hex())

    def cb_get_utf_chars(uc, addr, size, user):
        jptr = read_ptr(UC_ARM64_REG_X1)
        uc.reg_write(UC_ARM64_REG_X0, proxies.get(jptr, jptr))

    def cb_utf_length(uc, addr, size, user):
        jptr = read_ptr(UC_ARM64_REG_X1)
        cptr = proxies.get(jptr, jptr)
        uc.reg_write(UC_ARM64_REG_X0, len(_cbytes(cptr)) if cptr else 0)

    def cb_new_byte_array(uc, addr, size, user):
        n = read_ptr(UC_ARM64_REG_X1)
        p = h.alloc(max(1, n))
        lens[p] = n
        uc.reg_write(UC_ARM64_REG_X0, p)

    def cb_get_byte_array(uc, addr, size, user):
        uc.reg_write(UC_ARM64_REG_X0, read_ptr(UC_ARM64_REG_X1))

    def cb_get_byte_region(uc, addr, size, user):
        arr, start, length, buf = (read_ptr(UC_ARM64_REG_X1), read_ptr(UC_ARM64_REG_X2),
                                   read_ptr(UC_ARM64_REG_X3), read_ptr(UC_ARM64_REG_X4))
        try:
            h.write(buf, h.read(arr + start, length))
        except Exception:  # noqa: BLE001
            pass

    def cb_array_length(uc, addr, size, user):
        ptr = read_ptr(UC_ARM64_REG_X1)
        uc.reg_write(UC_ARM64_REG_X0, lens.get(ptr, len(_cbytes(ptr)) if ptr else 0))

    slots = {i: default_cb for i in range(0, 240)}
    slots.update({
        JNI_SLOTS["NewString"]: cb_new_string,
        JNI_SLOTS["NewStringUTF"]: cb_new_string_utf,
        JNI_SLOTS["GetStringUTFChars"]: cb_get_utf_chars,
        JNI_SLOTS["GetStringUTFLength"]: cb_utf_length,
        JNI_SLOTS["GetStringLength"]: cb_utf_length,
        JNI_SLOTS["NewByteArray"]: cb_new_byte_array,
        JNI_SLOTS["GetByteArrayElements"]: cb_get_byte_array,
        JNI_SLOTS["GetByteArrayRegion"]: cb_get_byte_region,
        JNI_SLOTS["SetByteArrayRegion"]: cb_set_byte_region,
        # 171: GetArrayLength —— 测试里传入的多是 C 字符串指针，用 strlen 近似
        171: cb_array_length,
    })
    if tracer is not None:
        slots = {i: tracer.wrap(jni_name(i), cb, tracer.JNI_REGS) for i, cb in slots.items()}
    if jni_log is not None:
        slots = {i: jni_log.wrap(i, cb) for i, cb in slots.items()}
    return h.jni_env(slots=slots)


def hexdump(data, base):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("  %08x  %-47s  %s" % (base + off, hexs, text))
    return "\n".join(out)


def _reg_const(name):
    import unicorn.arm64_const as ac
    return getattr(ac, "UC_ARM64_REG_" + name.strip().upper())


def parse_watch_buf_spec(spec):
    """'x19+0x61f0:16' / 'x0:64' -> (reg, off, n)"""
    loc, n_s = spec.split(":")
    m = re.match(r"^([a-zA-Z0-9_]+)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)$", loc.strip())
    if m:
        reg, sign, off_s = m.group(1), m.group(2), m.group(3)
        off = int(off_s, 0) * (1 if sign == "+" else -1)
    else:
        reg, off = loc.strip(), 0
    return reg, off, int(n_s, 0)


def install_watchers(h, args):
    """通用观测层：code 命中打印（寄存器/指针缓冲）、内存读写监视（聚合）、内存字节扫描。

    返回 report()：调用结束后打印汇总（Top PC + 触发扫描）。
    """
    import unicorn
    from unicorn.arm64_const import UC_ARM64_REG_PC

    code_hits = {}
    mem_hits = {}
    printed = {"code": 0, "mem": 0}
    bufs = [parse_watch_buf_spec(s) for s in args.watch_buf]
    regs = [r.strip() for r in args.watch_regs.split(",") if r.strip()]
    scan_pats = [bytes.fromhex(p.replace(" ", "")) for p in args.scan.split(",") if p.strip()]

    def fmt_hit(uc, addr, kind):
        parts = ["[%s] %#x" % (kind, addr)]
        for r in regs:
            try:
                parts.append("%s=%#x" % (r, uc.reg_read(_reg_const(r))))
            except Exception:  # noqa: BLE001
                parts.append("%s=?" % r)
        for reg, off, n in bufs:
            try:
                base = uc.reg_read(_reg_const(reg)) + off
                ptr = struct.unpack_from("<Q", bytes(h.uc.mem_read(base, 8)), 0)[0]
                data = bytes(h.uc.mem_read(ptr, n))
                parts.append("buf[%s%+d]->%#x(%d)=%s" % (reg, off, ptr, n, data.hex()))
            except Exception:  # noqa: BLE001
                parts.append("buf[%s%+d]=?" % (reg, off))
        return " ".join(parts)

    def mk_code_cb(pc):
        def cb(uc, addr, size, user):
            code_hits[pc] = code_hits.get(pc, 0) + 1
            if printed["code"] < args.watch_max:
                printed["code"] += 1
                print(fmt_hit(uc, pc, "code"), flush=True)
        return cb

    for spec in args.watch_code:
        for pc_s in spec.split(","):
            if pc_s.strip():
                pc = int(pc_s, 0)
                h.hook(pc, pc, mk_code_cb(pc))

    def mk_mem_cb(kind):
        def cb(uc, access, addr, size, value, user):
            pc = uc.reg_read(UC_ARM64_REG_PC)
            mem_hits[(kind, pc)] = mem_hits.get((kind, pc), 0) + 1
            if printed["mem"] < args.watch_max:
                printed["mem"] += 1
                if kind == "wr":
                    print("  [wr] %#x size=%d val=%#x pc=%#x" % (addr, size, value, pc), flush=True)
                else:
                    print("  [rd] %#x size=%d pc=%#x" % (addr, size, pc), flush=True)
        return cb

    for flag, hook_id, kind in ((args.watch_write, unicorn.UC_HOOK_MEM_WRITE, "wr"),
                                (args.watch_read, unicorn.UC_HOOK_MEM_READ, "rd")):
        for spec in flag:
            lo_s, hi_s = spec.split("-")
            lo, hi = int(lo_s, 0), int(hi_s, 0)
            h.uc.hook_add(hook_id, mk_mem_cb(kind), begin=lo, end=hi)

    def run_scans(tag):
        for pat in scan_pats:
            hits = 0
            for reg in h.uc.mem_regions():
                begin, end = reg[0], reg[1]
                name = reg[3] if len(reg) > 3 else ""
                try:
                    data = bytes(h.uc.mem_read(begin, end - begin))
                except Exception:  # noqa: BLE001
                    continue
                i = data.find(pat)
                while i >= 0 and hits < args.scan_limit:
                    print("[scan:%s] %s @ %#x (%s)" % (tag, pat.hex(), begin + i, name))
                    hits += 1
                    i = data.find(pat, i + 1)

    if scan_pats and args.scan_at:
        for pc_s in args.scan_at.split(","):
            if pc_s.strip():
                pc = int(pc_s, 0)
                state = {"n": 0}

                def mk_scan_cb(_pc, _st):
                    def cb(uc, addr, size, user):
                        if _st["n"] < 4:
                            _st["n"] += 1
                            run_scans("at-%#x" % _pc)
                    return cb

                h.hook(pc, pc, mk_scan_cb(pc, state))

    def report():
        if code_hits:
            print("[watch] code hits: " + ", ".join(
                "%#x x%d" % (k, v) for k, v in sorted(code_hits.items())), flush=True)
        if mem_hits:
            top = sorted(mem_hits.items(), key=lambda kv: -kv[1])[:args.watch_top]
            print("[watch] mem top PCs: " + ", ".join(
                "%s@%#x x%d" % (k, pc, v) for (k, pc), v in top), flush=True)
        if printed["code"] or printed["mem"]:
            print("[watch] printed %d code / %d mem events (cap=%d)"
                  % (printed["code"], printed["mem"], args.watch_max), flush=True)
        run_scans("post")

    return report


def main():
    ap = argparse.ArgumentParser(description="单函数离线仿真（Unicorn）")
    ap.add_argument("so")
    ap.add_argument("--sym", default="")
    ap.add_argument("--off", default="")
    ap.add_argument("--args", default="")
    ap.add_argument("--jni", action="store_true")
    ap.add_argument("--imp", default="", help="额外导入桩（逗号分隔）")
    ap.add_argument("--stub", action="append", default=[], help="覆盖导入桩返回值 name=val（可重复，如 getpid=1234）")
    ap.add_argument("--log-jni", action="store_true", help="JNI 调用日志：每次调用打印 [jni] name(args) -> ret")
    ap.add_argument("--dump-jni-out", default="", help="NewStringUTF / SetByteArrayRegion 内容追加落盘")
    ap.add_argument("--trace-stubs", action="store_true", help="桩命中日志：name(args) -> ret")
    ap.add_argument("--poke", action="append", default=[], help="addr:size=value")
    ap.add_argument("--poke-str", action="append", default=[], help="addr=text（写 UTF-8 字节串）")
    ap.add_argument("--read", action="append", default=[], help="addr:len")
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--timeout", type=int, default=0)
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--no-init", action="store_true",
                    help="不执行 DT_INIT/DT_INIT_ARRAY（默认执行，用于初始化 C++ 全局对象）")
    ap.add_argument("--no-syscalls", action="store_true",
                    help="不装 syscall 层（默认装：给直接 svc #0 的 .so 兜底）")
    ap.add_argument("--ret-str", action="store_true",
                    help="按 sret(x8) 调用并解码返回的 std::string（C++ 返回值）")
    ap.add_argument("--out-arg", action="append", default=[],
                    help="调用后 dump 第 N 个实参指向的缓冲：N:LEN（可重复）")
    ap.add_argument("--setup", default="")
    ap.add_argument("--watch-code", action="append", default=[], help="命中 PC（逗号分隔）时打印（可重复）")
    ap.add_argument("--watch-regs", default="", help="watch-code 打印的寄存器，如 x0,x1,x2")
    ap.add_argument("--watch-buf", action="append", default=[], help="打印指针缓冲，如 x19+0x61f0:16（可重复）")
    ap.add_argument("--watch-read", action="append", default=[], help="内存读监视 lo-hi（可重复）")
    ap.add_argument("--watch-write", action="append", default=[], help="内存写监视 lo-hi（可重复）")
    ap.add_argument("--watch-max", type=int, default=100, help="事件打印上限，超出只聚合")
    ap.add_argument("--watch-top", type=int, default=15, help="汇总 Top PC 数量")
    ap.add_argument("--scan", default="", help="调用后扫描内存字节模式（hex，逗号分隔）")
    ap.add_argument("--scan-at", default="", help="在命中这些 PC 时扫描（逗号分隔）")
    ap.add_argument("--scan-limit", type=int, default=8, help="每模式最多报告命中数")
    args = ap.parse_args()

    h = Harness(trace=args.trace)
    dump_fh = None
    try:
        if args.raw:
            h.map_raw(args.so)
        else:
            h.map_elf(args.so)
        h.setup_stack()
        h.setup_tls()

        overrides = {}
        for spec in args.stub:
            try:
                name_s, val_s = spec.split("=", 1)
                overrides[name_s.strip()] = int(val_s, 0)
            except ValueError:
                print("[-] bad --stub spec: %r (want name=val, e.g. getpid=1234)" % spec)
                return 1
        if args.dump_jni_out:
            dump_fh = open(args.dump_jni_out, "a", encoding="utf-8")
        tracer = StubTracer(args) if args.trace_stubs else None
        jni_log = JniLogger(args) if args.log_jni else None

        if args.sym:
            off = find_symbol(args.so, args.sym)
            if off is None:
                print("[-] symbol not found: %s" % args.sym)
                return 1
        elif args.off:
            off = int(args.off, 0)
        else:
            print("[-] need --sym or --off")
            return 1

        # loader-correct relocations (RELATIVE / defined GLOB_DAT first, then import stubs)
        extra = [x for x in args.imp.split(",") if x]
        extra += [n for n in overrides if n not in extra]
        libc_stubs = make_libc_stubs(h, extra, overrides, tracer)
        apply_relocations(h, args.so, libc_stubs)

        env = build_jni(h, _ret0, jni_log=jni_log, tracer=tracer, dumper=dump_fh) if args.jni else None
        call_args = parse_args_tokens(args.args.split(",") if args.args else [], h, env)

        for poke in args.poke:
            spec, val = poke.split("=")
            addr_s, size_s = spec.split(":")
            addr, size, value = int(addr_s, 0), int(size_s, 0), int(val, 0)
            h.write(addr, value.to_bytes(size, "little"))

        for spec in args.poke_str:
            addr_s, text = spec.split("=", 1)
            h.write(int(addr_s, 0), text.encode("utf-8"))

        if args.setup:
            ns = {"__file__": os.path.abspath(args.setup), "__name__": "__emu_setup__"}
            exec(compile(open(args.setup, encoding="utf-8").read(), args.setup, "exec"), ns)  # noqa: S102
            ns["setup"](h)

        if not args.no_init:
            n_init = run_init(h, args.so)
            if n_init:
                print("[init] ran %d initializer(s)" % n_init)

        if not args.no_syscalls:
            install_syscalls(h)

        _sret = None
        if args.ret_str:
            from unicorn.arm64_const import UC_ARM64_REG_X8
            _sret = h.alloc(32, align=8)
            h.uc.reg_write(UC_ARM64_REG_X8, _sret)

        report = install_watchers(h, args)

        r = h.call(off, args=call_args, timeout=args.timeout)
        print("x0=%#x  insns=%d" % (r.x0, r.insns))

        if _sret is not None:
            from emu_setup import read_std_string
            print("[ret-str] %r" % bytes(read_std_string(h, _sret)))

        for spec in args.out_arg:
            n_s, len_s = spec.split(":")
            i, ln = int(n_s, 0), int(len_s, 0)
            if i < len(call_args) and call_args[i]:
                print("[out-arg %d]" % i)
                print(hexdump(h.read(call_args[i], ln), call_args[i]))

        for spec in args.read:
            addr_s, len_s = spec.split(":")
            addr, ln = int(addr_s, 0), int(len_s, 0)
            data = h.read(addr, ln)
            print(hexdump(data, addr))
        report()
        if jni_log is not None:
            jni_log.report()
        if tracer is not None:
            tracer.report()
        return 0
    except Exception as e:  # noqa: BLE001
        try:
            h.fault(e)
        except Exception:  # noqa: BLE001
            print("[-] %s: %s" % (type(e).__name__, e))
        return 1
    finally:
        if dump_fh is not None:
            dump_fh.close()


if __name__ == "__main__":
    raise SystemExit(main())
