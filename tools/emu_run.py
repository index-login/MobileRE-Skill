#!/usr/bin/env python3
"""emu_run.py — 单函数离线仿真（Unicorn，基于 uniharness.py）。

用途：不碰真机，调用 .so 内指定函数并取回返回值；内置 JNIEnv 与常见 libc 导入桩，
可复算算法（如 crackme 校验函数）。

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
  --setup hooks.py                  自定义脚本：def setup(h): ...（拿到 Harness 全权）

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
    if not ptr:
        return ""
    try:
        data = bytes(uc.mem_read(ptr, limit))
    except Exception:  # noqa: BLE001
        return ""
    return data.split(b"\x00", 1)[0].decode("utf-8", "replace")


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
        pa = read_mem(a, 4096).split(b"\x00", 1)[0]
        pb = read_mem(b, 4096).split(b"\x00", 1)[0]
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
        s = read_mem(uc.reg_read(reg("x0")), 4096).split(b"\x00", 1)[0]
        uc.reg_write(reg("x0"), len(s))

    def cb_malloc(uc, addr, size, user):
        uc.reg_write(reg("x0"), h.alloc(max(1, uc.reg_read(reg("x0")))))

    def cb_free(uc, addr, size, user):
        pass

    builtins = {
        "strncmp": cb_strncmp, "strcmp": cb_strcmp, "memcmp": cb_memcmp,
        "strlen": cb_strlen, "malloc": cb_malloc, "free": cb_free,
        "__stack_chk_fail": None, "abort": None,
    }
    unknown = lambda uc, addr, size, user: uc.reg_write(reg("x0"), 0)  # noqa: E731
    result = {}
    names = set(extra) | set(builtins) | set(overrides)
    for name in names:
        if name in overrides:
            cb = cb_override(overrides[name])
        else:
            cb = builtins.get(name, unknown) or (lambda uc, a, s, u: None)
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


def apply_relocations(h, path, stubs):
    """Loader-correct relocation pass:

    - R_AARCH64_RELATIVE (1027) -> r_addend (base 0 in emulation)
    - GLOB_DAT/JUMP_SLOT on a DEFINED symbol -> its st_value (e.g. opaque-list globals)
    - Undefined symbols -> stub (builtin libc impl or ret-0)
    """
    from elftools.elf.elffile import ELFFile
    undef = {}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec_name in (".rela.plt", ".rela.dyn"):
            sec = elf.get_section_by_name(sec_name)
            if not sec:
                continue
            symtab = elf.get_section(sec["sh_link"])
            for rel in sec.iter_relocations():
                if rel["r_info_type"] == 1027:  # R_AARCH64_RELATIVE
                    h.write(rel["r_offset"], struct.pack("<Q", rel["r_addend"]))
                    continue
                symidx = rel["r_info_sym"]
                if not symidx:
                    continue
                sym = symtab.get_symbol(symidx)
                if sym["st_shndx"] == "SHN_UNDEF":
                    undef[rel["r_offset"]] = sym.name
                else:
                    h.write(rel["r_offset"], struct.pack("<Q", sym["st_value"]))
    for offset, name in undef.items():
        cb = stubs.get(name, _ret0)
        h.write(offset, struct.pack("<Q", h.stub(cb)))
    return len(undef)


def build_jni(h, default_cb, jni_log=None, tracer=None, dumper=None):
    """Fake JNIEnv with functional string/array stubs. Returns env address.

    All slots are pre-filled with default_cb (ret 0) so unknown calls never jump to 0.
    jni_log: JniLogger（--log-jni）；tracer: StubTracer（--trace-stubs）；dumper: 落盘文件（--dump-jni-out）。
    """
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4)

    proxies = {}

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
        s = h.read(cptr, 4096).split(b"\x00", 1)[0] if cptr else b""
        uc.reg_write(UC_ARM64_REG_X0, len(s))

    def cb_new_byte_array(uc, addr, size, user):
        n = read_ptr(UC_ARM64_REG_X1)
        uc.reg_write(UC_ARM64_REG_X0, h.alloc(max(1, n)))

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
        s = h.read(ptr, 4096).split(b"\x00", 1)[0] if ptr else b""
        uc.reg_write(UC_ARM64_REG_X0, len(s))

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
            ns = {}
            exec(compile(open(args.setup, encoding="utf-8").read(), args.setup, "exec"), ns)  # noqa: S102
            ns["setup"](h)

        report = install_watchers(h, args)

        r = h.call(off, args=call_args, timeout=args.timeout)
        print("x0=%#x  insns=%d" % (r.x0, r.insns))

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
