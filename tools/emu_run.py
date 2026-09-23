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
  --poke 0x15054:4=2                调用前写内存（可重复）
  --read 0x1000:32                  调用后读内存（hex+ascii，可重复）
  --trace / --timeout 10 / --raw    指令追踪 / 秒 / raw 映射（vaddr==offset 的 dump so）
  --setup hooks.py                  自定义脚本：def setup(h): ...（拿到 Harness 全权）
"""
import argparse
import os
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


def make_libc_stubs(h, extra):
    """Built-in host implementations for common imported libc functions."""

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
    names = set(extra) | set(builtins)
    for name in names:
        result[name] = builtins.get(name, unknown) or (lambda uc, a, s, u: None)
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


def build_jni(h, default_cb):
    """Fake JNIEnv with functional string/array stubs. Returns env address.

    All slots are pre-filled with default_cb (ret 0) so unknown calls never jump to 0.
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
        JNI_SLOTS["NewStringUTF"]: cb_new_string_utf,
        JNI_SLOTS["GetStringUTFChars"]: cb_get_utf_chars,
        JNI_SLOTS["GetStringUTFLength"]: cb_utf_length,
        JNI_SLOTS["GetStringLength"]: cb_utf_length,
        JNI_SLOTS["NewByteArray"]: cb_new_byte_array,
        JNI_SLOTS["GetByteArrayElements"]: cb_get_byte_array,
        JNI_SLOTS["GetByteArrayRegion"]: cb_get_byte_region,
        # 171: GetArrayLength —— 测试里传入的多是 C 字符串指针，用 strlen 近似
        171: cb_array_length,
    })
    return h.jni_env(slots=slots)


def hexdump(data, base):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("  %08x  %-47s  %s" % (base + off, hexs, text))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="单函数离线仿真（Unicorn）")
    ap.add_argument("so")
    ap.add_argument("--sym", default="")
    ap.add_argument("--off", default="")
    ap.add_argument("--args", default="")
    ap.add_argument("--jni", action="store_true")
    ap.add_argument("--imp", default="", help="额外导入桩（逗号分隔）")
    ap.add_argument("--poke", action="append", default=[], help="addr:size=value")
    ap.add_argument("--poke-str", action="append", default=[], help="addr=text（写 UTF-8 字节串）")
    ap.add_argument("--read", action="append", default=[], help="addr:len")
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--timeout", type=int, default=0)
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--setup", default="")
    args = ap.parse_args()

    h = Harness(trace=args.trace)
    try:
        if args.raw:
            h.map_raw(args.so)
        else:
            h.map_elf(args.so)
        h.setup_stack()
        h.setup_tls()

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
        libc_stubs = make_libc_stubs(h, extra)
        apply_relocations(h, args.so, libc_stubs)

        env = build_jni(h, _ret0) if args.jni else None
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

        r = h.call(off, args=call_args, timeout=args.timeout)
        print("x0=%#x  insns=%d" % (r.x0, r.insns))

        for spec in args.read:
            addr_s, len_s = spec.split(":")
            addr, ln = int(addr_s, 0), int(len_s, 0)
            data = h.read(addr, ln)
            print(hexdump(data, addr))
        return 0
    except Exception as e:  # noqa: BLE001
        try:
            h.fault(e)
        except Exception:  # noqa: BLE001
            print("[-] %s: %s" % (type(e).__name__, e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
