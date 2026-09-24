#!/usr/bin/env python3
"""so.py — SO 静态分析工具箱（ARM64）：ELF 侦察 / 字符串 / 字节 / 反汇编 / 交叉引用 / SVC / JNI 判型

合并六个旧工具：elfinfo.py + disasm.py + find_strref.py + find_branch_callers.py
                + scan_inline_svc.py + jni_sig.py

用法:
  python3 tools/so.py info    <so> [--json] [--grep PAT] [--v2o 0xADDR]
  python3 tools/so.py strings <so> [--min N] [--grep PAT]
  python3 tools/so.py dump    <so> 0xVADDR:LEN [--off]
  python3 tools/so.py disasm  <so> [--symbol X | --addr 0x...] [--size N] [--count N] [--grep RE]
  python3 tools/so.py strref  <so> 0xVADDR [0xVADDR ...]
  python3 tools/so.py callers <so> 0xVADDR [--bl-only]
  python3 tools/so.py svc     <so>
  python3 tools/so.py jni     <so> [--symbol X | --addr 0x...] [--size N]

旧工具 → 新命令:
  elfinfo.py <so> [--json] [--v2o a]          -> so.py info <so> [--json] [--v2o a]
  elfinfo.py <so> --strings [N] --grep P      -> so.py strings <so> --min N --grep P
  elfinfo.py <so> --dump a:l                  -> so.py dump <so> a:l [--off]
  disasm.py <so> ...                          -> so.py disasm <so> ...
  find_strref.py <so> <a>                     -> so.py strref <so> <a>
  find_branch_callers.py <so> <a>             -> so.py callers <so> <a>
  scan_inline_svc.py <so>                     -> so.py svc <so>
  jni_sig.py <so> ...                         -> so.py jni <so> ...

说明: 仅支持 ARM64（其它架构报 [!] unsupported machine，退出码 1）；只扫描可执行 PT_LOAD 段；
      内部建立 offset↔vaddr 双向映射，输出地址一律为 vaddr；不静默截断。

依赖: pip install pyelftools capstone
"""
import argparse
import io
import json
import re
import struct
import sys

import capstone
from elftools.elf.elffile import ELFFile

AARCH64_RELOC = {
    257: "ABS64", 258: "ABS32", 259: "ABS16", 260: "PREL64", 261: "PREL32", 262: "PREL16",
    275: "ADR_PREL_PG_HI21", 277: "ADD_ABS_LO12_NC", 278: "LDST8_ABS_LO12_NC",
    1024: "COPY", 1025: "GLOB_DAT", 1026: "JUMP_SLOT", 1027: "RELATIVE",
}

INTERESTING_SECTIONS = (".text", ".rodata", ".data", ".bss", ".init_array", ".fini_array",
                        ".rela.dyn", ".rela.plt", ".dynsym", ".dynstr", ".got", ".plt")

SVC_NAMES = {
    93: "exit", 94: "exit_group", 129: "kill", 130: "tkill", 131: "tgkill",
    220: "clone", 221: "execve", 56: "openat", 57: "close", 63: "read",
    64: "write", 226: "mprotect", 172: "getpid", 178: "gettid",
    260: "wait4", 79: "fstatat", 61: "getdents64", 98: "futex",
    117: "ptrace", 215: "munmap", 222: "mmap",
}

# JNI 函数表（顺序 = JNINativeInterface；arm64 offset = index*8）
JNI_FUNCS = [
    "reserved0", "reserved1", "reserved2", "reserved3",
    "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod", "FromReflectedField",
    "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom", "ToReflectedField", "Throw",
    "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError",
    "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef",
    "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject",
    "NewObjectV", "NewObjectA", "GetObjectClass", "IsInstanceOf", "GetMethodID",
    "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA",
    "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA",
    "CallByteMethod", "CallByteMethodV", "CallByteMethodA",
    "CallCharMethod", "CallCharMethodV", "CallCharMethodA",
    "CallShortMethod", "CallShortMethodV", "CallShortMethodA",
    "CallIntMethod", "CallIntMethodV", "CallIntMethodA",
    "CallLongMethod", "CallLongMethodV", "CallLongMethodA",
    "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA",
    "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA",
    "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA",
    "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA",
    "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA",
    "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV", "CallNonvirtualByteMethodA",
    "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA",
    "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV", "CallNonvirtualShortMethodA",
    "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA",
    "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV", "CallNonvirtualLongMethodA",
    "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV", "CallNonvirtualDoubleMethodA",
    "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA",
    "GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField",
    "GetShortField", "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField",
    "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField", "SetShortField",
    "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField",
    "GetStaticMethodID",
    "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA",
    "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA",
    "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA",
    "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA",
    "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA",
    "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA",
    "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA",
    "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA",
    "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA",
    "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA",
    "GetStaticFieldID",
    "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField",
    "GetStaticShortField", "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField",
    "GetStaticDoubleField",
    "SetStaticObjectField", "SetStaticBooleanField", "SetStaticByteField", "SetStaticCharField",
    "SetStaticShortField", "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField",
    "SetStaticDoubleField",
    "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars",
    "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars",
    "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement",
    "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray", "NewIntArray",
    "NewLongArray", "NewFloatArray", "NewDoubleArray",
    "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements",
    "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements",
    "GetFloatArrayElements", "GetDoubleArrayElements",
    "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements",
    "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements",
    "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements",
    "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion",
    "GetIntArrayRegion", "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion",
    "SetBooleanArrayRegion", "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion",
    "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion",
    "RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM",
    "GetStringRegion", "GetStringUTFRegion", "GetPrimitiveArrayCritical",
    "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical",
    "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer",
    "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType",
]
JNI_OFFSETS = {i * 8: n for i, n in enumerate(JNI_FUNCS)}

# API → (其第 1 个对象参数的类型, 该参数在 JNI 调用中的位置)
ARG_TYPES = {
    "GetStringUTFChars": ("jstring", 1), "GetStringUTFLength": ("jstring", 1),
    "GetStringChars": ("jstring", 1), "GetStringLength": ("jstring", 1),
    "GetStringRegion": ("jstring", 1), "GetStringUTFRegion": ("jstring", 1),
    "GetArrayLength": ("array", 1),
    "GetByteArrayElements": ("jbyteArray", 1), "GetByteArrayRegion": ("jbyteArray", 1),
    "ReleaseByteArrayElements": ("jbyteArray", 1), "SetByteArrayRegion": ("jbyteArray", 1),
    "GetBooleanArrayElements": ("jbooleanArray", 1), "GetBooleanArrayRegion": ("jbooleanArray", 1),
    "GetCharArrayElements": ("jcharArray", 1), "GetCharArrayRegion": ("jcharArray", 1),
    "GetShortArrayElements": ("jshortArray", 1), "GetShortArrayRegion": ("jshortArray", 1),
    "GetIntArrayElements": ("jintArray", 1), "GetIntArrayRegion": ("jintArray", 1),
    "GetLongArrayElements": ("jlongArray", 1), "GetLongArrayRegion": ("jlongArray", 1),
    "GetFloatArrayElements": ("jfloatArray", 1), "GetFloatArrayRegion": ("jfloatArray", 1),
    "GetDoubleArrayElements": ("jdoubleArray", 1), "GetDoubleArrayRegion": ("jdoubleArray", 1),
    "GetObjectArrayElement": ("jobjectArray", 1), "SetObjectArrayElement": ("jobjectArray", 1),
    "GetObjectField": ("jobject", 1), "GetBooleanField": ("jobject", 1),
    "GetIntField": ("jobject", 1), "GetLongField": ("jobject", 1),
}

CALLEE_SAVED = set("x19 x20 x21 x22 x23 x24 x25 x26 x27 x28 x29 x30".split())


class SOError(Exception):
    pass


def seg_flags(p):
    f = ("R" if p & 0x4 else "") + ("W" if p & 0x2 else "") + ("X" if p & 0x1 else "")
    return f or "-"


def sec_flags(sh):
    f = ("A" if sh["sh_flags"] & 0x2 else "") + ("W" if sh["sh_flags"] & 0x1 else "") \
        + ("X" if sh["sh_flags"] & 0x4 else "")
    return f or "-"


class SOImage:
    """ELF 图像：文件字节 + PT_LOAD 映射（offset↔vaddr）+ 可执行段扫描。"""

    def __init__(self, path):
        self.path = path
        try:
            with open(path, "rb") as f:
                self.data = f.read()
        except OSError as e:
            raise SOError("cannot read %s: %s" % (path, e))
        try:
            self.elf = ELFFile(io.BytesIO(self.data))
        except Exception as e:  # noqa: BLE001
            raise SOError("not an ELF (parse failed): %s" % e)
        self.machine = self.elf.header.e_machine
        self.loads = [{
            "vaddr": s["p_vaddr"], "offset": s["p_offset"],
            "filesz": s["p_filesz"], "memsz": s["p_memsz"],
            "flags": seg_flags(s["p_flags"]),
        } for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]

    def off2va(self, off):
        for s in self.loads:
            if s["offset"] <= off < s["offset"] + s["filesz"]:
                return s["vaddr"] + (off - s["offset"])
        return None

    def va2off(self, va):
        for s in self.loads:
            if s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
                return s["offset"] + (va - s["vaddr"])
        return None

    def exec_loads(self):
        return [s for s in self.loads if "X" in s["flags"] and s["filesz"] > 0]

    def iter_words(self):
        """产出可执行段内每个 4 字节对齐字的 (vaddr, word)。"""
        for s in self.exec_loads():
            end = s["offset"] + s["filesz"]
            for off in range(s["offset"], end - 3, 4):
                yield s["vaddr"] + (off - s["offset"]), struct.unpack_from("<I", self.data, off)[0]

    def word_map(self):
        return dict(self.iter_words())

    def read_va(self, va, n):
        off = self.va2off(va)
        if off is None:
            return None
        return self.data[off:off + n]


def find_symbol(img, name):
    for sec_name in (".dynsym", ".symtab"):
        sec = img.elf.get_section_by_name(sec_name)
        if not sec:
            continue
        for sym in sec.iter_symbols():
            if sym.name == name:
                return sym["st_value"], sym["st_size"]
    return None


def hexdump(data, base):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("  %08x  %-47s  %s" % (base + off, hexs, text))
    return "\n".join(out)


def compile_grep(pattern):
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise SOError("bad --grep regex: %s" % e)


def collect_info(img):
    info = {"file": img.path}
    eh = img.elf.header
    info["class"] = eh["e_ident"]["EI_CLASS"]
    info["machine"] = eh["e_machine"]
    info["type"] = eh["e_type"]
    info["entry"] = eh["e_entry"]

    info["segments"] = [dict(s, raw_ok=s["vaddr"] == s["offset"]) for s in img.loads]

    info["sections"] = [{
        "name": s.name, "addr": s["sh_addr"], "offset": s["sh_offset"],
        "size": s["sh_size"], "flags": sec_flags(s),
    } for s in img.elf.iter_sections()]

    needed, soname = [], None
    dyn = img.elf.get_section_by_name(".dynamic")
    if dyn is not None:
        for tag in dyn.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                needed.append(tag.needed)
            elif tag.entry.d_tag == "DT_SONAME":
                soname = tag.soname
    info["needed"] = needed
    info["soname"] = soname

    exports, imports = [], []
    dynsym = img.elf.get_section_by_name(".dynsym")
    if dynsym is not None:
        for sym in dynsym.iter_symbols():
            if not sym.name:
                continue
            typ = sym["st_info"]["type"]
            if sym["st_shndx"] == "SHN_UNDEF":
                imports.append({"name": sym.name, "type": typ})
            elif typ in ("STT_FUNC", "STT_OBJECT"):
                exports.append({"name": sym.name, "addr": sym["st_value"],
                                "size": sym["st_size"], "type": typ})
    info["exports"] = exports
    info["imports"] = imports

    counts, entries = {}, []
    for s in img.elf.iter_sections():
        if not s.name.startswith(".rela"):
            continue
        for rel in s.iter_relocations():
            tname = AARCH64_RELOC.get(rel["r_info_type"], "TYPE_%d" % rel["r_info_type"])
            counts[tname] = counts.get(tname, 0) + 1
            sym_name = None
            idx = rel["r_info_sym"]
            if dynsym is not None and idx and idx < dynsym.num_symbols():
                sym_name = dynsym.get_symbol(idx).name or None
            entries.append({"offset": rel["r_offset"], "type": tname, "symbol": sym_name})
    info["relocations"] = {"counts": counts, "entries": entries}
    return info


def print_info_text(info, rx=None):
    print("== ELF ==")
    print("  file=%s  class=%s  machine=%s  type=%s  entry=%#x"
          % (info["file"], info["class"], info["machine"], info["type"], info["entry"]))
    print()
    print("== PT_LOAD segments (raw-map check) ==")
    for i, s in enumerate(info["segments"]):
        print("  [%d] vaddr=%#010x offset=%#010x filesz=%#010x memsz=%#010x %-3s raw=%s"
              % (i, s["vaddr"], s["offset"], s["filesz"], s["memsz"], s["flags"],
                 "YES" if s["raw_ok"] else "NO"))
    if info["segments"] and all(s["raw_ok"] for s in info["segments"]):
        print("  -> all vaddr==offset: use map_raw(); otherwise use map_elf()")
    print()
    print("== Sections ==")
    for s in info["sections"]:
        if s["name"] in INTERESTING_SECTIONS and s["size"]:
            print("  %-12s addr=%#010x off=%#08x size=%#08x %s"
                  % (s["name"], s["addr"], s["offset"], s["size"], s["flags"]))
    print()
    print("== Dependencies ==")
    print("  SONAME: %s" % info["soname"])
    print("  NEEDED: %s" % " ".join(info["needed"]))
    print()

    exports = info["exports"]
    if rx is None:
        print("== Exports (.dynsym defined, %d) ==" % len(exports))
        for e in exports[:60]:
            print("  %#010x  %6d  %s" % (e["addr"], e["size"], e["name"]))
        if len(exports) > 60:
            print("  ... (%d total, use --json for all)" % len(exports))
    else:
        hits = [e for e in exports if rx.search(e["name"])]
        if hits:
            print("== Exports (%d filtered from %d) ==" % (len(hits), len(exports)))
            for e in hits:
                print("  %#010x  %6d  %s" % (e["addr"], e["size"], e["name"]))
        else:
            print("== Exports (0 matched) ==")
    print()

    imports = info["imports"]
    if rx is None:
        print("== Imports (UND, %d) ==" % len(imports))
        names = " ".join(i["name"] for i in imports)
        print("  " + (names if names else "(none)"))
    else:
        hits = [i["name"] for i in imports if rx.search(i["name"])]
        if hits:
            print("== Imports (%d filtered from %d) ==" % (len(hits), len(imports)))
            print("  " + " ".join(hits))
        else:
            print("== Imports (0 matched) ==")
    print()
    print("== Relocations ==")
    for k, v in sorted(info["relocations"]["counts"].items(), key=lambda kv: -kv[1]):
        print("  %s x%d" % (k, v))


def cmd_info(img, args):
    info = collect_info(img)
    if args.v2o:
        try:
            addr = int(args.v2o, 16)
        except ValueError:
            print("[!] bad --v2o value: %r (want hex, e.g. 0x1930)" % args.v2o)
            return 1
        off = img.va2off(addr)
        print("vaddr=%#x -> file offset=%s"
              % (addr, ("%#x" % off) if off is not None else "not in any PT_LOAD file range"))
        return 0
    rx = compile_grep(args.grep)
    if args.json:
        if rx:
            info["exports"] = [e for e in info["exports"] if rx.search(e["name"])]
            info["imports"] = [i for i in info["imports"] if rx.search(i["name"])]
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0
    print_info_text(info, rx)
    return 0


def cmd_strings(img, args):
    rx = compile_grep(args.grep)
    data = img.data
    n = len(data)
    printed = 0
    i = 0
    while i < n:
        if not (0x20 <= data[i] <= 0x7E):
            i += 1
            continue
        j = i
        while j < n and 0x20 <= data[j] <= 0x7E:
            j += 1
        run = j - i
        if run >= args.min:
            s = data[i:j].decode("ascii")
            if not rx or rx.search(s):
                va = img.off2va(i)
                if va is not None:
                    print("0x%08x  off=0x%08x  len=%d  '%s'" % (va, i, run, s))
                else:
                    print("off=0x%08x  (unmapped)  len=%d  '%s'" % (i, run, s))
                printed += 1
        i = j
    print("total: %d" % printed)
    return 0


def cmd_dump(img, args):
    try:
        addr_s, len_s = args.spec.split(":", 1)
        addr, ln = int(addr_s, 0), int(len_s, 0)
    except ValueError:
        print("[!] bad spec %r (want 0xVADDR:LEN, e.g. 0xf9d3:30)" % args.spec)
        return 1
    if ln <= 0:
        print("[!] non-positive length: %d" % ln)
        return 1

    if args.off:
        off, label = addr, addr
        va = img.off2va(off)
    else:
        va = addr
        off = img.va2off(va)
        label = va
        if off is None:
            print("[-] vaddr %#x not in any PT_LOAD file range (use --off for raw file offset)" % va)
            return 1

    chunk = img.data[off:off + ln]
    if len(chunk) < ln:
        print("[!] short read: %d of %d bytes (EOF at %#x)" % (len(chunk), ln, off + len(chunk)))
    if not chunk:
        return 1
    print("== dump %s (%#x, %d bytes) ==" % ("file offset" if args.off else "vaddr", label, len(chunk)))
    print(hexdump(chunk, label))
    if args.off and va is not None:
        print("[i] offset %#x maps to vaddr %#x" % (off, va))
    return 0


def cmd_disasm(img, args):
    data = img.data
    explicit_size = False
    if args.symbol:
        hit = find_symbol(img, args.symbol)
        if not hit:
            print("[-] symbol not found: %s" % args.symbol)
            return 1
        addr, sym_size = hit
        size = args.size or sym_size or 256
        explicit_size = bool(args.size or sym_size)
    elif args.addr:
        addr = int(args.addr, 0)
        size = args.size or 0
        explicit_size = bool(args.size)
    else:
        print("[-] need --symbol or --addr")
        return 1

    if not size:
        # 窗口自适应：--count N 至少要 N*4 字节
        size = (args.count * 4 + 0x40) if args.count else 0x100

    off = img.va2off(addr)
    if off is None:
        print("[-] vaddr 0x%x not found in any PT_LOAD" % addr)
        return 1

    rx = compile_grep(args.grep)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    scanned = 0
    printed = 0
    last = None
    for ins in md.disasm(data[off:off + size], addr):
        scanned += 1
        last = ins
        line = "0x%04x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str)
        if rx and not rx.search(line):
            continue
        print(line)
        printed += 1
        if args.count and printed >= args.count:
            break
    if scanned == 0:
        print("[-] nothing disassembled (bad offset/size?)")
        return 1
    if rx and printed == 0:
        print("[i] no instruction matched --grep %r (%d scanned)" % (args.grep, scanned))
        return 1
    if last is not None and (last.address + last.size) >= (addr + size):
        if not explicit_size or (args.count and printed < args.count):
            print("[!] truncated at 0x%x (window 0x%x bytes from 0x%x); use --size N for more"
                  % (last.address + last.size, size, addr))
    return 0


def _adr_target(pc, inst):
    imm = (((inst >> 5) & 0x7FFFF) << 2) | ((inst >> 29) & 0x3)
    if imm & (1 << 20):
        imm -= (1 << 21)
    return pc + imm


def _adrp_page(pc, inst):
    imm = (((inst >> 5) & 0x7FFFF) << 2) | ((inst >> 29) & 0x3)
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)


def scan_strrefs(img, targets):
    """反查字符串引用：adr / adrp+add / adrp+ldr（仅可执行段，命中给 vaddr + 类型）。"""
    tset = set(targets)
    hits = {t: [] for t in targets}
    words = img.word_map()
    for pc, inst in words.items():
        if (inst & 0x9F000000) == 0x10000000:  # ADR
            tgt = _adr_target(pc, inst)
            if tgt in tset:
                hits[tgt].append((pc, "adr"))
            continue
        if (inst & 0x9F000000) != 0x90000000:  # ADRP
            continue
        rd = inst & 0x1F
        page = _adrp_page(pc, inst)
        for j in range(pc + 4, pc + 28, 4):
            n2 = words.get(j)
            if n2 is None:
                break
            if (n2 & 0xFF800000) == 0x91000000 and ((n2 >> 5) & 0x1F) == rd:  # ADD imm
                off = ((n2 >> 10) & 0xFFF) << (12 if (n2 >> 22) & 1 else 0)
                if page + off in tset:
                    hits[page + off].append((pc, "adrp+add"))
                break
            if (n2 & 0xFFC00000) == 0xF9400000 and ((n2 >> 5) & 0x1F) == rd:  # LDR imm
                off = ((n2 >> 10) & 0xFFF) << 3
                if page + off in tset:
                    hits[page + off].append((pc, "adrp+ldr"))
                break
    return hits


def cmd_strref(img, args):
    try:
        targets = [int(t, 16) for t in args.targets]
    except ValueError:
        print("[!] bad target (want hex vaddr, e.g. 0xf9d3)")
        return 1
    hits = scan_strrefs(img, targets)
    for t in targets:
        refs = hits.get(t, [])
        body = ", ".join("0x%x (%s)" % (pc, kind) for pc, kind in refs) if refs else "(无)"
        print("串 vaddr 0x%x: 被引用 @ %s" % (t, body))
    if any(not hits.get(t) for t in targets):
        covered = ", ".join("%#x-%#x" % (s["vaddr"], s["vaddr"] + s["filesz"])
                            for s in img.exec_loads())
        print('[i] covered: adr / adrp+add / adrp+ldr in X segments (%s); '
              '可用 so.py disasm <so> --grep "adr|adrp" 复核' % covered)
    return 0


def cmd_callers(img, args):
    try:
        target = int(args.target, 16)
    except ValueError:
        print("[!] bad target (want hex vaddr, e.g. 0x10e0)")
        return 1
    callers = []
    for pc, inst in img.iter_words():
        tgt = None
        kind = None
        if (inst & 0xFC000000) == 0x94000000:  # BL
            imm = inst & 0x3FFFFFF
            if imm & (1 << 25):
                imm -= (1 << 26)
            tgt = pc + imm * 4
            kind = "bl"
        elif not args.bl_only and (inst & 0xFC000000) == 0x14000000:  # B
            imm = inst & 0x3FFFFFF
            if imm & (1 << 25):
                imm -= (1 << 26)
            tgt = pc + imm * 4
            kind = "b"
        elif not args.bl_only and (inst & 0xFF000010) == 0x54000000:  # B.cond
            imm = (inst >> 5) & 0x7FFFF
            if imm & (1 << 18):
                imm -= (1 << 19)
            tgt = pc + imm * 4
            kind = "b.cond"
        elif not args.bl_only and (inst & 0x7E000000) == 0x34000000:  # CBZ/CBNZ
            imm = (inst >> 5) & 0x7FFFF
            if imm & (1 << 18):
                imm -= (1 << 19)
            tgt = pc + imm * 4
            kind = "cbz/cbnz"
        elif not args.bl_only and (inst & 0x7E000000) == 0x36000000:  # TBZ/TBNZ
            imm = (inst >> 5) & 0x3FFF
            if imm & (1 << 13):
                imm -= (1 << 14)
            tgt = pc + imm * 4
            kind = "tbz/tbnz"
        if tgt == target:
            callers.append((pc, kind))
    print("目标 0x%x 被 %d 处跳转引用:" % (target, len(callers)))
    for a, k in callers:
        print("  %-9s @ 0x%x" % (k, a))
    return 0


def _movz_x8_nr(inst):
    """movz x8, #imm16 : 0xD2800008 | (imm16<<5)"""
    if inst is not None and (inst & 0xFFE0001F) == 0xD2800008:
        return (inst >> 5) & 0xFFFF
    return None


def cmd_svc(img, args):
    words = img.word_map()
    found = []
    for pc in sorted(words):
        if (words[pc] & 0xFFE0001F) != 0xD4000001:  # SVC #imm16
            continue
        nr = None
        for back in range(1, 8):  # 往前找 movz x8, #nr
            prev = words.get(pc - back * 4)
            if prev is None:
                break
            m = _movz_x8_nr(prev)
            if m is not None:
                nr = m
                break
        nm = SVC_NAMES.get(nr, "?") if nr is not None else "NOT-FOUND"
        print("  svc @0x%x  nr=%s (%s)" % (pc, nr, nm))
        found.append((pc, nr, nm))

    print()
    print("[+] %s: 共 %d 条 svc 指令" % (img.path, len(found)))

    kill = [f for f in found if f[1] in (93, 94, 129, 130, 131)]
    if kill:
        print()
        print("[!] 发现 %d 条 kill/exit 相关 SVC（exit_blocker 无法拦截这些）:" % len(kill))
        for pc, nr, nm in kill:
            print("    0x%x  nr=%s (%s)" % (pc, nr, nm))
    return 0


def norm_reg(reg):
    return re.sub(r"^w(\d+)$", r"x\1", reg)


def analyze_jni(insns):
    """跟踪寄存器来源，返回 JNI 调用点列表。"""
    regs = {"x0": "env"}
    for i in range(1, 8):
        regs["x%d" % i] = "arg%d" % i
    pending = {}
    calls = []

    def clobber(reg, prov=None):
        pending.pop(reg, None)
        regs[reg] = prov

    for ins in insns:
        m, ops = ins.mnemonic, ins.op_str
        if m == "mov":
            parts = [t.strip() for t in ops.split(",")]
            if len(parts) == 2:
                rd, rs = norm_reg(parts[0]), norm_reg(parts[1])
                clobber(rd, None if rs == "xzr" else regs.get(rs))
                if rs in pending:
                    pending[rd] = pending[rs]
            continue
        if m in ("movz", "movn", "movk", "adr", "adrp", "add", "sub", "and", "orr",
                 "lsl", "lsr", "ubfx", "sxtw", "uxtw", "csel"):
            r = re.match(r"(x\d+|w\d+)", ops)
            if r:
                clobber(norm_reg(r.group(1)))
            continue
        if m == "ldr":
            mt = re.match(r"(x\d+), \[(x\d+)(?:, #(0x[0-9a-fA-F]+|\d+))?\]", ops)
            if mt:
                rd, rb = mt.group(1), mt.group(2)
                imm = int(mt.group(3), 0) if mt.group(3) else 0
                bprov = regs.get(rb)
                if bprov == "vtable" and imm in JNI_OFFSETS:
                    clobber(rd)
                    pending[rd] = (JNI_OFFSETS[imm], imm)
                elif bprov == "env" and imm == 0:
                    clobber(rd, "vtable")
                else:
                    clobber(rd)
            else:
                r = re.match(r"(x\d+|w\d+)", ops)
                if r:
                    clobber(norm_reg(r.group(1)))
            continue
        if m in ("ldp", "ldur", "ldurb", "ldurh", "ldrb", "ldrh", "ldrsb", "ldrsh",
                 "ldrsw", "ldxr", "ldar", "ldxrb", "ldaxr"):
            r = re.match(r"(x\d+|w\d+)", ops)
            if r:
                clobber(norm_reg(r.group(1)))
            continue
        if m == "blr":
            r = ops.strip()
            info = pending.pop(r, None)
            if info:
                calls.append(dict(name=info[0], offset=info[1], pc=ins.address,
                                  x1=regs.get("x1"), x2=regs.get("x2")))
            for k in list(regs):
                if k not in CALLEE_SAVED:
                    clobber(k)
            continue
        if m == "bl":
            for k in list(regs):
                if k not in CALLEE_SAVED:
                    clobber(k)
            continue
    return calls


def infer_jni(calls):
    """由 JNI 调用点推断 Java 第 1 个参数（JNI 第 3 参）类型。

    "array"（仅 GetArrayLength 等泛化信号）作为兜底；出现具体类型时丢弃兜底。
    """
    found = {}
    for c in calls:
        t = ARG_TYPES.get(c["name"])
        if not t:
            continue
        ptype, pos = t
        if pos != 1 or c["x1"] != "arg2":
            continue
        if ptype == "array":
            if not found:
                found["array"] = c
            continue
        found.pop("array", None)
        found.setdefault(ptype, c)
    return found


def cmd_jni(img, args):
    if args.symbol:
        hit = find_symbol(img, args.symbol)
        if not hit:
            print("[-] symbol not found: %s" % args.symbol)
            return 1
        addr, size = hit
        size = args.size or size or 0x400
        label = args.symbol
    elif args.addr:
        addr = int(args.addr, 0)
        size = args.size or 0x400
        label = "0x%x" % addr
    else:
        print("[-] need --symbol or --addr")
        return 1

    off = img.va2off(addr)
    if off is None:
        print("[-] vaddr 0x%x not found in any PT_LOAD" % addr)
        return 1

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(img.data[off:off + size], addr))
    calls = analyze_jni(insns)

    print("== JNI probe: %s (0x%x, %d bytes, %d insns) ==" % (label, addr, size, len(insns)))
    if not calls:
        print("[-] no JNI call sites found (no JNI API used / env path not tracked / not a JNI export)")
        return 1
    for c in calls:
        print("  0x%04x  %-24s x1=%-6s x2=%s" % (c["pc"], c["name"], c["x1"], c["x2"]))

    found = infer_jni(calls)
    if found:
        print("[+] Java arg#1 (JNI args[2]) type inference:")
        for ptype, c in sorted(found.items()):
            print("    %-14s <- %s @0x%x (x1=arg2)" % (ptype, c["name"], c["pc"]))
    else:
        print("[i] cannot attribute call sites to x1=arg2 (arg may travel via other regs/paths)")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="so.py",
        description="SO 静态分析工具箱（ARM64）：ELF 侦察 / 字符串 / 字节 / 反汇编 / 交叉引用 / SVC / JNI 判型")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="ELF 侦察（段/节/依赖/导出/导入/重定位/vaddr-offset 换算）")
    p.add_argument("path")
    p.add_argument("--json", action="store_true", help="结构化 JSON 输出（12 键同旧 elfinfo）")
    p.add_argument("--grep", default="", metavar="PAT",
                   help="过滤 Exports/Imports（忽略大小写；命中解除 60 条上限）")
    p.add_argument("--v2o", metavar="0xADDR", help="vaddr 换算为文件偏移")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("strings", help="字符串枚举（可打印 ASCII run）")
    p.add_argument("path")
    p.add_argument("--min", type=int, default=6, help="最小 run 长度（默认 6）")
    p.add_argument("--grep", default="", metavar="PAT", help="过滤字符串（忽略大小写）")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("dump", help="按虚址/文件偏移读字节（hex+ascii）")
    p.add_argument("path")
    p.add_argument("spec", help="0xVADDR:LEN（LEN 支持 0x/十进制）")
    p.add_argument("--off", action="store_true", help="把 spec 地址解释为文件偏移")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("disasm", help="快速反汇编（capstone）")
    p.add_argument("path")
    p.add_argument("--symbol", help="符号名（dynsym/symtab）")
    p.add_argument("--addr", help="起始 vaddr，如 0x10e0")
    p.add_argument("--size", type=lambda v: int(v, 0), default=0, help="字节窗口")
    p.add_argument("--count", type=int, default=0, help="最多打印指令数（自动放宽窗口）")
    p.add_argument("--grep", default="", help="只打印匹配该正则的行（忽略大小写）")
    p.set_defaults(func=cmd_disasm)

    p = sub.add_parser("strref", help="反查字符串引用（adr / adrp+add / adrp+ldr）")
    p.add_argument("path")
    p.add_argument("targets", nargs="+", help="字符串 vaddr（hex，可多个）")
    p.set_defaults(func=cmd_strref)

    p = sub.add_parser("callers", help="反查跳转/调用者（BL/B/B.cond/CBZ/TBZ）")
    p.add_argument("path")
    p.add_argument("target", help="目标 vaddr（hex）")
    p.add_argument("--bl-only", action="store_true", help="只看 BL")
    p.set_defaults(func=cmd_callers)

    p = sub.add_parser("svc", help="内联 SVC 扫描 + syscall 号（向前回扫 movz x8）")
    p.add_argument("path")
    p.set_defaults(func=cmd_svc)

    p = sub.add_parser("jni", help="JNI 调用点 + Java 第 1 参类型推断")
    p.add_argument("path")
    p.add_argument("--symbol", help="符号名（dynsym/symtab）")
    p.add_argument("--addr", help="起始 vaddr，如 0x33a4")
    p.add_argument("--size", type=lambda v: int(v, 0), default=0, help="字节窗口")
    p.set_defaults(func=cmd_jni)

    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        img = SOImage(args.path)
    except SOError as e:
        print("[!] %s" % e)
        return 1
    if img.machine != "EM_AARCH64":
        print("[!] unsupported machine: %s (so.py supports ARM64 only)" % img.machine)
        return 1
    try:
        return args.func(img, args)
    except SOError as e:
        print("[!] %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
