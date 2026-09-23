#!/usr/bin/env python3
"""jni_sig.py — JNI 导出函数签名侦察（静态，无需设备）

用途：hook 一个 `Java_*` 导出前，先确认它的 Java 参数类型（第 3 参是
jstring 还是 jbyteArray……）。用错读取 API（如把 byte[] 当 jstring 读）
会把进程打崩在注入 agent 里（tombstone pc 落在 memfd），极易误判为反调试。

原理：反汇编函数体，跟踪 JNIEnv* 寄存器别名（x0=env，mov 传播），
识别 `ldr xR,[xM,#imm]`（xM 出自 env vtable）→ `blr xR` 调用点，
用 arm64 JNIEnv vtable offset 表（offset = index*8）解析被调 JNI API；
再由调用参数来源（x1 是否来自 x2=Java 第 1 参）推断“第 3 参”类型。

用法:
  python3 jni_sig.py libfoo.so --symbol Java_sg_vantagepoint_uncrackable3_CodeCheck_bar
  python3 jni_sig.py libfoo.so --addr 0x33a4 --size 0x100
"""
import argparse
import io
import re
import sys

import capstone
from elftools.elf.elffile import ELFFile

from disasm import ARCHES, find_symbol, vaddr_to_offset

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


def norm(reg):
    return re.sub(r"^w(\d+)$", r"x\1", reg)


def analyze(insns):
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
                rd, rs = norm(parts[0]), norm(parts[1])
                clobber(rd, None if rs == "xzr" else regs.get(rs))
                if rs in pending:
                    pending[rd] = pending[rs]
            continue
        if m in ("movz", "movn", "movk", "adr", "adrp", "add", "sub", "and", "orr",
                 "lsl", "lsr", "ubfx", "sxtw", "uxtw", "csel"):
            r = re.match(r"(x\d+|w\d+)", ops)
            if r:
                clobber(norm(r.group(1)))
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
                    clobber(norm(r.group(1)))
            continue
        if m in ("ldp", "ldur", "ldurb", "ldurh", "ldrb", "ldrh", "ldrsb", "ldrsh",
                 "ldrsw", "ldxr", "ldar", "ldxrb", "ldaxr"):
            r = re.match(r"(x\d+|w\d+)", ops)
            if r:
                clobber(norm(r.group(1)))
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


def infer(calls):
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--symbol", help="symbol name (dynsym/symtab)")
    ap.add_argument("--addr", help="start vaddr, e.g. 0x33a4")
    ap.add_argument("--size", type=lambda v: int(v, 0), default=0, help="byte count from --addr")
    args = ap.parse_args()

    data = open(args.path, "rb").read()
    elf = ELFFile(io.BytesIO(data))
    machine = elf.header.e_machine
    if machine not in ARCHES:
        print("[-] unsupported machine: %s" % machine)
        return 1
    cs_arch, cs_mode = ARCHES[machine]

    if args.symbol:
        hit = find_symbol(elf, args.symbol)
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

    off = vaddr_to_offset(elf, addr)
    if off is None:
        print("[-] vaddr 0x%x not found in any PT_LOAD" % addr)
        return 1

    md = capstone.Cs(cs_arch, cs_mode)
    insns = list(md.disasm(data[off:off + size], addr))
    calls = analyze(insns)

    print("== JNI probe: %s (0x%x, %d bytes, %d insns) ==" % (label, addr, size, len(insns)))
    if not calls:
        print("[-] no JNI call sites found (no JNI API used / env path not tracked / not a JNI export)")
        return 1
    for c in calls:
        print("  0x%04x  %-24s x1=%-6s x2=%s" % (c["pc"], c["name"], c["x1"], c["x2"]))

    found = infer(calls)
    if found:
        print("[+] Java arg#1 (JNI args[2]) type inference:")
        for ptype, c in sorted(found.items()):
            print("    %-14s <- %s @0x%x (x1=arg2)" % (ptype, c["name"], c["pc"]))
    else:
        print("[i] cannot attribute call sites to x1=arg2 (arg may travel via other regs/paths)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
