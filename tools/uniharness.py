#!/usr/bin/env python3
# uniharness.py — Unicorn arm64 模拟执行样板库
#
# 用途: 写 SO/代码片段模拟 harness 时复用样板：映射/栈/TLS/桩/JNI 表/调用/追踪/崩溃诊断。
#       方法论见 rev-unicorn-debug SKILL.md；SO 侦察（raw 映射判定/依赖/重定位）用 so.py info。
# 用法:
#   from uniharness import Harness, asm, JNI_SLOTS
#   h = Harness(trace=False)
#   h.map_raw("lib.so", 0, 0x10000)             # vaddr==file offset 时直接 raw 映射
#   # 或 h.map_elf("lib.so")                    # vaddr != file offset 时按 PT_LOAD 映射
#   h.setup_stack(); h.setup_tls()
#   env = h.jni_env(slots={JNI_SLOTS["NewByteArray"]: my_cb})   # 伪造 JNIEnv
#   r = h.call(0x196C, args=[env, 0])            # 调用到 ret；r.x0 / r.insns
#
# hook 回调签名: def cb(uc, addr, size, user)  （与 unicorn hook_add 一致）
# 依赖: pip install unicorn capstone keystone-engine（capstone/keystone 缺失时相应功能降级）
import struct

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UcError
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0,
)

RET_AARCH64 = b"\xc0\x03\x5f\xd6"
ARG_REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7)

# JNIEnv 函数表常用槽位（索引 = jni.h 声明序，表内偏移 = 索引 × 8）
JNI_SLOTS = {
    "FindClass": 6, "GetMethodID": 33, "GetFieldID": 94,
    "NewString": 163, "GetStringLength": 164,
    "NewStringUTF": 167, "GetStringUTFLength": 168,
    "GetStringUTFChars": 169, "ReleaseStringUTFChars": 170,
    "GetArrayLength": 171,
    "NewByteArray": 176, "GetByteArrayElements": 184, "ReleaseByteArrayElements": 192,
    "GetByteArrayRegion": 200, "SetByteArrayRegion": 208,
    "RegisterNatives": 215, "GetJavaVM": 219,
}


def asm(src, addr=0):
    """汇编 arm64 指令文本 → 机器码（需 keystone-engine）。"""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    code, _ = ks.asm(src, addr)
    return bytes(code)


class RunResult:
    __slots__ = ("x0", "insns")

    def __init__(self, x0, insns):
        self.x0 = x0
        self.insns = insns

    def __repr__(self):
        return "RunResult(x0=%#x, insns=%d)" % (self.x0, self.insns)


class Harness:
    """Unicorn arm64 harness。scratch arena 默认 0x10000000，按需自动扩页。"""

    def __init__(self, trace=False, arena=0x10000000):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        self.trace = trace
        self._arena = arena
        self._arena_mapped = arena
        self._arena_end = arena
        self._stop = None
        self._insns = 0
        self._md = None
        try:
            import capstone
            self._md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        except ImportError:
            pass

    # ---------- 映射 ----------
    def map(self, base, size):
        self.uc.mem_map(base, size)
        return base

    def map_raw(self, path, base=0, size=None):
        """raw 映射：文件字节按 [base, base+size) 直接铺开（要求 vaddr==file offset）。"""
        with open(path, "rb") as f:
            data = f.read() if size is None else f.read(size)
        self.uc.mem_map(base, (len(data) + 0xFFF) & ~0xFFF)
        self.uc.mem_write(base, data)
        return base

    def map_elf(self, path):
        """按 PT_LOAD 段映射（vaddr != file offset 时用；需 pyelftools）。返回段列表。"""
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as f:
            elf = ELFFile(f)
            segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"], s["p_memsz"])
                    for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
            spans = sorted([v & ~0xFFF, (v + m + 0xFFF) & ~0xFFF] for v, o, fs, m in segs)
            merged = []
            for s, e in spans:
                if merged and s <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], e)
                else:
                    merged.append([s, e])
            for s, e in merged:
                self.uc.mem_map(s, e - s)
            for v, o, fs, m in segs:
                f.seek(o)
                self.uc.mem_write(v, f.read(fs))
        return segs

    # ---------- arena / 运行环境 ----------
    def alloc(self, size, align=0x10):
        addr = (self._arena_end + align - 1) & ~(align - 1)
        need = addr + size
        if need > self._arena_mapped:
            new_end = (need + 0xFFF) & ~0xFFF
            self.uc.mem_map(self._arena_mapped, new_end - self._arena_mapped)
            self._arena_mapped = new_end
        self._arena_end = need
        return addr

    def setup_stack(self, size=0x10000):
        base = self.alloc(size)
        self.uc.reg_write(UC_ARM64_REG_SP, base + size - 0x1000)
        return base

    def setup_tls(self, canary=0x4141414142424242):
        """映射 TLS 页并设置 TPIDR_EL0；canary 写在 TLS+40（栈保护读的就是这里）。"""
        base = self.alloc(0x1000)
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, base)
        if canary is not None:
            self.uc.mem_write(base + 40, struct.pack("<Q", canary))
        return base

    # ---------- 桩 / hook ----------
    def hook(self, begin, end, callback):
        """注册代码 hook。注意：unicorn 的 hook 范围是闭区间 [begin, end]（end 包含在内）。"""
        return self.uc.hook_add(UC_HOOK_CODE, callback, begin=begin, end=end)

    def stub(self, callback=None, code=None):
        """写一段桩代码（默认 ret）；callback 非空时挂到桩入口。返回桩地址。"""
        code = RET_AARCH64 if code is None else code
        addr = self.alloc(len(code), align=4)
        self.uc.mem_write(addr, code)
        if callback is not None:
            self.hook(addr, addr + len(code) - 1, callback)  # 闭区间，勿越界到相邻桩
        return addr

    def jni_env(self, slots, env_addr=None):
        """伪造 JNIEnv：env[0]→函数表，各槽位→ret 桩+回调。slots={槽位索引: 回调}。返回 env 指针。"""
        if env_addr is None:
            env_addr = self.alloc(8)
        table = self.alloc((max(slots) + 1) * 8 if slots else 8)
        self.uc.mem_write(env_addr, struct.pack("<Q", table))
        for idx, cb in slots.items():
            self.uc.mem_write(table + idx * 8, struct.pack("<Q", self.stub(cb)))
        return env_addr

    # ---------- 内存 ----------
    def write(self, addr, data):
        self.uc.mem_write(addr, data)

    def read(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def read_cstr(self, addr, limit=4096):
        return self.read(addr, limit).split(b"\x00", 1)[0].decode("utf-8", "replace")

    def set_args(self, *args):
        for reg, val in zip(ARG_REGS, args):
            self.uc.reg_write(reg, val)

    # ---------- 运行 ----------
    def _stop_addr(self):
        if self._stop is None:
            self._stop = self.alloc(0x1000) + 0x800
        return self._stop

    def call(self, addr, args=(), timeout=0, trace=None, count=True):
        """调用函数（AAPCS64），ret 后返回。返回 RunResult(x0, insns)。"""
        self.set_args(*args)
        self.uc.reg_write(UC_ARM64_REG_LR, self._stop_addr())
        self._insns = 0
        hooks = []
        if count:
            hooks.append(self.uc.hook_add(UC_HOOK_CODE, self._count_hook))
        do_trace = self.trace if trace is None else trace
        if do_trace:
            hooks.append(self.uc.hook_add(UC_HOOK_CODE, self._trace_hook))
        try:
            self.uc.emu_start(addr, self._stop_addr(), timeout=timeout)
        except UcError as e:
            self.fault(e)
            raise
        finally:
            for h in hooks:
                self.uc.hook_del(h)
        return RunResult(self.uc.reg_read(UC_ARM64_REG_X0), self._insns)

    def run(self, begin, until=None, timeout=0, count=True):
        """执行任意代码片段 [begin, until)。until 默认用与 call 相同的停机地址。"""
        self._insns = 0
        hooks = []
        if count:
            hooks.append(self.uc.hook_add(UC_HOOK_CODE, self._count_hook))
        try:
            self.uc.emu_start(begin, self._stop_addr() if until is None else until, timeout=timeout)
        except UcError as e:
            self.fault(e)
            raise
        finally:
            for h in hooks:
                self.uc.hook_del(h)
        return self._insns

    # ---------- 诊断 / 追踪 ----------
    def fault(self, e=None):
        """打印崩溃现场（pc/关键寄存器），返回描述字符串（同一现场只打印一次）。"""
        vals = [self.uc.reg_read(r) for r in (UC_ARM64_REG_PC, UC_ARM64_REG_X0,
                                              UC_ARM64_REG_X1, UC_ARM64_REG_SP, UC_ARM64_REG_LR)]
        msg = "[fault] %s | pc=%#x x0=%#x x1=%#x sp=%#x lr=%#x" % (
            e, vals[0], vals[1], vals[2], vals[3], vals[4])
        if msg != getattr(self, "_last_fault_msg", None):
            print(msg)
        self._last_fault_msg = msg
        return msg

    def _count_hook(self, uc, addr, size, user):
        self._insns += 1

    def _trace_hook(self, uc, addr, size, user):
        code = bytes(uc.mem_read(addr, size))
        text = code.hex()
        if self._md is not None:
            insn = next(self._md.disasm(code, addr), None)
            if insn is not None:
                text = "%s %s" % (insn.mnemonic, insn.op_str)
        print("  %#07x: %s" % (addr, text))


if __name__ == "__main__":
    h = Harness()
    try:
        code = asm("mov x0, #0x41\nret")
    except ImportError:
        code = bytes.fromhex("200880d2c0035fd6")  # movz x0, #0x41 ; ret
    addr = h.alloc(0x100)
    h.write(addr, code)
    r = h.call(addr)
    assert r.x0 == 0x41, r
    print("uniharness self-test OK (x0=%#x, insns=%d)" % (r.x0, r.insns))
