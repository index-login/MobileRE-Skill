#!/usr/bin/env python3
"""emu_setup — emu_run 的通用 setup 助手库（复杂函数模拟脚手架）。

给 `emu_run --setup hooks.py` 的 `setup(h)` 复用，避免每个目标重写样板；
也可被任意脚本 `import emu_setup as E`。

典型用法:
    import emu_setup as E
    def setup(h):
        s = E.std_string(h, b"aGVoZWhlX3llc190aGlzX2lzX2l0")   # 造 libc++ std::string
        print(E.call_sret(h, 0x22168, [s]))                     # 调 sret 返回 std::string 的函数
        E.install_stub(h, 0x4F6A8, my_memmove)                  # 覆盖某 GOT 槽的桩

libc++ 布局约定:
    std::string  短: [0]=size<<1, data 从 [1]（<=22B）
                 长: [0]=(cap<<1)|1, [8]=size, [16]=data ptr
    std::vector  [0]=begin, [8]=end, [16]=cap
"""
import struct

from unicorn.arm64_const import UC_ARM64_REG_X8, UC_ARM64_REG_SP

SHORT_MAX = 22


def std_string(h, data, addr=None):
    """构造 libc++ std::string，返回对象地址（addr 非空则写入该处）。"""
    if isinstance(data, str):
        data = data.encode()
    obj = addr if addr is not None else h.alloc(24 if len(data) <= SHORT_MAX else 32, align=8)
    if len(data) <= SHORT_MAX:
        buf = bytearray(24)
        buf[0] = (len(data) << 1) & 0xFF
        buf[1:1 + len(data)] = data
        h.write(obj, bytes(buf))
    else:
        ptr = h.alloc(len(data) + 1, align=8)
        h.write(ptr, data + b"\x00")
        h.write(obj, struct.pack("<QQQ", (len(data) << 1) | 1, len(data), ptr))
    return obj


def read_std_string(h, obj):
    b0 = h.read(obj, 1)[0]
    if b0 & 1:
        size = struct.unpack("<Q", h.read(obj + 8, 8))[0]
        ptr = struct.unpack("<Q", h.read(obj + 16, 8))[0]
        return h.read(ptr, size)
    return h.read(obj + 1, b0 >> 1)


def std_vector(h, data):
    """构造 libc++ std::vector<char>，返回对象地址。"""
    if isinstance(data, str):
        data = data.encode()
    buf = h.alloc(max(1, len(data)), align=8)
    h.write(buf, data)
    obj = h.alloc(24, align=8)
    h.write(obj, struct.pack("<QQQ", buf, buf + len(data), buf + len(data)))
    return obj


def read_std_vector(h, obj):
    b, e, _ = struct.unpack("<QQQ", h.read(obj, 24))
    return h.read(b, e - b)


def cstr(h, s):
    """分配一个 C 字符串，返回地址。"""
    if isinstance(s, str):
        s = s.encode()
    p = h.alloc(len(s) + 1, align=8)
    h.write(p, s + b"\x00")
    return p


def call_sret(h, fn, args=(), ret="string"):
    """调用经 sret(x8) 返回的 C++ 函数。

    ret: "string" | "vector" | "raw"（返回 sret 缓冲地址）。
    """
    sret = h.alloc(32, align=8)
    h.uc.reg_write(UC_ARM64_REG_X8, sret)
    h.call(fn, args=list(args))
    if ret == "string":
        return read_std_string(h, sret)
    if ret == "vector":
        return read_std_vector(h, sret)
    return sret


def install_stub(h, got, impl):
    """在 GOT 槽装一个"干净桩"并挂 impl（避开 apply_relocations 已挂的 _ret0）。"""
    fresh = h.stub()
    h.hook(fresh, fresh + 3, impl)
    h.write(got, struct.pack("<Q", fresh))
    return fresh


def patch_data_import(h, got, data_addr):
    """把数据导入的 GOT 槽指向 data_addr。"""
    h.write(got, struct.pack("<Q", data_addr))


def ctype_table(h):
    """造 ctype 表（[c+1] 含 flags，bits0-2 = alnum），返回表地址。"""
    tbl = h.alloc(258, align=8)
    buf = bytearray(258)
    for c in range(256):
        f = 0
        if 0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A:
            f |= 7
        if c == 0x20 or 0x09 <= c <= 0x0D:
            f |= 8
        if c < 0x20 or c == 0x7F:
            f |= 0x20
        buf[c + 1] = f
    h.write(tbl, bytes(buf))
    return tbl


def argv_stack(h, argv):
    """在栈上摆 argv（argc 放 x0 前需自行设置），返回指向 argv[] 的地址。"""
    ptrs = [cstr(h, a) for a in argv]
    arr = h.alloc((len(ptrs) + 1) * 8, align=8)
    h.write(arr, b"".join(struct.pack("<Q", p) for p in ptrs) + b"\x00" * 8)
    return arr
