#!/usr/bin/env python3
"""vmp.py — 字节码 VM / VMP 壳逆向统一入口。

设计
----
VM 逆向的难点不在"写代码"，而在**编码模型是每个壳独有的**。所以本工具把
「模型」与「引擎」分离：

    vmp_profiles/<name>.json   ← 通用模板（tools/ 下）
    <包名>/tools/vm_profiles/<name>.json  ← 样本编码模型（自动发现）
    vmp.py                     ← 引擎（反汇编 / 校验 / 追踪 / 模型查询）

换一个壳 = 换一个 profile，引擎不动。

子命令
------
    disasm  <so> -p <profile> [--trace T --vm KEY] [--start PC --count N]
    verify  <so> -p <profile> [--trace T]
    trace   <so> -p <profile> [--sel N] [--limit N] [--out JSON]
    model   [--model JSON] [--op N] [--delta N] [--stats] [--markdown]
    profile [list|show <name>]

典型流程
--------
    # 1) 先用动态 trace 拿到真实 (pc, opcode) 序列
    python3 tools/vmp.py trace <so> -p <profile> --sel 0 --out trace.json

    # 2) 用 trace 校验解码模型（命中率必须 > 95%）
    python3 tools/vmp.py verify <so> -p <profile> --trace trace.json

    # 3) 反汇编字节码
    python3 tools/vmp.py disasm <so> -p <profile> --trace trace.json --vm VM-A_60384

    # 4) 看 handler 指令模型（需先跑 Ghidra 脚本导出）
    python3 tools/vmp.py model --stats

profile 必填字段
----------------
    name                   profile 名
    key_xor                key 的异或常量（链式差分的常数项）
    decode                 单字节解码参数 {sub_hi, mask_hi, sub_lo, mask_lo}
    opcodes                {opcode_hex: 语义名}
    handler_table_file_va  handler 跳转表文件偏移
    handler_count          表项数
    bytecode_file_va       字节码起始文件偏移

可选（trace 子命令需要）
------------------------
    entry_va               VM 入口（ELF VA）
    dispatch_hook_pc       dispatch 里 `ldr x9,[tbl,x8,lsl#3]` 的前一条指令
    selector_hook_pc       读 selector 参数的指令
    selector_arg_reg       传入 selector 的寄存器（默认 x5）
    frame_pc_off           栈帧里存 pc 的偏移（默认 0x820）
    frame_idx_off          栈帧里存 opcode 索引的偏移（默认 0x82c）
    frame_key_off          栈帧里存 key 的偏移（默认 0x81c）
"""
import argparse
import importlib.util
import json
import os
import struct
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(HERE, "vmp_profiles")

#: 本文件所在目录（tools/），供复用 emu_run / uniharness
sys.path.insert(0, HERE)


# ---------------------------------------------------------------- profile

TEMPLATE_NAME = "_template.json"


def _profile_dirs():
    """profile 搜索目录：tools/vmp_profiles（通用模板）+ 各样本 <pkg>/tools/vm_profiles。

    编码模型是**样本事实**，所以样本的 profile 留在样本目录；tools 下只放模板。
    """
    dirs = [PROFILE_DIR]
    root = os.path.dirname(HERE)
    try:
        for name in sorted(os.listdir(root)):
            sub = os.path.join(root, name, "tools", "vm_profiles")
            if os.path.isdir(sub):
                dirs.append(sub)
    except OSError:
        pass
    return dirs


def find_profile_path(name):
    """按名字找 profile 文件；找不到返回 None。"""
    if os.path.isfile(name):
        return name
    for d in _profile_dirs():
        p = os.path.join(d, name + ".json")
        if os.path.isfile(p):
            return p
    return None


def list_profiles():
    """列出所有可用 profile 名（含样本目录的）。"""
    seen = []
    for d in _profile_dirs():
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith(".json") and not f.startswith("_"):
                n = os.path.splitext(f)[0]
                if n not in seen:
                    seen.append(n)
    return seen


def new_profile(name, force=False):
    """从 _template.json 复制出 <name>.json，返回落盘路径。"""
    src = os.path.join(PROFILE_DIR, TEMPLATE_NAME)
    if not os.path.isfile(src):
        raise SystemExit("缺少模板: %s" % src)
    dst = os.path.join(PROFILE_DIR, name + ".json")
    if os.path.exists(dst) and not force:
        raise SystemExit("已存在: %s（要覆盖加 --force）" % dst)
    with open(src, encoding="utf-8") as f:
        prof = json.load(f)
    prof["name"] = name
    prof["description"] = "TODO 一句话：哪个壳 / 哪个 so / 什么特征"
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(prof, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return dst


def load_profile(name):
    p = find_profile_path(name)
    if not p:
        raise SystemExit("找不到 profile: %s（可用：%s）"
                         % (name, ", ".join(list_profiles()) or "(空)"))
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def decode_byte(prof, x, key):
    """单字节解码：((sub_hi - x) & mask_hi) | ((x - sub_lo) & mask_lo) ^ key。

    profile 只描述掩码与减数，公式本身固定 —— 这是从多个 VM 壳归纳出的
    「减法 + 掩码拼位」通用形式，换壳只需改 4 个数字。
    """
    d = prof["decode"]
    v = (d["sub_hi"] - x) & d["mask_hi"]
    v |= (x - d["sub_lo"]) & d["mask_lo"]
    return v ^ key


def opcode_names(prof):
    return {int(k, 16): v for k, v in prof.get("opcodes", {}).items()}


def handler_table(so_data, prof):
    """返回 {opcode_index: handler_va}。"""
    va = int(prof["handler_table_file_va"], 16)
    n = int(prof.get("handler_count", 256))
    vals = struct.unpack_from("<%dQ" % n, so_data, va)
    return {i: v for i, v in enumerate(vals)}


# ---------------------------------------------------------------- verify

def cmd_verify(args):
    """用动态 trace 的 (pc, opcode) 序列校验链式解码模型。

    判据：相邻两条指令之间必须满足
        op_next == decode(byte[next_pc-1], op_cur ^ key_xor)
    命中率 > 95% 才算模型可用；低于此值说明公式或 profile 错了。
    """
    prof = load_profile(args.profile)
    with open(args.so, "rb") as f:
        data = f.read()
    with open(args.trace, encoding="utf-8") as f:
        traces = json.load(f)

    kx = int(prof.get("key_xor", 0x5F))
    total = ok = forced = 0
    fails = []
    for vm_name, rows in traces.items():
        for i in range(len(rows) - 1):
            pc, op = rows[i][0], rows[i][1]
            npc, nxt = rows[i + 1][0], rows[i + 1][1]
            L = npc - pc
            if L <= 0 or L > 4096:
                continue                      # 跨函数跳转，不是顺序转移
            total += 1
            pred = decode_byte(prof, data[npc - 1], op ^ kx) & 0xFF
            if pred == nxt:
                ok += 1
                continue
            # 部分壳存在"强制 key"分支：条件满足时 key 被固定
            fk = prof.get("forced_key")
            if fk:
                pred2 = decode_byte(prof, data[npc - 1], int(fk["value"], 16)) & 0xFF
                if pred2 == nxt:
                    forced += 1
                    ok += 1
                    continue
            fails.append((vm_name, pc, op, npc, nxt, pred))

    print("=== 链式解码校验 (%s) ===" % os.path.basename(args.trace))
    print("  转移总数     : %d" % total)
    print("  链式命中     : %d  (%.1f%%)" % (ok - forced, (ok - forced) / max(total, 1) * 100))
    if forced:
        print("  强制 key 命中: %d  (%.1f%%)" % (forced, forced / max(total, 1) * 100))
    rate = ok / max(total, 1) * 100
    print("  合计         : %d/%d = %.2f%%" % (ok, total, rate))
    if fails:
        print("  未命中       : %d" % len(fails))
        for f in fails[:10]:
            print("    %-14s pc=%#x op=%#04x -> pc=%#x op=%#04x (pred %#04x)"
                  % f)
    print()
    print("判据：> 95% 可用；低于此值检查 profile 的 decode / key_xor")
    return 0 if rate >= 95 else 1


# ---------------------------------------------------------------- disasm

#: 操作数布局的**内置默认值**（仅适用于某个已解出的壳）。
#: 换壳必须用 profile 的 `operand_layout` 覆盖 —— 否则 disasm 的 operand 列会
#: 系统性错，而 verify 仍然通过（它只校验 opcode 链），表现为"长度对、语义错"。
_DEFAULT_OPERAND_LAYOUT = {
    "none":  [*range(0x00, 0x2C), *range(0x34, 0x36), *range(0x42, 0x4C),
              0x53, 0x56, *range(0x57, 0x85)],
    "u16x4": [0x30, 0x31, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
              0x3E, 0x3F, 0x40, 0x41, 0x4C, 0x52],
    "u16":   [0x4E, 0x4F, 0x50, 0x51, 0x54, 0x55],
    "u8":    [0x4D, 0x85, 0x86],
    "u32":   [0x32, 0x87],
    "u64":   [0x33, 0x88, 0x89],
    "idx8":  [0x8B, 0x8D, 0xBD, 0xBF, 0xC2, 0xCF, 0xF8],
}

#: kind -> 字节宽度（解码用）
_KIND_WIDTH = {"u64": 8, "u32": 4, "u8": 1, "idx8": 1, "u16x4": 2, "u16": 2}


def operand_layout(prof):
    """从 profile 取操作数布局；没配就用内置默认值并告警。

    返回 {kind: set(opcodes)}。profile 里写 {"operand_layout": {"u16x4": [..]}}，
    只写与默认值不同的项即可（其余沿用默认）。
    """
    layout = {k: set(v) for k, v in _DEFAULT_OPERAND_LAYOUT.items()}
    custom = (prof or {}).get("operand_layout") or {}
    if custom:
        for kind, ops in custom.items():
            layout[kind] = {int(o, 16) if isinstance(o, str) else o for o in ops}
    return layout


def decode_operand(op, body, layout=None):
    """返回 (kind, value, note)。body 不含尾部 delta 字节。

    layout 由 profile 提供；不给就用内置默认（只对某个已解出的壳成立）。
    """
    lay = layout or {k: set(v) for k, v in _DEFAULT_OPERAND_LAYOUT.items()}
    if not body:
        return ("none", None, "")
    for kind in ("u64", "u32", "u8", "u16x4", "u16", "idx8"):
        if op not in lay.get(kind, ()):
            continue
        w = _KIND_WIDTH[kind]
        if len(body) < w:
            continue
        v = int.from_bytes(body[:w], "little")
        if kind == "u64":
            return ("imm64", v, "%#x" % v)
        if kind == "u32":
            return ("imm32", v, "%#x" % v)
        if kind == "u8":
            return ("imm8", v, "%#x" % v)
        if kind == "u16x4":
            return ("u16x4", v, "frame+%#x" % (v * 4))
        if kind == "u16":
            return ("u16", v, "%#x" % v)
        if kind == "idx8":
            return ("idx8", v, "idx=%d" % v)
    if len(body) >= 2:
        v = int.from_bytes(body[:2], "little")
        return ("raw16", v, body.hex(" "))
    return ("raw", body[0], body.hex(" "))


def _rows_from_trace(trace, vm_key):
    """从 trace JSON 取某个 VM 的 [(pc, op), ...]。"""
    if vm_key in trace:
        return trace[vm_key]
    cand = [k for k in trace if k.startswith(vm_key)]
    if cand:
        return trace[cand[0]]
    return []


def disasm_from_trace(prof, data, rows, limit=0):
    names = opcode_names(prof)
    handlers = handler_table(data, prof)
    layout = operand_layout(prof)
    out = []
    for i, pair in enumerate(rows):
        pc, op = pair[0], pair[1]
        nxt = rows[i + 1][0] if i + 1 < len(rows) else pc + 3
        L = nxt - pc
        if L <= 0 or L > 4096:
            L = 3
        raw = data[pc:pc + L]
        body = raw[:-1] if L >= 2 else b""
        kind, val, note = decode_operand(op, body, layout)
        out.append({
            "idx": i, "pc": pc, "op": op,
            "name": names.get(op, "?"), "len": L,
            "handler": handlers.get(op),
            "raw": raw.hex(" "),
            "opnd_kind": kind, "opnd": val, "opnd_note": note,
        })
        if limit and len(out) >= limit:
            break
    return out


def disasm_static(prof, data, start, count):
    """无 trace 时的退化反汇编。

    长度无法静态确定（每条 handler 自定 pc 推进），这里按 profile 的
    `static_insn_len`（默认 3）推进，并在输出里明确标注为「推测」。
    """
    names = opcode_names(prof)
    handlers = handler_table(data, prof)
    layout = operand_layout(prof)
    kx = int(prof.get("key_xor", 0x5F))
    step = int(prof.get("static_insn_len", 3))
    out = []
    pc = start
    prev_op = None
    for i in range(count):
        if pc + step > len(data):
            break
        if prev_op is None:
            op = decode_byte(prof, data[pc + step - 1], int(prof.get("entry_key", 0)) ^ kx)
        else:
            op = decode_byte(prof, data[pc + step - 1], prev_op ^ kx)
        op &= 0xFF
        raw = data[pc:pc + step]
        body = raw[:-1]
        kind, val, note = decode_operand(op, body, layout)
        out.append({
            "idx": i, "pc": pc, "op": op,
            "name": names.get(op, "?"), "len": step,
            "handler": handlers.get(op), "raw": raw.hex(" "),
            "opnd_kind": kind, "opnd": val, "opnd_note": note,
            "guessed_len": True,
        })
        prev_op = op
        pc += step
    return out


def print_listing(rows, show_handlers=False):
    hdr = "  %4s  %8s  %4s  %3s  %-16s %-16s %s" % (
        "#", "pc", "op", "len", "name", "operand", "raw")
    if show_handlers:
        hdr = "  %4s  %8s  %4s  %3s  %9s  %-16s %-16s %s" % (
            "#", "pc", "op", "len", "handler", "name", "operand", "raw")
    print(hdr)
    for r in rows:
        opnd = r.get("opnd_note") or ""
        if show_handlers:
            h = "%#x" % r["handler"] if r["handler"] else "-"
            print("  %4d  %#08x  %#04x  %3d  %9s  %-16s %-16s %s"
                  % (r["idx"], r["pc"], r["op"], r["len"], h,
                     r["name"], opnd, r["raw"]))
        else:
            print("  %4d  %#08x  %#04x  %3d  %-16s %-16s %s"
                  % (r["idx"], r["pc"], r["op"], r["len"],
                     r["name"], opnd, r["raw"]))


def cmd_disasm(args):
    prof = load_profile(args.profile)
    with open(args.so, "rb") as f:
        data = f.read()

    if args.trace:
        with open(args.trace, encoding="utf-8") as f:
            trace = json.load(f)
        if args.list_vms:
            for k, v in trace.items():
                print("%-16s %4d 条  首 pc=%#x" % (k, len(v), v[0][0] if v else 0))
            return 0
        rows_raw = _rows_from_trace(trace, args.vm)
        if not rows_raw:
            print("trace 里没有 %s；可用：%s" % (args.vm, ", ".join(trace)))
            return 1
        rows = disasm_from_trace(prof, data, rows_raw, args.count)
        print("=== %s  共 %d 条指令，显示前 %d 条 ===" % (args.vm, len(rows_raw), len(rows)))
    else:
        if not args.start:
            print("没有 --trace 时必须给 --start <pc>（字节码起始 ELF VA）")
            return 1
        start = int(args.start, 0)
        rows = disasm_static(prof, data, start, args.count)
        print("=== 静态反汇编 @%#x（长度按 profile 推测，建议用 --trace 校准）===" % start)

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
    else:
        print_listing(rows, args.handlers)

    ops = Counter(r["op"] for r in rows)
    names = opcode_names(prof)
    print("\n=== opcode 频次 ===")
    for op, n in ops.most_common():
        print("  %#04x %-20s %d" % (op, names.get(op, "?"), n))
    return 0


# ---------------------------------------------------------------- trace

def _make_writable(h, path, addrs):
    """把包含这些地址的页改成 RWX。

    脱壳镜像的 GOT 常落在 .rodata（只读），VM 解释器还会把 opcode 表
    memcpy 到 .rodata 里的副本 —— 不放写权限会 UC_ERR_WRITE_UNMAPPED。
    """
    from unicorn import UC_PROT_ALL
    pages = {(a & ~0xFFF) for a in addrs if a}
    for pg in pages:
        try:
            h.uc.mem_protect(pg, 0x1000, UC_PROT_ALL)
        except Exception:  # noqa: BLE001
            pass


def _num(v, default=0):
    """profile 里的数值可能是 int 或 "0x..." 字符串。"""
    if v is None:
        return default
    if isinstance(v, str):
        return int(v, 0)
    return int(v)


def cmd_trace(args):
    """动态跑 VM 并记录每次 dispatch 的 (pc, opcode, key, handler)。

    全部地址来自 profile：entry_va / dispatch_hook_pc / selector_hook_pc /
    frame_*_off。换壳只改 profile。
    """
    prof = load_profile(args.profile)
    for k in ("entry_va", "dispatch_hook_pc"):
        if k not in prof:
            raise SystemExit("profile 缺 %s（trace 子命令必需）" % k)

    from uniharness import Harness
    from unicorn import UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X9
    import emu_run as E

    so = args.so
    with open(so, "rb") as f:
        data = f.read()

    h = Harness()
    h.map_elf(so)
    # VM 解释器栈帧很大（实测某壳单次执行耗用 ~350 KB），默认 64 KB 会写穿栈底
    h.setup_stack(_num(prof.get("stack_size"), 0x200000))
    h.setup_tls()

    # VM 运行时会在 arena 里 mmap 帧/表副本，默认按需扩页跟不上（memcpy 目标
    # 落在已映射区之外 → WRITE_UNMAPPED）。先按 profile 预扩。
    arena_pre = _num(prof.get("arena_presize"), 0)
    if arena_pre:
        try:
            h.alloc(arena_pre, align=0x1000)
        except Exception:  # noqa: BLE001
            pass

    E.clear_runtime_bss(h, so)

    vm_addr = 0
    env_addr = 0
    if args.setup:
        # 样本专属环境（GOT 桩 / bss 清零 / JNI 两级表 / syscall 层）由 setup
        # 脚本全权负责 —— 与 probe_layout 的 --setup 同一契约：prepare(h, so, data)
        spec = importlib.util.spec_from_file_location("vmp_setup", args.setup)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        prepare = getattr(mod, "prepare", None)
        if prepare is None:
            raise SystemExit("%s 里没有 prepare(h, so_path, data)" % args.setup)
        ret = prepare(h, so, data)
        vm_addr = ret[0] if isinstance(ret, tuple) else (ret or 0)
        env_addr = getattr(h, "jni_env_addr", 0) or 0
    else:
        # 通用路径：只做与样本无关的清理，GOT 走 PT_DYNAMIC 重定位
        stubs = E.make_libc_stubs(h, set())
        E.apply_relocations(h, so, stubs)
        reloc_offs = E._relocation_offsets(so)
        E.neutralize_runtime_ptrs(h, so, skip=reloc_offs)
        _make_writable(h, so, list(reloc_offs) + [int(prof["handler_table_file_va"], 16)])
        env_addr = E.build_jni(h, E._ret0)
        vm_addr = getattr(h, "jni_vm", 0)
        try:
            E.install_syscalls(h, log=False)
        except Exception:  # noqa: BLE001
            pass

    sel = args.sel
    sel_pc = prof.get("selector_hook_pc")
    # 只在需要覆盖 selector 时才 hook：vm_dispatch_entry 会被反复进入，
    # 每次都改写传参寄存器会破坏解释器自身的循环条件。
    if sel and sel_pc:
        sel_reg = prof.get("selector_arg_reg", "x5")
        from unicorn.arm64_const import (UC_ARM64_REG_X5, UC_ARM64_REG_X4,
                                         UC_ARM64_REG_X6, UC_ARM64_REG_X7)
        REGS = {"x4": UC_ARM64_REG_X4, "x5": UC_ARM64_REG_X5,
                "x6": UC_ARM64_REG_X6, "x7": UC_ARM64_REG_X7}
        reg = REGS.get(sel_reg.lower(), UC_ARM64_REG_X5)

        def sel_hook(uc, addr, size, user):
            uc.reg_write(reg, sel)

        pc = int(sel_pc, 16)
        h.uc.hook_add(UC_HOOK_CODE, sel_hook, begin=pc, end=pc)

    tbl_va = int(prof["handler_table_file_va"], 16)
    n_tbl = int(prof.get("handler_count", 256))
    table = struct.unpack_from("<%dQ" % n_tbl, data, tbl_va)

    pc_off = _num(prof.get("frame_pc_off"), 0x820)
    idx_off = _num(prof.get("frame_idx_off"), 0x82c)
    key_off = _num(prof.get("frame_key_off"), 0x81c)
    hook_pc = int(prof["dispatch_hook_pc"], 16)

    rows = []

    def hook(uc, addr, size, user):
        if addr != hook_pc:
            return
        sp = uc.reg_read(UC_ARM64_REG_SP)
        pc_v = struct.unpack("<Q", bytes(uc.mem_read(sp + pc_off, 8)))[0]
        idx = struct.unpack("<B", bytes(uc.mem_read(sp + idx_off, 1)))[0]
        key = struct.unpack("<B", bytes(uc.mem_read(sp + key_off, 1)))[0]
        hh = table[idx] if idx < len(table) else 0
        rows.append((pc_v, idx, key, hh, data[pc_v:pc_v + 6]))

    h.uc.hook_add(UC_HOOK_CODE, hook)

    entry = int(prof["entry_va"], 16)
    call_args = (vm_addr, sel) if prof.get("entry_takes_selector", True) else (vm_addr,)
    status = "completed"
    try:
        h.call(entry, args=call_args, timeout=int(args.timeout * 1_000_000))
    except Exception as e:  # noqa: BLE001
        status = "fault: %s" % e

    print("=== 动态追踪 sel=%d: %s ===" % (sel, status))
    print("dispatch 次数: %d" % len(rows))

    if args.out:
        payload = {"%s_%x" % (prof.get("name", "VM"), entry):
                   [[r[0], r[1]] for r in rows]}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        print("trace -> %s" % args.out)

    names = opcode_names(prof)
    print("\n=== 执行序列（前 %d 条）===" % args.limit)
    print("  %3s  %8s  %4s  %4s  %9s  %-18s name" % ("#", "pc", "op", "key", "handler", "raw@pc"))
    base = int(prof.get("bytecode_file_va", "0"), 16)
    for i, (pc_v, idx, key, hh, raw) in enumerate(rows[:args.limit]):
        print("  %3d  %#08x  %#04x  %#04x  %#09x  %-18s %s"
              % (i, pc_v - base, idx, key, hh, raw.hex(" "),
                 names.get(idx, "?")))

    if len(rows) > 1:
        steps = Counter(rows[i + 1][0] - rows[i][0] for i in range(len(rows) - 1))
        print("\n=== pc 步长分布 ===")
        for step, n in steps.most_common():
            print("  %+6d : %d" % (step, n))
    return 0


# ---------------------------------------------------------------- model

def cmd_model(args):
    """查询 Ghidra 导出的 handler 指令模型（so_vm_model_handlers.java）。"""
    path = args.model or os.path.join(
        os.environ.get("TMP", "/tmp"), "vm_handler_model.json")
    if not os.path.isfile(path):
        raise SystemExit("找不到模型文件: %s\n先跑 Ghidra 脚本 so_vm_model_handlers.java" % path)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get("handlers", [])

    if args.op is not None:
        want = int(args.op, 0)
        for it in items:
            if want in it.get("opcodes", []):
                print(json.dumps(it, ensure_ascii=False, indent=1))
                return 0
        print("没有 handler 覆盖 opcode %#x" % want)
        return 1

    if args.delta is not None:
        sel = [it for it in items if it.get("pc_delta") == args.delta]
        print("pc_delta == %d 的 handler: %d 个" % (args.delta, len(sel)))
        for it in sel:
            print("  %#010x  ops=%s  size=%s"
                  % (it.get("entry", 0), it.get("opcodes"), it.get("size")))
        return 0

    if args.stats:
        print("=== handler 模型统计 ===")
        print("  handler 总数 : %d" % len(items))
        d = Counter(it.get("pc_delta") for it in items)
        print("\n  pc_delta 分布:")
        for k, v in sorted(d.items(), key=lambda kv: -kv[1]):
            print("    %-6s %d" % (k, v))
        ex = Counter(it.get("exit") for it in items)
        print("\n  出口类型:")
        for k, v in ex.most_common():
            print("    %-12s %d" % (k, v))
        feat = Counter()
        for it in items:
            for f in it.get("features", []):
                feat[f] += 1
        print("\n  特征:")
        for k, v in feat.most_common():
            print("    %-16s %d" % (k, v))
        return 0

    if args.markdown:
        print("| entry | opcodes | size | pc_delta | exit | features |")
        print("|---|---|---|---|---|---|")
        for it in items:
            print("| `%#x` | %s | %s | %s | %s | %s |" % (
                it.get("entry", 0),
                ",".join("%#x" % o for o in it.get("opcodes", [])),
                it.get("size", ""), it.get("pc_delta", ""),
                it.get("exit", ""), ",".join(it.get("features", []))))
        return 0

    print("%-12s %-22s %-6s %-9s %-12s %s"
          % ("entry", "opcodes", "size", "pc_delta", "exit", "features"))
    for it in items:
        print("%#012x %-22s %-6s %-9s %-12s %s" % (
            it.get("entry", 0),
            ",".join("%#x" % o for o in it.get("opcodes", [])),
            it.get("size", ""), it.get("pc_delta", ""),
            it.get("exit", ""), ",".join(it.get("features", []))))
    return 0


# ---------------------------------------------------------------- profile

def cmd_profile(args):
    if args.action == "list" or not args.action:
        ps = list_profiles()
        if not ps:
            print("(没有可用 profile：tools/vmp_profiles 与各 <包名>/tools/vm_profiles 均为空)")
            return 0
        for name in ps:
            prof = load_profile(name)
            print("%-28s %s" % (name, prof.get("description", "")))
        return 0
    if args.action == "show":
        if not args.name:
            print("需要 profile 名")
            return 1
        print(json.dumps(load_profile(args.name), ensure_ascii=False, indent=1))
        return 0
    if args.action == "new":
        if not args.name:
            print("需要新 profile 名：vmp.py profile new <name>")
            return 1
        path = new_profile(args.name, force=args.force)
        print("已创建 -> %s" % path)
        print()
        print("下一步：按每个字段的 _comment 填值。")
        print("  [engine] 先填（key_xor / decode / handler_table_file_va / handler_count / bytecode_file_va）")
        print("  填完跑：python3 tools/vmp.py verify <so> -p %s --trace <trace.json>" % args.name)
        print("  命中率 > 95% 后再补 [trace] 字段")
        return 0
    print("用法: vmp.py profile [list|show <name>|new <name> [--force]]")
    return 1


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="字节码 VM / VMP 壳逆向（profile 驱动）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 tools/vmp.py profile list
  python3 tools/vmp.py verify <so> -p my-vmp --trace trace.json
  python3 tools/vmp.py disasm <so> -p my-vmp --trace trace.json --vm VM-A_60384
  python3 tools/vmp.py trace  <so> -p my-vmp --sel 0 --out trace.json
  python3 tools/vmp.py model --stats
""")
    sub = ap.add_subparsers(dest="cmd")

    p_dis = sub.add_parser("disasm", help="反汇编字节码")
    p_dis.add_argument("so")
    p_dis.add_argument("-p", "--profile", required=True)
    p_dis.add_argument("--trace", help="动态 trace JSON（推荐，长度才准）")
    p_dis.add_argument("--vm", default="VM", help="trace 里的 VM 键")
    p_dis.add_argument("--list-vms", action="store_true", help="只列出 trace 里的 VM")
    p_dis.add_argument("--start", help="无 trace 时的起始 pc（ELF VA）")
    p_dis.add_argument("--count", type=int, default=80)
    p_dis.add_argument("--handlers", action="store_true", help="显示 handler 地址")
    p_dis.add_argument("--json", action="store_true")
    p_dis.set_defaults(func=cmd_disasm)

    p_ver = sub.add_parser("verify", help="用 trace 校验解码模型")
    p_ver.add_argument("so")
    p_ver.add_argument("-p", "--profile", required=True)
    p_ver.add_argument("--trace", default=os.path.join(
        os.environ.get("TMP", "/tmp"), "vm_all_traces.json"))
    p_ver.set_defaults(func=cmd_verify)

    p_tr = sub.add_parser("trace", help="动态追踪 VM 执行路径")
    p_tr.add_argument("so")
    p_tr.add_argument("-p", "--profile", required=True)
    p_tr.add_argument("--sel", type=int, default=0, help="selector 索引")
    p_tr.add_argument("--limit", type=int, default=40, help="打印条数")
    p_tr.add_argument("--timeout", type=float, default=30)
    p_tr.add_argument("--out", help="trace 落盘 JSON")
    p_tr.add_argument("--setup",
                      help="样本环境准备脚本（定义 prepare(h, so_path, data)，"
                           "返回 JavaVM*）；复杂壳必须提供")
    p_tr.set_defaults(func=cmd_trace)

    p_md = sub.add_parser("model", help="查询 handler 指令模型")
    p_md.add_argument("--model", help="模型 JSON（默认 $TMP/vm_handler_model.json）")
    p_md.add_argument("--op", help="只看某个 opcode")
    p_md.add_argument("--delta", type=int, help="只看某个 pc_delta")
    p_md.add_argument("--stats", action="store_true")
    p_md.add_argument("--markdown", action="store_true")
    p_md.set_defaults(func=cmd_model)

    p_pf = sub.add_parser("profile", help="profile 列表/查看")
    p_pf.add_argument("action", nargs="?", choices=["list", "show", "new"], default="list")
    p_pf.add_argument("name", nargs="?")
    p_pf.add_argument("--force", action="store_true", help="new 时覆盖已存在的 profile")
    p_pf.set_defaults(func=cmd_profile)

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
