"""Rebuild PLT stubs, import prototypes and opcode switches in an IDA database.

Runs inside IDA (via ida_mcp `py_exec_file` or IDAPython console). Handles the
case where an Android arm64 SO was memory-dumped: IDA keeps the raw `.dynsym`
but never links GOT slots to import names, so every PLT stub stays `sub_XXXX`.

Usage:
    ida_rebuild_elf.py                  # all steps, current database
    ida_rebuild_elf.py plt proto switch # selected steps

Steps:
    plt     name PLT stubs `plt_<import>` from DT_JMPREL + DT_SYMTAB
    proto   copy the import's libc prototype onto each PLT stub
    switch  bind `BR Xn` jump tables so Hex-Rays emits a real switch
"""
import sys
import idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_segment
import idautils
import idc

DT_JMPREL = 0x24730
DT_PLTRELSZ = 190
DT_SYMTAB = 0x2F8
DT_STRTAB = 0x5658
SYM_ENT = 24
RELA_ENT = 24

# (BR address, table address, entry count, entry size, index register idx)
OPCODE_SWITCHES = [
    (0xBD75C, 0xF3AF0, 256, 8, 137),  # X8 -> off_F3AF0, 256 VM handlers
]

# X8/X9/X10 ... register indexes used by switch_info_t.regnum
REG_INDEX = {"X8": 137, "X9": 138, "X10": 139, "X11": 140, "W8": 137, "W9": 138}


def _reloc_got_map():
    """GOT slot -> import name, read straight from DT_JMPREL."""
    out = {}
    for i in range(DT_PLTRELSZ):
        off = DT_JMPREL + i * RELA_ENT
        r_offset = ida_bytes.get_qword(off)
        sym_idx = ida_bytes.get_qword(off + 8) >> 32
        st_name = ida_bytes.get_dword(DT_SYMTAB + sym_idx * SYM_ENT)
        raw = ida_bytes.get_strlit_contents(DT_STRTAB + st_name, -1, 0)
        out[r_offset] = raw.decode() if raw else None
    return out


def _got_of_stub(ea):
    """Resolve `ADRP X16,#got; LDR X17,[X16,#off]` to the GOT slot address."""
    if idc.print_insn_mnem(ea) != "ADRP" or idc.print_operand(ea, 0) != "X16":
        return None
    tgts = [x.to for x in idautils.XrefsFrom(ea, 0) if not x.iscode]
    if not tgts:
        return None
    if idc.print_insn_mnem(ea + 4) != "LDR" or idc.print_operand(ea + 4, 0) != "X17":
        return None
    return tgts[0]


def _text_stubs():
    """Map stub address -> GOT slot for every PLT pattern in .text."""
    got2sym = _reloc_got_map()
    stubs = {}
    for seg in idautils.Segments():
        sg = ida_segment.getseg(seg)
        if ida_segment.get_segm_name(sg) != ".text":
            continue
        ea = sg.start_ea
        while ea < sg.end_ea:
            got = _got_of_stub(ea)
            if got in got2sym and got2sym[got]:
                stubs[ea] = got
            ea += 4
    return stubs, got2sym


def _proto_from(ts, name):
    """`int(const char *s)` -> `int name(const char *s)`; None if unparsable."""
    i = ts.find("(")
    if i < 0:
        return None
    ret = ts[:i].strip()
    args = ts[i + 1:ts.rfind(")")].strip()
    return "%s %s(%s)" % (ret, name, args if args else "void")


def step_plt():
    stubs, got2sym = _text_stubs()
    named = 0
    for ea, got in stubs.items():
        if idc.set_name(ea, "plt_" + got2sym[got], idc.SN_NOWARN | idc.SN_NOCHECK):
            named += 1
    print("plt: named %d / %d stubs" % (named, len(stubs)))
    return named


def step_proto():
    stubs, got2sym = _text_stubs()
    applied, missing = 0, []
    for ea, got in stubs.items():
        sym = got2sym[got]
        ext = idc.get_name_ea_simple(sym)
        if ext == idaapi.BADADDR:
            missing.append(sym)
            continue
        ts = idc.get_type(ext)
        proto = _proto_from(ts, sym) if ts else None
        if proto and idc.SetType(ea, proto):
            applied += 1
        else:
            missing.append(sym)
    print("proto: applied %d, unresolved %d %s" % (applied, len(missing), missing[:8]))
    return applied


def step_switch():
    """Bind `BR Xn` to a pointer table so Hex-Rays reconstructs the switch."""
    done = 0
    for br, table, ncases, esize, regnum in OPCODE_SWITCHES:
        si = ida_nalt.switch_info_t()
        si.clear()
        si.startea = br
        si.jumps = table
        si.ncases = ncases
        si.lowcase = 0
        si.elbase = 0
        si.flags = ida_nalt.SWI_STDTBL
        si.set_jtable_element_size(esize)
        si.set_vtable_element_size(esize)
        # regnum/regdtype must be assigned last: set_expr() overwrites them.
        si.regnum = regnum
        si.regdtype = 2
        ida_nalt.set_switch_info(br, si)
        chk = ida_nalt.get_switch_info(br)
        ok = chk is not None and chk.ncases == ncases and chk.get_jtable_element_size() == esize
        print("switch %#x: ncases=%s elsize=%s regnum=%s -> %s"
              % (br, chk.ncases, chk.get_jtable_element_size(), chk.regnum, "ok" if ok else "FAIL"))
        done += 1 if ok else 0
    ida_hexrays.clear_cached_cfuncs()
    return done


STEPS = {"plt": step_plt, "proto": step_proto, "switch": step_switch}


def main(argv):
    wanted = argv or list(STEPS)
    for name in wanted:
        fn = STEPS.get(name)
        if not fn:
            print("unknown step: %s (have: %s)" % (name, ", ".join(STEPS)))
            continue
        fn()


if __name__ == "__main__":
    main(sys.argv[1:])
