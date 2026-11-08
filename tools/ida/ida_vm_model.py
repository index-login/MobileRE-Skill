"""IDA-side VM handler model extraction (mirror of Ghidra so_vm_model_handlers).

Emits the same JSON schema as `tools/ghidra/so_vm_model_handlers.java`:
entry / opcodes / size / insns / pc_delta / key_src / key_const / exit.

The decision rules are aligned field-by-field with the Ghidra version, including the
`end + 0x100` overrun: a handler's body is scanned past its nominal end so that
trailing dispatch code is still attributed to it.  Without that overrun IDA
reports `pc_delta = -1` for ~100 handlers that Ghidra resolves correctly.

Usage:
    ida_vm_model.py [out.json]        # default: <desktop>/vm_handler_model_ida.json

Inside IDA only (needs ida_bytes / idc).  Run via py_exec_file or the
IDAPython console.
"""
import json
import re
import sys

import ida_bytes
import idc

TABLE_VA = 0xF3AF0
TABLE_N = 256
RANGE_LO = 0xBD000
RANGE_HI = 0xC474F
DISPATCH = 0xBD8AC
VM_EXIT = 0xC46E8
SKIP_KEY_OFFS = {0x81C, 0x820, 0x82C}
OVERRUN = 0x100


def opcode_table():
    """handler entry -> list of opcodes that dispatch to it."""
    out = {}
    for i in range(TABLE_N):
        v = ida_bytes.get_qword(TABLE_VA + i * 8)
        if RANGE_LO <= v <= RANGE_HI:
            out.setdefault(v, []).append(i)
    return out


def stack_offset(disasm_low):
    """Read a stack slot offset from an IDA operand.

    IDA prints stack slots two ways: `[sp,#arg_82C]` for the frame the function
    borrowed, and `[sp,#0x820]` for plain numeric form.  Both must be handled.
    """
    m = re.search(r'\[sp,#arg_([0-9a-f]+)\]', disasm_low)
    if m:
        return int(m.group(1), 16)
    m = re.search(r'\[sp,#(?:0x)?([0-9a-f]+)\]', disasm_low)
    if m:
        return int(m.group(1), 16)
    return None


def model_handler(entry, opcodes, end):
    pc_delta = -1
    key_src = -1
    key_const = False
    exit_kind = "unknown"
    n_insns = 0

    ea = entry
    while ea < end + OVERRUN and n_insns < 500:
        low = idc.GetDisasm(ea).lower()
        mnem = idc.print_insn_mnem(ea).lower()
        n_insns += 1

        # pc advance: `add xN,xN,#M` immediately followed by `b <dispatch|vm_exit>`
        if pc_delta < 0:
            m = re.match(r'add\s+x(\d+),\s*x(\d+),\s*#(0x[0-9a-f]+|\d+)', low)
            if m and m.group(1) == m.group(2):
                nxt = ea + idc.get_item_size(ea)
                if idc.print_insn_mnem(nxt).lower() == 'b':
                    if idc.get_operand_value(nxt, 0) in (DISPATCH, VM_EXIT):
                        pc_delta = int(m.group(3), 0)

        # key slot: first `ldrb wN,[sp,#off]` that is not one of the three known slots
        if key_src < 0 and 'ldrb' in low and '[sp,' in low:
            off = stack_offset(low)
            if off is not None and off not in SKIP_KEY_OFFS:
                key_src = off

        if re.search(r'mov\s+w9,\s*#0x3b', low):
            key_const = True

        if mnem == 'b':
            tgt = idc.get_operand_value(ea, 0)
            if tgt == DISPATCH:
                exit_kind = "dispatch"
            elif tgt == VM_EXIT:
                exit_kind = "vm_exit"
        elif mnem == 'br':
            exit_kind = "indirect"

        ea += max(1, idc.get_item_size(ea))

    return {
        "entry": "0x%x" % entry,
        "opcodes": opcodes,
        "size": end - entry,
        "insns": n_insns,
        "pc_delta": pc_delta,
        "key_src": "-" if key_src < 0 else "0x%x" % key_src,
        "key_const": "0x3b" if key_const else None,
        "exit": exit_kind,
    }


def main(out_path=None):
    table = opcode_table()
    keys = sorted(table)
    rows = []
    for i, entry in enumerate(keys):
        end = keys[i + 1] if i + 1 < len(keys) else RANGE_HI
        rows.append(model_handler(entry, table[entry], end))
    if out_path:
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
        print("wrote %d handlers -> %s" % (len(rows), out_path))
    return rows


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
