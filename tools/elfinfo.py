#!/usr/bin/env python3
# elfinfo.py — ELF/SO 侦察：段表·节表·依赖·导出·导入·重定位·vaddr↔文件偏移
# 用法:
#   python3 elfinfo.py <so>              # 文本报告
#   python3 elfinfo.py <so> --json       # 结构化输出（供脚本/harness 消费）
#   python3 elfinfo.py <so> --v2o 0x1930 # vaddr → 文件偏移（raw 映射/字符串定位用）
#
# 用途: SO 静态分析与模拟 harness 前置——
#   1. raw 映射判定（vaddr==file offset?）决定用 map_raw 还是 map_elf
#   2. 导出地址喂给 emulator/Ghidra；导入符号决定 harness 要打哪些桩
#   3. 重定位类型统计决定要不要处理 GOT
#
# 依赖: pip install pyelftools
import argparse
import json
import sys

from elftools.elf.elffile import ELFFile

AARCH64_RELOC = {
    257: "ABS64", 258: "ABS32", 259: "ABS16", 260: "PREL64", 261: "PREL32", 262: "PREL16",
    275: "ADR_PREL_PG_HI21", 277: "ADD_ABS_LO12_NC", 278: "LDST8_ABS_LO12_NC",
    1024: "COPY", 1025: "GLOB_DAT", 1026: "JUMP_SLOT", 1027: "RELATIVE",
}

INTERESTING_SECTIONS = (".text", ".rodata", ".data", ".bss", ".init_array", ".fini_array",
                        ".rela.dyn", ".rela.plt", ".dynsym", ".dynstr", ".got", ".plt")


def seg_flags(p):
    f = ("R" if p & 0x4 else "") + ("W" if p & 0x2 else "") + ("X" if p & 0x1 else "")
    return f or "-"


def sec_flags(sh):
    f = ("A" if sh["sh_flags"] & 0x2 else "") + ("W" if sh["sh_flags"] & 0x1 else "") \
        + ("X" if sh["sh_flags"] & 0x4 else "")
    return f or "-"


def collect(path):
    info = {"file": path}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        eh = elf.header
        info["class"] = eh["e_ident"]["EI_CLASS"]
        info["machine"] = eh["e_machine"]
        info["type"] = eh["e_type"]
        info["entry"] = eh["e_entry"]

        info["segments"] = [{
            "vaddr": s["p_vaddr"], "offset": s["p_offset"],
            "filesz": s["p_filesz"], "memsz": s["p_memsz"],
            "flags": seg_flags(s["p_flags"]),
            "raw_ok": s["p_vaddr"] == s["p_offset"],
        } for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]

        info["sections"] = [{
            "name": s.name, "addr": s["sh_addr"], "offset": s["sh_offset"],
            "size": s["sh_size"], "flags": sec_flags(s),
        } for s in elf.iter_sections()]

        needed, soname = [], None
        dyn = elf.get_section_by_name(".dynamic")
        if dyn is not None:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)
                elif tag.entry.d_tag == "DT_SONAME":
                    soname = tag.soname
        info["needed"] = needed
        info["soname"] = soname

        exports, imports = [], []
        dynsym = elf.get_section_by_name(".dynsym")
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
        for s in elf.iter_sections():
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


def v2o(segments, addr):
    for s in segments:
        if s["vaddr"] <= addr < s["vaddr"] + s["filesz"]:
            return s["offset"] + (addr - s["vaddr"])
    return None


def print_text(info):
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
    print("== Exports (.dynsym defined, %d) ==" % len(info["exports"]))
    for e in info["exports"][:60]:
        print("  %#010x  %6d  %s" % (e["addr"], e["size"], e["name"]))
    if len(info["exports"]) > 60:
        print("  ... (%d total, use --json for all)" % len(info["exports"]))
    print()
    print("== Imports (UND, %d) ==" % len(info["imports"]))
    names = " ".join(i["name"] for i in info["imports"])
    print("  " + (names if names else "(none)"))
    print()
    print("== Relocations ==")
    for k, v in sorted(info["relocations"]["counts"].items(), key=lambda kv: -kv[1]):
        print("  %s x%d" % (k, v))


def main():
    ap = argparse.ArgumentParser(description="ELF/SO 侦察：段/依赖/导出/导入/重定位")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true", help="结构化 JSON 输出")
    ap.add_argument("--v2o", metavar="0xADDR", help="vaddr → 文件偏移")
    args = ap.parse_args()

    try:
        info = collect(args.path)
    except Exception as e:
        print("[!] not an ELF (parse failed): %s" % e)
        sys.exit(1)

    if args.v2o:
        addr = int(args.v2o, 16)
        off = v2o(info["segments"], addr)
        print("vaddr=%#x -> file offset=%s"
              % (addr, ("%#x" % off) if off is not None else "not in any PT_LOAD file range"))
        return

    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
    else:
        print_text(info)


if __name__ == "__main__":
    main()
