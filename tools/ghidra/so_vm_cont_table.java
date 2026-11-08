// so_vm_cont_table.java -- label the continuation table and handler table
//
// The interpreter dispatch is two-level:
//
//   handler table  @0x1f3af0   138 entries, indexed by decoded opcode
//   continuation   @0x1f3f40   593 entries, indexed by a per-handler base
//                              (e.g. 0x14d for `lea`) plus a 0/1 selector that
//                              distinguishes "carry the previous opcode as key"
//                              from "force key = 0x3b"
//
// Both tables are copied into the interpreter frame at 0x830 (memcpy of 0x1288
// bytes), so the static copies are the authoritative source.
//
// This script:
//   1. names the two tables
//   2. creates an array data type over each so the decompiler shows `table[i]`
//   3. adds a comment listing which handlers reach which continuation slots
//
// Config: $TMP/so_vm_cont_table.cfg
//   apply=1
//   handler_tbl=0x1f3af0
//   cont_tbl=0x1f3f40
//   handler_n=138
//   cont_n=593
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_vm_cont_table extends GhidraScript {

    private long cfgLong(Properties p, String k, long dflt) {
        String v = p.getProperty(k);
        if (v == null || v.trim().isEmpty()) return dflt;
        v = v.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return Long.parseLong(v.substring(2), 16);
        return Long.parseLong(v);
    }

    /** Add a label + plate comment without touching existing data units. */
    private int nameTable(long va, int n, String name, String comment) throws Exception {
        Address a = toAddr(va);
        Listing lst = currentProgram.getListing();
        currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
        lst.setComment(a, ghidra.program.model.listing.CommentType.PLATE, comment);
        return n;
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_vm_cont_table.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        long hTbl = cfgLong(cfg, "handler_tbl", 0x1f3af0L);
        long cTbl = cfgLong(cfg, "cont_tbl", 0x1f3f40L);
        int hN = (int) cfgLong(cfg, "handler_n", 138);
        int cN = (int) cfgLong(cfg, "cont_n", 593);

        Memory mem = currentProgram.getMemory();
        println(String.format("handler table %#x: %d entries (%d bytes)", hTbl, hN, hN * 8));
        println(String.format("cont table    %#x: %d entries (%d bytes)", cTbl, cN, cN * 8));

        // sanity: every entry must be a code pointer inside .text
        int badH = 0, badC = 0;
        for (int i = 0; i < hN; i++) {
            long v = mem.getLong(toAddr(hTbl + i * 8L));
            if (v < 0x140000L || v > 0x1f0000L) { badH++; if (badH < 4) println("  bad handler " + i + " = " + Long.toHexString(v)); }
        }
        for (int i = 0; i < cN; i++) {
            long v = mem.getLong(toAddr(cTbl + i * 8L));
            if (v < 0x140000L || v > 0x1f0000L) { badC++; if (badC < 4) println("  bad cont " + i + " = " + Long.toHexString(v)); }
        }
        println("out-of-range: handler=" + badH + " cont=" + badC);

        if (!apply) {
            println("dry run -- set apply=1 in $TMP/so_vm_cont_table.cfg");
            return;
        }

        nameTable(hTbl, hN, "g_vm_handler_tbl",
                "VM opcode -> handler table.\n"
                + hN + " entries, indexed by the decoded opcode (0x00-0x" + Integer.toHexString(hN - 1) + ").\n"
                + "Entries are ELF VAs; runtime adds the image base 0x100000.\n"
                + "The interpreter memcpy's 0x1288 bytes starting here into its frame at +0x830.");
        nameTable(cTbl, cN, "g_vm_cont_tbl",
                "VM continuation table.\n"
                + cN + " entries. Each handler ends with\n"
                + "  ldr x9,[x24, (base + cond)*8]\n"
                + "where base comes from a global (e.g. 0x14d for `lea`) and cond is\n"
                + "  (prev_opcode + 0x7b < 5) && (byte[2] == 0x3b)\n"
                + "cond=0 carries the previous opcode as the next key; cond=1 forces key 0x3b.");
        println("named g_vm_handler_tbl / g_vm_cont_tbl");
    }
}
