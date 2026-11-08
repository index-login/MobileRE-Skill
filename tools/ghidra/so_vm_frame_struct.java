// so_vm_frame_struct.java -- model the VM interpreter shared frame as a struct
//
// All VM opcode handlers are fragments of vm_interpreter entered by `br x9`
// from the dispatch site. They share one frame, so Ghidra renders the slots as
// `in_stack_XXXXXXXX` (or, after so_vm_frame_vars.java, as a long parameter
// list). Neither reads well.
//
// This script creates a `vm_frame` structure describing the measured layout and
// optionally retypes the handler functions so the shared frame is visible as a
// single pointer. Offsets come from a Unicorn snapshot at the dispatch site
// (see tools/ghidra/so_vm_frame_vars.java header for the measurement).
//
// Config: $TMP/so_vm_frame_struct.cfg
//   apply=1      create/refresh the struct (default 0 = dry run)
//   size=0x1288  struct size (dispatch + continuation table copy ends here)
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_vm_frame_struct extends GhidraScript {

    // offset, name, type, comment
    private static final Object[][] FIELDS = {
        {0x000L, "sp",            "void *",  "current operand stack pointer (grows up)"},
        {0x008L, "sp_alt",        "void *",  "second copy of sp used by pop-style ops"},
        {0x010L, "frame_base",    "void *",  "operand stack base"},
        {0x018L, "tbl2",          "void *",  "local variable table (0x1135d0)"},
        {0x020L, "tbl1",          "void *",  "local variable table (0x1135b0)"},
        {0x028L, "frame_base_4",  "void *",  "frame_base + 4"},
        {0x030L, "frame_base2",   "void *",  "frame_base (second copy)"},
        {0x038L, "sp2",           "void *",  "third copy of sp"},
        {0x040L, "sp3",           "void *",  "fourth copy of sp"},
        {0x048L, "sp_plus4",      "void *",  "sp + 4"},
        {0x050L, "local_base",    "void *",  "locals area base"},
        {0x058L, "saved_lr",      "long",    "-1 sentinel"},
        {0x060L, "tmp60",         "undefined8", "per-opcode temp"},
        {0x068L, "tmp68",         "undefined8", "per-opcode temp"},
        {0x070L, "tmp70",         "undefined8", "per-opcode temp"},
        {0x078L, "tmp78",         "undefined8", "per-opcode temp"},
        {0x080L, "tmp80",         "undefined8", "per-opcode temp"},
        {0x81cL, "prev_opcode",   "undefined1", "key carried from previous instruction"},
        {0x820L, "pc",            "void *",  "current bytecode pointer"},
        {0x82cL, "opcode",        "undefined1", "decoded opcode of current instruction"},
    };

    private long cfgLong(Properties p, String k, long dflt) {
        String v = p.getProperty(k);
        if (v == null || v.trim().isEmpty()) return dflt;
        v = v.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return Long.parseLong(v.substring(2), 16);
        return Long.parseLong(v);
    }

    private DataType resolve(String tn, DataTypeManager dtm) {
        DataType dt = dtm.getDataType("/" + tn);
        if (dt != null) return dt;
        dt = dtm.getDataType(tn);
        if (dt != null) return dt;
        if ("void *".equals(tn)) return new PointerDataType(dtm.getDataType("/void"));
        return dtm.getDataType("/undefined8");
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_vm_frame_struct.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        int size = (int) cfgLong(cfg, "size", 0x1288L);

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        if (!apply) {
            println("dry run -- fields=" + FIELDS.length + " size=" + size);
            for (Object[] f : FIELDS) {
                println(String.format("  +%#05x  %-14s %s", (Long) f[0], f[1], f[2]));
            }
            println("set apply=1 in $TMP/so_vm_frame_struct.cfg to write");
            return;
        }

        StructureDataType sd = new StructureDataType("vm_frame", 0, dtm);
        long cursor = 0;
        for (Object[] f : FIELDS) {
            long off = (Long) f[0];
            DataType dt = resolve((String) f[2], dtm);
            if (off > cursor) {
                sd.add(new ArrayDataType(Undefined1DataType.dataType,
                        (int) (off - cursor), 1, dtm), "pad_" + Long.toHexString(cursor), null);
            }
            sd.add(dt, (String) f[1], (String) f[3]);
            cursor = off + dt.getLength();
        }
        // 0x840 之后是 memcpy 进来的 handler+cont 表副本（0x1288 字节）
        if (cursor < 0x840L) {
            sd.add(new ArrayDataType(Undefined1DataType.dataType, (int) (0x840L - cursor), 1, dtm),
                    "pad_to_tables", "padding before table copy");
            cursor = 0x840L;
        }
        if (size > cursor) {
            sd.add(new ArrayDataType(Undefined1DataType.dataType, (int) (size - cursor), 1, dtm),
                    "table_copy", "memcpy of handler + continuation tables (0x1288 bytes)");
        }

        DataType existing = dtm.getDataType("/vm_frame");
        if (existing != null) {
            dtm.remove(existing, monitor);
        }
        dtm.addDataType(sd, DataTypeConflictHandler.REPLACE_HANDLER);
        println(String.format("created vm_frame: %d bytes, %d fields", sd.getLength(), sd.getNumComponents()));
    }
}
